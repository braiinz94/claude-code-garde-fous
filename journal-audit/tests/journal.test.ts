import type { On } from 'claude-code'
import { expect, mock, test } from 'claude-code/testing'

import { cible, DEBUT_CHAINE, issue, sha256, verifier } from '../hooks/journal'

test('la cible ne contient jamais d’argument sensible', async () => {
  expect(cible('Bash', { command: 'git push origin main' })).toBe('git push')
  expect(cible('Bash', { command: 'TOKEN=abc123 curl https://api.x.fr/v1?key=SECRET' })).toBe('curl')
  expect(cible('Bash', { command: '/usr/bin/python3 -c "print(1)"' })).toBe('python3')
  expect(cible('Bash', { command: 'gh pr create --fill' })).toBe('gh pr')
  expect(cible('WebFetch', { url: 'https://site.fr/page?token=SECRET#x' })).toBe('https://site.fr/page')
  expect(cible('Read', { file_path: '/Users/x/doc.pdf' })).toBe('/Users/x/doc.pdf')
  expect(cible('mcp__banque__get_transactions', { iban: 'FR76…' })).toBe(null)
})

test('issue : ok, erreur, refus', async () => {
  expect(issue({ result: 1, text: 'x' })).toBe('ok')
  expect(issue({ result: 1, text: 'x', isError: true })).toBe('erreur')
  expect(issue({ deny: 'non' })).toBe('refus')
})

test('la chaîne se vérifie et détecte une ligne modifiée ou retirée', async () => {
  const l1 = JSON.stringify({ a: 1, prev: DEBUT_CHAINE('s') })
  const l2 = JSON.stringify({ a: 2, prev: await sha256(l1) })
  const l3 = JSON.stringify({ a: 3, prev: await sha256(l2) })
  expect((await verifier([l1, l2, l3], DEBUT_CHAINE('s'))).ok).toBe(true)
  const altere = l2.replace('"a":2', '"a":9')
  expect(await verifier([l1, altere, l3], DEBUT_CHAINE('s'))).toEqual({ ok: false, n: 3, rupture: 3 })
  expect(await verifier([l1, l3], DEBUT_CHAINE('s'))).toEqual({ ok: false, n: 2, rupture: 2 })
})

// Monde de test : système de fichiers en mémoire, outil qui répond selon son nom.
function monde(on: On, avecFs = true) {
  mock.env(on, { HOME: '/maison' })
  mock.clock(on, { now: Date.UTC(2026, 9, 15, 9, 30) })
  mock.store(on)
  const fichiers = new Map<string, string>()
  if (avecFs) {
    on('fs.write', async (_$, e) => {
      fichiers.set(e.path, e.text)
      return { value: undefined }
    })
    on('fs.read', async (_$, e) => (fichiers.has(e.path) ? { value: fichiers.get(e.path) ?? '' } : { deny: 'absent' }))
  }
  on('session.id', async () => ({ value: 'sess-test' }))
  on('session.model', async () => ({ value: 'claude-opus-5-5' }))
  const executes: string[] = []
  on('tool.call', async (_$, e) => {
    executes.push(e.tool)
    if (e.tool === 'Write') return { deny: 'refusé par une règle' }
    if (e.tool === 'WebFetch') return { result: 'boom' as never, text: 'boom', isError: true }
    return { result: 'sortie' as never, text: 'sortie de l’outil' }
  })
  return { fichiers, executes }
}

test('une ligne chaînée par appel, empreintes complètes, aucun argument en clair', async ($, on) => {
  const { fichiers, executes } = monde(on)
  await $.tool.call({ tool: 'Bash', command: 'git push origin main --token=SECRET-ARG' })
  await $.tool.call({ tool: 'Write', file_path: '/tmp/a.txt', content: 'CONTENU-SECRET' })
  await $.tool.call({ tool: 'WebFetch', url: 'https://x.fr/p?k=SECRET-URL', prompt: 'p' })
  expect(executes).toEqual(['Bash', 'Write', 'WebFetch'])
  const chemin = '/maison/.claude/logs/audit-ia/2026-10-15/sess-test-001.jsonl'
  const texte = fichiers.get(chemin) ?? ''
  const lignes = texte.split('\n').filter(Boolean)
  expect(lignes.length).toBe(3)
  const [a, b, c] = lignes.map(l => JSON.parse(l) as Record<string, unknown>)
  expect([a?.outil, a?.cible, a?.issue, a?.modele, a?.modele_source]).toEqual(['Bash', 'git push', 'ok', 'claude-opus-5-5', 'session'])
  expect([b?.outil, b?.cible, b?.issue]).toEqual(['Write', '/tmp/a.txt', 'refus'])
  expect([c?.outil, c?.cible, c?.issue]).toEqual(['WebFetch', 'https://x.fr/p', 'erreur'])
  expect(String(a?.in_sha256).length).toBe(64)
  expect(String(a?.out_sha256)).toBe(await sha256('sortie de l’outil'))
  for (const secret of ['SECRET-ARG', 'CONTENU-SECRET', 'SECRET-URL', 'sortie de l’outil']) expect(texte.includes(secret)).toBe(false)
  expect((await verifier(lignes, DEBUT_CHAINE('sess-test'))).ok).toBe(true)
})

test('le skill actif est noté sur les appels qui suivent', async ($, on) => {
  const { fichiers } = monde(on)
  on('skill.prompt', async (_$, e) => ({ text: e.text }) as never)
  await $.skill.prompt({ skill: 'mon-skill', text: 'consigne' } as never)
  await $.tool.call({ tool: 'Read', file_path: '/tmp/b.txt' })
  const l = JSON.parse((fichiers.get('/maison/.claude/logs/audit-ia/2026-10-15/sess-test-001.jsonl') ?? '').trim()) as Record<string, unknown>
  expect(l.skill).toBe('mon-skill')
})

test('une panne du journal ne bloque jamais l’outil', async ($, on) => {
  const { executes } = monde(on, false)
  const r = await $.tool.call({ tool: 'Bash', command: 'ls' })
  expect(executes).toEqual(['Bash'])
  expect(('text' in r ? r.text : '') ?? '').toBe('sortie de l’outil')
})

test('le modèle réel de l’étape est noté, par boucle (sous-agent)', async ($, on) => {
  const { fichiers } = monde(on)
  on('turn.step', async function* (_$, e) {
    return { turnId: e.turnId, index: e.index, answer: '', toolUses: [] } as never
  })
  const flux = $.turn.step({ turnId: 't1', index: 0, model: 'claude-haiku-5-5', messageCount: 1, agentId: 'agent-1' } as never)
  for await (const _ of flux) {
    // rien à lire
  }
  await $.tool.call({ tool: 'Read', file_path: '/tmp/c.txt', agentId: 'agent-1' } as never)
  await $.tool.call({ tool: 'Read', file_path: '/tmp/d.txt' })
  const lignes = (fichiers.get('/maison/.claude/logs/audit-ia/2026-10-15/sess-test-001.jsonl') ?? '').split('\n').filter(Boolean).map(l => JSON.parse(l) as Record<string, unknown>)
  expect([lignes[0]?.agent, lignes[0]?.modele, lignes[0]?.modele_source]).toEqual(['agent-1', 'claude-haiku-5-5', 'etape'])
  expect([lignes[1]?.agent, lignes[1]?.modele, lignes[1]?.modele_source]).toEqual([null, 'claude-opus-5-5', 'session'])
})
