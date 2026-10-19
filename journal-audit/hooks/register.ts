// journal-audit : une ligne chaînée par appel d'outil, dans
// ~/.claude/logs/audit-ia/AAAA-MM-JJ/<session>-<nnn>.jsonl. Jamais bloquant.

import type { EngineInterface, Register } from 'claude-code'

import { argumentsSeuls, cible, DEBUT_CHAINE, issue, jour, nomSegment, serialiser, sha256, sortie, TAILLE_SEGMENT, VERSION_FORMAT, verifier } from './journal'
import type { Ligne } from './journal'

const DOSSIER = '.claude/logs/audit-ia'

type Etat = { jour: string; seg: number; dernier: string; lignes: string[] }

// Modèle et skill actifs, par boucle (« main » ou identifiant du sous-agent).
const modeles = new Map<string, string>()
const skills = new Map<string, string>()
let etat: Etat | null = null
let file: Promise<unknown> = Promise.resolve()

const cle = (agentId: unknown) => (typeof agentId === 'string' ? agentId : 'main')

async function racine($: EngineInterface): Promise<string> {
  return `${(await $.env.get('HOME')) ?? ''}/${DOSSIER}`
}

async function chargerEtat($: EngineInterface, session: string, aujourdhui: string): Promise<Etat> {
  if (etat) return etat
  const memo = (await $.store.get(`etat:${session}`).catch(() => null)) as Omit<Etat, 'lignes'> | null
  if (!memo) return (etat = { jour: aujourdhui, seg: 1, dernier: DEBUT_CHAINE(session), lignes: [] })
  // Reprise après rechargement : on relit le segment en cours pour continuer à l'identique.
  const chemin = `${await racine($)}/${memo.jour}/${nomSegment(session, memo.seg)}`
  const texte = await $.fs.read(chemin).catch(() => '')
  return (etat = { ...memo, lignes: texte.split('\n').filter(Boolean) })
}

async function ecrire($: EngineInterface, session: string, l: Omit<Ligne, 'prev'>): Promise<void> {
  const aujourdhui = jour(Date.parse(l.ts))
  const e = await chargerEtat($, session, aujourdhui)
  if (e.jour !== aujourdhui || e.lignes.length >= TAILLE_SEGMENT) {
    e.seg = e.jour !== aujourdhui ? 1 : e.seg + 1
    e.jour = aujourdhui
    e.lignes = []
  }
  const brut = serialiser({ ...l, prev: e.dernier })
  e.lignes.push(brut)
  await $.fs.write(`${await racine($)}/${e.jour}/${nomSegment(session, e.seg)}`, `${e.lignes.join('\n')}\n`)
  e.dernier = await sha256(brut)
  await $.store.set(`etat:${session}`, { jour: e.jour, seg: e.seg, dernier: e.dernier })
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command
      .register({ name: 'audit', description: 'journal-audit : lignes du jour, emplacement, vérification de la chaîne de cette session' })
      .catch(() => undefined)
    return next(e)
  })

  // Le modèle réel de chaque étape, par boucle.
  on('turn.step', async function* ($, e, next) {
    modeles.set(cle(e.agentId), e.model)
    return yield* next(e)
  })

  on('skill.prompt', async ($, e, next) => {
    skills.set(cle((e as unknown as { agentId?: unknown }).agentId), e.skill)
    return next(e)
  })

  on('tool.call', async ($, e, next) => {
    const t0 = await $.clock.now()
    const r = await next(e)
    try {
      const entree = e as unknown as Record<string, unknown>
      const boucle = cle(entree.agentId)
      const [session, fin] = await Promise.all([$.session.id(), $.clock.now()])
      let modele = modeles.get(boucle)
      const source = modele ? 'etape' : 'session'
      if (!modele) modele = await $.session.model().catch(() => 'inconnu')
      const args = argumentsSeuls(entree)
      const ligne: Omit<Ligne, 'prev'> = {
        v: VERSION_FORMAT,
        ts: new Date(fin).toISOString(),
        session,
        agent: boucle === 'main' ? null : boucle,
        modele,
        modele_source: source,
        skill: skills.get(boucle) ?? null,
        outil: e.tool,
        cible: cible(e.tool, args),
        tool_use_id: typeof entree.tool_use_id === 'string' ? entree.tool_use_id : null,
        in_sha256: await sha256(JSON.stringify(args)),
        out_sha256: await sha256(sortie(r)),
        issue: issue(r),
        duree_ms: Math.max(0, Math.round(fin - t0)),
      }
      // File d'attente : les appels parallèles s'écrivent dans l'ordre, la chaîne reste intacte.
      file = file.then(() => ecrire($, session, ligne)).catch(() => undefined)
      await file
    } catch {
      // Le journal ne doit jamais gêner l'outil.
    }
    return r
  }).catch(($, e, next) => next(e))

  on('command.run', { command: 'audit' }, async $ => {
    const session = await $.session.id()
    const base = await racine($)
    const aujourdhui = jour(await $.clock.now())
    const fichiers = await $.fs.list(`${base}/${aujourdhui}`).catch(() => [])
    let total = 0
    for (const f of fichiers) {
      if (!f.name.endsWith('.jsonl')) continue
      const t = await $.fs.read(`${base}/${aujourdhui}/${f.name}`).catch(() => '')
      total += t.split('\n').filter(Boolean).length
    }
    // Chaîne de cette session : tous ses segments, tous les jours, dans l'ordre.
    const jours = (await $.fs.list(base).catch(() => [])).filter(x => x.kind === 'dir').map(x => x.name).sort()
    const miennes: string[] = []
    for (const j of jours) {
      const segs = (await $.fs.list(`${base}/${j}`).catch(() => [])).map(x => x.name).filter(n => n.startsWith(`${session}-`)).sort()
      for (const s of segs) miennes.push(...(await $.fs.read(`${base}/${j}/${s}`).catch(() => '')).split('\n').filter(Boolean))
    }
    const v = await verifier(miennes, DEBUT_CHAINE(session))
    const chaine = v.n === 0 ? 'aucune ligne pour cette session' : v.ok ? `${v.n} lignes, chaîne intacte ✓` : `CHAÎNE ROMPUE à la ligne ${v.rupture} sur ${v.n}`
    return {
      text: [
        `journal-audit · ${total} ligne(s) aujourd’hui (${aujourdhui}), toutes sessions · ~/${DOSSIER}/${aujourdhui}/`,
        `Cette session (${session}) : ${chaine}.`,
        'Contenu noté : heure UTC, session, sous-agent, modèle, skill, outil, cible, SHA-256 entrée et sortie, issue, durée. Aucun argument ni résultat en clair.',
      ].join('\n'),
    }
  })
}
