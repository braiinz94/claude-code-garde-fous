import type { On } from 'claude-code'
import { expect, mock, test } from 'claude-code/testing'

import { classer, question } from '../hooks/regles'

const GMAIL = 'mcp__claude_ai_Gmail__send_message'
const DRAFT = 'mcp__claude_ai_Gmail__create_draft'
const DRIVE_SHARE = 'mcp__0a1b2c3d-0000-4000-8000-000000000001__share_file'
const IMESSAGE = 'mcp__Read_and_Send_iMessages__send_imessage'

test('chaque famille surveillée est reconnue, le reste passe', async () => {
  expect(classer(GMAIL, {})?.action).toBe('question')
  expect(classer(IMESSAGE, {})?.famille).toBe('Message')
  expect(classer('mcp__0a1b2c3d-0000-4000-8000-000000000002__create_event', {})?.famille).toBe('Agenda')
  expect(classer('mcp__plugin_legal_docusign__createEnvelope', {})?.famille).toBe('Signature')
  expect(classer('mcp__netlify__netlify-deploy-services-updater', {})?.famille).toBe('Déploiement')
  expect(classer('mcp__lovable__deploy_project', {})?.action).toBe('question')
  expect(classer('mcp__canva__comment-on-design', {})?.famille).toBe('Publication')
  expect(classer('Bash', { command: 'git push origin main' })?.famille).toBe('Terminal')
  expect(classer('Bash', { command: 'cd x && gh pr create --fill' })?.action).toBe('question')
  expect(classer('Bash', { command: 'npx vercel --prod' })?.action).toBe('question')
  // Ce qui ne publie rien passe sans question.
  expect(classer(DRAFT, {})).toBe(null)
  expect(classer('mcp__claude_ai_Gmail__search_threads', {})).toBe(null)
  expect(classer('Bash', { command: 'git status && git log -3' })).toBe(null)
  expect(classer('Read', { file_path: '/tmp/x' })).toBe(null)
  expect(classer('mcp__netlify__netlify-deploy-services-reader', {})).toBe(null)
})

test('les changements de partage ou de visibilité sont refusés d’office', async () => {
  expect(classer(DRIVE_SHARE, {})?.action).toBe('refus')
  expect(classer('mcp__lovable__set_project_visibility', {})?.action).toBe('refus')
})

test('la question montre destinataire, objet et contenu', async () => {
  const c = classer(GMAIL, {})
  const q = c ? question(c, { to: ['client@exemple.fr'], subject: 'Devis', body: 'Bonjour,  voici le devis.' }, false) : ''
  expect(q).toBe('Message · envoi d’un e-mail ou d’un message — à : client@exemple.fr — objet : Devis — contenu : Bonjour, voici le devis. — Autoriser cet envoi ?')
  expect(c ? question(c, {}, true).startsWith('[sous-agent] ') : false).toBe(true)
})

// Monde de test : l'outil répond « envoyé » ; la boîte de dialogue répond `reponse`.
function monde(on: On, reponse: string | null) {
  mock.store(on)
  mock.clock(on, { now: Date.UTC(2026, 9, 15, 9) })
  const executes: string[] = []
  const questions: string[] = []
  on('tool.call', async (_$, e) => {
    if (e.tool === 'AskUserQuestion') {
      const q = (e as unknown as { questions: { question: string }[] }).questions[0]?.question ?? ''
      questions.push(q)
      if (reponse === null) return { deny: 'question fermée' }
      return { result: { questions: [], answers: { [q]: reponse } } as never, text: reponse }
    }
    executes.push(e.tool)
    return { result: 'envoyé' as never, text: 'envoyé' }
  })
  return { executes, questions }
}

test('« Autoriser » : l’envoi part, une seule question posée', async ($, on) => {
  const { executes, questions } = monde(on, 'Autoriser')
  const r = await $.tool.call({ tool: GMAIL, to: 'a@b.fr', subject: 's', body: 'b' })
  expect('deny' in r && r.deny !== undefined).toBe(false)
  expect(executes).toEqual([GMAIL])
  expect(questions.length).toBe(1)
})

test('« Refuser » : rien ne part, le modèle reçoit le refus', async ($, on) => {
  const { executes } = monde(on, 'Refuser')
  const r = await $.tool.call({ tool: GMAIL, to: 'a@b.fr', subject: 's', body: 'b' })
  expect(executes).toEqual([])
  expect('deny' in r ? r.deny : '').toBe('garde-envoi : refusé par l’utilisateur')
})

test('question fermée ou personne pour répondre : rien ne part', async ($, on) => {
  const { executes } = monde(on, null)
  const r = await $.tool.call({ tool: IMESSAGE, phoneNumber: '+33600000000', message: 'test' })
  expect(executes).toEqual([])
  expect(('deny' in r ? r.deny : '') ?? '').toBe('garde-envoi : aucune confirmation possible (question fermée, ou session sans personne pour répondre) — envoi bloqué')
})

test('réponse libre (« Other ») : traitée comme un refus', async ($, on) => {
  const { executes } = monde(on, 'oui mais change l’objet')
  const r = await $.tool.call({ tool: GMAIL, to: 'a@b.fr' })
  expect(executes).toEqual([])
  expect(('deny' in r ? r.deny : '') ?? '').toBe('garde-envoi : refusé par l’utilisateur (réponse : « oui mais change l’objet »)')
})

test('partage Drive : refusé sans poser de question', async ($, on) => {
  const { executes, questions } = monde(on, 'Autoriser')
  const r = await $.tool.call({ tool: DRIVE_SHARE, fileId: 'f1', email: 'x@y.fr' })
  expect(executes).toEqual([])
  expect(questions).toEqual([])
  expect((('deny' in r ? r.deny : '') ?? '').startsWith('garde-envoi : refusé d’office')).toBe(true)
})

test('outil non concerné : aucune question, il s’exécute', async ($, on) => {
  const { executes, questions } = monde(on, 'Refuser')
  await $.tool.call({ tool: DRAFT, to: 'a@b.fr', body: 'brouillon' })
  expect(executes).toEqual([DRAFT])
  expect(questions).toEqual([])
})

test('panne du mod (horloge indisponible) : l’envoi est bloqué par précaution', async ($, on) => {
  mock.store(on)
  const executes: string[] = []
  on('tool.call', async (_$, e) => {
    executes.push(e.tool)
    return { result: 'envoyé' as never, text: 'envoyé' }
  })
  const r = await $.tool.call({ tool: GMAIL, to: 'a@b.fr', subject: 's' })
  expect(executes).toEqual([])
  expect(('deny' in r ? r.deny : '') ?? '').toBe('garde-envoi : contrôle impossible (erreur du mod) — envoi bloqué par précaution')
})
