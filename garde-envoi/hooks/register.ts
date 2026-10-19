// garde-envoi : avant tout envoi, publication ou déploiement, la question
// est posée à l'utilisateur dans la boîte de dialogue de Claude Code. Seul « Autoriser »
// laisse passer. Fermée par défaut : sans réponse, ou en cas d'erreur, l'appel est refusé.

import type { EngineInterface, Register } from 'claude-code'

import { bilan, classer, lecturesHorsListe, noterLectures, question } from './regles'
import { lireListe } from './reseau'
import type { Decision, Lectures } from './regles'

const CLE = 'decisions'
const CLE_LECTURES = 'lectures'

async function noter($: EngineInterface, d: Decision): Promise<void> {
  const avant = ((await $.store.get(CLE).catch(() => null)) ?? []) as Decision[]
  await $.store.set(CLE, [...avant, d].slice(-200)).catch(() => undefined)
}

export const register: Register = (on, options) => {
  const liste = lireListe(options.hotes)

  on('session.start', async ($, e, next) => {
    await $.command
      .register({ name: 'garde', description: 'garde-envoi : familles surveillées et dernières décisions' })
      .catch(() => undefined)
    return next(e)
  })

  on('command.run', { command: 'garde' }, async $ => {
    const d = ((await $.store.get(CLE).catch(() => null)) ?? []) as Decision[]
    const l = (await $.store.get(CLE_LECTURES).catch(() => null)) as Lectures | null
    return { text: bilan(d, l) }
  })

  on('tool.call', async ($, e, next) => {
    const entree = e as unknown as Record<string, unknown>
    // Lectures hors liste : seulement notées ; une panne de la note ne gêne jamais l'outil.
    const lus = lecturesHorsListe(e.tool, entree, liste)
    if (lus.length > 0) {
      try {
        const avant = (await $.store.get(CLE_LECTURES)) as Lectures | null
        await $.store.set(CLE_LECTURES, noterLectures(avant, lus, await $.clock.now()))
      } catch {
        // rien : la lecture passe
      }
    }
    const c = classer(e.tool, entree, liste)
    if (c === null) return next(e)
    const quand = await $.clock.now()
    const trace = (decision: Decision['decision']) => noter($, { quand, famille: c.famille, outil: e.tool, decision })

    if (c.action === 'refus') {
      await trace('refusé d’office')
      return { deny: `garde-envoi : refusé d’office — ${c.raison ?? 'interdit par la politique de sécurité'}` }
    }

    let choix: string
    try {
      choix = await $.ui.ask(question(c, entree, typeof entree.agentId === 'string'), {
        options: ['Autoriser', 'Refuser'],
        header: 'Envoi',
      })
    } catch {
      await trace('sans réponse')
      return { deny: 'garde-envoi : aucune confirmation possible (question fermée, ou session sans personne pour répondre) — envoi bloqué' }
    }
    if (choix !== 'Autoriser') {
      await trace('refusé')
      const precision = choix && choix !== 'Refuser' ? ` (réponse : « ${choix.slice(0, 200)} »)` : ''
      return { deny: `garde-envoi : refusé par l’utilisateur${precision}` }
    }
    await trace('autorisé')
    return next(e)
  }).catch(($, e, next) =>
    // Fermée par défaut : si la garde échoue avant d'avoir laissé passer, l'appel est refusé ;
    // si elle avait déjà laissé passer, le résultat est rejoué tel quel (rien ne s'exécute deux fois).
    next.called ? next(e) : { deny: 'garde-envoi : contrôle impossible (erreur du mod) — envoi bloqué par précaution' },
  )
}
