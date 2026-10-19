// masque-secrets : chaque ligne de la conversation passe ici avant
// d'être stockée et envoyée au modèle. En observation, rien n'est modifié ; en
// masquage, la valeur du secret est remplacée. La valeur n'est jamais notée.

import type { EngineInterface, Register } from 'claude-code'

import { ajouter, analyser, bilan, LONGUEUR_MIN_CONNUE, TYPE_INDICE } from './secrets'
import type { Connue, Evenement, Journal, Mode } from './secrets'

const CLE_JOURNAL = 'journal'

// Valeurs exactes des variables secrètes courantes, gardées en mémoire seulement :
// jamais écrites, jamais notées. L'API n'accepte que des noms écrits en toutes lettres.
let connues: Connue[] = []

async function lireConnues($: EngineInterface): Promise<Connue[]> {
  const lus = await Promise.all([
    $.env.get('ANTHROPIC_API_KEY').then(v => ['ANTHROPIC_API_KEY', v] as const),
    $.env.get('CLAUDE_CODE_OAUTH_TOKEN').then(v => ['CLAUDE_CODE_OAUTH_TOKEN', v] as const),
    $.env.get('OPENAI_API_KEY').then(v => ['OPENAI_API_KEY', v] as const),
    $.env.get('GITHUB_TOKEN').then(v => ['GITHUB_TOKEN', v] as const),
    $.env.get('GH_TOKEN').then(v => ['GH_TOKEN', v] as const),
    $.env.get('GITHUB_PERSONAL_ACCESS_TOKEN').then(v => ['GITHUB_PERSONAL_ACCESS_TOKEN', v] as const),
    $.env.get('GITLAB_TOKEN').then(v => ['GITLAB_TOKEN', v] as const),
    $.env.get('API_TOKEN').then(v => ['API_TOKEN', v] as const),
    $.env.get('SUPABASE_ACCESS_TOKEN').then(v => ['SUPABASE_ACCESS_TOKEN', v] as const),
    $.env.get('SUPABASE_SERVICE_ROLE_KEY').then(v => ['SUPABASE_SERVICE_ROLE_KEY', v] as const),
    $.env.get('DOPPLER_TOKEN').then(v => ['DOPPLER_TOKEN', v] as const),
    $.env.get('NETLIFY_AUTH_TOKEN').then(v => ['NETLIFY_AUTH_TOKEN', v] as const),
    $.env.get('VERCEL_TOKEN').then(v => ['VERCEL_TOKEN', v] as const),
    $.env.get('NPM_TOKEN').then(v => ['NPM_TOKEN', v] as const),
    $.env.get('AWS_SECRET_ACCESS_KEY').then(v => ['AWS_SECRET_ACCESS_KEY', v] as const),
    $.env.get('AWS_SESSION_TOKEN').then(v => ['AWS_SESSION_TOKEN', v] as const),
    $.env.get('STRIPE_SECRET_KEY').then(v => ['STRIPE_SECRET_KEY', v] as const),
    $.env.get('SLACK_BOT_TOKEN').then(v => ['SLACK_BOT_TOKEN', v] as const),
    $.env.get('GOOGLE_API_KEY').then(v => ['GOOGLE_API_KEY', v] as const),
    $.env.get('OP_SERVICE_ACCOUNT_TOKEN').then(v => ['OP_SERVICE_ACCOUNT_TOKEN', v] as const),
  ])
  return lus.flatMap(([nom, valeur]) => (valeur && valeur.length >= LONGUEUR_MIN_CONNUE ? [{ nom, valeur }] : []))
}

export const register: Register = (on, options) => {
  const mode: Mode = options.mode === 'masquage' ? 'masquage' : 'observation'

  on('session.start', async ($, e, next) => {
    connues = await lireConnues($).catch(() => [])
    await $.command
      .register({ name: 'secrets', description: 'Bilan de masque-secrets : secrets repérés par type et par source' })
      .catch(() => undefined)
    return next(e)
  })

  on('command.run', { command: 'secrets' }, async $ => {
    const journal = ((await $.store.get(CLE_JOURNAL)) ?? null) as Journal | null
    return { text: bilan(journal, mode) }
  })

  on('session.append', async ($, e, next) => {
    // Les notices et les lignes que le mod ajoute lui-même ne sont pas analysées.
    if (e.door === 'notice' || e.door === 'note') return next(e)
    const a = analyser(e.message.content, mode === 'masquage', connues)
    if (a.reperages.length === 0) return next(e)

    const source = e.origin.kind === 'tool' ? e.origin.tool : e.door
    const quand = await $.clock.now()
    const evts: Evenement[] = a.reperages.map(r => ({
      quand, type: r.type, source, mode, forme: r.forme, libelle: r.libelle, masque: mode === 'masquage' && r.masquable,
    }))
    const journal = ((await $.store.get(CLE_JOURNAL)) ?? null) as Journal | null
    await $.store.set(CLE_JOURNAL, ajouter(journal, evts))

    // Les indices sont seulement notés : pas d'alerte, pas de masquage.
    const secrets = a.reperages.filter(r => r.type !== TYPE_INDICE)
    if (secrets.length === 0) return next(e)
    const types = [...new Set(secrets.map(r => r.type))].join(', ')
    if (mode === 'masquage') {
      void $.ui.toast(`Secret masqué avant lecture (${types}) · ${source}`)
      return next({ ...e, message: { ...e.message, content: a.contenu } })
    }
    void $.ui.toast(`Secret repéré (${types}) · ${source} · observation : non masqué`)
    return next(e)
  }).catch(($, e, next) => next(e)) // panne du mod : la ligne passe telle quelle
}
