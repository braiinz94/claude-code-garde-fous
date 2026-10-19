// veille-injection : lit la sortie des outils qui ramènent du contenu extérieur
// (web, MCP, fichiers hors ~/.claude), et quand des motifs d’injection y sont, ajoute un
// avertissement que seul le modèle lit, affiche une notification et note l’alerte.
// Ne bloque jamais l’outil, ne retire rien de son résultat.

import type { EngineInterface, Register } from 'claude-code'

import { aSurveiller, analyser, avertissement } from './detection'

const DOSSIER = '.claude/logs/injection'

function jour(nowMs: number): string {
  try {
    const p = new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Paris', year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date(nowMs))
    const g = (t: string) => p.find(x => x.type === t)?.value ?? ''
    return `${g('year')}-${g('month')}-${g('day')}`
  } catch {
    return new Date(nowMs).toISOString().slice(0, 10)
  }
}

function cible(outil: string, a: Record<string, unknown>): string | null {
  const s = (k: string) => (typeof a[k] === 'string' ? (a[k] as string) : null)
  if (outil === 'Read') return s('file_path')
  if (outil === 'WebFetch') return (s('url') ?? '').split(/[?#]/)[0] || null
  if (outil === 'WebSearch') return 'recherche web'
  return null
}

async function base($: EngineInterface): Promise<string> {
  return `${(await $.env.get('HOME')) ?? ''}/${DOSSIER}`
}

let file: Promise<unknown> = Promise.resolve()

async function noter($: EngineInterface, ligne: Record<string, unknown>, nowMs: number): Promise<void> {
  const chemin = `${await base($)}/${jour(nowMs)}.jsonl`
  const avant = await $.fs.read(chemin).catch(() => '')
  await $.fs.write(chemin, `${avant}${JSON.stringify(ligne)}\n`)
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command
      .register({ name: 'injection', description: 'veille-injection : alertes du jour (outil, règles, cible)' })
      .catch(() => undefined)
    return next(e)
  })

  on('tool.call', async ($, e, next) => {
    const r = await next(e)
    try {
      if (r.deny !== undefined || typeof r.text !== 'string' || r.text === '') return r
      const args = e as unknown as Record<string, unknown>
      const home = (await $.env.get('HOME')) ?? ''
      if (!aSurveiller(e.tool, args, home)) return r
      const alerte = analyser(r.text)
      if (!alerte) return r
      const now = await $.clock.now()
      const session = await $.session.id().catch(() => 'inconnue')
      file = file
        .then(() =>
          noter($, {
            ts: new Date(now).toISOString(),
            session,
            agent: typeof args.agentId === 'string' ? args.agentId : null,
            outil: e.tool,
            cible: cible(e.tool, args),
            score: alerte.score,
            regles: alerte.regles,
            extraits: alerte.extraits,
          }, now),
        )
        .catch(() => undefined)
      await file
      $.ui.toast(`⚠️ Injection possible dans ${e.tool} : ${alerte.regles.join(', ')}`)
      return { ...r, context: [...(r.context ?? []), avertissement(e.tool, alerte)] }
    } catch {
      // La veille ne doit jamais gêner l’outil.
      return r
    }
  }).catch(($, e, next) => next(e))

  on('command.run', { command: 'injection' }, async $ => {
    const aujourdhui = jour(await $.clock.now())
    const texte = await $.fs.read(`${await base($)}/${aujourdhui}.jsonl`).catch(() => '')
    const lignes = texte.split('\n').filter(Boolean).map(l => {
      try {
        return JSON.parse(l) as { ts?: string; outil?: string; cible?: string | null; regles?: string[]; score?: number }
      } catch {
        return null
      }
    }).filter(x => x !== null)
    if (lignes.length === 0) return { text: `veille-injection · aucune alerte aujourd’hui (${aujourdhui}) · ~/${DOSSIER}/` }
    const dernieres = lignes.slice(-8).reverse().map(l =>
      `- ${(l.ts ?? '').slice(11, 16)} UTC · ${l.outil} · ${l.cible ?? '—'} · score ${l.score} · ${(l.regles ?? []).join(', ')}`,
    )
    return { text: [`veille-injection · ${lignes.length} alerte(s) aujourd’hui (${aujourdhui}) · ~/${DOSSIER}/${aujourdhui}.jsonl`, ...dernieres].join('\n') }
  })
}
