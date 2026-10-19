// Journal d'audit. Logique pure : empreintes, cible, ligne, chaîne.
// Jamais de contenu en clair : arguments et sorties ne sont notés que par leur SHA-256.

export const VERSION_FORMAT = 1
export const TAILLE_SEGMENT = 200
export const DEBUT_CHAINE = (session: string) => `debut:${session}`

export async function sha256(texte: string): Promise<string> {
  const octets = new TextEncoder().encode(texte)
  const h = await crypto.subtle.digest('SHA-256', octets)
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('')
}

// La date du jour à Paris (AAAA-MM-JJ), pour ranger les fichiers par jour.
export function jour(nowMs: number): string {
  try {
    const p = new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Paris', year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date(nowMs))
    const g = (t: string) => p.find(x => x.type === t)?.value ?? ''
    return `${g('year')}-${g('month')}-${g('day')}`
  } catch {
    return new Date(nowMs).toISOString().slice(0, 10)
  }
}

const RESERVES = new Set(['tool', 'tool_use_id', 'consent', 'agentId', 'requestMeta'])

export function argumentsSeuls(entree: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(entree)) if (!RESERVES.has(k)) out[k] = v
  return out
}

// URL sans requête ni fragment : un jeton peut s'y cacher.
function sansRequete(url: string): string {
  try {
    const u = new URL(url)
    return `${u.origin}${u.pathname}`
  } catch {
    return url.split(/[?#]/)[0] ?? ''
  }
}

// Ce sur quoi l'outil agit, sans contenu : chemin, URL nue, programme lancé.
export function cible(outil: string, a: Record<string, unknown>): string | null {
  const s = (k: string) => (typeof a[k] === 'string' ? (a[k] as string) : null)
  if (['Read', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(outil)) return s('file_path') ?? s('notebook_path')
  if (outil === 'Glob' || outil === 'Grep') return s('path')
  if (outil === 'WebFetch') return s('url') ? sansRequete(s('url') ?? '') : null
  if (outil === 'Skill') return s('skill')
  if (outil === 'Agent') return s('subagent_type') ?? 'general-purpose'
  if (outil === 'Bash') {
    const mots = (s('command') ?? '')
      .trim()
      .split(/\s+/)
      .filter(m => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(m)) // jamais une affectation de variable (secret possible)
    const [prog, sous] = mots
    if (!prog) return null
    // Le programme, plus sa sous-commande si c'en est une (« git push ») ; jamais une URL, un chemin ou une option.
    const nomProg = prog.split('/').pop() ?? prog
    return sous && /^[a-z][a-z0-9-]*$/.test(sous) ? `${nomProg} ${sous}` : nomProg
  }
  return null
}

export type Issue = 'ok' | 'erreur' | 'refus'

export function issue(r: unknown): Issue {
  const o = (r ?? {}) as { deny?: unknown; isError?: unknown }
  if (typeof o.deny === 'string') return 'refus'
  return o.isError === true ? 'erreur' : 'ok'
}

export function sortie(r: unknown): string {
  const o = (r ?? {}) as { deny?: unknown; text?: unknown; result?: unknown }
  if (typeof o.deny === 'string') return o.deny
  if (typeof o.text === 'string') return o.text
  try {
    return JSON.stringify(o.result ?? null) ?? ''
  } catch {
    return String(o.result)
  }
}

export type Ligne = {
  v: number
  ts: string
  session: string
  agent: string | null
  modele: string
  modele_source: 'etape' | 'session'
  skill: string | null
  outil: string
  cible: string | null
  tool_use_id: string | null
  in_sha256: string
  out_sha256: string
  issue: Issue
  duree_ms: number
  prev: string
}

export function serialiser(l: Ligne): string {
  // Ordre des clés fixe : la chaîne doit se recalculer à l'identique.
  return JSON.stringify({
    v: l.v, ts: l.ts, session: l.session, agent: l.agent, modele: l.modele, modele_source: l.modele_source,
    skill: l.skill, outil: l.outil, cible: l.cible, tool_use_id: l.tool_use_id,
    in_sha256: l.in_sha256, out_sha256: l.out_sha256, issue: l.issue, duree_ms: l.duree_ms, prev: l.prev,
  })
}

// Vérifie une chaîne : chaque ligne porte l'empreinte de la précédente.
export async function verifier(lignes: readonly string[], depart: string): Promise<{ ok: boolean; n: number; rupture: number | null }> {
  let attendu = depart
  for (let i = 0; i < lignes.length; i++) {
    const brut = lignes[i] ?? ''
    let prev: unknown
    try {
      prev = (JSON.parse(brut) as { prev?: unknown }).prev
    } catch {
      return { ok: false, n: lignes.length, rupture: i + 1 }
    }
    if (prev !== attendu) return { ok: false, n: lignes.length, rupture: i + 1 }
    attendu = await sha256(brut)
  }
  return { ok: true, n: lignes.length, rupture: null }
}

export const nomSegment = (session: string, n: number) => `${session}-${String(n).padStart(3, '0')}.jsonl`
