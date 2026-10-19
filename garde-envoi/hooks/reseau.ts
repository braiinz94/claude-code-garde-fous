// Envois réseau depuis le terminal, hôte par hôte. Logique pure.
// Idée reprise de net-guard (Singh-AP), sans son code ni ses listes par défaut.

// Liste d'hôtes autorisés, réglée par l'utilisateur (option « hotes »).
// « .x » = x et ses sous-domaines ; séparateurs : virgules ou espaces.
export function lireListe(texte: unknown): string[] {
  if (typeof texte !== 'string') return []
  return texte.split(/[\s,]+/).map(h => h.trim().toLowerCase()).filter(Boolean)
}

export function dansListe(hote: string, liste: readonly string[]): boolean {
  const h = hote.toLowerCase().replace(/\.$/, '')
  return liste.some(d => (d.startsWith('.') ? h === d.slice(1) || h.endsWith(d) : h === d))
}

// La machine elle-même : ni envoi externe, ni question.
export function estLocal(hote: string): boolean {
  const h = hote.toLowerCase().replace(/^\[|\]$/g, '')
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0' || h.endsWith('.localhost') || h.endsWith('.test')
}

export type Reseau = { envoi: boolean; quoi: string; hotes: string[] }

// Recréée à chaque usage : une expression globale partagée garde sa position
// d'un appel à l'autre et sauterait des hôtes.
const urlHote = () => /\b(?:https?|ftps?|wss?|sftp):\/\/(?:[^\s/@'"]+@)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)/g

export function hoteUrl(url: string): string | null {
  return urlHote().exec(url)?.[1]?.toLowerCase() ?? null
}

function hotesDesUrls(texte: string): string[] {
  return [...texte.matchAll(urlHote())].map(m => (m[1] ?? '').toLowerCase()).filter(Boolean)
}

// « utilisateur@hôte:chemin » ou « hôte:chemin » (scp, rsync) ; « hôte::module » (rsync).
function hoteDistant(mot: string): string | null {
  const m = /^(?:[^\s@/:]+@)?([A-Za-z0-9.-]+):(?!\/\/)/.exec(mot)
  if (!m?.[1]) return null
  const h = m[1]
  return mot.includes('@') || h.includes('.') ? h.toLowerCase() : null
}

const mots = (segment: string) => segment.trim().split(/\s+/).filter(m => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(m))
const programme = (m: readonly string[]) => (m[0] ?? '').split('/').pop() ?? ''

// Premier argument qui n'est pas une option ; les options à valeur sautent leur valeur.
function premierArgument(m: readonly string[], optionsAValeur: RegExp): string | null {
  for (let i = 1; i < m.length; i++) {
    const x = m[i] ?? ''
    if (x.startsWith('-')) {
      if (optionsAValeur.test(x)) i += 1
      continue
    }
    return x
  }
  return null
}

const CURL_ENVOI = /(?:^|\s)(?:-[a-zA-Z]*[dFT](?=$|\s|@|['"])|--data(?:-[a-z]+)?\b|--form(?:-string)?\b|--upload-file\b|--json\b|-X\s*['"]?(?:POST|PUT|PATCH|DELETE)\b|--request\s+['"]?(?:POST|PUT|PATCH|DELETE)\b)/i
const WGET_ENVOI = /--(?:post|body)-(?:data|file)\b|--method[=\s]+['"]?(?:POST|PUT|PATCH|DELETE)\b/i
const GH_API_ECRIT = /(?:^|\s)(?:-[fF]\b|--field\b|--raw-field\b|--input\b|-X\s*['"]?(?:POST|PUT|PATCH|DELETE)\b|--method\s+['"]?(?:POST|PUT|PATCH|DELETE)\b)/i

// Analyse une commande, segment par segment (« ; », « && », « | ») : ce qui part
// sur le réseau, vers quels hôtes, et s'il s'agit d'un envoi de données.
export function analyserBash(commande: string): { envois: Reseau[]; lectures: string[] } {
  const envois: Reseau[] = []
  const lectures: string[] = []
  for (const seg of commande.split(/\|\||&&|[;|&\n]/)) {
    const m = mots(seg)
    const p = programme(m)
    if (p === 'curl' || p === 'wget') {
      const hotes = hotesDesUrls(seg)
      const envoi = (p === 'curl' ? CURL_ENVOI : WGET_ENVOI).test(seg)
      if (envoi) envois.push({ envoi: true, quoi: `envoi de données (${p})`, hotes })
      else lectures.push(...hotes)
    } else if (p === 'gh' && m[1] === 'api' && GH_API_ECRIT.test(seg)) {
      const hote = m.find(x => /^--hostname=/.test(x))?.split('=')[1] ?? 'api.github.com'
      envois.push({ envoi: true, quoi: 'écriture par l’API GitHub (gh api)', hotes: [hote.toLowerCase()] })
    } else if (p === 'scp' || p === 'rsync' || p === 'sftp') {
      const hotes = m.slice(1).map(hoteDistant).filter((h): h is string => h !== null)
      if (hotes.length > 0) envois.push({ envoi: true, quoi: `copie réseau (${p})`, hotes })
    } else if (p === 'ssh') {
      const cible = premierArgument(m, /^-[bcDEeFIiJLlmOopQRSWw]$/)
      if (cible) envois.push({ envoi: true, quoi: 'commande à distance (ssh)', hotes: [cible.replace(/^[^@]*@/, '').toLowerCase()] })
    } else if (p === 'nc' || p === 'ncat' || p === 'netcat' || p === 'telnet' || p === 'socat') {
      const cible = premierArgument(m, /^-[ipswqx]$/)
      envois.push({ envoi: true, quoi: `connexion réseau brute (${p})`, hotes: cible ? [cible.toLowerCase()] : [] })
    }
  }
  // Un envoi vers la machine elle-même n'est pas un envoi externe.
  const externes = envois
    .map(e => ({ ...e, hotes: e.hotes.filter(h => !estLocal(h)) }))
    .filter((e, i) => e.hotes.length > 0 || (envois[i]?.hotes.length ?? 0) === 0)
  return { envois: externes, lectures: lectures.filter(h => !estLocal(h)) }
}
