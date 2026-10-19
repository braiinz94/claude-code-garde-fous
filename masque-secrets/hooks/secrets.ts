// Repérage et masquage des secrets dans les lignes de la conversation.
// Logique pure : aucun appel à `$`. Le secret lui-même n'est jamais renvoyé
// hors de la fonction de masquage : les trouvailles ne portent que le type et
// la position.

// `masquable` : faux pour un simple indice (chaîne aléatoire), qui n'est jamais
// masqué. `forme` et `libelle` décrivent le repérage sans révéler la valeur,
// pour juger les faux positifs à la revue.
export type Trouvaille = { type: string; debut: number; fin: number; masquable: boolean; forme: string; libelle: string | null }

// Valeur exacte d'une variable d'environnement secrète, lue en mémoire au démarrage.
export type Connue = { nom: string; valeur: string }
export const LONGUEUR_MIN_CONNUE = 12

export const TYPE_INDICE = 'chaîne aléatoire (indice)'

// Longueur et familles de caractères : jamais la valeur.
export function forme(valeur: string): string {
  const familles = [
    /[a-z]/.test(valeur) && 'minuscules',
    /[A-Z]/.test(valeur) && 'majuscules',
    /\d/.test(valeur) && 'chiffres',
    /[^A-Za-z0-9]/.test(valeur) && 'symboles',
  ].filter(Boolean)
  return `${valeur.length} car. (${familles.join(', ')})`
}

type Motif = { type: string; re: RegExp; groupe?: number }

// Formats d'éditeurs, puis secrets reconnus par leur libellé.
const MOTIFS: readonly Motif[] = [
  { type: 'clé Anthropic', re: /\bsk-ant-[a-z0-9]{2,8}-[A-Za-z0-9_-]{30,}/g },
  { type: 'clé OpenAI', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}/g },
  { type: 'jeton GitHub', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})/g },
  { type: 'jeton GitLab', re: /\bglpat-[0-9A-Za-z_-]{20,}/g },
  { type: 'clé Google', re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { type: 'jeton OAuth Google', re: /\bya29\.[0-9A-Za-z_-]{20,}/g },
  { type: 'clé AWS', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: 'jeton Slack', re: /\bxox[baprs]-[0-9A-Za-z-]{20,}/g },
  { type: 'jeton Doppler', re: /\bdp\.[sc]t\.[a-z]{3}\.[A-Za-z0-9_-]{40,}/g },
  { type: 'jeton Shopify', re: /\bshpat_[a-fA-F0-9]{32}\b/g },
  { type: 'clé Stripe', re: /\b[rs]k_live_[0-9A-Za-z]{20,}/g },
  { type: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { type: 'clé privée', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g },
  {
    type: 'cookie de session',
    re: /\b(?:__Secure-[0-9A-Za-z-]+|__Host-[0-9A-Za-z-]+|SAPISID|APISID|SSID|HSID|SID|OSID|sessionid|session_id|PHPSESSID|connect\.sid)=([^;\s"']{16,})/g,
    groupe: 1,
  },
  { type: 'identifiants dans une URL', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]{3,})@/gi, groupe: 1 },
  { type: 'en-tête Authorization', re: /\bAuthorization\s*:\s*(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{12,})/gi, groupe: 1 },
  {
    type: 'mot de passe ou secret',
    re: /(?:mot de passe|mdp|password|passwd|pwd|passphrase|pass phrase|secret|client[_ ]?secret|api[_ -]?key|apikey|cl[ée] (?:d['’])?api|access[_ ]?token|refresh[_ ]?token|auth[_ ]?token|bearer[_ ]?token|token)["']?\s*[:=]\s*["']?([^\s"',;)}\]]{6,})/gi,
    groupe: 1,
  },
  {
    type: 'code de vérification',
    re: /(?:code (?:de )?(?:v[ée]rification|validation|activation|confirmation|s[ée]curit[ée])|code OTP|\bOTP\b|\b2FA\b|one[- ]time (?:password|code)|verification code)\D{0,25}?\b(\d{4,8})\b/gi,
    groupe: 1,
  },
]

// Jamais masqué : identifiants juridiques et d'entreprise, empreintes.
const LISTE_BLANCHE: readonly RegExp[] = [
  /^[a-f0-9]{64}$/i, // SHA-256
  /^\d{2}-\d{2}\.\d{3}$/, // n° de pourvoi
  /^\d{2}\/\d{5}$/, // RG
  /^\d{9}$|^\d{14}$/, // SIREN, SIRET
]

// Valeurs qui sont du code, un type ou un emplacement à remplir, pas un secret.
const PAS_UN_SECRET =
  /^(?:process\.env|os\.environ|os\.getenv|env\.|import\.meta|\$\{|\$[A-Z_]|<|\{\{|%\(|getenv|config\.|settings\.|self\.|this\.|req\.|request\.|args\.|options\.|params\.)/
const MOTS_DE_CODE = new Set([
  'string', 'number', 'boolean', 'null', 'undefined', 'true', 'false', 'none', 'str', 'int', 'bool',
  'optional', 'required', 'redacted', 'masked', 'hidden', 'changeme', 'example', 'placeholder',
])

function estSecretPlausible(valeur: string, generique: boolean): boolean {
  if (LISTE_BLANCHE.some(re => re.test(valeur))) return false
  if (!generique) return true
  const v = valeur.replace(/[.;:,]+$/, '')
  if (v.length < 6) return false
  if (PAS_UN_SECRET.test(v)) return false
  if (MOTS_DE_CODE.has(v.toLowerCase())) return false
  // Emplacements à remplir, structures, et texte déjà masqué (le masquage ne doit jamais se re-masquer).
  if (/^[x*•.\-_]+$/i.test(v) || /^[[<{(]/.test(v) || /masqu[ée]/i.test(v)) return false
  if (/^(?:your|my|votre|mon)[_-]/i.test(v)) return false
  // Un appel ou une expression de code (« getToken() », « a.b.c »).
  if (/\(|\)/.test(v) || /^[a-z_][\w]*(?:\.[a-z_][\w]*)+$/i.test(v)) return false
  // Exiger un peu de variété : un chiffre, ou un mélange majuscules/minuscules,
  // ou un caractère spécial. « motdepasse » seul ne suffit pas.
  return /\d/.test(v) || (/[a-z]/.test(v) && /[A-Z]/.test(v)) || /[^A-Za-z0-9]/.test(v)
}

// Entropie de Shannon, en bits par caractère.
export function entropie(s: string): number {
  const n = new Map<string, number>()
  for (const c of s) n.set(c, (n.get(c) ?? 0) + 1)
  let h = 0
  for (const k of n.values()) {
    const p = k / s.length
    h -= p * Math.log2(p)
  }
  return h
}

// Indice : une chaîne longue et aléatoire sans libellé ni format connu.
// Prudent exprès : ni hexadécimal pur (empreintes, commits, identifiants de
// session), ni mots collés, ni chemins ; seulement noté, jamais masqué.
// Nom de page ou de fichier (« Piece_14_Contrat_… ») : au moins deux segments en
// forme de mot, de sigle ou de nombre entre séparateurs. Mesuré sur un corpus
// d'environ 3 000 notes Markdown : 240 indices sans cette règle, 53 avec ;
// 96 % des vraies chaînes aléatoires de 40 caractères restent repérées.
function estUnNom(s: string): boolean {
  const segments = s.split(/[_-]+/).filter(Boolean)
  const mots = segments.filter(x => /^(?:[A-Z]?[a-z]{2,}|[A-Z]{2,}|\d+|[A-Z]\d+)$/.test(x)).length
  return segments.length >= 3 && mots >= 2
}

export function estIndiceAleatoire(s: string): boolean {
  if (s.length < 32) return false
  if (/^[a-f0-9-]+$/i.test(s)) return false
  if (!(/[a-z]/.test(s) && /[A-Z]/.test(s) && /\d/.test(s))) return false
  if (/[a-z]{8,}|[A-Z]{8,}/.test(s)) return false
  if (estUnNom(s)) return false
  return entropie(s) >= 4.2
}

const MAX_INDICES = 5

export function trouver(texte: string, connues: readonly Connue[] = []): Trouvaille[] {
  const brutes: Trouvaille[] = []
  // Valeurs exactes connues d'abord : certitude totale, quel que soit le format.
  for (const c of connues) {
    if (c.valeur.length < LONGUEUR_MIN_CONNUE) continue
    for (let i = texte.indexOf(c.valeur); i !== -1; i = texte.indexOf(c.valeur, i + c.valeur.length)) {
      brutes.push({ type: `valeur de ${c.nom}`, debut: i, fin: i + c.valeur.length, masquable: true, forme: forme(c.valeur), libelle: null })
    }
  }
  for (const m of MOTIFS) {
    m.re.lastIndex = 0
    for (const r of texte.matchAll(m.re)) {
      const valeur = m.groupe ? r[m.groupe] : r[0]
      if (valeur === undefined || r.index === undefined) continue
      const debut = m.groupe ? r.index + r[0].lastIndexOf(valeur) : r.index
      if (!estSecretPlausible(valeur, m.groupe !== undefined)) continue
      // Le libellé est le texte qui précède la valeur (« mot de passe », « token ») : jamais la valeur.
      const libelle = m.groupe
        ? r[0].slice(0, r[0].lastIndexOf(valeur)).replace(/["'\s:=]+$/, '').trim().slice(-30).toLowerCase() || null
        : null
      brutes.push({ type: m.type, debut, fin: debut + valeur.length, masquable: true, forme: forme(valeur), libelle })
    }
  }
  // Fusion des chevauchements : la première trouvée (motif le plus spécifique) l'emporte.
  brutes.sort((a, b) => a.debut - b.debut || b.fin - a.fin)
  const out: Trouvaille[] = []
  for (const t of brutes) {
    const der = out[out.length - 1]
    if (der && t.debut < der.fin) {
      der.fin = Math.max(der.fin, t.fin)
      continue
    }
    out.push({ ...t })
  }
  // Indices, hors des zones déjà repérées.
  let indices = 0
  for (const r of texte.matchAll(/[A-Za-z0-9+_=-]{32,}/g)) {
    if (indices >= MAX_INDICES || r.index === undefined) break
    const debut = r.index
    const fin = debut + r[0].length
    if (out.some(t => debut < t.fin && t.debut < fin)) continue
    if (!estIndiceAleatoire(r[0])) continue
    out.push({ type: TYPE_INDICE, debut, fin, masquable: false, forme: forme(r[0]), libelle: null })
    indices += 1
  }
  return out.sort((a, b) => a.debut - b.debut)
}

export function masquer(texte: string, trouvailles: readonly Trouvaille[]): string {
  let out = ''
  let i = 0
  for (const t of trouvailles) {
    if (!t.masquable) continue
    out += `${texte.slice(i, t.debut)}[secret masqué : ${t.type}]`
    i = t.fin
  }
  return out + texte.slice(i)
}

type Bloc = { type: string; [champ: string]: unknown }

export type Reperage = { type: string; forme: string; libelle: string | null; masquable: boolean }
export type Analyse = { contenu: Bloc[]; types: string[]; reperages: Reperage[] }

function traiterTexte(texte: string, reperages: Reperage[], masque: boolean, connues: readonly Connue[]): string {
  const t = trouver(texte, connues)
  for (const x of t) reperages.push({ type: x.type, forme: x.forme, libelle: x.libelle, masquable: x.masquable })
  return masque && t.some(x => x.masquable) ? masquer(texte, t) : texte
}

// Parcourt les blocs d'une ligne : blocs texte et contenu des tool_result.
// Les autres blocs (images, tool_use, thinking) ne sont pas touchés.
export function analyser(contenu: readonly Bloc[], masque: boolean, connues: readonly Connue[] = []): Analyse {
  const reperages: Reperage[] = []
  const sortie = contenu.map(b => {
    if (b.type === 'text' && typeof b.text === 'string') {
      const text = traiterTexte(b.text, reperages, masque, connues)
      return text === b.text ? b : { ...b, text }
    }
    if (b.type === 'tool_result') {
      const c = b.content
      if (typeof c === 'string') {
        const content = traiterTexte(c, reperages, masque, connues)
        return content === c ? b : { ...b, content }
      }
      if (Array.isArray(c)) {
        let change = false
        const content = c.map((x: unknown) => {
          const bloc = x as Bloc
          if (bloc && bloc.type === 'text' && typeof bloc.text === 'string') {
            const text = traiterTexte(bloc.text, reperages, masque, connues)
            if (text !== bloc.text) change = true
            return text === bloc.text ? bloc : { ...bloc, text }
          }
          return bloc
        })
        return change ? { ...b, content } : b
      }
    }
    return b
  })
  return { contenu: sortie, types: reperages.map(r => r.type), reperages }
}

// ---------------------------------------------------------------- Journal
// Ce qui est noté : jamais la valeur, seulement le type, l'outil, la porte et l'heure.

export type Evenement = { quand: number; type: string; source: string; mode: Mode; forme?: string; libelle?: string | null; masque?: boolean }
export type Mode = 'observation' | 'masquage'

export type Journal = { depuis: number; evenements: Evenement[] }

export const MAX_EVENEMENTS = 500

export function ajouter(journal: Journal | null, evts: readonly Evenement[]): Journal {
  const base = journal ?? { depuis: evts[0]?.quand ?? 0, evenements: [] }
  return { depuis: base.depuis, evenements: [...base.evenements, ...evts].slice(-MAX_EVENEMENTS) }
}

const compte = (xs: readonly string[]) => {
  const m = new Map<string, number>()
  for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1)
  return [...m.entries()].sort((a, b) => b[1] - a[1])
}

function dateCourte(ms: number): string {
  const d = new Date(ms)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getUTCDate())}/${p(d.getUTCMonth() + 1)} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`
}

export function bilan(journal: Journal | null, mode: Mode): string {
  const tete = `masque-secrets · mode ${mode}${mode === 'observation' ? ' (rien n’est masqué)' : ' (les valeurs sont masquées avant lecture)'}`
  if (journal === null || journal.evenements.length === 0) return `${tete}\nAucun secret repéré pour l’instant.`
  const e = journal.evenements
  const parType = compte(e.map(x => x.type)).map(([t, n]) => `- ${t} : ${n}`)
  const parSource = compte(e.map(x => x.source)).map(([t, n]) => `- ${t} : ${n}`)
  const derniers = e.slice(-10).reverse().map(x => {
    const details = [x.forme, x.libelle ? `libellé « ${x.libelle} »` : null, x.masque === true ? 'masqué' : x.masque === false ? 'non masqué' : null]
      .filter(Boolean)
      .join(' · ')
    return `- ${dateCourte(x.quand)} · ${x.type} · ${x.source} · ${x.mode}${details ? ` · ${details}` : ''}`
  })
  const indices = e.filter(x => x.type === TYPE_INDICE).length
  return [
    tete,
    `${e.length} repérage(s) depuis le ${dateCourte(journal.depuis)} (la valeur n’est jamais notée), dont ${indices} indice(s) de chaîne aléatoire, jamais masqués.`,
    '',
    'Par type :',
    ...parType,
    '',
    'Par source :',
    ...parSource,
    '',
    'Les 10 derniers :',
    ...derniers,
  ].join('\n')
}
