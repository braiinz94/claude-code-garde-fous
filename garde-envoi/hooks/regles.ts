// Règles de la garde « envoi et publication ». Logique pure.
// Tout envoi, publication ou déploiement attend un « oui » explicite ;
// modifier un partage ou des droits d'accès est refusé d'office.

import { analyserBash, dansListe, hoteUrl } from './reseau'

export type Action = 'question' | 'refus'
export type Classement = { famille: string; quoi: string; action: Action; raison?: string }

// Règles sur le nom de l'outil MCP, quel que soit l'identifiant du serveur : les
// connecteurs claude.ai portent un identifiant propre à chaque installation.
// Un nom ambigu (« send_message ») déclenche une question de trop, jamais un envoi muet.
type RegleMcp = { noms: string[]; famille: string; quoi: string; action: Action; raison?: string }

const REFUS_ACCES = 'modifier un partage, la visibilité ou des droits d’accès est refusé d’office ; à faire soi-même'

const REGLES_MCP: RegleMcp[] = [
  { noms: ['send_message', 'send_email', 'reply', 'forward'], famille: 'Message', quoi: 'envoi d’un e-mail ou d’un message', action: 'question' },
  { noms: ['send_imessage', 'send_sms', 'post_message', 'chat_postMessage'], famille: 'Message', quoi: 'envoi d’un message', action: 'question' },
  { noms: ['create_event', 'update_event', 'delete_event', 'respond_to_event'], famille: 'Agenda', quoi: 'invitation ou réponse envoyée aux participants', action: 'question' },
  {
    noms: ['createEnvelope', 'createEnvelopeWithDocuments', 'updateEnvelope', 'updateEnvelopeRecipients', 'sendReminder', 'triggerWorkflow', 'startClmWorkflow', 'resumeWorkflow'],
    famille: 'Signature',
    quoi: 'envoi ou relance d’une demande de signature',
    action: 'question',
  },
  {
    noms: ['netlify-deploy-services-updater', 'netlify-project-services-updater', 'netlify-extension-services-updater', 'deploy_project', 'deploy_edge_function'],
    famille: 'Déploiement',
    quoi: 'déploiement ou modification d’un site en ligne',
    action: 'question',
  },
  { noms: ['comment-on-design', 'reply-to-comment', 'publish-brand-template'], famille: 'Publication', quoi: 'commentaire ou publication visible des collaborateurs', action: 'question' },
  { noms: ['share_file', 'set_project_visibility', 'set_folder_visibility'], famille: 'Accès', quoi: 'partage ou changement de visibilité', action: 'refus', raison: REFUS_ACCES },
]

// Commandes shell qui publient ou déploient.
const BASH_PUBLIE = /\b(git\s+push|gh\s+pr\s+(create|merge)|gh\s+release\s+create|npm\s+publish|netlify\s+deploy|vercel(\s+deploy|\s+--prod|\s*$|\s*[;&|])|firebase\s+deploy)/

function nomMcp(outil: string): string | null {
  if (!outil.startsWith('mcp__')) return null
  const parts = outil.split('__')
  return parts.length < 3 ? null : parts.slice(2).join('__')
}

export function classer(outil: string, entree: Record<string, unknown>, liste: readonly string[] = []): Classement | null {
  if (outil === 'Bash') {
    const cmd = typeof entree.command === 'string' ? entree.command : ''
    if (BASH_PUBLIE.test(cmd)) return { famille: 'Terminal', quoi: 'publication ou déploiement', action: 'question' }
    const { envois } = analyserBash(cmd)
    if (envois.length === 0) return null
    const hotes = [...new Set(envois.flatMap(e => e.hotes))]
    const hors = hotes.filter(h => !dansListe(h, liste))
    const vers = hotes.length > 0 ? ` vers ${hotes.join(', ')}` : ' (hôte non reconnu)'
    const marque = hotes.length === 0 || hors.length > 0 ? ' [hors liste]' : ' [dans la liste]'
    return { famille: 'Réseau', quoi: `${[...new Set(envois.map(e => e.quoi))].join(' + ')}${vers}${marque}`, action: 'question' }
  }
  const nom = nomMcp(outil)
  if (nom === null) return null
  const r = REGLES_MCP.find(x => x.noms.includes(nom))
  return r ? { famille: r.famille, quoi: r.quoi, action: r.action, raison: r.raison } : null
}

// Lectures réseau vers un hôte hors liste : notées, jamais bloquées
// (WebFetch, curl ou wget sans données). Seul l'hôte est noté, jamais le chemin.
export function lecturesHorsListe(outil: string, entree: Record<string, unknown>, liste: readonly string[] = []): string[] {
  let hotes: string[] = []
  if (outil === 'WebFetch' && typeof entree.url === 'string') {
    const h = hoteUrl(entree.url)
    hotes = h ? [h] : []
  } else if (outil === 'Bash' && typeof entree.command === 'string') {
    hotes = analyserBash(entree.command).lectures
  }
  return [...new Set(hotes)].filter(h => !dansListe(h, liste))
}

export type Lectures = Record<string, { n: number; dernier: number }>
export const MAX_HOTES = 300

export function noterLectures(avant: Lectures | null, hotes: readonly string[], quand: number): Lectures {
  const l: Lectures = { ...(avant ?? {}) }
  for (const h of hotes) l[h] = { n: (l[h]?.n ?? 0) + 1, dernier: quand }
  const tries = Object.entries(l).sort((a, b) => b[1].dernier - a[1].dernier).slice(0, MAX_HOTES)
  return Object.fromEntries(tries)
}

const DEST = ['to', 'cc', 'bcc', 'recipient', 'recipients', 'recipient_email', 'email', 'emails', 'attendees', 'phone', 'phoneNumber', 'handle', 'contact', 'signers', 'session_id']
const OBJET = ['subject', 'title', 'summary', 'name', 'project_id', 'projectId', 'site_id', 'siteId', 'envelopeId', 'fileId', 'file_id', 'designId', 'design_id']
const TEXTE = ['body', 'text', 'message', 'content', 'description', 'prompt', 'initial_message', 'command']

function enTexte(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'string') return v
  if (Array.isArray(v)) return v.map(enTexte).filter(Boolean).join(', ')
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    return enTexte(o.email ?? o.address ?? o.name ?? JSON.stringify(o))
  }
  return String(v)
}

const couper = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)

// Résumé montré à l'utilisateur dans la question (jamais journalisé).
export function resume(entree: Record<string, unknown>): string[] {
  const out: string[] = []
  const prend = (cles: string[], libelle: string, n: number) => {
    for (const k of cles) {
      const t = enTexte(entree[k]).replace(/\s+/g, ' ').trim()
      if (t) {
        out.push(`${libelle} : ${couper(t, n)}`)
        return
      }
    }
  }
  prend(DEST, 'à', 160)
  prend(OBJET, 'objet', 120)
  prend(TEXTE, 'contenu', 220)
  return out
}

export function question(c: Classement, entree: Record<string, unknown>, sousAgent: boolean): string {
  const details = resume(entree)
  const tete = `${sousAgent ? '[sous-agent] ' : ''}${c.famille} · ${c.quoi}`
  return `${[tete, ...details].join(' — ')} — Autoriser cet envoi ?`
}

export type Decision = { quand: number; famille: string; outil: string; decision: 'autorisé' | 'refusé' | 'refusé d’office' | 'sans réponse' }

export function bilan(decisions: readonly Decision[], lectures: Lectures | null = null): string {
  const familles = [
    ...new Set(REGLES_MCP.map(r => `${r.famille}${r.action === 'refus' ? ' (refus d’office)' : ''}`)),
    'Terminal (git push, gh pr, npm publish, déploiements)',
    'Réseau (curl et wget avec données, gh api en écriture, scp, rsync, ssh, nc ; hôte comparé à la liste autorisée)',
  ]
  const tete = `garde-envoi · ${familles.length} familles surveillées : ${familles.join(', ')}.`
  const p = (n: number) => String(n).padStart(2, '0')
  const hotes = Object.entries(lectures ?? {}).sort((a, b) => b[1].n - a[1].n)
  const blocLectures =
    hotes.length === 0
      ? []
      : ['', `Lectures hors liste (notées, non bloquées) : ${hotes.length} hôte(s)`, ...hotes.slice(0, 10).map(([h, x]) => `- ${h} : ${x.n}`)]
  if (decisions.length === 0) return [`${tete}`, 'Aucune décision enregistrée pour l’instant.', ...blocLectures].join('\n')
  const lignes = decisions
    .slice(-15)
    .reverse()
    .map(d => {
      const x = new Date(d.quand)
      return `- ${p(x.getUTCDate())}/${p(x.getUTCMonth() + 1)} ${p(x.getUTCHours())}:${p(x.getUTCMinutes())} UTC · ${d.famille} · ${d.decision} · ${d.outil}`
    })
  return [tete, '', 'Dernières décisions :', ...lignes, ...blocLectures].join('\n')
}
