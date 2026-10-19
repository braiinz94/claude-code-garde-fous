import { expect, mock, test } from 'claude-code/testing'

import { ajouter, analyser, bilan, estIndiceAleatoire, masquer, TYPE_INDICE, trouver } from '../hooks/secrets'

// Faux secrets assemblés à l'exécution : aucun motif reconnaissable n'est écrit
// tel quel dans ce fichier (l'audit hebdomadaire des secrets ne doit pas le signaler).
const j = (...p: string[]) => p.join('')
const FAUX = {
  anthropic: j('sk-', 'ant-', 'api03-', 'Zq'.repeat(48)),
  github: j('gh', 'p_', 'a1B2'.repeat(10)),
  google: j('AI', 'za', 'Sy', 'x'.repeat(33)),
  aws: j('AK', 'IA', 'ABCDEFGH12345678'),
  jwt: j('ey', 'JhbGciOiJIUzI1NiJ9', '.', 'ey', 'JzdWIiOiIxMjM0NTYifQ', '.', 'c2lnbmF0dXJlLXRlc3Q'),
}

const types = (texte: string) => trouver(texte).map(t => t.type)

test('les formats d’éditeurs sont repérés', async () => {
  expect(types(`clé : ${FAUX.anthropic}`)).toEqual(['clé Anthropic'])
  expect(types(`export TOKEN=${FAUX.github}`).includes('jeton GitHub')).toBe(true)
  expect(types(`url?key=${FAUX.google}`)).toEqual(['clé Google'])
  expect(types(`id ${FAUX.aws} ok`)).toEqual(['clé AWS'])
  expect(types(`jeton ${FAUX.jwt}`)).toEqual(['JWT'])
  expect(types(j('-----BEGIN OPENSSH ', 'PRIVATE KEY-----\nabc\n-----END OPENSSH ', 'PRIVATE KEY-----'))).toEqual(['clé privée'])
})

test('les secrets reconnus par leur libellé sont repérés', async () => {
  expect(types('mot de passe : Soleil2024!')).toEqual(['mot de passe ou secret'])
  expect(types('password=Xk9#mP2qL')).toEqual(['mot de passe ou secret'])
  expect(types(j('Authorization: Bearer ', 'abcDEF123456ghiJKL'))).toEqual(['en-tête Authorization'])
  expect(types(j('https://alice:', 'S3cret!x', '@imap.exemple.fr'))).toEqual(['identifiants dans une URL'])
  expect(types(j('Cookie: SAPI', 'SID=', 'a1B2'.repeat(6)))).toEqual(['cookie de session'])
  expect(types('Votre code de vérification : 482913')).toEqual(['code de vérification'])
})

test('les identifiants juridiques, les empreintes et le code ne sont pas pris pour des secrets', async () => {
  const sains = [
    'sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    'Appel RG 98/76543, pourvoi n° 98-76.543, SIREN 123456789, SIRET 12345678900012',
    'password: string;',
    'const apiKey = process.env.API_KEY',
    'token = getToken()',
    'Le mot de passe a été changé hier.',
    'token: xxxxxxxx',
    'mdp : [secret masqué : mot de passe ou secret]',
    'secret: config.secret_value',
    'password = "changeme"',
  ]
  for (const s of sains) expect(types(s)).toEqual([])
})

test('le masquage retire la valeur et garde le texte autour', async () => {
  const texte = `avant ${FAUX.anthropic} après`
  const sortie = masquer(texte, trouver(texte))
  expect(sortie).toBe('avant [secret masqué : clé Anthropic] après')
  expect(sortie.includes(FAUX.anthropic)).toBe(false)
  const libelle = 'mdp : Soleil2024! (à changer)'
  expect(masquer(libelle, trouver(libelle))).toBe('mdp : [secret masqué : mot de passe ou secret] (à changer)')
  // Un texte déjà masqué, relu, ne se re-masque pas.
  for (const x of [texte, libelle]) {
    const une = masquer(x, trouver(x))
    expect(trouver(une)).toEqual([])
  }
})

test('analyser parcourt texte et tool_result, sans toucher aux autres blocs', async () => {
  const image = { type: 'image', source: { type: 'base64', data: 'AAAA' } }
  const contenu = [
    { type: 'text', text: 'rien ici' },
    { type: 'tool_result', tool_use_id: 't1', content: `sortie ${FAUX.github}` },
    { type: 'tool_result', tool_use_id: 't2', content: [{ type: 'text', text: `mot de passe : Soleil2024!` }, image] },
  ]
  const obs = analyser(contenu, false)
  expect(obs.types).toEqual(['jeton GitHub', 'mot de passe ou secret'])
  expect(obs.contenu).toEqual(contenu)
  const masq = analyser(contenu, true)
  expect(JSON.stringify(masq.contenu).includes(FAUX.github)).toBe(false)
  expect(JSON.stringify(masq.contenu).includes('Soleil2024!')).toBe(false)
  expect(masq.contenu[0]).toBe(contenu[0])
  expect((masq.contenu[2]?.content as unknown[])[1]).toBe(image)
})

test('le bilan ne contient jamais de valeur', async () => {
  const journal = ajouter(null, [
    { quand: Date.UTC(2026, 9, 14, 8), type: 'clé Anthropic', source: 'Bash', mode: 'observation' },
    { quand: Date.UTC(2026, 9, 14, 9), type: 'clé Anthropic', source: 'Read', mode: 'observation' },
  ])
  const b = bilan(journal, 'observation')
  expect(b.includes('2 repérage(s)')).toBe(true)
  expect(b.includes('- clé Anthropic : 2')).toBe(true)
  expect(b.includes('sk-')).toBe(false)
  expect(bilan(null, 'observation').includes('Aucun secret')).toBe(true)
})

const ligne = (texte: string) => ({
  message: {
    type: 'user' as const,
    role: 'user' as const,
    content: [{ type: 'tool_result', tool_use_id: 'toolu_1', content: texte }],
  },
  door: 'tool-result' as const,
  origin: { kind: 'tool' as const, tool: 'Bash' },
  uuid: 'ligne-1',
})

test('en observation, la ligne est stockée telle quelle et le repérage est noté', async ($, on) => {
  const store = new Map<string, unknown>()
  on('store.get', async (_$, e) => ({ value: store.get(e.key) }))
  on('store.set', async (_$, e) => {
    store.set(e.key, e.value)
    return { value: undefined }
  })
  mock.clock(on, { now: Date.UTC(2026, 9, 14, 8) })
  const toasts: string[] = []
  on('ui.toast', async (_$, e) => {
    toasts.push(e.text)
    return { value: undefined }
  })
  const stockee = await $.session.append(ligne(`export K=${FAUX.anthropic}`))
  expect(JSON.stringify(stockee.message?.content).includes(FAUX.anthropic)).toBe(true)
  expect(toasts.length).toBe(1)
  expect(toasts[0]?.startsWith('Secret repéré (clé Anthropic) · Bash')).toBe(true)
  expect(toasts[0]?.includes(FAUX.anthropic)).toBe(false)
  const journal = store.get('journal') as { evenements: { type: string }[] }
  expect(journal.evenements.map(x => x.type)).toEqual(['clé Anthropic'])
  expect(JSON.stringify(journal).includes(FAUX.anthropic)).toBe(false)
})

test('en masquage, le modèle ne reçoit plus la valeur', { options: { mode: 'masquage' } }, async ($, on) => {
  mock.store(on)
  mock.clock(on, { now: Date.UTC(2026, 9, 14, 8) })
  on('ui.toast', async () => ({ value: undefined }))
  const stockee = await $.session.append(ligne(`export K=${FAUX.anthropic}`))
  const texte = JSON.stringify(stockee.message?.content)
  expect(texte.includes(FAUX.anthropic)).toBe(false)
  expect(texte.includes('[secret masqué : clé Anthropic]')).toBe(true)
})

test('une ligne sans secret passe sans bruit', async ($, on) => {
  mock.store(on)
  mock.clock(on, { now: 0 })
  let toasts = 0
  on('ui.toast', async () => {
    toasts += 1
    return { value: undefined }
  })
  const stockee = await $.session.append(ligne('Appel RG 98/76543 · audience le 15/10'))
  expect(JSON.stringify(stockee.message?.content).includes("98/76543")).toBe(true)
  expect(toasts).toBe(0)
})

// ---------------------------------------------------------------- v0.2

// Chaîne aléatoire fixe (base62, 40 caractères) assemblée à l'exécution.
const ALEA = j('Qm7xR2', 'pK9vT4', 'wZ1nB8', 'cY5hL3', 'dF6jS0', 'gU2eA7', 'Mt9q')

test('v0.2 · la valeur exacte d’une variable connue est repérée, puis masquée', async () => {
  const connue = { nom: 'GITHUB_TOKEN', valeur: j('mon', 'jeton', 'Maison', '2026xy') }
  const texte = `sortie : ${connue.valeur} fin`
  const t = trouver(texte, [connue])
  expect(t.map(x => x.type)).toEqual(['valeur de GITHUB_TOKEN'])
  expect(masquer(texte, t)).toBe('sortie : [secret masqué : valeur de GITHUB_TOKEN] fin')
  // Trop courte : ignorée (une variable de 3 caractères masquerait n'importe quoi).
  expect(trouver('abc abc', [{ nom: 'X', valeur: 'abc' }])).toEqual([])
})

test('v0.2 · forme et libellé décrivent le repérage sans la valeur', async () => {
  const [t] = trouver('mot de passe : Soleil2024!')
  expect([t?.forme, t?.libelle]).toEqual(['11 car. (minuscules, majuscules, chiffres, symboles)', 'mot de passe'])
  expect(JSON.stringify(t).includes('Soleil2024!')).toBe(false)
})

test('v0.2 · une chaîne aléatoire est un indice : notée, jamais masquée', async () => {
  const texte = `jeton inconnu ${ALEA} fin`
  const t = trouver(texte)
  expect(t.map(x => [x.type, x.masquable])).toEqual([[TYPE_INDICE, false]])
  expect(masquer(texte, t)).toBe(texte)
  const a = analyser([{ type: 'text', text: texte }], true)
  expect(JSON.stringify(a.contenu).includes(ALEA)).toBe(true)
  expect(a.types).toEqual([TYPE_INDICE])
})

test('v0.2 · empreintes, identifiants, chemins et noms ne sont pas des indices', async () => {
  const sains = [
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', // SHA-256
    '12345678-90ab-4cde-8f01-23456789abcd', // identifiant de session
    '0123456789abcdef0123456789abcdef01234567', // commit
    'compte_rendu_reunion_equipe_produit_avant_lancement', // nom de fichier
    'RapportMensuelObservationRevueDu21Octobre2026', // mots collés
    'notes_projet_emplacement-2026-10-15-version-finale-relue', // nom long
    'Piece_14_Contrat_DUPONT_BQXY_note-mai-2023', // nom de pièce
    '9-99-2026-1_Bordereau_RG_tribunal_Lyon_TJL-A-mai', // nom de bordereau
  ]
  for (const s of sains) expect([s, trouver(s).length]).toEqual([s, 0])
  expect(estIndiceAleatoire(ALEA)).toBe(true)
})

test('v0.2 · en masquage, la variable connue lue au démarrage est masquée ; un indice seul ne déclenche aucune alerte', { options: { mode: 'masquage' } }, async ($, on) => {
  const valeur = j('ghs', '_', 'ZZtestValeurConnue', '42')
  mock.env(on, { GH_TOKEN: valeur })
  mock.store(on)
  mock.clock(on, { now: Date.UTC(2026, 9, 15, 8) })
  const toasts: string[] = []
  on('ui.toast', async (_$, e) => {
    toasts.push(e.text)
    return { value: undefined }
  })
  on('command.register', async () => ({ value: undefined }) as never)
  on('session.start', async (_$, e) => ({ cwd: e.cwd }) as never)
  await $.session.start({ cwd: '/tmp', surface: null, interactive: false } as never)
  const stockee = await $.session.append(ligne(`token affiché sans libellé : ${valeur}`))
  const texte = JSON.stringify(stockee.message?.content)
  expect(texte.includes(valeur)).toBe(false)
  expect(texte.includes('[secret masqué : valeur de GH_TOKEN]')).toBe(true)
  expect(toasts.length).toBe(1)
  const seul = await $.session.append(ligne(`indice ${ALEA}`))
  expect(JSON.stringify(seul.message?.content).includes(ALEA)).toBe(true)
  expect(toasts.length).toBe(1)
})
