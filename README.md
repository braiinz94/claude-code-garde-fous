# Garde-fous pour Claude Code

[![CI](https://github.com/braiinz94/claude-code-garde-fous/actions/workflows/ci.yml/badge.svg)](https://github.com/braiinz94/claude-code-garde-fous/actions/workflows/ci.yml)
![Licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)

Quatre mods de sécurité pour [Claude Code](https://claude.com/claude-code), écrits pour un usage professionnel réel : un agent prépare, une personne décide.

| Mod | Ce qu'il fait | Bloque ? |
|---|---|---|
| **masque-secrets** | Repère clés d'API, jetons, mots de passe, cookies et codes dans la conversation avant que le modèle les lise. Mode observation par défaut, mode masquage sur réglage. | Non (masque en mode masquage) |
| **garde-envoi** | Pose la question « Autoriser cet envoi ? » avant tout e-mail, message, invitation, signature, déploiement, `git push`, `gh pr`, `npm publish`, ou envoi réseau du terminal (`curl -d`, `gh api` en écriture, `scp`, `rsync`, `ssh`, `nc`). Partages et changements de visibilité refusés d'office. | Oui, fermé par défaut |
| **journal-audit** | Écrit une ligne par appel d'outil : heure, modèle réel, skill, sous-agent, outil, cible, SHA-256 de l'entrée et de la sortie. Chaque ligne porte l'empreinte de la précédente : une ligne modifiée ou retirée se voit. Aucun contenu en clair. | Jamais |
| **veille-injection** | Lit la sortie des outils qui ramènent du contenu extérieur (web, MCP, fichiers) et repère les motifs d'injection de prompt : consignes à ignorer, faux messages système, demandes d'exfiltration, texte Unicode invisible. Ajoute un avertissement pour le modèle. | Jamais |

## Principes

- **Fermé par défaut là où ça compte** : si garde-envoi ne peut pas poser la question (session sans personne, erreur du mod), l'envoi est refusé.
- **Jamais bloquant ailleurs** : une panne de masque-secrets, journal-audit ou veille-injection laisse passer l'outil tel quel.
- **Rien en clair** : aucun secret, argument ni résultat n'est écrit sur disque. Seuls le type, la forme (longueur, familles de caractères) et des empreintes SHA-256 sont notés.
- **Aucun réseau** : les mods n'appellent aucun service extérieur.

## Installation

```bash
claude plugin marketplace add braiinz94/claude-code-garde-fous
claude plugin install garde-envoi@garde-fous --scope user
```

Même chose pour `masque-secrets`, `journal-audit` et `veille-injection`. Chaque mod s'installe seul.

## Commandes

| Commande | Mod | Affiche |
|---|---|---|
| `/secrets` | masque-secrets | secrets repérés, par type et par source |
| `/garde` | garde-envoi | familles surveillées et dernières décisions |
| `/audit` | journal-audit | lignes du jour et vérification de la chaîne de la session |
| `/injection` | veille-injection | alertes du jour |

## Réglages

- **masque-secrets** · `mode` : `observation` (par défaut, rien n'est modifié) ou `masquage` (la valeur est remplacée par `[secret masqué : <type>]`).
- **garde-envoi** · `hotes` : hôtes que vous considérez comme attendus, séparés par des virgules (`.exemple.fr` couvre ses sous-domaines). La confirmation reste demandée ; la question indique si l'hôte est dans la liste.

## Fichiers écrits

- `~/.claude/logs/audit-ia/AAAA-MM-JJ/<session>-<nnn>.jsonl` (journal-audit, 200 lignes par segment)
- `~/.claude/logs/injection/AAAA-MM-JJ.jsonl` (veille-injection)

Les jours sont comptés sur le fuseau Europe/Paris.

## Limites connues

- Les règles de garde-envoi portent sur le nom des outils MCP (`send_message`, `create_event`, `share_file`…). Un connecteur qui envoie sous un autre nom n'est pas reconnu ; un nom ambigu déclenche une question de trop, jamais un envoi muet.
- veille-injection est une heuristique : elle signale, elle ne prouve pas. Elle peut signaler les rappels internes que l'application ajoute aux résultats d'outils (balises `system-reminder`).
- masque-secrets ne voit que la conversation : il ne protège pas un secret déjà écrit dans un fichier ou un commit.

## Tests

```bash
for m in masque-secrets garde-envoi journal-audit veille-injection; do claude plugin test ./$m; done
```

## English summary

Four security mods for Claude Code: **masque-secrets** (detects and optionally redacts secrets before the model reads them), **garde-envoi** (human confirmation before any send, publish, deploy or outbound network write; fail-closed), **journal-audit** (hash-chained, content-free audit log of every tool call), **veille-injection** (prompt-injection heuristics on web, MCP and file outputs). French UI, no network calls, Apache-2.0.

## Licence

Apache-2.0 — © 2026 Mourad Barkaoui · [braiinz.fr](https://braiinz.fr)
