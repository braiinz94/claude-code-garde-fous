# Correspondance avec les référentiels

Ce tableau dit à quels risques et à quelles recommandations publiques chaque mod **contribue**. Il ne revendique aucune conformité : un mod de Claude Code ne rend conforme ni une organisation ni un système d'IA. La colonne « Ne couvre pas » compte autant que les autres.

Chaque référence a été lue dans le texte officiel le 19/10/2026 (voir [Sources](#sources)).

## Vue d'ensemble

| Mod | OWASP LLM Top 10 (2025) | NIST AI RMF 1.0 | ANSSI-PA-102 | AI Act (UE) 2024/1689, par analogie |
|---|---|---|---|---|
| **masque-secrets** | LLM02 Sensitive Information Disclosure | MEASURE 2.7 | R7, R25 | art. 15 |
| **garde-envoi** | LLM06 Excessive Agency · LLM01 Prompt Injection (conséquences) | MAP 3.5 · MANAGE 2.4 | R9, R26, R27 | art. 14 |
| **journal-audit** | LLM06 (traçabilité des actions) | MEASURE 2.8 · MANAGE 4.1 · MANAGE 4.3 | R29 (partiel) | art. 12 |
| **veille-injection** | LLM01 Prompt Injection | MEASURE 2.7 · MANAGE 4.1 | R25, R27 | art. 15 |

**À propos de l'AI Act.** Les articles 12, 14 et 15 se trouvent au chapitre III, section 2, « Exigences applicables aux systèmes d'IA à haut risque ». Ils ne s'appliquent pas à l'usage ordinaire d'un assistant de code. Ils sont cités ici **par analogie**, comme repères de bonne pratique, et non comme une obligation que ces mods rempliraient.

## Détail par mod

### masque-secrets

| Référentiel | Référence | Ce que le mod apporte | Ne couvre pas |
|---|---|---|---|
| OWASP | LLM02:2025 Sensitive Information Disclosure | Repère clés, jetons, mots de passe, cookies et codes avant lecture par le modèle ; en mode masquage, remplace la valeur. | Un secret déjà écrit dans un fichier, un commit ou un journal tiers ; un secret au format inconnu. |
| NIST | MEASURE 2.7 (sécurité et résilience évaluées et documentées) | Fournit un relevé (`/secrets`) des expositions, par type et par source. | L'évaluation elle-même : le relevé est une donnée d'entrée. |
| ANSSI | R7 (confidentialité dès la conception) ; R25 (filtrer entrées et sorties) | Un filtre sur ce qui entre dans le contexte du modèle. | Le filtrage des réponses du modèle et la limite de taille des réponses citée par R25. |
| AI Act | art. 15 « Exactitude, robustesse et cybersécurité », par analogie | Réduit une surface de fuite. | Toute exigence propre aux systèmes à haut risque. |

### garde-envoi

| Référentiel | Référence | Ce que le mod apporte | Ne couvre pas |
|---|---|---|---|
| OWASP | LLM06:2025 Excessive Agency | Confirmation humaine avant e-mail, message, invitation, signature, déploiement, `git push`, publication de paquet et envoi réseau du terminal. Partages et changements de visibilité refusés d'office. Fermé par défaut. | Les outils dont le nom ne révèle pas un envoi (limite documentée dans le README). |
| OWASP | LLM01:2025 Prompt Injection | Limite les conséquences d'une injection : l'action demandée par un contenu piégé doit encore être validée par une personne. | La détection de l'injection (voir veille-injection). |
| NIST | MAP 3.5 (processus de contrôle humain définis) ; MANAGE 2.4 (mécanismes pour désengager ou arrêter) | La question « Autoriser cet envoi ? » est un point de contrôle humain explicite, avec refus par défaut. | La définition organisationnelle des rôles et des responsabilités. |
| ANSSI | R9 (proscrire l'usage automatisé pour des actions critiques) ; R26 (maîtriser les interactions avec les applications métier) ; R27 (limiter les actions automatiques sur entrées non maîtrisées) | R9 cite la production de contenu public parmi les actions critiques : le mod la soumet à validation humaine, comme l'exemple « validation dans une IHM » du guide. | Le filtrage réseau, le chiffrement et l'authentification des flux demandés par R26. |
| AI Act | art. 14 « Contrôle humain », par analogie | Un contrôle effectif par une personne au moment de l'action. | Les interfaces et la formation des personnes chargées du contrôle. |

### journal-audit

| Référentiel | Référence | Ce que le mod apporte | Ne couvre pas |
|---|---|---|---|
| OWASP | LLM06:2025 Excessive Agency | Trace chaque appel d'outil : on peut reconstituer qui a fait quoi, avec quel modèle et quel sous-agent. | Il n'empêche rien : il constate. |
| NIST | MEASURE 2.8 (transparence et responsabilité) ; MANAGE 4.1 (surveillance après déploiement) ; MANAGE 4.3 (suivi des incidents) | Journal chaîné par SHA-256 : une ligne modifiée ou retirée se voit ; `/audit` vérifie la chaîne. | La conservation hors de la machine, la rotation et la protection du journal contre son effacement complet. |
| ANSSI | R29 (journaliser l'ensemble des traitements) | Journalise les appels aux outils (« appels à des plugins » dans R29). | **Partiel :** par choix, arguments et résultats ne sont notés que par leur SHA-256 ; seule la cible (chemin, URL sans paramètres, programme lancé) est écrite en clair. R29 recommande aussi de tracer les requêtes et les traitements en entrée du modèle. |
| AI Act | art. 12 « Enregistrement », par analogie | Enregistrement automatique des événements pendant l'utilisation. | La durée de conservation et l'accès des autorités, propres aux systèmes à haut risque. |

### veille-injection

| Référentiel | Référence | Ce que le mod apporte | Ne couvre pas |
|---|---|---|---|
| OWASP | LLM01:2025 Prompt Injection | 11 règles pondérées et détection de texte Unicode invisible sur les sorties web, MCP et fichiers ; avertissement ajouté pour le modèle. | Une injection reformulée hors des motifs connus. Le mod signale, il ne prouve pas et ne bloque jamais. |
| NIST | MEASURE 2.7 ; MANAGE 4.1 | Les alertes sont journalisées et listées par `/injection`. | L'analyse des alertes. |
| ANSSI | R25 (filtrer les entrées) ; R27 (entrées non maîtrisées : Internet, mails) | Le guide cite l'injection de requête indirecte par le contenu d'un mail ou d'une page web : ce sont les sorties que le mod inspecte. | Le blocage : avec garde-envoi, l'action qui suivrait reste soumise à validation. |
| AI Act | art. 15, par analogie | Robustesse face à des entrées manipulées. | Les attaques sur les données d'entraînement ou le modèle (empoisonnement, exemples contradictoires) : hors de portée d'un mod. |

## Ce que le pack ne traite pas

- **OWASP** LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption.
- **ANSSI** : les recommandations sur l'entraînement, l'hébergement, le cloisonnement et la chaîne de déploiement (R1 à R6, R10 à R24, R28) ; le contrôle du code généré (R30 à R32).
- **NIST** : toute la fonction GOVERN, qui relève de l'organisation et non d'un outil.

## Sources

Lues le 19/10/2026.

- OWASP, *Top 10 for LLM Applications 2025* — https://genai.owasp.org/llm-top-10/
- NIST, *Artificial Intelligence Risk Management Framework (AI RMF 1.0)*, NIST AI 100-1, janvier 2023 — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
- ANSSI, *Recommandations de sécurité pour un système d'IA générative*, ANSSI-PA-102, 29/04/2024, Licence Ouverte 2.0 — https://messervices.cyber.gouv.fr/documents-guides/Recommandations_de_s%C3%A9curit%C3%A9_pour_un_syst%C3%A8me_d_IA_g%C3%A9n%C3%A9rative.pdf
- Règlement (UE) 2024/1689 (AI Act), version française, art. 12, 14, 15 — https://eur-lex.europa.eu/legal-content/FR/TXT/HTML/?uri=CELEX:32024R1689

---

## English summary

What each mod **contributes to**, never "compliance": masque-secrets → OWASP LLM02, ANSSI R7/R25; garde-envoi → LLM06 and the consequences of LLM01, NIST MAP 3.5 / MANAGE 2.4, ANSSI R9/R26/R27; journal-audit → NIST MEASURE 2.8 / MANAGE 4.1 / 4.3, ANSSI R29 (partial: no plaintext by design); veille-injection → LLM01, ANSSI R25/R27. EU AI Act articles 12, 14 and 15 apply to high-risk systems only and are cited by analogy. All references were read in the official texts on 2026-10-19.
