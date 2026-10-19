# Journal des versions

## Non publié

- **MAPPING.md** : correspondance de chaque mod avec l'OWASP LLM Top 10 (2025), le NIST AI RMF 1.0, l'ANSSI-PA-102 et l'AI Act (par analogie), avec une colonne « Ne couvre pas ». Références lues dans les textes officiels le 19/10/2026.

## 2026-10-19 — première publication

- **masque-secrets 0.2.0** : formats d'éditeurs, secrets reconnus par leur libellé, valeurs exactes des variables d'environnement secrètes courantes, indices de chaînes aléatoires (notés, jamais masqués) ; modes observation et masquage ; `/secrets`.
- **garde-envoi 0.3.0** : confirmation avant envoi, publication, déploiement et envoi réseau du terminal ; partages et changements de visibilité refusés d'office ; règles sur le nom des outils MCP ; liste d'hôtes réglable (`hotes`) ; `/garde`.
- **journal-audit 0.1.0** : journal chaîné par SHA-256, sans contenu en clair, modèle réel par étape et par sous-agent ; `/audit`.
- **veille-injection 0.1.0** : 11 règles pondérées et détection de texte Unicode invisible sur les sorties web, MCP et fichiers ; avertissement pour le modèle, jamais de blocage ; `/injection`.
