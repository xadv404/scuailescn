# SQL Audit Scanner

Outil professionnel d'audit de sécurité web orienté détection d'injections SQL.
Conçu pour un usage **local et autorisé uniquement**.

---

## ⚠ Avertissement légal

Cet outil est réservé aux audits de sécurité expressément autorisés par écrit.
Toute utilisation sur des systèmes tiers sans autorisation est illégale.

---

## Architecture

```
scuailescn/
├── backend/
│   ├── main.py                  # FastAPI : routes, orchestration
│   ├── scanner/
│   │   ├── sqlmap_runner.py     # Exécution de SQLMap via subprocess
│   │   ├── analyzer.py          # Parsing et classification des résultats
│   │   └── reporter.py          # Génération des rapports JSON
│   ├── models/
│   │   └── scan.py              # Modèles Pydantic
│   └── utils/
│       ├── logger.py            # Logging centralisé
│       └── validators.py        # Validation des entrées
├── frontend/
│   ├── index.html               # Interface web SPA
│   └── static/
│       ├── css/style.css        # Design system dark
│       └── js/app.js            # Logique frontend
├── reports/                     # Rapports JSON générés (non versionnés)
├── logs/                        # Logs applicatifs (non versionnés)
├── temp/                        # Fichiers temporaires SQLMap (nettoyés)
├── config.py                    # Configuration centralisée
├── run.py                       # Point d'entrée uvicorn
├── run.sh                       # Script de lancement
├── install.sh                   # Script d'installation
└── requirements.txt             # Dépendances Python
```

---

## Installation

```bash
# Cloner / se placer dans le répertoire
cd scuailescn

# Lancer le script d'installation (installe .venv + dépendances + SQLMap)
chmod +x install.sh && ./install.sh
```

### Installation manuelle

```bash
# Python 3.10+
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# SQLMap (Debian/Ubuntu)
sudo apt install sqlmap

# SQLMap (autres distributions)
pip install sqlmap
# ou voir https://sqlmap.org
```

---

## Lancement

```bash
./run.sh
# ou
source .venv/bin/activate
python3 run.py
```

L'interface est accessible sur **http://127.0.0.1:8000**

### Variables d'environnement

| Variable        | Défaut          | Description                             |
|-----------------|-----------------|----------------------------------------|
| `SQLMAP_PATH`   | `sqlmap`        | Chemin vers le binaire SQLMap           |
| `SQLMAP_TIMEOUT`| `300`           | Timeout max par scan (secondes)         |
| `HOST`          | `127.0.0.1`     | Interface d'écoute du serveur           |
| `PORT`          | `8000`          | Port du serveur FastAPI                 |

---

## Utilisation

1. Ouvrir http://127.0.0.1:8000
2. Saisir une ou plusieurs URLs à auditer (ex : `https://site.com/page?id=1`)
3. Cliquer sur **Lancer le scan**
4. Suivre la progression en temps réel
5. Consulter le rapport de résultats
6. Exporter le rapport en JSON

---

## Format du rapport JSON

```json
{
  "report_metadata": { "tool": "SQL Audit Scanner", "version": "1.0.0", "generated_at": "…", "disclaimer": "…" },
  "scan_id": "abc1234567",
  "target": "https://exemple.com/page?id=1",
  "date": "2026-06-19T10:00:00",
  "end_date": "2026-06-19T10:04:23",
  "duration_seconds": 263.1,
  "status": "completed",
  "summary": {
    "total_findings": 2,
    "risk_level": "CRITICAL",
    "severity_breakdown": { "critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0 },
    "vulnerable": true
  },
  "findings": [
    {
      "type": "boolean_blind_sqli",
      "severity": "critical",
      "location": "https://exemple.com/page?id=1",
      "description": "Boolean-based Blind SQL Injection detected",
      "impact": "…",
      "recommendation": "…",
      "evidence": { "matched_pattern": "…", "occurrences": 3, "snippets": ["…"] }
    }
  ]
}
```

---

## API REST

La documentation interactive (Swagger) est disponible sur http://127.0.0.1:8000/api/docs

| Méthode | Endpoint                        | Description                        |
|---------|---------------------------------|------------------------------------|
| GET     | `/api/health`                   | État de l'application et SQLMap    |
| POST    | `/api/scan/start`               | Lancer un ou plusieurs scans       |
| GET     | `/api/scan/{id}/status`         | État temps réel d'un scan          |
| GET     | `/api/scan/{id}/report`         | Rapport complet JSON               |
| DELETE  | `/api/scan/{id}`                | Supprimer un scan et son rapport   |
| GET     | `/api/reports`                  | Liste de tous les rapports         |

---

## Sécurité de l'outil lui-même

- Écoute uniquement sur `127.0.0.1` par défaut (non exposé réseau)
- Validation des URLs côté backend avant tout lancement de processus
- SQLMap lancé en mode batch/non-interactif, sans extraction de données réelles
- Risk level 1 uniquement (pas de payloads UPDATE/DELETE)
- Fichiers temporaires nettoyés automatiquement après chaque scan
- Aucune donnée sensible conservée dans les rapports (extraits sanitisés)

---

## Dépendances

| Paquet             | Version min | Rôle                            |
|--------------------|-------------|---------------------------------|
| fastapi            | 0.111.0     | Framework API REST              |
| uvicorn[standard]  | 0.29.0      | Serveur ASGI                    |
| pydantic           | 2.0.0       | Validation des données          |
| python-multipart   | 0.0.9       | Support form-data               |
| sqlmap             | —           | Moteur d'analyse (externe)      |
