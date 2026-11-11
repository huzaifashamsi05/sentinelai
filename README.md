# SentinelAI — AI-Powered Security Operations Platform

**CS-2106 Information Security, Batch 25/F, Section B**
Abdul Rahman (25F-DS-106) · Muhammad Huzaifa Shamsi (25F-DS-135) · Basit Mirza (25F-DS-140) · Muhammad Hashir (25F-DS-152)

SentinelAI is a unified security-operations dashboard combining six
modules under one login, one database, and one live alert feed — each
module trained on real public datasets and explained with SHAP rather
than returning a bare label.

| Module | What it does | Model / technique |
|---|---|---|
| Network Intrusion Detection | Classifies network connection records as Normal / DoS / Probe / R2L / U2R | RandomForest on NSL-KDD (41 features) |
| Phishing / Malicious URL Detector | Classifies a URL as benign/malicious from lexical features only — no network calls | RandomForest on a 420k-URL public dataset |
| Malware Detection | Classifies an uploaded `.exe`/`.dll` from its real static PE-header structure | RandomForest on the ClaMP dataset + live `pefile` parsing |
| Vulnerability Scanner | Passive OWASP Top-10-style checks (headers, cookies, HTTPS, outdated libs) | Rule-based; **authorized-targets-only by design** |
| Secure Vault | AES-256 file encryption, RSA-2048 signatures, SHA-256 integrity checks | `cryptography` library |
| Unified Dashboard | Auth (JWT, bcrypt, RBAC, account lockout), shared alert feed, PDF reports | FastAPI + Streamlit |

Every ML module's prediction comes with a SHAP explanation ("why did it
flag this"), not just a label — this is the backbone of the "explainable"
part of the platform.

## Model performance (test set)

| Module | Accuracy | Macro F1 |
|---|---|---|
| Network IDS | 75.2% | 0.52 |
| Phishing Detector | 87.7% | 0.84 |
| Malware Detection | 99.0% | 0.99 |

Network IDS's macro F1 is low on the R2L/U2R classes specifically because
NSL-KDD itself has very few examples of those attack types (a few hundred
rows out of 125k) — a known, documented characteristic of this benchmark
dataset, not a bug. See each module's page in the dashboard for a
"how this works / limitations" note.

## Safety boundary (read this before touching the Vulnerability Scanner)

The scanner will **only** run against `localhost`/`127.0.0.1` or a host an
Admin has explicitly authorized after confirming ownership. This is
enforced in code, not just policy — see [`docs/ETHICS.md`](docs/ETHICS.md)
for why, and for safe local targets to demo against (OWASP Juice Shop,
DVWA).

## Running locally

Requires **Python 3.12** (SHAP 0.46.0 has no published wheel for 3.13 yet).

```bash
pip install -r requirements.txt --break-system-packages

# Terminal 1 — backend
cd backend && PYTHONPATH=. uvicorn app.main:app --reload --port 8000

# Terminal 2 — dashboard
cd frontend && streamlit run Home.py
```

The backend refuses to start without a `SECRET_KEY` (the JWT signing key)
set in the environment — it used to fall back to a value published right
here in the README, which meant anyone could forge an admin token offline.
Set it before running either terminal above:

```bash
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')"
```

Open http://localhost:8501. Two accounts are seeded automatically on
first backend startup (see `backend/app/main.py::seed_default_users`):

| Username | Password | Role |
|---|---|---|
| `admin` | from the `ADMIN_PASSWORD` env var — if unset, a random password is generated and printed to the backend's console log on startup | admin |
| `analyst1` | `AnalystPass123` (fixed, intentionally public — this account can't do anything admin-only) | analyst |

Set `ADMIN_PASSWORD` for a stable admin login across restarts, or just
register your own account from the login screen (self-registration always
creates an Analyst account; Admin only ever comes from this seed step).

## Retraining a model

Raw datasets live in `data/raw/` (gitignored — see `docs/` for sources).
Each module has its own trainer:

```bash
python ml/network_ids/train.py
python ml/phishing/train.py
python ml/malware/train.py
```

Each writes `models/<module>.joblib` (committed to this repo — see
below) and `models/<module>_metrics.json`.

## Why the trained models are committed to git

Normally you'd gitignore trained models. Here they're intentionally
**kept in git** (`models/*.joblib`) so that a fresh clone — including a
Streamlit Community Cloud deploy — runs immediately with no training
step and no need for the large raw datasets. Each `RandomForestClassifier`
is deliberately size-capped (`max_leaf_nodes`) so the three bundles
together stay under ~85MB, comfortably inside GitHub's 100MB-per-file
limit.

## Deployment

See [`DEPLOYMENT.md`](DEPLOYMENT.md) — the whole platform deploys as a
**single free Streamlit Community Cloud app** (no second host, no paid
domain).

## Project structure

```
backend/        FastAPI app — auth, shared alert/audit DB, all 5 module routers
frontend/       Streamlit multi-page dashboard (Home.py + pages/)
ml/             Training scripts (one per ML module)
models/         Trained model bundles (committed — see above)
data/           Raw datasets (gitignored) + processed/
docs/           ETHICS.md — the safety-boundary writeup
scripts/        Dev-time Playwright smoke test
reports/        Generated PDF reports land here (gitignored)
```
