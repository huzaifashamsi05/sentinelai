# Deploying SentinelAI (free, no domain purchase)

The six modules are deliberately packaged to deploy as **one single free
Streamlit Community Cloud app**. The FastAPI backend doesn't need its own
host — it starts itself in a background thread *inside* the same
Streamlit process (see `frontend/_backend_bootstrap.py`), and talks to it
over `localhost`, which always works since it's the same container. One
account, one free app, nothing to pay for.

This last step — connecting your own GitHub account and clicking
"Deploy" on Streamlit's site — has to be done by you, since it needs your
own login. Everything else is already done. Steps:

## 1. Push this project to your own GitHub repo

```bash
cd sentinelai
git remote add origin https://github.com/<your-username>/sentinelai.git
git branch -M main
git push -u origin main
```

(If you don't have a GitHub account yet, make a free one at
github.com/join — takes a minute, no card needed.)

The repo can be public or private — Streamlit Community Cloud works with
either once you've connected your GitHub account to it.

## 2. Deploy on Streamlit Community Cloud

1. Go to **[share.streamlit.io](https://share.streamlit.io)** and sign in
   with the same GitHub account.
2. Click **"New app"**.
3. Pick your `sentinelai` repo, branch `main`.
4. **Main file path:** `frontend/Home.py`
5. Click **Deploy**.

That's it — first boot takes a minute or two (installing
`requirements.txt`, loading the three model bundles). You'll get a public
URL like `https://sentinelai-<something>.streamlit.app` to put in the
proposal/report and show "sir."

## 3. Log in

Two accounts are seeded automatically on first boot (see
`backend/app/main.py::seed_default_users` — the database is ephemeral on
Streamlit Cloud, so this runs on every fresh container):

| Username | Password | Role |
|---|---|---|
| `admin` | `SentinelAI123` | admin |
| `analyst1` | `AnalystPass123` | analyst |

Change the password after first login (or just register a fresh account)
before sharing the link widely, since these are public credentials in
this repo.

## Optional: a stronger JWT secret key

`backend/app/core/config.py` falls back to a dev `SECRET_KEY` if none is
set. To set a real one on Streamlit Cloud: open your app → **Settings →
Secrets**, and add:

```toml
SECRET_KEY = "something-long-and-random"
```

`_backend_bootstrap.py` mirrors anything in Streamlit's secrets into the
backend's environment automatically — no code change needed.

## Notes / known limits of this setup

- **Ephemeral storage:** Streamlit Cloud's container resets on
  redeploy/restart/sleep, so the SQLite DB (users, alerts, audit log)
  does **not** persist across restarts. Fine for a live demo; not a
  place to store real long-term data. If you ever need real persistence,
  swap `DATABASE_URL` for a free hosted Postgres (e.g. Neon/Supabase free
  tier) — `backend/app/db/database.py` already reads it from an env var.
- **Free-tier memory (~1GB):** loading three RandomForest bundles plus
  FastAPI and Streamlit together is comfortable but not huge headroom.
  If the app ever restarts under load, that's almost certainly why.
- **The Vulnerability Scanner's "before/after" demo still only targets
  this app's own backend (`localhost:8000`)** — the safety boundary in
  `docs/ETHICS.md` holds in production exactly as it does locally.

## If you'd rather run backend and frontend as two separate free services

Not needed for this project, but if you ever want to split them (e.g. the
backend on Render's free tier, frontend on Streamlit Cloud separately):
set `SENTINELAI_EMBED_BACKEND=0` as an env var on the Streamlit app, and
`SENTINELAI_BACKEND_URL=https://your-backend-url` pointing at wherever
the backend is actually running. Everything in `frontend/api_client.py`
already reads the backend URL from that one env var, so no code changes
are needed either way.
