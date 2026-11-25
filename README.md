# Dashboard

Personal work dashboard served at https://dashboard.philipmtaylor.com via GitHub Pages.

- `index.html` — the dashboard (single static page).
- `data/` — headline and market JSON, refreshed by `.github/workflows/fetch-headlines.yml`
  (runs `.github/scripts/fetch-headlines.py` hourly on weekdays) plus the static Stoic quote list.
- `data/matters.enc.json` — the Client Matter Table (Google Sheet), synced weekly by
  `.github/workflows/fetch-matters.yml` and stored **encrypted** (AES-GCM, passphrase in the
  `MATTERS_PASSPHRASE` secret) because this repo and site are public. Never commit it decrypted.
- Legal tool links point to https://philipmtaylor.com.
