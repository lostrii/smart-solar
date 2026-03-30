# Smart Solar (admin-protected)

This folder contains a single-page front-end (`index.html`) plus a small Flask server (`app.py`) to protect the admin panel.

## 1) Set environment variables

Required:
- `SESSION_SECRET` (random string)
- `ADMIN_USERNAME` (owner username)
- One of:
  - `ADMIN_PASSWORD_HASH` (preferred): a Werkzeug password hash string
  - `ADMIN_PASSWORD_PLAIN` (fallback): plaintext password, hashed at server startup (not written to disk)

Optional:
- `PORT` (default `5000`)
- `SESSION_COOKIE_SECURE` (set to `true` behind HTTPS)
- Rate limiting for `/login`:
  - `LOGIN_MAX_ATTEMPTS` (default `5`)
  - `LOGIN_WINDOW_SECONDS` (default `900`, 15 minutes)
  - `LOGIN_LOCKOUT_SECONDS` (default `900`, 15 minutes)
  - `LOGIN_FAILURE_DELAY_SECONDS` (default `0.2`)
- Notifications (instant alerts):
  - `NOTIFY_TYPES` (default `General Inquiry,Loan Request`)
  - **WhatsApp (Meta Cloud API, recommended)**:
    - `META_WA_TOKEN`
    - `META_WA_PHONE_NUMBER_ID`
    - `META_WA_TO`
    - `META_WA_API_VERSION` (default `v22.0`)
  - **WhatsApp (Twilio, optional)**:
    - `TWILIO_ACCOUNT_SID`
    - `TWILIO_AUTH_TOKEN`
    - `TWILIO_WHATSAPP_FROM` (example: `whatsapp:+14155238886`)
    - `ADMIN_WHATSAPP_TO` (example: `whatsapp:+918400000810`)
  - **WhatsApp fallback (manual link)**:
    - `ADMIN_WHATSAPP_PHONE_E164` (digits only; example: `918400000810`)
  - **Email (SMTP, optional)**:
    - `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS`
    - `SMTP_USER`, `SMTP_PASS`
    - `SMTP_FROM`, `SMTP_TO`
    - `SMTP_SUBJECT_PREFIX`

## 2) Generate a password hash (recommended)

Run:

```powershell
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YOUR_PASSWORD'))"
```

Then set `ADMIN_PASSWORD_HASH` to the printed value.

## 3) Install & run (development)

```powershell
pip install -r requirements.txt
python app.py
```

## 6) Production deployment (recommended)

For production you should run this Flask app with a WSGI server (not `python app.py`).

### A) Required environment variables
- `SESSION_SECRET`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD_HASH` (preferred) or `ADMIN_PASSWORD_PLAIN`

### B) Optional environment variables
- `PORT` (default `5000`)
- `HOST` (default `0.0.0.0`)
- `SESSION_COOKIE_SECURE=true` (set this when your site is behind HTTPS)
- `TRUST_PROXY=true` (set this if you are behind a reverse proxy and want correct forwarded headers)

### C) Run command

On Linux / macOS:
```bash
gunicorn -w 3 -b 0.0.0.0:${PORT:-5000} app:app
```

On Windows:
```powershell
$env:PORT="5000"
waitress-serve --listen=0.0.0.0:$env:PORT app:app
```

## 7) Deploy to Render (recommended)

This repo includes a `render.yaml` that configures:
- Build: `python -m pip install -r requirements.txt`
- Start: `waitress-serve --listen=0.0.0.0:$PORT app:app`
- Persistent SQLite disk at `/var/data` (so `leads.db` survives deploys)
- Production env defaults: `TRUST_PROXY=true`, `SESSION_COOKIE_SECURE=true`, `DB_PATH=/var/data/leads.db`

### Steps
- Push this project to GitHub.
- In Render, create a new **Web Service** from the repo.
- Render will auto-detect `render.yaml`.
- In Render → **Environment**, set the required secrets:
  - `SESSION_SECRET`
  - `ADMIN_USERNAME`
  - `ADMIN_PASSWORD_HASH` (preferred) or `ADMIN_PASSWORD_PLAIN`
  - (Optional notifications): `META_WA_*`, SMTP vars, etc.

### After deploy
- Public site: `https://<your-render-service>.onrender.com/`
- Login: `/login`
- Admin: `/admin`

## 4) Using a .env file (recommended for local dev)

- Copy `.env.example` to `.env`
- Fill in values
- Never commit your real `.env`

## 5) Instant notifications (WhatsApp + Email)

All form submissions are saved in SQLite first. Notifications are **best-effort** (they won’t block saving).

### WhatsApp (instant, recommended)

This project supports **Meta WhatsApp Cloud API** (preferred). Add these to `.env`:
- `META_WA_TOKEN`
- `META_WA_PHONE_NUMBER_ID`
- `META_WA_TO` (example: `+918400000810`)
- `META_WA_API_VERSION` (optional; default `v22.0`)

It also supports **Twilio WhatsApp** (optional fallback) if you prefer Twilio.

### WhatsApp fallback (no API)

If you don’t want an API right now, set:
- `ADMIN_WHATSAPP_PHONE_E164` (digits only, country code included)

Then the backend returns a `notifications.whatsapp_fallback_url` (a `wa.me` link) in the `/api/leads` response.

### Email (SMTP)

Add these to `.env`:
- `SMTP_HOST` (example `smtp.gmail.com`)
- `SMTP_PORT` (example `587`)
- `SMTP_TLS` (`true` or `false`)
- `SMTP_USER`
- `SMTP_PASS` (use an app password if using Gmail)
- `SMTP_FROM`
- `SMTP_TO`

Open:
- Public site: `http://localhost:5000/` (replace with your domain in production)
- Login: `http://localhost:5000/login`
- Admin: `http://localhost:5000/admin`

