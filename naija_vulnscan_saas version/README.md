# NaijaVulnScan - Hosted Service (SaaS)

A hosted version of NaijaVulnScan: users sign up, get a **7-day free
trial**, verify domain ownership, and run vulnerability scans through
a web dashboard - no Python or command line required on their end.
Subscriptions are handled through **Paystack**.

This is the monetized version of the original CLI tool. It reuses the
same scanning logic (`port_scanner.py`, `ssl_checker.py`,
`http_headers.py`, `report.py`) wrapped in a FastAPI web app with
accounts, billing, and domain-ownership verification.

## Why domain verification exists

Anyone can type any domain into a scan box. Without proof of ownership,
this service would let strangers scan sites they don't control - which
is illegal (in Nigeria, under the Cybercrimes Act 2015) and a serious
liability for you as the operator. Every domain must be verified via a
DNS TXT record or a file upload **before** it can be scanned. This is
not optional and should not be removed.

## Project structure

```
naija_vulnscan_saas/
├── .env.example          # copy to .env and fill in real values
├── requirements.txt
├── reports/              # generated HTML scan reports land here
└── app/
    ├── main.py           # FastAPI routes
    ├── config.py         # settings, loaded from .env
    ├── database.py       # SQLAlchemy engine/session
    ├── models.py         # User, Domain, Scan, Payment tables
    ├── auth.py           # password hashing (bcrypt) + JWT sessions
    ├── access_control.py # trial/subscription gating - the monetization logic
    ├── domain_verify.py  # DNS TXT / file-based ownership verification
    ├── payments.py        # Paystack integration
    ├── scan_runner.py    # runs scans as a background task
    ├── vuln_scanner/     # the original scanning modules (copied in)
    └── templates/        # Jinja2 HTML pages
```

## Local setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# System dependency (same as the CLI version)
sudo apt install nmap

cp .env.example .env
# Edit .env: at minimum set SECRET_KEY to a long random string,
# and PAYSTACK_SECRET_KEY / PAYSTACK_PUBLIC_KEY to your test keys
# from https://dashboard.paystack.com/#/settings/developer

uvicorn app.main:app --reload
```

Visit `http://localhost:8000/signup` to create an account and try the
flow. Use Paystack's test card numbers (listed in their docs) to
simulate a successful payment without spending real money.

## What still needs to happen before this is genuinely production-ready

This is a working MVP, not a finished product. Before charging real
customers:

1. **Move off SQLite** to Postgres for anything beyond a handful of
   users (`DATABASE_URL=postgresql://...` in `.env`, SQLAlchemy handles
   the rest).
2. **Set up the Paystack webhook** in your Paystack dashboard pointing
   to `https://yourdomain.com/billing/webhook` - this is the
   authoritative source of "did they actually pay," not the browser
   redirect alone (the code already handles both, but the webhook URL
   has to be registered on Paystack's side).
3. **Get a real domain + HTTPS** (e.g. via Let's Encrypt/Certbot on a
   VPS) - Paystack requires HTTPS callback URLs in production, and
   session cookies should be `secure=True` once you're not on
   localhost.
4. **Move scans to a real task queue** (e.g. Celery + Redis) instead of
   FastAPI's `BackgroundTasks` once you have more than a few
   simultaneous users - background tasks in a single process don't
   scale well and a slow scan can back up others.
5. **Rate-limit scan requests** so one account can't hammer the server
   (or someone else's infrastructure) with repeated scans.
6. **Add password reset** - there's currently no way for a user to
   recover a forgotten password.
7. **Legal basics**: Terms of Service and a Privacy Policy, given you're
   handling payments and scanning third-party-adjacent infrastructure.

## Deployment sketch (when you're ready)

- A small VPS (DigitalOcean, Linode, or a Nigerian provider) with Nmap
  installed
- Run the app under a process manager (systemd or `pm2`) rather than
  `--reload`
- Nginx as a reverse proxy in front of it, with Certbot for free HTTPS
- Point your domain's DNS at the VPS, set `APP_BASE_URL` in `.env` to
  `https://yourdomain.com`, switch Paystack keys from test to live
