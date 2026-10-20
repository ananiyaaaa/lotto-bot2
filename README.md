# Ethiopia Lucky Star — Telegram Mini App demo

Mobile-first + desktop-friendly lottery-style demo site with Telegram bot registration, registration-gated Mini App access, SQLite demo accounts, and demo ticket records. **No payment integration or real-money ticket purchasing is implemented.** The payment flag is hard-disabled in code.

## Before deploying
- Use a NEW Telegram bot created with `@BotFather` and keep its token private.
- Create a NEW GitHub repository and upload the contents of this folder.
- Create a Render web service from that repository.
- Set Render environment variables:
  - `TELEGRAM_BOT_TOKEN` = token from BotFather
  - `WEBAPP_URL` = your final Render service URL, e.g. `https://your-service.onrender.com`
  - `DEMO_MODE` = `true`
  - `DATABASE_PATH` = `/opt/render/project/src/lucky_star.db` for a temporary demo database (it may reset on redeploy/restart). For persistent accounts, attach a Render persistent disk at `/var/data` and set `DATABASE_PATH=/var/data/lucky_star.db` (disk availability may depend on your Render plan).
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`

## Telegram setup
1. In `@BotFather`, use `/newbot`, follow the prompts, and copy the token into Render's `TELEGRAM_BOT_TOKEN` secret.
2. Deploy the service once to get its public URL.
3. Set `WEBAPP_URL` to that URL exactly, save the environment variable, and redeploy.
4. Open the bot in Telegram and send `/start`. Press **Register / My account**. After registration, the **Open Lucky Star Demo** button appears.
5. Open the Web App from that button. Direct browser access is preview-only; account APIs require valid Telegram Mini App init data and prior bot registration.

## GitHub upload
Create a new empty repository, then upload `app.py`, `requirements.txt`, `Procfile`, `render.yaml`, `.gitignore`, `README.md`, and `static/index.html`. Do not upload `.env` files or the bot token.

## Important production notes
- This is a prototype, not a licensed lottery platform. No cash payments, paid ticket sales, prize payouts, or real draws are available.
- For real-money lottery features, first obtain appropriate Ethiopian legal/regulatory advice and approvals and provider authorization. A compliant production system also needs secure identity/age checks, responsible-play controls, auditable draw logic, anti-fraud measures, secure persistent database, backups, and formal accounting.
- The current app uses Telegram polling from the web service and SQLite. Use one Render instance for this starter bot. For production, move to a managed database and a separately managed bot worker/webhook architecture.
- Render free instances may sleep and their filesystem is not a reliable permanent database. Add a persistent disk or managed PostgreSQL for account persistence.
