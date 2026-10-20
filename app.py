
import os
import json
import hmac
import hashlib
import secrets
import sqlite3
import time
from urllib.parse import parse_qsl

import httpx
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Ethiopia Lucky Star")

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
WEB_APP_URL = os.getenv(
    "WEB_APP_URL",
    "https://ethio-lottery-demo.onrender.com"
).rstrip("/")
DATABASE_PATH = os.getenv("DATABASE_PATH", "/tmp/lucky_star.db")
WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "")

GAMES = {"daily", "weekly", "monthly", "holiday", "jemaw", "lebet"}


def connect_db():
    folder = os.path.dirname(DATABASE_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_db():
    with connect_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS players (
                telegram_id TEXT PRIMARY KEY,
                first_name TEXT NOT NULL DEFAULT '',
                last_name TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                referral_code TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS demo_tickets (
                ticket_id TEXT PRIMARY KEY,
                telegram_id TEXT NOT NULL,
                game_id TEXT NOT NULL,
                digits_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (telegram_id)
                    REFERENCES players(telegram_id)
            )
        """)


initialize_db()


def validate_init_data(init_data):
    if not BOT_TOKEN:
        raise HTTPException(503, "Backend BOT_TOKEN is not configured.")
    if not init_data or len(init_data) > 10000:
        raise HTTPException(401, "Missing Telegram session.")

    pairs = parse_qsl(init_data, keep_blank_values=True)
    data = dict(pairs)
    if len(data) != len(pairs):
        raise HTTPException(401, "Invalid Telegram session.")

    received_hash = data.pop("hash", None)
    if not received_hash:
        raise HTTPException(401, "Missing Telegram signature.")

    check_string = "\n".join(
        f"{key}={value}" for key, value in sorted(data.items())
    )
    secret_key = hmac.new(
        b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256
    ).digest()
    expected_hash = hmac.new(
        secret_key, check_string.encode(), hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_hash, received_hash):
        raise HTTPException(401, "Telegram signature verification failed.")

    try:
        auth_date = int(data["auth_date"])
        if abs(int(time.time()) - auth_date) > 86400:
            raise HTTPException(401, "Telegram session expired.")
        user = json.loads(data["user"])
        if not isinstance(user, dict) or not user.get("id"):
            raise ValueError()
        return user
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(401, "Invalid Telegram user data.")


def registered_player(request):
    user = validate_init_data(
        request.headers.get("X-Telegram-Init-Data", "")
    )
    with connect_db() as conn:
        player = conn.execute(
            "SELECT * FROM players WHERE telegram_id = ?",
            (str(user["id"]),)
        ).fetchone()

    if not player:
        raise HTTPException(
            403, "Please register using the Telegram bot first."
        )
    return user, dict(player)


async def telegram_call(method, payload):
    if not BOT_TOKEN:
        raise HTTPException(503, "BOT_TOKEN is not configured.")
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
            json=payload
        )
    if response.status_code >= 400 or not response.json().get("ok"):
        raise HTTPException(502, "Telegram API request failed.")
    return response.json().get("result")


def register_user(user):
    telegram_id = str(user["id"])
    with connect_db() as conn:
        player = conn.execute(
            "SELECT * FROM players WHERE telegram_id = ?",
            (telegram_id,)
        ).fetchone()

        if player:
            conn.execute("""
                UPDATE players
                SET first_name=?, last_name=?, username=?
                WHERE telegram_id=?
            """, (
                str(user.get("first_name", ""))[:128],
                str(user.get("last_name", ""))[:128],
                str(user.get("username", ""))[:64],
                telegram_id
            ))
        else:
            referral = secrets.token_hex(4).upper()
            while conn.execute(
                "SELECT 1 FROM players WHERE referral_code=?",
                (referral,)
            ).fetchone():
                referral = secrets.token_hex(4).upper()

            conn.execute("""
                INSERT INTO players
                (telegram_id, first_name, last_name, username,
                 referral_code, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                telegram_id,
                str(user.get("first_name", ""))[:128],
                str(user.get("last_name", ""))[:128],
                str(user.get("username", ""))[:64],
                referral,
                int(time.time())
            ))

        return dict(conn.execute(
            "SELECT * FROM players WHERE telegram_id=?",
            (telegram_id,)
        ).fetchone())


@app.get("/")
async def home():
    return {
        "ok": True,
        "service": "Ethio Lottery",
        "mode": "DEMO",
        "payments_enabled": False
    }


@app.get("/health")
async def health():
    return {"ok": True, "mode": "DEMO", "payments_enabled": False}


@app.get("/api/me")
async def api_me(request: Request):
    _, player = registered_player(request)
    return {
        "ok": True,
        "user": {
            "first_name": player["first_name"],
            "last_name": player["last_name"],
            "username": player["username"],
            "referral_code": player["referral_code"]
        },
        "mode": "DEMO"
    }


class TicketInput(BaseModel):
    game_id: str = Field(min_length=1, max_length=24)
    digits: list[int] = Field(min_length=1, max_length=6)


@app.post("/api/demo-ticket")
async def demo_ticket(body: TicketInput, request: Request):
    _, player = registered_player(request)

    if body.game_id not in GAMES:
        raise HTTPException(422, "Unknown game.")
    if any(n < 1 or n > 9 for n in body.digits):
        raise HTTPException(422, "Digits must be from 1 to 9.")
    if len(set(body.digits)) != len(body.digits):
        raise HTTPException(422, "Digits must be unique.")

    ticket_id = "DEMO-" + secrets.token_hex(4).upper()
    with connect_db() as conn:
        conn.execute("""
            INSERT INTO demo_tickets
            (ticket_id, telegram_id, game_id, digits_json, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            ticket_id,
            player["telegram_id"],
            body.game_id,
            json.dumps(sorted(body.digits)),
            int(time.time())
        ))

    return {
        "ok": True,
        "ticket_id": ticket_id,
        "message": "Demo ticket saved. No payment taken.",
        "mode": "DEMO",
        "payments_enabled": False
    }


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    if WEBHOOK_SECRET and not hmac.compare_digest(
        request.headers.get("X-Telegram-Bot-Api-Secret-Token", ""),
        WEBHOOK_SECRET
    ):
        raise HTTPException(403, "Invalid webhook secret.")

    update = await request.json()
    message = update.get("message") or {}
    user = message.get("from") or {}
    chat_id = (message.get("chat") or {}).get("id")
    text = str(message.get("text", "")).strip()

    if not chat_id or not user.get("id"):
        return {"ok": True}

    if text.startswith("/start") or text.startswith("/register"):
        player = register_user(user)
        await telegram_call("sendMessage", {
            "chat_id": chat_id,
            "text": (
                f"Selam {player['first_name'] or 'player'}! 🇪🇹\n\n"
                "Your demo account is registered.\n"
                f"Referral code: {player['referral_code']}\n"
                "Payments and cash prizes are disabled."
            ),
            "reply_markup": {
                "inline_keyboard": [[{
                    "text": "🎰 Open Ethiopia Lucky Star",
                    "web_app": {"url": WEB_APP_URL}
                }]]
            }
        })
    elif text.startswith("/help"):
        await telegram_call("sendMessage", {
            "chat_id": chat_id,
            "text": "Send /start to register and open the demo game."
        })

    return {"ok": True}
