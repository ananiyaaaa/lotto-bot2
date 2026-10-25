from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
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

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
from fastapi.responses import FileResponse
from fastapi import HTTPException

@app.get("/admin", include_in_schema=False)
async def admin_page():
    admin_file = STATIC_DIR / "admin.html"

    if not admin_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="Admin page missing: static/admin.html"
        )

    return FileResponse(str(admin_file))
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
WEB_APP_URL = os.getenv(
    "WEB_APP_URL",
    "https://lotto-bot2.onrender.com"
).rstrip("/")
DATABASE_PATH = os.getenv("DATABASE_PATH", "/tmp/lucky_star.db")
WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# Demo only. No payment endpoints or payment processing are enabled.
GAMES = {
    "daily", "weekly", "monthly", "holiday",
    "accessory", "jemaw", "lebet", "beale",
}
PIN_ITERATIONS = 310_000
MAX_PIN_ATTEMPTS = 5
PIN_LOCK_SECONDS = 15 * 60


def connect_db():
    db_path = Path(DATABASE_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
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
                FOREIGN KEY (telegram_id) REFERENCES players(telegram_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS demo_payment_requests (
                payment_id TEXT PRIMARY KEY,
                telegram_id TEXT NOT NULL,
                method TEXT NOT NULL,
                reference TEXT NOT NULL,
                amount_birr INTEGER NOT NULL,
                game_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                created_at INTEGER NOT NULL,
                reviewed_at INTEGER,
                admin_note TEXT NOT NULL DEFAULT '',
                UNIQUE(method, reference),
                FOREIGN KEY (telegram_id) REFERENCES players(telegram_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS demo_wallets (
                telegram_id TEXT PRIMARY KEY,
                balance_birr INTEGER NOT NULL DEFAULT 0 CHECK(balance_birr >= 0),
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (telegram_id) REFERENCES players(telegram_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS demo_wallet_ledger (
                ledger_id TEXT PRIMARY KEY,
                telegram_id TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                amount_birr INTEGER NOT NULL,
                reference TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (telegram_id) REFERENCES players(telegram_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS demo_withdrawals (
                request_id TEXT PRIMARY KEY,
                telegram_id TEXT NOT NULL,
                amount_birr INTEGER NOT NULL CHECK(amount_birr > 0),
                status TEXT NOT NULL DEFAULT 'PENDING',
                created_at INTEGER NOT NULL,
                reviewed_at INTEGER,
                admin_note TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (telegram_id) REFERENCES players(telegram_id)
            )
        """)

        # Safe migrations for existing SQLite databases.
        existing = {
            row["name"] for row in
            conn.execute("PRAGMA table_info(players)").fetchall()
        }
        migrations = {
            "display_name": "TEXT NOT NULL DEFAULT ''",
            "phone": "TEXT NOT NULL DEFAULT ''",
            "pin_salt": "TEXT NOT NULL DEFAULT ''",
            "pin_hash": "TEXT NOT NULL DEFAULT ''",
            "failed_pin_attempts": "INTEGER NOT NULL DEFAULT 0",
            "pin_lock_until": "INTEGER NOT NULL DEFAULT 0",
        }
        for column, definition in migrations.items():
            if column not in existing:
                conn.execute(
                    f"ALTER TABLE players ADD COLUMN {column} {definition}"
                )

        # Canonicalize old digit JSON before enforcing uniqueness, because older
        # rows may contain whitespace while new rows use compact JSON.
        for old_ticket in conn.execute("SELECT rowid, digits_json FROM demo_tickets").fetchall():
            try:
                canonical_digits = json.dumps(json.loads(old_ticket["digits_json"]), separators=(",", ":"))
                conn.execute("UPDATE demo_tickets SET digits_json = ? WHERE rowid = ?", (canonical_digits, old_ticket["rowid"]))
            except (TypeError, ValueError):
                continue
        # If old demo data already contains duplicates, keep the earliest ticket only.
        conn.execute("""
            DELETE FROM demo_tickets
            WHERE rowid NOT IN (
                SELECT MIN(rowid) FROM demo_tickets GROUP BY game_id, digits_json
            )
        """)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_demo_ticket_game_digits ON demo_tickets(game_id, digits_json)")


initialize_db()


def validate_init_data(init_data):
    """Verify Telegram Mini App initData; never trust client-supplied user IDs."""
    if not BOT_TOKEN:
        raise HTTPException(503, "Backend BOT_TOKEN is not configured.")
    if not init_data or len(init_data) > 10000:
        raise HTTPException(
            401,
            "Open this page from the Telegram bot to verify your account."
        )

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
        # Reject old sessions and timestamps too far in the future.
        now = int(time.time())
        if auth_date > now + 60 or now - auth_date > 86400:
            raise HTTPException(401, "Telegram session expired.")
        user = json.loads(data["user"])
        if not isinstance(user, dict) or not user.get("id"):
            raise ValueError()
        return user
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(401, "Invalid Telegram user data.")


def request_telegram_user(request, body_init_data=""):
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    if not init_data:
        init_data = body_init_data or ""
    return validate_init_data(init_data)


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
            403, "Please send /start to the Telegram bot before playing."
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
    try:
        result = response.json()
    except ValueError:
        result = {}
    if response.status_code >= 400 or not result.get("ok"):
        raise HTTPException(502, "Telegram API request failed.")
    return result.get("result")


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


def hash_pin(pin, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", pin.encode("utf-8"), salt, PIN_ITERATIONS
    )
    return salt.hex(), digest.hex()


def pin_matches(pin, salt_hex, expected_hash):
    _, candidate = hash_pin(pin, salt_hex)
    return hmac.compare_digest(candidate, expected_hash)


class SignupInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    phone: str = Field(default="", max_length=32)
    pin: str = Field(min_length=4, max_length=4, pattern=r"^[0-9]{4}$")
    telegram_init_data: str = Field(default="", max_length=10000)


class LoginInput(BaseModel):
    name: str = Field(default="", max_length=80)
    pin: str = Field(min_length=4, max_length=4, pattern=r"^[0-9]{4}$")
    telegram_init_data: str = Field(default="", max_length=10000)


def auth_player_response(player):
    return {
        "name": player.get("display_name") or player.get("first_name") or "Player",
        "phone": player.get("phone", ""),
        "telegram_id": player["telegram_id"],
        "referral_code": player.get("referral_code", ""),
        "mode": "DEMO",
        "payments_enabled": False,
    }


@app.get("/", include_in_schema=False)
async def home():
    index_file = STATIC_DIR / "index.html"
    if not index_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="Game page missing: static/index.html"
        )
    return FileResponse(str(index_file))


@app.get("/health")
async def health():
    return {"ok": True, "mode": "DEMO", "payments_enabled": False}


@app.post("/api/auth/signup")
async def auth_signup(body: SignupInput, request: Request):
    # Only Telegram-signed Mini App data can bind this account to a Telegram ID.
    user = request_telegram_user(request, body.telegram_init_data)
    telegram_id = str(user["id"])
    display_name = body.name.strip()
    if not display_name:
        raise HTTPException(422, "Enter your name.")

    # Create the Telegram-linked player row if /start has not created it yet.
    register_user(user)

    salt, pin_hash = hash_pin(body.pin)
    with connect_db() as conn:
        player = conn.execute(
            "SELECT * FROM players WHERE telegram_id = ?",
            (telegram_id,)
        ).fetchone()

        if player["pin_hash"]:
            raise HTTPException(
                409,
                "This Telegram account already has a PIN. Please log in."
            )

        conn.execute("""
            UPDATE players
            SET display_name = ?, phone = ?, pin_salt = ?, pin_hash = ?,
                failed_pin_attempts = 0, pin_lock_until = 0
            WHERE telegram_id = ?
        """, (
            display_name[:80],
            body.phone.strip()[:32],
            salt,
            pin_hash,
            telegram_id,
        ))
        updated = dict(conn.execute(
            "SELECT * FROM players WHERE telegram_id = ?",
            (telegram_id,)
        ).fetchone())

    return {
        "ok": True,
        "player": auth_player_response(updated),
        "mode": "DEMO",
        "payments_enabled": False,
    }


@app.post("/api/auth/login")
async def auth_login(body: LoginInput, request: Request):
    user = request_telegram_user(request, body.telegram_init_data)
    telegram_id = str(user["id"])
    now = int(time.time())
    failure_status = None
    updated = None

    with connect_db() as conn:
        player = conn.execute(
            "SELECT * FROM players WHERE telegram_id = ?",
            (telegram_id,)
        ).fetchone()

        if not player or not player["pin_hash"]:
            raise HTTPException(
                401,
                "No PIN account found for this Telegram account. Please sign up first."
            )

        if int(player["pin_lock_until"] or 0) > now:
            wait_seconds = int(player["pin_lock_until"]) - now
            raise HTTPException(
                429,
                f"Too many incorrect PIN attempts. Try again in about "
                f"{max(1, (wait_seconds + 59) // 60)} minute(s)."
            )

        if not pin_matches(body.pin, player["pin_salt"], player["pin_hash"]):
            attempts = int(player["failed_pin_attempts"] or 0) + 1
            lock_until = now + PIN_LOCK_SECONDS if attempts >= MAX_PIN_ATTEMPTS else 0
            conn.execute("""
                UPDATE players
                SET failed_pin_attempts = ?, pin_lock_until = ?
                WHERE telegram_id = ?
            """, (attempts, lock_until, telegram_id))
            failure_status = 429 if lock_until else 401
        else:
            conn.execute("""
                UPDATE players
                SET failed_pin_attempts = 0, pin_lock_until = 0
                WHERE telegram_id = ?
            """, (telegram_id,))
            updated = dict(conn.execute(
                "SELECT * FROM players WHERE telegram_id = ?",
                (telegram_id,)
            ).fetchone())

    # Raise only after leaving the DB context, so failed attempts are committed.
    if failure_status == 429:
        raise HTTPException(
            429, "Too many incorrect PIN attempts. Try again in 15 minutes."
        )
    if failure_status == 401:
        raise HTTPException(401, "Incorrect PIN.")

    return {
        "ok": True,
        "player": auth_player_response(updated),
        "mode": "DEMO",
        "payments_enabled": False,
    }


@app.get("/api/me")
async def api_me(request: Request):
    _, player = registered_player(request)
    return {
        "ok": True,
        "user": {
            "first_name": player["first_name"],
            "last_name": player["last_name"],
            "username": player["username"],
            "referral_code": player["referral_code"],
            "name": player.get("display_name") or player["first_name"],
            "phone": player.get("phone", ""),
        },
        "mode": "DEMO",
        "payments_enabled": False,
    }


class TicketInput(BaseModel):
    game_id: str = Field(min_length=1, max_length=24)
    digits: list[int] = Field(min_length=6, max_length=6)


@app.post("/api/demo-ticket")
async def demo_ticket(body: TicketInput, request: Request):
    _, player = registered_player(request)

    if body.game_id not in GAMES:
        raise HTTPException(status_code=422, detail="Unknown game.")
    if len(body.digits) != 6:
        raise HTTPException(status_code=422, detail="Enter exactly six digits.")
    if any(n < 0 or n > 9 for n in body.digits):
        raise HTTPException(status_code=422, detail="Digits must be from 0 to 9.")

    # Demo ticket costs follow the game prices shown in the player app.
    # Games without a published price use a 50 demo-birr ticket cost.
    ticket_cost = {"daily": 100, "weekly": 50, "monthly": 50}.get(body.game_id, 50)
    digits_json = json.dumps(body.digits, separators=(",", ":"))
    ticket_id = "DEMO-" + secrets.token_hex(4).upper()
    now = int(time.time())

    try:
        with connect_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO demo_wallets (telegram_id, balance_birr, updated_at) VALUES (?, 0, ?) ON CONFLICT(telegram_id) DO NOTHING",
                (player["telegram_id"], now),
            )
            # The same six-digit number may be used once in each game, globally.
            duplicate = conn.execute(
                "SELECT ticket_id FROM demo_tickets WHERE game_id = ? AND digits_json = ? LIMIT 1",
                (body.game_id, digits_json),
            ).fetchone()
            if duplicate:
                raise HTTPException(
                    status_code=409,
                    detail="That number has already been taken in this game. Choose another number. The number may still be available in a different game.",
                )

            wallet = conn.execute(
                "SELECT balance_birr FROM demo_wallets WHERE telegram_id = ?",
                (player["telegram_id"],),
            ).fetchone()
            if not wallet or wallet["balance_birr"] < ticket_cost:
                balance = wallet["balance_birr"] if wallet else 0
                raise HTTPException(
                    status_code=402,
                    detail=f"Insufficient demo balance. This {body.game_id.title()} Loto ticket costs {ticket_cost} demo ETB and your balance is {balance}. Please request a demo deposit and wait for admin approval before choosing a ticket number.",
                )

            conn.execute(
                "UPDATE demo_wallets SET balance_birr = balance_birr - ?, updated_at = ? WHERE telegram_id = ?",
                (ticket_cost, now, player["telegram_id"]),
            )
            conn.execute("""
                INSERT INTO demo_tickets
                    (ticket_id, telegram_id, game_id, digits_json, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (ticket_id, player["telegram_id"], body.game_id, digits_json, now))
            conn.execute("""
                INSERT INTO demo_wallet_ledger
                    (ledger_id, telegram_id, entry_type, amount_birr, reference, created_at, note)
                VALUES (?, ?, 'DEMO_TICKET_PURCHASE', ?, ?, ?, ?)
            """, (
                "LED-" + secrets.token_hex(6).upper(), player["telegram_id"],
                -ticket_cost, "ticket:" + ticket_id, now,
                f"{body.game_id.title()} Loto demo ticket {''.join(map(str, body.digits))}",
            ))
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="That number has already been taken in this game. Choose another number.",
        )

    return {
        "ok": True,
        "ticket_id": ticket_id,
        "digits": "".join(map(str, body.digits)),
        "game_id": body.game_id,
        "cost_birr": ticket_cost,
        "message": f"Demo ticket saved. {ticket_cost} demo ETB deducted from your demo wallet. No real payment taken.",
        "mode": "DEMO",
        "payments_enabled": False,
    }


class DemoPaymentInput(BaseModel):
    method: str = Field(pattern=r"^(telebirr|cbe)$")
    reference: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9._/-]+$")
    amount_birr: int = Field(gt=0, le=1000000)
    game_id: str = Field(min_length=1, max_length=24)


class DemoPaymentReviewInput(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    note: str = Field(default="", max_length=300)


def require_admin(request: Request):
    if not ADMIN_TOKEN:
        raise HTTPException(503, "ADMIN_TOKEN is not configured in Render.")
    supplied = request.headers.get("X-Admin-Token", "")
    if not supplied or not hmac.compare_digest(supplied, ADMIN_TOKEN):
        raise HTTPException(401, "Invalid admin token.")


@app.post("/api/demo-payments")
async def create_demo_payment(body: DemoPaymentInput, request: Request):
    # Simulation-only workflow; it does not verify or collect real money.
    _, player = registered_player(request)
    if body.game_id not in GAMES:
        raise HTTPException(422, "Unknown game.")
    reference = body.reference.strip()
    payment_id = "DEMO-PAY-" + secrets.token_hex(5).upper()
    try:
        with connect_db() as conn:
            conn.execute("""
                INSERT INTO demo_payment_requests
                (payment_id, telegram_id, method, reference, amount_birr,
                 game_id, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?)
            """, (payment_id, player["telegram_id"], body.method, reference,
                  body.amount_birr, body.game_id, int(time.time())))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That test reference was already submitted.")
    return {"ok": True, "payment_id": payment_id, "status": "PENDING",
            "message": "Demo submission queued for manual-review testing. No money was collected or verified.",
            "mode": "DEMO", "payments_enabled": False}


@app.get("/api/my-demo-payments")
async def my_demo_payments(request: Request):
    _, player = registered_player(request)
    with connect_db() as conn:
        rows = conn.execute("""
            SELECT payment_id, method, reference, amount_birr, game_id,
                   status, created_at, reviewed_at, admin_note
            FROM demo_payment_requests WHERE telegram_id = ?
            ORDER BY created_at DESC LIMIT 50
        """, (player["telegram_id"],)).fetchall()
    return {"ok": True, "payments": [dict(row) for row in rows],
            "mode": "DEMO", "payments_enabled": False}


@app.get("/api/admin/demo-payments")
async def admin_list_demo_payments(request: Request):
    require_admin(request)
    with connect_db() as conn:
        rows = conn.execute("""
            SELECT p.payment_id, p.telegram_id, p.method, p.reference,
                   p.amount_birr, p.game_id, p.status, p.created_at,
                   p.reviewed_at, p.admin_note,
                   COALESCE(NULLIF(u.display_name, ''), u.first_name, 'Player') AS player_name
            FROM demo_payment_requests p
            LEFT JOIN players u ON u.telegram_id = p.telegram_id
            ORDER BY CASE p.status WHEN 'PENDING' THEN 0 ELSE 1 END,
                     p.created_at DESC LIMIT 500
        """).fetchall()
    return {"ok": True, "payments": [dict(row) for row in rows],
            "mode": "DEMO", "payments_enabled": False}


@app.post("/api/admin/demo-payments/{payment_id}/review")
async def admin_review_demo_payment(payment_id: str, body: DemoPaymentReviewInput,
                                    request: Request):
    require_admin(request)
    decision = "APPROVED_DEMO" if body.decision == "approve" else "REJECTED_DEMO"
    now = int(time.time())
    with connect_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT payment_id, telegram_id, amount_birr, status FROM demo_payment_requests WHERE payment_id = ?",
            (payment_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Demo submission not found.")
        if row["status"] != "PENDING":
            raise HTTPException(409, "This submission has already been reviewed.")
        conn.execute("UPDATE demo_payment_requests SET status = ?, reviewed_at = ?, admin_note = ? WHERE payment_id = ? AND status = 'PENDING'",
                     (decision, now, body.note.strip(), payment_id))
        if decision == "APPROVED_DEMO":
            conn.execute("INSERT INTO demo_wallets (telegram_id, balance_birr, updated_at) VALUES (?, 0, ?) ON CONFLICT(telegram_id) DO NOTHING", (row["telegram_id"], now))
            conn.execute("UPDATE demo_wallets SET balance_birr = balance_birr + ?, updated_at = ? WHERE telegram_id = ?",
                         (row["amount_birr"], now, row["telegram_id"]))
            conn.execute("INSERT INTO demo_wallet_ledger (ledger_id, telegram_id, entry_type, amount_birr, reference, created_at, note) VALUES (?, ?, 'DEMO_DEPOSIT', ?, ?, ?, ?)",
                         ("LED-" + secrets.token_hex(6).upper(), row["telegram_id"], row["amount_birr"], "deposit:" + payment_id, now, "Admin-approved simulated deposit"))
    try:
        message = (f"⭐ Ethiopia Lucky Star demo deposit {decision.lower().replace('_', ' ')}. "
                   + (f"{row['amount_birr']} demo ETB was added to your demo wallet." if decision == "APPROVED_DEMO" else "No wallet credit was added.")
                   + " This is a simulation only; no real payment was verified.")
        await telegram_call("sendMessage", {"chat_id": row["telegram_id"], "text": message})
    except Exception:
        pass
    return {"ok": True, "payment_id": payment_id, "status": decision,
            "message": "Demo status updated. Approval adds simulated demo balance only; no real transfer was verified.",
            "mode": "DEMO", "payments_enabled": False}


@app.get("/api/wallet")
async def get_demo_wallet(request: Request):
    _, player = registered_player(request)
    with connect_db() as conn:
        conn.execute("INSERT INTO demo_wallets (telegram_id, balance_birr, updated_at) VALUES (?, 0, ?) ON CONFLICT(telegram_id) DO NOTHING", (player["telegram_id"], int(time.time())))
        wallet = conn.execute("SELECT balance_birr, updated_at FROM demo_wallets WHERE telegram_id = ?", (player["telegram_id"],)).fetchone()
        ledger = conn.execute("SELECT ledger_id, entry_type, amount_birr, reference, created_at, note FROM demo_wallet_ledger WHERE telegram_id = ? ORDER BY created_at DESC LIMIT 30", (player["telegram_id"],)).fetchall()
    return {"ok": True, "balance_birr": wallet["balance_birr"], "ledger": [dict(row) for row in ledger], "mode": "DEMO", "payments_enabled": False}


class DemoWithdrawalInput(BaseModel):
    amount_birr: int = Field(gt=0, le=1000000)

class DemoWithdrawalReviewInput(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    note: str = Field(default="", max_length=300)

@app.post("/api/withdrawals")
async def create_demo_withdrawal(body: DemoWithdrawalInput, request: Request):
    _, player = registered_player(request)
    now = int(time.time())
    request_id = "DEMO-WD-" + secrets.token_hex(5).upper()
    with connect_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO demo_wallets (telegram_id, balance_birr, updated_at) VALUES (?, 0, ?) ON CONFLICT(telegram_id) DO NOTHING", (player["telegram_id"], now))
        wallet = conn.execute("SELECT balance_birr FROM demo_wallets WHERE telegram_id = ?", (player["telegram_id"],)).fetchone()
        if body.amount_birr > wallet["balance_birr"]:
            raise HTTPException(400, "Insufficient demo wallet balance.")
        conn.execute("UPDATE demo_wallets SET balance_birr = balance_birr - ?, updated_at = ? WHERE telegram_id = ?", (body.amount_birr, now, player["telegram_id"]))
        conn.execute("INSERT INTO demo_withdrawals (request_id, telegram_id, amount_birr, status, created_at) VALUES (?, ?, ?, 'PENDING', ?)", (request_id, player["telegram_id"], body.amount_birr, now))
        conn.execute("INSERT INTO demo_wallet_ledger (ledger_id, telegram_id, entry_type, amount_birr, reference, created_at, note) VALUES (?, ?, 'DEMO_WITHDRAWAL_HOLD', ?, ?, ?, ?)", ("LED-" + secrets.token_hex(6).upper(), player["telegram_id"], -body.amount_birr, "withdrawal-hold:" + request_id, now, "Reserved for simulated withdrawal request"))
    try:
        await telegram_call("sendMessage", {"chat_id": player["telegram_id"], "text": f"Your Ethiopia Lucky Star demo withdrawal request for {body.amount_birr} demo ETB was submitted for review. No real money will be sent."})
    except Exception:
        pass
    return {"ok": True, "request_id": request_id, "status": "PENDING", "message": "Demo withdrawal request submitted. No real payout will be made.", "mode": "DEMO", "payments_enabled": False}

@app.get("/api/my-withdrawals")
async def my_demo_withdrawals(request: Request):
    _, player = registered_player(request)
    with connect_db() as conn:
        rows = conn.execute("SELECT request_id, amount_birr, status, created_at, reviewed_at, admin_note FROM demo_withdrawals WHERE telegram_id = ? ORDER BY created_at DESC LIMIT 50", (player["telegram_id"],)).fetchall()
    return {"ok": True, "withdrawals": [dict(row) for row in rows], "mode": "DEMO", "payments_enabled": False}

@app.get("/api/admin/withdrawals")
async def admin_list_demo_withdrawals(request: Request):
    require_admin(request)
    with connect_db() as conn:
        rows = conn.execute("SELECT w.request_id, w.telegram_id, w.amount_birr, w.status, w.created_at, w.reviewed_at, w.admin_note, COALESCE(NULLIF(p.display_name, ''), p.first_name, 'Player') AS player_name FROM demo_withdrawals w LEFT JOIN players p ON p.telegram_id = w.telegram_id ORDER BY CASE w.status WHEN 'PENDING' THEN 0 ELSE 1 END, w.created_at DESC LIMIT 500").fetchall()
    return {"ok": True, "withdrawals": [dict(row) for row in rows], "mode": "DEMO", "payments_enabled": False}

@app.post("/api/admin/withdrawals/{request_id}/review")
async def admin_review_demo_withdrawal(request_id: str, body: DemoWithdrawalReviewInput, request: Request):
    require_admin(request)
    decision = "APPROVED_DEMO" if body.decision == "approve" else "REJECTED_DEMO"
    now = int(time.time())
    with connect_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT request_id, telegram_id, amount_birr, status FROM demo_withdrawals WHERE request_id = ?", (request_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Demo withdrawal request not found.")
        if row["status"] != "PENDING":
            raise HTTPException(409, "This withdrawal has already been reviewed.")
        conn.execute("UPDATE demo_withdrawals SET status = ?, reviewed_at = ?, admin_note = ? WHERE request_id = ? AND status = 'PENDING'", (decision, now, body.note.strip(), request_id))
        if decision == "REJECTED_DEMO":
            conn.execute("UPDATE demo_wallets SET balance_birr = balance_birr + ?, updated_at = ? WHERE telegram_id = ?", (row["amount_birr"], now, row["telegram_id"]))
            conn.execute("INSERT INTO demo_wallet_ledger (ledger_id, telegram_id, entry_type, amount_birr, reference, created_at, note) VALUES (?, ?, 'DEMO_WITHDRAWAL_REFUND', ?, ?, ?, ?)", ("LED-" + secrets.token_hex(6).upper(), row["telegram_id"], row["amount_birr"], "withdrawal-refund:" + request_id, now, "Refunded reserved demo balance after rejection"))
    try:
        await telegram_call("sendMessage", {"chat_id": row["telegram_id"], "text": f"Your Ethiopia Lucky Star demo withdrawal {decision.lower().replace('_', ' ')} for {row['amount_birr']} demo ETB. " + ("The reserved demo balance has been returned to your wallet." if decision == "REJECTED_DEMO" else "This is only a simulated approval; no money was sent.")})
    except Exception:
        pass
    return {"ok": True, "request_id": request_id, "status": decision, "message": "Demo withdrawal reviewed; no real payout occurred.", "mode": "DEMO", "payments_enabled": False}


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
                "Open the game to create your PIN. Payments and cash prizes "
                "are disabled in this demo."
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
