import os, json, hmac, hashlib, urllib.parse, sqlite3, secrets, time, asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.getenv('DATABASE_PATH', str(BASE_DIR / 'lucky_star.db'))
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '').strip()
WEBAPP_URL = os.getenv('WEBAPP_URL', '').strip().rstrip('/')
DEMO_MODE = os.getenv('DEMO_MODE', 'true').lower() == 'true'
PAYMENTS_ENABLED = False  # Intentionally hard-disabled in this starter project.
_bot_app = None

GAMES = [
    {'id':'daily','name':'Daily Loto','emoji':'☀️','price':100,'draw':'Daily · closes 6:00 PM','prize':'30,000 birr demo target','detail':'Fast daily demo draw. Proposed schedule: morning opening, 6:00 PM closing.'},
    {'id':'weekly','name':'Weekly Loto','emoji':'📅','price':50,'draw':'Sunday draw','prize':'50,000 birr demo target','detail':'Weekly Sunday draw concept.'},
    {'id':'monthly','name':'Monthly Loto','emoji':'🌙','price':50,'draw':'Monthly draw','prize':'100,000 birr demo target','detail':'Monthly draw concept.'},
    {'id':'holiday','name':'Holiday Loto','emoji':'🎉','price':50,'draw':'Ethiopian holiday calendar','prize':'Gifts and experiences','detail':'Concept prizes: holiday food gifts, concert tickets, vacations and other gifts.'},
    {'id':'jemaw','name':'Jemaw Loto','emoji':'🎁','price':50,'draw':'Friendship gifts','prize':'Gadgets and souvenirs','detail':'A friendship gifting concept with shareable demo numbers and QR-style invitations.'},
    {'id':'lebet','name':'Le Bet Loto','emoji':'🏠','price':50,'draw':'Limited-ticket concept','prize':'Home accessories','detail':'Concept prizes: freezer, juicer, oven and other household items. Each draw can have a configured ticket cap.'},
]

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.execute('''CREATE TABLE IF NOT EXISTS users (
        telegram_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, registered_at INTEGER NOT NULL,
        referral_code TEXT UNIQUE NOT NULL
    )''')
    con.execute('''CREATE TABLE IF NOT EXISTS demo_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT, telegram_id INTEGER NOT NULL, game_id TEXT NOT NULL,
        digits TEXT NOT NULL, created_at INTEGER NOT NULL
    )''')
    con.commit(); con.close()

def register_user(user):
    con = db()
    existing = con.execute('SELECT * FROM users WHERE telegram_id=?', (user.id,)).fetchone()
    if not existing:
        code = secrets.token_urlsafe(6)[:8].upper()
        con.execute('INSERT INTO users (telegram_id, username, first_name, registered_at, referral_code) VALUES (?,?,?,?,?)',
                    (user.id, user.username or '', user.first_name or '', int(time.time()), code))
        con.commit()
    row = con.execute('SELECT * FROM users WHERE telegram_id=?', (user.id,)).fetchone()
    con.close()
    return dict(row)

def get_user(telegram_id):
    con = db(); row = con.execute('SELECT * FROM users WHERE telegram_id=?', (telegram_id,)).fetchone(); con.close()
    return dict(row) if row else None

def verify_init_data(init_data: str):
    if not BOT_TOKEN or not init_data:
        return None
    try:
        parsed = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))
        received_hash = parsed.pop('hash', None)
        if not received_hash: return None
        auth_date = int(parsed.get('auth_date', '0'))
        if abs(int(time.time()) - auth_date) > 86400: return None
        data_check = '\n'.join(f'{k}={v}' for k,v in sorted(parsed.items()))
        secret_key = hmac.new(b'WebAppData', BOT_TOKEN.encode(), hashlib.sha256).digest()
        expected = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, received_hash): return None
        user_data = json.loads(parsed.get('user', '{}'))
        return user_data if user_data.get('id') else None
    except Exception:
        return None

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    registered = get_user(user.id)
    keyboard = [[InlineKeyboardButton('📝 Register / My account', callback_data='register')]]
    if registered and WEBAPP_URL:
        keyboard.insert(0, [InlineKeyboardButton('⭐ Open Lucky Star Demo', web_app=WebAppInfo(url=WEBAPP_URL))])
    text = ('🇪🇹 *Ethiopia Lucky Star*\n\nWelcome! Register using the button below. After registration, the demo game link will appear here.\n\n'
            '⚠️ Demo version only: no paid tickets, deposits, cash prizes, or payments are enabled.')
    await update.effective_message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')

async def register_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user = query.from_user
    register_user(user)
    rows = []
    if WEBAPP_URL:
        rows.append([InlineKeyboardButton('⭐ Open Lucky Star Demo', web_app=WebAppInfo(url=WEBAPP_URL))])
    rows.append([InlineKeyboardButton('🔄 Refresh menu', callback_data='menu')])
    await query.edit_message_text(
        f'✅ Registration complete, {user.first_name or "player"}!\n\nYour demo account is ready. Use the button below to open the mobile-friendly game.\n\nNo payments or real lottery entries are enabled.',
        reply_markup=InlineKeyboardMarkup(rows))

async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    user = query.from_user; registered = get_user(user.id)
    rows = []
    if registered and WEBAPP_URL:
        rows.append([InlineKeyboardButton('⭐ Open Lucky Star Demo', web_app=WebAppInfo(url=WEBAPP_URL))])
    rows += [[InlineKeyboardButton('📝 Register / My account', callback_data='register')]]
    await query.edit_message_text('🇪🇹 Ethiopia Lucky Star\n\nChoose an option. Demo mode only; payments are disabled.', reply_markup=InlineKeyboardMarkup(rows))

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _bot_app
    init_db()
    if BOT_TOKEN:
        _bot_app = Application.builder().token(BOT_TOKEN).build()
        _bot_app.add_handler(CommandHandler('start', start_command))
        _bot_app.add_handler(CallbackQueryHandler(register_callback, pattern='^register$'))
        _bot_app.add_handler(CallbackQueryHandler(menu_callback, pattern='^menu$'))
        await _bot_app.initialize()
        await _bot_app.start()
        await _bot_app.updater.start_polling(drop_pending_updates=True)
    yield
    if _bot_app:
        await _bot_app.updater.stop()
        await _bot_app.stop()
        await _bot_app.shutdown()

app = FastAPI(title='Ethiopia Lucky Star Demo', lifespan=lifespan)
app.mount('/static', StaticFiles(directory=str(BASE_DIR / 'static')), name='static')

@app.get('/')
async def root():
    return FileResponse(BASE_DIR / 'static' / 'index.html')

@app.get('/health')
async def health():
    return {'ok': True, 'service': 'Ethiopia Lucky Star', 'mode': 'DEMO', 'payments_enabled': False}

@app.get('/api/games')
async def games():
    return {'mode':'DEMO', 'payments_enabled':False, 'games':GAMES}

@app.get('/api/me')
async def me(request: Request):
    data = verify_init_data(request.headers.get('x-telegram-init-data', ''))
    if not data:
        raise HTTPException(status_code=401, detail='Open this game from the registered Telegram bot menu.')
    user = get_user(int(data['id']))
    if not user:
        raise HTTPException(status_code=403, detail='Please register with the Telegram bot first, then reopen the game.')
    return {'registered':True, 'user':{'first_name':user['first_name'], 'username':user['username'], 'referral_code':user['referral_code']}, 'mode':'DEMO'}

@app.post('/api/demo-ticket')
async def create_demo_ticket(request: Request):
    data = verify_init_data(request.headers.get('x-telegram-init-data', ''))
    if not data:
        raise HTTPException(status_code=401, detail='Open this game from the Telegram bot menu.')
    telegram_id = int(data['id'])
    if not get_user(telegram_id):
        raise HTTPException(status_code=403, detail='Register with the Telegram bot first.')
    body = await request.json()
    game_id = str(body.get('game_id',''))
    digits = body.get('digits', [])
    allowed = {g['id'] for g in GAMES}
    if game_id not in allowed or not isinstance(digits, list) or not 1 <= len(digits) <= 6:
        raise HTTPException(status_code=400, detail='Choose a game and 1–6 digits.')
    try: digits = [int(n) for n in digits]
    except Exception: raise HTTPException(status_code=400, detail='Digits must be numbers from 1 to 9.')
    if len(set(digits)) != len(digits) or any(n < 1 or n > 9 for n in digits):
        raise HTTPException(status_code=400, detail='Digits must be unique numbers from 1 to 9.')
    con = db()
    cur = con.execute('INSERT INTO demo_entries (telegram_id, game_id, digits, created_at) VALUES (?,?,?,?)',
                       (telegram_id, game_id, json.dumps(sorted(digits)), int(time.time())))
    con.commit(); entry_id = cur.lastrowid; con.close()
    return {'ok':True, 'mode':'DEMO', 'ticket_id':f'DEMO-{entry_id:06d}', 'game_id':game_id, 'digits':sorted(digits), 'payments_enabled':False,
            'message':'Demo ticket saved. This is not an official lottery entry and has no cash value.'}

@app.get('/telegram/webhook')
async def webhook_info():
    return JSONResponse({'ok':True, 'note':'This starter bot uses Telegram polling. Do not set a webhook URL for this deployment.', 'mode':'DEMO'})
