"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
Version: v8.1 - Lifespan fix + WhatsApp-style tap-to-record audio
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Depends, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import asyncio
import json
import os
import secrets
import base64
import hashlib
import time
import uuid
from typing import Dict, Optional, List
from collections import defaultdict
from pydantic import BaseModel
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
import asyncpg
from asyncpg import create_pool

from pywebpush import WebPushException, webpush
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ========== APP VERSION ==========
APP_VERSION = "v9.0"

# Expose cache version to frontend
CACHE_VERSION = "v9.1"
# ========== VAPID CONFIGURATION ==========
VAPID_PUBLIC_KEY = 'BL0X3NSYm0EbNslkt1afTEkuktGcvLRD4RS0MoWaYw6jEF8Yf9iryvnNBoDm7encOEBI2CPLNmCyYiehnWAbGQU'
VAPID_CLAIMS = {"sub": "mailto:abavandimwe@example.com"}

def get_vapid_private_key():
    try:
        private_key_pem = os.getenv('VAPID_PRIVATE_KEY')
        if private_key_pem:
            return serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
        with open("vapid_private_key.pem", "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    except Exception as e:
        print(f"⚠️ Could not load VAPID private key: {e}")
        return None

# ========== LIFESPAN (replaces deprecated on_event) ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting ABAVANDIMWE...")
    await init_db()
    start_cleanup()
    print("✅ Server ready")
    yield
    print("🛑 Shutting down...")
    if db_pool:
        await db_pool.close()

app = FastAPI(lifespan=lifespan)


# ========== CACHE BUSTING MIDDLEWARE ==========
@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    # Force fresh fetch for HTML, manifest, sw.js
    if (path == "/" or path.endswith(".html")
        or path == "/manifest.json" or path == "/sw.js"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# ========== STATIC FILES ==========
os.makedirs("static/icons", exist_ok=True)
os.makedirs("static/screenshots", exist_ok=True)
app.mount("/icons", StaticFiles(directory="static/icons"), name="icons")
app.mount("/screenshots", StaticFiles(directory="static/screenshots"), name="screenshots")
app.mount("/static/icons", StaticFiles(directory="static/icons"), name="static_icons")

@app.get("/manifest.json")
async def serve_manifest():
    try:
        with open("manifest.json", "r") as f:
            return Response(content=f.read(), media_type="application/json")
    except FileNotFoundError:
        return JSONResponse({"error": "manifest.json not found"}, status_code=404)

@app.get("/sw.js")
async def serve_sw():
    try:
        with open("sw.js", "r") as f:
            return Response(content=f.read(), media_type="text/javascript")
    except FileNotFoundError:
        return JSONResponse({"error": "sw.js not found"}, status_code=404)

@app.get("/offline.html")
async def serve_offline():
    try:
        with open("offline.html", "r") as f:
            return Response(content=f.read(), media_type="text/html")
    except FileNotFoundError:
        return JSONResponse({"error": "offline.html not found"}, status_code=404)

@app.get("/api/version")
async def get_version():
    return {"version": APP_VERSION, "cache": "v9.0"}


# ========== DATABASE ==========
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://neondb_owner:npg_CmR51yqfMxNZ@ep-plain-salad-axxvh942-pooler.c-4.us-east-2.aws.neon.tech/neondb?sslmode=require')
db_pool = None

async def init_db_pool():
    global db_pool
    db_pool = await create_pool(DATABASE_URL, min_size=1, max_size=10, ssl='require')
    return db_pool

async def get_db_connection():
    return await db_pool.acquire()

async def return_db_connection(conn):
    await db_pool.release(conn)

# ========== SECURITY ==========
ADMIN_USERNAME = "Mpc"
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'Mpc@Secure+_+')
ADMIN_PASSWORD_HASH = None

# ========== SESSIONS ==========
sessions: Dict[str, Dict] = {}
SESSION_TIMEOUT = 3600 * 24 * 7

def create_session(username, role, assigned_group=None, group_password=None):
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {
        "username": username, "role": role, "assigned_group": assigned_group,
        "group_password": group_password, "created_at": time.time(),
        "expires_at": time.time() + SESSION_TIMEOUT
    }
    return session_id

def get_session(session_id):
    if session_id not in sessions: return None
    s = sessions[session_id]
    if s["expires_at"] < time.time():
        del sessions[session_id]; return None
    return s

def delete_session(session_id):
    if session_id in sessions: del sessions[session_id]

async def get_session_from_cookie(request):
    sid = request.cookies.get("abavandimwe_session")
    if not sid: raise HTTPException(status_code=401, detail="No session")
    s = get_session(sid)
    if not s: raise HTTPException(status_code=401, detail="Invalid session")
    return s

async def require_admin(request):
    s = await get_session_from_cookie(request)
    if s["role"] != "admin": raise HTTPException(status_code=403, detail="Admin only")
    return s

# ========== CORS ==========
ALLOWED_ORIGINS = [
    "https://abavandimwe.onrender.com",
    "https://abavandimwe-production.up.railway.app",
    "http://localhost:8080", "http://localhost:8000", "http://localhost:3000",
]
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ========== MODELS ==========
class LoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    group_name: str
    group_password: str

class DeleteUserRequest(BaseModel):
    username: str

class DeleteGroupRequest(BaseModel):
    name: str

class DeleteMessageRequest(BaseModel):
    id: int

class SaveDisplayNameRequest(BaseModel):
    username: str
    display_name: str

# ========== PUSH SUBSCRIPTIONS ==========
push_subscriptions: Dict[str, List[Dict]] = defaultdict(list)

async def save_push_subscription(username, subscription):
    for sub in push_subscriptions[username]:
        if sub.get('endpoint') == subscription.get('endpoint'): return
    push_subscriptions[username].append(subscription)

async def get_push_subscriptions(username):
    return push_subscriptions.get(username, [])

async def send_push_notification(subscription, message, badge_count=0):
    pk = get_vapid_private_key()
    if not pk: return False
    try:
        data = json.dumps({"title": "ABAVANDIMWE", "body": message,
                          "badge": "/static/icons/badge-72x72.png", "icon": "/static/icons/icon-192x192.png",
                          "data": {"url": "/"}, "tag": "new-message", "renotify": True, "requireInteraction": True})
        webpush(subscription_info={"endpoint": subscription['endpoint'], "keys": subscription['keys']},
                data=data, vapid_private_key=pk, vapid_claims=VAPID_CLAIMS)
        return True
    except WebPushException as e:
        if "expired" in str(e).lower() or "410" in str(e):
            for u, subs in push_subscriptions.items():
                push_subscriptions[u] = [s for s in subs if s.get('endpoint') != subscription.get('endpoint')]
        return False

async def send_notification_to_group(group_name, sender):
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("SELECT username FROM users WHERE assigned_group = $1 AND username != $2", group_name, sender)
        users = [r['username'] for r in rows]
    finally:
        await return_db_connection(conn)
    for u in users:
        for sub in await get_push_subscriptions(u):
            await send_push_notification(sub, "You have a new message on ABAVANDIMWE.", 1)

# ========== CRYPTO ==========
ph = PasswordHasher()

def generate_salt(): return base64.b64encode(secrets.token_bytes(32)).decode()
def derive_key(pw, salt): return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000, 32)
def hash_password_argon2(pw): return ph.hash(pw)
def verify_password_argon2(pw, h):
    try: ph.verify(h, pw); return True
    except VerificationError: return False

def encrypt(text, password, salt):
    key = derive_key(password, salt)
    enc = bytearray()
    for i, c in enumerate(text.encode()):
        enc.append(c ^ key[i % len(key)])
    return base64.b64encode(secrets.token_bytes(8) + enc).decode()

def decrypt(encrypted, password, salt):
    data = base64.b64decode(encrypted)
    key = derive_key(password, salt)
    dec = bytearray()
    for i, c in enumerate(data[8:]):
        dec.append(c ^ key[i % len(key)])
    return dec.decode()

# ========== RATE LIMITING ==========
login_attempts = defaultdict(list)
login_blocks = {}
message_limits = defaultdict(list)

def check_login_rate_limit(username):
    now = time.time()
    if username in login_blocks and login_blocks[username] > now:
        return False, f"Too many failed attempts. Try again in {int((login_blocks[username] - now) / 60)} minutes."
    login_attempts[username] = [t for t in login_attempts[username] if t > now - 300]
    if len(login_attempts[username]) >= 5:
        login_blocks[username] = now + 900
        login_attempts[username] = []
        return False, "Too many failed attempts. Account blocked for 15 minutes."
    return True, None

def record_failed_login(u): login_attempts[u].append(time.time())
def reset_login_attempts(u):
    if u in login_attempts: login_attempts[u] = []
    if u in login_blocks: del login_blocks[u]

def check_message_rate_limit(u):
    now = time.time()
    message_limits[u] = [t for t in message_limits[u] if t > now - 5]
    if len(message_limits[u]) >= 10: return False
    message_limits[u].append(now); return True

# ========== DATABASE INIT ==========
async def init_db():
    global ADMIN_PASSWORD_HASH
    await init_db_pool()
    conn = await get_db_connection()
    try:
        await conn.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, salt TEXT,
            role TEXT DEFAULT 'user', assigned_group TEXT, display_name TEXT,
            status TEXT, current_group TEXT, last_seen DOUBLE PRECISION,
            created_at DOUBLE PRECISION, login_attempts INTEGER DEFAULT 0,
            locked_until DOUBLE PRECISION)''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY, ciphertext TEXT NOT NULL, group_name TEXT NOT NULL,
            sender TEXT NOT NULL, salt TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL,
            expires_at DOUBLE PRECISION NOT NULL, reply_to INTEGER DEFAULT NULL,
            voice_url TEXT, media_url TEXT, media_type TEXT,
            delivered BOOLEAN DEFAULT FALSE, read_by TEXT[] DEFAULT '{}')''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS groups (
            group_name TEXT PRIMARY KEY, salt TEXT NOT NULL, password_hash TEXT NOT NULL,
            group_password TEXT NOT NULL, created_by TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL)''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS admin_logs (
            id SERIAL PRIMARY KEY, admin_username TEXT NOT NULL, action TEXT NOT NULL,
            target TEXT, details TEXT, created_at DOUBLE PRECISION NOT NULL)''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY, filename TEXT NOT NULL UNIQUE, file_data BYTEA NOT NULL,
            mime_type TEXT NOT NULL, file_size INTEGER, created_at DOUBLE PRECISION,
            expires_at DOUBLE PRECISION, username TEXT, file_type TEXT)''')
        print("[✓] Database ready")
        try:
            cols = await conn.fetch("SELECT column_name FROM information_schema.columns WHERE table_name = 'messages'")
            ex = [c['column_name'] for c in cols]
            if 'voice_url' not in ex: await conn.execute('ALTER TABLE messages ADD COLUMN voice_url TEXT')
            if 'media_url' not in ex: await conn.execute('ALTER TABLE messages ADD COLUMN media_url TEXT')
            if 'media_type' not in ex: await conn.execute('ALTER TABLE messages ADD COLUMN media_type TEXT')
            if 'reply_to' not in ex: await conn.execute('ALTER TABLE messages ADD COLUMN reply_to INTEGER DEFAULT NULL')
            if 'delivered' not in ex: await conn.execute('ALTER TABLE messages ADD COLUMN delivered BOOLEAN DEFAULT FALSE')
            if 'read_by' not in ex: await conn.execute("ALTER TABLE messages ADD COLUMN read_by TEXT[] DEFAULT '{}'")
        except Exception as e: print(f"[!] Migration: {e}")
        try: await conn.execute("DELETE FROM groups WHERE group_name = 'admin' AND created_by != 'Mpc'")
        except: pass
        try: await conn.execute("DELETE FROM messages WHERE group_name = 'admin'")
        except: pass
        row = await conn.fetchrow("SELECT username FROM users WHERE username = $1", ADMIN_USERNAME)
        if not row:
            ADMIN_PASSWORD_HASH = hash_password_argon2(ADMIN_PASSWORD)
            await conn.execute("INSERT INTO users (username, password_hash, salt, role, created_at) VALUES ($1, $2, $3, $4, $5)",
                              ADMIN_USERNAME, ADMIN_PASSWORD_HASH, "admin_salt", "admin", time.time())
            print(f"[✓] Admin created: {ADMIN_USERNAME}")
        else:
            row = await conn.fetchrow("SELECT password_hash FROM users WHERE username = $1", ADMIN_USERNAME)
            ADMIN_PASSWORD_HASH = row[0]
    finally:
        await return_db_connection(conn)




# ========== DATABASE FUNCTIONS ==========
async def log_admin_action(admin_username, action, target, details=""):
    conn = await get_db_connection()
    try:
        await conn.execute("INSERT INTO admin_logs (admin_username, action, target, details, created_at) VALUES ($1, $2, $3, $4, $5)",
                          admin_username, action, target, details, time.time())
    finally: await return_db_connection(conn)

async def get_admin_logs(limit=50):
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("SELECT id, admin_username, action, target, details, created_at FROM admin_logs ORDER BY created_at DESC LIMIT $1", limit)
        return [dict(r) for r in rows]
    finally: await return_db_connection(conn)

async def cleanup_old_messages():
    now = time.time()
    conn = await get_db_connection()
    try: await conn.execute("DELETE FROM messages WHERE created_at < $1 OR expires_at < $2", now - 86400, now)
    finally: await return_db_connection(conn)

async def cleanup_old_files():
    conn = await get_db_connection()
    try: await conn.execute("DELETE FROM files WHERE expires_at < $1", time.time())
    finally: await return_db_connection(conn)

def start_cleanup():
    async def loop():
        while True:
            await asyncio.sleep(3600)
            await cleanup_old_messages()
            await cleanup_old_files()
    asyncio.create_task(loop())

async def authenticate_user(username, password):
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow("SELECT password_hash, role, assigned_group, display_name, locked_until FROM users WHERE username = $1", username)
    finally: await return_db_connection(conn)
    if not row: return None
    if row['locked_until'] and row['locked_until'] > time.time():
        return {"error": f"Account locked. Try again in {int((row['locked_until'] - time.time()) / 60)} minutes."}
    if verify_password_argon2(password, row['password_hash']):
        return {"username": username, "role": row['role'], "assigned_group": row['assigned_group'], "display_name": row['display_name']}
    return None

async def get_group_password(g):
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow("SELECT group_password FROM groups WHERE group_name = $1", g)
        return row[0] if row else None
    finally: await return_db_connection(conn)

async def create_user_with_group(username, password, group_name, group_password):
    conn = await get_db_connection()
    try:
        salt = generate_salt()
        pwh = hash_password_argon2(password)
        row = await conn.fetchrow("SELECT group_password FROM groups WHERE group_name = $1", group_name)
        if row:
            if row['group_password'] != group_password:
                return {"error": "Group password does not match the existing group's password."}
        else:
            await conn.execute("INSERT INTO groups (group_name, salt, password_hash, group_password, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
                              group_name, generate_salt(), hash_password_argon2(group_password), group_password, "admin", time.time())
        await conn.execute("INSERT INTO users (username, password_hash, salt, role, assigned_group, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
                          username, pwh, salt, "user", group_name, time.time())
        return {"success": True}
    except Exception as e: return {"error": str(e)}
    finally: await return_db_connection(conn)

async def save_user_display_name(username, display_name):
    conn = await get_db_connection()
    try: await conn.execute("UPDATE users SET display_name = $1 WHERE username = $2", display_name, username)
    finally: await return_db_connection(conn)

async def delete_user(username):
    if username == ADMIN_USERNAME: return False
    conn = await get_db_connection()
    try:
        result = await conn.execute("DELETE FROM users WHERE username = $1", username)
        return result != "DELETE 0"
    finally: await return_db_connection(conn)

async def get_all_users():
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("SELECT username, role, assigned_group, display_name, status, created_at FROM users ORDER BY created_at DESC")
        return [dict(r) for r in rows]
    finally: await return_db_connection(conn)

async def save_message_with_media(ciphertext, group, sender, salt, reply_to=None, voice_url=None, media_url=None, media_type=None):
    now = time.time()
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow('''INSERT INTO messages (ciphertext, group_name, sender, salt, created_at, expires_at, reply_to, voice_url, media_url, media_type, delivered, read_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, FALSE, '{}') RETURNING id, created_at''',
            ciphertext, group, sender, salt, now, now + 86400, reply_to, voice_url, media_url, media_type)
        return dict(result)
    finally: await return_db_connection(conn)

async def mark_message_delivered(mid):
    conn = await get_db_connection()
    try: await conn.execute("UPDATE messages SET delivered = TRUE WHERE id = $1", mid)
    finally: await return_db_connection(conn)

async def mark_message_read(mid, username):
    conn = await get_db_connection()
    try:
        await conn.execute("UPDATE messages SET read_by = array_append(read_by, $1) WHERE id = $2 AND NOT ($1 = ANY(read_by))", username, mid)
    finally: await return_db_connection(conn)

async def get_messages(group):
    cutoff = time.time() - 86400
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("SELECT * FROM messages WHERE group_name = $1 AND created_at > $2 ORDER BY id ASC", group, cutoff)
        return [dict(r) for r in rows]
    finally: await return_db_connection(conn)

async def get_all_messages(limit=100):
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("SELECT id, sender, group_name, created_at FROM messages ORDER BY created_at DESC LIMIT $1", limit)
        return [dict(r) for r in rows]
    finally: await return_db_connection(conn)

async def delete_message(mid):
    conn = await get_db_connection()
    try:
        result = await conn.execute("DELETE FROM messages WHERE id = $1", mid)
        return result != "DELETE 0"
    finally: await return_db_connection(conn)

async def set_user_status(username, status, group):
    conn = await get_db_connection()
    try: await conn.execute("UPDATE users SET status = $1, current_group = $2, last_seen = $3 WHERE username = $4",
                           status, group, time.time(), username)
    finally: await return_db_connection(conn)

async def get_online_users(group):
    cutoff = time.time() - 120
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("SELECT username FROM users WHERE status = 'online' AND current_group = $1 AND last_seen > $2", group, cutoff)
        return [r[0] for r in rows]
    finally: await return_db_connection(conn)

async def get_group_info(g):
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow("SELECT salt, password_hash FROM groups WHERE group_name = $1", g)
        return dict(row) if row else None
    finally: await return_db_connection(conn)

async def get_all_groups():
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("SELECT group_name, created_by, created_at FROM groups ORDER BY created_at DESC")
        return [dict(r) for r in rows]
    finally: await return_db_connection(conn)

async def delete_group(g):
    conn = await get_db_connection()
    try:
        await conn.execute("DELETE FROM users WHERE assigned_group = $1", g)
        await conn.execute("DELETE FROM messages WHERE group_name = $1", g)
        result = await conn.execute("DELETE FROM groups WHERE group_name = $1", g)
        return result != "DELETE 0"
    finally: await return_db_connection(conn)

async def save_file(filename, data, mime_type, username, file_type='voice'):
    conn = await get_db_connection()
    try:
        await conn.execute('''INSERT INTO files (filename, file_data, mime_type, file_size, created_at, expires_at, username, file_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)''',
            filename, data, mime_type, len(data), time.time(), time.time() + 604800, username, file_type)
    finally: await return_db_connection(conn)

async def get_file_data(filename):
    conn = await get_db_connection()
    try: return await conn.fetchrow("SELECT file_data, mime_type FROM files WHERE filename = $1", filename)
    finally: await return_db_connection(conn)

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self): self.connections = {}
    async def add(self, group, username, ws):
        if group not in self.connections: self.connections[group] = {}
        self.connections[group][username] = ws
    def remove(self, group, username):
        if group in self.connections:
            self.connections[group].pop(username, None)
            if not self.connections[group]: del self.connections[group]
    async def broadcast(self, group, message, exclude=None):
        if group not in self.connections: return
        for username, ws in self.connections[group].items():
            if username != exclude:
                try: await ws.send_json(message)
                except: pass

manager = ConnectionManager()

# ========== API ROUTES ==========
@app.get("/")
async def root(): return HTMLResponse(HTML)

@app.post("/login")
async def login(request: Request, login_data: LoginRequest):
    allowed, message = check_login_rate_limit(login_data.username)
    if not allowed: return JSONResponse(status_code=429, content={"success": False, "message": message})
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow("SELECT password_hash, role, assigned_group, display_name, locked_until FROM users WHERE username = $1", login_data.username)
    finally: await return_db_connection(conn)
    if not row:
        record_failed_login(login_data.username)
        return JSONResponse(status_code=401, content={"success": False, "message": "Invalid credentials"})
    if row['locked_until'] and row['locked_until'] > time.time():
        return JSONResponse(status_code=429, content={"success": False, "message": f"Account locked. Try again in {int((row['locked_until'] - time.time()) / 60)} minutes."})
    if verify_password_argon2(login_data.password, row['password_hash']):
        reset_login_attempts(login_data.username)
        gpass = await get_group_password(row['assigned_group']) if row['assigned_group'] else None
        if not gpass and row['assigned_group']: gpass = login_data.password
        sid = create_session(login_data.username, row['role'], row['assigned_group'], gpass)
        response = JSONResponse({"success": True, "username": login_data.username, "role": row['role'], "display_name": row['display_name']})
        response.set_cookie(key="abavandimwe_session", value=sid, httponly=True, secure=True, samesite="lax", max_age=SESSION_TIMEOUT, path="/")
        return response
    record_failed_login(login_data.username)
    return JSONResponse(status_code=401, content={"success": False, "message": "Invalid credentials"})

@app.post("/gatekeeper")
async def gatekeeper(login_data: LoginRequest):
    user = await authenticate_user(login_data.username, login_data.password)
    if not user:
        record_failed_login(login_data.username)
        return JSONResponse(status_code=401, content={"success": False, "message": "Invalid credentials"})
    if "error" in user: return JSONResponse(status_code=429, content={"success": False, "message": user["error"]})
    if user["role"] == "admin": return JSONResponse(status_code=403, content={"success": False, "message": "Admin cannot access chat"})
    if not user["assigned_group"]: return JSONResponse(status_code=404, content={"success": False, "message": "No group assigned"})
    gpass = await get_group_password(user["assigned_group"]) or login_data.password
    return {"success": True, "username": login_data.username, "assigned_group": user["assigned_group"],
            "assigned_group_password": gpass, "display_name": user.get("display_name")}

@app.post("/save_display_name")
async def save_display_name(data: SaveDisplayNameRequest, request: Request):
    session = await get_session_from_cookie(request)
    if session["username"] != data.username: raise HTTPException(status_code=403)
    await save_user_display_name(data.username, data.display_name)
    return {"success": True}

@app.get("/admin/data")
async def admin_data(request: Request):
    await require_admin(request)
    return {"users": await get_all_users(), "messages": await get_all_messages(),
            "messages_count": len(await get_all_messages()), "groups": await get_all_groups(), "logs": await get_admin_logs()}

@app.post("/admin/create_user")
async def admin_create_user(data: CreateUserRequest, request: Request):
    session = await require_admin(request)
    result = await create_user_with_group(data.username, data.password, data.group_name, data.group_password)
    if result.get("success"):
        await log_admin_action(session["username"], "create_user", data.username, f"Group: {data.group_name}")
        return {"success": True}
    return {"success": False, "error": result.get("error", "Unknown")}

@app.post("/admin/delete_user")
async def admin_delete_user(data: DeleteUserRequest, request: Request):
    session = await require_admin(request)
    if await delete_user(data.username):
        await log_admin_action(session["username"], "delete_user", data.username)
        return {"success": True}
    return {"success": False, "message": "Cannot delete"}

@app.post("/admin/delete_group")
async def admin_delete_group(data: DeleteGroupRequest, request: Request):
    session = await require_admin(request)
    if await delete_group(data.name):
        await log_admin_action(session["username"], "delete_group", data.name)
        return {"success": True}
    return {"success": False, "message": "Not found"}

@app.post("/admin/delete_message")
async def admin_delete_message(data: DeleteMessageRequest, request: Request):
    session = await require_admin(request)
    if await delete_message(data.id):
        await log_admin_action(session["username"], "delete_message", str(data.id))
        return {"success": True}
    return {"success": False, "message": "Not found"}

@app.post("/logout")
async def logout(request: Request):
    sid = request.cookies.get("abavandimwe_session")
    if sid: delete_session(sid)
    response = JSONResponse({"success": True})
    response.delete_cookie("abavandimwe_session")
    return response

@app.post("/api/push/subscribe")
async def subscribe_to_push(request: Request):
    try:
        session = await get_session_from_cookie(request)
        data = await request.json()
        await save_push_subscription(session["username"], data.get("subscription", {}))
        return {"success": True}
    except: return JSONResponse({"success": False}, status_code=401)

@app.get("/api/push/vapid_public_key")
async def get_vapid_public_key(): return {"publicKey": VAPID_PUBLIC_KEY}

@app.post("/api/upload_voice")
async def upload_voice(request: Request, file: UploadFile = File(...)):
    try:
        session = await get_session_from_cookie(request)
        content = await file.read()
        filename = f"{uuid.uuid4()}.webm"
        await save_file(filename, content, 'audio/webm', session['username'], 'voice')
        return {"success": True, "url": f"/api/files/{filename}"}
    except Exception as e: return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.post("/api/upload_media")
async def upload_media(request: Request, file: UploadFile = File(...)):
    try:
        session = await get_session_from_cookie(request)
        content = await file.read()
        ext = file.filename.split('.')[-1] if '.' in file.filename else 'bin'
        filename = f"{uuid.uuid4()}.{ext}"
        mime_type = file.content_type or 'application/octet-stream'
        await save_file(filename, content, mime_type, session['username'], 'media')
        return {"success": True, "url": f"/api/files/{filename}", "type": mime_type}
    except Exception as e: return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.get("/api/files/{filename}")
async def get_file(filename: str):
    row = await get_file_data(filename)
    if not row: raise HTTPException(status_code=404)
    return Response(content=row['file_data'], media_type=row['mime_type'])

@app.get("/health")
async def health(): return {"status": "ok", "system": "ABAVANDIMWE", "version": APP_VERSION}

# ========== WEBSOCKET ==========
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    sid = None
    for item in websocket.headers.get("cookie", "").split(";"):
        item = item.strip()
        if item.startswith("abavandimwe_session="):
            sid = item.split("=")[1]; break
    if not sid:
        await websocket.send_json({'type': 'error', 'message': 'No session'}); await websocket.close(); return
    session = get_session(sid)
    if not session:
        await websocket.send_json({'type': 'error', 'message': 'Invalid session'}); await websocket.close(); return
    username = session["username"]
    group_name = session["assigned_group"]
    if not group_name:
        await websocket.send_json({'type': 'error', 'message': 'No group'}); await websocket.close(); return
    group_info = await get_group_info(group_name)
    if not group_info:
        await websocket.send_json({'type': 'error', 'message': 'Group not found'}); await websocket.close(); return
    await manager.add(group_name, username, websocket)
    await set_user_status(username, 'online', group_name)
    await websocket.send_json({'type': 'users', 'users': await get_online_users(group_name)})
    messages = await get_messages(group_name)
    history = []
    for m in messages:
        history.append({'id': m['id'], 'ciphertext': m['ciphertext'], 'sender': m['sender'], 'salt': m['salt'],
                       'timestamp': m['created_at'], 'reply_to': m.get('reply_to'), 'voice_url': m.get('voice_url'),
                       'media_url': m.get('media_url'), 'media_type': m.get('media_type'),
                       'delivered': m.get('delivered', False), 'read_by': m.get('read_by', [])})
    await websocket.send_json({'type': 'history', 'messages': history})
    await manager.broadcast(group_name, {'type': 'user_joined', 'user': username}, exclude=username)
    await websocket.send_json({'type': 'ready', 'salt': group_info['salt'], 'group': group_name})
    print(f"[+] {username} joined {group_name}")
    try:
        while True:
            data = await websocket.receive_json()
            t = data.get('type')
            if t == 'message':
                if check_message_rate_limit(username):
                    r = await save_message_with_media(data.get('ciphertext'), group_name, username, data.get('salt'),
                        data.get('reply_to'), data.get('voice_url'), data.get('media_url'), data.get('media_type'))
                    asyncio.create_task(send_notification_to_group(group_name, username))
                    msg = {'type': 'message', 'message_id': r['id'], 'ciphertext': data.get('ciphertext'),
                          'sender': username, 'salt': data.get('salt'), 'timestamp': r['created_at'],
                          'reply_to': data.get('reply_to'), 'voice_url': data.get('voice_url'),
                          'media_url': data.get('media_url'), 'media_type': data.get('media_type'),
                          'delivered': False, 'read_by': []}
                    if data.get('temp_id'): msg['temp_id'] = data.get('temp_id')
                    await manager.broadcast(group_name, msg)
            elif t == 'delivered':
                mid = data.get('message_id')
                if mid:
                    await mark_message_delivered(mid)
                    await manager.broadcast(group_name, {'type': 'message_delivered', 'message_id': mid, 'user': username})
            elif t == 'read':
                mid = data.get('message_id')
                if mid:
                    await mark_message_read(mid, username)
                    await manager.broadcast(group_name, {'type': 'message_read', 'message_id': mid, 'user': username})
            elif t == 'typing':
                await manager.broadcast(group_name, {'type': 'typing', 'user': username}, exclude=username)
            elif t == 'stop_typing':
                await manager.broadcast(group_name, {'type': 'stop_typing', 'user': username}, exclude=username)
            elif t == 'ping':
                await set_user_status(username, 'online', group_name)
                await websocket.send_json({'type': 'pong'})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[!] WS error: {e}")
    finally:
        manager.remove(group_name, username)
        await set_user_status(username, 'offline', group_name)
        await manager.broadcast(group_name, {'type': 'users', 'users': await get_online_users(group_name)})
        await manager.broadcast(group_name, {'type': 'user_left', 'user': username})
        print(f"[-] {username} left {group_name}")





# ========== HTML (embedded) ==========
HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, viewport-fit=cover">
<title>ABAVANDIMWE | Secure Messaging</title>
<link rel="manifest" href="/manifest.json">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#0a0a0f">
<link rel="icon" type="image/png" sizes="192x192" href="/icons/icon-192x192.png">
<link rel="apple-touch-icon" href="/icons/icon-192x192.png">
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
html,body{width:100%;height:100%;overflow:hidden;background:#0a0a0f;font-family:monospace;color:#0f0;}

/* UPDATE BANNER */
.update-banner{position:fixed;top:0;left:0;right:0;background:linear-gradient(90deg,#ffaa00,#ff6600);color:#000;text-align:center;padding:12px;font-size:13px;font-weight:bold;z-index:999999;display:none;cursor:pointer;box-shadow:0 4px 20px rgba(255,170,0,0.5);}
.update-banner.show{display:block;}

/* LOGIN */
.login-container{position:fixed;inset:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;padding:20px;}
.login-card{background:#050508;border:2px solid #0f0;border-radius:24px;padding:32px 24px;width:100%;max-width:420px;}
.login-card-inner{background:#050508;padding:32px 24px;border-radius:22px;}
h1{text-align:center;margin-bottom:4px;font-size:28px;letter-spacing:2px;}
.sub{text-align:center;margin-bottom:12px;font-size:11px;color:#666;}
.admin-badge{text-align:center;margin-bottom:20px;font-size:10px;color:#0f0;border:1px solid #0f0;padding:4px 12px;display:inline-block;border-radius:20px;}
input{width:100%;padding:14px;margin:10px 0;background:#111;border:1px solid #0f0;border-radius:12px;color:#0f0;font-family:monospace;font-size:15px;outline:none;}
input:focus{box-shadow:0 0 20px rgba(0,255,65,0.2);}
input::placeholder{color:#444;}
button{width:100%;padding:14px;margin-top:20px;background:transparent;border:2px solid #0f0;border-radius:12px;color:#0f0;font-size:16px;font-weight:bold;cursor:pointer;transition:all 0.3s;}
button:hover{background:#0f0;color:#000;}
.btn-whatsapp{background:#25D366;border-color:#25D366;color:white;margin-top:12px;}
.error-message{color:#ff4444;font-size:12px;text-align:center;margin-top:12px;display:none;}
.success-message{color:#0f0;font-size:12px;text-align:center;margin-top:12px;display:none;}
.login-footer{text-align:center;margin-top:20px;font-size:9px;color:#333;border-top:1px solid #1a1a2e;padding-top:16px;}

/* ADMIN / GATEKEEPER / SETUP */
.admin-panel{display:none;position:fixed;inset:0;background:#0a0a0f;z-index:50;padding:20px;overflow-y:auto;}
.admin-panel.active{display:block;}
.admin-panel-header{display:flex;justify-content:space-between;align-items:center;padding:16px;border-bottom:2px solid #0f0;margin-bottom:20px;}
.admin-panel-header h2{color:#ffaa00;}
.admin-content{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;}
.admin-card{background:#050508;border:1px solid #0f0;border-radius:12px;padding:20px;}
.admin-card h3{color:#0f0;margin-bottom:12px;font-size:14px;}
.admin-card table{width:100%;font-size:11px;border-collapse:collapse;}
.admin-card table th{text-align:left;padding:6px;border-bottom:1px solid #1a1a2e;color:#666;}
.admin-card table td{padding:6px;border-bottom:1px solid #1a1a2e;}
.admin-card input{width:100%;padding:8px;margin:5px 0;background:#111;border:1px solid #0f0;border-radius:6px;color:#0f0;font-size:12px;}
.admin-card button{width:auto;padding:8px 16px;margin:5px;font-size:12px;}
.close-admin{background:#ff0041;border-color:#ff0041;color:white;padding:8px 16px;border-radius:8px;cursor:pointer;}
.admin-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px;}
.stat-box{background:#050508;border:1px solid #0f0;border-radius:10px;padding:16px;text-align:center;}
.stat-number{font-size:24px;color:#0f0;}
.stat-label{font-size:10px;color:#666;margin-top:4px;}
.admin-table-wrap{max-height:200px;overflow-y:auto;}
.action-btn{background:transparent;border:1px solid #ff0041;color:#ff0041;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:10px;margin:0 2px;}
.action-btn-green{background:transparent;border:1px solid #0f0;color:#0f0;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:10px;}
.admin-username{color:#ffaa00;font-size:12px;margin-left:10px;}

.gatekeeper-container,.user-setup-container{display:none;position:fixed;inset:0;background:#0a0a0f;z-index:900;padding:20px;justify-content:center;align-items:center;}
.gatekeeper-container.active,.user-setup-container.active{display:flex;}
.gatekeeper-card,.user-setup-card{background:#050508;border:2px solid #0f0;border-radius:24px;padding:32px 24px;width:100%;max-width:420px;}
.gatekeeper-card h2,.user-setup-card h2{text-align:center;margin-bottom:8px;font-size:24px;}
.gatekeeper-card .sub,.user-setup-card .sub{text-align:center;margin-bottom:24px;font-size:11px;color:#666;}
.user-setup-card input[readonly]{opacity:0.7;cursor:not-allowed;}

/* CHAT */
.chat-container{display:none;flex-direction:column;height:100dvh;background:#0a0a0f;}
.chat-container.active{display:flex;}
.chat-header{padding:12px 16px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;align-items:center;flex-shrink:0;min-height:56px;gap:8px;}
.chat-header-left{display:flex;align-items:center;gap:10px;flex:1;min-width:0;}
.chat-header h2{font-size:16px;flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;}
.online-badge{font-size:10px;padding:3px 10px;border:1px solid #0f0;border-radius:20px;background:rgba(0,255,0,0.05);}
.menu-btn,.logout-btn{background:transparent;border:1px solid #0f0;color:#0f0;padding:6px 12px;border-radius:8px;cursor:pointer;width:auto;margin:0;font-size:12px;}
.logout-btn:hover{border-color:#ff0041;color:#ff0041;}
.notification-btn{background:transparent;border:1px solid #0f0;color:#0f0;padding:4px 12px;border-radius:20px;cursor:pointer;font-size:10px;}
.notification-btn.enabled{background:#0f0;color:#000;}
.offline-bar{display:none;background:#ff0041;color:white;text-align:center;padding:4px;font-size:10px;font-weight:bold;flex-shrink:0;}
.offline-bar.active{display:block;}
.offline-bar .reconnect-btn{background:white;color:#ff0041;border:none;padding:1px 10px;border-radius:4px;cursor:pointer;font-weight:bold;font-size:10px;}
.main-content{display:flex;flex:1;min-height:0;position:relative;}
.sidebar{width:260px;background:#050508;border-right:1px solid #0f0;display:flex;flex-direction:column;flex-shrink:0;overflow:hidden;}
.sidebar-header{padding:16px;border-bottom:1px solid #0f0;font-size:14px;font-weight:bold;}
.users-list{flex:1;padding:12px;overflow-y:auto;}
.user-item{padding:10px 12px;margin:6px 0;border:1px solid #0f0;border-radius:10px;display:flex;align-items:center;gap:8px;font-size:13px;}
.user-item::before{content:"●";color:#0f0;font-size:10px;flex-shrink:0;}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:5;}
.overlay.active{display:block;}
@media (max-width:768px){
  .sidebar{position:fixed;left:-260px;top:0;bottom:0;z-index:20;transition:left 0.3s;width:260px;}
  .sidebar.open{left:0;}
}
@media (min-width:769px){.menu-btn,.overlay{display:none;}}

.chat-area{flex:1;display:flex;flex-direction:column;min-width:0;position:relative;
  background-color:#0a0a0f;
  background-image:
    url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='1000' height='1000' viewBox='0 0 1000 1000'><text x='50%25' y='50%25' font-family='monospace' font-size='88' font-weight='bold' fill='rgba(0,255,65,0.10)' text-anchor='middle' dominant-baseline='middle' letter-spacing='8'>ABAVANDIMWE</text></svg>"),
    url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='240' viewBox='0 0 240 240'><g fill='none' stroke='rgba(0,255,65,0.10)' stroke-width='1.6'><circle cx='30' cy='30' r='7'/><path d='M85 22 Q95 12 105 22 Q115 32 105 42 Q95 52 85 42 Q75 32 85 22 Z'/><rect x='130' y='18' width='24' height='16' rx='3'/><path d='M170 30 L195 30 M170 36 L190 36'/><circle cx='45' cy='95' r='5'/><path d='M25 130 L25 155 M30 130 L30 155'/><circle cx='80' cy='105' r='9'/><path d='M68 145 L92 145 L86 168 L74 168 Z'/><path d='M165 95 L190 120 M190 95 L165 120'/><circle cx='110' cy='195' r='6'/><rect x='150' y='170' width='35' height='24' rx='4'/><path d='M35 185 L58 185 M35 191 L52 191'/><path d='M135 65 L160 65 L160 90'/></g></svg>");
  background-repeat:no-repeat,repeat;
  background-position:center center,top left;
  background-size:100% 100%,240px 240px;
}
.messages-container{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px;min-height:0;overscroll-behavior:contain;}
.new-msgs-btn{position:absolute;bottom:100px;left:50%;transform:translateX(-50%);background:#0f0;color:#000;padding:8px 20px;border-radius:30px;font-size:14px;font-weight:bold;cursor:pointer;box-shadow:0 4px 15px rgba(0,255,65,0.4);z-index:30;display:none;border:2px solid #0f0;}
.new-msgs-btn.show{display:block;}

.message{display:flex;flex-direction:column;width:fit-content;max-width:85%;padding:4px 0;word-break:break-word;overflow-wrap:anywhere;animation:fadeIn 0.2s ease;}
.message.sent{align-self:flex-end;margin-left:auto;}
.message.received{align-self:flex-start;margin-right:auto;}
@media (max-width:600px){ .message{max-width:90%;} }
.message-bubble{padding:8px 14px;border-radius:18px;font-size:14px;line-height:1.5;word-wrap:break-word;max-width:100%;}
.sent .message-bubble{background:#0f0;color:#000;border-bottom-right-radius:4px;}
.received .message-bubble{background:#1a1a2e;border:1px solid #0f0;border-bottom-left-radius:4px;}
.message-sender{font-size:9px;opacity:0.7;padding-left:4px;margin-bottom:2px;}
.message-time{font-size:8px;opacity:0.5;margin-top:2px;}
.message-reply-preview{font-size:10px;color:#ffaa00;margin-bottom:4px;padding:4px 8px;background:rgba(255,170,0,0.08);border-left:2px solid #ffaa00;border-radius:4px;cursor:pointer;max-width:100%;}
.message-reply-preview .reply-sender{color:#ffaa00;font-weight:bold;}
.system-message{text-align:center;font-size:10px;color:#ffaa00;margin:4px 0;font-style:italic;}
.typing-indicator{padding:2px 16px 6px;font-size:10px;color:#0f0;font-style:italic;min-height:24px;flex-shrink:0;}

/* VOICE PLAYER (WhatsApp-style) */
.voice-player{display:flex;align-items:center;gap:10px;background:#0f0;padding:6px 10px;border-radius:20px;min-width:200px;max-width:min(90vw,340px);position:relative;}
.received .voice-player{background:#1a1a2e;border:1px solid #0f0;}
.voice-avatar{flex:0 0 34px;width:34px;height:34px;border-radius:50%;background:#0a0a0f;color:#0f0;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:bold;overflow:hidden;}
.received .voice-avatar{background:#0f0;color:#0a0a0f;}
.voice-play-btn{flex:0 0 32px;width:32px;height:32px;border:none;background:transparent;color:#0a0a0f;font-size:22px;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0;}
.received .voice-play-btn{color:#0f0;}
.voice-waveform{flex:1;display:flex;align-items:center;gap:2px;height:24px;cursor:pointer;min-width:80px;overflow:hidden;padding:4px 0;user-select:none;}
.voice-wave-bar{flex:0 0 2px;width:2px;background:#0a0a0f;border-radius:2px;opacity:0.55;}
.received .voice-wave-bar{background:#0f0;}
.voice-wave-bar.played{opacity:1;}
.voice-ball{position:absolute;top:50%;transform:translateY(-50%);width:10px;height:10px;border-radius:50%;background:#0a0a0f;pointer-events:none;left:60px;display:none;}
.received .voice-ball{background:#0f0;}
.voice-player.playing .voice-ball{display:block;}
.voice-info{display:flex;justify-content:space-between;align-items:center;font-size:10px;margin-top:2px;color:#888;padding:0 4px;max-width:min(90vw,340px);}
.voice-duration{color:#0a0a0f;font-weight:bold;}
.sent .voice-info .voice-duration{color:#0f0;}
.voice-time{color:#888;font-size:10px;}
.voice-download{flex:0 0 auto;font-size:14px;color:#0a0a0f;text-decoration:none;margin-left:4px;}
.received .voice-download{color:#0f0;}

/* IMAGE */
.image-bubble{background:#0f0;border-radius:18px;overflow:hidden;border:2px solid #0f0;max-width:100%;display:flex;flex-direction:column;width:fit-content;position:relative;}
.image-bubble img{display:block;width:100%;height:auto;max-height:420px;object-fit:contain;cursor:pointer;background:#111;}
.image-bubble .file-name{padding:6px 10px;font-size:12px;color:#111;background:#0f0;overflow-wrap:anywhere;display:flex;justify-content:space-between;align-items:center;}
.image-bubble .file-name .download-link{color:#0a0a0f;text-decoration:none;font-size:14px;margin-left:8px;}
.image-bubble .spinner{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:40px;height:40px;border:4px solid rgba(0,0,0,0.1);border-top:4px solid #0f0;border-radius:50%;animation:spin 0.8s linear infinite;pointer-events:none;}
@keyframes spin{0%{transform:translate(-50%,-50%) rotate(0);}100%{transform:translate(-50%,-50%) rotate(360deg);}}
.image-bubble.placeholder img{filter:blur(2px);}
.message-actions{display:flex;gap:6px;margin-top:4px;flex-wrap:wrap;align-items:center;}
.message-actions button{background:transparent;border:none;color:#888;font-size:10px;cursor:pointer;padding:1px 4px;}
.message-actions button:hover{color:#0f0;}

/* ========== COMPOSER (with WhatsApp-style tap-to-record) ========== */
.input-area{padding:8px 12px;background:#050508;border-top:1px solid #0f0;flex-shrink:0;display:flex;flex-direction:column;gap:6px;position:relative;}
.reply-preview{display:none;padding:4px 8px;background:rgba(255,170,0,0.1);border-left:2px solid #ffaa00;border-radius:4px;font-size:11px;color:#ffaa00;align-items:center;justify-content:space-between;}
.reply-preview .reply-cancel{color:#ff4444;cursor:pointer;font-weight:bold;padding:0 6px;}
.input-row{display:flex;gap:8px;align-items:flex-end;}
.input-row textarea{flex:1;min-width:0;padding:10px 14px;background:#111;border:1px solid #0f0;border-radius:12px;color:#0f0;font-family:monospace;font-size:14px;resize:vertical;max-height:80px;min-height:44px;line-height:1.5;outline:none;}
.input-row textarea:focus{box-shadow:0 0 20px rgba(0,255,65,0.2);}
.input-row button{flex:0 0 50px;width:50px;height:50px;margin:0;padding:0;border-radius:50%;font-size:18px;border:2px solid #0f0;background:transparent;color:#0f0;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;}
.input-row button:hover{background:rgba(0,255,0,0.1);}
.input-row .send-btn{background:#0f0;color:#000;border-color:#0f0;}

/* ========== RECORDING UI (replaces typing area) ========== */
.recording-row{display:none;align-items:center;gap:10px;padding:6px 4px;background:#050508;border-radius:30px;width:100%;}
.recording-row.active{display:flex;}
.recording-row .rec-delete{flex:0 0 44px;width:44px;height:44px;border-radius:50%;background:rgba(255,0,65,0.15);border:2px solid #ff0041;color:#ff0041;font-size:20px;display:flex;align-items:center;justify-content:center;cursor:pointer;}
.recording-row .rec-main{flex:1;display:flex;align-items:center;gap:10px;background:#1a1a2e;padding:8px 14px;border-radius:24px;min-width:0;}
.recording-row .rec-timer{flex:0 0 auto;font-size:14px;color:#ff0041;font-weight:bold;font-family:monospace;min-width:44px;}
.recording-row .rec-wave{flex:1;display:flex;align-items:center;gap:2px;height:24px;overflow:hidden;min-width:0;}
.recording-row .rec-wave .bar{flex:0 0 3px;width:3px;background:#ff0041;border-radius:2px;height:8px;transition:height 0.08s linear;}
.recording-row .rec-pause{flex:0 0 44px;width:44px;height:44px;border-radius:50%;background:transparent;border:2px solid #ffaa00;color:#ffaa00;font-size:18px;display:flex;align-items:center;justify-content:center;cursor:pointer;}
.recording-row .rec-pause.paused{background:#ffaa00;color:#000;}
.recording-row .rec-send{flex:0 0 52px;width:52px;height:52px;border-radius:50%;background:#0f0;border:2px solid #0f0;color:#000;font-size:22px;display:flex;align-items:center;justify-content:center;cursor:pointer;font-weight:bold;}

/* hidden state */
.hidden{display:none !important;}

.footer{text-align:center;padding:4px 0 2px;font-size:7px;color:#333;border-top:1px solid #1a1a2e;margin-top:4px;}
::-webkit-scrollbar{width:4px;}
::-webkit-scrollbar-track{background:#1a1a2e;}
::-webkit-scrollbar-thumb{background:#0f0;border-radius:2px;}

.install-btn{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:100;padding:14px 28px;background:#0f0;color:#000;border:none;border-radius:14px;font-size:15px;font-weight:bold;cursor:pointer;display:none;box-shadow:0 4px 30px rgba(0,255,65,0.4);}
.install-btn.show{display:block;}

.loading-overlay{position:fixed;inset:0;background:rgba(10,10,15,0.92);z-index:9999;display:none;justify-content:center;align-items:center;flex-direction:column;gap:30px;}
.loading-overlay.active{display:flex;}
.loader{width:60px;height:60px;border:3px solid rgba(0,255,65,0.1);border-top:3px solid #0f0;border-radius:50%;animation:spin 0.8s linear infinite;}
.loader-text{color:#0f0;font-size:16px;letter-spacing:2px;}

.offline-overlay{position:fixed;inset:0;background:#0a0a0f;z-index:99999;display:none;justify-content:center;align-items:center;flex-direction:column;gap:20px;padding:30px;}
.offline-overlay.active{display:flex;}
.offline-overlay h2{color:#ff4444;font-size:24px;text-align:center;}
.offline-overlay p{color:#888;font-size:14px;text-align:center;}
.offline-overlay .retry-btn{background:transparent;border:2px solid #0f0;color:#0f0;padding:14px 40px;border-radius:12px;font-size:16px;font-weight:bold;cursor:pointer;}

.connection-status{position:fixed;bottom:80px;right:16px;padding:6px 12px;background:#050508;border:1px solid #0f0;border-radius:20px;font-size:9px;z-index:40;}
.status-online{color:#0f0;}
.status-offline{color:#ff4444;}
.msg-tick{font-size:11px;margin-left:4px;color:#666;display:inline-block;vertical-align:middle;}
.msg-tick.delivered{color:#888;}
.msg-tick.read{color:#00d4ff;}

@media (max-width:480px){
  .input-row textarea{font-size:13px;padding:8px 12px;min-height:36px;}
  .input-row button{flex-basis:44px;width:44px;height:44px;font-size:16px;}
  .voice-player{min-width:180px;padding:5px 8px;}
  .voice-avatar{flex-basis:30px;width:30px;height:30px;font-size:11px;}
  .message{max-width:90%;}
  .sidebar{width:240px;left:-240px;}
  .recording-row .rec-delete{flex-basis:40px;width:40px;height:40px;}
  .recording-row .rec-pause{flex-basis:40px;width:40px;height:40px;}
  .recording-row .rec-send{flex-basis:48px;width:48px;height:48px;}
}
</style>
</head>
<body>

<!-- UPDATE BANNER -->
<div class="update-banner" id="updateBanner" onclick="applyUpdate()">🚀 New version available! Tap to update</div>

<!-- LOADING -->
<div class="loading-overlay" id="loadingOverlay">
  <div class="loader"></div>
  <div class="loader-text" id="loadingText">Loading...</div>
</div>

<!-- OFFLINE -->
<div class="offline-overlay" id="offlineOverlay">
  <h2>📶 No Internet Connection</h2>
  <p>Please check your network settings and try again.</p>
  <button class="retry-btn" id="retryOfflineBtn">↻ Retry</button>
</div>

<!-- LOGIN -->
<div id="loginScreen" class="login-container">
  <div class="login-card">
    <div class="login-card-inner">
      <h1># ABAVANDIMWE</h1>
      <div class="sub">Secure Messaging System</div>
      <div style="text-align:center;"><span class="admin-badge">🔐 Gatekeeper</span></div>
      <input type="text" id="loginUsername" placeholder="Username" autocomplete="username">
      <input type="password" id="loginPassword" placeholder="Password" autocomplete="current-password">
      <button id="loginBtn">▶ Login</button>
      <button class="btn-whatsapp" onclick="requestAccess()">💬 Request Access on WhatsApp</button>
      <div id="loginError" class="error-message"></div>
      <div class="login-footer">🔒 AES-256 | ⏰ Messages auto-delete after 24 hours<br>Developed by Mugisha Pc</div>
    </div>
  </div>
</div>

<!-- ADMIN PANEL -->
<div id="adminPanel" class="admin-panel">
  <div class="admin-panel-header">
    <h2>⚙️ Admin Dashboard <span class="admin-username">(Logged in as: <span id="adminUsername">Mpc</span>)</span></h2>
    <button class="close-admin" onclick="logout()">🚪 Logout</button>
  </div>
  <div class="admin-stats">
    <div class="stat-box"><div class="stat-number" id="statUsers">0</div><div class="stat-label">Total Users</div></div>
    <div class="stat-box"><div class="stat-number" id="statMessages">0</div><div class="stat-label">Total Messages</div></div>
    <div class="stat-box"><div class="stat-number" id="statGroups">0</div><div class="stat-label">Total Groups</div></div>
  </div>
  <div class="admin-content">
    <div class="admin-card">
      <h3>👤 Create User</h3>
      <input type="text" id="newUsername" placeholder="Username">
      <input type="text" id="newPassword" placeholder="Password">
      <input type="text" id="newGroupName" placeholder="Group Name">
      <input type="text" id="newGroupPassword" placeholder="Group Password">
      <button onclick="createUser()" class="action-btn-green">➕ Create User</button>
    </div>
    <div class="admin-card"><h3>📋 Users</h3>
      <div class="admin-table-wrap"><table><thead><tr><th>User</th><th>Group</th><th>Action</th></tr></thead><tbody id="usersTableBody"></tbody></table></div>
    </div>
    <div class="admin-card"><h3>📁 Groups</h3>
      <div class="admin-table-wrap"><table><thead><tr><th>Group</th><th>By</th><th>Action</th></tr></thead><tbody id="groupsTableBody"></tbody></table></div>
    </div>
    <div class="admin-card"><h3>📨 Messages</h3>
      <div class="admin-table-wrap"><table><thead><tr><th>Sender</th><th>Group</th><th>Action</th></tr></thead><tbody id="messagesTableBody"></tbody></table></div>
    </div>
  </div>
</div>

<!-- GATEKEEPER -->
<div id="gatekeeperScreen" class="gatekeeper-container">
  <div class="gatekeeper-card">
    <h2>🔐 Gatekeeper</h2>
    <div class="sub">Verify your credentials to access your group</div>
    <input type="text" id="gatekeeperUsername" placeholder="Username" readonly>
    <input type="password" id="gatekeeperPassword" placeholder="Password">
    <button id="gatekeeperBtn">▶ Verify</button>
    <div id="gatekeeperError" class="error-message"></div>
  </div>
</div>

<!-- USER SETUP -->
<div id="userSetupScreen" class="user-setup-container">
  <div class="user-setup-card">
    <h2>👤 Setup Profile</h2>
    <div class="sub">Enter your display name to start chatting</div>
    <input type="text" id="userDisplayName" placeholder="Your Display Name">
    <input type="text" id="userGroupName" placeholder="Group Name" readonly>
    <input type="password" id="userGroupPassword" placeholder="Group Password" readonly>
    <button id="enterChatBtn">▶ Enter Chat</button>
    <div id="setupError" class="error-message"></div>
    <div id="setupSuccess" class="success-message"></div>
  </div>
</div>

<!-- CHAT -->
<div id="chatScreen" class="chat-container">
  <div class="chat-header">
    <div class="chat-header-left">
      <button class="menu-btn" onclick="toggleSidebar()">☰</button>
      <span class="online-badge" id="connectionBadge">● Online</span>
      <button class="notification-btn" id="notificationBtn" onclick="toggleNotifications()">🔔 Enable</button>
    </div>
    <h2 id="groupTitle"># LOADING</h2>
    <button class="logout-btn" onclick="logout()">Leave</button>
  </div>
  <div class="offline-bar" id="offlineBar">⚠️ No internet <button class="reconnect-btn" onclick="reconnectManually()">↻ Retry</button></div>
  <div class="main-content">
    <div class="sidebar" id="sidebar">
      <div class="sidebar-header">● Online Users</div>
      <div class="users-list" id="usersList"><div class="user-item">Loading...</div></div>
    </div>
    <div class="overlay" id="overlay" onclick="toggleSidebar()"></div>
    <div class="chat-area">
      <div class="messages-container" id="messages"><div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div></div>
      <div class="new-msgs-btn" id="newMsgsBtn" onclick="scrollToBottom()"><span id="newMsgsCount">0</span> new messages</div>
      <div class="typing-indicator" id="typingIndicator"></div>
      <div class="input-area">
        <div class="reply-preview" id="replyPreview">
          <span>↩️ Replying to <span id="replyPreviewSender" style="color:#ffaa00;font-weight:bold;"></span>: <span id="replyPreviewText" style="color:#888;"></span></span>
          <span class="reply-cancel" onclick="cancelReply()">✕</span>
        </div>

        <!-- NORMAL TYPING ROW -->
        <div class="input-row" id="typingRow">
          <textarea id="messageInput" placeholder="Type a message..." rows="1"></textarea>
          <button id="voiceBtn" onclick="startRecordingTap()"><span id="voiceIcon">🎙️</span></button>
          <button id="mediaBtn" onclick="shareMedia()">📎</button>
          <button class="send-btn" onclick="sendMessage()">➥</button>
        </div>

        <!-- RECORDING ROW (replaces typing row) -->
        <div class="recording-row" id="recordingRow">
          <div class="rec-delete" onclick="cancelRecording()">🗑️</div>
          <div class="rec-main">
            <span class="rec-timer" id="recTimer">0:00</span>
            <div class="rec-wave" id="recWave"></div>
          </div>
          <div class="rec-pause" id="recPauseBtn" onclick="togglePauseRecording()">❚❚</div>
          <div class="rec-send" onclick="sendRecording()">➤</div>
        </div>
      </div>
      <div class="footer">🔐 End-to-End Encrypted | Messages self-destruct after 24 hours</div>
    </div>
  </div>
  <div class="connection-status status-online" id="connectionStatus">🟢 Connected</div>
</div>

<button id="installBtn" class="install-btn">📲 Install ABAVANDIMWE App</button>

<script>
// ==================== GLOBALS ====================
let ws, username, groupName, groupPassword, groupSalt, typingTimeout, reconnectAttempts = 0;
let currentUser = null, gatekeeperData = null, replyingToMessageId = null, messagesData = {};
let isManuallyReconnecting = false, lastActiveScreen = null;
let pushSubscription = null, vapidPublicKey = null, notificationsEnabled = false;

// Recording state
let mediaRecorder = null, audioChunks = [], isRecording = false, recordingSeconds = 0;
let recordingTimerInterval = null, recWaveInterval = null;
let isPaused = false;

// Audio player
let activeAudio = null, activeButton = null, activeProgressBar = null, activeDurationSpan = null;

// UI
let unreadCount = 0, isAtBottom = true;
const deliveredMessages = new Set();
const readMessages = new Set();

// ==================== AUTO-UPDATE ====================
async function checkForUpdates() {
  try {
    const res = await fetch('/api/version', { cache: 'no-store' });
    const data = await res.json();
    const stored = localStorage.getItem('abavandimwe_version');
    if (!stored) { localStorage.setItem('abavandimwe_version', data.version); return; }
    if (stored !== data.version) {
      document.getElementById('updateBanner').classList.add('show');
    }
  } catch(e) {}
}

async function applyUpdate() {
  const banner = document.getElementById('updateBanner');
  banner.textContent = '⏳ Updating...';
  try {
    if ('caches' in window) {
      const names = await caches.keys();
      await Promise.all(names.map(n => caches.delete(n)));
    }
    if ('serviceWorker' in navigator) {
      const regs = await navigator.serviceWorker.getRegistrations();
      for (let r of regs) await r.unregister();
    }
    const res = await fetch('/api/version', { cache: 'no-store' });
    const data = await res.json();
    localStorage.setItem('abavandimwe_version', data.version);
  } catch(e) {}
  window.location.reload(true);
}

window.addEventListener('load', () => { checkForUpdates(); setInterval(checkForUpdates, 60000); });
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') checkForUpdates(); });

// ==================== LOADING / PWA ====================
function showLoading(text, cb) {
  const o = document.getElementById('loadingOverlay');
  document.getElementById('loadingText').textContent = text;
  o.classList.add('active');
  setTimeout(async () => {
    try { await cb(); } catch(e){ console.error(e); }
    finally {
      if (!document.querySelector('.chat-container.active') && !document.querySelector('.admin-panel.active')
        && !document.querySelector('.gatekeeper-container.active') && !document.querySelector('.user-setup-container.active')) {
        setTimeout(() => o.classList.remove('active'), 500);
      }
    }
  }, 300);
}
function hideLoading() { document.getElementById('loadingOverlay').classList.remove('active'); }

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').then(reg => {
      window.swRegistration = reg;
      setInterval(() => reg.update().catch(()=>{}), 60000);
    }).catch(()=>{});
  });
}

let deferredPrompt;
const installBtn = document.getElementById('installBtn');
window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); deferredPrompt = e; installBtn.classList.add('show'); });
installBtn.addEventListener('click', async () => {
  if (deferredPrompt) { deferredPrompt.prompt(); await deferredPrompt.userChoice; deferredPrompt = null; installBtn.classList.remove('show'); }
});
window.addEventListener('appinstalled', () => installBtn.classList.remove('show'));
if (window.matchMedia('(display-mode: standalone)').matches || navigator.standalone) installBtn.classList.remove('show');

// ==================== PUSH ====================
function urlBase64ToUint8Array(b64) {
  const pad = '='.repeat((4 - b64.length % 4) % 4);
  const base64 = (b64 + pad).replace(/-/g,'+').replace(/_/g,'/');
  const raw = window.atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i=0;i<raw.length;i++) out[i]=raw.charCodeAt(i);
  return out;
}
async function getVapidPublicKey() {
  try { const r = await fetch('/api/push/vapid_public_key'); const d = await r.json(); vapidPublicKey = d.publicKey; return vapidPublicKey; } catch(e){ return null; }
}
async function subscribeToPush() {
  if (!window.swRegistration) return false;
  if (!vapidPublicKey) await getVapidPublicKey();
  if (!vapidPublicKey) return false;
  try {
    const sub = await window.swRegistration.pushManager.subscribe({
      userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(vapidPublicKey)
    });
    pushSubscription = sub;
    await fetch('/api/push/subscribe', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ subscription: { endpoint: sub.endpoint, keys: {
        p256dh: btoa(String.fromCharCode.apply(null, new Uint8Array(sub.getKey('p256dh')))),
        auth: btoa(String.fromCharCode.apply(null, new Uint8Array(sub.getKey('auth')))) }}})});
    notificationsEnabled = true; updateNotificationButton(); return true;
  } catch(e){ return false; }
}
async function unsubscribeFromPush() {
  if (!pushSubscription) {
    if (window.swRegistration) { const s = await window.swRegistration.pushManager.getSubscription(); if (s) pushSubscription = s; }
  }
  if (!pushSubscription) return;
  try { await pushSubscription.unsubscribe(); pushSubscription = null; notificationsEnabled = false; updateNotificationButton(); } catch(e){}
}
async function toggleNotifications() {
  if (!('Notification' in window)) { alert('Not supported.'); return; }
  if (notificationsEnabled) { await unsubscribeFromPush(); return; }
  if (Notification.permission === 'denied') { alert('Blocked.'); return; }
  if (Notification.permission === 'default') {
    const p = await Notification.requestPermission();
    if (p !== 'granted') return;
  }
  const ok = await subscribeToPush();
  alert(ok ? '🔔 Enabled!' : '❌ Failed.');
}
function updateNotificationButton() {
  const b = document.getElementById('notificationBtn');
  if (notificationsEnabled) { b.textContent = '🔔 Enabled'; b.classList.add('enabled'); }
  else { b.textContent = '🔔 Enable'; b.classList.remove('enabled'); }
}

// ==================== OFFLINE ====================
const offlineOverlay = document.getElementById('offlineOverlay');
function showOfflineOverlay() {
  const ca = document.getElementById('chatScreen').classList.contains('active');
  const aa = document.getElementById('adminPanel').classList.contains('active');
  const ga = document.getElementById('gatekeeperScreen').classList.contains('active');
  const ua = document.getElementById('userSetupScreen').classList.contains('active');
  const lv = document.getElementById('loginScreen').style.display !== 'none';
  if (ca) lastActiveScreen='chat'; else if (aa) lastActiveScreen='admin';
  else if (ga) lastActiveScreen='gatekeeper'; else if (ua) lastActiveScreen='userSetup';
  else if (lv) lastActiveScreen='login'; else lastActiveScreen=null;
  document.getElementById('loginScreen').style.display = 'none';
  document.getElementById('adminPanel').classList.remove('active');
  document.getElementById('gatekeeperScreen').classList.remove('active');
  document.getElementById('userSetupScreen').classList.remove('active');
  document.getElementById('chatScreen').classList.remove('active');
  document.getElementById('loadingOverlay').classList.remove('active');
  offlineOverlay.classList.add('active');
}
function hideOfflineOverlay() {
  offlineOverlay.classList.remove('active');
  if (lastActiveScreen === 'chat' && window.chatUsername && window.chatGroup) {
    document.getElementById('chatScreen').classList.add('active');
    connectToChat(window.chatUsername, window.chatGroup);
  } else if (lastActiveScreen === 'admin') { document.getElementById('adminPanel').classList.add('active'); loadAdminData(); }
  else if (lastActiveScreen === 'gatekeeper') { document.getElementById('gatekeeperScreen').classList.add('active'); }
  else if (lastActiveScreen === 'userSetup') { document.getElementById('userSetupScreen').classList.add('active'); }
  else { document.getElementById('loginScreen').style.display = 'flex'; }
  lastActiveScreen = null;
}
document.getElementById('retryOfflineBtn').addEventListener('click', function() {
  if (navigator.onLine) hideOfflineOverlay();
  else { this.textContent = '⏳ Still offline...'; setTimeout(()=>this.textContent='↻ Retry', 1000); }
});

// ==================== DOM READY ====================
document.addEventListener('DOMContentLoaded', function() {
  if (!navigator.onLine) showOfflineOverlay();

  document.getElementById('loginBtn').addEventListener('click', () => showLoading('Logging in', login));
  document.getElementById('gatekeeperBtn').addEventListener('click', () => showLoading('Verifying', gatekeeperLogin));
  document.getElementById('enterChatBtn').addEventListener('click', () => showLoading('Entering Chat', enterChat));
  document.getElementById('loginPassword').addEventListener('keypress', e => { if (e.key==='Enter') showLoading('Logging in', login); });
  document.getElementById('gatekeeperPassword').addEventListener('keypress', e => { if (e.key==='Enter') showLoading('Verifying', gatekeeperLogin); });
  document.getElementById('userDisplayName').addEventListener('keypress', e => { if (e.key==='Enter') showLoading('Entering Chat', enterChat); });

  document.getElementById('messageInput').addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 80) + 'px';
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({type:'typing'}));
      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type:'stop_typing'})); }, 1000);
    }
  });

  const mc = document.getElementById('messages');
  mc.addEventListener('scroll', function() {
    const th = 100;
    const ab = (this.scrollHeight - this.scrollTop - this.clientHeight) < th;
    if (ab && !isAtBottom) { isAtBottom = true; unreadCount = 0; updateNewMsgsButton(); }
    else if (!ab && isAtBottom) { isAtBottom = false; }
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && document.getElementById('chatScreen').classList.contains('active')) {
      if (!navigator.onLine) clearMessagesOffline();
      else if (!ws || ws.readyState !== WebSocket.OPEN) { if (window.chatUsername && window.chatGroup) connectToChat(window.chatUsername, window.chatGroup); }
    }
  });

  window.addEventListener('online', () => {
    if (offlineOverlay.classList.contains('active')) {
      if (lastActiveScreen === 'chat' && window.chatUsername && window.chatGroup) {
        offlineOverlay.classList.remove('active');
        document.getElementById('chatScreen').classList.add('active');
        connectToChat(window.chatUsername, window.chatGroup);
        lastActiveScreen = null;
      } else hideOfflineOverlay();
    }
  });
  window.addEventListener('offline', () => {
    showOfflineOverlay();
    if (document.getElementById('chatScreen').classList.contains('active')) clearMessagesOffline();
  });

  if ('PushManager' in window && 'serviceWorker' in navigator && 'Notification' in window) {
    getVapidPublicKey();
  } else {
    const b = document.getElementById('notificationBtn');
    if (b) b.style.display = 'none';
  }
});

function clearMessagesOffline() {
  const c = document.getElementById('messages');
  c.innerHTML = '<div style="text-align:center;color:#ff4444;padding:20px;">🔴 No internet connection.</div>';
  messagesData = {};
  document.getElementById('offlineBar').classList.add('active');
  updateStatus(false);
  if (ws && ws.readyState === WebSocket.OPEN) ws.close();
}

// ==================== NEW MSGS BUTTON ====================
function updateNewMsgsButton() {
  const b = document.getElementById('newMsgsBtn');
  const s = document.getElementById('newMsgsCount');
  if (unreadCount > 0) { s.textContent = unreadCount; b.classList.add('show'); }
  else b.classList.remove('show');
}
function scrollToBottom() {
  const c = document.getElementById('messages');
  c.scrollTop = c.scrollHeight;
  unreadCount = 0; updateNewMsgsButton(); isAtBottom = true;
}

// ==================== LOGIN ====================
async function login() {
  const u = document.getElementById('loginUsername').value.trim();
  const p = document.getElementById('loginPassword').value;
  if (!u || !p) { showError('Please enter username and password'); hideLoading(); return; }
  try {
    const r = await fetch('/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:u, password:p}) });
    const d = await r.json();
    if (d.success) {
      currentUser = { username: d.username, role: d.role };
      hideLoading();
      if (d.role === 'admin') {
        document.getElementById('loginScreen').style.display = 'none';
        document.getElementById('adminPanel').classList.add('active');
        document.getElementById('adminUsername').textContent = d.username;
        loadAdminData();
      } else {
        document.getElementById('loginScreen').style.display = 'none';
        document.getElementById('gatekeeperScreen').classList.add('active');
        document.getElementById('gatekeeperUsername').value = d.username;
        document.getElementById('gatekeeperPassword').value = '';
      }
    } else { showError(d.message || 'Invalid credentials.'); hideLoading(); }
  } catch(e) { showError('Connection error.'); hideLoading(); }
}

async function gatekeeperLogin() {
  const u = document.getElementById('gatekeeperUsername').value.trim();
  const p = document.getElementById('gatekeeperPassword').value;
  if (!u || !p) { showGatekeeperError('Enter password'); hideLoading(); return; }
  try {
    const r = await fetch('/gatekeeper', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:u, password:p}) });
    const d = await r.json();
    if (d.success) {
      gatekeeperData = d;
      document.getElementById('gatekeeperScreen').classList.remove('active');
      document.getElementById('userSetupScreen').classList.add('active');
      document.getElementById('userGroupName').value = d.assigned_group;
      document.getElementById('userGroupPassword').value = d.assigned_group_password;
      groupPassword = d.assigned_group_password;
      document.getElementById('userDisplayName').value = d.display_name || '';
      hideLoading();
    } else { showGatekeeperError(d.message || 'Invalid'); hideLoading(); }
  } catch(e) { showGatekeeperError('Connection error'); hideLoading(); }
}

async function enterChat() {
  const dn = document.getElementById('userDisplayName').value.trim();
  const gn = document.getElementById('userGroupName').value.trim();
  if (!dn) { showSetupError('Enter display name'); hideLoading(); return; }
  if (!gn) { showSetupError('Group missing'); hideLoading(); return; }
  try { await fetch('/save_display_name', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username: gatekeeperData.username, display_name: dn}) }); } catch(e){}
  window.chatUsername = dn; window.chatGroup = gn; window.groupPassword = groupPassword;
  document.getElementById('userSetupScreen').classList.remove('active');
  document.getElementById('chatScreen').classList.add('active');
  document.getElementById('messages').innerHTML = '';
  messagesData = {}; hideLoading();
  connectToChat(dn, gn);
}

// ==================== CONNECT TO CHAT ====================
function connectToChat(user, group) {
  messagesData = {};
  const c = document.getElementById('messages');
  c.innerHTML = '<div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div>';
  document.getElementById('offlineBar').classList.remove('active');
  if (!navigator.onLine) { c.innerHTML = '<div style="text-align:center;color:#ff4444;padding:20px;">🔴 No internet.</div>'; return; }
  document.getElementById('groupTitle').textContent = '# ' + group;
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(proto + '//' + window.location.host + '/ws');
  ws.onopen = function() {
    updateStatus(true);
    document.getElementById('offlineBar').classList.remove('active');
    ws.send(JSON.stringify({type:'join', username:user, group:group}));
    reconnectAttempts = 0; isManuallyReconnecting = false;
    unreadCount = 0; updateNewMsgsButton(); isAtBottom = true;
  };
  ws.onmessage = async function(e) {
    try {
      const d = JSON.parse(e.data);
      if (d.type === 'error') { showError(d.message); ws.close(); return; }
      if (d.type === 'ready') { groupSalt = d.salt; addSystemMessage('🔐 Connected'); }
      else if (d.type === 'history') {
        document.getElementById('messages').innerHTML = '';
        messagesData = {};
        if (d.messages && d.messages.length) {
          for (let m of d.messages) {
            try {
              const dec = await decrypt(m.ciphertext, window.groupPassword, m.salt);
              const isSent = m.sender === window.chatUsername;
              messagesData[m.id] = { sender:m.sender, text:dec, timestamp:m.created_at, voice_url:m.voice_url, media_url:m.media_url, media_type:m.media_type, delivered:m.delivered, read_by:m.read_by||[] };
              if (m.delivered) deliveredMessages.add(m.id);
              if (m.read_by && m.read_by.length) readMessages.add(m.id);
              addMessage(m.sender, dec, isSent, m.created_at, m.id, m.reply_to, m.voice_url, m.media_url, m.media_type, m.delivered, m.read_by);
            } catch(e) {
              const isSent = m.sender === window.chatUsername;
              messagesData[m.id] = { sender:m.sender, text:'🔒', timestamp:m.created_at, voice_url:m.voice_url, media_url:m.media_url, media_type:m.media_type, delivered:m.delivered, read_by:m.read_by||[] };
              addMessage(m.sender, '🔒', isSent, m.created_at, m.id, m.reply_to, m.voice_url, m.media_url, m.media_type, m.delivered, m.read_by);
            }
          }
        }
        setTimeout(() => { const x = document.getElementById('messages'); x.scrollTop = x.scrollHeight; isAtBottom = true; unreadCount = 0; updateNewMsgsButton(); }, 100);
      } else if (d.type === 'message') {
        if (d.temp_id) { const ph = document.querySelector(`.message[data-message-id="${d.temp_id}"]`); if (ph) ph.remove(); delete messagesData[d.temp_id]; }
        try {
          const dec = await decrypt(d.ciphertext, window.groupPassword, d.salt);
          const isSent = d.sender === window.chatUsername;
          messagesData[d.message_id] = { sender:d.sender, text:dec, timestamp:d.timestamp, voice_url:d.voice_url, media_url:d.media_url, media_type:d.media_type, delivered:d.delivered||false, read_by:d.read_by||[] };
          addMessage(d.sender, dec, isSent, d.timestamp, d.message_id, d.reply_to, d.voice_url, d.media_url, d.media_type, d.delivered, d.read_by);
          if (!isSent && ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type:'delivered', message_id: d.message_id }));
            ws.send(JSON.stringify({ type:'read', message_id: d.message_id }));
          }
        } catch(e) { console.error(e); }
        const c = document.getElementById('messages');
        const th = 100;
        const ab = (c.scrollHeight - c.scrollTop - c.clientHeight) < th;
        if (!ab && !d.temp_id) { unreadCount++; updateNewMsgsButton(); }
      } else if (d.type === 'message_delivered') {
        if (d.message_id) {
          deliveredMessages.add(d.message_id);
          const m = document.querySelector(`.message[data-message-id="${d.message_id}"]`);
          if (m) { const t = m.querySelector('.msg-tick'); if (t && !t.classList.contains('read')) { t.textContent='✓✓'; t.classList.add('delivered'); } }
        }
      } else if (d.type === 'message_read') {
        if (d.message_id) {
          readMessages.add(d.message_id); deliveredMessages.add(d.message_id);
          const m = document.querySelector(`.message[data-message-id="${d.message_id}"]`);
          if (m) { const t = m.querySelector('.msg-tick'); if (t) { t.textContent='✓✓'; t.classList.remove('delivered'); t.classList.add('read'); } }
        }
      } else if (d.type === 'users') updateUsers(d.users);
      else if (d.type === 'user_joined') addSystemMessage('👤 ' + d.user + ' joined');
      else if (d.type === 'user_left') addSystemMessage('👋 ' + d.user + ' left');
      else if (d.type === 'typing') document.getElementById('typingIndicator').textContent = '✏️ ' + d.user + ' typing...';
      else if (d.type === 'stop_typing') document.getElementById('typingIndicator').textContent = '';
      else if (d.type === 'pong') updateStatus(true);
    } catch(e) { console.error(e); }
  };
  ws.onerror = () => updateStatus(false);
  ws.onclose = () => {
    updateStatus(false);
    document.getElementById('offlineBar').classList.add('active');
    document.getElementById('messages').innerHTML = '<div style="text-align:center;color:#ff4444;padding:20px;">🔴 Disconnected.</div>';
    messagesData = {};
    if (document.getElementById('chatScreen').classList.contains('active') && !isManuallyReconnecting) {
      reconnectAttempts++;
      if (reconnectAttempts < 5) setTimeout(() => connectToChat(user, group), 3000);
    }
  };
}

function reconnectManually() {
  isManuallyReconnecting = true;
  if (ws) ws.close();
  messagesData = {};
  document.getElementById('messages').innerHTML = '<div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div>';
  document.getElementById('offlineBar').classList.remove('active');
  setTimeout(() => connectToChat(window.chatUsername, window.chatGroup), 500);
}

// ==================== UI ====================
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('overlay').classList.toggle('active');
}
function updateStatus(online) {
  const s = document.getElementById('connectionStatus');
  const b = document.getElementById('connectionBadge');
  if (online) { s.textContent='🟢 Connected'; s.className='connection-status status-online'; b.textContent='● Online'; b.style.color='#0f0'; document.getElementById('offlineBar').classList.remove('active'); }
  else { s.textContent='🔴 Disconnected'; s.className='connection-status status-offline'; b.textContent='● Offline'; b.style.color='#ff4444'; }
}
function addSystemMessage(text) {
  const c = document.getElementById('messages');
  const d = document.createElement('div');
  d.className = 'system-message';
  d.textContent = text;
  c.appendChild(d);
  c.scrollTop = c.scrollHeight;
}
function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

// ==================== ADD MESSAGE ====================
function addMessage(sender, text, isSent, timestamp, messageId, replyTo, voiceUrl, mediaUrl, mediaType, delivered, readBy) {
  const c = document.getElementById('messages');
  const d = document.createElement('div');
  d.className = 'message ' + (isSent ? 'sent' : 'received');
  d.dataset.messageId = messageId;
  d.dataset.sender = sender;
  d.dataset.text = text;

  const time = timestamp ? new Date(timestamp * 1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '';

  let tickHtml = '';
  if (isSent) {
    const isRead = (readBy && readBy.length) || readMessages.has(messageId);
    const isDel = delivered || deliveredMessages.has(messageId) || isRead;
    if (isRead) tickHtml = `<span class="msg-tick read">✓✓</span>`;
    else if (isDel) tickHtml = `<span class="msg-tick delivered">✓✓</span>`;
    else tickHtml = `<span class="msg-tick">✓</span>`;
  }

  let replyHtml = '';
  if (replyTo && messagesData[replyTo]) {
    const o = messagesData[replyTo];
    const ot = o.text || 'Message';
    replyHtml = '<div class="message-reply-preview" onclick="scrollToMessage(' + replyTo + ')">↩️ <span class="reply-sender">' + escapeHtml(o.sender) + '</span>: <span style="color:#888">' + escapeHtml(ot.substring(0,60)) + (ot.length>60?'...':'') + '</span></div>';
  }

  let content = '';
  if (voiceUrl) {
    const dl = voiceUrl + '?download=1';
    const bars = [];
    const seed = (messageId || Date.now()).toString();
    let sn = 0; for (let i=0;i<seed.length;i++) sn += seed.charCodeAt(i);
    for (let i=0;i<28;i++) bars.push(5 + ((sn * (i+3) * 13) % 18));
    const waveHtml = bars.map(h => `<span class="voice-wave-bar" style="height:${h}px;"></span>`).join('');
    const initial = (sender || '?').charAt(0).toUpperCase();
    content = `
      <div class="voice-player" data-voice-url="${voiceUrl}" data-message-id="${messageId}">
        <div class="voice-avatar">${initial}</div>
        <button class="voice-play-btn" onclick="playVoice(this, '${voiceUrl}')"><span class="play-icon">▶</span></button>
        <div class="voice-waveform" onclick="seekAudio(event, this)">${waveHtml}</div>
        <div class="voice-ball"></div>
        <a href="${dl}" download class="voice-download">⬇</a>
      </div>
      <div class="voice-info">
        <span class="voice-duration" data-duration-for="${messageId}">0:00</span>
        <span class="voice-time">${time}${isSent?tickHtml:''}</span>
      </div>
      ${text && text !== '🎤 Voice message' ? '<div style="font-size:11px;color:#888;margin-top:2px;">'+escapeHtml(text)+'</div>' : ''}`;
  } else if (mediaUrl) {
    if (mediaType && mediaType.startsWith('image/')) {
      const isPh = mediaUrl.startsWith('blob:') || messageId.toString().startsWith('temp_');
      const ph = isPh ? 'placeholder' : '';
      const dl = mediaUrl + '?download=1';
      content = `
        <div class="image-bubble ${ph}">
          <img src="${mediaUrl}" onclick="window.open('${mediaUrl}','_blank')" loading="lazy">
          ${isPh ? '<div class="spinner"></div>' : ''}
          <div class="file-name"><span>📎 ${escapeHtml(text.replace('📎 ',''))}</span><a href="${dl}" download class="download-link">⬇</a></div>
        </div>
        <div class="message-time">${time}${isSent?tickHtml:''}</div>`;
    } else {
      const dl = mediaUrl + '?download=1';
      content = `
        <div class="message-bubble">${escapeHtml(text)}<div style="margin-top:6px;"><a href="${mediaUrl}" target="_blank" style="color:#0f0;">📎 Open</a> | <a href="${dl}" download style="color:#0f0;">⬇️ Download</a></div></div>
        <div class="message-time">${time}${isSent?tickHtml:''}</div>`;
    }
  } else {
    content = `<div class="message-bubble">${escapeHtml(text)}</div><div class="message-time">${time}${isSent?tickHtml:''}</div>`;
  }

  d.innerHTML = '<div class="message-sender">' + (isSent ? 'YOU' : escapeHtml(sender)) + '</div>' + replyHtml + content + '<div class="message-actions"><button onclick="replyToMessage(' + messageId + ')">↩️ Reply</button></div>';

  // swipe
  let tsx=0, tcx=0, tsy=0;
  d.addEventListener('touchstart', e => { tsx = e.touches[0].clientX; tsy = e.touches[0].clientY; tcx = tsx; }, {passive:true});
  d.addEventListener('touchmove', e => { tcx = e.touches[0].clientX; const dx = tcx-tsx; const dy = e.touches[0].clientY-tsy; if (dx>0 && dx<80 && Math.abs(dy)<30) d.style.transform = 'translateX('+dx+'px)'; }, {passive:true});
  d.addEventListener('touchend', () => { const dx = tcx-tsx; d.style.transform=''; if (dx>=60) replyToMessage(messageId); tsx=tcx=tsy=0; }, {passive:true});

  c.appendChild(d);
  if (isAtBottom) c.scrollTop = c.scrollHeight;

  // Load duration
  if (voiceUrl) {
    const a = new Audio();
    a.preload = 'metadata';
    a.addEventListener('loadedmetadata', function() {
      if (isFinite(this.duration) && this.duration > 0) {
        const mins = Math.floor(this.duration / 60);
        const secs = Math.floor(this.duration % 60);
        const el = d.querySelector(`.voice-duration[data-duration-for="${messageId}"]`);
        if (el) el.textContent = mins + ':' + String(secs).padStart(2, '0');
      }
    });
    a.src = voiceUrl;
  }
}

function replyToMessage(id) {
  if (!id || !messagesData[id]) return;
  replyingToMessageId = id;
  const o = messagesData[id];
  document.getElementById('replyPreviewSender').textContent = o.sender;
  document.getElementById('replyPreviewText').textContent = o.text.substring(0,60) + (o.text.length>60?'...':'');
  document.getElementById('replyPreview').style.display = 'flex';
  document.getElementById('messageInput').focus();
}
function cancelReply() { replyingToMessageId = null; document.getElementById('replyPreview').style.display = 'none'; }
function scrollToMessage(id) {
  document.querySelectorAll('.message').forEach(m => {
    if (m.dataset.messageId == id) {
      m.scrollIntoView({behavior:'smooth', block:'center'});
      m.style.border = '2px solid #ffaa00';
      setTimeout(() => m.style.border='', 2000);
    }
  });
}
function updateUsers(users) {
  const ul = document.getElementById('usersList');
  ul.innerHTML = !users || !users.length ? '<div class="user-item">No users online</div>' : users.map(u=>'<div class="user-item">'+escapeHtml(u)+'</div>').join('');
}

// ==================== ENCRYPTION ====================
async function encrypt(text, pw, salt) {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  const k = await crypto.subtle.deriveKey({name:'PBKDF2', salt:enc.encode(salt), iterations:100000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, true, ['encrypt','decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const e = await crypto.subtle.encrypt({name:'AES-GCM', iv}, k, enc.encode(text));
  const combined = new Uint8Array(iv.length + e.byteLength);
  combined.set(iv); combined.set(new Uint8Array(e), iv.length);
  return btoa(String.fromCharCode.apply(null, combined));
}
async function decrypt(encrypted, pw, salt) {
  const enc = new TextEncoder(); const dec = new TextDecoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  const k = await crypto.subtle.deriveKey({name:'PBKDF2', salt:enc.encode(salt), iterations:100000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, true, ['encrypt','decrypt']);
  const data = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
  const iv = data.slice(0,12); const ct = data.slice(12);
  const d = await crypto.subtle.decrypt({name:'AES-GCM', iv}, k, ct);
  return dec.decode(d);
}
function generateSalt() {
  const a = new Uint8Array(32); crypto.getRandomValues(a);
  return btoa(String.fromCharCode.apply(null, a));
}

// ==================== SEND MESSAGE ====================
async function sendMessage() {
  const input = document.getElementById('messageInput');
  const text = input.value.trim();
  if (!text) return;
  if (!ws || ws.readyState !== WebSocket.OPEN) { alert('Not connected.'); return; }
  try {
    const salt = generateSalt();
    const enc = await encrypt(text, window.groupPassword, salt);
    ws.send(JSON.stringify({type:'message', ciphertext:enc, salt, reply_to: replyingToMessageId || null}));
    input.value = ''; input.style.height = 'auto'; cancelReply();
  } catch(e) { alert('Error sending.'); }
}

// ==================== WHATSAPP-STYLE TAP-TO-RECORD ====================
function buildRecWave() {
  const w = document.getElementById('recWave');
  w.innerHTML = '';
  for (let i=0;i<40;i++) {
    const b = document.createElement('div');
    b.className = 'bar';
    w.appendChild(b);
  }
}

async function startRecordingTap() {
  if (isRecording) return;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    let mimeType = 'audio/webm;codecs=opus';
    if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'audio/webm';
    if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'audio/mp4';

    mediaRecorder = new MediaRecorder(stream, { mimeType, audioBitsPerSecond: 64000 });
    audioChunks = [];
    mediaRecorder.ondataavailable = (e) => { if (e.data.size > 0) audioChunks.push(e.data); };
    mediaRecorder.onstop = async () => {
      const blob = new Blob(audioChunks, { type: mediaRecorder.mimeType || 'audio/webm' });
      if (shouldSendOnStop && blob.size > 0 && recordingSeconds >= 1) {
        await uploadVoice(blob);
      }
      stream.getTracks().forEach(t => t.stop());
      resetRecordingUI();
    };

    // Switch UI
    document.getElementById('typingRow').classList.add('hidden');
    document.getElementById('recordingRow').classList.add('active');
    buildRecWave();

    isRecording = true;
    isPaused = false;
    recordingSeconds = 0;
    document.getElementById('recTimer').textContent = '0:00';
    document.getElementById('recPauseBtn').textContent = '❚❚';
    document.getElementById('recPauseBtn').classList.remove('paused');

    mediaRecorder.start(1000);

    // Timer
    recordingTimerInterval = setInterval(() => {
      if (!isPaused) {
        recordingSeconds++;
        const m = Math.floor(recordingSeconds / 60);
        const s = recordingSeconds % 60;
        document.getElementById('recTimer').textContent = m + ':' + String(s).padStart(2, '0');
      }
    }, 1000);

    // Live waveform animation
    const bars = document.querySelectorAll('#recWave .bar');
    recWaveInterval = setInterval(() => {
      if (!isPaused) {
        bars.forEach(b => {
          const h = 6 + Math.floor(Math.random() * 20);
          b.style.height = h + 'px';
        });
      }
    }, 120);

  } catch (e) {
    alert('Microphone access denied.');
    resetRecordingUI();
  }
}

function togglePauseRecording() {
  if (!mediaRecorder || !isRecording) return;
  if (isPaused) {
    mediaRecorder.resume();
    isPaused = false;
    document.getElementById('recPauseBtn').textContent = '❚❚';
    document.getElementById('recPauseBtn').classList.remove('paused');
  } else {
    mediaRecorder.pause();
    isPaused = true;
    document.getElementById('recPauseBtn').textContent = '▶';
    document.getElementById('recPauseBtn').classList.add('paused');
  }
}

let shouldSendOnStop = false;

function sendRecording() {
  if (!mediaRecorder || !isRecording) return;
  if (recordingSeconds < 1) { cancelRecording(); return; }
  shouldSendOnStop = true;
  mediaRecorder.stop();
}

function cancelRecording() {
  if (!mediaRecorder || !isRecording) return;
  shouldSendOnStop = false;
  audioChunks = [];
  mediaRecorder.stop();
}

function resetRecordingUI() {
  isRecording = false;
  isPaused = false;
  clearInterval(recordingTimerInterval);
  clearInterval(recWaveInterval);
  recordingTimerInterval = null;
  recWaveInterval = null;
  recordingSeconds = 0;

  document.getElementById('recordingRow').classList.remove('active');
  document.getElementById('typingRow').classList.remove('hidden');
  document.getElementById('recTimer').textContent = '0:00';
  document.getElementById('recPauseBtn').textContent = '❚❚';
  document.getElementById('recPauseBtn').classList.remove('paused');
}

async function uploadVoice(blob) {
  const fd = new FormData();
  fd.append('file', blob, 'voice.webm');
  try {
    const r = await fetch('/api/upload_voice', { method:'POST', body: fd });
    const d = await r.json();
    if (d.success) await sendVoiceMessage(d.url);
    else alert('Upload failed');
  } catch(e) { alert('Upload failed'); }
}

async function sendVoiceMessage(url) {
  if (!ws || ws.readyState !== WebSocket.OPEN) { alert('Not connected.'); return; }
  const text = document.getElementById('messageInput').value.trim() || '🎤 Voice message';
  try {
    const salt = generateSalt();
    const enc = await encrypt(text, window.groupPassword, salt);
    ws.send(JSON.stringify({type:'message', ciphertext:enc, salt, reply_to: replyingToMessageId || null, voice_url: url}));
    document.getElementById('messageInput').value = '';
    document.getElementById('messageInput').style.height = 'auto';
    cancelReply();
  } catch(e) { alert('Error sending voice.'); }
}

// ==================== AUDIO PLAYER ====================
function playVoice(btn, url) {
  const player = btn.closest('.voice-player');
  const waveform = player.querySelector('.voice-waveform');
  const ball = player.querySelector('.voice-ball');
  const dur = player.parentElement.querySelector('.voice-duration');
  const bars = waveform.querySelectorAll('.voice-wave-bar');

  if (activeAudio && activeButton !== btn) {
    activeAudio.pause();
    if (activeButton) { activeButton.querySelector('.play-icon').textContent='▶'; activeButton.closest('.voice-player').classList.remove('playing'); }
  }
  if (activeButton === btn && activeAudio) {
    if (activeAudio.paused) { activeAudio.play(); btn.querySelector('.play-icon').textContent='❚❚'; player.classList.add('playing'); }
    else { activeAudio.pause(); btn.querySelector('.play-icon').textContent='▶'; player.classList.remove('playing'); }
    return;
  }
  const audio = new Audio(url);
  activeAudio = audio; activeButton = btn; activeProgressBar = waveform; activeDurationSpan = dur;
  if (activeAudio) activeAudio.pause();
  audio.onloadedmetadata = function() {
    if (isFinite(this.duration) && this.duration > 0) {
      const m = Math.floor(this.duration/60), s = Math.floor(this.duration%60);
      dur.textContent = m + ':' + String(s).padStart(2,'0');
    }
  };
  audio.ontimeupdate = function() {
    if (!isFinite(this.duration) || this.duration <= 0) return;
    const pct = this.currentTime / this.duration;
    const pb = Math.floor(pct * bars.length);
    bars.forEach((b,i) => { if (i<pb) b.classList.add('played'); else b.classList.remove('played'); });
    ball.style.left = (waveform.offsetLeft + pct * waveform.offsetWidth) + 'px';
    const m = Math.floor(this.currentTime/60), s = Math.floor(this.currentTime%60);
    dur.textContent = m + ':' + String(s).padStart(2,'0');
  };
  audio.onended = function() {
    btn.querySelector('.play-icon').textContent='▶'; player.classList.remove('playing');
    bars.forEach(b => b.classList.remove('played'));
    ball.style.left = waveform.offsetLeft + 'px';
    activeAudio = null; activeButton = null; activeProgressBar = null;
  };
  audio.play();
  btn.querySelector('.play-icon').textContent='❚❚';
  player.classList.add('playing');
}
function seekAudio(e, waveform) {
  if (!activeAudio || activeProgressBar !== waveform) return;
  const r = waveform.getBoundingClientRect();
  let cx = e.clientX; if (e.touches && e.touches.length) cx = e.touches[0].clientX;
  const pct = Math.min(1, Math.max(0, (cx - r.left) / r.width));
  if (isFinite(activeAudio.duration) && activeAudio.duration > 0) activeAudio.currentTime = activeAudio.duration * pct;
}

// ==================== MEDIA ====================
async function shareMedia() {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = 'image/*';
  input.onchange = async (e) => {
    const file = e.target.files[0]; if (!file) return;
    if (file.size > 10*1024*1024) { alert('Max 10MB'); return; }
    const tempId = 'temp_' + Date.now();
    const localUrl = URL.createObjectURL(file);
    const text = '📎 ' + file.name;
    const ts = Date.now() / 1000;
    messagesData[tempId] = { sender: window.chatUsername, text, timestamp: ts, media_url: localUrl, media_type: file.type };
    addMessage(window.chatUsername, text, true, ts, tempId, null, null, localUrl, file.type);
    const fd = new FormData(); fd.append('file', file);
    try {
      const r = await fetch('/api/upload_media', { method:'POST', body: fd });
      const d = await r.json();
      if (d.success) {
        const salt = generateSalt();
        const enc = await encrypt(text, window.groupPassword, salt);
        ws.send(JSON.stringify({type:'message', ciphertext:enc, salt, reply_to: replyingToMessageId || null, media_url: d.url, media_type: d.type || file.type, temp_id: tempId}));
      }
    } catch(err) {}
    setTimeout(() => URL.revokeObjectURL(localUrl), 5000);
  };
  input.click();
}

// ==================== ADMIN ====================
async function loadAdminData() {
  try {
    const r = await fetch('/admin/data'); const d = await r.json();
    document.getElementById('statUsers').textContent = d.users ? d.users.length : 0;
    document.getElementById('statMessages').textContent = d.messages_count || 0;
    document.getElementById('statGroups').textContent = d.groups ? d.groups.length : 0;
    const ut = document.getElementById('usersTableBody'); ut.innerHTML = '';
    (d.users||[]).forEach(u => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escapeHtml(u.username)}</td><td>${escapeHtml(u.assigned_group||'-')}</td><td>${u.username!=='Mpc'?`<button class="action-btn" onclick="deleteUser('${u.username}')">Delete</button>`:'Admin'}</td>`;
      ut.appendChild(tr);
    });
    const gt = document.getElementById('groupsTableBody'); gt.innerHTML = '';
    (d.groups||[]).forEach(g => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escapeHtml(g.group_name)}</td><td>${escapeHtml(g.created_by)}</td><td><button class="action-btn" onclick="deleteGroup('${g.group_name}')">Delete</button></td>`;
      gt.appendChild(tr);
    });
    const mt = document.getElementById('messagesTableBody'); mt.innerHTML = '';
    (d.messages||[]).forEach(m => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${escapeHtml(m.sender)}</td><td>${escapeHtml(m.group_name)}</td><td><button class="action-btn" onclick="deleteMessage(${m.id})">Delete</button></td>`;
      mt.appendChild(tr);
    });
  } catch(e) {}
}
async function createUser() {
  const u = document.getElementById('newUsername').value.trim();
  const p = document.getElementById('newPassword').value;
  const gn = document.getElementById('newGroupName').value.trim();
  const gp = document.getElementById('newGroupPassword').value;
  if (!u||!p||!gn||!gp) { alert('Fill all'); return; }
  const r = await fetch('/admin/create_user', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:u, password:p, group_name:gn, group_password:gp}) });
  const d = await r.json();
  if (d.success) { alert('✅ Created'); ['newUsername','newPassword','newGroupName','newGroupPassword'].forEach(id=>document.getElementById(id).value=''); loadAdminData(); }
  else alert('❌ ' + (d.error || 'Failed'));
}
async function deleteUser(u) { if (!confirm('Delete '+u+'?')) return; await fetch('/admin/delete_user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u})}); loadAdminData(); }
async function deleteGroup(n) { if (!confirm('Delete group '+n+'?')) return; await fetch('/admin/delete_group',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}); loadAdminData(); }
async function deleteMessage(id) { if (!confirm('Delete?')) return; await fetch('/admin/delete_message',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}); loadAdminData(); }

// ==================== AUTH HELPERS ====================
function showError(m) { const e=document.getElementById('loginError'); e.textContent=m; e.style.display='block'; setTimeout(()=>e.style.display='none',5000); }
function showGatekeeperError(m) { const e=document.getElementById('gatekeeperError'); e.textContent=m; e.style.display='block'; setTimeout(()=>e.style.display='none',5000); }
function showSetupError(m) { const e=document.getElementById('setupError'); e.textContent=m; e.style.display='block'; setTimeout(()=>e.style.display='none',5000); }
async function logout() {
  try { await fetch('/logout',{method:'POST'}); } catch(e){}
  if (ws && ws.readyState === WebSocket.OPEN) ws.close();
  document.getElementById('chatScreen').classList.remove('active');
  document.getElementById('adminPanel').classList.remove('active');
  document.getElementById('gatekeeperScreen').classList.remove('active');
  document.getElementById('userSetupScreen').classList.remove('active');
  document.getElementById('loginScreen').style.display = 'flex';
  sessionStorage.clear();
}
function requestAccess() { window.open('https://wa.me/250788495861?text=I%20need%20access%20to%20ABAVANDIMWE','_blank'); }

console.log('✅ ABAVANDIMWE v8.1 loaded');
</script>
</body>
</html>
'''

# ========== MAIN ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv('PORT', 8080))
    print("""
╔════════════════════════════════════════════════════════════╗
║              ABAVANDIMWE SECURE MESSAGING                  ║
║                    Version: v8.1                            ║
║                                                            ║
║  ✅ No deprecation warnings (lifespan)                      ║
║  ✅ WhatsApp-style tap-to-record audio                     ║
║  ✅ Tap 🎙️ → typing area replaced by recorder              ║
║  ✅ 🗑️ Delete · ❚❚ Pause · ➤ Send                          ║
║  ✅ Tap waveform to seek                                    ║
║  ✅ ✓✓ Read receipts                                        ║
║  ✅ Doodle background with ABAVANDIMWE                      ║
║  ✅ Auto-update banner                                      ║
╚════════════════════════════════════════════════════════════╝
""")
    print(f"[✓] Server running on port {port}")
    print(f"[✓] App Version: {APP_VERSION}")
    print(f"[✓] Admin: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    uvicorn.run(app, host="0.0.0.0", port=port)
