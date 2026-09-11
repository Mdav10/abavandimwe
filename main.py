"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
Messages stay for 24 hours then auto-delete
Database: PostgreSQL (Neon) with asyncpg
PWA Ready - Install as Android App with one click
Push Notifications: Web Push API with VAPID
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Depends, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import asyncio
import json
import os
import secrets
import base64
import hashlib
import threading
import time
import uuid
from datetime import datetime
from typing import Dict, Optional, List
from collections import defaultdict
from pydantic import BaseModel
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
import asyncpg
from asyncpg import create_pool

# ========== PUSH NOTIFICATION IMPORTS ==========
from pywebpush import WebPushException, webpush
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = FastAPI()

# ========== APP VERSION (bump this to force update prompt) ==========
APP_VERSION = "v7.0"

# ========== VAPID CONFIGURATION ==========
VAPID_PUBLIC_KEY = 'BL0X3NSYm0EbNslkt1afTEkuktGcvLRD4RS0MoWaYw6jEF8Yf9iryvnNBoDm7encOEBI2CPLNmCyYiehnWAbGQU'
VAPID_CLAIMS = {
    "sub": "mailto:abavandimwe@example.com"
}

def get_vapid_private_key():
    try:
        private_key_pem = os.getenv('VAPID_PRIVATE_KEY')
        if private_key_pem:
            return serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )
        with open("vapid_private_key.pem", "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        print(f"⚠️ Could not load VAPID private key: {e}")
        return None

# ========== SERVE STATIC FILES FOR PWA ==========
os.makedirs("static/icons", exist_ok=True)
os.makedirs("static/screenshots", exist_ok=True)

app.mount("/icons", StaticFiles(directory="static/icons"), name="icons")
app.mount("/screenshots", StaticFiles(directory="static/screenshots"), name="screenshots")
app.mount("/static/icons", StaticFiles(directory="static/icons"), name="static_icons")

# ========== SERVE PWA FILES ==========
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

# ========== VERSION ENDPOINT (for auto-update) ==========
@app.get("/api/version")
async def get_version():
    return {"version": APP_VERSION}

# ========== DATABASE CONFIG ==========
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://neondb_owner:npg_CmR51yqfMxNZ@ep-plain-salad-axxvh942-pooler.c-4.us-east-2.aws.neon.tech/neondb?sslmode=require')

db_pool = None

async def init_db_pool():
    global db_pool
    db_pool = await create_pool(
        DATABASE_URL,
        min_size=1,
        max_size=10,
        ssl='require'
    )
    return db_pool

async def get_db_connection():
    return await db_pool.acquire()

async def return_db_connection(conn):
    await db_pool.release(conn)

# ========== SECURITY CONFIG ==========
ADMIN_USERNAME = "Mpc"
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'Mpc@Secure+_+')
ADMIN_PASSWORD_HASH = None

# ========== SESSION MANAGEMENT ==========
sessions: Dict[str, Dict] = {}
SESSION_TIMEOUT = 3600 * 24 * 7

def create_session(username: str, role: str, assigned_group: str = None, group_password: str = None) -> str:
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {
        "username": username,
        "role": role,
        "assigned_group": assigned_group,
        "group_password": group_password,
        "created_at": time.time(),
        "expires_at": time.time() + SESSION_TIMEOUT
    }
    return session_id

def get_session(session_id: str) -> Optional[Dict]:
    if session_id not in sessions:
        return None
    session = sessions[session_id]
    if session["expires_at"] < time.time():
        del sessions[session_id]
        return None
    return session

def delete_session(session_id: str):
    if session_id in sessions:
        del sessions[session_id]

async def get_session_from_cookie(request: Request) -> Dict:
    session_id = request.cookies.get("abavandimwe_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="No session found")
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return session

async def require_admin(request: Request) -> Dict:
    session = await get_session_from_cookie(request)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return session

async def require_auth(request: Request) -> Dict:
    return await get_session_from_cookie(request)

# ========== CORS CONFIG ==========
ALLOWED_ORIGINS = [
    "https://abavandimwe.onrender.com",
    "https://abavandimwe-production.up.railway.app",
    "http://localhost:8080",
    "http://localhost:8000",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== PYDANTIC MODELS ==========
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

# ========== PUSH SUBSCRIPTIONS STORAGE ==========
push_subscriptions: Dict[str, List[Dict]] = defaultdict(list)

async def save_push_subscription(username: str, subscription: Dict):
    for sub in push_subscriptions[username]:
        if sub.get('endpoint') == subscription.get('endpoint'):
            return
    push_subscriptions[username].append(subscription)
    print(f"[🔔] Push subscription saved for {username}")

async def get_push_subscriptions(username: str) -> List[Dict]:
    return push_subscriptions.get(username, [])

async def send_push_notification(subscription: Dict, message: str, badge_count: int = 0):
    private_key = get_vapid_private_key()
    if not private_key:
        return False
    try:
        data = json.dumps({
            "title": "ABAVANDIMWE",
            "body": message,
            "badge": "/static/icons/badge-72x72.png",
            "icon": "/static/icons/icon-192x192.png",
            "data": {"url": "/"},
            "tag": "new-message",
            "renotify": True,
            "requireInteraction": True
        })
        webpush(
            subscription_info={"endpoint": subscription['endpoint'], "keys": subscription['keys']},
            data=data, vapid_private_key=private_key, vapid_claims=VAPID_CLAIMS
        )
        return True
    except WebPushException as e:
        if "expired" in str(e).lower() or "410" in str(e):
            for user, subs in push_subscriptions.items():
                push_subscriptions[user] = [s for s in subs if s.get('endpoint') != subscription.get('endpoint')]
        return False

async def send_notification_to_group(group_name: str, sender: str):
    conn = await get_db_connection()
    try:
        rows = await conn.fetch(
            "SELECT username FROM users WHERE assigned_group = $1 AND username != $2",
            group_name, sender
        )
        users = [row['username'] for row in rows]
    finally:
        await return_db_connection(conn)
    for username in users:
        subs = await get_push_subscriptions(username)
        for sub in subs:
            await send_push_notification(sub, "You have a new message on ABAVANDIMWE.", 1)

# ========== CRYPTO FUNCTIONS ==========
ph = PasswordHasher()

def generate_salt():
    return base64.b64encode(secrets.token_bytes(32)).decode()

def derive_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)

def hash_password_argon2(password):
    return ph.hash(password)

def verify_password_argon2(password, hashed):
    try:
        ph.verify(hashed, password)
        return True
    except VerificationError:
        return False

def encrypt(text, password, salt):
    key = derive_key(password, salt)
    text_bytes = text.encode()
    encrypted = bytearray()
    for i in range(len(text_bytes)):
        encrypted.append(text_bytes[i] ^ key[i % len(key)])
    nonce = secrets.token_bytes(8)
    result = nonce + encrypted
    return base64.b64encode(result).decode()

def decrypt(encrypted, password, salt):
    key = derive_key(password, salt)
    data = base64.b64decode(encrypted)
    ciphertext = data[8:]
    decrypted = bytearray()
    for i in range(len(ciphertext)):
        decrypted.append(ciphertext[i] ^ key[i % len(key)])
    return decrypted.decode()

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

def record_failed_login(username):
    login_attempts[username].append(time.time())

def reset_login_attempts(username):
    if username in login_attempts:
        login_attempts[username] = []
    if username in login_blocks:
        del login_blocks[username]

def check_message_rate_limit(username):
    now = time.time()
    message_limits[username] = [t for t in message_limits[username] if t > now - 5]
    if len(message_limits[username]) >= 10:
        return False
    message_limits[username].append(now)
    return True

# ========== DATABASE INIT ==========
async def init_db():
    global ADMIN_PASSWORD_HASH
    await init_db_pool()
    conn = await get_db_connection()
    try:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT,
                role TEXT DEFAULT 'user',
                assigned_group TEXT,
                display_name TEXT,
                status TEXT,
                current_group TEXT,
                last_seen DOUBLE PRECISION,
                created_at DOUBLE PRECISION,
                login_attempts INTEGER DEFAULT 0,
                locked_until DOUBLE PRECISION
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                ciphertext TEXT NOT NULL,
                group_name TEXT NOT NULL,
                sender TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at DOUBLE PRECISION NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                reply_to INTEGER DEFAULT NULL,
                voice_url TEXT,
                media_url TEXT,
                media_type TEXT,
                delivered BOOLEAN DEFAULT FALSE,
                read_by TEXT[] DEFAULT '{}'
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                group_name TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                group_password TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at DOUBLE PRECISION NOT NULL
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS admin_logs (
                id SERIAL PRIMARY KEY,
                admin_username TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                created_at DOUBLE PRECISION NOT NULL
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                filename TEXT NOT NULL UNIQUE,
                file_data BYTEA NOT NULL,
                mime_type TEXT NOT NULL,
                file_size INTEGER,
                created_at DOUBLE PRECISION,
                expires_at DOUBLE PRECISION,
                username TEXT,
                file_type TEXT
            )
        ''')
        print("[✓] PostgreSQL database ready")

        try:
            columns = await conn.fetch("""
                SELECT column_name FROM information_schema.columns WHERE table_name = 'messages'
            """)
            existing = [col['column_name'] for col in columns]
            if 'voice_url' not in existing:
                await conn.execute('ALTER TABLE messages ADD COLUMN voice_url TEXT')
            if 'media_url' not in existing:
                await conn.execute('ALTER TABLE messages ADD COLUMN media_url TEXT')
            if 'media_type' not in existing:
                await conn.execute('ALTER TABLE messages ADD COLUMN media_type TEXT')
            if 'reply_to' not in existing:
                await conn.execute('ALTER TABLE messages ADD COLUMN reply_to INTEGER DEFAULT NULL')
            if 'delivered' not in existing:
                await conn.execute('ALTER TABLE messages ADD COLUMN delivered BOOLEAN DEFAULT FALSE')
            if 'read_by' not in existing:
                await conn.execute("ALTER TABLE messages ADD COLUMN read_by TEXT[] DEFAULT '{}'")
        except Exception as e:
            print(f"[!] Column migration: {e}")

        try:
            await conn.execute("DELETE FROM groups WHERE group_name = 'admin' AND created_by != 'Mpc'")
        except: pass
        try:
            await conn.execute("DELETE FROM messages WHERE group_name = 'admin'")
        except: pass

        row = await conn.fetchrow("SELECT username FROM users WHERE username = $1", ADMIN_USERNAME)
        if not row:
            ADMIN_PASSWORD_HASH = hash_password_argon2(ADMIN_PASSWORD)
            await conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES ($1, $2, $3, $4, $5)",
                ADMIN_USERNAME, ADMIN_PASSWORD_HASH, "admin_salt", "admin", time.time()
            )
            print(f"[✓] Admin created: {ADMIN_USERNAME}")
            print(f"[✓] Admin Password: {ADMIN_PASSWORD}")
        else:
            row = await conn.fetchrow("SELECT password_hash FROM users WHERE username = $1", ADMIN_USERNAME)
            ADMIN_PASSWORD_HASH = row[0]
    finally:
        await return_db_connection(conn)
    print("[✓] Admin account ready")

# ========== DATABASE FUNCTIONS ==========
async def log_admin_action(admin_username, action, target, details=""):
    conn = await get_db_connection()
    try:
        await conn.execute(
            "INSERT INTO admin_logs (admin_username, action, target, details, created_at) VALUES ($1, $2, $3, $4, $5)",
            admin_username, action, target, details, time.time()
        )
    finally:
        await return_db_connection(conn)

async def get_admin_logs(limit=50):
    conn = await get_db_connection()
    try:
        rows = await conn.fetch(
            "SELECT id, admin_username, action, target, details, created_at FROM admin_logs ORDER BY created_at DESC LIMIT $1",
            limit
        )
        return [dict(row) for row in rows]
    finally:
        await return_db_connection(conn)

async def cleanup_old_messages():
    now = time.time()
    cutoff = now - (24 * 3600)
    conn = await get_db_connection()
    try:
        result = await conn.execute("DELETE FROM messages WHERE created_at < $1 OR expires_at < $2", cutoff, now)
        deleted = int(result.split()[1]) if result else 0
        if deleted > 0:
            print(f"[🧹] Deleted {deleted} old messages")
    finally:
        await return_db_connection(conn)

async def cleanup_old_files():
    conn = await get_db_connection()
    try:
        result = await conn.execute("DELETE FROM files WHERE expires_at < $1", time.time())
        deleted = int(result.split()[1]) if result else 0
        if deleted > 0:
            print(f"[🧹] Deleted {deleted} old files from Neon")
    finally:
        await return_db_connection(conn)

def start_cleanup():
    async def cleanup_loop():
        while True:
            await asyncio.sleep(3600)
            await cleanup_old_messages()
            await cleanup_old_files()
    asyncio.create_task(cleanup_loop())

async def authenticate_user(username, password):
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow(
            "SELECT password_hash, role, assigned_group, display_name, login_attempts, locked_until FROM users WHERE username = $1",
            username
        )
    finally:
        await return_db_connection(conn)
    if not row:
        return None
    stored_hash = row['password_hash']
    role = row['role']
    assigned_group = row['assigned_group']
    display_name = row['display_name']
    locked_until = row['locked_until']
    if locked_until and locked_until > time.time():
        return {"error": f"Account locked. Try again in {int((locked_until - time.time()) / 60)} minutes."}
    if verify_password_argon2(password, stored_hash):
        return {"username": username, "role": role, "assigned_group": assigned_group, "display_name": display_name}
    else:
        return None

async def get_group_password(group_name):
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow("SELECT group_password FROM groups WHERE group_name = $1", group_name)
        return row[0] if row else None
    finally:
        await return_db_connection(conn)

async def create_user_with_group(username, password, group_name, group_password):
    conn = await get_db_connection()
    try:
        salt = generate_salt()
        user_password_hash = hash_password_argon2(password)
        row = await conn.fetchrow("SELECT group_name, group_password FROM groups WHERE group_name = $1", group_name)
        if row:
            stored_group_password = row['group_password']
            if stored_group_password and stored_group_password != group_password:
                return {"error": "Group password does not match the existing group's password."}
            if not stored_group_password:
                await conn.execute("UPDATE groups SET group_password = $1 WHERE group_name = $2", group_password, group_name)
        else:
            group_salt = generate_salt()
            group_pwd_hash = hash_password_argon2(group_password)
            await conn.execute(
                "INSERT INTO groups (group_name, salt, password_hash, group_password, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
                group_name, group_salt, group_pwd_hash, group_password, "admin", time.time()
            )
        await conn.execute(
            "INSERT INTO users (username, password_hash, salt, role, assigned_group, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
            username, user_password_hash, salt, "user", group_name, time.time()
        )
        return {"success": True}
    except Exception as e:
        return {"error": str(e)}
    finally:
        await return_db_connection(conn)

async def save_user_display_name(username, display_name):
    conn = await get_db_connection()
    try:
        await conn.execute("UPDATE users SET display_name = $1 WHERE username = $2", display_name, username)
    finally:
        await return_db_connection(conn)

async def delete_user(username):
    if username == ADMIN_USERNAME:
        return False
    conn = await get_db_connection()
    try:
        result = await conn.execute("DELETE FROM users WHERE username = $1", username)
        return result != "DELETE 0"
    finally:
        await return_db_connection(conn)

async def get_all_users():
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("""
            SELECT username, role, assigned_group, display_name, status, 
                   current_group, last_seen, created_at 
            FROM users ORDER BY created_at DESC
        """)
        return [dict(row) for row in rows]
    finally:
        await return_db_connection(conn)

async def save_message_with_media(ciphertext, group, sender, salt, reply_to=None, voice_url=None, media_url=None, media_type=None):
    now = time.time()
    expiry = now + (24 * 3600)
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow(
            """INSERT INTO messages 
               (ciphertext, group_name, sender, salt, created_at, expires_at, reply_to, voice_url, media_url, media_type, delivered, read_by) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, FALSE, '{}') 
               RETURNING id, created_at""",
            ciphertext, group, sender, salt, now, expiry, reply_to, voice_url, media_url, media_type
        )
        return dict(result)
    finally:
        await return_db_connection(conn)

async def mark_message_delivered(message_id):
    conn = await get_db_connection()
    try:
        await conn.execute("UPDATE messages SET delivered = TRUE WHERE id = $1", message_id)
    finally:
        await return_db_connection(conn)

async def mark_message_read(message_id, username):
    conn = await get_db_connection()
    try:
        await conn.execute(
            "UPDATE messages SET read_by = array_append(read_by, $1) WHERE id = $2 AND NOT ($1 = ANY(read_by))",
            username, message_id
        )
    finally:
        await return_db_connection(conn)

async def get_messages(group):
    cutoff = time.time() - (24 * 3600)
    conn = await get_db_connection()
    try:
        rows = await conn.fetch(
            "SELECT id, ciphertext, sender, salt, created_at, reply_to, voice_url, media_url, media_type, delivered, read_by FROM messages WHERE group_name = $1 AND created_at > $2 ORDER BY id ASC",
            group, cutoff
        )
        return [dict(row) for row in rows]
    finally:
        await return_db_connection(conn)

async def get_all_messages(limit=100):
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("SELECT id, sender, group_name, created_at FROM messages ORDER BY created_at DESC LIMIT $1", limit)
        return [dict(row) for row in rows]
    finally:
        await return_db_connection(conn)

async def delete_message(message_id):
    conn = await get_db_connection()
    try:
        result = await conn.execute("DELETE FROM messages WHERE id = $1", message_id)
        return result != "DELETE 0"
    finally:
        await return_db_connection(conn)

async def set_user_status(username, status, group):
    conn = await get_db_connection()
    try:
        await conn.execute(
            "UPDATE users SET status = $1, current_group = $2, last_seen = $3 WHERE username = $4",
            status, group, time.time(), username
        )
    finally:
        await return_db_connection(conn)

async def get_online_users(group):
    cutoff = time.time() - 120
    conn = await get_db_connection()
    try:
        rows = await conn.fetch(
            "SELECT username FROM users WHERE status = 'online' AND current_group = $1 AND last_seen > $2",
            group, cutoff
        )
        return [row[0] for row in rows]
    finally:
        await return_db_connection(conn)

async def get_group_info(group):
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow("SELECT salt, password_hash FROM groups WHERE group_name = $1", group)
        return dict(row) if row else None
    finally:
        await return_db_connection(conn)

async def get_all_groups():
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("SELECT group_name, created_by, created_at FROM groups ORDER BY created_at DESC")
        return [dict(row) for row in rows]
    finally:
        await return_db_connection(conn)

async def delete_group(group_name):
    conn = await get_db_connection()
    try:
        await conn.execute("DELETE FROM users WHERE assigned_group = $1", group_name)
        await conn.execute("DELETE FROM messages WHERE group_name = $1", group_name)
        result = await conn.execute("DELETE FROM groups WHERE group_name = $1", group_name)
        return result != "DELETE 0"
    finally:
        await return_db_connection(conn)

async def save_file(filename, data, mime_type, username, file_type='voice'):
    conn = await get_db_connection()
    try:
        await conn.execute(
            """INSERT INTO files (filename, file_data, mime_type, file_size, created_at, expires_at, username, file_type) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
            filename, data, mime_type, len(data), time.time(), time.time() + (7 * 24 * 3600), username, file_type
        )
    finally:
        await return_db_connection(conn)

async def get_file_data(filename):
    conn = await get_db_connection()
    try:
        return await conn.fetchrow("SELECT file_data, mime_type FROM files WHERE filename = $1", filename)
    finally:
        await return_db_connection(conn)

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.connections: Dict[str, Dict[str, WebSocket]] = {}

    async def add(self, group: str, username: str, websocket: WebSocket):
        if group not in self.connections:
            self.connections[group] = {}
        self.connections[group][username] = websocket

    def remove(self, group: str, username: str):
        if group in self.connections:
            self.connections[group].pop(username, None)
            if not self.connections[group]:
                del self.connections[group]

    async def broadcast(self, group: str, message: dict, exclude: str = None):
        if group not in self.connections:
            return
        for username, ws in self.connections[group].items():
            if username != exclude:
                try:
                    await ws.send_json(message)
                except:
                    pass

manager = ConnectionManager()

# ========== INIT DATABASE ==========
@app.on_event("startup")
async def startup():
    await init_db()
    start_cleanup()

# ========== PUSH NOTIFICATION ENDPOINTS ==========
@app.post("/api/push/subscribe")
async def subscribe_to_push(request: Request):
    try:
        session = await get_session_from_cookie(request)
        username = session["username"]
        data = await request.json()
        subscription = data.get("subscription", {})
        await save_push_subscription(username, subscription)
        return {"success": True}
    except HTTPException:
        return JSONResponse({"success": False, "error": "Not authenticated"}, status_code=401)
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.get("/api/push/vapid_public_key")
async def get_vapid_public_key():
    return {"publicKey": VAPID_PUBLIC_KEY}

# ========== UPLOAD ENDPOINTS ==========
@app.post("/api/upload_voice")
async def upload_voice(request: Request, file: UploadFile = File(...)):
    try:
        session = await get_session_from_cookie(request)
        username = session["username"]
        content = await file.read()
        filename = f"{uuid.uuid4()}.webm"
        await save_file(filename, content, 'audio/webm', username, 'voice')
        return {"success": True, "url": f"/api/files/{filename}"}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.post("/api/upload_media")
async def upload_media(request: Request, file: UploadFile = File(...)):
    try:
        session = await get_session_from_cookie(request)
        username = session["username"]
        content = await file.read()
        ext = file.filename.split('.')[-1] if '.' in file.filename else 'bin'
        filename = f"{uuid.uuid4()}.{ext}"
        mime_type = file.content_type or 'application/octet-stream'
        await save_file(filename, content, mime_type, username, 'media')
        return {"success": True, "url": f"/api/files/{filename}", "type": mime_type}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)

@app.get("/api/files/{filename}")
async def get_file(filename: str):
    row = await get_file_data(filename)
    if not row:
        raise HTTPException(status_code=404)
    return Response(content=row['file_data'], media_type=row['mime_type'])

# ========== API ENDPOINTS ==========
@app.get("/")
async def root():
    return HTMLResponse(HTML)

@app.post("/login")
async def login(request: Request, login_data: LoginRequest):
    allowed, message = check_login_rate_limit(login_data.username)
    if not allowed:
        return JSONResponse(status_code=429, content={"success": False, "message": message})
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow(
            "SELECT password_hash, role, assigned_group, display_name, login_attempts, locked_until FROM users WHERE username = $1",
            login_data.username
        )
    finally:
        await return_db_connection(conn)
    if not row:
        record_failed_login(login_data.username)
        return JSONResponse(status_code=401, content={"success": False, "message": "Invalid credentials"})
    stored_hash = row['password_hash']
    role = row['role']
    assigned_group = row['assigned_group']
    display_name = row['display_name']
    locked_until = row['locked_until']
    if locked_until and locked_until > time.time():
        return JSONResponse(status_code=429, content={"success": False, "message": f"Account locked. Try again in {int((locked_until - time.time()) / 60)} minutes."})
    if verify_password_argon2(login_data.password, stored_hash):
        reset_login_attempts(login_data.username)
        group_password = None
        if assigned_group:
            group_password = await get_group_password(assigned_group)
            if not group_password:
                group_password = login_data.password
        session_id = create_session(login_data.username, role, assigned_group, group_password)
        response = JSONResponse({"success": True, "username": login_data.username, "role": role, "display_name": display_name})
        response.set_cookie(key="abavandimwe_session", value=session_id, httponly=True, secure=True, samesite="lax", max_age=SESSION_TIMEOUT, path="/")
        return response
    else:
        record_failed_login(login_data.username)
        return JSONResponse(status_code=401, content={"success": False, "message": "Invalid credentials"})

@app.post("/gatekeeper")
async def gatekeeper(login_data: LoginRequest):
    allowed, message = check_login_rate_limit(login_data.username)
    if not allowed:
        return JSONResponse(status_code=429, content={"success": False, "message": message})
    user = await authenticate_user(login_data.username, login_data.password)
    if not user:
        record_failed_login(login_data.username)
        return JSONResponse(status_code=401, content={"success": False, "message": "Invalid credentials"})
    if "error" in user:
        return JSONResponse(status_code=429, content={"success": False, "message": user["error"]})
    if user["role"] == "admin":
        return JSONResponse(status_code=403, content={"success": False, "message": "Admin cannot access chat"})
    assigned_group = user["assigned_group"]
    if not assigned_group:
        return JSONResponse(status_code=404, content={"success": False, "message": "No group assigned to this user"})
    group_password = await get_group_password(assigned_group)
    if not group_password:
        group_password = login_data.password
    return {
        "success": True,
        "username": login_data.username,
        "assigned_group": assigned_group,
        "assigned_group_password": group_password,
        "display_name": user.get("display_name")
    }

@app.post("/save_display_name")
async def save_display_name(data: SaveDisplayNameRequest, request: Request):
    session = await get_session_from_cookie(request)
    if session["username"] != data.username:
        raise HTTPException(status_code=403, detail="Cannot modify other users")
    await save_user_display_name(data.username, data.display_name)
    return {"success": True}

@app.get("/admin/data")
async def admin_data(request: Request):
    await require_admin(request)
    users = await get_all_users()
    messages = await get_all_messages()
    groups = await get_all_groups()
    logs = await get_admin_logs()
    online_users = await get_online_users("Main")
    return {
        "users": users, "messages": messages, "messages_count": len(messages),
        "groups": groups, "online_count": len(online_users), "logs": logs
    }

@app.post("/admin/create_user")
async def admin_create_user(data: CreateUserRequest, request: Request):
    session = await require_admin(request)
    result = await create_user_with_group(data.username, data.password, data.group_name, data.group_password)
    if result.get("success"):
        await log_admin_action(session["username"], "create_user", data.username, f"Group: {data.group_name}")
        return {"success": True}
    else:
        return {"success": False, "error": result.get("error", "Unknown error")}

@app.post("/admin/delete_user")
async def admin_delete_user(data: DeleteUserRequest, request: Request):
    session = await require_admin(request)
    if await delete_user(data.username):
        await log_admin_action(session["username"], "delete_user", data.username)
        return {"success": True}
    return {"success": False, "message": "Cannot delete admin or user not found"}

@app.post("/admin/delete_group")
async def admin_delete_group(data: DeleteGroupRequest, request: Request):
    session = await require_admin(request)
    if await delete_group(data.name):
        await log_admin_action(session["username"], "delete_group", data.name, f"Deleted group and all associated users and messages")
        return {"success": True}
    return {"success": False, "message": "Group not found"}

@app.post("/admin/delete_message")
async def admin_delete_message(data: DeleteMessageRequest, request: Request):
    session = await require_admin(request)
    if await delete_message(data.id):
        await log_admin_action(session["username"], "delete_message", str(data.id))
        return {"success": True}
    return {"success": False, "message": "Message not found"}

@app.post("/logout")
async def logout(request: Request):
    session_id = request.cookies.get("abavandimwe_session")
    if session_id:
        delete_session(session_id)
    response = JSONResponse({"success": True})
    response.delete_cookie("abavandimwe_session")
    return response

@app.get("/health")
async def health():
    return {"status": "ok", "system": "ABAVANDIMWE", "author": "Mugisha Pc", "version": APP_VERSION}

# ========== WEBSOCKET ==========
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    cookie_header = websocket.headers.get("cookie", "")
    session_id = None
    for item in cookie_header.split(";"):
        item = item.strip()
        if item.startswith("abavandimwe_session="):
            session_id = item.split("=")[1]
            break
    if not session_id:
        await websocket.send_json({'type': 'error', 'message': 'No session found'})
        await websocket.close()
        return
    session = get_session(session_id)
    if not session:
        await websocket.send_json({'type': 'error', 'message': 'Invalid session'})
        await websocket.close()
        return
    username = session["username"]
    assigned_group = session["assigned_group"]
    if not assigned_group:
        await websocket.send_json({'type': 'error', 'message': 'No group assigned'})
        await websocket.close()
        return
    group_name = assigned_group
    group_info = await get_group_info(group_name)
    if not group_info:
        await websocket.send_json({'type': 'error', 'message': 'Group not found'})
        await websocket.close()
        return
    group_salt = group_info['salt']
    await manager.add(group_name, username, websocket)
    await set_user_status(username, 'online', group_name)
    online = await get_online_users(group_name)
    await websocket.send_json({'type': 'users', 'users': online})
    messages = await get_messages(group_name)
    history_messages = []
    for msg in messages:
        history_messages.append({
            'id': msg['id'],
            'ciphertext': msg['ciphertext'],
            'sender': msg['sender'],
            'salt': msg['salt'],
            'timestamp': msg['created_at'],
            'reply_to': msg.get('reply_to'),
            'voice_url': msg.get('voice_url'),
            'media_url': msg.get('media_url'),
            'media_type': msg.get('media_type'),
            'delivered': msg.get('delivered', False),
            'read_by': msg.get('read_by', [])
        })
    await websocket.send_json({'type': 'history', 'messages': history_messages})
    await manager.broadcast(group_name, {'type': 'user_joined', 'user': username}, exclude=username)
    await websocket.send_json({'type': 'ready', 'salt': group_salt, 'group': group_name})
    print(f"[+] {username} joined {group_name}")
    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get('type')
            if msg_type == 'message':
                cipher = data.get('ciphertext')
                salt = data.get('salt')
                reply_to = data.get('reply_to')
                voice_url = data.get('voice_url')
                media_url = data.get('media_url')
                media_type = data.get('media_type')
                temp_id = data.get('temp_id')
                if username and group_name and check_message_rate_limit(username):
                    result = await save_message_with_media(cipher, group_name, username, salt, reply_to, voice_url, media_url, media_type)
                    message_id = result['id']
                    created_at = result['created_at']
                    asyncio.create_task(send_notification_to_group(group_name, username))
                    broadcast_msg = {
                        'type': 'message',
                        'message_id': message_id,
                        'ciphertext': cipher,
                        'sender': username,
                        'salt': salt,
                        'timestamp': created_at,
                        'reply_to': reply_to,
                        'voice_url': voice_url,
                        'media_url': media_url,
                        'media_type': media_type,
                        'delivered': False,
                        'read_by': []
                    }
                    if temp_id:
                        broadcast_msg['temp_id'] = temp_id
                    await manager.broadcast(group_name, broadcast_msg)
            elif msg_type == 'delivered':
                message_id = data.get('message_id')
                if message_id:
                    await mark_message_delivered(message_id)
                    await manager.broadcast(group_name, {
                        'type': 'message_delivered',
                        'message_id': message_id,
                        'user': username
                    })
            elif msg_type == 'read':
                message_id = data.get('message_id')
                if message_id:
                    await mark_message_read(message_id, username)
                    await manager.broadcast(group_name, {
                        'type': 'message_read',
                        'message_id': message_id,
                        'user': username
                    })
            elif msg_type == 'typing':
                if username and group_name:
                    await manager.broadcast(group_name, {'type': 'typing', 'user': username}, exclude=username)
            elif msg_type == 'stop_typing':
                if username and group_name:
                    await manager.broadcast(group_name, {'type': 'stop_typing', 'user': username}, exclude=username)
            elif msg_type == 'ping':
                await set_user_status(username, 'online', group_name)
                await websocket.send_json({'type': 'pong'})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[!] WebSocket error: {e}")
    finally:
        if username and group_name:
            manager.remove(group_name, username)
            await set_user_status(username, 'offline', group_name)
            online = await get_online_users(group_name)
            await manager.broadcast(group_name, {'type': 'users', 'users': online})
            await manager.broadcast(group_name, {'type': 'user_left', 'user': username})
            print(f"[-] {username} left {group_name}")

# ========== HTML ==========
HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>ABAVANDIMWE | Secure Messaging</title>
    
    <link rel="manifest" href="/manifest.json">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="ABAVANDIMWE">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="theme-color" content="#0a0a0f">
    <meta name="msapplication-TileColor" content="#0a0a0f">
    <meta name="msapplication-TileImage" content="/icons/icon-144x144.png">
    
    <link rel="icon" type="image/png" sizes="72x72" href="/icons/icon-72x72.png">
    <link rel="icon" type="image/png" sizes="96x96" href="/icons/icon-96x96.png">
    <link rel="icon" type="image/png" sizes="128x128" href="/icons/icon-128x128.png">
    <link rel="icon" type="image/png" sizes="144x144" href="/icons/icon-144x144.png">
    <link rel="icon" type="image/png" sizes="152x152" href="/icons/icon-152x152.png">
    <link rel="icon" type="image/png" sizes="192x192" href="/icons/icon-192x192.png">
    <link rel="icon" type="image/png" sizes="384x384" href="/icons/icon-384x384.png">
    <link rel="icon" type="image/png" sizes="512x512" href="/icons/icon-512x512.png">
    <link rel="apple-touch-icon" href="/icons/icon-192x192.png">
    
    <style>
        *{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
        html,body{width:100%;height:100%;overflow:hidden;background:#0a0a0f;font-family:monospace;color:#0f0;}

        /* ===================== UPDATE BANNER ===================== */
        .update-banner{
            position:fixed;
            top:0;
            left:0;
            right:0;
            background:linear-gradient(90deg, #ffaa00, #ff6600);
            color:#000;
            text-align:center;
            padding:12px;
            font-size:13px;
            font-weight:bold;
            z-index:999999;
            display:none;
            cursor:pointer;
            box-shadow:0 4px 20px rgba(255,170,0,0.5);
        }
        .update-banner.show{display:block;}
        .update-banner:active{opacity:0.85;}

        /* LOGIN */
        .login-container{position:fixed;top:0;left:0;right:0;bottom:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;padding:20px;}
        .login-card{background:#050508;border:2px solid #0f0;border-radius:24px;padding:32px 24px;width:100%;max-width:420px;position:relative;overflow:hidden;}
        .login-card::before{content:'';position:absolute;top:-2px;left:-2px;right:-2px;bottom:-2px;background:linear-gradient(45deg,#0f0,transparent,#0f0);background-size:400%;z-index:-1;animation:glow 3s linear infinite;}
        @keyframes glow{0%{background-position:0% 50%;}50%{background-position:100% 50%;}100%{background-position:0% 50%;}}
        .login-card-inner{background:#050508;padding:32px 24px;border-radius:22px;position:relative;}
        h1{text-align:center;margin-bottom:4px;font-size:28px;letter-spacing:2px;}
        .sub{text-align:center;margin-bottom:12px;font-size:11px;color:#666;}
        .admin-badge{text-align:center;margin-bottom:20px;font-size:10px;color:#0f0;border:1px solid #0f0;padding:4px 12px;display:inline-block;border-radius:20px;background:rgba(0,255,0,0.05);}
        input{width:100%;padding:14px;margin:10px 0;background:#111;border:1px solid #0f0;border-radius:12px;color:#0f0;font-family:monospace;font-size:15px;}
        input:focus{outline:none;box-shadow:0 0 20px rgba(0,255,65,0.2);border-color:#0f0;}
        input::placeholder{color:#444;}
        button{width:100%;padding:14px;margin-top:20px;background:transparent;border:2px solid #0f0;border-radius:12px;color:#0f0;font-size:16px;font-weight:bold;cursor:pointer;transition:all 0.3s;}
        button:hover{background:#0f0;color:#000;transform:translateY(-2px);box-shadow:0 5px 20px rgba(0,255,65,0.3);}
        button:active{transform:scale(0.98);}
        .btn-whatsapp{background:#25D366;border-color:#25D366;color:white;margin-top:12px;}
        .btn-whatsapp:hover{background:#128C7E;border-color:#128C7E;color:white;}
        .error-message{color:#ff4444;font-size:12px;text-align:center;margin-top:12px;display:none;}
        .success-message{color:#0f0;font-size:12px;text-align:center;margin-top:12px;display:none;}
        .login-footer{text-align:center;margin-top:20px;font-size:9px;color:#333;border-top:1px solid #1a1a2e;padding-top:16px;}

        /* ADMIN / GATEKEEPER / SETUP */
        .admin-panel{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:#0a0a0f;z-index:50;padding:20px;overflow-y:auto;}
        .admin-panel.active{display:block;}
        .admin-panel-header{display:flex;justify-content:space-between;align-items:center;padding:16px;border-bottom:2px solid #0f0;margin-bottom:20px;}
        .admin-panel-header h2{color:#ffaa00;}
        .admin-content{display:grid;grid-template-columns:repeat(auto-fit, minmax(300px, 1fr));gap:20px;}
        .admin-card{background:#050508;border:1px solid #0f0;border-radius:12px;padding:20px;}
        .admin-card h3{color:#0f0;margin-bottom:12px;font-size:14px;}
        .admin-card table{width:100%;font-size:11px;border-collapse:collapse;}
        .admin-card table th{text-align:left;padding:6px;border-bottom:1px solid #1a1a2e;color:#666;}
        .admin-card table td{padding:6px;border-bottom:1px solid #1a1a2e;}
        .admin-card input{width:100%;padding:8px;margin:5px 0;background:#111;border:1px solid #0f0;border-radius:6px;color:#0f0;font-size:12px;}
        .admin-card button{width:auto;padding:8px 16px;margin:5px;font-size:12px;}
        .close-admin{background:#ff0041;border-color:#ff0041;color:white;padding:8px 16px;border-radius:8px;cursor:pointer;}
        .admin-stats{display:grid;grid-template-columns:repeat(auto-fit, minmax(150px, 1fr));gap:12px;margin-bottom:20px;}
        .stat-box{background:#050508;border:1px solid #0f0;border-radius:10px;padding:16px;text-align:center;}
        .stat-number{font-size:24px;color:#0f0;}
        .stat-label{font-size:10px;color:#666;margin-top:4px;}
        .admin-table-wrap{max-height:200px;overflow-y:auto;}
        .action-btn{background:transparent;border:1px solid #ff0041;color:#ff0041;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:10px;margin:0 2px;}
        .action-btn:hover{background:#ff0041;color:white;}
        .action-btn-green{background:transparent;border:1px solid #0f0;color:#0f0;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:10px;margin:0 2px;}
        .action-btn-green:hover{background:#0f0;color:#000;}
        .admin-username{color:#ffaa00;font-size:12px;margin-left:10px;}
        
        .gatekeeper-container{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:#0a0a0f;z-index:900;padding:20px;justify-content:center;align-items:center;}
        .gatekeeper-container.active{display:flex;}
        .gatekeeper-card{background:#050508;border:2px solid #0f0;border-radius:24px;padding:32px 24px;width:100%;max-width:420px;}
        .gatekeeper-card h2{text-align:center;margin-bottom:8px;font-size:24px;}
        .gatekeeper-card .sub{text-align:center;margin-bottom:24px;font-size:11px;color:#666;}
        
        .user-setup-container{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:#0a0a0f;z-index:800;padding:20px;justify-content:center;align-items:center;}
        .user-setup-container.active{display:flex;}
        .user-setup-card{background:#050508;border:2px solid #0f0;border-radius:24px;padding:32px 24px;width:100%;max-width:420px;}
        .user-setup-card h2{text-align:center;margin-bottom:8px;font-size:24px;}
        .user-setup-card .sub{text-align:center;margin-bottom:24px;font-size:11px;color:#666;}
        .user-setup-card input[readonly]{opacity:0.7;cursor:not-allowed;}

        /* CHAT */
        .chat-container{display:none;flex-direction:column;height:100dvh;background:#0a0a0f;}
        .chat-container.active{display:flex;}

        .chat-header{padding:12px 16px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;align-items:center;flex-shrink:0;min-height:56px;gap:8px;}
        .chat-header-left{display:flex;align-items:center;gap:10px;flex:1;min-width:0;}
        .chat-header h2{font-size:16px;flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;}
        .online-badge{font-size:10px;padding:3px 10px;border:1px solid #0f0;border-radius:20px;background:rgba(0,255,0,0.05);white-space:nowrap;}
        .menu-btn,.logout-btn{background:transparent;border:1px solid #0f0;color:#0f0;padding:6px 12px;border-radius:8px;cursor:pointer;width:auto;margin:0;font-size:12px;flex-shrink:0;}
        .logout-btn:hover{border-color:#ff0041;color:#ff0041;}
        .notification-btn{background:transparent;border:1px solid #0f0;color:#0f0;padding:4px 12px;border-radius:20px;cursor:pointer;font-size:10px;white-space:nowrap;flex-shrink:0;}
        .notification-btn.enabled{background:#0f0;color:#000;}

        .offline-bar{display:none;background:#ff0041;color:white;text-align:center;padding:4px;font-size:10px;font-weight:bold;flex-shrink:0;}
        .offline-bar.active{display:block;}
        .offline-bar .reconnect-btn{background:white;color:#ff0041;border:none;padding:1px 10px;border-radius:4px;cursor:pointer;font-weight:bold;font-size:10px;}

        .main-content{display:flex;flex:1;min-height:0;position:relative;}

        .sidebar{width:260px;background:#050508;border-right:1px solid #0f0;display:flex;flex-direction:column;flex-shrink:0;overflow:hidden;z-index:10;}
        .sidebar-header{padding:16px;border-bottom:1px solid #0f0;font-size:14px;font-weight:bold;}
        .users-list{flex:1;padding:12px;overflow-y:auto;}
        .user-item{padding:10px 12px;margin:6px 0;border:1px solid #0f0;border-radius:10px;display:flex;align-items:center;gap:8px;font-size:13px;}
        .user-item::before{content:"●";color:#0f0;font-size:10px;animation:pulse 2s infinite;flex-shrink:0;}
        @keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.5;}}

        .overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:5;}
        .overlay.active{display:block;}
        @media (max-width:768px){
            .sidebar{position:fixed;left:-260px;top:0;bottom:0;z-index:20;transition:left 0.3s;width:260px;}
            .sidebar.open{left:0;}
        }
        @media (min-width:769px){.menu-btn,.overlay{display:none;}}

        /* ===================== CHAT BACKGROUND ===================== */
        /* Visible doodle pattern + big centered ABAVANDIMWE wordmark */
        .chat-area{
            flex:1;display:flex;flex-direction:column;min-width:0;width:100%;position:relative;
            background-color:#0a0a0f;
            background-image:
                /* Big centered ABAVANDIMWE wordmark (visible) */
                url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='1000' height='1000' viewBox='0 0 1000 1000'><text x='50%' y='50%' font-family='monospace' font-size='88' font-weight='bold' fill='rgba(0,255,65,0.10)' text-anchor='middle' dominant-baseline='middle' letter-spacing='8'>ABAVANDIMWE</text></svg>"),
                /* Doodle pattern (visible) */
                url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='240' viewBox='0 0 240 240'><g fill='none' stroke='rgba(0,255,65,0.10)' stroke-width='1.6'><circle cx='30' cy='30' r='7'/><path d='M85 22 Q95 12 105 22 Q115 32 105 42 Q95 52 85 42 Q75 32 85 22 Z'/><rect x='130' y='18' width='24' height='16' rx='3'/><path d='M170 30 L195 30 M170 36 L190 36'/><circle cx='45' cy='95' r='5'/><path d='M25 130 L25 155 M30 130 L30 155'/><circle cx='80' cy='105' r='9'/><path d='M68 145 L92 145 L86 168 L74 168 Z'/><path d='M165 95 L190 120 M190 95 L165 120'/><circle cx='110' cy='195' r='6'/><rect x='150' y='170' width='35' height='24' rx='4'/><path d='M35 185 L58 185 M35 191 L52 191'/><path d='M135 65 L160 65 L160 90'/><path d='M100 45 Q110 35 120 45'/><path d='M55 60 L70 75'/><circle cx='195' cy='175' r='4'/><path d='M200 55 L215 70 M215 55 L200 70'/></g></svg>");
            background-repeat: no-repeat, repeat;
            background-position: center center, top left;
            background-size: 100% 100%, 240px 240px;
            background-attachment: scroll, scroll;
        }

        .messages-container{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px;min-height:0;overscroll-behavior:contain;}

        .new-msgs-btn{
            position:absolute;
            bottom:100px;
            left:50%;
            transform:translateX(-50%);
            background:#0f0;
            color:#000;
            padding:8px 20px;
            border-radius:30px;
            font-size:14px;
            font-weight:bold;
            cursor:pointer;
            box-shadow:0 4px 15px rgba(0,255,65,0.4);
            z-index:30;
            display:none;
            border:2px solid #0f0;
            font-family:monospace;
        }
        .new-msgs-btn.show{display:block;}

        .message{
            display:flex;
            flex-direction:column;
            width:fit-content;
            max-width:85%;
            padding:4px 0;
            word-break:break-word;
            overflow-wrap:anywhere;
            animation:fadeIn 0.2s ease;
        }
        .message.sent{align-self:flex-end;margin-left:auto;}
        .message.received{align-self:flex-start;margin-right:auto;}
        @media (max-width:600px){ .message { max-width:90%; } }

        .message-bubble{
            padding:8px 14px;
            border-radius:18px;
            font-size:14px;
            line-height:1.5;
            word-wrap:break-word;
            max-width:100%;
        }
        .sent .message-bubble{background:#0f0;color:#000;border-bottom-right-radius:4px;}
        .received .message-bubble{background:#1a1a2e;border:1px solid #0f0;border-bottom-left-radius:4px;}

        .message-sender{font-size:9px;opacity:0.7;padding-left:4px;margin-bottom:2px;}
        .message-time{font-size:8px;opacity:0.5;margin-top:2px;}

        .message-reply-preview{
            font-size:10px;
            color:#ffaa00;
            margin-bottom:4px;
            padding:4px 8px;
            background:rgba(255,170,0,0.08);
            border-left:2px solid #ffaa00;
            border-radius:4px;
            cursor:pointer;
            max-width:100%;
        }
        .message-reply-preview .reply-sender{color:#ffaa00;font-weight:bold;}
        .message-reply-preview .reply-text{color:#888;}

        .system-message{text-align:center;font-size:10px;color:#ffaa00;margin:4px 0;font-style:italic;}
        .typing-indicator{padding:2px 16px 6px;font-size:10px;color:#0f0;font-style:italic;min-height:24px;flex-shrink:0;}

        /* ===== VOICE PLAYER ===== */
        .voice-player{
            display:flex;align-items:center;gap:10px;
            background:#0f0;padding:6px 10px;border-radius:20px;
            min-width:200px;max-width:min(90vw, 340px);position:relative;
        }
        .received .voice-player{background:#1a1a2e;border:1px solid #0f0;}

        .voice-avatar{
            flex:0 0 34px;width:34px;height:34px;border-radius:50%;
            background:#0a0a0f;color:#0f0;display:flex;align-items:center;
            justify-content:center;font-size:12px;font-weight:bold;overflow:hidden;
            position:relative;
        }
        .received .voice-avatar{background:#0f0;color:#0a0a0f;}

        .voice-play-btn{
            flex:0 0 32px;width:32px;height:32px;border:none;background:transparent;
            color:#0a0a0f;font-size:22px;cursor:pointer;display:flex;
            align-items:center;justify-content:center;padding:0;
        }
        .received .voice-play-btn{color:#0f0;}

        .voice-waveform{
            flex:1;display:flex;align-items:center;gap:2px;height:24px;
            cursor:pointer;min-width:80px;overflow:hidden;padding:4px 0;
            user-select:none;
        }
        .voice-wave-bar{
            flex:0 0 2px;width:2px;background:#0a0a0f;border-radius:2px;opacity:0.55;
        }
        .received .voice-wave-bar{background:#0f0;}
        .voice-wave-bar.played{opacity:1;}

        .voice-ball{
            position:absolute;top:50%;transform:translateY(-50%);
            width:10px;height:10px;border-radius:50%;background:#0a0a0f;
            pointer-events:none;left:60px;display:none;
        }
        .received .voice-ball{background:#0f0;}
        .voice-player.playing .voice-ball{display:block;}

        .voice-info{
            display:flex;justify-content:space-between;align-items:center;
            font-size:10px;margin-top:2px;color:#888;padding:0 4px;
            max-width:min(90vw, 340px);
        }
        .voice-duration{color:#0a0a0f;font-weight:bold;}
        .sent .voice-info .voice-duration{color:#0f0;}
        .voice-time{color:#888;font-size:10px;}
        .voice-tick{color:#0f0;font-size:11px;margin-left:4px;}

        .voice-download{
            flex:0 0 auto;font-size:14px;color:#0a0a0f;
            text-decoration:none;margin-left:4px;cursor:pointer;
        }
        .received .voice-download{color:#0f0;}

        /* ===== IMAGE MESSAGE ===== */
        .image-bubble{
            background:#0f0;border-radius:18px;overflow:hidden;
            border:2px solid #0f0;max-width:100%;display:flex;
            flex-direction:column;width:fit-content;position:relative;
        }
        .image-bubble img{
            display:block;width:100%;height:auto;max-height:420px;
            object-fit:contain;cursor:pointer;background:#111;
        }
        .image-bubble .file-name{
            padding:6px 10px;font-size:12px;color:#111;background:#0f0;
            overflow-wrap:anywhere;word-break:break-word;
            display:flex;justify-content:space-between;align-items:center;
        }
        .image-bubble .file-name .download-link{
            color:#0a0a0f;text-decoration:none;font-size:14px;
            cursor:pointer;margin-left:8px;
        }
        .image-bubble .spinner{
            position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
            width:40px;height:40px;border:4px solid rgba(0,0,0,0.1);
            border-top:4px solid #0f0;border-radius:50%;
            animation:spin 0.8s linear infinite;
            background:rgba(0,0,0,0.3);pointer-events:none;
        }
        @keyframes spin{0%{transform:translate(-50%,-50%) rotate(0);}100%{transform:translate(-50%,-50%) rotate(360deg);}}
        .image-bubble.placeholder img{filter:blur(2px);}

        .message-actions{
            display:flex;gap:6px;margin-top:4px;flex-wrap:wrap;align-items:center;
        }
        .message-actions button{
            background:transparent;border:none;color:#888;
            font-size:10px;cursor:pointer;padding:1px 4px;
        }
        .message-actions button:hover{color:#0f0;}

        /* ===== COMPOSER ===== */
        .input-area{
            padding:8px 12px;background:#050508;border-top:1px solid #0f0;
            flex-shrink:0;display:flex;flex-direction:column;gap:6px;
        }
        .reply-preview{
            display:none;padding:4px 8px;background:rgba(255,170,0,0.1);
            border-left:2px solid #ffaa00;border-radius:4px;
            font-size:11px;color:#ffaa00;align-items:center;justify-content:space-between;
        }
        .reply-preview .reply-cancel{
            color:#ff4444;cursor:pointer;font-weight:bold;padding:0 6px;
        }
        .input-row{display:flex;gap:8px;align-items:flex-end;}
        .input-row textarea{
            flex:1;min-width:0;padding:10px 14px;background:#111;
            border:1px solid #0f0;border-radius:12px;color:#0f0;
            font-family:monospace;font-size:14px;resize:vertical;
            max-height:80px;min-height:44px;line-height:1.5;outline:none;
        }
        .input-row textarea:focus{box-shadow:0 0 20px rgba(0,255,65,0.2);}
        .input-row textarea::placeholder{color:#444;}
        .input-row button{
            flex:0 0 50px;width:50px;height:50px;margin:0;padding:0;
            border-radius:50%;font-size:18px;border:2px solid #0f0;
            background:transparent;color:#0f0;cursor:pointer;display:flex;
            align-items:center;justify-content:center;flex-shrink:0;
        }
        .input-row button:hover{background:rgba(0,255,0,0.1);}
        .input-row .send-btn{background:#0f0;color:#000;border-color:#0f0;}
        .voice-btn.recording{border-color:#ff0041;background:rgba(255,0,65,0.15);animation:pulse-red 1s infinite;}
        @keyframes pulse-red{0%,100%{box-shadow:0 0 0 0 rgba(255,0,65,0.4);}50%{box-shadow:0 0 20px 10px rgba(255,0,65,0.15);}}

        .recording-status{
            display:none;align-items:center;gap:12px;padding:6px 12px;
            background:#1a1a2e;border-radius:8px;border:1px solid #ff0041;
        }
        .recording-status.active{display:flex;}
        #recordingTimer{color:#ff0041;font-size:14px;font-weight:bold;min-width:50px;}
        .wave{flex:1;display:flex;align-items:center;gap:2px;height:20px;}
        .wave .bar{width:3px;background:#ff0041;border-radius:2px;animation:wave 0.6s ease-in-out infinite alternate;}
        .wave .bar:nth-child(1){height:6px;animation-delay:0s;}
        .wave .bar:nth-child(2){height:14px;animation-delay:0.1s;}
        .wave .bar:nth-child(3){height:20px;animation-delay:0.2s;}
        .wave .bar:nth-child(4){height:12px;animation-delay:0.3s;}
        .wave .bar:nth-child(5){height:22px;animation-delay:0.4s;}
        .wave .bar:nth-child(6){height:16px;animation-delay:0.5s;}
        .wave .bar:nth-child(7){height:8px;animation-delay:0.6s;}
        .wave .bar:nth-child(8){height:18px;animation-delay:0.7s;}
        @keyframes wave{0%{transform:scaleY(0.3);}100%{transform:scaleY(1);}}
        #recordingText{font-size:10px;color:#ff0041;font-weight:bold;min-width:60px;}

        .footer{text-align:center;padding:4px 0 2px;font-size:7px;color:#333;border-top:1px solid #1a1a2e;margin-top:4px;}

        ::-webkit-scrollbar{width:4px;}
        ::-webkit-scrollbar-track{background:#1a1a2e;}
        ::-webkit-scrollbar-thumb{background:#0f0;border-radius:2px;}

        .install-btn{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:100;padding:14px 28px;background:#0f0;color:#000;border:none;border-radius:14px;font-size:15px;font-weight:bold;cursor:pointer;display:none;box-shadow:0 4px 30px rgba(0,255,65,0.4);font-family:monospace;}
        .install-btn.show{display:block;}

        .loading-overlay{position:fixed;inset:0;background:rgba(10,10,15,0.92);z-index:9999;display:none;justify-content:center;align-items:center;flex-direction:column;gap:30px;}
        .loading-overlay.active{display:flex;}
        .loader{width:60px;height:60px;border:3px solid rgba(0,255,65,0.1);border-top:3px solid #0f0;border-radius:50%;animation:spin 0.8s cubic-bezier(0.4,0.0,0.2,1) infinite;}
        .loader-pulse{position:absolute;width:60px;height:60px;border-radius:50%;border:1px solid rgba(0,255,65,0.3);animation:pulse-ring 1.5s cubic-bezier(0.4,0.0,0.2,1) infinite;}
        .loader-container{position:relative;display:flex;justify-content:center;align-items:center;}
        .loader-text{color:#0f0;font-size:16px;font-family:monospace;letter-spacing:2px;}
        @keyframes spin{0%{transform:rotate(0);}100%{transform:rotate(360deg);}}
        @keyframes pulse-ring{0%{transform:scale(1);opacity:1;}100%{transform:scale(1.6);opacity:0;}}
        .loader-dots{display:inline-block;}
        .loader-dots span{display:inline-block;animation:dot-bounce 1.4s ease-in-out infinite;}
        .loader-dots span:nth-child(1){animation-delay:0s;}
        .loader-dots span:nth-child(2){animation-delay:0.2s;}
        .loader-dots span:nth-child(3){animation-delay:0.4s;}
        @keyframes dot-bounce{0%,80%,100%{transform:scale(0);opacity:0.3;}40%{transform:scale(1);opacity:1;}}

        .offline-overlay{position:fixed;inset:0;background:#0a0a0f;z-index:99999;display:none;justify-content:center;align-items:center;flex-direction:column;gap:20px;padding:30px;}
        .offline-overlay.active{display:flex;}
        .offline-overlay .offline-icon{font-size:60px;}
        .offline-overlay h2{color:#ff4444;font-size:24px;text-align:center;}
        .offline-overlay p{color:#888;font-size:14px;text-align:center;}
        .offline-overlay .retry-btn{background:transparent;border:2px solid #0f0;color:#0f0;padding:14px 40px;border-radius:12px;font-size:16px;font-weight:bold;cursor:pointer;}

        .connection-status{position:fixed;bottom:80px;right:16px;padding:6px 12px;background:#050508;border:1px solid #0f0;border-radius:20px;font-size:9px;z-index:40;}
        .status-online{color:#0f0;}
        .status-offline{color:#ff4444;}

        .msg-tick{
            font-size:11px;margin-left:4px;color:#666;display:inline-block;vertical-align:middle;
        }
        .msg-tick.delivered{color:#888;}
        .msg-tick.read{color:#00d4ff;}

        @media (max-width:480px){
            .input-row textarea{font-size:13px;padding:8px 12px;min-height:36px;}
            .input-row button{flex-basis:44px;width:44px;height:44px;font-size:16px;}
            .voice-player{min-width:180px;padding:5px 8px;}
            .voice-avatar{flex-basis:30px;width:30px;height:30px;font-size:11px;}
            .voice-play-btn{flex-basis:28px;width:28px;height:28px;font-size:18px;}
            .voice-waveform{min-width:60px;}
            .message{max-width:90%;}
            .chat-header h2{font-size:14px;}
            .image-bubble img{max-height:280px;}
            .sidebar{width:240px;}
            @media (max-width:768px){.sidebar{width:240px;left:-240px;}}
            .new-msgs-btn{font-size:12px;padding:6px 16px;bottom:90px;}
        }
        @media (max-width:380px){
            .input-row button{flex-basis:38px;width:38px;height:38px;font-size:14px;}
            .voice-avatar{flex-basis:26px;width:26px;height:26px;font-size:10px;}
            .voice-play-btn{flex-basis:24px;width:24px;height:24px;font-size:16px;}
            .message{max-width:92%;}
            .new-msgs-btn{font-size:11px;padding:4px 14px;bottom:80px;}
        }
    </style>
</head>
<body>

<!-- UPDATE BANNER -->
<div class="update-banner" id="updateBanner" onclick="applyUpdate()">
    🚀 New version available! Tap to update
</div>

<!-- Loading Overlay -->
<div class="loading-overlay" id="loadingOverlay">
    <div class="loader-container">
        <div class="loader-pulse"></div>
        <div class="loader"></div>
    </div>
    <div class="loader-text">
        <span id="loadingText">Loading</span>
        <span class="loader-dots"><span>.</span><span>.</span><span>.</span></span>
    </div>
</div>

<!-- OFFLINE -->
<div class="offline-overlay" id="offlineOverlay">
    <div class="offline-icon">📶</div>
    <h2>No Internet Connection</h2>
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
            <div class="separator"><span>OR</span></div>
            <button class="btn-whatsapp" onclick="requestAccess()">💬 Request Access on WhatsApp</button>
            <div id="loginError" class="error-message"></div>
            <div id="loginSuccess" class="success-message"></div>
            <div class="login-footer">🔒 AES-256 | ⏰ Messages auto-delete after 24 hours<br><span style="color:#1a1a2e;">Developed by Mugisha Pc</span></div>
        </div>
    </div>
</div>

<!-- ADMIN PANEL -->
<div id="adminPanel" class="admin-panel">
    <div class="admin-panel-header">
        <h2>⚙️ Admin Dashboard <span class="admin-username">(Logged in as: <span id="adminUsername">Mpc</span>)</span></h2>
        <div><button class="close-admin" onclick="logout()">🚪 Logout</button></div>
    </div>
    <div class="admin-stats" id="adminStats">
        <div class="stat-box"><div class="stat-number" id="statUsers">0</div><div class="stat-label">Total Users</div></div>
        <div class="stat-box"><div class="stat-number" id="statMessages">0</div><div class="stat-label">Total Messages</div></div>
        <div class="stat-box"><div class="stat-number" id="statGroups">0</div><div class="stat-label">Total Groups</div></div>
        <div class="stat-box"><div class="stat-number" id="statOnline">0</div><div class="stat-label">Online Now</div></div>
    </div>
    <div class="admin-content">
        <div class="admin-card"><h3>👤 Create User</h3>
            <div style="margin-bottom:12px;">
                <input type="text" id="newUsername" placeholder="Username" style="width:100%;">
                <input type="text" id="newPassword" placeholder="Password" style="width:100%;">
                <input type="text" id="newGroupName" placeholder="Group Name" style="width:100%;">
                <input type="text" id="newGroupPassword" placeholder="Group Password" style="width:100%;">
                <button onclick="createUser()" class="action-btn-green">➕ Create User</button>
            </div>
            <div class="group-info">⚠️ If the group already exists, the Group Password you enter MUST match the existing group password!</div>
        </div>
        <div class="admin-card"><h3>📋 Users</h3>
            <div class="admin-table-wrap"><table><thead><tr><th>Username</th><th>Group</th><th>Display Name</th><th>Status</th><th>Action</th></tr></thead>
            <tbody id="usersTableBody"></tbody></table></div>
        </div>
        <div class="admin-card"><h3>📁 Groups</h3>
            <div class="admin-table-wrap"><table><thead><tr><th>Group Name</th><th>Created By</th><th>Action</th></tr></thead>
            <tbody id="groupsTableBody"></tbody></table></div>
        </div>
        <div class="admin-card"><h3>📨 Recent Messages</h3>
            <div class="admin-table-wrap"><table><thead><tr><th>Sender</th><th>Group</th><th>Time</th><th>Action</th></tr></thead>
            <tbody id="messagesTableBody"></tbody></table></div>
        </div>
        <div class="admin-card"><h3>📋 Admin Logs</h3>
            <div class="admin-table-wrap"><table><thead><tr><th>Admin</th><th>Action</th><th>Target</th><th>Time</th></tr></thead>
            <tbody id="logsTableBody"></tbody></table></div>
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
        <div class="login-footer" style="margin-top:20px;padding-top:16px;">🔒 Credentials provided by admin</div>
    </div>
</div>

<!-- USER SETUP -->
<div id="userSetupScreen" class="user-setup-container">
    <div class="user-setup-card">
        <h2>👤 Setup Profile</h2>
        <div class="sub">Enter your display name to start chatting</div>
        <input type="text" id="userDisplayName" placeholder="Your Display Name (e.g., John Doe)">
        <input type="text" id="userGroupName" placeholder="Group Name" readonly>
        <input type="password" id="userGroupPassword" placeholder="Group Password" readonly>
        <button id="enterChatBtn">▶ Enter Chat</button>
        <div id="setupError" class="error-message"></div>
        <div id="setupSuccess" class="success-message"></div>
        <div class="login-footer" style="margin-top:20px;padding-top:16px;">🔐 You'll be able to see messages from others in your group</div>
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
    <div class="offline-bar" id="offlineBar">⚠️ No internet connection <button class="reconnect-btn" onclick="reconnectManually()">↻ Retry</button></div>
    <div class="main-content">
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header"><h3>● Online Users</h3></div>
            <div class="users-list" id="usersList"><div class="user-item">Loading...</div></div>
        </div>
        <div class="overlay" id="overlay" onclick="toggleSidebar()"></div>
        <div class="chat-area">
            <div class="messages-container" id="messages"><div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div></div>
            <div class="new-msgs-btn" id="newMsgsBtn" onclick="scrollToBottom()">
                <span id="newMsgsCount">0</span> new messages
            </div>
            <div class="typing-indicator" id="typingIndicator"></div>
            <div class="input-area">
                <div class="reply-preview" id="replyPreview">
                    <span>↩️ Replying to <span id="replyPreviewSender" style="color:#ffaa00;font-weight:bold;"></span>: <span id="replyPreviewText" style="color:#888;"></span></span>
                    <span class="reply-cancel" onclick="cancelReply()">✕</span>
                </div>
                <div class="input-row">
                    <textarea id="messageInput" placeholder="Type a message..." rows="2"></textarea>
                    <button class="voice-btn" id="voiceBtn" onmousedown="startHoldRecording()" onmouseup="stopHoldRecording()" onmouseleave="stopHoldRecording()" ontouchstart="startHoldRecording()" ontouchend="stopHoldRecording()" ontouchcancel="stopHoldRecording()">
                        <span id="voiceIcon">🎙️</span>
                    </button>
                    <button class="media-btn" onclick="shareMedia()">📎</button>
                    <button class="send-btn" onclick="sendMessage()"><span class="btn-text">➥</span></button>
                </div>
                <div class="recording-status" id="recordingStatus">
                    <span id="recordingTimer">00:00</span>
                    <div class="wave"><span class="bar"></span><span class="bar"></span><span class="bar"></span><span class="bar"></span><span class="bar"></span><span class="bar"></span><span class="bar"></span><span class="bar"></span></div>
                    <span id="recordingText">🔴 Recording</span>
                </div>
            </div>
            <div class="footer">🔐 End-to-End Encrypted | Messages self-destruct after 24 hours</div>
        </div>
    </div>
    <div class="connection-status status-online" id="connectionStatus">🟢 Connected</div>
</div>

<!-- INSTALL BUTTON -->
<button id="installBtn" class="install-btn">📲 Install ABAVANDIMWE App</button>

<script>
// ========== GLOBALS ==========
let ws, username, groupName, groupPassword, groupSalt, typingTimeout, reconnectAttempts = 0;
let currentUser = null;
let gatekeeperData = null;
let replyingToMessageId = null;
let messagesData = {};
let isManuallyReconnecting = false;
let lastActiveScreen = null;
let pushSubscription = null;
let vapidPublicKey = null;
let notificationsEnabled = false;

// VOICE RECORDING
let mediaRecorder = null;
let audioChunks = [];
let isRecording = false;
let recordingTimer = null;
let recordingSeconds = 0;
let holdTimer = null;
let isHolding = false;

// Audio player state
let activeAudio = null;
let activeButton = null;
let activeProgressBar = null;
let activeDurationSpan = null;

// New messages counter
let unreadCount = 0;
let isAtBottom = true;

// Delivered & Read tracking
const deliveredMessages = new Set();
const readMessages = new Set();

// App version tracking (for auto-update)
let currentAppVersion = null;

// ========== AUTO-UPDATE SYSTEM ==========
async function checkForUpdates() {
    try {
        const res = await fetch('/api/version', { cache: 'no-store' });
        const data = await res.json();
        const serverVersion = data.version;
        const storedVersion = localStorage.getItem('abavandimwe_version');
        if (!storedVersion) {
            // First time — just record
            localStorage.setItem('abavandimwe_version', serverVersion);
            currentAppVersion = serverVersion;
            return;
        }
        if (storedVersion !== serverVersion) {
            // New version available
            currentAppVersion = serverVersion;
            const banner = document.getElementById('updateBanner');
            banner.classList.add('show');
            console.log('🚀 Update available:', serverVersion);
        }
    } catch(e) {
        // ignore network errors
    }
}

async function applyUpdate() {
    const banner = document.getElementById('updateBanner');
    banner.textContent = '⏳ Updating...';
    try {
        // Clear all caches
        if ('caches' in window) {
            const cacheNames = await caches.keys();
            await Promise.all(cacheNames.map(name => caches.delete(name)));
        }
        // Unregister old service workers
        if ('serviceWorker' in navigator) {
            const registrations = await navigator.serviceWorker.getRegistrations();
            for (let reg of registrations) {
                await reg.unregister();
            }
        }
        // Save new version
        const res = await fetch('/api/version', { cache: 'no-store' });
        const data = await res.json();
        localStorage.setItem('abavandimwe_version', data.version);
        // Hard reload bypassing cache
        window.location.reload(true);
    } catch(e) {
        window.location.reload(true);
    }
}

// Check for updates on page load + every 60 seconds
window.addEventListener('load', () => {
    checkForUpdates();
    setInterval(checkForUpdates, 60000);
});

// Also check when tab becomes visible
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') checkForUpdates();
});

// ========== LOADING ==========
function showLoading(text, callback) {
    const overlay = document.getElementById('loadingOverlay');
    const loadingText = document.getElementById('loadingText');
    loadingText.textContent = text;
    overlay.classList.add('active');
    setTimeout(async () => {
        try { await callback(); } catch(e) { console.error(e); }
        finally {
            if (!document.querySelector('.chat-container.active') && 
                !document.querySelector('.admin-panel.active') &&
                !document.querySelector('.gatekeeper-container.active') &&
                !document.querySelector('.user-setup-container.active')) {
                setTimeout(() => overlay.classList.remove('active'), 500);
            }
        }
    }, 300);
}
function hideLoading() { document.getElementById('loadingOverlay').classList.remove('active'); }

// ========== PWA ==========
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .then(reg => {
                console.log('✅ Service Worker registered');
                window.swRegistration = reg;
                // Check for SW updates periodically
                setInterval(() => reg.update().catch(() => {}), 60000);
            })
            .catch(err => console.log('❌ Service Worker failed:', err));
    });
}
let deferredPrompt;
const installBtn = document.getElementById('installBtn');
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    installBtn.classList.add('show');
});
async function installApp() {
    if (deferredPrompt) {
        deferredPrompt.prompt();
        const result = await deferredPrompt.userChoice;
        if (result.outcome === 'accepted') installBtn.classList.remove('show');
        deferredPrompt = null;
    }
}
installBtn.addEventListener('click', installApp);
window.addEventListener('appinstalled', () => installBtn.classList.remove('show'));
if (window.matchMedia('(display-mode: standalone)').matches || navigator.standalone) {
    installBtn.classList.remove('show');
}

// ========== PUSH NOTIFICATIONS ==========
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
    return outputArray;
}
async function getVapidPublicKey() {
    try {
        const response = await fetch('/api/push/vapid_public_key');
        const data = await response.json();
        vapidPublicKey = data.publicKey;
        return vapidPublicKey;
    } catch(e) { return null; }
}
async function subscribeToPush() {
    if (!window.swRegistration) return false;
    if (!vapidPublicKey) await getVapidPublicKey();
    if (!vapidPublicKey) return false;
    try {
        const subscription = await window.swRegistration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlBase64ToUint8Array(vapidPublicKey)
        });
        pushSubscription = subscription;
        await fetch('/api/push/subscribe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                subscription: {
                    endpoint: subscription.endpoint,
                    keys: {
                        p256dh: btoa(String.fromCharCode.apply(null, new Uint8Array(subscription.getKey('p256dh')))),
                        auth: btoa(String.fromCharCode.apply(null, new Uint8Array(subscription.getKey('auth'))))
                    }
                }
            })
        });
        notificationsEnabled = true;
        updateNotificationButton();
        return true;
    } catch(e) { return false; }
}
async function unsubscribeFromPush() {
    if (!pushSubscription) {
        if (window.swRegistration) {
            const sub = await window.swRegistration.pushManager.getSubscription();
            if (sub) pushSubscription = sub;
        }
    }
    if (!pushSubscription) return;
    try {
        await pushSubscription.unsubscribe();
        pushSubscription = null;
        notificationsEnabled = false;
        updateNotificationButton();
    } catch(e) {}
}
async function toggleNotifications() {
    if (!('Notification' in window)) { alert('Not supported.'); return; }
    if (notificationsEnabled) { await unsubscribeFromPush(); return; }
    if (Notification.permission === 'denied') { alert('Blocked.'); return; }
    if (Notification.permission === 'default') {
        const permission = await Notification.requestPermission();
        if (permission !== 'granted') { alert('Allow notifications.'); return; }
    }
    const success = await subscribeToPush();
    alert(success ? '🔔 Notifications enabled!' : '❌ Failed.');
}
function updateNotificationButton() {
    const btn = document.getElementById('notificationBtn');
    if (notificationsEnabled) {
        btn.textContent = '🔔 Enabled';
        btn.classList.add('enabled');
    } else {
        btn.textContent = '🔔 Enable';
        btn.classList.remove('enabled');
    }
}
function isPushSupported() {
    return 'PushManager' in window && 'serviceWorker' in navigator && 'Notification' in window;
}

// ========== OFFLINE ==========
const offlineOverlay = document.getElementById('offlineOverlay');
function showOfflineOverlay() {
    const chatActive = document.getElementById('chatScreen').classList.contains('active');
    const adminActive = document.getElementById('adminPanel').classList.contains('active');
    const gatekeeperActive = document.getElementById('gatekeeperScreen').classList.contains('active');
    const userSetupActive = document.getElementById('userSetupScreen').classList.contains('active');
    const loginVisible = document.getElementById('loginScreen').style.display !== 'none';
    if (chatActive) lastActiveScreen = 'chat';
    else if (adminActive) lastActiveScreen = 'admin';
    else if (gatekeeperActive) lastActiveScreen = 'gatekeeper';
    else if (userSetupActive) lastActiveScreen = 'userSetup';
    else if (loginVisible) lastActiveScreen = 'login';
    else lastActiveScreen = null;
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
    if (lastActiveScreen === 'chat') {
        if (window.chatUsername && window.chatGroup) {
            document.getElementById('chatScreen').classList.add('active');
            connectToChat(window.chatUsername, window.chatGroup);
        } else {
            document.getElementById('loginScreen').style.display = 'flex';
        }
    } else if (lastActiveScreen === 'admin') {
        document.getElementById('adminPanel').classList.add('active');
        loadAdminData();
    } else if (lastActiveScreen === 'gatekeeper') {
        document.getElementById('gatekeeperScreen').classList.add('active');
    } else if (lastActiveScreen === 'userSetup') {
        document.getElementById('userSetupScreen').classList.add('active');
    } else {
        document.getElementById('loginScreen').style.display = 'flex';
    }
    lastActiveScreen = null;
}
document.getElementById('retryOfflineBtn').addEventListener('click', function() {
    if (navigator.onLine) hideOfflineOverlay();
    else {
        this.textContent = '⏳ Still offline...';
        setTimeout(() => this.textContent = '↻ Retry', 1000);
    }
});

// ========== DOM READY ==========
document.addEventListener('DOMContentLoaded', function() {
    if (!navigator.onLine) showOfflineOverlay();

    document.getElementById('loginBtn').addEventListener('click', function(e) {
        if (this.classList.contains('btn-loading')) return;
        showLoading('Logging in', login);
    });
    document.getElementById('gatekeeperBtn').addEventListener('click', function(e) {
        if (this.classList.contains('btn-loading')) return;
        showLoading('Verifying', gatekeeperLogin);
    });
    document.getElementById('enterChatBtn').addEventListener('click', function(e) {
        if (this.classList.contains('btn-loading')) return;
        showLoading('Entering Chat', enterChat);
    });
    document.getElementById('loginPassword').addEventListener('keypress', function(e) {
        if(e.key === 'Enter') showLoading('Logging in', login);
    });
    document.getElementById('gatekeeperPassword').addEventListener('keypress', function(e) {
        if(e.key === 'Enter') showLoading('Verifying', gatekeeperLogin);
    });
    document.getElementById('userDisplayName').addEventListener('keypress', function(e) {
        if(e.key === 'Enter') showLoading('Entering Chat', enterChat);
    });
    
    document.getElementById('messageInput').addEventListener('input', function() {
        this.style.height = 'auto';
        this.style.height = Math.min(this.scrollHeight, 80) + 'px';
        if(ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({type:'typing'}));
            clearTimeout(typingTimeout);
            typingTimeout = setTimeout(() => {
                if(ws && ws.readyState === WebSocket.OPEN)
                    ws.send(JSON.stringify({type:'stop_typing'}));
            }, 1000);
        }
    });

    const messagesContainer = document.getElementById('messages');
    messagesContainer.addEventListener('scroll', function() {
        const threshold = 100;
        const atBottom = (this.scrollHeight - this.scrollTop - this.clientHeight) < threshold;
        if (atBottom && !isAtBottom) {
            isAtBottom = true;
            unreadCount = 0;
            updateNewMsgsButton();
        } else if (!atBottom && isAtBottom) {
            isAtBottom = false;
        }
    });

    document.addEventListener('visibilitychange', function() {
        if (document.visibilityState === 'visible' && document.getElementById('chatScreen').classList.contains('active')) {
            if (!navigator.onLine) clearMessagesOffline();
            else if (!ws || ws.readyState !== WebSocket.OPEN) {
                if (window.chatUsername && window.chatGroup) connectToChat(window.chatUsername, window.chatGroup);
            }
        }
    });

    window.addEventListener('online', function() {
        if (offlineOverlay.classList.contains('active')) {
            if (lastActiveScreen === 'chat' && window.chatUsername && window.chatGroup) {
                offlineOverlay.classList.remove('active');
                document.getElementById('chatScreen').classList.add('active');
                document.getElementById('offlineBar').classList.remove('active');
                connectToChat(window.chatUsername, window.chatGroup);
                lastActiveScreen = null;
            } else {
                hideOfflineOverlay();
            }
        } else {
            document.getElementById('offlineBar').classList.remove('active');
        }
    });

    window.addEventListener('offline', function() {
        showOfflineOverlay();
        if (document.getElementById('chatScreen').classList.contains('active')) clearMessagesOffline();
    });
    
    if (isPushSupported()) {
        getVapidPublicKey();
        if (window.swRegistration) {
            window.swRegistration.pushManager.getSubscription()
                .then(sub => {
                    if (sub) {
                        pushSubscription = sub;
                        notificationsEnabled = true;
                        updateNotificationButton();
                    }
                }).catch(e => console.error(e));
        }
    } else {
        const btn = document.getElementById('notificationBtn');
        if (btn) btn.style.display = 'none';
    }
});

function clearMessagesOffline() {
    const container = document.getElementById('messages');
    container.innerHTML = '<div class="offline-message">🔴 No internet connection. Messages are hidden.</div>';
    messagesData = {};
    document.getElementById('offlineBar').classList.add('active');
    updateStatus(false);
    if (ws && ws.readyState === WebSocket.OPEN) ws.close();
}

// ========== NEW MSGS BUTTON ==========
function updateNewMsgsButton() {
    const btn = document.getElementById('newMsgsBtn');
    const countSpan = document.getElementById('newMsgsCount');
    if (unreadCount > 0) {
        countSpan.textContent = unreadCount;
        btn.classList.add('show');
    } else {
        btn.classList.remove('show');
    }
}
function scrollToBottom() {
    const container = document.getElementById('messages');
    container.scrollTop = container.scrollHeight;
    unreadCount = 0;
    updateNewMsgsButton();
    isAtBottom = true;
}

// ========== LOGIN ==========
async function login() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    if(!username || !password) { showError('Please enter username and password'); hideLoading(); return; }
    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        const data = await response.json();
        if(data.success) {
            currentUser = {username: data.username, role: data.role};
            hideLoading();
            if(data.role === 'admin') {
                document.getElementById('loginScreen').style.display = 'none';
                document.getElementById('adminPanel').classList.add('active');
                document.getElementById('adminUsername').textContent = data.username;
                loadAdminData();
            } else {
                document.getElementById('loginScreen').style.display = 'none';
                document.getElementById('gatekeeperScreen').classList.add('active');
                document.getElementById('gatekeeperUsername').value = data.username;
                document.getElementById('gatekeeperPassword').value = '';
                if(data.display_name) {
                    const successDiv = document.createElement('div');
                    successDiv.id = 'gatekeeperSuccess';
                    successDiv.className = 'success-message';
                    successDiv.textContent = '✅ Welcome back ' + data.display_name + '! Enter your password to continue.';
                    const existing = document.getElementById('gatekeeperSuccess');
                    if(existing) existing.remove();
                    document.querySelector('.gatekeeper-card').appendChild(successDiv);
                    successDiv.style.display = 'block';
                }
            }
        } else {
            showError(data.message || 'Invalid credentials.');
            hideLoading();
        }
    } catch(e) {
        showError('Connection error. Please try again.');
        hideLoading();
    }
}

// ========== GATEKEEPER ==========
async function gatekeeperLogin() {
    const username = document.getElementById('gatekeeperUsername').value.trim();
    const password = document.getElementById('gatekeeperPassword').value;
    if(!username || !password) { showGatekeeperError('Please enter your password'); hideLoading(); return; }
    try {
        const response = await fetch('/gatekeeper', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        const data = await response.json();
        if(data.success) {
            gatekeeperData = data;
            document.getElementById('gatekeeperScreen').classList.remove('active');
            document.getElementById('userSetupScreen').classList.add('active');
            document.getElementById('userGroupName').value = data.assigned_group;
            document.getElementById('userGroupPassword').value = data.assigned_group_password;
            groupPassword = data.assigned_group_password;
            if(data.display_name) {
                document.getElementById('userDisplayName').value = data.display_name;
                showSetupSuccess('✅ Welcome back! Your display name is saved.');
            } else {
                document.getElementById('userDisplayName').value = '';
                showSetupSuccess('✅ Verified! Enter your display name to start chatting.');
            }
            hideLoading();
        } else {
            showGatekeeperError(data.message || 'Invalid credentials');
            hideLoading();
        }
    } catch(e) {
        showGatekeeperError('Connection error. Please try again.');
        hideLoading();
    }
}

// ========== ENTER CHAT ==========
async function enterChat() {
    const displayName = document.getElementById('userDisplayName').value.trim();
    const groupName = document.getElementById('userGroupName').value.trim();
    if(!displayName) { showSetupError('Please enter your display name'); hideLoading(); return; }
    if(!groupName) { showSetupError('Group missing. Please contact admin.'); hideLoading(); return; }
    try {
        await fetch('/save_display_name', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: gatekeeperData.username, display_name: displayName})
        });
    } catch(e) {}
    window.chatUsername = displayName;
    window.chatGroup = groupName;
    window.groupPassword = groupPassword;
    document.getElementById('userSetupScreen').classList.remove('active');
    document.getElementById('chatScreen').classList.add('active');
    document.getElementById('messages').innerHTML = '';
    messagesData = {};
    hideLoading();
    connectToChat(displayName, groupName);
}

// ========== CONNECT TO CHAT ==========
function connectToChat(username, group) {
    messagesData = {};
    const container = document.getElementById('messages');
    container.innerHTML = '<div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div>';
    document.getElementById('offlineBar').classList.remove('active');
    if (!navigator.onLine) {
        container.innerHTML = '<div class="offline-message">🔴 No internet connection. Messages are hidden.</div>';
        document.getElementById('offlineBar').classList.add('active');
        updateStatus(false);
        return;
    }
    document.getElementById('groupTitle').innerHTML = '# ' + group;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = protocol + '//' + window.location.host + '/ws';
    ws = new WebSocket(url);
    ws.onopen = function() {
        updateStatus(true);
        document.getElementById('offlineBar').classList.remove('active');
        const offlineMsg = document.querySelector('.offline-message');
        if (offlineMsg) offlineMsg.remove();
        ws.send(JSON.stringify({type: 'join', username: username, group: group}));
        reconnectAttempts = 0;
        isManuallyReconnecting = false;
        unreadCount = 0;
        updateNewMsgsButton();
        isAtBottom = true;
    };
    ws.onmessage = async function(e) {
        try {
            let d = JSON.parse(e.data);
            if(d.type === 'error') { showError(d.message); ws.close(); return; }
            if(d.type === 'ready') { groupSalt = d.salt; addSystemMessage('🔐 Connected - Messages last 24 hours'); }
            else if(d.type === 'history') {
                document.getElementById('messages').innerHTML = '';
                const offlineMsg = document.querySelector('.offline-message');
                if (offlineMsg) offlineMsg.remove();
                messagesData = {};
                if(d.messages && d.messages.length > 0) {
                    for(let msg of d.messages) {
                        try {
                            let dec = await decrypt(msg.ciphertext, window.groupPassword, msg.salt);
                            let isSent = msg.sender === window.chatUsername;
                            messagesData[msg.id] = {
                                sender: msg.sender, text: dec, timestamp: msg.created_at,
                                voice_url: msg.voice_url, media_url: msg.media_url,
                                media_type: msg.media_type, delivered: msg.delivered,
                                read_by: msg.read_by || []
                            };
                            if (msg.delivered) deliveredMessages.add(msg.id);
                            if (msg.read_by && msg.read_by.length > 0) readMessages.add(msg.id);
                            addMessage(msg.sender, dec, isSent, msg.timestamp, msg.id, msg.reply_to, msg.voice_url, msg.media_url, msg.media_type, msg.delivered, msg.read_by);
                        } catch(e) {
                            let isSent = msg.sender === window.chatUsername;
                            messagesData[msg.id] = {
                                sender: msg.sender, text: '🔒 Encrypted', timestamp: msg.created_at,
                                voice_url: msg.voice_url, media_url: msg.media_url,
                                media_type: msg.media_type, delivered: msg.delivered,
                                read_by: msg.read_by || []
                            };
                            addMessage(msg.sender, '🔒 Encrypted', isSent, msg.timestamp, msg.id, msg.reply_to, msg.voice_url, msg.media_url, msg.media_type, msg.delivered, msg.read_by);
                        }
                    }
                }
                setTimeout(() => {
                    const c = document.getElementById('messages');
                    c.scrollTop = c.scrollHeight;
                    isAtBottom = true;
                    unreadCount = 0;
                    updateNewMsgsButton();
                }, 100);
            } else if(d.type === 'message') {
                if (d.temp_id) {
                    const placeholderEl = document.querySelector(`.message[data-message-id="${d.temp_id}"]`);
                    if (placeholderEl) placeholderEl.remove();
                    delete messagesData[d.temp_id];
                }
                try {
                    let dec = await decrypt(d.ciphertext, window.groupPassword, d.salt);
                    let isSent = d.sender === window.chatUsername;
                    messagesData[d.message_id] = {
                        sender: d.sender, text: dec, timestamp: d.timestamp,
                        voice_url: d.voice_url, media_url: d.media_url,
                        media_type: d.media_type, delivered: d.delivered || false,
                        read_by: d.read_by || []
                    };
                    addMessage(d.sender, dec, isSent, d.timestamp, d.message_id, d.reply_to, d.voice_url, d.media_url, d.media_type, d.delivered, d.read_by);
                    if (!isSent && ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'delivered', message_id: d.message_id }));
                        ws.send(JSON.stringify({ type: 'read', message_id: d.message_id }));
                    }
                } catch(e) {
                    messagesData[d.message_id] = {
                        sender: d.sender, text: '🔒 Encrypted', timestamp: d.timestamp,
                        voice_url: d.voice_url, media_url: d.media_url,
                        media_type: d.media_type, delivered: d.delivered || false,
                        read_by: d.read_by || []
                    };
                    addMessage(d.sender, '🔒 Encrypted', false, d.timestamp, d.message_id, d.reply_to, d.voice_url, d.media_url, d.media_type, d.delivered, d.read_by);
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'delivered', message_id: d.message_id }));
                        ws.send(JSON.stringify({ type: 'read', message_id: d.message_id }));
                    }
                }
                const c = document.getElementById('messages');
                const threshold = 100;
                const atBottom = (c.scrollHeight - c.scrollTop - c.clientHeight) < threshold;
                if (!atBottom && !d.temp_id) {
                    unreadCount++;
                    updateNewMsgsButton();
                }
            } else if(d.type === 'message_delivered') {
                if (d.message_id) {
                    deliveredMessages.add(d.message_id);
                    const msgEl = document.querySelector(`.message[data-message-id="${d.message_id}"]`);
                    if (msgEl) {
                        const tick = msgEl.querySelector('.msg-tick');
                        if (tick && !tick.classList.contains('read')) {
                            tick.textContent = '✓✓';
                            tick.classList.add('delivered');
                        }
                    }
                }
            } else if(d.type === 'message_read') {
                if (d.message_id) {
                    readMessages.add(d.message_id);
                    deliveredMessages.add(d.message_id);
                    const msgEl = document.querySelector(`.message[data-message-id="${d.message_id}"]`);
                    if (msgEl) {
                        const tick = msgEl.querySelector('.msg-tick');
                        if (tick) {
                            tick.textContent = '✓✓';
                            tick.classList.remove('delivered');
                            tick.classList.add('read');
                        }
                    }
                }
            } else if(d.type === 'users') {
                updateUsers(d.users);
            } else if(d.type === 'user_joined') {
                addSystemMessage('👤 ' + d.user + ' joined');
            } else if(d.type === 'user_left') {
                addSystemMessage('👋 ' + d.user + ' left');
            } else if(d.type === 'typing') {
                document.getElementById('typingIndicator').innerHTML = '✏️ ' + d.user + ' typing...';
            } else if(d.type === 'stop_typing') {
                document.getElementById('typingIndicator').innerHTML = '';
            } else if(d.type === 'pong') {
                updateStatus(true);
            }
        } catch(e) { console.error('Error processing message:', e); }
    };
    ws.onerror = function(e) { updateStatus(false); };
    ws.onclose = function() {
        updateStatus(false);
        document.getElementById('offlineBar').classList.add('active');
        const messagesContainer = document.getElementById('messages');
        messagesContainer.innerHTML = '<div class="offline-message">🔴 No internet connection. Messages are hidden.</div>';
        messagesData = {};
        if(document.getElementById('chatScreen').classList.contains('active')) {
            if (!isManuallyReconnecting) {
                reconnectAttempts++;
                if(reconnectAttempts < 5) setTimeout(() => connectToChat(username, group), 3000);
            }
        }
    };
}

function reconnectManually() {
    isManuallyReconnecting = true;
    if (ws) ws.close();
    messagesData = {};
    const container = document.getElementById('messages');
    container.innerHTML = '<div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div>';
    document.getElementById('offlineBar').classList.remove('active');
    setTimeout(() => connectToChat(window.chatUsername, window.chatGroup), 500);
}

// ========== UI FUNCTIONS ==========
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('overlay').classList.toggle('active');
}
function updateStatus(online) {
    let status = document.getElementById('connectionStatus');
    let badge = document.getElementById('connectionBadge');
    if(online) {
        status.innerHTML = '🟢 Connected';
        status.className = 'connection-status status-online';
        badge.innerHTML = '● Online';
        badge.style.color = '#0f0';
        document.getElementById('offlineBar').classList.remove('active');
    } else {
        status.innerHTML = '🔴 Disconnected';
        status.className = 'connection-status status-offline';
        badge.innerHTML = '● Offline';
        badge.style.color = '#ff4444';
    }
}
function addSystemMessage(text) {
    let msgs = document.getElementById('messages');
    const offlineMsg = document.querySelector('.offline-message');
    if (offlineMsg) offlineMsg.remove();
    let div = document.createElement('div');
    div.className = 'system-message';
    div.textContent = text;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
}

// ========== ADD MESSAGE ==========
function addMessage(sender, text, isSent, timestamp, messageId, replyTo, voiceUrl, mediaUrl, mediaType, delivered, readBy) {
    let msgs = document.getElementById('messages');
    const offlineMsg = document.querySelector('.offline-message');
    if (offlineMsg) offlineMsg.remove();
    let div = document.createElement('div');
    div.className = 'message ' + (isSent ? 'sent' : 'received');
    div.dataset.messageId = messageId;
    div.dataset.sender = sender;
    div.dataset.text = text;
    if (voiceUrl) div.classList.add('voice-message');

    let time = timestamp ? new Date(timestamp * 1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '';

    // Determine tick
    let tickHtml = '';
    if (isSent) {
        const isRead = (readBy && readBy.length > 0) || readMessages.has(messageId);
        const isDelivered = delivered || deliveredMessages.has(messageId) || isRead;
        if (isRead) {
            tickHtml = `<span class="msg-tick read">✓✓</span>`;
        } else if (isDelivered) {
            tickHtml = `<span class="msg-tick delivered">✓✓</span>`;
        } else {
            tickHtml = `<span class="msg-tick">✓</span>`;
        }
    }

    // Reply preview
    let replyHtml = '';
    if(replyTo && messagesData[replyTo]) {
        let original = messagesData[replyTo];
        let originalText = original.text || 'Message';
        replyHtml = '<div class="message-reply-preview" onclick="scrollToMessage(' + replyTo + ')">' +
                    '↩️ <span class="reply-sender">' + escapeHtml(original.sender) + '</span>: ' +
                    '<span class="reply-text">' + escapeHtml(originalText.substring(0, 60)) + (originalText.length > 60 ? '...' : '') + '</span>' +
                    '</div>';
    }

    let messageContent = '';
    if (voiceUrl) {
        const downloadLink = voiceUrl + '?download=1';
        // Deterministic waveform
        const bars = [];
        const seed = (messageId || Date.now()).toString();
        let seedNum = 0;
        for (let i = 0; i < seed.length; i++) seedNum += seed.charCodeAt(i);
        for (let i = 0; i < 28; i++) {
            const h = 5 + ((seedNum * (i + 3) * 13) % 18);
            bars.push(h);
        }
        const waveHtml = bars.map(h => 
            `<span class="voice-wave-bar" style="height:${h}px;"></span>`
        ).join('');
        const initial = (sender || '?').charAt(0).toUpperCase();
        
        messageContent = `
            <div class="voice-player" data-voice-url="${voiceUrl}" data-message-id="${messageId}">
                <div class="voice-avatar">
                    ${initial}
                </div>
                <button class="voice-play-btn" onclick="playVoice(this, '${voiceUrl}')">
                    <span class="play-icon">▶</span>
                </button>
                <div class="voice-waveform" onclick="seekAudio(event, this)">
                    ${waveHtml}
                </div>
                <div class="voice-ball"></div>
                <a href="${downloadLink}" download class="voice-download" title="Download audio">⬇</a>
            </div>
            <div class="voice-info">
                <span class="voice-duration" data-duration-for="${messageId}">0:00</span>
                <span class="voice-time">${time}${isSent ? tickHtml : ''}</span>
            </div>
            ${text && text !== '🎤 Voice message' ? '<div class="voice-caption" style="font-size:11px;color:#888;margin-top:2px;">' + escapeHtml(text) + '</div>' : ''}
        `;
    } else if (mediaUrl) {
        if (mediaType && mediaType.startsWith('image/')) {
            const isPlaceholder = mediaUrl.startsWith('blob:') || messageId.toString().startsWith('temp_');
            const placeholderClass = isPlaceholder ? 'placeholder' : '';
            const downloadLink = mediaUrl + '?download=1';
            messageContent = `
                <div class="image-bubble ${placeholderClass}">
                    <img src="${mediaUrl}" onclick="window.open('${mediaUrl}','_blank')" loading="lazy">
                    ${isPlaceholder ? '<div class="spinner"></div>' : ''}
                    <div class="file-name">
                        <span>📎 ${escapeHtml(text.replace('📎 ',''))}</span>
                        <a href="${downloadLink}" download class="download-link" title="Download image">⬇</a>
                    </div>
                </div>
                <div class="message-time">${time}${isSent ? tickHtml : ''}</div>
            `;
        } else {
            const downloadLink = mediaUrl + '?download=1';
            messageContent = `
                <div class="message-bubble">
                    ${escapeHtml(text)}
                    <div style="margin-top:6px;">
                        <a href="${mediaUrl}" target="_blank" style="color:#0f0;text-decoration:underline;">📎 Open</a>
                        &nbsp;|&nbsp;
                        <a href="${downloadLink}" download style="color:#0f0;text-decoration:underline;">⬇️ Download</a>
                    </div>
                </div>
                <div class="message-time">${time}${isSent ? tickHtml : ''}</div>
            `;
        }
    } else {
        messageContent = '<div class="message-bubble">' + escapeHtml(text) + '</div>' +
                         '<div class="message-time">' + time + (isSent ? tickHtml : '') + '</div>';
    }

    const actionsHtml = `
        <div class="message-actions">
            <button onclick="replyToMessage(${messageId})">↩️ Reply</button>
        </div>
    `;

    div.innerHTML = '<div class="message-sender">' + (isSent ? 'YOU' : escapeHtml(sender)) + '</div>' + 
                    replyHtml +
                    messageContent + 
                    actionsHtml;

    // Swipe to reply
    let touchStartX = 0, touchCurrentX = 0, touchStartY = 0;
    div.addEventListener('touchstart', function(e) {
        touchStartX = e.touches[0].clientX;
        touchStartY = e.touches[0].clientY;
        touchCurrentX = touchStartX;
    }, {passive: true});
    div.addEventListener('touchmove', function(e) {
        touchCurrentX = e.touches[0].clientX;
        let diffX = touchCurrentX - touchStartX;
        let diffY = e.touches[0].clientY - touchStartY;
        if (diffX > 0 && diffX < 80 && Math.abs(diffY) < 30) {
            div.style.transform = 'translateX(' + diffX + 'px)';
        }
    }, {passive: true});
    div.addEventListener('touchend', function(e) {
        let diffX = touchCurrentX - touchStartX;
        div.style.transform = '';
        if (diffX >= 60) replyToMessage(messageId);
        touchStartX = 0; touchCurrentX = 0; touchStartY = 0;
    }, {passive: true});

    msgs.appendChild(div);
    if (isAtBottom) msgs.scrollTop = msgs.scrollHeight;
    
    // Immediately load the audio duration
    if (voiceUrl) {
        const tempAudio = new Audio();
        tempAudio.preload = 'metadata';
        tempAudio.addEventListener('loadedmetadata', function() {
            if (isFinite(this.duration) && this.duration > 0) {
                const mins = Math.floor(this.duration / 60);
                const secs = Math.floor(this.duration % 60);
                const durationSpan = div.querySelector(`.voice-duration[data-duration-for="${messageId}"]`);
                if (durationSpan) {
                    durationSpan.textContent = mins + ':' + String(secs).padStart(2, '0');
                }
            }
        });
        tempAudio.addEventListener('error', function() {
            const durationSpan = div.querySelector(`.voice-duration[data-duration-for="${messageId}"]`);
            if (durationSpan) durationSpan.textContent = '0:00';
        });
        tempAudio.src = voiceUrl;
    }
}

function replyToMessage(messageId) {
    if (!messageId || !messagesData[messageId]) return;
    replyingToMessageId = messageId;
    let original = messagesData[messageId];
    document.getElementById('replyPreviewSender').textContent = original.sender;
    document.getElementById('replyPreviewText').textContent = original.text.substring(0, 60) + (original.text.length > 60 ? '...' : '');
    document.getElementById('replyPreview').style.display = 'flex';
    document.getElementById('messageInput').focus();
}
function cancelReply() {
    replyingToMessageId = null;
    document.getElementById('replyPreview').style.display = 'none';
}
function scrollToMessage(messageId) {
    let messages = document.querySelectorAll('.message');
    for (let msg of messages) {
        if (msg.dataset.messageId == messageId) {
            msg.scrollIntoView({ behavior: 'smooth', block: 'center' });
            msg.style.border = '2px solid #ffaa00';
            setTimeout(() => { msg.style.border = ''; }, 2000);
            break;
        }
    }
}
function updateUsers(users) {
    let ul = document.getElementById('usersList');
    if(!users || users.length === 0) ul.innerHTML = '<div class="user-item">No users online</div>';
    else ul.innerHTML = users.map(u => '<div class="user-item">' + escapeHtml(u) + '</div>').join('');
}
function escapeHtml(t) { let d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

// ========== ENCRYPTION ==========
async function encrypt(text, password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        {name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256'},
        keyMaterial, {name: 'AES-GCM', length: 256}, true, ['encrypt', 'decrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({name: 'AES-GCM', iv: iv}, key, enc.encode(text));
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode.apply(null, combined));
}
async function decrypt(encrypted, password, salt) {
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        {name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256'},
        keyMaterial, {name: 'AES-GCM', length: 256}, true, ['encrypt', 'decrypt']
    );
    const data = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const decrypted = await crypto.subtle.decrypt({name: 'AES-GCM', iv: iv}, key, ciphertext);
    return dec.decode(decrypted);
}
function generateSalt() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode.apply(null, array));
}

// ========== SEND MESSAGE ==========
async function sendMessage() {
    const input = document.getElementById('messageInput');
    const text = input.value.trim();
    if (!text) return;
    if (!ws || ws.readyState !== WebSocket.OPEN) { alert('Not connected.'); return; }
    if (!window.groupPassword) { alert('Group password not set.'); return; }
    try {
        const salt = generateSalt();
        const encrypted = await encrypt(text, window.groupPassword, salt);
        ws.send(JSON.stringify({
            type: 'message',
            ciphertext: encrypted,
            salt: salt,
            reply_to: replyingToMessageId || null
        }));
        input.value = '';
        input.style.height = 'auto';
        cancelReply();
    } catch (error) { alert('Error sending message.'); }
}

// ========== VOICE RECORDING ==========
function startHoldRecording() {
    if (isRecording) return;
    isHolding = true;
    holdTimer = setTimeout(() => { if (isHolding) startRecording(); }, 300);
}
function stopHoldRecording() {
    isHolding = false;
    clearTimeout(holdTimer);
    if (isRecording) {
        if (recordingSeconds < 1) cancelRecording();
        else stopRecordingAndSend();
    }
}
async function startRecording() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        let mimeType = 'audio/webm;codecs=opus';
        if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'audio/webm';
        if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'audio/mp4';
        mediaRecorder = new MediaRecorder(stream, { mimeType: mimeType, audioBitsPerSecond: 64000 });
        audioChunks = [];
        mediaRecorder.ondataavailable = (event) => { if (event.data.size > 0) audioChunks.push(event.data); };
        mediaRecorder.onstop = async () => {
            if (audioChunks.length > 0 && recordingSeconds >= 1) {
                const audioBlob = new Blob(audioChunks, { type: mediaRecorder.mimeType || 'audio/webm' });
                await uploadVoice(audioBlob);
            }
            stream.getTracks().forEach(track => track.stop());
            document.getElementById('voiceBtn').classList.remove('recording');
            document.getElementById('voiceIcon').textContent = '🎙️';
            document.getElementById('recordingStatus').classList.remove('active');
            clearInterval(recordingTimer);
            recordingTimer = null;
            isRecording = false;
            recordingSeconds = 0;
            document.getElementById('recordingTimer').textContent = '00:00';
        };
        mediaRecorder.start(1000);
        isRecording = true;
        document.getElementById('voiceBtn').classList.add('recording');
        document.getElementById('voiceIcon').textContent = '⏺️';
        document.getElementById('recordingStatus').classList.add('active');
        recordingSeconds = 0;
        updateRecordingTimer();
        recordingTimer = setInterval(updateRecordingTimer, 1000);
    } catch (error) { alert('Could not access microphone.'); }
}
function updateRecordingTimer() {
    recordingSeconds++;
    const mins = Math.floor(recordingSeconds / 60);
    const secs = recordingSeconds % 60;
    document.getElementById('recordingTimer').textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}
function stopRecordingAndSend() { if (mediaRecorder && isRecording) mediaRecorder.stop(); }
function cancelRecording() {
    if (mediaRecorder && isRecording) {
        mediaRecorder.stop();
        isRecording = false;
        audioChunks = [];
        clearInterval(recordingTimer);
        recordingTimer = null;
        recordingSeconds = 0;
        document.getElementById('recordingTimer').textContent = '00:00';
    }
    document.getElementById('voiceBtn').classList.remove('recording');
    document.getElementById('voiceIcon').textContent = '🎙️';
    document.getElementById('recordingStatus').classList.remove('active');
}
async function uploadVoice(audioBlob) {
    const formData = new FormData();
    formData.append('file', audioBlob, 'voice.webm');
    try {
        const response = await fetch('/api/upload_voice', { method: 'POST', body: formData });
        const data = await response.json();
        if (data.success) await sendVoiceMessage(data.url);
        else alert('Failed to upload voice: ' + (data.error || 'Unknown error'));
    } catch (error) { alert('Failed to upload voice.'); }
}
async function sendVoiceMessage(voiceUrl) {
    const input = document.getElementById('messageInput');
    const text = input.value.trim();
    await sendMessageWithVoice(text || '🎤 Voice message', voiceUrl);
}
async function sendMessageWithVoice(text, voiceUrl) {
    if (!ws || ws.readyState !== WebSocket.OPEN) { alert('Not connected.'); return; }
    if (!window.groupPassword) { alert('Group password not set.'); return; }
    try {
        const salt = generateSalt();
        const encrypted = await encrypt(text, window.groupPassword, salt);
        ws.send(JSON.stringify({
            type: 'message',
            ciphertext: encrypted,
            salt: salt,
            reply_to: replyingToMessageId || null,
            voice_url: voiceUrl
        }));
        document.getElementById('messageInput').value = '';
        document.getElementById('messageInput').style.height = 'auto';
        cancelReply();
        document.getElementById('recordingStatus').classList.remove('active');
        document.getElementById('voiceBtn').classList.remove('recording');
        document.getElementById('voiceIcon').textContent = '🎙️';
    } catch (error) { alert('Error sending voice.'); }
}

// ========== AUDIO PLAYER (with clickable waveform) ==========
function playVoice(button, url) {
    const player = button.closest('.voice-player');
    const waveform = player.querySelector('.voice-waveform');
    const ball = player.querySelector('.voice-ball');
    const durationSpan = player.parentElement.querySelector('.voice-duration');
    const bars = waveform.querySelectorAll('.voice-wave-bar');

    if (activeAudio && activeButton !== button) {
        activeAudio.pause();
        if (activeButton) {
            activeButton.querySelector('.play-icon').textContent = '▶';
            activeButton.closest('.voice-player').classList.remove('playing');
        }
    }

    if (activeButton === button && activeAudio) {
        if (activeAudio.paused) {
            activeAudio.play();
            button.querySelector('.play-icon').textContent = '❚❚';
            player.classList.add('playing');
        } else {
            activeAudio.pause();
            button.querySelector('.play-icon').textContent = '▶';
            player.classList.remove('playing');
        }
        return;
    }

    const audio = new Audio(url);
    activeAudio = audio;
    activeButton = button;
    activeProgressBar = waveform;
    activeDurationSpan = durationSpan;

    if (activeAudio) activeAudio.pause();

    audio.onloadedmetadata = function() {
        if (isFinite(this.duration) && this.duration > 0) {
            const mins = Math.floor(this.duration / 60);
            const secs = Math.floor(this.duration % 60);
            durationSpan.textContent = mins + ':' + String(secs).padStart(2, '0');
        }
    };

    audio.ontimeupdate = function() {
        if (!isFinite(this.duration) || this.duration <= 0) return;
        const pct = this.currentTime / this.duration;
        const playedBars = Math.floor(pct * bars.length);
        bars.forEach((bar, i) => {
            if (i < playedBars) bar.classList.add('played');
            else bar.classList.remove('played');
        });
        const ballX = pct * waveform.offsetWidth;
        ball.style.left = (waveform.offsetLeft + ballX) + 'px';
        const mins = Math.floor(this.currentTime / 60);
        const secs = Math.floor(this.currentTime % 60);
        durationSpan.textContent = mins + ':' + String(secs).padStart(2, '0');
    };

    audio.onended = function() {
        button.querySelector('.play-icon').textContent = '▶';
        player.classList.remove('playing');
        bars.forEach(bar => bar.classList.remove('played'));
        ball.style.left = waveform.offsetLeft + 'px';
        const mins = Math.floor(this.duration / 60);
        const secs = Math.floor(this.duration % 60);
        durationSpan.textContent = mins + ':' + String(secs).padStart(2, '0');
        activeAudio = null;
        activeButton = null;
        activeProgressBar = null;
    };

    audio.onerror = function() {
        button.querySelector('.play-icon').textContent = '▶';
        player.classList.remove('playing');
        durationSpan.textContent = '0:00';
        activeAudio = null;
        activeButton = null;
    };

    audio.play();
    button.querySelector('.play-icon').textContent = '❚❚';
    player.classList.add('playing');
}

// Clickable waveform — tap anywhere on the bars to seek
function seekAudio(event, waveform) {
    if (!activeAudio) return;
    if (activeProgressBar !== waveform) return;
    const rect = waveform.getBoundingClientRect();
    let clientX = event.clientX;
    if (event.touches && event.touches.length > 0) clientX = event.touches[0].clientX;
    const x = clientX - rect.left;
    const pct = Math.min(1, Math.max(0, x / rect.width));
    if (isFinite(activeAudio.duration) && activeAudio.duration > 0) {
        activeAudio.currentTime = activeAudio.duration * pct;
    }
}

// ========== MEDIA SHARING ==========
async function shareMedia() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        if (file.size > 10 * 1024 * 1024) { alert('Max 10MB'); return; }
        const tempId = 'temp_' + Date.now();
        const localUrl = URL.createObjectURL(file);
        const text = '📎 ' + file.name;
        const timestamp = Date.now() / 1000;
        messagesData[tempId] = { sender: window.chatUsername, text: text, timestamp: timestamp, media_url: localUrl, media_type: file.type };
        addMessage(window.chatUsername, text, true, timestamp, tempId, null, null, localUrl, file.type);
        const formData = new FormData();
        formData.append('file', file);
        try {
            const response = await fetch('/api/upload_media', { method: 'POST', body: formData });
            const data = await response.json();
            if (data.success) {
                const salt = generateSalt();
                const encrypted = await encrypt(text, window.groupPassword, salt);
                ws.send(JSON.stringify({
                    type: 'message',
                    ciphertext: encrypted,
                    salt: salt,
                    reply_to: replyingToMessageId || null,
                    media_url: data.url,
                    media_type: data.type || file.type,
                    temp_id: tempId
                }));
            } else alert('Upload failed: ' + (data.error || 'Unknown error'));
        } catch (error) { alert('Failed to upload image.'); }
        setTimeout(() => URL.revokeObjectURL(localUrl), 5000);
    };
    input.click();
}

// ========== ADMIN ==========
async function loadAdminData() {
    try {
        const response = await fetch('/admin/data');
        const data = await response.json();
        document.getElementById('statUsers').textContent = data.users ? data.users.length : 0;
        document.getElementById('statMessages').textContent = data.messages_count || 0;
        document.getElementById('statGroups').textContent = data.groups ? data.groups.length : 0;
        document.getElementById('statOnline').textContent = data.online_count || 0;
        const usersBody = document.getElementById('usersTableBody');
        usersBody.innerHTML = '';
        if (data.users) {
            data.users.forEach(user => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${escapeHtml(user.username)}</td><td>${escapeHtml(user.assigned_group || 'None')}</td><td>${escapeHtml(user.display_name || '')}</td><td>${user.status || 'offline'}</td><td>${user.username !== 'Mpc' ? `<button onclick="deleteUser('${user.username}')" class="action-btn">Delete</button>` : 'Admin'}</td>`;
                usersBody.appendChild(tr);
            });
        }
        const groupsBody = document.getElementById('groupsTableBody');
        groupsBody.innerHTML = '';
        if (data.groups) {
            data.groups.forEach(group => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${escapeHtml(group.group_name)}</td><td>${escapeHtml(group.created_by)}</td><td><button onclick="deleteGroup('${group.group_name}')" class="action-btn">Delete</button></td>`;
                groupsBody.appendChild(tr);
            });
        }
        const messagesBody = document.getElementById('messagesTableBody');
        messagesBody.innerHTML = '';
        if (data.messages) {
            data.messages.forEach(msg => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${escapeHtml(msg.sender)}</td><td>${escapeHtml(msg.group_name)}</td><td>${new Date(msg.created_at * 1000).toLocaleString()}</td><td><button onclick="deleteMessage(${msg.id})" class="action-btn">Delete</button></td>`;
                messagesBody.appendChild(tr);
            });
        }
        const logsBody = document.getElementById('logsTableBody');
        logsBody.innerHTML = '';
        if (data.logs) {
            data.logs.forEach(log => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${escapeHtml(log.admin_username)}</td><td>${escapeHtml(log.action)}</td><td>${escapeHtml(log.target || '')}</td><td>${new Date(log.created_at * 1000).toLocaleString()}</td>`;
                logsBody.appendChild(tr);
            });
        }
    } catch (error) { console.error('Admin load error:', error); }
}
async function createUser() {
    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newPassword').value;
    const groupName = document.getElementById('newGroupName').value.trim();
    const groupPassword = document.getElementById('newGroupPassword').value;
    if (!username || !password || !groupName || !groupPassword) { alert('Fill all fields'); return; }
    try {
        const response = await fetch('/admin/create_user', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, group_name: groupName, group_password: groupPassword })
        });
        const data = await response.json();
        if (data.success) {
            alert('✅ User created!');
            document.getElementById('newUsername').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('newGroupName').value = '';
            document.getElementById('newGroupPassword').value = '';
            loadAdminData();
        } else alert('❌ ' + (data.error || 'Failed'));
    } catch (error) { alert('Error creating user.'); }
}
async function deleteUser(username) {
    if (!confirm(`Delete user "${username}"?`)) return;
    try {
        const response = await fetch('/admin/delete_user', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }) });
        const data = await response.json();
        if (data.success) { alert('✅ User deleted'); loadAdminData(); }
        else alert('❌ ' + (data.message || 'Failed'));
    } catch (error) { alert('Error.'); }
}
async function deleteGroup(groupName) {
    if (!confirm(`Delete group "${groupName}"?`)) return;
    try {
        const response = await fetch('/admin/delete_group', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: groupName }) });
        const data = await response.json();
        if (data.success) { alert('✅ Group deleted'); loadAdminData(); }
        else alert('❌ ' + (data.message || 'Failed'));
    } catch (error) { alert('Error.'); }
}
async function deleteMessage(messageId) {
    if (!confirm('Delete this message?')) return;
    try {
        const response = await fetch('/admin/delete_message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: messageId }) });
        const data = await response.json();
        if (data.success) { alert('✅ Deleted'); loadAdminData(); }
        else alert('❌ Failed');
    } catch (error) { alert('Error.'); }
}

// ========== AUTH ==========
function showError(msg) {
    const err = document.getElementById('loginError');
    err.textContent = msg; err.style.display = 'block';
    setTimeout(() => err.style.display = 'none', 5000);
}
function showGatekeeperError(msg) {
    const err = document.getElementById('gatekeeperError');
    err.textContent = msg; err.style.display = 'block';
    setTimeout(() => err.style.display = 'none', 5000);
}
function showSetupError(msg) {
    const err = document.getElementById('setupError');
    err.textContent = msg; err.style.display = 'block';
    setTimeout(() => err.style.display = 'none', 5000);
}
function showSetupSuccess(msg) {
    const success = document.getElementById('setupSuccess');
    success.textContent = msg; success.style.display = 'block';
    setTimeout(() => success.style.display = 'none', 5000);
}
async function logout() {
    try { await fetch('/logout', { method: 'POST' }); } catch(e) {}
    if (ws && ws.readyState === WebSocket.OPEN) ws.close();
    document.getElementById('chatScreen').classList.remove('active');
    document.getElementById('adminPanel').classList.remove('active');
    document.getElementById('gatekeeperScreen').classList.remove('active');
    document.getElementById('userSetupScreen').classList.remove('active');
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('loginPassword').value = '';
    sessionStorage.clear();
}
function requestAccess() {
    window.open('https://wa.me/250788495861?text=I%20need%20access%20to%20ABAVANDIMWE', '_blank');
}

console.log('✅ ABAVANDIMWE loaded (v7.0)');
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
║           Messages auto-delete after 24 hours              ║
║                    Author: Mugisha Pc                      ║
║                    Version: v7.0                            ║
║                                                            ║
║           ✓✓ Read Receipts (like WhatsApp)                 ║
║           🎙️ Voice Player with Real Duration               ║
║           👆 Tap Waveform to Seek                          ║
║           🖼️ Visible Doodle Background                     ║
║           🚀 Auto-Update Banner                            ║
╚════════════════════════════════════════════════════════════╝
""")
    print(f"[✓] Server running on port {port}")
    print(f"[✓] App Version: {APP_VERSION}")
    print(f"[✓] Admin: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    print(f"[✓] Database: PostgreSQL (Neon) with asyncpg")
    uvicorn.run(app, host="0.0.0.0", port=port)
