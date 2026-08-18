"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
Messages stay for 24 hours then auto-delete
Database: PostgreSQL (Neon) with asyncpg
PWA Ready - Install as Android App with one click
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Depends, HTTPException
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
from datetime import datetime
from typing import Dict, Optional
from collections import defaultdict
from pydantic import BaseModel
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
import asyncpg
from asyncpg import create_pool

app = FastAPI()

# ========== SERVE STATIC FILES FOR PWA ==========
os.makedirs("static/icons", exist_ok=True)
os.makedirs("static/screenshots", exist_ok=True)

app.mount("/icons", StaticFiles(directory="static/icons"), name="icons")
app.mount("/screenshots", StaticFiles(directory="static/screenshots"), name="screenshots")

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

# ========== DATABASE CONFIG ==========
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://neondb_owner:npg_CmR51yqfMxNZ@ep-plain-salad-axxvh942-pooler.c-4.us-east-2.aws.neon.tech/neondb?sslmode=require')

# Database connection pool
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
    """Get a connection from the pool"""
    return await db_pool.acquire()

async def return_db_connection(conn):
    """Return connection to the pool"""
    await db_pool.release(conn)

# ========== SECURITY CONFIG ==========
ADMIN_USERNAME = "Mpc"
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'Mpc@Secure+_+')
ADMIN_PASSWORD_HASH = None

# ========== SESSION MANAGEMENT ==========
sessions: Dict[str, Dict] = {}
SESSION_TIMEOUT = 3600 * 24 * 7  # 7 days

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
    now = time.time()
    login_attempts[username].append(now)

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
        # Create tables
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
                reply_to INTEGER DEFAULT NULL
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
        
        print("[✓] PostgreSQL database ready")
        
        # Add group_password column if it doesn't exist
        try:
            await conn.execute('''
                ALTER TABLE groups ADD COLUMN IF NOT EXISTS group_password TEXT
            ''')
            print("[✓] group_password column verified")
        except Exception as e:
            print(f"[!] group_password column: {e}")
        
        # Add reply_to column if it doesn't exist
        try:
            await conn.execute('''
                ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to INTEGER DEFAULT NULL
            ''')
            print("[✓] reply_to column verified")
        except Exception as e:
            print(f"[!] reply_to column: {e}")
        
        # Clean up corrupt data
        try:
            await conn.execute("DELETE FROM groups WHERE group_name = 'admin' AND created_by != 'Mpc'")
            print("[🧹] Cleaned up corrupt groups")
        except Exception as e:
            pass
        
        try:
            await conn.execute("DELETE FROM messages WHERE group_name = 'admin'")
        except Exception as e:
            pass
        
        # Create admin if not exists
        row = await conn.fetchrow("SELECT username FROM users WHERE username = $1", ADMIN_USERNAME)
        if not row:
            ADMIN_PASSWORD_HASH = hash_password_argon2(ADMIN_PASSWORD)
            await conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES ($1, $2, $3, $4, $5)",
                ADMIN_USERNAME, ADMIN_PASSWORD_HASH, "admin_salt", "admin", time.time()
            )
            print(f"[✓] Admin created: {ADMIN_USERNAME}")
            print(f"[✓] Admin Password: {ADMIN_PASSWORD}")
            print(f"⚠️  Keep this password safe!")
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

def start_cleanup():
    async def cleanup_loop():
        while True:
            await asyncio.sleep(3600)
            await cleanup_old_messages()
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
        return {
            "username": username, 
            "role": role,
            "assigned_group": assigned_group,
            "display_name": display_name
        }
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
        
        # Check if group exists
        row = await conn.fetchrow("SELECT group_name, group_password FROM groups WHERE group_name = $1", group_name)
        if row:
            stored_group_password = row['group_password']
            # If group exists, the provided group_password must match the stored one
            if stored_group_password and stored_group_password != group_password:
                return {"error": "Group password does not match the existing group's password. Use the correct group password."}
            # If group_password is NULL (should not happen), update it
            if not stored_group_password:
                await conn.execute(
                    "UPDATE groups SET group_password = $1 WHERE group_name = $2",
                    group_password, group_name
                )
            group_salt = None  # not needed
        else:
            # Create new group
            group_salt = generate_salt()
            group_pwd_hash = hash_password_argon2(group_password)
            await conn.execute(
                "INSERT INTO groups (group_name, salt, password_hash, group_password, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
                group_name, group_salt, group_pwd_hash, group_password, "admin", time.time()
            )
            print(f"[✓] New group created: '{group_name}'")
        
        # Insert user with assigned_group
        await conn.execute(
            "INSERT INTO users (username, password_hash, salt, role, assigned_group, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
            username, user_password_hash, salt, "user", group_name, time.time()
        )
        print(f"[✓] User created: '{username}' in group '{group_name}'")
        return {"success": True}
    except Exception as e:
        print(f"Error creating user: {e}")
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

async def delete_users_by_group(group_name):
    conn = await get_db_connection()
    try:
        result = await conn.execute("DELETE FROM users WHERE assigned_group = $1", group_name)
        return result != "DELETE 0"
    finally:
        await return_db_connection(conn)

async def get_all_users():
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("""
            SELECT username, role, assigned_group, display_name, status, 
                   current_group, last_seen, created_at 
            FROM users 
            ORDER BY created_at DESC
        """)
        return [dict(row) for row in rows]
    finally:
        await return_db_connection(conn)

async def get_user_role(username):
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow("SELECT role FROM users WHERE username = $1", username)
        return row[0] if row else None
    finally:
        await return_db_connection(conn)

async def get_user_assigned_group(username):
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow("SELECT assigned_group FROM users WHERE username = $1", username)
        return row[0] if row else None
    finally:
        await return_db_connection(conn)

async def save_message(ciphertext, group, sender, salt, reply_to=None):
    now = time.time()
    expiry = now + (24 * 3600)
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow(
            "INSERT INTO messages (ciphertext, group_name, sender, salt, created_at, expires_at, reply_to) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at",
            ciphertext, group, sender, salt, now, expiry, reply_to
        )
        return dict(result)
    finally:
        await return_db_connection(conn)

async def get_messages(group):
    cutoff = time.time() - (24 * 3600)
    conn = await get_db_connection()
    try:
        rows = await conn.fetch(
            "SELECT id, ciphertext, sender, salt, created_at, reply_to FROM messages WHERE group_name = $1 AND created_at > $2 ORDER BY id ASC",
            group, cutoff
        )
        return [dict(row) for row in rows]
    finally:
        await return_db_connection(conn)

async def get_all_messages(limit=100):
    conn = await get_db_connection()
    try:
        rows = await conn.fetch(
            "SELECT id, sender, group_name, created_at FROM messages ORDER BY created_at DESC LIMIT $1",
            limit
        )
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
        # Delete all users assigned to this group
        await conn.execute("DELETE FROM users WHERE assigned_group = $1", group_name)
        # Delete all messages in this group
        await conn.execute("DELETE FROM messages WHERE group_name = $1", group_name)
        # Delete the group itself
        result = await conn.execute("DELETE FROM groups WHERE group_name = $1", group_name)
        return result != "DELETE 0"
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

# ========== HTML ==========
HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>ABAVANDIMWE | Secure Messaging</title>
    
    <!-- PWA Meta Tags -->
    <link rel="manifest" href="/manifest.json">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="ABAVANDIMWE">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="theme-color" content="#0a0a0f">
    <meta name="msapplication-TileColor" content="#0a0a0f">
    <meta name="msapplication-TileImage" content="/icons/icon-144x144.png">
    
    <!-- Icons -->
    <link rel="icon" type="image/png" sizes="72x72" href="/icons/icon-72x72.png">
    <link rel="icon" type="image/png" sizes="96x96" href="/icons/icon-96x96.png">
    <link rel="icon" type="image/png" sizes="128x128" href="/icons/icon-128x128.png">
    <link rel="icon" type="image/png" sizes="144x144" href="/icons/icon-144x144.png">
    <link rel="icon" type="image/png" sizes="152x152" href="/icons/icon-152x152.png">
    <link rel="icon" type="image/png" sizes="192x192" href="/icons/icon-192x192.png">
    <link rel="icon" type="image/png" sizes="384x384" href="/icons/icon-384x384.png">
    <link rel="icon" type="image/png" sizes="512x512" href="/icons/icon-512x512.png">
    
    <!-- Apple Touch Icon -->
    <link rel="apple-touch-icon" href="/icons/icon-192x192.png">
    
    <style>
        *{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
        body{font-family:monospace;background:#0a0a0f;height:100vh;overflow:hidden;color:#0f0;}
        
        .login-container{position:fixed;top:0;left:0;right:0;bottom:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;padding:20px;}
        .login-card{background:#050508;border:2px solid #0f0;border-radius:24px;padding:32px 24px;width:100%;max-width:420px;position:relative;overflow:hidden;}
        .login-card::before{content:'';position:absolute;top:-2px;left:-2px;right:-2px;bottom:-2px;background:linear-gradient(45deg,#0f0,transparent,#0f0);background-size:400%;z-index:-1;animation:glow 3s linear infinite;}
        @keyframes glow{0%{background-position:0% 50%;}50%{background-position:100% 50%;}100%{background-position:0% 50%;}}
        .login-card-inner{background:#050508;padding:32px 24px;border-radius:22px;position:relative;}
        h1{text-align:center;margin-bottom:4px;font-size:28px;letter-spacing:2px;}
        .sub{text-align:center;margin-bottom:12px;font-size:11px;color:#666;}
        .admin-badge{text-align:center;margin-bottom:20px;font-size:10px;color:#0f0;border:1px solid #0f0;padding:4px 12px;display:inline-block;border-radius:20px;background:rgba(0,255,0,0.05);}
        input{width:100%;padding:14px;margin:10px 0;background:#111;border:1px solid #0f0;border-radius:12px;color:#0f0;font-family:monospace;font-size:15px;transition:all 0.3s;}
        input:focus{outline:none;box-shadow:0 0 20px rgba(0,255,65,0.2);border-color:#0f0;}
        input::placeholder{color:#444;}
        button{width:100%;padding:14px;margin-top:20px;background:transparent;border:2px solid #0f0;border-radius:12px;color:#0f0;font-size:16px;font-weight:bold;cursor:pointer;transition:all 0.3s;position:relative;overflow:hidden;}
        button:hover{background:#0f0;color:#000;transform:translateY(-2px);box-shadow:0 5px 20px rgba(0,255,65,0.3);}
        button:active{transform:scale(0.98);}
        .btn-whatsapp{background:#25D366;border-color:#25D366;color:white;margin-top:12px;}
        .btn-whatsapp:hover{background:#128C7E;border-color:#128C7E;color:white;box-shadow:0 5px 20px rgba(37,211,102,0.3);}
        .error-message{color:#ff4444;font-size:12px;text-align:center;margin-top:12px;display:none;}
        .success-message{color:#0f0;font-size:12px;text-align:center;margin-top:12px;display:none;}
        .login-footer{text-align:center;margin-top:20px;font-size:9px;color:#333;border-top:1px solid #1a1a2e;padding-top:16px;}
        
        .chat-container{display:none;width:100%;height:100%;flex-direction:column;background:#0a0a0f;position:fixed;top:0;left:0;right:0;bottom:0;}
        .chat-container.active{display:flex;}
        
        .chat-header{padding:12px 16px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;align-items:center;gap:8px;}
        .chat-header-left{display:flex;align-items:center;gap:10px;}
        .chat-header h2{font-size:16px;flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;}
        .online-badge{font-size:10px;padding:3px 10px;border:1px solid #0f0;border-radius:20px;background:rgba(0,255,0,0.05);}
        .menu-btn,.logout-btn{background:transparent;border:1px solid #0f0;color:#0f0;padding:6px 12px;border-radius:8px;cursor:pointer;width:auto;margin:0;font-size:12px;transition:all 0.3s;}
        .logout-btn:hover{border-color:#ff0041;color:#ff0041;}
        .logout-btn:active{background:#ff0041;border-color:#ff0041;color:white;}
        
        .main-content{flex:1;display:flex;overflow:hidden;position:relative;}
        .sidebar{width:260px;background:#050508;border-right:1px solid #0f0;display:flex;flex-direction:column;flex-shrink:0;}
        .sidebar-header{padding:16px;border-bottom:1px solid #0f0;}
        .sidebar-header h3{font-size:14px;}
        .users-list{flex:1;padding:12px;overflow-y:auto;}
        .user-item{padding:10px 12px;margin:6px 0;border:1px solid #0f0;border-radius:10px;display:flex;align-items:center;gap:8px;animation:fadeIn 0.3s ease;}
        .user-item::before{content:"●";color:#0f0;font-size:10px;animation:pulse 2s infinite;}
        @keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.5;}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
        
        @media (max-width:768px){
            .sidebar{position:fixed;left:-260px;top:0;bottom:0;z-index:20;transition:left 0.3s ease;}
            .sidebar.open{left:0;}
            .overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:15;display:none;}
            .overlay.active{display:block;}
        }
        @media (min-width:769px){.menu-btn,.overlay{display:none;}}
        
        .chat-area{flex:1;display:flex;flex-direction:column;}
        .messages-container{flex:1;padding:16px;overflow-y:auto;display:flex;flex-direction:column;gap:12px;}
        .message{max-width:85%;display:flex;flex-direction:column;animation:fadeIn 0.2s ease;position:relative;padding:8px 0;transition:transform 0.2s ease;}
        .message.sent{align-self:flex-end;}
        .message.received{align-self:flex-start;}
        .message-bubble{padding:10px 14px;border-radius:18px;font-size:14px;word-wrap:break-word;position:relative;}
        .message.sent .message-bubble{background:#0f0;color:#000;border-bottom-right-radius:4px;}
        .message.received .message-bubble{background:#1a1a2e;border:1px solid #0f0;border-bottom-left-radius:4px;}
        .message-sender{font-size:10px;margin-bottom:4px;opacity:0.7;padding-left:4px;}
        .message-time{font-size:9px;margin-top:4px;opacity:0.5;}
        .message-reply-preview{font-size:11px;color:#ffaa00;margin-bottom:6px;padding:6px 10px;background:rgba(255,170,0,0.08);border-left:3px solid #ffaa00;border-radius:4px;opacity:0.8;cursor:pointer;}
        .message-reply-preview .reply-sender{color:#ffaa00;font-weight:bold;}
        .message-reply-preview .reply-text{color:#888;}
        .system-message{text-align:center;font-size:11px;color:#ffaa00;margin:8px 0;font-style:italic;animation:fadeIn 0.3s ease;}
        .typing-indicator{padding:8px 16px;color:#0f0;font-style:italic;font-size:11px;min-height:36px;}
        
        .input-area{padding:12px 16px;background:#050508;border-top:1px solid #0f0;display:flex;flex-direction:column;gap:8px;}
        .reply-preview{display:none;padding:8px 12px;background:rgba(255,170,0,0.1);border-left:3px solid #ffaa00;border-radius:6px;font-size:12px;color:#ffaa00;align-items:center;justify-content:space-between;}
        .reply-preview .reply-cancel{color:#ff4444;cursor:pointer;font-weight:bold;padding:0 8px;}
        .reply-preview .reply-cancel:hover{color:#ff6666;}
        
        /* ===== FIX: Input row stability ===== */
        .input-row {
            display: flex;
            gap: 10px;
            align-items: flex-end; /* button stays at bottom */
        }
        .input-row textarea {
            flex: 1;
            margin: 0;
            padding: 12px 16px;
            background: #111;
            border: 1px solid #0f0;
            border-radius: 12px;
            color: #0f0;
            font-family: monospace;
            font-size: 14px;
            resize: none;          /* prevent manual resize */
            height: auto;          /* start at auto */
            min-height: 50px;
            max-height: 80px;      /* hard cap */
            overflow-y: auto;      /* scroll when content exceeds 80px */
            line-height: 1.5;
        }
        .input-row textarea:focus {
            outline: none;
            box-shadow: 0 0 20px rgba(0,255,65,0.2);
            border-color: #0f0;
        }
        .input-row textarea::placeholder {
            color: #444;
        }
        .input-row button {
            width: 60px;
            min-width: 60px;
            height: 50px;
            flex-shrink: 0;        /* never shrinks */
            margin: 0;
            padding: 0;
            background: transparent;
            border: 2px solid #0f0;
            border-radius: 12px;
            color: #0f0;
            font-size: 20px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        .input-row button:hover {
            background: #0f0;
            color: #000;
            box-shadow: 0 0 20px rgba(0,255,65,0.3);
        }
        .input-row button:active {
            transform: scale(0.95);
        }
        .input-row button .btn-text {
            font-size: 20px;
            line-height: 1;
        }
        
        .footer{text-align:center;padding:6px;font-size:8px;color:#333;border-top:1px solid #0f0;}
        
        ::-webkit-scrollbar{width:3px;}
        ::-webkit-scrollbar-track{background:#1a1a2e;}
        ::-webkit-scrollbar-thumb{background:#0f0;}
        
        .connection-status{position:fixed;bottom:70px;right:16px;padding:6px 12px;background:#050508;border:1px solid #0f0;border-radius:20px;font-size:9px;z-index:10;}
        .status-online{color:#0f0;}
        .status-offline{color:#ff4444;}
        
        .separator{display:flex;align-items:center;text-align:center;margin:16px 0;}
        .separator::before,.separator::after{content:'';flex:1;border-bottom:1px solid #1a1a2e;}
        .separator span{padding:0 10px;color:#666;font-size:10px;}
        
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
        .admin-card select{width:100%;padding:8px;margin:5px 0;background:#111;border:1px solid #0f0;border-radius:6px;color:#0f0;font-size:12px;}
        .admin-card button{width:auto;padding:8px 16px;margin:5px;font-size:12px;position:relative;overflow:hidden;}
        .close-admin{background:#ff0041;border-color:#ff0041;color:white;padding:8px 16px;border-radius:8px;cursor:pointer;}
        .close-admin:hover{background:#cc0033;}
        .admin-stats{display:grid;grid-template-columns:repeat(auto-fit, minmax(150px, 1fr));gap:12px;margin-bottom:20px;}
        .stat-box{background:#050508;border:1px solid #0f0;border-radius:10px;padding:16px;text-align:center;}
        .stat-number{font-size:24px;color:#0f0;}
        .stat-label{font-size:10px;color:#666;margin-top:4px;}
        .admin-table-wrap{max-height:200px;overflow-y:auto;}
        .action-btn{background:transparent;border:1px solid #ff0041;color:#ff0041;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:10px;margin:0 2px;position:relative;overflow:hidden;}
        .action-btn:hover{background:#ff0041;color:white;}
        .action-btn-green{background:transparent;border:1px solid #0f0;color:#0f0;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:10px;margin:0 2px;position:relative;overflow:hidden;}
        .action-btn-green:hover{background:#0f0;color:#000;}
        .admin-close-area{display:flex;justify-content:flex-end;gap:10px;}
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
        
        /* Install Button */
        .install-btn {
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 100;
            padding: 14px 28px;
            background: #0f0;
            color: #000;
            border: none;
            border-radius: 14px;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
            display: none;
            box-shadow: 0 4px 30px rgba(0, 255, 65, 0.4);
            transition: all 0.3s;
            font-family: monospace;
            letter-spacing: 0.5px;
            position:relative;
            overflow:hidden;
        }
        .install-btn:hover {
            transform: translateX(-50%) scale(1.05);
            box-shadow: 0 6px 40px rgba(0, 255, 65, 0.6);
        }
        .install-btn:active {
            transform: translateX(-50%) scale(0.95);
        }
        .install-btn.show {
            display: block;
        }
        
        /* Loading Overlay */
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(10, 10, 15, 0.92);
            z-index: 9999;
            display: none;
            justify-content: center;
            align-items: center;
            flex-direction: column;
            gap: 30px;
        }
        .loading-overlay.active {
            display: flex;
        }
        .loader {
            width: 80px;
            height: 80px;
            border: 3px solid rgba(0, 255, 65, 0.1);
            border-top: 3px solid #0f0;
            border-radius: 50%;
            animation: spin 0.8s cubic-bezier(0.4, 0.0, 0.2, 1) infinite;
            box-shadow: 0 0 30px rgba(0, 255, 65, 0.15);
        }
        .loader-pulse {
            position: absolute;
            width: 80px;
            height: 80px;
            border-radius: 50%;
            border: 1px solid rgba(0, 255, 65, 0.3);
            animation: pulse-ring 1.5s cubic-bezier(0.4, 0.0, 0.2, 1) infinite;
        }
        .loader-container {
            position: relative;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .loader-text {
            color: #0f0;
            font-size: 16px;
            font-family: monospace;
            letter-spacing: 2px;
            animation: text-pulse 1.5s ease-in-out infinite;
        }
        .loader-dots {
            display: inline-block;
        }
        .loader-dots span {
            display: inline-block;
            animation: dot-bounce 1.4s ease-in-out infinite;
        }
        .loader-dots span:nth-child(1) { animation-delay: 0s; }
        .loader-dots span:nth-child(2) { animation-delay: 0.2s; }
        .loader-dots span:nth-child(3) { animation-delay: 0.4s; }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        @keyframes pulse-ring {
            0% { transform: scale(1); opacity: 1; }
            100% { transform: scale(1.6); opacity: 0; }
        }
        @keyframes text-pulse {
            0%, 100% { opacity: 0.6; }
            50% { opacity: 1; }
        }
        @keyframes dot-bounce {
            0%, 80%, 100% { transform: scale(0); opacity: 0.3; }
            40% { transform: scale(1); opacity: 1; }
        }
        
        .group-info {
            font-size: 10px;
            color: #ffaa00;
            padding: 8px;
            background: rgba(255, 170, 0, 0.08);
            border-radius: 6px;
            margin-top: 8px;
            border-left: 2px solid #ffaa00;
        }
        
        /* Offline Status Bar (for when in chat and network drops) */
        .offline-bar {
            display: none;
            background: #ff0041;
            color: white;
            text-align: center;
            padding: 6px;
            font-size: 11px;
            font-weight: bold;
            position: sticky;
            top: 0;
            z-index: 5;
        }
        .offline-bar.active {
            display: block;
        }
        .offline-bar .reconnect-btn {
            background: white;
            color: #ff0041;
            border: none;
            padding: 2px 12px;
            border-radius: 4px;
            cursor: pointer;
            margin-left: 10px;
            font-weight: bold;
            font-size: 11px;
        }
        .offline-message {
            text-align: center;
            color: #ff4444;
            padding: 20px;
            font-size: 14px;
        }
        
        /* Full‑screen offline overlay */
        .offline-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: #0a0a0f;
            z-index: 99999;
            display: none;
            justify-content: center;
            align-items: center;
            flex-direction: column;
            gap: 20px;
            padding: 30px;
        }
        .offline-overlay.active {
            display: flex;
        }
        .offline-overlay .offline-icon {
            font-size: 60px;
            margin-bottom: 10px;
        }
        .offline-overlay h2 {
            color: #ff4444;
            font-size: 24px;
            text-align: center;
        }
        .offline-overlay p {
            color: #888;
            font-size: 14px;
            text-align: center;
            max-width: 300px;
        }
        .offline-overlay .retry-btn {
            background: transparent;
            border: 2px solid #0f0;
            color: #0f0;
            padding: 14px 40px;
            border-radius: 12px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s;
            margin-top: 10px;
        }
        .offline-overlay .retry-btn:hover {
            background: #0f0;
            color: #000;
        }
        .offline-overlay .retry-btn:active {
            transform: scale(0.95);
        }
    </style>
</head>
<body>

<!-- Loading Overlay -->
<div class="loading-overlay" id="loadingOverlay">
    <div class="loader-container">
        <div class="loader-pulse"></div>
        <div class="loader"></div>
    </div>
    <div class="loader-text">
        <span id="loadingText">Loading</span>
        <span class="loader-dots">
            <span>.</span><span>.</span><span>.</span>
        </span>
    </div>
</div>

<!-- Full‑screen Offline Overlay -->
<div class="offline-overlay" id="offlineOverlay">
    <div class="offline-icon">📶</div>
    <h2>No Internet Connection</h2>
    <p>Please check your network settings and try again.</p>
    <button class="retry-btn" id="retryOfflineBtn">↻ Retry</button>
</div>

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
            
            <button class="btn-whatsapp" onclick="requestAccess()">
                💬 Request Access on WhatsApp
            </button>
            
            <div id="loginError" class="error-message"></div>
            <div id="loginSuccess" class="success-message"></div>
            
            <div class="login-footer">
                🔒 AES-256 | ⏰ Messages auto-delete after 24 hours<br>
                <span style="color:#1a1a2e;">Developed by Mugisha Pc</span>
            </div>
        </div>
    </div>
</div>

<div id="adminPanel" class="admin-panel">
    <div class="admin-panel-header">
        <h2>⚙️ Admin Dashboard <span class="admin-username">(Logged in as: <span id="adminUsername">Mpc</span>)</span></h2>
        <div>
            <button class="close-admin" onclick="logout()">🚪 Logout</button>
        </div>
    </div>
    
    <div class="admin-stats" id="adminStats">
        <div class="stat-box"><div class="stat-number" id="statUsers">0</div><div class="stat-label">Total Users</div></div>
        <div class="stat-box"><div class="stat-number" id="statMessages">0</div><div class="stat-label">Total Messages</div></div>
        <div class="stat-box"><div class="stat-number" id="statGroups">0</div><div class="stat-label">Total Groups</div></div>
        <div class="stat-box"><div class="stat-number" id="statOnline">0</div><div class="stat-label">Online Now</div></div>
    </div>
    
    <div class="admin-content">
        <div class="admin-card">
            <h3>👤 Create User</h3>
            <div style="margin-bottom:12px;">
                <input type="text" id="newUsername" placeholder="Username" style="width:100%;">
                <input type="text" id="newPassword" placeholder="Password" style="width:100%;">
                <input type="text" id="newGroupName" placeholder="Group Name" style="width:100%;">
                <input type="text" id="newGroupPassword" placeholder="Group Password" style="width:100%;">
                <button onclick="createUser()" class="action-btn-green">➕ Create User</button>
            </div>
            <div class="group-info">
                ⚠️ If the group already exists, the Group Password you enter MUST match the existing group password!
            </div>
        </div>
        
        <div class="admin-card">
            <h3>📋 Users</h3>
            <div class="admin-table-wrap">
                <table>
                    <thead><tr><th>Username</th><th>Group</th><th>Display Name</th><th>Status</th><th>Action</th></tr></thead>
                    <tbody id="usersTableBody"></tbody>
                </table>
            </div>
        </div>
        
        <div class="admin-card">
            <h3>📁 Groups</h3>
            <div class="admin-table-wrap">
                <table>
                    <thead><tr><th>Group Name</th><th>Created By</th><th>Action</th></tr></thead>
                    <tbody id="groupsTableBody"></tbody>
                </table>
            </div>
        </div>
        
        <div class="admin-card">
            <h3>📨 Recent Messages</h3>
            <div class="admin-table-wrap">
                <table>
                    <thead><tr><th>Sender</th><th>Group</th><th>Time</th><th>Action</th></tr></thead>
                    <tbody id="messagesTableBody"></tbody>
                </table>
            </div>
        </div>
        
        <div class="admin-card">
            <h3>📋 Admin Logs</h3>
            <div class="admin-table-wrap">
                <table>
                    <thead><tr><th>Admin</th><th>Action</th><th>Target</th><th>Time</th></tr></thead>
                    <tbody id="logsTableBody"></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<div id="gatekeeperScreen" class="gatekeeper-container">
    <div class="gatekeeper-card">
        <h2>🔐 Gatekeeper</h2>
        <div class="sub">Verify your credentials to access your group</div>
        
        <input type="text" id="gatekeeperUsername" placeholder="Username" readonly>
        <input type="password" id="gatekeeperPassword" placeholder="Password">
        
        <button id="gatekeeperBtn">▶ Verify</button>
        
        <div id="gatekeeperError" class="error-message"></div>
        
        <div class="login-footer" style="margin-top:20px;padding-top:16px;border-top:1px solid #1a1a2e;">
            🔒 Credentials provided by admin
        </div>
    </div>
</div>

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
        
        <div class="login-footer" style="margin-top:20px;padding-top:16px;border-top:1px solid #1a1a2e;">
            🔐 You'll be able to see messages from others in your group
        </div>
    </div>
</div>

<div id="chatScreen" class="chat-container">
    <div class="chat-header">
        <div class="chat-header-left">
            <button class="menu-btn" onclick="toggleSidebar()">☰</button>
            <span class="online-badge" id="connectionBadge">● Online</span>
        </div>
        <h2 id="groupTitle"># LOADING</h2>
        <button class="logout-btn" onclick="logout()">Leave</button>
    </div>
    
    <!-- Offline Bar (shown when network drops during chat) -->
    <div class="offline-bar" id="offlineBar">
        ⚠️ No internet connection
        <button class="reconnect-btn" onclick="reconnectManually()">↻ Retry</button>
    </div>
    
    <div class="main-content">
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header"><h3>● Online Users</h3></div>
            <div class="users-list" id="usersList"><div class="user-item">Loading...</div></div>
        </div>
        <div class="overlay" id="overlay" onclick="toggleSidebar()"></div>
        
        <div class="chat-area">
            <div class="messages-container" id="messages">
                <div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div>
            </div>
            <div class="typing-indicator" id="typingIndicator"></div>
            <div class="input-area">
                <div class="reply-preview" id="replyPreview">
                    <span>↩️ Replying to <span id="replyPreviewSender" style="color:#ffaa00;font-weight:bold;"></span>: <span id="replyPreviewText" style="color:#888;"></span></span>
                    <span class="reply-cancel" onclick="cancelReply()">✕</span>
                </div>
                <div class="input-row">
                    <textarea id="messageInput" placeholder="Type a message..." rows="2"></textarea>
                    <button onclick="sendMessage()"><span class="btn-text">➥</span></button>
                </div>
            </div>
            <div class="footer">🔐 End-to-End Encrypted | Messages self-destruct after 24 hours</div>
        </div>
    </div>
    <div class="connection-status status-online" id="connectionStatus">🟢 Connected</div>
</div>

<!-- Install App Button -->
<button id="installBtn" class="install-btn">📲 Install ABAVANDIMWE App</button>

<script>
let ws, username, groupName, groupPassword, groupSalt, typingTimeout, reconnectAttempts = 0;
let currentUser = null;
let gatekeeperData = null;
let replyingToMessageId = null;
let messagesData = {};
let isManuallyReconnecting = false;
let lastActiveScreen = null;  // Track the active screen before offline overlay

// ========== LOADING OVERLAY ==========
function showLoading(text, callback) {
    const overlay = document.getElementById('loadingOverlay');
    const loadingText = document.getElementById('loadingText');
    loadingText.textContent = text;
    overlay.classList.add('active');
    
    setTimeout(async () => {
        try {
            await callback();
        } catch (e) {
            console.error('Error in callback:', e);
        } finally {
            if (!document.querySelector('.chat-container.active') && 
                !document.querySelector('.admin-panel.active') &&
                !document.querySelector('.gatekeeper-container.active') &&
                !document.querySelector('.user-setup-container.active')) {
                setTimeout(() => {
                    overlay.classList.remove('active');
                }, 500);
            }
        }
    }, 300);
}

function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('active');
}

// ========== PWA: Service Worker Registration ==========
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js')
            .then((registration) => {
                console.log('✅ Service Worker registered successfully');
            })
            .catch((error) => {
                console.log('❌ Service Worker registration failed:', error);
            });
    });
}

// ========== PWA: Install Button ==========
let deferredPrompt;
const installBtn = document.getElementById('installBtn');

window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    installBtn.classList.add('show');
    console.log('📱 App can be installed');
});

async function installApp() {
    if (deferredPrompt) {
        deferredPrompt.prompt();
        const choiceResult = await deferredPrompt.userChoice;
        if (choiceResult.outcome === 'accepted') {
            console.log('✅ User accepted the install prompt');
            installBtn.classList.remove('show');
        } else {
            console.log('❌ User dismissed the install prompt');
        }
        deferredPrompt = null;
    }
    hideLoading();
}

window.addEventListener('appinstalled', (evt) => {
    console.log('✅ ABAVANDIMWE was installed');
    installBtn.classList.remove('show');
    hideLoading();
});

if (window.matchMedia('(display-mode: standalone)').matches) {
    installBtn.classList.remove('show');
    console.log('📱 ABAVANDIMWE is running as installed app');
}

if (navigator.standalone) {
    installBtn.classList.remove('show');
    console.log('📱 ABAVANDIMWE is running as iOS standalone app');
}

// ========== OFFLINE OVERLAY MANAGEMENT ==========
const offlineOverlay = document.getElementById('offlineOverlay');

function showOfflineOverlay() {
    // Store the currently active screen before we hide everything
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

    // Hide all screens and show overlay
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
    // Restore the previous screen
    if (lastActiveScreen === 'chat') {
        // If we were in chat, try to reconnect
        if (window.chatUsername && window.chatGroup) {
            document.getElementById('chatScreen').classList.add('active');
            connectToChat(window.chatUsername, window.chatGroup);
        } else {
            // Fallback to login if no chat session
            document.getElementById('loginScreen').style.display = 'flex';
        }
    } else if (lastActiveScreen === 'admin') {
        document.getElementById('adminPanel').classList.add('active');
        loadAdminData(); // reload data
    } else if (lastActiveScreen === 'gatekeeper') {
        document.getElementById('gatekeeperScreen').classList.add('active');
    } else if (lastActiveScreen === 'userSetup') {
        document.getElementById('userSetupScreen').classList.add('active');
    } else {
        // Default to login
        document.getElementById('loginScreen').style.display = 'flex';
    }
    lastActiveScreen = null;
}

// Retry button
document.getElementById('retryOfflineBtn').addEventListener('click', function() {
    if (navigator.onLine) {
        hideOfflineOverlay();
    } else {
        // Still offline, show a quick feedback
        this.textContent = '⏳ Still offline...';
        setTimeout(() => { this.textContent = '↻ Retry'; }, 1000);
    }
});

// ========== DOM READY ==========
document.addEventListener('DOMContentLoaded', function() {
    // Initial offline check – show full overlay if offline
    if (!navigator.onLine) {
        showOfflineOverlay();
    }

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
        if(e.key === 'Enter') {
            showLoading('Logging in', login);
        }
    });
    document.getElementById('gatekeeperPassword').addEventListener('keypress', function(e) {
        if(e.key === 'Enter') {
            showLoading('Verifying', gatekeeperLogin);
        }
    });
    document.getElementById('userDisplayName').addEventListener('keypress', function(e) {
        if(e.key === 'Enter') {
            showLoading('Entering Chat', enterChat);
        }
    });
    
    // ===== NO AUTO-RESIZE JS – CSS handles height =====
    // Only the typing indicator remains
    const msgInput = document.getElementById('messageInput');
    msgInput.addEventListener('input', function() {
        // Do NOT change height – CSS with max-height and overflow handles it.
        if(ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({type:'typing'}));
            clearTimeout(typingTimeout);
            typingTimeout = setTimeout(() => {
                if(ws && ws.readyState === WebSocket.OPEN)
                    ws.send(JSON.stringify({type:'stop_typing'}));
            }, 1000);
        }
    });
    
    // Install button click listener
    document.getElementById('installBtn').addEventListener('click', installApp);

    // ----- OFFLINE / ONLINE HANDLING (IMPROVED) -----
    function handleVisibilityChange() {
        if (document.visibilityState === 'visible') {
            // If we are in the chat screen
            if (document.getElementById('chatScreen').classList.contains('active')) {
                if (!navigator.onLine) {
                    // Offline -> clear messages and show inline offline message inside chat
                    clearMessagesOffline();
                } else {
                    // Online -> if WebSocket is not open, reconnect
                    if (!ws || ws.readyState !== WebSocket.OPEN) {
                        if (window.chatUsername && window.chatGroup) {
                            connectToChat(window.chatUsername, window.chatGroup);
                        }
                    }
                }
            }
        }
    }

    document.addEventListener('visibilitychange', handleVisibilityChange);

    // When the device goes online, hide the full overlay and reconnect if needed
    window.addEventListener('online', function() {
        // Hide the overlay
        if (offlineOverlay.classList.contains('active')) {
            hideOfflineOverlay();
        }
        document.getElementById('offlineBar').classList.remove('active');
        if (document.getElementById('chatScreen').classList.contains('active')) {
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                if (window.chatUsername && window.chatGroup) {
                    connectToChat(window.chatUsername, window.chatGroup);
                }
            }
        }
    });

    // When the device goes offline, show full overlay
    window.addEventListener('offline', function() {
        showOfflineOverlay();
        // Also clear any chat messages if chat is visible
        if (document.getElementById('chatScreen').classList.contains('active')) {
            clearMessagesOffline();
        }
    });
});

// Helper to clear messages and show offline state inside chat (used when network drops while in chat)
function clearMessagesOffline() {
    const container = document.getElementById('messages');
    container.innerHTML = '<div class="offline-message">🔴 No internet connection. Messages are hidden.</div>';
    messagesData = {};
    document.getElementById('offlineBar').classList.add('active');
    updateStatus(false);
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.close();
    }
}

// ========== LOGIN ==========
async function login() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    
    if(!username || !password) {
        showError('Please enter username and password');
        hideLoading();
        return;
    }
    
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
            showError(data.message || 'Invalid credentials. Request access via WhatsApp if you need an account.');
            hideLoading();
        }
    } catch(e) {
        console.error('Login error:', e);
        showError('Connection error. Please try again.');
        hideLoading();
    }
}

// ========== GATEKEEPER ==========
async function gatekeeperLogin() {
    const username = document.getElementById('gatekeeperUsername').value.trim();
    const password = document.getElementById('gatekeeperPassword').value;
    
    if(!username || !password) {
        showGatekeeperError('Please enter your password');
        hideLoading();
        return;
    }
    
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
        console.error('Gatekeeper error:', e);
        showGatekeeperError('Connection error. Please try again.');
        hideLoading();
    }
}

// ========== ENTER CHAT ==========
async function enterChat() {
    const displayName = document.getElementById('userDisplayName').value.trim();
    const groupName = document.getElementById('userGroupName').value.trim();
    
    if(!displayName) {
        showSetupError('Please enter your display name');
        hideLoading();
        return;
    }
    
    if(!groupName) {
        showSetupError('Group missing. Please contact admin.');
        hideLoading();
        return;
    }
    
    try {
        await fetch('/save_display_name', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: gatekeeperData.username,
                display_name: displayName
            })
        });
    } catch(e) {
        console.error('Failed to save display name:', e);
    }
    
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
    // Clear old messages immediately
    messagesData = {};
    const container = document.getElementById('messages');
    container.innerHTML = '<div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div>';
    document.getElementById('offlineBar').classList.remove('active');
    
    // If offline, show inline offline message and abort
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
        // Remove offline message if present
        const offlineMsg = document.querySelector('.offline-message');
        if (offlineMsg) offlineMsg.remove();
        ws.send(JSON.stringify({
            type: 'join',
            username: username,
            group: group
        }));
        reconnectAttempts = 0;
        isManuallyReconnecting = false;
    };
    
    ws.onmessage = async function(e) {
        try {
            let d = JSON.parse(e.data);
            
            if(d.type === 'error') {
                showError(d.message);
                ws.close();
                return;
            }
            if(d.type === 'ready') {
                groupSalt = d.salt;
                addSystemMessage('🔐 Connected - Messages last 24 hours');
            } else if(d.type === 'history') {
                // Clear messages and remove offline message
                document.getElementById('messages').innerHTML = '';
                const offlineMsg = document.querySelector('.offline-message');
                if (offlineMsg) offlineMsg.remove();
                messagesData = {};
                
                if(d.messages && d.messages.length > 0) {
                    for(let msg of d.messages) {
                        try {
                            let dec = await decrypt(msg.ciphertext, window.groupPassword, msg.salt);
                            let isSent = msg.sender === window.chatUsername;
                            messagesData[msg.id] = {sender: msg.sender, text: dec, timestamp: msg.created_at};
                            addMessage(msg.sender, dec, isSent, msg.timestamp, msg.id, msg.reply_to);
                        } catch(e) {
                            console.error('Decryption error:', e);
                            let isSent = msg.sender === window.chatUsername;
                            messagesData[msg.id] = {sender: msg.sender, text: '🔒 Encrypted', timestamp: msg.created_at};
                            addMessage(msg.sender, '🔒 Encrypted', isSent, msg.timestamp, msg.id, msg.reply_to);
                        }
                    }
                }
            } else if(d.type === 'message') {
                try {
                    let dec = await decrypt(d.ciphertext, window.groupPassword, d.salt);
                    let isSent = d.sender === window.chatUsername;
                    messagesData[d.message_id] = {sender: d.sender, text: dec, timestamp: d.timestamp};
                    addMessage(d.sender, dec, isSent, d.timestamp, d.message_id, d.reply_to);
                } catch(e) {
                    messagesData[d.message_id] = {sender: d.sender, text: '🔒 Encrypted', timestamp: d.timestamp};
                    addMessage(d.sender, '🔒 Encrypted', false, d.timestamp, d.message_id, d.reply_to);
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
        } catch(e) {
            console.error('Error processing message:', e);
        }
    };
    
    ws.onerror = function(e) {
        console.error('WebSocket error:', e);
        updateStatus(false);
    };
    
    ws.onclose = function() {
        updateStatus(false);
        document.getElementById('offlineBar').classList.add('active');
        // Clear messages and show offline message
        const messagesContainer = document.getElementById('messages');
        messagesContainer.innerHTML = '<div class="offline-message">🔴 No internet connection. Messages are hidden.</div>';
        messagesData = {};
        
        if(document.getElementById('chatScreen').classList.contains('active')) {
            if (!isManuallyReconnecting) {
                reconnectAttempts++;
                if(reconnectAttempts < 5) {
                    setTimeout(() => connectToChat(username, group), 3000);
                }
            }
        }
    };
}

function reconnectManually() {
    isManuallyReconnecting = true;
    if (ws) {
        ws.close();
    }
    // Clear messages before retry
    messagesData = {};
    const container = document.getElementById('messages');
    container.innerHTML = '<div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div>';
    document.getElementById('offlineBar').classList.remove('active');
    setTimeout(() => {
        connectToChat(window.chatUsername, window.chatGroup);
    }, 500);
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
    // Remove offline message if present
    const offlineMsg = document.querySelector('.offline-message');
    if (offlineMsg) offlineMsg.remove();
    let div = document.createElement('div');
    div.className = 'system-message';
    div.textContent = text;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
}

function addMessage(sender, text, isSent, timestamp, messageId, replyTo) {
    let msgs = document.getElementById('messages');
    // Remove offline message if present
    const offlineMsg = document.querySelector('.offline-message');
    if (offlineMsg) offlineMsg.remove();
    let div = document.createElement('div');
    div.className = 'message ' + (isSent ? 'sent' : 'received');
    div.dataset.messageId = messageId;
    div.dataset.sender = sender;
    div.dataset.text = text;
    
    let time;
    if(timestamp) {
        let date = new Date(timestamp * 1000);
        time = date.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    } else {
        time = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    }
    
    let replyHtml = '';
    if(replyTo && messagesData[replyTo]) {
        let original = messagesData[replyTo];
        let originalText = original.text || 'Message';
        replyHtml = '<div class="message-reply-preview" onclick="scrollToMessage(' + replyTo + ')">' +
                    '↩️ <span class="reply-sender">' + escapeHtml(original.sender) + '</span>: ' +
                    '<span class="reply-text">' + escapeHtml(originalText.substring(0, 60)) + (originalText.length > 60 ? '...' : '') + '</span>' +
                    '</div>';
    }
    
    div.innerHTML = '<div class="message-sender">' + (isSent ? 'YOU' : escapeHtml(sender)) + '</div>' + 
                    replyHtml +
                    '<div class="message-bubble">' + escapeHtml(text) + '</div>' + 
                    '<div class="message-time">' + time + '</div>';
    
    // Swipe to reply on mobile
    let touchStartX = 0;
    let touchCurrentX = 0;
    let touchStartY = 0;
    
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
        
        if (diffX >= 60) {
            startReply(messageId);
        }
        touchStartX = 0;
        touchCurrentX = 0;
        touchStartY = 0;
    }, {passive: true});
    
    // Mouse swipe for desktop
    let mouseStartX = 0;
    let mouseCurrentX = 0;
    let mouseStartY = 0;
    let isMouseDown = false;
    
    div.addEventListener('mousedown', function(e) {
        mouseStartX = e.clientX;
        mouseStartY = e.clientY;
        mouseCurrentX = mouseStartX;
        isMouseDown = true;
    });
    
    div.addEventListener('mousemove', function(e) {
        if (!isMouseDown) return;
        mouseCurrentX = e.clientX;
        let diffX = mouseCurrentX - mouseStartX;
        let diffY = e.clientY - mouseStartY;
        
        if (diffX > 0 && diffX < 80 && Math.abs(diffY) < 30) {
            div.style.transform = 'translateX(' + diffX + 'px)';
        }
    });
    
    div.addEventListener('mouseup', function(e) {
        if (!isMouseDown) return;
        let diffX = mouseCurrentX - mouseStartX;
        div.style.transform = '';
        
        if (diffX >= 60) {
            startReply(messageId);
        }
        isMouseDown = false;
        mouseStartX = 0;
        mouseCurrentX = 0;
        mouseStartY = 0;
    });
    
    div.addEventListener('mouseleave', function() {
        if (isMouseDown) {
            div.style.transform = '';
            isMouseDown = false;
        }
    });
    
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
}

function startReply(messageId) {
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
            setTimeout(() => {
                msg.style.border = '';
            }, 2000);
            break;
        }
    }
}

function updateUsers(users) {
    let ul = document.getElementById('usersList');
    if(!users || users.length === 0) {
        ul.innerHTML = '<div class="user-item">No users online</div>';
    } else {
        ul.innerHTML = users.map(u => '<div class="user-item">' + escapeHtml(u) + '</div>').join('');
    }
}

function escapeHtml(t) {
    let d = document.createElement('div');
    d.textContent = t;
    return d.innerHTML;
}

// ========== ENCRYPTION ==========
async function encrypt(text, pwd, salt) {
    const e = new TextEncoder();
    const km = await crypto.subtle.importKey('raw', e.encode(pwd), 'PBKDF2', false, ['deriveKey']);
    const k = await crypto.subtle.deriveKey(
        {name:'PBKDF2', salt:e.encode(salt), iterations:100000, hash:'SHA-256'},
        km, {name:'AES-GCM', length:256}, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({name:'AES-GCM', iv}, k, e.encode(text));
    const c = new Uint8Array(iv.length + enc.byteLength);
    c.set(iv, 0);
    c.set(new Uint8Array(enc), iv.length);
    return btoa(String.fromCharCode(...c));
}

async function decrypt(enc, pwd, salt) {
    const d = Uint8Array.from(atob(enc), c => c.charCodeAt(0));
    const iv = d.slice(0, 12), data = d.slice(12);
    const e = new TextEncoder();
    const km = await crypto.subtle.importKey('raw', e.encode(pwd), 'PBKDF2', false, ['deriveKey']);
    const k = await crypto.subtle.deriveKey(
        {name:'PBKDF2', salt:e.encode(salt), iterations:100000, hash:'SHA-256'},
        km, {name:'AES-GCM', length:256}, false, ['decrypt']
    );
    const dec = await crypto.subtle.decrypt({name:'AES-GCM', iv}, k, data);
    return new TextDecoder().decode(dec);
}

// ========== MESSAGING ==========
// Only typing indicator – no height manipulation
document.getElementById('messageInput')?.addEventListener('input', function() {
    // CSS handles height – we only send typing events
    if(ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({type:'typing'}));
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => {
            if(ws && ws.readyState === WebSocket.OPEN)
                ws.send(JSON.stringify({type:'stop_typing'}));
        }, 1000);
    }
});

async function sendMessage() {
    let input = document.getElementById('messageInput');
    let text = input.value.trim();
    if(!text || !ws || ws.readyState !== WebSocket.OPEN || !groupSalt) {
        return;
    }
    
    try {
        let cipher = await encrypt(text, window.groupPassword, groupSalt);
        let timestamp = Date.now() / 1000;
        
        let replyToId = replyingToMessageId;
        
        let newId = Date.now();
        messagesData[newId] = {sender: window.chatUsername, text: text, timestamp: timestamp};
        addMessage(window.chatUsername, text, true, timestamp, newId, replyToId);
        input.value = '';
        // Reset height manually if needed – but it will auto-adjust via CSS
        input.style.height = 'auto';
        
        ws.send(JSON.stringify({
            type:'message',
            ciphertext:cipher,
            salt:groupSalt,
            timestamp: timestamp,
            reply_to: replyToId
        }));
        
        cancelReply();
    } catch(e) {
        alert('Failed to send message');
    }
}

function requestAccess() {
    const phone = '256762117982';
    const message = 'Hello, I would like to get access to ABAVANDIMWE secure messaging platform. Please send me login credentials.';
    const url = `https://wa.me/${phone}?text=${encodeURIComponent(message)}`;
    window.open(url, '_blank');
    showSuccess('📱 Opening WhatsApp... Please send your request.');
    hideLoading();
}

function showError(msg) {
    let err = document.getElementById('loginError');
    err.textContent = msg;
    err.style.display = 'block';
    document.getElementById('loginSuccess').style.display = 'none';
    setTimeout(() => err.style.display = 'none', 5000);
}

function showSuccess(msg) {
    let success = document.getElementById('loginSuccess');
    success.textContent = msg;
    success.style.display = 'block';
    document.getElementById('loginError').style.display = 'none';
    setTimeout(() => success.style.display = 'none', 5000);
}

function showGatekeeperError(msg) {
    let err = document.getElementById('gatekeeperError');
    err.textContent = msg;
    err.style.display = 'block';
    setTimeout(() => err.style.display = 'none', 5000);
}

function showSetupError(msg) {
    let err = document.getElementById('setupError');
    err.textContent = msg;
    err.style.display = 'block';
    document.getElementById('setupSuccess').style.display = 'none';
    setTimeout(() => err.style.display = 'none', 5000);
}

function showSetupSuccess(msg) {
    let success = document.getElementById('setupSuccess');
    success.textContent = msg;
    success.style.display = 'block';
    document.getElementById('setupError').style.display = 'none';
    setTimeout(() => success.style.display = 'none', 5000);
}

async function logout() {
    if(ws) ws.close();
    ws = null;
    
    try {
        await fetch('/logout', {method: 'POST'});
    } catch(e) {}
    
    document.getElementById('chatScreen').classList.remove('active');
    document.getElementById('adminPanel').classList.remove('active');
    document.getElementById('gatekeeperScreen').classList.remove('active');
    document.getElementById('userSetupScreen').classList.remove('active');
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('messages').innerHTML = '<div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div>';
    document.getElementById('usersList').innerHTML = '<div class="user-item">Loading...</div>';
    document.getElementById('loginUsername').value = '';
    document.getElementById('loginPassword').value = '';
    document.getElementById('gatekeeperUsername').value = '';
    document.getElementById('gatekeeperPassword').value = '';
    document.getElementById('userDisplayName').value = '';
    document.getElementById('userGroupName').value = '';
    document.getElementById('userGroupPassword').value = '';
    document.getElementById('gatekeeperSuccess')?.remove();
    document.getElementById('setupSuccess').style.display = 'none';
    document.getElementById('replyPreview').style.display = 'none';
    document.getElementById('offlineBar').classList.remove('active');
    reconnectAttempts = 0;
    currentUser = null;
    gatekeeperData = null;
    replyingToMessageId = null;
    messagesData = {};
    hideLoading();
}

async function loadAdminData() {
    try {
        const response = await fetch('/admin/data');
        const data = await response.json();
        
        document.getElementById('statUsers').textContent = data.users.length;
        document.getElementById('statMessages').textContent = data.messages_count;
        document.getElementById('statGroups').textContent = data.groups.length;
        document.getElementById('statOnline').textContent = data.online_count;
        
        let usersHtml = '';
        data.users.forEach(u => {
            usersHtml += `<tr>
                <td>${escapeHtml(u.username)}</td>
                <td>${escapeHtml(u.assigned_group || 'None')}</td>
                <td>${escapeHtml(u.display_name || u.username)}</td>
                <td>${u.status}</td>
                <td>
                    ${u.username !== 'Mpc' ? `<button class="action-btn" onclick="deleteUser('${u.username}')">Delete</button>` : '⭐ Admin'}
                </td>
            </tr>`;
        });
        document.getElementById('usersTableBody').innerHTML = usersHtml;
        
        // Fix #1: Use group_name instead of name
        let groupsHtml = '';
        data.groups.forEach(g => {
            groupsHtml += `<tr>
                <td>${escapeHtml(g.group_name)}</td>
                <td>${escapeHtml(g.created_by)}</td>
                <td><button class="action-btn" onclick="deleteGroup('${g.group_name}')">Delete</button></td>
            </tr>`;
        });
        document.getElementById('groupsTableBody').innerHTML = groupsHtml;
        
        let messagesHtml = '';
        data.messages.forEach(m => {
            let time = new Date(m.created_at * 1000).toLocaleString();
            messagesHtml += `<tr>
                <td>${escapeHtml(m.sender)}</td>
                <td>${escapeHtml(m.group)}</td>
                <td>${time}</td>
                <td><button class="action-btn" onclick="deleteMessage(${m.id})">Delete</button></td>
            </tr>`;
        });
        document.getElementById('messagesTableBody').innerHTML = messagesHtml;
        
        let logsHtml = '';
        data.logs.forEach(l => {
            let time = new Date(l.created_at * 1000).toLocaleString();
            logsHtml += `<tr>
                <td>${escapeHtml(l.admin_username)}</td>
                <td>${escapeHtml(l.action)}</td>
                <td>${escapeHtml(l.target)}</td>
                <td>${time}</td>
            </tr>`;
        });
        document.getElementById('logsTableBody').innerHTML = logsHtml;
        
    } catch(e) {
        console.error('Failed to load admin data:', e);
    }
}

async function createUser() {
    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newPassword').value.trim();
    const group_name = document.getElementById('newGroupName').value.trim();
    const group_password = document.getElementById('newGroupPassword').value.trim();
    
    if(!username || !password || !group_name || !group_password) {
        alert('Please fill all fields');
        hideLoading();
        return;
    }
    
    try {
        const response = await fetch('/admin/create_user', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password, group_name, group_password})
        });
        const data = await response.json();
        if(data.success) {
            alert('✅ User created successfully!\\n\\nUsername: ' + username + '\\nPassword: ' + password + '\\nGroup: ' + group_name);
            document.getElementById('newUsername').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('newGroupName').value = '';
            document.getElementById('newGroupPassword').value = '';
            loadAdminData();
        } else {
            alert(data.error || 'Failed to create user');
        }
        hideLoading();
    } catch(e) {
        alert('Error creating user');
        hideLoading();
    }
}

async function deleteUser(username) {
    if(!confirm(`Delete user "${username}"?`)) { hideLoading(); return; }
    try {
        const response = await fetch('/admin/delete_user', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username})
        });
        const data = await response.json();
        if(data.success) {
            alert('User deleted successfully');
            loadAdminData();
        } else {
            alert(data.message || 'Failed to delete user');
        }
        hideLoading();
    } catch(e) {
        alert('Error deleting user');
        hideLoading();
    }
}

async function deleteGroup(groupName) {
    if(!confirm(`Delete group "${groupName}"? This will delete all messages and users in this group.`)) { hideLoading(); return; }
    try {
        const response = await fetch('/admin/delete_group', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name: groupName})
        });
        const data = await response.json();
        if(data.success) {
            alert('Group deleted successfully');
            loadAdminData();
        } else {
            alert(data.message || 'Failed to delete group');
        }
        hideLoading();
    } catch(e) {
        alert('Error deleting group');
        hideLoading();
    }
}

async function deleteMessage(id) {
    if(!confirm('Delete this message?')) { hideLoading(); return; }
    try {
        const response = await fetch('/admin/delete_message', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({id})
        });
        const data = await response.json();
        if(data.success) {
            alert('Message deleted successfully');
            loadAdminData();
        } else {
            alert(data.message || 'Failed to delete message');
        }
        hideLoading();
    } catch(e) {
        alert('Error deleting message');
        hideLoading();
    }
}

console.log('🔐 ABAVANDIMWE Secure Messaging System');
console.log('📱 Developed by Mugisha Pc');
console.log('💬 Reply feature: Swipe any message left to right to reply');
console.log('📱 PWA: Click "Install ABAVANDIMWE App" to install as Android app');
console.log('⚠️ IMPORTANT: All users in a group must use the SAME group password');
console.log('📝 Enter key inserts new line. Use Send button to send.');
</script>
</body>
</html>'''

# ========== FASTAPI ENDPOINTS ==========
@app.get("/")
async def root():
    return HTMLResponse(HTML)

@app.post("/login")
async def login(request: Request, login_data: LoginRequest):
    # Check rate limit
    allowed, message = check_login_rate_limit(login_data.username)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"success": False, "message": message}
        )
    
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
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "Invalid credentials"}
        )
    
    stored_hash = row['password_hash']
    role = row['role']
    assigned_group = row['assigned_group']
    display_name = row['display_name']
    locked_until = row['locked_until']
    
    if locked_until and locked_until > time.time():
        return JSONResponse(
            status_code=429,
            content={"success": False, "message": f"Account locked. Try again in {int((locked_until - time.time()) / 60)} minutes."}
        )
    
    if verify_password_argon2(login_data.password, stored_hash):
        # Reset attempts on successful login
        reset_login_attempts(login_data.username)
        
        # Get the actual group password
        group_password = None
        if assigned_group:
            group_password = await get_group_password(assigned_group)
            if not group_password:
                group_password = login_data.password
        
        session_id = create_session(login_data.username, role, assigned_group, group_password)
        
        response = JSONResponse({
            "success": True, 
            "username": login_data.username, 
            "role": role,
            "display_name": display_name
        })
        response.set_cookie(
            key="abavandimwe_session",
            value=session_id,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=SESSION_TIMEOUT,
            path="/"
        )
        return response
    else:
        record_failed_login(login_data.username)
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "Invalid credentials"}
        )

@app.post("/gatekeeper")
async def gatekeeper(login_data: LoginRequest):
    allowed, message = check_login_rate_limit(login_data.username)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"success": False, "message": message}
        )
    
    user = await authenticate_user(login_data.username, login_data.password)
    if not user:
        record_failed_login(login_data.username)
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "Invalid credentials"}
        )
    
    if "error" in user:
        return JSONResponse(
            status_code=429,
            content={"success": False, "message": user["error"]}
        )
    
    if user["role"] == "admin":
        return JSONResponse(
            status_code=403,
            content={"success": False, "message": "Admin cannot access chat"}
        )
    
    assigned_group = user["assigned_group"]
    if not assigned_group:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "No group assigned to this user"}
        )
    
    # Get the actual group password from the groups table
    group_password = await get_group_password(assigned_group)
    
    # If no group password stored, use the user's login password
    if not group_password:
        group_password = login_data.password
        print(f"[!] No group password found for '{assigned_group}', using login password")
    
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
        "users": users,
        "messages": messages,
        "messages_count": len(messages),
        "groups": groups,
        "online_count": len(online_users),
        "logs": logs
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
    return {"status": "ok", "system": "ABAVANDIMWE", "author": "Mugisha Pc"}

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
    
    # Send users list
    online = await get_online_users(group_name)
    await websocket.send_json({'type': 'users', 'users': online})
    
    # Send message history with reply_to
    messages = await get_messages(group_name)
    
    history_messages = []
    for msg in messages:
        history_messages.append({
            'id': msg['id'],
            'ciphertext': msg['ciphertext'],
            'sender': msg['sender'],
            'salt': msg['salt'],
            'timestamp': msg['created_at'],
            'reply_to': msg.get('reply_to')
        })
    
    await websocket.send_json({
        'type': 'history',
        'messages': history_messages
    })
    
    # Broadcast user joined
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
                
                if username and group_name and check_message_rate_limit(username):
                    result = await save_message(cipher, group_name, username, salt, reply_to)
                    message_id = result['id']
                    created_at = result['created_at']
                    
                    await manager.broadcast(group_name, {
                        'type': 'message',
                        'message_id': message_id,
                        'ciphertext': cipher,
                        'sender': username,
                        'salt': salt,
                        'timestamp': created_at,
                        'reply_to': reply_to
                    }, exclude=username)
            
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

# ========== MAIN ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv('PORT', 8080))
    print("""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   █████╗ ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗    ║
║  ██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║    ║
║  ███████║██████╔╝███████║██║   ██║███████║██╔██╗ ██║    ║
║  ██╔══██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██╗██║    ║
║  ██║  ██║██████╔╝██║  ██║ ╚████╔╝ ██║  ██║██║ ╚████║    ║
║  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝    ║
║                                                            ║
║              ABAVANDIMWE SECURE MESSAGING                  ║
║           Messages auto-delete after 24 hours              ║
║                    Author: Mugisha Pc                      ║
║                                                            ║
║                   📱 PWA Ready - Install as App!           ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
""")
    print(f"[✓] Server running on port {port}")
    print(f"[✓] Admin: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    print(f"[✓] Database: PostgreSQL (Neon) with asyncpg")
    print(f"[✓] Messages expire after 24 hours")
    print(f"[✓] Open: http://localhost:{port}")
    print(f"\n📱 PWA Features:")
    print(f"   ✅ One-click Install as Android App")
    print(f"   ✅ No Chrome browser UI after install")
    print(f"   ✅ Offline support")
    print(f"   ✅ Custom app icon")
    print(f"   ✅ Loading animation on all button clicks")
    print(f"\n🔐 Group Encryption:")
    print(f"   ✅ All users in same group must use SAME group password")
    print(f"   ✅ Group password stored for consistent decryption")
    print(f"   ✅ Messages encrypted with group password")
    print(f"\n📋 Features:")
    print(f"   ✅ Multiline message input (max 80px height)")
    print(f"   ✅ Reply to messages (swipe left to right)")
    print(f"   ✅ Reply previews with original message")
    print(f"   ✅ Click reply preview to scroll to original")
    print(f"   ✅ Enter: New line, Shift+Enter: New line, Send button to send")
    print(f"   ✅ Offline status bar with reconnect button")
    print(f"   ✅ Send button with ➥ icon")
    print(f"   ✅ Messages hidden when offline")
    print(f"   ✅ Group deletion deletes users and messages, logged in admin logs")
    print(f"\n🔒 Security:")
    print(f"   ✅ Argon2id password hashing")
    print(f"   ✅ Secure HTTP-only session cookies")
    print(f"   ✅ Rate limiting on login and message sending")
    print(f"   ✅ CORS restricted to allowed origins")
    print(f"   ✅ All endpoints protected by session checks")
    uvicorn.run(app, host="0.0.0.0", port=port)
