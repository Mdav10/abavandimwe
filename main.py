"""
ABAVANDIMWE - Secure Messaging (FULLY FIXED)
All data in Neon PostgreSQL
Author: Mugisha Pc
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
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
from argon2 import PasswordHasher
import asyncpg
from asyncpg import create_pool

# ========== LIFESPAN ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting ABAVANDIMWE...")
    await init_db()
    asyncio.create_task(cleanup_loop())
    print("✅ Server ready")
    yield
    if db_pool:
        await db_pool.close()

app = FastAPI(lifespan=lifespan)

# ========== CORS ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== DATABASE ==========
DATABASE_URL = os.getenv('DATABASE_URL')
db_pool = None

async def get_db():
    global db_pool
    if db_pool is None:
        db_pool = await create_pool(DATABASE_URL, min_size=2, max_size=10, ssl='require')
    return await db_pool.acquire()

async def release_db(conn):
    await db_pool.release(conn)

# ========== TABLES ==========
async def init_db():
    conn = await get_db()
    try:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                assigned_group TEXT,
                display_name TEXT,
                created_at DOUBLE PRECISION
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
                reply_to INTEGER,
                voice_url TEXT,
                media_url TEXT,
                media_type TEXT,
                edited BOOLEAN DEFAULT FALSE,
                reactions JSONB DEFAULT '{}'
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                group_name TEXT PRIMARY KEY,
                group_password TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at DOUBLE PRECISION
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                filename TEXT NOT NULL UNIQUE,
                file_data BYTEA NOT NULL,
                mime_type TEXT,
                created_at DOUBLE PRECISION,
                expires_at DOUBLE PRECISION,
                username TEXT
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT,
                assigned_group TEXT,
                group_password TEXT,
                created_at DOUBLE PRECISION,
                expires_at DOUBLE PRECISION
            )
        ''')
        # Admin
        ph = PasswordHasher()
        admin_hash = ph.hash(os.getenv('ADMIN_PASSWORD', 'Mpc@Secure+_+'))
        await conn.execute('''
            INSERT INTO users (username, password_hash, role, created_at) 
            VALUES ($1, $2, 'admin', $3)
            ON CONFLICT (username) DO NOTHING
        ''', 'Mpc', admin_hash, time.time())
        print("✅ Database ready")
    finally:
        await release_db(conn)

# ========== CLEANUP ==========
async def cleanup_old():
    conn = await get_db()
    try:
        now = time.time()
        await conn.execute('DELETE FROM messages WHERE expires_at < $1', now)
        await conn.execute('DELETE FROM files WHERE expires_at < $1', now)
        await conn.execute('DELETE FROM sessions WHERE expires_at < $1', now)
    finally:
        await release_db(conn)

async def cleanup_loop():
    while True:
        await asyncio.sleep(3600)
        await cleanup_old()

# ========== CRYPTO ==========
ph = PasswordHasher()

def hash_pw(pw): return ph.hash(pw)
def verify_pw(pw, h):
    try: return ph.verify(h, pw)
    except: return False

def gen_salt():
    return base64.b64encode(secrets.token_bytes(32)).decode()

def encrypt(text, password, salt):
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)
    encrypted = bytearray()
    for i, c in enumerate(text.encode()):
        encrypted.append(c ^ key[i % len(key)])
    return base64.b64encode(secrets.token_bytes(8) + encrypted).decode()

def decrypt(encrypted, password, salt):
    data = base64.b64decode(encrypted)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)
    decrypted = bytearray()
    for i, c in enumerate(data[8:]):
        decrypted.append(c ^ key[i % len(key)])
    return decrypted.decode()

# ========== SESSIONS ==========
async def create_session(username, role, group, gpass):
    sid = secrets.token_urlsafe(32)
    conn = await get_db()
    try:
        await conn.execute('INSERT INTO sessions VALUES ($1,$2,$3,$4,$5,$6,$7)',
                          sid, username, role, group, gpass, time.time(), time.time()+604800)
        return sid
    finally:
        await release_db(conn)

async def get_session(sid):
    conn = await get_db()
    try:
        row = await conn.fetchrow('SELECT * FROM sessions WHERE session_id=$1 AND expires_at>$2', sid, time.time())
        return dict(row) if row else None
    finally:
        await release_db(conn)

async def delete_session(sid):
    conn = await get_db()
    try:
        await conn.execute('DELETE FROM sessions WHERE session_id=$1', sid)
    finally:
        await release_db(conn)

async def get_user(username):
    conn = await get_db()
    try:
        return await conn.fetchrow('SELECT * FROM users WHERE username=$1', username)
    finally:
        await release_db(conn)

async def auth_user(username, password):
    user = await get_user(username)
    if not user: return None
    if verify_pw(password, user['password_hash']):
        return dict(user)
    return None

async def get_group_pass(group):
    conn = await get_db()
    try:
        row = await conn.fetchrow('SELECT group_password FROM groups WHERE group_name=$1', group)
        return row['group_password'] if row else None
    finally:
        await release_db(conn)

async def save_msg(cipher, group, sender, salt, reply=None, voice=None, media=None, mtype=None):
    now = time.time()
    conn = await get_db()
    try:
        result = await conn.fetchrow('''
            INSERT INTO messages (ciphertext, group_name, sender, salt, created_at, expires_at, reply_to, voice_url, media_url, media_type)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id, created_at
        ''', cipher, group, sender, salt, now, now+86400, reply, voice, media, mtype)
        return dict(result)
    finally:
        await release_db(conn)

async def get_msgs(group):
    conn = await get_db()
    try:
        rows = await conn.fetch('SELECT * FROM messages WHERE group_name=$1 AND created_at>$2 ORDER BY id',
                               group, time.time()-86400)
        return [dict(r) for r in rows]
    finally:
        await release_db(conn)

async def save_file(filename, data, mime, username):
    conn = await get_db()
    try:
        await conn.execute('INSERT INTO files (filename,file_data,mime_type,created_at,expires_at,username) VALUES ($1,$2,$3,$4,$5,$6)',
                          filename, data, mime, time.time(), time.time()+604800, username)
    finally:
        await release_db(conn)

async def get_file(filename):
    conn = await get_db()
    try:
        return await conn.fetchrow('SELECT file_data,mime_type FROM files WHERE filename=$1', filename)
    finally:
        await release_db(conn)

async def create_user_group(username, password, group, gpass):
    conn = await get_db()
    try:
        row = await conn.fetchrow('SELECT group_password FROM groups WHERE group_name=$1', group)
        if row and row['group_password'] != gpass:
            return {"error": "Wrong group password"}
        if not row:
            await conn.execute('INSERT INTO groups VALUES ($1,$2,$3,$4)', group, gpass, 'admin', time.time())
        await conn.execute('INSERT INTO users VALUES ($1,$2,$3,$4,$5,$6)',
                          username, hash_pw(password), 'user', group, None, time.time())
        return {"success": True}
    except Exception as e:
        return {"error": str(e)}
    finally:
        await release_db(conn)

async def delete_user(username):
    if username == 'Mpc': return False
    conn = await get_db()
    try:
        await conn.execute('DELETE FROM users WHERE username=$1', username)
        return True
    finally:
        await release_db(conn)

async def delete_group(name):
    conn = await get_db()
    try:
        await conn.execute('DELETE FROM users WHERE assigned_group=$1', name)
        await conn.execute('DELETE FROM messages WHERE group_name=$1', name)
        await conn.execute('DELETE FROM groups WHERE group_name=$1', name)
        return True
    finally:
        await release_db(conn)

async def get_all_users():
    conn = await get_db()
    try:
        return [dict(r) for r in await conn.fetch('SELECT username, assigned_group FROM users')]
    finally:
        await release_db(conn)

async def get_all_groups():
    conn = await get_db()
    try:
        return [dict(r) for r in await conn.fetch('SELECT * FROM groups')]
    finally:
        await release_db(conn)

async def get_all_msgs():
    conn = await get_db()
    try:
        return [dict(r) for r in await conn.fetch('SELECT id, sender, group_name FROM messages ORDER BY id DESC LIMIT 50')]
    finally:
        await release_db(conn)

# ========== WEBSOCKET MANAGER ==========
class Manager:
    def __init__(self):
        self.connections: Dict[str, Dict[str, WebSocket]] = {}
        self.online_users: Dict[str, set] = {}

    async def add(self, group, user, ws):
        if group not in self.connections:
            self.connections[group] = {}
            self.online_users[group] = set()
        self.connections[group][user] = ws
        self.online_users[group].add(user)
        await self.broadcast_users(group)

    def remove(self, group, user):
        if group in self.connections:
            self.connections[group].pop(user, None)
            if group in self.online_users:
                self.online_users[group].discard(user)
            if not self.connections[group]:
                del self.connections[group]
                del self.online_users[group]
            else:
                asyncio.create_task(self.broadcast_users(group))

    async def broadcast_users(self, group):
        if group in self.online_users:
            users = list(self.online_users[group])
            await self.broadcast(group, {'type': 'users', 'users': users})

    async def broadcast(self, group, msg, exclude=None):
        if group not in self.connections:
            return
        for user, ws in self.connections[group].items():
            if user != exclude:
                try:
                    await ws.send_json(msg)
                except:
                    pass

manager = Manager()

# ========== API ENDPOINTS ==========
@app.post("/login")
async def login(data: dict):
    user = await auth_user(data.get('username'), data.get('password'))
    if not user:
        return JSONResponse({"success": False, "message": "Invalid"}, status_code=401)
    gpass = await get_group_pass(user['assigned_group']) if user['assigned_group'] else None
    sid = await create_session(user['username'], user['role'], user['assigned_group'], gpass)
    resp = JSONResponse({
        "success": True,
        "username": user['username'],
        "role": user['role'],
        "display_name": user.get('display_name')
    })
    resp.set_cookie("abavandimwe_session", sid, httponly=True, max_age=604800, path="/")
    return resp

@app.post("/gatekeeper")
async def gatekeeper(data: dict):
    user = await auth_user(data.get('username'), data.get('password'))
    if not user:
        return JSONResponse({"success": False, "message": "Invalid"}, status_code=401)
    if user['role'] == 'admin':
        return JSONResponse({"success": False, "message": "Admin cannot chat"}, status_code=403)
    gpass = await get_group_pass(user['assigned_group'])
    return {
        "success": True,
        "username": user['username'],
        "assigned_group": user['assigned_group'],
        "assigned_group_password": gpass,
        "display_name": user.get('display_name')
    }

@app.post("/save_display_name")
async def save_display_name(data: dict, request: Request):
    sid = request.cookies.get('abavandimwe_session')
    session = await get_session(sid) if sid else None
    if not session:
        return JSONResponse({"success": False}, status_code=401)
    conn = await get_db()
    try:
        await conn.execute('UPDATE users SET display_name=$1 WHERE username=$2', data['display_name'], data['username'])
    finally:
        await release_db(conn)
    return {"success": True}

@app.post("/api/upload_voice")
async def upload_voice(request: Request, file: UploadFile = File(...)):
    sid = request.cookies.get('abavandimwe_session')
    session = await get_session(sid) if sid else None
    if not session:
        return JSONResponse({"success": False, "error": "Auth required"}, status_code=401)
    content = await file.read()
    filename = f"{uuid.uuid4()}.webm"
    await save_file(filename, content, 'audio/webm', session['username'])
    return {"success": True, "url": f"/api/files/{filename}"}

@app.post("/api/upload_media")
async def upload_media(request: Request, file: UploadFile = File(...)):
    sid = request.cookies.get('abavandimwe_session')
    session = await get_session(sid) if sid else None
    if not session:
        return JSONResponse({"success": False, "error": "Auth required"}, status_code=401)
    content = await file.read()
    ext = file.filename.split('.')[-1] if '.' in file.filename else 'bin'
    filename = f"{uuid.uuid4()}.{ext}"
    # Store the correct mime type
    mime_type = file.content_type or 'application/octet-stream'
    await save_file(filename, content, mime_type, session['username'])
    return {"success": True, "url": f"/api/files/{filename}", "type": mime_type}

@app.get("/api/files/{filename}")
async def get_file(filename: str):
    row = await get_file(filename)
    if not row:
        raise HTTPException(status_code=404)
    return Response(content=row['file_data'], media_type=row['mime_type'])

@app.post("/edit_message")
async def edit_message(data: dict, request: Request):
    sid = request.cookies.get('abavandimwe_session')
    session = await get_session(sid) if sid else None
    if not session:
        return JSONResponse({"success": False}, status_code=401)
    conn = await get_db()
    try:
        row = await conn.fetchrow('SELECT sender, group_name FROM messages WHERE id=$1', data['message_id'])
        if not row or row['sender'] != session['username']:
            return JSONResponse({"success": False, "error": "Not your message"})
        salt = gen_salt()
        new_cipher = encrypt(data['new_text'], session['group_password'], salt)
        await conn.execute('UPDATE messages SET ciphertext=$1, salt=$2, edited=TRUE WHERE id=$3',
                          new_cipher, salt, data['message_id'])
        await manager.broadcast(row['group_name'], {
            'type': 'message_edited',
            'message_id': data['message_id'],
            'ciphertext': new_cipher,
            'salt': salt
        })
        return {"success": True}
    finally:
        await release_db(conn)

@app.post("/reaction")
async def reaction(data: dict, request: Request):
    sid = request.cookies.get('abavandimwe_session')
    session = await get_session(sid) if sid else None
    if not session:
        return JSONResponse({"success": False}, status_code=401)
    conn = await get_db()
    try:
        row = await conn.fetchrow('SELECT group_name, reactions FROM messages WHERE id=$1', data['message_id'])
        if not row:
            return JSONResponse({"success": False, "error": "Not found"})
        reactions = row['reactions'] or {}
        emoji = data['emoji']
        if emoji in reactions and session['username'] in reactions[emoji]:
            reactions[emoji].remove(session['username'])
            if not reactions[emoji]:
                del reactions[emoji]
        else:
            reactions.setdefault(emoji, []).append(session['username'])
        await conn.execute('UPDATE messages SET reactions=$1 WHERE id=$2', json.dumps(reactions), data['message_id'])
        counts = {e: len(u) for e, u in reactions.items()}
        await manager.broadcast(row['group_name'], {
            'type': 'reaction_update',
            'message_id': data['message_id'],
            'reactions': counts
        })
        return {"success": True, "reactions": counts}
    finally:
        await release_db(conn)

@app.get("/admin/data")
async def admin_data(request: Request):
    sid = request.cookies.get('abavandimwe_session')
    session = await get_session(sid) if sid else None
    if not session or session['role'] != 'admin':
        return JSONResponse({"success": False}, status_code=403)
    users = await get_all_users()
    groups = await get_all_groups()
    messages = await get_all_msgs()
    return {"users": users, "groups": groups, "messages": messages}

@app.post("/admin/create_user")
async def admin_create_user(data: dict, request: Request):
    sid = request.cookies.get('abavandimwe_session')
    session = await get_session(sid) if sid else None
    if not session or session['role'] != 'admin':
        return JSONResponse({"success": False}, status_code=403)
    return await create_user_group(data['username'], data['password'], data['group_name'], data['group_password'])

@app.post("/admin/delete_user")
async def admin_delete_user(data: dict, request: Request):
    sid = request.cookies.get('abavandimwe_session')
    session = await get_session(sid) if sid else None
    if not session or session['role'] != 'admin':
        return JSONResponse({"success": False}, status_code=403)
    return {"success": await delete_user(data['username'])}

@app.post("/admin/delete_group")
async def admin_delete_group(data: dict, request: Request):
    sid = request.cookies.get('abavandimwe_session')
    session = await get_session(sid) if sid else None
    if not session or session['role'] != 'admin':
        return JSONResponse({"success": False}, status_code=403)
    return {"success": await delete_group(data['name'])}

@app.post("/admin/delete_message")
async def admin_delete_message(data: dict, request: Request):
    sid = request.cookies.get('abavandimwe_session')
    session = await get_session(sid) if sid else None
    if not session or session['role'] != 'admin':
        return JSONResponse({"success": False}, status_code=403)
    conn = await get_db()
    try:
        await conn.execute('DELETE FROM messages WHERE id=$1', data['id'])
        return {"success": True}
    finally:
        await release_db(conn)

@app.post("/logout")
async def logout(request: Request):
    sid = request.cookies.get('abavandimwe_session')
    if sid:
        await delete_session(sid)
    resp = JSONResponse({"success": True})
    resp.delete_cookie("abavandimwe_session")
    return resp

@app.get("/")
async def root():
    return HTMLResponse(HTML)

# ========== WEBSOCKET ==========
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    sid = None
    for item in websocket.headers.get("cookie", "").split(";"):
        item = item.strip()
        if item.startswith("abavandimwe_session="):
            sid = item.split("=")[1]
            break
    if not sid:
        await websocket.send_json({'type': 'error', 'message': 'No session'})
        await websocket.close()
        return
    session = await get_session(sid)
    if not session:
        await websocket.send_json({'type': 'error', 'message': 'Invalid session'})
        await websocket.close()
        return
    username = session['username']
    group = session['assigned_group']
    gpass = session['group_password']
    if not group:
        await websocket.send_json({'type': 'error', 'message': 'No group'})
        await websocket.close()
        return

    await manager.add(group, username, websocket)
    await websocket.send_json({'type': 'history', 'messages': await get_msgs(group)})
    if group in manager.online_users:
        users_list = list(manager.online_users[group])
        await websocket.send_json({'type': 'users', 'users': users_list})
    await manager.broadcast(group, {'type': 'user_joined', 'user': username}, exclude=username)
    print(f"[+] {username} joined {group}")

    try:
        while True:
            data = await websocket.receive_json()
            if data.get('type') == 'message':
                result = await save_msg(
                    data['ciphertext'], group, username, data['salt'],
                    data.get('reply_to'), data.get('voice_url'),
                    data.get('media_url'), data.get('media_type')
                )
                await manager.broadcast(group, {
                    'type': 'message',
                    'message_id': result['id'],
                    'ciphertext': data['ciphertext'],
                    'sender': username,
                    'salt': data['salt'],
                    'timestamp': result['created_at'],
                    'reply_to': data.get('reply_to'),
                    'voice_url': data.get('voice_url'),
                    'media_url': data.get('media_url'),
                    'media_type': data.get('media_type')
                })
            elif data.get('type') == 'typing':
                await manager.broadcast(group, {'type': 'typing', 'user': username}, exclude=username)
            elif data.get('type') == 'stop_typing':
                await manager.broadcast(group, {'type': 'stop_typing', 'user': username}, exclude=username)
    except WebSocketDisconnect:
        pass
    finally:
        manager.remove(group, username)
        await manager.broadcast(group, {'type': 'user_left', 'user': username})
        print(f"[-] {username} left {group}")

# ========== HTML ==========
HTML = '''<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,user-scalable=no">
<title>ABAVANDIMWE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{font-family:monospace;background:#0a0a0f;color:#0f0;height:100dvh;overflow:hidden}

.login-container{position:fixed;inset:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;padding:20px}
.login-card{background:#050508;border:2px solid #0f0;border-radius:24px;padding:32px 24px;width:100%;max-width:400px}
h1{text-align:center;font-size:24px;margin-bottom:4px}
.sub{text-align:center;font-size:11px;color:#666;margin-bottom:16px}
input{width:100%;padding:14px;margin:8px 0;background:#111;border:1px solid #0f0;border-radius:12px;color:#0f0;font-size:15px;outline:none}
input:focus{box-shadow:0 0 20px rgba(0,255,65,0.2)}
button{width:100%;padding:14px;margin-top:12px;background:transparent;border:2px solid #0f0;border-radius:12px;color:#0f0;font-size:16px;font-weight:bold;cursor:pointer;transition:all 0.3s}
button:hover{background:#0f0;color:#000}
button:disabled{opacity:0.5;cursor:not-allowed}
.btn-whatsapp{background:#25D366;border-color:#25D366;color:white}
.btn-whatsapp:hover{background:#128C7E}
.error{color:#ff4444;font-size:12px;text-align:center;margin-top:8px;display:none}
.separator{display:flex;align-items:center;margin:16px 0}
.separator::before,.separator::after{content:'';flex:1;border-bottom:1px solid #1a1a2e}
.separator span{padding:0 10px;color:#666;font-size:10px}
.footer{text-align:center;margin-top:16px;font-size:8px;color:#333;border-top:1px solid #1a1a2e;padding-top:12px}

.gatekeeper-container,.setup-container{display:none;position:fixed;inset:0;background:#0a0a0f;z-index:900;padding:20px;justify-content:center;align-items:center}
.gatekeeper-container.active,.setup-container.active{display:flex}
.gatekeeper-card,.setup-card{background:#050508;border:2px solid #0f0;border-radius:24px;padding:32px 24px;width:100%;max-width:400px}
.gatekeeper-card h2,.setup-card h2{text-align:center;font-size:22px;margin-bottom:4px}
.gatekeeper-card .sub,.setup-card .sub{text-align:center;font-size:11px;color:#666;margin-bottom:16px}

.chat-container{display:none;flex-direction:column;height:100dvh;background:#0a0a0f}
.chat-container.active{display:flex}

.header{padding:10px 14px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;align-items:center;flex-shrink:0;min-height:50px}
.header h2{font-size:15px;text-align:center;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:0 8px}
.header-left{display:flex;align-items:center;gap:8px}
.online-badge{font-size:9px;padding:2px 8px;border:1px solid #0f0;border-radius:12px;background:rgba(0,255,0,0.05)}
.logout-btn{width:auto;padding:4px 12px;font-size:11px;margin:0;border-color:#ff0041;color:#ff0041}
.logout-btn:hover{background:#ff0041;color:white}

.main-content{display:flex;flex:1;min-height:0}
.sidebar{width:200px;background:#050508;border-right:1px solid #0f0;display:flex;flex-direction:column;flex-shrink:0;overflow:hidden}
.sidebar-header{padding:10px;border-bottom:1px solid #0f0;font-size:12px;font-weight:bold}
.online-users{flex:1;overflow-y:auto;padding:8px}
.online-user{padding:6px 10px;margin:4px 0;border:1px solid #0f0;border-radius:6px;font-size:12px;display:flex;align-items:center;gap:6px}
.online-user::before{content:"●";color:#0f0;font-size:8px}
@media(max-width:600px){.sidebar{position:fixed;left:-200px;top:0;bottom:0;z-index:20;transition:left 0.3s;width:200px}.sidebar.open{left:0}.overlay{position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:10;display:none}.overlay.active{display:block}}
.messages-area{flex:1;display:flex;flex-direction:column;min-width:0}
.messages{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:4px}
.message{max-width:85%;padding:4px 0;word-break:break-word;overflow-wrap:anywhere}
.message.sent{align-self:flex-end}
.message.received{align-self:flex-start}
.bubble{padding:8px 12px;border-radius:14px;font-size:14px;word-wrap:break-word;line-height:1.4}
.sent .bubble{background:#0f0;color:#000;border-bottom-right-radius:4px}
.received .bubble{background:#1a1a2e;border:1px solid #0f0;border-bottom-left-radius:4px}
.msg-sender{font-size:9px;opacity:0.7;padding-left:4px}
.msg-time{font-size:8px;opacity:0.5;margin-top:2px}
.system-msg{text-align:center;font-size:10px;color:#ffaa00;margin:4px 0;font-style:italic}
.typing-indicator{padding:2px 16px 6px;font-size:10px;color:#0f0;font-style:italic;min-height:22px;flex-shrink:0}

.composer{padding:8px;background:#050508;border-top:1px solid #0f0;flex-shrink:0}
.composer-row{display:flex;gap:6px;align-items:flex-end}
.composer-row textarea{flex:1;padding:10px 14px;background:#111;border:1px solid #0f0;border-radius:10px;color:#0f0;font-family:monospace;font-size:13px;resize:none;max-height:120px;min-height:40px;line-height:1.4;outline:none}
.composer-row textarea:focus{box-shadow:0 0 20px rgba(0,255,65,0.2)}
.composer-row button{width:40px;height:40px;min-width:40px;padding:0;margin:0;border-radius:50%;font-size:16px;display:flex;align-items:center;justify-content:center;flex-shrink:0;border:2px solid #0f0;background:transparent;color:#0f0;cursor:pointer;transition:all 0.2s}
.composer-row button:hover{background:rgba(0,255,0,0.1)}
.send-btn{background:#0f0;color:#000;border-color:#0f0}
.send-btn:hover{background:#00cc00}
.voice-btn{font-size:18px}
.voice-btn.recording{border-color:#ff0041;background:rgba(255,0,65,0.15);animation:pulse 1s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(255,0,65,0.4)}50%{box-shadow:0 0 20px 10px rgba(255,0,65,0.15)}}
.media-btn{font-size:16px}

.recording-status{display:none;padding:6px 12px;margin-top:4px;background:#1a1a2e;border:1px solid #ff0041;border-radius:8px;align-items:center;gap:8px}
.recording-status.active{display:flex}
#recTimer{color:#ff0041;font-size:14px;font-weight:bold;min-width:44px}
.wave{flex:1;display:flex;align-items:center;gap:2px;height:20px}
.wave .bar{width:3px;background:#ff0041;border-radius:2px;animation:wave 0.6s ease-in-out infinite alternate}
.wave .bar:nth-child(1){height:6px;animation-delay:0s}
.wave .bar:nth-child(2){height:14px;animation-delay:0.1s}
.wave .bar:nth-child(3){height:20px;animation-delay:0.2s}
.wave .bar:nth-child(4){height:12px;animation-delay:0.3s}
.wave .bar:nth-child(5){height:22px;animation-delay:0.4s}
.wave .bar:nth-child(6){height:16px;animation-delay:0.5s}
.wave .bar:nth-child(7){height:8px;animation-delay:0.6s}
.wave .bar:nth-child(8){height:18px;animation-delay:0.7s}
@keyframes wave{0%{transform:scaleY(0.3)}100%{transform:scaleY(1)}}
#cancelRec{background:transparent;border:1px solid #555;color:#888;padding:2px 10px;border-radius:4px;cursor:pointer;font-size:11px}
#cancelRec:hover{border-color:#ff0041;color:#ff0041}

.voice-play-btn{background:transparent;border:2px solid #0f0;color:#0f0;padding:4px 12px;border-radius:16px;cursor:pointer;font-size:12px;display:inline-flex;align-items:center;gap:8px}
.voice-play-btn.playing{border-color:#ffaa00;color:#ffaa00}
.voice-progress{width:80px;height:3px;background:#1a1a2e;border-radius:2px;overflow:hidden}
.voice-progress-bar{height:100%;background:#0f0;width:0%;transition:width 0.1s}
.voice-duration{font-size:10px;color:#888;min-width:35px}

.message-media{max-width:160px;max-height:160px;border-radius:8px;margin-top:4px;cursor:pointer}
.message-media:hover{opacity:0.8}

.reaction-container{display:flex;gap:4px;margin-top:4px;flex-wrap:wrap}
.reaction-emoji{background:#1a1a2e;padding:1px 6px;border-radius:8px;font-size:11px;cursor:pointer;border:1px solid transparent}
.reaction-emoji:hover{border-color:#0f0}
.reaction-picker{display:none;position:absolute;bottom:100%;left:0;background:#050508;border:1px solid #0f0;border-radius:8px;padding:4px;z-index:100}
.reaction-picker.active{display:flex;flex-wrap:wrap;gap:2px;max-width:160px}
.reaction-picker span{font-size:16px;cursor:pointer;padding:2px 4px;border-radius:4px}
.reaction-picker span:hover{background:#1a1a2e}
.message-actions{display:flex;gap:4px;margin-top:2px;flex-wrap:wrap}
.message-actions button{background:transparent;border:none;color:#888;font-size:10px;cursor:pointer;padding:1px 4px;width:auto;margin:0}
.message-actions button:hover{color:#0f0}
.edit-input{display:none;width:100%;padding:4px;background:#111;border:1px solid #0f0;border-radius:4px;color:#0f0;font-size:12px;margin-top:2px}

.offline-bar{display:none;background:#ff0041;color:white;text-align:center;padding:4px;font-size:10px;font-weight:bold;flex-shrink:0}
.offline-bar.active{display:block}

.loading-overlay{position:fixed;inset:0;background:rgba(10,10,15,0.95);z-index:9999;display:none;justify-content:center;align-items:center;flex-direction:column;gap:16px}
.loading-overlay.active{display:flex}
.loader{width:50px;height:50px;border:3px solid rgba(0,255,65,0.1);border-top:3px solid #0f0;border-radius:50%;animation:spin 0.8s linear infinite}
@keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}
.loader-text{color:#0f0;font-size:14px}

.admin-panel{display:none;position:fixed;inset:0;background:#0a0a0f;z-index:50;padding:16px;overflow-y:auto}
.admin-panel.active{display:block}
.admin-header{display:flex;justify-content:space-between;align-items:center;padding:12px;border-bottom:2px solid #0f0;margin-bottom:16px}
.admin-header h2{color:#ffaa00;font-size:18px}
.admin-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}
.admin-card{background:#050508;border:1px solid #0f0;border-radius:10px;padding:14px}
.admin-card h3{color:#0f0;font-size:13px;margin-bottom:8px}
.admin-card input{width:100%;padding:6px;margin:3px 0;background:#111;border:1px solid #0f0;border-radius:4px;color:#0f0;font-size:11px}
.admin-card button{width:auto;padding:4px 12px;font-size:11px;margin:3px}
.admin-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px;margin-bottom:12px}
.stat-box{background:#050508;border:1px solid #0f0;border-radius:8px;padding:10px;text-align:center}
.stat-number{font-size:20px;color:#0f0}
.stat-label{font-size:9px;color:#666}
.admin-table-wrap{max-height:150px;overflow-y:auto}
.admin-table-wrap table{width:100%;font-size:10px;border-collapse:collapse}
.admin-table-wrap th{text-align:left;padding:3px;border-bottom:1px solid #1a1a2e;color:#666}
.admin-table-wrap td{padding:3px;border-bottom:1px solid #1a1a2e}
.action-btn{background:transparent;border:1px solid #ff0041;color:#ff0041;padding:1px 6px;border-radius:3px;cursor:pointer;font-size:9px}
.action-btn:hover{background:#ff0041;color:white}
.action-btn-green{background:transparent;border:1px solid #0f0;color:#0f0;padding:1px 6px;border-radius:3px;cursor:pointer;font-size:9px}
.action-btn-green:hover{background:#0f0;color:#000}
.close-admin{background:#ff0041;border-color:#ff0041;color:white;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:12px;width:auto;margin:0}

::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:#1a1a2e}
::-webkit-scrollbar-thumb{background:#0f0;border-radius:2px}
@media(max-width:600px){.message{max-width:90%}}
</style>
</head>
<body>

<div class="loading-overlay" id="loadingOverlay">
    <div class="loader"></div>
    <div class="loader-text">Loading...</div>
</div>

<!-- LOGIN -->
<div class="login-container" id="loginScreen">
    <div class="login-card">
        <h1># ABAVANDIMWE</h1>
        <div class="sub">Secure Messaging</div>
        <input type="text" id="loginUser" placeholder="Username">
        <input type="password" id="loginPass" placeholder="Password">
        <button id="loginBtn">▶ Login</button>
        <div class="separator"><span>OR</span></div>
        <button class="btn-whatsapp" onclick="requestAccess()">💬 Request Access</button>
        <div class="error" id="loginError"></div>
        <div class="footer">🔒 AES-256 | Messages auto-delete after 24h<br>Developed by Mugisha Pc</div>
    </div>
</div>

<!-- GATEKEEPER -->
<div class="gatekeeper-container" id="gatekeeperScreen">
    <div class="gatekeeper-card">
        <h2>🔐 Gatekeeper</h2>
        <div class="sub">Verify your credentials</div>
        <input type="text" id="gkUser" placeholder="Username" readonly>
        <input type="password" id="gkPass" placeholder="Password">
        <button id="gkBtn">▶ Verify</button>
        <div class="error" id="gkError"></div>
    </div>
</div>

<!-- SETUP -->
<div class="setup-container" id="setupScreen">
    <div class="setup-card">
        <h2>👤 Setup Profile</h2>
        <div class="sub">Enter your display name</div>
        <input type="text" id="setupDisplay" placeholder="Your Display Name">
        <input type="text" id="setupGroup" placeholder="Group" readonly>
        <input type="password" id="setupPass" placeholder="Group Password" readonly>
        <button id="setupBtn">▶ Enter Chat</button>
        <div class="error" id="setupError"></div>
    </div>
</div>

<!-- CHAT -->
<div class="chat-container" id="chatScreen">
    <div class="header">
        <div class="header-left">
            <span class="online-badge" id="onlineBadge">● Online</span>
            <button class="menu-btn" onclick="toggleSidebar()" style="background:transparent;border:1px solid #0f0;color:#0f0;padding:2px 8px;border-radius:4px;cursor:pointer;font-size:14px;display:none">☰</button>
        </div>
        <h2 id="groupTitle"># LOADING</h2>
        <button class="logout-btn" onclick="logout()">Leave</button>
    </div>
    <div class="offline-bar" id="offlineBar">⚠️ Offline <button onclick="reconnect()">↻ Retry</button></div>
    <div class="main-content">
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header">● Online Users</div>
            <div class="online-users" id="onlineUsers"><div style="color:#666;padding:8px;font-size:12px;">Loading...</div></div>
        </div>
        <div class="overlay" id="overlay" onclick="toggleSidebar()"></div>
        <div class="messages-area">
            <div class="messages" id="messages"><div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div></div>
            <div class="typing-indicator" id="typingIndicator"></div>
            <div class="composer">
                <div class="composer-row">
                    <textarea id="msgInput" placeholder="Type a message..." rows="1"></textarea>
                    <button class="voice-btn" id="voiceBtn" onmousedown="startRecord()" onmouseup="stopRecord()" onmouseleave="stopRecord()" ontouchstart="startRecord()" ontouchend="stopRecord()" ontouchcancel="stopRecord()">🎙️</button>
                    <button class="media-btn" onclick="shareMedia()">📎</button>
                    <button class="send-btn" onclick="sendMessage()">➤</button>
                </div>
                <div class="recording-status" id="recStatus">
                    <span id="recTimer">00:00</span>
                    <div class="wave"><span class="bar"></span><span class="bar"></span><span class="bar"></span><span class="bar"></span><span class="bar"></span><span class="bar"></span><span class="bar"></span><span class="bar"></span></div>
                    <span id="recText">🔴 Recording</span>
                    <button id="cancelRec" onclick="cancelRecord()">✕ Cancel</button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ADMIN -->
<div class="admin-panel" id="adminPanel">
    <div class="admin-header">
        <h2>⚙️ Admin <span id="adminName">Mpc</span></h2>
        <button class="close-admin" onclick="logout()">🚪 Logout</button>
    </div>
    <div class="admin-stats" id="adminStats">
        <div class="stat-box"><div class="stat-number" id="statUsers">0</div><div class="stat-label">Users</div></div>
        <div class="stat-box"><div class="stat-number" id="statGroups">0</div><div class="stat-label">Groups</div></div>
        <div class="stat-box"><div class="stat-number" id="statMessages">0</div><div class="stat-label">Messages</div></div>
    </div>
    <div class="admin-grid">
        <div class="admin-card">
            <h3>👤 Create User</h3>
            <input type="text" id="newUser" placeholder="Username">
            <input type="text" id="newPass" placeholder="Password">
            <input type="text" id="newGroup" placeholder="Group Name">
            <input type="text" id="newGroupPass" placeholder="Group Password">
            <button class="action-btn-green" onclick="createUser()">➕ Create</button>
        </div>
        <div class="admin-card">
            <h3>📋 Users</h3>
            <div class="admin-table-wrap"><table><thead><tr><th>User</th><th>Group</th><th>Action</th></tr></thead>
            <tbody id="usersTable"></tbody></table></div>
        </div>
        <div class="admin-card">
            <h3>📁 Groups</h3>
            <div class="admin-table-wrap"><table><thead><tr><th>Group</th><th>Created</th><th>Action</th></tr></thead>
            <tbody id="groupsTable"></tbody></table></div>
        </div>
        <div class="admin-card">
            <h3>📨 Messages</h3>
            <div class="admin-table-wrap"><table><thead><tr><th>Sender</th><th>Group</th><th>Action</th></tr></thead>
            <tbody id="messagesTable"></tbody></table></div>
        </div>
    </div>
</div>

<script>
// ========== GLOBALS ==========
let ws, username, groupName, groupPassword, messagesData = {};
let replyingTo = null;
let recSeconds = 0, recTimer = null, mediaRecorder = null, audioChunks = [];
let isRecording = false, isHolding = false, holdTimer = null;

// ========== DOM REFS ==========
const loginBtn = document.getElementById('loginBtn');
const gkBtn = document.getElementById('gkBtn');
const setupBtn = document.getElementById('setupBtn');
const msgInput = document.getElementById('msgInput');

// ========== LOADING ==========
function showLoading() { document.getElementById('loadingOverlay').classList.add('active'); }
function hideLoading() { document.getElementById('loadingOverlay').classList.remove('active'); }

// ========== LOGIN ==========
loginBtn.addEventListener('click', login);
document.getElementById('loginPass').addEventListener('keypress', e => { if(e.key === 'Enter') login(); });

async function login() {
    const user = document.getElementById('loginUser').value.trim();
    const pass = document.getElementById('loginPass').value;
    if(!user || !pass) { showError('Please enter username and password'); return; }
    loginBtn.disabled = true; loginBtn.textContent = '⏳'; showLoading();
    try {
        const res = await fetch('/login', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({username:user, password:pass})
        });
        const data = await res.json();
        if(data.success) {
            if(data.role === 'admin') {
                document.getElementById('loginScreen').style.display = 'none';
                document.getElementById('adminPanel').classList.add('active');
                document.getElementById('adminName').textContent = data.username;
                loadAdmin();
            } else {
                document.getElementById('loginScreen').style.display = 'none';
                document.getElementById('gatekeeperScreen').classList.add('active');
                document.getElementById('gkUser').value = data.username;
                document.getElementById('gkPass').value = '';
                if(data.display_name) {
                    const el = document.getElementById('gkError');
                    el.textContent = '✅ Welcome back ' + data.display_name;
                    el.style.color = '#0f0';
                    el.style.display = 'block';
                }
            }
            hideLoading();
        } else {
            showError(data.message || 'Invalid credentials');
            hideLoading();
        }
    } catch(e) {
        showError('Connection error. Please try again.');
        hideLoading();
    }
    loginBtn.disabled = false; loginBtn.textContent = '▶ Login';
}

function showError(msg) {
    const el = document.getElementById('loginError');
    el.textContent = msg; el.style.display = 'block';
    setTimeout(() => el.style.display = 'none', 5000);
}

// ========== GATEKEEPER ==========
gkBtn.addEventListener('click', gatekeeper);
document.getElementById('gkPass').addEventListener('keypress', e => { if(e.key === 'Enter') gatekeeper(); });

async function gatekeeper() {
    const user = document.getElementById('gkUser').value.trim();
    const pass = document.getElementById('gkPass').value;
    if(!pass) { showGkError('Please enter your password'); return; }
    gkBtn.disabled = true; gkBtn.textContent = '⏳'; showLoading();
    try {
        const res = await fetch('/gatekeeper', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({username:user, password:pass})
        });
        const data = await res.json();
        if(data.success) {
            document.getElementById('gatekeeperScreen').classList.remove('active');
            document.getElementById('setupScreen').classList.add('active');
            document.getElementById('setupDisplay').value = data.display_name || '';
            document.getElementById('setupGroup').value = data.assigned_group;
            document.getElementById('setupPass').value = data.assigned_group_password;
            groupPassword = data.assigned_group_password;
            hideLoading();
        } else {
            showGkError(data.message || 'Invalid credentials');
            hideLoading();
        }
    } catch(e) {
        showGkError('Connection error');
        hideLoading();
    }
    gkBtn.disabled = false; gkBtn.textContent = '▶ Verify';
}

function showGkError(msg) {
    const el = document.getElementById('gkError');
    el.textContent = msg; el.style.color = '#ff4444'; el.style.display = 'block';
    setTimeout(() => el.style.display = 'none', 5000);
}

// ========== SETUP ==========
setupBtn.addEventListener('click', enterChat);
document.getElementById('setupDisplay').addEventListener('keypress', e => { if(e.key === 'Enter') enterChat(); });

async function enterChat() {
    const display = document.getElementById('setupDisplay').value.trim();
    const group = document.getElementById('setupGroup').value.trim();
    if(!display) { showSetupError('Please enter your display name'); return; }
    setupBtn.disabled = true; setupBtn.textContent = '⏳'; showLoading();
    try {
        await fetch('/save_display_name', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({username:document.getElementById('gkUser').value, display_name:display})
        });
        window.username = display;
        window.groupName = group;
        window.groupPassword = groupPassword;
        document.getElementById('setupScreen').classList.remove('active');
        document.getElementById('chatScreen').classList.add('active');
        document.getElementById('messages').innerHTML = '';
        messagesData = {};
        hideLoading();
        connectToChat(display, group);
    } catch(e) {
        showSetupError('Error entering chat');
        hideLoading();
    }
    setupBtn.disabled = false; setupBtn.textContent = '▶ Enter Chat';
}

function showSetupError(msg) {
    const el = document.getElementById('setupError');
    el.textContent = msg; el.style.color = '#ff4444'; el.style.display = 'block';
    setTimeout(() => el.style.display = 'none', 5000);
}

// ========== CONNECT TO CHAT ==========
function connectToChat(user, group) {
    document.getElementById('groupTitle').textContent = '# ' + group;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(protocol + '//' + window.location.host + '/ws');
    ws.onopen = function() {
        updateStatus(true);
        document.getElementById('offlineBar').classList.remove('active');
        ws.send(JSON.stringify({type:'join', username:user, group:group}));
    };
    ws.onmessage = async function(e) {
        try {
            const d = JSON.parse(e.data);
            if(d.type === 'history') {
                document.getElementById('messages').innerHTML = '';
                messagesData = {};
                if(d.messages && d.messages.length) {
                    for(let msg of d.messages) {
                        try {
                            const dec = await decrypt(msg.ciphertext, window.groupPassword, msg.salt);
                            const isSent = msg.sender === window.username;
                            messagesData[msg.id] = msg;
                            addMessage(msg.sender, dec, isSent, msg.created_at, msg.id, msg.reply_to, msg.voice_url, msg.media_url, msg.media_type);
                        } catch(e) { console.error(e); }
                    }
                }
            } else if(d.type === 'users') {
                updateOnlineUsers(d.users);
            } else if(d.type === 'message') {
                try {
                    const dec = await decrypt(d.ciphertext, window.groupPassword, d.salt);
                    const isSent = d.sender === window.username;
                    messagesData[d.message_id] = d;
                    addMessage(d.sender, dec, isSent, d.timestamp, d.message_id, d.reply_to, d.voice_url, d.media_url, d.media_type);
                } catch(e) { console.error(e); }
            } else if(d.type === 'user_joined') {
                addSystemMessage('👤 ' + d.user + ' joined');
            } else if(d.type === 'user_left') {
                addSystemMessage('👋 ' + d.user + ' left');
            } else if(d.type === 'typing') {
                document.getElementById('typingIndicator').textContent = '✏️ ' + d.user + ' typing...';
            } else if(d.type === 'stop_typing') {
                document.getElementById('typingIndicator').textContent = '';
            } else if(d.type === 'message_edited') {
                try {
                    const dec = await decrypt(d.ciphertext, window.groupPassword, d.salt);
                    if(messagesData[d.message_id]) {
                        messagesData[d.message_id].ciphertext = d.ciphertext;
                        messagesData[d.message_id].edited = true;
                        updateMessageDisplay(d.message_id, dec);
                    }
                } catch(e) {}
            } else if(d.type === 'reaction_update') {
                if(messagesData[d.message_id]) {
                    messagesData[d.message_id].reactions = d.reactions;
                    updateReactions(d.message_id, d.reactions);
                }
            }
        } catch(e) { console.error('WS error:', e); }
    };
    ws.onclose = function() {
        updateStatus(false);
        document.getElementById('offlineBar').classList.add('active');
    };
}

function updateStatus(online) {
    const badge = document.getElementById('onlineBadge');
    if(online) {
        badge.textContent = '● Online';
        badge.style.color = '#0f0';
        document.getElementById('offlineBar').classList.remove('active');
    } else {
        badge.textContent = '● Offline';
        badge.style.color = '#ff4444';
        document.getElementById('offlineBar').classList.add('active');
    }
}

function updateOnlineUsers(users) {
    const container = document.getElementById('onlineUsers');
    if(!users || users.length === 0) {
        container.innerHTML = '<div style="color:#666;padding:8px;font-size:12px;">No one online</div>';
    } else {
        container.innerHTML = users.map(u => `<div class="online-user">${escapeHtml(u)}</div>`).join('');
    }
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('overlay').classList.toggle('active');
}

function reconnect() {
    if(ws) ws.close();
    setTimeout(() => connectToChat(window.username, window.groupName), 500);
}

// ========== MESSAGES UI ==========
function addMessage(sender, text, isSent, timestamp, id, replyTo, voiceUrl, mediaUrl, mediaType) {
    const container = document.getElementById('messages');
    const div = document.createElement('div');
    div.className = 'message ' + (isSent ? 'sent' : 'received');
    div.dataset.id = id;
    const time = timestamp ? new Date(timestamp * 1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : '';
    let content = '';
    if(voiceUrl) {
        content = `<div style="display:flex;align-items:center;gap:8px;">
            <button class="voice-play-btn" onclick="playVoice(this,'${voiceUrl}')">
                <span>▶️</span><span>Play</span>
            </button>
            <div class="voice-progress"><div class="voice-progress-bar"></div></div>
            <span class="voice-duration">00:00</span>
        </div>`;
        if(text && text !== '🎤 Voice message') {
            content += `<div style="font-size:11px;color:#888;margin-top:4px;">${escapeHtml(text)}</div>`;
        }
    } else if(mediaUrl) {
        if(mediaType && mediaType.startsWith('image/')) {
            content = `<div class="bubble">${escapeHtml(text)}<div><img src="${mediaUrl}" class="message-media" onclick="window.open('${mediaUrl}')" loading="lazy"></div></div>`;
        } else {
            content = `<div class="bubble">${escapeHtml(text)}<div><a href="${mediaUrl}" target="_blank" style="color:#0f0;text-decoration:underline;">📎 Download ${mediaUrl.split('/').pop()}</a></div></div>`;
        }
    } else {
        const edited = messagesData[id]?.edited ? ' <span style="font-size:8px;color:#888;">(edited)</span>' : '';
        content = `<div class="bubble">${escapeHtml(text)}${edited}</div>`;
    }
    
    // Fix: Show replied message preview
    let replyHtml = '';
    if(replyTo && messagesData[replyTo]) {
        const orig = messagesData[replyTo];
        try {
            let origText = '🔒 Encrypted';
            if(orig.ciphertext) {
                try {
                    origText = await decrypt(orig.ciphertext, window.groupPassword, orig.salt);
                } catch(e) {}
            }
            replyHtml = `<div style="font-size:10px;color:#ffaa00;margin-bottom:3px;cursor:pointer;padding:4px 8px;background:rgba(255,170,0,0.08);border-left:2px solid #ffaa00;border-radius:4px;" onclick="scrollToMsg(${replyTo})">
                ↩️ <span style="color:#ffaa00;font-weight:bold;">${escapeHtml(orig.sender)}</span>: ${escapeHtml(origText.substring(0,60))}${origText.length>60?'...':''}
            </div>`;
        } catch(e) {
            console.error('Reply preview error:', e);
        }
    }
    
    let reactionsHtml = '';
    const reactions = messagesData[id]?.reactions || {};
    if(Object.keys(reactions).length) {
        reactionsHtml = '<div class="reaction-container">';
        for(let [emoji, users] of Object.entries(reactions)) {
            reactionsHtml += `<span class="reaction-emoji" onclick="toggleReaction(${id},'${emoji}')">${emoji} ${users.length}</span>`;
        }
        reactionsHtml += '</div>';
    }
    let actionsHtml = `
        <div class="message-actions">
            <div style="position:relative">
                <button onclick="togglePicker(this)">😊</button>
                <div class="reaction-picker">
                    <span onclick="toggleReaction(${id},'👍')">👍</span>
                    <span onclick="toggleReaction(${id},'❤️')">❤️</span>
                    <span onclick="toggleReaction(${id},'😂')">😂</span>
                    <span onclick="toggleReaction(${id},'😮')">😮</span>
                    <span onclick="toggleReaction(${id},'😢')">😢</span>
                    <span onclick="toggleReaction(${id},'👏')">👏</span>
                    <span onclick="toggleReaction(${id},'🔥')">🔥</span>
                    <span onclick="toggleReaction(${id},'🎉')">🎉</span>
                </div>
            </div>
            <button onclick="replyToMsg(${id})">↩️ Reply</button>
            ${isSent ? `<button onclick="editMessage(${id})">✏️ Edit</button>` : ''}
        </div>
        ${isSent ? `<div class="edit-input" id="edit-${id}"><input type="text" value="${escapeHtml(text)}" style="width:100%;padding:4px;background:#111;border:1px solid #0f0;border-radius:4px;color:#0f0;font-size:12px;"><div style="display:flex;gap:4px;margin-top:4px;"><button onclick="saveEdit(${id})" style="background:#0f0;color:#000;border:none;padding:2px 10px;border-radius:4px;cursor:pointer;font-size:10px;">Save</button><button onclick="cancelEdit(${id})" style="background:#ff0041;color:white;border:none;padding:2px 10px;border-radius:4px;cursor:pointer;font-size:10px;">Cancel</button></div></div>` : ''}
    `;
    div.innerHTML = `<div class="msg-sender">${isSent ? 'YOU' : escapeHtml(sender)}</div>
        ${replyHtml}
        ${content}
        ${reactionsHtml}
        ${actionsHtml}
        <div class="msg-time">${time}</div>`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    
    // Swipe to reply (touch)
    let startX = 0, currentX = 0;
    div.addEventListener('touchstart', e => { startX = e.touches[0].clientX; currentX = startX; }, {passive:true});
    div.addEventListener('touchmove', e => {
        currentX = e.touches[0].clientX;
        const diff = currentX - startX;
        if(diff > 0 && diff < 60) div.style.transform = 'translateX('+diff+'px)';
    }, {passive:true});
    div.addEventListener('touchend', e => {
        const diff = currentX - startX;
        div.style.transform = '';
        if(diff >= 50) replyToMsg(id);
    }, {passive:true});
}

function updateMessageDisplay(id, newText) {
    const msgs = document.querySelectorAll('.message');
    for(let msg of msgs) {
        if(msg.dataset.id == id) {
            const bubble = msg.querySelector('.bubble');
            if(bubble) {
                bubble.innerHTML = escapeHtml(newText) + ' <span style="font-size:8px;color:#888;">(edited)</span>';
            }
            break;
        }
    }
}

function updateReactions(id, reactions) {
    const msgs = document.querySelectorAll('.message');
    for(let msg of msgs) {
        if(msg.dataset.id == id) {
            let container = msg.querySelector('.reaction-container');
            if(!container) {
                container = document.createElement('div');
                container.className = 'reaction-container';
                const actions = msg.querySelector('.message-actions');
                if(actions) actions.parentNode.insertBefore(container, actions);
            }
            container.innerHTML = '';
            if(reactions && Object.keys(reactions).length) {
                for(let [emoji, users] of Object.entries(reactions)) {
                    container.innerHTML += `<span class="reaction-emoji" onclick="toggleReaction(${id},'${emoji}')">${emoji} ${users.length}</span>`;
                }
            }
            break;
        }
    }
}

function addSystemMessage(text) {
    const container = document.getElementById('messages');
    const div = document.createElement('div');
    div.className = 'system-msg';
    div.textContent = text;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

function scrollToMsg(id) {
    const msgs = document.querySelectorAll('.message');
    for(let msg of msgs) {
        if(msg.dataset.id == id) {
            msg.scrollIntoView({behavior:'smooth', block:'center'});
            msg.style.border = '2px solid #ffaa00';
            setTimeout(() => msg.style.border = '', 2000);
            break;
        }
    }
}

function togglePicker(btn) {
    const picker = btn.parentElement.querySelector('.reaction-picker');
    picker.classList.toggle('active');
}

function replyToMsg(id) {
    replyingTo = id;
    msgInput.placeholder = '↩️ Replying to ' + (messagesData[id]?.sender || 'message');
    msgInput.focus();
}

// ========== SEND MESSAGE ==========
msgInput.addEventListener('keydown', function(e) {
    if(e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
    }
});
msgInput.addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 120) + 'px';
    if(ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({type:'typing'}));
        clearTimeout(window.typingTimeout);
        window.typingTimeout = setTimeout(() => {
            if(ws && ws.readyState === WebSocket.OPEN)
                ws.send(JSON.stringify({type:'stop_typing'}));
        }, 1000);
    }
});

async function sendMessage() {
    const text = msgInput.value.trim();
    if(!text || !ws || ws.readyState !== WebSocket.OPEN) return;
    if(!window.groupPassword) { alert('Group password not set'); return; }
    try {
        const salt = genSalt();
        const encrypted = await encrypt(text, window.groupPassword, salt);
        ws.send(JSON.stringify({
            type:'message',
            ciphertext:encrypted,
            salt:salt,
            reply_to:replyingTo || null
        }));
        msgInput.value = '';
        msgInput.style.height = 'auto';
        msgInput.placeholder = 'Type a message...';
        replyingTo = null;
    } catch(e) {
        console.error('Send error:', e);
        alert('Error sending message');
    }
}

// ========== ENCRYPTION ==========
function genSalt() {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    return btoa(String.fromCharCode.apply(null, arr));
}

async function encrypt(text, password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        {name:'PBKDF2', salt:enc.encode(salt), iterations:100000, hash:'SHA-256'},
        keyMaterial, {name:'AES-GCM', length:256}, true, ['encrypt','decrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({name:'AES-GCM', iv:iv}, key, enc.encode(text));
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
        {name:'PBKDF2', salt:enc.encode(salt), iterations:100000, hash:'SHA-256'},
        keyMaterial, {name:'AES-GCM', length:256}, true, ['encrypt','decrypt']
    );
    const data = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const iv = data.slice(0,12);
    const ciphertext = data.slice(12);
    const decrypted = await crypto.subtle.decrypt({name:'AES-GCM', iv:iv}, key, ciphertext);
    return dec.decode(decrypted);
}

// ========== VOICE RECORDING ==========
function startRecord() {
    if(isRecording) return;
    isHolding = true;
    holdTimer = setTimeout(() => {
        if(isHolding) startRecording();
    }, 300);
}

function stopRecord() {
    isHolding = false;
    clearTimeout(holdTimer);
    if(isRecording) {
        if(recSeconds < 1) cancelRecord();
        else stopRecordingAndSend();
    }
}

async function startRecording() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({audio:true});
        // Try to use webm with opus codec for better compatibility
        let mimeType = 'audio/webm;codecs=opus';
        if(!MediaRecorder.isTypeSupported(mimeType)) {
            mimeType = 'audio/webm';
        }
        if(!MediaRecorder.isTypeSupported(mimeType)) {
            mimeType = 'audio/mp4';
        }
        mediaRecorder = new MediaRecorder(stream, { 
            mimeType: mimeType,
            audioBitsPerSecond: 64000 
        });
        audioChunks = [];
        mediaRecorder.ondataavailable = e => { if(e.data.size > 0) audioChunks.push(e.data); };
        mediaRecorder.onstop = async () => {
            if(audioChunks.length > 0 && recSeconds >= 1) {
                const blob = new Blob(audioChunks, {type: mediaRecorder.mimeType || 'audio/webm'});
                await uploadVoice(blob);
            }
            stream.getTracks().forEach(t => t.stop());
            document.getElementById('voiceBtn').classList.remove('recording');
            document.getElementById('recStatus').classList.remove('active');
            clearInterval(recTimer);
            isRecording = false;
            recSeconds = 0;
        };
        mediaRecorder.start(1000);
        isRecording = true;
        document.getElementById('voiceBtn').classList.add('recording');
        document.getElementById('recStatus').classList.add('active');
        recSeconds = 0;
        document.getElementById('recTimer').textContent = '00:00';
        recTimer = setInterval(() => {
            recSeconds++;
            const mins = String(Math.floor(recSeconds/60)).padStart(2,'0');
            const secs = String(recSeconds%60).padStart(2,'0');
            document.getElementById('recTimer').textContent = mins + ':' + secs;
        }, 1000);
    } catch(e) {
        console.error('Microphone error:', e);
        alert('Please allow microphone access');
    }
}

function stopRecordingAndSend() {
    if(mediaRecorder && isRecording) mediaRecorder.stop();
}

function cancelRecord() {
    if(mediaRecorder && isRecording) {
        mediaRecorder.stop();
        isRecording = false;
        audioChunks = [];
        clearInterval(recTimer);
        recSeconds = 0;
        document.getElementById('recTimer').textContent = '00:00';
    }
    document.getElementById('voiceBtn').classList.remove('recording');
    document.getElementById('recStatus').classList.remove('active');
}

async function uploadVoice(blob) {
    const formData = new FormData();
    // Use webm extension for compatibility
    formData.append('file', blob, 'voice.webm');
    try {
        const res = await fetch('/api/upload_voice', {method:'POST', body:formData});
        const data = await res.json();
        if(data.success) {
            await sendVoiceMessage(data.url);
        }
    } catch(e) { console.error('Upload error:', e); }
}

async function sendVoiceMessage(url) {
    const text = msgInput.value.trim() || '🎤 Voice message';
    try {
        const salt = genSalt();
        const encrypted = await encrypt(text, window.groupPassword, salt);
        ws.send(JSON.stringify({
            type:'message',
            ciphertext:encrypted,
            salt:salt,
            reply_to:replyingTo || null,
            voice_url:url
        }));
        msgInput.value = '';
        msgInput.style.height = 'auto';
        msgInput.placeholder = 'Type a message...';
        replyingTo = null;
    } catch(e) { console.error('Send voice error:', e); }
}

function playVoice(btn, url) {
    const audio = new Audio(url);
    const progress = btn.parentElement.querySelector('.voice-progress-bar');
    const duration = btn.parentElement.querySelector('.voice-duration');
    if(btn.classList.contains('playing')) {
        audio.pause();
        audio.currentTime = 0;
        btn.classList.remove('playing');
        btn.innerHTML = '<span>▶️</span><span>Play</span>';
        progress.style.width = '0%';
        duration.textContent = '00:00';
        return;
    }
    audio.addEventListener('loadedmetadata', function() {
        const m = Math.floor(this.duration/60);
        const s = Math.floor(this.duration%60);
        duration.textContent = String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
    });
    audio.addEventListener('timeupdate', function() {
        const pct = (this.currentTime / this.duration) * 100;
        progress.style.width = pct + '%';
        const m = Math.floor(this.currentTime/60);
        const s = Math.floor(this.currentTime%60);
        duration.textContent = String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
    });
    audio.addEventListener('ended', function() {
        btn.classList.remove('playing');
        btn.innerHTML = '<span>▶️</span><span>Play</span>';
        progress.style.width = '0%';
        duration.textContent = '00:00';
    });
    audio.play();
    btn.classList.add('playing');
    btn.innerHTML = '<span>⏸️</span><span>Pause</span>';
}

// ========== MEDIA SHARING ==========
async function shareMedia() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*,application/pdf,text/plain';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if(!file) return;
        if(file.size > 10*1024*1024) { alert('Max 10MB'); return; }
        const formData = new FormData();
        formData.append('file', file);
        try {
            const res = await fetch('/api/upload_media', {method:'POST', body:formData});
            const data = await res.json();
            if(data.success) {
                const text = '📎 ' + file.name;
                const salt = genSalt();
                const encrypted = await encrypt(text, window.groupPassword, salt);
                ws.send(JSON.stringify({
                    type:'message',
                    ciphertext:encrypted,
                    salt:salt,
                    reply_to:replyingTo || null,
                    media_url:data.url,
                    media_type:data.type || file.type
                }));
                msgInput.value = '';
                msgInput.style.height = 'auto';
                replyingTo = null;
            }
        } catch(e) { console.error('Upload error:', e); }
    };
    input.click();
}

// ========== REACTIONS ==========
async function toggleReaction(id, emoji) {
    if(!ws || ws.readyState !== WebSocket.OPEN) return;
    try {
        const res = await fetch('/reaction', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({message_id:id, emoji:emoji})
        });
        const data = await res.json();
        if(data.success && messagesData[id]) {
            messagesData[id].reactions = data.reactions;
            updateReactions(id, data.reactions);
        }
    } catch(e) { console.error('Reaction error:', e); }
}

// ========== EDIT MESSAGE ==========
function editMessage(id) {
    const el = document.getElementById('edit-'+id);
    if(el) el.style.display = 'block';
}
function cancelEdit(id) {
    const el = document.getElementById('edit-'+id);
    if(el) el.style.display = 'none';
}
async function saveEdit(id) {
    const el = document.getElementById('edit-'+id);
    if(!el) return;
    const input = el.querySelector('input');
    const text = input.value.trim();
    if(!text) return;
    try {
        const res = await fetch('/edit_message', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({message_id:id, new_text:text})
        });
        const data = await res.json();
        if(data.success) el.style.display = 'none';
    } catch(e) { console.error('Edit error:', e); }
}

// ========== ADMIN ==========
async function loadAdmin() {
    try {
        const res = await fetch('/admin/data');
        const data = await res.json();
        document.getElementById('statUsers').textContent = data.users ? data.users.length : 0;
        document.getElementById('statGroups').textContent = data.groups ? data.groups.length : 0;
        document.getElementById('statMessages').textContent = data.messages ? data.messages.length : 0;
        const usersTbl = document.getElementById('usersTable');
        usersTbl.innerHTML = '';
        if(data.users) {
            data.users.forEach(u => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${escapeHtml(u.username)}</td><td>${escapeHtml(u.assigned_group||'None')}</td><td>${u.username!=='Mpc'?`<button class="action-btn" onclick="deleteUser('${u.username}')">Delete</button>`:'Admin'}</td>`;
                usersTbl.appendChild(tr);
            });
        }
        const groupsTbl = document.getElementById('groupsTable');
        groupsTbl.innerHTML = '';
        if(data.groups) {
            data.groups.forEach(g => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${escapeHtml(g.group_name)}</td><td>${new Date(g.created_at*1000).toLocaleDateString()}</td><td><button class="action-btn" onclick="deleteGroup('${g.group_name}')">Delete</button></td>`;
                groupsTbl.appendChild(tr);
            });
        }
        const msgsTbl = document.getElementById('messagesTable');
        msgsTbl.innerHTML = '';
        if(data.messages) {
            data.messages.forEach(m => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${escapeHtml(m.sender)}</td><td>${escapeHtml(m.group_name)}</td><td><button class="action-btn" onclick="deleteMessage(${m.id})">Delete</button></td>`;
                msgsTbl.appendChild(tr);
            });
        }
    } catch(e) { console.error('Admin load error:', e); }
}

async function createUser() {
    const username = document.getElementById('newUser').value.trim();
    const password = document.getElementById('newPass').value;
    const group = document.getElementById('newGroup').value.trim();
    const gpass = document.getElementById('newGroupPass').value;
    if(!username || !password || !group || !gpass) { alert('Fill all fields'); return; }
    try {
        const res = await fetch('/admin/create_user', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body:JSON.stringify({username, password, group_name:group, group_password:gpass})
        });
        const data = await res.json();
        if(data.success) {
            alert('✅ User created');
            document.getElementById('newUser').value = '';
            document.getElementById('newPass').value = '';
            document.getElementById('newGroup').value = '';
            document.getElementById('newGroupPass').value = '';
            loadAdmin();
        } else alert('❌ ' + (data.error || 'Failed'));
    } catch(e) { alert('Error creating user'); }
}

async function deleteUser(username) {
    if(!confirm('Delete "'+username+'"?')) return;
    try {
        const res = await fetch('/admin/delete_user', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username})});
        const data = await res.json();
        if(data.success) { alert('✅ Deleted'); loadAdmin(); }
    } catch(e) { alert('Error'); }
}
async function deleteGroup(name) {
    if(!confirm('Delete group "'+name+'"?')) return;
    try {
        const res = await fetch('/admin/delete_group', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name})});
        const data = await res.json();
        if(data.success) { alert('✅ Deleted'); loadAdmin(); }
    } catch(e) { alert('Error'); }
}
async function deleteMessage(id) {
    if(!confirm('Delete message?')) return;
    try {
        const res = await fetch('/admin/delete_message', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id})});
        const data = await res.json();
        if(data.success) { alert('✅ Deleted'); loadAdmin(); }
    } catch(e) { alert('Error'); }
}

// ========== LOGOUT ==========
async function logout() {
    try { await fetch('/logout', {method:'POST'}); } catch(e) {}
    if(ws) ws.close();
    document.getElementById('chatScreen').classList.remove('active');
    document.getElementById('adminPanel').classList.remove('active');
    document.getElementById('gatekeeperScreen').classList.remove('active');
    document.getElementById('setupScreen').classList.remove('active');
    document.getElementById('loginScreen').style.display = 'flex';
    sessionStorage.clear();
}

function requestAccess() {
    window.open('https://wa.me/250788495861?text=I%20need%20access%20to%20ABAVANDIMWE', '_blank');
}

console.log('✅ ABAVANDIMWE loaded');
</script>
</body>
</html>
'''

# ========== RUN ==========
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv('PORT', 8080))
    print("""
╔═══════════════════════════════════════════════╗
║     ABAVANDIMWE SECURE MESSAGING v6.0        ║
║     Everything in Neon PostgreSQL            ║
║     Author: Mugisha Pc                       ║
╚═══════════════════════════════════════════════╝
""")
    print(f"✅ Server running on port {port}")
    print(f"✅ Admin: Mpc / {os.getenv('ADMIN_PASSWORD', 'Mpc@Secure+_+')}")
    print(f"✅ Database: PostgreSQL (Neon)")
    print(f"✅ Messages: 24h auto-delete")
    print(f"✅ Files: 7d auto-delete")
    print(f"✅ Online users: enabled")
    uvicorn.run(app, host="0.0.0.0", port=port)
