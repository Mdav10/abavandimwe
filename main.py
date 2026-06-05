#!/usr/bin/env python3
"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
"""

import asyncio
import json
import websockets
import sqlite3
import secrets
import base64
import hashlib
import os
from datetime import datetime
from typing import Dict, Set, List, Optional

# ============================================
# CRYPTO
# ============================================

class Crypto:
    @staticmethod
    def generate_salt() -> str:
        return base64.b64encode(secrets.token_bytes(32)).decode()
    
    @staticmethod
    def _derive_key(password: str, salt: str) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)
    
    @staticmethod
    def encrypt(plaintext: str, password: str, salt: str) -> str:
        key = Crypto._derive_key(password, salt)
        plaintext_bytes = plaintext.encode()
        ciphertext = bytearray()
        for i in range(len(plaintext_bytes)):
            ciphertext.append(plaintext_bytes[i] ^ key[i % len(key)])
        nonce = secrets.token_bytes(8)
        result = nonce + ciphertext
        return base64.b64encode(result).decode()
    
    @staticmethod
    def decrypt(encrypted: str, password: str, salt: str) -> str:
        key = Crypto._derive_key(password, salt)
        data = base64.b64decode(encrypted)
        ciphertext = data[8:]
        plaintext_bytes = bytearray()
        for i in range(len(ciphertext)):
            plaintext_bytes.append(ciphertext[i] ^ key[i % len(key)])
        return plaintext_bytes.decode()

crypto = Crypto()

# ============================================
# DATABASE
# ============================================

class Database:
    def __init__(self):
        self.db_path = "abavandimwe.db"
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Messages table
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ciphertext TEXT,
                group_name TEXT,
                sender TEXT,
                salt TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT (datetime('now', '+24 hours'))
            )
        ''')
        
        # Users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                status TEXT,
                current_group TEXT,
                last_seen TIMESTAMP
            )
        ''')
        
        # Groups table
        c.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                group_name TEXT PRIMARY KEY,
                salt TEXT,
                created_by TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print("[INFO] Database ready")
    
    async def save_message(self, ciphertext: str, group: str, sender: str, salt: str):
        def _save():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('INSERT INTO messages (ciphertext, group_name, sender, salt) VALUES (?, ?, ?, ?)',
                     (ciphertext, group, sender, salt))
            conn.commit()
            conn.close()
        await asyncio.to_thread(_save)
    
    async def get_messages(self, group: str):
        def _get():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('SELECT ciphertext, sender, salt FROM messages WHERE group_name = ? AND created_at > datetime("now", "-24 hours") ORDER BY id ASC', (group,))
            rows = c.fetchall()
            conn.close()
            return [{'ciphertext': r[0], 'sender': r[1], 'salt': r[2]} for r in rows]
        return await asyncio.to_thread(_get)
    
    async def set_user_status(self, username: str, status: str, group: str = None):
        def _set():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('INSERT OR REPLACE INTO users (username, status, current_group, last_seen) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
                     (username, status, group))
            conn.commit()
            conn.close()
        await asyncio.to_thread(_set)
    
    async def get_online_users(self, group: str):
        def _get():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('SELECT username FROM users WHERE status = "online" AND current_group = ? AND last_seen > datetime("now", "-2 minutes")', (group,))
            rows = c.fetchall()
            conn.close()
            return [r[0] for r in rows]
        return await asyncio.to_thread(_get)
    
    async def get_group_salt(self, group: str):
        def _get():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('SELECT salt FROM groups WHERE group_name = ?', (group,))
            row = c.fetchone()
            conn.close()
            return row[0] if row else None
        return await asyncio.to_thread(_get)
    
    async def create_group(self, group: str, salt: str, creator: str):
        def _create():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            try:
                c.execute('INSERT INTO groups (group_name, salt, created_by) VALUES (?, ?, ?)', (group, salt, creator))
                conn.commit()
            except:
                pass
            conn.close()
        await asyncio.to_thread(_create)
    
    async def cleanup_expired(self):
        def _clean():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('DELETE FROM messages WHERE expires_at < CURRENT_TIMESTAMP')
            conn.commit()
            conn.close()
        await asyncio.to_thread(_clean)
    
    async def start_cleaner(self):
        while True:
            await asyncio.sleep(3600)
            await self.cleanup_expired()

db = Database()

# ============================================
# HTML
# ============================================

HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ABAVANDIMWE</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:monospace;background:#0a0a0f;height:100vh;color:#0f0;}
        .login{position:fixed;top:0;left:0;right:0;bottom:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;}
        .card{background:#050508;border:2px solid #0f0;border-radius:8px;padding:40px;width:90%;max-width:400px;}
        h1{text-align:center;margin-bottom:20px;}
        input{width:100%;padding:12px;margin:10px 0;background:#111;border:1px solid #0f0;border-radius:4px;color:#0f0;font-family:monospace;}
        button{width:100%;padding:12px;background:transparent;border:2px solid #0f0;color:#0f0;cursor:pointer;font-size:16px;}
        button:hover{background:#0f0;color:#000;}
        .chat{display:none;width:100%;height:100%;flex-direction:column;}
        .chat.active{display:flex;}
        .header{padding:16px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;}
        .main{flex:1;display:flex;overflow:hidden;}
        .sidebar{width:250px;background:#050508;border-right:1px solid #0f0;}
        .sidebar h3{padding:16px;border-bottom:1px solid #0f0;}
        .users{padding:12px;}
        .user{padding:8px;margin:5px 0;border:1px solid #0f0;border-radius:4px;}
        .chatarea{flex:1;display:flex;flex-direction:column;}
        .msgs{flex:1;padding:16px;overflow-y:auto;}
        .msg{margin:10px 0;max-width:70%;}
        .msg.sent{margin-left:auto;text-align:right;}
        .msg-bubble{background:#1a1a2e;border:1px solid #0f0;padding:8px 12px;border-radius:8px;display:inline-block;}
        .msg.sent .msg-bubble{background:#0f0;color:#000;}
        .sender{font-size:10px;margin-bottom:4px;}
        .typing{padding:8px 16px;color:#0f0;font-style:italic;}
        .input{padding:16px;background:#050508;border-top:1px solid #0f0;display:flex;gap:10px;}
        .input input{flex:1;}
        .online-count{font-size:12px;}
    </style>
</head>
<body>
<div id="login" class="login">
    <div class="card">
        <h1># ABAVANDIMWE</h1>
        <p style="text-align:center;margin-bottom:20px;">by Mugisha Pc</p>
        <input type="text" id="username" placeholder="Username">
        <input type="text" id="group" placeholder="Group">
        <input type="password" id="password" placeholder="Password">
        <button onclick="connect()">CONNECT</button>
        <p style="text-align:center;margin-top:20px;font-size:11px;">🔒 Messages auto-delete after 24h</p>
    </div>
</div>
<div id="chat" class="chat">
    <div class="header">
        <span id="groupName"># LOADING</span>
        <span class="online-count" id="onlineCount">0 online</span>
    </div>
    <div class="main">
        <div class="sidebar">
            <h3>ONLINE</h3>
            <div class="users" id="users">connecting...</div>
        </div>
        <div class="chatarea">
            <div class="msgs" id="msgs"><div style="text-align:center;">connecting...</div></div>
            <div class="typing" id="typing"></div>
            <div class="input">
                <input type="text" id="msgInput" placeholder="Type message...">
                <button onclick="sendMsg()">SEND</button>
            </div>
        </div>
    </div>
</div>
<script>
let ws, username, group, password, salt;
let typingTimeout;

async function encrypt(text, pwd, s) {
    const enc = new TextEncoder();
    const keyMat = await crypto.subtle.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:enc.encode(s), iterations:100000, hash:'SHA-256'}, keyMat, {name:'AES-GCM', length:256}, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encData = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(text));
    const combined = new Uint8Array(iv.length + encData.byteLength);
    combined.set(iv,0);
    combined.set(new Uint8Array(encData), iv.length);
    return btoa(String.fromCharCode(...combined));
}

async function decrypt(encrypted, pwd, s) {
    const combined = Uint8Array.from(atob(encrypted), c=>c.charCodeAt(0));
    const iv = combined.slice(0,12);
    const data = combined.slice(12);
    const enc = new TextEncoder();
    const keyMat = await crypto.subtle.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:enc.encode(s), iterations:100000, hash:'SHA-256'}, keyMat, {name:'AES-GCM', length:256}, false, ['decrypt']);
    const dec = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, data);
    return new TextDecoder().decode(dec);
}

function connect() {
    username = document.getElementById('username').value.trim();
    group = document.getElementById('group').value.trim();
    password = document.getElementById('password').value;
    if(!username||!group||!password){alert('Fill all fields');return;}
    
    let wsUrl = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => ws.send(JSON.stringify({type:'join', username, group, password}));
    ws.onmessage = async (e) => {
        let data = JSON.parse(e.data);
        if(data.type==='ready'){
            salt = data.salt;
            document.getElementById('login').style.display='none';
            document.getElementById('chat').classList.add('active');
            document.getElementById('groupName').innerText = '# '+data.group;
        }else if(data.type==='message'){
            try{
                let dec = await decrypt(data.ciphertext, password, data.salt);
                addMsg(data.sender, dec, data.sender===username);
            }catch(e){addMsg(data.sender, '🔒 ENCRYPTED', data.sender===username);}
        }else if(data.type==='history'){
            try{
                let dec = await decrypt(data.ciphertext, password, data.salt);
                addMsg(data.sender, dec, data.sender===username);
            }catch(e){addMsg(data.sender, '🔒 ENCRYPTED', data.sender===username);}
        }else if(data.type==='users'){
            document.getElementById('onlineCount').innerText = data.users.length+' online';
            let usersDiv = document.getElementById('users');
            if(data.users.length===0) usersDiv.innerHTML = '<div class="user">> no users</div>';
            else usersDiv.innerHTML = data.users.map(u => '<div class="user">🟢 '+escapeHtml(u)+'</div>').join('');
        }else if(data.type==='typing'){
            document.getElementById('typing').innerHTML = '✏️ '+data.user+' is typing...';
        }else if(data.type==='stop_typing'){
            document.getElementById('typing').innerHTML = '';
        }
    };
    ws.onerror = () => alert('Connection failed');
}

function addMsg(sender, text, isSent){
    let msgsDiv = document.getElementById('msgs');
    if(msgsDiv.children.length===1 && msgsDiv.children[0].innerText.includes('connecting')) msgsDiv.innerHTML='';
    let div = document.createElement('div');
    div.className = 'msg '+(isSent?'sent':'received');
    div.innerHTML = '<div class="sender">'+(isSent?'YOU':sender)+'</div><div class="msg-bubble">'+escapeHtml(text)+'</div>';
    msgsDiv.appendChild(div);
    msgsDiv.scrollTop = msgsDiv.scrollHeight;
}

function escapeHtml(t){let d=document.createElement('div');d.textContent=t;return d.innerHTML;}

document.getElementById('msgInput')?.addEventListener('input',function(){
    if(ws && ws.readyState===WebSocket.OPEN){
        ws.send(JSON.stringify({type:'typing'}));
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(()=>ws.send(JSON.stringify({type:'stop_typing'})),1000);
    }
});
document.getElementById('msgInput')?.addEventListener('keypress',function(e){if(e.key==='Enter')sendMsg();});

async function sendMsg(){
    let input = document.getElementById('msgInput');
    let text = input.value.trim();
    if(!text||!ws||ws.readyState!==WebSocket.OPEN) return;
    try{
        let cipher = await encrypt(text, password, salt);
        ws.send(JSON.stringify({type:'message', ciphertext:cipher, salt:salt}));
        input.value='';
    }catch(e){}
}
</script>
</body>
</html>'''

# ============================================
# WEBSOCKET SERVER
# ============================================

class ChatServer:
    def __init__(self):
        self.conns: Dict[str, Dict[str, websockets.WebSocketServerProtocol]] = {}
        self.typing: Set[str] = set()
    
    async def broadcast(self, group: str, msg: dict, exclude=None):
        if group not in self.conns:
            return
        dead = []
        for user, ws in self.conns[group].items():
            if user == exclude:
                continue
            try:
                await ws.send(json.dumps(msg))
            except:
                dead.append(user)
        for user in dead:
            del self.conns[group][user]
    
    async def handle(self, ws, path):
        user = None
        group = None
        try:
            async for msg in ws:
                data = json.loads(msg)
                t = data.get('type')
                
                if t == 'join':
                    user = data['username']
                    group = data['group']
                    pwd = data['password']
                    
                    salt = await db.get_group_salt(group)
                    if not salt:
                        salt = crypto.generate_salt()
                        await db.create_group(group, salt, user)
                    
                    if group not in self.conns:
                        self.conns[group] = {}
                    self.conns[group][user] = ws
                    
                    await db.set_user_status(user, 'online', group)
                    
                    for m in await db.get_messages(group):
                        await ws.send(json.dumps({'type':'history','ciphertext':m['ciphertext'],'sender':m['sender'],'salt':m['salt']}))
                    
                    online = await db.get_online_users(group)
                    await self.broadcast(group, {'type':'users','users':online})
                    
                    await ws.send(json.dumps({'type':'ready','salt':salt,'group':group}))
                    print(f"[+] {user} joined {group}")
                
                elif t == 'message':
                    cipher = data['ciphertext']
                    salt = data['salt']
                    await db.save_message(cipher, group, user, salt)
                    await self.broadcast(group, {'type':'message','ciphertext':cipher,'sender':user,'salt':salt}, exclude=user)
                
                elif t == 'typing':
                    self.typing.add(user)
                    await self.broadcast(group, {'type':'typing','user':user}, exclude=user)
                
                elif t == 'stop_typing':
                    self.typing.discard(user)
                    await self.broadcast(group, {'type':'stop_typing','user':user}, exclude=user)
        
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            if user and group:
                if group in self.conns:
                    self.conns[group].pop(user, None)
                await db.set_user_status(user, 'offline', group)
                online = await db.get_online_users(group)
                await self.broadcast(group, {'type':'users','users':online})
                print(f"[-] {user} left {group}")

# ============================================
# HTTP HANDLER
# ============================================

async def http_handler(reader, writer):
    try:
        data = await reader.read(1024)
        if data:
            req = data.decode().split(' ')[0] if data else ''
            if req == 'GET':
                response = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(HTML)}\r\nConnection: close\r\n\r\n{HTML}'
                writer.write(response.encode())
                await writer.drain()
        writer.close()
        await writer.wait_closed()
    except:
        pass

# ============================================
# MAIN
# ============================================

PORT = int(os.getenv('PORT', 8080))

print("""
╔══════════════════════════════════════════╗
║        ABAVANDIMWE v12.0                 ║
║     Secure Messaging System              ║
║     Messages Auto-Delete After 24h       ║
║     Author: Mugisha Pc                   ║
╚══════════════════════════════════════════╝
""")

print(f"[INFO] Starting on port {PORT}")

async def main():
    await db.connect()
    asyncio.create_task(db.start_cleaner())
    
    server = ChatServer()
    ws_server = await websockets.serve(server.handle, '0.0.0.0', PORT)
    http_server = await asyncio.start_server(http_handler, '0.0.0.0', PORT)
    
    print(f"[INFO] Server running on port {PORT}")
    print(f"[INFO] Open https://abavandimwe.onrender.com")
    
    await asyncio.gather(ws_server.wait_closed(), http_server.wait_closed())

asyncio.run(main())
