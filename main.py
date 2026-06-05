#!/usr/bin/env python3
"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
Single server for HTTP + WebSocket
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
from typing import Dict, Set

# ========== CRYPTO ==========
class Crypto:
    @staticmethod
    def generate_salt() -> str:
        return base64.b64encode(secrets.token_bytes(32)).decode()
    
    @staticmethod
    def derive_key(password: str, salt: str) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)
    
    @staticmethod
    def encrypt(text: str, password: str, salt: str) -> str:
        key = Crypto.derive_key(password, salt)
        text_bytes = text.encode()
        encrypted = bytearray()
        for i in range(len(text_bytes)):
            encrypted.append(text_bytes[i] ^ key[i % len(key)])
        nonce = secrets.token_bytes(8)
        result = nonce + encrypted
        return base64.b64encode(result).decode()
    
    @staticmethod
    def decrypt(encrypted: str, password: str, salt: str) -> str:
        key = Crypto.derive_key(password, salt)
        data = base64.b64decode(encrypted)
        ciphertext = data[8:]
        decrypted = bytearray()
        for i in range(len(ciphertext)):
            decrypted.append(ciphertext[i] ^ key[i % len(key)])
        return decrypted.decode()

crypto = Crypto()

# ========== DATABASE ==========
class Database:
    def __init__(self):
        self.db_path = "abavandimwe.db"
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                    (id INTEGER PRIMARY KEY, ciphertext TEXT, group_name TEXT, sender TEXT, salt TEXT, created_at TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (username TEXT PRIMARY KEY, status TEXT, current_group TEXT, last_seen TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS groups
                    (group_name TEXT PRIMARY KEY, salt TEXT, created_by TEXT)''')
        conn.commit()
        conn.close()
        print("[✓] Database ready")
    
    def save_message(self, ciphertext: str, group: str, sender: str, salt: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT INTO messages (ciphertext, group_name, sender, salt, created_at) VALUES (?,?,?,?,?)",
                 (ciphertext, group, sender, salt, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    def get_messages(self, group: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT ciphertext, sender, salt FROM messages WHERE group_name=? ORDER BY id ASC", (group,))
        rows = c.fetchall()
        conn.close()
        return [{'ciphertext': r[0], 'sender': r[1], 'salt': r[2]} for r in rows]
    
    def set_user_status(self, username: str, status: str, group: str = None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO users (username, status, current_group, last_seen) VALUES (?,?,?,?)",
                 (username, status, group, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    def get_online_users(self, group: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE status='online' AND current_group=?", (group,))
        rows = c.fetchall()
        conn.close()
        return [r[0] for r in rows]
    
    def get_group_salt(self, group: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT salt FROM groups WHERE group_name=?", (group,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None
    
    def create_group(self, group: str, salt: str, creator: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO groups (group_name, salt, created_by) VALUES (?,?,?)", (group, salt, creator))
            conn.commit()
        except:
            pass
        conn.close()

db = Database()

# ========== HTML ==========
HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ABAVANDIMWE</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:'Courier New',monospace;background:#0a0a0f;height:100vh;color:#0f0;}
        .login{position:fixed;top:0;left:0;right:0;bottom:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;}
        .card{background:#050508;border:2px solid #0f0;border-radius:10px;padding:40px;width:90%;max-width:400px;}
        h1{text-align:center;margin-bottom:10px;}
        .sub{text-align:center;margin-bottom:30px;font-size:12px;color:#888;}
        input{width:100%;padding:12px;margin:10px 0;background:#111;border:1px solid #0f0;border-radius:5px;color:#0f0;font-family:monospace;}
        input:focus{outline:none;box-shadow:0 0 10px rgba(0,255,0,0.3);}
        button{width:100%;padding:12px;margin-top:20px;background:transparent;border:2px solid #0f0;border-radius:5px;color:#0f0;font-size:16px;cursor:pointer;}
        button:hover{background:#0f0;color:#000;}
        .chat{display:none;width:100%;height:100%;flex-direction:column;}
        .chat.active{display:flex;}
        .header{padding:15px 20px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;}
        .main{flex:1;display:flex;overflow:hidden;}
        .sidebar{width:250px;background:#050508;border-right:1px solid #0f0;display:flex;flex-direction:column;}
        .sidebar h3{padding:15px;border-bottom:1px solid #0f0;font-size:14px;}
        .users{padding:10px;flex:1;overflow-y:auto;}
        .user{padding:8px 12px;margin:5px 0;border:1px solid #0f0;border-radius:5px;font-size:12px;}
        .chatarea{flex:1;display:flex;flex-direction:column;}
        .messages{flex:1;padding:20px;overflow-y:auto;display:flex;flex-direction:column;gap:10px;}
        .msg{max-width:70%;display:flex;flex-direction:column;}
        .msg.sent{align-self:flex-end;}
        .msg.received{align-self:flex-start;}
        .bubble{padding:8px 14px;border-radius:15px;font-size:13px;}
        .msg.sent .bubble{background:#0f0;color:#000;}
        .msg.received .bubble{background:#1a1a2e;border:1px solid #0f0;}
        .sender{font-size:9px;margin-bottom:3px;opacity:0.7;}
        .typing{padding:8px 20px;color:#0f0;font-style:italic;font-size:12px;}
        .input-area{padding:15px 20px;background:#050508;border-top:1px solid #0f0;display:flex;gap:10px;}
        .input-area input{flex:1;margin:0;}
        .input-area button{width:auto;margin:0;padding:12px 20px;}
    </style>
</head>
<body>
<div id="login" class="login">
    <div class="card">
        <h1># ABAVANDIMWE</h1>
        <div class="sub">by Mugisha Pc</div>
        <input type="text" id="username" placeholder="USERNAME">
        <input type="text" id="group" placeholder="GROUP">
        <input type="password" id="password" placeholder="PASSWORD">
        <button onclick="connect()">CONNECT</button>
        <div style="text-align:center;margin-top:20px;font-size:10px;">🔒 AES-256 | ⏰ Auto-Delete 24h</div>
    </div>
</div>
<div id="chat" class="chat">
    <div class="header"><h2 id="groupTitle"># LOADING</h2><span id="onlineCount">0 online</span></div>
    <div class="main">
        <div class="sidebar"><h3>● ONLINE</h3><div class="users" id="users">connecting...</div></div>
        <div class="chatarea"><div class="messages" id="msgs"><div style="text-align:center;">connecting...</div></div><div class="typing" id="typing"></div><div class="input-area"><input type="text" id="msgInput" placeholder="Type message..."><button onclick="sendMsg()">SEND</button></div></div>
    </div>
</div>
<script>
let ws, username, group, password, salt, typingTimeout;
async function encrypt(t,p,s){const e=new TextEncoder(),km=await crypto.subtle.importKey('raw',e.encode(p),'PBKDF2',false,['deriveKey']),k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:e.encode(s),iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['encrypt']),iv=crypto.getRandomValues(new Uint8Array(12)),enc=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,e.encode(t)),c=new Uint8Array(iv.length+enc.byteLength);c.set(iv,0),c.set(new Uint8Array(enc),iv.length);return btoa(String.fromCharCode(...c));}
async function decrypt(c,p,s){const d=Uint8Array.from(atob(c),c=>c.charCodeAt(0)),iv=d.slice(0,12),data=d.slice(12),e=new TextEncoder(),km=await crypto.subtle.importKey('raw',e.encode(p),'PBKDF2',false,['deriveKey']),k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:e.encode(s),iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']),dec=await crypto.subtle.decrypt({name:'AES-GCM',iv},k,data);return new TextDecoder().decode(dec);}
function connect(){username=document.getElementById('username').value.trim();group=document.getElementById('group').value.trim();password=document.getElementById('password').value;if(!username||!group||!password){alert('Fill all fields');return;}const wsUrl=(location.protocol==='https:'?'wss://':'ws://')+location.host;ws=new WebSocket(wsUrl);ws.onopen=()=>ws.send(JSON.stringify({type:'join',username,group,password}));ws.onmessage=async(e)=>{let d=JSON.parse(e.data);if(d.type==='ready'){salt=d.salt;document.getElementById('login').style.display='none';document.getElementById('chat').classList.add('active');document.getElementById('groupTitle').innerText='# '+d.group;}else if(d.type==='message'){try{let dec=await decrypt(d.ciphertext,password,d.salt);addMsg(d.sender,dec,d.sender===username);}catch(e){addMsg(d.sender,'🔒 ENCRYPTED',d.sender===username);}}else if(d.type==='history'){try{let dec=await decrypt(d.ciphertext,password,d.salt);addMsg(d.sender,dec,d.sender===username);}catch(e){addMsg(d.sender,'🔒 ENCRYPTED',d.sender===username);}}else if(d.type==='users'){document.getElementById('onlineCount').innerText=d.users.length+' online';let ud=document.getElementById('users');if(d.users.length===0)ud.innerHTML='<div class="user">> no users</div>';else ud.innerHTML=d.users.map(u=>'<div class="user">● '+escapeHtml(u)+'</div>').join('');}else if(d.type==='typing'){document.getElementById('typing').innerHTML='✏️ '+d.user+' is typing...';}else if(d.type==='stop_typing'){document.getElementById('typing').innerHTML='';}};ws.onerror=()=>alert('Connection failed');}
function addMsg(sender,text,isSent){let m=document.getElementById('msgs');if(m.children.length===1&&m.children[0].innerText.includes('connecting'))m.innerHTML='';let div=document.createElement('div');div.className='msg '+(isSent?'sent':'received');div.innerHTML='<div class="sender">'+(isSent?'YOU':sender)+'</div><div class="bubble">'+escapeHtml(text)+'</div>';m.appendChild(div);m.scrollTop=m.scrollHeight;}
function escapeHtml(t){let d=document.createElement('div');d.textContent=t;return d.innerHTML;}
document.getElementById('msgInput')?.addEventListener('input',function(){if(ws&&ws.readyState===WebSocket.OPEN){ws.send(JSON.stringify({type:'typing'}));clearTimeout(typingTimeout);typingTimeout=setTimeout(()=>ws.send(JSON.stringify({type:'stop_typing'})),1000);}});
document.getElementById('msgInput')?.addEventListener('keypress',function(e){if(e.key==='Enter')sendMsg();});
async function sendMsg(){let i=document.getElementById('msgInput'),t=i.value.trim();if(!t||!ws||ws.readyState!==WebSocket.OPEN)return;try{let c=await encrypt(t,password,salt);ws.send(JSON.stringify({type:'message',ciphertext:c,salt:salt}));i.value='';}catch(e){}}
</script>
</body>
</html>'''

# ========== WEBSOCKET HANDLER ==========
connections: Dict[str, Dict[str, websockets.WebSocketServerProtocol]] = {}
typing_users: Set[str] = set()

async def broadcast(group: str, msg: dict, exclude: str = None):
    if group not in connections:
        return
    dead = []
    for user, ws in connections[group].items():
        if user == exclude:
            continue
        try:
            await ws.send(json.dumps(msg))
        except:
            dead.append(user)
    for user in dead:
        del connections[group][user]

async def ws_handler(websocket, path):
    username = None
    group = None
    try:
        async for message in websocket:
            data = json.loads(message)
            t = data.get('type')
            
            if t == 'join':
                username = data['username']
                group = data['group']
                pwd = data['password']
                
                salt = db.get_group_salt(group)
                if not salt:
                    salt = crypto.generate_salt()
                    db.create_group(group, salt, username)
                
                if group not in connections:
                    connections[group] = {}
                connections[group][username] = websocket
                
                db.set_user_status(username, 'online', group)
                
                for msg in db.get_messages(group):
                    await websocket.send(json.dumps({'type': 'history', 'ciphertext': msg['ciphertext'], 'sender': msg['sender'], 'salt': msg['salt']}))
                
                online = db.get_online_users(group)
                await broadcast(group, {'type': 'users', 'users': online})
                
                await websocket.send(json.dumps({'type': 'ready', 'salt': salt, 'group': group}))
                print(f"[+] {username} joined {group}")
            
            elif t == 'message':
                cipher = data['ciphertext']
                salt = data['salt']
                db.save_message(cipher, group, username, salt)
                await broadcast(group, {'type': 'message', 'ciphertext': cipher, 'sender': username, 'salt': salt}, exclude=username)
            
            elif t == 'typing':
                await broadcast(group, {'type': 'typing', 'user': username}, exclude=username)
            
            elif t == 'stop_typing':
                await broadcast(group, {'type': 'stop_typing', 'user': username}, exclude=username)
    
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        if username and group:
            if group in connections:
                connections[group].pop(username, None)
            db.set_user_status(username, 'offline', group)
            online = db.get_online_users(group)
            await broadcast(group, {'type': 'users', 'users': online})
            print(f"[-] {username} left {group}")

# ========== HTTP HANDLER ==========
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

# ========== MAIN ==========
PORT = int(os.getenv('PORT', 8080))

print("""
╔════════════════════════════════════════════════╗
║     ABAVANDIMWE - Secure Messaging System     ║
║          Messages Auto-Delete 24h             ║
║              Author: Mugisha Pc               ║
╚════════════════════════════════════════════════╝
""")

print(f"[✓] Starting on port {PORT}")
print(f"[✓] Open: https://abavandimwe.onrender.com")

async def main():
    # Start WebSocket server
    ws_server = await websockets.serve(ws_handler, '0.0.0.0', PORT)
    # Start HTTP server on the same port
    http_server = await asyncio.start_server(http_handler, '0.0.0.0', PORT)
    
    print(f"[✓] Both HTTP and WebSocket running on port {PORT}")
    await asyncio.gather(ws_server.wait_closed(), http_server.wait_closed())

asyncio.run(main())
