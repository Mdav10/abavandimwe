"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
Mobile Optimized CSS
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import asyncio
import json
import sqlite3
import secrets
import base64
import hashlib
import os
import threading
import time
from datetime import datetime
from typing import Dict

app = FastAPI()

# ========== DATABASE ==========
DB_PATH = "abavandimwe.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ciphertext TEXT,
            group_name TEXT,
            sender TEXT,
            salt TEXT,
            created_at REAL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            status TEXT,
            current_group TEXT,
            last_seen REAL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            group_name TEXT PRIMARY KEY,
            salt TEXT,
            password_hash TEXT,
            created_by TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("[✓] Database ready")

def cleanup_old_messages():
    now = time.time()
    cutoff = now - (24 * 3600)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM messages WHERE created_at < ?", (cutoff,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if deleted > 0:
        print(f"[🧹] Deleted {deleted} old messages")

def start_cleanup():
    def cleanup_loop():
        while True:
            time.sleep(3600)
            cleanup_old_messages()
    threading.Thread(target=cleanup_loop, daemon=True).start()

init_db()
start_cleanup()

# ========== CRYPTO ==========
def generate_salt():
    return base64.b64encode(secrets.token_bytes(32)).decode()

def derive_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)

def hash_password(password, salt):
    return base64.b64encode(derive_key(password, salt)).decode()

def verify_password(password, salt, stored_hash):
    return hash_password(password, salt) == stored_hash

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

# ========== DATABASE FUNCTIONS ==========
def save_message(ciphertext, group, sender, salt):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO messages (ciphertext, group_name, sender, salt, created_at) VALUES (?,?,?,?,?)",
             (ciphertext, group, sender, salt, time.time()))
    conn.commit()
    conn.close()

def get_messages(group):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    cutoff = time.time() - (24 * 3600)
    c.execute("SELECT ciphertext, sender, salt FROM messages WHERE group_name=? AND created_at > ? ORDER BY id ASC", 
             (group, cutoff))
    rows = c.fetchall()
    conn.close()
    return [{'ciphertext': r[0], 'sender': r[1], 'salt': r[2]} for r in rows]

def set_user_status(username, status, group):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO users (username, status, current_group, last_seen) VALUES (?,?,?,?)",
             (username, status, group, time.time()))
    conn.commit()
    conn.close()

def get_online_users(group):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    cutoff = time.time() - 120
    c.execute("SELECT username FROM users WHERE status='online' AND current_group=? AND last_seen > ?", 
             (group, cutoff))
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows]

def get_group_info(group):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT salt, password_hash FROM groups WHERE group_name=?", (group,))
    row = c.fetchone()
    conn.close()
    return {'salt': row[0], 'password_hash': row[1]} if row else None

def create_group(group, salt, password_hash, creator):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO groups (group_name, salt, password_hash, created_by) VALUES (?,?,?,?)",
                 (group, salt, password_hash, creator))
        conn.commit()
        conn.close()
        return True
    except:
        conn.close()
        return False

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

# ========== HTML - MOBILE OPTIMIZED ==========
HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes, viewport-fit=cover">
    <meta name="theme-color" content="#0a0a0f">
    <title>ABAVANDIMWE</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', monospace;
            background: #0a0a0f;
            height: 100vh;
            overflow: hidden;
            color: #00ff41;
        }

        /* Login Screen */
        .login-screen {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            background: #0a0a0f;
            z-index: 1000;
            padding: 20px;
        }

        .login-card {
            background: #050508;
            border: 2px solid #00ff41;
            border-radius: 24px;
            padding: 32px 24px;
            width: 100%;
            max-width: 400px;
        }

        h1 {
            text-align: center;
            font-size: 28px;
            margin-bottom: 8px;
            letter-spacing: 2px;
        }

        .sub {
            text-align: center;
            font-size: 11px;
            color: #666;
            margin-bottom: 32px;
        }

        input {
            width: 100%;
            padding: 14px 16px;
            margin: 10px 0;
            background: #111;
            border: 1px solid #00ff41;
            border-radius: 12px;
            color: #00ff41;
            font-family: monospace;
            font-size: 15px;
        }

        input:focus {
            outline: none;
            box-shadow: 0 0 10px rgba(0,255,65,0.3);
        }

        button {
            width: 100%;
            padding: 14px;
            margin-top: 20px;
            background: transparent;
            border: 2px solid #00ff41;
            border-radius: 12px;
            color: #00ff41;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.2s;
        }

        button:active {
            background: #00ff41;
            color: #000;
            transform: scale(0.98);
        }

        .error {
            color: #ff4444;
            font-size: 12px;
            text-align: center;
            margin-top: 12px;
            display: none;
        }

        /* Chat Screen */
        .chat-screen {
            display: none;
            width: 100%;
            height: 100%;
            flex-direction: column;
            background: #0a0a0f;
        }

        .chat-screen.active {
            display: flex;
        }

        /* Header */
        .chat-header {
            padding: 12px 16px;
            background: #050508;
            border-bottom: 1px solid #00ff41;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            flex-shrink: 0;
        }

        .chat-header h2 {
            font-size: 16px;
            font-weight: normal;
            flex: 1;
            text-align: center;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .menu-btn, .exit-btn {
            background: transparent;
            border: 1px solid #00ff41;
            border-radius: 8px;
            color: #00ff41;
            padding: 8px 14px;
            font-size: 13px;
            cursor: pointer;
            flex-shrink: 0;
        }

        .exit-btn:active {
            background: #ff0041;
            border-color: #ff0041;
            color: white;
        }

        /* Main Content */
        .main-content {
            flex: 1;
            display: flex;
            overflow: hidden;
            position: relative;
        }

        /* Sidebar */
        .sidebar {
            position: fixed;
            left: -280px;
            top: 0;
            bottom: 0;
            width: 280px;
            background: #050508;
            border-right: 1px solid #00ff41;
            z-index: 20;
            transition: left 0.3s ease;
            display: flex;
            flex-direction: column;
        }

        .sidebar.open {
            left: 0;
        }

        .sidebar h3 {
            padding: 16px;
            border-bottom: 1px solid #00ff41;
            font-size: 14px;
        }

        .users-list {
            flex: 1;
            padding: 12px;
            overflow-y: auto;
        }

        .user-item {
            padding: 10px 12px;
            margin: 6px 0;
            border: 1px solid #00ff41;
            border-radius: 10px;
            font-size: 13px;
        }

        .overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.7);
            z-index: 15;
            display: none;
        }

        .overlay.active {
            display: block;
        }

        /* Desktop: always show sidebar */
        @media (min-width: 769px) {
            .sidebar {
                position: relative;
                left: 0;
                width: 260px;
            }
            .menu-btn {
                display: none;
            }
            .overlay {
                display: none;
            }
        }

        /* Chat Area */
        .chat-area {
            flex: 1;
            display: flex;
            flex-direction: column;
            width: 100%;
        }

        /* Messages */
        .messages-container {
            flex: 1;
            padding: 16px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .message {
            max-width: 85%;
            display: flex;
            flex-direction: column;
            animation: fadeIn 0.2s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .message.sent {
            align-self: flex-end;
        }

        .message.received {
            align-self: flex-start;
        }

        .message-bubble {
            padding: 10px 14px;
            border-radius: 18px;
            font-size: 14px;
            word-wrap: break-word;
        }

        .message.sent .message-bubble {
            background: #00ff41;
            color: #000;
            border-bottom-right-radius: 4px;
        }

        .message.received .message-bubble {
            background: #1a1a2e;
            border: 1px solid #00ff41;
            border-bottom-left-radius: 4px;
        }

        .message-sender {
            font-size: 10px;
            margin-bottom: 4px;
            opacity: 0.7;
            padding-left: 4px;
        }

        .message-time {
            font-size: 9px;
            margin-top: 4px;
            opacity: 0.5;
        }

        .system-message {
            text-align: center;
            font-size: 11px;
            color: #ffaa00;
            margin: 8px 0;
            font-style: italic;
        }

        /* Typing Indicator */
        .typing-indicator {
            padding: 8px 16px;
            color: #00ff41;
            font-style: italic;
            font-size: 11px;
            min-height: 36px;
            flex-shrink: 0;
        }

        /* Input Area */
        .input-area {
            padding: 12px 16px;
            background: #050508;
            border-top: 1px solid #00ff41;
            display: flex;
            gap: 10px;
            flex-shrink: 0;
        }

        .input-area input {
            flex: 1;
            margin: 0;
            padding: 12px 16px;
            font-size: 14px;
        }

        .input-area button {
            width: auto;
            margin: 0;
            padding: 12px 20px;
            font-size: 14px;
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 6px;
            font-size: 8px;
            color: #333;
            border-top: 1px solid #00ff41;
            flex-shrink: 0;
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 3px;
        }

        ::-webkit-scrollbar-track {
            background: #1a1a2e;
        }

        ::-webkit-scrollbar-thumb {
            background: #00ff41;
        }
    </style>
</head>
<body>
<div id="loginScreen" class="login-screen">
    <div class="login-card">
        <h1># ABAVANDIMWE</h1>
        <div class="sub">Secure Messaging by Mugisha Pc</div>
        <input type="text" id="username" placeholder="USERNAME">
        <input type="text" id="groupName" placeholder="GROUP NAME">
        <input type="password" id="groupPassword" placeholder="PASSWORD">
        <button onclick="doConnect()">▶ CONNECT</button>
        <div id="errorMsg" class="error"></div>
        <div style="text-align:center;margin-top:20px;font-size:9px;color:#333;">🔒 24h auto-delete | AES-256</div>
    </div>
</div>

<div id="chatScreen" class="chat-screen">
    <div class="chat-header">
        <button class="menu-btn" onclick="toggleMenu()">☰</button>
        <h2 id="groupTitle"># LOADING</h2>
        <button class="exit-btn" onclick="doLogout()">EXIT</button>
    </div>
    <div class="main-content">
        <div class="sidebar" id="sidebar">
            <h3>● ONLINE USERS</h3>
            <div class="users-list" id="usersList">Loading...</div>
        </div>
        <div class="overlay" id="overlay" onclick="toggleMenu()"></div>
        <div class="chat-area">
            <div class="messages-container" id="messages"><div style="text-align:center;">Connecting...</div></div>
            <div class="typing-indicator" id="typingIndicator"></div>
            <div class="input-area">
                <input type="text" id="msgInput" placeholder="Type message...">
                <button onclick="sendMsg()">SEND</button>
            </div>
            <div class="footer">🔐 Encrypted | Messages last 24 hours</div>
        </div>
    </div>
</div>

<script>
    let ws, myName, myGroup, myPass, groupSalt, typingTO;
    
    async function encryptText(txt, pass, salt){
        const enc=new TextEncoder();
        const km=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);
        const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:enc.encode(salt),iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['encrypt']);
        const iv=crypto.getRandomValues(new Uint8Array(12));
        const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(txt));
        const c=new Uint8Array(iv.length+encrypted.byteLength);
        c.set(iv,0);c.set(new Uint8Array(encrypted),iv.length);
        return btoa(String.fromCharCode(...c));
    }
    
    async function decryptText(enc, pass, salt){
        const d=Uint8Array.from(atob(enc),c=>c.charCodeAt(0));
        const iv=d.slice(0,12),data=d.slice(12);
        const enc2=new TextEncoder();
        const km=await crypto.subtle.importKey('raw',enc2.encode(pass),'PBKDF2',false,['deriveKey']);
        const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:enc2.encode(salt),iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);
        const dec=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,data);
        return new TextDecoder().decode(dec);
    }
    
    function toggleMenu(){
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('overlay').classList.toggle('active');
    }
    
    function showError(msg){
        let err=document.getElementById('errorMsg');
        err.innerText=msg;
        err.style.display='block';
        setTimeout(()=>err.style.display='none',3000);
    }
    
    function addSystemMessage(txt){
        let msgs=document.getElementById('messages');
        if(msgs.children.length===1 && msgs.children[0].innerText.includes('Connecting')) msgs.innerHTML='';
        let div=document.createElement('div');
        div.className='system-message';
        div.innerText=txt;
        msgs.appendChild(div);
        msgs.scrollTop=msgs.scrollHeight;
    }
    
    function addMessage(sender, text, isSent){
        let msgs=document.getElementById('messages');
        if(msgs.children.length===1 && msgs.children[0].innerText.includes('Connecting')) msgs.innerHTML='';
        let div=document.createElement('div');
        div.className='message '+(isSent?'sent':'received');
        let now=new Date();
        let time=now.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
        div.innerHTML='<div class="message-sender">'+(isSent?'YOU':sender)+'</div><div class="message-bubble">'+escapeHtml(text)+'</div><div class="message-time">'+time+'</div>';
        msgs.appendChild(div);
        msgs.scrollTop=msgs.scrollHeight;
    }
    
    function escapeHtml(t){let d=document.createElement('div');d.textContent=t;return d.innerHTML;}
    
    function updateUsers(users){
        let ul=document.getElementById('usersList');
        if(users.length===0) ul.innerHTML='<div class="user-item">No users online</div>';
        else ul.innerHTML=users.map(u=>'<div class="user-item">● '+escapeHtml(u)+'</div>').join('');
    }
    
    function doLogout(){
        if(ws) ws.close();
        ws=null;
        document.getElementById('chatScreen').classList.remove('active');
        document.getElementById('loginScreen').style.display='flex';
        document.getElementById('messages').innerHTML='<div style="text-align:center;">Connecting...</div>';
        document.getElementById('usersList').innerHTML='Loading...';
        document.getElementById('username').value='';
        document.getElementById('groupName').value='';
        document.getElementById('groupPassword').value='';
    }
    
    function doConnect(){
        myName=document.getElementById('username').value.trim();
        myGroup=document.getElementById('groupName').value.trim();
        myPass=document.getElementById('groupPassword').value;
        if(!myName||!myGroup||!myPass){showError('Fill all fields');return;}
        
        let url='wss://'+window.location.host+'/ws';
        ws=new WebSocket(url);
        
        ws.onopen=()=>{
            ws.send(JSON.stringify({type:'join',username:myName,group:myGroup,password:myPass}));
        };
        
        ws.onmessage=async (e)=>{
            let d=JSON.parse(e.data);
            if(d.type==='error'){showError(d.message);ws.close();return;}
            if(d.type==='ready'){
                groupSalt=d.salt;
                document.getElementById('loginScreen').style.display='none';
                document.getElementById('chatScreen').classList.add('active');
                document.getElementById('groupTitle').innerHTML='# '+d.group;
                addSystemMessage('🔐 Connected - Messages last 24 hours');
            }
            else if(d.type==='message'||d.type==='history'){
                try{
                    let dec=await decryptText(d.ciphertext,myPass,d.salt);
                    addMessage(d.sender,dec,d.sender===myName);
                }catch(e){addMessage(d.sender,'🔒 Encrypted',d.sender===myName);}
            }
            else if(d.type==='users') updateUsers(d.users);
            else if(d.type==='user_joined') addSystemMessage('👤 '+d.user+' joined');
            else if(d.type==='user_left') addSystemMessage('👋 '+d.user+' left');
            else if(d.type==='typing') document.getElementById('typingIndicator').innerHTML='✏️ '+d.user+' typing...';
            else if(d.type==='stop_typing') document.getElementById('typingIndicator').innerHTML='';
        };
        
        ws.onerror=()=>showError('Connection failed');
    }
    
    document.getElementById('msgInput')?.addEventListener('input',function(){
        if(ws&&ws.readyState===WebSocket.OPEN){
            ws.send(JSON.stringify({type:'typing'}));
            clearTimeout(typingTO);
            typingTO=setTimeout(()=>ws.send(JSON.stringify({type:'stop_typing'})),1000);
        }
    });
    
    document.getElementById('msgInput')?.addEventListener('keypress',function(e){if(e.key==='Enter')sendMsg();});
    
    async function sendMsg(){
        let input=document.getElementById('msgInput'),txt=input.value.trim();
        if(!txt||!ws||ws.readyState!==WebSocket.OPEN||!groupSalt) return;
        try{
            let cipher=await encryptText(txt,myPass,groupSalt);
            ws.send(JSON.stringify({type:'message',ciphertext:cipher,salt:groupSalt}));
            addMessage(myName,txt,true);
            input.value='';
        }catch(e){alert('Failed');}
    }
</script>
</body>
</html>'''

# ========== FASTAPI ENDPOINTS ==========
@app.get("/")
async def root():
    return HTMLResponse(HTML)

@app.get("/health")
async def health():
    return {"status": "ok", "system": "ABAVANDIMWE", "author": "Mugisha Pc"}

# ========== WEBSOCKET ==========
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    username = None
    group_name = None
    
    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get('type')
            
            if msg_type == 'join':
                username = data.get('username')
                group_name = data.get('group')
                password = data.get('password')
                
                group_info = get_group_info(group_name)
                if group_info:
                    if not verify_password(password, group_info['salt'], group_info['password_hash']):
                        await websocket.send_json({'type': 'error', 'message': 'Wrong password'})
                        await websocket.close()
                        return
                    salt = group_info['salt']
                else:
                    salt = generate_salt()
                    pwd_hash = hash_password(password, salt)
                    create_group(group_name, salt, pwd_hash, username)
                
                await manager.add(group_name, username, websocket)
                set_user_status(username, 'online', group_name)
                
                for msg in get_messages(group_name):
                    await websocket.send_json({
                        'type': 'history',
                        'ciphertext': msg['ciphertext'],
                        'sender': msg['sender'],
                        'salt': msg['salt']
                    })
                
                online = get_online_users(group_name)
                await manager.broadcast(group_name, {'type': 'users', 'users': online})
                await manager.broadcast(group_name, {'type': 'user_joined', 'user': username}, exclude=username)
                await websocket.send_json({'type': 'ready', 'salt': salt, 'group': group_name})
                print(f"[+] {username} joined {group_name}")
            
            elif msg_type == 'message':
                cipher = data.get('ciphertext')
                salt = data.get('salt')
                save_message(cipher, group_name, username, salt)
                await manager.broadcast(group_name, {
                    'type': 'message',
                    'ciphertext': cipher,
                    'sender': username,
                    'salt': salt
                }, exclude=username)
            
            elif msg_type == 'typing':
                await manager.broadcast(group_name, {'type': 'typing', 'user': username}, exclude=username)
            
            elif msg_type == 'stop_typing':
                await manager.broadcast(group_name, {'type': 'stop_typing', 'user': username}, exclude=username)
    
    except WebSocketDisconnect:
        pass
    finally:
        if username and group_name:
            manager.remove(group_name, username)
            set_user_status(username, 'offline', group_name)
            online = get_online_users(group_name)
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
║              Mobile Optimized CSS                          ║
║                    Author: Mugisha Pc                      ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    """)
    print(f"[✓] Server on port {port}")
    print(f"[✓] Messages last 24 hours then auto-delete")
    print(f"[✓] Mobile optimized CSS")
    print(f"[✓] Open: https://abavandimwe.onrender.com")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
