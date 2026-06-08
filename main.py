"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
PostgreSQL Database - Messages persist for 24 hours
Multiple users can chat simultaneously
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import asyncio
import json
import secrets
import base64
import hashlib
import os
import asyncpg
from datetime import datetime, timedelta
from typing import Dict
from contextlib import asynccontextmanager

app = FastAPI()

# ========== POSTGRESQL DATABASE ==========
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://neondb_owner:npg_Cb7XtKr0BIoN@ep-holy-scene-apw8vqig.c-7.us-east-1.aws.neon.tech/neondb?sslmode=require')
db_pool = None

async def init_db():
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=5, max_size=20)
    
    async with db_pool.acquire() as conn:
        # Messages table with 24-hour expiration
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id BIGSERIAL PRIMARY KEY,
                ciphertext TEXT NOT NULL,
                group_name TEXT NOT NULL,
                sender TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP + INTERVAL '24 hours'
            )
        ''')
        
        # Users table for presence
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                status TEXT DEFAULT 'offline',
                current_group TEXT,
                last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Groups table with password hash
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                group_name TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Index for fast cleanup
        await conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_expires_at ON messages(expires_at)
        ''')
        
        print("[✓] PostgreSQL database ready")
        print("[✓] Messages persist for 24 hours")

async def cleanup_loop():
    """Delete expired messages every hour"""
    while True:
        await asyncio.sleep(3600)
        if db_pool:
            async with db_pool.acquire() as conn:
                result = await conn.execute("DELETE FROM messages WHERE expires_at < CURRENT_TIMESTAMP")
                print(f"[🧹] Cleaned up expired messages at {datetime.now()}")

# ========== CRYPTOGRAPHY ==========
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

# ========== DATABASE OPERATIONS ==========
async def save_message(ciphertext, group, sender, salt):
    async with db_pool.acquire() as conn:
        await conn.execute('''
            INSERT INTO messages (ciphertext, group_name, sender, salt)
            VALUES ($1, $2, $3, $4)
        ''', ciphertext, group, sender, salt)

async def get_messages(group):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch('''
            SELECT ciphertext, sender, salt, created_at
            FROM messages 
            WHERE group_name = $1 
                AND expires_at > CURRENT_TIMESTAMP
            ORDER BY id ASC
        ''', group)
        return [{'ciphertext': r[0], 'sender': r[1], 'salt': r[2]} for r in rows]

async def set_user_status(username, status, group):
    async with db_pool.acquire() as conn:
        await conn.execute('''
            INSERT INTO users (username, status, current_group, last_seen)
            VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
            ON CONFLICT (username) 
            DO UPDATE SET status = $2, current_group = $3, last_seen = CURRENT_TIMESTAMP
        ''', username, status, group)

async def get_online_users(group):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch('''
            SELECT username FROM users 
            WHERE status = 'online' AND current_group = $1
                AND last_seen > CURRENT_TIMESTAMP - INTERVAL '2 minutes'
        ''', group)
        return [r[0] for r in rows]

async def get_group_info(group):
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow('''
            SELECT salt, password_hash FROM groups WHERE group_name = $1
        ''', group)
        if row:
            return {'salt': row[0], 'password_hash': row[1]}
        return None

async def create_group(group, salt, password_hash, creator):
    async with db_pool.acquire() as conn:
        try:
            await conn.execute('''
                INSERT INTO groups (group_name, salt, password_hash, created_by)
                VALUES ($1, $2, $3, $4)
            ''', group, salt, password_hash, creator)
            return True
        except:
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

# ========== HTML ==========
HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>ABAVANDIMWE | Secure Chat</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
        body{font-family:monospace;background:#0a0a0f;height:100vh;overflow:hidden;color:#0f0;}
        .login-container{position:fixed;top:0;left:0;right:0;bottom:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;padding:20px;}
        .login-card{background:#050508;border:2px solid #0f0;border-radius:24px;padding:32px 24px;width:100%;max-width:400px;}
        h1{text-align:center;margin-bottom:8px;font-size:28px;letter-spacing:2px;}
        .sub{text-align:center;margin-bottom:32px;font-size:11px;color:#666;}
        input{width:100%;padding:14px;margin:10px 0;background:#111;border:1px solid #0f0;border-radius:12px;color:#0f0;font-family:monospace;font-size:15px;}
        input:focus{outline:none;box-shadow:0 0 10px rgba(0,255,65,0.3);}
        button{width:100%;padding:14px;margin-top:20px;background:transparent;border:2px solid #0f0;border-radius:12px;color:#0f0;font-size:16px;font-weight:bold;cursor:pointer;}
        button:active{background:#0f0;color:#000;transform:scale(0.98);}
        .error-message{color:#ff4444;font-size:12px;text-align:center;margin-top:12px;display:none;}
        .chat-container{display:none;width:100%;height:100%;flex-direction:column;background:#0a0a0f;position:fixed;top:0;left:0;right:0;bottom:0;}
        .chat-container.active{display:flex;}
        .chat-header{padding:12px 16px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;align-items:center;gap:8px;}
        .chat-header h2{font-size:16px;flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;}
        .online-badge{font-size:11px;padding:4px 10px;border:1px solid #0f0;border-radius:20px;}
        .menu-btn,.logout-btn{background:transparent;border:1px solid #0f0;color:#0f0;padding:6px 12px;border-radius:8px;cursor:pointer;width:auto;margin:0;font-size:12px;}
        .logout-btn:active{background:#ff0041;border-color:#ff0041;color:white;}
        .main-content{flex:1;display:flex;overflow:hidden;position:relative;}
        .sidebar{width:260px;background:#050508;border-right:1px solid #0f0;display:flex;flex-direction:column;flex-shrink:0;}
        .sidebar-header{padding:16px;border-bottom:1px solid #0f0;}
        .users-list{flex:1;padding:12px;overflow-y:auto;}
        .user-item{padding:10px 12px;margin:6px 0;border:1px solid #0f0;border-radius:10px;display:flex;align-items:center;gap:8px;}
        .user-item::before{content:"●";color:#0f0;font-size:10px;animation:pulse 2s infinite;}
        @keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.5;}}
        @media (max-width:768px){
            .sidebar{position:fixed;left:-260px;top:0;bottom:0;z-index:20;transition:left 0.3s ease;}
            .sidebar.open{left:0;}
            .overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:15;display:none;}
            .overlay.active{display:block;}
        }
        @media (min-width:769px){.menu-btn,.overlay{display:none;}}
        .chat-area{flex:1;display:flex;flex-direction:column;}
        .messages-container{flex:1;padding:16px;overflow-y:auto;display:flex;flex-direction:column;gap:12px;}
        .message{max-width:85%;display:flex;flex-direction:column;animation:fadeIn 0.2s ease;}
        @keyframes fadeIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
        .message.sent{align-self:flex-end;}
        .message.received{align-self:flex-start;}
        .message-bubble{padding:10px 14px;border-radius:18px;font-size:14px;word-wrap:break-word;}
        .message.sent .message-bubble{background:#0f0;color:#000;border-bottom-right-radius:4px;}
        .message.received .message-bubble{background:#1a1a2e;border:1px solid #0f0;border-bottom-left-radius:4px;}
        .message-sender{font-size:10px;margin-bottom:4px;opacity:0.7;padding-left:4px;}
        .message-time{font-size:9px;margin-top:4px;opacity:0.5;}
        .system-message{text-align:center;font-size:11px;color:#ffaa00;margin:8px 0;font-style:italic;}
        .typing-indicator{padding:8px 16px;color:#0f0;font-style:italic;font-size:11px;min-height:36px;}
        .input-area{padding:12px 16px;background:#050508;border-top:1px solid #0f0;display:flex;gap:10px;}
        .input-area input{flex:1;margin:0;padding:12px 16px;font-size:14px;}
        .input-area button{width:auto;margin:0;padding:12px 20px;}
        .footer{text-align:center;padding:6px;font-size:8px;color:#333;border-top:1px solid #0f0;}
        ::-webkit-scrollbar{width:3px;}
        ::-webkit-scrollbar-track{background:#1a1a2e;}
        ::-webkit-scrollbar-thumb{background:#0f0;}
    </style>
</head>
<body>
<div id="loginScreen" class="login-container">
    <div class="login-card">
        <h1># ABAVANDIMWE</h1>
        <div class="sub">Secure Encrypted Messaging by Mugisha Pc</div>
        <input type="text" id="username" placeholder="USERNAME">
        <input type="text" id="groupName" placeholder="GROUP NAME">
        <input type="password" id="groupPassword" placeholder="GROUP PASSWORD">
        <button onclick="connect()">▶ ENTER CHAT</button>
        <div id="loginError" class="error-message"></div>
        <div style="text-align:center;margin-top:20px;font-size:9px;color:#333;">
            🔒 AES-256 | ⏰ Messages auto-delete after 24 hours | 💾 PostgreSQL
        </div>
    </div>
</div>
<div id="chatScreen" class="chat-container">
    <div class="chat-header">
        <button class="menu-btn" onclick="toggleSidebar()">☰</button>
        <h2 id="groupTitle"># LOADING</h2>
        <button class="logout-btn" onclick="logout()">EXIT</button>
    </div>
    <div class="main-content">
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header"><h3>● ONLINE USERS</h3></div>
            <div class="users-list" id="usersList"><div class="user-item">Loading...</div></div>
        </div>
        <div class="overlay" id="overlay" onclick="toggleSidebar()"></div>
        <div class="chat-area">
            <div class="messages-container" id="messages"><div style="text-align:center;">Connecting...</div></div>
            <div class="typing-indicator" id="typingIndicator"></div>
            <div class="input-area">
                <input type="text" id="messageInput" placeholder="Type message...">
                <button onclick="sendMessage()">SEND</button>
            </div>
            <div class="footer">🔐 End-to-End Encrypted | Messages persist for 24 hours</div>
        </div>
    </div>
</div>
<script>
let ws, username, groupName, groupPassword, groupSalt, typingTimeout;

async function encrypt(text, pwd, salt){
    const e=new TextEncoder();
    const km=await crypto.subtle.importKey('raw',e.encode(pwd),'PBKDF2',false,['deriveKey']);
    const k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:e.encode(salt),iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['encrypt']);
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const enc=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,e.encode(text));
    const c=new Uint8Array(iv.length+enc.byteLength);
    c.set(iv,0);c.set(new Uint8Array(enc),iv.length);
    return btoa(String.fromCharCode(...c));
}

async function decrypt(enc,pwd,salt){
    const d=Uint8Array.from(atob(enc),c=>c.charCodeAt(0));
    const iv=d.slice(0,12),data=d.slice(12);
    const e=new TextEncoder();
    const km=await crypto.subtle.importKey('raw',e.encode(pwd),'PBKDF2',false,['deriveKey']);
    const k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:e.encode(salt),iterations:100000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);
    const dec=await crypto.subtle.decrypt({name:'AES-GCM',iv},k,data);
    return new TextDecoder().decode(dec);
}

function toggleSidebar(){
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('overlay').classList.toggle('active');
}

function showError(msg){
    let err=document.getElementById('loginError');
    err.textContent=msg;
    err.style.display='block';
    setTimeout(()=>err.style.display='none',3000);
}

function addSystemMessage(text){
    let msgs=document.getElementById('messages');
    if(msgs.children.length===1 && msgs.children[0].innerText.includes('Connecting')) msgs.innerHTML='';
    let div=document.createElement('div');
    div.className='system-message';
    div.innerHTML=text;
    msgs.appendChild(div);
    msgs.scrollTop=msgs.scrollHeight;
}

function addMessage(sender,text,isSent){
    let msgs=document.getElementById('messages');
    if(msgs.children.length===1 && msgs.children[0].innerText.includes('Connecting')) msgs.innerHTML='';
    let div=document.createElement('div');
    div.className='message '+(isSent?'sent':'received');
    let time=new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
    div.innerHTML='<div class="message-sender">'+(isSent?'YOU':sender)+'</div><div class="message-bubble">'+escapeHtml(text)+'</div><div class="message-time">'+time+'</div>';
    msgs.appendChild(div);
    msgs.scrollTop=msgs.scrollHeight;
}

function escapeHtml(t){let d=document.createElement('div');d.textContent=t;return d.innerHTML;}

function updateUsers(users){
    let ul=document.getElementById('usersList');
    if(users.length===0) ul.innerHTML='<div class="user-item">No users online</div>';
    else ul.innerHTML=users.map(u=>'<div class="user-item">'+escapeHtml(u)+'</div>').join('');
}

function logout(){
    if(ws) ws.close();
    ws=null;
    document.getElementById('chatScreen').classList.remove('active');
    document.getElementById('loginScreen').style.display='flex';
    document.getElementById('messages').innerHTML='<div style="text-align:center;">Connecting...</div>';
    document.getElementById('usersList').innerHTML='<div class="user-item">Loading...</div>';
    document.getElementById('username').value='';
    document.getElementById('groupName').value='';
    document.getElementById('groupPassword').value='';
}

function connect(){
    username=document.getElementById('username').value.trim();
    groupName=document.getElementById('groupName').value.trim();
    groupPassword=document.getElementById('groupPassword').value;
    if(!username||!groupName||!groupPassword){showError('Fill all fields');return;}
    let url='wss://'+window.location.host+'/ws';
    ws=new WebSocket(url);
    ws.onopen=()=>ws.send(JSON.stringify({type:'join',username,group:groupName,password:groupPassword}));
    ws.onmessage=async(e)=>{
        let d=JSON.parse(e.data);
        if(d.type==='error'){showError(d.message);ws.close();return;}
        if(d.type==='ready'){groupSalt=d.salt;document.getElementById('loginScreen').style.display='none';document.getElementById('chatScreen').classList.add('active');document.getElementById('groupTitle').innerHTML='# '+d.group;addSystemMessage('🔐 Connected - Messages persist for 24 hours');}
        else if(d.type==='message'||d.type==='history'){
            try{let dec=await decrypt(d.ciphertext,groupPassword,d.salt);addMessage(d.sender,dec,d.sender===username);}
            catch(e){addMessage(d.sender,'🔒 Encrypted',d.sender===username);}
        }
        else if(d.type==='users') updateUsers(d.users);
        else if(d.type==='user_joined') addSystemMessage('👤 '+d.user+' joined');
        else if(d.type==='user_left') addSystemMessage('👋 '+d.user+' left');
        else if(d.type==='typing') document.getElementById('typingIndicator').innerHTML='✏️ '+d.user+' typing...';
        else if(d.type==='stop_typing') document.getElementById('typingIndicator').innerHTML='';
    };
    ws.onerror=()=>showError('Connection failed');
}

document.getElementById('messageInput')?.addEventListener('input',function(){
    if(ws&&ws.readyState===WebSocket.OPEN){
        ws.send(JSON.stringify({type:'typing'}));
        clearTimeout(typingTimeout);
        typingTimeout=setTimeout(()=>ws.send(JSON.stringify({type:'stop_typing'})),1000);
    }
});
document.getElementById('messageInput')?.addEventListener('keypress',function(e){if(e.key==='Enter')sendMessage();});

async function sendMessage(){
    let input=document.getElementById('messageInput'),text=input.value.trim();
    if(!text||!ws||ws.readyState!==WebSocket.OPEN||!groupSalt) return;
    try{
        let cipher=await encrypt(text,groupPassword,groupSalt);
        ws.send(JSON.stringify({type:'message',ciphertext:cipher,salt:groupSalt}));
        addMessage(username,text,true);
        input.value='';
    }catch(e){alert('Failed to send');}
}
</script>
</body>
</html>'''

# ========== FASTAPI ENDPOINTS ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    asyncio.create_task(cleanup_loop())
    yield
    # Shutdown
    if db_pool:
        await db_pool.close()

app = FastAPI(title="ABAVANDIMWE", lifespan=lifespan)

@app.get("/")
async def root():
    return HTMLResponse(HTML)

@app.get("/health")
async def health():
    return {"status": "healthy", "database": "PostgreSQL", "auto_delete": "24 hours", "author": "Mugisha Pc"}

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
                
                group_info = await get_group_info(group_name)
                if group_info:
                    if not verify_password(password, group_info['salt'], group_info['password_hash']):
                        await websocket.send_json({'type': 'error', 'message': 'Wrong password'})
                        await websocket.close()
                        return
                    salt = group_info['salt']
                else:
                    salt = generate_salt()
                    pwd_hash = hash_password(password, salt)
                    await create_group(group_name, salt, pwd_hash, username)
                
                await manager.add(group_name, username, websocket)
                await set_user_status(username, 'online', group_name)
                
                for msg in await get_messages(group_name):
                    await websocket.send_json({
                        'type': 'history',
                        'ciphertext': msg['ciphertext'],
                        'sender': msg['sender'],
                        'salt': msg['salt']
                    })
                
                online = await get_online_users(group_name)
                await manager.broadcast(group_name, {'type': 'users', 'users': online})
                await manager.broadcast(group_name, {'type': 'user_joined', 'user': username}, exclude=username)
                await websocket.send_json({'type': 'ready', 'salt': salt, 'group': group_name})
                print(f"[+] {username} joined {group_name}")
            
            elif msg_type == 'message':
                cipher = data.get('ciphertext')
                salt = data.get('salt')
                await save_message(cipher, group_name, username, salt)
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
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   █████╗ ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗██████╗      ║
║  ██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔══██╗     ║
║  ███████║██████╔╝███████║██║   ██║███████║██╔██╗ ██║██║  ██║     ║
║  ██╔══██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║  ██║     ║
║  ██║  ██║██████╔╝██║  ██║ ╚████╔╝ ██║  ██║██║ ╚████║██████╔╝     ║
║  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝      ║
║                                                                   ║
║              ABAVANDIMWE SECURE MESSAGING SYSTEM                 ║
║              ✅ PostgreSQL Database (Persistent)                 ║
║              ✅ Messages persist for 24 hours                    ║
║              ✅ Multiple users can chat simultaneously           ║
║              ✅ Messages survive server restarts                  ║
║                        AUTHOR: MUGISHA PC                         ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    print(f"[✓] Server on port {port}")
    print(f"[✓] Database: PostgreSQL (Neon) - PERSISTENT")
    print(f"[✓] Messages last 24 hours then auto-delete")
    print(f"[✓] Multiple users can chat together")
    print(f"[✓] Open: https://abavandimwe.onrender.com")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
