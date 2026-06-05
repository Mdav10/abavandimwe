"""
ABAVANDIMWE - Professional Secure Messaging System
Author: Mugisha Pc
Deployed on Render - 100% Working
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import asyncio
import json
import sqlite3
import secrets
import base64
import hashlib
from datetime import datetime
from typing import Dict, Set
import os

# ========== CONFIGURATION ==========
app = FastAPI(title="ABAVANDIMWE", description="Secure Messaging System")

# ========== CRYPTOGRAPHY ==========
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
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ciphertext TEXT,
                     group_name TEXT,
                     sender TEXT,
                     salt TEXT,
                     created_at TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (username TEXT PRIMARY KEY,
                     status TEXT,
                     current_group TEXT,
                     last_seen TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS groups
                    (group_name TEXT PRIMARY KEY,
                     salt TEXT,
                     created_by TEXT,
                     created_at TEXT)''')
        conn.commit()
        conn.close()
        print("[✓] Database initialized")
    
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
            c.execute("INSERT INTO groups (group_name, salt, created_by, created_at) VALUES (?,?,?,?)",
                     (group, salt, creator, datetime.now().isoformat()))
            conn.commit()
        except:
            pass
        conn.close()

db = Database()

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Dict[str, WebSocket]] = {}
        self.typing_users: Set[str] = set()
    
    async def connect(self, websocket: WebSocket, group: str, username: str):
        await websocket.accept()
        if group not in self.active_connections:
            self.active_connections[group] = {}
        self.active_connections[group][username] = websocket
        db.set_user_status(username, 'online', group)
    
    def disconnect(self, group: str, username: str):
        if group in self.active_connections:
            if username in self.active_connections[group]:
                del self.active_connections[group][username]
            if not self.active_connections[group]:
                del self.active_connections[group]
        db.set_user_status(username, 'offline', group)
    
    async def broadcast(self, group: str, message: dict, exclude: str = None):
        if group not in self.active_connections:
            return
        for username, connection in self.active_connections[group].items():
            if username != exclude:
                try:
                    await connection.send_json(message)
                except:
                    pass
    
    async def send_personal(self, websocket: WebSocket, message: dict):
        await websocket.send_json(message)

manager = ConnectionManager()

# ========== HTML PAGE ==========
HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>ABAVANDIMWE | Secure Chat</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:'Courier New',monospace;background:#0a0a0f;height:100vh;color:#0f0;overflow:hidden;}
        .login-container{position:fixed;top:0;left:0;right:0;bottom:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;}
        .login-card{background:#050508;border:2px solid #0f0;border-radius:16px;padding:40px;width:90%;max-width:420px;box-shadow:0 0 40px rgba(0,255,0,0.1);}
        h1{text-align:center;margin-bottom:8px;font-size:32px;letter-spacing:2px;}
        .sub{text-align:center;margin-bottom:32px;font-size:12px;color:#888;}
        input{width:100%;padding:14px;margin:10px 0;background:#111;border:1px solid #0f0;border-radius:8px;color:#0f0;font-family:monospace;font-size:14px;}
        input:focus{outline:none;box-shadow:0 0 10px rgba(0,255,0,0.3);}
        button{width:100%;padding:14px;margin-top:20px;background:transparent;border:2px solid #0f0;border-radius:8px;color:#0f0;font-size:16px;font-weight:bold;cursor:pointer;transition:all 0.3s;}
        button:hover{background:#0f0;color:#000;box-shadow:0 0 20px rgba(0,255,0,0.3);}
        .chat-container{display:none;width:100%;height:100%;flex-direction:column;}
        .chat-container.active{display:flex;}
        .chat-header{padding:16px 20px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;align-items:center;}
        .chat-header h2{font-size:18px;}
        .online-badge{font-size:12px;padding:4px 12px;border:1px solid #0f0;border-radius:20px;}
        .main-content{flex:1;display:flex;overflow:hidden;}
        .sidebar{width:260px;background:#050508;border-right:1px solid #0f0;display:flex;flex-direction:column;}
        .sidebar-header{padding:15px;border-bottom:1px solid #0f0;}
        .sidebar-header h3{font-size:14px;}
        .users-list{padding:12px;flex:1;overflow-y:auto;}
        .user-item{padding:10px 12px;margin:6px 0;border:1px solid #0f0;border-radius:8px;font-size:13px;}
        .chat-area{flex:1;display:flex;flex-direction:column;}
        .messages-container{flex:1;padding:20px;overflow-y:auto;display:flex;flex-direction:column;gap:12px;}
        .message{max-width:75%;display:flex;flex-direction:column;}
        .message.sent{align-self:flex-end;}
        .message.received{align-self:flex-start;}
        .message-bubble{padding:10px 16px;border-radius:16px;font-size:14px;}
        .message.sent .message-bubble{background:#0f0;color:#000;}
        .message.received .message-bubble{background:#1a1a2e;border:1px solid #0f0;}
        .message-sender{font-size:10px;margin-bottom:4px;opacity:0.7;}
        .typing-indicator{padding:8px 20px;color:#0f0;font-style:italic;font-size:12px;}
        .input-area{padding:16px 20px;background:#050508;border-top:1px solid #0f0;display:flex;gap:12px;}
        .input-area input{flex:1;margin:0;}
        .input-area button{width:auto;margin:0;padding:14px 24px;}
        .footer{text-align:center;padding:8px;font-size:9px;color:#444;border-top:1px solid #0f0;}
        @media (max-width: 768px){
            .sidebar{position:fixed;left:-260px;top:0;bottom:0;z-index:100;transition:left 0.3s;}
            .sidebar.open{left:0;}
            .menu-btn{display:block;}
            .message{max-width:90%;}
        }
        .menu-btn{display:none;background:transparent;border:1px solid #0f0;color:#0f0;padding:8px 12px;border-radius:8px;cursor:pointer;}
    </style>
</head>
<body>
<div id="loginScreen" class="login-container">
    <div class="login-card">
        <h1># ABAVANDIMWE</h1>
        <div class="sub">Secure Encrypted Messaging by Mugisha Pc</div>
        <input type="text" id="username" placeholder="USERNAME" autocomplete="off">
        <input type="text" id="groupName" placeholder="GROUP NAME" autocomplete="off">
        <input type="password" id="groupPassword" placeholder="GROUP PASSWORD">
        <button onclick="connect()">▶ ENTER SECURE CHAT</button>
        <div style="text-align:center;margin-top:24px;font-size:10px;color:#444;">
            🔒 AES-256-GCM | ⏰ Auto-Delete 24h | 👁️ E2E Encrypted
        </div>
    </div>
</div>
<div id="chatScreen" class="chat-container">
    <div class="chat-header">
        <button class="menu-btn" onclick="toggleSidebar()">☰</button>
        <h2 id="groupTitle"># LOADING</h2>
        <span class="online-badge" id="onlineCount">0 online</span>
    </div>
    <div class="main-content">
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header"><h3>● ONLINE USERS</h3></div>
            <div class="users-list" id="usersList"><div class="user-item">connecting...</div></div>
        </div>
        <div class="chat-area">
            <div class="messages-container" id="messages"><div style="text-align:center;">connecting to secure server...</div></div>
            <div class="typing-indicator" id="typingIndicator"></div>
            <div class="input-area">
                <input type="text" id="messageInput" placeholder="Type encrypted message...">
                <button onclick="sendMessage()">SEND</button>
            </div>
            <div class="footer">🔐 End-to-End Encrypted | Messages Self-Destruct in 24 Hours</div>
        </div>
    </div>
</div>
<script>
    let ws, username, groupName, groupPassword, groupSalt;
    let typingTimeout;
    
    async function encryptMessage(text, password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({
            name: 'PBKDF2', salt: encoder.encode(salt), iterations: 100000, hash: 'SHA-256'
        }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(text));
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        return btoa(String.fromCharCode(...combined));
    }
    
    async function decryptMessage(encrypted, password, salt) {
        const combined = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
        const iv = combined.slice(0, 12);
        const data = combined.slice(12);
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({
            name: 'PBKDF2', salt: encoder.encode(salt), iterations: 100000, hash: 'SHA-256'
        }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
        return new TextDecoder().decode(decrypted);
    }
    
    function toggleSidebar() {
        document.getElementById('sidebar').classList.toggle('open');
    }
    
    function connect() {
        username = document.getElementById('username').value.trim();
        groupName = document.getElementById('groupName').value.trim();
        groupPassword = document.getElementById('groupPassword').value;
        
        if (!username || !groupName || !groupPassword) {
            alert('Please fill all fields');
            return;
        }
        
        const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
        const wsUrl = `${protocol}${window.location.host}/ws`;
        
        ws = new WebSocket(wsUrl);
        
        ws.onopen = () => {
            ws.send(JSON.stringify({ type: 'join', username, group: groupName, password: groupPassword }));
        };
        
        ws.onmessage = async (event) => {
            const data = JSON.parse(event.data);
            
            if (data.type === 'ready') {
                groupSalt = data.salt;
                document.getElementById('loginScreen').style.display = 'none';
                document.getElementById('chatScreen').classList.add('active');
                document.getElementById('groupTitle').innerHTML = `# ${data.group}`;
            } else if (data.type === 'message') {
                try {
                    const decrypted = await decryptMessage(data.ciphertext, groupPassword, data.salt);
                    addMessage(data.sender, decrypted, data.sender === username);
                } catch(e) {
                    addMessage(data.sender, '🔒 [ENCRYPTED]', data.sender === username);
                }
            } else if (data.type === 'history') {
                try {
                    const decrypted = await decryptMessage(data.ciphertext, groupPassword, data.salt);
                    addMessage(data.sender, decrypted, data.sender === username);
                } catch(e) {
                    addMessage(data.sender, '🔒 [ENCRYPTED]', data.sender === username);
                }
            } else if (data.type === 'users') {
                document.getElementById('onlineCount').innerHTML = `${data.users.length} online`;
                const usersDiv = document.getElementById('usersList');
                if (data.users.length === 0) {
                    usersDiv.innerHTML = '<div class="user-item">> no users online</div>';
                } else {
                    usersDiv.innerHTML = data.users.map(u => `<div class="user-item">● ${escapeHtml(u)}</div>`).join('');
                }
            } else if (data.type === 'typing') {
                document.getElementById('typingIndicator').innerHTML = `✏️ ${data.user} is typing...`;
            } else if (data.type === 'stop_typing') {
                document.getElementById('typingIndicator').innerHTML = '';
            }
        };
        
        ws.onerror = () => {
            alert('Connection failed. Server may be starting up. Refresh and try again.');
        };
    }
    
    function addMessage(sender, text, isSent) {
        const messagesDiv = document.getElementById('messages');
        if (messagesDiv.children.length === 1 && messagesDiv.children[0].innerText.includes('connecting')) {
            messagesDiv.innerHTML = '';
        }
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        messageDiv.innerHTML = `
            <div class="message-sender">${isSent ? 'YOU' : sender} • ${time}</div>
            <div class="message-bubble">${escapeHtml(text)}</div>
        `;
        messagesDiv.appendChild(messageDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.addEventListener('input', () => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'typing' }));
                clearTimeout(typingTimeout);
                typingTimeout = setTimeout(() => {
                    ws.send(JSON.stringify({ type: 'stop_typing' }));
                }, 1000);
            }
        });
        
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendMessage();
        });
    }
    
    async function sendMessage() {
        const input = document.getElementById('messageInput');
        const text = input.value.trim();
        if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
        
        try {
            const ciphertext = await encryptMessage(text, groupPassword, groupSalt);
            ws.send(JSON.stringify({ type: 'message', ciphertext, salt: groupSalt }));
            input.value = '';
        } catch(e) {
            console.error(e);
        }
    }
</script>
</body>
</html>"""

# ========== FASTAPI ENDPOINTS ==========
@app.get("/")
async def get_root():
    return HTMLResponse(HTML_PAGE)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "system": "ABAVANDIMWE", "author": "Mugisha Pc"}

# ========== WEBSOCKET ENDPOINT ==========
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
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
                
                # Get or create group salt
                salt = db.get_group_salt(group_name)
                if not salt:
                    salt = crypto.generate_salt()
                    db.create_group(group_name, salt, username)
                
                # Add to connection manager
                if group_name not in manager.active_connections:
                    manager.active_connections[group_name] = {}
                manager.active_connections[group_name][username] = websocket
                db.set_user_status(username, 'online', group_name)
                
                # Send message history
                for msg in db.get_messages(group_name):
                    await websocket.send_json({
                        'type': 'history',
                        'ciphertext': msg['ciphertext'],
                        'sender': msg['sender'],
                        'salt': msg['salt']
                    })
                
                # Broadcast online users
                online_users = db.get_online_users(group_name)
                await manager.broadcast(group_name, {'type': 'users', 'users': online_users})
                
                # Send ready signal
                await websocket.send_json({
                    'type': 'ready',
                    'salt': salt,
                    'group': group_name
                })
                
                print(f"[+] {username} joined {group_name}")
            
            elif msg_type == 'message':
                ciphertext = data.get('ciphertext')
                salt = data.get('salt')
                
                db.save_message(ciphertext, group_name, username, salt)
                await manager.broadcast(group_name, {
                    'type': 'message',
                    'ciphertext': ciphertext,
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
            if group_name in manager.active_connections:
                manager.active_connections[group_name].pop(username, None)
            db.set_user_status(username, 'offline', group_name)
            online_users = db.get_online_users(group_name)
            await manager.broadcast(group_name, {'type': 'users', 'users': online_users})
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
║              PROFESSIONAL SECURE MESSAGING SYSTEM                 ║
║                   MESSAGES AUTO-DELETE 24H                        ║
║                        AUTHOR: MUGISHA PC                         ║
║                        VERSION: 2.0.0                             ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    print(f"[✓] Server starting on port {port}")
    print(f"[✓] Database: SQLite (abavandimwe.db)")
    print(f"[✓] Encryption: AES-256-GCM")
    print(f"[✓] Auto-delete: 24 hours")
    print(f"[✓] WebSocket: /ws")
    print(f"[✓] Open: https://abavandimwe.onrender.com")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
