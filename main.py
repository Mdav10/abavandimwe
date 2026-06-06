"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
Complete Working Version - Clean UI
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

# ========== HTML - CLEAN WORKING VERSION ==========
HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
    <title>ABAVANDIMWE</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, sans-serif;
            background: #0a0a0f;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* Login */
        .login-container {
            flex: 1;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }

        .login-card {
            background: #0d1117;
            border: 1px solid #00ff41;
            border-radius: 16px;
            padding: 32px 24px;
            width: 100%;
            max-width: 360px;
        }

        .login-card h1 {
            color: #00ff41;
            font-size: 24px;
            text-align: center;
            margin-bottom: 8px;
        }

        .login-card p {
            color: #666;
            font-size: 12px;
            text-align: center;
            margin-bottom: 32px;
        }

        .login-card input {
            width: 100%;
            padding: 12px 14px;
            margin: 8px 0;
            background: #1a1a2e;
            border: 1px solid #2a2a3e;
            border-radius: 10px;
            color: #00ff41;
            font-size: 14px;
        }

        .login-card input:focus {
            outline: none;
            border-color: #00ff41;
        }

        .login-card button {
            width: 100%;
            padding: 12px;
            margin-top: 16px;
            background: #00ff41;
            border: none;
            border-radius: 10px;
            color: #000;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
        }

        .login-card button:active {
            opacity: 0.8;
        }

        .error {
            color: #ff4444;
            font-size: 12px;
            text-align: center;
            margin-top: 12px;
        }

        /* Chat */
        .chat-container {
            display: none;
            flex: 1;
            flex-direction: column;
            background: #0a0a0f;
        }

        .chat-container.active {
            display: flex;
        }

        /* Header */
        .chat-header {
            background: #0d1117;
            border-bottom: 1px solid #1a1a2e;
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .chat-header h3 {
            color: #00ff41;
            font-size: 16px;
            font-weight: 500;
        }

        .exit-btn {
            background: transparent;
            border: 1px solid #ff4444;
            color: #ff4444;
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 12px;
            cursor: pointer;
        }

        /* Main Area */
        .main-area {
            flex: 1;
            display: flex;
            overflow: hidden;
        }

        /* Sidebar - Online Users */
        .sidebar {
            width: 220px;
            background: #0d1117;
            border-right: 1px solid #1a1a2e;
            display: flex;
            flex-direction: column;
        }

        .sidebar h4 {
            color: #888;
            font-size: 11px;
            font-weight: 500;
            padding: 12px 16px;
            border-bottom: 1px solid #1a1a2e;
        }

        .users-list {
            flex: 1;
            padding: 8px;
            overflow-y: auto;
        }

        .user {
            padding: 8px 12px;
            margin: 4px 0;
            background: #1a1a2e;
            border-radius: 8px;
            color: #ccc;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .user::before {
            content: "●";
            color: #00ff41;
            font-size: 8px;
        }

        /* Chat Area */
        .chat-area {
            flex: 1;
            display: flex;
            flex-direction: column;
        }

        /* Messages */
        .messages {
            flex: 1;
            padding: 16px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .message {
            max-width: 75%;
            display: flex;
            flex-direction: column;
        }

        .message.sent {
            align-self: flex-end;
        }

        .message.received {
            align-self: flex-start;
        }

        .bubble {
            padding: 8px 12px;
            border-radius: 16px;
            font-size: 14px;
            line-height: 1.4;
        }

        .message.sent .bubble {
            background: #00ff41;
            color: #000;
        }

        .message.received .bubble {
            background: #1a1a2e;
            color: #e0e0e0;
        }

        .sender {
            font-size: 10px;
            margin-bottom: 4px;
            color: #888;
            padding-left: 4px;
        }

        .time {
            font-size: 9px;
            margin-top: 4px;
            color: #555;
            padding-left: 4px;
        }

        .system-msg {
            text-align: center;
            font-size: 11px;
            color: #ffaa00;
            margin: 8px 0;
        }

        /* Typing */
        .typing {
            padding: 6px 16px;
            color: #00ff41;
            font-size: 11px;
            font-style: italic;
            min-height: 28px;
        }

        /* Input */
        .input-area {
            padding: 12px 16px;
            background: #0d1117;
            border-top: 1px solid #1a1a2e;
            display: flex;
            gap: 10px;
        }

        .input-area input {
            flex: 1;
            padding: 10px 14px;
            background: #1a1a2e;
            border: 1px solid #2a2a3e;
            border-radius: 20px;
            color: #00ff41;
            font-size: 14px;
        }

        .input-area input:focus {
            outline: none;
            border-color: #00ff41;
        }

        .input-area button {
            background: #00ff41;
            border: none;
            border-radius: 20px;
            color: #000;
            padding: 10px 20px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
        }

        /* Mobile */
        @media (max-width: 768px) {
            .sidebar {
                display: none;
            }
            .message {
                max-width: 85%;
            }
        }

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

<!-- Login Screen -->
<div id="loginScreen" class="login-container">
    <div class="login-card">
        <h1>ABAVANDIMWE</h1>
        <p>Secure Messaging by Mugisha Pc</p>
        <input type="text" id="username" placeholder="Username">
        <input type="text" id="groupName" placeholder="Group name">
        <input type="password" id="groupPassword" placeholder="Group password">
        <button onclick="connect()">Connect</button>
        <div id="errorMsg" class="error"></div>
    </div>
</div>

<!-- Chat Screen -->
<div id="chatScreen" class="chat-container">
    <div class="chat-header">
        <h3 id="groupTitle">Loading...</h3>
        <button class="exit-btn" onclick="logout()">Exit</button>
    </div>
    <div class="main-area">
        <div class="sidebar">
            <h4>ONLINE USERS</h4>
            <div class="users-list" id="usersList"></div>
        </div>
        <div class="chat-area">
            <div class="messages" id="messages"></div>
            <div class="typing" id="typingIndicator"></div>
            <div class="input-area">
                <input type="text" id="messageInput" placeholder="Type a message...">
                <button onclick="sendMessage()">Send</button>
            </div>
        </div>
    </div>
</div>

<script>
    let ws, username, groupName, groupPassword, groupSalt, typingTimeout;

    async function encryptMessage(text, password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({
            name: 'PBKDF2',
            salt: encoder.encode(salt),
            iterations: 100000,
            hash: 'SHA-256'
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
            name: 'PBKDF2',
            salt: encoder.encode(salt),
            iterations: 100000,
            hash: 'SHA-256'
        }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
        return new TextDecoder().decode(decrypted);
    }

    function addSystemMessage(text) {
        const messagesDiv = document.getElementById('messages');
        if (messagesDiv.children.length === 0 || (messagesDiv.children.length === 1 && messagesDiv.children[0].innerText.includes('Connecting'))) {
            messagesDiv.innerHTML = '';
        }
        const div = document.createElement('div');
        div.className = 'system-msg';
        div.innerText = text;
        messagesDiv.appendChild(div);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    function addMessage(sender, text, isSent) {
        const messagesDiv = document.getElementById('messages');
        if (messagesDiv.children.length === 0 || (messagesDiv.children.length === 1 && messagesDiv.children[0].innerText.includes('Connecting'))) {
            messagesDiv.innerHTML = '';
        }
        const div = document.createElement('div');
        div.className = `message ${isSent ? 'sent' : 'received'}`;
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        div.innerHTML = `
            <div class="sender">${isSent ? 'You' : sender}</div>
            <div class="bubble">${escapeHtml(text)}</div>
            <div class="time">${time}</div>
        `;
        messagesDiv.appendChild(div);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function updateUsersList(users) {
        const usersDiv = document.getElementById('usersList');
        if (users.length === 0) {
            usersDiv.innerHTML = '<div style="color:#666; padding:8px;">No users online</div>';
        } else {
            usersDiv.innerHTML = users.map(u => `<div class="user">${escapeHtml(u)}</div>`).join('');
        }
    }

    function logout() {
        if (ws) ws.close();
        ws = null;
        document.getElementById('chatScreen').classList.remove('active');
        document.getElementById('loginScreen').style.display = 'flex';
        document.getElementById('messages').innerHTML = '';
        document.getElementById('username').value = '';
        document.getElementById('groupName').value = '';
        document.getElementById('groupPassword').value = '';
    }

    function connect() {
        username = document.getElementById('username').value.trim();
        groupName = document.getElementById('groupName').value.trim();
        groupPassword = document.getElementById('groupPassword').value;

        if (!username || !groupName || !groupPassword) {
            document.getElementById('errorMsg').innerText = 'Fill all fields';
            return;
        }

        const wsUrl = `wss://${window.location.host}/ws`;
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            ws.send(JSON.stringify({ type: 'join', username, group: groupName, password: groupPassword }));
        };

        ws.onmessage = async (e) => {
            const data = JSON.parse(e.data);
            
            if (data.type === 'error') {
                document.getElementById('errorMsg').innerText = data.message;
                return;
            }
            
            if (data.type === 'ready') {
                groupSalt = data.salt;
                document.getElementById('loginScreen').style.display = 'none';
                document.getElementById('chatScreen').classList.add('active');
                document.getElementById('groupTitle').innerText = data.group;
                addSystemMessage('Connected - Messages last 24 hours');
            }
            else if (data.type === 'message' || data.type === 'history') {
                try {
                    const decrypted = await decryptMessage(data.ciphertext, groupPassword, data.salt);
                    addMessage(data.sender, decrypted, data.sender === username);
                } catch(e) {
                    addMessage(data.sender, '🔒 Encrypted', data.sender === username);
                }
            }
            else if (data.type === 'users') {
                updateUsersList(data.users);
            }
            else if (data.type === 'user_joined') {
                addSystemMessage(`👤 ${data.user} joined`);
            }
            else if (data.type === 'user_left') {
                addSystemMessage(`👋 ${data.user} left`);
            }
            else if (data.type === 'typing') {
                document.getElementById('typingIndicator').innerHTML = `✏️ ${data.user} is typing...`;
            }
            else if (data.type === 'stop_typing') {
                document.getElementById('typingIndicator').innerHTML = '';
            }
        };

        ws.onerror = () => {
            document.getElementById('errorMsg').innerText = 'Connection failed';
        };
    }

    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.addEventListener('input', () => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'typing' }));
                clearTimeout(typingTimeout);
                typingTimeout = setTimeout(() => {
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'stop_typing' }));
                    }
                }, 1000);
            }
        });
        
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                sendMessage();
            }
        });
    }

    async function sendMessage() {
        const input = document.getElementById('messageInput');
        const text = input.value.trim();
        
        if (!text || !ws || ws.readyState !== WebSocket.OPEN || !groupSalt) return;
        
        try {
            const ciphertext = await encryptMessage(text, groupPassword, groupSalt);
            ws.send(JSON.stringify({ type: 'message', ciphertext, salt: groupSalt }));
            addMessage(username, text, true);
            input.value = '';
        } catch(e) {
            console.error(e);
        }
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
║                    Author: Mugisha Pc                      ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    """)
    print(f"[✓] Server on port {port}")
    print(f"[✓] Messages last 24 hours then auto-delete")
    print(f"[✓] Open: https://abavandimwe.onrender.com")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
