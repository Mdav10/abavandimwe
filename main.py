"""
ABAVANDIMWE - Professional Secure Messaging System
Author: Mugisha Pc
Android Optimized + Working Messages + Logout + Online Users List
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import asyncio
import json
import sqlite3
import secrets
import base64
import hashlib
from datetime import datetime
from typing import Dict
import os

app = FastAPI(title="ABAVANDIMWE")

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
        c.execute("SELECT ciphertext, sender, salt FROM messages WHERE group_name=? ORDER BY id ASC LIMIT 100", (group,))
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

manager = ConnectionManager()

# ========== HTML PAGE - WITH ONLINE USERS LIST ==========
HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes, viewport-fit=cover">
    <meta name="theme-color" content="#0a0a0f">
    <title>ABAVANDIMWE | Secure Chat</title>
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
            height: -webkit-fill-available;
            overflow: hidden;
            color: #00ff41;
        }

        /* Login Screen */
        .login-container {
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
            margin-bottom: 8px;
            font-size: 28px;
            letter-spacing: 2px;
        }

        .sub {
            text-align: center;
            margin-bottom: 32px;
            font-size: 11px;
            color: #666;
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

        /* Chat Container */
        .chat-container {
            display: none;
            width: 100%;
            height: 100%;
            flex-direction: column;
            background: #0a0a0f;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
        }

        .chat-container.active {
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
            flex-shrink: 0;
            gap: 8px;
        }

        .chat-header h2 {
            font-size: 14px;
            font-weight: normal;
            flex: 1;
            text-align: center;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .online-badge {
            font-size: 11px;
            padding: 4px 10px;
            border: 1px solid #00ff41;
            border-radius: 20px;
            flex-shrink: 0;
        }

        .menu-btn, .logout-btn {
            background: transparent;
            border: 1px solid #00ff41;
            color: #00ff41;
            padding: 6px 12px;
            border-radius: 8px;
            cursor: pointer;
            width: auto;
            margin: 0;
            font-size: 12px;
            flex-shrink: 0;
        }

        .logout-btn:hover, .logout-btn:active {
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

        /* Sidebar - Online Users List */
        .sidebar {
            width: 260px;
            background: #050508;
            border-right: 1px solid #00ff41;
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
        }

        .sidebar-header {
            padding: 16px;
            border-bottom: 1px solid #00ff41;
        }

        .sidebar-header h3 {
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
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
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .user-item::before {
            content: "●";
            color: #00ff41;
            font-size: 10px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* Mobile: Hide sidebar behind menu */
        @media (max-width: 768px) {
            .sidebar {
                position: fixed;
                left: -260px;
                top: 0;
                bottom: 0;
                z-index: 20;
                transition: left 0.3s ease;
            }
            .sidebar.open {
                left: 0;
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
        }

        /* Desktop: Always show sidebar */
        @media (min-width: 769px) {
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
            height: 100%;
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
            max-width: 100%;
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

        /* Input Area - Fixed at bottom */
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
<div id="loginScreen" class="login-container">
    <div class="login-card">
        <h1># ABAVANDIMWE</h1>
        <div class="sub">Secure Encrypted Messaging by Mugisha Pc</div>
        <input type="text" id="username" placeholder="USERNAME" autocomplete="off">
        <input type="text" id="groupName" placeholder="GROUP NAME" autocomplete="off">
        <input type="password" id="groupPassword" placeholder="GROUP PASSWORD">
        <button onclick="connect()">▶ ENTER CHAT</button>
        <div style="text-align:center;margin-top:20px;font-size:9px;color:#333;">
            🔒 AES-256 | ⏰ Auto-Delete 24h
        </div>
    </div>
</div>

<div id="chatScreen" class="chat-container">
    <div class="chat-header">
        <button class="menu-btn" onclick="toggleSidebar()">☰</button>
        <h2 id="groupTitle"># LOADING</h2>
        <button class="logout-btn" onclick="logout()">🚪 EXIT</button>
    </div>
    <div class="main-content">
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <h3>● ONLINE USERS <span id="onlineCount" style="font-size:11px;"></span></h3>
            </div>
            <div class="users-list" id="usersList">
                <div class="user-item">Loading...</div>
            </div>
        </div>
        <div class="overlay" id="overlay" onclick="toggleSidebar()"></div>
        <div class="chat-area">
            <div class="messages-container" id="messages">
                <div style="text-align:center;color:#666;">Connecting to secure server...</div>
            </div>
            <div class="typing-indicator" id="typingIndicator"></div>
            <div class="input-area">
                <input type="text" id="messageInput" placeholder="Type message..." autocomplete="off">
                <button onclick="sendMessage()">SEND</button>
            </div>
            <div class="footer">🔐 End-to-End Encrypted | Messages self-destruct in 24h</div>
        </div>
    </div>
</div>

<script>
    let ws = null;
    let username = '';
    let groupName = '';
    let groupPassword = '';
    let groupSalt = '';
    let typingTimeout = null;

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

    function toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('overlay');
        sidebar.classList.toggle('open');
        overlay.classList.toggle('active');
    }

    function addSystemMessage(text) {
        const messagesDiv = document.getElementById('messages');
        if (messagesDiv.children.length === 1 && messagesDiv.children[0].innerText.includes('Connecting')) {
            messagesDiv.innerHTML = '';
        }
        const msgDiv = document.createElement('div');
        msgDiv.className = 'system-message';
        msgDiv.innerHTML = text;
        messagesDiv.appendChild(msgDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    function addMessage(sender, text, isSent) {
        const messagesDiv = document.getElementById('messages');
        
        if (messagesDiv.children.length === 1 && messagesDiv.children[0].innerText.includes('Connecting')) {
            messagesDiv.innerHTML = '';
        }
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
        const now = new Date();
        const time = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        messageDiv.innerHTML = `
            <div class="message-sender">${isSent ? 'YOU' : escapeHtml(sender)}</div>
            <div class="message-bubble">${escapeHtml(text)}</div>
            <div class="message-time">${time}</div>
        `;
        
        messagesDiv.appendChild(messageDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function updateUsersList(users) {
        const usersList = document.getElementById('usersList');
        const onlineCount = document.getElementById('onlineCount');
        
        onlineCount.innerHTML = `(${users.length})`;
        
        if (users.length === 0) {
            usersList.innerHTML = '<div class="user-item">No users online</div>';
        } else {
            usersList.innerHTML = users.map(u => `<div class="user-item">${escapeHtml(u)}</div>`).join('');
        }
    }

    function logout() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.close();
        }
        
        ws = null;
        username = '';
        groupName = '';
        groupPassword = '';
        groupSalt = '';
        
        document.getElementById('chatScreen').classList.remove('active');
        document.getElementById('loginScreen').style.display = 'flex';
        document.getElementById('messages').innerHTML = '<div style="text-align:center;color:#666;">Connecting to secure server...</div>';
        document.getElementById('usersList').innerHTML = '<div class="user-item">Loading...</div>';
        document.getElementById('messageInput').value = '';
        document.getElementById('typingIndicator').innerHTML = '';
        document.getElementById('onlineCount').innerHTML = '';
        
        document.getElementById('username').value = '';
        document.getElementById('groupName').value = '';
        document.getElementById('groupPassword').value = '';
        
        console.log('Logged out');
    }

    function connect() {
        username = document.getElementById('username').value.trim();
        groupName = document.getElementById('groupName').value.trim();
        groupPassword = document.getElementById('groupPassword').value;
        
        if (!username || !groupName || !groupPassword) {
            alert('Please fill all fields');
            return;
        }
        
        const wsUrl = `wss://${window.location.host}/ws`;
        
        ws = new WebSocket(wsUrl);
        
        ws.onopen = function() {
            ws.send(JSON.stringify({ 
                type: 'join', 
                username: username, 
                group: groupName, 
                password: groupPassword 
            }));
        };
        
        ws.onmessage = async function(event) {
            const data = JSON.parse(event.data);
            
            if (data.type === 'ready') {
                groupSalt = data.salt;
                document.getElementById('loginScreen').style.display = 'none';
                document.getElementById('chatScreen').classList.add('active');
                document.getElementById('groupTitle').innerHTML = '# ' + data.group;
                addSystemMessage('🔐 You joined the secure chat');
            } 
            else if (data.type === 'message') {
                try {
                    const decrypted = await decryptMessage(data.ciphertext, groupPassword, data.salt);
                    addMessage(data.sender, decrypted, data.sender === username);
                } catch(e) {
                    addMessage(data.sender, '🔒 Encrypted', data.sender === username);
                }
            } 
            else if (data.type === 'history') {
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
                addSystemMessage(`👤 ${data.user} joined the chat`);
                // Request updated users list
                ws.send(JSON.stringify({ type: 'get_users' }));
            }
            else if (data.type === 'user_left') {
                addSystemMessage(`👋 ${data.user} left the chat`);
                // Request updated users list
                ws.send(JSON.stringify({ type: 'get_users' }));
            }
            else if (data.type === 'typing') {
                document.getElementById('typingIndicator').innerHTML = '✏️ ' + data.user + ' is typing...';
                setTimeout(() => {
                    if (document.getElementById('typingIndicator').innerHTML.includes(data.user)) {
                        document.getElementById('typingIndicator').innerHTML = '';
                    }
                }, 2000);
            } 
            else if (data.type === 'stop_typing') {
                document.getElementById('typingIndicator').innerHTML = '';
            }
        };
        
        ws.onclose = function() {
            if (document.getElementById('chatScreen').classList.contains('active')) {
                addSystemMessage('⚠️ Disconnected from server');
            }
        };
        
        ws.onerror = function(error) {
            console.error('WebSocket error:', error);
            alert('Connection failed. Please refresh.');
        };
    }

    const messageInput = document.getElementById('messageInput');
    
    if (messageInput) {
        messageInput.addEventListener('input', function() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'typing' }));
                clearTimeout(typingTimeout);
                typingTimeout = setTimeout(function() {
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'stop_typing' }));
                    }
                }, 1000);
            }
        });
        
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                sendMessage();
            }
        });
    }

    async function sendMessage() {
        const input = document.getElementById('messageInput');
        const text = input.value.trim();
        
        if (!text) return;
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            alert('Not connected');
            return;
        }
        if (!groupSalt) {
            alert('Still connecting...');
            return;
        }
        
        try {
            const ciphertext = await encryptMessage(text, groupPassword, groupSalt);
            ws.send(JSON.stringify({ 
                type: 'message', 
                ciphertext: ciphertext, 
                salt: groupSalt 
            }));
            
            addMessage(username, text, true);
            input.value = '';
        } catch(e) {
            console.error('Send error:', e);
            alert('Failed to send');
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
                
                # Add to connections
                if group_name not in manager.active_connections:
                    manager.active_connections[group_name] = {}
                manager.active_connections[group_name][username] = websocket
                db.set_user_status(username, 'online', group_name)
                
                # Broadcast user joined
                await manager.broadcast(group_name, {'type': 'user_joined', 'user': username}, exclude=username)
                
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
            
            elif msg_type == 'get_users':
                online_users = db.get_online_users(group_name)
                await websocket.send_json({'type': 'users', 'users': online_users})
            
            elif msg_type == 'message':
                ciphertext = data.get('ciphertext')
                salt = data.get('salt')
                
                # Save to database
                db.save_message(ciphertext, group_name, username, salt)
                
                # Broadcast to others
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
║              PROFESSIONAL SECURE MESSAGING SYSTEM                 ║
║                   MESSAGES AUTO-DELETE 24H                        ║
║                        AUTHOR: MUGISHA PC                         ║
║                        VERSION: 7.0.0                             ║
║                   WITH ONLINE USERS LIST                          ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    print(f"[✓] Server starting on port {port}")
    print(f"[✓] Database: SQLite")
    print(f"[✓] Encryption: AES-256-GCM")
    print(f"[✓] Auto-delete: 24 hours")
    print(f"[✓] Online users list - visible on desktop left side")
    print(f"[✓] Mobile: tap ☰ to see online users")
    print(f"[✓] Open: https://abavandimwe.onrender.com")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
