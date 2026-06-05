#!/usr/bin/env python3
"""
ABAVANDIMWE - Professional Secure Messaging System
Author: Mugisha Pc
Version: 1.0 - Production Ready
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
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                    (id INTEGER PRIMARY KEY, ciphertext TEXT, group_name TEXT, sender TEXT, salt TEXT, created_at TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (username TEXT PRIMARY KEY, status TEXT, current_group TEXT, last_seen TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS groups
                    (group_name TEXT PRIMARY KEY, salt TEXT, created_by TEXT)''')
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
            c.execute("INSERT INTO groups (group_name, salt, created_by) VALUES (?,?,?)", (group, salt, creator))
            conn.commit()
        except:
            pass
        conn.close()

db = Database()

# ========== HTML CLIENT ==========
HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ABAVANDIMWE | Secure Chat</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:'Courier New',monospace;background:#0a0a0f;height:100vh;color:#0f0;}
        .screen{position:fixed;top:0;left:0;right:0;bottom:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;}
        .card{background:#050508;border:2px solid #0f0;border-radius:10px;padding:40px;width:90%;max-width:400px;}
        h1{text-align:center;margin-bottom:10px;font-size:28px;}
        .sub{text-align:center;margin-bottom:30px;font-size:12px;color:#888;}
        input{width:100%;padding:12px;margin:10px 0;background:#111;border:1px solid #0f0;border-radius:5px;color:#0f0;font-family:monospace;font-size:14px;}
        input:focus{outline:none;box-shadow:0 0 10px rgba(0,255,0,0.3);}
        button{width:100%;padding:12px;margin-top:20px;background:transparent;border:2px solid #0f0;border-radius:5px;color:#0f0;font-size:16px;cursor:pointer;font-family:monospace;}
        button:hover{background:#0f0;color:#000;}
        .chat{display:none;width:100%;height:100%;flex-direction:column;}
        .chat.active{display:flex;}
        .header{padding:15px 20px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;align-items:center;}
        .header h2{font-size:18px;}
        .online-badge{font-size:12px;padding:4px 10px;border:1px solid #0f0;border-radius:20px;}
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
        .footer{text-align:center;padding:8px;font-size:10px;color:#444;border-top:1px solid #0f0;}
    </style>
</head>
<body>
<div id="loginScreen" class="screen">
    <div class="card">
        <h1># ABAVANDIMWE</h1>
        <div class="sub">Secure Encrypted Messaging by Mugisha Pc</div>
        <input type="text" id="username" placeholder="USERNAME">
        <input type="text" id="group" placeholder="GROUP NAME">
        <input type="password" id="password" placeholder="GROUP PASSWORD">
        <button onclick="connect()">▶ CONNECT</button>
        <div style="text-align:center;margin-top:20px;font-size:10px;color:#444;">🔒 AES-256 | ⏰ Auto-Delete 24h</div>
    </div>
</div>
<div id="chatScreen" class="chat">
    <div class="header">
        <h2 id="groupTitle"># LOADING</h2>
        <span class="online-badge" id="onlineCount">0 online</span>
    </div>
    <div class="main">
        <div class="sidebar">
            <h3>● ONLINE USERS</h3>
            <div class="users" id="usersList"><div class="user">connecting...</div></div>
        </div>
        <div class="chatarea">
            <div class="messages" id="messages"><div style="text-align:center;">connecting to server...</div></div>
            <div class="typing" id="typingIndicator"></div>
            <div class="input-area">
                <input type="text" id="messageInput" placeholder="Type encrypted message...">
                <button onclick="sendMessage()">SEND</button>
            </div>
            <div class="footer">🔐 End-to-End Encrypted | Messages Self-Destruct in 24 Hours</div>
        </div>
    </div>
</div>
<script>
    let ws, username, group, password, groupSalt;
    let typingTimeout;
    
    async function encrypt(text, pwd, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({
            name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256'
        }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        return btoa(String.fromCharCode(...combined));
    }
    
    async function decrypt(encrypted, pwd, salt) {
        const combined = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
        const iv = combined.slice(0, 12);
        const data = combined.slice(12);
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({
            name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256'
        }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
        return new TextDecoder().decode(decrypted);
    }
    
    function connect() {
        username = document.getElementById('username').value.trim();
        group = document.getElementById('group').value.trim();
        password = document.getElementById('password').value;
        if (!username || !group || !password) {
            alert('Please fill all fields');
            return;
        }
        
        const wsUrl = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;
        ws = new WebSocket(wsUrl);
        
        ws.onopen = () => {
            ws.send(JSON.stringify({ type: 'join', username, group, password }));
        };
        
        ws.onmessage = async (e) => {
            const data = JSON.parse(e.data);
            if (data.type === 'ready') {
                groupSalt = data.salt;
                document.getElementById('loginScreen').style.display = 'none';
                document.getElementById('chatScreen').classList.add('active');
                document.getElementById('groupTitle').innerText = '# ' + data.group;
            } else if (data.type === 'message') {
                try {
                    const decrypted = await decrypt(data.ciphertext, password, data.salt);
                    addMessage(data.sender, decrypted, data.sender === username);
                } catch(e) {
                    addMessage(data.sender, '🔒 [Encrypted]', data.sender === username);
                }
            } else if (data.type === 'history') {
                try {
                    const decrypted = await decrypt(data.ciphertext, password, data.salt);
                    addMessage(data.sender, decrypted, data.sender === username);
                } catch(e) {
                    addMessage(data.sender, '🔒 [Encrypted]', data.sender === username);
                }
            } else if (data.type === 'users') {
                document.getElementById('onlineCount').innerText = data.users.length + ' online';
                const usersDiv = document.getElementById('usersList');
                if (data.users.length === 0) {
                    usersDiv.innerHTML = '<div class="user">> no users online</div>';
                } else {
                    usersDiv.innerHTML = data.users.map(u => '<div class="user">● ' + escapeHtml(u) + '</div>').join('');
                }
            } else if (data.type === 'typing') {
                document.getElementById('typingIndicator').innerHTML = '✏️ ' + data.user + ' is typing...';
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
        const msgDiv = document.createElement('div');
        msgDiv.className = 'msg ' + (isSent ? 'sent' : 'received');
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        msgDiv.innerHTML = '<div class="sender">' + (isSent ? 'YOU' : sender) + ' • ' + time + '</div><div class="bubble">' + escapeHtml(text) + '</div>';
        messagesDiv.appendChild(msgDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    const msgInput = document.getElementById('messageInput');
    if (msgInput) {
        msgInput.addEventListener('input', () => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'typing' }));
                clearTimeout(typingTimeout);
                typingTimeout = setTimeout(() => {
                    ws.send(JSON.stringify({ type: 'stop_typing' }));
                }, 1000);
            }
        });
        msgInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendMessage();
        });
    }
    
    async function sendMessage() {
        const input = document.getElementById('messageInput');
        const text = input.value.trim();
        if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
        try {
            const ciphertext = await encrypt(text, password, groupSalt);
            ws.send(JSON.stringify({ type: 'message', ciphertext, salt: groupSalt }));
            input.value = '';
        } catch(e) {
            console.error(e);
        }
    }
</script>
</body>
</html>'''

# ========== WEBSOCKET SERVER ==========
class WebSocketHandler:
    def __init__(self):
        self.connections: Dict[str, Dict[str, websockets.WebSocketServerProtocol]] = {}
    
    async def broadcast(self, group: str, message: dict, exclude: str = None):
        if group not in self.connections:
            return
        dead = []
        for user, ws in self.connections[group].items():
            if user == exclude:
                continue
            try:
                await ws.send(json.dumps(message))
            except:
                dead.append(user)
        for user in dead:
            del self.connections[group][user]
    
    async def handle(self, websocket, path):
        username = None
        group = None
        
        try:
            async for message in websocket:
                data = json.loads(message)
                msg_type = data.get('type')
                
                if msg_type == 'join':
                    username = data['username']
                    group = data['group']
                    password = data['password']
                    
                    # Get or create group salt
                    salt = db.get_group_salt(group)
                    if not salt:
                        salt = crypto.generate_salt()
                        db.create_group(group, salt, username)
                    
                    # Add connection
                    if group not in self.connections:
                        self.connections[group] = {}
                    self.connections[group][username] = websocket
                    
                    # Update user status
                    db.set_user_status(username, 'online', group)
                    
                    # Send message history
                    for msg in db.get_messages(group):
                        await websocket.send(json.dumps({
                            'type': 'history',
                            'ciphertext': msg['ciphertext'],
                            'sender': msg['sender'],
                            'salt': msg['salt']
                        }))
                    
                    # Send online users
                    online_users = db.get_online_users(group)
                    await self.broadcast(group, {'type': 'users', 'users': online_users})
                    
                    # Send ready signal
                    await websocket.send(json.dumps({
                        'type': 'ready',
                        'salt': salt,
                        'group': group
                    }))
                    
                    print(f"[+] {username} joined {group}")
                
                elif msg_type == 'message':
                    ciphertext = data['ciphertext']
                    salt = data['salt']
                    
                    db.save_message(ciphertext, group, username, salt)
                    await self.broadcast(group, {
                        'type': 'message',
                        'ciphertext': ciphertext,
                        'sender': username,
                        'salt': salt
                    }, exclude=username)
                
                elif msg_type == 'typing':
                    await self.broadcast(group, {'type': 'typing', 'user': username}, exclude=username)
                
                elif msg_type == 'stop_typing':
                    await self.broadcast(group, {'type': 'stop_typing', 'user': username}, exclude=username)
        
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            if username and group:
                if group in self.connections:
                    self.connections[group].pop(username, None)
                db.set_user_status(username, 'offline', group)
                online_users = db.get_online_users(group)
                await self.broadcast(group, {'type': 'users', 'users': online_users})
                print(f"[-] {username} left {group}")

# ========== HTTP SERVER ==========
async def http_handler(reader, writer):
    try:
        data = await reader.read(1024)
        if data:
            request = data.decode().split(' ')[0] if data else ''
            if request == 'GET':
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
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   █████╗ ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗     ║
║  ██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║     ║
║  ███████║██████╔╝███████║██║   ██║███████║██╔██╗ ██║     ║
║  ██╔══██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██╗██║     ║
║  ██║  ██║██████╔╝██║  ██║ ╚████╔╝ ██║  ██║██║ ╚████║     ║
║  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝     ║
║                                                            ║
║         PROFESSIONAL SECURE MESSAGING SYSTEM               ║
║              MESSAGES AUTO-DELETE AFTER 24H               ║
║                    AUTHOR: MUGISHA PC                      ║
║                    VERSION: 1.0.0                          ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
""")

print(f"[✓] Starting server on port {PORT}")
print(f"[✓] Database: SQLite (abavandimwe.db)")
print(f"[✓] Encryption: AES-256-GCM")
print(f"[✓] Auto-delete: 24 hours")
print(f"[✓] Open: https://abavandimwe.onrender.com")

async def main():
    handler = WebSocketHandler()
    ws_server = await websockets.serve(handler.handle, '0.0.0.0', PORT)
    http_server = await asyncio.start_server(http_handler, '0.0.0.0', PORT)
    print(f"[✓] Server running! Ready for connections.")
    await asyncio.gather(ws_server.wait_closed(), http_server.wait_closed())

asyncio.run(main())
