#!/usr/bin/env python3
"""
ABAVANDIMWE - Complete Secure Messaging System
Author: Mugisha Pc
Single server handling HTTP + WebSocket on same port
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
# CRYPTO ENGINE
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
# DATABASE MANAGER
# ============================================

class Database:
    def __init__(self):
        self.db_path = "abavandimwe.db"
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ciphertext TEXT NOT NULL,
                group_name TEXT NOT NULL,
                sender TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT (datetime('now', '+24 hours'))
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                status TEXT DEFAULT 'offline',
                current_group TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                group_name TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    
    async def get_messages(self, group: str, limit: int = 100) -> List[dict]:
        def _get():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''SELECT ciphertext, sender, salt, created_at FROM messages 
                        WHERE group_name = ? AND created_at > datetime("now", "-24 hours") 
                        ORDER BY created_at ASC LIMIT ?''', (group, limit))
            rows = c.fetchall()
            conn.close()
            return [{'ciphertext': r[0], 'sender': r[1], 'salt': r[2], 'created_at': r[3]} for r in rows]
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
    
    async def get_online_users(self, group: str) -> List[str]:
        def _get():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('SELECT username FROM users WHERE status = "online" AND current_group = ? AND last_seen > datetime("now", "-2 minutes")', (group,))
            rows = c.fetchall()
            conn.close()
            return [r[0] for r in rows]
        return await asyncio.to_thread(_get)
    
    async def get_group_salt(self, group: str) -> Optional[str]:
        def _get():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('SELECT salt FROM groups WHERE group_name = ?', (group,))
            row = c.fetchone()
            conn.close()
            return row[0] if row else None
        return await asyncio.to_thread(_get)
    
    async def create_group(self, group: str, salt: str, creator: str) -> bool:
        def _create():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            try:
                c.execute('INSERT INTO groups (group_name, salt, created_by) VALUES (?, ?, ?)', (group, salt, creator))
                conn.commit()
                conn.close()
                return True
            except:
                conn.close()
                return False
        return await asyncio.to_thread(_create)
    
    async def cleanup_expired(self):
        def _clean():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('DELETE FROM messages WHERE expires_at < CURRENT_TIMESTAMP')
            deleted = c.rowcount
            conn.commit()
            conn.close()
            if deleted > 0:
                print(f"[INFO] Cleaned {deleted} expired messages")
        await asyncio.to_thread(_clean)
    
    async def start_cleaner(self):
        while True:
            await asyncio.sleep(3600)
            await self.cleanup_expired()
    
    async def connect(self):
        asyncio.create_task(self.start_cleaner())
        return self

db = Database()

# ============================================
# HTML PAGE
# ============================================

HTML_PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ABAVANDIMWE - Secure Messaging</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0f;
            height: 100vh;
            overflow: hidden;
            color: #00ff41;
        }
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
        }
        .login-card {
            background: #050508;
            border: 2px solid #00ff41;
            border-radius: 8px;
            padding: 40px;
            width: 90%;
            max-width: 450px;
            box-shadow: 0 0 40px rgba(0,255,65,0.3);
        }
        .logo { text-align: center; margin-bottom: 32px; }
        .logo h1 { font-size: 28px; color: #00ff41; letter-spacing: 4px; }
        .logo p { color: #888; font-size: 12px; margin-top: 8px; }
        .input-group { margin-bottom: 20px; }
        .input-group label { display: block; margin-bottom: 8px; color: #00ff41; font-size: 12px; }
        .input-group input {
            width: 100%;
            padding: 12px;
            background: rgba(0,0,0,0.5);
            border: 1px solid #00ff41;
            border-radius: 4px;
            color: #00ff41;
            font-family: monospace;
        }
        .input-group input:focus { outline: none; box-shadow: 0 0 10px rgba(0,255,65,0.3); }
        .btn-primary {
            width: 100%;
            padding: 12px;
            background: transparent;
            border: 2px solid #00ff41;
            border-radius: 4px;
            color: #00ff41;
            font-size: 16px;
            cursor: pointer;
        }
        .btn-primary:hover { background: #00ff41; color: #0a0a0f; }
        .chat-container { display: none; width: 100vw; height: 100vh; flex-direction: column; }
        .chat-container.active { display: flex; }
        .chat-header {
            padding: 16px;
            background: #050508;
            border-bottom: 1px solid #00ff41;
            display: flex;
            justify-content: space-between;
        }
        .chat-header h2 { font-size: 18px; }
        .main-content { flex: 1; display: flex; overflow: hidden; }
        .sidebar {
            width: 260px;
            background: #050508;
            border-right: 1px solid #00ff41;
            display: flex;
            flex-direction: column;
        }
        .sidebar-header { padding: 16px; border-bottom: 1px solid #00ff41; }
        .online-users { flex: 1; padding: 12px; overflow-y: auto; }
        .user-item {
            padding: 8px 12px;
            margin-bottom: 6px;
            border: 1px solid #00ff41;
            border-radius: 4px;
        }
        .chat-area { flex: 1; display: flex; flex-direction: column; }
        .messages {
            flex: 1;
            padding: 16px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .message { display: flex; flex-direction: column; max-width: 70%; }
        .message.sent { align-self: flex-end; }
        .message.received { align-self: flex-start; }
        .message-bubble {
            padding: 8px 14px;
            border-radius: 8px;
        }
        .message.sent .message-bubble { background: #00ff41; color: #0a0a0f; }
        .message.received .message-bubble { background: #1a1a2e; border: 1px solid #00ff41; }
        .message-sender { font-size: 10px; margin-bottom: 4px; }
        .typing-indicator { padding: 8px 16px; color: #00ff41; font-style: italic; font-size: 12px; }
        .input-area {
            padding: 16px;
            background: #050508;
            border-top: 1px solid #00ff41;
            display: flex;
            gap: 10px;
        }
        .input-area input {
            flex: 1;
            padding: 12px;
            background: rgba(0,0,0,0.5);
            border: 1px solid #00ff41;
            border-radius: 4px;
            color: #00ff41;
            font-family: monospace;
        }
        .input-area button {
            padding: 12px 24px;
            background: transparent;
            border: 1px solid #00ff41;
            border-radius: 4px;
            color: #00ff41;
            cursor: pointer;
        }
        .online-count { font-size: 12px; }
        @media (max-width: 768px) {
            .sidebar { position: fixed; left: -260px; top: 0; bottom: 0; z-index: 100; transition: left 0.3s; }
            .sidebar.open { left: 0; }
            .menu-btn { display: block; }
            .message { max-width: 90%; }
        }
        .menu-btn { display: none; background: transparent; border: 1px solid #00ff41; color: #00ff41; padding: 8px 12px; cursor: pointer; }
    </style>
</head>
<body>
    <div id="loginScreen" class="login-container">
        <div class="login-card">
            <div class="logo">
                <h1># ABAVANDIMWE</h1>
                <p>Secure Encrypted Messaging by Mugisha Pc</p>
            </div>
            <div class="input-group"><label>$ USERNAME</label><input type="text" id="username" placeholder="username"></div>
            <div class="input-group"><label>$ GROUP</label><input type="text" id="group" placeholder="group_name"></div>
            <div class="input-group"><label>$ PASSWORD</label><input type="password" id="password" placeholder="********"></div>
            <button class="btn-primary" onclick="connect()">>> CONNECT</button>
        </div>
    </div>
    <div id="chatContainer" class="chat-container">
        <div class="chat-header">
            <button class="menu-btn" onclick="toggleSidebar()">☰</button>
            <h2 id="groupName"># LOADING</h2>
            <div class="online-count" id="onlineCount">0 online</div>
        </div>
        <div class="main-content">
            <div class="sidebar" id="sidebar">
                <div class="sidebar-header"><h3>> ONLINE USERS</h3></div>
                <div class="online-users" id="usersList"><div>connecting...</div></div>
            </div>
            <div class="chat-area">
                <div class="messages" id="messages"><div style="text-align:center;">> connecting to secure server...</div></div>
                <div class="typing-indicator" id="typingIndicator"></div>
                <div class="input-area">
                    <input type="text" id="messageInput" placeholder="> type message...">
                    <button onclick="sendMessage()">SEND</button>
                </div>
            </div>
        </div>
    </div>
    <script>
        let ws, username, group, password, groupSalt, typingTimeout;
        
        async function encrypt(text, pwd, salt) {
            const encoder = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(pwd), 'PBKDF2', false, ['deriveKey']);
            const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:encoder.encode(salt), iterations:100000, hash:'SHA-256'}, keyMaterial, {name:'AES-GCM', length:256}, false, ['encrypt']);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, encoder.encode(text));
            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv,0); combined.set(new Uint8Array(encrypted), iv.length);
            return btoa(String.fromCharCode.apply(null, combined));
        }
        
        async function decrypt(encrypted, pwd, salt) {
            const combined = Uint8Array.from(atob(encrypted), c=>c.charCodeAt(0));
            const iv = combined.slice(0,12), ciphertext = combined.slice(12);
            const encoder = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(pwd), 'PBKDF2', false, ['deriveKey']);
            const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:encoder.encode(salt), iterations:100000, hash:'SHA-256'}, keyMaterial, {name:'AES-GCM', length:256}, false, ['decrypt']);
            const decrypted = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ciphertext);
            return new TextDecoder().decode(decrypted);
        }
        
        function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }
        
        function connect() {
            username = document.getElementById('username').value.trim();
            group = document.getElementById('group').value.trim();
            password = document.getElementById('password').value;
            
            if(!username||!group||!password){
                alert('All fields required');
                return;
            }
            
            // Use WebSocket on same host and port
            let wsUrl;
            if (window.location.protocol === 'https:') {
                wsUrl = `wss://${window.location.host}`;
            } else {
                wsUrl = `ws://${window.location.host}`;
            }
            
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function() {
                ws.send(JSON.stringify({type:'join', username, group, password}));
            };
            
            ws.onmessage = async function(e) {
                const data = JSON.parse(e.data);
                
                if(data.type==='ready'){
                    groupSalt = data.salt;
                    document.getElementById('loginScreen').style.display='none';
                    document.getElementById('chatContainer').classList.add('active');
                    document.getElementById('groupName').innerHTML = `# ${data.group}`;
                } else if(data.type==='message'){
                    try{ 
                        const decrypted = await decrypt(data.ciphertext, password, data.salt); 
                        addMessage(data.sender, decrypted, data.sender===username); 
                    } catch(e){ 
                        addMessage(data.sender, '🔒 ENCRYPTED', data.sender===username); 
                    }
                } else if(data.type==='history'){
                    try{ 
                        const decrypted = await decrypt(data.ciphertext, password, data.salt); 
                        addMessage(data.sender, decrypted, data.sender===username, true); 
                    } catch(e){ 
                        addMessage(data.sender, '🔒 ENCRYPTED', data.sender===username, true); 
                    }
                } else if(data.type==='users'){ 
                    updateUsers(data.users); 
                } else if(data.type==='typing'){ 
                    document.getElementById('typingIndicator').innerHTML = `✏️ ${data.user} is typing...`; 
                } else if(data.type==='stop_typing'){ 
                    document.getElementById('typingIndicator').innerHTML = ''; 
                }
            };
            
            ws.onerror = function(error) {
                alert('Connection failed. Server may be starting up. Refresh and try again.');
            };
        }
        
        function addMessage(sender, text, isSent){
            const messagesDiv = document.getElementById('messages');
            if(messagesDiv.children.length===1 && messagesDiv.children[0].innerText.includes('connecting')) messagesDiv.innerHTML='';
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
            const time = new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
            messageDiv.innerHTML = `<div class="message-sender">${isSent ? 'YOU' : sender}</div><div class="message-bubble">${escapeHtml(text)}<div style="font-size:9px;margin-top:4px;">${time}</div></div>`;
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        function updateUsers(users){
            document.getElementById('onlineCount').innerHTML = `${users.length} online`;
            const usersDiv = document.getElementById('usersList');
            if(users.length===0){ usersDiv.innerHTML = '<div class="user-item">> no users online</div>'; return; }
            usersDiv.innerHTML = users.map(u => `<div class="user-item"><div style="width:6px;height:6px;border-radius:50%;background:#00ff41;display:inline-block;margin-right:8px;"></div>${escapeHtml(u)}</div>`).join('');
        }
        
        function escapeHtml(text){ const div=document.createElement('div'); div.textContent=text; return div.innerHTML; }
        
        document.getElementById('messageInput')?.addEventListener('input',function(){
            if(ws && ws.readyState===WebSocket.OPEN){
                ws.send(JSON.stringify({type:'typing'}));
                clearTimeout(typingTimeout);
                typingTimeout = setTimeout(function(){ ws.send(JSON.stringify({type:'stop_typing'})); }, 1000);
            }
        });
        
        document.getElementById('messageInput')?.addEventListener('keypress',function(e){ if(e.key==='Enter') sendMessage(); });
        
        async function sendMessage(){
            const input = document.getElementById('messageInput'), text = input.value.trim();
            if(!text||!ws||ws.readyState!==WebSocket.OPEN) return;
            try{
                const ciphertext = await encrypt(text, password, groupSalt);
                ws.send(JSON.stringify({type:'message', ciphertext, salt:groupSalt}));
                input.value = '';
            } catch(e){ console.error(e); }
        }
    </script>
</body>
</html>'''

# ============================================
# COMBINED HTTP + WEBSOCKET SERVER
# ============================================

async def handle_http(reader, writer):
    """Handle HTTP requests"""
    try:
        data = await reader.read(1024)
        request = data.decode()
        
        if request.startswith('GET /') or request.startswith('GET /index.html'):
            response = f"""HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: {len(HTML_PAGE)}
Connection: close

{HTML_PAGE}"""
            writer.write(response.encode())
        else:
            response = """HTTP/1.1 404 Not Found
Content-Type: text/plain
Content-Length: 9

Not Found"""
            writer.write(response.encode())
        
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    except:
        pass

async def main():
    PORT = int(os.getenv('PORT', 8080))
    
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
║              SECURE MESSAGING SYSTEM                              ║
║           Messages Auto-Delete After 24 Hours                     ║
║                    Author: Mugisha Pc                             ║
║                    Version: 11.0.0                                ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
""")
    
    print(f"[INFO] ABAVANDIMWE v11.0 starting on port {PORT}")
    
    await db.connect()
    
    # Create WebSocket server
    ws_server = await websockets.serve(
        WebSocketChatServer().handler, 
        '0.0.0.0', 
        PORT
    )
    
    print(f"[INFO] WebSocket server on ws://0.0.0.0:{PORT}")
    
    # Create HTTP server
    http_server = await asyncio.start_server(handle_http, '0.0.0.0', PORT)
    
    print(f"[INFO] HTTP server on http://0.0.0.0:{PORT}")
    print(f"[INFO] Open https://abavandimwe.onrender.com in your browser")
    
    # Run both servers
    await asyncio.gather(ws_server.wait_closed(), http_server.wait_closed())

class WebSocketChatServer:
    def __init__(self):
        self.connections: Dict[str, Dict[str, websockets.WebSocketServerProtocol]] = {}
        self.typing: Set[str] = set()
    
    async def broadcast(self, group: str, message: dict, exclude: str = None):
        if group not in self.connections:
            return
        disconnected = []
        for user, ws in self.connections[group].items():
            if user == exclude:
                continue
            try:
                await ws.send(json.dumps(message))
            except:
                disconnected.append(user)
        for user in disconnected:
            del self.connections[group][user]
    
    async def handler(self, websocket: websockets.WebSocketServerProtocol, path: str):
        user = None
        group = None
        
        try:
            async for message in websocket:
                data = json.loads(message)
                msg_type = data.get('type')
                
                if msg_type == 'join':
                    user = data['username']
                    group = data['group']
                    password = data['password']
                    
                    salt = await db.get_group_salt(group)
                    if not salt:
                        salt = crypto.generate_salt()
                        await db.create_group(group, salt, user)
                    
                    if group not in self.connections:
                        self.connections[group] = {}
                    self.connections[group][user] = websocket
                    
                    await db.set_user_status(user, 'online', group)
                    
                    for msg in await db.get_messages(group):
                        await websocket.send(json.dumps({
                            'type': 'history',
                            'ciphertext': msg['ciphertext'],
                            'sender': msg['sender'],
                            'salt': msg['salt']
                        }))
                    
                    online = await db.get_online_users(group)
                    await self.broadcast(group, {'type': 'users', 'users': online})
                    
                    await websocket.send(json.dumps({
                        'type': 'ready',
                        'salt': salt,
                        'group': group
                    }))
                    
                    print(f"[INFO] User {user} joined {group}")
                
                elif msg_type == 'message':
                    ciphertext = data['ciphertext']
                    salt = data['salt']
                    
                    await db.save_message(ciphertext, group, user, salt)
                    await self.broadcast(group, {
                        'type': 'message',
                        'ciphertext': ciphertext,
                        'sender': user,
                        'salt': salt,
                        'time': datetime.now().isoformat()
                    }, exclude=user)
                
                elif msg_type == 'typing':
                    self.typing.add(user)
                    await self.broadcast(group, {'type': 'typing', 'user': user}, exclude=user)
                
                elif msg_type == 'stop_typing':
                    self.typing.discard(user)
                    await self.broadcast(group, {'type': 'stop_typing', 'user': user}, exclude=user)
        
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            if user and group:
                if group in self.connections:
                    self.connections[group].pop(user, None)
                await db.set_user_status(user, 'offline', group)
                online = await db.get_online_users(group)
                await self.broadcast(group, {'type': 'users', 'users': online})
                print(f"[INFO] User {user} left")

if __name__ == "__main__":
    asyncio.run(main())
