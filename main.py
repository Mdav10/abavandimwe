"""
ABAVANDIMWE - WhatsApp-Style Secure Messaging
Author: Mugisha Pc
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
            msg_type TEXT DEFAULT 'text',
            content TEXT,
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
    conn.commit()
    conn.close()

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

# ========== DATABASE OPS ==========
def save_message(msg_type, content, group, sender, salt):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO messages (msg_type, content, group_name, sender, salt, created_at) VALUES (?,?,?,?,?,?)",
             (msg_type, content, group, sender, salt, time.time()))
    conn.commit()
    conn.close()

def get_messages(group):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    cutoff = time.time() - (24 * 3600)
    c.execute("SELECT msg_type, content, sender, salt, created_at FROM messages WHERE group_name=? AND created_at > ? ORDER BY id ASC", 
             (group, cutoff))
    rows = c.fetchall()
    conn.close()
    return [{'type': r[0], 'content': r[1], 'sender': r[2], 'salt': r[3], 'time': r[4]} for r in rows]

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
        self.typing: Dict[str, str] = {}
    
    async def add(self, group: str, username: str, websocket: WebSocket):
        if group not in self.connections:
            self.connections[group] = {}
        self.connections[group][username] = websocket
    
    def remove(self, group: str, username: str):
        if group in self.connections:
            self.connections[group].pop(username, None)
            if not self.connections[group]:
                del self.connections[group]
        self.typing.pop(username, None)
    
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

# ========== HTML - WHATSAPP STYLE ==========
HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes, viewport-fit=cover">
    <title>ABAVANDIMWE</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, sans-serif;
            background: #0a0a0f;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* ========== LOGIN SCREEN ========== */
        .login-container {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: #0a0a0f;
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
            padding: 20px;
        }

        .login-card {
            background: #0d1117;
            border: 1px solid #00ff41;
            border-radius: 20px;
            padding: 40px 28px;
            width: 100%;
            max-width: 380px;
        }

        .login-card h1 {
            color: #00ff41;
            font-size: 28px;
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
            padding: 14px;
            margin: 8px 0;
            background: #1a1a2e;
            border: 1px solid #2a2a3e;
            border-radius: 12px;
            color: #00ff41;
            font-size: 15px;
        }

        .login-card input:focus {
            outline: none;
            border-color: #00ff41;
        }

        .login-card button {
            width: 100%;
            padding: 14px;
            margin-top: 20px;
            background: #00ff41;
            border: none;
            border-radius: 12px;
            color: #000;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }

        .error {
            color: #ff4444;
            font-size: 12px;
            text-align: center;
            margin-top: 12px;
            display: none;
        }

        /* ========== CHAT SCREEN ========== */
        .chat-container {
            display: none;
            flex-direction: column;
            height: 100vh;
            background: #0a0a0f;
        }

        .chat-container.active {
            display: flex;
        }

        /* Header */
        .chat-header {
            background: #0d1117;
            padding: 12px 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid #1a1a2e;
        }

        .group-info h3 {
            color: #00ff41;
            font-size: 16px;
            font-weight: 600;
        }

        .group-info p {
            color: #666;
            font-size: 11px;
            margin-top: 2px;
        }

        .exit-btn {
            background: transparent;
            border: 1px solid #ff4444;
            color: #ff4444;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            cursor: pointer;
        }

        /* Online Users Row */
        .online-row {
            background: #0d1117;
            padding: 10px 16px;
            border-bottom: 1px solid #1a1a2e;
            overflow-x: auto;
            white-space: nowrap;
        }

        .online-user {
            display: inline-block;
            padding: 6px 14px;
            margin-right: 8px;
            background: #1a1a2e;
            border-radius: 20px;
            font-size: 12px;
            color: #00ff41;
        }

        .online-user.typing {
            color: #ffaa00;
        }

        .online-user::before {
            content: "●";
            display: inline-block;
            margin-right: 6px;
            font-size: 8px;
        }

        /* Messages Area */
        .messages-area {
            flex: 1;
            padding: 16px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        /* Message Bubbles - WhatsApp Style */
        .message-row {
            display: flex;
            width: 100%;
        }

        .message-row.sent {
            justify-content: flex-end;
        }

        .message-row.received {
            justify-content: flex-start;
        }

        .message-bubble {
            max-width: 75%;
            padding: 10px 14px;
            border-radius: 18px;
            font-size: 14px;
            line-height: 1.4;
            word-break: break-word;
        }

        .message-row.sent .message-bubble {
            background: #00ff41;
            color: #000;
            border-bottom-right-radius: 4px;
        }

        .message-row.received .message-bubble {
            background: #1a1a2e;
            color: #e0e0e0;
            border-bottom-left-radius: 4px;
        }

        .message-sender {
            font-size: 11px;
            color: #888;
            margin-bottom: 4px;
        }

        .message-time {
            font-size: 9px;
            color: #666;
            margin-top: 4px;
            text-align: right;
        }

        .system-message {
            text-align: center;
            font-size: 11px;
            color: #ffaa00;
            margin: 8px 0;
            font-style: italic;
        }

        /* Voice Message */
        .voice-message {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .play-btn {
            background: transparent;
            border: 1px solid currentColor;
            border-radius: 50%;
            width: 36px;
            height: 36px;
            cursor: pointer;
            font-size: 14px;
        }

        /* Typing Indicator */
        .typing-area {
            padding: 8px 16px;
            color: #666;
            font-size: 11px;
            font-style: italic;
        }

        /* Input Area */
        .input-area {
            padding: 12px 16px;
            background: #0d1117;
            border-top: 1px solid #1a1a2e;
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .input-area input {
            flex: 1;
            padding: 12px 16px;
            background: #1a1a2e;
            border: 1px solid #2a2a3e;
            border-radius: 24px;
            color: #00ff41;
            font-size: 14px;
        }

        .input-area input:focus {
            outline: none;
            border-color: #00ff41;
        }

        .voice-btn {
            background: #1a1a2e;
            border: 1px solid #00ff41;
            border-radius: 50%;
            width: 44px;
            height: 44px;
            font-size: 18px;
            cursor: pointer;
            color: #00ff41;
        }

        .voice-btn.recording {
            background: #ff4444;
            border-color: #ff4444;
            color: white;
            animation: pulse 1s infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }

        .send-btn {
            background: #00ff41;
            border: none;
            border-radius: 24px;
            color: #000;
            padding: 12px 24px;
            font-weight: 600;
            cursor: pointer;
        }

        .recording-status {
            position: fixed;
            bottom: 80px;
            left: 50%;
            transform: translateX(-50%);
            background: #ff4444;
            color: white;
            padding: 8px 20px;
            border-radius: 30px;
            font-size: 13px;
            display: none;
            z-index: 100;
        }

        ::-webkit-scrollbar {
            width: 4px;
        }
        ::-webkit-scrollbar-track {
            background: #1a1a2e;
        }
        ::-webkit-scrollbar-thumb {
            background: #00ff41;
            border-radius: 4px;
        }
    </style>
</head>
<body>

<div id="loginScreen" class="login-container">
    <div class="login-card">
        <h1>ABAVANDIMWE</h1>
        <p>Secure Team Chat by Mugisha Pc</p>
        <input type="text" id="username" placeholder="Username">
        <input type="text" id="groupName" placeholder="Group name">
        <input type="password" id="groupPassword" placeholder="Group password">
        <button id="joinBtn">Join Chat</button>
        <div id="errorMsg" class="error"></div>
        <div style="text-align:center;margin-top:16px;font-size:9px;color:#333;">🔒 24h auto-delete | 🎤 Voice | 👥 Team</div>
    </div>
</div>

<div id="chatContainer" class="chat-container">
    <div class="chat-header">
        <div class="group-info">
            <h3 id="groupTitle">Loading...</h3>
            <p id="groupStatus">connecting...</p>
        </div>
        <button class="exit-btn" id="exitBtn">Exit</button>
    </div>
    <div class="online-row" id="onlineRow"></div>
    <div class="messages-area" id="messagesArea"></div>
    <div class="typing-area" id="typingArea"></div>
    <div class="input-area">
        <input type="text" id="messageInput" placeholder="Type a message">
        <button class="voice-btn" id="voiceBtn">🎤</button>
        <button class="send-btn" id="sendBtn">Send</button>
    </div>
</div>
<div id="recordingStatus" class="recording-status">🎤 Recording...</div>

<script>
    let ws, username, groupName, groupPassword, groupSalt;
    let typingTimeout;
    let mediaRecorder, audioChunks = [];
    let isRecording = false;
    let audioBuffers = {};

    // DOM elements
    const joinBtn = document.getElementById('joinBtn');
    const exitBtn = document.getElementById('exitBtn');
    const sendBtn = document.getElementById('sendBtn');
    const voiceBtn = document.getElementById('voiceBtn');
    const messageInput = document.getElementById('messageInput');

    async function encryptText(text, password, salt) {
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

    async function decryptText(encrypted, password, salt) {
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

    async function encryptVoice(data, password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({
            name: 'PBKDF2', salt: encoder.encode(salt), iterations: 100000, hash: 'SHA-256'
        }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(data));
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        return btoa(String.fromCharCode(...combined));
    }

    // Voice Recording
    async function startRecording() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            mediaRecorder = new MediaRecorder(stream);
            audioChunks = [];
            
            mediaRecorder.ondataavailable = (event) => audioChunks.push(event.data);
            mediaRecorder.onstop = async () => {
                const blob = new Blob(audioChunks, { type: 'audio/webm' });
                const reader = new FileReader();
                reader.onloadend = async () => {
                    const base64 = reader.result.split(',')[1];
                    const encrypted = await encryptVoice(base64, groupPassword, groupSalt);
                    ws.send(JSON.stringify({ type: 'voice', content: encrypted, salt: groupSalt }));
                };
                reader.readAsDataURL(blob);
                stream.getTracks().forEach(t => t.stop());
                voiceBtn.classList.remove('recording');
                document.getElementById('recordingStatus').style.display = 'none';
                isRecording = false;
                ws.send(JSON.stringify({ type: 'stop_typing' }));
            };
            
            mediaRecorder.start();
            isRecording = true;
            voiceBtn.classList.add('recording');
            document.getElementById('recordingStatus').style.display = 'block';
            ws.send(JSON.stringify({ type: 'typing' }));
            
            setTimeout(() => {
                if (isRecording && mediaRecorder?.state === 'recording') {
                    mediaRecorder.stop();
                }
            }, 30000);
        } catch(e) {
            alert('Microphone access required');
        }
    }

    function stopRecording() {
        if (mediaRecorder?.state === 'recording') {
            mediaRecorder.stop();
        }
    }

    function toggleRecording() {
        if (isRecording) stopRecording();
        else startRecording();
    }

    // UI Functions
    function formatTime(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    function addSystemMessage(text) {
        const container = document.getElementById('messagesArea');
        const div = document.createElement('div');
        div.className = 'system-message';
        div.innerText = text;
        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
    }

    function addTextMessage(sender, text, isSent, timestamp = null) {
        const container = document.getElementById('messagesArea');
        const timeStr = timestamp ? formatTime(timestamp) : new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        const row = document.createElement('div');
        row.className = `message-row ${isSent ? 'sent' : 'received'}`;
        row.innerHTML = `
            <div class="message-bubble">
                <div class="message-sender">${isSent ? 'You' : sender}</div>
                <div>${escapeHtml(text)}</div>
                <div class="message-time">${timeStr}</div>
            </div>
        `;
        container.appendChild(row);
        container.scrollTop = container.scrollHeight;
    }

    function addVoiceMessage(sender, isSent, msgId, timestamp = null) {
        const container = document.getElementById('messagesArea');
        const timeStr = timestamp ? formatTime(timestamp) : new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        const row = document.createElement('div');
        row.className = `message-row ${isSent ? 'sent' : 'received'}`;
        row.innerHTML = `
            <div class="message-bubble">
                <div class="message-sender">${isSent ? 'You' : sender}</div>
                <div class="voice-message">
                    <button class="play-btn" onclick="playVoice('${msgId}')">▶</button>
                    <span>Voice message</span>
                </div>
                <div class="message-time">${timeStr}</div>
            </div>
        `;
        container.appendChild(row);
        container.scrollTop = container.scrollHeight;
    }

    async function playVoice(msgId) {
        const data = audioBuffers[msgId];
        if (!data) return;
        try {
            const decrypted = await decryptText(data.content, groupPassword, data.salt);
            const blob = base64ToBlob(decrypted, 'audio/webm');
            const url = URL.createObjectURL(blob);
            const audio = new Audio(url);
            audio.play();
            audio.onended = () => URL.revokeObjectURL(url);
        } catch(e) {}
    }

    function base64ToBlob(base64, mime) {
        const bytes = atob(base64);
        const arr = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
        return new Blob([arr], { type: mime });
    }

    function escapeHtml(t) {
        const d = document.createElement('div');
        d.textContent = t;
        return d.innerHTML;
    }

    function updateOnlineUsers(users, typingUser = null) {
        const row = document.getElementById('onlineRow');
        if (!users.length) {
            row.innerHTML = '<span style="color:#666;">No one online</span>';
        } else {
            row.innerHTML = users.map(u => {
                const isTyping = typingUser === u;
                return `<span class="online-user${isTyping ? ' typing' : ''}">${escapeHtml(u)}${isTyping ? ' typing...' : ''}</span>`;
            }).join('');
        }
        document.getElementById('groupStatus').innerHTML = `${users.length} online`;
    }

    function logout() {
        if (ws) ws.close();
        document.getElementById('chatContainer').classList.remove('active');
        document.getElementById('loginScreen').style.display = 'flex';
        document.getElementById('messagesArea').innerHTML = '';
    }

    // WebSocket Connection
    function connect() {
        username = document.getElementById('username').value.trim();
        groupName = document.getElementById('groupName').value.trim();
        groupPassword = document.getElementById('groupPassword').value;

        if (!username || !groupName || !groupPassword) {
            document.getElementById('errorMsg').innerText = 'Fill all fields';
            document.getElementById('errorMsg').style.display = 'block';
            setTimeout(() => {
                document.getElementById('errorMsg').style.display = 'none';
            }, 3000);
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
                document.getElementById('errorMsg').style.display = 'block';
                return;
            }
            
            if (data.type === 'ready') {
                groupSalt = data.salt;
                document.getElementById('loginScreen').style.display = 'none';
                document.getElementById('chatContainer').classList.add('active');
                document.getElementById('groupTitle').innerText = data.group;
                addSystemMessage('You joined the chat');
            }
            else if (data.type === 'text') {
                try {
                    const decrypted = await decryptText(data.content, groupPassword, data.salt);
                    addTextMessage(data.sender, decrypted, data.sender === username, data.time);
                } catch(e) {
                    addTextMessage(data.sender, '🔒 Encrypted', data.sender === username, data.time);
                }
            }
            else if (data.type === 'voice') {
                const msgId = data.id || Date.now() + Math.random();
                audioBuffers[msgId] = { content: data.content, salt: data.salt };
                addVoiceMessage(data.sender, data.sender === username, msgId, data.time);
            }
            else if (data.type === 'history') {
                for (const msg of data.messages) {
                    if (msg.type === 'text') {
                        try {
                            const decrypted = await decryptText(msg.content, groupPassword, msg.salt);
                            addTextMessage(msg.sender, decrypted, msg.sender === username, msg.time);
                        } catch(e) {}
                    } else if (msg.type === 'voice') {
                        const msgId = Date.now() + Math.random();
                        audioBuffers[msgId] = { content: msg.content, salt: msg.salt };
                        addVoiceMessage(msg.sender, msg.sender === username, msgId, msg.time);
                    }
                }
            }
            else if (data.type === 'users') {
                updateOnlineUsers(data.users, data.typing_user);
            }
            else if (data.type === 'user_joined') {
                addSystemMessage(`👤 ${data.user} joined`);
            }
            else if (data.type === 'user_left') {
                addSystemMessage(`👋 ${data.user} left`);
            }
            else if (data.type === 'typing') {
                updateOnlineUsers(data.users || [], data.user);
                document.getElementById('typingArea').innerText = `${data.user} is typing...`;
                setTimeout(() => {
                    if (document.getElementById('typingArea').innerText.includes(data.user)) {
                        document.getElementById('typingArea').innerText = '';
                    }
                }, 2000);
            }
        };
    }

    // Event Listeners
    joinBtn.onclick = connect;
    exitBtn.onclick = logout;
    sendBtn.onclick = () => sendTextMessage();
    voiceBtn.onclick = toggleRecording;

    messageInput.addEventListener('input', () => {
        if (ws?.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'typing' }));
            clearTimeout(typingTimeout);
            typingTimeout = setTimeout(() => {
                if (ws?.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'stop_typing' }));
                }
            }, 1000);
        }
    });

    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendTextMessage();
    });

    async function sendTextMessage() {
        const text = messageInput.value.trim();
        if (!text || !ws || ws.readyState !== WebSocket.OPEN || !groupSalt) return;
        try {
            const encrypted = await encryptText(text, groupPassword, groupSalt);
            ws.send(JSON.stringify({ type: 'text', content: encrypted, salt: groupSalt }));
            addTextMessage(username, text, true);
            messageInput.value = '';
        } catch(e) {}
    }
</script>
</body>
</html>'''

# ========== FASTAPI ==========
@app.get("/")
async def root():
    return HTMLResponse(HTML)

@app.get("/health")
async def health():
    return {"status": "ok", "author": "Mugisha Pc"}

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
                
                # Send history
                messages = get_messages(group_name)
                await websocket.send_json({
                    'type': 'history',
                    'messages': messages
                })
                
                online = get_online_users(group_name)
                await manager.broadcast(group_name, {'type': 'users', 'users': online})
                await manager.broadcast(group_name, {'type': 'user_joined', 'user': username}, exclude=username)
                await websocket.send_json({'type': 'ready', 'salt': salt, 'group': group_name})
                print(f"[+] {username} joined {group_name}")
            
            elif msg_type == 'text':
                content = data.get('content')
                salt = data.get('salt')
                save_message('text', content, group_name, username, salt)
                await manager.broadcast(group_name, {
                    'type': 'text',
                    'content': content,
                    'sender': username,
                    'salt': salt,
                    'time': time.time()
                }, exclude=username)
            
            elif msg_type == 'voice':
                content = data.get('content')
                salt = data.get('salt')
                save_message('voice', content, group_name, username, salt)
                await manager.broadcast(group_name, {
                    'type': 'voice',
                    'content': content,
                    'sender': username,
                    'salt': salt,
                    'time': time.time()
                }, exclude=username)
            
            elif msg_type == 'typing':
                online = get_online_users(group_name)
                await manager.broadcast(group_name, {'type': 'users', 'users': online, 'typing_user': username})
            
            elif msg_type == 'stop_typing':
                online = get_online_users(group_name)
                await manager.broadcast(group_name, {'type': 'users', 'users': online})
    
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
║                      ABAVANDIMWE                          ║
║              WhatsApp-Style Secure Team Chat              ║
║                    Author: Mugisha Pc                     ║
╚════════════════════════════════════════════════════════════╝
    """)
    print(f"[✓] Server on port {port}")
    print(f"[✓] Open: https://abavandimwe.onrender.com")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
