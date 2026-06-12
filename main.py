"""
ABAVANDIMWE - Professional Secure Messaging System
Author: Mugisha Pc
Complete: Text + Voice + Team Chat + 24h Auto-Delete
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
            type TEXT DEFAULT 'text',
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

# ========== DATABASE OPS ==========
def save_text_message(content, group, sender, salt):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO messages (type, content, group_name, sender, salt, created_at) VALUES ('text', ?, ?, ?, ?, ?)",
             (content, group, sender, salt, time.time()))
    conn.commit()
    conn.close()

def save_voice_message(content, group, sender, salt):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO messages (type, content, group_name, sender, salt, created_at) VALUES ('voice', ?, ?, ?, ?, ?)",
             (content, group, sender, salt, time.time()))
    conn.commit()
    conn.close()

def get_messages(group):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    cutoff = time.time() - (24 * 3600)
    c.execute("SELECT type, content, sender, salt FROM messages WHERE group_name=? AND created_at > ? ORDER BY id ASC", 
             (group, cutoff))
    rows = c.fetchall()
    conn.close()
    return [{'type': r[0], 'content': r[1], 'sender': r[2], 'salt': r[3]} for r in rows]

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
        self.recording: Dict[str, str] = {}
    
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
        self.recording.pop(username, None)
    
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
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes, viewport-fit=cover">
    <title>ABAVANDIMWE | Professional Team Chat</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, sans-serif;
            background: #0a0a0f;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* Login Screen */
        .login-screen {
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
            border-radius: 24px;
            padding: 40px 28px;
            width: 100%;
            max-width: 380px;
        }

        .login-card h1 {
            color: #00ff41;
            font-size: 28px;
            text-align: center;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
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
            transition: opacity 0.2s;
        }

        .login-card button:active {
            opacity: 0.8;
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
            flex-direction: column;
            height: 100vh;
            background: #0a0a0f;
        }

        .chat-screen.active {
            display: flex;
        }

        /* Header */
        .chat-header {
            background: #0d1117;
            padding: 14px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #1a1a2e;
        }

        .chat-header h3 {
            color: #00ff41;
            font-size: 17px;
            font-weight: 600;
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

        /* Online Users Bar */
        .online-bar {
            background: #0d1117;
            padding: 10px 16px;
            border-bottom: 1px solid #1a1a2e;
            overflow-x: auto;
            white-space: nowrap;
            display: flex;
            gap: 12px;
        }

        .online-user {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 5px 12px;
            background: #1a1a2e;
            border-radius: 20px;
            font-size: 12px;
            color: #00ff41;
        }

        .online-user::before {
            content: "●";
            font-size: 8px;
            color: #00ff41;
        }

        .online-user.typing::before {
            color: #ffaa00;
        }

        .online-user.recording::before {
            color: #ff4444;
            animation: blink 1s infinite;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
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
            padding: 10px 14px;
            border-radius: 18px;
            font-size: 14px;
            line-height: 1.4;
            word-break: break-word;
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
            font-style: italic;
        }

        /* Voice Message */
        .voice-message {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 6px 0;
        }

        .play-btn {
            background: transparent;
            border: 1px solid currentColor;
            border-radius: 50%;
            width: 32px;
            height: 32px;
            cursor: pointer;
            font-size: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .voice-duration {
            font-size: 12px;
            font-family: monospace;
        }

        /* Typing Indicator */
        .typing-indicator {
            padding: 8px 16px;
            color: #888;
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
            transition: all 0.2s;
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

        .send-btn:active, .voice-btn:active {
            transform: scale(0.96);
        }

        .recording-status {
            position: fixed;
            bottom: 80px;
            left: 50%;
            transform: translateX(-50%);
            background: #ff4444;
            color: white;
            padding: 10px 20px;
            border-radius: 30px;
            font-size: 14px;
            display: none;
            z-index: 100;
            white-space: nowrap;
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

<div id="loginScreen" class="login-screen">
    <div class="login-card">
        <h1>ABAVANDIMWE</h1>
        <p>Professional Team Chat by Mugisha Pc</p>
        <input type="text" id="username" placeholder="Username">
        <input type="text" id="groupName" placeholder="Group name">
        <input type="password" id="groupPassword" placeholder="Group password">
        <button id="joinBtn">Join Team Chat</button>
        <div id="errorMsg" class="error"></div>
        <div style="text-align:center;margin-top:16px;font-size:9px;color:#333;">🔒 24h auto-delete | 🎤 Voice | 👥 Team</div>
    </div>
</div>

<div id="chatScreen" class="chat-screen">
    <div class="chat-header">
        <h3 id="groupTitle">Loading...</h3>
        <button class="exit-btn" id="exitBtn">Exit</button>
    </div>
    <div class="online-bar" id="onlineBar">
        <span style="color:#666;">Loading users...</span>
    </div>
    <div class="messages" id="messages"></div>
    <div class="typing-indicator" id="typingIndicator"></div>
    <div class="input-area">
        <input type="text" id="messageInput" placeholder="Type a message...">
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
    let audioContext, audioBuffers = {};

    // DOM Elements
    const joinBtn = document.getElementById('joinBtn');
    const exitBtn = document.getElementById('exitBtn');
    const sendBtn = document.getElementById('sendBtn');
    const voiceBtn = document.getElementById('voiceBtn');
    const messageInput = document.getElementById('messageInput');
    const usernameInput = document.getElementById('username');
    const groupNameInput = document.getElementById('groupName');
    const groupPasswordInput = document.getElementById('groupPassword');

    // Encryption
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

    async function encryptVoice(voiceData, password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({
            name: 'PBKDF2', salt: encoder.encode(salt), iterations: 100000, hash: 'SHA-256'
        }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(voiceData));
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
            
            mediaRecorder.ondataavailable = (event) => {
                audioChunks.push(event.data);
            };
            
            mediaRecorder.onstop = async () => {
                const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                const reader = new FileReader();
                reader.onloadend = async () => {
                    const base64Audio = reader.result.split(',')[1];
                    const encryptedVoice = await encryptVoice(base64Audio, groupPassword, groupSalt);
                    ws.send(JSON.stringify({ type: 'voice_message', content: encryptedVoice, salt: groupSalt }));
                    addSystemMessage('Voice message sent');
                };
                reader.readAsDataURL(audioBlob);
                stream.getTracks().forEach(track => track.stop());
                voiceBtn.classList.remove('recording');
                document.getElementById('recordingStatus').style.display = 'none';
                isRecording = false;
                ws.send(JSON.stringify({ type: 'stop_recording' }));
            };
            
            mediaRecorder.start();
            isRecording = true;
            voiceBtn.classList.add('recording');
            document.getElementById('recordingStatus').style.display = 'block';
            ws.send(JSON.stringify({ type: 'start_recording' }));
            
            setTimeout(() => {
                if (isRecording && mediaRecorder && mediaRecorder.state === 'recording') {
                    mediaRecorder.stop();
                }
            }, 30000);
        } catch(e) {
            alert('Microphone access required for voice messages');
        }
    }

    function stopRecording() {
        if (mediaRecorder && mediaRecorder.state === 'recording') {
            mediaRecorder.stop();
        }
    }

    function toggleRecording() {
        if (isRecording) {
            stopRecording();
        } else {
            startRecording();
        }
    }

    // UI Functions
    function addSystemMessage(text) {
        const msgsDiv = document.getElementById('messages');
        if (msgsDiv.children.length === 0) msgsDiv.innerHTML = '';
        const div = document.createElement('div');
        div.className = 'system-msg';
        div.innerText = text;
        msgsDiv.appendChild(div);
        msgsDiv.scrollTop = msgsDiv.scrollHeight;
    }

    function addTextMessage(sender, text, isSent) {
        const msgsDiv = document.getElementById('messages');
        if (msgsDiv.children.length === 0) msgsDiv.innerHTML = '';
        const div = document.createElement('div');
        div.className = `message ${isSent ? 'sent' : 'received'}`;
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        div.innerHTML = `<div class="sender">${isSent ? 'You' : sender}</div><div class="bubble">${escapeHtml(text)}</div><div class="time">${time}</div>`;
        msgsDiv.appendChild(div);
        msgsDiv.scrollTop = msgsDiv.scrollHeight;
    }

    function addVoiceMessage(sender, isSent, messageId) {
        const msgsDiv = document.getElementById('messages');
        if (msgsDiv.children.length === 0) msgsDiv.innerHTML = '';
        const div = document.createElement('div');
        div.className = `message ${isSent ? 'sent' : 'received'}`;
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        div.innerHTML = `
            <div class="sender">${isSent ? 'You' : sender}</div>
            <div class="bubble">
                <div class="voice-message">
                    <button class="play-btn" onclick="playVoice('${messageId}')">▶</button>
                    <span class="voice-duration">Voice message</span>
                </div>
            </div>
            <div class="time">${time}</div>
        `;
        msgsDiv.appendChild(div);
        msgsDiv.scrollTop = msgsDiv.scrollHeight;
    }

    function escapeHtml(t) {
        const d = document.createElement('div');
        d.textContent = t;
        return d.innerHTML;
    }

    function updateOnlineUsers(users, typingUser = null, recordingUser = null) {
        const bar = document.getElementById('onlineBar');
        if (users.length === 0) {
            bar.innerHTML = '<span style="color:#666;">No one online</span>';
        } else {
            bar.innerHTML = users.map(u => {
                let statusClass = '';
                if (typingUser === u) statusClass = 'typing';
                if (recordingUser === u) statusClass = 'recording';
                return `<span class="online-user ${statusClass}">${escapeHtml(u)}</span>`;
            }).join('');
        }
    }

    function logout() {
        if (ws) ws.close();
        ws = null;
        document.getElementById('chatScreen').classList.remove('active');
        document.getElementById('loginScreen').style.display = 'flex';
        document.getElementById('messages').innerHTML = '';
        usernameInput.value = '';
        groupNameInput.value = '';
        groupPasswordInput.value = '';
    }

    // WebSocket Connection
    function connect() {
        username = usernameInput.value.trim();
        groupName = groupNameInput.value.trim();
        groupPassword = groupPasswordInput.value;

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
                document.getElementById('chatScreen').classList.add('active');
                document.getElementById('groupTitle').innerText = data.group;
                addSystemMessage('You joined the team chat');
            }
            else if (data.type === 'text_message') {
                try {
                    const decrypted = await decryptText(data.content, groupPassword, data.salt);
                    addTextMessage(data.sender, decrypted, data.sender === username);
                } catch(e) {
                    addTextMessage(data.sender, '🔒 Encrypted', data.sender === username);
                }
            }
            else if (data.type === 'voice_message') {
                addVoiceMessage(data.sender, data.sender === username, data.id || Date.now());
                // Store voice data for playback
                audioBuffers[data.id || Date.now()] = { data: data.content, salt: data.salt };
            }
            else if (data.type === 'history') {
                for (const msg of data.messages) {
                    if (msg.type === 'text') {
                        try {
                            const decrypted = await decryptText(msg.content, groupPassword, msg.salt);
                            addTextMessage(msg.sender, decrypted, msg.sender === username);
                        } catch(e) {}
                    } else if (msg.type === 'voice') {
                        addVoiceMessage(msg.sender, msg.sender === username, msg.id);
                        audioBuffers[msg.id] = { data: msg.content, salt: msg.salt };
                    }
                }
            }
            else if (data.type === 'users') {
                updateOnlineUsers(data.users, data.typing_user, data.recording_user);
            }
            else if (data.type === 'user_joined') {
                addSystemMessage(`👤 ${data.user} joined`);
            }
            else if (data.type === 'user_left') {
                addSystemMessage(`👋 ${data.user} left`);
            }
            else if (data.type === 'typing') {
                document.getElementById('typingIndicator').innerText = `${data.user} is typing...`;
            }
            else if (data.type === 'stop_typing') {
                document.getElementById('typingIndicator').innerText = '';
            }
            else if (data.type === 'start_recording') {
                addSystemMessage(`🎤 ${data.user} is recording a voice message...`);
            }
        };

        ws.onerror = () => {
            document.getElementById('errorMsg').innerText = 'Connection failed';
            document.getElementById('errorMsg').style.display = 'block';
        };
    }

    // Voice Playback
    async function playVoice(messageId) {
        const voiceData = audioBuffers[messageId];
        if (!voiceData) return;
        
        try {
            const decryptedBase64 = await decryptText(voiceData.data, groupPassword, voiceData.salt);
            const audioBlob = base64ToBlob(decryptedBase64, 'audio/webm');
            const audioUrl = URL.createObjectURL(audioBlob);
            const audio = new Audio(audioUrl);
            audio.play();
            audio.onended = () => URL.revokeObjectURL(audioUrl);
        } catch(e) {
            console.error('Playback error:', e);
        }
    }

    function base64ToBlob(base64, mimeType) {
        const byteCharacters = atob(base64);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        return new Blob([byteArray], { type: mimeType });
    }

    // Event Listeners
    joinBtn.onclick = connect;
    exitBtn.onclick = logout;
    sendBtn.onclick = sendTextMessage;
    voiceBtn.onclick = toggleRecording;

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
            sendTextMessage();
        }
    });

    async function sendTextMessage() {
        const text = messageInput.value.trim();
        if (!text || !ws || ws.readyState !== WebSocket.OPEN || !groupSalt) return;
        
        try {
            const ciphertext = await encryptText(text, groupPassword, groupSalt);
            ws.send(JSON.stringify({ type: 'text_message', content: ciphertext, salt: groupSalt }));
            addTextMessage(username, text, true);
            messageInput.value = '';
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
    return {"status": "healthy", "system": "ABAVANDIMWE", "author": "Mugisha Pc"}

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
            
            elif msg_type == 'text_message':
                content = data.get('content')
                salt = data.get('salt')
                save_text_message(content, group_name, username, salt)
                await manager.broadcast(group_name, {
                    'type': 'text_message',
                    'content': content,
                    'sender': username,
                    'salt': salt
                }, exclude=username)
            
            elif msg_type == 'voice_message':
                content = data.get('content')
                salt = data.get('salt')
                save_voice_message(content, group_name, username, salt)
                await manager.broadcast(group_name, {
                    'type': 'voice_message',
                    'content': content,
                    'sender': username,
                    'salt': salt
                }, exclude=username)
            
            elif msg_type == 'typing':
                online = get_online_users(group_name)
                await manager.broadcast(group_name, {'type': 'users', 'users': online, 'typing_user': username})
            
            elif msg_type == 'stop_typing':
                online = get_online_users(group_name)
                await manager.broadcast(group_name, {'type': 'users', 'users': online})
            
            elif msg_type == 'start_recording':
                online = get_online_users(group_name)
                await manager.broadcast(group_name, {'type': 'users', 'users': online, 'recording_user': username})
                await manager.broadcast(group_name, {'type': 'start_recording', 'user': username})
            
            elif msg_type == 'stop_recording':
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
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   █████╗ ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗██████╗      ║
║  ██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔══██╗     ║
║  ███████║██████╔╝███████║██║   ██║███████║██╔██╗ ██║██║  ██║     ║
║  ██╔══██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║  ██║     ║
║  ██║  ██║██████╔╝██║  ██║ ╚████╔╝ ██║  ██║██║ ╚████║██████╔╝     ║
║  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝      ║
║                                                                   ║
║                    ABAVANDIMWE - FINAL v14                        ║
║                                                                   ║
║  ✅ Professional WhatsApp-Style Design                           ║
║  ✅ Text Messages + Voice Messages                                ║
║  ✅ Real-time Team Chat                                           ║
║  ✅ 24-Hour Auto-Delete                                           ║
║  ✅ Online Users with Typing/Recording Status                     ║
║  ✅ Mobile Optimized                                              ║
║                                                                   ║
║                        AUTHOR: MUGISHA PC                         ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    print(f"[✓] Server on port {port}")
    print(f"[✓] Open: https://abavandimwe.onrender.com")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
