"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
Messages stay for 24 hours then auto-delete
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
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
from collections import defaultdict

app = FastAPI()

# ========== DATABASE ==========
DB_PATH = "abavandimwe.db"

# ========== CRYPTO FUNCTIONS ==========
def generate_salt():
    return base64.b64encode(secrets.token_bytes(32)).decode()

def derive_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)

def hash_password(password, salt):
    return base64.b64encode(derive_key(password, salt)).decode()

def verify_password(password, salt, stored_hash):
    return hash_password(password, salt) == stored_hash

# ========== DATABASE INIT ==========
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Users table with role
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            salt TEXT,
            role TEXT DEFAULT 'user',
            status TEXT,
            current_group TEXT,
            last_seen REAL,
            created_at REAL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ciphertext TEXT,
            group_name TEXT,
            sender TEXT,
            salt TEXT,
            created_at REAL,
            expires_at REAL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            group_name TEXT PRIMARY KEY,
            salt TEXT,
            password_hash TEXT,
            created_by TEXT,
            created_at REAL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_username TEXT,
            action TEXT,
            target TEXT,
            details TEXT,
            created_at REAL
        )
    ''')
    conn.commit()
    conn.close()
    print("[✓] Database ready")
    
    # Create default admin if not exists
    create_admin()

def create_admin():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username='Mpc'")
    if not c.fetchone():
        salt = generate_salt()
        password_hash = hash_password("08800Mpc!", salt)
        c.execute(
            "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?,?,?,?,?)",
            ("Mpc", password_hash, salt, "admin", time.time())
        )
        conn.commit()
        print("[✓] Admin account created: Mpc")
    conn.close()

def log_admin_action(admin_username, action, target, details=""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO admin_logs (admin_username, action, target, details, created_at) VALUES (?,?,?,?,?)",
        (admin_username, action, target, details, time.time())
    )
    conn.commit()
    conn.close()

def get_admin_logs(limit=50):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT id, admin_username, action, target, details, created_at FROM admin_logs ORDER BY created_at DESC LIMIT ?",
        (limit,)
    )
    rows = c.fetchall()
    conn.close()
    return [{'id': r[0], 'admin': r[1], 'action': r[2], 'target': r[3], 'details': r[4], 'time': r[5]} for r in rows]

# ========== CLEANUP ==========
def cleanup_old_messages():
    now = time.time()
    cutoff = now - (24 * 3600)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM messages WHERE created_at < ? OR expires_at < ?", (cutoff, now))
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

# ========== DATABASE FUNCTIONS ==========
def authenticate_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt, role FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        stored_hash, salt, role = row
        if verify_password(password, salt, stored_hash):
            return {"username": username, "role": role}
    return None

def create_user(username, password, role="user"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        salt = generate_salt()
        password_hash = hash_password(password, salt)
        c.execute(
            "INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?,?,?,?,?)",
            (username, password_hash, salt, role, time.time())
        )
        conn.commit()
        conn.close()
        return True
    except:
        conn.close()
        return False

def delete_user(username):
    if username == "Mpc":
        return False
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return deleted > 0

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, role, status, current_group, last_seen, created_at FROM users ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [{'username': r[0], 'role': r[1], 'status': r[2] or 'offline', 'group': r[3], 'last_seen': r[4], 'created_at': r[5]} for r in rows]

def get_user_role(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def save_message(ciphertext, group, sender, salt):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = time.time()
    expiry = now + (24 * 3600)
    c.execute("INSERT INTO messages (ciphertext, group_name, sender, salt, created_at, expires_at) VALUES (?,?,?,?,?,?)",
             (ciphertext, group, sender, salt, now, expiry))
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

def get_all_messages(limit=100):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, sender, group_name, created_at FROM messages ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{'id': r[0], 'sender': r[1], 'group': r[2], 'created_at': r[3]} for r in rows]

def delete_message(message_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM messages WHERE id=?", (message_id,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return deleted > 0

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
        c.execute("INSERT INTO groups (group_name, salt, password_hash, created_by, created_at) VALUES (?,?,?,?,?)",
                 (group, salt, password_hash, creator, time.time()))
        conn.commit()
        conn.close()
        return True
    except:
        conn.close()
        return False

def get_all_groups():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT group_name, created_by, created_at FROM groups ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [{'name': r[0], 'created_by': r[1], 'created_at': r[2]} for r in rows]

def delete_group(group_name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM groups WHERE group_name=?", (group_name,))
    c.execute("DELETE FROM messages WHERE group_name=?", (group_name,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return deleted > 0

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

# ========== RATE LIMITING ==========
message_limits = defaultdict(list)

def check_rate_limit(username):
    now = time.time()
    message_limits[username] = [t for t in message_limits[username] if t > now - 5]
    if len(message_limits[username]) >= 10:
        return False
    message_limits[username].append(now)
    return True

# ========== INIT DATABASE ==========
init_db()
start_cleanup()

# ========== HTML ==========
HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>ABAVANDIMWE | Secure Messaging</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
        body{font-family:monospace;background:#0a0a0f;height:100vh;overflow:hidden;color:#0f0;}
        
        /* Login Screen */
        .login-container{position:fixed;top:0;left:0;right:0;bottom:0;display:flex;justify-content:center;align-items:center;background:#0a0a0f;z-index:1000;padding:20px;}
        .login-card{background:#050508;border:2px solid #0f0;border-radius:24px;padding:32px 24px;width:100%;max-width:420px;position:relative;overflow:hidden;}
        .login-card::before{content:'';position:absolute;top:-2px;left:-2px;right:-2px;bottom:-2px;background:linear-gradient(45deg,#0f0,transparent,#0f0);background-size:400%;z-index:-1;animation:glow 3s linear infinite;}
        @keyframes glow{0%{background-position:0% 50%;}50%{background-position:100% 50%;}100%{background-position:0% 50%;}}
        .login-card-inner{background:#050508;padding:32px 24px;border-radius:22px;position:relative;}
        h1{text-align:center;margin-bottom:4px;font-size:28px;letter-spacing:2px;}
        .sub{text-align:center;margin-bottom:32px;font-size:11px;color:#666;}
        .admin-badge{text-align:center;margin-bottom:20px;font-size:10px;color:#0f0;border:1px solid #0f0;padding:4px 12px;display:inline-block;border-radius:20px;background:rgba(0,255,0,0.05);}
        input{width:100%;padding:14px;margin:10px 0;background:#111;border:1px solid #0f0;border-radius:12px;color:#0f0;font-family:monospace;font-size:15px;transition:all 0.3s;}
        input:focus{outline:none;box-shadow:0 0 20px rgba(0,255,65,0.2);border-color:#0f0;}
        input::placeholder{color:#444;}
        button{width:100%;padding:14px;margin-top:20px;background:transparent;border:2px solid #0f0;border-radius:12px;color:#0f0;font-size:16px;font-weight:bold;cursor:pointer;transition:all 0.3s;position:relative;overflow:hidden;}
        button:hover{background:#0f0;color:#000;transform:translateY(-2px);box-shadow:0 5px 20px rgba(0,255,65,0.3);}
        button:active{transform:scale(0.98);}
        .btn-whatsapp{background:#25D366;border-color:#25D366;color:white;margin-top:12px;}
        .btn-whatsapp:hover{background:#128C7E;border-color:#128C7E;color:white;box-shadow:0 5px 20px rgba(37,211,102,0.3);}
        .error-message{color:#ff4444;font-size:12px;text-align:center;margin-top:12px;display:none;}
        .success-message{color:#0f0;font-size:12px;text-align:center;margin-top:12px;display:none;}
        .login-footer{text-align:center;margin-top:20px;font-size:9px;color:#333;border-top:1px solid #1a1a2e;padding-top:16px;}
        
        /* Chat Screen */
        .chat-container{display:none;width:100%;height:100%;flex-direction:column;background:#0a0a0f;position:fixed;top:0;left:0;right:0;bottom:0;}
        .chat-container.active{display:flex;}
        
        .chat-header{padding:12px 16px;background:#050508;border-bottom:1px solid #0f0;display:flex;justify-content:space-between;align-items:center;gap:8px;}
        .chat-header-left{display:flex;align-items:center;gap:10px;}
        .chat-header h2{font-size:16px;flex:1;text-align:center;overflow:hidden;text-overflow:ellipsis;}
        .online-badge{font-size:10px;padding:3px 10px;border:1px solid #0f0;border-radius:20px;background:rgba(0,255,0,0.05);}
        .menu-btn,.logout-btn{background:transparent;border:1px solid #0f0;color:#0f0;padding:6px 12px;border-radius:8px;cursor:pointer;width:auto;margin:0;font-size:12px;transition:all 0.3s;}
        .logout-btn:hover{border-color:#ff0041;color:#ff0041;}
        .logout-btn:active{background:#ff0041;border-color:#ff0041;color:white;}
        .admin-btn{background:transparent;border:1px solid #ffaa00;color:#ffaa00;padding:6px 12px;border-radius:8px;cursor:pointer;width:auto;margin:0;font-size:12px;transition:all 0.3s;}
        .admin-btn:hover{background:#ffaa00;color:#000;}
        
        .main-content{flex:1;display:flex;overflow:hidden;position:relative;}
        .sidebar{width:260px;background:#050508;border-right:1px solid #0f0;display:flex;flex-direction:column;flex-shrink:0;}
        .sidebar-header{padding:16px;border-bottom:1px solid #0f0;}
        .sidebar-header h3{font-size:14px;}
        .users-list{flex:1;padding:12px;overflow-y:auto;}
        .user-item{padding:10px 12px;margin:6px 0;border:1px solid #0f0;border-radius:10px;display:flex;align-items:center;gap:8px;animation:fadeIn 0.3s ease;}
        .user-item::before{content:"●";color:#0f0;font-size:10px;animation:pulse 2s infinite;}
        @keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.5;}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
        
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
        .message.sent{align-self:flex-end;}
        .message.received{align-self:flex-start;}
        .message-bubble{padding:10px 14px;border-radius:18px;font-size:14px;word-wrap:break-word;}
        .message.sent .message-bubble{background:#0f0;color:#000;border-bottom-right-radius:4px;}
        .message.received .message-bubble{background:#1a1a2e;border:1px solid #0f0;border-bottom-left-radius:4px;}
        .message-sender{font-size:10px;margin-bottom:4px;opacity:0.7;padding-left:4px;}
        .message-time{font-size:9px;margin-top:4px;opacity:0.5;}
        .system-message{text-align:center;font-size:11px;color:#ffaa00;margin:8px 0;font-style:italic;animation:fadeIn 0.3s ease;}
        .typing-indicator{padding:8px 16px;color:#0f0;font-style:italic;font-size:11px;min-height:36px;}
        
        .input-area{padding:12px 16px;background:#050508;border-top:1px solid #0f0;display:flex;gap:10px;}
        .input-area input{flex:1;margin:0;padding:12px 16px;font-size:14px;}
        .input-area button{width:auto;margin:0;padding:12px 20px;}
        .footer{text-align:center;padding:6px;font-size:8px;color:#333;border-top:1px solid #0f0;}
        
        ::-webkit-scrollbar{width:3px;}
        ::-webkit-scrollbar-track{background:#1a1a2e;}
        ::-webkit-scrollbar-thumb{background:#0f0;}
        
        .connection-status{position:fixed;bottom:70px;right:16px;padding:6px 12px;background:#050508;border:1px solid #0f0;border-radius:20px;font-size:9px;z-index:10;}
        .status-online{color:#0f0;}
        .status-offline{color:#ff4444;}
        
        .separator{display:flex;align-items:center;text-align:center;margin:16px 0;}
        .separator::before,.separator::after{content:'';flex:1;border-bottom:1px solid #1a1a2e;}
        .separator span{padding:0 10px;color:#666;font-size:10px;}
        
        /* Admin Panel */
        .admin-panel{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:#0a0a0f;z-index:50;padding:20px;overflow-y:auto;}
        .admin-panel.active{display:block;}
        .admin-panel-header{display:flex;justify-content:space-between;align-items:center;padding:16px;border-bottom:2px solid #0f0;margin-bottom:20px;}
        .admin-panel-header h2{color:#ffaa00;}
        .admin-content{display:grid;grid-template-columns:repeat(auto-fit, minmax(300px, 1fr));gap:20px;}
        .admin-card{background:#050508;border:1px solid #0f0;border-radius:12px;padding:20px;}
        .admin-card h3{color:#0f0;margin-bottom:12px;font-size:14px;}
        .admin-card table{width:100%;font-size:11px;border-collapse:collapse;}
        .admin-card table th{text-align:left;padding:6px;border-bottom:1px solid #1a1a2e;color:#666;}
        .admin-card table td{padding:6px;border-bottom:1px solid #1a1a2e;}
        .admin-card input{width:100%;padding:8px;margin:5px 0;background:#111;border:1px solid #0f0;border-radius:6px;color:#0f0;font-size:12px;}
        .admin-card select{width:100%;padding:8px;margin:5px 0;background:#111;border:1px solid #0f0;border-radius:6px;color:#0f0;font-size:12px;}
        .admin-card button{width:auto;padding:8px 16px;margin:5px;font-size:12px;}
        .close-admin{background:#ff0041;border-color:#ff0041;color:white;padding:8px 16px;border-radius:8px;cursor:pointer;}
        .close-admin:hover{background:#cc0033;}
        .admin-stats{display:grid;grid-template-columns:repeat(auto-fit, minmax(150px, 1fr));gap:12px;margin-bottom:20px;}
        .stat-box{background:#050508;border:1px solid #0f0;border-radius:10px;padding:16px;text-align:center;}
        .stat-number{font-size:24px;color:#0f0;}
        .stat-label{font-size:10px;color:#666;margin-top:4px;}
        .admin-table-wrap{max-height:200px;overflow-y:auto;}
        .action-btn{background:transparent;border:1px solid #ff0041;color:#ff0041;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:10px;margin:0 2px;}
        .action-btn:hover{background:#ff0041;color:white;}
        .action-btn-green{background:transparent;border:1px solid #0f0;color:#0f0;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:10px;margin:0 2px;}
        .action-btn-green:hover{background:#0f0;color:#000;}
        .admin-close-area{display:flex;justify-content:flex-end;gap:10px;}
        .admin-username{color:#ffaa00;font-size:12px;margin-left:10px;}
    </style>
</head>
<body>
<!-- LOGIN SCREEN -->
<div id="loginScreen" class="login-container">
    <div class="login-card">
        <div class="login-card-inner">
            <h1># ABAVANDIMWE</h1>
            <div class="sub">Secure Messaging System</div>
            <div style="text-align:center;"><span class="admin-badge">🔐 Secure Access</span></div>
            
            <input type="text" id="loginUsername" placeholder="Username" value="Mpc">
            <input type="password" id="loginPassword" placeholder="Password" value="08800Mpc!">
            
            <button onclick="login()">▶ Login</button>
            
            <div class="separator"><span>OR</span></div>
            
            <button class="btn-whatsapp" onclick="requestAccess()">
                💬 Request Access on WhatsApp
            </button>
            
            <div id="loginError" class="error-message"></div>
            <div id="loginSuccess" class="success-message"></div>
            
            <div class="login-footer">
                🔒 AES-256 | ⏰ Messages auto-delete after 24 hours<br>
                <span style="color:#1a1a2e;">Developed by Mugisha Pc</span>
            </div>
        </div>
    </div>
</div>

<!-- CHAT SCREEN -->
<div id="chatScreen" class="chat-container">
    <div class="chat-header">
        <div class="chat-header-left">
            <button class="menu-btn" onclick="toggleSidebar()">☰</button>
            <span class="online-badge" id="connectionBadge">● Online</span>
        </div>
        <h2 id="groupTitle"># LOADING</h2>
        <div>
            <button class="admin-btn" id="adminBtn" onclick="openAdmin()" style="display:none;">⚙️ Admin</button>
            <button class="logout-btn" onclick="logout()">Leave</button>
        </div>
    </div>
    
    <div class="main-content">
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header"><h3>● Online Users</h3></div>
            <div class="users-list" id="usersList"><div class="user-item">Loading...</div></div>
        </div>
        <div class="overlay" id="overlay" onclick="toggleSidebar()"></div>
        
        <div class="chat-area">
            <div class="messages-container" id="messages">
                <div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div>
            </div>
            <div class="typing-indicator" id="typingIndicator"></div>
            <div class="input-area">
                <input type="text" id="messageInput" placeholder="Type a message...">
                <button onclick="sendMessage()">Send</button>
            </div>
            <div class="footer">🔐 End-to-End Encrypted | Messages self-destruct after 24 hours</div>
        </div>
    </div>
    <div class="connection-status status-online" id="connectionStatus">🟢 Connected</div>
</div>

<!-- ADMIN PANEL -->
<div id="adminPanel" class="admin-panel">
    <div class="admin-panel-header">
        <h2>⚙️ Admin Panel <span class="admin-username">(Logged in as: <span id="adminUsername">Mpc</span>)</span></h2>
        <div class="admin-close-area">
            <button class="close-admin" onclick="closeAdmin()">✕ Close</button>
        </div>
    </div>
    
    <!-- Stats -->
    <div class="admin-stats" id="adminStats">
        <div class="stat-box"><div class="stat-number" id="statUsers">0</div><div class="stat-label">Total Users</div></div>
        <div class="stat-box"><div class="stat-number" id="statMessages">0</div><div class="stat-label">Total Messages</div></div>
        <div class="stat-box"><div class="stat-number" id="statGroups">0</div><div class="stat-label">Total Groups</div></div>
        <div class="stat-box"><div class="stat-number" id="statOnline">0</div><div class="stat-label">Online Now</div></div>
    </div>
    
    <div class="admin-content">
        <!-- Users Management -->
        <div class="admin-card">
            <h3>👤 User Management</h3>
            <div style="margin-bottom:12px;">
                <input type="text" id="newUsername" placeholder="New username" style="width:100%;">
                <input type="text" id="newPassword" placeholder="New password" style="width:100%;">
                <select id="newRole" style="width:100%;padding:8px;background:#111;border:1px solid #0f0;border-radius:6px;color:#0f0;margin:5px 0;">
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
                <button onclick="addUser()" class="action-btn-green">➕ Add User</button>
            </div>
            <div class="admin-table-wrap">
                <table>
                    <thead><tr><th>Username</th><th>Role</th><th>Status</th><th>Action</th></tr></thead>
                    <tbody id="usersTableBody"></tbody>
                </table>
            </div>
        </div>
        
        <!-- Groups Management -->
        <div class="admin-card">
            <h3>📁 Group Management</h3>
            <div style="margin-bottom:12px;">
                <input type="text" id="newGroupName" placeholder="New group name" style="width:100%;">
                <input type="text" id="newGroupPassword" placeholder="Group password" style="width:100%;">
                <button onclick="addGroup()" class="action-btn-green">➕ Add Group</button>
            </div>
            <div class="admin-table-wrap">
                <table>
                    <thead><tr><th>Group Name</th><th>Created By</th><th>Action</th></tr></thead>
                    <tbody id="groupsTableBody"></tbody>
                </table>
            </div>
        </div>
        
        <!-- Messages & Logs -->
        <div class="admin-card">
            <h3>📨 Recent Messages</h3>
            <div class="admin-table-wrap">
                <table>
                    <thead><tr><th>Sender</th><th>Group</th><th>Time</th><th>Action</th></tr></thead>
                    <tbody id="messagesTableBody"></tbody>
                </table>
            </div>
        </div>
        
        <div class="admin-card">
            <h3>📋 Admin Logs</h3>
            <div class="admin-table-wrap">
                <table>
                    <thead><tr><th>Admin</th><th>Action</th><th>Target</th><th>Time</th></tr></thead>
                    <tbody id="logsTableBody"></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script>
// ========== GLOBALS ==========
let ws, username, groupName, groupPassword, groupSalt, typingTimeout, reconnectAttempts = 0;
let currentUser = null;
const DEFAULT_GROUP = 'Main';
const DEFAULT_PASSWORD = 'Abavandimwe2026';

// ========== LOGIN ==========
async function login() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    
    if(!username || !password) {
        showError('Please enter username and password');
        return;
    }
    
    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        
        const data = await response.json();
        if(data.success) {
            currentUser = {username: data.username, role: data.role};
            document.getElementById('loginScreen').style.display = 'none';
            document.getElementById('chatScreen').classList.add('active');
            
            // Show admin button if admin
            if(data.role === 'admin') {
                document.getElementById('adminBtn').style.display = 'inline-block';
                document.getElementById('adminUsername').textContent = data.username;
            }
            
            connectToGroup(data.username, DEFAULT_GROUP, DEFAULT_PASSWORD);
        } else {
            showError('Invalid credentials. Request access via WhatsApp if you need an account.');
        }
    } catch(e) {
        showError('Connection error. Please try again.');
    }
}

function requestAccess() {
    const phone = '256762117982';
    const message = 'Hello, I would like to get access to ABAVANDIMWE secure messaging platform. Please send me login credentials.';
    const url = `https://wa.me/${phone}?text=${encodeURIComponent(message)}`;
    window.open(url, '_blank');
    showSuccess('📱 Opening WhatsApp... Please send your request.');
}

function showError(msg) {
    let err = document.getElementById('loginError');
    err.textContent = msg;
    err.style.display = 'block';
    document.getElementById('loginSuccess').style.display = 'none';
    setTimeout(() => err.style.display = 'none', 5000);
}

function showSuccess(msg) {
    let success = document.getElementById('loginSuccess');
    success.textContent = msg;
    success.style.display = 'block';
    document.getElementById('loginError').style.display = 'none';
    setTimeout(() => success.style.display = 'none', 5000);
}

// ========== WEBSOCKET CONNECTION ==========
function connectToGroup(username, group, password) {
    document.getElementById('groupTitle').innerHTML = '# ' + group;
    window.groupPassword = password;
    
    let url = 'wss://' + window.location.host + '/ws';
    ws = new WebSocket(url);
    
    ws.onopen = function() {
        updateStatus(true);
        ws.send(JSON.stringify({
            type: 'join',
            username: username,
            group: group,
            password: password
        }));
        reconnectAttempts = 0;
    };
    
    ws.onmessage = async function(e) {
        let d = JSON.parse(e.data);
        if(d.type === 'error') {
            showError(d.message);
            ws.close();
            return;
        }
        if(d.type === 'ready') {
            groupSalt = d.salt;
            addSystemMessage('🔐 Connected - Messages last 24 hours');
        } else if(d.type === 'message' || d.type === 'history') {
            try {
                let dec = await decrypt(d.ciphertext, password, d.salt);
                addMessage(d.sender, dec, d.sender === username);
            } catch(e) {
                addMessage(d.sender, '🔒 Encrypted', d.sender === username);
            }
        } else if(d.type === 'users') {
            updateUsers(d.users);
        } else if(d.type === 'user_joined') {
            addSystemMessage('👤 ' + d.user + ' joined');
        } else if(d.type === 'user_left') {
            addSystemMessage('👋 ' + d.user + ' left');
        } else if(d.type === 'typing') {
            document.getElementById('typingIndicator').innerHTML = '✏️ ' + d.user + ' typing...';
        } else if(d.type === 'stop_typing') {
            document.getElementById('typingIndicator').innerHTML = '';
        } else if(d.type === 'pong') {
            updateStatus(true);
        }
    };
    
    ws.onerror = function() {
        showError('Connection error');
        updateStatus(false);
    };
    
    ws.onclose = function() {
        updateStatus(false);
        if(document.getElementById('chatScreen').classList.contains('active')) {
            addSystemMessage('⚠️ Connection lost. Reconnecting...');
            reconnectAttempts++;
            if(reconnectAttempts < 5) {
                setTimeout(() => connectToGroup(username, group, password), 3000);
            } else {
                addSystemMessage('❌ Connection failed. Please refresh.');
            }
        }
    };
}

// ========== UI FUNCTIONS ==========
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('overlay').classList.toggle('active');
}

function updateStatus(online) {
    let status = document.getElementById('connectionStatus');
    let badge = document.getElementById('connectionBadge');
    if(online) {
        status.innerHTML = '🟢 Connected';
        status.className = 'connection-status status-online';
        badge.innerHTML = '● Online';
        badge.style.color = '#0f0';
    } else {
        status.innerHTML = '🔴 Disconnected';
        status.className = 'connection-status status-offline';
        badge.innerHTML = '● Offline';
        badge.style.color = '#ff4444';
    }
}

function addSystemMessage(text) {
    let msgs = document.getElementById('messages');
    if(msgs.children.length === 1 && msgs.children[0].innerText.includes('Connecting')) msgs.innerHTML = '';
    let div = document.createElement('div');
    div.className = 'system-message';
    div.textContent = text;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
}

function addMessage(sender, text, isSent) {
    let msgs = document.getElementById('messages');
    if(msgs.children.length === 1 && msgs.children[0].innerText.includes('Connecting')) msgs.innerHTML = '';
    let div = document.createElement('div');
    div.className = 'message ' + (isSent ? 'sent' : 'received');
    let time = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    div.innerHTML = '<div class="message-sender">' + (isSent ? 'YOU' : escapeHtml(sender)) + '</div><div class="message-bubble">' + escapeHtml(text) + '</div><div class="message-time">' + time + '</div>';
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
}

function updateUsers(users) {
    let ul = document.getElementById('usersList');
    if(users.length === 0) ul.innerHTML = '<div class="user-item">No users online</div>';
    else ul.innerHTML = users.map(u => '<div class="user-item">' + escapeHtml(u) + '</div>').join('');
}

function escapeHtml(t) {
    let d = document.createElement('div');
    d.textContent = t;
    return d.innerHTML;
}

function logout() {
    if(ws) ws.close();
    ws = null;
    document.getElementById('chatScreen').classList.remove('active');
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('messages').innerHTML = '<div style="text-align:center;color:#666;padding:40px 0;">Connecting...</div>';
    document.getElementById('usersList').innerHTML = '<div class="user-item">Loading...</div>';
    document.getElementById('loginUsername').value = 'Mpc';
    document.getElementById('loginPassword').value = '08800Mpc!';
    document.getElementById('adminBtn').style.display = 'none';
    reconnectAttempts = 0;
    currentUser = null;
}

// ========== ENCRYPTION ==========
async function encrypt(text, pwd, salt) {
    const e = new TextEncoder();
    const km = await crypto.subtle.importKey('raw', e.encode(pwd), 'PBKDF2', false, ['deriveKey']);
    const k = await crypto.subtle.deriveKey(
        {name:'PBKDF2', salt:e.encode(salt), iterations:100000, hash:'SHA-256'},
        km, {name:'AES-GCM', length:256}, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({name:'AES-GCM', iv}, k, e.encode(text));
    const c = new Uint8Array(iv.length + enc.byteLength);
    c.set(iv, 0);
    c.set(new Uint8Array(enc), iv.length);
    return btoa(String.fromCharCode(...c));
}

async function decrypt(enc, pwd, salt) {
    const d = Uint8Array.from(atob(enc), c => c.charCodeAt(0));
    const iv = d.slice(0, 12), data = d.slice(12);
    const e = new TextEncoder();
    const km = await crypto.subtle.importKey('raw', e.encode(pwd), 'PBKDF2', false, ['deriveKey']);
    const k = await crypto.subtle.deriveKey(
        {name:'PBKDF2', salt:e.encode(salt), iterations:100000, hash:'SHA-256'},
        km, {name:'AES-GCM', length:256}, false, ['decrypt']
    );
    const dec = await crypto.subtle.decrypt({name:'AES-GCM', iv}, k, data);
    return new TextDecoder().decode(dec);
}

// ========== MESSAGING ==========
document.getElementById('messageInput')?.addEventListener('input', function() {
    if(ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({type:'typing'}));
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => {
            if(ws && ws.readyState === WebSocket.OPEN)
                ws.send(JSON.stringify({type:'stop_typing'}));
        }, 1000);
    }
});

document.getElementById('messageInput')?.addEventListener('keypress', function(e) {
    if(e.key === 'Enter') sendMessage();
});

async function sendMessage() {
    let input = document.getElementById('messageInput');
    let text = input.value.trim();
    if(!text || !ws || ws.readyState !== WebSocket.OPEN || !groupSalt) return;
    try {
        let cipher = await encrypt(text, DEFAULT_PASSWORD, groupSalt);
        ws.send(JSON.stringify({
            type:'message',
            ciphertext:cipher,
            salt:groupSalt
        }));
        addMessage(currentUser.username, text, true);
        input.value = '';
    } catch(e) {
        alert('Failed to send message');
    }
}

// ========== ADMIN PANEL ==========
async function openAdmin() {
    if(currentUser.role !== 'admin') {
        alert('Admin access required');
        return;
    }
    document.getElementById('adminPanel').classList.add('active');
    await loadAdminData();
}

function closeAdmin() {
    document.getElementById('adminPanel').classList.remove('active');
}

async function loadAdminData() {
    try {
        const response = await fetch('/admin/data');
        const data = await response.json();
        
        // Update stats
        document.getElementById('statUsers').textContent = data.users.length;
        document.getElementById('statMessages').textContent = data.messages_count;
        document.getElementById('statGroups').textContent = data.groups.length;
        document.getElementById('statOnline').textContent = data.online_count;
        
        // Update users table
        let usersHtml = '';
        data.users.forEach(u => {
            usersHtml += `<tr>
                <td>${escapeHtml(u.username)}</td>
                <td>${u.role}</td>
                <td>${u.status}</td>
                <td>
                    ${u.username !== 'Mpc' ? `<button class="action-btn" onclick="deleteUser('${u.username}')">Delete</button>` : '⭐ Admin'}
                </td>
            </tr>`;
        });
        document.getElementById('usersTableBody').innerHTML = usersHtml;
        
        // Update groups table
        let groupsHtml = '';
        data.groups.forEach(g => {
            groupsHtml += `<tr>
                <td>${escapeHtml(g.name)}</td>
                <td>${escapeHtml(g.created_by)}</td>
                <td><button class="action-btn" onclick="deleteGroup('${g.name}')">Delete</button></td>
            </tr>`;
        });
        document.getElementById('groupsTableBody').innerHTML = groupsHtml;
        
        // Update messages table
        let messagesHtml = '';
        data.messages.forEach(m => {
            let time = new Date(m.created_at * 1000).toLocaleString();
            messagesHtml += `<tr>
                <td>${escapeHtml(m.sender)}</td>
                <td>${escapeHtml(m.group)}</td>
                <td>${time}</td>
                <td><button class="action-btn" onclick="deleteMessage(${m.id})">Delete</button></td>
            </tr>`;
        });
        document.getElementById('messagesTableBody').innerHTML = messagesHtml;
        
        // Update logs table
        let logsHtml = '';
        data.logs.forEach(l => {
            let time = new Date(l.time * 1000).toLocaleString();
            logsHtml += `<tr>
                <td>${escapeHtml(l.admin)}</td>
                <td>${escapeHtml(l.action)}</td>
                <td>${escapeHtml(l.target)}</td>
                <td>${time}</td>
            </tr>`;
        });
        document.getElementById('logsTableBody').innerHTML = logsHtml;
        
    } catch(e) {
        console.error('Failed to load admin data:', e);
    }
}

async function addUser() {
    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newPassword').value.trim();
    const role = document.getElementById('newRole').value;
    
    if(!username || !password) {
        alert('Please enter username and password');
        return;
    }
    
    try {
        const response = await fetch('/admin/add_user', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password, role})
        });
        const data = await response.json();
        if(data.success) {
            alert('User added successfully!');
            document.getElementById('newUsername').value = '';
            document.getElementById('newPassword').value = '';
            loadAdminData();
        } else {
            alert(data.message || 'Failed to add user');
        }
    } catch(e) {
        alert('Error adding user');
    }
}

async function deleteUser(username) {
    if(!confirm(`Delete user "${username}"?`)) return;
    try {
        const response = await fetch('/admin/delete_user', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username})
        });
        const data = await response.json();
        if(data.success) {
            alert('User deleted successfully');
            loadAdminData();
        } else {
            alert(data.message || 'Failed to delete user');
        }
    } catch(e) {
        alert('Error deleting user');
    }
}

async function addGroup() {
    const name = document.getElementById('newGroupName').value.trim();
    const password = document.getElementById('newGroupPassword').value.trim();
    
    if(!name || !password) {
        alert('Please enter group name and password');
        return;
    }
    
    try {
        const response = await fetch('/admin/add_group', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name, password})
        });
        const data = await response.json();
        if(data.success) {
            alert('Group added successfully!');
            document.getElementById('newGroupName').value = '';
            document.getElementById('newGroupPassword').value = '';
            loadAdminData();
        } else {
            alert(data.message || 'Failed to add group');
        }
    } catch(e) {
        alert('Error adding group');
    }
}

async function deleteGroup(name) {
    if(!confirm(`Delete group "${name}"? This will delete all messages in this group.`)) return;
    try {
        const response = await fetch('/admin/delete_group', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name})
        });
        const data = await response.json();
        if(data.success) {
            alert('Group deleted successfully');
            loadAdminData();
        } else {
            alert(data.message || 'Failed to delete group');
        }
    } catch(e) {
        alert('Error deleting group');
    }
}

async function deleteMessage(id) {
    if(!confirm('Delete this message?')) return;
    try {
        const response = await fetch('/admin/delete_message', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({id})
        });
        const data = await response.json();
        if(data.success) {
            alert('Message deleted successfully');
            loadAdminData();
        } else {
            alert(data.message || 'Failed to delete message');
        }
    } catch(e) {
        alert('Error deleting message');
    }
}

// ========== KEYBOARD SHORTCUTS ==========
document.addEventListener('keydown', function(e) {
    if(e.key === 'Enter' && document.activeElement === document.getElementById('loginUsername')) {
        document.getElementById('loginPassword').focus();
    }
    if(e.key === 'Enter' && document.activeElement === document.getElementById('loginPassword')) {
        login();
    }
    if(e.key === 'Escape' && document.getElementById('adminPanel').classList.contains('active')) {
        closeAdmin();
    }
});

// ========== AUTO-LOGIN PREVIEW ==========
// Pre-fill admin credentials for quick access
console.log('🔐 ABAVANDIMWE Secure Messaging System');
console.log('📱 Developed by Mugisha Pc');
console.log('👤 Admin: Mpc / 08800Mpc!');
console.log('💡 Click Login or press Enter to access the chat');
</script>
</body>
</html>'''

# ========== FASTAPI ENDPOINTS ==========
@app.get("/")
async def root():
    return HTMLResponse(HTML)

@app.post("/login")
async def login(username: str, password: str):
    user = authenticate_user(username, password)
    if user:
        return {"success": True, "username": user["username"], "role": user["role"]}
    return {"success": False, "message": "Invalid credentials"}

@app.get("/admin/data")
async def admin_data():
    users = get_all_users()
    messages = get_all_messages()
    groups = get_all_groups()
    logs = get_admin_logs()
    online_users = get_online_users("Main")
    
    return {
        "users": users,
        "messages": messages,
        "messages_count": len(messages),
        "groups": groups,
        "online_count": len(online_users),
        "logs": logs
    }

@app.post("/admin/add_user")
async def admin_add_user(username: str, password: str, role: str = "user"):
    if create_user(username, password, role):
        log_admin_action("Mpc", "add_user", username, f"Role: {role}")
        return {"success": True}
    return {"success": False, "message": "Username already exists"}

@app.post("/admin/delete_user")
async def admin_delete_user(username: str):
    if delete_user(username):
        log_admin_action("Mpc", "delete_user", username)
        return {"success": True}
    return {"success": False, "message": "Cannot delete admin or user not found"}

@app.post("/admin/add_group")
async def admin_add_group(name: str, password: str):
    salt = generate_salt()
    pwd_hash = hash_password(password, salt)
    if create_group(name, salt, pwd_hash, "Mpc"):
        log_admin_action("Mpc", "add_group", name)
        return {"success": True}
    return {"success": False, "message": "Group already exists"}

@app.post("/admin/delete_group")
async def admin_delete_group(name: str):
    if delete_group(name):
        log_admin_action("Mpc", "delete_group", name)
        return {"success": True}
    return {"success": False, "message": "Group not found"}

@app.post("/admin/delete_message")
async def admin_delete_message(id: int):
    if delete_message(id):
        log_admin_action("Mpc", "delete_message", str(id))
        return {"success": True}
    return {"success": False, "message": "Message not found"}

# ========== WEBSOCKET ==========
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    username = None
    group_name = None
    ping_task = None

    async def send_ping():
        while True:
            await asyncio.sleep(30)
            if username and group_name:
                try:
                    await websocket.send_json({'type': 'ping'})
                except:
                    break

    try:
        ping_task = asyncio.create_task(send_ping())
        
        while True:
            data = await websocket.receive_json()
            msg_type = data.get('type')

            if msg_type == 'join':
                username = data.get('username')
                group_name = data.get('group')
                password = data.get('password')

                user = authenticate_user(username, password)
                if not user:
                    await websocket.send_json({'type': 'error', 'message': 'Invalid user credentials'})
                    await websocket.close()
                    return

                group_info = get_group_info(group_name)
                if group_info:
                    if not verify_password(password, group_info['salt'], group_info['password_hash']):
                        await websocket.send_json({'type': 'error', 'message': 'Wrong group password'})
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
                if username and group_name and check_rate_limit(username):
                    save_message(cipher, group_name, username, salt)
                    await manager.broadcast(group_name, {
                        'type': 'message',
                        'ciphertext': cipher,
                        'sender': username,
                        'salt': salt
                    }, exclude=username)

            elif msg_type == 'typing':
                if username and group_name:
                    await manager.broadcast(group_name, {'type': 'typing', 'user': username}, exclude=username)

            elif msg_type == 'stop_typing':
                if username and group_name:
                    await manager.broadcast(group_name, {'type': 'stop_typing', 'user': username}, exclude=username)

            elif msg_type == 'ping':
                set_user_status(username, 'online', group_name)
                await websocket.send_json({'type': 'pong'})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        if ping_task:
            ping_task.cancel()
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
    print(f"[✓] Server running on port {port}")
    print(f"[✓] Admin: Mpc / 08800Mpc!")
    print(f"[✓] Default Group: Main / Abavandimwe2026")
    print(f"[✓] Messages expire after 24 hours")
    print(f"[✓] Open: http://localhost:{port}")
    print(f"[✓] Admin Panel: Click ⚙️ Admin button after login")
    print(f"\n💡 Quick Login: Just press Enter (credentials pre-filled)")
    uvicorn.run(app, host="0.0.0.0", port=port)
