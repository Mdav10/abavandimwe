#!/usr/bin/env python3
"""
ABAVANDIMWE - Complete Secure Messaging System
Author: Mugisha Pc
One file - No import issues!
"""

import asyncio
import json
import websockets
import sqlite3
import secrets
import base64
import hashlib
import os
import sys
from datetime import datetime
from typing import Dict, Set, List, Optional
from loguru import logger

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
        logger.info("✅ Database ready")
    
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
                logger.info(f"🧹 Cleaned {deleted} messages")
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
# WEBSOCKET SERVER
# ============================================

class WebSocketServer:
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
    
    async def handle(self, websocket: websockets.WebSocketServerProtocol, path: str):
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
                    
                    # Send history
                    for msg in await db.get_messages(group):
                        await websocket.send(json.dumps({
                            'type': 'history',
                            'ciphertext': msg['ciphertext'],
                            'sender': msg['sender'],
                            'salt': msg['salt']
                        }))
                    
                    # Send online users
                    online = await db.get_online_users(group)
                    await self.broadcast(group, {'type': 'users', 'users': online})
                    
                    await websocket.send(json.dumps({
                        'type': 'ready',
                        'salt': salt,
                        'group': group
                    }))
                    
                    logger.info(f"✅ {user} joined {group}")
                
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
            logger.error(f"Error: {e}")
        finally:
            if user and group:
                if group in self.connections:
                    self.connections[group].pop(user, None)
                await db.set_user_status(user, 'offline', group)
                online = await db.get_online_users(group)
                await self.broadcast(group, {'type': 'users', 'users': online})
                logger.info(f"👋 {user} left")
    
    async def start(self, host: str = "0.0.0.0", port: int = 8080):
        async with websockets.serve(self.handle, host, port):
            logger.info(f"🚀 Server on ws://{host}:{port}")
            await asyncio.Future()

server = WebSocketServer()

# ============================================
# MAIN
# ============================================

HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 8080))

logger.remove()
logger.add(sys.stdout, format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | <message>", level="INFO")

BANNER = """
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
║                    Version: 6.0.0                                 ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""

async def main():
    print(BANNER)
    logger.info(f"🔥 ABAVANDIMWE v6.0 starting on {HOST}:{PORT}")
    await db.connect()
    await server.start(HOST, PORT)

if __name__ == "__main__":
    asyncio.run(main())
