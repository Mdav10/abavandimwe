"""
ABAVANDIMWE Database Manager - SQLite
Author: Mugisha Pc
"""

import sqlite3
import asyncio
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from loguru import logger
import json

class Database:
    def __init__(self, url: str = None):
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
        logger.info("✅ SQLite database initialized")
    
    async def connect(self):
        asyncio.create_task(self._cleanup_loop())
        return self
    
    async def save_message(self, ciphertext: str, group: str, sender: str, salt: str):
        def _save():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                INSERT INTO messages (ciphertext, group_name, sender, salt)
                VALUES (?, ?, ?, ?)
            ''', (ciphertext, group, sender, salt))
            conn.commit()
            conn.close()
        
        await asyncio.to_thread(_save)
    
    async def get_messages(self, group: str, limit: int = 100) -> List[Dict]:
        def _get():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                SELECT ciphertext, sender, salt, created_at
                FROM messages 
                WHERE group_name = ? 
                AND created_at > datetime('now', '-24 hours')
                ORDER BY created_at ASC LIMIT ?
            ''', (group, limit))
            rows = c.fetchall()
            conn.close()
            return [{'ciphertext': r[0], 'sender': r[1], 'salt': r[2], 'created_at': r[3]} for r in rows]
        
        return await asyncio.to_thread(_get)
    
    async def set_user_status(self, username: str, status: str, group: str = None):
        def _set():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                INSERT OR REPLACE INTO users (username, status, current_group, last_seen)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (username, status, group))
            conn.commit()
            conn.close()
        
        await asyncio.to_thread(_set)
    
    async def get_online_users(self, group: str) -> List[str]:
        def _get():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                SELECT username FROM users 
                WHERE status = 'online' AND current_group = ?
                AND last_seen > datetime('now', '-2 minutes')
            ''', (group,))
            rows = c.fetchall()
            conn.close()
            return [r[0] for r in rows]
        
        return await asyncio.to_thread(_get)
    
    async def get_group_salt(self, group: str) -> Optional[str]:
        def _get():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT salt FROM groups WHERE group_name = ?", (group,))
            row = c.fetchone()
            conn.close()
            return row[0] if row else None
        
        return await asyncio.to_thread(_get)
    
    async def create_group(self, group: str, salt: str, creator: str) -> bool:
        def _create():
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            try:
                c.execute("INSERT INTO groups (group_name, salt, created_by) VALUES (?, ?, ?)",
                         (group, salt, creator))
                conn.commit()
                conn.close()
                return True
            except:
                conn.close()
                return False
        
        return await asyncio.to_thread(_create)
    
    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(3600)
            def _cleanup():
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                c.execute("DELETE FROM messages WHERE expires_at < CURRENT_TIMESTAMP")
                deleted = c.rowcount
                conn.commit()
                conn.close()
                if deleted > 0:
                    logger.info(f"🧹 Cleaned {deleted} expired messages")
            
            await asyncio.to_thread(_cleanup)
    
    async def close(self):
        pass
