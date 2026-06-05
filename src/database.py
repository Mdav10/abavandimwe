"""
ABAVANDIMWE Database Manager
Author: Mugisha Pc
"""

import asyncpg
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from loguru import logger

class Database:
    def __init__(self, url: str):
        self.url = url
        self.pool = None
    
    async def connect(self):
        self.pool = await asyncpg.create_pool(
            self.url,
            min_size=5,
            max_size=20,
            command_timeout=60
        )
        await self._init_tables()
        asyncio.create_task(self._cleanup_loop())
        logger.info("✅ Database connected")
    
    async def _init_tables(self):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id BIGSERIAL PRIMARY KEY,
                    ciphertext TEXT NOT NULL,
                    group_name VARCHAR(255) NOT NULL,
                    sender VARCHAR(255) NOT NULL,
                    salt VARCHAR(255) NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP + INTERVAL '24 hours'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username VARCHAR(255) PRIMARY KEY,
                    status VARCHAR(20) DEFAULT 'offline',
                    current_group VARCHAR(255),
                    last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS groups (
                    group_name VARCHAR(255) PRIMARY KEY,
                    salt VARCHAR(255) NOT NULL,
                    created_by VARCHAR(255) NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON messages(expires_at)")
    
    async def save_message(self, ciphertext: str, group: str, sender: str, salt: str):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO messages (ciphertext, group_name, sender, salt)
                VALUES ($1, $2, $3, $4)
            """, ciphertext, group, sender, salt)
    
    async def get_messages(self, group: str, limit: int = 100) -> List[Dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT ciphertext, sender, salt, created_at
                FROM messages WHERE group_name = $1 
                AND created_at > NOW() - INTERVAL '24 hours'
                ORDER BY created_at ASC LIMIT $2
            """, group, limit)
            return [dict(r) for r in rows]
    
    async def set_user_status(self, username: str, status: str, group: str = None):
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO users (username, status, current_group, last_seen)
                VALUES ($1, $2, $3, NOW())
                ON CONFLICT (username) DO UPDATE SET 
                    status = $2, current_group = $3, last_seen = NOW()
            """, username, status, group)
    
    async def get_online_users(self, group: str) -> List[str]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT username FROM users 
                WHERE status = 'online' AND current_group = $1
                AND last_seen > NOW() - INTERVAL '2 minutes'
            """, group)
            return [r['username'] for r in rows]
    
    async def get_group_salt(self, group: str) -> Optional[str]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT salt FROM groups WHERE group_name = $1", group)
            return row['salt'] if row else None
    
    async def create_group(self, group: str, salt: str, creator: str) -> bool:
        async with self.pool.acquire() as conn:
            try:
                await conn.execute(
                    "INSERT INTO groups (group_name, salt, created_by) VALUES ($1, $2, $3)",
                    group, salt, creator
                )
                return True
            except:
                return False
    
    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(3600)
            async with self.pool.acquire() as conn:
                result = await conn.execute("DELETE FROM messages WHERE expires_at < NOW()")
                logger.info(f"🧹 Cleanup completed")
    
    async def close(self):
        if self.pool:
            await self.pool.close()
