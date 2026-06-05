"""
ABAVANDIMWE - WebSocket Server
Author: Mugisha Pc
"""

import asyncio
import json
import websockets
from typing import Dict, Set
from datetime import datetime
from loguru import logger

from crypto import crypto
from database import db

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
