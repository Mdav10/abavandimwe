#!/usr/bin/env python3
"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
"""

import asyncio
import os
import sys
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

from src.database import Database
from src.websocket import WebSocketManager

HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 8080))

logger.remove()
logger.add(sys.stdout, format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | <message>", level="INFO")

async def main():
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
    ║              Messages Auto-Delete After 24 Hours                  ║
    ║                    Author: Mugisha Pc                             ║
    ║                    Version: 4.0.0                                 ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    logger.info(f"Starting ABAVANDIMWE on {HOST}:{PORT}")
    
    db = Database()
    await db.connect()
    
    ws = WebSocketManager(db)
    await ws.start(HOST, PORT)

if __name__ == "__main__":
    asyncio.run(main())
