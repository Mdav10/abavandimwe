#!/usr/bin/env python3
"""
ABAVANDIMWE - Ultimate Secure Messaging System
Author: Mugisha Pc
"""

import asyncio
import os
import sys
from loguru import logger

from src.database_manager import db
from src.websocket_server import handler

HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 8080))

logger.remove()
logger.add(sys.stdout, format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | <message>", level="INFO")

BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   █████╗ ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗██████╗ ██╗███╗   ███╗ ██╗
║  ██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔══██╗██║████╗ ████║ ██║
║  ███████║██████╔╝███████║██║   ██║███████║██╔██╗ ██║██║  ██║██║██╔████╔██║ ██║
║  ██╔══██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║  ██║██║██║╚██╔╝██║ ╚═╝
║  ██║  ██║██████╔╝██║  ██║ ╚████╔╝ ██║  ██║██║ ╚████║██████╔╝██║██║ ╚═╝ ██║ ██╗
║  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝╚═╝     ╚═╝ ╚═╝
║                                                                              ║
║                    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗        ║
║                    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝        ║
║                    ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗          ║
║                    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝          ║
║                    ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗        ║
║                    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝        ║
║                                                                              ║
║              NEXT GENERATION SECURE MESSAGING SYSTEM                         ║
║                   MESSAGES AUTO-DELETE AFTER 24H                             ║
║                                                                              ║
║                      AUTHOR: MUGISHA PC                                      ║
║                      VERSION: 5.0.0 - HACKER EDITION                         ║
║                                                                              ║
║  ⚡ FEATURES:                                                                ║
║  🔐 AES-256-GCM Encryption                                                  ║
║  ⏰ Auto-Delete Messages (24 Hours)                                         ║
║  👥 Real-time User Presence                                                 ║
║  ✏️ Typing Indicators                                                       ║
║  📱 Mobile Optimized                                                        ║
║  🚀 Blazing Fast                                                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

async def main():
    print(BANNER)
    logger.info(f"🔥 ABAVANDIMWE v5.0 starting on {HOST}:{PORT}")
    await db.connect()
    await handler.start(HOST, PORT)

if __name__ == "__main__":
    asyncio.run(main())
