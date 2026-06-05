#!/usr/bin/env python3
"""
ABAVANDIMWE - Secure Messaging System
Author: Mugisha Pc
"""

import asyncio
import os
import sys
from loguru import logger

from src.database import db
from src.server import server

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
║                    Version: 5.0.0                                 ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""

async def main():
    print(BANNER)
    logger.info(f"🔥 ABAVANDIMWE v5.0 starting on {HOST}:{PORT}")
    await db.connect()
    await server.start(HOST, PORT)

if __name__ == "__main__":
    asyncio.run(main())
