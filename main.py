#!/usr/bin/env python3
"""
ABAVANDIMWE - Next Generation Secure Messaging
Author: Mugisha Pc
"""

import asyncio
import os
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    'DATABASE_URL',
    'postgresql://neondb_owner:npg_Cb7XtKr0BIoN@ep-holy-scene-apw8vqig.c-7.us-east-1.aws.neon.tech/neondb?sslmode=require'
)

from src.database import Database
from src.websocket import WebSocketManager

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
    ║              NEXT GENERATION SECURE MESSAGING                     ║
    ║                   MESSAGES AUTO-DELETE 24H                        ║
    ║                      AUTHOR: MUGISHA PC                           ║
    ║                      VERSION: 4.0.0                               ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    logger.info("Starting ABAVANDIMWE v4.0")
    
    db = Database(DATABASE_URL)
    await db.connect()
    
    ws = WebSocketManager(db)
    await ws.start(host="0.0.0.0", port=8080)

if __name__ == "__main__":
    asyncio.run(main())
