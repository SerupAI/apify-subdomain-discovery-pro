"""
Advanced Subdomain Discovery & Security Intelligence Actor
Main entry point for the Apify actor
"""
import asyncio
from apify import Actor
from .main import main

if __name__ == "__main__":
    asyncio.run(main())