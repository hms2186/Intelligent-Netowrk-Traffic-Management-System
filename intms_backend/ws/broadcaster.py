"""
ws/broadcaster.py
WebSocket connection manager.
Keeps track of all connected clients and broadcasts JSON payloads.
"""

import asyncio
import json
import logging
from typing import List

from fastapi import WebSocket

log = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self._clients: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._clients.append(ws)
        log.info(f"[WS] Client connected. Total: {len(self._clients)}")

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self._clients:
                self._clients.remove(ws)
        log.info(f"[WS] Client disconnected. Total: {len(self._clients)}")

    async def broadcast(self, payload: dict):
        """Send payload to all connected clients. Remove dead connections."""
        text = json.dumps(payload, default=str)
        dead = []

        async with self._lock:
            clients = list(self._clients)

        for ws in clients:
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    if ws in self._clients:
                        self._clients.remove(ws)


manager = ConnectionManager()
