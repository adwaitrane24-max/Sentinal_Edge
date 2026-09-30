"""
dashboard.py — FastAPI + WebSocket live dashboard.

Endpoints:
  GET  /                → main dashboard page
  GET  /api/alerts      → last 100 alerts (JSON)
  GET  /api/blocks      → current block list (JSON)
  POST /api/blocks      → manually add block  {ip, reason}
  DELETE /api/blocks/{ip} → remove a block
  GET  /api/whitelist   → current whitelist (JSON)
  POST /api/whitelist   → add to whitelist   {ip, note}
  DELETE /api/whitelist/{ip} → remove from whitelist
  WS   /ws             → real-time alert push
"""
import asyncio
import json
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from .database import (
    get_alerts, get_blocks, add_block, remove_block,
    get_whitelist, add_whitelist, remove_whitelist
)

from contextlib import asynccontextmanager

_loop: asyncio.AbstractEventLoop | None = None

@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    global _loop
    _loop = asyncio.get_running_loop()
    yield

app = FastAPI(title="SentinelEdge Dashboard", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

# ── WebSocket connection manager ──────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._clients: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._clients.append(ws)

    def disconnect(self, ws: WebSocket):
        self._clients.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self._clients:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients.remove(ws)


manager = ConnectionManager()


async def push_alert(alert_dict: dict):
    """Called from the detection engine (via asyncio) to push new alerts."""
    await manager.broadcast({"type": "alert", "data": alert_dict})


def push_alert_from_thread(alert_dict: dict):
    """Thread-safe helper to push alerts from background capture thread."""
    if _loop and _loop.is_running():
        asyncio.run_coroutine_threadsafe(push_alert(alert_dict), _loop)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/api/alerts")
async def api_alerts():
    return get_alerts(limit=100)


@app.get("/api/blocks")
async def api_blocks():
    return get_blocks()


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual"


@app.post("/api/blocks")
async def api_add_block(body: BlockRequest):
    add_block(body.ip, body.reason)
    await manager.broadcast({"type": "block_added", "ip": body.ip})
    return {"status": "ok"}


@app.delete("/api/blocks/{ip}")
async def api_remove_block(ip: str):
    remove_block(ip)
    await manager.broadcast({"type": "block_removed", "ip": ip})
    return {"status": "ok"}


@app.get("/api/whitelist")
async def api_whitelist():
    return get_whitelist()


class WhitelistRequest(BaseModel):
    ip: str
    note: str = ""


@app.post("/api/whitelist")
async def api_add_whitelist(body: WhitelistRequest):
    add_whitelist(body.ip, body.note)
    return {"status": "ok"}


@app.delete("/api/whitelist/{ip}")
async def api_remove_whitelist(ip: str):
    remove_whitelist(ip)
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()   # keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(ws)
