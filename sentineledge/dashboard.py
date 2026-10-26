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

All /api/* routes need 'Authorization: Bearer <token>'; /ws needs ?token=<token>.
"""
import asyncio
import json
import secrets
from pathlib import Path
from ipaddress import IPv4Address
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from .database import (
    get_alerts, get_blocks, add_block, remove_block,
    get_whitelist, add_whitelist, remove_whitelist, is_whitelisted, get_alert_summary, is_blocked
)
from .decision import firewall_block, firewall_unblock

from contextlib import asynccontextmanager

_loop: asyncio.AbstractEventLoop | None = None
_capture = None
_dry_run = True
_token = secrets.token_urlsafe(24)   # replaced by run.py; never empty

def configure_capture(capture, dry_run: bool = True):
    global _capture, _dry_run
    _capture, _dry_run = capture, dry_run

def configure_auth(token: str):
    """Set the access token required by /api/* and /ws."""
    global _token
    if not token:
        raise ValueError("access token must not be empty")
    _token = token

def token_ok(candidate: str | None) -> bool:
    return bool(candidate) and secrets.compare_digest(candidate.encode(), _token.encode())

def capture_status() -> dict:
    return {**(_capture.snapshot() if _capture else {"status": "starting", "mode": "unknown", "uptime_seconds": 0}),
            "dry_run": _dry_run}

async def publish_telemetry():
    while True:
        await manager.broadcast({"type": "packet_stats", "data": capture_status()})
        await asyncio.sleep(1)

@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    global _loop
    _loop = asyncio.get_running_loop()
    task = asyncio.create_task(publish_telemetry())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        _loop = None
        if _capture:
            _capture.stop()

app = FastAPI(title="SentinelEdge Dashboard", lifespan=lifespan)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


@app.middleware("http")
async def require_token(request: Request, call_next):
    """Every /api/* request needs 'Authorization: Bearer <token>'; the page itself holds no data."""
    if request.url.path.startswith("/api"):
        scheme, _, candidate = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token_ok(candidate):
            return JSONResponse({"detail": "Missing or invalid access token"}, status_code=401)
    return await call_next(request)

# ── WebSocket connection manager ──────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._clients: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._clients.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self._clients:
            self._clients.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in list(self._clients):
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


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

@app.get("/api/status")
async def api_status():
    return {**capture_status(), **get_alert_summary(), "blocked_ips": len(get_blocks())}

def validate_ip(ip: str):
    try:
        IPv4Address(ip)
    except ValueError:
        raise HTTPException(422, "A valid IPv4 address is required")


@app.get("/api/blocks")
async def api_blocks():
    return get_blocks()


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual"


@app.post("/api/blocks")
async def api_add_block(body: BlockRequest):
    validate_ip(body.ip)
    if body.ip in ("127.0.0.1", "192.168.56.1") or is_whitelisted(body.ip):
        raise HTTPException(409, "Protected or whitelisted address")
    # Manual blocks are enforced in live mode and last until removed
    if not _dry_run and not firewall_block(body.ip):
        raise HTTPException(502, "Firewall update failed; see the server log")
    add_block(body.ip, body.reason)
    await manager.broadcast({"type": "block_added", "ip": body.ip})
    return {"status": "ok"}


async def _unblock(ip: str):
    if not _dry_run:
        firewall_unblock(ip)
    remove_block(ip)
    await manager.broadcast({"type": "block_removed", "ip": ip})


@app.delete("/api/blocks/{ip}")
async def api_remove_block(ip: str):
    validate_ip(ip)
    await _unblock(ip)
    return {"status": "ok"}


@app.get("/api/whitelist")
async def api_whitelist():
    return get_whitelist()


class WhitelistRequest(BaseModel):
    ip: str
    note: str = ""


@app.post("/api/whitelist")
async def api_add_whitelist(body: WhitelistRequest):
    validate_ip(body.ip)
    add_whitelist(body.ip, body.note)
    if is_blocked(body.ip):            # trusting an address also lifts its block
        await _unblock(body.ip)
    return {"status": "ok"}


@app.delete("/api/whitelist/{ip}")
async def api_remove_whitelist(ip: str):
    remove_whitelist(ip)
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    # Browsers can't set headers on WebSockets, so the token travels as ?token=
    if not token_ok(ws.query_params.get("token")):
        await ws.close(code=1008)   # policy violation; rejects the handshake
        return
    await manager.connect(ws)
    try:
        await ws.send_json({"type": "packet_stats", "data": capture_status()})
        while True:
            await ws.receive_text()   # keep connection alive
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(ws)
