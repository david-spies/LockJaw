"""
LockJaw — Hybrid Encryption Messaging System
Server Entry Point (FastAPI + WebSocket)
"""

import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Set

# Ensure the project root is in the path for module discovery
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from auth.totp_manager import TOTPManager
from auth.session_manager import SessionManager
from crypto.hybrid_cipher import HybridCipher
from config.settings import Settings

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("lockjaw")

settings = Settings()
totp_manager = TOTPManager()
session_manager = SessionManager()
cipher = HybridCipher()


# ── Connection Manager ─────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: Dict[str, WebSocket] = {}  # node_id -> websocket

    async def connect(self, node_id: str, ws: WebSocket):
        await ws.accept()
        self.active[node_id] = ws
        logger.info(f"Node connected: {node_id} | peers online: {len(self.active)}")

    def disconnect(self, node_id: str):
        self.active.pop(node_id, None)
        logger.info(f"Node disconnected: {node_id}")

    async def send_to(self, node_id: str, payload: dict):
        ws = self.active.get(node_id)
        if ws:
            await ws.send_text(json.dumps(payload))

    async def broadcast(self, payload: dict, exclude: str = None):
        for nid, ws in list(self.active.items()):
            if nid != exclude:
                try:
                    await ws.send_text(json.dumps(payload))
                except Exception:
                    pass

    def online_nodes(self) -> list:
        return list(self.active.keys())


manager = ConnectionManager()


# ── App Lifespan ───────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("LockJaw server starting — Zero-Trust mode active")
    yield
    logger.info("LockJaw server shutting down — clearing sessions")
    session_manager.clear_all()


# ── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="LockJaw",
    description="Hybrid Encryption Messaging System",
    version="2.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the frontend
if os.path.isdir("client/dist"):
    app.mount("/static", StaticFiles(directory="client/dist"), name="static")


# ── REST Endpoints ─────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    if os.path.isfile("client/dist/index.html"):
        return FileResponse("client/dist/index.html")
    return {"app": "LockJaw", "version": "2.1.0", "status": "running"}


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "nodes_online": len(manager.active),
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/api/auth/register")
async def register(payload: dict):
    """Register a new node and provision its TOTP secret."""
    node_id = payload.get("node_id", "").upper().strip()
    if not node_id:
        raise HTTPException(400, "node_id required")
    secret, uri = totp_manager.provision(node_id)
    logger.info(f"Node registered: {node_id}")
    return {"node_id": node_id, "totp_uri": uri, "secret": secret}


@app.post("/api/auth/verify")
async def verify_totp(payload: dict):
    """Verify a TOTP code and issue a session token."""
    node_id = payload.get("node_id", "").upper()
    code = payload.get("code", "")
    beale_phrase = payload.get("beale_phrase", "")
    machine_id = payload.get("machine_id", node_id)

    if not totp_manager.verify(node_id, code):
        raise HTTPException(401, "Invalid or expired 2FA code")

    token = session_manager.create_session(node_id, machine_id, beale_phrase)
    logger.info(f"Session created for node: {node_id}")
    return {"token": token, "node_id": node_id, "expires_in": 3600}


@app.get("/api/nodes/online")
async def online_nodes():
    return {"nodes": manager.online_nodes(), "count": len(manager.active)}


# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws/{node_id}")
async def websocket_endpoint(websocket: WebSocket, node_id: str):
    """
    Main WebSocket channel. Server NEVER decrypts messages —
    it routes ciphertext only. Zero-Trust by design.
    """
    node_id = node_id.upper()
    await manager.connect(node_id, websocket)

    # Notify peers this node came online
    await manager.broadcast(
        {"type": "PEER_ONLINE", "node_id": node_id, "ts": datetime.utcnow().isoformat()},
        exclude=node_id,
    )

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"type": "ERROR", "detail": "Invalid JSON"}))
                continue

            msg_type = msg.get("type", "")

            # ── Routing only — server never sees plaintext ──────────────────────
            if msg_type == "MSG":
                target = msg.get("to", "").upper()
                payload = {
                    "type": "MSG",
                    "from": node_id,
                    "ciphertext": msg.get("ciphertext", ""),
                    "ts": datetime.utcnow().isoformat(),
                }
                if target and target in manager.active:
                    await manager.send_to(target, payload)
                else:
                    await websocket.send_text(json.dumps({"type": "ERROR", "detail": f"Node {target} not online"}))

            elif msg_type == "PING":
                await websocket.send_text(json.dumps({"type": "PONG", "ts": datetime.utcnow().isoformat()}))

            elif msg_type == "WHO":
                await websocket.send_text(json.dumps({"type": "NODES", "nodes": manager.online_nodes()}))

    except WebSocketDisconnect:
        manager.disconnect(node_id)
        await manager.broadcast(
            {"type": "PEER_OFFLINE", "node_id": node_id, "ts": datetime.utcnow().isoformat()},
            exclude=node_id,
        )


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Using 'server.app:app' ensures Uvicorn can find the instance 
    # when running from the project root.
    uvicorn.run(
        "server.app:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
    )
