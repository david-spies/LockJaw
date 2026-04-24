"""
LockJaw — Hybrid Encryption Messaging Server
Zero-Trust WebSocket relay. Server never holds plaintext.
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Set

import websockets
from websockets.server import WebSocketServerProtocol

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("lockjaw")

# ── In-memory peer registry ─────────────────────────────────────────────────
# { node_id: websocket }
PEERS: Dict[str, WebSocketServerProtocol] = {}
# { node_id: set of subscribers }
CHANNELS: Dict[str, Set[str]] = {}

SERVER_VERSION = "2.1.0"
MAX_PAYLOAD_BYTES = 65_536  # 64 KB ceiling per message


def ts() -> str:
    return datetime.now(timezone.utc).isoformat()


async def broadcast_presence(event: str, node_id: str):
    """Notify all connected peers of a join/leave event."""
    payload = json.dumps({"type": "presence", "event": event, "node": node_id, "ts": ts()})
    for peer_id, ws in list(PEERS.items()):
        if peer_id != node_id:
            try:
                await ws.send(payload)
            except Exception:
                pass


async def relay_message(sender_id: str, raw: str):
    """
    Relay an encrypted message envelope to the target peer.
    The server only reads the envelope metadata (to, from).
    It NEVER touches or logs the ciphertext payload.
    """
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError:
        return {"type": "error", "msg": "Malformed envelope"}

    required = {"to", "ciphertext"}
    if not required.issubset(envelope.keys()):
        return {"type": "error", "msg": "Missing envelope fields: to, ciphertext"}

    if len(raw) > MAX_PAYLOAD_BYTES:
        return {"type": "error", "msg": "Payload exceeds 64 KB limit"}

    target_id = envelope["to"]
    if target_id not in PEERS:
        return {"type": "error", "msg": f"Peer '{target_id}' not online"}

    delivery = json.dumps({
        "type": "message",
        "from": sender_id,
        "ciphertext": envelope["ciphertext"],   # opaque blob — server never decodes this
        "ts": ts(),
    })

    try:
        await PEERS[target_id].send(delivery)
        log.info("relay %s → %s (%d bytes, ciphertext only)", sender_id, target_id, len(delivery))
        return {"type": "ack", "ts": ts()}
    except Exception as exc:
        log.warning("delivery failed %s → %s: %s", sender_id, target_id, exc)
        return {"type": "error", "msg": "Delivery failed"}


async def handle_connection(ws: WebSocketServerProtocol):
    node_id = None
    try:
        # ── Handshake ──────────────────────────────────────────────────────
        hello_raw = await asyncio.wait_for(ws.recv(), timeout=10)
        hello = json.loads(hello_raw)

        if hello.get("type") != "hello" or not hello.get("node_id"):
            await ws.send(json.dumps({"type": "error", "msg": "Expected hello frame"}))
            return

        node_id = str(hello["node_id"])[:32]   # cap length

        if node_id in PEERS:
            await ws.send(json.dumps({"type": "error", "msg": "Node ID already connected"}))
            return

        PEERS[node_id] = ws
        log.info("+ %s connected (%d peers online)", node_id, len(PEERS))

        await ws.send(json.dumps({
            "type": "welcome",
            "node_id": node_id,
            "server_version": SERVER_VERSION,
            "peers_online": list(PEERS.keys()),
            "ts": ts(),
        }))

        await broadcast_presence("join", node_id)

        # ── Message loop ───────────────────────────────────────────────────
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send(json.dumps({"type": "error", "msg": "Invalid JSON"}))
                continue

            msg_type = msg.get("type")

            if msg_type == "send":
                result = await relay_message(node_id, json.dumps(msg))
                await ws.send(json.dumps(result))

            elif msg_type == "peers":
                await ws.send(json.dumps({
                    "type": "peers",
                    "online": [p for p in PEERS if p != node_id],
                    "ts": ts(),
                }))

            elif msg_type == "ping":
                await ws.send(json.dumps({"type": "pong", "ts": ts()}))

            else:
                await ws.send(json.dumps({"type": "error", "msg": f"Unknown type: {msg_type}"}))

    except asyncio.TimeoutError:
        log.warning("handshake timeout")
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as exc:
        log.error("connection error: %s", exc)
    finally:
        if node_id and node_id in PEERS:
            del PEERS[node_id]
            log.info("- %s disconnected (%d peers online)", node_id, len(PEERS))
            await broadcast_presence("leave", node_id)


async def main():
    host = os.getenv("LJ_HOST", "0.0.0.0")
    port = int(os.getenv("LJ_PORT", "8765"))

    log.info("LockJaw server v%s starting on ws://%s:%d", SERVER_VERSION, host, port)
    log.info("Zero-Trust relay — server never decrypts payloads")

    async with websockets.serve(handle_connection, host, port, max_size=MAX_PAYLOAD_BYTES):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
