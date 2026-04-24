"""
LockJaw — Python CLI Client
Command-line node for sending and receiving encrypted messages.

Usage:
    python client.py --node NEXUS_01 --peer GHOST_NODE
"""

import argparse
import asyncio
import json
import sys
from getpass import getpass

import httpx
import websockets

from crypto.hybrid_cipher import HybridCipher

cipher = HybridCipher()


async def recv_loop(ws, local_node: str, beale_phrase: str, totp_code: str, machine_id: str):
    """Background task: receive and decrypt incoming messages."""
    async for raw in ws:
        try:
            msg = json.loads(raw)
        except Exception:
            continue

        mtype = msg.get("type", "")

        if mtype == "MSG":
            sender = msg.get("from", "?")
            ciphertext = msg.get("ciphertext", "")
            nonce = msg.get("nonce", "")
            result = cipher.decrypt(ciphertext, nonce, beale_phrase, totp_code, machine_id)
            if result.verified:
                print(f"\n[{sender}] {result.plaintext}")
            else:
                print(f"\n[{sender}] <decryption failed — wrong phrase or expired 2FA>")

        elif mtype == "PEER_ONLINE":
            print(f"\n  *** {msg['node_id']} came online ***")
        elif mtype == "PEER_OFFLINE":
            print(f"\n  *** {msg['node_id']} went offline ***")
        elif mtype == "ERROR":
            print(f"\n  [ERROR] {msg.get('detail')}")

        sys.stdout.write("> ")
        sys.stdout.flush()


async def main():
    parser = argparse.ArgumentParser(description="LockJaw CLI Node")
    parser.add_argument("--node", required=True, help="Your node ID (e.g. NEXUS_01)")
    parser.add_argument("--peer", required=True, help="Target peer node ID")
    parser.add_argument("--host", default="localhost", help="Server host")
    parser.add_argument("--port", default=8765, type=int, help="Server port")
    args = parser.parse_args()

    node_id = args.node.upper()
    peer_id = args.peer.upper()
    base_url = f"http://{args.host}:{args.port}"
    ws_url = f"ws://{args.host}:{args.port}/ws/{node_id}"

    print(f"\n{'='*50}")
    print(f"  LOCKJAW — Hybrid Encryption Messaging")
    print(f"  Node: {node_id}  →  Peer: {peer_id}")
    print(f"{'='*50}\n")

    beale_phrase = getpass("Beale key phrase: ")
    totp_code = input("2FA code: ").strip()
    machine_id = node_id

    # Authenticate
    async with httpx.AsyncClient() as http:
        resp = await http.post(f"{base_url}/api/auth/verify", json={
            "node_id": node_id,
            "code": totp_code,
            "beale_phrase": beale_phrase,
            "machine_id": machine_id,
        })
        if resp.status_code != 200:
            print(f"Auth failed: {resp.text}")
            sys.exit(1)
        token = resp.json()["token"]
        print(f"  Authenticated. Session token: {token[:16]}…\n")

    async with websockets.connect(ws_url) as ws:
        print(f"  Connected. Type messages and press Enter. Ctrl+C to quit.\n")

        recv_task = asyncio.create_task(recv_loop(ws, node_id, beale_phrase, totp_code, machine_id))

        try:
            while True:
                sys.stdout.write("> ")
                sys.stdout.flush()
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                text = line.strip()
                if not text:
                    continue

                packet = cipher.encrypt(text, beale_phrase, totp_code, machine_id)
                payload = {
                    "type": "MSG",
                    "to": peer_id,
                    "ciphertext": packet.ciphertext_b64,
                    "nonce": packet.nonce_b64,
                }
                await ws.send(json.dumps(payload))

        except (KeyboardInterrupt, EOFError):
            recv_task.cancel()
            print("\n  Session terminated.")


if __name__ == "__main__":
    asyncio.run(main())
