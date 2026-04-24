"""
LockJaw CLI Client
Interactive terminal interface for the hybrid encryption messaging system.
"""

import asyncio
import base64
import json
import os
import sys
import time
from pathlib import Path

# Ensure crypto module is importable when running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import websockets
except ImportError:
    print("[ERROR] websockets not installed. Run: pip install websockets")
    sys.exit(1)

from crypto.engine import (
    EncryptedEnvelope,
    decrypt,
    encrypt,
    generate_totp,
    new_totp_secret,
    totp_secret_to_b32,
    verify_totp,
)

# ── Config ─────────────────────────────────────────────────────────────────
CONFIG_PATH = Path.home() / ".lockjaw" / "config.json"
SERVER_URL  = os.getenv("LJ_SERVER", "ws://localhost:8765")


def load_or_create_config() -> dict:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    # First-run setup
    print("\n── LockJaw first-run setup ──────────────────────────────")
    node_id = input("  Choose a node identity (e.g. NEXUS_01): ").strip().upper() or "NODE_A"
    phrase  = input("  Set your Beale phrase (shared secret): ").strip() or "default-phrase"
    secret  = new_totp_secret()

    cfg = {
        "node_id": node_id,
        "beale_phrase": phrase,
        "totp_secret": base64.b64encode(secret).decode(),
    }
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    print(f"\n  Config saved → {CONFIG_PATH}")
    print(f"  TOTP secret (base32): {totp_secret_to_b32(secret)}")
    print("  Import this into any RFC 6238 authenticator app.\n")
    return cfg


# ── Terminal helpers ────────────────────────────────────────────────────────

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def banner():
    print(f"""
{CYAN}{BOLD}
  ██╗      ██████╗  ██████╗██╗  ██╗     ██╗ █████╗ ██╗    ██╗
  ██║     ██╔═══██╗██╔════╝██║ ██╔╝     ██║██╔══██╗██║    ██║
  ██║     ██║   ██║██║     █████╔╝      ██║███████║██║ █╗ ██║
  ██║     ██║   ██║██║     ██╔═██╗ ██   ██║██╔══██║██║███╗██║
  ███████╗╚██████╔╝╚██████╗██║  ██╗╚█████╔╝██║  ██║╚███╔███╔╝
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝ ╚══╝╚══╝
{RESET}{DIM}  Hybrid Encryption Messaging · v2.1 · Zero-Trust E2EE{RESET}
""")


def fmt_time() -> str:
    return time.strftime("%H:%M:%S")


def info(msg: str):
    print(f"  {DIM}[{fmt_time()}]{RESET} {msg}")


def success(msg: str):
    print(f"  {GREEN}✓{RESET} {msg}")


def error(msg: str):
    print(f"  {RED}✗{RESET} {msg}")


def warn(msg: str):
    print(f"  {YELLOW}⚠{RESET} {msg}")


# ── Client ─────────────────────────────────────────────────────────────────

class LockJawClient:
    def __init__(self, cfg: dict):
        self.node_id     = cfg["node_id"]
        self.phrase      = cfg["beale_phrase"]
        self.totp_secret = base64.b64decode(cfg["totp_secret"])
        self.ws          = None
        self.peers: list[str] = []
        self._recv_task  = None

    def current_totp(self) -> str:
        return generate_totp(self.totp_secret)

    async def connect(self):
        info(f"Connecting to {SERVER_URL} as {CYAN}{self.node_id}{RESET} …")
        self.ws = await websockets.connect(SERVER_URL)

        # Handshake
        await self.ws.send(json.dumps({"type": "hello", "node_id": self.node_id}))
        welcome_raw = await self.ws.recv()
        welcome = json.loads(welcome_raw)

        if welcome.get("type") == "error":
            error(welcome.get("msg", "Connection rejected"))
            sys.exit(1)

        self.peers = welcome.get("peers_online", [])
        success(f"Connected · server v{welcome.get('server_version','?')} · "
                f"{len(self.peers)} peer(s) online")

        # Start background receiver
        self._recv_task = asyncio.create_task(self._receive_loop())

    async def _receive_loop(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                await self._handle_incoming(msg)
        except websockets.exceptions.ConnectionClosed:
            warn("Server connection closed.")

    async def _handle_incoming(self, msg: dict):
        mtype = msg.get("type")
        if mtype == "message":
            sender = msg.get("from", "?")
            b64    = msg.get("ciphertext", "")
            try:
                env = EncryptedEnvelope.from_b64(b64)
                plaintext = decrypt(env, self.phrase, self.current_totp(), sender)
                print(f"\n  {CYAN}[{fmt_time()}] {sender}{RESET}: {plaintext}")
            except Exception as exc:
                warn(f"Decryption failed from {sender}: {exc}")
                print(f"  {DIM}  (raw ciphertext: {b64[:40]}…){RESET}")
            print(f"  > ", end="", flush=True)

        elif mtype == "presence":
            event = msg.get("event")
            node  = msg.get("node", "?")
            if event == "join":
                self.peers.append(node)
                info(f"{GREEN}{node} joined the network{RESET}")
            elif event == "leave":
                self.peers = [p for p in self.peers if p != node]
                info(f"{DIM}{node} left the network{RESET}")
            print(f"  > ", end="", flush=True)

    async def send_to(self, target: str, plaintext: str):
        totp = self.current_totp()
        env  = encrypt(plaintext, self.phrase, totp, self.node_id)
        envelope = {
            "type":       "send",
            "to":         target,
            "ciphertext": env.to_b64(),
        }
        await self.ws.send(json.dumps(envelope))
        result_raw = await asyncio.wait_for(self.ws.recv(), timeout=5)
        result = json.loads(result_raw)
        # swallow ack; UI already echoes locally
        if result.get("type") == "error":
            error(result.get("msg", "Send failed"))

    async def run_repl(self):
        banner()
        await self.connect()
        print()
        print(f"  {BOLD}Commands:{RESET}")
        print(f"    {CYAN}@PEER_ID message{RESET}  — send encrypted message")
        print(f"    {CYAN}/peers{RESET}            — list online peers")
        print(f"    {CYAN}/totp{RESET}             — show current 2FA code")
        print(f"    {CYAN}/quit{RESET}             — exit")
        print()

        loop = asyncio.get_event_loop()

        while True:
            try:
                line = await loop.run_in_executor(None, lambda: input("  > "))
            except (EOFError, KeyboardInterrupt):
                break

            line = line.strip()
            if not line:
                continue

            if line.lower() in ("/quit", "/exit", "/q"):
                break

            elif line.lower() == "/peers":
                if self.peers:
                    print(f"  Online: {', '.join(f'{CYAN}{p}{RESET}' for p in self.peers)}")
                else:
                    print("  No peers online.")

            elif line.lower() == "/totp":
                code = self.current_totp()
                window_end = 30 - (int(time.time()) % 30)
                print(f"  2FA code: {GREEN}{code}{RESET}  (expires in {window_end}s)")

            elif line.startswith("@"):
                parts = line[1:].split(" ", 1)
                if len(parts) < 2:
                    warn("Usage: @PEER_ID message")
                    continue
                target, plaintext = parts
                target = target.upper()
                try:
                    await self.send_to(target, plaintext)
                    print(f"  {DIM}[{fmt_time()}] you → {target}{RESET}: {plaintext}")
                    totp_val = self.current_totp()
                    print(f"  {DIM}  └ encrypted with TOTP {totp_val} · Beale+AES-256-GCM{RESET}")
                except Exception as exc:
                    error(f"Send failed: {exc}")
            else:
                warn("Unknown command. Use @PEER message or /peers /totp /quit")

        if self.ws:
            await self.ws.close()
        success("Disconnected. Session keys purged.")


async def main():
    cfg = load_or_create_config()
    client = LockJawClient(cfg)
    await client.run_repl()


if __name__ == "__main__":
    asyncio.run(main())
