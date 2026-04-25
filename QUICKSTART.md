# LockJaw — QUICKSTART

Get two encrypted nodes talking in under 5 minutes.

---

## Prerequisites

- Python 3.11+
- pip
- (Optional) Docker + docker-compose for containerized deployment

---

## Option A — Direct Python (Recommended for local dev)

### 1. Clone and enter the project

```bash
git clone https://github.com/david-spies/lockjaw.git
cd lockjaw
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate      # macOS / Linux
.venv\Scripts\activate         # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
```

Open `.env` and set a strong secret key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the output as `LOCKJAW_SECRET_KEY` in `.env`.

### 5. Start the server

```bash
python3 -m server.app
```

You should see:

```
INFO     LockJaw server starting - Zero-Trust mode active
INFO     Uvicorn running on http://0.0.0.0:8765
```

### 6. Register your first node

In a new terminal (.venv activated):

```bash
source .venv/bin/activate
```


```bash
curl -s -X POST http://localhost:8765/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"node_id": "NEXUS_01"}' | python -m json.tool
```

You will receive a `totp_uri`. Scan it with Google Authenticator, Authy, or any TOTP app.
The `secret` field can also be entered manually if your app supports it.

Register the second node:

```bash
curl -s -X POST http://localhost:8765/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"node_id": "GHOST_NODE"}' | python -m json.tool
```

### 7. Agree on a Beale phrase

Both nodes must share the same Beale key phrase out-of-band (in person, via a pre-shared channel, etc.).

Example phrase: `quantum-oracle-7734`

This phrase is NEVER sent to the server — it lives only in the clients.

### 8. Launch CLI client — Node A

```bash
python client/client.py --node NEXUS_01 --peer GHOST_NODE
```

When prompted:
- Beale key phrase: `quantum-oracle-7734`
- 2FA code: Enter the current 6-digit code from your authenticator app

### 9. Launch CLI client — Node B

Open a second terminal:

```bash
python client/client.py --node GHOST_NODE --peer NEXUS_01
```

Enter the same Beale phrase and the TOTP code for GHOST_NODE.

### 10. Send a message

In Node A's terminal:

```
> TRANSFER COORDINATES CONFIRMED
```

Node B will display:

```
[NEXUS_01] TRANSFER COORDINATES CONFIRMED
```

Full three-layer hybrid encryption, end-to-end.

---

## Option B — Docker

### 1. Build and start

```bash
cp .env.example .env
# Edit .env and set LOCKJAW_SECRET_KEY

docker-compose up --build -d
```

### 2. Verify

```bash
curl http://localhost:8765/health
```

### 3. Register nodes and run clients

Same as steps 6-10 above.

### Stop

```bash
docker-compose down
```

---

## Test the cipher pipeline directly

```bash
python - << 'EOF'
from crypto.hybrid_cipher import HybridCipher

cipher  = HybridCipher()
phrase  = "quantum-oracle-7734"
totp    = "123456"
machine = "NEXUS_01"

packet = cipher.encrypt("HELLO LOCKJAW", phrase, totp, machine)
print("Morse     :", packet.morse)
print("Ciphertext:", packet.ciphertext_b64[:48], "...")
print("Session Ke:", packet.session_key_hex)

result = cipher.decrypt(packet.ciphertext_b64, packet.nonce_b64, phrase, totp, machine)
print("Decrypted :", result.plaintext)
print("Verified  :", result.verified)
EOF
```

---

## Run tests

```bash
pytest tests/ -v
```

---

## API quick reference

```bash
# Health check
curl http://localhost:8765/health

# Register a node
curl -X POST http://localhost:8765/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"node_id": "MY_NODE"}'

# Verify 2FA
curl -X POST http://localhost:8765/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"node_id":"MY_NODE","code":"123456","beale_phrase":"your-phrase","machine_id":"MY_NODE"}'

# List online nodes
curl http://localhost:8765/api/nodes/online
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Invalid or expired 2FA code` | Ensure system clock is synced. Server allows +/-30s drift. |
| `Node X not online` | Target node must be connected via WebSocket first. |
| `decryption failed` | Both nodes must use identical Beale phrase and matching TOTP window. |
| Port 8765 in use | Change `LOCKJAW_PORT` in `.env` and restart. |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` inside your activated venv. |

---

## Pre-deployment security checklist

- [ ] LOCKJAW_SECRET_KEY is a strong random value
- [ ] .env is in .gitignore and never committed
- [ ] Beale phrase exchanged out-of-band
- [ ] Server running behind HTTPS/WSS for non-local deployment
- [ ] TOTP secrets backed up securely

---

> Zero-Trust means the server is always untrusted — even if it is yours.
