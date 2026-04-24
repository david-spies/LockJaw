"""
LockJaw Crypto Engine
Hybrid pipeline: Morse-ASCII → Beale XOR → AES-256-GCM → Base64

All encryption/decryption runs locally. The server sees only opaque ciphertext.
"""

import base64
import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional

# ── Morse table ────────────────────────────────────────────────────────────
MORSE_ENCODE: dict[str, str] = {
    'A':'.-',   'B':'-...', 'C':'-.-.', 'D':'-..',  'E':'.',    'F':'..-.',
    'G':'--.',  'H':'....', 'I':'..',   'J':'.---', 'K':'-.-',  'L':'.-..',
    'M':'--',   'N':'-.',   'O':'---',  'P':'.--.', 'Q':'--.-', 'R':'.-.',
    'S':'...',  'T':'-',    'U':'..-',  'V':'...-', 'W':'.--',  'X':'-..-',
    'Y':'-.--', 'Z':'--..',
    '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-',
    '5':'.....','6':'-....','7':'--...','8':'---..','9':'----.',
    '.':'.-.-.-',',':'--..--','?':'..--..','/':'-..-.','-':'-....-',
    '(':'-.--.',')':'-.--.-',' ':' ',
}

MORSE_DECODE: dict[str, str] = {v: k for k, v in MORSE_ENCODE.items() if k != ' '}


@dataclass
class EncryptedEnvelope:
    """Wire-format for a LockJaw encrypted message."""
    nonce: bytes        # 12-byte GCM nonce
    ciphertext: bytes   # AES-GCM ciphertext
    tag: bytes          # 16-byte GCM authentication tag
    beale_iv: bytes     # 8-byte Beale layer IV
    version: int = 2

    def to_b64(self) -> str:
        """Serialize to compact Base64 for transmission."""
        header = struct.pack(">BH", self.version, len(self.ciphertext))
        raw = header + self.nonce + self.beale_iv + self.tag + self.ciphertext
        return base64.b64encode(raw).decode()

    @classmethod
    def from_b64(cls, data: str) -> "EncryptedEnvelope":
        raw = base64.b64decode(data)
        version, ct_len = struct.unpack(">BH", raw[:3])
        offset = 3
        nonce = raw[offset:offset+12]; offset += 12
        beale_iv = raw[offset:offset+8]; offset += 8
        tag = raw[offset:offset+16]; offset += 16
        ciphertext = raw[offset:offset+ct_len]
        return cls(nonce=nonce, ciphertext=ciphertext, tag=tag, beale_iv=beale_iv, version=version)


# ── Layer A: Morse-ASCII ───────────────────────────────────────────────────

def text_to_morse_binary(text: str) -> bytes:
    """
    Plaintext → ASCII → Morse → binary representation.
    Encoding: '.' = 0x00, '-' = 0x01, char_sep = 0x02, word_sep = 0x03
    """
    tokens = []
    for char in text.upper():
        if char == ' ':
            tokens.append(b'\x03')
        elif char in MORSE_ENCODE:
            morse = MORSE_ENCODE[char]
            char_bits = bytes(0x00 if c == '.' else 0x01 for c in morse)
            tokens.append(char_bits)
            tokens.append(b'\x02')
    return b''.join(tokens)


def morse_binary_to_text(data: bytes) -> str:
    """Reverse the Morse-binary layer back to plaintext."""
    result = []
    current = []
    for byte in data:
        if byte == 0x02:
            if current:
                morse = ''.join('.' if b == 0x00 else '-' for b in current)
                result.append(MORSE_DECODE.get(morse, '?'))
                current = []
        elif byte == 0x03:
            if current:
                morse = ''.join('.' if b == 0x00 else '-' for b in current)
                result.append(MORSE_DECODE.get(morse, '?'))
                current = []
            result.append(' ')
        elif byte in (0x00, 0x01):
            current.append(byte)
    if current:
        morse = ''.join('.' if b == 0x00 else '-' for b in current)
        result.append(MORSE_DECODE.get(morse, '?'))
    return ''.join(result).strip()


# ── Layer B: Beale XOR ────────────────────────────────────────────────────

def _beale_keystream(phrase: str, iv: bytes, length: int) -> bytes:
    """
    Derive a keystream from the Beale phrase using HKDF-SHA256.
    The phrase is the shared secret; iv provides per-message randomness.
    """
    prk = hmac.new(iv, phrase.encode(), hashlib.sha256).digest()
    stream = b''
    counter = 0
    while len(stream) < length:
        stream += hmac.new(prk, counter.to_bytes(4, 'big'), hashlib.sha256).digest()
        counter += 1
    return stream[:length]


def beale_encrypt(data: bytes, phrase: str) -> tuple[bytes, bytes]:
    """XOR data with Beale keystream. Returns (ciphertext, iv)."""
    iv = os.urandom(8)
    keystream = _beale_keystream(phrase, iv, len(data))
    return bytes(a ^ b for a, b in zip(data, keystream)), iv


def beale_decrypt(data: bytes, phrase: str, iv: bytes) -> bytes:
    """Reverse Beale XOR (symmetric operation)."""
    keystream = _beale_keystream(phrase, iv, len(data))
    return bytes(a ^ b for a, b in zip(data, keystream))


# ── Layer C: AES-256-GCM (pure-Python fallback using PyCryptodome) ────────

def _derive_aes_key(machine_id: str, totp_code: str, phrase: str) -> bytes:
    """
    Ke = HKDF-SHA256( HMAC-SHA256(machine_id, totp_code) , phrase )
    Produces a 256-bit key binding identity + temporal factor + shared secret.
    """
    identity_hash = hmac.new(
        machine_id.encode(),
        totp_code.encode(),
        hashlib.sha256
    ).digest()
    key = hashlib.pbkdf2_hmac(
        'sha256',
        identity_hash,
        phrase.encode(),
        iterations=100_000,
        dklen=32
    )
    return key


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """AES-256-GCM encrypt. Returns (nonce, ciphertext, tag)."""
    try:
        from Crypto.Cipher import AES
        nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce, ciphertext, tag
    except ImportError:
        # Fallback: XOR with key expansion (demo mode — not production secure)
        nonce = os.urandom(12)
        expanded = hashlib.sha256(key + nonce).digest() * ((len(plaintext) // 32) + 1)
        ct = bytes(a ^ b for a, b in zip(plaintext, expanded))
        tag = hashlib.sha256(key + ct + nonce).digest()[:16]
        return nonce, ct, tag


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """AES-256-GCM decrypt with authentication."""
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ImportError:
        expanded = hashlib.sha256(key + nonce).digest() * ((len(ciphertext) // 32) + 1)
        pt = bytes(a ^ b for a, b in zip(ciphertext, expanded))
        expected_tag = hashlib.sha256(key + ciphertext + nonce).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication tag mismatch — message tampered or wrong key")
        return pt


# ── Public API ─────────────────────────────────────────────────────────────

def encrypt(
    plaintext: str,
    beale_phrase: str,
    totp_code: str,
    machine_id: str,
) -> EncryptedEnvelope:
    """
    Full hybrid encryption pipeline:
      plaintext → Morse-binary → Beale XOR → AES-256-GCM → EncryptedEnvelope
    """
    # Layer A
    morse_bytes = text_to_morse_binary(plaintext)
    # Layer B
    beale_ct, beale_iv = beale_encrypt(morse_bytes, beale_phrase)
    # Layer C
    aes_key = _derive_aes_key(machine_id, totp_code, beale_phrase)
    nonce, ciphertext, tag = _aes_gcm_encrypt(aes_key, beale_ct)

    return EncryptedEnvelope(nonce=nonce, ciphertext=ciphertext, tag=tag, beale_iv=beale_iv)


def decrypt(
    envelope: EncryptedEnvelope,
    beale_phrase: str,
    totp_code: str,
    machine_id: str,
) -> str:
    """
    Reverse pipeline:
      EncryptedEnvelope → AES-256-GCM → Beale XOR → Morse-binary → plaintext
    """
    # Layer C reverse
    aes_key = _derive_aes_key(machine_id, totp_code, beale_phrase)
    beale_ct = _aes_gcm_decrypt(aes_key, envelope.nonce, envelope.ciphertext, envelope.tag)
    # Layer B reverse
    morse_bytes = beale_decrypt(beale_ct, beale_phrase, envelope.beale_iv)
    # Layer A reverse
    return morse_binary_to_text(morse_bytes)


# ── TOTP (RFC 6238 compatible) ────────────────────────────────────────────

def generate_totp(secret: bytes, window: Optional[int] = None) -> str:
    """Generate a 6-digit TOTP code (RFC 6238, SHA-1, 30s window)."""
    if window is None:
        window = int(time.time()) // 30
    msg = struct.pack(">Q", window)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)


def verify_totp(secret: bytes, code: str, drift: int = 1) -> bool:
    """Verify a TOTP code allowing ±drift windows for clock skew."""
    current = int(time.time()) // 30
    return any(
        hmac.compare_digest(generate_totp(secret, current + d), code)
        for d in range(-drift, drift + 1)
    )


def new_totp_secret() -> bytes:
    """Generate a cryptographically random 20-byte TOTP seed."""
    return os.urandom(20)


def totp_secret_to_b32(secret: bytes) -> str:
    """Encode secret for QR code / authenticator app import."""
    return base64.b32encode(secret).decode()


# ── Quick smoke test ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("LockJaw Crypto Engine — self-test")
    phrase = "quantum-oracle-7734"
    machine = "NEXUS_01"
    secret = new_totp_secret()
    totp = generate_totp(secret)

    msg = "Hello, LockJaw. Transmission is secure."
    print(f"  Plaintext : {msg}")

    env = encrypt(msg, phrase, totp, machine)
    b64 = env.to_b64()
    print(f"  Ciphertext: {b64[:64]}…")

    recovered = decrypt(EncryptedEnvelope.from_b64(b64), phrase, totp, machine)
    print(f"  Decrypted : {recovered}")
    assert recovered.upper() == msg.upper(), "Round-trip FAILED"
    print("  ✓ Round-trip passed")

    assert verify_totp(secret, totp), "TOTP verify FAILED"
    print("  ✓ TOTP verify passed")
