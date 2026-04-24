"""
LockJaw — Hybrid Cipher Engine
Implements: Morse-ASCII → Beale XOR → AES-256-GCM pipeline
"""

import base64
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ── Morse Alphabet ─────────────────────────────────────────────────────────────
MORSE_TABLE: dict[str, str] = {
    "A": ".-",   "B": "-...", "C": "-.-.", "D": "-..",  "E": ".",
    "F": "..-.", "G": "--.",  "H": "....", "I": "..",   "J": ".---",
    "K": "-.-",  "L": ".-..", "M": "--",   "N": "-.",   "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.",  "S": "...",  "T": "-",
    "U": "..-",  "V": "...-", "W": ".--",  "X": "-..-", "Y": "-.--",
    "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "!": "-.-.--",
    "-": "-....-", "/": "-..-.",  " ": "/",
}

REVERSE_MORSE: dict[str, str] = {v: k for k, v in MORSE_TABLE.items() if k != " "}


@dataclass
class CipherPacket:
    """Full cipher packet produced during encryption."""
    plaintext: str
    ascii_ints: list[int]
    morse: str
    binary_str: str
    beale_scrambled: bytes
    ciphertext_b64: str
    nonce_b64: str
    session_key_hex: str


@dataclass
class DecryptResult:
    plaintext: str
    verified: bool


class MorseCodec:
    """Layer A: Plaintext ↔ Morse ↔ Binary"""

    @staticmethod
    def encode(text: str) -> tuple[list[int], str, str]:
        """
        Returns (ascii_ints, morse_string, binary_string)
        binary: '.' → '0', '-' → '1', ' ' → '2', '/' → '3'
        """
        ascii_ints = [ord(c) for c in text]
        morse_tokens = []
        for ch in text.upper():
            token = MORSE_TABLE.get(ch)
            if token:
                morse_tokens.append(token)

        morse_str = " ".join(morse_tokens)

        binary_parts = []
        for ch in morse_str:
            if ch == ".":
                binary_parts.append("0")
            elif ch == "-":
                binary_parts.append("1")
            elif ch == " ":
                binary_parts.append("2")
            elif ch == "/":
                binary_parts.append("3")
        binary_str = "".join(binary_parts)

        return ascii_ints, morse_str, binary_str

    @staticmethod
    def decode(binary_str: str) -> str:
        """Reconstruct Morse string from binary, then decode to text."""
        morse_str = ""
        for ch in binary_str:
            if ch == "0":
                morse_str += "."
            elif ch == "1":
                morse_str += "-"
            elif ch == "2":
                morse_str += " "
            elif ch == "3":
                morse_str += "/"
            else:
                morse_str += ch  # pass-through for other chars

        tokens = morse_str.split(" ")
        chars = []
        for token in tokens:
            if token == "/":
                chars.append(" ")
            elif token in REVERSE_MORSE:
                chars.append(REVERSE_MORSE[token])
        return "".join(chars)


class BealeLayer:
    """
    Layer B: Beale-inspired polyalphabetic XOR.
    Uses the shared phrase as a key-text, deriving per-character keys
    from the phrase's character positions (mimicking Beale index lookup).
    """

    @staticmethod
    def _derive_key_stream(phrase: str, length: int) -> bytes:
        """
        Expand the phrase into a key stream of the required length
        using HMAC-SHA256 in a CTR-like fashion.
        """
        key_bytes = phrase.encode("utf-8")
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            block = hmac.new(key_bytes, struct.pack(">I", counter), hashlib.sha256).digest()
            stream.extend(block)
            counter += 1
        return bytes(stream[:length])

    @staticmethod
    def scramble(binary_str: str, phrase: str) -> bytes:
        """XOR the binary string (as UTF-8 bytes) against the Beale key stream."""
        data = binary_str.encode("utf-8")
        key_stream = BealeLayer._derive_key_stream(phrase, len(data))
        return bytes(b ^ k for b, k in zip(data, key_stream))

    @staticmethod
    def unscramble(scrambled: bytes, phrase: str) -> str:
        """Reverse the XOR to recover the binary string."""
        key_stream = BealeLayer._derive_key_stream(phrase, len(scrambled))
        original = bytes(b ^ k for b, k in zip(scrambled, key_stream))
        return original.decode("utf-8")


class KeyDeriver:
    """
    Layer C: Derive AES session key from Machine ID + 2FA code + Beale phrase.
    Ke = HKDF-SHA256(IKM = SHA256(machine_id || totp || beale_phrase))
    """

    @staticmethod
    def derive(machine_id: str, totp_code: str, beale_phrase: str) -> bytes:
        ikm_raw = f"{machine_id}:{totp_code}:{beale_phrase}".encode("utf-8")
        ikm = hashlib.sha256(ikm_raw).digest()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"LockJawSaltV1",
            info=b"lockjaw-session-key",
        )
        return hkdf.derive(ikm)


class HybridCipher:
    """
    Full pipeline:
      encrypt: plaintext → Morse binary → Beale scramble → AES-256-GCM → base64
      decrypt: base64 → AES-256-GCM → Beale unscramble → Morse binary → plaintext
    """

    def encrypt(
        self,
        plaintext: str,
        beale_phrase: str,
        totp_code: str,
        machine_id: str,
    ) -> CipherPacket:
        # Layer A
        ascii_ints, morse_str, binary_str = MorseCodec.encode(plaintext)

        # Layer B
        beale_scrambled = BealeLayer.scramble(binary_str, beale_phrase)

        # Layer C — derive session key
        session_key = KeyDeriver.derive(machine_id, totp_code, beale_phrase)

        # AES-256-GCM encryption
        nonce = os.urandom(12)
        aesgcm = AESGCM(session_key)
        ciphertext_bytes = aesgcm.encrypt(nonce, beale_scrambled, None)

        return CipherPacket(
            plaintext=plaintext,
            ascii_ints=ascii_ints,
            morse=morse_str,
            binary_str=binary_str,
            beale_scrambled=beale_scrambled,
            ciphertext_b64=base64.b64encode(ciphertext_bytes).decode(),
            nonce_b64=base64.b64encode(nonce).decode(),
            session_key_hex=session_key.hex(),
        )

    def decrypt(
        self,
        ciphertext_b64: str,
        nonce_b64: str,
        beale_phrase: str,
        totp_code: str,
        machine_id: str,
    ) -> DecryptResult:
        try:
            session_key = KeyDeriver.derive(machine_id, totp_code, beale_phrase)
            ciphertext_bytes = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)

            aesgcm = AESGCM(session_key)
            beale_scrambled = aesgcm.decrypt(nonce, ciphertext_bytes, None)

            binary_str = BealeLayer.unscramble(beale_scrambled, beale_phrase)
            plaintext = MorseCodec.decode(binary_str)

            return DecryptResult(plaintext=plaintext, verified=True)
        except Exception as e:
            return DecryptResult(plaintext="", verified=False)
