"""
LockJaw Test Suite
Run with: pytest tests/ -v
"""

import base64
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from crypto.engine import (
    EncryptedEnvelope,
    _beale_keystream,
    beale_decrypt,
    beale_encrypt,
    decrypt,
    encrypt,
    generate_totp,
    morse_binary_to_text,
    new_totp_secret,
    text_to_morse_binary,
    totp_secret_to_b32,
    verify_totp,
)


# ── Layer A: Morse-ASCII ───────────────────────────────────────────────────

class TestMorseLayer:
    def test_roundtrip_simple(self):
        for msg in ["HELLO", "SOS", "LOCKJAW", "A"]:
            binary = text_to_morse_binary(msg)
            assert morse_binary_to_text(binary) == msg

    def test_roundtrip_with_spaces(self):
        msg = "HELLO WORLD"
        binary = text_to_morse_binary(msg)
        recovered = morse_binary_to_text(binary)
        assert recovered == msg

    def test_roundtrip_numbers(self):
        msg = "CODE 42"
        binary = text_to_morse_binary(msg)
        assert morse_binary_to_text(binary) == msg

    def test_empty_string(self):
        binary = text_to_morse_binary("")
        assert morse_binary_to_text(binary) == ""

    def test_binary_contains_only_valid_bytes(self):
        binary = text_to_morse_binary("TEST")
        for byte in binary:
            assert byte in (0x00, 0x01, 0x02, 0x03)

    def test_lowercase_normalized(self):
        binary_lower = text_to_morse_binary("hello")
        binary_upper = text_to_morse_binary("HELLO")
        assert binary_lower == binary_upper


# ── Layer B: Beale XOR ────────────────────────────────────────────────────

class TestBealeLayer:
    PHRASE = "quantum-oracle-7734"

    def test_roundtrip(self):
        data = b"\x00\x01\x02\x03\x00\x01" * 10
        ct, iv = beale_encrypt(data, self.PHRASE)
        assert beale_decrypt(ct, self.PHRASE, iv) == data

    def test_different_iv_different_ciphertext(self):
        data = b"test data 1234"
        ct1, iv1 = beale_encrypt(data, self.PHRASE)
        ct2, iv2 = beale_encrypt(data, self.PHRASE)
        # IVs should differ (random); ciphertexts should therefore differ
        assert iv1 != iv2
        assert ct1 != ct2

    def test_wrong_phrase_fails(self):
        data = b"\x00\x01\x02\x03" * 8
        ct, iv = beale_encrypt(data, self.PHRASE)
        recovered = beale_decrypt(ct, "wrong-phrase", iv)
        assert recovered != data

    def test_keystream_length(self):
        iv = b'\x00' * 8
        ks = _beale_keystream(self.PHRASE, iv, 100)
        assert len(ks) == 100

    def test_empty_data(self):
        ct, iv = beale_encrypt(b"", self.PHRASE)
        assert beale_decrypt(ct, self.PHRASE, iv) == b""


# ── Layer C: AES + Full Pipeline ──────────────────────────────────────────

class TestFullPipeline:
    PHRASE    = "secure-test-phrase"
    MACHINE   = "TEST_NODE"
    MESSAGES  = [
        "Hello LockJaw",
        "SOS URGENT HELP",
        "Transfer the coordinates now",
        "A",
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
    ]

    def _get_totp(self) -> str:
        return generate_totp(new_totp_secret())

    def test_roundtrip_all_messages(self):
        secret = new_totp_secret()
        totp   = generate_totp(secret)
        for msg in self.MESSAGES:
            env = encrypt(msg, self.PHRASE, totp, self.MACHINE)
            recovered = decrypt(env, self.PHRASE, totp, self.MACHINE)
            assert recovered.upper() == msg.upper(), f"Roundtrip failed for: {msg}"

    def test_envelope_serialization(self):
        secret = new_totp_secret()
        totp   = generate_totp(secret)
        env    = encrypt("TEST MESSAGE", self.PHRASE, totp, self.MACHINE)
        b64    = env.to_b64()
        env2   = EncryptedEnvelope.from_b64(b64)
        assert env.nonce      == env2.nonce
        assert env.ciphertext == env2.ciphertext
        assert env.tag        == env2.tag
        assert env.beale_iv   == env2.beale_iv

    def test_b64_output_is_valid(self):
        secret = new_totp_secret()
        totp   = generate_totp(secret)
        env    = encrypt("VALID BASE64 TEST", self.PHRASE, totp, self.MACHINE)
        b64    = env.to_b64()
        # Should be valid base64
        decoded = base64.b64decode(b64)
        assert len(decoded) > 0

    def test_wrong_phrase_raises(self):
        secret = new_totp_secret()
        totp   = generate_totp(secret)
        env    = encrypt("SECRET MESSAGE", self.PHRASE, totp, self.MACHINE)
        with pytest.raises(Exception):
            decrypt(env, "wrong-phrase", totp, self.MACHINE)

    def test_wrong_totp_raises(self):
        secret = new_totp_secret()
        totp   = generate_totp(secret)
        env    = encrypt("SECRET MESSAGE", self.PHRASE, totp, self.MACHINE)
        with pytest.raises(Exception):
            decrypt(env, self.PHRASE, "999999", self.MACHINE)

    def test_each_message_unique_ciphertext(self):
        secret = new_totp_secret()
        totp   = generate_totp(secret)
        msg    = "SAME MESSAGE"
        env1   = encrypt(msg, self.PHRASE, totp, self.MACHINE)
        env2   = encrypt(msg, self.PHRASE, totp, self.MACHINE)
        # Nonces should differ; ciphertexts should therefore differ
        assert env1.nonce != env2.nonce


# ── TOTP ──────────────────────────────────────────────────────────────────

class TestTOTP:
    def test_generate_6_digits(self):
        secret = new_totp_secret()
        code = generate_totp(secret)
        assert len(code) == 6
        assert code.isdigit()

    def test_verify_current_code(self):
        secret = new_totp_secret()
        code = generate_totp(secret)
        assert verify_totp(secret, code)

    def test_reject_wrong_code(self):
        secret = new_totp_secret()
        assert not verify_totp(secret, "000000")

    def test_drift_tolerance(self):
        secret = new_totp_secret()
        window = int(time.time()) // 30
        # Previous window code should be accepted with drift=1
        prev_code = generate_totp(secret, window - 1)
        assert verify_totp(secret, prev_code, drift=1)

    def test_b32_encoding(self):
        secret = new_totp_secret()
        b32 = totp_secret_to_b32(secret)
        assert len(b32) > 0
        # Should be valid base32
        decoded = base64.b32decode(b32)
        assert decoded == secret

    def test_different_secrets_different_codes(self):
        s1, s2 = new_totp_secret(), new_totp_secret()
        assert generate_totp(s1) != generate_totp(s2)  # astronomically likely
