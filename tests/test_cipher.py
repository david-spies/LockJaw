"""
LockJaw — Cipher Test Suite
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from crypto.hybrid_cipher import HybridCipher, MorseCodec, BealeLayer, KeyDeriver


PHRASE = "quantum-oracle-7734"
TOTP = "123456"
MACHINE = "NEXUS_01"


class TestMorseCodec:
    def test_encode_simple(self):
        ascii_ints, morse, binary = MorseCodec.encode("SOS")
        assert "..." in morse
        assert "---" in morse
        assert len(binary) > 0

    def test_roundtrip(self):
        _, _, binary = MorseCodec.encode("HELLO WORLD")
        result = MorseCodec.decode(binary)
        assert result == "HELLO WORLD"

    def test_single_char(self):
        _, _, binary = MorseCodec.encode("E")
        result = MorseCodec.decode(binary)
        assert result == "E"

    def test_numbers(self):
        _, _, binary = MorseCodec.encode("42")
        result = MorseCodec.decode(binary)
        assert result == "42"


class TestBealeLayer:
    def test_scramble_unscramble(self):
        original = "0110221300112"
        scrambled = BealeLayer.scramble(original, PHRASE)
        assert isinstance(scrambled, bytes)
        recovered = BealeLayer.unscramble(scrambled, PHRASE)
        assert recovered == original

    def test_different_phrase_fails(self):
        original = "0110221300112"
        scrambled = BealeLayer.scramble(original, PHRASE)
        wrong = BealeLayer.unscramble(scrambled, "wrong-phrase")
        assert wrong != original

    def test_key_stream_length(self):
        data = "test" * 100
        scrambled = BealeLayer.scramble(data, PHRASE)
        assert len(scrambled) == len(data.encode())


class TestKeyDeriver:
    def test_deterministic(self):
        k1 = KeyDeriver.derive(MACHINE, TOTP, PHRASE)
        k2 = KeyDeriver.derive(MACHINE, TOTP, PHRASE)
        assert k1 == k2

    def test_length(self):
        k = KeyDeriver.derive(MACHINE, TOTP, PHRASE)
        assert len(k) == 32

    def test_different_inputs_differ(self):
        k1 = KeyDeriver.derive(MACHINE, TOTP, PHRASE)
        k2 = KeyDeriver.derive(MACHINE, "999999", PHRASE)
        assert k1 != k2


class TestHybridCipher:
    def setup_method(self):
        self.cipher = HybridCipher()

    def test_encrypt_returns_packet(self):
        pkt = self.cipher.encrypt("HELLO", PHRASE, TOTP, MACHINE)
        assert pkt.ciphertext_b64
        assert pkt.nonce_b64
        assert pkt.morse
        assert pkt.session_key_hex

    def test_roundtrip(self):
        plaintext = "SECURE MESSAGE TEST"
        pkt = self.cipher.encrypt(plaintext, PHRASE, TOTP, MACHINE)
        result = self.cipher.decrypt(pkt.ciphertext_b64, pkt.nonce_b64, PHRASE, TOTP, MACHINE)
        assert result.verified
        assert result.plaintext == plaintext

    def test_wrong_phrase_fails(self):
        pkt = self.cipher.encrypt("SECRET", PHRASE, TOTP, MACHINE)
        result = self.cipher.decrypt(pkt.ciphertext_b64, pkt.nonce_b64, "wrong-phrase", TOTP, MACHINE)
        assert not result.verified

    def test_wrong_totp_fails(self):
        pkt = self.cipher.encrypt("SECRET", PHRASE, TOTP, MACHINE)
        result = self.cipher.decrypt(pkt.ciphertext_b64, pkt.nonce_b64, PHRASE, "000000", MACHINE)
        assert not result.verified

    def test_tampered_ciphertext_fails(self):
        pkt = self.cipher.encrypt("SECRET", PHRASE, TOTP, MACHINE)
        tampered = pkt.ciphertext_b64[:-4] + "XXXX"
        result = self.cipher.decrypt(tampered, pkt.nonce_b64, PHRASE, TOTP, MACHINE)
        assert not result.verified

    def test_long_message(self):
        long_msg = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG 1234567890" * 3
        pkt = self.cipher.encrypt(long_msg, PHRASE, TOTP, MACHINE)
        result = self.cipher.decrypt(pkt.ciphertext_b64, pkt.nonce_b64, PHRASE, TOTP, MACHINE)
        assert result.verified
        assert result.plaintext == long_msg
