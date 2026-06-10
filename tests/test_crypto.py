"""Unit tests for core/crypto.py cryptographic primitives.

Covers:
    - PBKDF2 key derivation (determinism, salt sensitivity)
    - HKDF per-file key isolation
    - AES-256-GCM encrypt/decrypt round-trip
    - Authentication tag integrity
    - gen_decoy_data (text, binary, edge cases)
    - Secure random generators
"""

import os
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

import pytest
from cryptography.exceptions import InvalidTag

from core.crypto import (
    KEY_LENGTH,
    NONCE_LENGTH,
    PBKDF2_ITERATIONS,
    SALT_LENGTH,
    TAG_LENGTH,
    _TEXT_SUFFIXES,
    decrypt,
    derive_file_key,
    derive_key,
    encrypt,
    gen_decoy_data,
    generate_nonce,
    generate_salt,
)


# ============================================================================
# Key derivation
# ============================================================================


class TestDeriveKey:
    """PBKDF2-HMAC-SHA256 master-key derivation."""

    def test_deterministic(self):
        """Same (password, salt) → same key."""
        salt = b"0123456789abcdef"
        k1 = derive_key("secret", salt)
        k2 = derive_key("secret", salt)
        assert k1 == k2

    def test_salt_sensitivity(self):
        """Different salts → different keys."""
        k1 = derive_key("secret", b"aaaaaaaaaaaaaaaa")
        k2 = derive_key("secret", b"bbbbbbbbbbbbbbbb")
        assert k1 != k2

    def test_password_sensitivity(self):
        """Different passwords → different keys."""
        salt = b"0123456789abcdef"
        k1 = derive_key("secret1", salt)
        k2 = derive_key("secret2", salt)
        assert k1 != k2

    def test_output_length(self):
        """Default length is 32 bytes (AES-256)."""
        k = derive_key("hello", b"0123456789abcdef")
        assert len(k) == KEY_LENGTH

    def test_custom_length(self):
        """Custom length overrides the default."""
        k = derive_key("hello", b"0123456789abcdef", length=64)
        assert len(k) == 64

    def test_unicode_password(self):
        """Unicode (Chinese) passwords are supported."""
        salt = b"0123456789abcdef"
        k = derive_key("中文密码测试", salt)
        assert len(k) == KEY_LENGTH

    def test_high_iteration_count(self):
        """PBKDF2 uses 600k iterations (OWASP 2023)."""
        assert PBKDF2_ITERATIONS == 600_000


class TestDeriveFileKey:
    """HKDF-SHA256 per-file key derivation."""

    def test_different_salts_yield_different_keys(self):
        master = derive_key("master", b"0123456789abcdef")
        fk1 = derive_file_key(master, b"aaaaaaaaaaaaaaaa")
        fk2 = derive_file_key(master, b"bbbbbbbbbbbbbbbb")
        assert fk1 != fk2

    def test_different_masters_yield_different_keys(self):
        m1 = derive_key("master1", b"0123456789abcdef")
        m2 = derive_key("master2", b"0123456789abcdef")
        fk1 = derive_file_key(m1, b"aaaaaaaaaaaaaaaa")
        fk2 = derive_file_key(m2, b"aaaaaaaaaaaaaaaa")
        assert fk1 != fk2

    def test_output_length(self):
        master = derive_key("master", b"0123456789abcdef")
        fk = derive_file_key(master, b"aaaaaaaaaaaaaaaa")
        assert len(fk) == KEY_LENGTH


# ============================================================================
# Secure random generators
# ============================================================================


class TestGenerators:
    def test_salt_length(self):
        assert len(generate_salt()) == SALT_LENGTH

    def test_nonce_length(self):
        assert len(generate_nonce()) == NONCE_LENGTH

    def test_salt_is_random(self):
        """Consecutive calls produce different salts."""
        s1 = generate_salt()
        s2 = generate_salt()
        assert s1 != s2

    def test_nonce_is_random(self):
        n1 = generate_nonce()
        n2 = generate_nonce()
        assert n1 != n2


# ============================================================================
# AES-256-GCM encrypt / decrypt
# ============================================================================


class TestEncryptDecrypt:
    KEY = derive_key("test-key", b"0123456789abcdef")

    def test_round_trip_empty(self):
        nonce, ct, tag = encrypt(b"", self.KEY)
        pt = decrypt(nonce, ct, tag, self.KEY)
        assert pt == b""

    def test_round_trip_short(self):
        nonce, ct, tag = encrypt(b"hello", self.KEY)
        pt = decrypt(nonce, ct, tag, self.KEY)
        assert pt == b"hello"

    def test_round_trip_large(self):
        data = os.urandom(1_000_000)  # 1 MB
        nonce, ct, tag = encrypt(data, self.KEY)
        pt = decrypt(nonce, ct, tag, self.KEY)
        assert pt == data

    def test_round_trip_chinese(self):
        data = "这是一份机密文档，包含重要信息。".encode("utf-8")
        nonce, ct, tag = encrypt(data, self.KEY)
        pt = decrypt(nonce, ct, tag, self.KEY)
        assert pt == data

    def test_nonce_is_unique_per_call(self):
        n1, _, _ = encrypt(b"data", self.KEY)
        n2, _, _ = encrypt(b"data", self.KEY)
        assert n1 != n2

    def test_ciphertext_differs_from_plaintext(self):
        nonce, ct, tag = encrypt(b"secret", self.KEY)
        assert ct != b"secret"

    def test_wrong_key_fails(self):
        """Decryption with wrong key raises InvalidTag."""
        k1 = derive_key("key1", b"0123456789abcdef")
        k2 = derive_key("key2", b"0123456789abcdef")
        nonce, ct, tag = encrypt(b"data", k1)
        with pytest.raises(InvalidTag):
            decrypt(nonce, ct, tag, k2)

    def test_wrong_nonce_fails(self):
        nonce, ct, tag = encrypt(b"data", self.KEY)
        bad_nonce = b"\x00" * NONCE_LENGTH
        with pytest.raises(InvalidTag):
            decrypt(bad_nonce, ct, tag, self.KEY)

    def test_wrong_tag_fails(self):
        nonce, ct, tag = encrypt(b"data", self.KEY)
        bad_tag = b"\xff" * TAG_LENGTH
        with pytest.raises(InvalidTag):
            decrypt(nonce, ct, bad_tag, self.KEY)

    def test_ciphertext_tampering_fails(self):
        nonce, ct, tag = encrypt(b"data", self.KEY)
        # Flip a bit in the ciphertext
        tampered = bytearray(ct)
        tampered[0] ^= 1
        with pytest.raises(InvalidTag):
            decrypt(nonce, bytes(tampered), tag, self.KEY)

    def test_associated_data(self):
        """AAD is authenticated but not encrypted."""
        aad = b"metadata-here"
        nonce, ct, tag = encrypt(b"payload", self.KEY, associated_data=aad)
        pt = decrypt(nonce, ct, tag, self.KEY, associated_data=aad)
        assert pt == b"payload"

    def test_wrong_aad_fails(self):
        nonce, ct, tag = encrypt(b"payload", self.KEY, associated_data=b"aad1")
        with pytest.raises(InvalidTag):
            decrypt(nonce, ct, tag, self.KEY, associated_data=b"aad2")

    def test_tag_length(self):
        _, _, tag = encrypt(b"data", self.KEY)
        assert len(tag) == TAG_LENGTH

    def test_nonce_length(self):
        nonce, _, _ = encrypt(b"data", self.KEY)
        assert len(nonce) == NONCE_LENGTH


# ============================================================================
# gen_decoy_data — plausible deniability
# ============================================================================


class TestGenDecoyData:
    """gen_decoy_data for plausible-deniability decoy generation."""

    def test_text_txt(self):
        real = b"x" * 500
        decoy = gen_decoy_data(real, ".txt")
        assert len(decoy) == 500
        assert "文档".encode("utf-8") in decoy

    def test_text_md(self):
        real = b"confidential notes\n" * 30
        decoy = gen_decoy_data(real, ".md")
        assert len(decoy) == len(real)
        assert "文档".encode("utf-8") in decoy

    def test_text_log(self):
        decoy = gen_decoy_data(b"log entry", ".log")
        assert len(decoy) == 9
        # Short input only captures the beginning of the template.
        # Verify it is Chinese text (UTF-8 CJK bytes 0xE4-0xE9).
        assert any(0xE4 <= b <= 0xE9 for b in decoy), "not Chinese text"

    def test_text_csv(self):
        decoy = gen_decoy_data(b"a,b,c\n1,2,3\n", ".csv")
        assert len(decoy) == 12
        assert any(0xE4 <= b <= 0xE9 for b in decoy), "not Chinese text"

    def test_case_insensitive(self):
        real = b"abc"
        d1 = gen_decoy_data(real, ".txt")
        d2 = gen_decoy_data(real, ".TXT")
        d3 = gen_decoy_data(real, ".Txt")
        assert d1 == d2 == d3

    def test_binary_pdf(self):
        real = os.urandom(1024)
        decoy = gen_decoy_data(real, ".pdf")
        assert len(decoy) == 1024
        assert decoy == b"\x20" * 1024

    def test_binary_png(self):
        decoy = gen_decoy_data(b"\x89PNG\r\n\x1a\n", ".png")
        assert decoy == b"\x20" * 8

    def test_binary_unknown_suffix(self):
        decoy = gen_decoy_data(b"data", ".xyz")
        assert decoy == b"\x20" * 4

    def test_empty_input(self):
        assert gen_decoy_data(b"", ".txt") == b""
        assert gen_decoy_data(b"", ".pdf") == b""

    def test_exact_template_boundary(self):
        """Regression: decoy at exactly the template length."""
        from core.crypto import _DECOY_TEMPLATE
        tlen = len(_DECOY_TEMPLATE)
        decoy = gen_decoy_data(b"x" * tlen, ".txt")
        assert len(decoy) == tlen
        assert decoy == _DECOY_TEMPLATE  # exact match, no tail

    def test_validation_empty_suffix(self):
        with pytest.raises(ValueError, match="must not be empty"):
            gen_decoy_data(b"x", "")

    def test_validation_no_dot(self):
        with pytest.raises(ValueError, match="must start with"):
            gen_decoy_data(b"x", "txt")

    def test_length_always_matches(self):
        """Fuzz: decoy length == real length for various sizes and suffixes."""
        for size in [0, 1, 16, 117, 118, 500, 1023, 1024, 10000]:
            for suffix in (".txt", ".md", ".log", ".csv", ".pdf", ".docx", ".jpg"):
                real = b"A" * size
                decoy = gen_decoy_data(real, suffix)
                assert len(decoy) == size, (
                    f"length mismatch: suffix={suffix}, size={size}, "
                    f"decoy_len={len(decoy)}"
                )

    def test_text_suffixes_set(self):
        """Verify the text suffix set is correct."""
        assert _TEXT_SUFFIXES == frozenset({".txt", ".md", ".log", ".csv"})


# ============================================================================
# Integration — full crypto workflow
# ============================================================================


class TestFullCryptoWorkflow:
    """End-to-end: password → key → encrypt → decrypt → verify."""

    def test_workflow_english(self):
        password = "correct horse battery staple"
        plaintext = b"The quick brown fox jumps over the lazy dog."

        salt = generate_salt()
        key = derive_key(password, salt)

        nonce, ct, tag = encrypt(plaintext, key)
        decrypted = decrypt(nonce, ct, tag, key)

        assert decrypted == plaintext

    def test_workflow_chinese(self):
        password = "我的安全密码123"
        plaintext = "量子密码学是密码学的一个分支。".encode("utf-8")

        salt = generate_salt()
        key = derive_key(password, salt)

        nonce, ct, tag = encrypt(plaintext, key)
        decrypted = decrypt(nonce, ct, tag, key)

        assert decrypted == plaintext

    def test_workflow_with_file_key_isolation(self):
        """Simulate the vault's full key hierarchy."""
        master_pw = "vault-master-123"
        master_salt = generate_salt()
        master_key = derive_key(master_pw, master_salt)

        # Per-file key 1
        file_salt_1 = generate_salt()
        file_key_1 = derive_file_key(master_key, file_salt_1)
        nonce1, ct1, tag1 = encrypt(b"file 1 content", file_key_1)

        # Per-file key 2 (different salt)
        file_salt_2 = generate_salt()
        file_key_2 = derive_file_key(master_key, file_salt_2)
        nonce2, ct2, tag2 = encrypt(b"file 2 content", file_key_2)

        # Decrypt with correct per-file keys
        assert decrypt(nonce1, ct1, tag1, file_key_1) == b"file 1 content"
        assert decrypt(nonce2, ct2, tag2, file_key_2) == b"file 2 content"

        # Cross-decryption must fail (file 1 key cannot decrypt file 2)
        with pytest.raises(InvalidTag):
            decrypt(nonce2, ct2, tag2, file_key_1)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])