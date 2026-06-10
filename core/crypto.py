"""Core cryptographic operations using AES-256-GCM and PBKDF2-HMAC-SHA256.

This module provides low-level cryptographic primitives for the vault system:

    - Password-based key derivation via PBKDF2-HMAC-SHA256 (OWASP 600k iterations)
    - Per-file key derivation via HKDF-SHA256 (so compromising one file key
      does not reveal the master key or any other file key)
    - AES-256-GCM authenticated encryption / decryption
    - Secure random salt and nonce generation via ``os.urandom``

All public functions carry full type annotations and are safe to call from
any module.

Examples
--------
>>> from core.crypto import derive_key, encrypt, decrypt, generate_salt
>>> salt = generate_salt()
>>> key = derive_key("horse staple battery", salt)
>>> nonce, ct, tag = encrypt(b"hello world", key)
>>> decrypt(nonce, ct, tag, key)
b'hello world'
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS: int = 600_000   # OWASP 2023 recommended minimum for SHA256
KEY_LENGTH: int = 32               # AES-256 → 32-byte key
SALT_LENGTH: int = 16              # 128-bit salt
NONCE_LENGTH: int = 12             # AES-GCM standard nonce (96 bits)
TAG_LENGTH: int = 16               # AES-GCM authentication tag (128 bits)

# Plausible-deniability decoy template — normal-looking Chinese text used as
# the repeating unit when generating fake plaintext for text-based files.
_DECOY_TEMPLATE: bytes = (
    "这是一份普通文档，仅用作日常记录与测试使用。"
    "文档内容无敏感信息，仅供参考查阅。"
).encode("utf-8")

# File suffixes that should receive text-based decoy content rather than
# binary padding.  Compare case-insensitively.
_TEXT_SUFFIXES: frozenset[str] = frozenset({".txt", ".md", ".log", ".csv"})

# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_key(
    password: str,
    salt: bytes,
    length: int = KEY_LENGTH,
) -> bytes:
    """Derive a cryptographic key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: User-provided password (UTF-8 encoded internally).
        salt: Random salt, ideally ``SALT_LENGTH`` bytes.
        length: Desired key length in bytes (default 32 for AES-256).

    Returns:
        Derived key as raw bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_file_key(
    master_key: bytes,
    file_salt: bytes,
    length: int = KEY_LENGTH,
) -> bytes:
    """Derive a per-file encryption key from the master key via HKDF-SHA256.

    Each file receives a **unique** key derived from the master key and a
    random per-file salt.  This property ensures that an attacker who
    recovers one file key cannot derive the master key or any other file key
    (forward security within the vault).

    Args:
        master_key: Vault master key (output of :func:`derive_key`).
        file_salt: Per-file random salt.
        length: Desired key length (default 32 for AES-256).

    Returns:
        Per-file encryption key as raw bytes.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=file_salt,
        info=b"vault-file-key-v1",
    )
    return hkdf.derive(master_key)


# ---------------------------------------------------------------------------
# Secure random generators
# ---------------------------------------------------------------------------


def generate_salt(length: int = SALT_LENGTH) -> bytes:
    """Return a cryptographically random salt."""
    return os.urandom(length)


def generate_nonce(length: int = NONCE_LENGTH) -> bytes:
    """Return a cryptographically random nonce for AES-GCM."""
    return os.urandom(length)


# ---------------------------------------------------------------------------
# Plausible-deniability decoy generation
# ---------------------------------------------------------------------------


def gen_decoy_data(real_data: bytes, file_suffix: str) -> bytes:
    """Generate plausible fake data that is **byte-for-byte identical in
    length** to *real_data*.

    This function supports plausible-deniability workflows: given an
    encrypted file whose ciphertext length leaks the plaintext length,
    the caller can produce decoy plaintext of the same size so that an
    adversary cannot distinguish real from decoy based on size alone.

    Rules
    -----
    * **Text files** (``.txt``, ``.md``, ``.log``, ``.csv``):
      A repeating Chinese prose template is cycled until the output
      reaches the exact length of *real_data*.
    * **All other files** (binary / unknown suffix):
      Every byte is set to ``0x20`` (ASCII space).

    Args:
        real_data: The original file bytes (only ``len(real_data)`` is
            used; the content itself is never inspected).
        file_suffix: File extension including the leading dot
            (e.g. ``".txt"``, ``".pdf"``, ``".xlsx"``).  Comparison is
            **case-insensitive** — ``".TXT"`` and ``".txt"`` are
            treated identically.

    Returns:
        Decoy bytes such that ``len(result) == len(real_data)``.

    Raises:
        ValueError: If *file_suffix* is empty or does not start with
            a dot.

    Examples
    --------
    >>> gen_decoy_data(b"secret plans\\n", ".txt")
    b'...'  # same length, Chinese text

    >>> gen_decoy_data(b"\\x89PNG...", ".png")
    b'                        '  # same length, all spaces
    """
    # ---- argument validation ------------------------------------------------
    if not file_suffix:
        raise ValueError("file_suffix must not be empty")
    if not file_suffix.startswith("."):
        raise ValueError(
            f"file_suffix must start with '.', got {file_suffix!r}"
        )

    data_len = len(real_data)

    # ---- text decoy ---------------------------------------------------------
    if file_suffix.lower() in _TEXT_SUFFIXES:
        template_len = len(_DECOY_TEMPLATE)
        # Pre-allocate and copy full repetitions + one partial tail
        full_repeats = data_len // template_len
        tail = data_len % template_len

        buf = bytearray(data_len)
        # Fill full repetitions
        for i in range(full_repeats):
            offset = i * template_len
            buf[offset : offset + template_len] = _DECOY_TEMPLATE
        # Fill the remaining tail
        if tail:
            buf[full_repeats * template_len :] = _DECOY_TEMPLATE[:tail]

        return bytes(buf)

    # ---- binary decoy --------------------------------------------------------
    return b"\x20" * data_len


def encrypt(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes = b"",
) -> tuple[bytes, bytes, bytes]:
    """Encrypt *plaintext* with AES-256-GCM.

    A fresh 96-bit nonce is generated internally for every call.

    Args:
        plaintext: The data to encrypt.
        key: 32-byte AES-256 key.
        associated_data: Optional authenticated-but-not-encrypted data.

    Returns:
        A tuple ``(nonce, ciphertext, tag)``.  **All three components must
        be stored** — every one of them is required for decryption.
    """
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext ‖ tag (tag is the final 16 bytes)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext = ct_with_tag[:-TAG_LENGTH]
    tag = ct_with_tag[-TAG_LENGTH:]
    return nonce, ciphertext, tag


def decrypt(
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    key: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt *ciphertext* with AES-256-GCM.

    Args:
        nonce: The nonce that was used during encryption.
        ciphertext: The encrypted data (without the tag).
        tag: The 16-byte authentication tag.
        key: 32-byte AES-256 key.
        associated_data: Must match the value passed to :func:`encrypt`.

    Returns:
        Decrypted plaintext.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
            (wrong key, corrupted ciphertext, or tampered data).
    """
    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_with_tag, associated_data)