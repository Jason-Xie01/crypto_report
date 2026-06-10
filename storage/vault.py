"""Encrypted file vault with plausible deniability.

Supports dual-key encryption: a **real** master password decrypts the
original files; a **decoy** password (set up at init time) decrypts
plausible-looking fake data of identical length.

Storage layout (inside ``.vault/`` relative to the working directory)::

    .vault/
    ├── master.salt        # 16 B — PBKDF2 salt (shared by both passwords)
    ├── master.check       # 12B nonce ‖ 8B ct  ‖ 16B tag — encrypted magic (REAL)
    ├── master.decoy       # (optional) same format — encrypted magic (DECOY)
    ├── manifest.json      # list of VaultEntry (dual crypto params)
    └── objects/           # <uuid>.enc (real) + <uuid>.decoy (decoy)

Key design points
-----------------
* A single ``master.salt`` is shared by both the real and decoy passwords.
  An attacker inspecting ``.vault/`` cannot determine whether a decoy
  password exists.
* ``master.check`` and ``master.decoy`` each contain the 8-byte magic
  ``VAULT_OK`` encrypted with the respective derived key.  On ``open``
  the module tries both check files; the one that decrypts successfully
  determines which role the supplied password plays.
* ``vault list`` requires **no password** and returns identical output
  regardless of which key the caller holds.
* Each file produces two independent ciphertext blobs:
  ``objects/<uuid>.enc`` (real) and ``objects/<uuid>.decoy`` (decoy).
  The manifest stores the per-file salt / nonce / tag for both.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Tuple

from core.crypto import (
    decrypt,
    derive_file_key,
    derive_key,
    encrypt,
    gen_decoy_data,
    generate_nonce,
    generate_salt,
    KEY_LENGTH,
    NONCE_LENGTH,
    SALT_LENGTH,
    TAG_LENGTH,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VAULT_DIR_NAME: str = ".vault"
MASTER_SALT_FILE: str = "master.salt"
MASTER_CHECK_FILE: str = "master.check"   # encrypted with REAL master key
MASTER_DECOY_FILE: str = "master.decoy"   # encrypted with DECOY master key
MANIFEST_FILE: str = "manifest.json"
OBJECTS_DIR: str = "objects"

# Known plaintext for master-password verification (must be short).
_MAGIC: bytes = b"VAULT_OK"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class VaultError(Exception):
    """Base exception for vault-level errors."""


class VaultNotInitializedError(VaultError):
    """Raised when a vault operation is attempted before ``vault init``."""


class VaultPasswordError(VaultError):
    """Raised when the provided password matches neither real nor decoy."""


class VaultFileConflictError(VaultError):
    """Raised when a file with the same name already exists in the vault."""


class VaultFileNotFoundError(VaultError):
    """Raised when the requested file is not in the vault."""


class VaultDecoyRequiredError(VaultError):
    """Raised when the decoy password is required but not provided."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class VaultEntry:
    """Metadata for a single encrypted file (dual-encryption).

    Public fields (visible in ``vault list`` with no password):
        name, original_path, file_suffix, size, added

    Crypto fields (two complete independent parameter sets):
        real_*  — decrypts the original file with the REAL master key
        decoy_* — decrypts plausible fake data with the DECOY master key
    """

    # ---- public metadata ----
    name: str
    original_path: str
    file_suffix: str          # e.g. ".txt", ".pdf" — for gen_decoy_data
    size: int                 # original plaintext size (real == decoy)
    added: str                # ISO-8601 timestamp

    # ---- real crypto params ----
    real_salt: str = ""       # base64 per-file HKDF salt
    real_nonce: str = ""      # base64 AES-GCM nonce
    real_tag: str = ""        # base64 AES-GCM tag
    real_object_id: str = ""  # filename inside objects/

    # ---- decoy crypto params ----
    decoy_salt: str = ""
    decoy_nonce: str = ""
    decoy_tag: str = ""
    decoy_object_id: str = ""

    def __post_init__(self) -> None:
        # Always generate a real object id (every file has a real encryption).
        if not self.real_object_id:
            self.real_object_id = f"{uuid.uuid4().hex}.enc"
        # Only auto-generate a decoy id when decoy crypto params are
        # actually populated (salt is the discriminator).
        if not self.decoy_object_id and self.decoy_salt:
            self.decoy_object_id = f"{uuid.uuid4().hex}.decoy"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _vault_root() -> Path:
    """Return the ``.vault`` directory path (always relative to CWD)."""
    return Path.cwd() / VAULT_DIR_NAME


def _require_vault() -> Path:
    """Return the vault root, raising if ``.vault`` does not exist."""
    root = _vault_root()
    if not root.is_dir():
        raise VaultNotInitializedError(
            "Vault not found — run 'vault init' first."
        )
    return root


def _b64(data: bytes) -> str:
    """Encode bytes as a base64 string (URL-safe, no padding)."""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _from_b64(s: str, expected_len: int) -> bytes:
    """Decode a base64 string back to bytes, restoring padding."""
    import base64
    padded = s + "=" * (-len(s) % 4)
    data = base64.urlsafe_b64decode(padded)
    if len(data) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(data)}")
    return data


# ---------------------------------------------------------------------------
# Check-file helpers (master password verification)
# ---------------------------------------------------------------------------


def _compute_check(password: str, salt: bytes) -> bytes:
    """Encrypt the magic constant and return *nonce + ct + tag*."""
    key = derive_key(password, salt)
    nonce, ct, tag = encrypt(_MAGIC, key)
    return nonce + ct + tag


def _try_check(key: bytes, check_path: Path) -> bool:
    """Return True if *key* successfully decrypts *check_path*."""
    if not check_path.is_file():
        return False
    raw = check_path.read_bytes()
    expected = NONCE_LENGTH + len(_MAGIC) + TAG_LENGTH
    if len(raw) != expected:
        return False
    nonce = raw[:NONCE_LENGTH]
    ct = raw[NONCE_LENGTH:-TAG_LENGTH]
    tag = raw[-TAG_LENGTH:]
    try:
        result = decrypt(nonce, ct, tag, key)
        return result == _MAGIC
    except Exception:
        return False


def _authenticate(password: str, root: Path) -> Tuple[bytes, str]:
    """Derive a key from *password* and determine its **role**.

    Returns:
        ``(key, "real")`` if the password matches ``master.check``.
        ``(key, "decoy")`` if it matches ``master.decoy``.

    Raises:
        VaultPasswordError: If the password matches **neither** check file.
        VaultNotInitializedError: If ``master.salt`` is missing.
    """
    salt_path = root / MASTER_SALT_FILE
    if not salt_path.is_file():
        raise VaultNotInitializedError("Master salt missing — re-run init.")
    salt = salt_path.read_bytes()
    if len(salt) != SALT_LENGTH:
        raise VaultError("Corrupted master.salt")

    key = derive_key(password, salt)

    # Try real check first
    if _try_check(key, root / MASTER_CHECK_FILE):
        return key, "real"

    # Try decoy check
    if _try_check(key, root / MASTER_DECOY_FILE):
        return key, "decoy"

    raise VaultPasswordError("Incorrect master password.")


def _has_decoy(root: Path) -> bool:
    """Return True if the vault was initialised with ``--decoy``."""
    return (root / MASTER_DECOY_FILE).is_file()


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------


def _load_manifest(root: Path) -> list[VaultEntry]:
    """Load the vault manifest, returning an empty list if it doesn't exist."""
    path = root / MANIFEST_FILE
    if not path.is_file():
        return []
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return [VaultEntry(**item) for item in raw]


def _save_manifest(manifest: list[VaultEntry], root: Path) -> None:
    """Atomically write the manifest to disk."""
    path = root / MANIFEST_FILE
    tmp = path.with_suffix(".json.tmp")
    payload = [asdict(entry) for entry in manifest]
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    tmp.replace(path)


# ===================================================================
# Public API
# ===================================================================


def vault_init(password: str, decoy_password: str | None = None) -> None:
    """Initialise a new vault in the current working directory.

    Args:
        password: Real master password.
        decoy_password: Optional decoy (plausible-deniability) password.
            When provided, the vault supports dual-key decryption:
            *password* decrypts real files, *decoy_password* decrypts
            plausible fakes.

    Raises:
        FileExistsError: If ``.vault`` already exists.
    """
    root = _vault_root()
    if root.is_dir():
        raise FileExistsError(f"Vault already exists at {root}")

    # Create directory tree
    root.mkdir(parents=True)
    (root / OBJECTS_DIR).mkdir()

    # Shared master salt
    master_salt = generate_salt()
    (root / MASTER_SALT_FILE).write_bytes(master_salt)

    # Real check file
    real_check = _compute_check(password, master_salt)
    (root / MASTER_CHECK_FILE).write_bytes(real_check)

    # Optional decoy check file
    if decoy_password is not None:
        decoy_check = _compute_check(decoy_password, master_salt)
        (root / MASTER_DECOY_FILE).write_bytes(decoy_check)

    # Empty manifest
    _save_manifest([], root)


def vault_add(
    password: str,
    file_path: str | Path,
    name: str | None = None,
    decoy_password: str | None = None,
) -> VaultEntry:
    """Encrypt *file_path* and store it in the vault.

    If the vault has a decoy setup, **both** *password* (real) and
    *decoy_password* must be supplied so that two independent ciphertexts
    can be produced.  The function authenticates each password against
    its respective check file before proceeding.

    Args:
        password: Real master password.
        file_path: Filesystem path to the file to encrypt.
        name: Logical name inside the vault (defaults to the source filename).
        decoy_password: Decoy master password.  Required if the vault
            was initialised with ``--decoy``.

    Returns:
        The :class:`VaultEntry` metadata for the newly added file.

    Raises:
        FileNotFoundError: If *file_path* does not exist.
        VaultFileConflictError: If *name* already exists in the vault.
        VaultPasswordError: If either password is wrong.
        VaultDecoyRequiredError: If the vault has a decoy but
            *decoy_password* was not provided.
    """
    root = _require_vault()
    src = Path(file_path).resolve()
    if not src.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    file_name = name or src.name
    file_suffix = src.suffix.lower()  # e.g. ".txt"

    # Read original plaintext
    plaintext = src.read_bytes()
    data_len = len(plaintext)

    # --- authenticate real password ---
    master_salt = (root / MASTER_SALT_FILE).read_bytes()
    real_key = derive_key(password, master_salt)
    if not _try_check(real_key, root / MASTER_CHECK_FILE):
        raise VaultPasswordError("Incorrect real master password.")

    # --- authenticate decoy password (if vault has one) ---
    vault_has_decoy = _has_decoy(root)
    if vault_has_decoy:
        if decoy_password is None:
            raise VaultDecoyRequiredError(
                "This vault requires a decoy password for 'vault add'. "
                "Pass --decoy-password or provide it interactively."
            )
        decoy_key = derive_key(decoy_password, master_salt)
        if not _try_check(decoy_key, root / MASTER_DECOY_FILE):
            raise VaultPasswordError("Incorrect decoy master password.")
    else:
        decoy_key = None  # type: ignore[assignment]

    # --- check for name collision ---
    manifest = _load_manifest(root)
    if any(e.name == file_name for e in manifest):
        raise VaultFileConflictError(
            f"File '{file_name}' already exists in vault. Remove it first."
        )

    # --- generate decoy plaintext (always, even without decoy key) ---
    decoy_plaintext = gen_decoy_data(plaintext, file_suffix)
    assert len(decoy_plaintext) == data_len, "decoy length mismatch"

    # --- encrypt REAL data with real key ---
    real_file_salt = generate_salt()
    real_file_key = derive_file_key(real_key, real_file_salt)
    real_nonce, real_ct, real_tag = encrypt(plaintext, real_file_key)
    real_oid = f"{uuid.uuid4().hex}.enc"
    (root / OBJECTS_DIR / real_oid).write_bytes(real_ct)

    # --- encrypt DECOY data ---
    if decoy_key is not None:
        decoy_file_salt = generate_salt()
        decoy_file_key = derive_file_key(decoy_key, decoy_file_salt)
        decoy_nonce, decoy_ct, decoy_tag = encrypt(decoy_plaintext, decoy_file_key)
        decoy_oid = f"{uuid.uuid4().hex}.decoy"
        (root / OBJECTS_DIR / decoy_oid).write_bytes(decoy_ct)
    else:
        # No decoy password → store empty params
        decoy_file_salt = b""
        decoy_nonce = b""
        decoy_ct = b""
        decoy_tag = b""
        decoy_oid = ""

    # --- persist manifest entry ---
    entry = VaultEntry(
        name=file_name,
        original_path=str(src),
        file_suffix=file_suffix,
        size=data_len,
        added=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        real_salt=_b64(real_file_salt),
        real_nonce=_b64(real_nonce),
        real_tag=_b64(real_tag),
        real_object_id=real_oid,
        decoy_salt=_b64(decoy_file_salt) if decoy_file_salt else "",
        decoy_nonce=_b64(decoy_nonce) if decoy_nonce else "",
        decoy_tag=_b64(decoy_tag) if decoy_tag else "",
        decoy_object_id=decoy_oid,
    )

    manifest.append(entry)
    _save_manifest(manifest, root)

    return entry


def vault_remove(password: str, name: str) -> VaultEntry:
    """Remove *name* from the vault (deletes both ciphertext blobs).

    Args:
        password: Either the real or decoy master password.
        name: Logical file name in the vault.

    Returns:
        The removed entry (for reference).

    Raises:
        VaultFileNotFoundError: If *name* is not in the vault.
        VaultPasswordError: If *password* is wrong.
    """
    root = _require_vault()
    _authenticate(password, root)  # accepts either real or decoy

    manifest = _load_manifest(root)
    for i, entry in enumerate(manifest):
        if entry.name == name:
            # Remove both ciphertext blobs (one or both may exist)
            for oid in (entry.real_object_id, entry.decoy_object_id):
                if oid:
                    obj_path = root / OBJECTS_DIR / oid
                    if obj_path.is_file():
                        obj_path.unlink()
            manifest.pop(i)
            _save_manifest(manifest, root)
            return entry

    raise VaultFileNotFoundError(f"'{name}' not found in vault.")


def vault_list() -> list[VaultEntry]:
    """Return the full vault manifest **(no password required)**.

    The returned list has identical ``name`` / ``size`` / ``added``
    fields regardless of which key the caller holds — this is essential
    for plausible deniability.
    """
    try:
        root = _require_vault()
    except VaultNotInitializedError:
        return []
    return _load_manifest(root)


def vault_open(
    password: str,
    name: str,
    output_path: str | Path,
) -> Path:
    """Decrypt *name* from the vault and write it to *output_path*.

    **Key routing** (automatic, zero user-visible difference):
        - If *password* matches the **real** master key → the original
          file is decrypted.
        - If *password* matches the **decoy** master key → plausible
          fake data is decrypted instead.
        - If *password* matches **neither** → :class:`VaultPasswordError`.

    Args:
        password: Real or decoy master password.
        name: Logical file name in the vault.
        output_path: Destination path for the decrypted file.

    Returns:
        The resolved output path.

    Raises:
        VaultFileNotFoundError: If *name* is not in the vault.
        VaultPasswordError: If *password* is wrong.
    """
    root = _require_vault()
    key, role = _authenticate(password, root)

    # Find entry
    manifest = _load_manifest(root)
    entry: VaultEntry | None = None
    for e in manifest:
        if e.name == name:
            entry = e
            break

    if entry is None:
        raise VaultFileNotFoundError(f"'{name}' not found in vault.")

    # Select the appropriate crypto params
    if role == "real":
        salt_b64 = entry.real_salt
        nonce_b64 = entry.real_nonce
        tag_b64 = entry.real_tag
        object_id = entry.real_object_id
    else:  # decoy
        salt_b64 = entry.decoy_salt
        nonce_b64 = entry.decoy_nonce
        tag_b64 = entry.decoy_tag
        object_id = entry.decoy_object_id

    if not object_id:
        raise VaultError(
            f"No {'decoy' if role == 'decoy' else 'real'} encryption "
            f"data for '{name}'. The vault may have been created without "
            f"--decoy and you are using the decoy password, or vice versa."
        )

    # Read ciphertext
    obj_path = root / OBJECTS_DIR / object_id
    if not obj_path.is_file():
        raise VaultError(f"Ciphertext blob missing: {object_id}")
    ciphertext = obj_path.read_bytes()

    # Derive per-file key
    file_salt = _from_b64(salt_b64, SALT_LENGTH)
    file_key = derive_file_key(key, file_salt)

    # Decrypt
    nonce = _from_b64(nonce_b64, NONCE_LENGTH)
    tag = _from_b64(tag_b64, TAG_LENGTH)
    plaintext = decrypt(nonce, ciphertext, tag, file_key)

    # Write output
    dest = Path(output_path).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(plaintext)

    return dest