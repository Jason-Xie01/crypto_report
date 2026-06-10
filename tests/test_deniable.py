"""Integration test for plausible-deniability (dual-key) vault.

Run from project root::

    python tests/test_deniable.py

Covers
------
1. vault init --decoy    —  dual-password initialisation
2. vault add             —  dual encryption (real + decoy ciphertext blobs)
3. vault list            —  identity-masked output (no key needed)
4. vault list consistency — list output identical regardless of which key is used
5. vault open real key   —  real password → original file
6. vault open decoy key  —  decoy password → plausible fake (text & binary)
7. vault open wrong key  —  VaultPasswordError (no crash)
8. vault remove          —  deletes both blobs
9. Backward compat       —  vault init (no --decoy) still works
10. Cannot distinguish    —  adversary sees same size, dual params opaque
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from storage.vault import (
    VaultDecoyRequiredError,
    VaultError,
    VaultFileConflictError,
    VaultFileNotFoundError,
    VaultPasswordError,
    _has_decoy,
    _load_manifest,
    _require_vault,
    vault_add,
    vault_init,
    vault_list,
    vault_open,
    vault_remove,
)

PASS_REAL  = "my-real-secret-1234"
PASS_DECOY = "totally-harmless-42"


def test_init_with_decoy(workspace: str):
    """vault init --decoy creates master.salt, master.check, master.decoy."""
    vault_init(PASS_REAL, decoy_password=PASS_DECOY)
    root = Path(workspace) / ".vault"
    assert root.is_dir()
    assert (root / "master.salt").is_file()
    assert (root / "master.check").is_file()
    assert (root / "master.decoy").is_file(), "master.decoy MISSING"
    assert (root / "manifest.json").is_file()
    assert (root / "objects").is_dir()
    assert _has_decoy(root)
    print("  [OK] vault init --decoy")


def test_add_text_file(workspace: str):
    """Encrypt a .txt file and verify dual blobs exist."""
    src = Path(workspace) / "secret.txt"
    src.write_bytes(b"TOP SECRET: launch codes are 12345.\n")

    entry = vault_add(PASS_REAL, str(src), decoy_password=PASS_DECOY)
    assert entry.name == "secret.txt"
    assert entry.size == len(b"TOP SECRET: launch codes are 12345.\n")
    assert entry.real_object_id
    assert entry.decoy_object_id
    assert entry.real_salt and entry.real_nonce and entry.real_tag
    assert entry.decoy_salt and entry.decoy_nonce and entry.decoy_tag

    root = Path(workspace) / ".vault"
    assert (root / "objects" / entry.real_object_id).is_file(), "real blob missing"
    assert (root / "objects" / entry.decoy_object_id).is_file(), "decoy blob missing"

    # Both blobs should be different
    real_blob = (root / "objects" / entry.real_object_id).read_bytes()
    decoy_blob = (root / "objects" / entry.decoy_object_id).read_bytes()
    assert real_blob != decoy_blob, "real and decoy ciphertexts must differ"
    print(f"  [OK] vault add .txt  (real={len(real_blob)}B, decoy={len(decoy_blob)}B)")


def test_add_binary_file(workspace: str):
    """Encrypt a .dat (binary) file with random content."""
    src = Path(workspace) / "data.dat"
    src.write_bytes(os.urandom(2048))

    entry = vault_add(PASS_REAL, str(src), decoy_password=PASS_DECOY)
    assert entry.name == "data.dat"
    assert entry.size == 2048
    assert entry.real_object_id and entry.decoy_object_id
    print(f"  [OK] vault add .dat (binary, 2048 bytes)")


def test_add_multiple_files(workspace: str):
    """Add multiple files of mixed types — each gets dual encryption."""
    files = {
        "notes.md": b"# Meeting Notes\n\n- Discuss budget\n- Plan roadmap\n",
        "data.csv": b"id,name,value\n1,Alice,100\n2,Bob,200\n",
        "key.log": b"[INFO] Server started\n[WARN] Connection timeout\n",
    }
    for fname, content in files.items():
        src = Path(workspace) / fname
        src.write_bytes(content)
        entry = vault_add(PASS_REAL, str(src), decoy_password=PASS_DECOY)
        assert entry.name == fname
        assert entry.size == len(content)
        assert entry.real_object_id and entry.decoy_object_id
    print(f"  [OK] vault add {len(files)} mixed-type files")


def test_list_no_password(workspace: str):
    """vault list returns consistent output without any password."""
    entries = vault_list()
    # At this point we have secret.txt, data.dat, notes.md, data.csv, key.log
    assert len(entries) >= 5, f"expected >=5 entries, got {len(entries)}"
    names = {e.name for e in entries}
    assert "secret.txt" in names
    assert "data.dat" in names

    # Verify no crypto-internal fields leak in the public view
    for e in entries:
        assert e.name and e.size >= 0 and e.added
        # Public API should not expose internal paths
        assert "master.salt" not in str(e.name)
    print(f"  [OK] vault list ({len(entries)} files, no password)")


def test_list_identity_under_different_keys(workspace: str):
    """After opening with real & decoy keys, vault_list is identical."""
    # Snapshot before
    before = [(e.name, e.size, e.added) for e in vault_list()]

    # Open one file with real key (this should not mutate list)
    vault_open(PASS_REAL, "secret.txt", str(Path(workspace) / "temp1.txt"))
    mid = [(e.name, e.size, e.added) for e in vault_list()]
    assert before == mid, "list changed after real-key open!"

    # Open same file with decoy key
    vault_open(PASS_DECOY, "secret.txt", str(Path(workspace) / "temp2.txt"))
    after = [(e.name, e.size, e.added) for e in vault_list()]
    assert before == after, "list changed after decoy-key open!"

    print(f"  [OK] vault list identity preserved across real & decoy accesses")


def test_open_real_key(workspace: str):
    """Real password → original plaintext."""
    dest = vault_open(PASS_REAL, "secret.txt", str(Path(workspace) / "out_real.txt"))
    content = dest.read_bytes()
    expected = b"TOP SECRET: launch codes are 12345.\n"
    assert content == expected, f"real decrypt mismatch: {content!r}"
    print(f"  [OK] vault open (real key) → original content")


def test_open_decoy_key(workspace: str):
    """Decoy password → plausible fake (Chinese text, same length)."""
    dest = vault_open(PASS_DECOY, "secret.txt", str(Path(workspace) / "out_decoy.txt"))
    content = dest.read_bytes()
    expected_len = len(b"TOP SECRET: launch codes are 12345.\n")
    assert len(content) == expected_len, (
        f"decoy length mismatch: {len(content)} vs {expected_len}"
    )
    # Must contain Chinese text from the decoy template
    assert "文档".encode("utf-8") in content, f"no Chinese text in decoy: {content!r}"
    # Must NOT contain the real secret
    assert b"launch codes" not in content, "decoy leaked real content!"
    print(f"  [OK] vault open (decoy key) → plausible fake ({len(content)} bytes)")


def test_open_decoy_binary(workspace: str):
    """Decoy password on binary file → all-space padding, same length."""
    dest = vault_open(PASS_DECOY, "data.dat", str(Path(workspace) / "out_decoy.dat"))
    content = dest.read_bytes()
    assert len(content) == 2048, f"decoy binary length mismatch: {len(content)}"
    assert content == b"\x20" * 2048, "decoy binary must be all 0x20"
    print(f"  [OK] vault open (decoy key, binary) → all spaces (2048 bytes)")


def test_open_decoy_text_files_are_plausible(workspace: str):
    """Every text-type file decrypts to plausible-looking content with decoy key."""
    text_files = ["notes.md", "data.csv", "key.log"]
    for fname in text_files:
        dest = vault_open(PASS_DECOY, fname, str(Path(workspace) / f"decoy_{fname}"))
        content = dest.read_bytes()
        assert "文档".encode("utf-8") in content, (
            f"decoy {fname} should contain Chinese text"
        )
        # Verify length matches original
        entries = vault_list()
        entry = next(e for e in entries if e.name == fname)
        assert len(content) == entry.size, f"{fname}: decoy length mismatch"
    print(f"  [OK] all text decoys are plausible Chinese text")


def test_open_wrong_password(workspace: str):
    """Wrong password → VaultPasswordError."""
    try:
        vault_open("wrong-password", "secret.txt", str(Path(workspace) / "nope.txt"))
        assert False, "should have raised VaultPasswordError"
    except VaultPasswordError:
        print(f"  [OK] vault open (wrong password) → VaultPasswordError")


def test_remove_with_real_key(workspace: str):
    """vault remove with real password deletes both blobs."""
    removed = vault_remove(PASS_REAL, "data.dat")
    assert removed.name == "data.dat"

    # Verify blob files are gone
    root = Path(workspace) / ".vault"
    assert not (root / "objects" / removed.real_object_id).is_file()
    assert not (root / "objects" / removed.decoy_object_id).is_file()
    print(f"  [OK] vault remove (real key) → both blobs deleted")


def test_remove_with_decoy_key(workspace: str):
    """vault remove with decoy password also works."""
    src = Path(workspace) / "todelete.txt"
    src.write_bytes(b"file to be removed by decoy key")
    entry = vault_add(PASS_REAL, str(src), decoy_password=PASS_DECOY)

    removed = vault_remove(PASS_DECOY, "todelete.txt")
    assert removed.name == "todelete.txt"

    root = Path(workspace) / ".vault"
    assert not (root / "objects" / removed.real_object_id).is_file()
    assert not (root / "objects" / removed.decoy_object_id).is_file()
    print(f"  [OK] vault remove (decoy key) → both blobs deleted")


def test_open_removed_file_fails(workspace: str):
    """Opening a removed file raises VaultFileNotFoundError."""
    try:
        vault_open(PASS_REAL, "data.dat", str(Path(workspace) / "nope.dat"))
        assert False, "should have raised VaultFileNotFoundError"
    except VaultFileNotFoundError:
        print(f"  [OK] removed file cannot be opened")


def test_backward_compat_no_decoy(workspace: str):
    """vault init without --decoy still works (single-key mode)."""
    sub = Path(workspace) / "backward_compat"
    sub.mkdir(parents=True)
    prev_cwd = os.getcwd()
    os.chdir(sub)
    try:
        vault_init("simple1234")
        root = sub / ".vault"
        assert root.is_dir()
        assert (root / "master.salt").is_file()
        assert (root / "master.check").is_file()
        assert not (root / "master.decoy").is_file(), "decoy file should not exist"
        assert not _has_decoy(root)

        # Add a file
        src = sub / "plain.txt"
        src.write_bytes(b"Hello, single-key vault!")
        entry = vault_add("simple1234", str(src))
        assert entry.name == "plain.txt"
        assert entry.real_object_id
        assert not entry.decoy_object_id  # no decoy blob

        # Open with real key
        dest = vault_open("simple1234", "plain.txt", str(sub / "out.txt"))
        assert dest.read_bytes() == b"Hello, single-key vault!"

        # Wrong password
        try:
            vault_open("wrong", "plain.txt", str(sub / "out2.txt"))
            assert False
        except VaultPasswordError:
            pass

        # Remove
        vault_remove("simple1234", "plain.txt")
        assert len(vault_list()) == 0
        print(f"  [OK] backward compat: single-key vault works")
    finally:
        os.chdir(prev_cwd)


def test_len_equality_cannot_distinguish(workspace: str):
    """Adversary inspecting manifest cannot distinguish real from decoy by size."""
    src = Path(workspace) / "equal.txt"
    src.write_bytes(b"A" * 500)
    vault_add(PASS_REAL, str(src), decoy_password=PASS_DECOY)

    manifest = _load_manifest(Path(workspace) / ".vault")
    entry = next(e for e in manifest if e.name == "equal.txt")
    assert entry.size == 500
    assert entry.real_salt and entry.decoy_salt
    print(f"  [OK] manifest shows single size=500, dual crypto params opaque")


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------


def run():
    tmpdir = tempfile.mkdtemp(prefix="vault_deniable_")
    orig_cwd = os.getcwd()
    passed = 0
    failed = 0

    try:
        os.chdir(tmpdir)
        print(f"[*] Test workspace: {tmpdir}\n")

        tests = [
            # Phase 1 — initialise with decoy
            ("init with --decoy",              lambda: test_init_with_decoy(tmpdir)),
            # Phase 2 — add files
            ("add .txt file",                  lambda: test_add_text_file(tmpdir)),
            ("add .dat binary file",           lambda: test_add_binary_file(tmpdir)),
            ("add multiple mixed-type files",  lambda: test_add_multiple_files(tmpdir)),
            # Phase 3 — list (no password, identity across keys)
            ("list (no password)",             lambda: test_list_no_password(tmpdir)),
            ("list identity under both keys",  lambda: test_list_identity_under_different_keys(tmpdir)),
            # Phase 4 — open with different keys
            ("open with real key",             lambda: test_open_real_key(tmpdir)),
            ("open with decoy key",            lambda: test_open_decoy_key(tmpdir)),
            ("open decoy binary",              lambda: test_open_decoy_binary(tmpdir)),
            ("open decoy all text files",      lambda: test_open_decoy_text_files_are_plausible(tmpdir)),
            ("open with wrong password",       lambda: test_open_wrong_password(tmpdir)),
            # Phase 5 — remove
            ("remove with real key",           lambda: test_remove_with_real_key(tmpdir)),
            ("remove with decoy key",          lambda: test_remove_with_decoy_key(tmpdir)),
            ("open removed file fails",        lambda: test_open_removed_file_fails(tmpdir)),
            # Phase 6 — backward compat
            ("backward compat",                lambda: test_backward_compat_no_decoy(tmpdir)),
            # Phase 7 — size indistinguishability
            ("manifest size equality",         lambda: test_len_equality_cannot_distinguish(tmpdir)),
        ]

        for label, fn in tests:
            sys.stdout.write(f"[ ] {label} ... ")
            sys.stdout.flush()
            try:
                fn()
                passed += 1
            except Exception as exc:
                failed += 1
                import traceback
                traceback.print_exc()

        print(f"\n{'='*50}")
        print(f"RESULTS: {passed} passed, {failed} failed")
        print(f"{'='*50}")
        return failed == 0

    finally:
        os.chdir(orig_cwd)
        try:
            shutil.rmtree(tmpdir)
        except OSError:
            pass
        print(f"[cleanup] removed {tmpdir}")


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)