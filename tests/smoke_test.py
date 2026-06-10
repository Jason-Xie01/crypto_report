"""Integration smoke test for the vault system.

Run from project root::

    python tests/smoke_test.py

This script performs a complete round-trip:
  1. vault init
  2. vault add  (3 files)
  3. vault list
  4. vault open (decrypt + compare)
  5. vault remove
  6. vault list (verify removal)

All steps are automated — no interactive password prompts.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

# Ensure project root is importable
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Work in a temporary directory so we don't touch the real project
# ---------------------------------------------------------------------------
tmpdir = tempfile.mkdtemp(prefix="vault_smoke_")
orig_cwd = os.getcwd()

try:
    os.chdir(tmpdir)
    print(f"[*] Test workspace: {tmpdir}")

    from storage.vault import (
        vault_init,
        vault_add,
        vault_list,
        vault_open,
        vault_remove,
    )

    PASSWORD = "test1234"

    # ------------------------------------------------------------------
    # 1. Init
    # ------------------------------------------------------------------
    print("[1] vault init ... ", end="", flush=True)
    vault_init(PASSWORD)
    assert Path(".vault").is_dir(), ".vault not created"
    assert Path(".vault/master.salt").is_file(), "master.salt missing"
    assert Path(".vault/master.check").is_file(), "master.check missing"
    assert Path(".vault/manifest.json").is_file(), "manifest.json missing"
    assert Path(".vault/objects").is_dir(), "objects/ missing"
    print("OK")

    # ------------------------------------------------------------------
    # 2. Add files
    # ------------------------------------------------------------------
    # Create test files with known content
    test_files = {}
    for fname, content in [
        ("hello.txt", b"Hello, world!\n"),
        ("numbers.csv", b"1,2,3,4,5\n6,7,8,9,10\n"),
        ("binary.dat", os.urandom(1024)),  # 1 KiB random
    ]:
        path = Path(fname)
        path.write_bytes(content)
        test_files[fname] = content
        print(f"[2] vault add {fname} ... ", end="", flush=True)
        entry = vault_add(PASSWORD, str(path))
        assert entry.name == fname, f"name mismatch: {entry.name}"
        print(f"OK (size={entry.size})")

    # ------------------------------------------------------------------
    # 3. List
    # ------------------------------------------------------------------
    print("[3] vault list ... ", end="", flush=True)
    entries = vault_list()
    assert len(entries) == 3, f"expected 3 entries, got {len(entries)}"
    names = {e.name for e in entries}
    assert names == {"hello.txt", "numbers.csv", "binary.dat"}, f"names={names}"
    print("OK")

    # ------------------------------------------------------------------
    # 4. Decrypt and verify
    # ------------------------------------------------------------------
    for fname, expected in test_files.items():
        out_path = Path(f"decrypted_{fname}")
        print(f"[4] vault open {fname} → {out_path} ... ", end="", flush=True)
        dest = vault_open(PASSWORD, fname, str(out_path))
        actual = dest.read_bytes()
        assert actual == expected, (
            f"decrypt mismatch for {fname}: "
            f"expected {len(expected)} B, got {len(actual)} B"
        )
        print("OK (content verified)")

    # ------------------------------------------------------------------
    # 5. Remove
    # ------------------------------------------------------------------
    print("[5] vault remove hello.txt ... ", end="", flush=True)
    removed = vault_remove(PASSWORD, "hello.txt")
    assert removed.name == "hello.txt"
    entries = vault_list()
    assert len(entries) == 2, f"expected 2 after removal, got {len(entries)}"
    assert "hello.txt" not in {e.name for e in entries}
    print("OK")

    # ------------------------------------------------------------------
    # 6. Verify removed file can't be opened
    # ------------------------------------------------------------------
    print("[6] verify removed file is gone ... ", end="", flush=True)
    try:
        vault_open(PASSWORD, "hello.txt", "should_fail.txt")
        assert False, "Expected VaultFileNotFoundError"
    except Exception as exc:
        assert "not found" in str(exc).lower(), f"unexpected error: {exc}"
    print("OK")

    # ------------------------------------------------------------------
    # Summary (print to stdout so it's always visible)
    # ------------------------------------------------------------------
    print("\n==================================================")
    print("ALL SMOKE TESTS PASSED")
    print("==================================================")

finally:
    # Always restore CWD before removing temp dir (Windows requirement)
    os.chdir(orig_cwd)
    try:
        shutil.rmtree(tmpdir)
    except OSError:
        pass  # Windows may hold file handles briefly
    print(f"[cleanup] removed {tmpdir}")