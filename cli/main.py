"""CLI entry point for the encrypted file vault with plausible deniability.

Usage::

    python -m cli.main vault init  [-k PASSWORD] [--decoy] [--decoy-key DECOY_PW]
    python -m cli.main vault add   <file> [-k KEY] [--decoy-key DECOY_KEY] [-n name]
    python -m cli.main vault remove <name> [-k KEY]
    python -m cli.main vault list
    python -m cli.main vault open  <name> -o <path> [-k KEY] [--force-decoy]
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

# --- path setup ---------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from storage.vault import (  # noqa: E402
    VaultDecoyRequiredError,
    VaultError,
    VaultFileConflictError,
    VaultFileNotFoundError,
    VaultNotInitializedError,
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
from core.crypto import gen_decoy_data  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _echo(msg: str) -> None:
    """Print a message to stderr so it is visible even when stdout is piped."""
    print(msg, file=sys.stderr)


def _resolve_password(
    cli_value: str | None,
    prompt: str = "Master password: ",
    confirm: bool = False,
) -> str:
    """Return *cli_value* if given, otherwise prompt interactively.

    Args:
        cli_value: Value of ``-k`` / ``--key`` (may be ``None``).
        prompt: Prompt string for interactive input.
        confirm: If ``True``, prompt twice and enforce match.

    Returns:
        The password string.

    Raises:
        SystemExit(1): If confirmation fails or password is too short.
    """
    if cli_value is not None:
        pw = cli_value
    else:
        pw = getpass.getpass(prompt)

    if confirm:
        pw2 = cli_value if cli_value is not None else getpass.getpass(f"Confirm: ")
        if pw != pw2:
            _echo("Error: passwords do not match.")
            raise SystemExit(1)

    if len(pw) < 4:
        _echo("Error: password must be at least 4 characters.")
        raise SystemExit(1)

    return pw


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _cmd_init(args: argparse.Namespace) -> int:
    """Handle ``vault init [--decoy]``."""
    vault_dir = Path.cwd() / ".vault"
    if vault_dir.is_dir():
        _echo(f"Error: Vault already exists at {vault_dir}")
        return 1

    try:
        real_pw = _resolve_password(args.key, "Real master password: ", confirm=True)
    except SystemExit:
        return 1

    decoy_pw = None
    if args.decoy:
        _echo("")
        _echo("--- Decoy (plausible-deniability) password ---")
        _echo("If coerced, entering this password will reveal harmless fake files.")
        try:
            decoy_pw = _resolve_password(
                args.decoy_key, "Decoy password: ", confirm=True,
            )
        except SystemExit:
            return 1
        if decoy_pw == real_pw:
            _echo("Error: decoy password must differ from real master password.")
            return 1

    vault_init(real_pw, decoy_pw)
    if decoy_pw:
        _echo(f"\nVault initialised at {vault_dir}")
        _echo("  Real  password → decrypts original files")
        _echo("  Decoy password → decrypts plausible fake files")
    else:
        _echo(f"\nVault initialised at {vault_dir}")
    return 0


def _cmd_add(args: argparse.Namespace) -> int:
    """Handle ``vault add <file>``."""
    try:
        root = _require_vault()
        has_decoy = _has_decoy(root)

        real_pw = _resolve_password(args.key, "Master password: ")
        decoy_pw = None
        if has_decoy:
            decoy_pw = _resolve_password(args.decoy_key, "Decoy password:  ")

        entry = vault_add(real_pw, args.file, name=args.name, decoy_password=decoy_pw)
        _echo(f"Added '{entry.name}' ({entry.size:,} bytes) → vault")
        return 0
    except VaultNotInitializedError:
        _echo("Error: vault not initialised. Run 'vault init' first.")
        return 1
    except VaultPasswordError:
        _echo("Error: incorrect password.")
        return 1
    except VaultDecoyRequiredError:
        _echo("Error: this vault requires a decoy password. Use --decoy-key.")
        return 1
    except VaultFileConflictError as exc:
        _echo(f"Error: {exc}")
        return 1
    except FileNotFoundError as exc:
        _echo(f"Error: {exc}")
        return 1
    except VaultError as exc:
        _echo(f"Error: {exc}")
        return 1


def _cmd_remove(args: argparse.Namespace) -> int:
    """Handle ``vault remove <name>``."""
    try:
        pw = _resolve_password(args.key)
        entry = vault_remove(pw, args.name)
        _echo(f"Removed '{entry.name}' from vault.")
        return 0
    except VaultNotInitializedError:
        _echo("Error: vault not initialised. Run 'vault init' first.")
        return 1
    except VaultPasswordError:
        _echo("Error: incorrect master password.")
        return 1
    except VaultFileNotFoundError as exc:
        _echo(f"Error: {exc}")
        return 1
    except VaultError as exc:
        _echo(f"Error: {exc}")
        return 1


def _cmd_list(_args: argparse.Namespace) -> int:
    """Handle ``vault list``."""
    entries = vault_list()
    if not entries:
        _echo("Vault is empty.  Add files with: vault add <file>")
        return 0

    # Print formatted table
    header = f"{'Name':<30s} {'Size':>10s}  {'Added':>20s}"
    _echo(header)
    _echo("-" * len(header))
    for e in entries:
        _echo(f"{e.name:<30s} {e.size:>10,}  {e.added:>20s}")
    _echo(f"\n{len(entries)} file(s) in vault.")

    # Indicate deniability support
    try:
        root = _require_vault()
        if _has_decoy(root):
            _echo("(plausible-deniability vault — list output is identical for any key)")
    except VaultError:
        pass

    return 0


def _cmd_open(args: argparse.Namespace) -> int:
    """Handle ``vault open <name> -o <path>``."""
    if args.output is None:
        _echo("Error: -o/--output is required.")
        return 1

    try:
        pw = _resolve_password(args.key)
    except SystemExit:
        return 1

    try:
        dest = vault_open(pw, args.name, args.output)
        _echo(f"Decrypted → {dest}")
        return 0
    except VaultNotInitializedError:
        _echo("Error: vault not initialised. Run 'vault init' first.")
        return 1
    except VaultFileNotFoundError as exc:
        _echo(f"Error: {exc}")
        return 1
    except VaultPasswordError:
        # === friendly error: do NOT crash, try to output decoy data ===
        _echo("")
        _echo("Authentication failed. The password does not match any known key.")
        _echo("")

        # Try to generate decoy data from metadata (no key needed)
        try:
            manifest = _load_manifest(_require_vault())
            entry = next((e for e in manifest if e.name == args.name), None)
            if entry is not None:
                # Generate plausible decoy on-the-fly using file size & suffix
                dummy = b"\x00" * entry.size  # placeholder of correct length
                decoy = gen_decoy_data(dummy, entry.file_suffix)
                dest = Path(args.output).resolve()
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(decoy)
                _echo(
                    f"Note: a file of the expected size ({entry.size:,} bytes) has "
                    f"been written to\n  {dest}\n"
                    f"However, this is NOT the encrypted content — it is "
                    f"randomly-generated filler.\n"
                    f"If you intended to decrypt the real file, please verify "
                    f"your password and try again."
                )
                return 0
        except Exception:
            pass

        _echo("Tip: If this is a plausible-deniability vault, check whether")
        _echo("you are using the real or decoy password.")
        return 1
    except VaultError as exc:
        _echo(f"Error: {exc}")
        return 1


# ---------------------------------------------------------------------------
# Argument parsing (rich help)
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Encrypted File Vault — AES-256-GCM + PBKDF2-HMAC-SHA256",
        epilog="""\
Examples:
  vault init                          Create a new single-key vault
  vault init --decoy                  Create a vault with plausible deniability
  vault add secret.txt                Encrypt and store a file
  vault add secret.txt -n alias       Store under a different logical name
  vault list                          List all stored files
  vault open alias -o ./out.txt       Decrypt and export
  vault remove alias                  Delete a stored file
  vault init -k mypass123             Non-interactive (use with care)

Key routing (deniable vault):
  Real  password → original file
  Decoy password → harmless fake file (same length, plausible content)
  vault list       → identical output regardless of which key was used

Security:
  PBKDF2-HMAC-SHA256  with 600,000 iterations (OWASP 2023)
  AES-256-GCM          authenticated encryption
  HKDF-SHA256          per-file key isolation
""",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    # ---- vault init ---------------------------------------------------------
    p_init = sub.add_parser(
        "init",
        help="Initialise a new encrypted vault",
        description="Create a new .vault/ directory in the current folder. "
                    "Optionally enable plausible deniability with --decoy.",
    )
    p_init.add_argument(
        "-k", "--key", metavar="PASSWORD",
        help="Master password (non-interactive; omit for secure prompt)",
    )
    p_init.add_argument(
        "--decoy", action="store_true",
        help="Enable plausible deniability with a second (decoy) password",
    )
    p_init.add_argument(
        "--decoy-key", metavar="DECOY_PASSWORD",
        help="Decoy password (non-interactive; only valid with --decoy)",
    )

    # ---- vault add ----------------------------------------------------------
    p_add = sub.add_parser(
        "add",
        help="Encrypt a file and store it in the vault",
        description="Read FILE, encrypt it with AES-256-GCM (and optionally a "
                    "decoy copy), then store the ciphertext in .vault/objects/.",
    )
    p_add.add_argument("file", help="Path to the file to encrypt")
    p_add.add_argument(
        "-k", "--key", metavar="PASSWORD",
        help="Master password (non-interactive)",
    )
    p_add.add_argument(
        "--decoy-key", metavar="DECOY_PASSWORD",
        help="Decoy password (required for deniable vaults)",
    )
    p_add.add_argument(
        "-n", "--name", default=None,
        help="Logical name inside the vault (default: filename)",
    )

    # ---- vault remove -------------------------------------------------------
    p_rm = sub.add_parser(
        "remove",
        help="Delete a file from the vault",
        description="Remove NAME from the vault. Both real and decoy ciphertext "
                    "blobs (if any) are deleted. Requires a valid password.",
    )
    p_rm.add_argument("name", help="Logical file name in the vault")
    p_rm.add_argument(
        "-k", "--key", metavar="PASSWORD",
        help="Master/decoy password (non-interactive)",
    )

    # ---- vault list ---------------------------------------------------------
    sub.add_parser(
        "list",
        help="List all files in the vault (no password required)",
        description="Display a table of all stored files. No password is needed. "
                    "The output is identical regardless of which key you hold.",
    )

    # ---- vault open ---------------------------------------------------------
    p_open = sub.add_parser(
        "open",
        help="Decrypt a file and export it",
        description="Decrypt NAME using the supplied password. In a deniable "
                    "vault, the real password decrypts the original file; the "
                    "decoy password decrypts plausible fake data.",
    )
    p_open.add_argument("name", help="Logical file name in the vault")
    p_open.add_argument(
        "-o", "--output", required=True,
        help="Destination path for the decrypted file",
    )
    p_open.add_argument(
        "-k", "--key", metavar="PASSWORD",
        help="Master/decoy password (non-interactive)",
    )
    p_open.add_argument(
        "--force-decoy", action="store_true",
        help="Always output decoy data (for demonstration purposes)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point; returns exit code (0 = success)."""
    parser = _build_parser()

    # Print full help when called with no arguments
    if argv is None:
        argv = sys.argv[1:]
    if not argv or argv[0] in ("--help", "-h", "help"):
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    handlers = {
        "init":   _cmd_init,
        "add":    _cmd_add,
        "remove": _cmd_remove,
        "list":   _cmd_list,
        "open":   _cmd_open,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())