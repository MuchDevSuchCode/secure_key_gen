#!/usr/bin/env python3
"""
Two-passphrase deterministic key generator for VeraCrypt.

OVERVIEW
========
This tool derives high-entropy key material from TWO independent passphrases.

Workflow:
  1. Prompt for "Passphrase #1" (with confirmation)
  2. Prompt for "Passphrase #2" (with confirmation)
  3. Compute:
       preimage = SHA-512(pass1) || SHA-512(pass2)
  4. Run a KDF (PBKDF2-HMAC-SHA512 by default, or scrypt if requested)
  5. Use the derived bytes in one of several output modes.

OUTPUT MODES
============

  --output-mode full       (default)
      * Outputs a full 256-character hex key (128 bytes of key material).
      * Printed to stdout (or copied with --copy).

  --output-mode veracrypt  (or just use --veracrypt)
      * Outputs the FIRST 64 hexadecimal characters (32 bytes).
      * This matches the maximum VeraCrypt password length (64 chars).
      * Printed to stdout (or copied with --copy).

  --output-mode keyfile --keyfile PATH
      * Writes the raw key bytes directly to a binary file at PATH.
      * Designed for use as a VeraCrypt keyfile.
      * SAME passphrases + SAME KDF options => SAME keyfile contents.
      * Key material is not printed; it only goes to the file.

KDF OPTIONS
===========

  --kdf pbkdf2   (default)
      * Uses PBKDF2-HMAC-SHA512.
      * Tunable with --pbkdf2-iter (default: 600000 iterations).

  --kdf scrypt
      * Uses scrypt (memory-hard).
      * Parameters: --scrypt-n, --scrypt-r, --scrypt-p
      * On constrained systems, large N/r/p may cause "memory limit exceeded".

CLIPBOARD SUPPORT
=================
  --copy
      * Copies the derived key to the system clipboard instead of printing it.
      * Works on:
          - Linux desktop (xclip/xsel if available)
          - macOS (pbcopy)
          - Windows (clip)
          - WSL (clip.exe)
      * Not allowed together with --output-mode keyfile (nothing to copy).

OTHER FLAGS
===========

  --quiet
      * Suppresses banners and extra information; prints ONLY the key
        (or only a success message when using --copy).

  --no-warnings
      * Suppresses safety warnings at startup.

SECURITY NOTES
==============
  - Anyone who learns the passphrases OR the derived key/keyfile can decrypt
    anything protected with it.
  - Passphrase entropy is critical. Use long, non-reused, high-entropy phrases.
  - In keyfile mode, the keyfile is written to disk: store and back it up
    like any other critical secret.
"""

import argparse
import getpass
import hashlib
import math
import sys
import os
import subprocess
import shutil


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_KEY_LEN_BYTES = 128   # 128 bytes → 256 hex chars
DEFAULT_PBKDF2_ITER   = 600_000

# Conservative scrypt defaults; you can override them via CLI
DEFAULT_SCRYPT_N      = 2**14
DEFAULT_SCRYPT_R      = 8
DEFAULT_SCRYPT_P      = 1


# ---------------------------------------------------------------------------
# Entropy estimation and passphrase warnings
# ---------------------------------------------------------------------------

def estimate_passphrase_strength(pw: str) -> float:
    """Extremely rough entropy estimate in bits based on charset and length."""
    if not pw:
        return 0.0

    charspace = 0
    if any("a" <= c <= "z" for c in pw):
        charspace += 26
    if any("A" <= c <= "Z" for c in pw):
        charspace += 26
    if any("0" <= c <= "9" for c in pw):
        charspace += 10
    if any(not c.isalnum() for c in pw):
        charspace += 32
    if charspace == 0:
        charspace = 95  # printable ASCII

    return len(pw) * math.log2(charspace)


def warn_if_weak(passphrase: str, label: str) -> None:
    bits = estimate_passphrase_strength(passphrase)
    if len(passphrase) < 16 or bits < 80:
        print("WARNING:", file=sys.stderr)
        print("  {} appears weak.".format(label), file=sys.stderr)
        print("  Length: {} characters".format(len(passphrase)), file=sys.stderr)
        print("  Estimated entropy: ~{:.1f} bits".format(bits), file=sys.stderr)
        print("  Consider a longer, more random passphrase.\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# Prompting
# ---------------------------------------------------------------------------

def prompt_passphrase(label: str) -> str:
    """Prompt for a passphrase twice, confirm, and warn if weak."""
    while True:
        p1 = getpass.getpass("Enter {}: ".format(label))
        p2 = getpass.getpass("Re-enter {}: ".format(label))

        if p1 != p2:
            print("Passphrases do not match.\n", file=sys.stderr)
            continue

        if not p1:
            print("Passphrase cannot be empty.\n", file=sys.stderr)
            continue

        warn_if_weak(p1, label)
        return p1


# ---------------------------------------------------------------------------
# Preimage construction: SHA-512(pass1) || SHA-512(pass2)
# ---------------------------------------------------------------------------

def _make_preimage(pass1: str, pass2: str) -> bytearray:
    """Hash both passphrases and concatenate into a mutable buffer."""
    h1 = hashlib.sha512(pass1.encode("utf-8")).digest()
    h2 = hashlib.sha512(pass2.encode("utf-8")).digest()

    preimage = bytearray(h1 + h2)

    # Scrub originals (best effort in Python)
    pass1 = pass2 = None
    h1 = h2 = None
    return preimage


# ---------------------------------------------------------------------------
# KDFs
# ---------------------------------------------------------------------------

def derive_key_pbkdf2(pass1: str, pass2: str, iterations: int, key_len_bytes: int) -> bytes:
    """Derive key using PBKDF2-HMAC-SHA512."""
    preimage = _make_preimage(pass1, pass2)

    # Deterministic salt from context + hash(preimage)
    context = b"VC2PBKDF2"
    pre_hash = hashlib.sha512(preimage).digest()
    salt = hashlib.sha512(context + pre_hash).digest()

    key_bytes = hashlib.pbkdf2_hmac(
        "sha512",
        preimage,
        salt,
        iterations,
        dklen=key_len_bytes,
    )

    # Scrub preimage
    for i in range(len(preimage)):
        preimage[i] = 0
    preimage = None

    return key_bytes


def derive_key_scrypt(pass1: str, pass2: str, n: int, r: int, p: int, key_len_bytes: int) -> bytes:
    """Derive key using scrypt. May fail on low-memory or restricted systems."""
    preimage = _make_preimage(pass1, pass2)

    context = b"VC2SCRYPT"
    pre_hash = hashlib.sha512(preimage).digest()
    salt = hashlib.sha512(context + pre_hash).digest()

    try:
        key_bytes = hashlib.scrypt(
            preimage,
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=key_len_bytes,
        )
    except ValueError as e:
        print("ERROR: scrypt key derivation failed.", file=sys.stderr)
        msg = str(e).lower()
        if "memory" in msg:
            print("  Memory limit exceeded or too little available.", file=sys.stderr)
            print("  Try smaller parameters, e.g.: --scrypt-n 4096 --scrypt-r 4 --scrypt-p 1", file=sys.stderr)
        else:
            print("  Details: {}".format(e), file=sys.stderr)
        # Scrub preimage before exiting
        for i in range(len(preimage)):
            preimage[i] = 0
        preimage = None
        raise

    # Scrub preimage
    for i in range(len(preimage)):
        preimage[i] = 0
    preimage = None

    return key_bytes


# ---------------------------------------------------------------------------
# Clipboard handling (Linux, macOS, Windows, WSL)
# ---------------------------------------------------------------------------

def running_under_wsl() -> bool:
    """Detect WSL by inspecting /proc/version."""
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except Exception:
        return False


def copy_to_clipboard(data: str) -> bool:
    """
    Copy text to the system clipboard.

    Supports:
      - WSL (clip.exe)
      - Windows (clip)
      - macOS (pbcopy)
      - Linux desktop (xclip or xsel if installed)

    Returns True on success, False on failure.
    """
    try:
        # WSL: use Windows' clip.exe
        if running_under_wsl():
            p = subprocess.Popen(["clip.exe"], stdin=subprocess.PIPE)
            p.communicate(input=data.encode("utf-8"))
            return p.returncode == 0

        # macOS
        if sys.platform == "darwin":
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(input=data.encode("utf-8"))
            return p.returncode == 0

        # Native Windows (non-WSL)
        if sys.platform.startswith("win"):
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
            p.communicate(input=data.encode("utf-8"))
            return p.returncode == 0

        # Linux / Unix desktop: try xclip
        if shutil.which("xclip"):
            p = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
            p.communicate(input=data.encode("utf-8"))
            return p.returncode == 0

        # Fallback: try xsel
        if shutil.which("xsel"):
            p = subprocess.Popen(["xsel", "--clipboard", "--input"], stdin=subprocess.PIPE)
            p.communicate(input=data.encode("utf-8"))
            return p.returncode == 0

        return False

    except Exception:
        return False


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deterministic two-passphrase key generator for VeraCrypt.",
    )

    # KDF selection
    parser.add_argument(
        "--kdf",
        choices=["pbkdf2", "scrypt"],
        default="pbkdf2",
        help="Which KDF to use (default: pbkdf2).",
    )

    # PBKDF2 options
    parser.add_argument(
        "--pbkdf2-iter",
        type=int,
        default=DEFAULT_PBKDF2_ITER,
        help="PBKDF2 iteration count (default: {}).".format(DEFAULT_PBKDF2_ITER),
    )

    # scrypt options
    parser.add_argument(
        "--scrypt-n",
        type=int,
        default=DEFAULT_SCRYPT_N,
        help="scrypt N parameter (CPU/memory cost, default: {}).".format(DEFAULT_SCRYPT_N),
    )
    parser.add_argument(
        "--scrypt-r",
        type=int,
        default=DEFAULT_SCRYPT_R,
        help="scrypt r parameter (block size, default: {}).".format(DEFAULT_SCRYPT_R),
    )
    parser.add_argument(
        "--scrypt-p",
        type=int,
        default=DEFAULT_SCRYPT_P,
        help="scrypt p parameter (parallelism, default: {}).".format(DEFAULT_SCRYPT_P),
    )

    # Output mode
    parser.add_argument(
        "--output-mode",
        choices=["full", "veracrypt", "keyfile"],
        default="full",
        help="full = 256 hex chars; veracrypt = first 64 hex chars; keyfile = write raw bytes to file.",
    )

    # Shortcut alias for veracrypt output mode
    parser.add_argument(
        "--veracrypt",
        action="store_true",
        help="Shortcut for --output-mode veracrypt.",
    )

    # Keyfile path (used only in keyfile mode)
    parser.add_argument(
        "--keyfile",
        type=str,
        help="Path to write keyfile when using --output-mode keyfile.",
    )

    # Behavior flags
    parser.add_argument(
        "--copy",
        action="store_true",
        help="Copy key to clipboard instead of printing it.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress extra output; print only the key or a success message.",
    )
    parser.add_argument(
        "--no-warnings",
        action="store_true",
        help="Suppress safety warnings.",
    )

    args = parser.parse_args()

    # Map shorthand flag to proper mode
    if args.veracrypt:
        args.output_mode = "veracrypt"

    return args


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # Basic validation
    if args.output_mode == "keyfile" and not args.keyfile:
        print("ERROR: --output-mode keyfile requires --keyfile PATH", file=sys.stderr)
        sys.exit(1)

    if args.output_mode == "keyfile" and args.copy:
        print("ERROR: --copy cannot be used with --output-mode keyfile (nothing to copy).", file=sys.stderr)
        sys.exit(1)

    if not args.no_warnings and not args.quiet:
        print("WARNING: This tool derives sensitive key material.", file=sys.stderr)
        if args.output_mode == "keyfile":
            print("  Keyfile will be written to disk at: {}".format(args.keyfile), file=sys.stderr)
        else:
            print("  Key will be shown on stdout unless --copy is used.", file=sys.stderr)
        print("", file=sys.stderr)

    try:
        # Collect passphrases
        pass1 = prompt_passphrase("Passphrase #1")
        pass2 = prompt_passphrase("Passphrase #2")

        if pass1 == pass2:
            print("WARNING: Passphrase #1 and #2 are identical.\n", file=sys.stderr)

        # Derive key
        if args.kdf == "pbkdf2":
            key_bytes = derive_key_pbkdf2(pass1, pass2, args.pbkdf2_iter, DEFAULT_KEY_LEN_BYTES)
        else:
            key_bytes = derive_key_scrypt(pass1, pass2, args.scrypt_n, args.scrypt_r, args.scrypt_p, DEFAULT_KEY_LEN_BYTES)

        # Drop passphrases ASAP
        pass1 = pass2 = None

        # Handle keyfile mode
        if args.output_mode == "keyfile":
            if os.path.exists(args.keyfile):
                print("ERROR: Keyfile already exists: {}".format(args.keyfile), file=sys.stderr)
                print("       Move or delete it before creating a new one.", file=sys.stderr)
                sys.exit(1)
            try:
                with open(args.keyfile, "wb") as f:
                    f.write(key_bytes)
            except OSError as e:
                print("ERROR: Failed to write keyfile: {}".format(e), file=sys.stderr)
                sys.exit(1)

            if not args.quiet:
                print("Keyfile written to: {}".format(args.keyfile))
                print("Keyfile size: {} bytes".format(len(key_bytes)))
                print("Same passphrases + same KDF settings will recreate this file.", file=sys.stderr)
            return

        # Non-keyfile: hex output
        key_hex = key_bytes.hex()
        if args.output_mode == "veracrypt":
            key_out = key_hex[:64]  # 64 hex chars → 32 bytes
        else:
            key_out = key_hex       # full 256 hex chars

        # If --copy, send to clipboard and do NOT print the key
        if args.copy:
            ok = copy_to_clipboard(key_out)
            if not ok:
                print("ERROR: Failed to copy to clipboard. Install xclip/xsel (Linux) or ensure clipboard tools are available.", file=sys.stderr)
                sys.exit(1)
            if not args.quiet:
                print("Key copied to clipboard. (Not printed.)")
            return

        # Otherwise, print to stdout
        if args.quiet:
            print(key_out)
        else:
            print("\n=== DERIVED KEY ===")
            print(key_out)
            print("===================")

    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        sys.exit(1)
    except ValueError:
        # scrypt failures or other KDF-related issues are already logged
        sys.exit(1)


if __name__ == "__main__":
    main()