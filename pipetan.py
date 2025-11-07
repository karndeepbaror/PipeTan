#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PipeTan — Interactive Encrypt / Decrypt tool
Developer: Karndeep Baror - Ethical Hacker 
Purpose  : Friendly terminal tool to encrypt and decrypt arbitrary files with AES-GCM-256.
Usage    : python pipetan.py
Depends  : cryptography (required), rich
Notes    : Container format is self-contained and stores header JSON (nonce, salt, mode).
          Keep keys safe. This tool performs local encryption only.
"""

from __future__ import annotations
import os
import sys
import time
import json
import struct
import base64
import getpass
import pathlib
import secrets
import argparse
from typing import Optional, Tuple

# crypto
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
except Exception:
    print("Missing required package 'cryptography'. Install: pip install cryptography")
    sys.exit(1)

# optional UI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.align import Align
    RICH = True
    console = Console()
except Exception:
    RICH = False
    console = None  # type: ignore

# ---- constants ----
MAGIC = b"PTENCv1"
HEADER_LEN_FMT = ">I"
AES_KEY_BYTES = 32
NONCE_BYTES = 12
DEFAULT_PBKDF2_ITERS = 200_000

# ---- helpers ----
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def nowts() -> str:
    from datetime import datetime
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def sanitize_name(n: str) -> str:
    return os.path.basename(n)

def derive_key(passphrase: str, salt: bytes, iterations: int = DEFAULT_PBKDF2_ITERS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode("utf-8"))

# ---- container format ----
def make_header(mode: str, nonce: bytes, salt: Optional[bytes], iters: int, orig_name: str) -> dict:
    return {
        "alg": "AES-GCM-256",
        "mode": mode,
        "nonce": b64(nonce),
        "salt": b64(salt) if salt else "",
        "iterations": iters if salt else 0,
        "orig_name": sanitize_name(orig_name)
    }

def pack_container(header: dict, ciphertext: bytes) -> bytes:
    header_json = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    header_len = struct.pack(HEADER_LEN_FMT, len(header_json))
    return MAGIC + header_len + header_json + ciphertext

def unpack_container(data: bytes) -> Tuple[dict, bytes]:
    if not data.startswith(MAGIC):
        raise ValueError("Not a valid PTENC container (magic mismatch).")
    offset = len(MAGIC)
    (hlen,) = struct.unpack(HEADER_LEN_FMT, data[offset:offset+4])
    offset += 4
    header_json = data[offset: offset + hlen]
    offset += hlen
    header = json.loads(header_json.decode("utf-8"))
    ciphertext = data[offset:]
    return header, ciphertext

# ---- core encrypt / decrypt ----
def encrypt_bytes(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    nonce = secrets.token_bytes(NONCE_BYTES)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ct

def decrypt_bytes(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# ---- UI helpers ----
def print_panel(title: str, body: str):
    if RICH:
        console.print(Panel(Text(body), title=title, expand=False))
    else:
        print(f"--- {title} ---")
        print(body)
        print("-" * 24)

def print_banner():
    header = "PipeTan — Encrypt / Decrypt (Karndeep Baror)"
    if RICH:
        console.print(Panel(Align.center(Text(header, style="bold cyan")), subtitle="AES-GCM / PBKDF2", expand=False))
    else:
        print("="*len(header))
        print(header)
        print("="*len(header))

def progress_simulate(task_text: str, duration: float = 1.2):
    if RICH:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn()) as prog:
            t = prog.add_task(task_text, total=None)
            steps = int(duration / 0.12)
            for _ in range(steps):
                time.sleep(0.12)
            prog.remove_task(t)
    else:
        sys.stdout.write(task_text + " ... ")
        sys.stdout.flush()
        time.sleep(duration)
        print("done")

# ---- high-level flows ----
def do_encrypt_flow():
    print_panel("Step 1 — File to encrypt", "Provide path to the file you want to encrypt.")
    inp = Prompt.ask("Input file path") if RICH else input("Input file path: ").strip()
    inp = inp.strip('"').strip("'")
    if not inp:
        print("No input provided. Aborting.")
        return

    if not os.path.isfile(inp):
        print(f"File not found: {inp}")
        return

    # show options
    print_panel("Encryption Options",
                "1) Key-file mode (recommended) — generates a random key and saves a .key file.\n"
                "2) Passphrase mode — derive key from a passphrase you provide.")
    choice = Prompt.ask("Choose mode", choices=["1","2"], default="1") if RICH else input("Choose mode [1=keyfile,2=passphrase]: ").strip() or "1"

    use_passphrase = (choice.strip() == "2")

    # read plaintext in chunks to simulate progress
    total_bytes = os.path.getsize(inp)
    chunk_sz = 1024 * 1024
    # read all into memory for simplicity (could be streaming)
    with open(inp, "rb") as f:
        data = f.read()

    # derive key
    if use_passphrase:
        # ask passphrase twice
        while True:
            p1 = getpass.getpass("Enter passphrase: ")
            p2 = getpass.getpass("Confirm passphrase: ")
            if p1 != p2:
                print("Passphrases do not match. Try again.")
                continue
            if not p1:
                print("Empty passphrase not allowed.")
                continue
            passphrase = p1
            break
        salt = secrets.token_bytes(16)
        iters = DEFAULT_PBKDF2_ITERS
        progress_simulate("Deriving key from passphrase", 0.9)
        key = derive_key(passphrase, salt, iters)
        keyfile_path = None
    else:
        key = secrets.token_bytes(AES_KEY_BYTES)
        salt = None
        iters = 0
        # decide where to save key
        suggested = str(pathlib.Path(inp).with_suffix(pathlib.Path(inp).suffix + ".key"))
        ask = Confirm.ask(f"Save generated key to '{suggested}'? (recommended)") if RICH else input(f"Save generated key to '{suggested}'? [Y/n]: ").strip().lower() or "y"
        if (RICH and ask) or (not RICH and ask in ("y","yes","")):
            keyfile_path = suggested
            # write binary key and readable base64
            with open(keyfile_path, "wb") as kf:
                kf.write(key)
            with open(keyfile_path + ".b64.txt", "w") as kt:
                kt.write(b64(key))
        else:
            # save automatically next to container later
            keyfile_path = None

    # encrypt
    progress_simulate("Encrypting", 1.4 if total_bytes < 5_000_000 else 2.0)
    nonce, ciphertext = encrypt_bytes(data, key)
    header = make_header("passphrase" if use_passphrase else "keyfile", nonce, salt, iters, os.path.basename(inp))
    container = pack_container(header, ciphertext)
    # write container
    outp = str(pathlib.Path(inp).with_suffix(pathlib.Path(inp).suffix + ".ptenc"))
    if os.path.exists(outp):
        # avoid overwrite: add timestamp
        outp = str(pathlib.Path(inp).with_name(pathlib.Path(inp).stem + f"_{nowts()}") .with_suffix(".ptenc"))
    with open(outp, "wb") as f:
        f.write(container)

    # if keyfile not saved earlier for keyfile mode, save it now
    if not use_passphrase and keyfile_path is None:
        auto = str(pathlib.Path(outp).with_suffix(".key"))
        with open(auto, "wb") as kf:
            kf.write(key)
        with open(auto + ".b64.txt", "w") as kt:
            kt.write(b64(key))
        keyfile_path = auto

    # show results
    msg = f"Encrypted: {outp}\nOriginal: {inp}\nMode: {'passphrase' if use_passphrase else 'keyfile'}"
    if keyfile_path:
        msg += f"\nKey file: {keyfile_path}  (keep this safe)"
    else:
        msg += "\nWARNING: Key file was not saved. That means you must remember your passphrase to decrypt."
    print_panel("Encryption Complete", msg)

    # also show base64 key to user (only for keyfile mode)
    if not use_passphrase:
        kb64 = b64(key)
        if RICH:
            console.print(Panel(Text("Base64 key (copy & store safely):\n" + kb64), title="Key (base64)"))
        else:
            print("Base64 key:", kb64)

def do_decrypt_flow():
    print_panel("Step 1 — Container to decrypt", "Provide path to the .ptenc container file.")
    inp = Prompt.ask("Container path") if RICH else input("Container path: ").strip()
    inp = inp.strip('"').strip("'")
    if not inp or not os.path.isfile(inp):
        print("No such container file.")
        return

    # read header
    try:
        data = open(inp, "rb").read()
        header, ciphertext = unpack_container(data)
    except Exception as e:
        print("Failed to read container:", e)
        return

    mode = header.get("mode", "keyfile")
    nonce = ub64(header.get("nonce"))
    salt_b64 = header.get("salt", "")
    iters = int(header.get("iterations", 0))
    orig_name = header.get("orig_name", "decrypted.output")
    desc = f"Container mode: {mode}\nOriginal filename: {orig_name}\nIterations: {iters}"
    print_panel("Container Info", desc)

    if mode == "passphrase":
        p = getpass.getpass("Enter passphrase: ")
        progress_simulate("Deriving key", 0.9)
        salt = ub64(salt_b64) if salt_b64 else None
        if salt is None:
            print("Missing salt in container; cannot derive key.")
            return
        try:
            key = derive_key(p, salt, iters)
        except Exception as e:
            print("Key derivation failed:", e)
            return
    else:
        # keyfile required
        kpath = Prompt.ask("Provide path to keyfile (binary or base64 txt)") if RICH else input("Keyfile path: ").strip()
        if not kpath or not os.path.isfile(kpath):
            print("Keyfile not found.")
            return
        # read key
        raw = open(kpath, "rb").read()
        if len(raw) == AES_KEY_BYTES:
            key = raw
        else:
            # maybe base64 text
            try:
                key = ub64(raw.decode("ascii").strip())
            except Exception:
                print("Key file invalid length or format.")
                return
            if len(key) != AES_KEY_BYTES:
                print("Decoded key has invalid length.")
                return

    # decrypt
    progress_simulate("Decrypting", 1.4)
    try:
        plaintext = decrypt_bytes(nonce, ciphertext, key)
    except Exception as e:
        print("Decryption failed: probably wrong key/passphrase or corrupted container.")
        return

    # write output file (avoid overwriting)
    outdir = os.path.dirname(inp) or "."
    outpath = os.path.join(outdir, orig_name)
    if os.path.exists(outpath):
        outpath = os.path.join(outdir, pathlib.Path(orig_name).stem + "_decrypted" + pathlib.Path(orig_name).suffix)
    with open(outpath, "wb") as f:
        f.write(plaintext)

    print_panel("Decryption Complete", f"Decrypted file: {outpath}")

def interactive_main():
    print_banner()
    while True:
        menu = Table(show_header=False, box=None) if RICH else None
        if RICH:
            menu.add_column("", justify="left")
            menu.add_row("[cyan]1.[/cyan] Encrypt a file — create a secure container")
            menu.add_row("[cyan]2.[/cyan] Decrypt a container — restore original file")
            menu.add_row("[cyan]3.[/cyan] Exit")
            console.print(menu)
            choice = Prompt.ask("Select option", choices=["1","2","3"], default="1")
        else:
            print("1) Encrypt a file")
            print("2) Decrypt a container")
            print("3) Exit")
            choice = input("Choose [1-3]: ").strip() or "1"

        if choice == "1":
            do_encrypt_flow()
        elif choice == "2":
            do_decrypt_flow()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")

# entry
def main():
    parser = argparse.ArgumentParser(description="PipeTan interactive encrypt/decrypt - Karndeep Baror")
    parser.add_argument("--encrypt", "-e", nargs=1, help="Encrypt file (cli mode)")
    parser.add_argument("--decrypt", "-d", nargs=1, help="Decrypt container (cli mode)")
    parser.add_argument("--no-ui", action="store_true", help="Do not use rich UI even if available")
    args = parser.parse_args()

    if args.no_ui:
        global RICH
        RICH = False

    if args.encrypt:
        # non-interactive: encrypt single file via keyfile mode auto save
        infile = args.encrypt[0]
        if not os.path.isfile(infile):
            print("File not found.")
            return
        # auto keypath next to output
        try:
            # simple wrapper to reuse flows:
            # create key, encrypt
            key = secrets.token_bytes(AES_KEY_BYTES)
            data = open(infile, "rb").read()
            nonce, ct = encrypt_bytes(data, key)
            header = make_header("keyfile", nonce, None, 0, os.path.basename(infile))
            container = pack_container(header, ct)
            outp = str(pathlib.Path(infile).with_suffix(pathlib.Path(infile).suffix + ".ptenc"))
            open(outp, "wb").write(container)
            keypath = pathlib.Path(outp).with_suffix(".key")
            open(keypath, "wb").write(key)
            open(str(keypath)+".b64.txt", "w").write(b64(key))
            print("Encrypted ->", outp)
            print("Key saved ->", keypath)
        except Exception as e:
            print("Error:", e)
    elif args.decrypt:
        infile = args.decrypt[0]
        if not os.path.isfile(infile):
            print("File not found.")
            return
        # direct decrypt in interactive manner
        do_decrypt_flow()
    else:
        try:
            interactive_main()
        except KeyboardInterrupt:
            print("\nCancelled by user.")

if __name__ == "__main__":
    main()
