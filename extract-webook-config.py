#!/usr/bin/env python3
"""
Load a webook page in Playwright and extract runtime config including apiToken.
"""

import argparse
import json
import os
import sys

from playwright.sync_api import sync_playwright


def load_session(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", required=True)
    parser.add_argument("--url", default="https://webook.com/ar/events/ramy-sabry-jeddah-concert-2026-tickets")
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()

    session = load_session(args.session)
    cookies = session.get("cookies", [])

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=args.headless)
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )
        if cookies:
            fixed = []
            for c in cookies:
                if "sameSite" in c and c["sameSite"] not in ("Strict", "Lax", "None"):
                    del c["sameSite"]
                fixed.append(c)
            context.add_cookies(fixed)

        page = context.new_page()
        page.goto(args.url, wait_until="load", timeout=60000)
        page.wait_for_timeout(8000)

        # Try to extract config from common global variables
        result = page.evaluate("""
            () => {
                const candidates = ['wbk', 'WBK', 'wbkConfig', 'appConfig', 'config', '__WBK__', '__APP_CONFIG__', '__NUXT__', '__NEXT_DATA__'];
                const found = {};
                for (const name of candidates) {
                    if (window[name] !== undefined) {
                        try {
                            found[name] = JSON.parse(JSON.stringify(window[name]));
                        } catch (e) {
                            found[name] = String(window[name]).slice(0, 500);
                        }
                    }
                }
                return found;
            }
        """)

        with open("webook-runtime-config.json", "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        print("Runtime config saved to webook-runtime-config.json")
        print(json.dumps(result, ensure_ascii=False, indent=2)[:2000])

        # Also search for apiToken in page source
        html = page.content()
        import re
        tokens = re.findall(r'apiToken["\']?\s*[:=]\s*["\']([^"\']+)["\']', html)
        print(f"\napiToken strings found in HTML: {tokens}")

        browser.close()


if __name__ == "__main__":
    main()
