#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kimiko Single-User Local Booking Bot (Python alternative)

Requires:
  pip install playwright
  playwright install chromium

Run:
  python single-user-bot.py
  EVENT_URL="..." TARGET_SECTION="B5" python single-user-bot.py

Mirrors the logic of single-user-bot.js:
  - one visible browser
  - intercepts SeatCloud WebSocket
  - tries bestAvailable / specific seats / iframe bridge
  - keep-alive until user presses Enter
"""

import asyncio
import json
import os
import re
import sys
import zlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# Optional visual-click fallback (PyAutoGUI)
try:
    import visual_click_helper as vch
except Exception as _vch_exc:
    vch = None

# Playwright is required for this script
try:
    from playwright.async_api import async_playwright, devices
except ImportError as exc:
    print("Playwright not installed. Run:  pip install playwright  &&  playwright install chromium")
    raise SystemExit(1)

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
EMAIL = os.environ.get("EMAIL", "tariqibrahim20@hotmail.com")
PASSWORD = os.environ.get("PASSWORD", "Dd112233@")
EVENT_URL = os.environ.get(
    "EVENT_URL",
    "https://webook.com/ar/sa/jed/music-events/events/this-is-michael-musical-show-jeddah-tickets-2026/book",
)
TARGET_SECTION = (os.environ.get("TARGET_SECTION") or "B5").strip().upper()
# TARGET_SECTIONS overrides TARGET_SECTION and accepts comma-separated sections, e.g. "A4,B5,C3"
TARGET_SECTIONS = os.environ.get("TARGET_SECTIONS", TARGET_SECTION)
TARGET_COUNT = max(1, min(30, int(os.environ.get("TARGET_COUNT", "30"))))
HEADLESS = os.environ.get("HEADLESS", "false").lower() == "true"
KEEP_ALIVE_MS = max(10000, int(os.environ.get("KEEP_ALIVE_MS", "45000")))
MAX_RUNTIME_MINUTES = int(os.environ.get("MAX_RUNTIME_MINUTES", "120"))

# Real-time sniper config
SNIPER_ENABLED = os.environ.get("SNIPER_ENABLED", "true").lower() == "true"
SNIPER_INTERVAL_MS = max(100, int(os.environ.get("SNIPER_INTERVAL_MS", "500")))
SNIPER_BURST_GAP_MS = max(10, int(os.environ.get("SNIPER_BURST_GAP_MS", "50")))
SNIPER_TIMEOUT_MS = max(2000, int(os.environ.get("SNIPER_TIMEOUT_MS", "8000")))
SNIPER_MAX_HELD = max(1, min(30, int(os.environ.get("SNIPER_MAX_HELD", str(TARGET_COUNT)))))

# Visual-click fallback config (PyAutoGUI)
USE_VISUAL_CLICK = os.environ.get("USE_VISUAL_CLICK", "true").lower() == "true"
SECTION_TEMPLATE = os.environ.get("SECTION_TEMPLATE", "section_a4.png")
SEAT_TEMPLATE = os.environ.get("SEAT_TEMPLATE", "seat_empty.png")
VISUAL_CONFIDENCE = float(os.environ.get("VISUAL_CONFIDENCE", "0.8"))
VISUAL_REGION = os.environ.get("VISUAL_REGION")  # "left,top,width,height"

WB_API_BASE = "https://api.webook.com/api/v2"
WB_ORIGIN = "https://webook.com"
WB_API_TOKEN = "e9aac1f2f0b6c07d6be070ed684264278359148d6a582ca65a50934d2"

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs", "single-user")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"bot-py-{datetime.now().strftime('%Y-%m-%d')}-{int(datetime.now().timestamp())}.log")


def log(level: str, message: str, extra=None):
    ts = datetime.now().isoformat()
    extra_str = ""
    if extra is not None:
        try:
            extra_str = " | " + json.dumps(extra, ensure_ascii=False, default=str)
        except Exception:
            extra_str = " | " + str(extra)
    line = f"[{ts}] [{level}] {message}{extra_str}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


async def sleep(ms: float):
    await asyncio.sleep(ms / 1000)


# ------------------------------------------------------------------
# Browser helpers
# ------------------------------------------------------------------
STEALTH_SCRIPT = """
(() => {
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
  Object.defineProperty(navigator, 'mimeTypes', { get: () => [1, 2, 3, 4, 5] });
  Object.defineProperty(navigator, 'languages', { get: () => ['ar-SA', 'ar', 'en-US', 'en'] });
  Object.defineProperty(navigator, 'platform', { get: () => 'iPhone' });
  window.chrome = window.chrome || {};
  window.chrome.runtime = window.chrome.runtime || {};
})();
"""

WS_INTERCEPT_SCRIPT = """
(() => {
  const OrigWS = window.WebSocket;
  window.__chartWS = null;
  window.WebSocket = function(...args) {
    const ws = new OrigWS(...args);
    if ((args[0] || '').includes('seatcloud.com')) window.__chartWS = ws;
    return ws;
  };
  window.WebSocket.prototype = OrigWS.prototype;
  window.WebSocket.CONNECTING = OrigWS.CONNECTING;
  window.WebSocket.OPEN = OrigWS.OPEN;
  window.WebSocket.CLOSING = OrigWS.CLOSING;
  window.WebSocket.CLOSED = OrigWS.CLOSED;
})();
"""

IFRAME_BRIDGE_JS = """
(() => {
  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
  function ensureBridge() {
    let b = document.getElementById('__kimiko_py_bridge');
    if (!b) {
      b = document.createElement('textarea');
      b.id = '__kimiko_py_bridge';
      b.style.display = 'none';
      document.body.appendChild(b);
    }
    return b;
  }
  async function getChart() {
    for (let i = 0; i < 100; i++) {
      const chart = window.chartRender || window.SeatsChart || (window.seatsio && window.seatsio.chart);
      if (chart && typeof chart.selectObjects === 'function') return chart;
      await sleep(100);
    }
    return null;
  }
  async function selectViaChart(labels, clearPrevious) {
    const chart = await getChart();
    if (!chart) return {ok:false, reason:'chart_not_ready'};
    try {
      if (clearPrevious && typeof chart.deselectObjects === 'function') await chart.deselectObjects().catch(()=>{});
      await chart.selectObjects(labels);
      const selected = [];
      try {
        const ss = chart.selectedObjects || (chart.getSelectedObjects && chart.getSelectedObjects());
        if (Array.isArray(ss)) ss.forEach(s => selected.push(s.label || s.id || s));
        else if (ss instanceof Set) Array.from(ss).forEach(s => selected.push(s.label || s.id || s));
      } catch (e) {}
      return {ok:true, selectedLabels: selected};
    } catch (e) {
      return {ok:false, reason: String(e && e.message || e)};
    }
  }
  async function postLabels(labels) {
    const posted = [];
    for (const label of labels) {
      const parts = label.split('-');
      const seat = parts.pop(), row = parts.pop(), section = parts.join('-');
      window.parent.postMessage({
        event: 'onObjectSelected',
        data: [{ id: label, label, objectType: 'Seat', itemType: 'Seat',
                 labels: { section, parent: row, own: seat },
                 sectionLabel: section, rowLabel: row, displayLabel: seat }]
      }, '*');
      posted.push(label);
      await sleep(80);
    }
    return {ok:true, postedLabels: posted};
  }
  async function runSelect(cmd) {
    const labels = (cmd.labels || []).map(String).filter(Boolean);
    if (!labels.length) return {ok:false, reason:'no_labels'};
    const chartRes = await selectViaChart(labels, cmd.clearPrevious !== false);
    const selected = set(chartRes.selectedLabels || []);
    const missing = labels.filter(l => !selected.has(l));
    if (missing.length) {
      const fb = await postLabels(missing);
      return {ok: fb.postedLabels.length > 0,
              selectedLabels: Array.from(selected).concat(fb.postedLabels),
              chartResult: chartRes, fallback: fb};
    }
    return {ok:true, selectedLabels: labels, chartResult: chartRes};
  }
  setInterval(() => {
    const b = ensureBridge();
    const text = b.value || '';
    if (!text || text.startsWith('RESULT:')) return;
    let cmd;
    try { cmd = JSON.parse(text); } catch { b.value = 'RESULT:' + JSON.stringify({ok:false,reason:'parse'}); return; }
    if (!cmd || cmd._processed) return;
    cmd._processed = true;
    runSelect(cmd).then(r => { b.value = 'RESULT:' + JSON.stringify(r); })
      .catch(e => { b.value = 'RESULT:' + JSON.stringify({ok:false,error:String(e)}); });
  }, 200);
})();
"""


def parse_slug(url: str) -> str:
    try:
        u = urlparse(url)
        parts = [p for p in u.path.split("/") if p]
        if "book" in parts:
            return parts[parts.index("book") - 1]
        return parts[-1]
    except Exception:
        return url.strip()


def extract_hold_token(payload) -> str | None:
    if not isinstance(payload, dict):
        return None
    stack = [payload]
    seen = set()
    keys = ("hold_token", "holdToken", "token")
    while stack:
        cur = stack.pop()
        if not isinstance(cur, dict):
            continue
        ident = id(cur)
        if ident in seen:
            continue
        seen.add(ident)
        for key in keys:
            val = cur.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        for v in cur.values():
            if isinstance(v, dict):
                stack.append(v)
    return None


def parse_seat_name(name: str):
    parts = name.split("-")
    if len(parts) < 3:
        return None
    seat = parts.pop()
    row = parts.pop()
    section = "-".join(parts)
    return {"section": section, "row": row, "seat": seat}


def build_candidate_groups(items, section_label: str, target_count: int):
    available = [i["name"] for i in items if i.get("section") == section_label and i.get("availableCount", 0) > 0]
    if not available:
        available = [i["name"] for i in items if i.get("section", "").startswith(section_label) and i.get("availableCount", 0) > 0]
    if len(available) < target_count:
        return []

    def parse_seat(n):
        parts = n.split("-")
        return {"name": n, "row": parts[-2], "seat": int(parts[-1])}

    sorted_available = sorted([parse_seat(n) for n in available], key=lambda x: (x["row"], x["seat"]))
    candidates = []
    by_row = {}
    for s in sorted_available:
        by_row.setdefault(s["row"], []).append(s)
    for row, seats in by_row.items():
        seats = sorted(seats, key=lambda x: x["seat"])
        for i in range(len(seats) - target_count + 1):
            run = seats[i:i + target_count]
            if all(run[j]["seat"] == run[0]["seat"] + j for j in range(target_count)):
                candidates.append([s["name"] for s in run])
    candidates.append([s["name"] for s in sorted_available[:target_count]])
    return candidates


def parse_target_sections(items=None) -> list[str]:
    """Return the explicit list of sections to snipe, from TARGET_SECTIONS."""
    raw = (TARGET_SECTIONS or TARGET_SECTION or "").strip()
    if not raw:
        if items:
            return sorted({i.get("section") for i in items if i.get("section")})
        return []
    sections = []
    for part in raw.split(","):
        part = part.strip().upper()
        if part:
            sections.append(part)
    return sections


class SeatWatcher:
    """Real-time watcher that polls inventory and snipes seats in target sections only."""

    def __init__(self, workspace_key: str, event_key: str, target_sections: list[str], target_count: int):
        self.workspace_key = workspace_key
        self.event_key = event_key
        self.target_sections = target_sections
        self.target_count = target_count
        self.last_available: dict[str, set[str]] = {}
        self.last_poll_ts = 0
        self.poll_counter = 0

    def section_matches(self, section: str) -> bool:
        if not self.target_sections:
            return True
        sec = (section or "").upper()
        for wanted in self.target_sections:
            if sec == wanted or sec.startswith(wanted):
                return True
        return False

    def detect_new_seats(self, items: list[dict]) -> dict[str, list[str]]:
        """Compare current inventory with last snapshot and return newly-free seats per section."""
        current: dict[str, set[str]] = {}
        for it in items:
            section = it.get("section")
            if not section or not self.section_matches(section):
                continue
            if it.get("availableCount", 0) <= 0 and it.get("status") not in ("free", "available"):
                continue
            name = it.get("name") or it.get("label") or it.get("objectId") or it.get("id")
            if not name:
                continue
            current.setdefault(section, set()).add(name)

        new_by_section: dict[str, list[str]] = {}
        for section, names in current.items():
            prev = self.last_available.get(section, set())
            new = sorted(names - prev)
            if new:
                new_by_section[section] = new

        self.last_available = current
        return new_by_section

    def pick_priority_targets(self, items: list[dict], needed: int) -> list[str]:
        """Pick the best contiguous groups from target sections for immediate holds."""
        targets = []
        for section in self.target_sections:
            if len(targets) >= needed:
                break
            groups = build_candidate_groups(items, section, min(needed - len(targets), self.target_count))
            for group in groups[:5]:
                for seat in group:
                    if seat not in targets:
                        targets.append(seat)
                if len(targets) >= needed:
                    break
        return targets[:needed]


async def send_hold_burst(state, object_ids, hold_token, gap_ms=SNIPER_BURST_GAP_MS, timeout_ms=SNIPER_TIMEOUT_MS):
    """Send one hold-object frame per seat for maximum speed and clear ack tracking."""
    if not state["server"] or state["closed"]:
        return []
    wanted = list(dict.fromkeys(object_ids))[:SNIPER_MAX_HELD]
    if not wanted:
        return []
    wanted_set = set(wanted)
    state["queue"].clear()

    for idx, oid in enumerate(wanted):
        payload = {
            "action": "hold-object",
            "objects": [{"objectId": oid}],
            "token": hold_token,
            "tracing_id": f"py_sniper_{int(datetime.now().timestamp()*1000)}_{idx}",
        }
        try:
            state["server"].send(ws_compress(json.dumps(payload)))
        except Exception as e:
            log("WARN", f"Sniper burst send error: {e}")
            break
        if idx < len(wanted) - 1:
            await sleep(gap_ms)

    held = []
    deadline = datetime.now().timestamp() * 1000 + timeout_ms
    while datetime.now().timestamp() * 1000 < deadline and len(held) < len(wanted):
        if not state["queue"]:
            await sleep(30)
            continue
        msg = state["queue"].pop(0)
        data = msg.get("data") or {}
        if isinstance(data.get("objects"), list):
            for o in data["objects"]:
                oid = o if isinstance(o, str) else o.get("objectId")
                if oid and oid in wanted_set and oid not in held:
                    held.append(oid)
        status = data.get("status")
        num_held = data.get("numHeldByCurrentToken", 0)
        if (status in ("reservedByToken", "held") or (status == "free" and num_held > 0)) and data.get("objects"):
            for o in data["objects"]:
                oid = o if isinstance(o, str) else o.get("objectId")
                if oid and oid in wanted_set and oid not in held:
                    held.append(oid)
        err = msg.get("error")
        if err:
            err_str = json.dumps(err).lower()
            if "max" in err_str and "hold" in err_str:
                break
    return held


async def fetch_event_detail(slug: str):
    url = f"{WB_API_BASE}/event-detail/{slug}?lang=ar&visible_in=rs"
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(
            url,
            headers={
                "Accept": "application/json",
                "Origin": WB_ORIGIN,
                "Referer": f"{WB_ORIGIN}/",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "token": WB_API_TOKEN,
            },
        ) as resp:
            if resp.status != 200:
                raise Exception(f"event-detail HTTP {resp.status}")
            return await resp.json()


async def fetch_seatcloud_items(workspace_key: str, event_key: str):
    url = f"https://api.seatcloud.com/api/v2/{workspace_key}/event/{event_key}/items?allocations=NO_CHANNEL&trace_id={int(datetime.now().timestamp()*1000)}&plain=true"
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(
            url,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Accept-Language": "ar-SA,ar;q=0.9",
            },
        ) as resp:
            if resp.status != 200:
                raise Exception(f"SeatCloud items HTTP {resp.status}")
            buf = await resp.read()
            key = event_key.encode("utf-8")
            xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(buf))
            dec = zlib.decompress(xored, 16 + zlib.MAX_WBITS)
            return json.loads(dec.decode("utf-8"))


async def get_hold_token_from_api(slug: str, webook_event_id: str):
    try:
        url = f"{WB_API_BASE}/event-detail/{slug}/hold-token?lang=ar"
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Origin": WB_ORIGIN,
                    "Referer": f"{WB_ORIGIN}/",
                    "token": WB_API_TOKEN,
                },
                json={"event_id": webook_event_id, "lang": "ar"},
            ) as resp:
                if resp.status not in (200, 201):
                    return None
                data = await resp.json()
                return extract_hold_token(data)
    except Exception as e:
        log("WARN", f"API hold-token fallback failed: {e}")
        return None


async def read_hold_token(page, slug: str, webook_event_id: str):
    for frame in page.frames:
        url = frame.url or ""
        try:
            qs = parse_qs(urlparse(url).query)
            for key in ("hold_token", "holdToken", "token"):
                vals = qs.get(key)
                if vals and vals[0]:
                    return {"token": vals[0].strip(), "source": "iframe_url"}
        except Exception:
            pass
        if "seatcloud.com" in url:
            try:
                tok = await frame.evaluate(
                    """() => (window.chartState && window.chartState.holdToken) ||
                             (window.currentChartConfig && window.currentChartConfig.holdToken) || null"""
                )
                if tok:
                    return {"token": tok, "source": "iframe_js"}
            except Exception:
                pass
    try:
        for cookie in await page.context.cookies():
            if cookie.get("name") == "holdToken" and cookie.get("value"):
                return {"token": cookie["value"].strip(), "source": "cookie"}
    except Exception:
        pass
    tok = await get_hold_token_from_api(slug, webook_event_id)
    if tok:
        return {"token": tok, "source": "api"}
    return {"token": None, "source": "none"}


async def find_chart_frame(page):
    if page.is_closed():
        return None
    for pattern in [r"chart\.seatcloud\.com", r"seats\.seatcloud\.com", r"seatcloud\.com"]:
        try:
            frame = page.frame(url=re.compile(pattern))
            if frame:
                return frame
        except Exception:
            pass
    return None


async def is_chart_ready(page):
    frame = await find_chart_frame(page)
    if not frame:
        return False
    try:
        return await frame.evaluate(
            """() => {
                const hasGrecaptcha = !!(window.grecaptcha &&
                    ((window.grecaptcha.enterprise && window.grecaptcha.enterprise.execute) || window.grecaptcha.execute));
                const hasChart = !!(window.chartRender || window.SeatsChart || (window.seatsio && window.seatsio.chart));
                const hasWs = !!(window.__chartWS && window.__chartWS.readyState === WebSocket.OPEN);
                return hasGrecaptcha && (hasChart || hasWs);
            }"""
        )
    except Exception:
        return False


async def get_ticket_count(page):
    try:
        text = await page.evaluate("() => document.body ? document.body.innerText || '' : ''")
        m = re.search(r"(\d+)\s*تذاكر", text)
        return int(m.group(1)) if m else 0
    except Exception:
        return 0


async def safe_screenshot(page, name: str):
    try:
        if page.is_closed():
            return None
        d = os.path.join(LOG_DIR, "screenshots")
        os.makedirs(d, exist_ok=True)
        fp = os.path.join(d, f"{int(datetime.now().timestamp()*1000)}-{name}.png")
        await page.screenshot(path=fp, full_page=False)
        log("SCREENSHOT", f"Saved {fp}")
        return fp
    except Exception as e:
        log("WARN", f"Screenshot failed: {e}")
        return None


async def wait_for_any_selector(page, selectors, timeout_ms=10000, visible=True):
    import time
    start = time.time()
    while (time.time() - start) * 1000 < timeout_ms:
        for sel in selectors:
            try:
                el = await page.query_selector(sel)
                if el:
                    if not visible:
                        return el
                    if await el.is_visible():
                        return el
            except Exception:
                pass
        await sleep(300)
    return None


# ------------------------------------------------------------------
# WebSocket route helpers
# ------------------------------------------------------------------
def ws_decompress(data):
    if isinstance(data, str):
        return data
    try:
        return zlib.decompress(data, -15).decode("utf-8")
    except Exception:
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return None


def ws_compress(text: str) -> bytes:
    return zlib.compressobj(wbits=-15).compress(text.encode("utf-8")) + zlib.compressobj(wbits=-15).flush()


def setup_ws_route(page):
    state = {"server": None, "queue": [], "closed": False, "ready": False, "url": None}

    async def handler(route):
        state["url"] = route.url
        log("WS", "Intercepting SeatCloud WebSocket", {"url": re.sub(r"reCaptchaToken=[^&]+", "reCaptchaToken=***", route.url)})
        server = await route.connect_to_server()
        state["server"] = server
        state["ready"] = True

        def on_msg(message):
            try:
                route.send(message)
            except Exception:
                pass
            text = ws_decompress(message)
            try:
                msg = json.loads(text or "{}")
            except Exception:
                msg = None
            if isinstance(msg, dict) and msg.get("action") == "hold-object":
                state["queue"].append(msg)

        def on_close():
            state["closed"] = True

        server.on_message(on_msg)
        server.on_close(on_close)

    page.route_web_socket(re.compile(r"seatcloud\.com"), handler)
    return state


async def send_hold_via_route(state, object_ids, hold_token, target_count, timeout_ms=15000):
    if not state["server"] or state["closed"]:
        return []
    wanted = list(dict.fromkeys(object_ids))
    wanted_set = set(wanted)
    payload = {
        "action": "hold-object",
        "objects": [{"objectId": oid} for oid in wanted],
        "token": hold_token,
        "tracing_id": f"py_{int(datetime.now().timestamp()*1000)}",
    }
    try:
        state["server"].send(ws_compress(json.dumps(payload)))
    except Exception as e:
        log("WARN", f"WS route send error: {e}")
        return []

    held = []
    deadline = datetime.now().timestamp() * 1000 + timeout_ms
    while datetime.now().timestamp() * 1000 < deadline and len(held) < target_count:
        if not state["queue"]:
            await sleep(50)
            continue
        msg = state["queue"].pop(0)
        data = msg.get("data") or {}
        if isinstance(data.get("objects"), list):
            for o in data["objects"]:
                oid = o if isinstance(o, str) else o.get("objectId")
                if oid and oid in wanted_set and oid not in held:
                    held.append(oid)
        status = data.get("status")
        num_held = data.get("numHeldByCurrentToken", 0)
        if (status == "reservedByToken" or (status == "free" and num_held > 0)) and data.get("objects"):
            for o in data["objects"]:
                oid = o if isinstance(o, str) else o.get("objectId")
                if oid and oid in wanted_set and oid not in held:
                    held.append(oid)
        err = msg.get("error")
        if err:
            err_str = json.dumps(err).lower()
            if "max" in err_str and "hold" in err_str:
                break
    log("HOLD", f"Route hold result: {len(held)}/{target_count}", {"held": held})
    return held


async def send_best_available_via_route(state, count, hold_token, categories=None, timeout_ms=12000):
    if not state["server"] or state["closed"]:
        return []
    payload = {
        "action": "hold-object",
        "bestAvailable": {"number": count, "categories": [str(c) for c in (categories or [])]},
        "token": hold_token,
        "tracing_id": f"py_ba_{int(datetime.now().timestamp()*1000)}",
    }
    try:
        state["server"].send(ws_compress(json.dumps(payload)))
    except Exception as e:
        log("WARN", f"bestAvailable send error: {e}")
        return []

    held = []
    deadline = datetime.now().timestamp() * 1000 + timeout_ms
    while datetime.now().timestamp() * 1000 < deadline and len(held) < count:
        if not state["queue"]:
            await sleep(50)
            continue
        msg = state["queue"].pop(0)
        data = msg.get("data") or {}
        if data.get("status") == "reservedByToken" and data.get("objects"):
            for o in data["objects"]:
                oid = o if isinstance(o, str) else o.get("objectId")
                if oid and oid not in held:
                    held.append(oid)
    log("HOLD", f"bestAvailable result: {len(held)}/{count}", {"held": held})
    return held


async def select_via_iframe_bridge(frame, labels):
    try:
        await frame.evaluate(IFRAME_BRIDGE_JS)
        await sleep(500)
        await frame.evaluate(
            """(cmd) => {
                const b = document.getElementById('__kimiko_py_bridge');
                if (!b) throw new Error('bridge not found');
                b.value = JSON.stringify(cmd);
            }""",
            {"labels": labels, "clearPrevious": True},
        )
        import time
        start = time.time()
        while (time.time() - start) * 1000 < 12000:
            val = await frame.evaluate("() => { const b = document.getElementById('__kimiko_py_bridge'); return b ? b.value : null; }")
            if val and val.startswith("RESULT:"):
                try:
                    return json.loads(val[7:])
                except Exception:
                    return {"ok": False, "reason": "parse_result"}
            await sleep(250)
        return {"ok": False, "reason": "timeout"}
    except Exception as e:
        return {"ok": False, "reason": str(e)}


def parse_visual_region() -> tuple | None:
    if not VISUAL_REGION:
        return None
    try:
        parts = [int(p.strip()) for p in VISUAL_REGION.split(",")]
        if len(parts) == 4:
            return tuple(parts)
    except Exception:
        pass
    return None


async def try_visual_click_fallback(target_count: int) -> dict:
    """
    Fallback that uses PyAutoGUI to click the section template and then seat
    templates on the actual screen. This works for canvas-based charts where
    only real mouse events register a selection.
    """
    if not USE_VISUAL_CLICK:
        return {"ok": False, "reason": "visual_click_disabled"}
    if vch is None:
        return {"ok": False, "reason": "visual_click_helper_not_imported"}
    try:
        vch._check()
    except Exception as e:
        return {"ok": False, "reason": str(e)}

    region = parse_visual_region()
    clicked_seats: list[tuple[int, int]] = []
    section_point = None

    # 1) Click the section label/box (e.g. green A4 box) so the chart zooms in.
    if os.path.isfile(SECTION_TEMPLATE):
        log("VISUAL", f"Looking for section template: {SECTION_TEMPLATE}")
        section_point = vch.click_section(SECTION_TEMPLATE, confidence=VISUAL_CONFIDENCE, region=region)
        if section_point:
            log("VISUAL", f"Clicked section at {section_point}")
            await sleep(1200)
            # Narrow seat search to the area around the section label.
            region = vch.safe_region_around(section_point, width=500, height=500)
        else:
            log("WARN", f"Section template not found on screen: {SECTION_TEMPLATE}")

    # 2) Click empty seats.
    if os.path.isfile(SEAT_TEMPLATE):
        log("VISUAL", f"Looking for seat template: {SEAT_TEMPLATE}")
        clicked_seats = vch.click_seats(
            SEAT_TEMPLATE,
            target_count=target_count,
            confidence=VISUAL_CONFIDENCE,
            region=region,
            interval=0.25,
        )
        log("VISUAL", f"Clicked {len(clicked_seats)} seats", {"points": clicked_seats})
    else:
        log("WARN", f"Seat template not found on disk: {SEAT_TEMPLATE}")

    # Give the UI time to update the cart counter.
    await sleep(1500)
    return {"ok": len(clicked_seats) > 0, "sectionPoint": section_point, "seatPoints": clicked_seats}


async def wait_for_input(prompt_text="Press ENTER to continue..."):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt_text)


# ------------------------------------------------------------------
# Main flow
# ------------------------------------------------------------------
async def run_booking():
    log("START", "Kimiko single-user Python bot starting", {
        "email": EMAIL, "event": EVENT_URL, "section": TARGET_SECTION, "count": TARGET_COUNT,
        "visual_click": USE_VISUAL_CLICK, "section_template": SECTION_TEMPLATE, "seat_template": SEAT_TEMPLATE,
    })

    slug = parse_slug(EVENT_URL)
    log("EVENT", f"Slug: {slug}")

    try:
        data = await fetch_event_detail(slug)
    except Exception as e:
        log("ERROR", f"Cannot fetch event detail: {e}")
        raise

    event_data = data.get("data") or data
    seats_io = event_data.get("seats_io") or {}
    workspace_key = seats_io.get("workspace_key")
    event_key = seats_io.get("event_key")
    webook_event_id = event_data.get("_id")
    if not workspace_key or not event_key:
        raise Exception("Event does not have SeatCloud keys")
    log("EVENT", f"SeatCloud workspace={workspace_key} event={event_key}")

    log("BROWSER", "Launching Chromium (headful, one user)...")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=HEADLESS, args=["--disable-blink-features=AutomationControlled"])
        page = None
        try:
            context = await browser.new_context(
                **devices["iPhone 14 Pro"],
                locale="ar-SA",
                timezone_id="Asia/Riyadh",
                permissions=["geolocation"],
                color_scheme="dark",
                reduced_motion="no-preference",
            )
            await context.add_init_script(STEALTH_SCRIPT)
            await context.add_init_script(WS_INTERCEPT_SCRIPT)
            page = await context.new_page()

            page.on("console", lambda msg: log("BROWSER", f"[{msg.type}] {msg.text}") if msg.type == "error" or "Kimiko" in msg.text else None)
            page.on("pageerror", lambda err: log("BROWSER", f"[pageerror] {err}"))

            route_state = setup_ws_route(page)

            log("NAV", "Navigating to event page")
            await page.goto(EVENT_URL, wait_until="domcontentloaded", timeout=60000)
            await safe_screenshot(page, "event-page")

            for sel in ['button:has-text("قبول الكل")', 'button:has-text("Accept All")']:
                try:
                    el = await page.query_selector(sel)
                    if el and await el.is_visible():
                        await el.click()
                        await sleep(800)
                        break
                except Exception:
                    pass

            log("LOGIN", f"Logging in as {EMAIL}")
            logged_in = False
            try:
                body_text = await page.evaluate("() => document.body ? document.body.innerText || '' : ''")
                logged_in = "حسابي" in body_text or "My Account" in body_text or "الملف الشخصي" in body_text
            except Exception:
                pass
            if logged_in:
                log("LOGIN", "Already logged in")

            for attempt in range(1, 4):
                if logged_in:
                    break
                login_btn = await wait_for_any_selector(page, [
                    'button:has-text("تسجيل الدخول")',
                    'button:has-text("Login")',
                    'a:has-text("تسجيل الدخول")',
                ], 5000)
                if login_btn:
                    try:
                        await login_btn.click()
                    except Exception:
                        pass
                    await sleep(1500)
                email_in = await wait_for_any_selector(page, [
                    'input[data-testid="auth_login_email_input"]',
                    'input[type="email"]',
                    'input[inputmode="email"]',
                ], 7000)
                pass_in = await wait_for_any_selector(page, [
                    'input[data-testid="auth_login_password_input"]',
                    'input[type="password"]',
                ], 7000)
                if email_in and pass_in:
                    await email_in.fill(EMAIL)
                    await sleep(200)
                    await pass_in.fill(PASSWORD)
                    await sleep(200)
                    sub = await wait_for_any_selector(page, [
                        'button[data-testid="auth_login_submit_button"]',
                        'button[type="submit"]',
                        'button:has-text("تسجيل الدخول")',
                    ], 3000)
                    if sub:
                        try:
                            await sub.click()
                        except Exception:
                            pass
                    await sleep(5000)
                    await safe_screenshot(page, "after-login")
                    body_text = await page.evaluate("() => document.body ? document.body.innerText || '' : ''")
                    if "بيانات اعتماد غير صحيحة" in body_text or "كلمة المرور غير صحيحة" in body_text:
                        raise Exception("Invalid credentials")
                    logged_in = True
                else:
                    log("WARN", f"Login form not found, attempt {attempt}/3")
                    await sleep(2000)

            if not logged_in:
                raise Exception("Login failed after retries")

            for txt in ["تحديث", "تخطي", "تطبيق"]:
                try:
                    btn = await page.query_selector(f'button:has-text("{txt}")')
                    if btn and await btn.is_visible():
                        await btn.click()
                        await sleep(800)
                except Exception:
                    pass

            if "/book" not in page.url:
                await page.goto(EVENT_URL, wait_until="domcontentloaded", timeout=60000)

            log("CHART", "Waiting for SeatCloud chart...")
            await page.wait_for_load_state("networkidle", timeout=30000).catch(lambda: None)
            chart_ready = False
            for _ in range(60):
                chart_ready = await is_chart_ready(page)
                if chart_ready:
                    break
                await sleep(1000)
            if not chart_ready:
                await safe_screenshot(page, "chart-not-ready")
                raise Exception("Chart not ready after 60s")
            log("CHART", "Chart ready")
            await safe_screenshot(page, "chart-ready")

            token_info = await read_hold_token(page, slug, webook_event_id)
            if not token_info["token"]:
                raise Exception("Could not obtain hold token")
            hold_token = token_info["token"]
            log("TOKEN", f"Hold token obtained via {token_info['source']}", {"prefix": hold_token[:16]})

            try:
                items = await fetch_seatcloud_items(workspace_key, event_key)
                log("SEATS", f"Fetched {len(items)} items")
            except Exception as e:
                log("WARN", f"Could not fetch items: {e}")
                items = []

            sections_to_try = parse_target_sections(items)
            if not sections_to_try and items:
                sections_to_try = sorted({i.get("section") for i in items if i.get("section")})
            log("SEATS", f"Will try sections: {', '.join(sections_to_try)}")

            watcher = SeatWatcher(workspace_key, event_key, sections_to_try, TARGET_COUNT)

            held = []
            if route_state["ready"]:
                held = await send_best_available_via_route(route_state, TARGET_COUNT, hold_token, [])
                await sleep(1500)

            if len(held) < TARGET_COUNT:
                for section in sections_to_try:
                    if len(held) >= TARGET_COUNT:
                        break
                    candidates = build_candidate_groups(items, section, TARGET_COUNT)
                    if not candidates:
                        continue
                    for group in candidates[:20]:
                        if len(held) >= TARGET_COUNT:
                            break
                        new_held = await send_hold_via_route(route_state, group, hold_token, TARGET_COUNT, 10000)
                        for s in new_held:
                            if s not in held:
                                held.append(s)
                        await sleep(600)

            if len(held) < TARGET_COUNT:
                frame = await find_chart_frame(page)
                if frame:
                    for section in sections_to_try:
                        if len(held) >= TARGET_COUNT:
                            break
                        candidates = build_candidate_groups(items, section, TARGET_COUNT)
                        for group in candidates[:10]:
                            if len(held) >= TARGET_COUNT:
                                break
                            result = await select_via_iframe_bridge(frame, group)
                            log("BRIDGE", "iframe bridge result", result)
                            if result.get("ok") and result.get("selectedLabels"):
                                for s in result["selectedLabels"]:
                                    if s not in held:
                                        held.append(s)
                            await sleep(800)
                            count = await get_ticket_count(page)
                            if count >= TARGET_COUNT:
                                held = held[:TARGET_COUNT]
                                break

            # Last-resort fallback: real mouse clicks via PyAutoGUI image recognition.
            if len(held) < TARGET_COUNT:
                needed = TARGET_COUNT - len(held)
                log("VISUAL", f"Trying PyAutoGUI visual click fallback for {needed} seats...")
                vis_result = await try_visual_click_fallback(needed)
                log("VISUAL", "Visual click result", vis_result)
                await safe_screenshot(page, "after-visual-click")
                if vis_result.get("ok"):
                    # Wait a bit for the cart to update, then read the count.
                    await sleep(2000)
                    vis_count = await get_ticket_count(page)
                    log("VISUAL", f"Cart count after visual clicks: {vis_count}")
                    # We do not know exact seat labels from screen clicks, so we
                    # just mark that visual selection succeeded.
                    if vis_count > 0 and not held:
                        held = [f"visual-{i}" for i in range(vis_count)]

            final_count = await get_ticket_count(page)
            log("RESULT", f"Final cart count: {final_count}, held seats: {len(held)}", {"held": held})
            await safe_screenshot(page, "after-hold")

            if not held:
                log("WARN", "Could not hold any seats. Will keep polling for availability...")

            start_time = datetime.now().timestamp() * 1000
            max_runtime_ms = MAX_RUNTIME_MINUTES * 60 * 1000
            keep_alive_timer = None
            stopped = False
            last_keepalive_ts = start_time

            async def heartbeat():
                nonlocal hold_token, held, keep_alive_timer, stopped, last_keepalive_ts
                if stopped:
                    return
                try:
                    now = datetime.now().timestamp() * 1000
                    elapsed = now - start_time

                    # --- KEEPALIVE: refresh token and re-hold existing seats ---
                    if now - last_keepalive_ts >= KEEP_ALIVE_MS:
                        last_keepalive_ts = now
                        refreshed = await read_hold_token(page, slug, webook_event_id)
                        if refreshed["token"] and refreshed["token"] != hold_token:
                            hold_token = refreshed["token"]
                            log("TOKEN", "Hold token refreshed", {"source": refreshed["source"]})
                        if held and route_state["ready"]:
                            re_held = await send_hold_via_route(route_state, held, hold_token, len(held), 10000)
                            log("KEEPALIVE", f"Re-held {len(re_held)}/{len(held)} seats")

                    # --- REAL-TIME SNIPER: only watch selected sections ---
                    if SNIPER_ENABLED and len(held) < TARGET_COUNT and route_state["ready"]:
                        watcher.poll_counter += 1
                        try:
                            current_items = await fetch_seatcloud_items(workspace_key, event_key)
                        except Exception as e:
                            log("WARN", f"Sniper inventory poll failed: {e}")
                            current_items = []

                        if current_items:
                            new_seats_by_section = watcher.detect_new_seats(current_items)
                            needed = TARGET_COUNT - len(held)
                            sniped: list[str] = []

                            if new_seats_by_section:
                                log("SNIPER", "New free seats detected", {
                                    "sections": list(new_seats_by_section.keys()),
                                    "counts": {k: len(v) for k, v in new_seats_by_section.items()},
                                    "needed": needed,
                                })
                                # Strategy A: contiguous groups from target sections
                                priority_targets = watcher.pick_priority_targets(current_items, needed)
                                if priority_targets:
                                    log("SNIPER", "Sniping priority targets", {"targets": priority_targets})
                                    burst_held = await send_hold_burst(route_state, priority_targets, hold_token)
                                    for s in burst_held:
                                        if s not in held:
                                            held.append(s)
                                            sniped.append(s)

                                # Strategy B: bestAvailable restricted to target sections
                                if len(held) < TARGET_COUNT:
                                    cats = [f"Section {s}" for s in sections_to_try]
                                    ba_needed = TARGET_COUNT - len(held)
                                    ba_held = await send_best_available_via_route(route_state, ba_needed, hold_token, cats, 6000)
                                    for s in ba_held:
                                        if s not in held:
                                            held.append(s)
                                            sniped.append(s)

                                # Strategy C: individual new seats as fallback
                                if len(held) < TARGET_COUNT:
                                    fallback = []
                                    for section, seats in new_seats_by_section.items():
                                        for seat in seats:
                                            if seat not in held and seat not in fallback:
                                                fallback.append(seat)
                                    fallback = fallback[:needed]
                                    if fallback:
                                        log("SNIPER", "Sniping individual new seats", {"targets": fallback})
                                        fb_held = await send_hold_burst(route_state, fallback, hold_token)
                                        for s in fb_held:
                                            if s not in held:
                                                held.append(s)
                                                sniped.append(s)

                            if sniped:
                                log("SNIPER", f"Sniped {len(sniped)} seats", {"sniped": sniped, "total_held": len(held)})
                                await safe_screenshot(page, "after-snipe")
                            elif watcher.poll_counter % 10 == 0:
                                log("SNIPER", f"Watching {len(watcher.target_sections)} sections, held={len(held)}/{TARGET_COUNT}")

                    # Safety refill if cart count dropped
                    count = await get_ticket_count(page)
                    if count < TARGET_COUNT:
                        log("WATCHER", f"Ticket count dropped to {count}, trying to refill...")
                        if route_state["ready"]:
                            cats = [f"Section {s}" for s in sections_to_try]
                            refill = await send_best_available_via_route(route_state, TARGET_COUNT - count, hold_token, cats, 6000)
                            for s in refill:
                                if s not in held:
                                    held.append(s)
                except Exception as e:
                    log("WARN", f"Keepalive/sniper error: {e}")
                if not stopped and datetime.now().timestamp() * 1000 - start_time < max_runtime_ms:
                    keep_alive_timer = asyncio.get_event_loop().call_later(SNIPER_INTERVAL_MS / 1000, lambda: asyncio.create_task(heartbeat()))

            asyncio.create_task(heartbeat())

            log("INFO", "Hold active. Browser will stay open. Press ENTER to proceed to payment, or Ctrl+C to stop.")
            await wait_for_input()

            if stopped:
                return

            if keep_alive_timer:
                keep_alive_timer.cancel()
            log("PAYMENT", "Proceeding to payment...")
            clicked = False
            for sel in ['button:has-text("التالي")', 'button:has-text("Next")', 'button:has-text("متابعة")', 'button:has-text("Continue")', 'button[type="submit"]']:
                try:
                    el = await page.query_selector(sel)
                    if el and await el.is_visible() and await el.is_enabled():
                        await el.click()
                        clicked = True
                        break
                except Exception:
                    pass
            if not clicked:
                log("WARN", "Could not find Next button automatically")
            await page.wait_for_load_state("domcontentloaded", timeout=30000).catch(lambda: None)
            await sleep(3000)
            await safe_screenshot(page, "payment-page")
            log("PAYMENT", f"Payment page URL: {page.url}")
            log("INFO", "Complete payment manually in the browser.")
            await wait_for_input("Press ENTER again after payment (or to exit)...")

        except Exception as e:
            log("ERROR", f"Booking error: {e}")
            await safe_screenshot(page, "error")
            log("INFO", "Browser will remain open for inspection. Press ENTER to close.")
            await wait_for_input()
        finally:
            log("INFO", "Cleanup skipped: browser left open for manual inspection.")
            # Keep browser open


if __name__ == "__main__":
    try:
        asyncio.run(run_booking())
    except KeyboardInterrupt:
        log("STOP", "Interrupted by user")
    except Exception as e:
        log("FATAL", str(e))
        sys.exit(1)
