#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kimiko Combined Strategy Booking Bot
====================================
Runs every seat-selection strategy at the same time (rapid-fire + parallel
probes) instead of trying them one-by-one. Built from the analysis of:

  D:\\webook\\kimiko\\webapp3\\logs\\recording\\rec-*

Key findings from the recordings:
  * The holdToken cookie appears only after the SeatCloud chart iframe loads.
  * The browser opens WSS to api.seatcloud.com:8443 with token=<holdToken>.
  * Frames are raw-deflate compressed (zlib wbits=-15).
  * Real clients send individual "hold-object" frames, one per seat, ~40-80 ms apart.
  * Without patching chart limits, each new hold replaces the previous one
    (numHeldByCurrentToken stays at 1).
  * Server-side truth is GET .../items/held?hold_token=... (not the cart counter).
  * bestAvailable() is not exposed on the chart object in the recorded build,
    so we route it through the intercepted WebSocket.

Strategies used together:
  1. WebSocket bestAvailable (routed, categories restricted to target section).
  2. WebSocket individual hold-object frames for contiguous row groups.
  3. WebSocket individual hold-object frames for scattered fallback seats.
  4. iframe bridge chart.selectObjects (with the `new Set()` bug fixed).
  5. Chart API selectObjects via repeated Section-label clicks.
  6. PyAutoGUI visual-click fallback (optional).

After the burst, the bot verifies what is actually held on the server and
keeps only the verified seats.
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
except Exception:
    vch = None

try:
    from playwright.async_api import async_playwright
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
TARGET_COUNT = max(1, int(os.environ.get("TARGET_COUNT", "30")))
HEADLESS = os.environ.get("HEADLESS", "false").lower() == "true"
FAST_MODE = os.environ.get("FAST_MODE", "true").lower() == "true"
FRAME_GAP_MS = int(os.environ.get("FRAME_GAP_MS", "20" if FAST_MODE else "50"))
KEEP_ALIVE_MS = max(10000, int(os.environ.get("KEEP_ALIVE_MS", "45000")))
MAX_RUNTIME_MINUTES = int(os.environ.get("MAX_RUNTIME_MINUTES", "120"))
AUTO_PROCEED = os.environ.get("AUTO_PROCEED", "false").lower() == "true"

# Real-time sniper config
SNIPER_ENABLED = os.environ.get("SNIPER_ENABLED", "true").lower() == "true"
SNIPER_INTERVAL_MS = max(100, int(os.environ.get("SNIPER_INTERVAL_MS", "500")))
SNIPER_BURST_GAP_MS = max(10, int(os.environ.get("SNIPER_BURST_GAP_MS", "50")))
SNIPER_TIMEOUT_MS = max(2000, int(os.environ.get("SNIPER_TIMEOUT_MS", "8000")))
SNIPER_MAX_HELD = max(1, min(30, int(os.environ.get("SNIPER_MAX_HELD", str(TARGET_COUNT)))))

USE_VISUAL_CLICK = os.environ.get("USE_VISUAL_CLICK", "true").lower() == "true"
SECTION_TEMPLATE = os.environ.get("SECTION_TEMPLATE", "section_a4.png")
SEAT_TEMPLATE = os.environ.get("SEAT_TEMPLATE", "seat_empty.png")
VISUAL_CONFIDENCE = float(os.environ.get("VISUAL_CONFIDENCE", "0.8"))
VISUAL_REGION = os.environ.get("VISUAL_REGION")  # "left,top,width,height"

WB_API_BASE = "https://api.webook.com/api/v2"
WB_ORIGIN = "https://webook.com"
WB_API_TOKEN = "e9aac1f2f0b6c07d6be070ed684264278359148d6a582ca65a50934d2"

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs", "all-strategies")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"bot-all-{datetime.now().strftime('%Y-%m-%d')}-{int(datetime.now().timestamp())}.log")


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

# Load the standalone constructor hook that removes the 5-seat front-end cap.
_CHART_PATCH_PATH = os.path.join(os.path.dirname(__file__), "chart-limit-patch.js")
_CHART_PATCH_SCRIPT = ""
try:
    with open(_CHART_PATCH_PATH, "r", encoding="utf-8") as _fh:
        _CHART_PATCH_SCRIPT = _fh.read()
except Exception as _e:
    log("WARN", f"Could not load chart-limit-patch.js: {_e}")

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
    const selected = new Set(chartRes.selectedLabels || []);  // FIXED: was `set(...)`
    const missing = labels.filter(l => !selected.has(l));
    if (missing.length) {
      const fb = await postLabels(missing);
      return {ok: fb.postLabels.length > 0,
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

LIMIT_PATCH_JS = """
(() => {
  const set100 = (obj, keys) => {
    if (!obj) return;
    for (const key of keys) {
      if (typeof obj[key] === 'number') obj[key] = 100;
      if (typeof obj[key] === 'string') obj[key] = '100';
    }
  };
  const keys = ['maxNumberOfHolds','maxSelectedObjects','maxNumberOfSelectedObjects','maxObjects','maxSeats','selectionLimit','holdLimit','maxHold','maxSelection','maxPerOrder','max_per_order','maxTickets','maxTicketCount','ticketLimit','purchaseLimit'];
  set100(window.chartState, keys);
  set100(window.currentChartConfig, keys);
  if (window.chartRender) {
    set100(window.chartRender.state, keys);
    set100(window.chartRender.config, keys);
    if (window.chartRender._config) set100(window.chartRender._config, keys);
    if (window.chartRender.options) set100(window.chartRender.options, keys);
  }
  if (window.chart) {
    set100(window.chart.state, keys);
    set100(window.chart.config, keys);
    if (window.chart._config) set100(window.chart._config, keys);
    if (window.chart.options) set100(window.chart.options, keys);
  }
  if (window.seatsio && window.seatsio.config) set100(window.seatsio.config, keys);
  if (window.seatsioConfig) set100(window.seatsioConfig, keys);
  try {
    const chart = window.chart || window.chartRender;
    if (chart && chart.state) {
      if (!chart.state.selectedObjects) chart.state.selectedObjects = [];
      if (chart.state._selectionCount) chart.state._selectionCount = 0;
      if (chart.state._holdCount) chart.state._holdCount = 0;
    }
  } catch (e) {}
  return true;
})();
"""


async def safe_screenshot(page, name):
    try:
        if not page or page.is_closed():
            return None
        p = os.path.join(LOG_DIR, f"{int(datetime.now().timestamp()*1000)}-{name}.png")
        await page.screenshot(path=p, full_page=False)
        log("SCREENSHOT", f"Saved {p}")
        return p
    except Exception as e:
        log("WARN", f"Screenshot failed: {e}")
        return None


async def wait_for_any_selector(page, selectors, timeout_ms=10000, visible=True):
    start = datetime.now().timestamp() * 1000
    while datetime.now().timestamp() * 1000 - start < timeout_ms:
        for sel in selectors:
            try:
                el = await page.query_selector(sel)
                if not el:
                    continue
                if visible:
                    if await el.is_visible():
                        return el
                else:
                    return el
            except Exception:
                pass
        await sleep(300)
    return None


async def find_chart_frame(page):
    patterns = [re.compile(r"chart\.seatcloud\.com"), re.compile(r"seats\.seatcloud\.com"), re.compile(r"seatcloud\.com")]
    for frame in page.frames:
        url = frame.url
        if any(p.search(url) for p in patterns):
            return frame
    for iframe in await page.locator("iframe").all():
        try:
            frame = await iframe.content_frame()
            if frame and any(p.search(frame.url) for p in patterns):
                return frame
        except Exception:
            pass
    return None


async def is_chart_ready(page):
    frame = await find_chart_frame(page)
    if not frame:
        return False
    try:
        info = await frame.evaluate("""() => ({
          hasChart: !!(window.chartRender || window.SeatsChart || (window.seatsio && window.seatsio.chart)),
          hasWs: !!(window.__chartWS && window.__chartWS.readyState === WebSocket.OPEN),
          hasSvg: !!document.querySelector('svg'),
          hasCanvas: !!document.querySelector('canvas'),
          holdToken: window.chartState?.holdToken || window.currentChartConfig?.holdToken || null
        })""")
        log("CHART-CHECK", f"frame info: {json.dumps(info, default=str)}")
        return info.get("hasChart") or info.get("hasWs") or info.get("hasSvg") or info.get("hasCanvas")
    except Exception as e:
        log("WARN", f"chart ready check error: {e}")
        return False


# ------------------------------------------------------------------
# Event / seat helpers
# ------------------------------------------------------------------
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


async def fetch_event_detail(slug: str, page=None):
    url = f"{WB_API_BASE}/event-detail/{slug}?lang=ar&visible_in=rs"
    # Try through the browser first: it has the real cookies and anti-bot tokens.
    if page:
        try:
            result = await page.evaluate(
                """async (apiUrl) => {
                    try {
                        const resp = await fetch(apiUrl, { credentials: 'include', headers: { 'Accept': 'application/json' } });
                        const text = await resp.text();
                        return { ok: resp.ok, status: resp.status, text };
                    } catch (e) {
                        return { ok: false, error: String(e && e.message || e) };
                    }
                }""",
                url,
            )
            if result and result.get("ok"):
                return json.loads(result["text"])
            log("WARN", f"Browser event-detail returned {result.get('status') if result else 'none'}, falling back to direct fetch")
        except Exception as e:
            log("WARN", f"Browser event-detail fetch failed: {e}")

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


def extract_seatcloud_keys(url: str) -> dict:
    """Pull workspaceKey / event out of a SeatCloud iframe or WebSocket URL."""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        return {
            "workspace_key": qs.get("workspaceKey", [None])[0] or qs.get("workspace_key", [None])[0],
            "event_key": qs.get("event", [None])[0] or qs.get("eventKey", [None])[0] or qs.get("event_key", [None])[0],
        }
    except Exception:
        return {"workspace_key": None, "event_key": None}


async def fetch_seatcloud_items(workspace_key: str, event_key: str):
    url = f"https://api.seatcloud.com/api/v2/{workspace_key}/event/{event_key}/items?allocations=NO_CHANNEL&trace_id={int(datetime.now().timestamp()*1000)}&plain=true"
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(
            url,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Origin": WB_ORIGIN,
                "Referer": f"{WB_ORIGIN}/",
            },
        ) as resp:
            if resp.status != 200:
                raise Exception(f"items HTTP {resp.status}")
            buf = await resp.read()
            key = event_key.encode("utf-8")
            try:
                xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(buf))
                dec = zlib.decompress(xored)
                return json.loads(dec.decode("utf-8"))
            except Exception:
                try:
                    return json.loads(buf.decode("utf-8"))
                except Exception:
                    return []


async def fetch_held_items(workspace_key: str, event_key: str, hold_token: str):
    url = f"https://api.seatcloud.com/api/v2/{workspace_key}/event/{event_key}/items/held?hold_token={hold_token}&trace_id={int(datetime.now().timestamp()*1000)}&plain=true"
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(
            url,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Origin": WB_ORIGIN,
                "Referer": f"{WB_ORIGIN}/",
            },
        ) as resp:
            if resp.status != 200:
                log("WARN", f"items/held HTTP {resp.status}")
                return []
            buf = await resp.read()
            key = event_key.encode("utf-8")
            try:
                xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(buf))
                dec = zlib.decompress(xored)
                data = json.loads(dec.decode("utf-8"))
            except Exception:
                try:
                    data = json.loads(buf.decode("utf-8"))
                except Exception:
                    return []
            if isinstance(data, dict):
                data = data.get("items", data.get("objects", data.get("data", [])))
            return [it.get("label") or it.get("name") or it.get("objectId") or it.get("id") for it in data if isinstance(it, dict)]


def build_candidate_groups(items, section_label: str, target_count: int):
    available = [i for i in items if i.get("section") == section_label and i.get("availableCount", 0) > 0]
    if not available:
        available = [i for i in items if i.get("section", "").startswith(section_label) and i.get("availableCount", 0) > 0]
    if len(available) < target_count:
        return []

    def parse_seat(item):
        name = item["name"]
        parts = name.split("-")
        return {"name": name, "row": parts[-2], "seat": int(parts[-1])}

    sorted_available = sorted([parse_seat(i) for i in available], key=lambda x: (x["row"], x["seat"]))
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



async def read_hold_token(page, slug: str, webook_event_id: str):
    frame = await find_chart_frame(page)
    if frame:
        try:
            url = frame.url
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for key in ("hold_token", "holdToken", "token"):
                v = qs.get(key, [None])[0]
                if v:
                    return {"token": v, "source": "iframe_url"}
        except Exception:
            pass
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
        cookies = await page.context().cookies()
        for c in cookies:
            if c.get("name") == "holdToken" and c.get("value"):
                return {"token": c["value"], "source": "cookie"}
    except Exception:
        pass
    if slug and webook_event_id:
        try:
            import aiohttp
            url = f"{WB_API_BASE}/event-detail/{slug}/hold-token?lang=ar"
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
                    data = await resp.json()
                    tok = extract_hold_token(data)
                    if tok:
                        return {"token": tok, "source": "api"}
        except Exception as e:
            log("WARN", f"API hold-token fallback failed: {e}")
    return {"token": None, "source": "none"}


async def get_ticket_count(page):
    try:
        return await page.evaluate("""() => {
          const text = document.body ? document.body.innerText || '' : '';
          const patterns = [/(\\d+)\\s*تذاكر/, /(\\d+)\\s*تذكرة/, /(\\d+)\\s*tickets/i, /(\\d+)\\s*ticket/i];
          for (const p of patterns) { const m = text.match(p); if (m) return parseInt(m[1], 10); }
          return 0;
        }""")
    except Exception:
        return 0


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
    if not wanted:
        return []
    wanted_set = set(wanted)

    # Clear stale queue messages so we only read responses from this burst.
    state["queue"].clear()

    held = []
    # Send one seat per frame, matching the real browser (recording shows ~40-80 ms gap).
    # In fast mode we tighten the gap to FRAME_GAP_MS to hit 30 seats in <10s.
    for idx, oid in enumerate(wanted):
        payload = {
            "action": "hold-object",
            "objects": [{"objectId": oid}],
            "token": hold_token,
            "tracing_id": f"py_{int(datetime.now().timestamp()*1000)}_{idx}",
        }
        try:
            state["server"].send(ws_compress(json.dumps(payload)))
        except Exception as e:
            log("WARN", f"WS route send error: {e}")
            break
        await sleep(FRAME_GAP_MS)

    deadline = datetime.now().timestamp() * 1000 + timeout_ms
    while datetime.now().timestamp() * 1000 < deadline and len(held) < len(wanted):
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
        if (status == "reservedByToken" or status == "held" or (status == "free" and num_held > 0)) and data.get("objects"):
            for o in data["objects"]:
                oid = o if isinstance(o, str) else o.get("objectId")
                if oid and oid in wanted_set and oid not in held:
                    held.append(oid)

        err = msg.get("error")
        if err:
            err_str = json.dumps(err).lower()
            if "max" in err_str and "hold" in err_str:
                break

    log("HOLD", f"Route hold result: {len(held)}/{len(wanted)}", {"held": held})
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
        if (data.get("status") in ("reservedByToken", "held") or data.get("numHeldByCurrentToken", 0) > 0) and data.get("objects"):
            for o in data["objects"]:
                oid = o if isinstance(o, str) else o.get("objectId")
                if oid and oid not in held:
                    held.append(oid)
    log("HOLD", f"bestAvailable result: {len(held)}/{count}", {"held": held})
    return held


# ------------------------------------------------------------------
# iframe bridge and chart API
# ------------------------------------------------------------------
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
            val = await frame.evaluate(
                "() => { const b = document.getElementById('__kimiko_py_bridge'); return b ? b.value : null; }"
            )
            if val and val.startswith("RESULT:"):
                try:
                    return json.loads(val[7:])
                except Exception:
                    return {"ok": False, "reason": "parse_result"}
            await sleep(250)
        return {"ok": False, "reason": "timeout"}
    except Exception as e:
        return {"ok": False, "reason": str(e)}


async def select_via_chart_api(frame, section_label: str, target_count: int):
    """Strategy used by ahlam-a4-bot.js: click the section label via chart.selectObjects repeatedly."""
    if not frame:
        return {"ok": False, "reason": "no_frame"}
    full_label = section_label if section_label.startswith("Section ") else f"Section {section_label}"
    try:
        await frame.evaluate("""() => {
          const chart = window.chartRender || window.chart;
          if (chart && typeof chart.clearSelection === 'function') chart.clearSelection();
        }""")
        await sleep(500)
        attempts = []
        for i in range(target_count):
            res = await frame.evaluate(
                """(lbl) => {
                  const chart = window.chartRender || window.chart;
                  if (!chart || typeof chart.selectObjects !== 'function') return { noChart: true };
                  try { chart.selectObjects([lbl]); return { ok: true }; }
                  catch (e) { return { ok: false, error: e.message }; }
                }""",
                full_label,
            )
            attempts.append(res)
            if res.get("noChart"):
                return {"ok": False, "reason": "chart_not_ready", "attempts": attempts}
            await sleep(300)
        await sleep(1000)
        return {"ok": True, "attempts": attempts}
    except Exception as e:
        return {"ok": False, "reason": str(e)}


# ------------------------------------------------------------------
# Visual click fallback
# ------------------------------------------------------------------
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
    if not USE_VISUAL_CLICK:
        return {"ok": False, "reason": "visual_click_disabled"}
    if vch is None:
        return {"ok": False, "reason": "visual_click_helper_not_imported"}
    try:
        vch._check()
    except Exception as e:
        return {"ok": False, "reason": str(e)}

    region = parse_visual_region()
    clicked_seats = []
    section_point = None

    if os.path.isfile(SECTION_TEMPLATE):
        log("VISUAL", f"Looking for section template: {SECTION_TEMPLATE}")
        section_point = vch.click_section(SECTION_TEMPLATE, confidence=VISUAL_CONFIDENCE, region=region)
        if section_point:
            log("VISUAL", f"Clicked section at {section_point}")
            await sleep(1200)
            region = vch.safe_region_around(section_point, width=500, height=500)
        else:
            log("WARN", f"Section template not found on screen: {SECTION_TEMPLATE}")

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

    await sleep(1500)
    return {"ok": len(clicked_seats) > 0, "sectionPoint": section_point, "seatPoints": clicked_seats}


# ------------------------------------------------------------------
# Strategy orchestra: run everything together
# ------------------------------------------------------------------
async def run_ws_bestavailable(route_state, hold_token, section, target_count):
    """Strategy 1: bestAvailable routed through intercepted WebSocket."""
    if not route_state["ready"]:
        return []
    cats = [f"Section {section}"] if section else []
    held = await send_best_available_via_route(route_state, target_count, hold_token, cats)
    log("STRATEGY", f"WS bestAvailable done: {len(held)}", {"strategy": "ws_bestavailable", "held": held})
    return held


async def run_ws_group_holds(route_state, hold_token, candidate_groups, already_held: set, target_count):
    """Strategy 2: send individual hold-object frames for candidate groups."""
    if not route_state["ready"]:
        return []
    held = []
    for group in candidate_groups[:10]:
        if len(held) + len(already_held) >= target_count:
            break
        new = await send_hold_via_route(route_state, group, hold_token, target_count, 10000)
        for s in new:
            if s not in held and s not in already_held:
                held.append(s)
        await sleep(400)
    log("STRATEGY", f"WS group holds done: {len(held)}", {"strategy": "ws_group_holds", "held": held})
    return held


async def run_iframe_bridge(frame, candidate_groups, already_held: set, target_count):
    """Strategy 3: iframe bridge with chart.selectObjects."""
    if not frame:
        return []
    held = []
    for group in candidate_groups[:8]:
        if len(held) + len(already_held) >= target_count:
            break
        result = await select_via_iframe_bridge(frame, group)
        log("BRIDGE", "iframe bridge result", result)
        if result.get("ok") and result.get("selectedLabels"):
            for s in result["selectedLabels"]:
                if s not in held and s not in already_held:
                    held.append(s)
        await sleep(600)
    log("STRATEGY", f"iframe bridge done: {len(held)}", {"strategy": "iframe_bridge", "held": held})
    return held


async def run_chart_api(frame, section, target_count):
    """Strategy 4: chart API selectObjects via repeated Section-label clicks."""
    if not frame:
        return []
    result = await select_via_chart_api(frame, section, target_count)
    log("CHART-API", "chart API result", result)
    # Labels cannot be read directly from this strategy; verification is required.
    return []


async def run_visual_fallback(target_count):
    """Strategy 5: PyAutoGUI visual click fallback."""
    result = await try_visual_click_fallback(target_count)
    log("VISUAL", "Visual fallback result", result)
    if result.get("ok"):
        return [f"visual-{i}" for i in range(len(result.get("seatPoints", [])))]
    return []


async def fast_burst_hold(route_state, hold_token, object_ids, target_count):
    """Send a rapid burst of individual hold-object frames and collect acks."""
    if not route_state["ready"]:
        return []
    wanted = list(dict.fromkeys(object_ids))[:target_count]
    if not wanted:
        return []
    wanted_set = set(wanted)
    route_state["queue"].clear()

    t0 = datetime.now().timestamp() * 1000
    for idx, oid in enumerate(wanted):
        payload = {
            "action": "hold-object",
            "objects": [{"objectId": oid}],
            "token": hold_token,
            "tracing_id": f"py_{int(t0)}_{idx}",
        }
        try:
            route_state["server"].send(ws_compress(json.dumps(payload)))
        except Exception as e:
            log("WARN", f"WS burst send error: {e}")
            break
        await sleep(FRAME_GAP_MS)
    log("BURST", f"Sent {len(wanted)} hold-object frames in {int(datetime.now().timestamp()*1000 - t0)}ms")

    held = []
    deadline = datetime.now().timestamp() * 1000 + 5000
    while datetime.now().timestamp() * 1000 < deadline and len(held) < len(wanted):
        if not route_state["queue"]:
            await sleep(30)
            continue
        msg = route_state["queue"].pop(0)
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


async def send_hold_burst(route_state, object_ids, hold_token, gap_ms=SNIPER_BURST_GAP_MS, timeout_ms=SNIPER_TIMEOUT_MS):
    """Sniper variant: send one hold-object frame per seat with tight ack tracking."""
    if not route_state["ready"]:
        return []
    wanted = list(dict.fromkeys(object_ids))[:SNIPER_MAX_HELD]
    if not wanted:
        return []
    wanted_set = set(wanted)
    route_state["queue"].clear()

    for idx, oid in enumerate(wanted):
        payload = {
            "action": "hold-object",
            "objects": [{"objectId": oid}],
            "token": hold_token,
            "tracing_id": f"py_sniper_{int(datetime.now().timestamp()*1000)}_{idx}",
        }
        try:
            route_state["server"].send(ws_compress(json.dumps(payload)))
        except Exception as e:
            log("WARN", f"Sniper burst send error: {e}")
            break
        if idx < len(wanted) - 1:
            await sleep(gap_ms)

    held = []
    deadline = datetime.now().timestamp() * 1000 + timeout_ms
    while datetime.now().timestamp() * 1000 < deadline and len(held) < len(wanted):
        if not route_state["queue"]:
            await sleep(30)
            continue
        msg = route_state["queue"].pop(0)
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


async def orchestrate_strategies(page, route_state, hold_token, items, workspace_key, event_key):
    """Run every strategy in a tight burst and verify against the server."""
    sections_to_try = parse_target_sections(items)
    if not sections_to_try and items:
        sections_to_try = sorted({i.get("section") for i in items if i.get("section")})
    log("ORCHESTRATE", f"Target sections: {sections_to_try}, fast_mode={FAST_MODE}, frame_gap={FRAME_GAP_MS}ms")

    # Patch limits in parent page context (intercepts seatsio.SeatingChart constructor).
    if _CHART_PATCH_SCRIPT:
        try:
            await page.evaluate(_CHART_PATCH_SCRIPT)
            log("LIMITS", "Injected chart-limit-patch.js into parent page")
        except Exception as e:
            log("WARN", f"Could not inject chart-limit-patch.js into parent: {e}")

    frame = await find_chart_frame(page)
    if frame:
        try:
            await frame.evaluate(LIMIT_PATCH_JS)
            log("LIMITS", "Patched chart limits to 100")
        except Exception as e:
            log("WARN", f"Could not patch chart limits: {e}")
        if _CHART_PATCH_SCRIPT:
            try:
                await frame.evaluate(_CHART_PATCH_SCRIPT)
                log("LIMITS", "Injected chart-limit-patch.js into iframe")
            except Exception as e:
                log("WARN", f"Could not inject chart-limit-patch.js into iframe: {e}")
    await sleep(100)

    all_held = []

    for section in sections_to_try:
        if len(all_held) >= TARGET_COUNT:
            break
        log("SECTION", f"Trying section {section}")
        candidates = build_candidate_groups(items, section, TARGET_COUNT)
        if not candidates:
            log("SECTION", f"No candidate groups for {section}")
            continue

        # --- Phase 1: fastest path, individual hold-object frames (matches recording) ---
        t_start = datetime.now().timestamp() * 1000
        flat_seats = []
        for group in candidates[:5]:
            for s in group:
                if s not in flat_seats:
                    flat_seats.append(s)
        burst_held = await fast_burst_hold(route_state, hold_token, flat_seats, TARGET_COUNT)
        for s in burst_held:
            if s not in all_held:
                all_held.append(s)
        log("PHASE1", f"Individual burst: {len(burst_held)} seats in {int(datetime.now().timestamp()*1000 - t_start)}ms")

        # Verify immediately; this is the only truth.
        verified = await fetch_held_items(workspace_key, event_key, hold_token)
        log("VERIFY", f"Server reports {len(verified)} held seats", {"verified": verified})
        if verified:
            all_held = [s for s in verified if s]

        # --- Phase 2: bestAvailable fallback (still under 10s budget) ---
        if len(all_held) < TARGET_COUNT:
            t_start = datetime.now().timestamp() * 1000
            cats = [f"Section {section}"]
            ba_held = await send_best_available_via_route(route_state, TARGET_COUNT - len(all_held), hold_token, cats, 5000)
            for s in ba_held:
                if s not in all_held:
                    all_held.append(s)
            log("PHASE2", f"bestAvailable: {len(ba_held)} seats in {int(datetime.now().timestamp()*1000 - t_start)}ms")
            verified = await fetch_held_items(workspace_key, event_key, hold_token)
            if verified:
                all_held = [s for s in verified if s]

        # --- Phase 3: iframe bridge + chart API (DOM-based) ---
        if len(all_held) < TARGET_COUNT and frame:
            t_start = datetime.now().timestamp() * 1000
            bridge_held = await run_iframe_bridge(frame, candidates, set(all_held), TARGET_COUNT)
            for s in bridge_held:
                if s not in all_held:
                    all_held.append(s)
            await run_chart_api(frame, section, TARGET_COUNT)
            log("PHASE3", f"DOM strategies attempted in {int(datetime.now().timestamp()*1000 - t_start)}ms")
            await sleep(800)
            verified = await fetch_held_items(workspace_key, event_key, hold_token)
            if verified:
                all_held = [s for s in verified if s]

        if len(all_held) >= TARGET_COUNT:
            break

    # Final fallback: visual clicks if nothing worked.
    if not all_held:
        visual = await run_visual_fallback(TARGET_COUNT)
        if visual:
            all_held = visual

    return all_held[:TARGET_COUNT]


# ------------------------------------------------------------------
# Main flow
# ------------------------------------------------------------------
async def wait_for_input(prompt_text="Press ENTER to continue..."):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt_text)


async def run_booking():
    log("START", "Kimiko combined-strategy bot starting", {
        "email": EMAIL, "event": EVENT_URL, "section": TARGET_SECTION, "count": TARGET_COUNT,
    })

    slug = parse_slug(EVENT_URL)
    log("EVENT", f"Slug: {slug}")

    # Try to get SeatCloud keys from environment first (useful when event-detail is blocked).
    workspace_key = os.environ.get("SEATCLOUD_WORKSPACE_KEY")
    event_key = os.environ.get("SEATCLOUD_EVENT_KEY")
    webook_event_id = None

    if not workspace_key or not event_key:
        try:
            data = await fetch_event_detail(slug)
            event_data = data.get("data") or data
            seats_io = event_data.get("seats_io") or {}
            workspace_key = workspace_key or seats_io.get("workspace_key")
            event_key = event_key or seats_io.get("event_key")
            webook_event_id = event_data.get("_id")
        except Exception as e:
            log("WARN", f"event-detail failed: {e}; will extract SeatCloud keys from chart WebSocket/iframe")

    if workspace_key and event_key:
        log("EVENT", f"SeatCloud workspace={workspace_key} event={event_key}")
    else:
        log("WARN", "No SeatCloud keys yet; will extract from chart after load")

    # Pre-fetch seat inventory only if we already know the keys.
    items_task = None
    if workspace_key and event_key:
        log("SEATS", "Pre-fetching inventory in background...")
        items_task = asyncio.create_task(fetch_seatcloud_items(workspace_key, event_key))

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=HEADLESS, args=["--disable-blink-features=AutomationControlled"])
        try:
            context = await browser.new_context(
                viewport={"width": 393, "height": 852},
                device_scale_factor=3,
                is_mobile=True,
                has_touch=True,
                user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                locale="ar-SA",
                timezone_id="Asia/Riyadh",
                permissions=["geolocation"],
                color_scheme="dark",
                reduced_motion="no-preference",
            )
            await context.add_init_script(STEALTH_SCRIPT)
            await context.add_init_script(WS_INTERCEPT_SCRIPT)
            if _CHART_PATCH_SCRIPT:
                await context.add_init_script(_CHART_PATCH_SCRIPT)
            page = await context.new_page()
            page.on("console", lambda msg: log("BROWSER", f"[{msg.type}] {msg.text}") if msg.type == "error" else None)

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

            for attempt in range(1, 4):
                if logged_in:
                    break
                login_btn = await wait_for_any_selector(page, [
                    'button:has-text("تسجيل الدخول")',
                    'button:has-text("Log In")',
                    'a:has-text("تسجيل الدخول")',
                    'a:has-text("Log In")',
                ])
                if login_btn:
                    await login_btn.click()
                    await sleep(1000)
                    email_input = await wait_for_any_selector(page, [
                        'input[type="email"]',
                        'input[inputmode="email"]',
                        'input[placeholder*="البريد"]',
                        'input[placeholder*="email"]',
                    ])
                    pass_input = await wait_for_any_selector(page, [
                        'input[type="password"]',
                        'input[placeholder*="كلمة"]',
                        'input[placeholder*="password"]',
                    ])
                    if email_input and pass_input:
                        await email_input.fill(EMAIL)
                        await pass_input.fill(PASSWORD)
                        await sleep(300)
                        submit = await wait_for_any_selector(page, [
                            'button[type="submit"]',
                            'button:has-text("دخول")',
                            'button:has-text("Login")',
                        ])
                        if submit:
                            await submit.click()
                            await sleep(4000)
                    try:
                        body_text = await page.evaluate("() => document.body ? document.body.innerText || '' : ''")
                        logged_in = "حسابي" in body_text or "My Account" in body_text or "الملف الشخصي" in body_text or "تسجيل الخروج" in body_text
                    except Exception:
                        pass
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
            chart_poll_interval = 200 if FAST_MODE else 1000
            chart_poll_max = 150 if FAST_MODE else 60
            for _ in range(chart_poll_max):
                if await is_chart_ready(page):
                    break
                await sleep(chart_poll_interval)
            else:
                await safe_screenshot(page, "chart-not-ready")
                raise Exception("Chart not ready after 60s")
            log("CHART", "Chart ready")
            await safe_screenshot(page, "chart-ready")

            # If we still don't have SeatCloud keys, extract them from the iframe/WS URL.
            if not workspace_key or not event_key:
                extracted = {}
                frame = await find_chart_frame(page)
                if frame:
                    extracted = extract_seatcloud_keys(frame.url)
                if (not extracted.get("workspace_key") or not extracted.get("event_key")) and route_state.get("url"):
                    extracted = extract_seatcloud_keys(route_state["url"])
                workspace_key = workspace_key or extracted.get("workspace_key")
                event_key = event_key or extracted.get("event_key")
                if workspace_key and event_key:
                    log("EVENT", f"Extracted SeatCloud keys from chart: workspace={workspace_key} event={event_key}")
                else:
                    log("WARN", "Could not extract SeatCloud keys from chart URL")

            token_info = await read_hold_token(page, slug, webook_event_id)
            if not token_info["token"]:
                raise Exception("Could not obtain hold token")
            hold_token = token_info["token"]
            log("TOKEN", f"Hold token obtained via {token_info['source']}", {"prefix": hold_token[:16]})

            try:
                if items_task is not None:
                    items = await items_task
                    log("SEATS", f"Fetched {len(items)} items (pre-fetched)")
                elif workspace_key and event_key:
                    items = await fetch_seatcloud_items(workspace_key, event_key)
                    log("SEATS", f"Fetched {len(items)} items")
                else:
                    items = []
                    log("WARN", "No SeatCloud keys; skipping seat inventory fetch")
            except Exception as e:
                log("WARN", f"Could not fetch items: {e}")
                items = []

            sections_to_try = parse_target_sections(items)
            if not sections_to_try and items:
                sections_to_try = sorted({i.get("section") for i in items if i.get("section")})

            held = await orchestrate_strategies(page, route_state, hold_token, items, workspace_key, event_key)
            final_count = await get_ticket_count(page)
            log("RESULT", f"Final cart count: {final_count}, verified held seats: {len(held)}", {"held": held})
            await safe_screenshot(page, "after-hold")

            if not held:
                log("WARN", "Could not hold any seats. Will keep polling for availability...")

            watcher = SeatWatcher(workspace_key, event_key, sections_to_try, TARGET_COUNT)

            # Keep-alive + real-time sniper loop
            start_time = datetime.now().timestamp() * 1000
            max_runtime_ms = MAX_RUNTIME_MINUTES * 60 * 1000
            stopped = False
            last_keepalive_ts = start_time

            async def heartbeat():
                nonlocal hold_token, held, stopped, last_keepalive_ts
                if stopped:
                    return
                try:
                    now = datetime.now().timestamp() * 1000

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
                        verified = await fetch_held_items(workspace_key, event_key, hold_token)
                        if verified:
                            held = [s for s in verified if s][:TARGET_COUNT]

                    # --- REAL-TIME SNIPER: only watch selected sections ---
                    if SNIPER_ENABLED and len(held) < TARGET_COUNT and route_state["ready"] and workspace_key and event_key:
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
                    asyncio.get_event_loop().call_later(SNIPER_INTERVAL_MS / 1000, lambda: asyncio.create_task(heartbeat()))

            asyncio.create_task(heartbeat())

            if FAST_MODE and AUTO_PROCEED:
                log("INFO", "Fast mode + auto-proceed: continuing to payment automatically in 3s...")
                await sleep(3000)
            else:
                log("INFO", "Hold active. Browser will stay open. Press ENTER to proceed to payment, or Ctrl+C to stop.")
                await wait_for_input()

            if stopped:
                return

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
            if FAST_MODE and AUTO_PROCEED:
                log("INFO", "Auto-proceed enabled. Browser left open for manual payment.")
            else:
                await wait_for_input("Press ENTER again after payment (or to exit)...")

        except Exception as e:
            log("ERROR", f"Booking error: {e}")
            await safe_screenshot(page, "error")
            log("INFO", "Browser will remain open for inspection. Press ENTER to close.")
            await wait_for_input()


if __name__ == "__main__":
    try:
        asyncio.run(run_booking())
    except KeyboardInterrupt:
        log("STOP", "Interrupted by user")
    except Exception as e:
        log("FATAL", str(e))
        sys.exit(1)
