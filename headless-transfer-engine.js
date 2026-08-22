// ------------------------------------------------------------------
// Headless WebSocket Transfer Engine for SeatCloud / Webook
// ------------------------------------------------------------------
// Cookie-only, browser-independent seat transfers.
// Uses raw WebSocket connections to api.seatcloud.com:8443 with the same
// deflate-framed JSON protocol the chart iframe uses.
// ------------------------------------------------------------------

const WebSocket = require('ws');
const zlib = require('zlib');
const crypto = require('crypto');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

const WB_ORIGIN = 'https://webook.com';
const SEATCLOUD_WS_HOST = 'api.seatcloud.com';
const SEATCLOUD_WS_ORIGIN = 'https://chart.seatcloud.com';

function makeTraceId(prefix = '') {
  const rand = Math.random().toString(36).slice(2, 13).padEnd(11, '0');
  return `${prefix}${Date.now()}-${rand}`;
}

function waitFor(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ------------------------------------------------------------------
// Cookie parsing
// ------------------------------------------------------------------
function parseCookies(rawCookies, structuredCookies) {
  const map = new Map();
  if (typeof rawCookies === 'string' && rawCookies.trim()) {
    rawCookies.split(';').forEach(part => {
      const idx = part.indexOf('=');
      if (idx > 0) {
        const name = part.slice(0, idx).trim();
        const value = part.slice(idx + 1).trim();
        if (name) map.set(name, value);
      }
    });
  }
  if (Array.isArray(structuredCookies)) {
    for (const c of structuredCookies) {
      if (c && typeof c.name === 'string' && c.name) {
        map.set(c.name, String(c.value || ''));
      }
    }
  }
  return map;
}

function buildCookieHeader(cookieMap) {
  const parts = [];
  for (const [name, value] of cookieMap) {
    parts.push(`${name}=${value}`);
  }
  return parts.join('; ');
}

function getCookie(cookieMap, names) {
  for (const n of names) {
    const v = cookieMap.get(n);
    if (v) return v;
  }
  return null;
}

// ------------------------------------------------------------------
// Proxy helpers
// ------------------------------------------------------------------
function buildProxyAgent(proxyConfig) {
  if (!proxyConfig || !proxyConfig.server) return null;
  const s = proxyConfig.server.trim();
  if (s.startsWith('socks5://') || s.startsWith('socks4://')) {
    return new SocksProxyAgent(s);
  }
  let url = s;
  if (!url.startsWith('http://') && !url.startsWith('https://')) url = `http://${url}`;
  if (proxyConfig.username || proxyConfig.password) {
    const u = encodeURIComponent(proxyConfig.username || '');
    const p = encodeURIComponent(proxyConfig.password || '');
    url = url.replace(/^https?:\/\//, `http://${u}:${p}@`);
  }
  return new HttpsProxyAgent(url);
}

// ------------------------------------------------------------------
// SeatCloud frame encoding / decoding
// ------------------------------------------------------------------
function decompressWsMessage(data) {
  if (typeof data === 'string') return data;
  const buf = Buffer.from(data);
  try { return zlib.inflateRawSync(buf).toString('utf8'); } catch {}
  try { return zlib.inflateSync(buf).toString('utf8'); } catch {}
  try { return buf.toString('utf8'); } catch { return null; }
}

function compressWsMessage(text) {
  return zlib.deflateRawSync(Buffer.from(text, 'utf8'));
}

function buildSeatcloudWsUrl(eventKey, holdToken, workspaceKey, tracingId, channel = 'NO_CHANNEL') {
  return `wss://${SEATCLOUD_WS_HOST}:8443/?event=${encodeURIComponent(eventKey)}&token=${encodeURIComponent(holdToken)}&teamID=${encodeURIComponent(workspaceKey)}&channel=${encodeURIComponent(channel)}&tracingId=${encodeURIComponent(tracingId)}`;
}

// ------------------------------------------------------------------
// REST helpers
// ------------------------------------------------------------------
async function fetchWithCookies(url, options = {}, cookieMap = null, proxyConfig = null) {
  const headers = options.headers ? { ...options.headers } : {};
  if (cookieMap && cookieMap.size > 0) {
    headers.Cookie = buildCookieHeader(cookieMap);
  }
  const fetchOptions = { ...options, headers };
  if (proxyConfig) {
    const agent = buildProxyAgent(proxyConfig);
    if (agent) fetchOptions.agent = agent;
  }
  return fetch(url, fetchOptions);
}

function tryDecompress(buf) {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try { return zlib.gunzipSync(buf); } catch {}
  }
  try { return zlib.inflateSync(buf); } catch {}
  try { return zlib.inflateRawSync(buf); } catch {}
  return null;
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function tryAesGcmDecrypt(buf, keyString) {
  try {
    const key = Buffer.from(sha256Hex(keyString), 'hex');
    if (buf.length < 29) return null;
    const iv = buf.slice(0, 12);
    const tag = buf.slice(buf.length - 16);
    const ciphertext = buf.slice(12, buf.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const r1 = decipher.update(ciphertext);
    const r2 = decipher.final();
    return Buffer.concat([r1, r2]);
  } catch { return null; }
}

function xorDecrypt(buf, key) {
  const out = Buffer.alloc(buf.length);
  const k = Buffer.from(key, 'utf8');
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i] ^ k[i % k.length];
  }
  return out;
}

function decodeSeatcloudItems(rawBytes, { eventKey, holdToken } = {}) {
  try {
    const text = rawBytes.toString('utf8').trim();
    if (text.length > 0 && (text[0] === '[' || text[0] === '{')) return JSON.parse(text);
  } catch {}

  const decompressed = tryDecompress(rawBytes);
  if (decompressed) {
    try { return JSON.parse(decompressed.toString('utf8')); } catch {}
  }

  if (holdToken) {
    const plain = tryAesGcmDecrypt(rawBytes, holdToken);
    if (plain) {
      const d = tryDecompress(plain);
      const final = d || plain;
      try { return JSON.parse(final.toString('utf8')); } catch {}
    }
  }

  if (eventKey) {
    const xored = xorDecrypt(rawBytes, eventKey);
    const d = tryDecompress(xored);
    const final = d || xored;
    try { return JSON.parse(final.toString('utf8')); } catch {}
  }

  try { return JSON.parse(rawBytes.toString('utf8')); } catch {
    throw new Error(`decodeSeatcloudItems: unable to decode ${rawBytes.length} bytes`);
  }
}

async function getAuthTokenFromCookies(cookieMap) {
  return getCookie(cookieMap, ['token', 'authToken', 'access_token']);
}

function getHoldTokenFromCookies(cookieMap) {
  return getCookie(cookieMap, ['holdToken', 'hold_token']);
}

async function getHoldTokenFromWebook(slug, cookieMap = null, proxyConfig = null) {
  const traceId = makeTraceId();
  const url = `https://api.webook.com/api/v2/event-detail/${slug}/hold-token?lang=ar&trace_id=${traceId}`;
  const authToken = await getAuthTokenFromCookies(cookieMap);
  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    Origin: WB_ORIGIN,
    Referer: `${WB_ORIGIN}/`,
    token: authToken || '',
  };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;

  const res = await fetchWithCookies(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({ event_id: '', lang: 'ar' }),
  }, cookieMap, proxyConfig);
  if (!res.ok) throw new Error(`hold-token HTTP ${res.status}`);
  const data = await res.json().catch(() => ({}));

  // Extract hold token from nested response.
  const stack = [data];
  const seen = new Set();
  const keys = ['hold_token', 'holdToken', 'token'];
  while (stack.length) {
    const cur = stack.pop();
    if (!cur || typeof cur !== 'object') continue;
    const id = JSON.stringify(cur);
    if (seen.has(id)) continue;
    seen.add(id);
    for (const key of keys) {
      const val = cur[key];
      if (typeof val === 'string' && val.trim()) return val.trim();
    }
    for (const v of Object.values(cur)) {
      if (v && typeof v === 'object') stack.push(v);
    }
  }
  return null;
}

async function refreshHoldToken(holdToken, minutes = 15, cookieMap = null, proxyConfig = null) {
  if (!holdToken) return null;
  const url = `https://api.seatcloud.com/api/v2/token/${encodeURIComponent(holdToken)}?trace_id=${makeTraceId()}`;
  const res = await fetchWithCookies(url, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Origin: WB_ORIGIN,
      Referer: `${WB_ORIGIN}/`,
    },
    body: JSON.stringify({ expiresInMinutes: minutes }),
  }, cookieMap, proxyConfig);
  if (!res.ok) return null;
  const data = await res.json().catch(() => null);
  return data?.token || holdToken;
}

async function fetchSeatcloudKeys(slug, cookieMap = null, proxyConfig = null) {
  // Try the same endpoint the browser uses to load event detail.
  const traceId = makeTraceId();
  const url = `https://api.webook.com/api/v2/event-detail/${slug}?lang=ar&trace_id=${traceId}`;
  const res = await fetchWithCookies(url, {
    headers: {
      Accept: 'application/json',
      Origin: WB_ORIGIN,
      Referer: `${WB_ORIGIN}/`,
    },
  }, cookieMap, proxyConfig);
  if (!res.ok) throw new Error(`event-detail HTTP ${res.status}`);
  const data = await res.json().catch(() => ({}));

  // Heuristic extraction: walk the response looking for workspace/event keys.
  const keys = {};
  const stack = [data];
  const seen = new Set();
  while (stack.length) {
    const cur = stack.pop();
    if (!cur || typeof cur !== 'object') continue;
    const id = JSON.stringify(cur);
    if (seen.has(id)) continue;
    seen.add(id);
    for (const [k, v] of Object.entries(cur)) {
      if (typeof v === 'string') {
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) {
          if (k.toLowerCase().includes('event') && !k.toLowerCase().includes('season')) keys.eventKey = v;
          if (k.toLowerCase().includes('workspace') || k.toLowerCase().includes('team')) keys.workspaceKey = v;
        }
      } else if (v && typeof v === 'object') {
        stack.push(v);
      }
    }
  }
  return keys;
}

// ------------------------------------------------------------------
// Headless SeatCloud WebSocket client
// ------------------------------------------------------------------
class HeadlessSeatCloudClient {
  constructor({
    username,
    rawCookies,
    structuredCookies,
    holdToken,
    workspaceKey,
    eventKey,
    channel = 'NO_CHANNEL',
    proxyConfig = null,
    userAgent = null,
  }) {
    this.username = username;
    this.cookieMap = parseCookies(rawCookies, structuredCookies);
    this.holdToken = holdToken || getHoldTokenFromCookies(this.cookieMap);
    this.workspaceKey = workspaceKey;
    this.eventKey = eventKey;
    this.channel = channel;
    this.proxyConfig = proxyConfig;
    this.userAgent = userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36';
    this.ws = null;
    this.connected = false;
    this.messageQueue = [];
    this.pending = new Map();
    this.onMessageCb = null;
    this.onCloseCb = null;
  }

  async resolveKeysFromSlug(slug) {
    if (this.workspaceKey && this.eventKey) return true;
    const keys = await fetchSeatcloudKeys(slug, this.cookieMap, this.proxyConfig);
    if (keys.workspaceKey) this.workspaceKey = keys.workspaceKey;
    if (keys.eventKey) this.eventKey = keys.eventKey;
    return !!(this.workspaceKey && this.eventKey);
  }

  async connect(timeoutMs = 10000) {
    if (!this.workspaceKey || !this.eventKey || !this.holdToken) {
      throw new Error('Missing workspaceKey, eventKey or holdToken');
    }
    const tracingId = makeTraceId('hte_');
    const url = buildSeatcloudWsUrl(this.eventKey, this.holdToken, this.workspaceKey, tracingId, this.channel);

    const cookieHeader = buildCookieHeader(this.cookieMap);
    const wsOptions = {
      perMessageDeflate: false,
      handshakeTimeout: timeoutMs,
      origin: SEATCLOUD_WS_ORIGIN,
      headers: {
        Origin: SEATCLOUD_WS_ORIGIN,
        Referer: `${SEATCLOUD_WS_ORIGIN}/`,
        'User-Agent': this.userAgent,
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
      },
    };
    if (this.proxyConfig) {
      const agent = buildProxyAgent(this.proxyConfig);
      if (agent) wsOptions.agent = agent;
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        try { this.ws.terminate(); } catch {}
        reject(new Error('WebSocket connection timeout'));
      }, timeoutMs);

      this.ws = new WebSocket(url, wsOptions);

      this.ws.on('open', () => {
        clearTimeout(timer);
        this.connected = true;
        resolve();
      });

      this.ws.on('message', (data) => {
        try {
          const text = decompressWsMessage(data);
          const msg = text ? JSON.parse(text) : null;
          if (msg) this._handleMessage(msg);
        } catch {}
      });

      this.ws.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      this.ws.on('close', () => {
        this.connected = false;
        if (this.onCloseCb) this.onCloseCb();
      });
    });
  }

  _handleMessage(msg) {
    if (this.onMessageCb) this.onMessageCb(msg);
    const id = msg && (msg.tracing_id || msg.tracingId || msg.trace_id);
    if (id && this.pending.has(id)) {
      const { resolve } = this.pending.get(id);
      this.pending.delete(id);
      resolve(msg);
    }
  }

  onMessage(cb) { this.onMessageCb = cb; }
  onClose(cb) { this.onCloseCb = cb; }

  send(payload) {
    const compressed = compressWsMessage(JSON.stringify(payload));
    if (!this.connected || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket not connected');
    }
    this.ws.send(compressed);
  }

  sendAndWait(payload, timeoutMs = 5000) {
    const id = payload.tracing_id || payload.tracingId || makeTraceId();
    payload.tracing_id = id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('WebSocket response timeout'));
      }, timeoutMs);
      this.pending.set(id, { resolve: (msg) => { clearTimeout(timer); resolve(msg); }, reject });
      try {
        this.send(payload);
      } catch (e) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(e);
      }
    });
  }

  holdObjects(objectIds, tracingId = null) {
    const payload = {
      action: 'hold-object',
      objects: objectIds.map(objectId => ({ objectId })),
      token: this.holdToken,
      tracing_id: tracingId || makeTraceId(`hte_hold_${this.username}_`),
    };
    return this.sendAndWait(payload, 5000);
  }

  releaseObjects(objectIds, tracingId = null) {
    const base = {
      objects: objectIds.map(objectId => ({ objectId })),
      token: this.holdToken,
      tracing_id: tracingId || makeTraceId(`hte_rel_${this.username}_`),
    };
    return Promise.all([
      this.sendAndWait({ ...base, action: 'release-object' }, 5000).catch(() => null),
      this.sendAndWait({ ...base, action: 'free-object' }, 5000).catch(() => null),
    ]);
  }

  close() {
    try { if (this.ws) this.ws.terminate(); } catch {}
    this.connected = false;
  }
}

// ------------------------------------------------------------------
// REST hold/release fallbacks
// ------------------------------------------------------------------
async function holdSeatsViaRest(workspaceKey, eventKey, holdToken, objectIds, channel = 'NO_CHANNEL', cookieMap = null, proxyConfig = null, paramName = 'allocations') {
  const seats = [...new Set((objectIds || []).map(String).filter(Boolean))];
  if (!seats.length) return [];
  const traceId = makeTraceId();
  const url = `https://api.seatcloud.com/api/v2/${workspaceKey}/event/${eventKey}/actions/hold?trace_id=${traceId}&plain=true`;

  async function tryHold(fieldName) {
    const body = {
      holdToken,
      objects: seats.map(objectId => ({ objectId })),
      [fieldName]: channel,
    };
    const res = await fetchWithCookies(url, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Accept-Encoding': 'identity',
        'Accept-Language': 'ar-SA,ar;q=0.9',
        'Content-Type': 'application/json',
        Origin: WB_ORIGIN,
        Referer: `${WB_ORIGIN}/`,
      },
      body: JSON.stringify(body),
    }, cookieMap, proxyConfig);

    const text = await res.text().catch(() => '');
    if (!res.ok) return [];
    let data = null;
    try { data = JSON.parse(text); } catch { data = decodeSeatcloudItems(Buffer.from(text, 'utf8'), { eventKey, holdToken }); }
    const held = [];
    const extract = (o) => {
      const id = typeof o === 'string' ? o : (o?.objectId || o?.label || o?.id);
      if (id && seats.includes(id) && !held.includes(id)) held.push(id);
    };
    if (Array.isArray(data)) data.forEach(extract);
    else if (data?.objects) data.objects.forEach(extract);
    else if (data?.data?.objects) data.data.objects.forEach(extract);
    return held;
  }

  let held = await tryHold(paramName);
  if (held.length) return held;
  const fallback = paramName === 'channels' ? 'allocations' : 'channels';
  held = await tryHold(fallback);
  return held;
}

async function releaseSeatsViaRest(workspaceKey, eventKey, holdToken, objectIds, channel = 'NO_CHANNEL', cookieMap = null, proxyConfig = null, paramName = 'allocations') {
  const seats = [...new Set((objectIds || []).map(String).filter(Boolean))];
  if (!seats.length) return [];
  const traceId = makeTraceId();
  const url = `https://api.seatcloud.com/api/v2/${workspaceKey}/event/${eventKey}/actions/release?trace_id=${traceId}&plain=true`;
  const body = {
    holdToken,
    objects: seats.map(objectId => ({ objectId })),
    [paramName]: channel,
  };
  const res = await fetchWithCookies(url, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Accept-Encoding': 'identity',
      'Accept-Language': 'ar-SA,ar;q=0.9',
      'Content-Type': 'application/json',
      Origin: WB_ORIGIN,
      Referer: `${WB_ORIGIN}/`,
    },
    body: JSON.stringify(body),
  }, cookieMap, proxyConfig);
  if (!res.ok) return [];
  return seats;
}

async function verifyHeldSeats(workspaceKey, eventKey, holdToken, wantedSeats, channel = 'NO_CHANNEL', cookieMap = null, proxyConfig = null, paramName = 'allocations') {
  const wantedSet = new Set(wantedSeats.map(String));
  const traceId = makeTraceId();
  const url = `https://api.seatcloud.com/api/v2/${workspaceKey}/event/${eventKey}/items/held?hold_token=${encodeURIComponent(holdToken)}&${paramName}=${encodeURIComponent(channel)}&trace_id=${traceId}&plain=true`;
  const res = await fetchWithCookies(url, {
    headers: {
      Accept: 'application/json',
      'Accept-Encoding': 'identity',
      'Accept-Language': 'ar-SA,ar;q=0.9',
      Origin: WB_ORIGIN,
      Referer: `${WB_ORIGIN}/`,
    },
  }, cookieMap, proxyConfig);
  if (!res.ok) return [];
  const buf = Buffer.from(await res.arrayBuffer());
  const held = decodeSeatcloudItems(buf, { eventKey, holdToken });
  if (!Array.isArray(held)) return [];
  const heldLabels = held.map(it => String(it.label || it.name || it.objectId || it.id)).filter(Boolean);
  return heldLabels.filter(l => wantedSet.has(l));
}

// ------------------------------------------------------------------
// V3 live-stream atomic transfer (headless)
// ------------------------------------------------------------------
async function headlessTransferV3(sourceAccount, destAccount, seats, options = {}) {
  const {
    slug,
    workspaceKey,
    eventKey,
    channel = 'NO_CHANNEL',
    maxAttempts = 200,
    pollMs = 5,
    releaseDelayMs = 15,
    useRestFallback = true,
    onStatus = () => {},
  } = options;

  if (!seats || seats.length === 0) return { held: [], missing: [] };

  const sourceClient = new HeadlessSeatCloudClient({ ...sourceAccount, workspaceKey, eventKey, channel });
  const destClient = new HeadlessSeatCloudClient({ ...destAccount, workspaceKey, eventKey, channel });

  // Resolve keys from slug if not provided.
  if (slug && (!workspaceKey || !eventKey)) {
    await Promise.all([
      sourceClient.resolveKeysFromSlug(slug),
      destClient.resolveKeysFromSlug(slug),
    ]);
  }

  // Try to refresh/extend source hold token before the transfer.
  if (slug) {
    const refreshed = await refreshHoldToken(sourceClient.holdToken, 15, sourceClient.cookieMap, sourceAccount.proxyConfig);
    if (refreshed) sourceClient.holdToken = refreshed;
  }

  // Destination needs its own fresh hold token. Try to obtain one via Webook API.
  if (slug && destClient.holdToken) {
    const refreshed = await refreshHoldToken(destClient.holdToken, 15, destClient.cookieMap, destAccount.proxyConfig);
    if (refreshed) destClient.holdToken = refreshed;
  } else if (slug) {
    try {
      const newToken = await getHoldTokenFromWebook(slug, destClient.cookieMap, destAccount.proxyConfig);
      if (newToken) destClient.holdToken = newToken;
    } catch {}
  }

  const startMs = Date.now();
  onStatus('connecting', `Connecting source ${sourceAccount.username} and destination ${destAccount.username}`);
  await Promise.all([
    sourceClient.connect(10000).catch(err => { throw new Error(`Source WS failed: ${err.message}`); }),
    destClient.connect(10000).catch(err => { throw new Error(`Dest WS failed: ${err.message}`); }),
  ]);

  // Pre-warm: send a lightweight ping/keepalive style frame on both sockets.
  onStatus('pre-warm', `Pre-warming WebSocket channels`);
  try { destClient.holdObjects([], makeTraceId('hte_warm_')).catch(() => {}); } catch {}
  await waitFor(20);

  try {
    onStatus('livestream-start', `V3 live-stream transfer of ${seats.length} seat(s) to ${destAccount.username}`);
    const heldSet = new Set();
    const failedSet = new Set();
    let loopFinished = false;
    const releaseStartPromise = { started: false };

    const holdLoop = (async () => {
      for (let i = 0; i < maxAttempts && !loopFinished; i++) {
        const still = seats.filter(s => !heldSet.has(s) && !failedSet.has(s));
        if (!still.length) break;
        try {
          // Fire-and-forget holds; do not wait for ack to keep loop tight.
          destClient.send({
            action: 'hold-object',
            objects: still.map(objectId => ({ objectId })),
            token: destClient.holdToken,
            tracing_id: makeTraceId(`hte_bomb_${i}_`),
          });
        } catch {}

        // Every 10 attempts, verify held seats via REST to update heldSet.
        if (i > 0 && i % 10 === 0) {
          try {
            const verified = await verifyHeldSeats(
              destClient.workspaceKey,
              destClient.eventKey,
              destClient.holdToken,
              still,
              channel,
              destClient.cookieMap,
              destAccount.proxyConfig,
            );
            for (const s of verified) heldSet.add(s);
          } catch {}
        }

        if (heldSet.size < seats.length) await waitFor(pollMs);
      }
    })();

    // Start release slightly after destination bombardment begins.
    await waitFor(releaseDelayMs);
    releaseStartPromise.started = true;
    await sourceClient.releaseObjects(seats, makeTraceId('hte_release_'));

    await Promise.race([holdLoop, waitFor(maxAttempts * pollMs + 3000)]);
    loopFinished = true;

    // Final verification via REST.
    let held = [];
    try {
      held = await verifyHeldSeats(
        destClient.workspaceKey,
        destClient.eventKey,
        destClient.holdToken,
        seats,
        channel,
        destClient.cookieMap,
        destAccount.proxyConfig,
      );
    } catch {}
    for (const s of held) heldSet.add(s);

    const allHeld = seats.filter(s => heldSet.has(s));
    const missing = seats.filter(s => !heldSet.has(s));

    // REST fallback for any missing seats.
    if (missing.length && useRestFallback) {
      onStatus('rest-fallback', `Attempting REST fallback for ${missing.length} missing seat(s)`);
      const restHeld = await holdSeatsViaRest(
        destClient.workspaceKey,
        destClient.eventKey,
        destClient.holdToken,
        missing,
        channel,
        destClient.cookieMap,
        destAccount.proxyConfig,
      );
      for (const s of restHeld) {
        if (!heldSet.has(s)) {
          heldSet.add(s);
          allHeld.push(s);
        }
      }
    }

    const finalMissing = seats.filter(s => !heldSet.has(s));
    onStatus('livestream-result', `Headless transfer: ${allHeld.length}/${seats.length} held`);
    return { held: allHeld, missing: finalMissing, durationMs: Date.now() - startMs };
  } finally {
    sourceClient.close();
    destClient.close();
  }
}

// ------------------------------------------------------------------
// Batch transfers
// ------------------------------------------------------------------
async function headlessTransferBatch(transfers, options = {}) {
  // transfers: [{ sourceAccount, destAccount, seats }]
  const results = [];
  for (const t of transfers) {
    try {
      const r = await headlessTransferV3(t.sourceAccount, t.destAccount, t.seats, options);
      results.push({ ...r, destination: t.destAccount.username });
    } catch (err) {
      results.push({ held: [], missing: t.seats, error: err.message, destination: t.destAccount.username });
    }
  }
  return results;
}

// ------------------------------------------------------------------
// Exports
// ------------------------------------------------------------------
module.exports = {
  HeadlessSeatCloudClient,
  headlessTransferV3,
  headlessTransferBatch,
  holdSeatsViaRest,
  releaseSeatsViaRest,
  verifyHeldSeats,
  parseCookies,
  fetchSeatcloudKeys,
  getHoldTokenFromCookies,
  getHoldTokenFromWebook,
  refreshHoldToken,
  buildSeatcloudWsUrl,
  buildProxyAgent,
};
