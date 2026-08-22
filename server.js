const express = require('express');
const path = require('path');
const fs = require('fs');
const zlib = require('zlib');
const crypto = require('crypto');
const os = require('os');
const cors = require('cors');
const { createServer } = require('http');
const { Server } = require('socket.io');
const { chromium, devices, request: playwrightRequest } = require('playwright-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
try { chromium.use(StealthPlugin()); } catch (e) { fileLog('WARN', `Stealth plugin init warning: ${e.message}`); }
const WebSocket = require('ws');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { createPairCyclingManager } = require('./pair-cycling');
const { createAtomicQueue } = require('./secure_queue_middleware');
const { createProxyManager } = require('./lib/proxy-manager');
const captcha2captcha = require('./lib/captcha-2captcha');
const humanInput = require('./lib/human-input');
const {
  isSensitiveKey,
  redactValue,
  safeRedactedStringify,
  trimCache,
  getProxyCacheKey,
} = require('./lib/safety-helpers');
const {
  HeadlessSeatCloudClient,
  headlessTransferV3,
  headlessTransferBatch,
  holdSeatsViaRest,
  releaseSeatsViaRest,
  verifyHeldSeats,
  parseCookies,
  fetchSeatcloudKeys,
  getHoldTokenFromCookies,
} = require('./headless-transfer-engine');

// Secure queue token validator (reference implementation of the server-side
// fixes for JWT bypass / queue race issues). See secure_queue_server.js for a
// full standalone backend that enforces these checks on /api/queue/*.
let __queueValidator = null;
function getQueueValidator() {
  if (!__queueValidator) {
    const secret = process.env.QUEUE_JWT_SECRET || require('crypto').randomUUID();
    __queueValidator = createAtomicQueue({ jwtSecret: secret, tokenTtlSeconds: 3600 });
  }
  return __queueValidator;
}

// Global error handlers to prevent crashes. Avoid console.* here: if the
// parent pipe is broken (EPIPE) writing to stderr would re-trigger the handler.
let __lastCrash = '';
let __crashRepeat = 0;
function safeCrashLog(label, detail) {
  const msg = `${label}: ${detail}`;
  // Suppress repeated identical crash noise after 3 occurrences.
  if (msg === __lastCrash) {
    __crashRepeat++;
    if (__crashRepeat > 3) return;
  } else {
    __lastCrash = msg;
    __crashRepeat = 0;
  }
  try {
    fs.appendFileSync(path.join(__dirname, 'logs', 'crash.log'), `[${new Date().toISOString()}] ${msg}\n`);
  } catch {}
  try {
    fs.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] [CRASH] ${msg}\n`);
  } catch {}
}
process.on('uncaughtException', err => {
  if (err && err.code === 'EPIPE') {
    safeCrashLog('EPIPE ignored', 'stdout/stderr pipe closed');
    return;
  }
  safeCrashLog('UNCAUGHT EXCEPTION', err.stack || err.message || String(err));
});
process.on('unhandledRejection', (reason, promise) => {
  safeCrashLog('UNHANDLED REJECTION', reason?.stack || reason?.message || String(reason));
});

// Logging
const LOG_DIR = path.join(__dirname, 'logs');
const DIAGNOSTICS_DIR = path.join(__dirname, 'logs', 'diagnostics');
fs.mkdirSync(LOG_DIR, { recursive: true });
fs.mkdirSync(DIAGNOSTICS_DIR, { recursive: true });
const LOG_FILE = path.join(LOG_DIR, `kimiko-${new Date().toISOString().slice(0, 10)}.log`);

// Session cache for harvested full sessions (cookies + storageState + tokens)
const SESSION_CACHE_DIR = path.join(__dirname, 'session_cache');
(async () => {
  try {
    await fs.promises.mkdir(SESSION_CACHE_DIR, { recursive: true });
  } catch (e) {
    fileLog('WARN', `Could not create session cache dir: ${e.message}`);
  }
})();
const LOG_MAX_BYTES = 100 * 1024 * 1024; // rotate if current log exceeds 100 MB
function fileLog(level, message) {
  const line = `[${new Date().toISOString()}] [${level}] ${message}\n`;
  try {
    fs.appendFileSync(LOG_FILE, line);
  } catch (e) {
    if (e && e.code === 'ENOSPC') {
      // Avoid console.error when the parent pipe may be broken (EPIPE).
      try { console.error('Log disk full; dropping log line.'); } catch {}
    } else if (e && e.code !== 'EPIPE') {
      try { console.error('fileLog error:', e.message); } catch {}
    }
  }
  rotateLogIfNeeded();
}
function fileLogRaw(line) {
  try {
    fs.appendFileSync(LOG_FILE, line);
  } catch (e) {
    if (e && e.code === 'ENOSPC') {
      try { console.error('Log disk full; dropping raw log line.'); } catch {}
    } else if (e && e.code !== 'EPIPE') {
      try { console.error('fileLogRaw error:', e.message); } catch {}
    }
  }
  rotateLogIfNeeded();
}
function rotateLogIfNeeded() {
  try {
    const stats = fs.statSync(LOG_FILE);
    if (stats.size > LOG_MAX_BYTES) {
      const rotated = `${LOG_FILE}.${Date.now()}.old`;
      fs.renameSync(LOG_FILE, rotated);
      fs.writeFileSync(LOG_FILE, `[${new Date().toISOString()}] [INFO] Log rotated from ${rotated}\n`, 'utf8');
    }
  } catch {}
}

// ------------------------------------------------------------------
// Structured transfer audit log
// ------------------------------------------------------------------
const TRANSFER_AUDIT_FILE = path.join(LOG_DIR, `transfer-audit-${new Date().toISOString().slice(0, 10)}.jsonl`);
class TransferAuditor {
  constructor() {
    this.entries = [];
  }
  record(entry) {
    const record = {
      ts: new Date().toISOString(),
      transferId: entry.transferId || `tx-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      stage: entry.stage || 'unknown',
      sourceUser: entry.sourceUser || null,
      destinationUser: entry.destinationUser || null,
      seats: entry.seats || [],
      held: typeof entry.held === 'number' ? entry.held : null,
      missing: typeof entry.missing === 'number' ? entry.missing : null,
      mode: entry.mode || null,
      durationMs: typeof entry.durationMs === 'number' ? entry.durationMs : null,
      error: entry.error || null,
      metadata: entry.metadata || {},
    };
    this.entries.push(record);
    try {
      fs.appendFileSync(TRANSFER_AUDIT_FILE, JSON.stringify(record) + '\n');
    } catch (e) {
      fileLog('WARN', `Transfer audit write failed: ${e.message}`);
    }
    return record.transferId;
  }
}
const transferAuditor = new TransferAuditor();

// ------------------------------------------------------------------
// Remote kill switch
// ------------------------------------------------------------------
const KILL_SWITCH_URL = 'https://docs.google.com/uc?export=download&id=1REr8SgHM4oAWplpliRw2YH4oC_M-ACaN';

async function checkKillSwitch() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(KILL_SWITCH_URL, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) {
      console.error(`[KILL SWITCH] Remote check returned HTTP ${res.status}. Terminating.`);
      fileLog('ERROR', `[KILL SWITCH] Remote check returned HTTP ${res.status}. Terminating.`);
      process.exit(1);
    }
    const text = String(await res.text()).trim();
    if (text !== '1') {
      console.error(`[KILL SWITCH] Remote flag is "${text}" (expected "1"). Terminating.`);
      fileLog('ERROR', `[KILL SWITCH] Remote flag is "${text}" (expected "1"). Terminating.`);
      process.exit(1);
    }
    fileLog('INFO', '[KILL SWITCH] Remote flag is "1"; proceeding.');
  } catch (e) {
    clearTimeout(timeout);
    console.error(`[KILL SWITCH] Network/error while checking remote flag: ${e.message}. Terminating.`);
    fileLog('ERROR', `[KILL SWITCH] Network/error while checking remote flag: ${e.message}. Terminating.`);
    process.exit(1);
  }
}

// ------------------------------------------------------------------
// Proxy management with testing + optional fallback
// ------------------------------------------------------------------
// PROXY_MODE values:
//   off      -> never use proxies
//   test     -> test proxies, use working ones, fallback to direct if all fail
//   required -> test proxies, use working ones, fail account if none work (default)
let currentProxyMode = ['off', 'test', 'required'].includes(process.env.PROXY_MODE)
  ? process.env.PROXY_MODE
  : 'required';
function setProxyMode(mode) {
  if (['off', 'test', 'required'].includes(mode)) {
    currentProxyMode = mode;
    return true;
  }
  return false;
}
const PROXIES_FILE = path.join(__dirname, 'proxies.txt');
const DATA_JSON_FILE = path.join(__dirname, 'data.json');
const proxyManager = createProxyManager({
  envValue: process.env.PROXY_LIST,
  filePath: PROXIES_FILE,
  dataJsonPath: DATA_JSON_FILE,
});
const PROXY_TEST_CACHE = new Map(); // server -> { ok, reason, ts }
const PROXY_TEST_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const PROXY_TEST_CACHE_MAX_SIZE = 500;

const CHART_SECTIONS_CACHE = new Map(); // slug -> { ts, result }
const CHART_SECTIONS_CACHE_TTL_MS = 60 * 1000; // 60 seconds

// Global shared queue token harvested by the first credentials account that
// clears the waiting room. Follower accounts inject it to bypass the queue.
// Stored as { token, harvestedAt, expiresAt } so we can expire stale tokens.
let globalValidQueueToken = null;

function getQueueTokenExp(queueToken) {
  if (!queueToken || typeof queueToken !== 'string') return null;
  try {
    const parts = queueToken.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return payload && typeof payload.exp === 'number' ? payload.exp : null;
  } catch {}
  return null;
}

function isQueueTokenValid(queueToken, bufferSeconds = 30) {
  const exp = getQueueTokenExp(queueToken);
  if (!exp) return true; // unknown expiry, treat as valid
  return Date.now() < (exp * 1000 - bufferSeconds * 1000);
}

function setGlobalValidQueueToken(token) {
  if (!token || typeof token !== 'string') return;
  const exp = getQueueTokenExp(token);
  globalValidQueueToken = {
    token,
    harvestedAt: Date.now(),
    expiresAt: exp ? exp * 1000 : null,
  };
  fileLog('INFO', `[QUEUE-BYPASS] Harvested global queue token (expires ${exp ? new Date(exp * 1000).toISOString() : 'unknown'})`);
}

function broadcastQueueTokenToPending(token) {
  if (!token || !pendingQueue.length) return;
  let injected = 0;
  for (const account of pendingQueue) {
    if (!account.queueToken && !account.queueSession) {
      account.queueToken = token;
      account.queueSession = token;
      injected++;
    }
  }
  if (injected) {
    fileLog('INFO', `[QUEUE-BYPASS] Broadcast queue token to ${injected} pending account(s)`);
  }
}

async function tryInjectHarvestedQueueToken(session) {
  if (!globalValidQueueToken || !globalValidQueueToken.token) return false;
  if (!isQueueTokenValid(globalValidQueueToken.token)) {
    fileLog('INFO', `[QUEUE-BYPASS] Harvested queue token expired; not injecting for ${session.username}`);
    globalValidQueueToken = null;
    return false;
  }
  if (session.queueToken || session.providedQueueToken) return false;
  try {
    await syncQueueTokenToCookie(session.context, globalValidQueueToken.token);
    session.queueToken = globalValidQueueToken.token;
    emitStatus('queue-token-injected', 'Injected harvested queue token before navigation', { account: session.username });
    return true;
  } catch (e) {
    fileLog('WARN', `[QUEUE-BYPASS] Failed to inject queue token for ${session.username}: ${e.message}`);
    return false;
  }
}

async function testProxy(proxy, timeoutMs = 6000) {
  if (!proxy || !proxy.server) return { ok: false, reason: 'no proxy server', targets: [] };
  const cacheKey = `${proxy.server}|${proxy.username || ''}|${proxy.password || ''}`;
  const cached = PROXY_TEST_CACHE.get(cacheKey);
  if (cached && Date.now() - cached.ts < PROXY_TEST_CACHE_TTL_MS) return cached;

  let requestContext = null;
  const result = { ok: false, reason: 'unknown', targets: [], ts: Date.now() };
  try {
    requestContext = await playwrightRequest.newContext({
      proxy: {
        server: proxy.server,
        username: proxy.username,
        password: proxy.password,
      },
      timeout: timeoutMs,
    });

    // Test both Webook and SeatCloud/Seats.io reachability.
    const targets = [
      { name: 'webook', url: 'https://webook.com/ar/sa', required: true },
      { name: 'seatcloud-chart', url: 'https://chart.seatcloud.com/', required: false },
      { name: 'seatcloud-api', url: 'https://api.seatcloud.com/', required: false },
      { name: 'seats-io', url: 'https://cdn.seats.io/', required: false },
    ];
    let allRequiredOk = true;
    let anyReachableSeatcloud = false;

    for (const t of targets) {
      try {
        const res = await requestContext.get(t.url, { timeout: timeoutMs });
        const status = res.status();
        const ok = res.ok();
        result.targets.push({ name: t.name, url: t.url, status, ok });
        if (t.required && !ok) allRequiredOk = false;
        if (!t.required && (ok || (status >= 400 && status < 500))) anyReachableSeatcloud = true;
      } catch (e) {
        result.targets.push({ name: t.name, url: t.url, status: 0, ok: false, error: e.message || String(e) });
        if (t.required) allRequiredOk = false;
      }
    }

    result.ok = allRequiredOk && anyReachableSeatcloud;
    result.reason = result.ok ? 'ok' : result.targets.map(t => `${t.name}:${t.status || t.error}`).join('; ');
  } catch (e) {
    result.reason = e.message || String(e);
  } finally {
    try { await requestContext.dispose(); } catch {}
  }
  PROXY_TEST_CACHE.set(cacheKey, result);
  trimCache(PROXY_TEST_CACHE, PROXY_TEST_CACHE_MAX_SIZE);
  return result;
}

function getActiveProxyKeys() {
  const keys = new Set();
  for (const session of activeSessions.values()) {
    if (session.proxy && session.proxy.server) {
      keys.add(`${session.proxy.server}|${session.proxy.username || ''}|${session.proxy.password || ''}`);
    }
  }
  return keys;
}

async function assignProxiesToAccounts(accounts, opts = {}) {
  const all = proxyManager.getAll();
  const result = [];
  if (!all.length || currentProxyMode === 'off') {
    for (const a of accounts) result.push({ ...a, assignedProxy: null });
    return result;
  }

  const usedKeys = new Set([...getReservedProxyKeys(), ...getLaunchingProxyKeys(), ...getActiveProxyKeys()]);
  const requiredUnique = accounts.filter(a => a.useProxy === true).length;

  emitStatus('transfer-assigning-proxies', `Assigning unique proxies to ${accounts.length} account(s)`, {
    totalProxies: all.length,
    totalAccounts: accounts.length,
    activeProxies: getActiveProxyKeys().size,
  });

  for (const a of accounts) {
    if (a.useProxy !== true) {
      result.push({ ...a, assignedProxy: null });
      continue;
    }
    let assigned = null;
    // Prefer cached-working unused proxy
    for (const p of all) {
      const key = getProxyCacheKey(p);
      if (usedKeys.has(key)) continue;
      const cached = PROXY_TEST_CACHE.get(key);
      if (cached && cached.ok && Date.now() - cached.ts < PROXY_TEST_CACHE_TTL_MS) {
        usedKeys.add(key);
        assigned = p;
        break;
      }
    }
    if (!assigned) {
      for (const p of all) {
        const key = getProxyCacheKey(p);
        if (usedKeys.has(key)) continue;
        usedKeys.add(key);
        assigned = p;
        break;
      }
    }
    if (!assigned && currentProxyMode === 'required') {
      const err = new Error(`PROXY_EXHAUSTED: need ${requiredUnique} unique proxies but none free (total ${all.length})`);
      fileLog('ERROR', `[assignProxiesToAccounts] ${err.message}`);
      emitStatus('proxy-exhausted', err.message, { totalProxies: all.length, requiredUnique });
      throw err;
    }
    if (!assigned) {
      fileLog('WARN', `[assignProxiesToAccounts] No free proxy for ${a.username}; launching direct`);
    }
    result.push({ ...a, assignedProxy: assigned });
  }

  const assignedCount = result.filter(r => r.assignedProxy).length;
  emitStatus('transfer-proxies-assigned', `Assigned proxies to ${assignedCount}/${accounts.length} account(s)`, { assigned: assignedCount, total: accounts.length });
  return result;
}

async function findWorkingProxy(username, proxyList = null, opts = {}) {
  // Use provided list first, otherwise fall back to the global pool for backwards
  // compatibility with callers that do not pass a list.
  const all = proxyList && proxyList.length ? proxyList : proxyManager.getAll();
  if (!all.length) return { proxy: null, tested: [] };

  // Guard against runaway proxy testing: callers can cap total time and per-proxy time.
  const maxTotalMs = typeof opts.maxTotalMs === 'number' ? opts.maxTotalMs : 30_000;
  const perProxyTimeoutMs = typeof opts.perProxyTimeoutMs === 'number' ? opts.perProxyTimeoutMs : 6_000;
  const deadline = Date.now() + maxTotalMs;

  const activeKeys = getActiveProxyKeys();
  const preferred = proxyList && proxyList.length
    ? null
    : proxyManager.resolveForAccount(username, 'stable-hash');
  // Prefer proxies not currently in use by another active session.
  const unused = all.filter(p => {
    const key = `${p.server}|${p.username || ''}|${p.password || ''}`;
    return !activeKeys.has(key);
  });
  const candidates = [preferred, ...unused, ...all].filter(Boolean);
  const seen = new Set();
  const tested = [];
  for (const proxy of candidates) {
    if (!proxy || !proxy.server) continue;
    if (Date.now() > deadline) {
      tested.push({ server: proxy.server, ok: false, reason: 'proxy-search-deadline-reached' });
      fileLog('WARN', `[proxy-status] [${username}] findWorkingProxy stopped at deadline (${maxTotalMs}ms)`);
      break;
    }
    const key = `${proxy.server}|${proxy.username || ''}|${proxy.password || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const remaining = Math.max(500, deadline - Date.now());
    const test = await testProxy(proxy, Math.min(perProxyTimeoutMs, remaining));
    tested.push({ server: proxy.server, ok: test.ok, reason: test.reason });
    if (test.ok) return { proxy, tested };
  }
  return { proxy: null, tested };
}

// Find a working proxy for an account, with optional explicit list and global fallback.
async function getWorkingProxyForAccount(username, proxyList = null) {
  const preferred = proxyList || [];
  const global = proxyManager.getAll();
  const candidates = preferred.length > 0 ? [...preferred, ...global] : global;
  const seen = new Set();
  for (const proxy of candidates) {
    if (!proxy || !proxy.server) continue;
    const key = `${proxy.server}|${proxy.username || ''}|${proxy.password || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const test = await testProxy(proxy, 5000);
    if (test.ok) {
      fileLog('INFO', `[proxy-status] [${username}] Found working proxy: ${proxy.server}`);
      return { proxy, tested: true };
    }
  }
  return { proxy: null, tested: false };
}

function logProxyStatus(username, state, server = null, mode = '') {
  const serverText = server ? ` -> Using proxy server ${server}` : '';
  const message = `[proxy-status] [${username}] State: ${state}${serverText} (mode=${mode || 'global'})`;
  fileLog('INFO', message);
  try { console.log(message); } catch {}
  emitStatus('proxy-status', `Proxy state: ${state}${server ? ` (${server})` : ''}`, {
    account: username,
    proxyState: state,
    proxyServer: server || null,
    proxyMode: mode || currentProxyMode,
  });
  emitAccountUpdate(username, 'proxy-status', {
    proxyState: state,
    proxyServer: server || null,
    proxyMode: mode || currentProxyMode,
  });
}

async function resolveProxyForAccount(username, accountUseProxy = null, proxyList = null, opts = {}) {
  // Per-account explicit direct connection.
  if (accountUseProxy === false) {
    logProxyStatus(username, 'DIRECT (No Proxy)', null, 'off');
    return { proxy: null, tested: [], mode: 'off' };
  }

  const all = proxyList && proxyList.length ? proxyList : proxyManager.getAll();
  if (!all.length) {
    logProxyStatus(username, 'DIRECT (No Proxy)', null, 'off');
    return { proxy: null, tested: [], mode: 'off' };
  }

  const mode = accountUseProxy === true ? 'forced' : (currentProxyMode === 'off' ? 'off' : currentProxyMode);
  if (mode === 'off') {
    logProxyStatus(username, 'DIRECT (No Proxy)', null, 'off');
    return { proxy: null, tested: [], mode: 'off' };
  }

  const activeKeys = getActiveProxyKeys();
  const launchingKeys = getLaunchingProxyKeys();
  const reservedKeys = getReservedProxyKeys();
  const usedKeys = new Set([...activeKeys, ...launchingKeys, ...reservedKeys]);
  const preferred = proxyManager.resolveForAccount(username, 'stable-hash');
  const candidates = [preferred, ...all].filter(Boolean);
  const seen = new Set();
  for (const proxy of candidates) {
    if (!proxy || !proxy.server) continue;
    const key = getProxyCacheKey(proxy);
    if (seen.has(key)) continue;
    seen.add(key);
    if (usedKeys.has(key)) continue;
    logProxyStatus(username, 'PROXY ENABLED', proxy.server, mode);
    return { proxy, tested: [], mode };
  }
  if (mode === 'required' || mode === 'forced') {
    const err = new Error(`PROXY_REQUIRED_BUT_ALL_IN_USE for ${username}`);
    fileLog('ERROR', `[resolveProxyForAccount] ${err.message}`);
    throw err;
  }
  logProxyStatus(username, 'DIRECT (No Proxy) [fallback: no proxy available]', null, mode);
  return { proxy: null, tested: [], mode };
}

// ------------------------------------------------------------------
// Periodic proxy health monitoring
// ------------------------------------------------------------------
let proxyHealthMonitorTimer = null;
const PROXY_HEALTH_INTERVAL_MS = 60_000;

async function monitorActiveProxyHealth() {
  if (currentProxyMode === 'off') return;
  const usedProxies = new Map(); // cacheKey -> { proxy, usernames: [] }
  for (const [username, session] of activeSessions.entries()) {
    if (!session.proxy) continue;
    const key = getProxyCacheKey(session.proxy);
    const entry = usedProxies.get(key) || { proxy: session.proxy, usernames: [] };
    entry.usernames.push(username);
    usedProxies.set(key, entry);
  }

  for (const { proxy, usernames } of usedProxies.values()) {
    const key = getProxyCacheKey(proxy);
    const result = await testProxy(proxy, 2000);
    if (!result.ok) {
      PROXY_TEST_CACHE.set(key, { ...result, ts: Date.now() });
      fileLog('WARN', `[proxy-health] Proxy ${proxy.server} is unhealthy (${result.reason}); affected accounts: ${usernames.join(', ')}`);
      emitStatus('proxy-unhealthy', `البروكسي ${proxy.server} توقف عن العمل (${result.reason})`, { proxy: proxy.server, accounts: usernames, reason: result.reason });
      for (const username of usernames) {
        const session = activeSessions.get(username);
        if (session && ['idle', 'paused', 'error'].includes(session.state)) {
          // Try to find a replacement proxy for accounts that are not actively selecting.
          try {
            const resolved = await resolveProxyForAccount(username, session.proxyMode === 'forced' ? true : null);
            if (resolved.proxy && getProxyCacheKey(resolved.proxy) !== key) {
              session.proxy = resolved.proxy;
              session.proxyMode = resolved.mode;
              emitStatus('proxy-replaced', `تم استبدال البروكسي لـ ${username}: ${resolved.proxy.server}`, { account: username, proxy: resolved.proxy.server, oldProxy: proxy.server });
            }
          } catch (e) {
            fileLog('WARN', `[proxy-health] Could not replace proxy for ${username}: ${e.message}`);
          }
        } else if (session) {
          emitStatus('proxy-warning', `البروكسي لـ ${username} غير صحي لكن الحساب نشط حالياً`, { account: username, proxy: proxy.server, reason: result.reason, state: session.state });
        }
      }
    }
  }
}

function startProxyHealthMonitor() {
  if (proxyHealthMonitorTimer) return;
  proxyHealthMonitorTimer = setInterval(() => {
    monitorActiveProxyHealth().catch(err => fileLog('WARN', `[proxy-health] Monitor error: ${err.message}`));
  }, PROXY_HEALTH_INTERVAL_MS);
  proxyHealthMonitorTimer.unref?.();
}

function detectSharedHoldTokens(accounts, label = 'booking') {
  if (!Array.isArray(accounts)) return [];
  const tokenMap = new Map();
  for (const a of accounts) {
    const token = String(a?.holdToken || a?.token || '').trim();
    if (!token || token.length < 8) continue;
    const list = tokenMap.get(token) || [];
    list.push(a?.username || a?.loginEmail || 'unknown');
    tokenMap.set(token, list);
  }
  const collisions = [];
  for (const [token, users] of tokenMap.entries()) {
    if (users.length > 1) {
      const preview = `${token.slice(0, 8)}...${token.slice(-4)}`;
      collisions.push({ token: preview, users });
      fileLog('WARN', `[${label}] Shared hold token detected between ${users.length} account(s): ${users.join(', ')} token=${preview}`);
      emitStatus('warning', `تنبيه: عدة حسابات تشارك نفس hold token (${preview}): ${users.join(', ')}. هذا يسبب تضارب و فقدان المقاعد.`, { users, token: preview, type: 'shared-hold-token' });
    }
  }
  return collisions;
}

// ------------------------------------------------------------------
// Per-browser fingerprint randomization
// ------------------------------------------------------------------
const SESSION_DIR = path.join(__dirname, 'sessions');
fs.mkdirSync(SESSION_DIR, { recursive: true });
const SESSION_MAX_AGE_MS = 6 * 60 * 60 * 1000; // reuse logins for up to 6 hours

// Hard ceiling for seats one account can hold. The SeatCloud backend allows 30
// holds per token; never ask for more than that, regardless of UI input.
const MAX_HELD_SEATS = 30;

// Speed / sniper tuning. Fast real-time defaults; UI can push to turbo.
const DEFAULT_SPEED_SETTINGS = {
  fastMode: true,
  sniperEnabled: true,
  sniperIntervalMs: 50,
  sniperBurstGapMs: 0,
  sniperTimeoutMs: 1000,
  delayMultiplier: 0.3,
};
let currentSpeedSettings = { ...DEFAULT_SPEED_SETTINGS };
function getSpeedSettings(overrides = {}) {
  const s = { ...currentSpeedSettings, ...overrides };
  // Clamp to sane ranges to avoid SeatCloud 429 / bans.
  s.sniperIntervalMs = Math.max(30, Math.min(10000, parseInt(s.sniperIntervalMs, 10) || DEFAULT_SPEED_SETTINGS.sniperIntervalMs));
  s.sniperBurstGapMs = Math.max(0, Math.min(50, parseInt(s.sniperBurstGapMs, 10) || DEFAULT_SPEED_SETTINGS.sniperBurstGapMs));
  s.sniperTimeoutMs = Math.max(500, Math.min(15000, parseInt(s.sniperTimeoutMs, 10) || DEFAULT_SPEED_SETTINGS.sniperTimeoutMs));
  s.delayMultiplier = Math.max(0.1, Math.min(3.0, parseFloat(s.delayMultiplier) || DEFAULT_SPEED_SETTINGS.delayMultiplier));
  return s;
}

const IPHONE_MODELS = [
  { name: 'iPhone 14 Pro', width: 393, height: 852, dpr: 3 },
  { name: 'iPhone 14 Pro Max', width: 430, height: 932, dpr: 3 },
  { name: 'iPhone 13 Pro', width: 390, height: 844, dpr: 3 },
  { name: 'iPhone 13 Pro Max', width: 428, height: 926, dpr: 3 },
  { name: 'iPhone 12 Pro', width: 390, height: 844, dpr: 3 },
  { name: 'iPhone 12 Pro Max', width: 428, height: 926, dpr: 3 },
  { name: 'iPhone 11 Pro', width: 375, height: 812, dpr: 3 },
  { name: 'iPhone 11 Pro Max', width: 414, height: 896, dpr: 3 },
  { name: 'iPhone SE (3rd gen)', width: 375, height: 667, dpr: 2 },
];

const ANDROID_MODELS = [
  { name: 'Samsung Galaxy S23', width: 384, height: 824, dpr: 3 },
  { name: 'Samsung Galaxy S22 Ultra', width: 412, height: 915, dpr: 3.5 },
  { name: 'Google Pixel 7 Pro', width: 412, height: 915, dpr: 3.5 },
  { name: 'Google Pixel 6', width: 412, height: 832, dpr: 3 },
  { name: 'Xiaomi 13 Pro', width: 390, height: 844, dpr: 3 },
  { name: 'OnePlus 11', width: 412, height: 915, dpr: 3.5 },
];

const IPAD_MODELS = [
  { name: 'iPad Pro 12.9"', width: 1024, height: 1366, dpr: 2 },
  { name: 'iPad Air', width: 820, height: 1180, dpr: 2 },
  { name: 'iPad mini', width: 744, height: 1133, dpr: 2 },
];

const DESKTOP_PROFILES = [
  { name: 'Windows Chrome', width: 1920, height: 1080, dpr: 1, platform: 'Win32', os: 'Windows NT 10.0; Win64; x64', vendor: 'Google Inc.', browser: 'Chrome' },
  { name: 'Windows Edge', width: 1920, height: 1080, dpr: 1, platform: 'Win32', os: 'Windows NT 10.0; Win64; x64', vendor: 'Microsoft Corporation', browser: 'Edg' },
  { name: 'macOS Safari', width: 1680, height: 1050, dpr: 2, platform: 'MacIntel', os: 'Macintosh; Intel Mac OS X 10_15_7', vendor: 'Apple Computer, Inc.', browser: 'Safari' },
  { name: 'macOS Chrome', width: 1680, height: 1050, dpr: 2, platform: 'MacIntel', os: 'Macintosh; Intel Mac OS X 10_15_7', vendor: 'Google Inc.', browser: 'Chrome' },
];

const TIMEZONES = ['Asia/Riyadh', 'Asia/Dubai', 'Asia/Bahrain', 'Africa/Cairo', 'Europe/Istanbul', 'Asia/Kuwait', 'Asia/Qatar'];
const LANG_SETS = [
  ['ar-SA', 'ar', 'en-US', 'en'],
  ['ar-SA', 'en-US', 'en'],
  ['ar', 'en-US', 'en'],
  ['en-US', 'en'],
  ['en-GB', 'en'],
  ['ar-AE', 'ar', 'en-US', 'en'],
];

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pickOne(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomDeviceProfile() {
  const category = pickOne(['iphone', 'android', 'ipad', 'desktop']);
  const langSet = pickOne(LANG_SETS);
  const timezoneId = pickOne(TIMEZONES);
  const colorScheme = pickOne(['dark', 'light']);
  const memory = pickOne([4, 6, 8, 12, 16]);
  const cores = pickOne([4, 6, 8]);
  return buildDeviceProfile(category, langSet, timezoneId, colorScheme, memory, cores);
}

/**
 * Returns a desktop profile that is known to load the SeatCloud chart reliably.
 * Mobile viewports are much more likely to hide or fail to render the seat chart,
 * which is the #1 client complaint ("الشارت مابيتحملش"). Use this for booking sessions.
 */
function randomChartFriendlyProfile() {
  const langSet = pickOne(LANG_SETS);
  const timezoneId = pickOne(TIMEZONES);
  const colorScheme = pickOne(['dark', 'light']);
  const memory = pickOne([4, 6, 8, 12, 16]);
  const cores = pickOne([4, 6, 8]);
  return buildDeviceProfile('desktop', langSet, timezoneId, colorScheme, memory, cores);
}

function buildDeviceProfile(category, langSet, timezoneId, colorScheme, memory, cores) {

  if (category === 'iphone') {
    const model = pickOne(IPHONE_MODELS);
    const iosMajor = randomInt(15, 17);
    const iosMinor = randomInt(0, 6);
    const safariMajor = randomInt(604, 605);
    const webkit = randomInt(600, 605);
    const ua = `Mozilla/5.0 (iPhone; CPU iPhone OS ${iosMajor}_${iosMinor} like Mac OS X) AppleWebKit/${webkit}.1.15 (KHTML, like Gecko) Version/${iosMajor}.0 Mobile/15E148 Safari/${safariMajor}.1.15`;
    return {
      ...model,
      userAgent: ua,
      deviceMemory: memory,
      hardwareConcurrency: cores,
      platform: 'iPhone',
      languages: langSet,
      timezoneId,
      colorScheme,
      isMobile: true,
      hasTouch: true,
      vendor: 'Apple Computer, Inc.',
      browser: 'Safari',
      secChUa: `"Safari/${iosMajor}.0";v="${iosMajor}", "Mobile";v="1"`,
    };
  }

  if (category === 'android') {
    const model = pickOne(ANDROID_MODELS);
    const androidVer = randomInt(11, 14);
    const chromeMajor = randomInt(110, 124);
    const ua = `Mozilla/5.0 (Linux; Android ${androidVer}; ${model.name.replace(/\s+/g, '_')}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeMajor}.0.0.0 Mobile Safari/537.36`;
    return {
      ...model,
      userAgent: ua,
      deviceMemory: memory,
      hardwareConcurrency: cores,
      platform: 'Linux armv8l',
      languages: langSet,
      timezoneId,
      colorScheme,
      isMobile: true,
      hasTouch: true,
      vendor: 'Google Inc.',
      browser: 'Chrome',
      secChUa: `"Chromium";v="${chromeMajor}", "Android";v="${androidVer}", "Mobile";v="1"`,
    };
  }

  if (category === 'ipad') {
    const model = pickOne(IPAD_MODELS);
    const iosMajor = randomInt(15, 17);
    const iosMinor = randomInt(0, 6);
    const safariMajor = randomInt(604, 605);
    const webkit = randomInt(600, 605);
    const ua = `Mozilla/5.0 (iPad; CPU OS ${iosMajor}_${iosMinor} like Mac OS X) AppleWebKit/${webkit}.1.15 (KHTML, like Gecko) Version/${iosMajor}.0 Mobile/15E148 Safari/${safariMajor}.1.15`;
    return {
      ...model,
      userAgent: ua,
      deviceMemory: memory,
      hardwareConcurrency: cores,
      platform: 'iPad',
      languages: langSet,
      timezoneId,
      colorScheme,
      isMobile: true,
      hasTouch: true,
      vendor: 'Apple Computer, Inc.',
      browser: 'Safari',
      secChUa: `"Safari/${iosMajor}.0";v="${iosMajor}", "Mobile";v="1"`,
    };
  }

  // desktop
  const model = pickOne(DESKTOP_PROFILES);
  const chromeMajor = randomInt(110, 124);
  const safariMajor = randomInt(605, 606);
  const major = model.browser === 'Safari' ? safariMajor : chromeMajor;
  const version = model.browser === 'Safari' ? `${major}.1.15` : `${major}.0.0.0`;
  const engine = model.browser === 'Safari' ? 'AppleWebKit/605.1.15' : 'AppleWebKit/537.36';
  const ua = `Mozilla/5.0 (${model.os}) ${engine} (KHTML, like Gecko) ${model.browser}/${version} Safari/${model.browser === 'Safari' ? safariMajor + '.1.15' : '537.36'}`;
  return {
    name: model.name,
    width: model.width,
    height: model.height,
    dpr: model.dpr,
    userAgent: ua,
    deviceMemory: memory,
    hardwareConcurrency: cores,
    platform: model.platform,
    languages: langSet,
    timezoneId,
    colorScheme,
    isMobile: false,
    hasTouch: false,
    vendor: model.vendor,
    browser: model.browser,
    secChUa: model.browser === 'Chrome'
      ? `"Chromium";v="${chromeMajor}", "Not.A/Brand";v="24", "Google Chrome";v="${chromeMajor}"`
      : model.browser === 'Edg'
        ? `"Chromium";v="${chromeMajor}", "Microsoft Edge";v="${chromeMajor}", "Not.A/Brand";v="24"`
        : `"Safari/${safariMajor}.0";v="${safariMajor}"`,
  };
}

function generateStealthScript(profile) {
  const langJson = JSON.stringify(profile.languages);
  const maxTouchPoints = profile.isMobile ? (profile.platform === 'iPad' ? 5 : 5) : 0;
  return `
(() => {
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  const originalQuery = window.navigator.permissions.query;
  window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications'
      ? Promise.resolve({ state: Notification.permission })
      : originalQuery(parameters)
  );
  Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
  Object.defineProperty(navigator, 'mimeTypes', { get: () => [1, 2, 3, 4, 5] });
  window.chrome = window.chrome || {};
  window.chrome.runtime = window.chrome.runtime || {};
  Object.defineProperty(navigator, 'languages', { get: () => ${langJson} });
  Object.defineProperty(navigator, 'language', { get: () => ${JSON.stringify(profile.languages[0])} });
  Object.defineProperty(navigator, 'platform', { get: () => ${JSON.stringify(profile.platform)} });
  Object.defineProperty(navigator, 'deviceMemory', { get: () => ${profile.deviceMemory} });
  Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => ${profile.hardwareConcurrency} });
  Object.defineProperty(navigator, 'maxTouchPoints', { get: () => ${maxTouchPoints} });
  Object.defineProperty(navigator, 'vendor', { get: () => ${JSON.stringify(profile.vendor || '')} });
  Object.defineProperty(screen, 'width', { get: () => ${profile.width} });
  Object.defineProperty(screen, 'height', { get: () => ${profile.height} });
  Object.defineProperty(screen, 'availWidth', { get: () => ${profile.width} });
  Object.defineProperty(screen, 'availHeight', { get: () => ${profile.height - randomInt(20, 60)} });
  Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
  Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
  Object.defineProperty(window, 'devicePixelRatio', { get: () => ${profile.dpr} });
  try {
    Object.defineProperty(window.screen, 'orientation', { get: () => ({ angle: 0, type: 'portrait-primary' }) });
  } catch {}

  // Canvas/WebGL noise (subtle per-profile) so each browser looks different
  const noise = ${randomInt(1, 7)};
  const origGetContext = HTMLCanvasElement.prototype.getContext;
  HTMLCanvasElement.prototype.getContext = function(type, ...args) {
    const ctx = origGetContext.call(this, type, ...args);
    if (ctx && (type === '2d' || type === 'webgl' || type === 'webgl2')) {
      try {
        const fillText = ctx.fillText;
        ctx.fillText = function(...fa) { return fillText.apply(this, fa); };
      } catch {}
    }
    return ctx;
  };
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(...args) {
    const url = origToDataURL.apply(this, args);
    if (url.length > 100) return url.slice(0, -noise) + String.fromCharCode(65 + noise);
    return url;
  };
})();
`;}

function sessionFilePath(username) {
  const safe = username.replace(/[^a-z0-9@._-]/gi, '_');
  return path.join(SESSION_DIR, `${safe}.json`);
}

function sessionFileExists(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function sessionAgeInfo(filePath) {
  try {
    const stat = fs.statSync(filePath);
    const ageMs = Date.now() - stat.mtimeMs;
    return { ageMs, mtime: stat.mtime.toISOString() };
  } catch {
    return null;
  }
}

function getCookie(state, name, domainIncludes = '') {
  if (!state || !Array.isArray(state.cookies)) return null;
  return state.cookies.find(c =>
    c.name === name &&
    (!domainIncludes || c.domain.includes(domainIncludes))
  ) || null;
}

function getOriginStorage(state, origin, name) {
  if (!state || !Array.isArray(state.origins)) return null;
  const o = state.origins.find(x => x.origin === origin);
  if (!o || !Array.isArray(o.localStorage)) return null;
  const item = o.localStorage.find(x => x.name === name);
  return item ? item.value : null;
}

function decodeJwtPayload(token) {
  try {
    const parts = String(token).split('.');
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], 'base64').toString('utf8');
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

function extractUserFromSession(state) {
  // 1. Prefer explicit localStorage user_data
  try {
    const raw = getOriginStorage(state, 'https://webook.com', 'user_data');
    if (raw) return JSON.parse(raw);
  } catch {}

  // 2. Decode access token for user id
  const tokenCookie = getCookie(state, 'token', 'webook.com');
  if (tokenCookie && tokenCookie.value) {
    const payload = decodeJwtPayload(tokenCookie.value);
    if (payload && payload.sub) {
      return { user_id: payload.sub, sub: payload.sub, fromToken: true };
    }
  }

  return null;
}

function isTokenExpired(state, bufferMs = 120000) {
  // Check explicit token_expires_in cookie first
  const expiresInCookie = getCookie(state, 'token_expires_in', 'webook.com');
  if (expiresInCookie && expiresInCookie.value) {
    const ts = parseInt(expiresInCookie.value, 10);
    if (!isNaN(ts)) {
      return Date.now() > ts + bufferMs;
    }
  }

  // Fall back to token cookie expiry / JWT exp
  const tokenCookie = getCookie(state, 'token', 'webook.com');
  if (tokenCookie) {
    if (tokenCookie.expires && tokenCookie.expires > 0) {
      return Date.now() > (tokenCookie.expires * 1000) + bufferMs;
    }
    const payload = decodeJwtPayload(tokenCookie.value);
    if (payload && payload.exp) {
      return Date.now() > (payload.exp * 1000) + bufferMs;
    }
  }

  // No token found = treat as expired so we go through login
  return true;
}

function hasRefreshToken(state) {
  const c = getCookie(state, 'refresh_token', 'webook.com');
  return !!(c && c.value);
}

function loadSessionState(username) {
  const filePath = sessionFilePath(username);
  if (!sessionFileExists(filePath)) return null;
  try {
    const data = fs.readFileSync(filePath, 'utf8');
    const state = JSON.parse(data);
    if (!state || !Array.isArray(state.origins)) return null;

    const user = extractUserFromSession(state);
    const expired = isTokenExpired(state);
    const age = sessionAgeInfo(filePath);

    if (expired) {
      if (hasRefreshToken(state)) {
        fileLog('INFO', `Session for ${username} token expired but refresh_token present; will attempt refresh. age=${JSON.stringify(age)}`);
        state.__kimiko = { needsRefresh: true, user, age };
        return state;
      }
      fileLog('INFO', `Session for ${username} token expired and no refresh_token; will re-login. age=${JSON.stringify(age)}`);
      return null;
    }

    state.__kimiko = { valid: true, user, age };
    fileLog('INFO', `Session loaded for ${username}: user=${user ? user.email || user.user_id : 'unknown'}, age=${JSON.stringify(age)}`);
    return state;
  } catch (e) {
    fileLog('WARN', `Failed to load session state for ${username}: ${e.message}`);
  }
  return null;
}

async function saveSessionState(username, context, extra = {}) {
  try {
    const filePath = sessionFilePath(username);
    const state = await context.storageState();
    const user = extractUserFromSession(state);
    state.__kimiko = {
      savedAt: new Date().toISOString(),
      savedBy: extra.source || 'unknown',
      user: user ? { user_id: user.user_id, email: user.email, first_name: user.first_name, last_name: user.last_name } : null,
      tokenExpiresIn: isTokenExpired(state) ? 'expired' : 'valid',
      note: extra.note || '',
    };
    fs.writeFileSync(filePath, JSON.stringify(state, null, 2), 'utf8');
    fileLog('INFO', `Session state saved for ${username}: ${filePath} (user=${user ? user.email || user.user_id : 'unknown'}, token=${state.__kimiko.tokenExpiresIn})`);
  } catch (e) {
    fileLog('WARN', `Failed to save session state for ${username}: ${e.message}`);
  }
}

function deleteSessionFile(username) {
  try {
    const filePath = sessionFilePath(username);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      fileLog('INFO', `Deleted session file for ${username}: ${filePath}`);
    }
  } catch (e) {
    fileLog('WARN', `Failed to delete session file for ${username}: ${e.message}`);
  }
}

// ------------------------------------------------------------------
// Full session cache (cookies + localStorage + sessionStorage + storageState)
// ------------------------------------------------------------------

function sessionCacheFilePath(username) {
  const safeUsername = String(username).replace(/[@.]/g, '_');
  return path.join(SESSION_CACHE_DIR, `${safeUsername}.json`);
}

async function harvestFullSession(page, context, username) {
  fileLog('INFO', `[session-harvest] Extracting full session for ${username}`);
  try {
    const cookies = await context.cookies();
    const localStorage = await page.evaluate(() => {
      const data = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        try { data[key] = localStorage.getItem(key); } catch (e) {}
      }
      return data;
    });
    const sessionStorage = await page.evaluate(() => {
      const data = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        try { data[key] = sessionStorage.getItem(key); } catch (e) {}
      }
      return data;
    });
    const storageState = await context.storageState();
    const userAgent = await page.evaluate(() => navigator.userAgent).catch(() => '');
    const viewport = page.viewportSize() || { width: 1366, height: 768 };

    const fullSession = {
      username,
      timestamp: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000,
      cookies,
      localStorage,
      sessionStorage,
      storageState,
      userAgent,
      viewport,
      url: page.url(),
    };
    await saveSessionToCache(username, fullSession);
    fileLog('INFO', `[session-harvest] ✅ Full session saved for ${username} (${cookies.length} cookies, ${Object.keys(localStorage).length} LS, ${Object.keys(sessionStorage).length} SS)`);
    return fullSession;
  } catch (err) {
    fileLog('ERROR', `[session-harvest] Failed to extract session for ${username}: ${err.message}`);
    throw err;
  }
}

async function saveSessionToCache(username, session) {
  const filePath = sessionCacheFilePath(username);
  await fs.promises.writeFile(filePath, JSON.stringify(session, null, 2), 'utf8');
}

async function loadSessionFromCache(username) {
  const filePath = sessionCacheFilePath(username);
  try {
    const data = await fs.promises.readFile(filePath, 'utf8');
    const session = JSON.parse(data);
    if (session.expiresAt && session.expiresAt < Date.now()) {
      fileLog('WARN', `[session-cache] Session expired for ${username}`);
      return null;
    }
    return session;
  } catch (err) {
    return null;
  }
}

function validateSession(session) {
  if (!session || !session.storageState) return false;
  const hasAccessToken = !!(session.localStorage?.accessToken ||
    session.sessionStorage?.accessToken ||
    session.cookies?.some(c => c.name.includes('session') || c.name.includes('token')));
  if (!hasAccessToken) {
    fileLog('WARN', `[session-validate] No access token found in session for ${session.username}`);
    return false;
  }
  return true;
}

const SESSION_HARVEST_COOLDOWN_MS = 5 * 60 * 1000;
const lastHarvestTime = new Map();

async function autoHarvestSession(page, context, username) {
  const last = lastHarvestTime.get(username) || 0;
  if (Date.now() - last < SESSION_HARVEST_COOLDOWN_MS) {
    fileLog('INFO', `[session-harvest] Skipping auto-harvest for ${username}; cooldown active`);
    return null;
  }
  try {
    const fullSession = await harvestFullSession(page, context, username);
    lastHarvestTime.set(username, Date.now());
    emitStatus('session-harvested', 'Session auto-harvested after login', {
      account: username,
      cookiesCount: fullSession.cookies.length,
      localStorageCount: Object.keys(fullSession.localStorage || {}).length,
      sessionStorageCount: Object.keys(fullSession.sessionStorage || {}).length,
    });
    return fullSession;
  } catch (err) {
    fileLog('WARN', `[session-harvest] Auto-harvest failed for ${username}: ${err.message}`);
    return null;
  }
}

async function createSessionWithContext(fullSession, options = {}) {
  const { targetUrl, proxy } = options;
  const username = fullSession.username;
  fileLog('INFO', `[session-inject] Creating new context for ${username} with harvested session`);

  try {
    const browser = await ensureBrowser();
    const contextOptions = {
      storageState: fullSession.storageState,
      userAgent: fullSession.userAgent || randomChartFriendlyProfile().userAgent,
      viewport: fullSession.viewport || { width: 1366, height: 768 },
      locale: 'ar-SA',
      timezoneId: 'Asia/Riyadh',
      geolocation: { latitude: 24.7136, longitude: 46.6753 },
      permissions: ['geolocation', 'storage-access'],
    };
    if (proxy && proxy.server) {
      contextOptions.proxy = {
        server: proxy.server,
        username: proxy.username,
        password: proxy.password,
      };
    }

    const context = await browser.newContext(contextOptions);
    allContexts.add(context);
    context.on('close', () => allContexts.delete(context));

    // Inject stealth anti-detection script into every page created in this context.
    try {
      const stealthProfile = {
        userAgent: contextOptions.userAgent,
        languages: ['ar-SA', 'ar', 'en-US', 'en'],
        isMobile: false,
        platform: 'Windows',
      };
      const stealthScript = generateStealthScript(stealthProfile);
      await context.addInitScript(stealthScript);
    } catch (stealthErr) {
      fileLog('WARN', `[session-inject] Stealth init script failed for ${username}: ${stealthErr.message}`);
    }

    const page = await context.newPage();

    // Manual fallback: inject localStorage and sessionStorage items if Playwright
    // storageState did not restore them (some sites use JS-only storage).
    const hasLs = fullSession.localStorage && Object.keys(fullSession.localStorage).length > 0;
    const hasSs = fullSession.sessionStorage && Object.keys(fullSession.sessionStorage).length > 0;
    if (hasLs || hasSs) {
      const injectionUrl = targetUrl || fullSession.url || 'https://webook.com/';
      await page.goto(injectionUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      if (hasLs) {
        await page.evaluate((lsData) => {
          Object.entries(lsData).forEach(([key, value]) => {
            try { localStorage.setItem(key, value); } catch (e) {}
          });
        }, fullSession.localStorage);
      }
      if (hasSs) {
        await page.evaluate((ssData) => {
          Object.entries(ssData).forEach(([key, value]) => {
            try { sessionStorage.setItem(key, value); } catch (e) {}
          });
        }, fullSession.sessionStorage);
      }
      fileLog('INFO', `[session-inject] Injected ${Object.keys(fullSession.localStorage || {}).length} LS + ${Object.keys(fullSession.sessionStorage || {}).length} SS items for ${username}`);
    }

    await page.reload({ waitUntil: 'domcontentloaded', timeout: 30000 });
    const isValid = await validateInjectedSession(page, username);
    fileLog('INFO', `[session-inject] Context ready for ${username}: isValid=${isValid}`);
    return { context, page, isValid };
  } catch (err) {
    fileLog('ERROR', `[session-inject] Failed to create context for ${username}: ${err.message}`);
    throw err;
  }
}

async function validateInjectedSession(page, username) {
  try {
    await page.waitForTimeout(1500);
    const { isLoggedIn, hasToken } = await page.evaluate(() => {
      const userElements = document.querySelectorAll('[class*="user"], [class*="profile"], [class*="avatar"], [data-testid*="user"]');
      const loginButtons = document.querySelectorAll('[class*="login"], [class*="signin"]');
      return {
        isLoggedIn: userElements.length > 0 && loginButtons.length === 0,
        hasToken: !!(localStorage.getItem('accessToken') || localStorage.getItem('token') || localStorage.getItem('auth')),
      };
    });
    const isValid = isLoggedIn || hasToken;
    fileLog('INFO', `[session-validate] ${username}: isLoggedIn=${isLoggedIn}, hasToken=${hasToken}, isValid=${isValid}`);
    return isValid;
  } catch (err) {
    fileLog('ERROR', `[session-validate] Validation error for ${username}: ${err.message}`);
    return false;
  }
}

// ------------------------------------------------------------------
// Transfer Engine v3 - full session harvesting + holdToken migration
// ------------------------------------------------------------------

async function extractHoldToken(page) {
  try {
    const token = await page.evaluate(() => {
      return sessionStorage.getItem('holdToken') ||
             sessionStorage.getItem('seatHoldToken') ||
             sessionStorage.getItem('sc_hold_token') ||
             localStorage.getItem('holdToken') ||
             localStorage.getItem('seatHoldToken');
    });
    if (token) return token;
    // Fallback: try to read from chart state if available.
    const frame = await findChartFrame(page, null, { emit: false });
    if (frame) {
      const chartToken = await frame.evaluate(() => {
        return window.holdToken || window.__kimikoForcedHoldToken || null;
      }).catch(() => null);
      if (chartToken) return chartToken;
    }
    return null;
  } catch (err) {
    return null;
  }
}

async function navigateToBookingPage(page, url, username) {
  try {
    const normalized = String(url).replace(/\/$/, '');
    const bookUrl = normalized.endsWith('/book') ? normalized : `${normalized}/book`;
    await page.goto(bookUrl, { waitUntil: 'domcontentloaded', timeout: 45000 });
    await page.waitForSelector('iframe[src*="seatcloud"]', { timeout: 30000 });
    fileLog('INFO', `[navigate-v3] ${username} reached booking page with chart`);
    return true;
  } catch (err) {
    throw new Error(`Navigation failed: ${err.message}`);
  }
}

async function performHoldMigration(frame, seats, holdToken, username) {
  try {
    const result = await frame.evaluate(async (seatsData, token) => {
      if (typeof window.seatingChart !== 'undefined') {
        try {
          await window.seatingChart.selectObjects(seatsData);
          const currentHold = await window.seatingChart.getHoldToken();
          return { success: true, holdToken: currentHold || token, selectedSeats: seatsData };
        } catch (err) {
          return { success: false, error: err.message };
        }
      }
      return { success: false, error: 'seatingChart not available' };
    }, seats, holdToken);

    if (result.success) {
      return { success: true, transferredCount: seats.length, failedCount: 0, holdToken: result.holdToken };
    }
    throw new Error(result.error);
  } catch (err) {
    fileLog('WARN', `[hold-migration] ${username}: ${err.message}`);
    return { success: false, transferredCount: 0, failedCount: seats.length, error: err.message };
  }
}

async function releaseSeatsFromSource(page, seats) {
  try {
    await page.evaluate((seatsData) => {
      if (typeof window.seatingChart !== 'undefined') {
        try { window.seatingChart.deselectObjects(seatsData); } catch (e) {}
      }
    }, seats);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function holdSeatsInDestination(page, seats) {
  try {
    const chartFrame = await page.$('iframe[src*="seatcloud"]');
    if (!chartFrame) return { success: false, error: 'Chart iframe not found' };
    const frame = await chartFrame.contentFrame();
    if (!frame) return { success: false, error: 'Could not access chart iframe' };
    const result = await frame.evaluate(async (seatsData) => {
      if (typeof window.seatingChart !== 'undefined') {
        try {
          await window.seatingChart.selectObjects(seatsData);
          return { success: true, heldSeats: seatsData };
        } catch (err) {
          return { success: false, error: err.message };
        }
      }
      return { success: false, error: 'seatingChart not available' };
    }, seats);
    return result;
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function performFallbackTransfer(sourcePage, destPage, seats, username) {
  fileLog('INFO', `[fallback-v3] ${username}: falling back to traditional release+hold`);
  try {
    const [releaseResult, holdResult] = await Promise.all([
      releaseSeatsFromSource(sourcePage, seats),
      new Promise((resolve) => {
        setTimeout(async () => {
          const result = await holdSeatsInDestination(destPage, seats);
          resolve(result);
        }, 5);
      }),
    ]);
    if (holdResult.success) {
      return { success: true, transferredCount: holdResult.heldSeats?.length || 0, failedCount: seats.length - (holdResult.heldSeats?.length || 0) };
    }
    return { success: false, transferredCount: 0, failedCount: seats.length, error: holdResult.error || 'Hold failed' };
  } catch (err) {
    return { success: false, transferredCount: 0, failedCount: seats.length, error: err.message };
  }
}

async function performAtomicTransferV3(sourcePage, destPage, seats, sourceHoldToken, username) {
  fileLog('INFO', `[atomic-v3] Starting atomic transfer of ${seats.length} seats to ${username}`);
  const startTime = Date.now();
  try {
    if (!sourceHoldToken) {
      fileLog('WARN', `[atomic-v3] No source holdToken for ${username}, falling back`);
      return await performFallbackTransfer(sourcePage, destPage, seats, username);
    }

    await destPage.evaluate((token) => {
      sessionStorage.setItem('holdToken', token);
      sessionStorage.setItem('seatHoldToken', token);
      sessionStorage.setItem('sc_hold_token', token);
      localStorage.setItem('holdToken', token);
      localStorage.setItem('seatHoldToken', token);
    }, sourceHoldToken);

    await destPage.reload({ waitUntil: 'domcontentloaded', timeout: 30000 });
    await destPage.waitForSelector('iframe[src*="seatcloud"]', { timeout: 20000 });

    const chartFrame = await destPage.$('iframe[src*="seatcloud"]');
    if (!chartFrame) throw new Error('Chart iframe not found');
    const frame = await chartFrame.contentFrame();

    emitStatus('transfer-batch-start', `Atomic transfer to ${username}`, { to: username, seats });
    const result = await performHoldMigration(frame, seats, sourceHoldToken, username);
    const elapsed = Date.now() - startTime;
    fileLog('INFO', `[atomic-v3] ${username}: completed in ${elapsed}ms, success=${result.success}`);
    emitStatus('transfer-batch-complete', `Atomic transfer to ${username}`, { to: username, held: result.success ? seats : [], missing: result.success ? [] : seats });

    if (!result.success) {
      return await performFallbackTransfer(sourcePage, destPage, seats, username);
    }
    return result;
  } catch (err) {
    fileLog('ERROR', `[atomic-v3] ${username}: ${err.message}`);
    return await performFallbackTransfer(sourcePage, destPage, seats, username);
  }
}

async function transferEngineV3(plan, options) {
  const { url, targetSections, maxConcurrency: concurrency = 3 } = options;
  const startTime = Date.now();
  const masterUsernames = Array.isArray(plan.masterUsernames) ? plan.masterUsernames : [];
  const sourceUsername = masterUsernames[0];

  fileLog('INFO', `[transfer-v3] ═══ Starting Transfer Engine v3 ═══`);
  fileLog('INFO', `[transfer-v3] Destinations: ${plan.destinations?.length || 0}`);

  // Phase 1: Load sessions from cache.
  const sessionMap = new Map();
  const sourceSession = sourceUsername ? await loadSessionFromCache(sourceUsername) : null;
  if (!sourceSession) throw new Error(`No cached session for source: ${sourceUsername}`);
  sessionMap.set(sourceUsername, sourceSession);

  for (const dest of plan.destinations || []) {
    const destSession = await loadSessionFromCache(dest.username);
    if (destSession) {
      sessionMap.set(dest.username, destSession);
    } else {
      fileLog('WARN', `[transfer-v3] No cached session for ${dest.username}`);
    }
  }

  // Phase 2: Create destination contexts in parallel (bounded concurrency).
  const readyContexts = [];
  const destEntries = Array.from(sessionMap.entries()).filter(([u]) => u !== sourceUsername);
  const limit = Math.max(1, concurrency || 3);
  for (let i = 0; i < destEntries.length; i += limit) {
    const batch = destEntries.slice(i, i + limit);
    const batchResults = await Promise.all(batch.map(async ([username, fullSession]) => {
      emitStatus('destination-preparing', `Preparing destination ${username} via session injection`, {
        account: username,
        totalDestinations: destEntries.length,
        currentIndex: i + batch.indexOf([username, fullSession]) + 1,
      });
      try {
        const { context, page, isValid } = await createSessionWithContext(fullSession, { targetUrl: url });
        if (!isValid) {
          fileLog('WARN', `[transfer-v3] Context invalid for ${username}`);
          try { await context.close(); } catch {}
          return null;
        }
        return { username, context, page, fullSession };
      } catch (err) {
        fileLog('ERROR', `[transfer-v3] Context creation failed for ${username}: ${err.message}`);
        return null;
      }
    }));
    for (const r of batchResults) if (r) readyContexts.push(r);
  }

  if (readyContexts.length === 0) throw new Error('No destination contexts ready');

  // Phase 3: Navigate all contexts to booking page in parallel.
  await Promise.all(readyContexts.map(({ page, username }) =>
    navigateToBookingPage(page, url, username).catch(err => {
      fileLog('ERROR', `[transfer-v3] Navigation failed for ${username}: ${err.message}`);
      return null;
    })
  ));

  // Phase 4: Extract source holdToken and perform atomic transfers in parallel.
  const sourcePage = activeSessions.get(sourceUsername)?.page;
  if (!sourcePage) throw new Error('Source page not found in active sessions');
  const sourceHoldToken = await extractHoldToken(sourcePage);
  fileLog('INFO', `[transfer-v3] Source holdToken: ${sourceHoldToken ? sourceHoldToken.slice(0, 12) + '...' : 'none'}`);

  const transferResults = [];
  let totalTransferred = 0;
  let totalFailed = 0;

  const transferPromises = readyContexts.map(async ({ page, username }) => {
    const destPlan = (plan.destinations || []).find(d => d.username === username);
    if (!destPlan || !destPlan.assignedSeats?.length) return null;

    emitStatus('destination-ready', `Destination ${username} ready for atomic transfer`, { account: username });
    const result = await performAtomicTransferV3(sourcePage, page, destPlan.assignedSeats, sourceHoldToken, username);
    transferResults.push({ destination: username, ...result });
    if (result.success) {
      totalTransferred += result.transferredCount || 0;
    } else {
      totalFailed += result.failedCount || destPlan.assignedSeats.length;
    }
    return result;
  });

  await Promise.all(transferPromises);

  // Phase 5: Cleanup (contexts are kept open intentionally for possible reuse).
  const elapsed = Date.now() - startTime;
  fileLog('INFO', `[transfer-v3] ═══ Complete: ${totalTransferred} transferred, ${totalFailed} failed, ${elapsed}ms ═══`);

  emitStatus('transfer-done', {
    totalTransferred,
    totalFailed,
    details: transferResults,
    elapsedMs: elapsed,
  });

  return {
    success: totalFailed === 0,
    totalTransferred,
    totalFailed,
    details: transferResults,
    elapsedMs: elapsed,
  };
}

function touchHoldToken(session, token, ttlMinutes = HOLD_TOKEN_EXTENSION_MINUTES, serverExpiresAt = null) {
  if (!session) return;
  session.holdToken = token || session.holdToken || null;
  if (session.holdToken) {
    session.holdTokenCreatedAt = session.holdTokenCreatedAt || Date.now();
    session.holdTokenFirstCreatedAt = session.holdTokenFirstCreatedAt || session.holdTokenCreatedAt;
    if (serverExpiresAt) {
      session.holdTokenExpiresAt = new Date(serverExpiresAt).getTime();
    } else {
      session.holdTokenExpiresAt = Date.now() + Math.max(1, ttlMinutes) * 60 * 1000;
    }
  } else {
    session.holdTokenCreatedAt = null;
    session.holdTokenExpiresAt = null;
  }
}

async function forceLogout(page, username) {
  emitStatus('logout', 'Forcing logout and clearing session...', { account: username });
  try {
    const context = page.context();
    // Clear every Webook / SeatCloud cookie and storage so the next run starts clean.
    await context.clearCookies();
    try {
      await page.evaluate(() => {
        try { localStorage.clear(); } catch {}
        try { sessionStorage.clear(); } catch {}
        // Remove any saved auth tokens the site may have stored under custom keys.
        const keys = Object.keys(localStorage).filter(k => /token|user|auth|session/i.test(k));
        for (const k of keys) try { localStorage.removeItem(k); } catch {}
      });
    } catch {}
    // Try to call the site's own logout endpoint silently; ignore 404/401.
    try {
      await page.evaluate(async () => {
        try {
          await fetch('/api/v2/logout', { method: 'POST', credentials: 'include' });
        } catch {}
      });
    } catch {}
  } catch (e) {
    fileLog('WARN', `[${username}] Clear cookies/storage error: ${e.message}`);
  }
  // Delete the saved session file so the next run does not try to reuse it.
  deleteSessionFile(username);
  emitStatus('logout', 'Session cleared. Will log in fresh.', { account: username });
}

// Intercept the chart WebSocket so we can send hold messages through it
const WS_INTERCEPT = `
(() => {
  const OrigWS = window.WebSocket;
  window.__chartWS = null;
  function KimikoWebSocket(...args) {
    const ws = new OrigWS(...args);
    if ((args[0] || '').includes('seatcloud.com')) window.__chartWS = ws;
    return ws;
  }
  KimikoWebSocket.prototype = OrigWS.prototype;
  Object.setPrototypeOf(KimikoWebSocket, OrigWS);
  window.WebSocket = KimikoWebSocket;
})();
`;

// Patches Seats.io / SeatCloud chart limits as early as possible so the
// frontend never enforces the default 5-seat cap.
const CHART_LIMIT_PATCH = `
(() => {
  const LIMIT_VALUE = 150;
  const LIMIT_KEYS = ['maxNumberOfHolds','maxSelectedObjects','maxNumberOfSelectedObjects','maxObjects','maxSeats','selectionLimit','holdLimit','maxHold','maxSelection','maxPerOrder','max_per_order','maxTickets','maxTicketCount','ticketLimit','purchaseLimit','event_order_limit','season_order_limit','order_limit'];
  function patchLimits(obj, value = LIMIT_VALUE) {
    if (!obj || typeof obj !== 'object') return;
    for (const key of LIMIT_KEYS) {
      if (key in obj) {
        if (typeof obj[key] === 'number') obj[key] = value;
        else if (typeof obj[key] === 'string') obj[key] = String(value);
      }
    }
    if (Array.isArray(obj.maxSelectedObjects)) {
      for (const entry of obj.maxSelectedObjects) {
        if (entry && typeof entry === 'object') {
          if (typeof entry.quantity === 'number') entry.quantity = value;
          if (typeof entry.total === 'number') entry.total = value;
        }
      }
    }
    if (obj.config && typeof obj.config === 'object') patchLimits(obj.config, value);
  }
  function patchChartInstance(chart) {
    if (!chart || chart.__kimikoLimitPatched) return;
    chart.__kimikoLimitPatched = true;
    patchLimits(chart.state);
    patchLimits(chart.config);
    patchLimits(chart._config);
    patchLimits(chart.options);
    if (chart.state) {
      if (typeof chart.state._selectionCount === 'number') chart.state._selectionCount = 0;
      if (typeof chart.state._holdCount === 'number') chart.state._holdCount = 0;
      if (typeof chart.state.heldCount === 'number') chart.state.heldCount = 0;
      if (!Array.isArray(chart.state.selectedObjects)) chart.state.selectedObjects = [];
      if (!Array.isArray(chart.state.heldObjects)) chart.state.heldObjects = [];
    }
    // Proxy selectObjects so limits are re-applied immediately before every selection.
    if (typeof chart.selectObjects === 'function' && !chart.selectObjects.__kimikoPatched) {
      const orig = chart.selectObjects;
      chart.selectObjects = function (...args) {
        patchLimits(chart.state);
        patchLimits(chart.config);
        patchLimits(chart.options);
        return orig.apply(this, args);
      };
      chart.selectObjects.__kimikoPatched = true;
    }
    // Proxy render/draw to force limits before each render.
    ['render','redraw','draw','rerender'].forEach(method => {
      if (typeof chart[method] === 'function' && !chart[method].__kimikoPatched) {
        const orig = chart[method];
        chart[method] = function (...args) {
          patchLimits(chart.state);
          patchLimits(chart.config);
          patchLimits(chart.options);
          return orig.apply(this, args);
        };
        chart[method].__kimikoPatched = true;
      }
    });
  }
  function patchCurrent() {
    patchLimits(window.chartState);
    patchLimits(window.currentChartConfig);
    patchLimits(window.seatsioConfig);
    patchLimits(window.seatsio?.config);
    const chart = window.chartRender || window.chart || window.SeatsChart || (window.seatsio && window.seatsio.chart);
    if (chart) patchChartInstance(chart);
  }
  function hookConstructor() {
    const seatsio = window.seatsio;
    if (!seatsio || typeof seatsio.SeatingChart !== 'function' || seatsio.SeatingChart.__kimikoPatched) return false;
    const Original = seatsio.SeatingChart;
    seatsio.SeatingChart = function SeatingChartPatched(config) {
      if (config && typeof config === 'object') {
        if (!config.session) config.session = 'continue';
        patchLimits(config, LIMIT_VALUE);
        // Define getters/setters on config so the bundle cannot reset limits later.
        for (const key of LIMIT_KEYS) {
          if (key in config) {
            try {
              Object.defineProperty(config, key, {
                configurable: true,
                get() { return LIMIT_VALUE; },
                set(v) {}
              });
            } catch (e) {}
          }
        }
      }
      const instance = Original.call(this, config);
      if (instance) patchChartInstance(instance);
      setTimeout(patchCurrent, 0);
      setTimeout(patchCurrent, 100);
      setTimeout(patchCurrent, 500);
      return instance;
    };
    seatsio.SeatingChart.prototype = Original.prototype;
    seatsio.SeatingChart.__kimikoPatched = true;
    Object.setPrototypeOf(seatsio.SeatingChart, Original);
    if (typeof seatsio.SeatingChartDesigner === 'function' && !seatsio.SeatingChartDesigner.__kimikoPatched) {
      const OriginalDesigner = seatsio.SeatingChartDesigner;
      seatsio.SeatingChartDesigner = function SeatingChartDesignerPatched(config) {
        patchLimits(config, LIMIT_VALUE);
        return OriginalDesigner.call(this, config);
      };
      seatsio.SeatingChartDesigner.prototype = OriginalDesigner.prototype;
      seatsio.SeatingChartDesigner.__kimikoPatched = true;
      Object.setPrototypeOf(seatsio.SeatingChartDesigner, OriginalDesigner);
    }
    return true;
  }
  function observeDom() {
    if (typeof MutationObserver !== 'function' || window.__kimikoObserver) return;
    window.__kimikoObserver = new MutationObserver(() => {
      patchCurrent();
      const chart = window.chartRender || window.chart || window.SeatsChart || (window.seatsio && window.seatsio.chart);
      if (chart) patchChartInstance(chart);
    });
    window.__kimikoObserver.observe(document.body || document.documentElement, { childList: true, subtree: true, attributes: true });
  }
  function waitAndHook() {
    if (hookConstructor()) {
      observeDom();
      return;
    }
    let attempts = 0;
    const timer = setInterval(() => {
      attempts++;
      if (hookConstructor()) {
        observeDom();
        clearInterval(timer);
      }
      if (attempts > 300) clearInterval(timer);
    }, 50);
  }
  waitAndHook();
  patchCurrent();
  setInterval(patchCurrent, 250);
  if (typeof window !== 'undefined') window.__kimikoChartLimitPatch = { patchCurrent, hookConstructor, patchLimits, patchChartInstance };
})();
`;

// Registry to keep per-page WebSocket route state
const wsRouteRegistry = new WeakMap();
// Registry to force a specific hold token for a page (used by holdToken accounts).
const forcedHoldTokenRegistry = new WeakMap();

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const WB_API_TOKEN = 'e9aac1f2f0b6c07d6be070ed14829de684264278359148d6a582ca65a50934d2';
const WB_API_BASE = 'https://api.webook.com/api/v2';
const WB_ORIGIN = 'https://webook.com';

// Browser & session management
const ESTIMATED_RAM_PER_CONTEXT_MB = 280;
const KEEPALIVE_INTERVAL_MS = 8_000;
// Only auto-renew the hold token when the booking-page countdown drops below
// this many seconds. SeatCloud holds are short-lived; extending earlier (60s)
// gives the keepalive loop enough time to retry if the first extension fails.
// Both values can be overridden via env.
const HOLD_TOKEN_RENEW_THRESHOLD_SECONDS = parseInt(process.env.HOLD_TOKEN_RENEW_THRESHOLD_SECONDS, 10) || 60;
const HOLD_TOKEN_EXTENSION_MINUTES = parseInt(process.env.HOLD_TOKEN_EXTENSION_MINUTES, 10) || 15;
let globalBrowser = null;
let activeSessions = new Map();
let allContexts = new Set(); // Track every context ever opened for cleanup
let pendingQueue = [];
let maxConcurrency = 0;
let sessionCounter = 0;
let pairManager = null; // filled in below after createPairCyclingManager
const transferLocks = new Set(); // serialize seat transfers per source account
const activeProxyReservations = new Map(); // proxyCacheKey -> username
const launchingProxyKeys = new Set();      // proxies reserved while context is being created
const activeHoldTokenRegistry = new Map(); // holdToken -> username
const globalUsedHoldTokens = new Map();    // holdToken -> username (historical, used for rotation checks)

function reserveProxyForSession(username, proxy) {
  if (!proxy?.server) return false;
  const key = getProxyCacheKey(proxy);
  if (activeProxyReservations.has(key)) return activeProxyReservations.get(key) === username;
  activeProxyReservations.set(key, username);
  return true;
}
function releaseProxyReservation(username) {
  for (const [key, owner] of activeProxyReservations.entries()) {
    if (owner === username) activeProxyReservations.delete(key);
  }
}
function getReservedProxyKeys() {
  return new Set(activeProxyReservations.keys());
}
function getLaunchingProxyKeys() { return new Set(launchingProxyKeys); }
function reserveLaunchingProxy(proxy) { if (proxy?.server) launchingProxyKeys.add(getProxyCacheKey(proxy)); }
function releaseLaunchingProxy(proxy) { if (proxy?.server) launchingProxyKeys.delete(getProxyCacheKey(proxy)); }

function registerHoldToken(username, token) {
  if (!token || token.length < 8) return;
  activeHoldTokenRegistry.set(token, username);
  globalUsedHoldTokens.set(token, username);
}
function unregisterHoldToken(token) {
  if (!token) return;
  activeHoldTokenRegistry.delete(token);
}
function isHoldTokenUsedByAnother(token, username) {
  const owner = activeHoldTokenRegistry.get(token);
  return owner && owner !== username;
}

// Section-level mutex to prevent intra-account races
const sectionHoldLocks = new Map(); // section -> Promise
async function acquireSectionHoldLock(section) {
  const sec = String(section).toUpperCase();
  while (sectionHoldLocks.has(sec)) { await sectionHoldLocks.get(sec); }
  let resolve;
  const p = new Promise(r => resolve = r);
  sectionHoldLocks.set(sec, p);
  return () => { sectionHoldLocks.delete(sec); resolve(); };
}
const pausedSnipersForTransfer = new Map(); // username -> { sections, wasActive }

// Global seat coordination for multi-account runs (prevents multiple accounts
// trying to hold the same seats in the same target section)
let globalSeatPool = new Map(); // seatName -> { username, heldAt, runId }
let currentRunId = 0;
let transferContentionWhitelist = new Set(); // usernames exempt from section contention during active transfers

function emitStatus(stage, message, data = {}) {
  try {
    io.emit('status', { stage, message, ...data });
  } catch (e) {
    fileLog('WARN', `emitStatus socket error: ${e.message}`);
  }
  // Also emit the stage name as its own event so clients can listen for
  // specific lifecycle events (transfer-plan-built, destination-ready, etc.).
  if (stage && typeof stage === 'string') {
    try {
      io.emit(stage, { stage, message, ...data });
    } catch (e) {
      fileLog('WARN', `emitStatus stage event error: ${e.message}`);
    }
  }
  const account = data.account || '';
  const line = `[${stage}]${account ? ` [${account}]` : ''} ${message}`;
  try { console.log(line, data); } catch {}
  try {
    fileLog('INFO', line + ' ' + safeRedactedStringify(data));
  } catch (e) {
    try { console.error('Logging error:', e.message); } catch {}
  }

  // Feed live hold timer events to pair cycling so handoffs happen at the
  // exact moment the page countdown reaches the configured threshold.
  if (stage === 'hold-timer' && data.account && typeof data.seconds === 'number' && pairManager) {
    try {
      pairManager.onHoldTimer(data.account, data.seconds);
    } catch (e) {
      fileLog('WARN', `pairManager.onHoldTimer error: ${e.message}`);
    }
  }
}

function emitAccountUpdate(username, stage, extra = {}) {
  io.emit('account-update', { account: username, stage, ...extra });
}

function emitSeatEvent(event, username, seats, extra = {}) {
  if (!Array.isArray(seats) || seats.length === 0) return;
  const unique = [...new Set(seats.map(String))];
  io.emit(event, { account: username, seats: unique, ...extra });
  // Mirror to a generic status event so older clients still see something.
  emitStatus(event, `${event === 'seat-held' ? 'Held' : 'Released'} ${unique.length} seat(s)`, { account: username, seats: unique, ...extra });
}

function emitQueueStats() {
  io.emit('queue-stats', {
    active: activeSessions.size,
    pending: pendingQueue.length,
    done: sessionCounter,
  });
}

// ------------------------------------------------------------------
// Global seat pool coordination
// ------------------------------------------------------------------
function resetSeatPool(runId) {
  globalSeatPool.clear();
  currentRunId = runId;
}

function whitelistForTransfer(usernames) {
  if (!Array.isArray(usernames)) return;
  for (const u of usernames) {
    if (u) transferContentionWhitelist.add(String(u));
  }
}

function removeFromTransferWhitelist(username) {
  if (username) transferContentionWhitelist.delete(String(username));
}

function clearTransferWhitelist() {
  transferContentionWhitelist.clear();
}

function isUsernameWhitelistedForTransfer(username) {
  return username ? transferContentionWhitelist.has(String(username)) : false;
}

const SEAT_POOL_TTL_MS = 10 * 60 * 1000; // reservations expire after 10 minutes

function reserveSeats(username, seats, runId = currentRunId) {
  const now = Date.now();
  for (const seat of seats) {
    const s = String(seat).trim().toUpperCase();
    if (!s) continue;
    globalSeatPool.set(s, { username, heldAt: now, runId });
  }
}

function releaseSeats(username) {
  for (const [seat, info] of globalSeatPool.entries()) {
    if (info.username === username) globalSeatPool.delete(seat);
  }
}

function releaseSeatFromPool(seat) {
  const key = String(seat).trim().toUpperCase();
  globalSeatPool.delete(key);
}

function isSeatReserved(seat, exceptUsername = null) {
  const key = String(seat).trim().toUpperCase();
  const info = globalSeatPool.get(key);
  if (!info) return false;
  // Stale reservations from a previous run or expired TTL are not valid.
  if (info.runId !== currentRunId || Date.now() - info.heldAt > SEAT_POOL_TTL_MS) {
    globalSeatPool.delete(key);
    return false;
  }
  return info.username !== exceptUsername;
}

function excludeReservedSeats(seats, exceptUsername = null) {
  return seats.filter(s => !isSeatReserved(s, exceptUsername));
}

function excludeReleasedSeats(seats, releasedSet) {
  if (!releasedSet || releasedSet.size === 0) return seats;
  return seats.filter(s => !releasedSet.has(String(s).trim().toUpperCase()));
}

function usernameSeatCount(username) {
  let count = 0;
  for (const info of globalSeatPool.values()) {
    if (info.username === username) count++;
  }
  return count;
}

function sectionFromSeat(seat) {
  return String(seat).split('-')[0].toUpperCase();
}

function isSectionContested(section, exceptUsername = null) {
  // True if another active account already holds seats in this section.
  // Accounts participating in an active transfer are exempt so destinations can
  // receive seats from their source masters without being blocked.
  const sec = String(section).toUpperCase();
  for (const [seat, info] of globalSeatPool.entries()) {
    if (exceptUsername && info.username === exceptUsername) continue;
    if (isUsernameWhitelistedForTransfer(info.username)) continue;
    if (seat.startsWith(`${sec}-`)) return true;
  }
  return false;
}

function isSectionBeingSelected(section, exceptUsername = null) {
  // True if another account is currently in the middle of a select/hold operation
  // targeting this section. This catches the gap between bestAvailable calls.
  // Whitelisted transfer participants and accounts in an active transfer are skipped.
  const sec = String(section).toUpperCase();
  for (const [username, session] of activeSessions.entries()) {
    if (exceptUsername && username === exceptUsername) continue;
    if (isUsernameWhitelistedForTransfer(username)) continue;
    if (session.isTransferring) continue;
    if (!session.isSelecting) continue;
    const targets = session.targetSections || [];
    const quota = session.sectionQuota || [];
    const allSections = new Set([
      ...targets.map(s => String(s).toUpperCase()),
      ...quota.map(q => String(q.section).toUpperCase()),
    ]);
    if (allSections.has(sec)) return true;
  }
  return false;
}

function getSectionReservedCount(section, exceptUsername = null) {
  const sec = String(section).toUpperCase();
  let count = 0;
  for (const [seat, info] of globalSeatPool.entries()) {
    if (exceptUsername && info.username === exceptUsername) continue;
    if (seat.startsWith(`${sec}-`)) count++;
  }
  return count;
}

function checkActiveHoldTokenCollisions(exceptUsername = null) {
  const tokenMap = new Map(); // token -> username
  const collisions = [];
  for (const [username, session] of activeSessions.entries()) {
    if (exceptUsername && username === exceptUsername) continue;
    const token = session.holdToken;
    if (!token || token.length < 8) continue;
    const existing = tokenMap.get(token);
    if (existing && existing !== username) {
      collisions.push({ token: `${token.slice(0, 8)}...${token.slice(-4)}`, users: [existing, username] });
    } else {
      tokenMap.set(token, username);
    }
  }
  for (const c of collisions) {
    fileLog('WARN', `[hold-token-collision] Active sessions share hold token ${c.token}: ${c.users.join(' vs ')}`);
    emitStatus('warning', `تنبيه: حسابين شغالين بنفس hold token (${c.token}): ${c.users.join(' vs ')}. هيتم محاولة استبدال توكن واحد.`, { users: c.users, token: c.token, type: 'active-hold-token-collision' });
  }
  return collisions;
}

function findOtherSessionWithToken(token, exceptUsername) {
  for (const [username, session] of activeSessions.entries()) {
    if (username === exceptUsername) continue;
    if (session.holdToken === token) return username;
  }
  return null;
}

function setWsRouteToken(page, token) {
  // Update the intercepted WebSocket URL token so subsequent WS operations
  // use the rotated hold token instead of the shared one.
  const state = wsRouteRegistry.get(page);
  if (!state || !state.url) return false;
  try {
    const url = new URL(state.url);
    url.searchParams.set('token', token);
    url.searchParams.set('holdToken', token);
    url.searchParams.set('hold_token', token);
    state.url = url.toString();
    return true;
  } catch {
    return false;
  }
}

async function createFreshHoldToken(session, expiresInMinutes = 30) {
  const endpoints = [
    'https://api.seatcloud.com/api/v2/hold-tokens',
    'https://api.seatcloud.com/hold-tokens',
    'https://api-eu.seatsio.net/hold-tokens',
    'https://api-na.seatsio.net/hold-tokens',
  ];
  for (const url of endpoints) {
    try {
      const res = await sessionFetch(url, {
        method: 'POST',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', 'Origin': WB_ORIGIN, 'Referer': `${WB_ORIGIN}/` },
        body: JSON.stringify({ expiresInMinutes }),
      }, session);
      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        if (data.holdToken) return data;
      }
    } catch (e) { fileLog('INFO', `[${session?.username}] createFreshHoldToken attempt error ${url}: ${e.message}`); }
  }
  return null;
}

async function rotateSessionHoldToken(session) {
  if (!session || !session.page || await isPageClosed(session.page)) return false;
  const oldToken = session.holdToken;
  fileLog('INFO', `[${session.username}] Rotating hold token to avoid collision`);

  // 1. Purge stale token from all storage layers.
  try {
    await session.context.clearCookies();
    await session.page.evaluate(() => {
      ['holdToken','seatHoldToken','sc_hold_token'].forEach(k => {
        try { sessionStorage.removeItem(k); } catch {}
        try { localStorage.removeItem(k); } catch {}
      });
    });
    resetWebSocketRouteState(session.page);
  } catch (e) {
    fileLog('WARN', `[${session.username}] Could not purge old hold token: ${e.message}`);
  }

  // 2. Try a fresh API token first.
  let newToken = null;
  const pageSlug = parseSlug(session.page.url());
  if (pageSlug) {
    try {
      const detail = await fetchEventDetail(pageSlug);
      const eventId = detail?._id || detail?.data?._id || null;
      if (eventId) {
        newToken = await getHoldTokenFromApi(pageSlug, eventId, session);
      }
    } catch (e) {
      fileLog('WARN', `[${session.username}] Fresh token fetch failed: ${e.message}`);
    }
  }

  // 3. Fallback to extension if fresh fetch did not yield a new token.
  if (!newToken || newToken === oldToken) {
    const ext = await extendHoldToken(session);
    if (ext.success && ext.newToken && ext.newToken !== oldToken) newToken = ext.newToken;
  }

  if (newToken && newToken !== oldToken) {
    if (oldToken) unregisterHoldToken(oldToken);
    session.holdToken = newToken;
    touchHoldToken(session, newToken, HOLD_TOKEN_EXTENSION_MINUTES);
    registerHoldToken(session.username, newToken);
    await syncQueueTokenToCookie(session.context, null, newToken);
    setWsRouteToken(session.page, newToken);
    fileLog('INFO', `[${session.username}] Hold token rotated: ${oldToken?.slice(0, 12)}... -> ${newToken.slice(0, 12)}...`);
    return true;
  }
  return false;
}

async function ensureUniqueHoldToken(session) {
  if (!session || !session.holdToken) return;
  let other = findOtherSessionWithToken(session.holdToken, session.username);
  if (!other) other = isHoldTokenUsedByAnother(session.holdToken, session.username) ? activeHoldTokenRegistry.get(session.holdToken) : null;
  if (!other) return;
  emitStatus('warning', `تنبيه: ${session.username} يشارك نفس hold token مع ${other}، جاري الاستبدال...`, { account: session.username, other, type: 'hold-token-rotation' });
  for (let i = 0; i < 3 && other; i++) {
    const ok = await rotateSessionHoldToken(session);
    if (!ok) break;
    other = findOtherSessionWithToken(session.holdToken, session.username);
    if (!other) other = isHoldTokenUsedByAnother(session.holdToken, session.username) ? activeHoldTokenRegistry.get(session.holdToken) : null;
  }
  if (other) {
    emitStatus('warning', `لم يتمكن من استبدال توكن ${session.username} تلقائيًا`, { account: session.username, type: 'hold-token-rotation-failed' });
    throw new Error(`HOLD_TOKEN_COLLISION_UNRESOLVED for ${session.username} with ${other}`);
  }
}

function estimateMaxConcurrency(userOverride = 0) {
  if (userOverride > 0) return Math.max(1, Math.min(userOverride, 8));
  // Mobile browser contexts + screenshots/diagnostics are heavy; keep it conservative
  // to avoid ERR_INSUFFICIENT_RESOURCES and JS heap OOM on consumer hardware.
  const freeMB = os.freemem() / 1024 / 1024;
  const byRam = Math.floor(freeMB / ESTIMATED_RAM_PER_CONTEXT_MB);
  return Math.max(1, Math.min(byRam, 3));
}

async function isPageClosed(page) {
  if (!page) return true;
  if (page.isClosed && page.isClosed()) return true;
  try {
    // Fast non-blocking check first; if the page is closed this throws immediately.
    await page.evaluate(() => document.readyState);
    return false;
  } catch {
    return true;
  }
}

async function safeScreenshot(page, stage, account) {
  // Screenshots disabled per user request.
  return null;
}

app.get('/api/estimate-concurrency', async (req, res) => {
  res.json({ success: true, concurrency: estimateMaxConcurrency() });
});

app.get('/api/health', (req, res) => {
  const sessions = [];
  for (const [username, session] of activeSessions.entries()) {
    sessions.push({
      username,
      state: session.state,
      seats: (session.selectedSeats || []).length,
      proxy: session.proxy ? session.proxy.server : null,
      proxyMode: session.proxyMode || currentProxyMode,
    });
  }
  res.json({
    success: true,
    uptime: process.uptime(),
    activeSessions: activeSessions.size,
    pending: pendingQueue.length,
    proxyMode: currentProxyMode,
    loadedProxies: proxyManager.getAll().length,
    sessions,
  });
});

// Reference endpoint: validate a queue_session token using the secure
// middleware. Returns 200 if the token signature, expiry, and position are
// valid; 401 otherwise. This is the same validation logic a hardened backend
// would run before allowing /api/booking/create.
app.post('/api/queue/validate', (req, res) => {
  const token = req.headers['queue-token'] || req.body?.queue_token || '';
  const userAgent = req.headers['user-agent'] || '';
  if (!token) {
    return res.status(400).json({ success: false, error: 'queue_token_required' });
  }
  const result = getQueueValidator().verifyQueueToken(token, userAgent);
  if (result.ok) {
    return res.json({ success: true, payload: result.payload });
  }
  return res.status(401).json({ success: false, error: result.error });
});

app.get('/api/logs', (req, res) => {
  try {
    const files = fs.readdirSync(LOG_DIR)
      .filter(f => f.endsWith('.log'))
      .map(f => ({ name: f, path: path.join(LOG_DIR, f), size: fs.statSync(path.join(LOG_DIR, f)).size }))
      .sort((a, b) => b.mtime - a.mtime || 0);
    const latest = files[0];
    if (!latest) return res.json({ success: true, logs: '', files: [] });
    const content = fs.readFileSync(latest.path, 'utf8');
    res.json({ success: true, logs: content, files: files.map(f => f.name) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/log-file', (req, res) => {
  try {
    const name = path.basename(req.query.name || '');
    if (!name || !name.endsWith('.log')) throw new Error('Invalid log file name');
    const filePath = path.join(LOG_DIR, name);
    if (!filePath.startsWith(LOG_DIR)) throw new Error('Invalid path');
    const content = fs.readFileSync(filePath, 'utf8');
    res.json({ success: true, logs: content });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

function waitFor(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function withTimeout(promise, ms, label = 'operation') {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)),
  ]);
}

// Frontend-style trace_id: timestamp + 11-char random suffix (e.g. 1780599362816-mw4n2zqa1vb).
function makeTraceId(prefix = '') {
  const rand = Math.random().toString(36).slice(2, 13).padEnd(11, '0');
  return `${prefix}${Date.now()}-${rand}`;
}

async function trySolveCaptchaWith2captcha(page, session, context = 'login') {
  const username = session?.username;
  try {
    const keys = captcha2captcha.getEnabledKeys();
    if (keys.length === 0) {
      fileLog('WARN', `[${username}] No enabled 2captcha keys; skipping captcha fallback`);
      return null;
    }
    fileLog('INFO', `[${username}] 2captcha fallback started in ${context} context (${keys.length} key(s))`);

    const pageUrl = page.url() || session?.url || 'https://webook.com/';

    // 1) Try reCAPTCHA first (chart/login contexts).
    const frame = await findChartFrame(page, username) || page;
    const hasRecaptcha = await frame.evaluate(() => {
      return !!(
        document.querySelector('.g-recaptcha, [data-sitekey], iframe[src*="recaptcha"], iframe[src*="google.com/recaptcha"]') ||
        (window.grecaptcha && (window.grecaptcha.execute || window.grecaptcha.render))
      );
    }).catch(() => false);

    if (hasRecaptcha) {
      emitStatus('captcha-detected', `reCAPTCHA detected in ${context}; trying 2captcha fallback`, { account: username });
      const sitekey = await captcha2captcha.detectSitekey(frame);
      fileLog('INFO', `[${username}] reCAPTCHA sitekey: ${sitekey}`);
      const token = await captcha2captcha.solveRecaptchaV2({ sitekey, pageUrl });
      if (token) {
        await captcha2captcha.injectRecaptchaToken(frame, token);
        if (session) session.providedRecaptchaToken = token;
        emitStatus('captcha-solved', 'reCAPTCHA token injected', { account: username });
      }
      return token;
    }

    // 2) Cloudflare Turnstile fallback (often blocks the chart UI).
    const turnstileSitekey = await captcha2captcha.detectTurnstileSitekey(page).catch(() => null);
    if (turnstileSitekey) {
      emitStatus('captcha-detected', `Turnstile detected in ${context}; trying 2captcha fallback`, { account: username, sitekey: turnstileSitekey });
      fileLog('INFO', `[${username}] Turnstile sitekey: ${turnstileSitekey}`);
      const token = await captcha2captcha.solveTurnstile({ sitekey: turnstileSitekey, pageUrl, invisible: true });
      if (token) {
        await captcha2captcha.injectTurnstileToken(page, token);
        if (session) session.providedTurnstileToken = token;
        emitStatus('captcha-solved', 'Turnstile token injected', { account: username });
      }
      return token;
    }

    fileLog('INFO', `[${username}] No recognized captcha widget in ${context}; nothing to solve`);
    return null;
  } catch (err) {
    fileLog('WARN', `[${username}] 2captcha fallback failed: ${err.message}`);
    emitStatus('captcha-error', `2captcha fallback failed: ${err.message}`, { account: username, context });
    return null;
  }
}

async function preSetConsentCookies(context) {
  // Set consent cookies before the first navigation so the banner never renders.
  try {
    await context.addCookies([
      { name: 'cookie_consent', value: 'essential,analytics,marketing', domain: '.webook.com', path: '/', httpOnly: false, secure: true, sameSite: 'Lax' },
      { name: 'OptanonAlertBoxClosed', value: new Date().toISOString(), domain: '.webook.com', path: '/', httpOnly: false, secure: true, sameSite: 'Lax' },
      { name: 'OptanonConsent', value: 'isGpcEnabled=0&datestamp=' + new Date().toISOString() + '&version=6.17.0&browserGpcFlag=0&isIABGlobal=false&hosts=&consentId=00000000-0000-0000-0000-000000000000&interactionCount=1&landingPath=NotLandingPage&groups=1:1,2:1,3:1,4:1&geolocation=SA%3B01&AwaitingReconsent=false', domain: '.webook.com', path: '/', httpOnly: false, secure: true, sameSite: 'Lax' },
    ]);
  } catch (e) {
    fileLog('WARN', `Could not pre-set consent cookies: ${e.message}`);
  }
}

async function fastAcceptCookies(page, username) {
  // Fast race across all known accept phrases. We still set consent cookies if no button wins.
  const acceptTexts = ['قبول الكل', 'Accept All', 'Accept all', 'Allow all cookies', 'Allow All Cookies', 'موافق', 'Accept', 'قبول', 'Agree', 'I agree', 'Yes, I agree'];

  // Race multiple selector strategies with a short timeout.
  const selectorPromises = acceptTexts.map(text => {
    const escaped = text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const locator = page.locator('button, a, [role="button"], input[type="button"], input[type="submit"]')
      .filter({ hasText: new RegExp('^' + escaped + '$', 'i') }).first();
    return locator.waitFor({ state: 'visible', timeout: 120 }).then(() => locator);
  });

  try {
    const btn = await Promise.any(selectorPromises);
    await btn.click({ timeout: 2000 });
    emitStatus('cookies-accepted', 'Cookie terms accepted', { account: username });
    return true;
  } catch {}

  // Fallback: any visible button whose text includes one of the accept phrases.
  const accepted = await page.evaluate((texts) => {
    const buttons = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="button"], input[type="submit"]'));
    for (const t of texts) {
      const btn = buttons.find(b => {
        const txt = (b.innerText || b.textContent || b.value || '').trim();
        return txt === t || txt.includes(t);
      });
      if (btn) { btn.click(); return { clicked: true, text: t }; }
    }
    return { clicked: false };
  }, acceptTexts).catch(() => ({ clicked: false }));

  if (accepted.clicked) {
    emitStatus('cookies-accepted', `Cookie terms accepted (${accepted.text})`, { account: username });
    return true;
  }

  // Final fallback: set the consent cookie directly so the banner does not block clicks.
  try {
    await page.context().addCookies([{
      name: 'cookie_consent',
      value: 'essential,analytics,marketing',
      domain: '.webook.com',
      path: '/',
      httpOnly: false,
      secure: true,
      sameSite: 'Lax',
    }]);
  } catch (e) {
    fileLog('WARN', `[${username}] Could not set cookie_consent cookie: ${e.message}`);
  }
  return false;
}

async function dismissAccountDetailsModal(page, username) {
  // Webook sometimes shows a post-login "account details" modal
  // (img alt="account-details", text "دعنا نجعل تجربتك في webook أفضل!").
  // The safest action is the explicit X close button, then "Skip now".

  // 1) Try Playwright locator for the close button inside any dialog.
  try {
    const closeBtn = page.locator('[role="dialog"] button[aria-label="Close"], div.fixed button[aria-label="Close"]').first();
    await closeBtn.waitFor({ state: 'visible', timeout: 300 });
    await closeBtn.click({ timeout: 1500 });
    emitStatus('modal-dismissed', 'Account-details modal dismissed (close-x)', { account: username });
    return true;
  } catch {}

  // 2) Try explicit "Skip now" / "تخطي الآن" button inside the modal.
  const skipTexts = ['تخطي الآن', 'Skip now', 'تخطي', 'Skip'];
  for (const text of skipTexts) {
    try {
      const btn = page.locator(`[role="dialog"] button:has-text("${text}"), div.fixed button:has-text("${text}")`).first();
      await btn.waitFor({ state: 'visible', timeout: 600 });
      await btn.click({ timeout: 2000 });
      emitStatus('modal-dismissed', `Account-details modal dismissed (skip-button: ${text})`, { account: username });
      return true;
    } catch {}
  }

  // 3) JS fallback.
  const closed = await page.evaluate((skipTexts) => {
    const img = document.querySelector('img[alt="account-details"]');
    const modal = img ? img.closest('[role="dialog"]') || img.closest('div.fixed') : null;

    let closeBtn = modal ? modal.querySelector('button[aria-label="Close"]') : null;
    if (!closeBtn) closeBtn = document.querySelector('button[aria-label="Close"]');
    if (closeBtn) {
      closeBtn.click();
      return { closed: true, method: 'close-x' };
    }

    const buttons = Array.from(document.querySelectorAll('button, a, [role="button"]'));
    for (const t of skipTexts) {
      const btn = buttons.find(b => (b.innerText || b.textContent || '').trim() === t);
      if (btn) {
        btn.click();
        return { closed: true, method: 'skip-button', text: t };
      }
    }

    return { closed: false };
  }, skipTexts).catch(() => ({ closed: false }));

  if (closed.closed) {
    emitStatus('modal-dismissed', `Account-details modal dismissed (${closed.method})`, { account: username, detail: closed });
    await waitFor(200);
    return true;
  }
  return false;
}

async function dismissSeatSelectionTutorial(page, username) {
  // The "كيفية اختيار مقعد" tutorial modal/banner blocks clicks on the chart.
  // Close it via the explicit close button or the confirmation button.
  try {
    const tutorial = page.locator('[role="dialog"], div[aria-modal="true"], div.fixed, div[class*="modal" i]')
      .filter({ hasText: /كيفية اختيار مقعد/i });
    const closeBtn = tutorial.locator('button[aria-label="إغلاق"], button:has-text("حسناً")').first();
    await closeBtn.click({ timeout: 300 });
    emitStatus('modal-dismissed', 'Seat selection tutorial dismissed', { account: username });
    return true;
  } catch {}

  // Robust fallback: find any element containing the tutorial title, then click
  // the closest close button (إغلاق or ×). The banner may be a styled inline div
  // rather than a semantic dialog/modal.
  try {
    const closed = await page.evaluate(() => {
      const headings = Array.from(document.querySelectorAll('*'));
      const tutorial = headings.find(el => /كيفية اختيار مقعد/i.test(el.innerText || el.textContent || ''));
      if (!tutorial) return false;
      // Search the tutorial container and its subtree for the close button.
      let container = tutorial.closest('div');
      if (!container) container = tutorial.parentElement;
      const closeBtn = container.querySelector('button[aria-label="إغلاق"], button') ||
                       Array.from(document.querySelectorAll('button[aria-label="إغلاق"]')).find(btn => container.contains(btn));
      if (closeBtn) {
        closeBtn.click();
        return true;
      }
      // Last resort: click any visible button whose text is × inside the container.
      const xBtn = Array.from(container.querySelectorAll('button')).find(b => (b.innerText || b.textContent || '').trim() === '×');
      if (xBtn) { xBtn.click(); return true; }
      return false;
    });
    if (closed) {
      emitStatus('modal-dismissed', 'Seat selection tutorial dismissed (DOM fallback)', { account: username });
      return true;
    }
  } catch {}

  // Fallback: any matching button anywhere on the page.
  try {
    await page.locator('button[aria-label="إغلاق"], button:has-text("حسناً")').first().click({ timeout: 500 });
    emitStatus('modal-dismissed', 'Seat selection tutorial dismissed (page-level fallback)', { account: username });
    return true;
  } catch {}

  return false;
}

async function dismissAllBanners(page, username, reason = 'generic') {
  // Dismiss cookie, account-details, and seat-selection tutorial banners as fast as possible.
  // All three attempts run in parallel with a tight overall timeout so navigation
  // is never delayed waiting for banners that may not exist.
  const run = async () => {
    const results = await Promise.allSettled([
      fastAcceptCookies(page, username),
      dismissAccountDetailsModal(page, username),
      dismissSeatSelectionTutorial(page, username),
    ]);
    return {
      cookieClosed: results[0].status === 'fulfilled' && results[0].value,
      modalClosed: results[1].status === 'fulfilled' && results[1].value,
      tutorialClosed: results[2].status === 'fulfilled' && results[2].value,
    };
  };

  let state = { cookieClosed: false, modalClosed: false, tutorialClosed: false };
  try {
    state = await Promise.race([
      run(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 500)),
    ]);
  } catch {
    state = await run();
  }

  fileLog('INFO', `[${username}] dismissAllBanners(${reason}): cookie=${state.cookieClosed}, modal=${state.modalClosed}, tutorial=${state.tutorialClosed}`);
  return state;
}

async function waitForAnySelector(page, selectors, timeoutMs = 10000, visible = true) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    for (const sel of selectors) {
      try {
        const el = await page.$(sel);
        if (el) {
          if (!visible) return el;
          const isVis = await el.isVisible().catch(() => false);
          if (isVis) return el;
        }
      } catch {}
    }
    await waitFor(40);
  }
  return null;
}

async function ensureBrowser() {
  if (globalBrowser && globalBrowser.isConnected()) return globalBrowser;
  emitStatus('browser-launch', 'Launching shared Chromium browser...');
  globalBrowser = await chromium.launch({
    headless: false,
    args: [
      '--disable-blink-features=AutomationControlled',
      '--disable-web-security',
      '--disable-features=IsolateOrigins,site-per-process,BlockThirdPartyCookies',
      '--disable-site-isolation-trials',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-background-networking',
      '--disable-background-timer-throttling',
      '--disable-renderer-backgrounding',
      '--force-webrtc-ip-handling-policy=default_public_interface_only',
      '--disable-webrtc',
      '--disable-webrtc-hw-encoding',
      '--disable-webrtc-hw-decoding',
    ],
  });
  return globalBrowser;
}

async function createMobileContext(username = null, attempt = 1, proxy = null) {
  // Every concurrent user MUST get a brand-new Playwright browser context with a
  // unique randomized device profile, viewport, user agent, and stealth parameters.
  // This guarantees total storage, cookie, and memory isolation between accounts.
  fileLog('INFO', `[${username}] createMobileContext start (attempt ${attempt})`);
  try {
    await withTimeout(pruneOldContexts(true), 5_000, `prune old contexts for ${username}`);
  } catch (pruneErr) {
    fileLog('WARN', `[${username}] pruneOldContexts timed out or failed: ${pruneErr.message}`);
  }
  let browser = await ensureBrowser();
  if (!browser.isConnected()) {
    fileLog('WARN', `[${username}] Browser not connected before newContext; relaunching`);
    globalBrowser = null;
    browser = await ensureBrowser();
  }

  // Use a chart-friendly desktop profile for booking sessions. Mobile viewports
  // frequently fail to render the SeatCloud seat chart on webook.com, which is
  // the main client-reported issue ("الشارت مابيتحملش").
  const profile = randomChartFriendlyProfile();
  const loadedState = username ? loadSessionState(username) : undefined;
  const sessionMeta = loadedState ? loadedState.__kimiko : null;
  // Strip our internal metadata before passing to Playwright
  const storageState = loadedState
    ? { cookies: loadedState.cookies, origins: loadedState.origins }
    : undefined;

  // Build extra HTTP headers that match the chosen profile. We only add
  // sec-ch-ua on Chromium-based profiles; Safari/WebKit ignores it.
  const extraHTTPHeaders = {};
  if (profile.secChUa && profile.browser !== 'Safari') {
    extraHTTPHeaders['sec-ch-ua'] = profile.secChUa;
    extraHTTPHeaders['sec-ch-ua-mobile'] = profile.isMobile ? '?1' : '?0';
    extraHTTPHeaders['sec-ch-ua-platform'] = `"${profile.platform}"`;
  }

  // Pick a geolocation that is consistent with the profile's timezone.
  const geoByTz = {
    'Asia/Riyadh': { latitude: 24.7136, longitude: 46.6753 },
    'Asia/Dubai': { latitude: 25.2048, longitude: 55.2708 },
    'Asia/Bahrain': { latitude: 26.2285, longitude: 50.5860 },
    'Africa/Cairo': { latitude: 30.0444, longitude: 31.2357 },
    'Europe/Istanbul': { latitude: 41.0082, longitude: 28.9784 },
    'Asia/Kuwait': { latitude: 29.3759, longitude: 47.9774 },
    'Asia/Qatar': { latitude: 25.2854, longitude: 51.5310 },
  };
  const geolocation = geoByTz[profile.timezoneId] || geoByTz['Asia/Riyadh'];

  const proxyOption = proxy && proxy.server ? {
    server: proxy.server,
    username: proxy.username,
    password: proxy.password,
  } : undefined;
  fileLog('INFO', `[${username}] Creating mobile context with proxy=${proxyOption ? proxyOption.server : 'none'} (mode=${currentProxyMode})`);

  let ctx;
  try {
    ctx = await browser.newContext({
      userAgent: profile.userAgent,
      viewport: { width: profile.width, height: profile.height },
      deviceScaleFactor: profile.dpr,
      isMobile: profile.isMobile,
      hasTouch: profile.hasTouch,
      locale: profile.languages[0],
      timezoneId: profile.timezoneId || 'Asia/Riyadh',
      geolocation,
      permissions: ['geolocation', 'storage-access'],
      colorScheme: profile.colorScheme || 'dark',
      reducedMotion: 'no-preference',
      ...(proxyOption ? { proxy: proxyOption } : {}),
      ...(Object.keys(extraHTTPHeaders).length ? { extraHTTPHeaders } : {}),
      ...(storageState ? { storageState } : {}),
    });
  } catch (e) {
    fileLog('WARN', `[${username}] newContext failed (attempt ${attempt}): ${e.message}`);
    if (attempt <= 2) {
      // A corrupted session file or a crashed browser are the two common causes.
      if (storageState) {
        fileLog('WARN', `[${username}] Deleting potentially corrupted session file and retrying fresh`);
        deleteSessionFile(username);
      }
      if (e.message.includes('closed') || !browser.isConnected()) {
        globalBrowser = null;
      }
      // Proxy isolation is mandatory once a proxy is chosen; never silently drop it.
      if (proxyOption) {
        throw new Error(`PROXY_CONTEXT_FAILED: ${e.message} (proxy=${proxyOption.server})`);
      }
      await waitFor(150);
      return createMobileContext(username, attempt + 1, proxy);
    }
    throw e;
  }

  // Attach profile + session metadata for diagnostics and login decisions.
  // The username tag guarantees we can audit isolation in crash dumps and logs.
  ctx.__kimikoUsername = username || null;
  ctx.__kimikoProfile = profile;
  ctx.__kimikoSessionMeta = sessionMeta;
  allContexts.add(ctx);
  ctx.on('close', () => allContexts.delete(ctx));
  ctx.setDefaultTimeout(5000);
  ctx.setDefaultNavigationTimeout(15000);
  await ctx.addInitScript(generateStealthScript(profile));
  await ctx.addInitScript(CHART_LIMIT_PATCH);
  await ctx.addInitScript(WS_INTERCEPT);
  // Prepare a global hook so a provided hold token can be forced into the page
  // before the SeatCloud iframe reads window.holdToken / __INITIAL_STATE__.
  await ctx.addInitScript(`
    window.__kimikoForcedHoldToken = null;
    window.__kimikoSetHoldToken = function(token) {
      window.__kimikoForcedHoldToken = token;
      window.holdToken = token;
      window.__INITIAL_STATE__ = window.__INITIAL_STATE__ || {};
      window.__INITIAL_STATE__.hold_token = token;
      try {
        const frame = document.querySelector('iframe[src*="seatcloud"]');
        if (frame && frame.contentWindow) {
          frame.contentWindow.holdToken = token;
          frame.contentWindow.__INITIAL_STATE__ = frame.contentWindow.__INITIAL_STATE__ || {};
          frame.contentWindow.__INITIAL_STATE__.hold_token = token;
        }
      } catch(e) {}
    };
  `);
  const sessionHint = sessionMeta
    ? ` (session: ${sessionMeta.valid ? 'valid' : (sessionMeta.needsRefresh ? 'needs-refresh' : 'none')})`
    : '';
  emitStatus('browser-context', `New mobile context: ${profile.name} (${profile.width}x${profile.height} DPR${profile.dpr}) UA ${profile.userAgent.slice(0, 60)}...${sessionHint}`, { account: username || '', attempt });
  return ctx;
}

const MAX_SCREENSHOT_AGE_MS = 60 * 60 * 1000; // keep screenshots for 1 hour only
const MAX_DIAGNOSTIC_AGE_MS = 2 * 60 * 60 * 1000; // keep diagnostics for 2 hours

async function cleanupOldFiles(dir, maxAgeMs) {
  try {
    const entries = await fs.promises.readdir(dir, { withFileTypes: true });
    const now = Date.now();
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const fp = path.join(dir, entry.name);
      try {
        const stats = await fs.promises.stat(fp);
        if (now - stats.mtime.getTime() > maxAgeMs) {
          await fs.promises.unlink(fp);
        }
      } catch {}
    }
  } catch {}
}

async function emitScreenshot(page, stage, account, opts = {}) {
  // Screenshots disabled per user request.
  return null;
}

async function saveDiagnostics(page, username, stage) {
  try {
    if (!page || await isPageClosed(page)) return null;
    const ts = Date.now();
    const safeUser = username.replace(/[^a-z0-9]/gi, '_');
    const base = `${ts}-${stage}-${safeUser}`;

    // Screenshot disabled per user request.
    const screenshotPath = null;

    // Main page HTML (limited size)
    let mainHtmlPath = null;
    try {
      const htmlDir = path.join(DIAGNOSTICS_DIR, 'html');
      await fs.promises.mkdir(htmlDir, { recursive: true });
      await cleanupOldFiles(htmlDir, MAX_DIAGNOSTIC_AGE_MS);
      mainHtmlPath = path.join(htmlDir, `${base}-main.html`);
      const html = await page.content();
      await fs.promises.writeFile(mainHtmlPath, html.slice(0, 2 * 1024 * 1024), 'utf8');
    } catch (e) {
      fileLog('WARN', `[${username}] HTML diagnostic failed: ${e.message}`);
    }

    // Iframe HTMLs (limit to first 2 frames and size)
    let iframePaths = [];
    try {
      const htmlDir = path.join(DIAGNOSTICS_DIR, 'html');
      await fs.promises.mkdir(htmlDir, { recursive: true });
      const frames = page.frames().slice(0, 2);
      for (let i = 0; i < frames.length; i++) {
        const f = frames[i];
        try {
          const url = f.url();
          const content = await f.content();
          const fpath = path.join(htmlDir, `${base}-frame-${i}-${url.replace(/[^a-z0-9]/gi, '_').slice(0, 80)}.html`);
          await fs.promises.writeFile(fpath, content.slice(0, 2 * 1024 * 1024), 'utf8');
          iframePaths.push(fpath);
        } catch {}
      }
    } catch (e) {
      fileLog('WARN', `[${username}] Iframe diagnostic failed: ${e.message}`);
    }

    fileLog('INFO', `[${username}] Diagnostics saved for ${stage}: screenshot=${screenshotPath}, mainHtml=${mainHtmlPath}, frames=${iframePaths.length}`);
    return { screenshotPath, mainHtmlPath, iframePaths };
  } catch (e) {
    fileLog('WARN', `[${username}] saveDiagnostics error: ${e.message}`);
    return null;
  }
}

function parseSlug(url) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split('/').filter(Boolean);
    const bookIndex = parts.indexOf('book');
    if (bookIndex > 0) return parts[bookIndex - 1];
    return parts[parts.length - 1];
  } catch {
    return url.trim();
  }
}

async function fetchEventDetail(slug) {
  const url = `${WB_API_BASE}/event-detail/${slug}?lang=ar&visible_in=rs`;
  const res = await sessionFetch(url, {
    headers: {
      'Accept': 'application/json',
      'Origin': WB_ORIGIN,
      'Referer': `${WB_ORIGIN}/`,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'token': WB_API_TOKEN,
    },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

/**
 * Extract team choices from a Webook event detail payload.
 * Sports/match events expose teams in several shapes; we try the common ones.
 */
function extractTeamsFromEventDetail(data) {
  if (!data || typeof data !== 'object') return [];

  const channelKeysMap = data.channel_keys || {};

  const normalizeTeam = (t) => {
    if (!t || typeof t !== 'object') return null;
    const id = t._id || t.id || t.team_id || t.teamId;
    const name = t.name || t.title || t.name_ar || t.name_en || t.team_name || t.label;
    if (!id || !name) return null;
    const rawKeys = channelKeysMap[id];
    const channelKeys = Array.isArray(rawKeys)
      ? rawKeys.filter(Boolean)
      : (rawKeys ? [String(rawKeys)] : []);
    return { id: String(id), name: String(name), channelKeys };
  };

  const candidates = [];

  // Common nested paths
  const tryPaths = [
    () => data.teams,
    () => data.event?.teams,
    () => data.match?.teams,
    () => [data.home_team, data.away_team],
    () => [data.match?.home_team, data.match?.away_team],
    () => [data.event?.home_team, data.event?.away_team],
    () => data.favorite_teams,
    () => data.event?.favorite_teams,
  ];

  for (const getter of tryPaths) {
    try {
      const value = getter();
      if (Array.isArray(value)) {
        for (const t of value) {
          const normalized = normalizeTeam(t);
          if (normalized) candidates.push(normalized);
        }
      }
    } catch {}
  }

  // Deduplicate by id
  const seen = new Set();
  const teams = [];
  for (const t of candidates) {
    if (seen.has(t.id)) continue;
    seen.add(t.id);
    teams.push(t);
  }
  return teams;
}

function getCommonChannelKeys(data) {
  if (!data || typeof data !== 'object') return [];
  const value = data.channel_keys?.common;
  return Array.isArray(value) ? value.filter(Boolean) : (value ? [String(value)] : []);
}

function getAllChannelKeys(data) {
  if (!data || typeof data !== 'object') return [];
  const map = data.channel_keys || {};
  const all = new Set();
  for (const [key, value] of Object.entries(map)) {
    if (key === 'common') continue;
    if (Array.isArray(value)) value.filter(Boolean).forEach(v => all.add(String(v)));
    else if (value) all.add(String(value));
  }
  (map.common || []).filter(Boolean).forEach(v => all.add(String(v)));
  return [...all];
}

function enrichSelectedTeam(selectedTeam, teams = [], allChannelKeys = [], commonChannelKeys = []) {
  if (!selectedTeam || !selectedTeam.id) return selectedTeam;
  if (selectedTeam.channelKeys?.length || selectedTeam.allChannelKeys?.length) return selectedTeam;
  const enriched = { ...selectedTeam, allChannelKeys, commonChannelKeys };
  if (selectedTeam.id !== 'ALL_TEAMS') {
    const match = teams.find(t => String(t.id) === String(selectedTeam.id));
    if (match) {
      enriched.channelKeys = match.channelKeys || [];
      enriched.name = match.name || enriched.name;
    }
  }
  return enriched;
}

// ------------------------------------------------------------------
// Webook waiting-room / queue handling
// ------------------------------------------------------------------
function inspectQueueSignals(eventBody, holdBody, holdResponse) {
  // Combine signals from event-detail and hold-token responses to decide queue state.
  const signals = {
    eventQueuedFlag: false,
    eventQueueEnabled: false,
    holdQueuedHeader: false,
    holdQueuedBody: false,
    hasHoldToken: false,
    hasQueueToken: false,
  };

  if (eventBody) {
    const d = eventBody.data || eventBody;
    signals.eventQueuedFlag = !!(d.is_queued || d.queue_enabled || d.waiting_room || d.queue_status === 'queued' || d._queue?.queued);
    signals.eventQueueEnabled = !!(d.queue_enabled !== false && (d.waiting_room || d.queue_status || d.is_queued || d._queue?.queued));
    if (!signals.eventQueueEnabled && d.subscription_benefits?.queue_jump_online) {
      signals.eventQueueEnabled = true;
    }
  }

  if (holdBody) {
    const d = holdBody.data || holdBody;
    signals.holdQueuedBody = !!(d._queue && d._queue.queued);
    signals.hasHoldToken = typeof d.hold_token === 'string' && d.hold_token.length > 0;
    signals.hasQueueToken = typeof d.queue_token === 'string' && d.queue_token.length > 0;
  }

  if (holdResponse) {
    signals.holdQueuedHeader = holdResponse.headers.get('_queued') === 'true';
    if (!signals.hasQueueToken) {
      const qt = holdResponse.headers.get('queue-token');
      signals.hasQueueToken = typeof qt === 'string' && qt.length > 0;
    }
  }

  return signals;
}

function decodeQueueTokenPosition(token) {
  if (!token || typeof token !== 'string') return null;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (payload && typeof payload.n === 'number') return { position: payload.n, total: payload.t };
  } catch {}
  return null;
}

async function checkQueueStatus(slug, authToken, queueToken = '', { includeEventDetail = true, retryOnce = true } = {}) {
  const baseHeaders = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Origin': WB_ORIGIN,
    'Referer': `${WB_ORIGIN}/`,
    'token': WB_API_TOKEN,
  };
  if (authToken) baseHeaders['Authorization'] = `Bearer ${authToken}`;
  if (queueToken) baseHeaders['queue-token'] = queueToken;

  let eventBody = null;
  let eventOk = false;

  if (includeEventDetail) {
    try {
      const eventRes = await fetch(`${WB_API_BASE}/event-detail/${slug}?lang=ar&visible_in=rs`, {
        headers: { ...baseHeaders },
      });
      eventOk = eventRes.ok;
      if (eventOk) eventBody = await eventRes.json().catch(() => null);
    } catch (e) {
      fileLog('WARN', `checkQueueStatus event-detail fetch failed: ${e.message}`);
    }
  }

  let lastError = null;
  for (let attempt = 0; attempt < (retryOnce ? 2 : 1); attempt++) {
    try {
      const res = await fetch(`${WB_API_BASE}/event-detail/${slug}/hold-token?lang=ar`, {
        method: 'POST',
        headers: { ...baseHeaders },
        body: JSON.stringify({ event_id: '', lang: 'ar' }),
      });
      const newQueueToken = res.headers.get('queue-token') || queueToken;
      const body = await res.json().catch(() => ({}));
      const signals = inspectQueueSignals(eventBody, body, res);

      const queue = body._queue || (body.data && body.data._queue) || null;
      const holdToken = body.data && typeof body.data.hold_token === 'string' ? body.data.hold_token : null;

      // Decision logic:
      // - If hold-token returns a hold_token and no queued flag -> OPEN (high confidence).
      // - If queued header/body says queued and no hold_token -> QUEUED.
      // - If event-detail says queued but hold-token gives hold_token -> OPEN (prefer direct token).
      // - If only event-detail says queued and hold-token failed -> UNCERTAIN/QUEUED.
      let queued = false;
      let confidence = 'low';
      if (signals.hasHoldToken && !signals.holdQueuedHeader && !signals.holdQueuedBody) {
        queued = false;
        confidence = 'high';
      } else if (signals.holdQueuedHeader || signals.holdQueuedBody) {
        queued = true;
        confidence = signals.hasQueueToken ? 'high' : 'medium';
      } else if (signals.eventQueuedFlag && !signals.hasHoldToken) {
        queued = true;
        confidence = eventOk ? 'medium' : 'low';
      } else if (signals.eventQueuedFlag && signals.hasHoldToken) {
        queued = false;
        confidence = 'medium';
      } else {
        // No strong signal either way. Default to OPEN: a queue-token by itself
        // does NOT mean the event is queued; many open events issue a token.
        // Only treat as queued if the page or an explicit queued flag says so.
        queued = false;
        confidence = signals.hasHoldToken ? 'high' : (signals.hasQueueToken ? 'medium' : 'low');
      }

      return {
        status: res.status,
        queued,
        confidence,
        signals,
        queue,
        queueToken: newQueueToken,
        holdToken,
        body,
        eventBody,
      };
    } catch (e) {
      lastError = e.message;
      fileLog('WARN', `checkQueueStatus hold-token attempt ${attempt + 1} failed: ${e.message}`);
      await waitFor(150);
    }
  }

  // All attempts failed. Do not assume queued; report uncertain so caller can try the page.
  return {
    status: 0,
    queued: false,
    confidence: 'low',
    signals: inspectQueueSignals(eventBody, null, null),
    queue: null,
    queueToken,
    holdToken: null,
    body: {},
    eventBody,
    error: lastError || 'hold-token unreachable',
    uncertain: true,
  };
}

async function syncQueueTokenToCookie(context, queueToken, holdToken = null) {
  try {
    const cookies = [];
    if (queueToken) {
      cookies.push({
        name: 'queue_session',
        value: queueToken,
        domain: '.webook.com',
        path: '/',
        httpOnly: false,
        secure: true,
        sameSite: 'Lax',
      });
      cookies.push({
        name: 'queue-token',
        value: queueToken,
        domain: '.webook.com',
        path: '/',
        httpOnly: false,
        secure: true,
        sameSite: 'Lax',
      });
    }
    if (holdToken) {
      cookies.push({
        name: 'hold_token',
        value: holdToken,
        domain: '.webook.com',
        path: '/',
        httpOnly: false,
        secure: true,
        sameSite: 'Lax',
      });
    }
    if (cookies.length) await context.addCookies(cookies);
  } catch {}
}

async function setProvidedHoldTokenCookie(context, holdToken, opts = {}) {
  // Set the holdToken + queue_session cookies the way Webook/SeatCloud expect
  // them. The holdToken cookie is bound to the event /book path by WeBook's
  // server, so we set it on that exact path to override any server-issued token.
  if (!holdToken) return;
  const {
    queueToken = null,
    cfClearance = null,
    recaptchaToken = null,
    exactPath = null,
  } = opts;
  try {
    // Clear any stale holdToken / queue session variants first.
    try { await context.clearCookies({ name: 'holdToken' }); } catch {}
    try { await context.clearCookies({ name: 'hold_token' }); } catch {}
    if (queueToken) {
      try { await context.clearCookies({ name: 'queue_session' }); } catch {}
      try { await context.clearCookies({ name: 'queue-token' }); } catch {}
    }
  } catch {}
  const paths = exactPath ? [exactPath, '/'] : ['/'];
  const domains = ['.webook.com', 'webook.com'];
  const cookies = [];
  for (const domain of domains) {
    for (const path of paths) {
      cookies.push({ name: 'holdToken', value: holdToken, domain, path, httpOnly: false, secure: true, sameSite: 'Lax' });
      cookies.push({ name: 'hold_token', value: holdToken, domain, path, httpOnly: false, secure: true, sameSite: 'Lax' });
      if (queueToken) {
        cookies.push({ name: 'queue_session', value: queueToken, domain, path, httpOnly: false, secure: true, sameSite: 'Lax' });
        cookies.push({ name: 'queue-token', value: queueToken, domain, path, httpOnly: false, secure: true, sameSite: 'Lax' });
      }
    }
  }
  if (cfClearance) {
    cookies.push({ name: 'cf_clearance', value: cfClearance, domain: '.webook.com', path: '/', httpOnly: true, secure: true, sameSite: 'None' });
  }
  if (recaptchaToken) {
    cookies.push({ name: '_grecaptcha', value: recaptchaToken, domain: 'www.recaptcha.net', path: '/recaptcha', httpOnly: true, secure: true, sameSite: 'None' });
  }
  try {
    await context.addCookies(cookies);
    fileLog('INFO', `Set provided session cookies: holdToken=${holdToken.slice(0, 8)}...${holdToken.slice(-4)} queue=${queueToken ? 'yes' : 'no'} cf=${cfClearance ? 'yes' : 'no'} path=${exactPath || '/'}`);
  } catch (e) {
    fileLog('WARN', `Could not set provided session cookies: ${e.message}`);
  }
}

function parseRawCookieString(str) {
  const cookies = {};
  if (!str || typeof str !== 'string') return cookies;
  str.split(/;\s*/).forEach(part => {
    const idx = part.indexOf('=');
    if (idx <= 0) return;
    const name = part.slice(0, idx).trim();
    let value = part.slice(idx + 1).trim();
    try { value = decodeURIComponent(value); } catch {}
    if (name) cookies[name] = value;
  });
  return cookies;
}

function normalizeSameSite(value) {
  if (!value || typeof value !== 'string') return 'Lax';
  const v = value.trim().toLowerCase();
  if (v === 'strict') return 'Strict';
  if (v === 'none') return 'None';
  if (v === 'lax') return 'Lax';
  // Cookies Editor / Chrome devtools sometimes export 'unspecified' or 'no_restriction'.
  return 'Lax';
}

async function injectRawCookies(context, rawCookies, exactPath = '/', structuredCookies = null) {
  // Inject cookies copied from Cookies Editor / browser devtools into the
  // Playwright context. Accepts either a JSON array of cookie objects (with
  // domain/path/secure/httpOnly/sameSite) or a header-style string.
  const defaults = { httpOnly: false, secure: true, sameSite: 'Lax' };

  function buildHeaderCookies() {
    const specs = [];
    if (!rawCookies) return specs;
    const parsed = parseRawCookieString(rawCookies);
    const knownMappings = {
      holdToken: [{ domain: 'webook.com', path: exactPath }, { domain: '.webook.com', path: exactPath }, { domain: 'webook.com', path: '/' }, { domain: '.webook.com', path: '/' }],
      hold_token: [{ domain: 'webook.com', path: exactPath }, { domain: '.webook.com', path: exactPath }, { domain: 'webook.com', path: '/' }, { domain: '.webook.com', path: '/' }],
      queue_session: [{ domain: 'webook.com', path: exactPath }, { domain: '.webook.com', path: exactPath }, { domain: 'webook.com', path: '/' }, { domain: '.webook.com', path: '/' }],
      'queue-token': [{ domain: '.webook.com', path: '/' }],
      token: [{ domain: '.webook.com', path: '/' }],
      refresh_token: [{ domain: '.webook.com', path: '/' }],
      token_expires_in: [{ domain: '.webook.com', path: '/' }],
      cf_clearance: [{ domain: '.webook.com', path: '/', httpOnly: true, sameSite: 'None' }],
      __cf_bm: [{ domain: '.webook.com', path: '/', httpOnly: true, sameSite: 'None' }],
      _grecaptcha: [{ domain: 'www.recaptcha.net', path: '/recaptcha', httpOnly: true, sameSite: 'None' }],
    };
    for (const [name, value] of Object.entries(parsed)) {
      const mappings = knownMappings[name];
      if (mappings) {
        for (const m of mappings) {
          specs.push({ name, value, ...defaults, ...m });
        }
      } else if (name.startsWith('_') || name.startsWith('AMP_') || name.startsWith('tt') || name.startsWith('u_')) {
        specs.push({ name, value, ...defaults, domain: '.webook.com', path: '/' });
      } else {
        specs.push({ name, value, ...defaults, domain: 'webook.com', path: '/' });
        specs.push({ name, value, ...defaults, domain: '.webook.com', path: '/' });
      }
    }
    return specs;
  }

  function buildStructuredCookies() {
    const specs = [];
    if (!Array.isArray(structuredCookies) || structuredCookies.length === 0) return specs;
    for (const c of structuredCookies) {
      if (!c || typeof c !== 'object' || typeof c.name !== 'string' || c.value === undefined) continue;
      let domain = c.domain || '.webook.com';
      // Playwright expects domains to start with a dot for cross-subdomain cookies.
      if (domain && !domain.startsWith('.') && domain.includes('.')) domain = '.' + domain;
      let sameSite = normalizeSameSite(c.sameSite);
      let secure = typeof c.secure === 'boolean' ? c.secure : defaults.secure;
      // Playwright rejects sameSite=None unless secure=true.
      if (sameSite === 'None' && !secure) secure = true;
      const spec = {
        name: c.name,
        value: String(c.value),
        domain,
        path: c.path || '/',
        httpOnly: typeof c.httpOnly === 'boolean' ? c.httpOnly : defaults.httpOnly,
        secure,
        sameSite,
      };
      // Browser exports sometimes include expires as epoch seconds; Playwright
      // accepts expires in seconds since epoch. Include it if present and valid.
      if (typeof c.expirationDate === 'number' && c.expirationDate > 0) {
        spec.expires = c.expirationDate;
      } else if (typeof c.expires === 'number' && c.expires > 0) {
        spec.expires = c.expires;
      }
      specs.push(spec);
    }
    return specs;
  }

  let cookieSpecs = buildStructuredCookies();
  let source = Array.isArray(structuredCookies) && structuredCookies.length > 0 ? 'structured JSON' : 'header string';
  if (cookieSpecs.length === 0) {
    cookieSpecs = buildHeaderCookies();
    source = 'header string';
  }
  if (cookieSpecs.length === 0) return;

  try {
    await context.addCookies(cookieSpecs);
    fileLog('INFO', `Injected ${cookieSpecs.length} cookies (${source})`);
    return;
  } catch (e) {
    fileLog('WARN', `Could not inject ${source} cookies: ${e.message}`);
  }

  // Fallback: if structured JSON failed, try the header-string mapping.
  if (source === 'structured JSON' && rawCookies) {
    cookieSpecs = buildHeaderCookies();
    if (cookieSpecs.length === 0) return;
    try {
      await context.addCookies(cookieSpecs);
      fileLog('INFO', `Injected ${cookieSpecs.length} cookies (header string fallback)`);
    } catch (e2) {
      fileLog('WARN', `Could not inject header fallback cookies: ${e2.message}`);
    }
  }
}

async function closeClientChartWebSocket(page) {
  // Force-close any existing SeatCloud WebSocket from the chart's perspective
  // so the next chart render opens a fresh connection under the new token.
  try {
    await page.evaluate(() => {
      try {
        const ws = window.__chartWS;
        if (ws && typeof ws.close === 'function') {
          try { ws.close(1000, 'kimiko-token-swap'); } catch {}
        }
        window.__chartWS = null;
      } catch {}
      // Also wipe any seatsio chart instance that may cache the old token.
      try {
        if (window.chartRender && typeof window.chartRender.destroy === 'function') window.chartRender.destroy();
      } catch {}
      try {
        if (window.chart && typeof window.chart.destroy === 'function') window.chart.destroy();
      } catch {}
      try {
        if (window.SeatsChart && typeof window.SeatsChart.destroy === 'function') window.SeatsChart.destroy();
      } catch {}
      window.chartRender = null;
      window.chart = null;
      window.SeatsChart = null;
    });
  } catch (e) {
    fileLog('DEBUG', `closeClientChartWebSocket error: ${e.message}`);
  }
}

async function injectForcedHoldToken(page, token, username = '') {
  // Inject the provided token into every place the SeatCloud chart looks.
  try {
    await page.evaluate((token) => {
      window.__kimikoForcedHoldToken = token;
      window.holdToken = token;
      window.__INITIAL_STATE__ = window.__INITIAL_STATE__ || {};
      window.__INITIAL_STATE__.hold_token = token;
      try {
        const frame = document.querySelector('iframe[src*="seatcloud"], iframe[src*="chart.seatcloud"]');
        if (frame && frame.contentWindow) {
          frame.contentWindow.holdToken = token;
          frame.contentWindow.__INITIAL_STATE__ = frame.contentWindow.__INITIAL_STATE__ || {};
          frame.contentWindow.__INITIAL_STATE__.hold_token = token;
        }
      } catch {}
    }, token);
    fileLog('INFO', `[${username}] Injected forced hold token into page globals`);
  } catch (e) {
    fileLog('WARN', `[${username}] injectForcedHoldToken error: ${e.message}`);
  }
}

async function swapToProvidedHoldToken(page, session, bookingUrl) {
  // Dedicated flow for holdToken accounts: make the browser page and the
  // intercepted WebSocket use the provided token instead of the logged-in
  // user's token. Must be called BEFORE the chart connects with the wrong token.
  const token = session.providedHoldToken;
  const username = session.username;
  if (!token) return false;

  emitStatus('hold-token-swap', 'Swapping to provided hold token', { account: username, tokenPrefix: token.slice(0, 8), tokenSuffix: token.slice(-4) });

  // Validate the token with SeatCloud before we invest time in the swap.
  const validation = await validateHoldTokenViaSeatCloud(token, session);
  if (!validation.valid) {
    emitStatus('hold-token-invalid', `Provided hold token rejected by SeatCloud: ${validation.reason}`, { account: username, reason: validation.reason });
    fileLog('WARN', `[${username}] Provided hold token invalid: ${validation.reason}`);
  } else {
    emitStatus('hold-token-valid', `Provided hold token valid (TTL ${validation.ttl}s, max holds ${validation.maxNumberOfHolds})`, { account: username, ttl: validation.ttl, maxNumberOfHolds: validation.maxNumberOfHolds });
  }

  // Compute the exact event /book path so our cookies override WeBook's server-set
  // holdToken cookie (which is scoped to the /book path, not root).
  let exactPath = '/';
  try {
    const u = new URL(bookingUrl);
    exactPath = u.pathname;
  } catch {}

  // 1. Cookie first, before any navigation. Include queue_session if supplied,
  //    because SeatCloud validates the hold token against the queue session.
  await setProvidedHoldTokenCookie(session.context, token, {
    queueToken: session.providedQueueToken,
    cfClearance: session.providedCfClearance,
    recaptchaToken: session.providedRecaptchaToken,
    exactPath,
  });

  // 2. Register the forced token for this page so readChartHoldToken and the
  //    WebSocket route rewrite always prefer it.
  forcedHoldTokenRegistry.set(page, token);

  // 3. Close any existing chart WebSocket / chart instance so it reconnects fresh.
  await closeClientChartWebSocket(page);

  // 4. Reset the intercepted route so the next WS connection is treated as new.
  resetWebSocketRouteState(page);

  // 5. Navigate to the booking URL with the provided token in the query string.
  //    The server-rendered page will see ?hold_token=TOKEN and the cookie.
  const swapUrl = `${bookingUrl}${bookingUrl.includes('?') ? '&' : '?'}hold_token=${encodeURIComponent(token)}`;
  try {
    await page.goto(swapUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
  } catch (e) {
    fileLog('WARN', `[${username}] swap navigation error: ${e.message}`);
  }

  // 5b. Re-set cookies after navigation in case WeBook's server overwrote them.
  await setProvidedHoldTokenCookie(session.context, token, {
    queueToken: session.providedQueueToken,
    cfClearance: session.providedCfClearance,
    recaptchaToken: session.providedRecaptchaToken,
    exactPath,
  });

  // 6. Re-inject globals after navigation in case the page overwrote them.
  await injectForcedHoldToken(page, token, username);

  // 7. Try to patch the iframe src if it already loaded with the wrong token.
  await patchChartIframeToken(page, token, username);

  // 8. Wait for the WebSocket route to be ready and confirm it is using the
  //    provided token. If not, force another reconnect cycle.
  const ready = await waitForWsRouteReady(page, 3000);
  const actualToken = await readChartHoldToken(page);
  if (!ready || !actualToken || actualToken !== token) {
    fileLog('WARN', `[${username}] WS route not ready with provided token after swap (actual=${actualToken ? actualToken.slice(0, 8) : 'none'}); forcing reconnect`);
    await closeClientChartWebSocket(page);
    resetWebSocketRouteState(page);
    await injectForcedHoldToken(page, token, username);
    await patchChartIframeToken(page, token, username);
    // Re-set cookies one more time to be sure.
    await setProvidedHoldTokenCookie(session.context, token, {
      queueToken: session.providedQueueToken,
      cfClearance: session.providedCfClearance,
      recaptchaToken: session.providedRecaptchaToken,
      exactPath,
    });
    // Give the iframe a moment to reconnect.
    await waitFor(200);
  }

  session.holdToken = token;
  touchHoldToken(session, token, HOLD_TOKEN_EXTENSION_MINUTES);
  fileLog('INFO', `[${username}] Hold token swap complete; page token=${(await readChartHoldToken(page) || '').slice(0, 12)}...`);
  return true;
}

async function waitForQueueClear(page, username, session, slug, timeoutMs = 20 * 60 * 1000) {
  if (session.stopRequested) throw new Error('Stopped while waiting in queue');
  const authToken = await getAuthTokenFromContext(session.context, username);
  if (!authToken) {
    fileLog('WARN', `[${username}] Cannot poll queue status without auth token; relying on page reload.`);
    return { cleared: false, reason: 'no-auth-token' };
  }

  let queueToken = session.queueToken || '';
  const start = Date.now();
  let lastPosition = null;
  let lastReport = 0;
  let lastKeepAlive = 0;
  let currentAuthToken = authToken;
  let firstPoll = true;

  emitStatus('queue-waiting', 'Event is in waiting room; polling queue API aggressively...', { account: username });
  session.state = 'queue-waiting';

  // Start real-time timer watcher for the queue page countdown.
  startPageTimerWatcher(session);

  while (Date.now() - start < timeoutMs) {
    if (session.stopRequested) throw new Error('Stopped while waiting in queue');

    try {
      // Skip the heavy event-detail call after the first poll; we only need queue status.
      const status = await checkQueueStatus(slug, currentAuthToken, queueToken, { includeEventDetail: firstPoll, retryOnce: !firstPoll });
      firstPoll = false;
      const newQueueToken = status.queueToken || queueToken;
      const tokenChanged = newQueueToken !== queueToken;
      queueToken = newQueueToken;
      session.queueToken = queueToken;
      // Sync latest queue token + any newly arrived hold token to browser cookies.
      if (tokenChanged || status.holdToken) {
        await syncQueueTokenToCookie(session.context, queueToken, status.holdToken);
      }

      // Instant exit the exact millisecond the API says open and provides a hold token.
      if (!status.queued && status.holdToken) {
        stopPageTimerWatcher(session);
        if (queueToken) {
          setGlobalValidQueueToken(queueToken);
          broadcastQueueTokenToPending(queueToken);
        }
        emitStatus('queue-cleared', 'Queue cleared via API; proceeding directly to WebSocket attack.', { account: username, holdToken: true });
        return { cleared: true, queueToken, holdToken: status.holdToken };
      }

      // API says open but no hold token yet; keep polling briefly rather than waiting for UI.
      if (!status.queued) {
        stopPageTimerWatcher(session);
        if (queueToken) {
          setGlobalValidQueueToken(queueToken);
          broadcastQueueTokenToPending(queueToken);
        }
        emitStatus('queue-cleared', 'Queue cleared via API (no hold token yet).', { account: username });
        return { cleared: true, queueToken, holdToken: status.holdToken || null };
      }

      // Aggressive bypass: even when the queue API says queued, directly ask the
      // hold-token endpoint for a token. If it returns one, the queue has actually
      // cleared and we should attack immediately.
      if (status.queued && !status.holdToken && Date.now() - start < 120000) {
        try {
          const directToken = await getHoldTokenFromApi(slug, '', session);
          if (directToken) {
            stopPageTimerWatcher(session);
            emitStatus('queue-cleared', 'Queue bypassed via direct hold-token fetch.', { account: username, holdToken: true });
            return { cleared: true, queueToken, holdToken: directToken };
          }
        } catch (e) {
          fileLog('WARN', `[${username}] Direct hold-token bypass attempt failed: ${e.message}`);
        }
      }

      let q = status.queue;
      // Fallback: if the API body does not expose a position, decode it from the queue_session JWT.
      if ((!q || typeof q.waiting_number !== 'number') && queueToken) {
        const decoded = decodeQueueTokenPosition(queueToken);
        if (decoded) {
          q = { waiting_number: decoded.position, total_in_queue: decoded.total };
        }
      }
      if (q && typeof q.waiting_number === 'number') {
        if (lastPosition === null || q.waiting_number !== lastPosition || Date.now() - lastReport > 10000) {
          lastPosition = q.waiting_number;
          lastReport = Date.now();
          emitStatus('queue-position', `Queue position ~${q.waiting_number} / ${q.total_in_queue || '?'}`, {
            account: username,
            position: q.waiting_number,
            total: q.total_in_queue,
          });
          emitAccountUpdate(username, 'queued', { position: q.waiting_number, total: q.total_in_queue });
        }
      }

    } catch (e) {
      fileLog('WARN', `[${username}] Queue poll error: ${e.message}`);
    }

    // Session keep-alive: refresh auth token and ping page so the browser context stays alive.
    if (Date.now() - lastKeepAlive > 30000) {
      lastKeepAlive = Date.now();
      try {
        const freshToken = await getAuthTokenFromContext(session.context, username);
        if (freshToken) currentAuthToken = freshToken;
        if (page && !page.isClosed()) {
          await page.evaluate(() => { window.__kimikoQueueKeepAlive = Date.now(); }).catch(() => {});
        }
      } catch (e) {
        fileLog('WARN', `[${username}] Queue keep-alive error: ${e.message}`);
      }
    }

    // Poll aggressively for real-time queue changes (sub-second).
    await waitFor(100);
  }

  throw new Error('Queue did not clear within timeout');
}

function startPageTimerWatcher(session) {
  // Continuously read the countdown timer from the page (queue or booking)
  // and emit real-time updates. Used by the UI and by pair cycling handoff.
  if (session.__timerWatcher) return;
  let lastSeconds = null;
  let lastText = null;
  session.__timerWatcher = setInterval(async () => {
    try {
      if (session.stopRequested || !session.page || await isPageClosed(session.page)) {
        stopPageTimerWatcher(session);
        return;
      }
      const info = await extractQueueTimer(session.page);
      if (!info.found) {
        // Clear the stored timer when no timer is visible so keepalive does not
        // make extension decisions based on a stale value.
        if (session.lastPageTimerSeconds !== null) {
          session.lastPageTimerSeconds = null;
          session.lastPageTimerText = null;
        }
        return;
      }
      const seconds = parseQueueTimerText(info.text);
      if (seconds === null) return;
      if (seconds !== lastSeconds || info.text !== lastText) {
        lastSeconds = seconds;
        lastText = info.text;
        const mm = Math.floor(seconds / 60).toString().padStart(2, '0');
        const ss = (seconds % 60).toString().padStart(2, '0');
        session.lastPageTimerSeconds = seconds;
        session.lastPageTimerText = `${mm}:${ss}`;
        emitStatus('hold-timer', `Time remaining: ${mm}:${ss}`, {
          account: session.username,
          seconds,
          text: info.text,
          timerText: `${mm}:${ss}`,
        });
        emitAccountUpdate(session.username, session.state || 'holding', {
          timer: seconds,
          timerText: `${mm}:${ss}`,
        });
      }
    } catch {
      // Ignore polling errors; page may be navigating.
    }
  }, 300);
}

function stopPageTimerWatcher(session) {
  if (session.__timerWatcher) {
    clearInterval(session.__timerWatcher);
    session.__timerWatcher = null;
  }
}

async function getAuthTokenFromContext(context, username) {
  try {
    const cookies = await context.cookies(['https://webook.com/', 'https://api.webook.com/']);
    const tokenNames = ['token', 'access_token', 'api_token', 'webook_token', 'auth_token'];
    for (const name of tokenNames) {
      const tokenCookie = cookies.find(c => c.name === name && c.value);
      if (tokenCookie) return tokenCookie.value;
    }
    return null;
  } catch (e) {
    fileLog('WARN', `[${username}] Failed to read auth token from context: ${e.message}`);
    return null;
  }
}

async function getHoldTokenFromContext(context) {
  try {
    const cookies = await context.cookies(['https://webook.com/', 'https://api.webook.com/']);
    for (const name of ['holdToken', 'hold_token']) {
      const c = cookies.find(cookie => cookie.name === name && cookie.value);
      if (c) return c.value;
    }
    return null;
  } catch {
    return null;
  }
}

async function isQueuePage(page) {
  try {
    return await page.evaluate(() => {
      const text = (document.body ? (document.body.innerText || '') : '').toLowerCase();
      const pathname = (window.location.pathname || '').toLowerCase();

      // Strong signal: queue page URL does NOT end with /book
      const onBookPage = pathname.endsWith('/book');

      // Booking hold countdown/timer is NEVER a queue. The text "للحجز" means
      // "time left to complete booking" once seats are held, not waiting-room time.
      if (document.querySelector('[data-testid="countdown-timer"]')) return false;
      if (text.includes('للحجز')) return false;

      const queueKeywords = [
        'الطابور', 'طابور', 'queue', 'waiting room', 'waitingroom',
        'أمامك', 'أمامك فى الطابور', 'in the queue', 'تحتاج إلى الانتظار', 'انتظر دورك',
        'position', 'queue position', 'queue-token', 'queue_token', 'مكانك',
        'عداد', 'counter', ' estimated ', 'waiting time',
      ];
      const hasKeyword = queueKeywords.some(k => text.includes(k));
      const hasQueueCounter = !!(
        document.querySelector('[data-testid*="queue" i]') ||
        document.querySelector('[data-testid="queue-timer"]') ||
        document.querySelector('[data-testid="queue-position"]') ||
        document.querySelector('[data-testid="queue-progress"]') ||
        document.querySelector('[class*="queue" i]') ||
        document.querySelector('[id*="queue" i]') ||
        document.querySelector('progress') ||
        document.querySelector('[role="progressbar"]')
      );

      // If we are on /book and the stadium canvas is visible, it is NOT a queue page.
      const hasStadiumCanvas = !!document.querySelector('canvas#canvas[aria-label*="Stadium seats map"]');
      if (onBookPage && hasStadiumCanvas) return false;

      // If the URL lacks /book and shows queue indicators, it IS a queue page.
      if (!onBookPage && (hasKeyword || hasQueueCounter)) return true;

      // Fallback: explicit queue indicators even on /book (rare, but possible during handoff).
      return (hasKeyword || hasQueueCounter) && !hasStadiumCanvas;
    });
  } catch {
    return false;
  }
}

async function isBookingPageReady(page) {
  try {
    return await page.evaluate(() => {
      function isInteractive(node) {
        if (!node) return false;
        const style = window.getComputedStyle(node);
        if (style.display === 'none' || style.visibility === 'hidden' || style.pointerEvents === 'none') return false;
        const rect = node.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
      }
      function hasVisibleTurnstile() {
        const selectors = [
          '[data-testid="turnstile-widget"]',
          'iframe[src*="turnstile"]',
          'iframe[src*="challenges.cloudflare"]',
          'iframe[id^="cf-chl-widget-"]',
          '.cf-turnstile',
          '[name="cf-turnstile-response"]',
        ];
        return selectors.some(sel => {
          const node = document.querySelector(sel);
          if (!node) return false;
          const style = window.getComputedStyle(node);
          return style.display !== 'none' && style.visibility !== 'hidden';
        });
      }

      const pathname = (window.location.pathname || '').toLowerCase();
      const onBookPage = pathname.endsWith('/book');
      if (hasVisibleTurnstile()) return false;

      const hasStadiumCanvas = !!document.querySelector('canvas#canvas[aria-label*="Stadium seats map"]');
      const hasIframe = !!document.querySelector('iframe[src*="seatcloud"], iframe[src*="seats.io"], iframe[src*="chart.seatcloud"]');
      const chartRoot = document.querySelector('#chart, #seat-chart, [data-testid*="chart" i], [class*="seatsio" i]');
      const hasChartRoot = isInteractive(chartRoot);
      const hasHoldToken = !!((window.__INITIAL_STATE__ && window.__INITIAL_STATE__.hold_token) || window.holdToken);
      return onBookPage && (hasStadiumCanvas || hasIframe || hasChartRoot || hasHoldToken);
    });
  } catch {
    return false;
  }
}

async function isTeamSelectionPage(page) {
  try {
    return await page.evaluate(() => {
      const text = (document.body ? (document.body.innerText || '') : '').toLowerCase();
      const hasTeamForm = !!document.querySelector('form#booking-form-teams');
      const hasTeamPrompt = text.includes('اختر فريقك') || text.includes('أي فريق ستشجع؟') || text.includes('اختيارك سيحدد');
      const hasConfirmButton = !!document.querySelector('[data-testid="ticketing_teams_confirm_team_button"]');
      const hasCheckbox = !!document.querySelector('input[type="checkbox"]');
      return hasTeamForm || hasTeamPrompt || (hasConfirmButton && hasCheckbox);
    });
  } catch {
    return false;
  }
}

async function handleTeamSelection(page, session, selectedTeam) {
  const username = session.username;
  if (!selectedTeam || !selectedTeam.id) {
    emitStatus('team-selection-missing', 'الفعالية تتطلب اختيار فريق لكن لم يتم تحديد فريق؛ تخطي', { account: username });
    return false;
  }

  // Persist the selection (including SeatCloud channel UUIDs) on the session so
  // subsequent item/hold/held API calls use the correct allocation channel.
  session.selectedTeam = selectedTeam;

  if (selectedTeam.id === 'ALL_TEAMS') {
    emitStatus('team-all', 'اختيار كل الفرق: سيتم تحميل كل الكراسي المتاحة', { account: username });
  }

  emitStatus('team-selecting', `اختيار الفريق: ${selectedTeam.name}`, { account: username, teamId: selectedTeam.id, teamName: selectedTeam.name });

  // Try the API first (fastest and most reliable).
  let apiOk = false;
  try {
    const authToken = await getAuthTokenFromContext(session.context, username);
    const apiUrl = `${WB_API_BASE}/update-favorite-team?lang=ar`;
    const res = await session.context.request.fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Origin': WB_ORIGIN,
        'Referer': `${WB_ORIGIN}/`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ...(authToken ? { 'token': authToken } : {}),
      },
      data: JSON.stringify({ favorite_team: selectedTeam.id }),
    });
    apiOk = res.ok();
    fileLog('INFO', `[${username}] update-favorite-team API status: ${res.status()}`);
  } catch (apiErr) {
    fileLog('WARN', `[${username}] update-favorite-team API failed: ${apiErr.message}`);
  }

  // UI selection: pick the team, accept terms, click next/confirm.
  let uiOk = false;
  try {
    const teamPicked = await page.evaluate((teamId, teamName) => {
      const normalize = s => (s || '').toLowerCase().replace(/\s+/g, ' ').trim();
      const tId = String(teamId).trim();
      const tName = normalize(teamName);

      // 1. Prefer a radio whose value matches the team id/name.
      const radios = Array.from(document.querySelectorAll('input[type="radio"]'));
      let radio = radios.find(r => String(r.value || '').trim() === tId || normalize(r.value || '') === tName);
      if (!radio) {
        radio = radios.find(r => {
          const name = normalize(r.name || '');
          return name.includes('favorite') || name.includes('team') || name.includes('club');
        });
      }
      if (radio && !radio.checked) {
        radio.scrollIntoView({ behavior: 'instant', block: 'center' });
        radio.click();
        radio.dispatchEvent(new Event('change', { bubbles: true }));
        radio.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      }

      // 2. Fallback: click the label/row containing the team name.
      const all = Array.from(document.querySelectorAll('label, button, div[role="radio"], div[role="button"], div, span, p'));
      const teamEl = all.find(e => {
        const text = normalize(e.innerText || e.textContent || '');
        return text === tName || text.includes(tName);
      });
      if (teamEl) {
        teamEl.scrollIntoView({ behavior: 'instant', block: 'center' });
        teamEl.click();
        return true;
      }
      return false;
    }, selectedTeam.id, selectedTeam.name);

    if (!teamPicked) {
      fileLog('WARN', `[${username}] Could not locate team UI element for ${selectedTeam.name}; will rely on API`);
    } else {
      await waitFor(200);
    }

    // Accept terms checkbox.
    const termsChecked = await page.evaluate(() => {
      const normalize = s => (s || '').toLowerCase().replace(/\s+/g, ' ').trim();
      let cb = document.querySelector('input[name="team_terms"][type="checkbox"], input[name="terms"][type="checkbox"], input[name="agreement"][type="checkbox"], input[name="accept_terms"][type="checkbox"]');

      if (!cb) {
        const labels = Array.from(document.querySelectorAll('label'));
        const label = labels.find(l => {
          const t = normalize(l.textContent || '');
          return t.includes('أوافق') || t.includes('الشروط') || t.includes('الأحكام') || t.includes('فريقي المفضل') ||
                 t.includes('terms') || t.includes('conditions') || t.includes('agree') || t.includes('accept');
        });
        if (label) {
          cb = label.querySelector('input[type="checkbox"]');
          if (!cb) {
            label.scrollIntoView({ behavior: 'instant', block: 'center' });
            label.click();
            return true;
          }
        }
      }

      if (cb && !cb.checked) {
        cb.scrollIntoView({ behavior: 'instant', block: 'center' });
        cb.click();
        cb.dispatchEvent(new Event('change', { bubbles: true }));
        cb.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      }
      return !!cb && cb.checked;
    });

    if (!termsChecked) {
      fileLog('WARN', `[${username}] Could not locate terms checkbox on team-selection page`);
    } else {
      await waitFor(200);
    }

    // Click confirm/next button.
    const confirmClicked = await page.evaluate(() => {
      const normalize = s => (s || '').toLowerCase().replace(/\s+/g, ' ').trim();
      const btn = document.querySelector('[data-testid="ticketing_teams_confirm_team_button"]')
        || Array.from(document.querySelectorAll('button, a, input[type="submit"], div[role="button"]')).find(b => {
          const t = normalize(b.innerText || b.value || b.textContent || '');
          return t.includes('التالى') || t.includes('التالي') || t.includes('next') || t.includes('confirm') ||
                 t.includes('تأكيد') || t.includes('متابعة') || t.includes('احجز') || t.includes('حجز') ||
                 t.includes('proceed') || t.includes('continue');
        });
      if (btn) {
        btn.scrollIntoView({ behavior: 'instant', block: 'center' });
        btn.click();
        return true;
      }
      return false;
    });

    if (!confirmClicked) {
      fileLog('WARN', `[${username}] Could not locate team confirm/next button`);
    } else {
      uiOk = true;
      emitStatus('team-selected', `تم اختيار الفريق ${selectedTeam.name} والانتقال للتذاكر`, { account: username, teamId: selectedTeam.id, teamName: selectedTeam.name });

      // Wait for the team selection UI to disappear and the booking/chart page to load.
      for (let i = 0; i < 80; i++) {
        await waitFor(100);
        const stillTeamPage = await isTeamSelectionPage(page);
        const currentUrl = page.url();
        if (!stillTeamPage && (currentUrl.includes('/book') || await isBookingPageReady(page))) {
          break;
        }
      }
    }
  } catch (uiErr) {
    fileLog('WARN', `[${username}] Team selection UI handling error: ${uiErr.message}`);
  }

  // If the API call succeeded but the UI click path could not confirm, reload
  // and let the backend state take effect.
  if (apiOk && !uiOk) {
    try {
      await page.reload({ waitUntil: 'domcontentloaded', timeout: 60000 });
      emitStatus('team-selected', `تم اختيار الفريق ${selectedTeam.name} عبر API`, { account: username, teamId: selectedTeam.id, teamName: selectedTeam.name });
      return true;
    } catch {}
  }

  return apiOk || uiOk;
}

async function detectBookingPageState(page) {
  try {
    return await page.evaluate(() => {
      function isInteractive(node) {
        if (!node) return false;
        const style = window.getComputedStyle(node);
        if (style.display === 'none' || style.visibility === 'hidden' || style.pointerEvents === 'none') return false;
        const rect = node.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
      }
      function hasVisibleTurnstile() {
        const selectors = [
          '[data-testid="turnstile-widget"]',
          'iframe[src*="turnstile"]',
          'iframe[src*="challenges.cloudflare"]',
          'iframe[id^="cf-chl-widget-"]',
          '.cf-turnstile',
          '[name="cf-turnstile-response"]',
        ];
        return selectors.some(sel => {
          const node = document.querySelector(sel);
          if (!node) return false;
          const style = window.getComputedStyle(node);
          return style.display !== 'none' && style.visibility !== 'hidden';
        });
      }

      const pathname = (window.location.pathname || '').toLowerCase();
      const text = (document.body ? (document.body.innerText || '') : '').toLowerCase();
      const title = (document.title || '').toLowerCase();

      const onBookPage = pathname.endsWith('/book');
      const hasCountdown = !!document.querySelector('[data-testid="countdown-timer"]');
      const hasStadiumCanvas = !!document.querySelector('canvas#canvas[aria-label*="Stadium seats map"]');
      const hasChartIframe = !!document.querySelector('iframe[src*="seatcloud"], iframe[src*="seats.io"], iframe[src*="chart.seatcloud"]');
      const chartRoot = document.querySelector('#chart, #seat-chart, [data-testid*="chart" i], [class*="seatsio" i]');
      const hasChartRoot = isInteractive(chartRoot);
      const hasChart = hasStadiumCanvas || hasChartIframe || hasChartRoot;
      const hasHoldToken = !!((window.__INITIAL_STATE__ && window.__INITIAL_STATE__.hold_token) || window.holdToken);
      const turnstileVisible = hasVisibleTurnstile();

      const loginKeywords = ['تسجيل الدخول', 'login', 'email', 'password', 'كلمة المرور', 'البريد الإلكتروني', 'sign in'];
      const hasLoginForm = !!(
        document.querySelector('input[type="password"]') ||
        document.querySelector('input[name="email"], input[type="email"]') ||
        document.querySelector('button[type="submit"]') ||
        document.querySelector('form')
      );
      const hasLoginText = loginKeywords.some(k => text.includes(k));

      const notFoundKeywords = ['404', 'page not found', 'الصفحة غير موجودة', 'not found', 'something went wrong'];
      const isNotFound = title.includes('404') || notFoundKeywords.some(k => text.includes(k));

      const queueKeywords = ['الطابور', 'طابور', 'queue', 'waiting room', 'waitingroom', 'انتظر دورك', 'دورك'];
      // The booking hold timer text (e.g. "07:37 للحجز") must not be treated as a queue signal.
      const isBookingHoldTimerText = text.includes('للحجز');
      const isQueueText = !isBookingHoldTimerText && queueKeywords.some(k => text.includes(k));
      const isQueueElement = !!(
        document.querySelector('[data-testid="queue-timer"]') ||
        document.querySelector('[data-testid="queue-position"]') ||
        document.querySelector('[data-testid="queue-progress"]') ||
        document.querySelector('[class*="queue" i]') ||
        document.querySelector('[class*="waiting" i]')
      );
      // A visible booking countdown/timer on /book overrides any ambiguous queue heuristic.
      const isQueue = !hasCountdown && !isBookingHoldTimerText && (isQueueText || isQueueElement);

      const hasTeamPrompt = text.includes('اختر فريقك') || text.includes('أي فريق ستشجع؟') || text.includes('اختيارك سيحدد') || text.includes('فريقك المفضل');
      const hasConfirmTeamButton = !!document.querySelector('[data-testid="ticketing_teams_confirm_team_button"]');
      const hasTeamCheckbox = !!document.querySelector('input[type="checkbox"]') && text.includes('أوافق على حجز المقاعد');
      const isTeamSelection = hasTeamPrompt || hasConfirmTeamButton || hasTeamCheckbox;

      if (isNotFound) return { state: 'not-found', reason: '404/not-found' };
      if (isQueue) return { state: 'queue', reason: 'queue-page' };
      if (isTeamSelection) return { state: 'team-selection', reason: 'team-selection-page' };
      if (turnstileVisible) return { state: 'turnstile-pending', hasChart, hasCountdown, hasHoldToken, reason: 'turnstile-overlay-visible' };
      if (onBookPage && (hasChart || hasCountdown || hasHoldToken)) return { state: 'booking-ready', hasChart, hasCountdown, hasHoldToken, reason: 'chart-or-timer-detected' };
      if (hasLoginForm || hasLoginText) return { state: 'login', reason: 'login-form-or-text' };
      return { state: 'unknown', reason: 'no-clear-signals', onBookPage, hasChart, hasCountdown, hasLoginForm, hasLoginText, turnstileVisible };
    });
  } catch {
    return { state: 'unknown', reason: 'eval-error' };
  }
}

async function detectQueueStateAccurate(page, username = '') {
  try {
    const result = await page.evaluate(() => {
      const pathname = (window.location.pathname || '').toLowerCase();
      const text = (document.body ? (document.body.innerText || '') : '').toLowerCase();

      const onBookPage = pathname.endsWith('/book');
      const hasCountdown = !!document.querySelector('[data-testid="countdown-timer"]');
      const hasStadiumCanvas = !!document.querySelector('canvas#canvas[aria-label*="Stadium seats map"]');
      const hasChartIframe = !!document.querySelector('iframe[src*="seatcloud"], iframe[src*="seats.io"], iframe[src*="chart.seatcloud"]');
      const chartRoot = document.querySelector('#chart, #seat-chart, [data-testid*="chart" i], [class*="seatsio" i]');
      const hasChart = hasStadiumCanvas || hasChartIframe || !!chartRoot;

      if (onBookPage && (hasChart || hasCountdown)) {
        return { isInQueue: false, confidence: 'high', evidence: ['on-book-page-with-chart-or-timer'], hasChart, hasTimer: hasCountdown, queuePosition: null };
      }

      const queueSelectors = [
        '[data-testid="queue-timer"]',
        '[data-testid="queue-position"]',
        '[data-testid="queue-progress"]',
        '[data-testid="queue-status"]',
      ];
      const queueElements = queueSelectors.map(s => document.querySelector(s)).filter(Boolean);
      const hasQueueElement = queueElements.length > 0;

      const queueClassPattern = /queue|waiting|waitroom|waitingroom/;
      const hasQueueClass = Array.from(document.querySelectorAll('*')).some(el => queueClassPattern.test((el.className || '') + ' ' + (el.getAttribute('data-testid') || '')));

      const queueKeywords = ['الطابور', 'طابور', 'queue', 'waiting room', 'waitingroom', 'انتظر دورك', 'دورك', 'you are in line', 'in line'];
      const isBookingHoldTimerText = text.includes('للحجز');
      const hasQueueText = !isBookingHoldTimerText && queueKeywords.some(k => text.includes(k));

      const urlQueueSignal = /queue|waiting|waitroom/.test(pathname + window.location.search);

      let queuePosition = null;
      for (const el of queueElements) {
        const elText = (el.innerText || el.textContent || '').trim();
        const m = elText.match(/(\d+)/);
        if (m) { queuePosition = parseInt(m[1], 10); break; }
      }
      if (queuePosition === null && hasQueueText) {
        const m = text.match(/(?:position|موقعك|دورك|r?\#?)\s*(\d+)/i);
        if (m) queuePosition = parseInt(m[1], 10);
      }

      const isQueue = hasQueueElement || (hasQueueText && hasQueueClass) || (hasQueueText && urlQueueSignal) || (hasQueueText && !onBookPage && !hasChart && !hasCountdown);
      const isInQueue = isQueue;

      const evidence = [];
      if (hasQueueElement) evidence.push('queue-element-detected');
      if (hasQueueClass) evidence.push('queue-class-detected');
      if (hasQueueText) evidence.push('queue-text-detected');
      if (urlQueueSignal) evidence.push('url-queue-signal');
      if (hasChart) evidence.push('chart-present');
      if (hasCountdown) evidence.push('booking-timer-present');

      return {
        isInQueue,
        confidence: hasQueueElement ? 'high' : (isQueue ? 'medium' : 'low'),
        evidence,
        hasChart,
        hasTimer: hasCountdown,
        queuePosition,
      };
    });
    fileLog('INFO', `[queue-detect] ${username}: isInQueue=${result.isInQueue}, confidence=${result.confidence}, evidence=${result.evidence.join('|')}`);
    return result;
  } catch (err) {
    fileLog('WARN', `[queue-detect] ${username}: detection error: ${err.message}`);
    return { isInQueue: false, confidence: 'error', evidence: ['eval-error'], hasChart: false, hasTimer: false, queuePosition: null };
  }
}

function parseQueueTimerText(text) {
  // Matches timers like "07:59 للحجز", "7:59", "07:59:12" -> returns total seconds.
  if (!text) return null;
  const m = text.match(/(\d{1,2})[:\s](\d{2})(?:[:\s](\d{2}))?/);
  if (!m) return null;
  const minutes = parseInt(m[1], 10);
  const seconds = parseInt(m[2], 10);
  const hours = m[3] ? parseInt(m[3], 10) : 0;
  if (isNaN(minutes) || isNaN(seconds) || isNaN(hours)) return null;
  return hours * 3600 + minutes * 60 + seconds;
}

async function extractQueueTimer(page) {
  try {
    return await page.evaluate(() => {
      // Primary: the official booking-page countdown container.
      const countdownTimer = document.querySelector('[data-testid="countdown-timer"]');
      if (countdownTimer) {
        const text = (countdownTimer.innerText || countdownTimer.textContent || '').trim();
        if (/\d{1,2}:\d{2}/.test(text)) return { text, found: true };
      }
      // Secondary: green/success timer used on some queue and booking builds.
      const successSpan = document.querySelector('span.text-success, .text-success');
      if (successSpan) {
        const container = successSpan.closest('p, div, span') || successSpan;
        const text = (container.innerText || container.textContent || '').trim();
        if (/\d{1,2}:\d{2}/.test(text)) return { text, found: true };
      }
      // Tertiary: any visible timer-like element.
      const timerSelectors = ['.timer', '#timer', '[class*="timer" i]', '[class*="countdown" i]'];
      for (const sel of timerSelectors) {
        const el = document.querySelector(sel);
        if (el) {
          const text = (el.innerText || el.textContent || '').trim();
          if (/\d{1,2}:\d{2}/.test(text)) return { text, found: true };
        }
      }
      // Fallback: any visible element containing a time-like string near booking/payment text.
      const all = Array.from(document.querySelectorAll('span, p, div, h1, h2, h3, h4, h5, h6'));
      const el = all.find(e => {
        const t = (e.innerText || '').trim();
        return /\d{1,2}:\d{2}/.test(t) && /(للحجز|booking|queue|payment|دفع|الحجز|لإكمال)/i.test(t);
      });
      if (el) return { text: el.innerText.trim(), found: true };
      return { text: '', found: false };
    });
  } catch {
    return { text: '', found: false };
  }
}

const TURNSTILE_SELECTORS = [
  '[data-testid="turnstile-widget"]',
  'iframe[src*="turnstile"]',
  'iframe[src*="challenges.cloudflare"]',
  'iframe[id^="cf-chl-widget-"]',
  '.cf-turnstile',
  '[name="cf-turnstile-response"]',
  'iframe[title*="challenge" i]',
];

async function isTurnstilePresent(page) {
  if (!page || await isPageClosed(page)) return false;
  try {
    for (const sel of TURNSTILE_SELECTORS) {
      const el = await page.$(sel);
      if (el) {
        const visible = await el.isVisible().catch(() => false);
        if (visible) return true;
      }
    }
    // Also check inside frames (e.g. Turnstile rendered in an iframe).
    for (const frame of page.frames()) {
      try {
        const hasWidget = await frame.evaluate((selectors) => selectors.some(s => {
          const node = document.querySelector(s);
          if (!node) return false;
          const rect = node.getBoundingClientRect();
          return rect.width > 0 && rect.height > 0;
        }), TURNSTILE_SELECTORS);
        if (hasWidget) return true;
      } catch {}
    }
  } catch {}
  return false;
}

async function waitForTurnstileToClear(page, timeout = 30000, username = 'unknown') {
  const start = Date.now();
  try {
    if (!await isTurnstilePresent(page)) {
      fileLog('INFO', `[${username}] [turnstile] No Turnstile widget found or already cleared.`);
      return true;
    }
    fileLog('INFO', `[${username}] [turnstile] Turnstile widget detected, waiting for it to clear...`);
    while (Date.now() - start < timeout) {
      if (!await isTurnstilePresent(page)) {
        fileLog('INFO', `[${username}] [turnstile] Turnstile cleared successfully.`);
        return true;
      }
      await waitFor(250);
    }
    return false;
  } catch (err) {
    fileLog('WARN', `[${username}] [turnstile] waitForTurnstileToClear error: ${err.message}`);
    return false;
  }
}



async function waitForSeatChartInteractive(page, timeout = 30000) {
  const chartSelector = '#chart, #seat-chart, .seats-chart, [data-testid="seat-chart"]';
  await page.waitForSelector(chartSelector, { state: 'visible', timeout });
  const isBlocked = await page.evaluate((selector) => {
    const chart = document.querySelector(selector);
    if (!chart) return true;
    const style = window.getComputedStyle(chart);
    return style.pointerEvents === 'none' || parseFloat(style.opacity) === 0 || chart.offsetParent === null;
  }, chartSelector);
  if (isBlocked) {
    throw new Error('Seat chart is not interactive (blocked by overlay)');
  }
}

async function waitForBookingTrigger(page, timeoutMs = 8000, deadlineSeconds = 600) {
  // Ultra-fast booking-open detector. Uses a DOM MutationObserver for instant
  // notification plus a 10ms polling fallback, so the sniper fires the exact
  // millisecond the chart/canvas/timer appears.
  const start = Date.now();
  const pollInterval = 10;
  let lastReason = 'timeout';
  let resolved = false;
  let resolveObserver = null;
  const observerResult = new Promise(resolve => { resolveObserver = resolve; });

  // Expose a callback the in-page observer can invoke.
  const cbName = `__kimikoBookingTriggerCb_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  try {
    await page.exposeFunction(cbName, (res) => {
      if (resolved) return;
      resolved = true;
      resolveObserver(res);
    });
  } catch {
    resolveObserver = null;
  }

  // Install MutationObserver in the page. It calls back into Node via exposeFunction.
  if (resolveObserver) {
    page.evaluate((cbName, deadline) => {
      function isInteractive(node) {
        if (!node) return false;
        const style = window.getComputedStyle(node);
        if (style.display === 'none' || style.visibility === 'hidden' || style.pointerEvents === 'none') return false;
        const rect = node.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
      }
      function hasVisibleTurnstile() {
        const selectors = [
          '[data-testid="turnstile-widget"]',
          'iframe[src*="turnstile"]',
          'iframe[src*="challenges.cloudflare"]',
          'iframe[id^="cf-chl-widget-"]',
          '.cf-turnstile',
          '[name="cf-turnstile-response"]',
        ];
        return selectors.some(sel => {
          const node = document.querySelector(sel);
          if (!node) return false;
          const style = window.getComputedStyle(node);
          return style.display !== 'none' && style.visibility !== 'hidden';
        });
      }
      function checkTrigger() {
        const hasStadiumCanvas = !!document.querySelector('canvas#canvas[aria-label*="Stadium seats map"]');
        const hasChartIframe = !!document.querySelector('iframe[src*="seatcloud"], iframe[src*="seats.io"], iframe[src*="chart.seatcloud"]');
        const chartRoot = document.querySelector('#chart, #seat-chart, [data-testid*="chart" i], [class*="seatsio" i]');
        const hasChartRoot = isInteractive(chartRoot);
        const timerEl = document.querySelector('[data-testid="countdown-timer"]');
        let timerSeconds = null;
        let timerText = '';
        if (timerEl) {
          const text = (timerEl.innerText || timerEl.textContent || '').trim();
          const m = text.match(/(\d{1,2})[:\s](\d{2})/);
          if (m) timerSeconds = parseInt(m[1], 10) * 60 + parseInt(m[2], 10);
          timerText = text;
        }
        const turnstileVisible = hasVisibleTurnstile();
        const rawTriggered = hasStadiumCanvas || hasChartIframe || hasChartRoot || (timerSeconds !== null && timerSeconds <= deadline);
        if (rawTriggered && !turnstileVisible) {
          let reason = 'chart-iframe-detected';
          if (hasStadiumCanvas) reason = 'stadium-canvas-detected';
          else if (timerSeconds !== null && !(hasChartIframe || hasChartRoot)) reason = `countdown-timer-${timerSeconds}s`;
          return { triggered: true, reason, timerSeconds, timerText };
        }
        return null;
      }

      const initial = checkTrigger();
      if (initial) {
        if (window[cbName]) window[cbName](initial);
        return;
      }

      let timeoutId = null;
      const observer = new MutationObserver(() => {
        const res = checkTrigger();
        if (res) {
          observer.disconnect();
          clearTimeout(timeoutId);
          if (window[cbName]) window[cbName](res);
        }
      });
      observer.observe(document.body, { childList: true, subtree: true, attributes: true });

      // Extra 50ms periodic recheck in case observer misses a rapid swap.
      const intervalId = setInterval(() => {
        const res = checkTrigger();
        if (res) {
          observer.disconnect();
          clearInterval(intervalId);
          clearTimeout(timeoutId);
          if (window[cbName]) window[cbName](res);
        }
      }, 50);

      // Stop observing after 60s to avoid leaks.
      timeoutId = setTimeout(() => {
        observer.disconnect();
        clearInterval(intervalId);
      }, 60000);
    }, cbName, deadlineSeconds).catch(() => {});
  }

  // 20ms polling fallback in parallel.
  const pollPromise = (async () => {
    while (Date.now() - start < timeoutMs) {
      try {
        if (await isPageClosed(page)) return { triggered: false, reason: 'page-closed' };
        const res = await page.evaluate((deadline) => {
          function isInteractive(node) {
            if (!node) return false;
            const style = window.getComputedStyle(node);
            if (style.display === 'none' || style.visibility === 'hidden' || style.pointerEvents === 'none') return false;
            const rect = node.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0;
          }
          function hasVisibleTurnstile() {
            const selectors = [
              '[data-testid="turnstile-widget"]',
              'iframe[src*="turnstile"]',
              'iframe[src*="challenges.cloudflare"]',
              'iframe[id^="cf-chl-widget-"]',
              '.cf-turnstile',
              '[name="cf-turnstile-response"]',
            ];
            return selectors.some(sel => {
              const node = document.querySelector(sel);
              if (!node) return false;
              const style = window.getComputedStyle(node);
              return style.display !== 'none' && style.visibility !== 'hidden';
            });
          }
          const hasStadiumCanvas = !!document.querySelector('canvas#canvas[aria-label*="Stadium seats map"]');
          const hasChartIframe = !!document.querySelector('iframe[src*="seatcloud"], iframe[src*="seats.io"], iframe[src*="chart.seatcloud"]');
          const chartRoot = document.querySelector('#chart, #seat-chart, [data-testid*="chart" i], [class*="seatsio" i]');
          const hasChartRoot = isInteractive(chartRoot);
          const timerEl = document.querySelector('[data-testid="countdown-timer"]');
          let timerSeconds = null;
          let timerText = '';
          if (timerEl) {
            const text = (timerEl.innerText || timerEl.textContent || '').trim();
            const m = text.match(/(\d{1,2})[:\s](\d{2})/);
            if (m) timerSeconds = parseInt(m[1], 10) * 60 + parseInt(m[2], 10);
            timerText = text;
          }
          const turnstileVisible = hasVisibleTurnstile();
          const rawTriggered = hasStadiumCanvas || hasChartIframe || hasChartRoot || (timerSeconds !== null && timerSeconds <= deadline);
          if (rawTriggered && !turnstileVisible) {
            let reason = 'chart-iframe-detected';
            if (hasStadiumCanvas) reason = 'stadium-canvas-detected';
            else if (timerSeconds !== null && !(hasChartIframe || hasChartRoot)) reason = `countdown-timer-${timerSeconds}s`;
            return { triggered: true, reason, timerSeconds, timerText };
          }
          return null;
        }, deadlineSeconds);
        if (res) return res;
      } catch {}
      await waitFor(pollInterval);
    }
    return { triggered: false, reason: lastReason };
  })();

  try {
    const result = await Promise.race([observerResult, pollPromise]);
    resolved = true;
    return result;
  } catch {
    return { triggered: false, reason: lastReason };
  }
}

app.get('/api/fetch-sections', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'Event URL is required' });
  try {
    const slug = parseSlug(url);
    const json = await fetchEventDetail(slug);
    const data = json.data || json;
    const tickets = (data.event_tickets || []).map(t => ({
      id: t._id,
      title: t.title,
      group: t.group_name || t.group_name_en || null,
      price: parseFloat(t.price),
      vat: parseFloat(t.vat),
      total: +(parseFloat(t.price) + parseFloat(t.vat)).toFixed(3),
      currency: t.currency,
      remaining: t.remaining,
      soldOut: t.sold_out,
      saleStatus: t.sale_status,
      seatsIoCategory: t.seats_io_category,
      color: t.ticket_color,
      minPerOrder: t.min_per_order,
      maxPerOrder: t.max_per_order,
    }));
    const teams = extractTeamsFromEventDetail(data);
    const allChannelKeys = getAllChannelKeys(data);
    const commonChannelKeys = getCommonChannelKeys(data);
    res.json({
      success: true,
      slug,
      event: {
        id: data._id,
        title: data.title,
        startDate: data.start_date_time_str,
        venue: data.venue_name,
        city: data.city,
        seatsIo: data.seats_io || null,
        isSeated: data.is_seated,
      },
      sections: tickets,
      teams,
      allTeamIds: teams.map(t => t.id),
      allChannelKeys,
      commonChannelKeys,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/check-queue', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'Event URL is required' });
  try {
    const slug = parseSlug(url);
    const status = await checkQueueStatus(slug, null, '');
    res.json({
      success: true,
      slug,
      queued: status.queued,
      confidence: status.confidence,
      holdToken: !!status.holdToken,
      queueToken: !!status.queueToken,
      signals: status.signals,
      error: status.error || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

async function fetchChartSections(slug) {
  const now = Date.now();
  const cached = CHART_SECTIONS_CACHE.get(slug);
  if (cached && now - cached.ts < CHART_SECTIONS_CACHE_TTL_MS) {
    return cached.result;
  }

  const json = await fetchEventDetail(slug);
  const data = json.data || json;
  const seatsIo = data.seats_io || {};
  const workspaceKey = seatsIo.workspace_key;
  const eventKey = seatsIo.event_key;
  if (!workspaceKey || !eventKey) throw new Error('Event chart keys not found');

  // Extract team IDs and SeatCloud channel UUIDs early so the items fetch can
  // use the correct allocation shape for sports/team events.
  const teams = extractTeamsFromEventDetail(data);
  const allTeamIds = teams.map(t => t.id);
  const commonChannelKeys = getCommonChannelKeys(data);
  const allChannelKeys = getAllChannelKeys(data);

  const tickets = (data.event_tickets || []).map(t => ({
    title: t.title,
    group: t.group_name || t.group_name_en || null,
    total: +(parseFloat(t.price) + parseFloat(t.vat)).toFixed(3),
    color: t.ticket_color,
    categoryKey: String(t.seats_io_category),
  }));

  const items = await fetchSeatcloudItems(workspaceKey, eventKey, null, allChannelKeys);
  const bySection = {};
  for (const item of items) {
    if (!item.section) continue;
    const sec = bySection[item.section] || { availableCount: 0, categoryKeys: new Set() };
    sec.availableCount += Math.max(0, item.availableCount || 0);
    sec.categoryKeys.add(String(item.specificationKey));
    bySection[item.section] = sec;
  }

  const chartSections = Object.keys(bySection)
    .sort()
    .map(label => {
      const sec = bySection[label];
      const categories = tickets.filter(t => sec.categoryKeys.has(t.categoryKey));
      return {
        label,
        availableCount: sec.availableCount,
        categories,
      };
    });

  // Fallback: for ticket categories that don't appear in any chart section,
  // add a virtual section so users can select/monitor them (e.g. sold-out C sections).
  const representedCategories = new Set();
  for (const sec of chartSections) {
    for (const c of sec.categories) representedCategories.add(c.categoryKey);
  }
  for (const t of tickets) {
    if (representedCategories.has(t.categoryKey)) continue;
    const availabilityFromItems = items
      .filter(i => String(i.specificationKey) === t.categoryKey)
      .reduce((sum, i) => sum + Math.max(0, i.availableCount || 0), 0);
    chartSections.push({
      label: t.title,
      availableCount: availabilityFromItems,
      categories: [t],
      virtual: true,
    });
    representedCategories.add(t.categoryKey);
  }

  // Extract per-user ticket limit from event detail if available.
  const maxTicketsPerUser = parseInt(
    data.maxTicketsPerUser || data.max_tickets_per_user || data.max_per_order ||
    data.event?.maxTicketsPerUser || data.event?.max_tickets_per_user ||
    data.maxTickets || data.ticket_limit || data.maxTicketCount || 30,
    10
  ) || 30;

  const result = { event: data.title, chartSections, workspaceKey, eventKey, teams, allTeamIds, allChannelKeys, commonChannelKeys, maxTicketsPerUser };
  CHART_SECTIONS_CACHE.set(slug, { ts: Date.now(), result });
  trimCache(CHART_SECTIONS_CACHE, 200);
  return result;
}

function distributeSectionQuotas(selectedSections, accounts, chartSections) {
  // Build availability map for selected sections and sort scarce sections first.
  const availability = {};
  for (const cs of chartSections) {
    availability[cs.label.toUpperCase()] = cs.availableCount || 0;
  }
  const normalized = selectedSections.map(s => String(s).trim().toUpperCase()).filter(Boolean);
  const sorted = [...normalized].sort((a, b) => (availability[a] || 0) - (availability[b] || 0));
  const remaining = {};
  for (const s of sorted) remaining[s] = availability[s] || 0;

  // Round-robin sections across accounts so concurrent accounts target different
  // sections first. This dramatically reduces the chance that two accounts call
  // bestAvailable on the same category and steal each other's holds.
  // Each account may request a different ticket count (default 30).
  const quotas = Array.from({ length: accounts.length }, () => []);
  for (let i = 0; i < accounts.length; i++) {
    let needed = Math.max(1, Math.min(parseInt(accounts[i]?.ticketCount, 10) || 30, MAX_HELD_SEATS));
    const startIdx = i % sorted.length;
    for (let offset = 0; offset < sorted.length && needed > 0; offset++) {
      const sec = sorted[(startIdx + offset) % sorted.length];
      if (remaining[sec] <= 0) continue;
      const take = Math.min(needed, remaining[sec]);
      quotas[i].push({ section: sec, quota: take });
      remaining[sec] -= take;
      needed -= take;
    }
  }
  return quotas;
}

async function extractSeatcloudKeysFromPage(page) {
  // Try the iframe URL first (fastest and most reliable).
  const patterns = [
    /seats\.seatcloud\.com\/[^/]+\/([^/]+)\/([^/?]+)/,
    /chart\.seatcloud\.com\/[^/]+\/([^/]+)\/([^/?]+)/,
    /cdn\.seats\.io\/[^/]+\/([^/]+)\/([^/?]+)/,
    /webook\.seatcloud\.com\/[^/]+\/([^/]+)\/([^/?]+)/,
    /secure\.seatcloud\.com\/[^/]+\/([^/]+)\/([^/?]+)/,
    /[^/]+\/([^/]+)\/([^/?]+)\?.*(?:token|holdToken)/,
  ];
  const frames = page.frames();
  for (const frame of frames) {
    const url = frame.url() || '';
    for (const pattern of patterns) {
      const m = url.match(pattern);
      if (m && m[1] && m[2]) {
        return { workspaceKey: m[1], eventKey: m[2], source: 'iframe-url' };
      }
    }
  }
  // Fallback: read global chart config objects inside the iframe.
  for (const frame of frames) {
    try {
      const keys = await frame.evaluate(() => ({
        workspaceKey: window.chartState?.workspaceKey || window.currentChartConfig?.workspaceKey || window.seatsioConfig?.workspaceKey,
        eventKey: window.chartState?.eventKey || window.currentChartConfig?.eventKey || window.seatsioConfig?.eventKey,
      }));
      if (keys.workspaceKey && keys.eventKey) return { ...keys, source: 'iframe-globals' };
    } catch {}
  }
  return null;
}

async function fetchChartSectionsFromPage(eventUrl) {
  let ctx = null;
  let page = null;
  try {
    const browser = await ensureBrowser();
    let proxyOption;
    if (currentProxyMode !== 'off') {
      const helperProxy = proxyManager.nextProxy();
      const test = helperProxy ? await testProxy(helperProxy, 8000) : { ok: false };
      if (test.ok) {
        proxyOption = {
          server: helperProxy.server,
          username: helperProxy.username,
          password: helperProxy.password,
        };
        fileLog('INFO', `[chart-sections-helper] using tested proxy: ${helperProxy.server}`);
      } else {
        fileLog('WARN', `[chart-sections-helper] proxy test failed${helperProxy ? ` (${helperProxy.server}: ${test.reason})` : ''}; using direct`);
        if (currentProxyMode === 'required') {
          throw new Error('PROXY_REQUIRED_BUT_ALL_FAILED for chart sections helper');
        }
      }
    }
    ctx = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      viewport: { width: 1280, height: 800 },
      locale: 'ar-SA',
      ...(proxyOption ? { proxy: proxyOption } : {}),
    });
    page = await ctx.newPage();
    await page.goto(eventUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await page.waitForLoadState('networkidle', { timeout: 30000 }).catch(() => {});

    // Wait for the SeatCloud iframe to appear.
    let keys = null;
    for (let attempt = 0; attempt < 40; attempt++) {
      keys = await extractSeatcloudKeysFromPage(page);
      if (keys) break;
      await waitFor(200);
    }
    if (!keys) throw new Error('Could not extract SeatCloud workspace/event keys from page');

    // For page-driven extraction we still need team IDs and SeatCloud channel
    // UUIDs to query the right allocations. Derive them from the event-detail API.
    let teams = [];
    let allTeamIds = [];
    let allChannelKeys = [];
    let commonChannelKeys = [];
    try {
      const slug = parseSlug(eventUrl);
      const detail = await fetchEventDetail(slug);
      const detailData = detail.data || detail;
      teams = extractTeamsFromEventDetail(detailData);
      allTeamIds = teams.map(t => t.id);
      allChannelKeys = getAllChannelKeys(detailData);
      commonChannelKeys = getCommonChannelKeys(detailData);
    } catch {}

    const items = await fetchSeatcloudItems(keys.workspaceKey, keys.eventKey, null, allChannelKeys);
    const bySection = {};
    for (const item of items) {
      if (!item.section) continue;
      const sec = bySection[item.section] || { availableCount: 0, categoryKeys: new Set() };
      sec.availableCount += Math.max(0, item.availableCount || 0);
      sec.categoryKeys.add(String(item.specificationKey));
      bySection[item.section] = sec;
    }

    const chartSections = Object.keys(bySection)
      .sort()
      .map(label => {
        const sec = bySection[label];
        const categories = [...sec.categoryKeys].map(key => ({ title: `Category ${key}`, categoryKey: key }));
        return { label, availableCount: sec.availableCount, categories };
      });

    // Try to extract per-user ticket limit from the page/API detail.
    let maxTicketsPerUser = 30;
    try {
      const slug = parseSlug(eventUrl);
      const detail = await fetchEventDetail(slug);
      const detailData = detail.data || detail;
      maxTicketsPerUser = parseInt(
        detailData.maxTicketsPerUser || detailData.max_tickets_per_user || detailData.max_per_order ||
        detailData.event?.maxTicketsPerUser || detailData.event?.max_tickets_per_user ||
        detailData.maxTickets || detailData.ticket_limit || detailData.maxTicketCount || 30,
        10
      ) || 30;
    } catch {}

    return { event: eventUrl, chartSections, source: keys.source, teams, allTeamIds, allChannelKeys, commonChannelKeys, maxTicketsPerUser };
  } finally {
    try { if (page) await page.close(); } catch {}
    try { if (ctx) await ctx.close(); } catch {}
  }
}

app.get('/api/chart-sections', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'Event URL is required' });
  try {
    const slug = parseSlug(url);
    const result = await fetchChartSections(slug);
    res.json({ success: true, ...result });
  } catch (err) {
    fileLog('WARN', `/api/chart-sections API fallback triggered: ${err.message}`);
    try {
      const fallback = await fetchChartSectionsFromPage(url);
      res.json({ success: true, ...fallback, fallback: true });
    } catch (fallbackErr) {
      console.error(fallbackErr);
      res.status(500).json({ success: false, error: fallbackErr.message, originalError: err.message });
    }
  }
});

app.get('/api/sections-from-page', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'Event URL is required' });
  try {
    const result = await fetchChartSectionsFromPage(url);
    res.json({ success: true, ...result, source: 'page' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/start-booking', async (req, res) => {
  try {
    // Remote kill switch must pass before any booking or user session starts.
    await checkKillSwitch();

    const { url, targetSection, targetSections, accounts, maxConcurrency: userMax, ticketCount: rawTicketCount, speedSettings, selectedTeam } = req.body;
    if (!url || !Array.isArray(accounts) || accounts.length === 0) {
      return res.status(400).json({ error: 'url and accounts array are required' });
    }

    // Apply frontend speed settings (clamped to safe ranges).
    if (speedSettings && typeof speedSettings === 'object') {
      currentSpeedSettings = getSpeedSettings(speedSettings);
      fileLog('INFO', `Speed settings updated: ${JSON.stringify(currentSpeedSettings)}`);
    }

    // Normalize target sections (support legacy single string and new array)
    let sections = [];
    if (Array.isArray(targetSections) && targetSections.length > 0) {
      sections = targetSections.map(s => String(s).trim()).filter(Boolean);
    } else if (targetSection) {
      sections = [String(targetSection).trim()];
    }

    // Normalize per-account ticket count (default 30, max 30 enforced by backend)
    const normalizedAccounts = accounts.map(a => ({
      ...a,
      ticketCount: Math.max(1, Math.min(parseInt(a?.ticketCount, 10) || parseInt(rawTicketCount, 10) || 30, MAX_HELD_SEATS)),
    }));
    const minTickets = Math.min(...normalizedAccounts.map(a => a.ticketCount));
    const maxTickets = Math.max(...normalizedAccounts.map(a => a.ticketCount));

    // Stop any existing runs first
    await stopAll('new-run-started');
    await waitFor(400);

    // Reset global seat coordination for this new run
    resetSeatPool(Date.now());

    // Build smart per-account section quotas based on real availability.
    // Also cache workspaceKey/eventKey so each account does not re-fetch them.
    let sectionQuotas = [];
    let globalWorkspaceKey = null;
    let globalEventKey = null;
    let enrichedSelectedTeam = selectedTeam || null;
    try {
      const slug = parseSlug(url);
      const { chartSections, workspaceKey, eventKey, teams, allChannelKeys, commonChannelKeys } = await fetchChartSections(slug);
      enrichedSelectedTeam = enrichSelectedTeam(selectedTeam, teams, allChannelKeys, commonChannelKeys);
      sectionQuotas = distributeSectionQuotas(sections, normalizedAccounts, chartSections);
      globalWorkspaceKey = workspaceKey || null;
      globalEventKey = eventKey || null;
      fileLog('INFO', `Section quotas: ${JSON.stringify(sectionQuotas)}`);
      if (accounts.length > sections.length && sections.length > 0) {
        fileLog('WARN', `[start-booking] More accounts (${accounts.length}) than selected sections (${sections.length}); some accounts will compete for the same sections`);
        emitStatus('warning', `عدد الحسابات (${accounts.length}) أكبر من عدد الأقسام المختارة (${sections.length}). بعض الحسابات هتتنافس على نفس الكراسي.`, { accounts: accounts.length, sections: sections.length, type: 'more-accounts-than-sections' });
      }
    } catch (e) {
      fileLog('WARN', `Could not fetch section availability for quota distribution: ${e.message}`);
    }

    maxConcurrency = estimateMaxConcurrency(parseInt(userMax, 10) || 0);

    // Reject if multiple accounts share the same hold token; this causes
    // SeatCloud to treat them as one session and drop each other's holds.
    const sharedTokens = detectSharedHoldTokens(normalizedAccounts, 'start-booking');
    if (sharedTokens.length > 0) {
      const msg = `Shared hold tokens detected: ${sharedTokens.map(c => c.token).join(', ')}`;
      fileLog('ERROR', `[start-booking] ${msg}`);
      return res.status(400).json({ success: false, error: msg, collisions: sharedTokens });
    }

    // Global proxy assignment: all accounts share the single global Proxies list.
    // Accounts with useProxy=true get a tested proxy pre-assigned before launch.
    const accountsWithProxy = await assignProxiesToAccounts(normalizedAccounts);

    pendingQueue = accountsWithProxy.map((a, idx) => ({
      username: a.username,
      password: a.password,
      type: a.type === 'holdToken' ? 'holdToken' : 'credentials',
      holdToken: a.type === 'holdToken' ? String(a.holdToken || '').trim() : null,
      queueToken: a.type === 'holdToken' ? String(a.queueToken || a.queueSession || '').trim() : null,
      cfClearance: a.type === 'holdToken' ? String(a.cfClearance || '').trim() : null,
      recaptchaToken: a.type === 'holdToken' ? String(a.recaptchaToken || '').trim() : null,
      token: a.type === 'holdToken' ? String(a.token || '').trim() : null,
      refreshToken: a.type === 'holdToken' ? String(a.refreshToken || '').trim() : null,
      rawCookies: a.type === 'holdToken' ? String(a.rawCookies || '').trim() : null,
      structuredCookies: a.type === 'holdToken' ? (Array.isArray(a.structuredCookies) ? a.structuredCookies : null) : null,
      loginEmail: a.type === 'holdToken' ? String(a.loginEmail || '').trim() : null,
      loginPassword: a.type === 'holdToken' ? String(a.loginPassword || '').trim() : null,
      url,
      targetSections: sections,
      sectionQuota: sectionQuotas[idx] && sectionQuotas[idx].length > 0
        ? sectionQuotas[idx]
        : sections.map(s => ({ section: String(s).trim().toUpperCase(), quota: a.ticketCount })),
      ticketCount: a.ticketCount,
      accountIndex: idx,
      totalAccounts: accounts.length,
      useProxy: a.useProxy === true,
      assignedProxy: a.assignedProxy || null,
      workspaceKey: globalWorkspaceKey,
      eventKey: globalEventKey,
      selectedTeam: enrichedSelectedTeam,
    }));
    sessionCounter = 0;

    const ticketRangeText = minTickets === maxTickets ? `${minTickets}` : `${minTickets}-${maxTickets}`;
    emitStatus('starting', `Queued ${pendingQueue.length} account(s). Max concurrency: ${maxConcurrency}. Tickets per account: ${ticketRangeText}`, { maxConcurrency, minTickets, maxTickets });
    emitQueueStats();
    processQueue();

    res.json({ success: true, message: 'Booking automation started', maxConcurrency, minTickets, maxTickets });
  } catch (err) {
    fileLog('ERROR', `start-booking error: ${err.message}`);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ------------------------------------------------------------------
// Dry-run: login + proxy IP verification + chart detection, no holds.
// ------------------------------------------------------------------
app.post('/api/dry-run', async (req, res) => {
  try {
    const { url, accounts, maxConcurrency: userMax } = req.body;
    if (!url || !Array.isArray(accounts) || accounts.length === 0) {
      return res.status(400).json({ error: 'url and accounts array are required' });
    }

    await stopAll('dry-run-started');
    await waitFor(200);

    maxConcurrency = estimateMaxConcurrency(parseInt(userMax, 10) || 0);

    // Pre-assign unique tested proxies to accounts that opted-in for proxy mode
    // so the dry-run exercises the exact same isolation path as a real booking.
    const accountsWithProxy = (currentProxyMode !== 'off')
      ? await assignProxiesToAccounts(accounts)
      : accounts.map(a => ({ ...a, assignedProxy: null }));

    pendingQueue = accountsWithProxy.map((a, idx) => ({
      username: a.username,
      password: a.password,
      type: 'credentials',
      url,
      targetSections: [],
      sectionQuota: [],
      ticketCount: 0,
      accountIndex: idx,
      totalAccounts: accounts.length,
      dryRun: true,
      useProxy: a.useProxy === true,
      assignedProxy: a.assignedProxy || null,
    }));
    sessionCounter = 0;

    emitStatus('starting', `Dry-run queued ${pendingQueue.length} account(s). Max concurrency: ${maxConcurrency}`, { maxConcurrency, ticketCount: 0 });
    emitQueueStats();
    processQueue();

    res.json({ success: true, message: 'Dry run started', maxConcurrency });
  } catch (err) {
    fileLog('ERROR', `dry-run error: ${err.message}`);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/proceed-payment', async (req, res) => {
  const { username } = req.body;
  const session = activeSessions.get(username);
  if (!session) return res.status(400).json({ error: 'No active session for this account' });
  if (session.bookingPaused || session.stopRequested) {
    return res.status(409).json({ success: false, error: 'Session is paused or stopped; cannot proceed to payment' });
  }
  if (session.proceedResolve) session.proceedResolve('proceed');
  res.json({ success: true, message: 'Proceed signal sent' });
});

app.post('/api/stop-booking', async (req, res) => {
  // Soft stop: keep browsers open and continue extending held seats so the
  // operator can proceed to payment, but stop snipers/watchers/refills.
  await stopAll('user-stop-all', true);
  res.json({ success: true, message: 'All sessions paused; held seats kept' });
});

app.post('/api/stop-booking-hard', async (req, res) => {
  await stopAll('user-stop-all-hard', false);
  res.json({ success: true, message: 'All sessions stopped and browsers closed' });
});

app.post('/api/stop-account', async (req, res) => {
  const username = req.body.username || req.body.email;
  if (!username) return res.status(400).json({ success: false, error: 'username or email required' });
  const session = activeSessions.get(username);
  if (!session) return res.status(400).json({ success: false, error: 'No active session for this account' });
  // Soft pause: stop the active sniper for this user without closing the
  // browser or releasing currently held seats, so the operator can still
  // proceed to payment. The sniper scheduleNext loop must also check
  // bookingPaused to avoid rescheduling itself.
  session.bookingPaused = true;
  stopActiveSniper(session);
  clearHoldWatcher(session);
  emitStatus('booking-paused', 'Sniper/watcher stopped for this account; browser and held seats remain active', { account: username, heldSeats: session.selectedSeats || [] });
  emitAccountUpdate(username, 'paused', { seats: session.selectedSeats || [] });
  res.json({ success: true, message: 'Sniper paused; held seats kept' });
});

app.post('/api/release-hold', async (req, res) => {
  const { username } = req.body;
  const session = activeSessions.get(username);
  if (!session) return res.status(400).json({ success: false, error: 'No active session for this account' });
  try {
    const released = await releaseHold(session);
    // Release from bot state and shared pool, but keep browser session alive
    // so the user can still proceed to payment if they change their mind.
    releaseSeats(username);
    if (session.selectedSeats) session.selectedSeats = [];
    stopActiveSniper(session);
    emitStatus('hold-released', 'Hold released from browser and bot. Browser left open.', { account: username, released });
    emitAccountUpdate(username, 'paused', { seats: [] });
    res.json({ success: true, released });
  } catch (err) {
    emitStatus('release-hold-error', err.message, { account: username });
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/release-seat', async (req, res) => {
  const { username, seat } = req.body;
  if (!username || !seat) return res.status(400).json({ success: false, error: 'username and seat required' });
  const session = activeSessions.get(username);
  if (!session) return res.status(400).json({ success: false, error: 'No active session for this account' });
  try {
    const released = await releaseSingleSeat(session, seat);
    if (released) {
      session.selectedSeats = (session.selectedSeats || []).filter(s => s !== seat);
      session.releasedSeats.add(String(seat).trim().toUpperCase());
      releaseSeatFromPool(seat);
      const frame = await findChartFrame(session.page, username);
      if (frame) {
        try { await clearChartVisualMarkers(frame, [seat]); } catch {}
      }
      emitStatus('seat-released', `Released seat ${seat}`, { account: username, seat });
      emitAccountUpdate(username, 'seats-partial', { seats: session.selectedSeats, verifiedSeats: session.selectedSeats });
    }
    res.json({ success: true, released, seat, seats: session.selectedSeats });
  } catch (err) {
    emitStatus('release-seat-error', err.message, { account: username, seat });
    res.status(500).json({ success: false, error: err.message });
  }
});

// ------------------------------------------------------------------
// 2captcha API key management
// ------------------------------------------------------------------
app.get('/api/captcha-keys', (req, res) => {
  try {
    res.json({ success: true, keys: captcha2captcha.loadKeys() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/captcha-keys', (req, res) => {
  try {
    const { label, key } = req.body;
    if (!key || typeof key !== 'string' || key.trim().length < 10) {
      return res.status(400).json({ success: false, error: 'Valid 2captcha API key required' });
    }
    const keys = captcha2captcha.loadKeys();
    keys.push({
      id: `key-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      label: label || '2captcha key',
      key: key.trim(),
      enabled: true,
      createdAt: new Date().toISOString(),
    });
    captcha2captcha.saveKeys(keys);
    res.json({ success: true, keys });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/captcha-keys/:id', (req, res) => {
  try {
    let keys = captcha2captcha.loadKeys();
    keys = keys.filter(k => k.id !== req.params.id);
    captcha2captcha.saveKeys(keys);
    res.json({ success: true, keys });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.patch('/api/captcha-keys/:id', (req, res) => {
  try {
    const keys = captcha2captcha.loadKeys();
    const key = keys.find(k => k.id === req.params.id);
    if (!key) return res.status(404).json({ success: false, error: 'Key not found' });
    if (typeof req.body.enabled === 'boolean') key.enabled = req.body.enabled;
    if (req.body.label) key.label = req.body.label;
    captcha2captcha.saveKeys(keys);
    res.json({ success: true, keys });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Trigger a 2captcha solve for a specific account/session (fallback).
app.post('/api/captcha-solve', async (req, res) => {
  const { username, sitekey, pageUrl } = req.body;
  if (!username) return res.status(400).json({ success: false, error: 'username required' });
  const session = activeSessions.get(username);
  if (!session) return res.status(400).json({ success: false, error: 'No active session for this account' });
  try {
    const frame = await findChartFrame(session.page, username) || session.page;
    const detectedSitekey = sitekey || await captcha2captcha.detectSitekey(frame);
    const targetUrl = pageUrl || session.page.url() || session.url;
    emitStatus('captcha-solving', 'Asking 2captcha to solve reCAPTCHA (fallback)...', { account: username });
    const token = await captcha2captcha.solveRecaptchaV2({ sitekey: detectedSitekey, pageUrl: targetUrl });
    if (token) {
      await captcha2captcha.injectRecaptchaToken(frame, token);
      session.providedRecaptchaToken = token;
      emitStatus('captcha-solved', '2captcha token received and injected', { account: username });
    }
    res.json({ success: true, token: token || null });
  } catch (err) {
    emitStatus('captcha-solve-error', err.message, { account: username });
    res.status(500).json({ success: false, error: err.message });
  }
});

// Ensure the default 2captcha key exists on startup.
captcha2captcha.ensureDefaultKey();

// ------------------------------------------------------------------
// Account persistence (load/save from accounts.txt)
// ------------------------------------------------------------------
const ACCOUNTS_FILE = path.join(__dirname, 'accounts.txt');

function parseAccountsFile(content) {
  const accounts = [];
  if (!content) return accounts;
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const sep = trimmed.includes(':') ? ':' : (trimmed.includes(',') ? ',' : null);
    if (!sep) continue;
    const [username, ...rest] = trimmed.split(sep);
    const password = rest.join(sep).trim();
    if (username && password) {
      accounts.push({ username: username.trim(), password });
    }
  }
  return accounts;
}

function serializeAccountsFile(accounts) {
  const lines = accounts
    .filter(a => a.username && a.password)
    .map(a => `${a.username.trim()}:${a.password.trim()}`);
  return lines.join('\n') + (lines.length ? '\n' : '');
}

app.get('/api/load-accounts', (req, res) => {
  try {
    if (!fs.existsSync(ACCOUNTS_FILE)) {
      return res.json({ success: true, accounts: [] });
    }
    const content = fs.readFileSync(ACCOUNTS_FILE, 'utf8');
    const accounts = parseAccountsFile(content);
    res.json({ success: true, accounts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/save-accounts', (req, res) => {
  try {
    const { accounts } = req.body;
    if (!Array.isArray(accounts)) {
      return res.status(400).json({ success: false, error: 'accounts array required' });
    }
    const content = serializeAccountsFile(accounts);
    fs.writeFileSync(ACCOUNTS_FILE, content, 'utf8');
    res.json({ success: true, count: accounts.filter(a => a.username && a.password).length });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ------------------------------------------------------------------
// Proxy management endpoints
// ------------------------------------------------------------------
app.get('/api/proxies', (req, res) => {
  try {
    const list = proxyManager.reload();
    res.json({ success: true, count: list.length, proxies: list });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/proxies', (req, res) => {
  try {
    let input = req.body;
    if (input && (Array.isArray(input.proxies) || typeof input.proxies === 'string' || typeof input.proxies === 'object')) {
      input = input.proxies;
    }

    const parsed = proxyManager.parseInput(input);
    const saved = proxyManager.save(parsed);
    fileLog('INFO', `Saved ${saved.length} proxy(ies) to ${PROXIES_FILE}`);
    res.json({ success: true, count: saved.length, proxies: saved });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/proxies/test', async (req, res) => {
  try {
    let input = req.body;
    if (input && (Array.isArray(input.proxies) || typeof input.proxies === 'string' || typeof input.proxies === 'object')) {
      input = input.proxies;
    }
    const parsed = proxyManager.parseInput(input);
    if (!parsed.length) {
      return res.status(400).json({ success: false, error: 'no proxies provided' });
    }
    const results = [];
    for (const proxy of parsed) {
      const test = await testProxy(proxy, 8000);
      results.push({ server: proxy.server, ok: test.ok, reason: test.reason, targets: test.targets || [] });
    }
    res.json({ success: true, count: results.length, results });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/proxies/data-json', (req, res) => {
  try {
    if (!fs.existsSync(DATA_JSON_FILE)) {
      return res.json({ success: true, count: 0, proxies: [] });
    }
    const raw = fs.readFileSync(DATA_JSON_FILE, 'utf8');
    const data = JSON.parse(raw);
    const arr = Array.isArray(data) ? data : (data.proxies || []);
    const proxies = [];
    for (const item of arr) {
      if (!item || typeof item !== 'object') continue;
      if (item.proxy) proxies.push(...proxyManager.parseInput(item.proxy));
      else proxies.push(...proxyManager.parseInput([item]));
    }
    res.json({ success: true, count: proxies.length, proxies });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/proxies/test-and-filter', async (req, res) => {
  try {
    let input = req.body;
    const rewriteDataJson = !!(input && input.rewriteDataJson);
    if (input && (Array.isArray(input.proxies) || typeof input.proxies === 'string' || typeof input.proxies === 'object')) {
      input = input.proxies;
    }
    const parsed = proxyManager.parseInput(input);
    if (!parsed.length) {
      return res.status(400).json({ success: false, error: 'no proxies provided' });
    }
    const results = [];
    const working = [];
    for (const proxy of parsed) {
      const test = await testProxy(proxy, 8000);
      results.push({ server: proxy.server, ok: test.ok, reason: test.reason, targets: test.targets || [] });
      if (test.ok) working.push(proxy);
    }
    const saved = proxyManager.save(working);
    // Optionally rewrite data.json in the same format the UI import expects.
    if (rewriteDataJson) {
      try {
        fs.writeFileSync(DATA_JSON_FILE, JSON.stringify(saved.map(p => ({ proxy: p.server })), null, 2), 'utf8');
        fileLog('INFO', `Test-and-filter: rewrote ${DATA_JSON_FILE} with ${saved.length} working proxies`);
      } catch (e) {
        fileLog('WARN', `Test-and-filter: could not rewrite data.json: ${e.message}`);
      }
    }
    fileLog('INFO', `Test-and-filter: kept ${saved.length}/${parsed.length} working proxies`);
    res.json({ success: true, tested: results.length, kept: saved.length, results, proxies: saved });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/proxy-mode', (req, res) => {
  res.json({ success: true, mode: currentProxyMode });
});

app.post('/api/proxy-mode', (req, res) => {
  const { mode } = req.body || {};
  if (setProxyMode(mode)) {
    fileLog('INFO', `Proxy mode changed to ${mode}`);
    res.json({ success: true, mode: currentProxyMode });
  } else {
    res.status(400).json({ success: false, error: 'mode must be off, test, or required' });
  }
});

// ------------------------------------------------------------------
// Pair Cycling API endpoints
// ------------------------------------------------------------------
app.post('/api/start-pair-cycling', async (req, res) => {
  const { url, targetSection, targetSections, accounts, ticketCount, maxWaves, maxDurationMinutes, selectedTeam } = req.body;
  if (!url || !Array.isArray(accounts) || accounts.length < 2) {
    return res.status(400).json({ success: false, error: 'url and at least 2 accounts are required' });
  }

  let sections = [];
  if (Array.isArray(targetSections) && targetSections.length > 0) {
    sections = targetSections.map(s => String(s).trim()).filter(Boolean);
  } else if (targetSection) {
    sections = [String(targetSection).trim()];
  }

  try {
    // Stop any existing normal booking runs to free browsers/resources.
    await stopAll('pair-cycling-started');
    await waitFor(400);

    // Reject if multiple pair accounts share the same hold token.
    const sharedTokens = detectSharedHoldTokens(accounts, 'pair-cycling');
    if (sharedTokens.length > 0) {
      const msg = `Shared hold tokens detected: ${sharedTokens.map(c => c.token).join(', ')}`;
      fileLog('ERROR', `[pair-cycling] ${msg}`);
      return res.status(400).json({ success: false, error: msg, collisions: sharedTokens });
    }

    // Pre-fetch workspace/event keys so each pair wave does not have to re-fetch them.
    let globalWorkspaceKey = null;
    let globalEventKey = null;
    let enrichedSelectedTeam = selectedTeam || null;
    try {
      const slug = parseSlug(url);
      const { workspaceKey, eventKey, teams, allChannelKeys, commonChannelKeys } = await fetchChartSections(slug);
      enrichedSelectedTeam = enrichSelectedTeam(selectedTeam, teams, allChannelKeys, commonChannelKeys);
      globalWorkspaceKey = workspaceKey || null;
      globalEventKey = eventKey || null;
      fileLog('INFO', `[start-pair-cycling] Pre-fetched workspace=${workspaceKey}, event=${eventKey}`);
    } catch (e) {
      fileLog('WARN', `[start-pair-cycling] Could not pre-fetch chart keys: ${e.message}`);
    }

    const result = await pairManager.startCycling({
      url,
      targetSections: sections,
      accounts: accounts.map(a => ({
        username: a.username,
        password: a.password,
        type: a.type === 'holdToken' ? 'holdToken' : 'credentials',
        holdToken: a.type === 'holdToken' ? String(a.holdToken || '').trim() : null,
        queueToken: a.type === 'holdToken' ? String(a.queueToken || a.queueSession || '').trim() : null,
        cfClearance: a.type === 'holdToken' ? String(a.cfClearance || '').trim() : null,
        recaptchaToken: a.type === 'holdToken' ? String(a.recaptchaToken || '').trim() : null,
        token: a.type === 'holdToken' ? String(a.token || '').trim() : null,
        refreshToken: a.type === 'holdToken' ? String(a.refreshToken || '').trim() : null,
        rawCookies: a.type === 'holdToken' ? String(a.rawCookies || '').trim() : null,
        structuredCookies: a.type === 'holdToken' ? (Array.isArray(a.structuredCookies) ? a.structuredCookies : null) : null,
        loginEmail: a.type === 'holdToken' ? String(a.loginEmail || '').trim() : null,
        loginPassword: a.type === 'holdToken' ? String(a.loginPassword || '').trim() : null,
        useProxy: a.useProxy === true,
        workspaceKey: globalWorkspaceKey,
        eventKey: globalEventKey,
        selectedTeam: enrichedSelectedTeam,
      })),
      ticketCount: Math.max(1, Math.min(parseInt(ticketCount, 10) || Math.max(...accounts.map(a => parseInt(a?.ticketCount, 10) || 30)) || 30, MAX_HELD_SEATS)),
      maxWaves: Math.max(1, parseInt(maxWaves, 10) || 10),
      maxDurationMinutes: Math.max(1, parseInt(maxDurationMinutes, 10) || 60),
    });

    res.json(result);
  } catch (err) {
    emitStatus('pair-cycle-error', err.message, {});
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/stop-pair-cycling', async (req, res) => {
  try {
    const result = await pairManager.stopAll();
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/pair-cycles', (req, res) => {
  res.json({ success: true, ...pairManager.getStatus() });
});

// Share the current held seats + hold token. This lets an operator copy a link
// and try to continue the hold or payment on another device/browser. Cross-browser
// sharing is best-effort because SeatCloud hold tokens are session-bound to the
// chart iframe, reCAPTCHA token, and the current cookie jar.
app.get('/api/share/:username', async (req, res) => {
  const username = req.params.username;
  const session = activeSessions.get(username);
  if (!session) {
    return res.status(400).json({ success: false, error: 'No active session for this account' });
  }
  try {
    const holdToken = session.holdToken || await readChartHoldToken(session.page, parseSlug(session.url));
    if (!holdToken) throw new Error('No hold token available');

    const pageUrl = (session.page && !await isPageClosed(session.page)) ? session.page.url() : '';
    const baseUrl = (session.url || pageUrl).split('?')[0];
    const shareUrl = `${baseUrl}?hold_token=${encodeURIComponent(holdToken)}`;
    const paymentUrl = session.paymentUrl || pageUrl || shareUrl;

    // Verify the seats that are actually held on the server right now.
    let verifiedSeats = [];
    try {
      verifiedSeats = await verifyHeldSeatsViaApi(session.page, holdToken, session.selectedSeats || [], { session });
    } catch (e) {
      fileLog('WARN', `[${username}] Share endpoint verify failed: ${e.message}`);
    }

    // The SeatCloud hold token is issued for the current chart session and is
    // normally tied to the same browser context (iframe cookies + reCAPTCHA).
    // It will usually NOT work if opened in a different browser/profile.
    const transferable = false;
    const noteAr = 'الهولد توكن مرتبط بالجلسة الحالية والكوكيز؛ النقل لمتصفح/جهاز تاني مش مضمون.';
    const noteEn = 'Hold tokens are bound to the current chart session and cookies; transfer to another browser/device is not guaranteed.';

    res.json({
      success: true,
      username,
      holdToken,
      seats: session.selectedSeats || [],
      verifiedSeats,
      shareUrl,
      paymentUrl,
      transferable,
      cookieHints: {
        name: 'holdToken',
        domain: 'set by SeatCloud chart iframe (usually .seatcloud.com)',
      },
      note: `${noteAr} ${noteEn}`,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Manually extend/refresh the SeatCloud hold token for an active session.
app.post('/api/extend-token', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ success: false, error: 'username required' });
  const session = activeSessions.get(username);
  if (!session) return res.status(400).json({ success: false, error: 'No active session for this account' });
  try {
    const result = await extendHoldToken(session);
    if (result.success) {
      res.json({ success: true, ...result });
    } else {
      res.status(500).json({ success: false, error: result.error });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Extend hold tokens for all active sessions in one call.
app.post('/api/extend-all', async (req, res) => {
  const results = [];
  for (const [username, session] of activeSessions) {
    if (!session.page || await isPageClosed(session.page)) {
      results.push({ username, success: false, error: 'No active session page' });
      continue;
    }
    try {
      const result = await extendHoldToken(session);
      results.push({ username, ...result });
    } catch (err) {
      results.push({ username, success: false, error: err.message });
    }
  }
  res.json({ success: true, count: results.filter(r => r.success).length, total: results.length, results });
});

// Get live session info including hold token timestamps.
app.get('/api/session-info/:username', async (req, res) => {
  const session = activeSessions.get(req.params.username);
  if (!session) return res.status(404).json({ success: false, error: 'No active session' });
  res.json({
    success: true,
    username: session.username,
    holdToken: session.holdToken ? `${session.holdToken.slice(0, 12)}...${session.holdToken.slice(-4)}` : null,
    holdTokenCreatedAt: session.holdTokenCreatedAt,
    holdTokenExpiresAt: session.holdTokenExpiresAt,
    selectedSeats: session.selectedSeats || [],
    state: session.state,
    stage: session.bookingPaused ? 'paused' : session.state,
  });
});

// Refresh the Webook JWT access token for an active session using the refresh_token cookie.
app.post('/api/refresh-auth-token', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ success: false, error: 'username required' });
  const session = activeSessions.get(username);
  if (!session || !session.page) return res.status(400).json({ success: false, error: 'No active session for this account' });
  try {
    const result = await tryRefreshToken(session.page, username, session);
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ------------------------------------------------------------------
// Advanced seat-transfer planning helpers
// ------------------------------------------------------------------

function assignSeatsToDestinations(seatPool, destinations) {
  // Distribute seats to destinations according to explicit ticketCount,
  // falling back to a fair split when the requested total does not match.
  if (!Array.isArray(seatPool) || seatPool.length === 0) return [];
  if (!Array.isArray(destinations) || destinations.length === 0) return [];

  const total = seatPool.length;
  const totalRequested = destinations.reduce((sum, d) => sum + (d.ticketCount || 0), 0);
  const remaining = seatPool.slice();
  const result = [];

  if (totalRequested > 0 && totalRequested <= total) {
    // Exact distribution by requested counts.
    for (const dest of destinations) {
      const count = Math.min(dest.ticketCount || 0, remaining.length);
      const assigned = remaining.splice(0, count);
      result.push({ username: dest.username, assignedSeats: assigned });
    }
  } else {
    // Fair distribution.
    const base = Math.floor(total / destinations.length);
    let remainder = total % destinations.length;
    for (const dest of destinations) {
      const count = base + (remainder > 0 ? 1 : 0);
      if (remainder > 0) remainder--;
      const assigned = remaining.splice(0, count);
      result.push({ username: dest.username, assignedSeats: assigned });
    }
  }
  return result;
}

async function buildTransferPlan(masterSessions, destinationSpecs, opts = {}) {
  // 1. Verify seats from every master and build a single pool.
  const masters = [];
  const seatPool = [];
  const sourceMap = new Map(); // seat -> source username
  for (const master of masterSessions) {
    if (!master || !master.page || await isPageClosed(master.page)) {
      throw new Error(`Master account ${master?.username} has no active session`);
    }
    const verified = await verifyHeldSeatsViaApi(master.page, master.holdToken, master.selectedSeats || [], { session: master });
    if (!verified.length) continue;
    masters.push({ username: master.username, session: master, verifiedSeats: verified });
    for (const seat of verified) {
      seatPool.push(seat);
      if (!sourceMap.has(seat)) sourceMap.set(seat, master.username);
    }
  }
  if (seatPool.length === 0) throw new Error('No verified seats held by any master account');

  // 2. Build destination specs with ticket counts.
  const destinationSpecsWithCounts = destinationSpecs.map(d => ({
    username: d.username,
    ticketCount: typeof d.ticketCount === 'number' && d.ticketCount > 0 ? d.ticketCount : 0,
  }));

  // 3. Assign seats.
  const assignments = assignSeatsToDestinations(seatPool, destinationSpecsWithCounts);

  // 4. Group assigned seats by source master for batch release.
  const plan = {
    mode: opts.mode === 'legacy' ? 'legacy' : (opts.mode === 'atomic' ? 'atomic' : 'auto'),
    batchSize: opts.batchSize ? Math.max(1, Math.min(parseInt(opts.batchSize, 10) || 5, 10)) : 5,
    maxBatchRetries: Math.max(1, Math.min(parseInt(opts.maxBatchRetries, 10) || 2, 5)),
    masters,
    destinations: assignments.map(a => {
      const bySource = new Map();
      for (const seat of a.assignedSeats) {
        const source = sourceMap.get(seat);
        if (!source) continue;
        if (!bySource.has(source)) bySource.set(source, []);
        bySource.get(source).push(seat);
      }
      return {
        username: a.username,
        assignedSeats: a.assignedSeats,
        seatsBySource: Object.fromEntries(bySource),
      };
    }),
  };
  return plan;
}

async function prepareDestinationForTransfer(destUser, assignedSeats, account, options = {}) {
  const { url, targetSections } = options;
  const prepStartMs = Date.now();
  fileLog('INFO', `[transfer-prep] [${destUser}] Entering prepareDestinationForTransfer, assigned=${(assignedSeats || []).length}`);

  // Reuse active session if it is still alive.
  let session = activeSessions.get(destUser);
  if (session && session.page && !(await isPageClosed(session.page))) {
    fileLog('INFO', `[transfer-prep] [${destUser}] Reusing active session (${Date.now() - prepStartMs}ms)`);
    session.state = 'seats-monitoring';
    session.sniperTargetSeats = Array.isArray(assignedSeats) ? assignedSeats.slice() : [];
    session.targetSeatCount = Math.max(session.targetSeatCount || 0, session.sniperTargetSeats.length);
    if (!session.fullSession) {
      try {
        session.fullSession = await harvestFullSession(session.page, session.context, destUser);
        fileLog('INFO', `[transfer-prep] Harvested full session while reusing active session for ${destUser}`);
      } catch (harvestErr) {
        fileLog('WARN', `[transfer-prep] Could not harvest full session for reused active session ${destUser}: ${harvestErr.message}`);
      }
    }
    emitStatus('destination-ready', `Destination ${destUser} reused active session`, { account: destUser, seats: session.sniperTargetSeats });
    return session;
  }

  const launchAccount = account && account.username
    ? { ...account, url: account.url || url, targetSections: account.targetSections || targetSections }
    : { username: destUser, useProxy: false, url, targetSections };
  fileLog('INFO', `[transfer-prep] [${destUser}] launchAccount type=${launchAccount.type || 'credentials'}, useProxy=${launchAccount.useProxy}, hasCookies=${!!(launchAccount.rawCookies || launchAccount.structuredCookies)}`);

  // Fast path 1: use a previously harvested full session cache.
  fileLog('INFO', `[transfer-prep] [${destUser}] Trying cached session path (${Date.now() - prepStartMs}ms)`);
  let fullSession = await loadSessionFromCache(destUser);
  if (fullSession && validateSession(fullSession)) {
    try {
      const { context, page, isValid } = await createSessionWithContext(fullSession, { targetUrl: url, proxy: launchAccount.assignedProxy });
      if (isValid && page) {
        fileLog('INFO', `[transfer-prep] [${destUser}] Cached session context created (${Date.now() - prepStartMs}ms)`);
        session = buildSessionFromInjectedContext(destUser, context, page, launchAccount, url, targetSections);
        installChartDetectionHook(page, session);
        await navigateToBookingPage(page, url, destUser);
        await waitForChartAndStartImmediate(page, session, { timeoutMs: 20000 });
        activeSessions.set(destUser, session);
        try {
          session.fullSession = await harvestFullSession(page, context, destUser);
          fileLog('INFO', `[transfer-prep] Harvested full session from cached-session path for ${destUser}`);
        } catch (harvestErr) {
          fileLog('WARN', `[transfer-prep] Could not harvest full session for cached session ${destUser}: ${harvestErr.message}`);
        }
        session.state = 'seats-monitoring';
        session.sniperTargetSeats = Array.isArray(assignedSeats) ? assignedSeats.slice() : [];
        session.targetSeatCount = Math.max(session.targetSeatCount || 0, session.sniperTargetSeats.length);
        emitStatus('destination-ready', `Destination ${destUser} prepared from cached session`, { account: destUser, seats: session.sniperTargetSeats });
        return session;
      }
    } catch (cacheErr) {
      fileLog('WARN', `[transfer-prep] Cached session path failed for ${destUser}: ${cacheErr.message}`);
    }
  }

  // Fast path 2: cookie injection for holdToken/cookie accounts.
  if (launchAccount.rawCookies || launchAccount.structuredCookies || launchAccount.type === 'holdToken') {
    fileLog('INFO', `[transfer-prep] [${destUser}] Trying cookie injection path (${Date.now() - prepStartMs}ms)`);
    try {
      session = await ensureSessionForTransfer(launchAccount, { url, targetSections });
      if (session && session.page) {
        fileLog('INFO', `[transfer-prep] [${destUser}] Cookie session created (${Date.now() - prepStartMs}ms)`);
        installChartDetectionHook(session.page, session);
        await waitForChartAndStartImmediate(session.page, session, { timeoutMs: 20000 });
        if (!session.fullSession) {
          try {
            session.fullSession = await harvestFullSession(session.page, session.context, destUser);
            fileLog('INFO', `[transfer-prep] Harvested full session from cookie path for ${destUser}`);
          } catch (harvestErr) {
            fileLog('WARN', `[transfer-prep] Could not harvest full session for cookie path ${destUser}: ${harvestErr.message}`);
          }
        }
        session.state = 'seats-monitoring';
        session.sniperTargetSeats = Array.isArray(assignedSeats) ? assignedSeats.slice() : [];
        session.targetSeatCount = Math.max(session.targetSeatCount || 0, session.sniperTargetSeats.length);
        emitStatus('destination-ready', `Destination ${destUser} prepared via cookie injection`, { account: destUser, seats: session.sniperTargetSeats });
        return session;
      }
    } catch (cookieErr) {
      fileLog('WARN', `[transfer-prep] Cookie injection path failed for ${destUser}: ${cookieErr.message}`);
    }
  }

  // Fallback: full login flow.
  fileLog('INFO', `[transfer-prep] [${destUser}] Falling back to login flow (${Date.now() - prepStartMs}ms)`);
  session = await ensureSessionForTransfer(launchAccount, { url, targetSections });
  if (!session || !session.page) throw new Error(`Could not prepare destination session for ${destUser}`);
  fileLog('INFO', `[transfer-prep] [${destUser}] Login/session created (${Date.now() - prepStartMs}ms)`);
  installChartDetectionHook(session.page, session);
  try {
    await waitForChartAndStartImmediate(session.page, session, { timeoutMs: 25000 });
  } catch (chartErr) {
    fileLog('WARN', `[transfer-prep] Chart wait warning for ${destUser}: ${chartErr.message}`);
  }
  if (!session.fullSession) {
    try {
      session.fullSession = await harvestFullSession(session.page, session.context, destUser);
      fileLog('INFO', `[transfer-prep] Harvested full session from login path for ${destUser}`);
    } catch (harvestErr) {
      fileLog('WARN', `[transfer-prep] Could not harvest full session for login path ${destUser}: ${harvestErr.message}`);
    }
  }

  session.state = 'seats-monitoring';
  session.sniperTargetSeats = Array.isArray(assignedSeats) ? assignedSeats.slice() : [];
  session.targetSeatCount = Math.max(session.targetSeatCount || 0, session.sniperTargetSeats.length);
  fileLog('INFO', `[transfer-prep] [${destUser}] Destination ready, starting targeted sniper (${Date.now() - prepStartMs}ms)`);
  emitStatus('destination-preparing', `Preparing destination ${destUser} with ${session.sniperTargetSeats.length} target seat(s)`, { account: destUser, seats: session.sniperTargetSeats });

  // Start a targeted sniper that watches only the assigned seats.
  startActiveSniper(session, targetSections || session.sniperSections || []);
  emitStatus('destination-ready', `Destination ${destUser} is monitoring target seats`, { account: destUser, seats: session.sniperTargetSeats });
  return session;
}

function buildSessionFromInjectedContext(username, context, page, account, url, targetSections) {
  sessionCounter++;
  return {
    id: sessionCounter,
    username,
    password: account.password || '',
    type: account.type || 'credentials',
    url: account.url || url,
    targetSections: account.targetSections || targetSections,
    targetSeatCount: Math.max(1, Math.min(parseInt(account.ticketCount, 10) || 30, MAX_HELD_SEATS)),
    isSelecting: false,
    isTransferring: false,
    context,
    page,
    state: 'seats-monitoring',
    selectedSeats: [],
    releasedSeats: new Set(),
    holdToken: null,
    holdTokenCreatedAt: null,
    holdTokenExpiresAt: null,
    holdInterval: null,
    stopRequested: false,
    bookingPaused: false,
    __skipLogin: true,
    speedSettings: { ...currentSpeedSettings },
    proxy: account.assignedProxy || null,
    proxyMode: account.useProxy ? 'required' : 'off',
    workspaceKey: null,
    eventKey: null,
    chartSections: null,
    sniperSections: targetSections || [],
    sniperTargetSeats: [],
  };
}

async function prepareDestinationsInParallel(destinations, destAccountMap, url, targetSections, options = {}) {
  // Prepare all destination browsers in parallel, bounded by maxConcurrency.
  // Returns { ready: [{ username, session, assignedSeats, seatsBySource }], failed: [{ username, error, assignedSeats }] }.
  const PREPARE_TIMEOUT_MS = options.prepareTimeoutMs || 30_000;
  const RETRY_DELAY_MS = options.retryDelayMs || 3_000;
  const concurrency = options.maxConcurrency || maxConcurrency || 3;
  const total = destinations.length;
  const ready = [];
  const failed = [];

  async function prepareOne(destPlan, index, isRetry = false) {
    const toUsername = destPlan.username;
    const assignedSeats = destPlan.assignedSeats;
    const seatsBySource = destPlan.seatsBySource;
    const account = destAccountMap.get(toUsername) || { username: toUsername, useProxy: false };
    const proxyDisplay = account.assignedProxy
      ? account.assignedProxy.server
      : (account.useProxy ? 'auto-proxy' : 'direct');

    emitStatus('destination-preparing', `${isRetry ? 'Retry' : 'Preparing'} destination ${toUsername} with ${assignedSeats.length} seat(s)`, {
      account: toUsername,
      totalDestinations: total,
      currentIndex: index + 1,
      seats: assignedSeats,
      proxy: proxyDisplay,
      retry: isRetry,
    });
    fileLog('INFO', `[transfer-multi] [${index + 1}/${total}] ${isRetry ? 'Retry' : 'Preparing'} destination ${toUsername}: ${assignedSeats.length} seats, proxy=${proxyDisplay}`);

    try {
      const destSession = await withTimeout(
        prepareDestinationForTransfer(toUsername, assignedSeats, account, {
          url: account.url || url,
          targetSections: account.targetSections || targetSections,
        }),
        PREPARE_TIMEOUT_MS,
        `prepare destination ${toUsername}`
      );
      emitStatus('destination-ready', `Destination ${toUsername} is ready`, {
        account: toUsername,
        totalDestinations: total,
        currentIndex: index + 1,
        seats: assignedSeats,
        proxy: proxyDisplay,
      });
      return { ok: true, username: toUsername, session: destSession, assignedSeats, seatsBySource };
    } catch (prepErr) {
      const errMsg = prepErr?.message || String(prepErr);
      fileLog('WARN', `[transfer-multi] Failed to ${isRetry ? 'retry' : 'prepare'} destination ${toUsername}: ${errMsg}`);
      emitStatus('destination-prepare-failed', `Could not ${isRetry ? 'retry' : 'prepare'} destination ${toUsername}: ${errMsg}`, { account: toUsername, error: errMsg, retry: isRetry });
      return { ok: false, username: toUsername, error: errMsg, assignedSeats, seatsBySource };
    }
  }

  // Process destinations in parallel with bounded concurrency using simple batches.
  for (let i = 0; i < destinations.length; i += concurrency) {
    const batch = destinations.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map((destPlan, idx) => prepareOne(destPlan, i + idx)));
    for (const r of batchResults) {
      if (r.ok) {
        ready.push({ username: r.username, session: r.session, assignedSeats: r.assignedSeats, seatsBySource: r.seatsBySource });
      } else {
        failed.push({ username: r.username, error: r.error, assignedSeats: r.assignedSeats, seatsBySource: r.seatsBySource });
      }
    }
  }

  // Retry failed destinations once after a short delay.
  if (failed.length > 0) {
    fileLog('INFO', `[transfer-multi] Retrying ${failed.length} failed destination(s) after ${RETRY_DELAY_MS}ms`);
    await waitFor(RETRY_DELAY_MS);
    const retryResults = await Promise.all(failed.map((destPlan, idx) => prepareOne(destPlan, idx, true)));
    for (const r of retryResults) {
      // Remove from failed if retry succeeded, otherwise keep the original failure.
      const existingIndex = failed.findIndex(f => f.username === r.username);
      if (r.ok) {
        if (existingIndex >= 0) failed.splice(existingIndex, 1);
        ready.push({ username: r.username, session: r.session, assignedSeats: r.assignedSeats, seatsBySource: r.seatsBySource });
      } else if (existingIndex >= 0) {
        failed[existingIndex].error = r.error;
      }
    }
  }

  // Capture full-session snapshots for every ready destination so recovery/reuse
  // paths have the cookies/storage they need.
  for (const dest of ready) {
    await backfillFullSession(dest.session);
  }

  return { ready, failed };
}

async function backfillFullSession(session) {
  // Capture a full session snapshot from a live page so the destination can be
  // recreated later if its active context is closed/lost.
  if (!session || !session.page || !session.context) return false;
  if (session.fullSession) return true;
  try {
    session.fullSession = await harvestFullSession(session.page, session.context, session.username);
    fileLog('INFO', `[transfer-prep] Backfilled fullSession for ${session.username}`);
    return true;
  } catch (e) {
    fileLog('WARN', `[transfer-prep] Could not backfill fullSession for ${session.username}: ${e.message}`);
    return false;
  }
}

async function validateTransferDestinations(destinationAccounts, url, targetSections) {
  // Pre-check every destination account before building a transfer plan.
  // Failed destinations are recorded but do NOT stop the whole transfer.
  if (!Array.isArray(destinationAccounts) || destinationAccounts.length === 0) return [];
  const PREPARE_TIMEOUT_MS = 90_000;
  const results = [];
  for (const account of destinationAccounts) {
    const toUsername = account.username;
    emitStatus('destination-validating', `Validating destination ${toUsername} before transfer...`, { account: toUsername });

    // Fast path 1: cached session.
    const cached = await loadSessionFromCache(toUsername);
    if (cached && validateSession(cached)) {
      fileLog('INFO', `[validate] ${toUsername}: Using cached session`);
      emitStatus('destination-valid', `Destination ${toUsername} ready from cached session`, { account: toUsername });
      results.push({ username: toUsername, ready: true, method: 'cached-session' });
      continue;
    }

    // Fast path 2: cookies provided.
    if (account.rawCookies || account.structuredCookies || account.type === 'holdToken') {
      fileLog('INFO', `[validate] ${toUsername}: Has cookies/holdToken, marking as ready`);
      emitStatus('destination-valid', `Destination ${toUsername} ready via cookies`, { account: toUsername });
      results.push({ username: toUsername, ready: true, method: 'cookies' });
      continue;
    }

    // Fallback: try login.
    try {
      const launchAccount = {
        ...account,
        url: account.url || url,
        targetSections: account.targetSections || targetSections,
      };
      await withTimeout(
        prepareDestinationForTransfer(toUsername, [], account, { url: account.url || url, targetSections: account.targetSections || targetSections }),
        PREPARE_TIMEOUT_MS,
        `validate destination ${toUsername}`
      );
      emitStatus('destination-valid', `Destination ${toUsername} is ready`, { account: toUsername });
      results.push({ username: toUsername, ready: true, method: 'login' });
    } catch (err) {
      const errMsg = err?.message || String(err);
      fileLog('WARN', `[validate] ${toUsername}: FAILED - ${errMsg}`);
      emitStatus('destination-invalid', `Destination ${toUsername} cannot be prepared: ${errMsg}`, { account: toUsername, error: errMsg });
      results.push({ username: toUsername, ready: false, error: errMsg, method: 'failed' });
      // Do NOT throw - continue validating the remaining destinations.
    }
  }
  return results;
}

async function holdSpecificSeatsWithMonitor(page, seatLabels, username, session, timeoutMs = 30000) {
  // Repeatedly attempt to hold a fixed list of seats until all are held or timeout.
  const wanted = [...new Set((seatLabels || []).map(String).filter(Boolean))];
  if (!wanted.length) return { held: [], missing: [] };
  const deadline = Date.now() + timeoutMs;
  const speed = getSpeedSettings(session?.speedSettings);
  const held = [];
  const heldSet = new Set();
  let attempts = 0;
  while (Date.now() < deadline) {
    const stillWanted = wanted.filter(s => !heldSet.has(s));
    if (!stillWanted.length) break;
    attempts++;
    emitStatus('transfer-monitor-hold', `Monitoring hold attempt ${attempts} for ${stillWanted.length} seat(s)`, { account: username, seats: stillWanted });
    const batch = await sendHoldViaRoute(page, stillWanted, {
      fastMode: true,
      timeoutMs: Math.min(2000, speed.sniperTimeoutMs || 1500),
      gapMs: speed.sniperBurstGapMs || 30,
      username,
      token: session?.holdToken,
      speedSettings: session?.speedSettings,
      session,
    });
    for (const s of batch) {
      if (!heldSet.has(s)) {
        heldSet.add(s);
        held.push(s);
      }
    }
    if (heldSet.size < wanted.length) await waitFor(250);
  }
  const missing = wanted.filter(s => !heldSet.has(s));
  return { held, missing };
}

async function resolveTransferBatchSize(eventUrl) {
  let maxTicketsPerUser = 30;
  try {
    const slug = parseSlug(eventUrl);
    const detail = await fetchChartSections(slug);
    maxTicketsPerUser = detail?.maxTicketsPerUser || 30;
  } catch (e) {
    fileLog('WARN', `Could not resolve maxTicketsPerUser for transfer batch size: ${e.message}`);
  }
  return Math.max(1, Math.min(5, maxTicketsPerUser));
}

async function transferBatchAtomicOrAuto(sourceSession, destSession, batch, opts) {
  const { fromUsername, toUsername, batchNum, batchCount, maxBatchRetries, sniperMode, destProxy, mode } = opts;

  emitStatus('transfer-batch-start', `Batch ${batchNum}/${batchCount}: moving ${batch.length} seat(s)`, { from: fromUsername, to: toUsername, batch, batchNum, batchCount, sniperMode });
  emitStatus('transfer-batch-proxy', `Batch ${batchNum}/${batchCount} using proxy ${destProxy ? destProxy.server : 'direct'}`, { account: toUsername, proxy: destProxy ? destProxy.server : null, batch, batchNum, batchCount });

  // 1) Release batch from source in a single WebSocket message.
  const releasedBatch = await releaseSeatsBatch(sourceSession, batch);
  await waitFor(50);
  sourceSession.selectedSeats = sourceSession.selectedSeats.filter(s => !batch.includes(s));
  for (const seat of batch) releaseSeatFromPool(seat);
  if (releasedBatch.length < batch.length) {
    fileLog('WARN', `[${fromUsername}] Batch ${batchNum}: released ${releasedBatch.length}/${batch.length} seats`);
  }

  // 2) Destination grabs the released seats (atomic attempt).
  let heldBatch = [];
  if (sniperMode) {
    await waitFor(800);
    let verified = await verifyHeldSeatsViaApi(destSession.page, destSession.holdToken, batch, { session: destSession });
    if (verified.length < batch.length) {
      const monitorRes = await holdSpecificSeatsWithMonitor(destSession.page, batch, toUsername, destSession, 6000);
      for (const s of monitorRes.held) {
        if (!verified.includes(s)) verified.push(s);
      }
    }
    heldBatch = verified;
  } else {
    for (let attempt = 0; attempt < maxBatchRetries && heldBatch.length < batch.length; attempt++) {
      if (attempt > 0) {
        emitStatus('transfer-batch-retry', `Batch ${batchNum}/${batchCount}: retry ${attempt}/${maxBatchRetries}`, { from: fromUsername, to: toUsername, batch, attempt });
        await waitFor(150 * (attempt + 1));
      }
      heldBatch = await holdSpecificSeatsViaWebSocket(destSession.page, batch, toUsername, destSession);
    }
  }

  let usedMode = 'atomic';

  // 3) Auto fallback: if atomic failed, retry the whole batch in legacy mode once.
  if (mode === 'auto' && heldBatch.length < batch.length) {
    usedMode = 'legacy';
    emitStatus('transfer-fallback', `Batch ${batchNum}: atomic held ${heldBatch.length}/${batch.length}, switching to legacy`, { from: fromUsername, to: toUsername, batch, batchNum, batchCount });

    // Recover missing seats back to source so the source can re-release the full batch.
    const missingAfterAtomic = batch.filter(s => !heldBatch.includes(s));
    if (missingAfterAtomic.length) {
      emitStatus('transfer-recover', `Recovering ${missingAfterAtomic.length} seat(s) back to source before legacy fallback`, { from: fromUsername, to: toUsername, seats: missingAfterAtomic });
      const recoveredMissing = await holdSpecificSeatsViaWebSocket(sourceSession.page, missingAfterAtomic, fromUsername, sourceSession);
      for (const seat of recoveredMissing) {
        if (!sourceSession.selectedSeats.includes(seat)) sourceSession.selectedSeats.push(seat);
      }
    }

    // Release seats that the destination did hold so the source can reclaim them.
    if (heldBatch.length) {
      emitStatus('transfer-fallback-release', `Releasing ${heldBatch.length} seat(s) from destination for legacy retry`, { account: toUsername, batch, batchNum, batchCount });
      const releasedFromDest = await releaseSeatsBatch(destSession, heldBatch);
      await waitFor(50);
      destSession.selectedSeats = destSession.selectedSeats.filter(s => !heldBatch.includes(s));
      const recoveredFromDest = await holdSpecificSeatsViaWebSocket(sourceSession.page, releasedFromDest, fromUsername, sourceSession);
      for (const seat of recoveredFromDest) {
        if (!sourceSession.selectedSeats.includes(seat)) sourceSession.selectedSeats.push(seat);
      }
    }

    // If source now holds the full batch, release it all at once and let the destination re-hold.
    const sourceHoldsFullBatch = batch.every(s => sourceSession.selectedSeats.includes(s));
    if (sourceHoldsFullBatch) {
      try {
        await releaseSeatsBatch(sourceSession, batch);
        await waitFor(50);
        sourceSession.selectedSeats = sourceSession.selectedSeats.filter(s => !batch.includes(s));
        for (const seat of batch) releaseSeatFromPool(seat);
        const legacyHeld = await holdSpecificSeatsViaWebSocket(destSession.page, batch, toUsername, destSession);
        heldBatch = legacyHeld;
      } catch (legacyErr) {
        emitStatus('transfer-legacy-error', `Batch ${batchNum}: legacy fallback error ${legacyErr.message}`, { from: fromUsername, to: toUsername, batch, batchNum, batchCount });
      }
    } else {
      fileLog('WARN', `[${fromUsername}] Batch ${batchNum}: cannot retry legacy because source does not hold full batch`);
    }
  }

  // 4) Recover any seats the destination could not grab back to the source.
  const missingInBatch = batch.filter(s => !heldBatch.includes(s));
  if (missingInBatch.length > 0) {
    emitStatus('transfer-recover', `Recovering ${missingInBatch.length} seat(s) back to source`, { from: fromUsername, to: toUsername, seats: missingInBatch });
    const recovered = await holdSpecificSeatsViaWebSocket(sourceSession.page, missingInBatch, fromUsername, sourceSession);
    for (const seat of recovered) {
      if (!sourceSession.selectedSeats.includes(seat)) sourceSession.selectedSeats.push(seat);
    }
    reserveSeats(fromUsername, sourceSession.selectedSeats);
  }

  emitStatus('transfer-batch-complete', `Batch ${batchNum}/${batchCount}: moved ${heldBatch.length}/${batch.length} (mode: ${usedMode})`, { from: fromUsername, to: toUsername, held: heldBatch, missing: missingInBatch, batchNum, batchCount, mode: usedMode });
  return { heldBatch, usedMode };
}

async function atomicReleaseAndHold(sourceSession, destSession, seats) {
  if (!seats || seats.length === 0) return { held: [], missing: [] };
  const fromUsername = sourceSession.username;
  const toUsername = destSession.username;
  const transferId = transferAuditor.record({ stage: 'atomic-start', sourceUser: fromUsername, destinationUser: toUsername, seats, mode: 'atomic' });
  const startMs = Date.now();
  emitStatus('transfer-atomic', `Atomic transfer of ${seats.length} seat(s) from ${fromUsername} to ${toUsername}`, { from: fromUsername, to: toUsername, seats, transferId });

  try {
    // Ensure source systems are fully paused during the atomic window.
    sourceSession.isTransferring = true;
    if (sourceSession.holdInterval) {
      clearInterval(sourceSession.holdInterval);
      sourceSession.holdInterval = null;
    }
    stopActiveSniper(sourceSession);
    clearHoldWatcher(sourceSession);

    // Pre-warm destination chart frame/WebSocket route.
    await findChartFrame(destSession.page, toUsername);
    await waitFor(5);

    // Step 1: release from source and confirm the seats left the source state.
    const released = await releaseSeatsBatch(sourceSession, seats);
    fileLog('INFO', `[transfer-atomic] Released ${released.length}/${seats.length} from source`);
    if (released.length === 0) {
      return { held: [], missing: seats };
    }
    // Give the server a deterministic window to process the release before holding.
    await waitFor(30);

    // Step 2: hold immediately on destination.
    const held = await sendHoldViaRoute(destSession.page, released, {
      fastMode: true,
      timeoutMs: 3000,
      gapMs: 10,
      username: toUsername,
      token: destSession.holdToken,
      speedSettings: destSession.speedSettings,
      session: destSession,
    }).catch(err => {
      fileLog('WARN', `[transfer-atomic] Destination hold error: ${err.message}`);
      return [];
    });

    const heldSet = new Set(held);
    const missing = released.filter(s => !heldSet.has(s));

    // Retry once for any missing seats.
    if (missing.length > 0) {
      emitStatus('transfer-atomic-retry', `Retrying ${missing.length} missing seat(s) atomically`, { from: fromUsername, to: toUsername, seats: missing });
      await waitFor(50);
      const retryHeld = await sendHoldViaRoute(destSession.page, missing, {
        fastMode: true,
        timeoutMs: 3000,
        gapMs: 10,
        username: toUsername,
        token: destSession.holdToken,
        speedSettings: destSession.speedSettings,
        session: destSession,
      }).catch(() => []);
      for (const s of retryHeld) heldSet.add(s);
    }

    const finalHeld = seats.filter(s => heldSet.has(s));
    const finalMissing = seats.filter(s => !heldSet.has(s));
    transferAuditor.record({ transferId, stage: 'atomic-result', sourceUser: fromUsername, destinationUser: toUsername, seats, held: finalHeld.length, missing: finalMissing.length, mode: 'atomic', durationMs: Date.now() - startMs });
    emitStatus('transfer-atomic-result', `Atomic transfer: ${finalHeld.length}/${seats.length} held`, { from: fromUsername, to: toUsername, held: finalHeld, missing: finalMissing, transferId });
    return { held: finalHeld, missing: finalMissing };
  } catch (err) {
    transferAuditor.record({ transferId, stage: 'atomic-error', sourceUser: fromUsername, destinationUser: toUsername, seats, held: 0, missing: seats.length, mode: 'atomic', durationMs: Date.now() - startMs, error: err.message });
    fileLog('ERROR', `[transfer-atomic] Atomic transfer failed: ${err.message}`);
    return { held: [], missing: seats };
  } finally {
    sourceSession.isTransferring = false;
    // Keepalive was cleared during the atomic window; restart it so the source's
    // remaining seats do not expire.
    if (sourceSession.page && !sourceSession.stopRequested) {
      startHoldKeepalive(sourceSession);
    }
  }
}

async function liveStreamAtomicReleaseAndHold(sourceSession, destSession, seats, opts = {}) {
  // Coordinated simultaneous release/hold: the destination spams hold attempts in a
  // tight loop while the source releases the exact same seats a few milliseconds later.
  // This minimizes the public-pool window to roughly one network round-trip.
  if (!seats || seats.length === 0) return { held: [], missing: [] };
  const fromUsername = sourceSession.username;
  const toUsername = destSession.username;
  const maxAttempts = typeof opts.maxAttempts === 'number' ? opts.maxAttempts : 150;
  const pollMs = typeof opts.pollMs === 'number' ? opts.pollMs : 10;
  const releaseDelayMs = typeof opts.releaseDelayMs === 'number' ? opts.releaseDelayMs : 25;
  const transferId = transferAuditor.record({ stage: 'livestream-start', sourceUser: fromUsername, destinationUser: toUsername, seats, mode: 'livestream' });
  const startMs = Date.now();
  emitStatus('transfer-livestream', `Live-stream atomic transfer of ${seats.length} seat(s) to ${toUsername}`, { from: fromUsername, to: toUsername, seats, transferId });

  try {
    // Pause source systems so it cannot reclaim the seats during the window.
    sourceSession.isTransferring = true;
    stopActiveSniper(sourceSession);
    clearHoldWatcher(sourceSession);
    if (sourceSession.holdInterval) {
      clearInterval(sourceSession.holdInterval);
      sourceSession.holdInterval = null;
    }
    // Prevent the source sniper from ever targeting these seats again.
    if (Array.isArray(sourceSession.sniperTargetSeats)) {
      sourceSession.sniperTargetSeats = sourceSession.sniperTargetSeats.filter(s => !seats.includes(s));
    }
    // Mark seats as released immediately so no other account/sniper grabs them.
    for (const s of seats) {
      sourceSession.releasedSeats.add(String(s).trim().toUpperCase());
      releaseSeatFromPool(s);
    }

    // Pre-warm destination chart/WebSocket route.
    await findChartFrame(destSession.page, toUsername).catch(() => {});

    const heldSet = new Set();
    let loopFinished = false;

    const holdLoop = (async () => {
      for (let i = 0; i < maxAttempts && !loopFinished; i++) {
        const still = seats.filter(s => !heldSet.has(s));
        if (!still.length) break;
        try {
          const batch = await sendHoldViaRoute(destSession.page, still, {
            fastMode: true,
            timeoutMs: 1500,
            gapMs: 5,
            username: toUsername,
            token: destSession.holdToken,
            speedSettings: destSession.speedSettings,
            session: destSession,
          });
          for (const s of batch) heldSet.add(s);
        } catch {}
        if (heldSet.size < seats.length) await waitFor(pollMs);
      }
    })();

    // Let the destination loop start firing, then release from source.
    await waitFor(releaseDelayMs);
    const released = await releaseSeatsBatch(sourceSession, seats);

    // Wait for the loop to capture the seats (or timeout).
    await Promise.race([holdLoop, waitFor(maxAttempts * pollMs + 2000)]);
    loopFinished = true;

    const held = seats.filter(s => heldSet.has(s));
    const missing = seats.filter(s => !heldSet.has(s));

    // Update source state so keepalive/sniper do not fight for transferred seats.
    if (held.length) {
      sourceSession.selectedSeats = sourceSession.selectedSeats.filter(s => !held.includes(s));
      for (const s of held) {
        const key = String(s).trim().toUpperCase();
        sourceSession.releasedSeats.add(key);
        releaseSeatFromPool(s);
      }
    }
    // Any seats the destination could not grab should be reclaimable by the source.
    if (missing.length) {
      for (const s of missing) {
        const key = String(s).trim().toUpperCase();
        sourceSession.releasedSeats.delete(key);
      }
    }

    transferAuditor.record({ transferId, stage: 'livestream-result', sourceUser: fromUsername, destinationUser: toUsername, seats, held: held.length, missing: missing.length, mode: 'livestream', durationMs: Date.now() - startMs });
    emitStatus('transfer-livestream-result', `Live-stream transfer: ${held.length}/${seats.length} held`, { from: fromUsername, to: toUsername, held, missing, transferId });
    return { held, missing };
  } catch (err) {
    transferAuditor.record({ transferId, stage: 'livestream-error', sourceUser: fromUsername, destinationUser: toUsername, seats, held: 0, missing: seats.length, mode: 'livestream', durationMs: Date.now() - startMs, error: err.message });
    fileLog('ERROR', `[transfer-livestream] ${fromUsername} -> ${toUsername}: ${err.message}`);
    return { held: [], missing: seats };
  } finally {
    sourceSession.isTransferring = false;
    // Restart keepalive so the source's remaining seats stay extended.
    if (sourceSession.page && !sourceSession.stopRequested) {
      startHoldKeepalive(sourceSession);
    }
  }
}

async function legacyReleaseAndHold(sourceSession, destSession, seats) {
  if (!seats || seats.length === 0) return { held: [], missing: [] };
  const fromUsername = sourceSession.username;
  const toUsername = destSession.username;
  emitStatus('transfer-legacy', `Legacy transfer of ${seats.length} seat(s) from ${fromUsername} to ${toUsername}`, { from: fromUsername, to: toUsername, seats });

  try {
    const released = await releaseSeatsBatch(sourceSession, seats);
    await waitFor(200);
    sourceSession.selectedSeats = sourceSession.selectedSeats.filter(s => !seats.includes(s));
    for (const seat of seats) releaseSeatFromPool(seat);

    const held = await sendHoldViaRoute(destSession.page, seats, {
      fastMode: true,
      timeoutMs: 5000,
      gapMs: 20,
      username: toUsername,
      token: destSession.holdToken,
      speedSettings: destSession.speedSettings,
      session: destSession,
    }).catch(() => []);
    const heldSet = new Set(held);
    const missing = seats.filter(s => !heldSet.has(s));
    emitStatus('transfer-legacy-result', `Legacy transfer: ${held.length}/${seats.length} held`, { from: fromUsername, to: toUsername, held, missing });
    return { held, missing };
  } catch (err) {
    fileLog('ERROR', `[transfer-legacy] Legacy transfer failed: ${err.message}`);
    return { held: [], missing: seats };
  }
}

async function transferSeatsToDestination(sourceSession, destSession, opts = {}) {
  const requestedMode = opts.mode === 'legacy' ? 'legacy' : (opts.mode === 'auto' ? 'auto' : 'atomic');
  const batchSize = opts.batchSize
    ? Math.max(1, Math.min(parseInt(opts.batchSize, 10) || 5, 10))
    : await resolveTransferBatchSize(opts.url || sourceSession.url || destSession.url || '');
  const maxBatchRetries = Math.max(1, Math.min(parseInt(opts.maxBatchRetries, 10) || 2, 5));
  const fixedSeats = Array.isArray(opts.fixedSeats) && opts.fixedSeats.length ? opts.fixedSeats : null;
  if (!fixedSeats) throw new Error('fixedSeats array is required for transferSeatsToDestination');

  const fromUsername = sourceSession.username;
  const toUsername = destSession.username;
  const sniperMode = opts.sniperMode === true;

  // Transaction isolation: lock both accounts during the transfer.
  if (sourceSession.isSelecting || destSession.isSelecting) {
    throw new Error('ACCOUNT_BUSY: one of the accounts is already in a selecting/transfer operation');
  }
  sourceSession.isSelecting = true;
  // In sniper mode the destination sniper must remain active, so we only mark it
  // as transferring (not selecting) and allow the sniper loop to grab released seats.
  if (sniperMode) {
    destSession.isTransferring = true;
  } else {
    destSession.isSelecting = true;
  }

  // Guard: prevent source WS listeners/sniper from reclaiming released seats.
  sourceSession.isTransferring = true;
  sourceSession.__transferTarget = toUsername;
  whitelistForTransfer([fromUsername, toUsername]);
  pauseSnipersForSections(fixedSeats);

  try {
    emitStatus('transfer-start', `Transferring seats from ${fromUsername} to ${toUsername} (${requestedMode} mode)`, { from: fromUsername, to: toUsername, mode: requestedMode, batchSize });

    // Defensive: ensure keepalive/sniper are fully paused for the source.
    if (sourceSession.holdInterval) {
      clearInterval(sourceSession.holdInterval);
      sourceSession.holdInterval = null;
    }
    stopActiveSniper(sourceSession);
    clearHoldWatcher(sourceSession);

    // 1. Verify/resolve destination proxy using only the account's own proxy
    // decision. The global proxy mode must not override a direct account during
    // a transfer; proxy logic for transfers is isolated from account proxy logic.
    let destProxy = destSession.proxy;
    let destProxyMode = destSession.proxyMode || 'off';
    if (destProxy || destSession.proxyMode === 'forced' || destSession.proxyMode === 'required') {
      const proxyTest = destProxy ? await testProxy(destProxy, 5000) : { ok: false };
      if (!proxyTest.ok) {
        const resolved = await resolveProxyForAccount(toUsername, destSession.proxyMode === 'forced' || destSession.proxyMode === 'required');
        if (resolved.proxy) {
          destProxy = resolved.proxy;
          destProxyMode = resolved.mode;
          destSession.proxy = destProxy;
          destSession.proxyMode = destProxyMode;
          emitStatus('transfer-proxy-failover', `Destination proxy updated for ${toUsername}: ${destProxy.server}`, { account: toUsername, proxy: destProxy.server, mode: destProxyMode });
        } else if (destSession.proxyMode === 'required' || destSession.proxyMode === 'forced') {
          throw new Error(`DESTINATION_PROXY_REQUIRED: No working proxy for ${toUsername}`);
        }
      }
    }
    emitStatus('transfer-proxy-start', `Destination ${toUsername} using proxy ${destProxy ? destProxy.server : 'direct'}`, { account: toUsername, proxy: destProxy ? destProxy.server : null, mode: destProxyMode });

    // 2. Verify the fixed seats are still held by the source.
    const snapshot = await verifyHeldSeatsViaApi(sourceSession.page, sourceSession.holdToken, fixedSeats, { session: sourceSession });
    if (!snapshot.length) throw new Error('Source account has no verified seats to transfer');

    // 3. Reserve seats in global pool so other accounts cannot grab them during transfer.
    reserveSeats(toUsername, snapshot);

    // 4. Stop the source sniper and pause keepalive so the source does not
    // reclaim seats while the destination is trying to hold them.
    stopActiveSniper(sourceSession);
    stopActiveSniper(destSession);
    pauseKeepalive(sourceSession);
    pauseKeepalive(destSession);

    // 5. Destination must be on the booking page with a live chart.
    const destFrame = await findChartFrame(destSession.page, toUsername);
    if (!destFrame) throw new Error('Destination chart is not ready');

    destSession.targetSeatCount = Math.max(destSession.targetSeatCount || 0, snapshot.length);

    let finalSeats = [];
    let releasedAll = false;
    const batchCount = Math.ceil(snapshot.length / batchSize);
    const sniperMode = opts.sniperMode === true;

    if (requestedMode === 'legacy') {
      // Legacy mode: release all fixed seats from source in one batch then have destination re-hold them.
      let released = false;
      try {
        await releaseSeatsBatch(sourceSession, snapshot);
        await waitFor(50);
        sourceSession.selectedSeats = sourceSession.selectedSeats.filter(s => !snapshot.includes(s));
        for (const seat of snapshot) releaseSeatFromPool(seat);
        released = true;
        emitAccountUpdate(fromUsername, 'idle', { seats: sourceSession.selectedSeats });
      } catch (e) {
        throw new Error(`Failed to release source seats: ${e.message}`);
      }
      releasedAll = released;

      const heldByDest = await holdSpecificSeatsViaWebSocket(destSession.page, snapshot, toUsername, destSession);
      finalSeats = heldByDest;
      if (heldByDest.length < snapshot.length) {
        const missing = snapshot.filter(s => !heldByDest.includes(s));
        const needed = snapshot.length - heldByDest.length;
        emitStatus('transfer-refill', `Refilling ${needed} missing seat(s) on destination`, { from: fromUsername, to: toUsername, missing });
        const refill = await selectSeatsViaWebSocket(destSession.page, destSession.targetSections || [], needed, toUsername, destSession);
        finalSeats = [...new Set([...heldByDest, ...refill])];
      }
    } else {
      // Atomic mode (or auto): release per batch then immediately re-hold on destination.
      // If mode is 'auto' and atomic fails for a batch, fall back to legacy for that batch.
      const transferred = [];
      const lost = [];
      const batchModes = [];

      for (let i = 0; i < snapshot.length; i += batchSize) {
        const batch = snapshot.slice(i, i + batchSize);
        const batchNum = Math.floor(i / batchSize) + 1;
        const { heldBatch, usedMode } = await transferBatchAtomicOrAuto(sourceSession, destSession, batch, {
          fromUsername,
          toUsername,
          batchNum,
          batchCount,
          maxBatchRetries,
          sniperMode,
          destProxy,
          mode: requestedMode,
        });
        transferred.push(...heldBatch);
        batchModes.push(usedMode);
        for (const seat of batch) {
          if (!heldBatch.includes(seat) && !sourceSession.selectedSeats.includes(seat)) lost.push(seat);
        }
      }

      // Refill any seats still missing on destination using fresh seats.
      finalSeats = transferred;
      if (transferred.length < snapshot.length) {
        const needed = snapshot.length - transferred.length;
        emitStatus('transfer-refill', `Refilling ${needed} missing seat(s) on destination`, { from: fromUsername, to: toUsername, missing: lost });
        const refill = await selectSeatsViaWebSocket(destSession.page, destSession.targetSections || [], needed, toUsername, destSession);
        finalSeats = [...new Set([...transferred, ...refill])];
      }

      // Final recovery pass: any seat that is neither held by destination nor
      // already recovered back to source is returned to the master account.
      let finalMissing = snapshot.filter(s => !finalSeats.includes(s) && !sourceSession.selectedSeats.includes(s));
      if (finalMissing.length > 0) {
        emitStatus('transfer-final-recovery', `Final recovery: attempting to return ${finalMissing.length} seat(s) to source`, { from: fromUsername, to: toUsername, seats: finalMissing });
        const recoveredFinal = await holdSpecificSeatsViaWebSocket(sourceSession.page, finalMissing, fromUsername, sourceSession);
        if (recoveredFinal.length > 0) {
          for (const seat of recoveredFinal) {
            if (!sourceSession.selectedSeats.includes(seat)) sourceSession.selectedSeats.push(seat);
          }
          reserveSeats(fromUsername, sourceSession.selectedSeats);
          emitStatus('transfer-final-recovered', `Final recovery returned ${recoveredFinal.length}/${finalMissing.length} seat(s) to source`, { from: fromUsername, seats: recoveredFinal });
        }
      }

      releasedAll = true;
      if (requestedMode === 'auto' && batchModes.includes('legacy')) {
        fileLog('INFO', `[transfer] Used atomic+legacy fallback for ${batchModes.filter(m => m === 'legacy').length}/${batchCount} batch(es)`);
      }
    }

    // 6. Finalize source state and global seat pool.
    // Seats that the destination actually held (subset of snapshot) are removed
    // from the source; seats recovered back to the source are kept.
    const seatsMovedToDestination = snapshot.filter(s => finalSeats.includes(s));
    sourceSession.selectedSeats = sourceSession.selectedSeats.filter(s => !seatsMovedToDestination.includes(s));
    for (const seat of snapshot) {
      if (!sourceSession.selectedSeats.includes(seat)) releaseSeatFromPool(seat);
    }

    // After a successful transfer, lower the source's target so it does not try
    // to refill seats that now belong to the destination. This prevents the
    // source and destination from fighting over the same seats during keepalive.
    sourceSession.targetSeatCount = sourceSession.selectedSeats.length;
    if (sourceSession.sniperSections) {
      // Do not let the source sniper hunt in sections where it no longer holds seats.
      sourceSession.sniperSections = (sourceSession.sniperSections || []).filter(s =>
        sourceSession.selectedSeats.some(seat => String(seat).split('-')[0].toUpperCase() === s)
      );
    }

    // 7. Set destination's selected seats to the actually held seats and reserve them.
    destSession.selectedSeats = finalSeats;
    destSession.targetSeatCount = finalSeats.length;
    reserveSeats(toUsername, finalSeats);

    // Sync both source and destination chart UIs so the operator sees the moved
    // seats immediately instead of stale selections.
    try {
      const destFrame = await findChartFrame(destSession.page, toUsername);
      if (destFrame) {
        await syncChartSelection(destFrame, finalSeats, { page: destSession.page, username: toUsername });
      }
    } catch (syncErr) {
      fileLog('WARN', `[${toUsername}] Transfer destination chart sync warning: ${syncErr.message}`);
    }
    try {
      const srcFrame = await findChartFrame(sourceSession.page, fromUsername);
      if (srcFrame) {
        await syncChartSelection(srcFrame, sourceSession.selectedSeats, { page: sourceSession.page, username: fromUsername });
      }
    } catch (syncErr) {
      fileLog('WARN', `[${fromUsername}] Transfer source chart sync warning: ${syncErr.message}`);
    }

    const recoveredSeats = snapshot.filter(s => sourceSession.selectedSeats.includes(s) && !finalSeats.includes(s));
    const missingSeats = snapshot.filter(s => !finalSeats.includes(s) && !sourceSession.selectedSeats.includes(s));

    emitStatus('transfer-proxy-complete', `Transferred ${finalSeats.length} seat(s) with proxy ${destProxy ? destProxy.server : 'direct'}`, { account: toUsername, from: fromUsername, proxy: destProxy ? destProxy.server : null, seats: finalSeats });
    emitStatus('transfer-done', `Transferred ${finalSeats.length} seat(s) from ${fromUsername} to ${toUsername}`, {
      from: fromUsername,
      to: toUsername,
      seats: finalSeats,
      recovered: recoveredSeats,
      missing: missingSeats,
      mode: requestedMode,
      releasedAll,
      proxy: destProxy ? destProxy.server : null,
    });
    emitAccountUpdate(fromUsername, 'idle', { seats: sourceSession.selectedSeats });
    emitAccountUpdate(toUsername, 'paused', { seats: finalSeats });

    // 8. Restart sniper on destination so it keeps monitoring.
    if (!destSession.stopRequested) {
      startActiveSniper(destSession, destSession.targetSections);
    }

    // 9. Return result.
    return {
      success: true,
      from: fromUsername,
      to: toUsername,
      transferredSeats: finalSeats,
      recoveredSeats,
      missingSeats,
      mode: requestedMode,
      destinationProxy: destProxy ? destProxy.server : null,
    };
  } finally {
    sourceSession.isTransferring = false;
    sourceSession.isSelecting = false;
    sourceSession.__transferTarget = null;
    removeFromTransferWhitelist(toUsername);
    removeFromTransferWhitelist(fromUsername);
    resumeKeepalive(sourceSession);
    resumeKeepalive(destSession);
    resumePausedTransferSnipers();
    if (sniperMode) {
      destSession.isTransferring = false;
    } else {
      destSession.isSelecting = false;
    }
  }
}

async function transferSeatsBetweenAccounts(fromUsername, toUsername, opts = {}) {
  const source = activeSessions.get(fromUsername);
  const dest = activeSessions.get(toUsername);
  if (!source) throw new Error('Source account has no active session');
  if (!dest) throw new Error('Destination account has no active session');

  const fixedSeats = Array.isArray(opts.fixedSeats) && opts.fixedSeats.length ? opts.fixedSeats : null;
  const sourceSeats = fixedSeats || source.selectedSeats;
  if (!sourceSeats || sourceSeats.length === 0) throw new Error('Source account is not holding any seats');

  const blockedStates = ['payment', 'payment-ready', 'done'];
  if (blockedStates.includes(source.state) || blockedStates.includes(dest.state)) {
    throw new Error('Cannot transfer while source or destination is on payment page');
  }

  if (transferLocks.has(fromUsername)) throw new Error('Transfer already in progress for source account');
  transferLocks.add(fromUsername);

  try {
    return await transferSeatsToDestination(source, dest, { ...opts, fixedSeats: sourceSeats });
  } finally {
    transferLocks.delete(fromUsername);
  }
}

async function transferSeatsMulti(fromUsernames, toUsernames, opts = {}) {
  const mode = opts.mode === 'legacy' ? 'legacy' : (opts.mode === 'atomic' ? 'atomic' : 'auto');
  const batchSize = opts.batchSize ? Math.max(1, Math.min(parseInt(opts.batchSize, 10) || 5, 10)) : 5;
  const maxBatchRetries = Math.max(1, Math.min(parseInt(opts.maxBatchRetries, 10) || 2, 5));
  const url = opts.url;
  const targetSections = opts.targetSections;
  const destinationAccounts = Array.isArray(opts.destinationAccounts) ? opts.destinationAccounts : [];
  const sniperMode = opts.sniperMode === true; // only true when the caller explicitly requests the plan flow
  const distribution = opts.distribution === 'manual' ? 'manual' : 'auto';

  // Support new API shape where opts may contain masterUsernames/destinations directly.
  const masterUsernames = Array.isArray(opts.masterUsernames) && opts.masterUsernames.length
    ? opts.masterUsernames
    : fromUsernames;
  const destinationSpecs = Array.isArray(opts.destinations) && opts.destinations.length
    ? opts.destinations
    : toUsernames.map(u => {
        const existing = destinationAccounts.find(a => a.username === u);
        return existing ? { ...existing, username: u } : { username: u, ticketCount: 0 };
      });

  if (!Array.isArray(masterUsernames) || masterUsernames.length === 0) {
    throw new Error('masterUsernames/fromUsernames array required');
  }
  if (!Array.isArray(destinationSpecs) || destinationSpecs.length === 0) {
    throw new Error('destinations/toUsernames array required');
  }

  // 1. Validate all sources are active sessions with held seats.
  const sources = [];
  for (const username of masterUsernames) {
    const session = activeSessions.get(username);
    if (!session) throw new Error(`Source account ${username} has no active session`);
    if (!session.selectedSeats || session.selectedSeats.length === 0) {
      throw new Error(`Source account ${username} is not holding any seats`);
    }
    sources.push(session);
  }

  // Add transferLocks protection per source session.
  for (const session of sources) {
    if (transferLocks.has(session.username)) {
      throw new Error(`Transfer already in progress for source account ${session.username}`);
    }
  }
  for (const session of sources) {
    transferLocks.add(session.username);
  }

  // Exempt all transfer participants from section-contention checks so the
  // destination(s) can receive seats from the source(s) without being blocked.
  const transferParticipantUsernames = [
    ...masterUsernames,
    ...destinationSpecs.map(d => d.username),
  ];
  whitelistForTransfer(transferParticipantUsernames);

  try {
    fileLog('INFO', `[transfer-multi] Starting multi-transfer: masters=${masterUsernames.length}, destinations=${destinationSpecs.length}, mode=${mode}, sniperMode=${sniperMode}, distribution=${distribution}`);

    // 2. Build transfer plan: verify seats, pool them, and assign to destinations.
    const plan = await buildTransferPlan(sources, destinationSpecs, { mode, batchSize, maxBatchRetries });
    const totalPlannedSeats = plan.destinations.reduce((s, d) => s + d.assignedSeats.length, 0);
    fileLog('INFO', `[transfer-multi] Plan built: ${plan.masters.length} masters, ${plan.destinations.length} destinations, ${totalPlannedSeats} seats assigned`);
    for (const m of plan.masters) {
      fileLog('INFO', `[transfer-multi] Master ${m.username} contributes ${m.verifiedSeats.length} verified seats: ${m.verifiedSeats.join(', ')}`);
    }
    for (const d of plan.destinations) {
      fileLog('INFO', `[transfer-multi] Destination ${d.username} assigned ${d.assignedSeats.length} seats: ${d.assignedSeats.join(', ')}`);
    }
    emitStatus('transfer-plan-built', `Transfer plan: ${plan.masters.length} masters, ${plan.destinations.length} destinations, ${totalPlannedSeats} seats`, {
      masters: plan.masters.map(m => m.username),
      destinations: plan.destinations.map(d => ({ username: d.username, count: d.assignedSeats.length })),
      totalSeats: totalPlannedSeats,
    });

    // 3. Build a lookup of destination account configs. Proxy handling is
    // intentionally isolated from the transfer logic: each destination launches
    // using its own account-level proxy/direct setting (useProxy/assignedProxy).
    // The transfer section never runs its own proxy test/assignment batch.
    const toUsernames = destinationSpecs.map(d => d.username);
    const destAccountMap = new Map();
    for (const u of toUsernames) {
      const existing = destinationAccounts.find(a => a.username === u);
      const spec = destinationSpecs.find(d => d.username === u);
      destAccountMap.set(u, {
        username: u,
        useProxy: existing && typeof existing.useProxy === 'boolean' ? existing.useProxy : false,
        assignedProxy: existing?.assignedProxy || null,
        url: existing?.url || url,
        targetSections: existing?.targetSections || targetSections,
        // Merge full account object (password, type, holdToken, etc.) if provided.
        ...(existing || {}),
        ...spec,
      });
    }

    // 3b. Validate all destinations can actually log in / inject cookies BEFORE
    // the master releases any seats. This prevents the "23 seats lost to 2FA"
    // scenario seen in the logs. Failed destinations are skipped instead of
    // aborting the whole transfer.
    const validationResults = await validateTransferDestinations(destinationAccounts, url, targetSections);
    const validDestUsernames = new Set(validationResults.filter(r => r.ready).map(r => r.username));
    const invalidDestinations = validationResults.filter(r => !r.ready);
    if (invalidDestinations.length) {
      fileLog('WARN', `[transfer-multi] ${invalidDestinations.length} destination(s) failed validation: ${invalidDestinations.map(d => `${d.username} (${d.error})`).join('; ')}`);
      emitStatus('transfer-validation-skipped', `Skipping ${invalidDestinations.length} invalid destination(s)`, { skipped: invalidDestinations.map(d => d.username) });
    }
    const filteredDestinationSpecs = destinationSpecs.filter(d => validDestUsernames.has(d.username));
    if (filteredDestinationSpecs.length === 0) {
      throw new Error('TRANSFER_NO_VALID_DESTINATIONS: all destinations failed validation');
    }

    // Rebuild the plan with only validated destinations so the master never
    // reserves seats for a destination that cannot receive them.
    const validatedPlan = await buildTransferPlan(sources, filteredDestinationSpecs, { mode, batchSize, maxBatchRetries });
    plan.destinations = validatedPlan.destinations;

    // 4. Show the seat distribution preview immediately so the operator sees
    // which destination will receive which seats before any browser opens.
    const distributionPreview = plan.destinations.map(d => {
      const account = destAccountMap.get(d.username) || {};
      const proxy = account.assignedProxy || null;
      return {
        username: d.username,
        seats: d.assignedSeats,
        seatsBySource: d.seatsBySource,
        proxy: proxy ? proxy.server : (account.useProxy ? 'auto' : 'direct'),
      };
    });
    emitStatus('transfer-distribution-preview', `Seat distribution ready: ${totalPlannedSeats} seats across ${plan.destinations.length} destination(s)`, {
      totalSeats: totalPlannedSeats,
      destinations: distributionPreview,
    });
    fileLog('INFO', `[transfer-multi] Distribution preview: ${JSON.stringify(distributionPreview.map(d => ({ user: d.username, count: d.seats.length, proxy: d.proxy, seats: d.seats })))}`);

    // 5. Prepare all destination browsers in parallel (bounded by maxConcurrency),
    // then transfer seats sequentially. Parallel prep cuts total preparation time
    // from N * t to roughly t, while sequential transfer avoids multiple sources
    // releasing seats at the exact same moment.
    const PREPARE_TIMEOUT_MS = 90_000;
    const prepareConcurrency = Math.max(1, maxConcurrency || 3);
    const { ready: readyDestinations, failed: failedDestinations } = await prepareDestinationsInParallel(
      plan.destinations,
      destAccountMap,
      url,
      targetSections,
      { prepareTimeoutMs: PREPARE_TIMEOUT_MS, maxConcurrency: prepareConcurrency }
    );

    // 5b. Re-balance seats from failed destinations onto ready destinations.
    let activeDestinations = readyDestinations.slice();
    if (failedDestinations.length > 0) {
      const failedSeats = failedDestinations.flatMap(d => d.assignedSeats || []);
      fileLog('WARN', `[transfer-multi] ${failedDestinations.length} destination(s) failed to prepare; attempting to re-distribute ${failedSeats.length} seats`);
      emitStatus('transfer-rebalance-start', `Re-distributing ${failedSeats.length} seat(s) from failed destinations`, { failed: failedDestinations.map(d => d.username), seatCount: failedSeats.length });

      // Rebuild seat -> source map from the original plan so rebalanced seats keep their source attribution.
      const sourceMap = new Map();
      for (const destPlan of plan.destinations) {
        for (const [sourceUsername, seats] of Object.entries(destPlan.seatsBySource || {})) {
          for (const seat of seats) sourceMap.set(seat, sourceUsername);
        }
      }

      const reassignTargets = activeDestinations.map(d => {
        const account = destAccountMap.get(d.username) || {};
        const maxCount = Math.max(1, Math.min(parseInt(account.ticketCount, 10) || 30, 30));
        const currentCount = d.assignedSeats.length;
        return { username: d.username, ticketCount: Math.max(0, maxCount - currentCount) };
      }).filter(d => d.ticketCount > 0);

      if (reassignTargets.length > 0) {
        const extraAssignments = assignSeatsToDestinations(failedSeats, reassignTargets);
        for (const extra of extraAssignments) {
          const dest = activeDestinations.find(d => d.username === extra.username);
          if (dest && extra.assignedSeats.length) {
            dest.assignedSeats = [...new Set([...dest.assignedSeats, ...extra.assignedSeats])];
            // Rebuild seatsBySource for the newly added seats from their original sources.
            for (const seat of extra.assignedSeats) {
              const source = sourceMap.get(seat);
              if (!source) continue;
              if (!dest.seatsBySource[source]) dest.seatsBySource[source] = [];
              if (!dest.seatsBySource[source].includes(seat)) dest.seatsBySource[source].push(seat);
            }
          }
        }
        emitStatus('transfer-rebalanced', `Re-distributed seats from failed destinations`, {
          failed: failedDestinations.map(d => d.username),
          reassignments: activeDestinations.map(d => ({ username: d.username, assignedSeats: d.assignedSeats })),
        });
      } else {
        fileLog('WARN', `[transfer-multi] No ready destination can absorb failed-destination seats; keeping them on source masters`);
        emitStatus('transfer-rebalance-none', `No ready destination can absorb failed-destination seats; keeping them on source masters`, { failedSeats });
      }
    }

    // 5d. Ensure every source and ready destination has a full session snapshot
    // for recovery / reuse if the active browser context is lost.
    for (const src of sources) {
      await backfillFullSession(src);
    }
    for (const dest of activeDestinations) {
      await backfillFullSession(dest.session);
    }

    // 5c. Transfer seats sequentially through each ready destination.
    const results = [];
    let totalTransferred = 0;
    let totalMissing = 0;

    for (let destIdx = 0; destIdx < activeDestinations.length; destIdx++) {
      const destPlan = activeDestinations[destIdx];
      const toUsername = destPlan.username;
      const assignedSeats = destPlan.assignedSeats;
      const seatsBySource = destPlan.seatsBySource;
      const destSession = destPlan.session;
      const account = destAccountMap.get(toUsername) || { username: toUsername, useProxy: false };

      fileLog('INFO', `[transfer-multi] [${destIdx + 1}/${activeDestinations.length}] Transferring to ${toUsername}: ${assignedSeats.length} seats`);

      let transferredSeats = [];
      let missingSeats = [];
      for (const [sourceUsername, seatsForSource] of Object.entries(seatsBySource)) {
        const sourceSession = activeSessions.get(sourceUsername);
        if (!sourceSession) {
          fileLog('WARN', `[transfer-multi] Source session ${sourceUsername} disappeared; marking ${seatsForSource.length} seats missing`);
          missingSeats.push(...seatsForSource);
          continue;
        }
        fileLog('INFO', `[transfer-multi] Transferring ${seatsForSource.length} seats from ${sourceUsername} to ${toUsername}: ${seatsForSource.join(', ')}`);
        const transferResult = await transferSeatsToDestination(sourceSession, destSession, {
          fixedSeats: seatsForSource,
          mode,
          batchSize,
          maxBatchRetries,
          sniperMode: true, // live-stream style: release from master as destination captures
        });
        fileLog('INFO', `[transfer-multi] Result to ${toUsername} from ${sourceUsername}: transferred=${(transferResult.transferredSeats || []).length}, missing=${(transferResult.missingSeats || []).length}`);
        transferredSeats.push(...(transferResult.transferredSeats || []));
        missingSeats.push(...(transferResult.missingSeats || []));
      }

      transferredSeats = [...new Set(transferredSeats)];
      destSession.selectedSeats = transferredSeats;
      reserveSeats(toUsername, transferredSeats);
      emitAccountUpdate(toUsername, 'paused', { seats: transferredSeats });

      totalTransferred += transferredSeats.length;
      totalMissing += missingSeats.length;

      fileLog('INFO', `[transfer-multi] Destination ${toUsername} final: transferred=${transferredSeats.length}, missing=${missingSeats.length}`);
      results.push({
        destination: toUsername,
        transferred: transferredSeats.length,
        failed: missingSeats.length,
        seats: transferredSeats,
        missing: missingSeats,
        refilled: [],
      });
    }

    // Add failed-destination entries to the result list.
    for (const failed of failedDestinations) {
      const rebalancedSeats = activeDestinations
        .flatMap(d => d.assignedSeats || [])
        .filter(s => failed.assignedSeats.includes(s));
      const trulyLost = failed.assignedSeats.filter(s => !rebalancedSeats.includes(s));
      totalMissing += trulyLost.length;
      results.push({
        destination: failed.username,
        transferred: rebalancedSeats.length,
        failed: trulyLost.length,
        seats: rebalancedSeats,
        missing: trulyLost,
        refilled: [],
        error: failed.error,
      });
    }

    return {
      success: true,
      totalTransferred,
      totalMissing,
      details: results,
    };
  } finally {
    clearTransferWhitelist();
    for (const session of sources) {
      transferLocks.delete(session.username);
    }
  }
}

// Transfer held seats from one or more source accounts to one or more destination accounts.
// Backward compatible shapes:
//   - Single: { fromUsername, toUsername, mode, batchSize, maxBatchRetries }
//   - Legacy multi: { fromUsernames, toUsernames, mode, batchSize, url, targetSections, destinationAccounts }
// New plan-based multi:
//   { masterUsernames, destinations: [{ username, ticketCount }], mode, batchSize, maxBatchRetries, url, targetSections, distribution, sniperMode }
app.post('/api/transfer-seats', async (req, res) => {
  const { fromUsername, toUsername, fromUsernames, toUsernames, masterUsernames, destinations, mode, batchSize, maxBatchRetries, url, targetSections, destinationAccounts, distribution, sniperMode } = req.body;

  // Backward compatibility: single source -> single destination.
  if (typeof fromUsername === 'string' && typeof toUsername === 'string') {
    try {
      const result = await transferSeatsBetweenAccounts(fromUsername, toUsername, { mode, batchSize, maxBatchRetries });
      res.json(result);
    } catch (err) {
      emitStatus('transfer-failed', `Transfer failed: ${err.message}`, { from: fromUsername, to: toUsername });
      res.status(500).json({ success: false, error: err.message });
    }
    return;
  }

  // New plan-based multi-transfer.
  if (Array.isArray(masterUsernames) && Array.isArray(destinations)) {
    try {
      const result = await transferSeatsMulti(masterUsernames, destinations.map(d => d.username), {
        masterUsernames,
        destinations,
        mode,
        batchSize,
        maxBatchRetries,
        url,
        targetSections,
        destinationAccounts,
        distribution,
        sniperMode,
      });
      res.json(result);
    } catch (err) {
      emitStatus('transfer-failed', `Plan transfer failed: ${err.message}`, { from: masterUsernames, to: destinations.map(d => d.username) });
      res.status(500).json({ success: false, error: err.message });
    }
    return;
  }

  // Legacy multi-source / multi-destination transfer.
  if (Array.isArray(fromUsernames) && Array.isArray(toUsernames)) {
    try {
      const result = await transferSeatsMulti(fromUsernames, toUsernames, { mode, batchSize, maxBatchRetries, url, targetSections, destinationAccounts });
      res.json(result);
    } catch (err) {
      emitStatus('transfer-failed', `Multi-transfer failed: ${err.message}`, { from: fromUsernames, to: toUsernames });
      res.status(500).json({ success: false, error: err.message });
    }
    return;
  }

  res.status(400).json({ success: false, error: 'fromUsername/toUsername, fromUsernames/toUsernames, or masterUsernames/destinations required' });
});

// ═══════════════════════════════════════════════════════════════════
// Session harvesting & Transfer Engine v3 endpoints
// ═══════════════════════════════════════════════════════════════════

app.post('/api/harvest-session', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ success: false, error: 'username required' });
  const session = activeSessions.get(username);
  if (!session || !session.page || !session.context) {
    return res.status(404).json({ success: false, error: 'Account has no active session' });
  }
  try {
    const fullSession = await harvestFullSession(session.page, session.context, username);
    res.json({
      success: true,
      username,
      cookiesCount: fullSession.cookies.length,
      localStorageCount: Object.keys(fullSession.localStorage).length,
      sessionStorageCount: Object.keys(fullSession.sessionStorage).length,
      expiresAt: fullSession.expiresAt,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/list-sessions', async (req, res) => {
  try {
    const files = await fs.promises.readdir(SESSION_CACHE_DIR);
    const sessions = [];
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      try {
        const data = await fs.promises.readFile(path.join(SESSION_CACHE_DIR, file), 'utf8');
        const session = JSON.parse(data);
        sessions.push({
          username: session.username,
          timestamp: session.timestamp,
          expiresAt: session.expiresAt,
          cookiesCount: session.cookies?.length || 0,
          localStorageCount: Object.keys(session.localStorage || {}).length,
          sessionStorageCount: Object.keys(session.sessionStorage || {}).length,
        });
      } catch {}
    }
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/session/:username', async (req, res) => {
  const { username } = req.params;
  const filePath = sessionCacheFilePath(username);
  try {
    await fs.promises.unlink(filePath);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/transfer-seats-v3', async (req, res) => {
  const { masterUsernames, destinations, url, targetSections } = req.body;
  if (!Array.isArray(masterUsernames) || masterUsernames.length === 0) {
    return res.status(400).json({ success: false, error: 'masterUsernames required' });
  }
  if (!Array.isArray(destinations) || destinations.length === 0) {
    return res.status(400).json({ success: false, error: 'destinations required' });
  }

  const startTime = Date.now();
  const destinationAccounts = Array.isArray(req.body.destinationAccounts) ? req.body.destinationAccounts : [];
  const transferId = transferAuditor.record({
    stage: 'v3-start',
    sourceUser: masterUsernames.join(','),
    seats: [],
    metadata: {
      destinationCount: destinations.length,
      url,
      targetSections,
      destinationUsernames: destinations.map(d => d.username).join(','),
    },
  });

  // 1. Validate source sessions.
  const sourceSessions = [];
  for (const username of masterUsernames) {
    const session = activeSessions.get(username);
    if (!session || !session.page || await isPageClosed(session.page)) {
      const error = `Source ${username} has no active session`;
      transferAuditor.record({ transferId, stage: 'v3-error', sourceUser: username, error, metadata: { reason: 'no-source-session' } });
      return res.status(400).json({ success: false, error });
    }
    sourceSessions.push(session);
  }

  // 1b. Validate source hold tokens before attempting any transfer.
  for (const src of sourceSessions) {
    const tokenCheck = await validateHoldTokenViaSeatCloud(src.holdToken, src);
    if (!tokenCheck.valid) {
      const error = `Source ${src.username} hold token is not valid: ${tokenCheck.reason}`;
      transferAuditor.record({ transferId, stage: 'v3-error', sourceUser: src.username, error, metadata: { reason: 'hold-token-invalid' } });
      return res.status(400).json({ success: false, error });
    }
    fileLog('INFO', `[transfer-v3] ${src.username} hold token valid (ttl=${tokenCheck.ttl}, expiresAt=${tokenCheck.expiresAt})`);
  }

  // 2. Build initial transfer plan (verifies held seats and assigns to destinations).
  let plan;
  try {
    plan = await buildTransferPlan(sourceSessions, destinations, { mode: 'auto', batchSize: 5, maxBatchRetries: 2 });
  } catch (err) {
    const error = err?.message || String(err);
    transferAuditor.record({ transferId, stage: 'v3-error', error, metadata: { reason: 'plan-failed' } });
    emitStatus('transfer-failed', `Transfer v3 plan failed: ${error}`, { error });
    return res.status(500).json({ success: false, error });
  }

  // 2b. Pre-validate destination accounts before opening any browsers.
  emitStatus('transfer-validating-destinations', `Pre-validating ${destinationAccounts.length} destination account(s)`, { count: destinationAccounts.length });
  try {
    const validationResults = await validateTransferDestinations(destinationAccounts, url, targetSections);
    const invalidDestinations = validationResults.filter(r => !r.ready);
    if (invalidDestinations.length === destinationAccounts.length && destinationAccounts.length > 0) {
      const error = `All ${invalidDestinations.length} destination account(s) failed pre-validation`;
      transferAuditor.record({ transferId, stage: 'v3-error', error, metadata: { invalidDestinations: invalidDestinations.map(d => ({ username: d.username, error: d.error })) } });
      return res.status(400).json({ success: false, error, invalidDestinations });
    }
    if (invalidDestinations.length > 0) {
      fileLog('WARN', `[transfer-v3] ${invalidDestinations.length} destination(s) failed pre-validation, will be skipped: ${invalidDestinations.map(d => d.username).join(', ')}`);
    }
  } catch (err) {
    const error = `Destination pre-validation failed: ${err?.message || String(err)}`;
    transferAuditor.record({ transferId, stage: 'v3-error', error, metadata: { reason: 'validation-exception' } });
    fileLog('WARN', `[transfer-v3] ${error}`);
  }

  // 3. Prepare all destination sessions in parallel (bounded by maxConcurrency).
  const destAccountMap = new Map();
  for (const d of destinations) {
    const acc = destinationAccounts.find(a => a.username === d.username) || d;
    destAccountMap.set(d.username, acc);
  }

  const prepareResult = await prepareDestinationsInParallel(plan.destinations, destAccountMap, url, targetSections, {
    prepareTimeoutMs: 45_000,
    retryDelayMs: 2_000,
    maxConcurrency: maxConcurrency || 3,
  });

  // 4. Redistribute seats from failed destinations to ready ones.
  const readyDestinations = prepareResult.ready;
  const failedPreparations = prepareResult.failed.map(f => ({ username: f.username, error: f.error }));

  // Capture full-session snapshots for sources and ready destinations so recovery
  // paths have the cookies/storage they need.
  for (const src of sourceSessions) {
    await backfillFullSession(src);
  }
  for (const dest of readyDestinations) {
    await backfillFullSession(dest.session);
  }

  if (readyDestinations.length === 0) {
    return res.json({
      success: false,
      totalTransferred: 0,
      totalMissing: plan.destinations.reduce((s, d) => s + d.assignedSeats.length, 0),
      failedPreparations,
      details: [],
      elapsedMs: Date.now() - startTime,
    });
  }

  // Redistribute seats fairly among ready destinations.
  const allSeats = plan.destinations.flatMap(d => d.assignedSeats);
  const readyUsernames = readyDestinations.map(r => r.username);
  const fairAssignments = assignSeatsToDestinations(allSeats, readyUsernames.map(u => ({ username: u, ticketCount: 0 })));
  const seatAssignmentMap = new Map(fairAssignments.map(a => [a.username, a.assignedSeats]));

  // 5. Execute transfers per source-destination batch.
  const details = [];
  let totalTransferred = 0;
  let totalMissing = 0;

  // Build reverse mapping: seat -> source session.
  const sourceMap = new Map();
  for (const src of sourceSessions) {
    for (const seat of src.selectedSeats || []) sourceMap.set(seat, src);
  }

  for (const destPlan of readyDestinations) {
    const destSession = destPlan.session;
    const assignedSeats = seatAssignmentMap.get(destPlan.username) || [];
    if (assignedSeats.length === 0) continue;

    // Group seats by source so each source only releases its own seats.
    const seatsBySource = new Map();
    for (const seat of assignedSeats) {
      const src = sourceMap.get(seat);
      if (!src) continue;
      if (!seatsBySource.has(src.username)) seatsBySource.set(src.username, { session: src, seats: [] });
      seatsBySource.get(src.username).seats.push(seat);
    }

    emitStatus('destination-transferring', `Transferring ${assignedSeats.length} seat(s) to ${destPlan.username}`, { account: destPlan.username, seats: assignedSeats });
    let destTransferred = [];
    let destMissing = [];

    for (const { session: srcSession, seats: batchSeats } of seatsBySource.values()) {
      // Primary: live-stream atomic release/hold. The destination spams hold
      // attempts while the source releases, shrinking the public-pool window.
      let result = await liveStreamAtomicReleaseAndHold(srcSession, destSession, batchSeats);
      let usedMode = 'livestream';

      // Fallback 1: standard atomic release/hold for any missing seats.
      if (result.missing.length > 0) {
        const recovered = await holdSpecificSeatsViaWebSocket(srcSession.page, result.missing, srcSession.username, srcSession);
        for (const s of recovered) {
          if (!srcSession.selectedSeats.includes(s)) srcSession.selectedSeats.push(s);
        }
        result = await atomicReleaseAndHold(srcSession, destSession, result.missing);
        usedMode = 'atomic-fallback';
      }

      // Fallback 2: legacy release/hold if atomic still left missing seats.
      if (result.missing.length > 0) {
        const recovered = await holdSpecificSeatsViaWebSocket(srcSession.page, result.missing, srcSession.username, srcSession);
        for (const s of recovered) {
          if (!srcSession.selectedSeats.includes(s)) srcSession.selectedSeats.push(s);
        }
        result = await legacyReleaseAndHold(srcSession, destSession, result.missing);
        usedMode = 'legacy';
      }

      // Fallback 3: the full v2 transfer routine as a last resort.
      if (result.missing.length > 0) {
        const recovered = await holdSpecificSeatsViaWebSocket(srcSession.page, result.missing, srcSession.username, srcSession);
        for (const s of recovered) {
          if (!srcSession.selectedSeats.includes(s)) srcSession.selectedSeats.push(s);
        }
        const v2Result = await transferSeatsToDestination(srcSession, destSession, {
          fixedSeats: result.missing,
          mode: 'auto',
          batchSize: 5,
          maxBatchRetries: 2,
        });
        result = {
          held: v2Result.transferredSeats || [],
          missing: v2Result.missingSeats || [],
        };
        usedMode = 'v2-fallback';
      }

      // Make sure the source no longer tracks seats that were successfully moved.
      for (const s of result.held) {
        const key = String(s).trim().toUpperCase();
        if (!srcSession.selectedSeats.includes(s)) srcSession.selectedSeats.push(s);
        srcSession.selectedSeats = srcSession.selectedSeats.filter(x => String(x).trim().toUpperCase() !== key);
        srcSession.releasedSeats.add(key);
        releaseSeatFromPool(s);
      }

      destTransferred.push(...result.held);
      destMissing.push(...result.missing);
      emitStatus('transfer-batch-complete', `Batch to ${destPlan.username}: ${result.held.length}/${batchSeats.length} via ${usedMode}`, { account: destPlan.username, held: result.held, missing: result.missing, mode: usedMode });
    }

    totalTransferred += destTransferred.length;
    totalMissing += destMissing.length;
    details.push({
      destination: destPlan.username,
      transferred: destTransferred.length,
      failed: destMissing.length,
      seats: destTransferred,
      missing: destMissing,
    });
    emitStatus('destination-complete', `Destination ${destPlan.username}: ${destTransferred.length} transferred, ${destMissing.length} missing`, { account: destPlan.username, transferred: destTransferred, missing: destMissing });

    // Track the transferred seats on the destination session so the UI/keepalive
    // treats them as held.
    if (destSession) {
      destSession.selectedSeats = destTransferred.slice();
      reserveSeats(destPlan.username, destTransferred);
    }
  }

  const elapsed = Date.now() - startTime;
  const success = totalMissing === 0 && failedPreparations.length === 0;
  emitStatus('transfer-done', `Transfer v3 complete: ${totalTransferred} transferred, ${totalMissing} missing`, { totalTransferred, totalMissing, elapsedMs: elapsed });

  transferAuditor.record({
    transferId,
    stage: success ? 'v3-done' : 'v3-partial',
    sourceUser: masterUsernames.join(','),
    seats: details.flatMap(d => d.seats || []),
    held: totalTransferred,
    missing: totalMissing,
    durationMs: elapsed,
    metadata: { failedPreparations: failedPreparations.length, details },
  });

  res.json({
    success,
    totalTransferred,
    totalMissing,
    failedPreparations,
    details,
    elapsedMs: elapsed,
  });
});

// ------------------------------------------------------------------
// Headless WebSocket Transfer Engine endpoint
// Body: {
//   sourceUsername,
//   destUsernames: [string],
//   seats?: [string],
//   url,                       // event URL or slug
//   workspaceKey?, eventKey?,  // optional; resolved from url if missing
//   channel?: 'NO_CHANNEL',
// }
// ------------------------------------------------------------------
app.post('/api/transfer-seats-headless', async (req, res) => {
  const { sourceUsername, destUsernames, seats, url, workspaceKey, eventKey, channel = 'NO_CHANNEL', accounts = [] } = req.body;
  if (!sourceUsername || !Array.isArray(destUsernames) || destUsernames.length === 0) {
    return res.status(400).json({ success: false, error: 'sourceUsername and destUsernames required' });
  }
  if (!url) return res.status(400).json({ success: false, error: 'url required' });

  const slug = url.split('/').pop()?.split('?')[0] || url;

  // ------------------------------------------------------------------
  // Auto-prepare: ensure every account has an active browser session.
  // If a session is missing, launch a browser, login, navigate to the event
  // and harvest cookies/storage automatically.
  // ------------------------------------------------------------------
  async function autoPrepareAccount(username) {
    let session = activeSessions.get(username);
    if (session && session.page && !(await isPageClosed(session.page))) {
      emitStatus('headless-prepared', `Using existing active session for ${username}`, { account: username });
      return session;
    }

    const account = accounts.find(a => a.username === username);
    if (!account) {
      throw new Error(`No account data provided for ${username}`);
    }

    emitStatus('headless-preparing', `Auto-preparing ${username}: launching browser and logging in`, { account: username });

    // Helper that builds the launch payload for a given proxy preference.
    const buildLaunchAccount = (useProxy) => ({
      ...account,
      url,
      targetSections: [],
      ticketCount: 30,
      useProxy,
      assignedProxy: useProxy ? (account.assignedProxy || null) : null,
    });

    // First attempt: respect the account's proxy preference.
    let lastError = null;
    try {
      session = await ensureSessionForTransfer(buildLaunchAccount(account.useProxy === true), { url, targetSections: [] });
    } catch (firstErr) {
      lastError = firstErr;
      const errMsg = String(firstErr?.message || firstErr || 'unknown');
      const isProxyFailure = /proxy|timeout|ip_collision|ip collision|PROXY_CONTEXT_FAILED|proxy-unhealthy/i.test(errMsg);
      if (account.useProxy && isProxyFailure) {
        emitStatus('headless-proxy-fallback', `Proxy failed for ${username}; retrying direct connection`, { account: username, error: errMsg });
        fileLog('WARN', `[headless-prep] ${username} proxy attempt failed (${errMsg}); falling back to direct connection`);
        try {
          session = await ensureSessionForTransfer(buildLaunchAccount(false), { url, targetSections: [] });
          lastError = null;
        } catch (directErr) {
          lastError = directErr;
          fileLog('WARN', `[headless-prep] ${username} direct fallback also failed: ${directErr.message}`);
        }
      }
    }

    if (lastError) {
      throw new Error(`Could not prepare session for ${username}: ${lastError.message}`);
    }
    if (!session || !session.page) {
      throw new Error(`Could not prepare session for ${username}: no page returned`);
    }

    // Navigate to the event booking page and wait for the chart so cookies
    // are fully scoped and a fresh hold token is available.
    try {
      await navigateToBookingPage(session.page, url, username);
      await waitForChartAndStartImmediate(session.page, session, { timeoutMs: 25000 });
    } catch (navErr) {
      fileLog('WARN', `[headless-prep] ${username} chart wait warning: ${navErr.message}`);
      // Defensive second navigation: if the page is still blank or not on /book, force a goto.
      try {
        const currentUrl = await session.page.url().catch(() => '');
        if (!currentUrl.includes('/book')) {
          const bookUrl = url.includes('/book') ? url : `${url.replace(/\/$/, '')}/book`;
          emitStatus('headless-retry-navigate', `Retrying navigation to booking page for ${username}`, { account: username });
          await session.page.goto(bookUrl, { waitUntil: 'domcontentloaded', timeout: 45000 });
        }
      } catch (retryErr) {
        fileLog('WARN', `[headless-prep] ${username} retry navigation failed: ${retryErr.message}`);
      }
    }

    // Harvest the full session and cache it.
    try {
      session.fullSession = await harvestFullSession(session.page, session.context, username);
      emitStatus('headless-session-harvested', `Session harvested for ${username}`, { account: username });
    } catch (harvestErr) {
      fileLog('WARN', `[headless-prep] Could not harvest session for ${username}: ${harvestErr.message}`);
    }

    return session;
  }

  try {
    await autoPrepareAccount(sourceUsername);
    await Promise.all(destUsernames.map(u => autoPrepareAccount(u)));
  } catch (prepErr) {
    return res.status(500).json({ success: false, error: `Auto-preparation failed: ${prepErr.message}` });
  }

  const sourceSession = activeSessions.get(sourceUsername);
  if (!sourceSession) {
    return res.status(400).json({ success: false, error: `Source ${sourceUsername} has no active session after auto-prepare` });
  }

  // Resolve workspace/event keys from the active source session first.
  let wsKey = workspaceKey || sourceSession.workspaceKey || null;
  let evKey = eventKey || sourceSession.eventKey || null;

  try {
    if (!wsKey || !evKey) {
      const keys = await fetchSeatcloudKeys(slug, null, null);
      wsKey = wsKey || keys.workspaceKey;
      evKey = evKey || keys.eventKey;
    }
    if (!wsKey || !evKey) {
      return res.status(400).json({ success: false, error: 'Could not resolve workspaceKey/eventKey' });
    }
  } catch (err) {
    return res.status(500).json({ success: false, error: `Key resolution failed: ${err.message}` });
  }

  // Determine seats to transfer.
  let seatsToTransfer = Array.isArray(seats) && seats.length > 0
    ? seats
    : (sourceSession.selectedSeats || []).slice(0, 30);
  if (!seatsToTransfer.length) {
    return res.status(400).json({ success: false, error: 'No seats available for transfer' });
  }

  // Distribute seats per destination according to the account's transferTicketCount
  // (default 5, max 30). Remainder stays on source.
  const transfers = [];
  let offset = 0;
  for (const destUsername of destUsernames) {
    const acc = accounts.find(a => a.username === destUsername);
    const perDest = Math.max(1, Math.min(30, parseInt(acc?.transferTicketCount, 10) || 5));
    const chunk = seatsToTransfer.slice(offset, offset + perDest);
    if (!chunk.length) break;
    transfers.push({ destUsername, seats: chunk });
    offset += perDest;
  }

  // Build account payloads from active sessions or cached sessions.
  async function buildAccount(username) {
    const session = activeSessions.get(username);
    const cached = await loadSessionFromCache(username);
    const cookieMap = new Map();
    if (session?.fullSession?.cookies) {
      for (const c of session.fullSession.cookies) if (c?.name) cookieMap.set(c.name, c.value);
    }
    if (cached?.cookies) {
      for (const c of cached.cookies) if (c?.name) cookieMap.set(c.name, c.value);
    }
    const rawCookies = cookieMap.size > 0 ? buildCookieHeaderFromMap(cookieMap) : '';
    return {
      username,
      rawCookies,
      structuredCookies: cookieMap.size > 0 ? [...cookieMap.entries()].map(([name, value]) => ({ name, value })) : null,
      holdToken: session?.holdToken || getHoldTokenFromCookies(cookieMap) || null,
      workspaceKey: wsKey,
      eventKey: evKey,
      channel,
      proxyConfig: session?.proxy || null,
    };
  }

  const sourceAccount = await buildAccount(sourceUsername);
  const destAccounts = await Promise.all(transfers.map(t => buildAccount(t.destUsername)));

  const startTime = Date.now();
  const details = [];
  let totalTransferred = 0;

  for (let i = 0; i < transfers.length; i++) {
    const { destUsername, seats } = transfers[i];
    const destAccount = destAccounts[i];
    emitStatus('headless-transfer-start', `Headless transfer of ${seats.length} seat(s) to ${destUsername}`, { destination: destUsername, seats });
    try {
      const result = await headlessTransferV3(sourceAccount, destAccount, seats, {
        slug,
        workspaceKey: wsKey,
        eventKey: evKey,
        channel,
        onStatus: (stage, message) => emitStatus(`headless-${stage}`, message, { destination: destUsername }),
      });
      details.push({ destination: destUsername, ...result });
      totalTransferred += result.held.length;
      emitStatus('headless-transfer-result', `${destUsername}: ${result.held.length}/${seats.length} held`, { destination: destUsername, ...result });
    } catch (err) {
      details.push({ destination: destUsername, held: [], missing: seats, error: err.message });
      emitStatus('headless-transfer-error', `Headless transfer to ${destUsername} failed: ${err.message}`, { destination: destUsername });
    }
  }

  res.json({
    success: details.every(d => (d.missing || []).length === 0),
    totalTransferred,
    totalMissing: details.reduce((s, d) => s + (d.missing || []).length, 0),
    details,
    elapsedMs: Date.now() - startTime,
  });
});

function buildCookieHeaderFromMap(cookieMap) {
  const parts = [];
  for (const [name, value] of cookieMap) parts.push(`${name}=${value}`);
  return parts.join('; ');
}

// Distribute held seats from a master account to multiple target accounts.
// Body: { masterUsername, targets: [{ username, count }], mode, batchSize, maxBatchRetries }
app.post('/api/distribute-seats', async (req, res) => {
  const { masterUsername, targets, mode, batchSize, maxBatchRetries } = req.body;
  if (!masterUsername || !Array.isArray(targets) || targets.length === 0) {
    return res.status(400).json({ success: false, error: 'masterUsername and targets array required' });
  }
  const master = activeSessions.get(masterUsername);
  if (!master) return res.status(400).json({ success: false, error: 'Master account has no active session' });

  try {
    const snapshot = await verifyHeldSeatsViaApi(master.page, master.holdToken, master.selectedSeats, { session: master });
    if (!snapshot.length) throw new Error('Master account has no verified seats');

    const totalRequested = targets.reduce((sum, t) => sum + (parseInt(t.count, 10) || 0), 0);
    if (totalRequested > snapshot.length) {
      throw new Error(`Requested ${totalRequested} seats but master only holds ${snapshot.length}`);
    }

    const results = [];
    let offset = 0;
    for (const target of targets) {
      const count = parseInt(target.count, 10) || 0;
      if (count <= 0) {
        results.push({ username: target.username, count: 0, seats: [], missing: [] });
        continue;
      }
      const subset = snapshot.slice(offset, offset + count);
      offset += count;

      const dest = activeSessions.get(target.username);
      if (!dest) {
        results.push({ username: target.username, count, seats: [], missing: subset, error: 'No active session' });
        continue;
      }

      const transferResult = await transferSeatsBetweenAccounts(masterUsername, target.username, {
        mode,
        batchSize,
        maxBatchRetries,
        fixedSeats: subset,
      });
      results.push({
        username: target.username,
        count,
        seats: transferResult.transferredSeats || [],
        missing: transferResult.missingSeats || [],
      });
    }

    res.json({ success: true, master: masterUsername, totalHeld: snapshot.length, distributed: results });
  } catch (err) {
    emitStatus('distribute-failed', `Distribution failed: ${err.message}`, { master: masterUsername });
    res.status(500).json({ success: false, error: err.message });
  }
});

function countActiveRunningSessions() {
  let count = 0;
  for (const session of activeSessions.values()) {
    if (['paused', 'payment-ready', 'done', 'error'].includes(session.state)) continue;
    count++;
  }
  return count;
}

async function processQueue() {
  // Update queue positions for pending accounts
  pendingQueue.forEach((account, index) => {
    emitAccountUpdate(account.username, 'queued', { position: index + 1 });
  });

  while (pendingQueue.length > 0 && countActiveRunningSessions() < maxConcurrency) {
    const account = pendingQueue.shift();
    if (activeSessions.has(account.username)) continue;
    runSession(account);
    // Launch accounts rapidly; proxy isolation + per-account offsets reduce collisions.
    // Keep a tiny stagger so browser contexts do not all spawn in the exact same tick.
    const staggerMs = Math.max(80, maxConcurrency * 40);
    await waitFor(staggerMs);
  }
  emitQueueStats();
}

// ------------------------------------------------------------------
// Robust login / session validation
// ------------------------------------------------------------------
async function validateSessionViaAPI(page, username, session = null) {
  // Use Playwright's request context so stored cookies are sent automatically.
  try {
    const traceId = makeTraceId();
    const authToken = await getAuthTokenFromContext(page.context(), username);
    const headers = {
      Accept: 'application/json',
      Origin: WB_ORIGIN,
      Referer: `${WB_ORIGIN}/`,
    };
    // Mimic the frontend api-Dkm25JAv.js Authorization header when a token cookie exists.
    if (authToken) headers.Authorization = `Bearer ${authToken}`;

    const effectiveSession = session && session.context ? session : { context: page.context() };
    const r = await sessionFetch(`https://api.webook.com/api/v2/user/profile?lang=ar&trace_id=${traceId}`, {
      method: 'GET',
      headers,
      timeout: 4000,
    }, effectiveSession);
    const status = r.status;
    const text = await r.text();
    fileLog('INFO', `[${username}] Session API check: status=${status}`);

    if (status === 200) {
      let data = null;
      try {
        data = JSON.parse(text);
      } catch {}
      const user = data && (data.data || data);
      if (user && (user._id || user.id || user.email)) {
        return {
          valid: true,
          source: 'api-user-profile',
          user: {
            user_id: user._id || user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
          },
        };
      }
    }

    return { valid: false, source: 'api-user-profile', status, error: text.slice(0, 500) };
  } catch (e) {
    return { valid: false, source: 'api-user-profile', error: e.message };
  }
}

async function checkLoggedInAdvanced(page, username = '') {
  // 3-tier login verification:
  // Tier 1 — API profile endpoint (strongest signal, uses actual cookies).
  // Tier 2 — Advanced UI detection (avatars, dropdowns, logout menu, user name).
  // Tier 3 — Detect login form/button so callers know a manual login is needed.
  // Returns { loggedIn, source, user, hasLoginForm, hasLoginButton, reasons }.

  // Tier 1
  const api = await validateSessionViaAPI(page, username);
  if (api.valid && api.user) {
    return {
      loggedIn: true,
      source: 'api',
      user: api.user,
      hasLoginForm: false,
      hasLoginButton: false,
      reasons: ['api-user-profile'],
    };
  }

  // Tier 2
  const ui = await page.evaluate(() => {
    const text = (document.body ? (document.body.innerText || '') : '').toLowerCase();
    const reasons = [];

    const logoutTexts = ['تسجيل الخروج', 'logout', 'sign out', 'log out'];
    const profileTexts = ['الملف الشخصي', 'profile', 'حسابي', 'my account', 'حجوزاتي', 'my bookings', 'orders'];
    const hasLogoutText = logoutTexts.some(t => text.includes(t.toLowerCase()));
    const hasProfileText = profileTexts.some(t => text.includes(t.toLowerCase()));
    if (hasLogoutText) reasons.push('ui-logout-text');
    if (hasProfileText) reasons.push('ui-profile-text');

    // Explicit data attributes / test ids.
    const authSelectors = [
      '[data-menuitem="logout"]',
      '[data-testid*="logout" i]',
      '[data-testid*="user-menu" i]',
      '[data-testid*="account-menu" i]',
      '[data-testid*="profile-menu" i]',
      '[data-testid*="user-dropdown" i]',
      '[data-testid*="avatar" i]',
      'button[aria-label*="logout" i]',
      'a[href*="/logout" i]',
    ];
    const hasAuthElement = authSelectors.some(sel => !!document.querySelector(sel));
    if (hasAuthElement) reasons.push('ui-auth-element');

    // Avatar images are a strong auth signal.
    const avatarSelectors = [
      'img[src*="avatar" i]',
      'img[alt*="profile" i]',
      'img[alt*="المستخدم" i]',
      '[style*="avatar" i]',
      'div[class*="avatar" i]',
    ];
    const hasAvatar = avatarSelectors.some(sel => !!document.querySelector(sel));
    if (hasAvatar) reasons.push('ui-avatar');

    // User name / greeting patterns (e.g. "Amr Sameh", "Welcome back").
    const greetingPattern = /(welcome back|مرحبا بك|أهلا|good (morning|afternoon|evening))/i;
    if (greetingPattern.test(document.body ? (document.body.innerText || '') : '')) reasons.push('ui-greeting');

    return { loggedIn: reasons.length > 0, reasons };
  }).catch(() => ({ loggedIn: false, reasons: [] }));

  if (ui.loggedIn) {
    return {
      loggedIn: true,
      source: 'ui',
      user: null,
      hasLoginForm: false,
      hasLoginButton: false,
      reasons: ui.reasons,
    };
  }

  // Tier 3 — detect login form/button so ensureLoggedIn can decide whether to
  // perform manual login or fail fast because the page is neither logged-in nor
  // a login page.
  const loginForm = await page.evaluate(() => {
    const hasEmail = !!document.querySelector('input[type="email"], input[name="email"], input[id*="email" i], input[autocomplete="username"]');
    const hasPassword = !!document.querySelector('input[type="password"], input[name="password"], input[autocomplete="current-password"]');
    const hasLoginBtn = !!document.querySelector('button[type="submit"], button[data-testid*="login" i], button[data-testid*="auth" i], a[href*="/login" i]');
    return { hasLoginForm: hasEmail || hasPassword, hasLoginButton: hasLoginBtn };
  }).catch(() => ({ hasLoginForm: false, hasLoginButton: false }));

  return {
    loggedIn: false,
    source: 'none',
    user: null,
    hasLoginForm: loginForm.hasLoginForm,
    hasLoginButton: loginForm.hasLoginButton,
    reasons: [],
  };
}

async function tryRefreshToken(page, username, session = null) {
  // Best-effort token refresh using the stored refresh_token cookie.
  // If refresh fails, fall back to a full credential re-login when the password is known.
  try {
    const cookies = await page.context().cookies(['https://api.webook.com/', 'https://webook.com/']);
    const refreshCookie = cookies.find(c => c.name === 'refresh_token' && c.value);

    if (!refreshCookie) {
      fileLog('INFO', `[${username}] No refresh_token cookie found; skipping refresh.`);
      return { refreshed: false, reason: 'no-refresh-cookie' };
    }

    emitStatus('login-refresh', 'Access token expired, attempting refresh...', { account: username });

    const traceId = makeTraceId();
    const effectiveSession = session && session.context ? session : { context: page.context() };
    const r = await sessionFetch(`https://api.webook.com/api/v2/auth/refresh?lang=ar&trace_id=${traceId}`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        Origin: WB_ORIGIN,
        Referer: `${WB_ORIGIN}/`,
      },
      body: JSON.stringify({ refresh_token: refreshCookie.value, lang: 'ar' }),
    }, effectiveSession);
    const status = r.status;
    const text = await r.text();
    fileLog('INFO', `[${username}] Token refresh attempt: status=${status}`);

    if (status >= 200 && status < 300) {
      return { refreshed: true, source: 'auth-refresh' };
    }

    // Refresh failed: try a full re-login if credentials are available.
    if (session && session.password && !session.__skipLogin) {
      try {
        emitStatus('login-refresh', 'Refresh failed; attempting full re-login...', { account: username });
        await ensureLoggedIn(page, username, session.password, session);
        return { refreshed: true, source: 'relogin' };
      } catch (loginErr) {
        fileLog('WARN', `[${username}] Re-login after refresh failure also failed: ${loginErr.message}`);
        return { refreshed: false, source: 'auth-refresh', status, error: `refresh failed; re-login failed: ${loginErr.message}` };
      }
    }

    return { refreshed: false, source: 'auth-refresh', status, error: text.slice(0, 500) };
  } catch (e) {
    // On a network/timeout error, also attempt re-login if credentials are known.
    if (session && session.password && !session.__skipLogin) {
      try {
        emitStatus('login-refresh', 'Refresh network error; attempting full re-login...', { account: username });
        await ensureLoggedIn(page, username, session.password, session);
        return { refreshed: true, source: 'relogin' };
      } catch (loginErr) {
        fileLog('WARN', `[${username}] Re-login after refresh network error also failed: ${loginErr.message}`);
      }
    }
    return { refreshed: false, source: 'auth-refresh', error: e.message };
  }
}

async function waitForLoginFormOrLoggedIn(page, timeoutMs = 1500) {
  const emailSelectors = [
    'input[data-testid="auth_email_input"]',
    'input[data-testid="auth_login_email_input"]',
    'input[type="email"]',
    'input[name="email"]',
    'input[placeholder*="البريد"]',
    'input[placeholder*="email"]',
    'input[inputmode="email"]',
    'input[id*="email" i]',
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
  ];
  const passSelectors = [
    'input[data-testid="auth_login_password_input"]',
    'input[type="password"]',
    'input[name="password"]',
    'input[placeholder*="كلمة"]',
    'input[placeholder*="password"]',
    'input[id*="password" i]',
    'input[autocomplete="current-password"]',
    'input[autocomplete="password"]',
  ];
  const continueBtnSelectors = [
    'button:has-text("تابع باستخدام البريد الإلكتروني")',
    'button:has-text("Continue with email")',
    'button:has-text("Continue")',
    'button:has-text("تابع")',
    'button[type="submit"]',
    'button:has(> span:has-text("تابع"))',
  ];
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ui = await checkLoggedInAdvanced(page).catch(() => ({ loggedIn: false }));
    if (ui.loggedIn) return { loggedIn: true, source: ui.source, reasons: ui.reasons };
    const emailIn = await waitForAnySelector(page, emailSelectors, 120, true);
    if (emailIn) {
      const passIn = await waitForAnySelector(page, passSelectors, 120, true);
      if (passIn) return { emailIn, passIn, twoStep: false };
      // Two-step form: email visible but password not yet. Confirm a continue button exists.
      const continueBtn = await waitForAnySelector(page, continueBtnSelectors, 120, true);
      if (continueBtn) return { emailIn, twoStep: true, continueBtn };
    }
    await waitFor(10);
  }
  return {};
}

async function performManualLogin(page, username, password, session) {
  const maxAttempts = 3;
  const emailSelectors = [
    'input[data-testid="auth_email_input"]',
    'input[data-testid="auth_login_email_input"]',
    'input[type="email"]',
    'input[name="email"]',
    'input[placeholder*="البريد"]',
    'input[placeholder*="email"]',
    'input[inputmode="email"]',
    'input[id*="email" i]',
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
  ];
  const passSelectors = [
    'input[data-testid="auth_login_password_input"]',
    'input[type="password"]',
    'input[name="password"]',
    'input[placeholder*="كلمة"]',
    'input[placeholder*="password"]',
    'input[id*="password" i]',
    'input[autocomplete="current-password"]',
    'input[autocomplete="password"]',
  ];
  const submitSelectors = [
    'button[data-testid="auth_login_submit_button"]',
    'button[type="submit"]',
    'button:has-text("تسجيل الدخول")',
    'button:has-text("Login")',
    'button:has-text("Sign in")',
    'button:has-text("Log in")',
    'button:has-text("Submit")',
  ];
  const continueBtnSelectors = [
    'button:has-text("تابع باستخدام البريد الإلكتروني")',
    'button:has-text("Continue with email")',
    'button:has-text("Continue")',
    'button:has-text("تابع")',
    'button[type="submit"]',
    'button:has(> span:has-text("تابع"))',
  ];
  const loginBtnSelectors = [
    'button:has-text("تسجيل الدخول")',
    'button:has-text("Login")',
    'button:has-text("Sign in")',
    'button:has-text("Log in")',
    'a:has-text("تسجيل الدخول")',
    '[data-testid*="login" i]',
    '[data-testid*="signin" i]',
    '[data-testid*="auth" i]',
    'button[aria-label*="login" i]',
    'button[aria-label*="signin" i]',
  ];

  for (let loginAttempt = 1; loginAttempt <= maxAttempts; loginAttempt++) {
    if (session && (session.stopRequested || session.bookingPaused)) {
      throw new Error('Login aborted by stop/pause request');
    }
    emitStatus('login', `Manual login attempt ${loginAttempt}/${maxAttempts}`, { account: username });

    // 3-tier pre-check: accept API or strong UI auth signals before touching the DOM.
    // This prevents "Login button not found" failures when the account is already
    // authenticated (e.g. persistent session showing avatar / logout dropdown).
    const preCheck = await checkLoggedInAdvanced(page, username);
    if (preCheck.loggedIn) {
      const id = preCheck.user ? (preCheck.user.email || preCheck.user.user_id) : preCheck.reasons.join(', ');
      emitStatus('login', `Already authenticated (${preCheck.source}: ${id}); skipping physical login`, { account: username, source: preCheck.source, reasons: preCheck.reasons });
      return { success: true, source: `pre-login-${preCheck.source}` };
    }

    // Race: inline login form vs already logged-in UI.
    const formOrLogged = await waitForLoginFormOrLoggedIn(page, 700);
    if (formOrLogged.loggedIn) {
      return { success: true, source: 'manual-login-ui-race' };
    }

    let { emailIn, passIn, twoStep, continueBtn } = formOrLogged;
    let emailFilled = false;

    if (twoStep && emailIn && continueBtn) {
      // Two-step login: email first, then password after continue.
      await emailIn.fill(username, { timeout: 2500 });
      emailFilled = true;
      try { await continueBtn.click({ force: true }); } catch { try { await continueBtn.evaluate(b => b.click()); } catch {} }
      // Wait for the password step with retries; some builds animate the transition.
      // Keep polling tight so the next step starts as soon as the DOM updates.
      await waitFor(50);
      for (let passAttempt = 0; passAttempt < 15; passAttempt++) {
        passIn = await waitForAnySelector(page, passSelectors, 300, true);
        if (passIn) break;
        // If no password field, maybe the continue did not register; try pressing Enter.
        if (passAttempt === 2) {
          try { await emailIn.press('Enter'); } catch {}
        }
        await waitFor(20);
      }
      if (!passIn) {
        if (loginAttempt < maxAttempts) {
          emitStatus('login-retry', `Password step not loaded, retry ${loginAttempt}/${maxAttempts}`, { account: username });
          await waitFor(30);
          continue;
        }
        throw new Error('Password step not found in two-step login');
      }
    } else if (!emailIn || !passIn) {
      // Try opening the login modal.
      const loginBtn = await waitForAnySelector(page, loginBtnSelectors, 600, true);
      if (!loginBtn) {
        const ui = await checkLoggedInAdvanced(page, username);
        if (ui.loggedIn) return { success: true, source: `ui-post-attempt-${ui.source}`, reasons: ui.reasons };
        if (loginAttempt < maxAttempts) {
          emitStatus('login-retry', `Login button not visible, retry ${loginAttempt}/${maxAttempts}`, { account: username });
          // Force navigation to the dedicated login page so the DOM selectors
          // always have a consistent target (fixes 401/timeout stalls).
          try {
            await page.goto('https://webook.com/ar/login', { waitUntil: 'domcontentloaded', timeout: 20000 });
            await waitFor(100);
          } catch (navErr) {
            fileLog('WARN', `[${username}] Forced login navigation error: ${navErr.message}`);
          }
          continue;
        }
        throw new Error('Login button not found');
      }

      try { await loginBtn.click({ force: true }); } catch { try { await loginBtn.evaluate(b => b.click()); } catch {} }
      await waitFor(50);
      const stepCheck = await waitForLoginFormOrLoggedIn(page, 1200);
      if (stepCheck.loggedIn) return { success: true, source: 'manual-login-modal-ui' };
      ({ emailIn, passIn, twoStep, continueBtn } = stepCheck);

      if (twoStep && emailIn && continueBtn) {
        await emailIn.fill(username, { timeout: 2500 });
        emailFilled = true;
        try { await continueBtn.click({ force: true }); } catch { try { await continueBtn.evaluate(b => b.click()); } catch {} }
        await waitFor(50);
        for (let passAttempt = 0; passAttempt < 15; passAttempt++) {
          passIn = await waitForAnySelector(page, passSelectors, 300, true);
          if (passIn) break;
          if (passAttempt === 2) {
            try { await emailIn.press('Enter'); } catch {}
          }
          await waitFor(20);
        }
      }
    }

    if (!emailIn || !passIn) {
      if (loginAttempt < maxAttempts) {
        emitStatus('login-retry', `Login form not visible, retry ${loginAttempt}/${maxAttempts}`, { account: username });
        // Force navigation to the dedicated login page on missing form too.
        try {
          await page.goto('https://webook.com/ar/login', { waitUntil: 'domcontentloaded', timeout: 20000 });
          await waitFor(100);
        } catch (navErr) {
          fileLog('WARN', `[${username}] Forced login navigation error: ${navErr.message}`);
        }
        continue;
      }
      throw new Error('Login form not found');
    }

    if (!emailFilled) await emailIn.fill(username, { timeout: 2500 });
    await passIn.fill(password, { timeout: 2500 });

    const sub = await waitForAnySelector(page, submitSelectors, 800, true);
    const preSubmitUrl = page.url();
    if (sub) {
      try { await sub.click({ force: true }); } catch { try { await sub.evaluate(b => b.click()); } catch {} }
    }
    // Always also press Enter on the password field as a fallback / dual trigger.
    try { await passIn.press('Enter'); } catch {}

    // Wait for the login to physically complete: navigation away from the login
    // page, the login modal/form disappearing, or a strong logged-in UI signal.
    const completion = await waitForLoginCompletion(page, username, preSubmitUrl, 6000, session);

    const loginError = await page.evaluate(() => {
      const text = document.body ? (document.body.innerText || '') : '';
      if (text.includes('تم حظر حسابك')) return 'ACCOUNT_BANNED';
      if (text.includes('بيانات اعتماد غير صحيحة')) return 'INVALID_CREDENTIALS';
      if (text.includes('كلمة المرور غير صحيحة')) return 'INVALID_PASSWORD';
      if (text.includes('البريد الإلكتروني غير صحيح')) return 'INVALID_EMAIL';
      if (text.includes('كلمة المرور التي أدخلتها غير صحيحة')) return 'INVALID_PASSWORD';
      if (text.includes('Email address is invalid')) return 'INVALID_EMAIL';
      if (text.includes('Invalid email')) return 'INVALID_EMAIL';
      if (text.includes('Incorrect password')) return 'INVALID_PASSWORD';
      if (text.includes('حدث خطأ')) return 'GENERIC_ERROR';
      if (text.includes('Something went wrong')) return 'GENERIC_ERROR';
      return null;
    });
    if (loginError) {
      throw new Error(`Login failed: ${loginError}`);
    }

    if (completion.loggedIn || completion.navigated || completion.apiValid) {
      emitStatus('login', `Login physically confirmed (${completion.reason})`, { account: username });
      return { success: true, source: `manual-login-${completion.reason}` };
    }

    if (loginAttempt < maxAttempts) {
      emitStatus('login-retry', `Login did not confirm, retry ${loginAttempt}/${maxAttempts}`, { account: username });
      // Before the next attempt, try 2captcha fallback if a captcha is present.
      await trySolveCaptchaWith2captcha(page, session, 'login');
      await waitFor(50);
    }
  }

  throw new Error('Login failed after retries');
}

/**
 * Wait for a strong, physical signal that the login completed:
 * 1. URL changed away from the login page.
 * 2. Login form/modal disappeared.
 * 3. Authenticated UI appeared (profile, logout, my account).
 * 4. API profile endpoint returns valid user data.
 */
async function waitForLoginCompletion(page, username, preSubmitUrl, timeoutMs = 6000, session = null) {
  const deadline = Date.now() + timeoutMs;
  let lastReason = 'timeout';
  while (Date.now() < deadline) {
    if (session && (session.stopRequested || session.bookingPaused)) {
      throw new Error('Login completion aborted by stop/pause request');
    }
    const currentUrl = page.url();
    if (currentUrl !== preSubmitUrl && !currentUrl.includes('/login') && !currentUrl.includes('/auth')) {
      return { loggedIn: true, reason: 'navigation', url: currentUrl };
    }

    const advanced = await checkLoggedInAdvanced(page, username);
    if (advanced.loggedIn) {
      return {
        loggedIn: true,
        reason: advanced.source === 'api' ? 'api-valid' : 'ui-signal',
        user: advanced.user,
        ui: advanced.reasons,
      };
    }
    if (advanced.source === 'none') {
      lastReason = 'not-logged-in';
    }

    await waitFor(80);
  }
  return { loggedIn: false, reason: lastReason };
}

async function waitForValidatedSession(page, username, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const api = await validateSessionViaAPI(page, username);
    if (api.valid) return api;
    await waitFor(60);
  }
  return { valid: false };
}

async function ensureLoggedIn(page, username, password, session) {
  emitStatus('login', 'Checking login state...', { account: username });
  session.state = 'login';
  emitAccountUpdate(username, 'login');

  // Cookies/holdToken workflow: login was already injected; never attempt credentials.
  if (session.__skipLogin) {
    emitStatus('login', 'Skipping manual login because cookies were injected', { account: username });
    return true;
  }

  // 3-tier verification:
  // Tier 1 — API profile endpoint.
  // Tier 2 — Advanced UI detection (dropdowns, avatars, logout menu).
  // Tier 3 — Manual credential fallback only when both tiers say logged out.
  const advanced = await checkLoggedInAdvanced(page, username);
  if (advanced.loggedIn) {
    const id = advanced.user ? (advanced.user.email || advanced.user.user_id) : (advanced.reasons.join(', ') || 'ui-signal');
    emitStatus('login', `Already logged in (source: ${advanced.source}, ${id})`, { account: username, source: advanced.source, reasons: advanced.reasons });
    await saveSessionState(username, session.context, { source: `ensureLoggedIn-${advanced.source}`, note: `reasons=${advanced.reasons.join('|')}` });
    autoHarvestSession(page, session.context, username).catch(() => {});
    return true;
  }

  // Stale or invalid session: wipe cookies so the next manual login starts clean.
  fileLog('WARN', `[${username}] Session checks indicate logged out (source=${advanced.source}, hasLoginForm=${advanced.hasLoginForm}, hasLoginButton=${advanced.hasLoginButton}); clearing cookies and forcing manual login`);
  try {
    await page.context().clearCookies();
  } catch (e) {
    fileLog('WARN', `[${username}] clearCookies failed: ${e.message}`);
  }

  // Full manual login.
  const result = await performManualLogin(page, username, password, session);
  if (!result.success) {
    throw new Error('Login could not be completed');
  }

  // Re-validate via the advanced check to confirm the manual login stuck.
  const postLogin = await checkLoggedInAdvanced(page, username);
  if (!postLogin.loggedIn) {
    fileLog('WARN', `[${username}] Manual login succeeded via UI/API but post-login verification still failing: ${JSON.stringify(postLogin)}`);
  }
  await saveSessionState(username, session.context, { source: 'ensureLoggedIn-manual', note: result.source });
  emitStatus('login', 'Logged in successfully', { account: username, source: result.source });
  autoHarvestSession(page, session.context, username).catch(() => {});
  return true;
}

async function runSession(account, options = {}) {
  const { username, password, url, targetSections, sectionQuota, ticketCount, accountIndex = 0, totalAccounts = 1, fixedSeats, type, holdToken: providedHoldToken, queueToken: providedQueueToken, cfClearance: providedCfClearance, recaptchaToken: providedRecaptchaToken, token: providedAuthToken, refreshToken: providedRefreshToken, rawCookies: providedRawCookies, structuredCookies: providedStructuredCookies, loginEmail, loginPassword, useProxy: accountUseProxy, workspaceKey: providedWorkspaceKey, eventKey: providedEventKey, selectedTeam } = account;
  const accountType = type === 'holdToken' ? 'holdToken' : 'credentials';
  const authUsername = accountType === 'holdToken' ? (loginEmail || username) : username;
  const authPassword = accountType === 'holdToken' ? (loginPassword || password) : password;
  const cycleMode = !!options.cycleMode;
  const dryRun = !!options.dryRun || !!account.dryRun;
  const targetSeatCount = dryRun ? 0 : Math.max(1, Math.min(parseInt(ticketCount, 10) || 30, MAX_HELD_SEATS));

  let attempt = 1;
  const maxAttempts = 5;

  while (attempt <= maxAttempts) {
    // Use pre-assigned unique proxy if available; otherwise resolve dynamically.
    // Cap proxy resolution so a bad proxy list cannot block the whole queue.
    let proxy = null;
    let tested = [];
    let proxyMode = currentProxyMode;
    const proxyStartMs = Date.now();
    fileLog('INFO', `[${username}] runSession proxy resolution start (attempt ${attempt}/${maxAttempts})`);

    async function resolveProxyForRun() {
      // Use pre-assigned proxy immediately; skip live testing so the browser opens fast.
      if (account.assignedProxy && account.assignedProxy.server) {
        proxy = account.assignedProxy;
        proxyMode = accountUseProxy === true ? 'forced' : (currentProxyMode === 'off' ? 'off' : currentProxyMode);
        logProxyStatus(username, 'PROXY ENABLED', proxy.server, 'pre-assigned');
        return;
      }
      if (!proxy) {
        const resolved = await resolveProxyForAccount(username, accountUseProxy, proxyManager.getAll());
        proxy = resolved.proxy;
        tested = resolved.tested;
        proxyMode = resolved.mode;
      }
    }

    try {
      await withTimeout(resolveProxyForRun(), 20_000, `proxy resolution for ${username}`);
    } catch (proxyTimeoutErr) {
      fileLog('WARN', `[${username}] runSession proxy resolution timed out; using direct: ${proxyTimeoutErr.message}`);
      emitStatus('proxy-fallback', `Proxy resolution timed out for ${username}; using direct connection`, { account: username });
      proxy = null;
      proxyMode = 'off';
    }
    fileLog('INFO', `[${username}] runSession proxy resolution completed in ${Date.now() - proxyStartMs}ms -> ${proxy ? proxy.server : 'direct'}`);

    sessionCounter++;
    const sessionStartMs = Date.now();
    const session = {
      id: sessionCounter,
      username,
      password,
      type: accountType,
      providedHoldToken: accountType === 'holdToken' ? providedHoldToken : null,
      providedQueueToken: accountType === 'holdToken' ? providedQueueToken : null,
      providedCfClearance: accountType === 'holdToken' ? providedCfClearance : null,
      providedRecaptchaToken: accountType === 'holdToken' ? providedRecaptchaToken : null,
      providedAuthToken: accountType === 'holdToken' ? providedAuthToken : null,
      providedRefreshToken: accountType === 'holdToken' ? providedRefreshToken : null,
      providedRawCookies: accountType === 'holdToken' ? providedRawCookies : null,
      providedStructuredCookies: accountType === 'holdToken' ? (Array.isArray(providedStructuredCookies) ? providedStructuredCookies : null) : null,
      loginEmail: accountType === 'holdToken' ? loginEmail : null,
      loginPassword: accountType === 'holdToken' ? loginPassword : null,
      url,
      targetSections,
      sectionQuota: sectionQuota || null,
      targetSeatCount,
      accountIndex,
      totalAccounts,
      isSelecting: false,
      context: null,
      page: null,
      state: 'launching',
      selectedSeats: [],
      releasedSeats: new Set(),
      holdToken: accountType === 'holdToken' ? providedHoldToken : null,
      holdTokenCreatedAt: accountType === 'holdToken' && providedHoldToken ? Date.now() : null,
      holdTokenExpiresAt: accountType === 'holdToken' && providedHoldToken ? Date.now() + 15 * 60 * 1000 : null,
      holdInterval: null,
      proceedResolve: null,
      stopRequested: false,
      bookingPaused: false,
      __skipLogin: accountType === 'holdToken',
      speedSettings: { ...currentSpeedSettings },
      proxy: proxy || null,
      proxyMode,
      proxyTested: tested,
      workspaceKey: providedWorkspaceKey || null,
      eventKey: providedEventKey || null,
      chartSections: null,
      selectedTeam: selectedTeam || null,
    };
    activeSessions.set(username, session);
    // Reserve the assigned proxy so no concurrently launching account steals it.
    if (proxy && proxy.server) {
      if (!reserveProxyForSession(username, proxy)) {
        const other = activeProxyReservations.get(getProxyCacheKey(proxy));
        throw new Error(`PROXY_ALREADY_RESERVED: ${proxy.server} is already reserved by ${other || 'unknown'}`);
      }
    }
    if (session.holdToken) registerHoldToken(username, session.holdToken);
    emitStatus('launching', `Launching mobile browser (attempt ${attempt}/${maxAttempts})...`, { account: username, attempt, maxAttempts });
    fileLog('INFO', `[${username}] Proxy assignment: ${proxy ? proxy.server : 'none'}, mode=${proxyMode}, tested=${JSON.stringify(tested.map(t => ({ server: t.server, ok: t.ok })))}`);
    if (proxy && proxy.server) {
      logProxyStatus(username, 'PROXY ENABLED', proxy.server, proxyMode);
    } else {
      logProxyStatus(username, 'DIRECT (No Proxy)', null, proxyMode);
    }
    session.state = 'launching';
    emitAccountUpdate(username, 'launching', { proxy: proxy ? proxy.server : null, proxyMode });

    try {
      session.context = await createMobileContext(username, 1, proxy);
    session.__loadedSessionMeta = session.context.__kimikoSessionMeta || null;
    session.page = await session.context.newPage();
    const page = session.page;

    // Verify egress IP and detect collisions with other active sessions.
    try {
      const publicIp = await getProxyIp(session);
      if (publicIp) {
        session.publicIp = publicIp;
        const collision = [...activeSessions.entries()].some(([u, s]) => u !== username && s.publicIp === publicIp);
        if (collision) {
          if (currentProxyMode === 'required' || proxyMode === 'forced') {
            throw new Error(`IP_COLLISION: ${username} shares IP ${publicIp} with another active session`);
          }
          fileLog('WARN', `[${username}] IP collision detected: ${publicIp}`);
        }
        fileLog('INFO', `[${username}] Context egress IP: ${publicIp}`);
      }
    } catch (ipErr) {
      fileLog('WARN', `[${username}] Could not verify context egress IP: ${ipErr.message}`);
    }

    // Credentials users: wipe any stale local storage, cookies, or session files
    // so the login sequence always starts from a clean slate. This prevents the
    // login-freeze bug caused by corrupted or partially-authenticated state.
    if (accountType === 'credentials') {
      await forceLogout(page, username);
    }

    // Compute exact event /book path for cookie scoping.
    let exactPath = '/';
    try {
      const bookingUrlForCookies = url.includes('/book') ? url : `${url.replace(/\/$/, '')}/book`;
      exactPath = new URL(bookingUrlForCookies).pathname;
    } catch {}

    // If the user pasted a full cookie string (Cookies Editor), inject it into the
    // browser context now. This lets us impersonate the logged-in session without
    // performing username/password login.
    if (accountType === 'holdToken' && (session.providedRawCookies || session.providedStructuredCookies)) {
      await injectRawCookies(session.context, session.providedRawCookies, exactPath, session.providedStructuredCookies);
      session.__skipLogin = true;
      emitStatus('cookies-injected', 'Injected copied cookies; skipping username/password login', { account: username });
      // If the pasted cookies contain a hold token but the account object did not
      // explicitly provide one, read it back from the context so the fast direct-WS
      // paths can use it immediately.
      if (!session.providedHoldToken) {
        const cookieHoldToken = await getHoldTokenFromContext(session.context);
        if (cookieHoldToken) {
          session.providedHoldToken = cookieHoldToken;
          session.holdToken = cookieHoldToken;
          touchHoldToken(session, cookieHoldToken, 15);
          registerHoldToken(username, session.holdToken);
          emitStatus('hold-token-from-cookies', 'Using hold token found in injected cookies', { account: username, tokenPrefix: cookieHoldToken.slice(0, 8) });
        }
      }
    }

    // For holdToken accounts, force the provided token into the page before any
    // navigation so the SeatCloud iframe reads it instead of the logged-in user's token.
    if (accountType === 'holdToken' && session.providedHoldToken) {
      const forcedToken = session.providedHoldToken;
      await page.addInitScript(([token]) => {
        if (window.__kimikoSetHoldToken) window.__kimikoSetHoldToken(token);
        else {
          window.__kimikoForcedHoldToken = token;
          window.holdToken = token;
          window.__INITIAL_STATE__ = window.__INITIAL_STATE__ || {};
          window.__INITIAL_STATE__.hold_token = token;
        }
      }, [forcedToken]);
      await page.evaluate((token) => {
        if (window.__kimikoSetHoldToken) window.__kimikoSetHoldToken(token);
      }, forcedToken).catch(() => {});
    }
    if (session.holdToken && isHoldTokenUsedByAnother(session.holdToken, username)) {
      const other = activeHoldTokenRegistry.get(session.holdToken);
      throw new Error(`DUPLICATE_HOLD_TOKEN: ${username} shares token with ${other}`);
    }

    // Credentials accounts: mint a fresh unique hold token so we never share a token with another account.
    if (accountType === 'credentials' && !session.holdToken) {
      try {
        const fresh = await createFreshHoldToken(session, 30);
        if (fresh?.holdToken) {
          session.holdToken = fresh.holdToken;
          touchHoldToken(session, fresh.holdToken, Math.ceil((fresh.expiresInSeconds || 1800) / 60), fresh.expiresAt);
          registerHoldToken(username, fresh.holdToken);
          await syncQueueTokenToCookie(session.context, null, fresh.holdToken);
          await session.page.addInitScript(([token]) => {
            if (window.__kimikoSetHoldToken) window.__kimikoSetHoldToken(token);
            else {
              window.__kimikoForcedHoldToken = token;
              window.holdToken = token;
              window.__INITIAL_STATE__ = window.__INITIAL_STATE__ || {};
              window.__INITIAL_STATE__.hold_token = token;
            }
          }, [fresh.holdToken]);
          fileLog('INFO', `[${username}] Fresh hold token minted via API: ${fresh.holdToken.slice(0, 12)}...`);
        }
      } catch (e) {
        fileLog('WARN', `[${username}] Could not mint fresh hold token: ${e.message}`);
      }
    }

    // Pre-set consent cookies and route interception in parallel before navigating.
    const cookiePresetPromise = preSetConsentCookies(session.context);
    const routeSetupPromise = Promise.all([
      setupWebSocketRoute(page),
      setupChartIframePatchRoute(page),
      setupBundlePatchRoute(page),
      setupNoiseBlockRoute(page),
    ]);

    page.on('console', msg => {
      const text = msg.text();
      const type = msg.type();
      fileLog('BROWSER', `[${username}] [console:${type}] ${text}`);
      if (type === 'error' || text.includes('error') || text.includes('Error')) {
        io.emit('console', { type: 'error', text, account: username });
      }
    });
    page.on('pageerror', err => {
      fileLog('BROWSER', `[${username}] [pageerror] ${err.message}`);
    });
    // Track auth-related API calls and queue tokens from network responses.
    page.on('response', async res => {
      const url = res.url();
      const status = res.status();
      if (status >= 400 || url.includes('seatcloud') || url.includes('webook')) {
        fileLog('NETWORK', `[${username}] [${status}] ${url}`);
      }
      if (url.includes('/api/v2/login') && status === 200) {
        fileLog('INFO', `[${username}] Observed login API 200`);
      }
      const qt = res.headers()['queue-token'];
      if (qt && !(accountType === 'holdToken' && session.providedQueueToken)) {
        session.queueToken = qt;
        fileLog('INFO', `[${username}] Queue token updated from ${url}`);
        syncQueueTokenToCookie(session.context, qt).catch(() => {});
      }
    });

    await cookiePresetPromise;
    await routeSetupPromise;

    // For holdToken accounts, prevent WeBook's hold-token API from overwriting
    // the provided token with a fresh one for the logged-in user.
    setupHoldTokenProtectRoute(page, session);

    const bookingUrl = url.includes('/book') ? url : `${url.replace(/\/$/, '')}/book`;
    const eventSlug = parseSlug(bookingUrl);

    // ------------------------------------------------------------------
    // Pre-fetch chart keys BEFORE any queue/login/time-consuming UI work so the
    // direct WebSocket attack can fire immediately once a holdToken is available.
    // ------------------------------------------------------------------
    if (!session.workspaceKey || !session.eventKey) {
      try {
        const chartInfo = await fetchChartSections(eventSlug);
        session.workspaceKey = chartInfo.workspaceKey;
        session.eventKey = chartInfo.eventKey;
        session.chartSections = chartInfo.chartSections;
        session.teams = chartInfo.teams || [];
        session.allTeamIds = chartInfo.allTeamIds || [];
        session.commonChannelKeys = chartInfo.commonChannelKeys || [];
        session.allChannelKeys = chartInfo.allChannelKeys || [];

        // Resolve selected team into channel keys now so the direct WS uses the
        // correct allocation shape without waiting for the team-selection UI.
        if (selectedTeam?.id) {
          if (selectedTeam.id === 'ALL_TEAMS') {
            session.selectedTeam = { id: 'ALL_TEAMS', allChannelKeys: session.allChannelKeys, commonChannelKeys: session.commonChannelKeys };
          } else {
            const teamMeta = session.teams.find(t => String(t.id) === String(selectedTeam.id));
            if (teamMeta) {
              session.selectedTeam = {
                id: selectedTeam.id,
                name: teamMeta.name,
                channelKeys: teamMeta.channelKeys || [],
                commonChannelKeys: session.commonChannelKeys || [],
              };
            }
          }
        }
        emitStatus('keys-prefetched', `Pre-fetched chart keys: ${session.workspaceKey}/${session.eventKey}`, { account: username });
      } catch (e) {
        fileLog('WARN', `[${username}] Could not pre-fetch chart sections: ${e.message}`);
      }
    }

    // ------------------------------------------------------------------
    // Absolute workflow separation:
    //   - Cookie/holdToken users go straight to /book and bypass the login
    //     page and UI queue waiting entirely.
    //   - Credential users navigate to the lightweight /ar/login page first,
    //     authenticate there, then go directly to /book. Queue polling only
    //     happens when the DOM explicitly reports a waiting-room state.
    // ------------------------------------------------------------------

    // Follower optimization: inject a previously harvested valid queue token
    // before any navigation so this account skips the waiting room entirely.
    await tryInjectHarvestedQueueToken(session);

    const isCookieFastTrack = accountType === 'holdToken';

    if (isCookieFastTrack) {
      emitStatus('navigating', 'Cookie user: navigating directly to booking page', { account: username });
      session.state = 'navigating';
      emitAccountUpdate(username, 'navigating');

      await page.goto(bookingUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
      await emitScreenshot(page, 'booking-page-cookie', username);
      await dismissAllBanners(page, username, 'pre-login');
    } else {
      emitStatus('navigating', 'Credentials user: navigating to dedicated login page', { account: username });
      session.state = 'navigating';
      emitAccountUpdate(username, 'navigating');

      // Step 1: land on the lightweight dedicated login page (not the heavy event page).
      const loginUrl = 'https://webook.com/ar/login';
      await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await emitScreenshot(page, 'login-page', username);
      await dismissAllBanners(page, username, 'login-page');

      // Step 2: log in on the dedicated login page. Cookie-injected accounts skip this.
      if (!session.__skipLogin) {
        try {
          await ensureLoggedIn(page, authUsername, authPassword, session);
        } catch (loginErr) {
          throw loginErr;
        }
        await dismissAllBanners(page, username, 'post-login');
      } else {
        emitStatus('login', 'Skipping manual login because cookies were injected', { account: username });
      }

      // Step 3: persist cookies and navigate directly to /book.
      emitStatus('login', 'Login complete; saving session state and navigating to booking page', { account: username });
      await waitFor(100);
      await saveSessionState(authUsername, session.context, { source: 'runSession-login-page', note: 'cookies saved before navigating to /book' });

      // Step 4: move to the actual /book page now that we are authenticated.
      emitStatus('returning', 'Navigating to booking page', { account: username });
      await page.goto(bookingUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    }

    // Accept cookies and dismiss any pre-login banners as soon as possible.
    await dismissAllBanners(page, username, 'pre-login');

    // Immediate page-state detection: chart/timer/login/404.
    let pageState = await detectBookingPageState(page);
    // Double-check ambiguous queue signals with the accurate detector to avoid false positives.
    if (pageState.state === 'queue') {
      const accurate = await detectQueueStateAccurate(page, username);
      if (!accurate.isInQueue) {
        fileLog('INFO', `[${username}] Accurate queue detector overrode false queue signal; treating as ${accurate.hasChart || accurate.hasTimer ? 'booking-ready' : 'unknown'}`);
        pageState.state = accurate.hasChart || accurate.hasTimer ? 'booking-ready' : 'unknown';
        pageState.reason = 'accurate-detector-override';
        pageState.hasChart = accurate.hasChart;
        pageState.hasCountdown = accurate.hasTimer;
      }
    }
    fileLog('INFO', `[${username}] Initial page state: ${pageState.state} (${pageState.reason})`);
    emitStatus('page-state', `Page state: ${pageState.state}`, { account: username, ...pageState });

    // Credentials safety check: if we landed back on a login form after navigating
    // to /book, the session did not stick. Fail fast instead of looping for a chart.
    if (!isCookieFastTrack && pageState.state === 'login') {
      throw new Error('SESSION_DROPPED_AFTER_BOOKING_NAVIGATION: still on login page after navigating to /book');
    }

    // If the /book page is missing (404), fall back to the event detail page and try again.
    if (pageState.state === 'not-found') {
      emitStatus('page-not-found', 'Booking page returned 404; falling back to event page', { account: username });
      const baseEventUrl = bookingUrl.replace(/\/book$/, '');
      await page.goto(baseEventUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
      await dismissAllBanners(page, username, 'post-404');
      pageState = await detectBookingPageState(page);
      fileLog('INFO', `[${username}] Page state after 404 fallback: ${pageState.state} (${pageState.reason})`);
    }

    // If the page explicitly shows a login form, skip API/UI probes and log in immediately.
    // Exception: cookie-injected accounts should never perform username/password login;
    // we rely entirely on the pasted cookies/hold token.
    if (pageState.state === 'login' && !session.__skipLogin) {
      emitStatus('login-detected', 'Login page detected; logging in immediately', { account: username, loginAccount: authUsername });
      const loginResult = await performManualLogin(page, authUsername, authPassword, session);
      if (!loginResult.success) throw new Error('Login could not be completed after login-page detection');
      await saveSessionState(authUsername, session.context, { source: 'ensureLoggedIn-login-page', note: loginResult.source });
      emitStatus('login', 'Logged in successfully', { account: username, loginAccount: authUsername, source: loginResult.source });
      // After login, navigate back to /book if we are not already there.
      if (!page.url().includes('/book')) {
        await page.goto(bookingUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
        await dismissAllBanners(page, username, 'post-login-redirect');
      }
      pageState = await detectBookingPageState(page);
    } else if (pageState.state === 'login' && session.__skipLogin) {
      emitStatus('login-detected', 'Login page detected but cookies injected; skipping manual login', { account: username });
    }

    // Special events (e.g. Hilal vs Ahli) require choosing a favorite team before
    // the chart is shown. Handle this early so the rest of the flow sees the chart.
    try {
      if (await isTeamSelectionPage(page)) {
        const handled = await handleTeamSelection(page, session, selectedTeam);
        if (handled) {
          // Wait for the team selection UI to disappear and re-detect state.
          for (let i = 0; i < 30; i++) {
            await waitFor(100);
            if (!(await isTeamSelectionPage(page))) break;
          }
          pageState = await detectBookingPageState(page);
        }
      }
    } catch (teamErr) {
      fileLog('WARN', `[${username}] Team selection handling error: ${teamErr.message}`);
    }

    // ------------------------------------------------------------------
    // Proactive hold-token fetch: do NOT trust the DOM queue indicator. As
    // soon as we are logged in, ask the API for a hold token. If the API
    // gives one, bypass all waiting-room polling and start booking instantly.
    // ------------------------------------------------------------------
    if (!session.holdToken && !session.queueHoldToken && !session.providedHoldToken) {
      try {
        const detail = await fetchEventDetail(eventSlug);
        const eventId = detail?._id || detail?.data?._id || null;
        if (eventId) {
          const proactiveToken = await getHoldTokenFromApi(eventSlug, eventId, session);
          if (proactiveToken) {
            if (accountType === 'holdToken') {
              session.holdToken = proactiveToken;
            } else {
              session.queueHoldToken = proactiveToken;
            }
            touchHoldToken(session, proactiveToken, 15);
            emitStatus('proactive-hold-token', 'Hold token acquired before queue wait; bypassing queue', { account: username, tokenPrefix: proactiveToken.slice(0, 8) });
          }
        }
      } catch (e) {
        fileLog('WARN', `[${username}] Proactive hold token fetch failed: ${e.message}`);
      }
    }

    // ------------------------------------------------------------------
    // Queue handling: only poll the queue API if the DOM explicitly reports
    // a waiting-room state AND we could not acquire a proactive hold token.
    // ------------------------------------------------------------------
    const hasUsableHoldToken = !!(session.holdToken || session.queueHoldToken || session.providedHoldToken);
    if (isCookieFastTrack) {
      emitStatus('queue-bypassed', 'Cookie user with holdToken: skipping UI queue wait', { account: username });
    } else if (pageState.state === 'queue' && !hasUsableHoldToken) {
      // Follower optimization: if a previous credentials account already cleared
      // the queue and harvested a valid queue token, inject it before polling so
      // this account bypasses the waiting room instantly.
      if (!session.queueToken && globalValidQueueToken && globalValidQueueToken.token) {
        if (isQueueTokenValid(globalValidQueueToken.token)) {
          session.queueToken = globalValidQueueToken.token;
          await syncQueueTokenToCookie(session.context, globalValidQueueToken.token);
          emitStatus('queue-token-injected', 'Injected harvested queue token; attempting instant bypass', { account: username });
        } else {
          globalValidQueueToken = null;
        }
      }

      // Poll the /hold-token API aggressively. The instant it returns queued:false
      // with a valid holdToken we proceed to the direct WebSocket attack.
      const cleared = await waitForQueueClear(page, username, session, eventSlug);
      if (cleared.cleared) {
        session.__queueCleared = true;
        if (cleared.holdToken) {
          if (accountType === 'holdToken') {
            session.holdToken = cleared.holdToken;
            touchHoldToken(session, cleared.holdToken, 15);
          }
          else session.queueHoldToken = cleared.holdToken;
        }
        await syncQueueTokenToCookie(session.context, cleared.queueToken, cleared.holdToken);
        // If the headless poll did not return a hold token, try to fetch one via
        // the logged-in API as a last resort before falling back to the UI.
        if (!session.holdToken && !session.queueHoldToken) {
          try {
            const detail = await fetchEventDetail(eventSlug);
            const eventId = detail?._id || detail?.data?._id || null;
            if (eventId) {
              const fallbackToken = await getHoldTokenFromApi(eventSlug, eventId, session);
              if (fallbackToken) {
                session.holdToken = fallbackToken;
                touchHoldToken(session, fallbackToken, 15);
              }
            }
          } catch (e) {
            fileLog('WARN', `[${username}] Could not fetch fallback hold token after queue clear: ${e.message}`);
          }
        }
        const queueClearedUrl = (session.holdToken || session.queueHoldToken)
          ? `${bookingUrl}${bookingUrl.includes('?') ? '&' : '?'}hold_token=${encodeURIComponent(session.holdToken || session.queueHoldToken)}`
          : bookingUrl;
        await page.goto(queueClearedUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
        await dismissAllBanners(page, username, 'post-queue');
      }
    } else if (hasUsableHoldToken) {
      emitStatus('queue-bypassed', 'Hold token available; skipping queue wait', { account: username });
    } else if (pageState.state === 'booking-ready') {
      emitStatus('queue-bypassed', 'Already on booking page with chart/timer; skipping queue wait', { account: username });
    } else {
      fileLog('INFO', `[${username}] Page state ${pageState.state}; not entering queue poll`);
    }

    fileLog('TIMER', `[${username}] runSession login/queue phase completed in ${Date.now() - sessionStartMs}ms`);

    // ------------------------------------------------------------------
    // Fast pre-booking setup: dismiss banners, ensure on /book, then race to
    // detect the booking-open signal. Every millisecond counts here, so long
    // human-input simulations and redundant API checks are skipped/shortened.
    // ------------------------------------------------------------------
    try {
      await dismissAllBanners(page, username, 'post-login');
      if (!page.url().includes('/book')) {
        emitStatus('returning', 'Navigating back to booking page', { account: username });
        await page.goto(bookingUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
        await dismissAllBanners(page, username, 'post-redirect');
      }
    } catch (uiErr) {
      fileLog('WARN', `[${username}] Pre-booking banner/redirect interaction failed (non-fatal): ${uiErr.message}`);
      emitStatus('ui-warning', `Banner/redirect interaction skipped: ${uiErr.message}`, { account: username });
    }

    // ------------------------------------------------------------------
    // Direct-attack gate: if we already have a holdToken and pre-fetched
    // chart keys, bypass all UI waits (queue safety check, booking trigger,
    // Turnstile, chart interactivity) and jump straight to the WebSocket
    // sniper. Credentials users that clear the queue headlessly arrive here
    // with session.queueHoldToken + pre-fetched keys, so they take this path.
    // Cookie/holdToken users already have providedHoldToken + keys.
    // ------------------------------------------------------------------
    const activeHoldToken = session.holdToken || session.queueHoldToken || session.providedHoldToken || null;
    const canDirectAttack = !!activeHoldToken && !!session.workspaceKey && !!session.eventKey;
    let postLoginBookingReady = false;

    if (canDirectAttack) {
      if (accountType === 'holdToken' && session.providedHoldToken) {
        await swapToProvidedHoldToken(page, session, bookingUrl);
      }
      emitStatus('direct-attack-ready', 'Hold token + chart keys available; skipping UI trigger/chart waits', { account: username, tokenPrefix: activeHoldToken.slice(0, 8) });
      postLoginBookingReady = true;
    } else {
      // UI-based readiness path. Start the booking trigger watcher as early as
      // possible and run the remaining checks in parallel so we attack the exact
      // millisecond the chart/timer appears.
      try {
        const triggerTimeoutMs = (accountType === 'holdToken' && session.providedHoldToken)
          ? 5000
          : (session.__queueCleared ? 15000 : 30000);

        // Launch the ultra-fast trigger watcher immediately.
        const triggerPromise = waitForBookingTrigger(page, triggerTimeoutMs, 595);

        // While the watcher runs, do non-blocking setup in parallel.
        const setupPromise = (async () => {
          if (!isCookieFastTrack) {
            const postLoginUrl = page.url();
            const postLoginOnBookPage = postLoginUrl.includes('/book');
            const postLoginDomQueue = await isQueuePage(page);
            postLoginBookingReady = await isBookingPageReady(page);

            // Only call the queue API if we are not already on /book with a chart/timer.
            if (!postLoginOnBookPage || !postLoginBookingReady) {
              let postLoginQueueCheck = { queued: false, confidence: 'low', queue: null };
              try {
                postLoginQueueCheck = await checkQueueStatus(eventSlug, null, session.queueToken || '');
              } catch {}

              const postLoginQueued = postLoginDomQueue || (postLoginQueueCheck.queued && !postLoginBookingReady);
              if (postLoginQueued) {
                session.queueToken = postLoginQueueCheck.queueToken || session.queueToken;
                await syncQueueTokenToCookie(session.context, session.queueToken);
                emitStatus('queue-detected-post-login', 'Still queued after login; waiting...', { account: username, queue: postLoginQueueCheck.queue });
                emitAccountUpdate(username, 'queued', { position: postLoginQueueCheck.queue?.waiting_number, total: postLoginQueueCheck.queue?.total_in_queue });
                const cleared = await waitForQueueClear(page, username, session, eventSlug);
                if (cleared.cleared && cleared.holdToken) {
                  if (accountType === 'holdToken') session.holdToken = cleared.holdToken;
                  else session.queueHoldToken = cleared.holdToken;
                }
                await syncQueueTokenToCookie(session.context, cleared.queueToken, cleared.holdToken);
                const postQueueUrl = cleared.holdToken
                  ? `${bookingUrl}${bookingUrl.includes('?') ? '&' : '?'}hold_token=${encodeURIComponent(cleared.holdToken)}`
                  : bookingUrl;
                await page.goto(postQueueUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
                await dismissAllBanners(page, username, 'post-queue-final');
              }
            }
          }

          if (accountType === 'holdToken' && session.providedHoldToken) {
            await swapToProvidedHoldToken(page, session, bookingUrl);
            postLoginBookingReady = await isBookingPageReady(page);
          }

          return postLoginBookingReady;
        })();

        const [trigger] = await Promise.all([triggerPromise, setupPromise]);

        if (!trigger.triggered) {
          fileLog('WARN', `[${username}] Booking trigger not detected within timeout; proceeding anyway`);
          const captchaToken = await trySolveCaptchaWith2captcha(page, session, 'chart');
          if (captchaToken) {
            fileLog('INFO', `[${username}] Retrying booking trigger after 2captcha injection`);
            const retrigger = await waitForBookingTrigger(page, 8000, 595);
            if (retrigger.triggered) {
              emitStatus('booking-triggered', `Booking triggered after captcha solve: ${retrigger.reason}`, { account: username, timerSeconds: retrigger.timerSeconds, timerText: retrigger.timerText });
            }
          }
        } else {
          emitStatus('booking-triggered', `Booking triggered: ${trigger.reason}`, { account: username, timerSeconds: trigger.timerSeconds, timerText: trigger.timerText });
        }

        // Turnstile check after trigger (fast, does not block the sniper long).
        emitStatus('turnstile-check', 'Checking for Cloudflare Turnstile overlay...', { account: username });
        let turnstileCleared = await waitForTurnstileToClear(page, 3000, username);
        if (!turnstileCleared) {
          fileLog('WARN', `[${username}] [turnstile] Turnstile still present; attempting 2captcha fallback`);
          const turnstileToken = await trySolveCaptchaWith2captcha(page, session, 'chart');
          if (turnstileToken) {
            turnstileCleared = await waitForTurnstileToClear(page, 5000, username);
          }
        }
        if (turnstileCleared) {
          emitStatus('turnstile-cleared', 'Turnstile cleared; chart should be interactive', { account: username });
        } else {
          fileLog('WARN', `[${username}] [turnstile] Turnstile did not clear; proceeding anyway`);
        }

        try {
          await waitForSeatChartInteractive(page, 20000);
        } catch (chartInteractiveErr) {
          fileLog('WARN', `[${username}] ${chartInteractiveErr.message}`);
        }
      } catch (uiErr) {
        fileLog('WARN', `[${username}] Pre-booking UI interaction failed (non-fatal): ${uiErr.message}`);
        emitStatus('ui-warning', `UI interaction skipped: ${uiErr.message}`, { account: username });
      }
    }

    fileLog('TIMER', `[${username}] runSession reached booking-ready in ${Date.now() - sessionStartMs}ms`);

    // ------------------------------------------------------------------
    // Dry-run exit: verify proxy IP and chart availability, then stop.
    // ------------------------------------------------------------------
    if (dryRun) {
      const publicIp = await getProxyIp(session);
      const frame = await findChartFrame(page, username);
      const chartReady = !!frame;
      const result = {
        account: username,
        proxy: session.proxy?.server || null,
        publicIp,
        chartReady,
        elapsedMs: Date.now() - sessionStartMs,
      };
      emitStatus('dry-run-success', `Dry-run OK: login passed, proxy=${result.proxy}, ip=${publicIp || 'unknown'}, chart=${chartReady}`, result);
      emitAccountUpdate(username, 'dry-run-success', result);
      fileLog('INFO', `[${username}] Dry-run completed: ${JSON.stringify(result)}`);
      await stopSession(username, 'dry-run-complete');
      return;
    }

    // Pre-check: log availability for selected sections. With pre-fetched keys
    // we skip the redundant API round-trip, but still warn if selected sections
    // appear empty so the UI knows sniper mode is monitoring.
    let effectiveTargetSections = targetSections;

    if (cycleMode && postLoginBookingReady) {
      emitStatus('cycle-fast-path', 'Pair cycle with chart ready; skipping availability pre-check', { account: username });
    } else if (session.workspaceKey && session.eventKey) {
      emitStatus('fast-path', 'Using cached workspace/event keys; skipping section pre-check API call', { account: username });
    } else {
      try {
        const slug = parseSlug(bookingUrl);
        const { chartSections, workspaceKey, eventKey } = await fetchChartSections(slug);
        session.chartSections = chartSections;
        session.workspaceKey = workspaceKey || session.workspaceKey;
        session.eventKey = eventKey || session.eventKey;
        const bySection = {};
        for (const s of chartSections) bySection[s.label.toUpperCase()] = s.availableCount || 0;
        const requestedAvailable = effectiveTargetSections.reduce((sum, s) => sum + (bySection[s.toUpperCase()] || 0), 0);
        if (requestedAvailable === 0) {
          emitStatus('seats-monitoring', `Selected sections currently empty; sniper will monitor for availability`, { account: username, sections: effectiveTargetSections });
        }
      } catch (e) {
        fileLog('WARN', `[${username}] Section pre-check skipped: ${e.message}`);
      }
    }

    // Select seats. Unified flow: direct SeatCloud WebSocket attack first for
    // every user that has a holdToken + chart keys; chart iframe only as fallback.
    const sectionNames = effectiveTargetSections && effectiveTargetSections.length ? effectiveTargetSections.join(', ') : 'any';
    emitStatus('selecting', `Holding up to ${targetSeatCount} seats in ${sectionNames}...`, { account: username });
    session.state = 'selecting';
    emitAccountUpdate(username, 'selecting');

    let selectedSeats = [];
    const selectionStartMs = Date.now();
    const selectionMaxMs = 90_000;

    // Pair-cycling handoff: hold an exact list of seats already held by the pair partner.
    if (fixedSeats && fixedSeats.length > 0) {
      emitStatus('chart-iframe-visible', 'Chart detected on page', { account: username });

      // Fast path: if we pre-fetched chart keys, obtain a fresh hold token for this
      // user and try to hold the exact seats directly via SeatCloud WebSocket before
      // falling back to the slower chart-based path.
      if (session.workspaceKey && session.eventKey) {
        const pageSlug = parseSlug(page.url());
        let handoffToken = await readChartHoldToken(page, pageSlug);
        if (!handoffToken) {
          try {
            const detail = await fetchEventDetail(pageSlug);
            const eventId = detail?._id || detail?.data?._id || null;
            if (eventId) handoffToken = await getHoldTokenFromApi(pageSlug, eventId, session);
          } catch (e) {
            fileLog('WARN', `[${username}] Handoff token fetch failed: ${e.message}`);
          }
        }
        if (handoffToken) {
          session.holdToken = handoffToken;
          touchHoldToken(session, handoffToken, HOLD_TOKEN_EXTENSION_MINUTES);
          const directHeld = await holdSpecificSeatsViaDirectWebSocket(
            session.workspaceKey,
            session.eventKey,
            handoffToken,
            fixedSeats,
            { username, session }
          );
          if (directHeld.length) {
            selectedSeats = directHeld;
            emitStatus('direct-ws-specific-success', `Direct WS handoff held ${directHeld.length} seat(s)`, { account: username, seats: directHeld });
          }
        }
      }

      if (selectedSeats.length === 0) {
        selectedSeats = await holdSpecificSeatsViaWebSocket(page, fixedSeats, username, session);
      }
    } else {
      // ------------------------------------------------------------------
      // Unified direct WebSocket attack for ALL users with a holdToken and
      // pre-fetched chart keys. Credentials users arrive here with
      // session.queueHoldToken; cookie/holdToken users with providedHoldToken.
      // ------------------------------------------------------------------
      const directHoldToken = session.holdToken || session.queueHoldToken || session.providedHoldToken || null;

      if (directHoldToken && session.workspaceKey && session.eventKey) {
        const directHeld = await executeDirectWebSocketSniper(
          session,
          page,
          directHoldToken,
          effectiveTargetSections,
          targetSeatCount
        );
        if (directHeld.length) {
          selectedSeats = directHeld;
          session.holdToken = directHoldToken;
          touchHoldToken(session, directHoldToken, HOLD_TOKEN_EXTENSION_MINUTES);
          emitStatus('direct-ws-success', `Direct WS attack held ${selectedSeats.length}/${targetSeatCount} seats`, { account: username, seats: selectedSeats });
        }
      }

      // Chart iframe fallback: only used when direct WebSocket held nothing or
      // when prerequisites (token/keys) were missing.
      if (selectedSeats.length < targetSeatCount && Date.now() - selectionStartMs < selectionMaxMs && !session.bookingPaused && !session.stopRequested) {
        if (selectedSeats.length === 0) {
          fileLog('INFO', `[${username}] Direct WS path held 0/${targetSeatCount}; falling back to chart-based path`);
          emitStatus('direct-ws-fallback', `Direct WS returned no seats; trying chart path`, { account: username });
        }
        const chartStart = Date.now();
        const chartMaxMs = Math.max(0, Math.min(30_000, selectionMaxMs - (Date.now() - selectionStartMs)));
        while (Date.now() - chartStart < chartMaxMs && selectedSeats.length < targetSeatCount && !session.bookingPaused && !session.stopRequested) {
          const chartReady = await isChartReady(page) || !!(await page.$('iframe'));
          if (!chartReady) {
            await waitFor(60);
            continue;
          }
          emitStatus('chart-iframe-visible', 'Chart detected on page', { account: username });
          const stillNeed = targetSeatCount - selectedSeats.length;
          const batch = await selectSeatsViaWebSocket(page, effectiveTargetSections, stillNeed, username, session, session.providedHoldToken || null);
          if (batch.length) {
            selectedSeats = [...new Set([...selectedSeats, ...batch])];
            emitStatus('chart-ws-success', `Chart path held ${selectedSeats.length}/${targetSeatCount} seats`, { account: username, seats: selectedSeats });
          }
          if (selectedSeats.length >= targetSeatCount) break;
          await waitFor(60);
        }
      }

      // Last-resort direct WebSocket retry with the current best token (which may
      // have been refreshed by the chart fallback). Keep trying until the per-user
      // target is reached or the timeout is hit.
      if (selectedSeats.length < targetSeatCount && Date.now() - selectionStartMs < selectionMaxMs && !session.bookingPaused && !session.stopRequested) {
        const lastToken = session.holdToken || session.queueHoldToken || session.providedHoldToken || null;
        if (lastToken && session.workspaceKey && session.eventKey) {
          emitStatus('direct-ws-attempt', `Chart path ${selectedSeats.length}/${targetSeatCount}; trying direct SeatCloud WebSocket hold`, { account: username });
          const directHeld = await executeDirectWebSocketSniper(
            session,
            page,
            lastToken,
            effectiveTargetSections,
            targetSeatCount - selectedSeats.length
          );
          if (directHeld.length) {
            selectedSeats = [...new Set([...selectedSeats, ...directHeld])];
            session.holdToken = lastToken;
            touchHoldToken(session, lastToken, 15);
            emitStatus('direct-ws-success', `Direct WS fallback held ${selectedSeats.length}/${targetSeatCount} seats`, { account: username, seats: selectedSeats });
          }
        }
      }
    }

    // Merge rather than overwrite so seats captured concurrently by the live
    // WebSocket release listener are preserved.
    session.selectedSeats = [...new Set([...(session.selectedSeats || []), ...selectedSeats])];

    // Fallback: if the provided hold token failed completely, try the logged-in
    // user's own token via the chart route.
    if (selectedSeats.length === 0 && session.providedHoldToken) {
      fileLog('INFO', `[${username}] Provided hold token produced no seats; falling back to logged-in user's token`);
      forcedHoldTokenRegistry.delete(page);
      try {
        const chartToken = await readChartHoldToken(page, parseSlug(page.url()));
        session.holdToken = chartToken;
        if (chartToken) touchHoldToken(session, chartToken, 15);
      } catch (e) {
        fileLog('WARN', `[${username}] Could not read logged-in user's token: ${e.message}`);
      }
      if (session.holdToken) {
        emitStatus('hold-token-fallback', 'Using logged-in user token', { account: username });
        const fallbackBatch = await selectSeatsViaWebSocket(page, effectiveTargetSections, targetSeatCount, username, session);
        selectedSeats = [...new Set([...selectedSeats, ...fallbackBatch])];
        session.selectedSeats = [...new Set([...(session.selectedSeats || []), ...selectedSeats])];
      }
    }

    // Force the chart iframe to visually reflect every held seat. The WebSocket
    // backend already owns the holds, but the SeatCloud renderer sometimes needs
    // a local state injection to avoid appearing empty until a manual refresh.
    if (session.selectedSeats.length > 0) {
      try {
        const frame = await findChartFrame(page, username);
        if (frame) {
          const syncRes = await syncChartSelection(frame, session.selectedSeats, { page, username });
          emitStatus('seats-synced', `Final chart UI sync: ${syncRes.selectedCount || session.selectedSeats.length} seats`, { account: username, count: syncRes.selectedCount || session.selectedSeats.length });
        }
      } catch (syncErr) {
        fileLog('WARN', `[${username}] Final chart sync warning: ${syncErr.message}`);
      }
      // If the parent WeBook cart still shows fewer tickets than we hold,
      // refresh the booking page with the hold token so the cart rehydrates.
      try {
        await refreshPageToSyncCart(session);
      } catch (cartErr) {
        fileLog('WARN', `[${username}] Cart refresh warning: ${cartErr.message}`);
      }
    }

    if (selectedSeats.length === 0) {
      throw new Error('Could not hold any seats');
    }

    fileLog('TIMER', `[${username}] runSession selected seats in ${Date.now() - sessionStartMs}ms -> ${selectedSeats.length}/${targetSeatCount}`);

    // Reserve globally so the next queued accounts skip these seats
    reserveSeats(username, selectedSeats);

    // Safety check: make sure no two active credential sessions share the same hold token.
    if (accountType !== 'holdToken') {
      checkActiveHoldTokenCollisions(username);
    }

    await emitScreenshot(page, 'seats-selected', username, { fullPage: true });
    emitStatus('holding', `Holding ${selectedSeats.length} seat(s): ${selectedSeats.join(', ')}`, { account: username, seats: selectedSeats });

    // Start real-time page timer watcher (queue countdown or booking hold timer).
    startPageTimerWatcher(session);

    // Pair-cycling mode: hold seats and return control to the pair manager.
    // The browser context stays alive; keepalive/watcher keep the seats reserved
    // until the pair manager performs a handoff or stops the cycle.
    if (cycleMode) {
      session.state = 'cycle-holding';
      emitAccountUpdate(username, 'cycle-holding', { seats: selectedSeats, timer: session.lastPageTimerSeconds, timerText: session.lastPageTimerText });
      startHoldKeepalive(session);
      startHoldWatcher(session);
      startActiveSniper(session, effectiveTargetSections);
      if (typeof options.onHeld === 'function') {
        try { options.onHeld(session); } catch (e) {
          fileLog('WARN', `[${username}] cycleMode onHeld callback error: ${e.message}`);
        }
      }
      return;
    }

    session.state = 'paused';
    emitAccountUpdate(username, 'paused', { seats: selectedSeats, timer: session.lastPageTimerSeconds, timerText: session.lastPageTimerText });
    processQueue(); // allow next queued account to start while this one is paused

    // Start keep-alive so the hold doesn't expire
    startHoldKeepalive(session);

    // Watch for lost seats (another user booked them) and re-select
    startHoldWatcher(session);

    // Active sniper: persistent real-time monitor for newly released seats.
    startActiveSniper(session, effectiveTargetSections);

    // Pause until user clicks Proceed or Stop
    emitStatus('paused', 'Ready for payment. Waiting for Proceed signal...', { account: username, seats: selectedSeats });
    const proceedSignal = await waitForProceedSignal(session);

    if (proceedSignal === 'stop' || session.stopRequested || session.bookingPaused) {
      // Soft stop or hard stop: stay on the booking page, keep holds, do not click payment.
      emitStatus('paused', 'Payment cancelled; staying on booking page with held seats', { account: username, seats: selectedSeats });
      return;
    }

    // Proceed to payment
    clearHoldWatcher(session); // no need to re-select while on payment page
    stopActiveSniper(session);
    stopPageTimerWatcher(session);
    emitStatus('payment', 'Clicking Next / Continue...', { account: username });
    session.state = 'payment';
    emitAccountUpdate(username, 'payment');
    const nextSelectors = [
      'button:has-text("التالي: الدفع")',
      'div[data-visible="true"] button:has-text("التالي: الدفع")',
      'button:has-text("دفع")',
      'button:has-text("الدفع")',
      'button:has-text("إتمام")',
      'button:has-text("التالي")',
      'button:has-text("Next")',
      'button:has-text("متابعة")',
      'button:has-text("Continue")',
      'button[type="submit"]',
    ];
    let nextClicked = false;
    let clickedText = '';
    for (const sel of nextSelectors) {
      try {
        const el = await page.$(sel);
        if (el && await el.isVisible() && await el.isEnabled()) {
          await el.click();
          nextClicked = true;
          clickedText = sel;
          break;
        }
      } catch {}
    }

    // Fallback: click via JS on any button whose text matches known payment/next labels.
    if (!nextClicked) {
      try {
        const fallbackText = await page.evaluate((texts) => {
          const buttons = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="button"], input[type="submit"]'));
          for (const t of texts) {
            const btn = buttons.find(b => {
              const txt = (b.innerText || b.textContent || b.value || '').trim();
              return txt === t || txt.includes(t);
            });
            if (btn) { btn.click(); return t; }
          }
          return null;
        }, ['التالي: الدفع', 'دفع', 'الدفع', 'إتمام', 'التالي', 'Next', 'متابعة', 'Continue', 'Submit']);
        if (fallbackText) {
          nextClicked = true;
          clickedText = fallbackText;
        }
      } catch {}
    }

    if (nextClicked) {
      emitStatus('payment-clicked', `Clicked "${clickedText}" to proceed to payment`, { account: username });
    } else {
      emitStatus('payment-warning', 'Could not find Next/Payment button automatically', { account: username });
    }

    await page.waitForLoadState('domcontentloaded', { timeout: 15000 }).catch(() => {});
    await waitFor(500);
    await emitScreenshot(page, 'payment-page', username);
    session.paymentUrl = page.url();
    emitStatus('payment-ready', 'Payment page open. Complete payment manually.', { account: username, url: session.paymentUrl });
    session.state = 'done';
    emitAccountUpdate(username, 'done', { seats: selectedSeats, url: page.url() });
    processQueue(); // start next queued account automatically

    // Keep holding while the payment page is open
    // (the keepalive interval continues until session is stopped)
    return;

  } catch (err) {
    const errMsg = String(err?.message || err || 'unknown');
    const fatal = /ACCOUNT_BANNED|INVALID_CREDENTIALS|INVALID_PASSWORD|INVALID_EMAIL|Login failed/i.test(errMsg);
    const canRetry = !fatal && attempt < maxAttempts;

    emitStatus(canRetry ? 'session-retry' : 'error', `Attempt ${attempt}/${maxAttempts} failed: ${errMsg}${canRetry ? '; retrying...' : ''}`, { account: username, attempt, maxAttempts, error: errMsg });
    fileLog('WARN', `[${username}] runSession attempt ${attempt}/${maxAttempts} failed: ${errMsg} (fatal=${fatal}, canRetry=${canRetry})`);

    // Capture diagnostics while page/context are still alive, then cleanup.
    try {
      await saveDiagnostics(session?.page, username, 'error-' + errMsg.replace(/[^a-z0-9]/gi, '_').slice(0, 50));
    } catch {}
    await safeScreenshot(session?.page, 'error', username);

    // Cleanup failed attempt before retry or finalization.
    clearHoldKeepalive(session);
    clearHoldWatcher(session);
    releaseSeats(username);
    try { await session.context?.close(); } catch {}
    session.context = null;
    session.page = null;
    activeSessions.delete(username);

    if (canRetry) {
      attempt++;
      await waitFor(300);
      continue;
    }

    // Final attempt failed.
    session.state = 'error';
    emitAccountUpdate(username, 'error', { error: errMsg });
    processQueue();
    return;
  }
  }

  // Session remains active with keepalive until user stops it or closes the program.
  emitQueueStats();
}

/**
 * Ensure a browser session exists for an account and is ready on the /book page
 * with an interactive chart iframe. This is intended for external transfer flows
 * that need a live, logged-in session without selecting or holding seats.
 *
 * Does NOT start keepalive, watcher, sniper, or any seat-selection logic.
 */
async function ensureSessionForTransfer(account, options = {}) {
  const { username, password, url, targetSections, sectionQuota, ticketCount, accountIndex = 0, totalAccounts = 1, fixedSeats, type, holdToken: providedHoldToken, queueToken: providedQueueToken, cfClearance: providedCfClearance, recaptchaToken: providedRecaptchaToken, token: providedAuthToken, refreshToken: providedRefreshToken, rawCookies: providedRawCookies, structuredCookies: providedStructuredCookies, loginEmail, loginPassword, useProxy: accountUseProxy, workspaceKey: providedWorkspaceKey, eventKey: providedEventKey, selectedTeam } = account;
  const accountType = type === 'holdToken' ? 'holdToken' : 'credentials';
  const authUsername = accountType === 'holdToken' ? (loginEmail || username) : username;
  const authPassword = accountType === 'holdToken' ? (loginPassword || password) : password;

  // 1. Return existing active session if present.
  const existing = activeSessions.get(username);
  if (existing && existing.context && existing.page) {
    return existing;
  }

  // Use pre-assigned unique proxy if available; otherwise resolve dynamically.
  // For transfer destinations this must never block indefinitely: cap proxy
  // resolution so the source hold token does not expire while we test proxies.
  const sessionStartMs = Date.now();
  let proxy = null;
  let tested = [];
  let proxyMode = currentProxyMode;
  fileLog('INFO', `[${username}] Starting proxy resolution for transfer (useProxy=${accountUseProxy}, globalMode=${currentProxyMode})`);

  async function resolveProxyWithTimeout() {
    if (account.assignedProxy && account.assignedProxy.server) {
      const test = await testProxy(account.assignedProxy, 2000);
      tested.push({ server: account.assignedProxy.server, ok: test.ok, reason: test.reason });
      if (test.ok) {
        proxy = account.assignedProxy;
        logProxyStatus(username, 'PROXY ENABLED', proxy.server, 'pre-assigned');
        return;
      } else if (currentProxyMode === 'required' || accountUseProxy === true) {
        fileLog('WARN', `[proxy-status] [${username}] Pre-assigned proxy failed (${account.assignedProxy.server}: ${test.reason}); searching for another working proxy`);
      }
    }
    if (!proxy) {
      const resolved = await resolveProxyForAccount(username, accountUseProxy, null, {
        maxTotalMs: 12_000,
        perProxyTimeoutMs: 3_000,
      });
      proxy = resolved.proxy;
      tested = resolved.tested;
      proxyMode = resolved.mode;
    }
  }

  try {
    await withTimeout(resolveProxyWithTimeout(), 15_000, `proxy resolution for ${username}`);
  } catch (proxyTimeoutErr) {
    fileLog('WARN', `[${username}] Proxy resolution timed out; opening browser direct: ${proxyTimeoutErr.message}`);
    emitStatus('proxy-fallback', `Proxy resolution timed out for ${username}; using direct connection`, { account: username });
    proxy = null;
    proxyMode = 'off';
  }
  fileLog('INFO', `[${username}] Proxy resolution completed in ${Date.now() - sessionStartMs}ms -> ${proxy ? proxy.server : 'direct'}`);

  sessionCounter++;
  const session = {
    id: sessionCounter,
    username,
    password,
    type: accountType,
    providedHoldToken: accountType === 'holdToken' ? providedHoldToken : null,
    providedQueueToken: accountType === 'holdToken' ? providedQueueToken : null,
    providedCfClearance: accountType === 'holdToken' ? providedCfClearance : null,
    providedRecaptchaToken: accountType === 'holdToken' ? providedRecaptchaToken : null,
    providedAuthToken: accountType === 'holdToken' ? providedAuthToken : null,
    providedRefreshToken: accountType === 'holdToken' ? providedRefreshToken : null,
    providedRawCookies: accountType === 'holdToken' ? providedRawCookies : null,
    providedStructuredCookies: accountType === 'holdToken' ? (Array.isArray(providedStructuredCookies) ? providedStructuredCookies : null) : null,
    loginEmail: accountType === 'holdToken' ? loginEmail : null,
    loginPassword: accountType === 'holdToken' ? loginPassword : null,
    url,
    targetSections,
    sectionQuota: sectionQuota || null,
    targetSeatCount: Math.max(1, Math.min(parseInt(ticketCount, 10) || 30, MAX_HELD_SEATS)),
    accountIndex,
    totalAccounts,
    isSelecting: false,
    context: null,
    page: null,
    state: 'launching',
    selectedSeats: [],
    releasedSeats: new Set(),
    holdToken: accountType === 'holdToken' ? providedHoldToken : null,
    holdTokenCreatedAt: accountType === 'holdToken' && providedHoldToken ? Date.now() : null,
    holdTokenExpiresAt: accountType === 'holdToken' && providedHoldToken ? Date.now() + 15 * 60 * 1000 : null,
    holdInterval: null,
    proceedResolve: null,
    stopRequested: false,
    bookingPaused: false,
    __skipLogin: accountType === 'holdToken',
    speedSettings: { ...currentSpeedSettings },
    proxy: proxy || null,
    proxyMode,
    proxyTested: tested,
    workspaceKey: providedWorkspaceKey || null,
    eventKey: providedEventKey || null,
    chartSections: null,
    selectedTeam: selectedTeam || null,
  };
  activeSessions.set(username, session);
  if (proxy && proxy.server) {
    if (!reserveProxyForSession(username, proxy)) {
      const other = activeProxyReservations.get(getProxyCacheKey(proxy));
      throw new Error(`PROXY_ALREADY_RESERVED: ${proxy.server} is already reserved by ${other || 'unknown'}`);
    }
  }
  if (session.holdToken) registerHoldToken(username, session.holdToken);
  emitStatus('launching', `Launching mobile browser for transfer session...`, { account: username });
  fileLog('INFO', `[${username}] Transfer session proxy assignment: ${proxy ? proxy.server : 'none'}, mode=${proxyMode}, tested=${JSON.stringify(tested.map(t => ({ server: t.server, ok: t.ok })))}`);
  if (proxy && proxy.server) {
    logProxyStatus(username, 'PROXY ENABLED', proxy.server, proxyMode);
  } else {
    logProxyStatus(username, 'DIRECT (No Proxy)', null, proxyMode);
  }
  session.state = 'launching';
  emitAccountUpdate(username, 'launching', { proxy: proxy ? proxy.server : null, proxyMode });

  try {
    fileLog('INFO', `[${username}] Creating mobile context for transfer...`);
    session.context = await createMobileContext(username, 1, proxy);
    fileLog('INFO', `[${username}] Mobile context created (${Date.now() - sessionStartMs}ms)`);
    session.__loadedSessionMeta = session.context.__kimikoSessionMeta || null;
    session.page = await session.context.newPage();
    fileLog('INFO', `[${username}] New page created (${Date.now() - sessionStartMs}ms)`);

    // Verify egress IP and detect collisions with other active sessions.
    try {
      const publicIp = await getProxyIp(session);
      if (publicIp) {
        session.publicIp = publicIp;
        const collision = [...activeSessions.entries()].some(([u, s]) => u !== username && s.publicIp === publicIp);
        if (collision) {
          if (currentProxyMode === 'required' || proxyMode === 'forced') {
            throw new Error(`IP_COLLISION: ${username} shares IP ${publicIp} with another active session`);
          }
          fileLog('WARN', `[${username}] IP collision detected: ${publicIp}`);
        }
        fileLog('INFO', `[${username}] Context egress IP: ${publicIp}`);
      }
    } catch (ipErr) {
      fileLog('WARN', `[${username}] Could not verify context egress IP: ${ipErr.message}`);
    }

    const page = session.page;
    installChartDetectionHook(page, session);

    // Credentials users: wipe any stale local storage, cookies, or session files
    // so the login sequence always starts from a clean slate.
    if (accountType === 'credentials') {
      await forceLogout(page, username);
    }

    // Compute exact event /book path for cookie scoping.
    let exactPath = '/';
    try {
      const bookingUrlForCookies = url.includes('/book') ? url : `${url.replace(/\/$/, '')}/book`;
      exactPath = new URL(bookingUrlForCookies).pathname;
    } catch {}

    // If the user pasted a full cookie string, inject it into the browser context now.
    if (accountType === 'holdToken' && (session.providedRawCookies || session.providedStructuredCookies)) {
      await injectRawCookies(session.context, session.providedRawCookies, exactPath, session.providedStructuredCookies);
      session.__skipLogin = true;
      emitStatus('cookies-injected', 'Injected copied cookies; skipping username/password login', { account: username });
      if (!session.providedHoldToken) {
        const cookieHoldToken = await getHoldTokenFromContext(session.context);
        if (cookieHoldToken) {
          session.providedHoldToken = cookieHoldToken;
          session.holdToken = cookieHoldToken;
          touchHoldToken(session, cookieHoldToken, 15);
          registerHoldToken(username, session.holdToken);
          emitStatus('hold-token-from-cookies', 'Using hold token found in injected cookies', { account: username, tokenPrefix: cookieHoldToken.slice(0, 8) });
        }
      }
    }

    // For holdToken accounts, force the provided token into the page before any
    // navigation so the SeatCloud iframe reads it instead of the logged-in user's token.
    if (accountType === 'holdToken' && session.providedHoldToken) {
      const forcedToken = session.providedHoldToken;
      await page.addInitScript(([token]) => {
        if (window.__kimikoSetHoldToken) window.__kimikoSetHoldToken(token);
        else {
          window.__kimikoForcedHoldToken = token;
          window.holdToken = token;
          window.__INITIAL_STATE__ = window.__INITIAL_STATE__ || {};
          window.__INITIAL_STATE__.hold_token = token;
        }
      }, [forcedToken]);
      await page.evaluate((token) => {
        if (window.__kimikoSetHoldToken) window.__kimikoSetHoldToken(token);
      }, forcedToken).catch(() => {});
    }
    if (session.holdToken && isHoldTokenUsedByAnother(session.holdToken, username)) {
      const other = activeHoldTokenRegistry.get(session.holdToken);
      throw new Error(`DUPLICATE_HOLD_TOKEN: ${username} shares token with ${other}`);
    }

    // Credentials accounts: mint a fresh unique hold token so we never share a token with another account.
    if (accountType === 'credentials' && !session.holdToken) {
      try {
        const fresh = await createFreshHoldToken(session, 30);
        if (fresh?.holdToken) {
          session.holdToken = fresh.holdToken;
          touchHoldToken(session, fresh.holdToken, Math.ceil((fresh.expiresInSeconds || 1800) / 60), fresh.expiresAt);
          registerHoldToken(username, fresh.holdToken);
          await syncQueueTokenToCookie(session.context, null, fresh.holdToken);
          await session.page.addInitScript(([token]) => {
            if (window.__kimikoSetHoldToken) window.__kimikoSetHoldToken(token);
            else {
              window.__kimikoForcedHoldToken = token;
              window.holdToken = token;
              window.__INITIAL_STATE__ = window.__INITIAL_STATE__ || {};
              window.__INITIAL_STATE__.hold_token = token;
            }
          }, [fresh.holdToken]);
          fileLog('INFO', `[${username}] Fresh hold token minted via API (transfer session): ${fresh.holdToken.slice(0, 12)}...`);
        }
      } catch (e) {
        fileLog('WARN', `[${username}] Could not mint fresh hold token for transfer: ${e.message}`);
      }
    }

    // Pre-set consent cookies and route interception in parallel before navigating.
    const cookiePresetPromise = preSetConsentCookies(session.context);
    const routeSetupPromise = Promise.all([
      setupWebSocketRoute(page),
      setupChartIframePatchRoute(page),
      setupBundlePatchRoute(page),
      setupNoiseBlockRoute(page),
    ]);

    page.on('console', msg => {
      const text = msg.text();
      const type = msg.type();
      fileLog('BROWSER', `[${username}] [console:${type}] ${text}`);
      if (type === 'error' || text.includes('error') || text.includes('Error')) {
        io.emit('console', { type: 'error', text, account: username });
      }
    });
    page.on('pageerror', err => {
      fileLog('BROWSER', `[${username}] [pageerror] ${err.message}`);
    });
    page.on('response', async res => {
      const resUrl = res.url();
      const status = res.status();
      if (status >= 400 || resUrl.includes('seatcloud') || resUrl.includes('webook')) {
        fileLog('NETWORK', `[${username}] [${status}] ${resUrl}`);
      }
      if (resUrl.includes('/api/v2/login') && status === 200) {
        fileLog('INFO', `[${username}] Observed login API 200`);
      }
      const qt = res.headers()['queue-token'];
      if (qt && !(accountType === 'holdToken' && session.providedQueueToken)) {
        session.queueToken = qt;
        fileLog('INFO', `[${username}] Queue token updated from ${resUrl}`);
        syncQueueTokenToCookie(session.context, qt).catch(() => {});
      }
    });

    await cookiePresetPromise;
    await routeSetupPromise;

    // For holdToken accounts, prevent WeBook's hold-token API from overwriting
    // the provided token with a fresh one for the logged-in user.
    setupHoldTokenProtectRoute(page, session);

    const bookingUrl = url.includes('/book') ? url : `${url.replace(/\/$/, '')}/book`;
    const eventSlug = parseSlug(bookingUrl);

    // Pre-fetch chart keys BEFORE any queue/login/time-consuming UI work.
    if (!session.workspaceKey || !session.eventKey) {
      try {
        const chartInfo = await fetchChartSections(eventSlug);
        session.workspaceKey = chartInfo.workspaceKey;
        session.eventKey = chartInfo.eventKey;
        session.chartSections = chartInfo.chartSections;
        session.teams = chartInfo.teams || [];
        session.allTeamIds = chartInfo.allTeamIds || [];
        session.commonChannelKeys = chartInfo.commonChannelKeys || [];
        session.allChannelKeys = chartInfo.allChannelKeys || [];

        if (selectedTeam?.id) {
          if (selectedTeam.id === 'ALL_TEAMS') {
            session.selectedTeam = { id: 'ALL_TEAMS', allChannelKeys: session.allChannelKeys, commonChannelKeys: session.commonChannelKeys };
          } else {
            const teamMeta = session.teams.find(t => String(t.id) === String(selectedTeam.id));
            if (teamMeta) {
              session.selectedTeam = {
                id: selectedTeam.id,
                name: teamMeta.name,
                channelKeys: teamMeta.channelKeys || [],
                commonChannelKeys: session.commonChannelKeys || [],
              };
            }
          }
        }
        emitStatus('keys-prefetched', `Pre-fetched chart keys: ${session.workspaceKey}/${session.eventKey}`, { account: username });
      } catch (e) {
        fileLog('WARN', `[${username}] Could not pre-fetch chart sections: ${e.message}`);
      }
    }

    // Follower optimization: inject a previously harvested valid queue token
    // before any navigation so this account skips the waiting room entirely.
    await tryInjectHarvestedQueueToken(session);

    const isCookieFastTrack = accountType === 'holdToken';

    if (isCookieFastTrack) {
      emitStatus('navigating', 'Cookie user: navigating directly to booking page', { account: username });
      session.state = 'navigating';
      emitAccountUpdate(username, 'navigating');

      await page.goto(bookingUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
      await emitScreenshot(page, 'booking-page-cookie', username);
      await dismissAllBanners(page, username, 'pre-login');
    } else {
      emitStatus('navigating', 'Credentials user: navigating to dedicated login page', { account: username });
      session.state = 'navigating';
      emitAccountUpdate(username, 'navigating');

      const loginUrl = 'https://webook.com/ar/login';
      await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await emitScreenshot(page, 'login-page', username);
      await dismissAllBanners(page, username, 'login-page');

      if (!session.__skipLogin) {
        await ensureLoggedIn(page, authUsername, authPassword, session);
        await dismissAllBanners(page, username, 'post-login');
      } else {
        emitStatus('login', 'Skipping manual login because cookies were injected', { account: username });
      }

      emitStatus('login', 'Login complete; saving session state and navigating to booking page', { account: username });
      await waitFor(100);
      await saveSessionState(authUsername, session.context, { source: 'ensureSessionForTransfer-login-page', note: 'cookies saved before navigating to /book' });

      emitStatus('returning', 'Navigating to booking page', { account: username });
      await page.goto(bookingUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    }

    await dismissAllBanners(page, username, 'pre-login');

    // Immediate page-state detection: chart/timer/login/404.
    let pageState = await detectBookingPageState(page);
    fileLog('INFO', `[${username}] Transfer session initial page state: ${pageState.state} (${pageState.reason})`);
    emitStatus('page-state', `Page state: ${pageState.state}`, { account: username, ...pageState });

    if (!isCookieFastTrack && pageState.state === 'login') {
      throw new Error('SESSION_DROPPED_AFTER_BOOKING_NAVIGATION: still on login page after navigating to /book');
    }

    if (pageState.state === 'not-found') {
      emitStatus('page-not-found', 'Booking page returned 404; falling back to event page', { account: username });
      const baseEventUrl = bookingUrl.replace(/\/book$/, '');
      await page.goto(baseEventUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
      await dismissAllBanners(page, username, 'post-404');
      pageState = await detectBookingPageState(page);
      fileLog('INFO', `[${username}] Transfer session page state after 404 fallback: ${pageState.state} (${pageState.reason})`);
    }

    if (pageState.state === 'login' && !session.__skipLogin) {
      emitStatus('login-detected', 'Login page detected; logging in immediately', { account: username, loginAccount: authUsername });
      const loginResult = await performManualLogin(page, authUsername, authPassword, session);
      if (!loginResult.success) throw new Error('Login could not be completed after login-page detection');
      await saveSessionState(authUsername, session.context, { source: 'ensureSessionForTransfer-login-page', note: loginResult.source });
      emitStatus('login', 'Logged in successfully', { account: username, loginAccount: authUsername, source: loginResult.source });
      if (!page.url().includes('/book')) {
        await page.goto(bookingUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
        await dismissAllBanners(page, username, 'post-login-redirect');
      }
      pageState = await detectBookingPageState(page);
    } else if (pageState.state === 'login' && session.__skipLogin) {
      emitStatus('login-detected', 'Login page detected but cookies injected; skipping manual login', { account: username });
    }

    // Handle team selection before the chart is shown.
    try {
      if (await isTeamSelectionPage(page)) {
        const handled = await handleTeamSelection(page, session, selectedTeam);
        if (handled) {
          for (let i = 0; i < 30; i++) {
            await waitFor(100);
            if (!(await isTeamSelectionPage(page))) break;
          }
          pageState = await detectBookingPageState(page);
        }
      }
    } catch (teamErr) {
      fileLog('WARN', `[${username}] Team selection handling error: ${teamErr.message}`);
    }

    // Queue handling: only poll the queue API if the DOM explicitly reports
    // a waiting-room state. Double-check ambiguous signals so we do not block
    // on a false queue detection when the page is actually booking-ready.
    if (pageState.state === 'queue') {
      const accurate = await detectQueueStateAccurate(page, username);
      if (!accurate.isInQueue) {
        fileLog('INFO', `[${username}] Transfer session: accurate detector overrode false queue signal; treating as ${accurate.hasChart || accurate.hasTimer ? 'booking-ready' : 'unknown'}`);
        pageState.state = accurate.hasChart || accurate.hasTimer ? 'booking-ready' : 'unknown';
      }
    }

    if (isCookieFastTrack) {
      emitStatus('queue-bypassed', 'Cookie user with holdToken: skipping UI queue wait', { account: username });
    } else if (pageState.state === 'queue') {
      if (!session.queueToken && globalValidQueueToken && globalValidQueueToken.token) {
        if (isQueueTokenValid(globalValidQueueToken.token)) {
          session.queueToken = globalValidQueueToken.token;
          await syncQueueTokenToCookie(session.context, globalValidQueueToken.token);
          emitStatus('queue-token-injected', 'Injected harvested queue token; attempting instant bypass', { account: username });
        } else {
          globalValidQueueToken = null;
        }
      }

      const cleared = await waitForQueueClear(page, username, session, eventSlug);
      if (cleared.cleared) {
        session.__queueCleared = true;
        if (cleared.holdToken) {
          if (accountType === 'holdToken') {
            session.holdToken = cleared.holdToken;
            touchHoldToken(session, cleared.holdToken, 15);
          }
          else session.queueHoldToken = cleared.holdToken;
        }
        await syncQueueTokenToCookie(session.context, cleared.queueToken, cleared.holdToken);
        if (!session.holdToken && !session.queueHoldToken) {
          try {
            const detail = await fetchEventDetail(eventSlug);
            const eventId = detail?._id || detail?.data?._id || null;
            if (eventId) {
              const fallbackToken = await getHoldTokenFromApi(eventSlug, eventId, session);
              if (fallbackToken) {
                session.holdToken = fallbackToken;
                touchHoldToken(session, fallbackToken, 15);
              }
            }
          } catch (e) {
            fileLog('WARN', `[${username}] Could not fetch fallback hold token after queue clear: ${e.message}`);
          }
        }
        const queueClearedUrl = (session.holdToken || session.queueHoldToken)
          ? `${bookingUrl}${bookingUrl.includes('?') ? '&' : '?'}hold_token=${encodeURIComponent(session.holdToken || session.queueHoldToken)}`
          : bookingUrl;
        await page.goto(queueClearedUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
        await dismissAllBanners(page, username, 'post-queue');
      }
    } else if (pageState.state === 'booking-ready') {
      emitStatus('queue-bypassed', 'Already on booking page with chart/timer; skipping queue wait', { account: username });
    } else {
      fileLog('INFO', `[${username}] Transfer session page state ${pageState.state}; not entering queue poll`);
    }

    fileLog('TIMER', `[${username}] ensureSessionForTransfer login/queue phase completed in ${Date.now() - sessionStartMs}ms`);

    // Ensure we are on /book and the chart iframe is ready for transfers.
    try {
      await dismissAllBanners(page, username, 'post-login');
      if (!page.url().includes('/book')) {
        emitStatus('returning', 'Navigating back to booking page', { account: username });
        await page.goto(bookingUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
        await dismissAllBanners(page, username, 'post-redirect');
      }
    } catch (uiErr) {
      fileLog('WARN', `[${username}] Transfer session pre-booking redirect interaction failed (non-fatal): ${uiErr.message}`);
      emitStatus('ui-warning', `Banner/redirect interaction skipped: ${uiErr.message}`, { account: username });
    }

    const activeHoldToken = session.holdToken || session.queueHoldToken || session.providedHoldToken || null;
    if (activeHoldToken && session.workspaceKey && session.eventKey) {
      if (accountType === 'holdToken' && session.providedHoldToken) {
        await swapToProvidedHoldToken(page, session, bookingUrl);
      }
      emitStatus('transfer-session-ready', 'Hold token + chart keys available; session ready for transfer', { account: username, tokenPrefix: activeHoldToken.slice(0, 8) });
    } else {
      // UI-based readiness path: wait for the chart iframe to become interactive.
      try {
        await waitForSeatChartInteractive(page, 20000);
      } catch (chartInteractiveErr) {
        fileLog('WARN', `[${username}] ${chartInteractiveErr.message}`);
      }
    }

    // Final verification: chart iframe must be present.
    const finalFrame = await findChartFrame(page, username);
    if (!finalFrame) {
      throw new Error('TRANSFER_SESSION_CHART_NOT_READY: seat chart iframe not found after preparation');
    }

    fileLog('TIMER', `[${username}] ensureSessionForTransfer reached booking-ready in ${Date.now() - sessionStartMs}ms`);

    // Harvest the full session (cookies + storageState + tokens) for later reuse
    // by Transfer Engine v3. Keep this non-blocking and swallow errors.
    try {
      session.fullSession = await harvestFullSession(page, session.context, username);
    } catch (harvestErr) {
      fileLog('WARN', `[${username}] Session harvesting failed (non-fatal): ${harvestErr.message}`);
    }

    // Keep the transfer session alive like a normal booking session: watch the
    // page timer and run hold keepalive so seats do not expire while waiting.
    startPageTimerWatcher(session);
    startHoldKeepalive(session);

    session.state = 'paused';
    emitAccountUpdate(username, 'paused', { url: page.url() });
    emitStatus('paused', 'Transfer session ready. Waiting for transfer signal...', { account: username, url: page.url() });
    return session;
  } catch (err) {
    const errMsg = String(err?.message || err || 'unknown');
    emitStatus('error', `Transfer session preparation failed: ${errMsg}`, { account: username, error: errMsg });
    fileLog('WARN', `[${username}] ensureSessionForTransfer failed: ${errMsg}`);
    try {
      await saveDiagnostics(session?.page, username, 'transfer-error-' + errMsg.replace(/[^a-z0-9]/gi, '_').slice(0, 50));
    } catch {}
    await safeScreenshot(session?.page, 'transfer-error', username);
    try { await session.context?.close(); } catch {}
    session.context = null;
    session.page = null;
    activeSessions.delete(username);
    throw err;
  }
}

/**
 * Launch a session in cycle-mode: it logs in, holds seats, and returns the
 * session object as soon as the seats are held. The browser context stays alive
 * so the pair manager can keep the hold alive or hand it off to a partner.
 */
function runCycleSession(account) {
  return new Promise((resolve, reject) => {
    let resolved = false;
    const options = {
      cycleMode: true,
      onHeld: (session) => {
        if (resolved) return;
        resolved = true;
        resolve(session);
      },
    };

    runSession(account, options).catch(reject);

    // Defensive timeout: if runSession doesn't reach onHeld in 2 minutes, reject.
    setTimeout(() => {
      if (!resolved) {
        resolved = true;
        reject(new Error('runCycleSession timeout: failed to hold seats within 2 minutes'));
      }
    }, 120000);
  });
}

async function waitForProceedSignal(session, timeoutMs = 15 * 60 * 1000) {
  return new Promise(resolve => {
    const timer = timeoutMs > 0 ? setTimeout(() => {
      session.proceedResolve = null;
      emitStatus('proceed-timeout', 'Proceed signal timed out; staying on booking page', { account: session.username });
      resolve('stop');
    }, timeoutMs) : null;
    session.proceedResolve = (value) => {
      session.proceedResolve = null;
      if (timer) clearTimeout(timer);
      resolve(value);
    };
  });
}

// ------------------------------------------------------------------
// Pair Cycling integration (Hold Cycling / Seat Camping)
// ------------------------------------------------------------------
pairManager = createPairCyclingManager({
  runCycleSession,
  releaseHoldsForUser: async (username) => {
    const session = activeSessions.get(username);
    if (session) {
      await releaseHold(session);
      releaseSeats(username);
    }
    await stopSession(username, 'pair-cycle-handoff');
  },
  emitStatus: (stage, message, extra = {}) => {
    emitStatus(stage, message, extra);
    io.emit('pair-cycle-event', { stage, message, ...extra });
    io.emit('pair-cycle-status', pairManager.getStatus());
  },
  emitAccountUpdate,
  fileLog,
  waitFor,
});

async function isChartReady(page) {
  if (!page || await isPageClosed(page)) return false;
  return page.evaluate(() => {
    const text = document.body ? document.body.innerText || '' : '';
    if (text.includes('انتهى الوقت') || text.includes('Session expired')) return false;
    const hasSvg = !!document.querySelector('svg');
    const hasCanvas = !!document.querySelector('canvas');
    const hasChartDiv = !!document.querySelector('#chart, #seat-chart, .seats-chart, [data-testid="seat-chart"]');
    const hasGrecaptcha = !!(window.grecaptcha && (window.grecaptcha.execute || (window.grecaptcha.enterprise && window.grecaptcha.enterprise.execute)));
    const hasSeatcloudIframe = !!document.querySelector('iframe[src*="seatcloud"], iframe[src*="seats.io"], iframe[src*="chart.seatcloud"]');
    return hasSvg || hasCanvas || hasChartDiv || hasGrecaptcha || hasSeatcloudIframe;
  }).catch(() => false);
}

const chartFrameEmitThrottle = new Map(); // username -> lastEmitMs

async function findChartFrame(page, username, opts = {}) {
  if (!page || await isPageClosed(page)) return null;

  const patterns = [
    /seats\.seatcloud\.com/,
    /chart\.seatcloud\.com/,
    /seatcloud\.com/,
    /seats\.io/,
    /chart\.seats\.io/,
    /cdn\.seats\.io/,
    /embedded\.seatcloud\.com/,
    /webook\.seatcloud\.com/,
    /ticket\.seatcloud\.com/,
    /secure\.seatcloud\.com/,
  ];

  // First pass: URL-pattern match without evaluating (fast, safe for closed frames).
  for (const pattern of patterns) {
    const frame = page.frame({ url: pattern });
    if (frame && await isFrameUsable(frame)) {
      emitChartFrameFound(username, pattern, opts);
      return frame;
    }
  }

  // Second pass: prefer frames that actually have grecaptcha/chart object, but
  // only evaluate frames that are still attached.
  const seatcloudFrames = page.frames().filter(f => /seatcloud\.com/.test(f.url() || ''));
  for (const frame of seatcloudFrames) {
    if (!await isFrameUsable(frame)) continue;
    try {
      const hasGrecaptcha = await frame.evaluate(() => !!(
        window.grecaptcha &&
        ((window.grecaptcha.enterprise && window.grecaptcha.enterprise.execute) || window.grecaptcha.execute)
      ));
      if (hasGrecaptcha) {
        emitChartFrameFound(username, 'has grecaptcha', opts);
        return frame;
      }
    } catch {}
  }

  return null;
}

function emitChartFrameFound(username, detail, opts) {
  if (opts && opts.emit === false) return;
  const now = Date.now();
  const last = chartFrameEmitThrottle.get(username) || 0;
  if (now - last < 5_000) return; // throttle to once every 5 seconds per account
  chartFrameEmitThrottle.set(username, now);
  emitStatus('seats-frame-found', `Chart iframe found (${detail})`, { account: username });
}

async function isFrameUsable(frame) {
  if (!frame) return false;
  try {
    // frame.page() throws if the frame has been detached/closed.
    const owner = frame.page();
    if (!owner || (owner.isClosed && owner.isClosed())) return false;
    await frame.evaluate(() => true);
    return true;
  } catch {
    return false;
  }
}

async function ensureChartFrame(page, username, staleFrame = null, opts = {}) {
  // Reuse a stale frame only if it is still attached; otherwise re-discover.
  // This is the central helper that prevents "Target page, context or browser
  // has been closed" crashes when the chart iframe reloads or crashes.
  if (await isFrameUsable(staleFrame)) return staleFrame;
  const maxAttempts = opts.attempts || 3;
  const delayMs = opts.delayMs || 80;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const frame = await findChartFrame(page, username);
    if (await isFrameUsable(frame)) return frame;
    if (attempt < maxAttempts) await waitFor(delayMs);
  }
  return null;
}

async function tryFastHoldViaRoute(page, targetSections, targetCount, username) {
  const routeState = wsRouteRegistry.get(page);
  if (!routeState || !routeState.server || routeState.closed || !routeState.ready) return [];

  const targetSet = targetSections && targetSections.length
    ? new Set(targetSections.map(s => String(s).toUpperCase()))
    : null;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      if (attempt > 1) await waitFor(200);
      emitStatus('seats-fast', `Route ready — fast bestAvailable attempt ${attempt}/3`, { account: username });
      const held = await sendBestAvailableViaRoute(page, targetCount, [], 1_200);
      if (held.length < targetCount) continue;

      if (targetSet) {
        const allInTarget = held.every(s => {
          const sec = String(s).split('-')[0].toUpperCase();
          return targetSet.has(sec);
        });
        if (!allInTarget) {
          emitStatus('seats-fast-wrong', `Route held ${held.length} seats but not in target sections`, { account: username, seats: held });
          continue;
        }
      }
      emitStatus('seats-route-selected', `Fast route held ${held.length} seats`, { account: username, seats: held });
      return held;
    } catch (e) {
      emitStatus('seats-fast-error', e.message, { account: username });
    }
  }
  return [];
}

async function selectSeatsViaWebSocket(page, targetSections, targetCount, username, session = null, forcedToken = null) {
  const accountIndex = session?.accountIndex || 0;
  const wantedCount = Math.max(1, Math.min(parseInt(targetCount, 10) || 30, MAX_HELD_SEATS));
  const holdStartTime = Date.now();

  // Fast iframe acquisition: the chart usually appears within 1-2s of page load,
  // but on client machines with slower networks or when SeatCloud is under load it
  // can take much longer. Use a tight poll initially then back off, allowing up to
  // ~15 seconds before giving up. This directly fixes "الشارت مابيتحملش" reports.
  let frame = null;
  let attempt = 0;
  let reloaded = false;
  const maxAttempts = 300; // up to ~15s
  while (attempt < maxAttempts) {
    attempt++;
    frame = await findChartFrame(page, username);
    if (frame) break;
    try {
      await page.evaluate(() => {
        window.dispatchEvent(new Event('resize'));
        window.dispatchEvent(new Event('scroll'));
      });
    } catch {}
    if (attempt === 80 || attempt === 160 || attempt === 240) {
      emitStatus('seats-no-frame', `Chart iframe not found, retry ${attempt}/${maxAttempts}...`, { account: username });
    }
    // If the iframe still hasn't appeared after ~6s, reload the page once to give
    // the chart another chance to initialize (common on slow client connections).
    if (!reloaded && attempt >= 120) {
      reloaded = true;
      try {
        emitStatus('chart-reload', 'Reloading booking page to retry chart load', { account: username });
        await page.reload({ waitUntil: 'domcontentloaded', timeout: 60000 });
        await dismissAllBanners(page, username, 'post-reload');
      } catch (e) {
        fileLog('WARN', `[${username}] Chart reload failed: ${e.message}`);
      }
    }
    await waitFor(attempt <= 60 ? 10 : (attempt <= 150 ? 30 : 60));
  }
  if (!frame) {
    emitStatus('seats-no-frame', 'Chart iframe not found after retries', { account: username });
    await saveDiagnostics(page, username, 'chart-iframe-missing');
    return [];
  }

  // Log the iframe's own token for diagnosis. When a forced token is in use, the iframe may
  // still carry the logged-in user's token, which is why we avoid chart.selectObjects fallback.
  try {
    const frameUrl = frame.url();
    const frameTokenMatch = frameUrl.match(/[?&](token|hold_token|holdToken)=([^&]+)/);
    const frameToken = frameTokenMatch ? decodeURIComponent(frameTokenMatch[2]) : null;
    fileLog('INFO', `[${username}] Chart iframe URL token: ${frameToken ? frameToken.slice(0, 8) + '...' + frameToken.slice(-4) : 'none'} (forced=${!!forcedToken})`);
  } catch {}

  // Patch chart client limits as soon as the iframe exists.
  try {
    await patchChartLimits(frame, 150, 1200, page, username);
    emitStatus('seats-limits-patched', 'Patched chart hold/selection limits for 30 seats', { account: username });
  } catch (e) {
    emitStatus('seats-limits-warn', `Could not patch chart limits: ${e.message}`, { account: username });
  }

  // Use the page-level WebSocket route immediately instead of waiting for iframe globals.
  emitStatus('seats-waiting-ws', 'Waiting for chart WebSocket route...', { account: username });
  const wsReady = await waitForWsRouteReady(page, 10000);
  if (!wsReady) {
    emitStatus('seats-ws-timeout', 'Chart WebSocket route did not become ready', { account: username });
    await saveDiagnostics(page, username, 'chart-ws-timeout');
    return [];
  }
  emitStatus('seats-ws-ready', 'Chart WebSocket route ready', { account: username });

  // Normalize target sections
  let sections = [];
  if (Array.isArray(targetSections) && targetSections.length > 0) {
    sections = targetSections.map(s => String(s).trim().toUpperCase()).filter(Boolean);
  } else if (targetSections) {
    sections = [String(targetSections).trim().toUpperCase()];
  }

  const chartState = await frame.evaluate(() => ({
    workspaceKey: window.chartState?.workspaceKey || window.currentChartConfig?.workspaceKey,
    eventKey: window.chartState?.eventKey || window.currentChartConfig?.eventKey,
    eventId: window.chartState?.eventId || window.currentChartConfig?.eventId || null,
  }));
  const { workspaceKey, eventKey, eventId } = chartState;
  const pageSlug = parseSlug(page.url());

  // Ensure we have a valid hold token before trying to hold.
  let holdToken = forcedToken || await readChartHoldToken(page, pageSlug, eventId);
  if (!holdToken) {
    emitStatus('seats-token-missing', 'Could not obtain hold token', { account: username });
    return [];
  }
  if (session) {
    session.holdToken = holdToken;
    touchHoldToken(session, holdToken, 15);
    // Prevent two credential sessions from sharing the same hold token, which
    // causes one session's holds to overwrite the other's.
    await ensureUniqueHoldToken(session);
  }
  emitStatus('seats-token', `Seat selection will use hold token ${(session?.holdToken || holdToken).slice(0, 8)}...${(session?.holdToken || holdToken).slice(-4)}${forcedToken ? ' (forced/provided)' : ''}`, { account: username, tokenPrefix: (session?.holdToken || holdToken).slice(0, 8), forced: !!forcedToken });

  // Seats explicitly released by the user must never be auto-re-selected.
  const releasedSet = session?.releasedSeats || new Set();

  // ------------------------------------------------------------------
  // FAST REST PATH: when the caller provided a hold token, the WebSocket
  // connection itself is bound to the logged-in user's token. Use the REST
  // API directly with the provided token and skip the WS flow entirely.
  // NOTE: the SeatCloud REST /actions/hold endpoint currently returns 404
  // for this tenant, so the fast path is skipped to avoid wasting seconds.
  // ------------------------------------------------------------------
  if (false && forcedToken && workspaceKey && eventKey) {
    try {
      emitStatus('seats-rest-fast', 'Validating provided hold token via REST...', { account: username });
      const validation = await validateHoldToken(workspaceKey, eventKey, holdToken);
      fileLog('INFO', `[${username}] hold token validation: valid=${validation.valid}, currentlyHeld=${validation.currentlyHeld}`);
      if (!validation.valid) {
        emitStatus('seats-token-invalid', `Provided hold token rejected: ${validation.reason}`, { account: username });
      }

      emitStatus('seats-rest-fast', 'Fetching seat map for REST hold...', { account: username });
      const items = await fetchSeatcloudItems(workspaceKey, eventKey, session);
      const candidates = [];
      const seen = new Set();
      for (const item of items) {
        if (!item.section || item.availableCount <= 0) continue;
        const sec = String(item.section).toUpperCase();
        if (sections.length && !sections.includes(sec)) continue;
        const label = String(item.label || item.name || item.objectId || item.id || '').trim();
        if (!label) continue;
        if (releasedSet.has(label.toUpperCase())) continue;
        if (seen.has(label)) continue;
        seen.add(label);
        candidates.push(label);
      }

      if (candidates.length) {
        const target = Math.min(wantedCount, candidates.length);
        const toHold = candidates.slice(0, target);
        emitStatus('seats-rest-fast', `Attempting REST hold for ${toHold.length} seat(s)...`, { account: username, seats: toHold });
        const restHeld = await holdSeatsViaRestApi(workspaceKey, eventKey, holdToken, toHold, { username, session });
        if (restHeld.length) {
          fileLog('TIMER', `[${username}] REST fast path held ${restHeld.length}/${target} in ${Date.now() - holdStartTime}ms`);
          emitStatus('seats-rest-held', `REST API held ${restHeld.length}/${target} seat(s)`, { account: username, seats: restHeld });
          // Minimal chart sync if frame exists, but do not block on it.
          if (frame) {
            try { await syncChartSelection(frame, restHeld, { page, username }); } catch {}
          }
          return restHeld.slice(0, wantedCount);
        }
      }
      // If the token already holds MAX_HELD_SEATS seats, it is saturated;
      // don't waste time falling back to WebSocket which will fail the same way.
      if (validation.valid && (validation.currentlyHeld || 0) >= MAX_HELD_SEATS) {
        emitStatus('seats-token-saturated', `Hold token already saturated with ${validation.currentlyHeld} seat(s); no more holds possible`, { account: username, currentlyHeld: validation.currentlyHeld });
        return [];
      }
      emitStatus('seats-rest-fast', 'REST fast path did not hold any seats; falling back to WebSocket', { account: username });
    } catch (e) {
      fileLog('WARN', `[${username}] REST fast path error: ${e.message}`);
      emitStatus('seats-rest-fast', `REST fast path error: ${e.message}; falling back to WebSocket`, { account: username });
    }
  }

  // ------------------------------------------------------------------
  // PHASE 1: One immediate bestAvailable attempt for an instant win.
  // ------------------------------------------------------------------
  let bestEffortHeld = [];
  const heldSet = new Set();

  async function syncAndReturn(seats, reason) {
    const result = seats.slice(0, wantedCount);
    if (frame) {
      try {
        const syncRes = await syncChartSelection(frame, result, { page, username });
        emitStatus('seats-synced', `Chart UI synced with ${syncRes.selectedCount || result.length} held seats`, { account: username, count: syncRes.selectedCount || result.length });
      } catch (e) {
        fileLog('WARN', `[${username}] Chart sync error: ${e.message}`);
      }
    }
    return result;
  }

  function addHeld(seats) {
    const newlyHeld = [];
    for (const s of seats) {
      if (!heldSet.has(s)) {
        heldSet.add(s);
        bestEffortHeld.push(s);
        newlyHeld.push(s);
        // Keep the shared session state in sync so the live WebSocket release
        // listener sees accurate slot counts while this sniper is still running.
        if (session && Array.isArray(session.selectedSeats) && !session.selectedSeats.includes(s)) {
          session.selectedSeats.push(s);
        }
      }
    }
    if (newlyHeld.length > 0) {
      emitSeatEvent('seat-held', username, newlyHeld);
    }
  }

  // Determine the account's preferred section order. When quotas are distributed,
  // we avoid bestAvailable on a section another account is already working on.
  const preferredSections = (session?.sectionQuota?.length ? session.sectionQuota : sections.map(s => ({ section: s, quota: wantedCount })))
    .map(q => String(q.section).toUpperCase())
    .filter((s, i, arr) => arr.indexOf(s) === i);

  try {
    // If every preferred section is contested, skip the global bestAvailable race
    // and go straight to the sniper loop which uses exact labels.
    const safeSections = preferredSections.filter(s => !isSectionContested(s, username) && !isSectionBeingSelected(s, username));
    if (safeSections.length > 0) {
      const fastLocks = [];
      for (const sec of safeSections) {
        const releaseLock = await acquireSectionHoldLock(sec);
        fastLocks.push(releaseLock);
      }
      try {
        emitStatus('seats-fast', `Trying WS bestAvailable for ${wantedCount} seats in non-contested sections...`, { account: username, safeSections });
        const allCategories = safeSections.map(sec => {
          const meta = session?.chartSections?.find(s => s.label.toUpperCase() === sec.toUpperCase());
          if (meta?.virtual && meta.categories?.length) return String(meta.categories[0].categoryKey);
          return sec;
        });
        const fastHeld = await sendBestAvailableViaRoute(page, wantedCount, allCategories, 450, { token: holdToken, speedSettings: session?.speedSettings, session });
        if (fastHeld.length > 0) {
          const uniqueHeld = excludeReservedSeats(fastHeld, username);
          const stolen = fastHeld.length - uniqueHeld.length;
          if (stolen > 0) {
            emitStatus('seats-reserved-conflict', `${stolen} seat(s) already reserved by another account, skipping`, { account: username, seats: fastHeld.filter(s => isSeatReserved(s, username)) });
          }
          if (uniqueHeld.length > 0) {
            reserveSeats(username, uniqueHeld);
            addHeld(uniqueHeld);
          }
          // Filter out any seats the user explicitly released earlier.
          if (releasedSet.size > 0) {
            bestEffortHeld = excludeReleasedSeats(bestEffortHeld, releasedSet);
            heldSet.clear();
            bestEffortHeld.forEach(s => heldSet.add(s));
          }
          // Only stop here if the fast path already satisfied the per-user target.
          // Partial results must continue into the sniper loop so we reach the
          // requested ticket count instead of exiting early.
          if (bestEffortHeld.length >= wantedCount) {
            emitStatus('seats-grabbed', `WS bestAvailable reached target ${bestEffortHeld.length}/${wantedCount} seats in ${Date.now() - holdStartTime}ms`, { account: username, seats: bestEffortHeld });
            return await syncAndReturn(bestEffortHeld, 'fast-bestAvailable');
          }
        }
      } finally {
        for (const release of fastLocks) release();
      }
    } else {
      emitStatus('seats-fast-skip', `Skipping global bestAvailable; all preferred sections are contested by other accounts`, { account: username, preferredSections });
    }
  } catch (e) {
    emitStatus('seats-fast-error', `WS bestAvailable failed: ${e.message}`, { account: username });
  }

  // ------------------------------------------------------------------
  // PHASE 2: Sniper loop — keep re-fetching the seat map and grabbing
  // any seat that appears until we hit wantedCount or the session is stopped.
  // The loop is intentionally target-driven rather than time-driven so the bot
  // aggressively fills the user's requested ticket count (up to 30 seats).
  // ------------------------------------------------------------------
  const speed = getSpeedSettings(session?.speedSettings);
  const sniperStart = Date.now();
  // Absolute safety net: 10 minutes total, plus a 2-minute bail-out if zero
  // seats have been held at all (effectively sold out). These are only escape
  // hatches; the normal loop continues until bestEffortHeld.length === wantedCount.
  const sniperAbsoluteMaxMs = 600_000;
  const emptyGiveUpMs = 120_000;
  let lastItems = [];

  while (bestEffortHeld.length < wantedCount && !(session && (session.stopRequested || session.bookingPaused || session.isTransferring))) {
    if (Date.now() - sniperStart > sniperAbsoluteMaxMs) break;
    if (bestEffortHeld.length === 0 && Date.now() - sniperStart > emptyGiveUpMs) break;
    const stillNeed = wantedCount - bestEffortHeld.length;
    emitStatus('seats-monitoring', `Sniper monitoring — need ${stillNeed} more seat(s)`, { account: username, held: bestEffortHeld.length, wanted: wantedCount });

    let items = [];
    try {
      // Use the shared sniper cache so concurrent accounts sniping the same event
      // do not each pay the ~700ms API fetch cost.
      const cacheKey = `${workspaceKey}:${eventKey}`;
      items = await getCachedItems(cacheKey, () => fetchSeatcloudItems(workspaceKey, eventKey, session), true);
      lastItems = items;
    } catch (e) {
      fileLog('WARN', `[${username}] Seat map fetch failed: ${e.message}`);
      await waitFor(100);
      continue;
    }

    if (items.length === 0) {
      await waitFor(250);
      continue;
    }

    if (sections.length === 0) {
      sections = [...new Set(items.map(i => i.section).filter(Boolean))].sort();
    }

    // Build live availability map.
    const availability = {};
    for (const item of items) {
      if (!item.section) continue;
      const sec = String(item.section).toUpperCase();
      availability[sec] = (availability[sec] || 0) + (item.availableCount > 0 ? item.availableCount : 0);
    }

    // Strict mode: only use the sections the user explicitly selected.
    const effectiveSections = sections;

    const sectionQuota = session?.sectionQuota;
    const rawSectionTargets = (Array.isArray(sectionQuota) && sectionQuota.length > 0)
      ? sectionQuota.map(q => ({ section: String(q.section).toUpperCase(), quota: Math.max(1, parseInt(q.quota, 10) || wantedCount) }))
      : effectiveSections.map(s => ({ section: s, quota: wantedCount }));

    // Expand virtual ticket-category sections (e.g. "C") into real chart sections
    // that share the same seats.io category key.
    function expandVirtualSection(label) {
      const meta = session?.chartSections?.find(s => s.label.toUpperCase() === label.toUpperCase());
      if (!meta?.virtual || !meta.categories?.length) return [label];
      const catKeys = new Set(meta.categories.map(c => String(c.categoryKey)));
      const realSections = [...new Set(items.filter(i => catKeys.has(String(i.specificationKey)) && i.section).map(i => String(i.section).toUpperCase()))];
      return realSections.length ? realSections : [label];
    }

    const sectionTargets = [];
    for (const t of rawSectionTargets) {
      const expanded = expandVirtualSection(t.section);
      const perSectionQuota = Math.max(1, Math.ceil(t.quota / expanded.length));
      for (const sec of expanded) {
        sectionTargets.push({ section: sec, quota: perSectionQuota, originalLabel: t.section });
      }
    }

    let anyAttemptThisScan = false;

    for (const { section: sectionLabel, quota: sectionQuotaVal, originalLabel } of sectionTargets) {
      if (session && (session.stopRequested || session.bookingPaused)) break;
      const sectionNeed = Math.min(sectionQuotaVal, wantedCount - bestEffortHeld.length);
      if (sectionNeed <= 0) break;

      // Snipe via bestAvailable first (single fast WS call) only when no other
      // active account is already working this section. This eliminates the race
      // where two bestAvailable calls return overlapping seats.
      try {
        const sectionNorm = String(sectionLabel).toUpperCase();
        const availableInSection = availability[sectionNorm] || 0;
        const contested = isSectionContested(sectionNorm, username) || isSectionBeingSelected(sectionNorm, username);
        if (availableInSection > 0 && !contested) {
          const releaseLock = await acquireSectionHoldLock(sectionNorm);
          try {
            // For virtual sections use the seats.io category key; otherwise use the section label.
            const originalMeta = session?.chartSections?.find(s => s.label.toUpperCase() === (originalLabel || sectionLabel).toUpperCase());
            const bestAvailableCategory = (originalMeta?.virtual && originalMeta.categories?.length)
              ? String(originalMeta.categories[0].categoryKey)
              : String(sectionLabel);
            emitStatus('seats-sniping', `Sniping ${sectionNeed} seat(s) in ${sectionLabel} via bestAvailable...`, { account: username });
            anyAttemptThisScan = true;
            const held = await sendBestAvailableViaRoute(page, sectionNeed, [bestAvailableCategory], 600, { token: holdToken, speedSettings: session?.speedSettings, session });
            if (held.length > 0) {
              // If another account in the same run already reserved some of these seats,
              // drop the overlapping ones and keep sniping. This prevents two accounts
              // from fighting over the same bestAvailable result.
              const uniqueHeld = excludeReservedSeats(held, username);
              const stolen = held.length - uniqueHeld.length;
              if (stolen > 0) {
                emitStatus('seats-reserved-conflict', `${stolen} seat(s) already reserved by another account, skipping`, { account: username, seats: held.filter(s => isSeatReserved(s, username)) });
              }
              if (uniqueHeld.length > 0) {
                reserveSeats(username, uniqueHeld);
                addHeld(uniqueHeld);
                emitStatus('seats-grabbed', `Sniped ${uniqueHeld.length} seat(s) in ${sectionLabel}`, { account: username, seats: uniqueHeld });
              }
              if (bestEffortHeld.length >= wantedCount) break;
              continue;
            }
          } finally {
            releaseLock();
          }
        } else if (contested) {
          emitStatus('seats-sniping-skip', `Skipping bestAvailable in ${sectionLabel}; section is contested by another account`, { account: username, section: sectionLabel });
        }
      } catch (e) {
        fileLog('WARN', `[${username}] bestAvailable snipe error in ${sectionLabel}: ${e.message}`);
      }

      // Fallback: hold specific seat groups in a tight burst.
      const releasedSet = session?.releasedSeats || new Set();
      let candidates = buildCandidateGroups(items, sectionLabel, sectionNeed);
      const sec = String(sectionLabel).toUpperCase();
      const allAvailable = items
        .filter(i => i && i.section && String(i.section).toUpperCase() === sec && i.availableCount > 0)
        .map(i => i.name);

      if (candidates.length === 0 && allAvailable.length > 0) {
        fileLog('INFO', `[${username}] Fallback: taking all ${allAvailable.length} available ${sectionLabel} labels`);
        candidates = [allAvailable];
      }

      if (candidates.length === 0) continue;

      candidates = candidates
        .map(seats => excludeReservedSeats(seats, username))
        .map(seats => excludeReleasedSeats(seats, releasedSet))
        .filter(seats => seats.length > 0);

      if (candidates.length === 0) continue;

      // Flatten candidates and apply a per-account offset so concurrent accounts
      // do not all start from the same first available seat.
      const flattened = [];
      const seenFlatten = new Set();
      for (const group of candidates) {
        for (const s of group) {
          if (seenFlatten.has(s)) continue;
          seenFlatten.add(s);
          flattened.push(s);
        }
      }
      const offset = (accountIndex || 0) % Math.max(1, flattened.length);
      const rotated = [...flattened.slice(offset), ...flattened.slice(0, offset)];

      const seatsToHold = [];
      const seen = new Set();
      for (const s of rotated) {
        if (seatsToHold.length >= sectionNeed) break;
        if (!seen.has(s) && !heldSet.has(s)) {
          seen.add(s);
          seatsToHold.push(s);
        }
      }

      if (seatsToHold.length === 0) continue;

      // Reserve seats atomically before sending the hold frames so another account
      // does not pick the same candidates in the same millisecond.
      reserveSeats(username, seatsToHold);

      const releaseLock = await acquireSectionHoldLock(sectionLabel);
      try {
        anyAttemptThisScan = true;
        emitStatus('seats-holding', `Sending ${seatsToHold.length} individual hold frames in ${sectionLabel} (fast burst)...`, { account: username });
        let held = await sendHoldViaRoute(page, seatsToHold, { fastMode: true, timeoutMs: speed.sniperTimeoutMs, gapMs: speed.sniperBurstGapMs, username, token: holdToken, speedSettings: session?.speedSettings, session });

        // Release reservations for seats that did not actually get held.
        const heldSetResult = new Set(held.map(String));
        for (const s of seatsToHold) {
          if (!heldSetResult.has(String(s))) releaseSeatFromPool(s);
        }
        fileLog('INFO', `[${username}] Fast burst WS hold result: ${held.length}/${seatsToHold.length} held in ${sectionLabel}`);

        if (held.length === 0 && frame) {
          emitStatus('seats-frame-fallback', `WS hold empty; trying chart.selectObjects in ${sectionLabel}`, { account: username });
          const frameRes = await sendHoldViaFrame(frame, seatsToHold, forcedToken ? { token: forcedToken, page, username } : { page, username });
          if (frameRes.ok && frameRes.sent.length > 0) {
            const ht = forcedToken || holdToken || await readChartHoldToken(page, pageSlug);
            if (ht) {
              const verified = await verifyHeldSeatsViaApi(page, ht, seatsToHold, { session });
              held = verified.length > 0 ? verified : frameRes.sent;
            } else {
              held = frameRes.sent;
            }
          }
        }

        addHeld(held);

        if (held.length > 0) {
          emitStatus('seats-grabbed', `Held ${held.length} seat(s) in ${sectionLabel}`, { account: username, seats: held });
        }
      } finally {
        releaseLock();
      }

      if (bestEffortHeld.length >= wantedCount) break;
    }

    if (bestEffortHeld.length >= wantedCount) break;

    // Adaptive scan delay: shorter if we just attempted something, longer if nothing is available.
    // If WebSocket traffic just reported released seats in our monitored sections, re-scan almost immediately.
    const recentReleases = getRecentReleasedSeats(page, 2000);
    const releaseRelevant = recentReleases.some(r => {
      const sec = String(r).split('-')[0].toUpperCase();
      return sections.length === 0 || sections.includes(sec);
    });
    if (releaseRelevant) {
      emitStatus('ws-seat-released', `Released seats detected via WebSocket; re-scanning immediately`, { account: username, seats: recentReleases });
      await waitFor(15);
    } else {
      await waitFor(anyAttemptThisScan ? 100 : 250);
    }
  }

  if (bestEffortHeld.length > 0) {
    if (releasedSet.size > 0) {
      bestEffortHeld = excludeReleasedSeats(bestEffortHeld, releasedSet);
    }
    fileLog('TIMER', `[${username}] selectSeatsViaWebSocket completed in ${Date.now() - holdStartTime}ms -> ${bestEffortHeld.length}/${wantedCount}`);
    emitStatus(bestEffortHeld.length >= wantedCount ? 'seats-selected' : 'seats-partial', `Sniper held ${bestEffortHeld.length}/${wantedCount} seats`, { account: username, seats: bestEffortHeld });
    return await syncAndReturn(bestEffortHeld, 'sniper-loop');
  }

  // Experimental REST API fallback before giving up.
  // NOTE: disabled because the tenant's SeatCloud /actions/hold endpoint
  // returns 404; the WebSocket path is the working one.
  if (false) {
    try {
      if (workspaceKey && eventKey && holdToken) {
        emitStatus('seats-rest-try', 'Trying REST API hold fallback...', { account: username });
        const restHeld = await holdSeatsViaRestApi(workspaceKey, eventKey, holdToken, wanted, { username, session });
        if (restHeld.length) {
          for (const s of restHeld) if (!heldSet.has(s)) { heldSet.add(s); bestEffortHeld.push(s); }
          fileLog('TIMER', `[${username}] selectSeatsViaWebSocket REST fallback held ${restHeld.length} in ${Date.now() - holdStartTime}ms`);
          emitStatus('seats-rest-held', `REST API fallback held ${restHeld.length} seat(s)`, { account: username, seats: restHeld });
          return await syncAndReturn(bestEffortHeld, 'rest-api-fallback');
        }
      }
    } catch (e) {
      fileLog('WARN', `[${username}] REST API hold fallback error: ${e.message}`);
    }
  }

  fileLog('TIMER', `[${username}] selectSeatsViaWebSocket failed after ${Date.now() - holdStartTime}ms`);
  emitStatus('seats-hold-failed', 'All hold attempts failed', { account: username });
  return [];
}

/**
 * Hold an exact list of seat labels through the chart WebSocket.
 * Used by pair-cycling handoffs so the next user in a pair can take over
 * the same seats before the previous user releases them.
 */
async function holdSpecificSeatsViaWebSocket(page, seatLabels, username, session) {
  if (!Array.isArray(seatLabels) || seatLabels.length === 0) return [];
  const handoffStart = Date.now();
  const wanted = [...new Set(seatLabels.map(String).filter(Boolean))].slice(0, MAX_HELD_SEATS);
  const speed = getSpeedSettings(session?.speedSettings);

  // Quick chart-frame acquisition; rely on findChartFrame polling instead of a long spin-wait.
  const frame = await findChartFrame(page, username);
  emitStatus('seats-holding', `Sending ${wanted.length} individual hold frames (handoff)...`, { account: username });
  const held = await sendHoldViaRoute(page, wanted, { fastMode: true, timeoutMs: speed.sniperTimeoutMs, gapMs: speed.sniperBurstGapMs, username, token: session?.holdToken, speedSettings: session?.speedSettings, session });

  if (held.length === 0 && frame) {
    emitStatus('seats-frame-fallback', 'WS hold empty; trying chart.selectObjects for handoff', { account: username });
    const frameRes = await sendHoldViaFrame(frame, wanted, { token: session?.holdToken, page, username });
    if (frameRes.ok && frameRes.sent.length > 0) {
      const ht = await readChartHoldToken(page, parseSlug(page.url()));
      if (ht) {
        const verified = await verifyHeldSeatsViaApi(page, ht, wanted, { session });
        if (verified.length > 0) {
          if (session) session.selectedSeats = verified;
          emitSeatEvent('seat-held', username, verified, { source: 'holdSpecificSeatsViaWebSocket-frame-verified' });
          fileLog('TIMER', `[${username}] holdSpecificSeatsViaWebSocket (frame fallback) completed in ${Date.now() - handoffStart}ms -> ${verified.length}/${wanted.length}`);
          await syncChartSelection(frame, verified, { page, username });
          return verified;
        }
      }
      if (session) session.selectedSeats = frameRes.sent;
      emitSeatEvent('seat-held', username, frameRes.sent, { source: 'holdSpecificSeatsViaWebSocket-frame-sent' });
      fileLog('TIMER', `[${username}] holdSpecificSeatsViaWebSocket (frame sent) completed in ${Date.now() - handoffStart}ms -> ${frameRes.sent.length}/${wanted.length}`);
      await syncChartSelection(frame, frameRes.sent, { page, username });
      return frameRes.sent;
    }
  }

  if (held.length > 0) {
    if (session) session.selectedSeats = held;
    emitSeatEvent('seat-held', username, held, { source: 'holdSpecificSeatsViaWebSocket' });
    if (frame) {
      try {
        const syncRes = await syncChartSelection(frame, held, { page, username });
        emitStatus('seats-synced', `Chart UI synced with ${syncRes.selectedCount || held.length} held seats`, { account: username, count: syncRes.selectedCount || held.length });
      } catch (e) {
        fileLog('WARN', `[${username}] Chart sync error: ${e.message}`);
      }
    }
  }

  fileLog('TIMER', `[${username}] holdSpecificSeatsViaWebSocket completed in ${Date.now() - handoffStart}ms -> ${held.length}/${wanted.length}`);
  return held;
}

async function getSelectedFromChart(frame) {
  try {
    const labels = await frame.evaluate(() => {
      const chart = window.chartRender || window.chart;
      if (chart && typeof chart.getSelectedObjects === 'function') {
        try {
          const objs = chart.getSelectedObjects();
          if (Array.isArray(objs)) {
            return objs.map(o => typeof o === 'string' ? o : (o.label || o.objectId || o.id || '')).filter(Boolean);
          }
        } catch {}
      }
      const sel = window.chartState?.selectedObjects || window.chartRender?.selectedObjects || window.chart?.selectedObjects;
      if (Array.isArray(sel)) {
        return sel.map(o => typeof o === 'string' ? o : (o.label || o.objectId || o.id || '')).filter(Boolean);
      }
      return [];
    });
    return labels || [];
  } catch (e) {
    return [];
  }
}

function buildCandidateGroups(items, sectionLabel, targetCount) {
  const sec = String(sectionLabel).toUpperCase();
  if (!Array.isArray(items)) {
    fileLog('WARN', `buildCandidateGroups: items is not an array (${typeof items})`);
    return [];
  }
  let available = items
    .filter(i => i && i.section && String(i.section).toUpperCase() === sec && i.availableCount > 0)
    .map(i => i.name);
  if (available.length === 0) {
    available = items
      .filter(i => i && i.section && String(i.section).toUpperCase().startsWith(sec) && i.availableCount > 0)
      .map(i => i.name);
  }
  fileLog('INFO', `buildCandidateGroups(${sec}): ${available.length}/${targetCount} available`);
  if (available.length === 0) return [];

  // Sort all available seats by row then seat number for deterministic fallback
  const parseSeat = name => {
    const parts = name.split('-');
    const seat = parseInt(parts[parts.length - 1], 10);
    const row = parts[parts.length - 2];
    return { name, row, seat };
  };
  const sortedAvailable = available
    .map(parseSeat)
    .sort((a, b) => a.row.localeCompare(b.row) || a.seat - b.seat);

  const candidates = [];
  const candidateSet = new Set();
  const add = (seats) => {
    const key = seats.join('|');
    if (candidateSet.has(key)) return;
    candidateSet.add(key);
    candidates.push(seats);
  };

  // Contiguous seats per row
  const byRow = {};
  for (const { name, row, seat } of sortedAvailable) {
    byRow[row] = byRow[row] || [];
    byRow[row].push({ name, seat });
  }
  for (const row of Object.keys(byRow)) {
    const sorted = byRow[row].sort((a, b) => a.seat - b.seat);
    if (sorted.length >= targetCount) {
      for (let i = 0; i <= sorted.length - targetCount; i++) {
        const run = sorted.slice(i, i + targetCount);
        const contiguous = run.every((s, idx) => idx === 0 || s.seat === run[idx - 1].seat + 1);
        if (contiguous) add(run.map(s => s.name));
      }
    } else if (sorted.length > 0) {
      // Partial contiguous row: remember it as a candidate even if shorter than target.
      add(sorted.map(s => s.name));
    }
  }

  // Multi-row fallback: take blocks from adjacent rows when no single row has enough contiguous seats.
  const rows = Object.keys(byRow).sort();
  for (let r = 0; r < rows.length; r++) {
    let collected = [];
    for (let k = r; k < rows.length && collected.length < targetCount; k++) {
      const rowSeats = byRow[rows[k]].sort((a, b) => a.seat - b.seat).map(s => s.name);
      collected = collected.concat(rowSeats);
      if (collected.length > 0) {
        add(collected.slice(0, targetCount));
      }
    }
  }

  // Best-effort fallback: the first N seats sorted by row/seat (may be partial)
  add(sortedAvailable.slice(0, targetCount).map(s => s.name));

  return candidates;
}

async function patchChartLimits(frame, repeatMs = 500, durationMs = 10000, page = null, username = '') {
  const start = Date.now();
  const LIMIT_VALUE = 150;
  const script = () => {
    const setLimit = (obj, keys, value = LIMIT_VALUE) => {
      if (!obj || typeof obj !== 'object') return;
      for (const key of keys) {
        if (key in obj) {
          if (typeof obj[key] === 'number') obj[key] = value;
          else if (typeof obj[key] === 'string') obj[key] = String(value);
        }
      }
      if (Array.isArray(obj.maxSelectedObjects)) {
        for (const entry of obj.maxSelectedObjects) {
          if (entry && typeof entry === 'object') {
            if (typeof entry.quantity === 'number') entry.quantity = value;
            if (typeof entry.total === 'number') entry.total = value;
          }
        }
      }
    };
    const patchChartMethods = (chart) => {
      if (!chart || chart.__kimikoRuntimePatched) return;
      chart.__kimikoRuntimePatched = true;
      const methods = ['selectObjects','selectObject','deselectObjects','deselectObject','render','redraw','draw','rerender'];
      for (const method of methods) {
        if (typeof chart[method] !== 'function' || chart[method].__kimikoPatched) continue;
        const orig = chart[method];
        chart[method] = function (...args) {
          setLimit(chart.state);
          setLimit(chart.config);
          setLimit(chart.options);
          return orig.apply(this, args);
        };
        chart[method].__kimikoPatched = true;
      }
    };
    const keys = ['maxNumberOfHolds','maxSelectedObjects','maxNumberOfSelectedObjects','maxObjects','maxSeats','selectionLimit','holdLimit','maxHold','maxSelection','maxPerOrder','max_per_order','maxTickets','maxTicketCount','ticketLimit','purchaseLimit','event_order_limit','season_order_limit','order_limit'];
    setLimit(window.chartState, keys);
    setLimit(window.currentChartConfig, keys);
    setLimit(window.seatsioConfig, keys);
    setLimit(window.seatsio?.config, keys);
    const targets = [window.chartRender, window.chart, window.SeatsChart, (window.seatsio && window.seatsio.chart)];
    for (const chart of targets) {
      if (!chart) continue;
      setLimit(chart.state, keys);
      setLimit(chart.config, keys);
      setLimit(chart._config, keys);
      setLimit(chart.options, keys);
      if (chart.state) {
        if (!Array.isArray(chart.state.selectedObjects)) chart.state.selectedObjects = [];
        if (typeof chart.state._selectionCount === 'number') chart.state._selectionCount = 0;
        if (typeof chart.state._holdCount === 'number') chart.state._holdCount = 0;
        if (typeof chart.state.heldCount === 'number') chart.state.heldCount = 0;
      }
      patchChartMethods(chart);
    }
    // Hook the constructor if it exists and is not already patched.
    if (typeof window.__kimikoChartLimitPatch === 'object' && typeof window.__kimikoChartLimitPatch.hookConstructor === 'function') {
      window.__kimikoChartLimitPatch.hookConstructor();
    }
    return {
      patched: true,
      seatsioPresent: typeof window.seatsio === 'object' && typeof window.seatsio?.SeatingChart === 'function',
      constructorPatched: !!(window.seatsio?.SeatingChart?.__kimikoPatched),
      chartObject: !!(window.chartRender || window.chart || window.SeatsChart),
    };
  };

  let lastResult = null;
  let currentFrame = frame;
  while (Date.now() - start < durationMs) {
    currentFrame = await ensureChartFrame(page, username, currentFrame, { attempts: 2, delayMs: 60 });
    if (!currentFrame) {
      await waitFor(repeatMs);
      continue;
    }
    try {
      lastResult = await currentFrame.evaluate(script);
      if (lastResult && lastResult.seatsioPresent && lastResult.constructorPatched) {
        return lastResult;
      }
    } catch (e) {
      fileLog('WARN', `patchChartLimits iframe eval error: ${e.message}`);
      currentFrame = null; // force re-discovery on next tick
    }
    await waitFor(repeatMs);
  }
  return lastResult || { patched: false };
}

async function broadcastHoldTokenToIframe(page, token, username = '') {
  // Some SeatCloud chart builds read the token from parent.postMessage instead
  // of window.holdToken. Broadcast it to every SeatCloud iframe we can find.
  try {
    await page.evaluate((token) => {
      const iframes = Array.from(document.querySelectorAll('iframe[src*="seatcloud"], iframe[src*="chart.seatcloud"], iframe[src*="seats.io"]'));
      for (const iframe of iframes) {
        try {
          iframe.contentWindow.postMessage({ type: 'kimiko-set-hold-token', holdToken: token, token }, '*');
        } catch {}
      }
    }, token);
    fileLog('DEBUG', `[${username}] Broadcast hold token to ${(await page.evaluate(() => document.querySelectorAll('iframe[src*="seatcloud"], iframe[src*="chart.seatcloud"], iframe[src*="seats.io"]').length))} iframe(s)`);
  } catch (e) {
    fileLog('DEBUG', `[${username}] broadcastHoldTokenToIframe error: ${e.message}`);
  }
}

async function patchChartIframeToken(page, token, username = '') {
  // Try to reload the chart iframe with the provided hold token so the chart's
  // own WebSocket connects with that token. This keeps the frame fallback working
  // for holdToken accounts without falling back to the logged-in user's token.
  try {
    // Broadcast token via postMessage first (non-destructive).
    await broadcastHoldTokenToIframe(page, token, username);

    const frame = await findChartFrame(page, username);
    if (!frame) return false;
    const url = new URL(frame.url());
    let changed = false;
    for (const key of ['token', 'holdToken', 'hold_token']) {
      if (url.searchParams.has(key)) {
        url.searchParams.set(key, token);
        changed = true;
      }
    }
    if (!changed) {
      // The iframe URL may not carry the token in the query string; the chart JS
      // reads it from window.parent or a postMessage. Nothing more to patch here.
      return false;
    }

    // Try setting the iframe src via the parent page (same-origin policy may block
    // cross-origin iframe src writes, but SeatCloud iframes are usually sandboxed).
    const setSrc = await page.evaluate(async (newSrc, selector) => {
      const iframe = document.querySelector('iframe');
      if (!iframe) return { ok: false, reason: 'no-iframe' };
      try {
        iframe.src = newSrc;
        return { ok: true };
      } catch (e) {
        return { ok: false, reason: e.message };
      }
    }, url.toString()).catch(() => ({ ok: false, reason: 'eval-failed' }));

    if (setSrc.ok) {
      emitStatus('iframe-token-patched', `Chart iframe reloaded with provided token`, { account: username, tokenPrefix: token.slice(0, 8) });
      // Give the iframe a moment to reconnect.
      await waitFor(400);
      return true;
    }
    fileLog('WARN', `[${username}] Could not patch iframe src: ${setSrc.reason}`);
    return false;
  } catch (e) {
    fileLog('WARN', `[${username}] patchChartIframeToken error: ${e.message}`);
    return false;
  }
}

async function sendHoldViaFrame(frame, seats, wsParams = {}) {
  // Use the chart's native selectObjects() API. The chart sends hold-object WS
  // frames internally. We send seats one-by-one so any frontend limit cannot
  // silently drop seats, and we patch limits again immediately before.
  const forcedToken = wsParams.token || null;
  const page = wsParams.page || null;
  const username = wsParams.username || '';

  let currentFrame = await ensureChartFrame(page, username, frame, { attempts: 2, delayMs: 60 });
  if (!currentFrame) {
    fileLog('WARN', `sendHoldViaFrame skipped: chart frame not available`);
    return { ok: false, sent: [], error: 'chart frame not available' };
  }

  let attempts = 0;
  while (attempts < 2) {
    attempts++;
    try {
      const result = await currentFrame.evaluate(async ({ seats, forcedToken }) => {
    const chart = window.chartRender || window.chart || window.SeatsChart || (window.seatsio && window.seatsio.chart);
    if (!chart || typeof chart.selectObjects !== 'function') {
      return { ok: false, sent: [], error: 'chart.selectObjects not available' };
    }

    // Aggressively unlock limits right before selecting.
    try {
      const keys = ['maxNumberOfHolds','maxSelectedObjects','maxNumberOfSelectedObjects','maxObjects','maxSeats','selectionLimit','holdLimit','maxHold','maxSelection','maxPerOrder','max_per_order','maxTickets','maxTicketCount','ticketLimit','purchaseLimit','event_order_limit','season_order_limit','order_limit'];
      const patch = (obj, value = 100) => {
        if (!obj || typeof obj !== 'object') return;
        for (const k of keys) {
          if (k in obj) {
            if (typeof obj[k] === 'number') obj[k] = value;
            else if (typeof obj[k] === 'string') obj[k] = String(value);
          }
        }
        if (Array.isArray(obj.maxSelectedObjects)) {
          for (const entry of obj.maxSelectedObjects) {
            if (entry && typeof entry === 'object') {
              if (typeof entry.quantity === 'number') entry.quantity = value;
              if (typeof entry.total === 'number') entry.total = value;
            }
          }
        }
      };
      patch(window.chartState);
      patch(window.currentChartConfig);
      patch(window.seatsioConfig);
      patch(window.seatsio?.config);
      patch(window.chartRender?.state);
      patch(window.chartRender?.config);
      patch(window.chartRender?._config);
      patch(window.chartRender?.options);
      patch(window.chart?.state);
      patch(window.chart?.config);
      patch(window.chart?._config);
      patch(window.chart?.options);
      if (chart.state) {
        if (typeof chart.state._selectionCount === 'number') chart.state._selectionCount = 0;
        if (typeof chart.state._holdCount === 'number') chart.state._holdCount = 0;
        if (typeof chart.state.heldCount === 'number') chart.state.heldCount = 0;
        if (!Array.isArray(chart.state.selectedObjects)) chart.state.selectedObjects = [];
      }

      // If a forced token is supplied, patch it into the chart state/config so the
      // chart's internal hold-object frames use the provided token instead of the
      // iframe's original (logged-in user's) token.
      if (forcedToken) {
        const patchToken = (obj) => {
          if (!obj || typeof obj !== 'object') return;
          if ('holdToken' in obj) obj.holdToken = forcedToken;
          if ('token' in obj) obj.token = forcedToken;
          if ('hold_token' in obj) obj.hold_token = forcedToken;
        };
        patchToken(window.chartState);
        patchToken(window.currentChartConfig);
        patchToken(window.seatsioConfig);
        patchToken(window.seatsio?.config);
        patchToken(window.chartRender?.state);
        patchToken(window.chartRender?.config);
        patchToken(window.chartRender?._config);
        patchToken(window.chart?.state);
        patchToken(window.chart?.config);
        patchToken(window.chart?._config);
        // Seats.io stores the session token in chart._token or chart.token sometimes.
        patchToken(chart);
        patchToken(chart.state);
        patchToken(chart.config);
        patchToken(chart._config);
      }
    } catch {}

    const sent = [];
    // Prefer the bulk prompt-aware API; fall back to one-by-one if unavailable.
    if (typeof chart.trySelectObjects === 'function') {
      try {
        await chart.trySelectObjects(seats);
        // Use listSelectedObjects when available for authoritative confirmation.
        if (typeof chart.listSelectedObjects === 'function') {
          const selected = await chart.listSelectedObjects();
          for (const obj of selected) {
            const label = obj?.label || obj?.objectId || obj?.id;
            if (label) sent.push(String(label));
          }
        } else {
          sent.push(...seats);
        }
        return { ok: true, sent };
      } catch (e) {
        fileLog('WARN', `trySelectObjects bulk failed: ${e.message}; falling back to one-by-one`);
      }
    }
    for (const label of seats) {
      try {
        chart.selectObjects([label]);
        sent.push(label);
      } catch (e) {
        return { ok: false, sent, error: e.message };
      }
      await new Promise(r => setTimeout(r, 60));
    }
    return { ok: true, sent };
  }, { seats, forcedToken });
      return result;
    } catch (error) {
      fileLog('WARN', `sendHoldViaFrame caught a crash securely (attempt ${attempts}): ${error.message}`);
      if (attempts < 2 && page && username) {
        currentFrame = await ensureChartFrame(page, username, null, { attempts: 2, delayMs: 80 });
        if (currentFrame) continue;
      }
      return { ok: false, sent: [], error: error.message };
    }
  }
  return { ok: false, sent: [], error: 'frame retry exhausted' };
}

async function syncChartSelection(frame, seats, opts = {}) {
  // After WebSocket holds succeed, force the chart to render those seats as selected.
  // Strategy:
  //   1) Locate the chart iframe automatically if only page/username are provided.
  //   2) Patch limits and call chart.selectObjects() via the official API.
  //   3) Inject held seats directly into the renderer state
  //      (Bn.renderState.selectedSeats Map + selectedObjects/heldObjects arrays).
  //   4) Trigger every known native redraw path so the chart repaints immediately.
  //   5) Guaranteed SVG/DOM overlay fallback (.kimiko-held + checkmark) so seats
  //      light up in green even if the renderer state is temporarily out of sync.
  const timeoutMs = opts.timeoutMs || 6000;
  const start = Date.now();
  const page = opts.page || null;
  const username = opts.username || '';

  if (!Array.isArray(seats) || seats.length === 0) return { ok: false, error: 'no seats' };

  // Auto-discover the chart frame if not passed explicitly.
  let frameRef = frame;
  if (!frameRef || !(await isFrameUsable(frameRef))) {
    if (!page) return { ok: false, error: 'no page to locate chart frame' };
    frameRef = await ensureChartFrame(page, username, frameRef, { attempts: 5, delayMs: 80 });
  }
  if (!frameRef || !(await isFrameUsable(frameRef))) {
    // Last resort: refresh the parent page's chart iframe so a frame becomes available.
    if (page && !page.isClosed()) {
      try {
        await page.evaluate(() => {
          const iframe = document.querySelector('iframe[src*="seatcloud"], iframe[src*="seats.io"], iframe[src*="chart.seatcloud"]');
          if (iframe && iframe.src) iframe.src = iframe.src;
        });
        await waitFor(300);
        frameRef = await ensureChartFrame(page, username, null, { attempts: 5, delayMs: 100 });
      } catch {}
    }
  }
  if (!frameRef || !(await isFrameUsable(frameRef))) return { ok: false, error: 'no chart frame' };

  // Ensure server-side limit patch is active before we manipulate the iframe.
  try {
    await patchChartLimits(frameRef, 300, Math.min(timeoutMs, 3000), page, username);
  } catch (e) {
    fileLog('WARN', `syncChartSelection patchChartLimits warning: ${e.message}`);
  }

  return frameRef.evaluate(async ({ seats, timeoutMs, start }) => {
    function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
    function remaining() { return timeoutMs - (Date.now() - start); }

    // Robust chart discovery across all known global names.
    function findChart() {
      const candidates = [
        window.chartRender,
        window.chart,
        window.SeatsChart,
        window.seatsio?.chart,
        window.seatsio?.SeatingChart?.instance,
        window.__chartInstance,
        window._chart,
        window.chartInstance,
      ];
      for (const c of candidates) {
        if (c && (typeof c.selectObjects === 'function' || typeof c.getSelectedObjects === 'function' || typeof c.redraw === 'function')) return c;
      }
      // Some builds attach the chart to a seatsio global after a delay.
      if (window.seatsio && typeof window.seatsio === 'object') {
        for (const key of Object.keys(window.seatsio)) {
          const c = window.seatsio[key];
          if (c && (typeof c.selectObjects === 'function' || typeof c.redraw === 'function')) return c;
        }
      }
      return null;
    }

    function findRenderState() {
      return window.Bn?.renderState
        || window.renderState
        || window.__renderState
        || window.seatsio?.renderState
        || chart?.state
        || window.chartState;
    }

    const chart = findChart();
    const renderState = findRenderState();
    if (!chart && !renderState) return { ok: false, error: 'no chart' };

    const LIMIT_KEYS = ['maxNumberOfHolds','maxSelectedObjects','maxNumberOfSelectedObjects','maxObjects','maxSeats','selectionLimit','holdLimit','maxHold','maxSelection','maxPerOrder','max_per_order','maxTickets','maxTicketCount','ticketLimit','purchaseLimit','event_order_limit','season_order_limit','order_limit'];

    function patchAny(obj, value = 100) {
      if (!obj || typeof obj !== 'object') return;
      for (const key of LIMIT_KEYS) {
        if (key in obj) {
          if (typeof obj[key] === 'number') obj[key] = value;
          else if (typeof obj[key] === 'string') obj[key] = String(value);
        }
      }
      if (Array.isArray(obj.maxSelectedObjects)) {
        for (const entry of obj.maxSelectedObjects) {
          if (entry && typeof entry === 'object') {
            if (typeof entry.quantity === 'number') entry.quantity = value;
            if (typeof entry.total === 'number') entry.total = value;
          }
        }
      }
      if (obj && (typeof obj.maxSelectedObjects === 'number' || typeof obj.maxSelectedObjects === 'undefined')) {
        obj.maxSelectedObjects = value;
      }
      if (obj.config && typeof obj.config === 'object') patchAny(obj.config, value);
    }

    function patchChart(chart) {
      if (!chart) return;
      patchAny(chart);
      patchAny(chart.state);
      patchAny(chart.config);
      patchAny(chart._config);
      patchAny(chart.options);
      patchAny(window.chartState);
      patchAny(window.currentChartConfig);
      patchAny(window.seatsioConfig);
      patchAny(window.seatsio?.config);
      [chart.config, chart._config, chart.options, window.chartState, window.currentChartConfig].forEach(cfg => {
        if (cfg && typeof cfg === 'object') cfg.session = 'continue';
      });
      if (chart.state) {
        if (typeof chart.state._selectionCount === 'number') chart.state._selectionCount = 0;
        if (typeof chart.state._holdCount === 'number') chart.state._holdCount = 0;
        if (typeof chart.state.heldCount === 'number') chart.state.heldCount = 0;
        if (typeof chart.state.selectionCount === 'number') chart.state.selectionCount = 0;
        if (typeof chart.state.numHeldByCurrentToken === 'number') chart.state.numHeldByCurrentToken = 0;
        if (!Array.isArray(chart.state.selectedObjects)) chart.state.selectedObjects = [];
        if (!Array.isArray(chart.state.heldObjects)) chart.state.heldObjects = [];
      }
      if (renderState) {
        if (typeof renderState._selectionCount === 'number') renderState._selectionCount = 0;
        if (typeof renderState._holdCount === 'number') renderState._holdCount = 0;
        if (typeof renderState.heldCount === 'number') renderState.heldCount = 0;
        if (typeof renderState.selectionCount === 'number') renderState.selectionCount = 0;
        if (typeof renderState.numHeldByCurrentToken === 'number') renderState.numHeldByCurrentToken = 0;
        renderState.maxNumberOfHolds = 100;
      }
    }

    function findSeatObject(label) {
      const rs = findRenderState();
      const cd = rs?.chartData;
      if (!cd) return null;
      const lists = [
        cd.content?.chairs,
        cd.content?.tables,
        cd.content?.areas,
        Array.from(cd.chairsByUuid?.values() || []),
        Array.from(cd.tablesByUuid?.values() || []),
        Array.from(cd.areasByUuid?.values() || []),
        Object.values(cd.renderingInfo?.objectsMap || {}),
        Object.values(cd.objectsMap || {}),
      ];
      for (const list of lists) {
        if (!Array.isArray(list)) continue;
        for (const obj of list) {
          const name = obj?.renderingInfo?.name ?? obj?.name ?? obj?.label ?? obj?.objectId;
          if (name === label) return obj;
        }
      }
      return null;
    }

    function getSelectedLabels() {
      try {
        if (chart && typeof chart.getSelectedObjects === 'function') {
          const objs = chart.getSelectedObjects();
          if (Array.isArray(objs)) return objs.map(o => typeof o === 'string' ? o : (o.label || o.objectId || o.id)).filter(Boolean);
        }
      } catch {}
      const sel = chart?.state?.selectedObjects || window.chartState?.selectedObjects || renderState?.selectedObjects || [];
      return sel.map(o => typeof o === 'string' ? o : (o.label || o.objectId || o.id)).filter(Boolean);
    }

    function forceRedraw() {
      const methods = ['redraw','render','refresh','update','repaint','draw','reRender','rerender'];
      methods.forEach(m => {
        try { if (chart && typeof chart[m] === 'function') chart[m](); } catch {}
      });
      try { window.dispatchEvent(new Event('resize')); } catch {}
      try { window.dispatchEvent(new UIEvent('resize')); } catch {}
      try { window.postMessage({ type: 'kimiko-redraw' }, '*'); } catch {}
    }

    // 1) Patch limits and try official API in one batch.
    patchChart(chart);
    try {
      if (chart && typeof chart.selectObjects === 'function') chart.selectObjects(seats);
    } catch {}
    await sleep(60);

    let selected = getSelectedLabels();

    // 2) If batch failed, try per-seat bursts.
    if (selected.length < seats.length && remaining() > 200) {
      const missing = seats.filter(s => !selected.includes(s));
      const batchSize = 6;
      for (let i = 0; i < missing.length && remaining() > 80; i += batchSize) {
        patchChart(chart);
        const batch = missing.slice(i, i + batchSize);
        try {
          if (chart && typeof chart.selectObjects === 'function') chart.selectObjects(batch);
        } catch {}
        await sleep(10);
      }
      await sleep(Math.min(100, Math.max(30, remaining() / 5)));
      selected = getSelectedLabels();
    }

    // 3) Inject into renderState.selectedSeats so the renderer colours the seats.
    try {
      const rs = findRenderState();
      const selectedSeats = rs?.selectedSeats;
      if (selectedSeats instanceof Map) {
        for (const label of seats) {
          if (selectedSeats.has(label)) continue;
          const obj = findSeatObject(label);
          const entry = {
            amount: 1,
            uuid: obj?.id || obj?.uuid || obj?.objectId || label,
            itemType: obj?.renderingInfo?.itemType || obj?.itemType || 'Seat',
            specificationKey: obj?.renderingInfo?.specificationKey || obj?.specification?.key || obj?.specificationKey || '',
            ticketType: obj?.renderingInfo?.pricing?.[0]?.ticketType || obj?.ticketType || '',
            selectedTicketType: obj?.renderingInfo?.pricing?.[0]?.ticketType || obj?.ticketType || '',
            label,
            parentSectionName: obj?.parentSectionName || null,
          };
          selectedSeats.set(label, entry);
        }
      }
      // Also update selectedObjects / heldObjects arrays on chart.state and renderState.
      for (const arrName of ['selectedObjects', 'heldObjects', 'reservedObjects']) {
        const arr = chart?.state?.[arrName] || window.chartState?.[arrName] || rs?.[arrName];
        if (Array.isArray(arr)) {
          for (const label of seats) {
            const exists = arr.some(o => (o?.label || o?.objectId || o?.id || o) === label);
            if (!exists) arr.push({ label, objectId: label, uuid: label, status: 'reservedByToken', heldByCurrentToken: true, selected: true });
          }
        }
      }
      // Reset internal counters so the chart never self-blocks on limits.
      if (rs) {
        ['_selectionCount','_holdCount','heldCount','selectionCount','numHeldByCurrentToken'].forEach(k => {
          if (typeof rs[k] === 'number') rs[k] = 0;
        });
        rs.maxNumberOfHolds = 100;
      }
      forceRedraw();
      for (let i = 0; i < 5; i++) {
        requestAnimationFrame(() => { forceRedraw(); });
      }
      await sleep(80);
    } catch {}

    selected = getSelectedLabels();

    // 4) Guaranteed visual DOM fallback for SVG-rendered charts.
    try {
      const ns = 'http://www.w3.org/2000/svg';
      const styleId = 'kimiko-held-style';
      let style = document.getElementById(styleId);
      if (!style) {
        style = document.createElementNS('http://www.w3.org/1999/xhtml', 'style');
        style.id = styleId;
        style.textContent = `
          .kimiko-held { stroke: #22c55e !important; stroke-width: 3px !important; filter: drop-shadow(0 0 2px #22c55e); fill: #22c55e !important; fill-opacity: 0.35 !important; }
          .kimiko-check { pointer-events: none; }
          .kimiko-check path { stroke: #22c55e; }
        `;
        (document.head || document.documentElement).appendChild(style);
      }
      for (const label of seats) {
        // Try a wide set of selectors, and also walk text nodes for exact label matches.
        let el = document.querySelector(`[data-object-id="${label}"], [data-objectid="${label}"], [data-label="${label}"], [data-object-label="${label}"], [id="${label}"], [aria-label*="${label}"], [title*="${label}"]`);
        if (!el) {
          const all = document.querySelectorAll('text, tspan, [class*="seat" i], [class*="object" i]');
          for (const node of all) {
            const txt = (node.textContent || '').trim();
            if (txt === label || txt.endsWith(`-${label}`) || txt.startsWith(`${label}-`)) {
              el = node;
              break;
            }
          }
        }
        if (!el) continue;
        el.classList.add('kimiko-held');
        let parent = el.closest('g[data-object-id], g[data-objectid], g[data-label], g[id]') || el.closest('g') || el.parentElement;
        if (!parent) parent = el;
        if (!parent.querySelector('.kimiko-check')) {
          const bbox = (el.getBBox && el.getBBox()) || (parent.getBBox && parent.getBBox());
          if (bbox && bbox.width > 0 && bbox.height > 0) {
            const scale = Math.min(bbox.width, bbox.height) / 22;
            const g = document.createElementNS(ns, 'g');
            g.setAttribute('class', 'kimiko-check');
            g.setAttribute('transform', `translate(${bbox.x + bbox.width * 0.55}, ${bbox.y + bbox.height * 0.05}) scale(${scale})`);
            const path = document.createElementNS(ns, 'path');
            path.setAttribute('d', 'M4 12l6 6 10-14');
            path.setAttribute('fill', 'none');
            path.setAttribute('stroke', '#22c55e');
            path.setAttribute('stroke-width', '4');
            path.setAttribute('stroke-linecap', 'round');
            path.setAttribute('stroke-linejoin', 'round');
            g.appendChild(path);
            parent.appendChild(g);
          }
        }
      }
      forceRedraw();
    } catch {}

    // 5) Notify the parent WeBook page so its cart/summary refreshes. The Seats.io
    // React wrapper normally invokes onObjectSelected callbacks for user clicks;
    // when we hold via raw WebSocket we must replay those callbacks manually.
    try {
      const seatObjects = seats.map(label => ({
        label,
        objectId: label,
        id: label,
        selected: true,
        status: 'reservedByToken',
        heldByCurrentToken: true,
      }));
      if (chart) {
        for (const cbName of ['onObjectSelected', 'onObjectsSelected', 'objectSelected', 'objectsSelected']) {
          const cb = chart.config?.[cbName] || chart[cbName];
          if (typeof cb === 'function') {
            cb(seatObjects.length === 1 ? seatObjects[0] : seatObjects);
            break;
          }
        }
      }
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ type: 'objectsSelected', objects: seatObjects }, '*');
        window.parent.postMessage({ event: 'objectsSelected', objects: seatObjects }, '*');
      }
    } catch {}

    selected = getSelectedLabels();
    return { ok: selected.length > 0 || seats.length > 0, selectedCount: selected.length, requested: seats.length, selected };
  }, { seats, timeoutMs, start });
}

async function clearChartVisualMarkers(frame, seats) {
  // Remove our custom markers and try to deselect the seats in the chart.
  return frame.evaluate(async ({ seats }) => {
    const chart = window.chartRender || window.chart || window.SeatsChart || (window.seatsio && window.seatsio.chart);
    // Try official deselect first.
    try {
      if (chart && typeof chart.deselectObjects === 'function') chart.deselectObjects(seats);
    } catch {}
    // Remove DOM markers.
    try {
      for (const label of seats) {
        const el = document.querySelector(`[data-object-id="${label}"], [data-label="${label}"], [data-object-label="${label}"], [id="${label}"], [aria-label*="${label}"]`);
        if (el) el.classList.remove('kimiko-held');
      }
      document.querySelectorAll('.kimiko-check').forEach(n => n.remove());
      ['redraw','render','refresh','update'].forEach(m => { try { if (typeof chart[m] === 'function') chart[m](); } catch {} });
      window.dispatchEvent(new Event('resize'));
    } catch {}
    return { ok: true };
  }, { seats });
}

// ------------------------------------------------------------------
// Playwright WebSocketRoute interception for validated SeatCloud socket
// ------------------------------------------------------------------
function decompressWsMessage(data) {
  if (typeof data === 'string') return data;
  const buf = Buffer.from(data);
  // SeatCloud uses raw deflate (wbits=-15).
  try {
    return zlib.inflateRawSync(buf).toString('utf8');
  } catch {}
  // Fallback: standard zlib wrapper.
  try {
    return zlib.inflateSync(buf).toString('utf8');
  } catch {}
  // Plain text fallback (should not happen for binary frames).
  try {
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

function compressWsMessage(text) {
  return zlib.deflateRawSync(Buffer.from(text, 'utf8'));
}

// ------------------------------------------------------------------
// Direct SeatCloud WebSocket hold (bypasses the browser chart iframe)
// ------------------------------------------------------------------
function buildSeatcloudWsUrl(eventKey, holdToken, workspaceKey, tracingId, channel = 'NO_CHANNEL') {
  return `wss://api.seatcloud.com:8443/?event=${encodeURIComponent(eventKey)}&token=${encodeURIComponent(holdToken)}&teamID=${encodeURIComponent(workspaceKey)}&channel=${encodeURIComponent(channel)}&tracingId=${encodeURIComponent(tracingId)}`;
}

function parseSeatcloudChannel(urlString) {
  try {
    const url = new URL(urlString);
    return url.searchParams.get('channel') || 'NO_CHANNEL';
  } catch {
    return 'NO_CHANNEL';
  }
}

function getAllTeamsChannel(session) {
  if (!session?.selectedTeam || session.selectedTeam.id !== 'ALL_TEAMS') return null;
  const keys = session.selectedTeam.allChannelKeys || [];
  if (!keys.length) return 'NO_CHANNEL';
  const ids = ['NO_CHANNEL', ...keys.map(String)];
  return [...new Set(ids)].join(',');
}

function getSelectedTeamChannelKeys(session) {
  const st = session?.selectedTeam;
  if (!st) return [];
  if (st.id === 'ALL_TEAMS') return st.allChannelKeys || [];
  return [...new Set([
    ...(st.channelKeys || []),
    ...(st.commonChannelKeys || []),
  ].map(String))];
}

function getSeatcloudChannel(session, page) {
  const allTeamsChannel = getAllTeamsChannel(session);
  if (allTeamsChannel) return allTeamsChannel;

  // Team events: use the selected team's SeatCloud channel UUIDs (plus common seats).
  const keys = getSelectedTeamChannelKeys(session);
  if (keys.length) return keys.join(',');

  if (session?.channel && session.channel !== 'NO_CHANNEL') return session.channel;
  if (page) {
    const state = wsRouteRegistry.get(page);
    if (state?.url) {
      const ch = parseSeatcloudChannel(state.url);
      if (ch && ch !== 'NO_CHANNEL') {
        if (session) session.channel = ch;
        return ch;
      }
    }
  }
  return 'NO_CHANNEL';
}

/**
 * Convert the Playwright-style proxy object ({ server, username, password })
 * into a full URL string, preserving the original scheme (http/https/socks4/socks5).
 */
function buildProxyUrl(proxy) {
  if (!proxy || !proxy.server) return null;
  try {
    const server = String(proxy.server).trim();
    if (!server) return null;

    // Detect scheme. Default to http for bare host:port entries.
    const schemeMatch = server.match(/^(https?|socks4|socks5):\/\//i);
    const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : 'http';
    const hostPart = schemeMatch ? server.slice(schemeMatch[0].length) : server;

    const u = new URL(`${scheme}://${hostPart}`);
    if (proxy.username) {
      u.username = encodeURIComponent(proxy.username);
      u.password = encodeURIComponent(proxy.password || '');
    }
    return u.toString();
  } catch (e) {
    fileLog('WARN', `Invalid proxy server format: ${proxy?.server}`);
    return null;
  }
}

/**
 * Build the correct proxy agent for a WebSocket connection.
 * Supports HTTP/HTTPS and SOCKS4/SOCKS5 proxies (with auth).
 */
function getProxyAgent(proxyConfig) {
  const proxyUrl = buildProxyUrl(proxyConfig);
  if (!proxyUrl) return null;
  const scheme = proxyUrl.split('://')[0].toLowerCase();
  if (scheme === 'socks4' || scheme === 'socks5') {
    return new SocksProxyAgent(proxyUrl);
  }
  return new HttpsProxyAgent(proxyUrl);
}

async function resolveWebSocketProxy(proxyConfig) {
  // Resolve the proxy that should be used for a raw WebSocket connection.
  // Returns { agent, proxyServer } or throws a descriptive error.
  let effectiveProxy = proxyConfig;
  if (effectiveProxy && effectiveProxy.server) {
    let agent;
    try {
      agent = getProxyAgent(effectiveProxy);
    } catch (agentErr) {
      fileLog('WARN', `[proxy-status] [direct-ws] Proxy agent creation failed for ${effectiveProxy.server}: ${agentErr.message}; trying fallback`);
      const fallback = await getWorkingProxyForAccount('direct-ws', proxyManager.getAll().filter(p => p.server !== effectiveProxy.server));
      if (fallback.proxy) {
        effectiveProxy = fallback.proxy;
        try {
          agent = getProxyAgent(effectiveProxy);
          fileLog('INFO', `[proxy-status] [direct-ws] Using fallback proxy: ${effectiveProxy.server}`);
        } catch (fallbackErr) {
          throw new Error(`PROXY_FALLBACK_FAILED: ${fallbackErr.message}`);
        }
      } else {
        throw new Error(`PROXY_AGENT_CREATION_FAILED: ${agentErr.message}`);
      }
    }
    if (agent) {
      fileLog('INFO', `[proxy-status] [direct-ws] Routing WebSocket through proxy ${effectiveProxy.server}`);
      return { agent, proxyServer: effectiveProxy.server };
    }
    // If a proxy was explicitly supplied, do not silently bypass it.
    throw new Error('PROXY_REQUIRED_BUT_INVALID_DIRECT_WS');
  }

  if (currentProxyMode === 'required') {
    const fallback = await getWorkingProxyForAccount('direct-ws');
    if (fallback.proxy) {
      try {
        const agent = getProxyAgent(fallback.proxy);
        fileLog('INFO', `[proxy-status] [direct-ws] Using fallback proxy for required mode: ${fallback.proxy.server}`);
        return { agent, proxyServer: fallback.proxy.server };
      } catch (e) {
        throw new Error(`PROXY_REQUIRED_BUT_NO_WORKING_PROXY: ${e.message}`);
      }
    }
    throw new Error('PROXY_REQUIRED_BUT_NO_PROXY_DIRECT_WS');
  }

  fileLog('INFO', '[proxy-status] [direct-ws] Routing WebSocket direct (no proxy)');
  return { agent: null, proxyServer: null };
}

async function openSeatcloudWebSocket(url, timeoutMs = 8000, proxyConfig = null) {
  const wsOptions = {
    perMessageDeflate: false,
    handshakeTimeout: timeoutMs,
    headers: {
      Origin: WB_ORIGIN,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    },
  };

  // Resolve proxy outside the Promise executor to avoid the async-executor anti-pattern.
  const { agent } = await resolveWebSocketProxy(proxyConfig);
  if (agent) wsOptions.agent = agent;

  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, wsOptions);
    const timer = setTimeout(() => {
      try { ws.terminate(); } catch {}
      reject(new Error('WS open timeout'));
    }, timeoutMs);
    ws.once('open', () => { clearTimeout(timer); resolve(ws); });
    ws.once('error', (err) => { clearTimeout(timer); reject(err); });
  });
}

async function sendDirectWsAndWait(ws, payload, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const messages = [];
    const deadline = Date.now() + timeoutMs;
    const timer = setInterval(() => {
      if (Date.now() >= deadline) {
        cleanup();
        resolve(messages);
      }
    }, 40);
    function onMessage(data) {
      const text = decompressWsMessage(data);
      if (text) {
        try { messages.push(JSON.parse(text)); } catch {}
      }
      if (messages.length >= 2) {
        cleanup();
        resolve(messages);
      }
    }
    function cleanup() {
      clearInterval(timer);
      try { ws.off('message', onMessage); } catch {}
    }
    ws.on('message', onMessage);
    try {
      ws.send(compressWsMessage(JSON.stringify(payload)));
    } catch (e) {
      cleanup();
      resolve(messages);
    }
  });
}

function getItemsParamName(session) {
  // Normal events use ?channels=..., team/allocation events use ?allocations=...
  return session?.itemsParamName || 'allocations';
}

async function fetchHeldItemsRaw(workspaceKey, eventKey, holdToken, session = null, paramName = 'allocations') {
  const channel = getSeatcloudChannel(session, session?.page);
  const url = `https://api.seatcloud.com/api/v2/${workspaceKey}/event/${eventKey}/items/held?hold_token=${encodeURIComponent(holdToken)}&${paramName}=${encodeURIComponent(channel)}&trace_id=${makeTraceId()}&plain=true`;
  const res = await sessionFetch(url, {
    headers: {
      'Accept': 'application/json',
      'Accept-Encoding': 'identity',
      'Accept-Language': 'ar-SA,ar;q=0.9',
      'Origin': WB_ORIGIN,
      'Referer': `${WB_ORIGIN}/`,
    },
  }, session);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  return decodeSeatcloudItems(buf, { eventKey, holdToken });
}

async function verifyHeldSeatsByKeys(workspaceKey, eventKey, holdToken, wantedSet, retries = 2, session = null) {
  const held = [];
  const paramName = getItemsParamName(session);
  for (let i = 0; i < retries; i++) {
    try {
      const items = await fetchHeldItemsRaw(workspaceKey, eventKey, holdToken, session, paramName);
      if (Array.isArray(items)) {
        for (const it of items) {
          const label = String(it.label || it.name || it.objectId || it.id || '').trim();
          if (label && wantedSet.has(label)) held.push(label);
        }
      }
      if (held.length) break;
    } catch (e) {
      fileLog('WARN', `verifyHeldSeatsByKeys error: ${e.message}`);
    }
    if (i < retries - 1) await waitFor(60);
  }
  return held;
}

async function holdSeatsViaDirectWebSocket(workspaceKey, eventKey, holdToken, targetSections, targetCount, opts = {}) {
  const username = opts.username || '';
  const session = opts.session || null;
  const wantedCount = Math.max(1, Math.min(parseInt(targetCount, 10) || 30, MAX_HELD_SEATS));
  const sections = (targetSections || []).map(s => String(s).trim().toUpperCase()).filter(Boolean);
  if (sections.length === 0) {
    fileLog('WARN', `[direct-ws] ${username} no target sections provided`);
    return [];
  }

  const channel = getSeatcloudChannel(session, session?.page);
  const tracingId = `direct_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const url = buildSeatcloudWsUrl(eventKey, holdToken, workspaceKey, tracingId, channel);
  fileLog('INFO', `[direct-ws] ${username} connecting to SeatCloud WS ${url.replace(/token=[^&]+/, 'token=***')}`);
  emitStatus('direct-ws', 'Connecting directly to SeatCloud WebSocket...', { account: username });

  let ws;
  try {
    ws = await openSeatcloudWebSocket(url, 4000, session?.proxy);
  } catch (e) {
    fileLog('WARN', `[direct-ws] ${username} connection failed: ${e.message}`);
    emitStatus('direct-ws-error', `Direct WS connection failed: ${e.message}`, { account: username });
    return [];
  }

  try {
    // Build category list per section. For virtual ticket-only sections we need the
    // seats.io category key; real chart sections use the section label itself.
    const chartSections = session?.chartSections || [];
    const sectionCategories = sections.map(sec => {
      const meta = chartSections.find(s => s.label && s.label.toUpperCase() === sec);
      if (meta?.virtual && meta.categories?.length) {
        return { section: sec, categories: meta.categories.map(c => String(c.categoryKey)).filter(Boolean) };
      }
      return { section: sec, categories: [sec] };
    }).filter(sc => sc.categories.length > 0);

    if (sectionCategories.length === 0) {
      fileLog('WARN', `[direct-ws] ${username} could not map sections to categories: ${sections.join(',')}`);
      emitStatus('direct-ws-no-seats', 'Could not map sections to categories', { account: username, sections });
      return [];
    }

    // Try bestAvailable per section until we reach wantedCount.
    const held = [];
    const heldSet = new Set();
    const releasedSet = opts.releasedSeats || new Set();

    for (const { section, categories } of sectionCategories) {
      if (held.length >= wantedCount) break;
      const need = wantedCount - held.length;
      const payload = {
        action: 'hold-object',
        objects: [],
        bestAvailable: { number: need, categories },
        token: holdToken,
        tracing_id: `${tracingId}_${section}`,
      };
      fileLog('INFO', `[direct-ws] ${username} bestAvailable ${need} in ${section} (categories=${categories.join('|')})`);
      emitStatus('direct-ws-hold', `Requesting ${need} seat(s) in ${section}`, { account: username, section, count: need });

      const responses = await sendDirectWsAndWait(ws, payload, 1500);
      const ack = [];
      for (const msg of responses) {
        const data = msg && msg.data ? msg.data : msg;
        // Direct acknowledgement: { action: 'hold-object', data: { objects: [...] } }
        if (msg.action === 'hold-object' && data && Array.isArray(data.objects)) {
          for (const o of data.objects) {
            const oid = typeof o === 'string' ? o : (o.objectId || o.label || o.id);
            if (oid && !heldSet.has(oid)) { ack.push(oid); heldSet.add(oid); }
          }
        }
        // Status broadcasts: { data: { status, objectId, objects, numHeldByCurrentToken } }
        if (data) {
          const status = data.status;
          const numHeld = data.numHeldByCurrentToken || 0;
          const objs = [];
          if (Array.isArray(data.objects)) objs.push(...data.objects);
          if (data.objectId) objs.push(data.objectId);
          if ((status === 'reservedByToken' || status === 'held' || (status === 'free' && numHeld > 0)) && objs.length) {
            for (const o of objs) {
              const oid = typeof o === 'string' ? o : (o.objectId || o.label || o.id);
              if (oid && !heldSet.has(oid)) { ack.push(oid); heldSet.add(oid); }
            }
          }
        }
      }

      if (ack.length) {
        for (const s of ack) {
          if (!releasedSet.has(String(s).toUpperCase()) && !isSeatReserved(s, username) && held.length < wantedCount) {
            held.push(s);
          }
        }
        emitStatus('direct-ws-held', `Direct WS acknowledged ${ack.length} seat(s) in ${section}`, { account: username, section, seats: ack });
      }
    }

    // Ultimate source of truth: ask the server which seats this token actually holds.
    const verified = await verifyHeldSeatsByKeys(workspaceKey, eventKey, holdToken, new Set(held.length ? held : []), 4, session);
    if (verified.length) {
      fileLog('INFO', `[direct-ws] ${username} verified held ${verified.length}/${wantedCount}`);
      emitStatus('direct-ws-success', `Direct WS verified ${verified.length} seat(s)`, { account: username, seats: verified });
      return verified.slice(0, wantedCount);
    }

    // If verification returned nothing but we had acks, the seats may have been
    // released immediately; return acks as a fallback only if we got enough.
    if (held.length >= wantedCount) {
      fileLog('INFO', `[direct-ws] ${username} WS ack ${held.length} seats (verification empty)`);
      return held.slice(0, wantedCount);
    }

    fileLog('WARN', `[direct-ws] ${username} no verified seats in sections ${sections.join(',')}`);
    emitStatus('direct-ws-no-seats', 'No verified seats in selected sections', { account: username, sections });
    return [];
  } catch (e) {
    fileLog('WARN', `[direct-ws] ${username} error: ${e.message}`);
    emitStatus('direct-ws-error', `Direct WS error: ${e.message}`, { account: username });
    return [];
  } finally {
    try { ws.terminate(); } catch {}
  }
}

/**
 * Aggressive direct-WS sniper that keeps calling SeatCloud until the per-user
 * target is reached, the timeout expires, or the session is stopped.
 */
async function executeDirectWebSocketSniper(session, page, holdToken, targetSections, targetCount) {
  if (!session.workspaceKey || !session.eventKey || !holdToken) return [];
  const username = session.username;
  const speed = getSpeedSettings(session?.speedSettings);
  const directStart = Date.now();
  const directMaxMs = 20_000;
  const held = [];
  const heldSet = new Set();

  emitStatus('direct-ws-attack', `Launching direct WebSocket attack for ${targetCount} seat(s)`, { account: username, target: targetCount });

  while (Date.now() - directStart < directMaxMs && held.length < targetCount && !session.bookingPaused && !session.stopRequested && !session.isTransferring) {
    const stillNeed = targetCount - held.length;
    const batch = await holdSeatsViaDirectWebSocket(
      session.workspaceKey,
      session.eventKey,
      holdToken,
      targetSections,
      stillNeed,
      { username, session, releasedSeats: session.releasedSeats }
    );
    if (batch.length) {
      for (const s of batch) {
        if (!heldSet.has(s)) {
          heldSet.add(s);
          held.push(s);
        }
      }
      emitStatus('direct-ws-progress', `Direct WS attack held ${held.length}/${targetCount}`, { account: username, seats: held });
    }
    if (held.length >= targetCount) break;
    await waitFor(Math.min(speed.sniperIntervalMs, 250));
  }

  return held;
}

/**
 * Hold an exact list of seat labels through a direct SeatCloud WebSocket.
 * Used by pair-cycling handoffs so the next user in a pair can take over the
 * same seats before the previous user releases them, without waiting for the
 * chart iframe to fully render.
 */
async function holdSpecificSeatsViaDirectWebSocket(workspaceKey, eventKey, holdToken, seatLabels, opts = {}) {
  const username = opts.username || '';
  const wanted = [...new Set((seatLabels || []).map(String).filter(Boolean))].slice(0, MAX_HELD_SEATS);
  if (wanted.length === 0) return [];

  const channel = getSeatcloudChannel(opts.session, opts.session?.page);
  const tracingId = `direct_specific_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const url = buildSeatcloudWsUrl(eventKey, holdToken, workspaceKey, tracingId, channel);
  fileLog('INFO', `[direct-ws-specific] ${username} connecting for ${wanted.length} specific seats`);
  emitStatus('direct-ws-specific', `Direct WS handoff for ${wanted.length} seat(s)...`, { account: username, seats: wanted });

  let ws;
  try {
    ws = await openSeatcloudWebSocket(url, 4000, opts.session?.proxy);
  } catch (e) {
    fileLog('WARN', `[direct-ws-specific] ${username} connection failed: ${e.message}`);
    return [];
  }

  try {
    // Send one batched hold-object frame for the exact seats.
    const payload = {
      action: 'hold-object',
      objects: wanted.map(objectId => ({ objectId })),
      token: holdToken,
      tracing_id: tracingId,
    };
    const responses = await sendDirectWsAndWait(ws, payload, 2000);

    const ackSet = new Set();
    for (const msg of responses) {
      const data = msg && msg.data ? msg.data : msg;
      if (msg.action === 'hold-object' && data && Array.isArray(data.objects)) {
        for (const o of data.objects) {
          const oid = typeof o === 'string' ? o : (o.objectId || o.label || o.id);
          if (oid) ackSet.add(String(oid));
        }
      }
      if (data) {
        const objs = [];
        if (Array.isArray(data.objects)) objs.push(...data.objects);
        if (data.objectId) objs.push(data.objectId);
        if (objs.length) {
          for (const o of objs) {
            const oid = typeof o === 'string' ? o : (o.objectId || o.label || o.id);
            if (oid) ackSet.add(String(oid));
          }
        }
      }
    }

    // Ultimate source of truth: ask the server which seats this token actually holds.
    const verified = await verifyHeldSeatsByKeys(workspaceKey, eventKey, holdToken, new Set(wanted), 4, opts.session);
    if (verified.length) {
      fileLog('INFO', `[direct-ws-specific] ${username} verified ${verified.length}/${wanted.length}`);
      emitStatus('direct-ws-specific-success', `Direct WS handoff verified ${verified.length} seat(s)`, { account: username, seats: verified });
      // Sync the chart iframe so the handoff seats appear selected immediately.
      try {
        const page = opts.session?.page;
        if (page) {
          const frame = await findChartFrame(page, username);
          if (frame) await syncChartSelection(frame, verified, { page, username });
        }
      } catch (syncErr) {
        fileLog('WARN', `[direct-ws-specific] ${username} chart sync warning: ${syncErr.message}`);
      }
      return verified.slice(0, wanted.length);
    }

    // Fallback to acks if verification is empty but acks cover everything.
    const ackList = wanted.filter(s => ackSet.has(String(s)));
    if (ackList.length >= wanted.length) {
      fileLog('INFO', `[direct-ws-specific] ${username} ack ${ackList.length} seats (verification empty)`);
      return ackList.slice(0, wanted.length);
    }

    fileLog('WARN', `[direct-ws-specific] ${username} no verified seats`);
    return [];
  } catch (e) {
    fileLog('WARN', `[direct-ws-specific] ${username} error: ${e.message}`);
    return [];
  } finally {
    try { ws.terminate(); } catch {}
  }
}

function setupNoiseBlockRoute(page) {
  // Block non-essential analytics / telemetry endpoints that can trigger 429s
  // and add request noise during high-frequency sniping. Webook functionality
  // does not depend on these beacons.
  const noisePatterns = [
    /\/cdn-cgi\/rum\?/,
    /\/api\/v2\/event-detail\/[^/]+\/view/,
    /analytics\.google\.com/,
    /google-analytics\.com/,
    /googletagmanager\.com/,
    /doubleclick\.net/,
    /facebook\.com\/tr/,
    /connect\.facebook\.net/,
    /sentry\.io/,
    /ingest\.de\.sentry\.io/,
  ];
  page.route('**/*', async (route) => {
    const url = route.request().url();
    const shouldBlock = noisePatterns.some(p => p.test(url));
    if (shouldBlock) {
      try {
        await route.abort('aborted');
      } catch {
        try { await route.fallback(); } catch {}
      }
      return;
    }
    try { await route.fallback(); } catch { await route.continue().catch(() => {}); }
  });
}

function setupChartIframePatchRoute(page) {
  // Inject the chart limit patch directly into the chart iframe HTML before any
  // of its scripts run. This guarantees maxSelectedObjects/maxNumberOfHolds are
  // unlocked before the Seats.io chart instance is created, so the chart will
  // natively allow (and render) more than 5 selected/held seats.
  const iframeHosts = /(chart\.seatcloud\.com|seats\.seatcloud\.com|embedded\.seatcloud\.com|cdn\.seats\.io|chart\.seats\.io)/;
  page.route(iframeHosts, async (route) => {
    const url = route.request().url();
    try {
      const response = await route.fetch();
      const contentType = (response.headers()['content-type'] || '').toLowerCase();
      // Only patch HTML documents; pass through JS/CSS/images unchanged.
      if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
        await route.fulfill({ response });
        return;
      }
      let body = await response.text();
      // Bail out if we already injected the patch (redundant route hits).
      if (body.includes('__kimikoChartLimitPatch')) {
        await route.fulfill({ response });
        return;
      }
      const scripts = [`<script>${CHART_LIMIT_PATCH}</script>`];

      // If a hold token was forced for the parent page, seed the iframe with it
      // before the chart bundle runs. The bundle usually reads window.holdToken
      // or window.__INITIAL_STATE__.hold_token, so we set both.
      try {
        const frame = route.request().frame();
        const parentPage = frame ? frame.page() : null;
        const forcedToken = parentPage ? forcedHoldTokenRegistry.get(parentPage) : null;
        if (forcedToken) {
          const tokenScript = `<script>(function(){const t=${JSON.stringify(forcedToken)};window.holdToken=t;window.__INITIAL_STATE__=window.__INITIAL_STATE__||{};window.__INITIAL_STATE__.hold_token=t;window.__INITIAL_STATE__.holdToken=t;window.__kimikoForcedHoldToken=t;})();</script>`;
          scripts.unshift(tokenScript);
        }
      } catch {}

      const patchScript = scripts.join('');
      if (body.includes('<head>')) {
        body = body.replace('<head>', `<head>${patchScript}`);
      } else if (body.includes('<html>')) {
        body = body.replace('<html>', `<html>${patchScript}`);
      } else if (body.includes('<body>')) {
        body = body.replace('<body>', `${patchScript}<body>`);
      } else {
        body = patchScript + body;
      }
      const headers = response.headers();
      delete headers['content-length'];
      delete headers['content-encoding'];
      await route.fulfill({ status: response.status(), headers, body });
      fileLog('INFO', `Injected chart limit patch into chart iframe HTML: ${url}`);
    } catch (e) {
      fileLog('WARN', `Chart iframe patch route failed for ${url}: ${e.message}`);
      await route.continue();
    }
  });
}

function setupHoldTokenProtectRoute(page, session) {
  // For holdToken accounts, block WeBook's /hold-token API from returning a
  // fresh token for the logged-in user and overwriting the provided token in
  // cookies / page state. We keep the queue-token header but strip hold_token.
  if (session.type !== 'holdToken' || !session.providedHoldToken) return;
  const holdTokenPattern = /\/event-detail\/[^/]+\/hold-token/;
  page.route(holdTokenPattern, async (route) => {
    try {
      const response = await route.fetch();
      const body = await response.text();
      let modified = body;
      try {
        const json = JSON.parse(body);
        // Remove any server-issued hold_token from the body.
        if (json.data && typeof json.data.hold_token === 'string') {
          delete json.data.hold_token;
          modified = JSON.stringify(json);
        }
      } catch {}
      const headers = response.headers();
      delete headers['set-cookie']; // prevent server from overwriting our cookie
      delete headers['content-length'];
      delete headers['content-encoding'];
      await route.fulfill({ status: response.status(), headers, body: modified });
      fileLog('INFO', `[${session.username}] Blocked server hold-token overwrite`);
    } catch (e) {
      fileLog('WARN', `[${session.username}] hold-token protect route error: ${e.message}`);
      await route.continue();
    }
  });
}

function patchSeatcloudBundle(js) {
  // The SeatCloud/Seats.io bundle has a gatekeeper function that decides whether
  // a seat can be added to the current selection. It checks maxSelectedObjects /
  // maxNumberOfHolds and returns false when the limit is reached. Replacing its
  // body with `return !0` removes the frontend cap so the chart will accept and
  // render 30+ holds.
  let patchedFn = false;

  // Try known signatures first (Qn and similar obfuscated names).
  const signatures = [
    'function Qn(e,t,{ticketType:n,categoryKey:i,label:o},a)',
    'function Qn(e,t,{ticketType:n,categoryKey:i,label:o},a){',
    'function Kn(e,t,{ticketType:n,categoryKey:i,label:o},a)',
    'function Kn(e,t,{ticketType:n,categoryKey:i,label:o},a){',
    'function $n(e,t,{ticketType:n,categoryKey:i,label:o},a)',
    'function $n(e,t,{ticketType:n,categoryKey:i,label:o},a){',
  ];
  for (const sig of signatures) {
    const idx = js.indexOf(sig);
    if (idx === -1) continue;
    const open = js.indexOf('{', idx + sig.length - 1);
    if (open === -1) continue;
    let depth = 1;
    let close = open + 1;
    while (depth > 0 && close < js.length) {
      if (js[close] === '{') depth++;
      else if (js[close] === '}') depth--;
      close++;
    }
    if (depth === 0) {
      js = js.slice(0, open + 1) + 'return !0;' + js.slice(close - 1);
      patchedFn = true;
      break;
    }
  }

  // Generic gatekeeper detection: functions whose body references the limit keys
  // and returns a boolean decision. We match a few common shapes.
  if (!patchedFn) {
    const genericPatterns = [
      // function Xn(e,t,n,i){ ... c.total+r>t ... return ... }
      /function\s+[a-zA-Z$][a-zA-Z0-9$]*\([a-zA-Z$,]+\)\s*\{[^}]*(?:c\.total\s*\+\s*r\s*[<>]=?\s*t|maxNumberOfHolds|maxSelectedObjects|maxObjects)[^}]*\}/,
      // function Xn(e,t,n){ ... e>t ... }
      /function\s+[a-zA-Z$][a-zA-Z0-9$]*\([a-zA-Z$,]+\)\s*\{[^}]*(?:maxNumberOfHolds|maxSelectedObjects|maxObjects)[^}]*return\s*(?:!0|!1|true|false)[^}]*\}/,
    ];
    for (const genericRe of genericPatterns) {
      const match = js.match(genericRe);
      if (!match) continue;
      const sig = match[0];
      const idx = js.indexOf(sig);
      const open = js.indexOf('{', idx);
      let depth = 1, close = open + 1;
      while (depth > 0 && close < js.length) {
        if (js[close] === '{') depth++;
        else if (js[close] === '}') depth--;
        close++;
      }
      if (depth === 0) {
        js = js.slice(0, open + 1) + 'return !0;' + js.slice(close - 1);
        patchedFn = true;
        break;
      }
    }
  }

  // Rewrite literal initialisations of the 5-seat (and 4/6/8/10) cap so even code
  // paths that read the default config see a high limit.
  const limitLiterals = [
    { re: /maxNumberOfHolds\s*:\s*\d+\b/g, to: 'maxNumberOfHolds:150' },
    { re: /maxSelectedObjects\s*:\s*\d+\b/g, to: 'maxSelectedObjects:150' },
    { re: /maxSelectedObjects\s*:\s*\[\s*\{[^\]]*quantity\s*:\s*\d+\b[^\]]*\}\s*\]/g, to: 'maxSelectedObjects:[{category:"",quantity:150,total:150}]' },
    { re: /maxNumberOfSelectedObjects\s*:\s*\d+\b/g, to: 'maxNumberOfSelectedObjects:150' },
    { re: /maxObjects\s*:\s*\d+\b/g, to: 'maxObjects:150' },
    { re: /selectionLimit\s*:\s*\d+\b/g, to: 'selectionLimit:150' },
    { re: /holdLimit\s*:\s*\d+\b/g, to: 'holdLimit:150' },
  ];
  for (const { re, to } of limitLiterals) {
    const before = js;
    js = js.replace(re, to);
    if (js !== before) patchedFn = true;
  }

  return { js, didPatch: patchedFn };
}

function setupBundlePatchRoute(page) {
  // Intercept JS served by SeatCloud/Seats.io CDNs and rewrite the bundle's
  // internal seat-limit checker so it never says "no".
  const hosts = /(chart\.seatcloud\.com|seats\.seatcloud\.com|embedded\.seatcloud\.com|cdn\.seats\.io|chart\.seats\.io|cdn\.seatcloud\.com)/;
  page.route(hosts, async (route) => {
    const url = route.request().url();
    try {
      const response = await route.fetch();
      const contentType = (response.headers()['content-type'] || '').toLowerCase();
      const isJs = contentType.includes('javascript') || contentType.includes('application/js') || /\.js(\?|$)/i.test(url);
      if (!isJs) {
        await route.fulfill({ response });
        return;
      }
      let body = await response.text();
      if (body.includes('__kimikoBundlePatch')) {
        await route.fulfill({ response });
        return;
      }
      const { js: patched, didPatch } = patchSeatcloudBundle(body);
      if (didPatch) {
        body = patched + '\n/* __kimikoBundlePatch applied */';
        fileLog('INFO', `Patched SeatCloud bundle limits: ${url}`);
      } else {
        fileLog('DEBUG', `SeatCloud bundle not patched (no match): ${url}`);
      }
      const headers = { ...response.headers() };
      delete headers['content-length'];
      delete headers['content-encoding'];
      delete headers['transfer-encoding'];
      await route.fulfill({ status: response.status(), headers, body });
    } catch (e) {
      fileLog('WARN', `Bundle patch route failed for ${url}: ${e.message}`);
      await route.continue();
    }
  });
}

function setupWebSocketRoute(page) {
  const state = { server: null, queue: [], closed: false, ready: false, url: null, lastMessageAt: 0, connecting: false, lastReleasedSeats: new Map() };
  wsRouteRegistry.set(page, state);

  page.routeWebSocket(/seatcloud\.com/, async (route) => {
    // If a hold token was forced for this page, the WebSocket URL must use it.
    // If an existing server connection is present but uses a different token,
    // close it so the new connection opens under the forced token.
    let forcedToken = null;
    try {
      const frame = route.request().frame();
      const wsPage = frame ? frame.page() : null;
      forcedToken = wsPage ? forcedHoldTokenRegistry.get(wsPage) : null;
      if (forcedToken) {
        const currentUrl = new URL(route.url());
        const currentToken = currentUrl.searchParams.get('token') || currentUrl.searchParams.get('holdToken') || currentUrl.searchParams.get('hold_token');
        if (state.server && !state.closed && currentToken && currentToken !== forcedToken) {
          try { state.server.close(); } catch {}
          state.server = null;
          state.ready = false;
          state.closed = true;
          fileLog('INFO', 'Closed stale WS route server to force reconnect with provided token');
        }
      }
    } catch (e) {
      fileLog('DEBUG', `WS forced-token check error: ${e.message}`);
    }

    // Prevent duplicate server connections if Playwright calls the handler more than once.
    if (state.connecting || (state.server && !state.closed)) {
      fileLog('DEBUG', `WS route handler skipped: already connected or connecting`);
      return;
    }
    state.connecting = true;
    state.url = route.url();
    try {
      const channel = parseSeatcloudChannel(state.url);
      if (channel && channel !== 'NO_CHANNEL') {
        const session = findSessionByPage(page);
        if (session) session.channel = channel;
      }
    } catch {}
    emitStatus('ws-route', 'Intercepted SeatCloud WebSocket', { url: state.url.replace(/reCaptchaToken=[^&]+/, 'reCaptchaToken=***') });

    // If a hold token was forced for this page, rewrite the WebSocket URL
    // so the server-side session uses the provided token instead of the logged-in
    // user's token. The payload already carries the token, but a matching URL
    // prevents server-side confusion.
    try {
      if (forcedToken) {
        const newUrl = new URL(route.url());
        newUrl.searchParams.set('token', forcedToken);
        newUrl.searchParams.set('holdToken', forcedToken);
        newUrl.searchParams.set('hold_token', forcedToken);
        Object.defineProperty(route, 'url', {
          get: () => newUrl.toString(),
          configurable: true,
          enumerable: true,
        });
        state.url = newUrl.toString();
        fileLog('DEBUG', `WS route URL forced to token ${forcedToken.slice(0, 8)}...`);
      }
    } catch (e) {
      fileLog('DEBUG', `WS route URL rewrite skipped: ${e.message}`);
    }

    try {
      const server = await route.connectToServer();
      state.server = server;
      state.ready = true;
      state.closed = false;
      state.connecting = false;
      state.lastMessageAt = Date.now();

      server.onMessage((message) => {
        try {
          route.send(message);
        } catch {}
        state.lastMessageAt = Date.now();
        const text = decompressWsMessage(message);
        let msg = null;
        try {
          msg = JSON.parse(text || '{}');
        } catch {}
        if (msg) {
          // Keep the last 100 messages for diagnostics (not just hold-object).
          state.queue.push(msg);
          if (state.queue.length > 100) state.queue.shift();

          // Detect seat-release broadcasts so the active sniper can react instantly.
          const releasedNow = extractReleasedSeatLabels(msg);
          if (releasedNow.length) {
            const ts = Date.now();
            for (const label of releasedNow) state.lastReleasedSeats.set(label, ts);
            // Prune stale entries older than 30s.
            for (const [label, t] of state.lastReleasedSeats) {
              if (ts - t > 30000) state.lastReleasedSeats.delete(label);
            }
            // Wake the sniper immediately for these specific seats.
            onWsSeatReleased(page, releasedNow);
          }

          // Log a short, safe summary so we can debug response formats.
          const summary = {
            action: msg.action,
            status: msg.data?.status,
            hasError: !!msg.error,
            errorMsg: msg.error?.message?.slice(0, 200),
            objectCount: Array.isArray(msg.data?.objects) ? msg.data.objects.length : (msg.data?.objectId ? 1 : 0),
          };
          fileLog('DEBUG', `WS recv: ${JSON.stringify(summary)}`);
        } else if (text) {
          fileLog('DEBUG', `WS recv raw (unparsed): ${text.slice(0, 300)}`);
        }
      });

      server.onClose(() => {
        state.closed = true;
        state.ready = false;
        state.connecting = false;
        if (state.silenceTimer) {
          clearInterval(state.silenceTimer);
          state.silenceTimer = null;
        }
        emitStatus('ws-route-closed', 'SeatCloud WebSocket route closed');
      });

      // Detect silent server-side disconnects. If no message arrives for 90s,
      // force a reconnect by closing the server side; Playwright will re-invoke
      // the route handler when the client reconnects.
      if (state.silenceTimer) clearInterval(state.silenceTimer);
      state.silenceTimer = setInterval(() => {
        if (state.closed || !state.server) {
          clearInterval(state.silenceTimer);
          state.silenceTimer = null;
          return;
        }
        const silence = Date.now() - state.lastMessageAt;
        if (silence > 90000) {
          fileLog('WARN', `SeatCloud WS route silent for ${silence}ms; forcing reconnect`);
          try { state.server.close(); } catch {}
          state.closed = true;
          state.ready = false;
          state.server = null;
          clearInterval(state.silenceTimer);
          state.silenceTimer = null;
        }
      }, 30000);
    } catch (e) {
      emitStatus('ws-route-error', `WebSocket route setup failed: ${e.message}`);
    }
  });

  return state;
}

function resetWebSocketRouteState(page) {
  // Force the next chart WebSocket connection to be treated as a brand-new
  // route. This is critical for holdToken accounts: after we swap the page to
  // a provided token and reload the chart iframe, the new WebSocket must open
  // under that token instead of reusing the logged-in user's old connection.
  const state = wsRouteRegistry.get(page);
  if (!state) {
    wsRouteRegistry.set(page, {
      server: null,
      queue: [],
      closed: false,
      ready: false,
      url: null,
      lastMessageAt: 0,
      connecting: false,
      lastReleasedSeats: new Map(),
    });
    return;
  }
  try {
    if (state.server && typeof state.server.close === 'function') {
      try { state.server.close(); } catch {}
    }
  } catch {}
  if (state.silenceTimer) {
    clearInterval(state.silenceTimer);
    state.silenceTimer = null;
  }
  state.server = null;
  state.queue.length = 0;
  state.closed = false;
  state.ready = false;
  state.url = null;
  state.lastMessageAt = 0;
  state.connecting = false;
  state.lastReleasedSeats = new Map();
  fileLog('INFO', 'WebSocket route state reset for hold-token swap');
}

function extractReleasedSeatLabels(msg) {
  if (!msg || typeof msg !== 'object') return [];
  const data = msg.data || {};
  const status = data.status;
  // SeatCloud broadcasts seat-status changes under many names; be broad so the
  // sniper wakes up the instant any monitored seat becomes free.
  const releaseStatuses = new Set([
    'free', 'released', 'available', 'releasedByToken', 'unheld',
    'empty', 'notHeld', 'unselected', 'deselected',
  ]);
  const releaseActions = new Set([
    'release-object', 'free-object', 'changeObjectStatus',
    'objectsChanged', 'statusChanged', 'objectStatusChanged',
  ]);
  const looksLikeRelease = releaseStatuses.has(status)
    || releaseActions.has(msg.action)
    || (data.previousStatus && (data.previousStatus === 'reservedByToken' || data.previousStatus === 'held'));
  if (!looksLikeRelease) return [];
  const labels = [];
  const seen = new Set();
  function add(o) {
    const id = typeof o === 'string' ? o : (o?.label || o?.objectId || o?.id || o?.object_id || o?.name || '');
    if (id && !seen.has(id)) {
      seen.add(id);
      labels.push(String(id));
    }
  }
  if (Array.isArray(data.objects)) data.objects.forEach(add);
  if (Array.isArray(data.objectIds)) data.objectIds.forEach(add);
  if (data.objectId) add(data.objectId);
  if (data.object) add(data.object);
  if (Array.isArray(data.seats)) data.seats.forEach(add);
  if (Array.isArray(data.labels)) data.labels.forEach(add);
  return labels;
}

function getRecentReleasedSeats(page, withinMs = 3000) {
  const state = wsRouteRegistry.get(page);
  if (!state || !state.lastReleasedSeats) return [];
  const now = Date.now();
  const out = [];
  for (const [label, ts] of state.lastReleasedSeats) {
    if (now - ts <= withinMs) out.push(label);
  }
  return out;
}

// Immediate sniper wake-up when WebSocket reports released seats.
async function onWsSeatReleased(page, labels) {
  const session = findSessionByPage(page);
  if (!session || session.stopRequested || session.isTransferring) return;
  const speed = getSpeedSettings(session?.speedSettings);
  const state = wsRouteRegistry.get(page);
  if (state) state.skipItemCache = true;

  const monitored = session.sniperSections || session.targetSections || [];
  const releasedSet = session?.releasedSeats || new Set();
  const relevant = labels.filter(l => {
    const sec = String(l).split('-')[0].toUpperCase();
    return (monitored.length === 0 || monitored.includes(sec)) && !releasedSet.has(String(l).trim().toUpperCase());
  });
  if (!relevant.length) return;

  const targetCount = Math.min(session.targetSeatCount || 30, MAX_HELD_SEATS);

  // Keep trying to hold released seats until the per-user target is reached or
  // the released batch is exhausted. Do not stop after a single partial hold.
  let stillRelevant = relevant.slice();
  session.isSelecting = true;
  try {
    while (stillRelevant.length > 0 && session.selectedSeats.length < targetCount && !session.stopRequested) {
      const slots = Math.max(0, targetCount - session.selectedSeats.length);
      if (slots === 0) break;
      const toHold = stillRelevant.slice(0, Math.min(stillRelevant.length, slots, MAX_HELD_SEATS - session.selectedSeats.length));
      if (toHold.length === 0) break;

      emitStatus('ws-seat-released', `WebSocket release detected: ${toHold.join(', ')}`, { account: session.username, seats: toHold });
      const holdStart = Date.now();
      const held = await sendHoldViaRoute(page, toHold, { fastMode: true, gapMs: speed.sniperBurstGapMs, timeoutMs: speed.sniperTimeoutMs, username: session.username, token: session.holdToken, speedSettings: session?.speedSettings, session });
      fileLog('TIMER', `[${session.username}] onWsSeatReleased hold took ${Date.now() - holdStart}ms -> ${held.length}/${toHold.length}`);

      if (held.length === 0) {
        // Seats were sniped by someone else between detection and hold; stop this
        // batch and wait for the next release event.
        emitStatus('seats-sniping', `Released seats still unavailable via WS; sniper will poll`, { account: session.username, seats: toHold });
        break;
      }

      for (const s of held) if (!session.selectedSeats.includes(s)) session.selectedSeats.push(s);
      reserveSeats(session.username, session.selectedSeats);
      emitStatus('seats-grabbed', `Sniper instantly held ${held.length} released seat(s)`, { account: session.username, seats: held });

      // Update the chart UI so the user sees the newly held seats immediately.
      const frame = await findChartFrame(page, session.username);
      if (frame) {
        try { await syncChartSelection(frame, session.selectedSeats, { page, username: session.username }); } catch {}
      }
      emitAccountUpdate(session.username, session.state || 'paused', { seats: session.selectedSeats });

      // Drop successfully held seats and loop again if we still need more.
      stillRelevant = stillRelevant.filter(s => !session.selectedSeats.includes(s));
    }

    if (session.selectedSeats.length >= targetCount) {
      emitStatus('ws-seat-released', `Target reached via WebSocket releases: ${session.selectedSeats.length}/${targetCount}`, { account: session.username, seats: session.selectedSeats });
    }
  } catch (e) {
    fileLog('WARN', `[${session.username}] onWsSeatReleased error: ${e.message}`);
  } finally {
    session.isSelecting = false;
  }
}

function findSessionByPage(page) {
  for (const session of activeSessions.values()) {
    if (session.page === page) return session;
  }
  return null;
}

function collectWsErrors(state, actionFilter = null) {
  if (!state || !Array.isArray(state.queue)) return [];
  return state.queue
    .filter(m => m && m.error && (!actionFilter || m.action === actionFilter))
    .map(m => ({ action: m.action, code: m.error.code, message: m.error.message || '' }));
}

function looksLikeHoldTokenSaturated(errors) {
  return errors.some(e =>
    /maximum number of holds exceeded/i.test(e.message) ||
    /invalid hold token/i.test(e.message) ||
    /hold token.*exceeded/i.test(e.message)
  );
}

async function sendHoldViaRoute(page, seats, opts = {}) {
  const routeStart = Date.now();
  const speed = getSpeedSettings(opts.speedSettings);
  const fastMode = opts.fastMode !== false;
  const timeoutMs = opts.timeoutMs || speed.sniperTimeoutMs;
  const gapMs = fastMode
    ? (opts.gapMs ?? Math.max(0, Math.round(speed.sniperBurstGapMs * speed.delayMultiplier)))
    : (opts.gapMs || 60);
  const state = wsRouteRegistry.get(page);
  if (!state || !state.server || state.closed || !state.ready) {
    fileLog('WARN', `sendHoldViaRoute skipped: WS route not ready`);
    return [];
  }

  const wanted = [...new Set(seats.map(String))];
  const pageSlug = parseSlug(page.url());
  const holdToken = opts.token || await readChartHoldToken(page, pageSlug);
  if (!holdToken) {
    fileLog('WARN', `sendHoldViaRoute skipped: no hold token for page`);
    return [];
  }

  const wsParams = await readChartWsParams(page);
  const tracingId = wsParams.tracingId || `svr_${Date.now()}`;

  fileLog('INFO', `sendHoldViaRoute start: wanted=${wanted.length}, fastMode=${fastMode}, token=${holdToken.slice(0, 12)}..., forced=${!!opts.token}, tracingId=${tracingId}, gapMs=${gapMs}`);
  emitStatus('seats-token', `Holding seats with token ${holdToken.slice(0, 8)}...${holdToken.slice(-4)}${opts.token ? ' (forced)' : ''}`, { account: opts.username || '', tokenPrefix: holdToken.slice(0, 8), forced: !!opts.token });

  const errors = [];
  const serverLimits = [];
  let verifiedHeld = [];

  // Helper: try to rotate token if the current one is saturated.
  let activeHoldToken = holdToken;
  async function tryRotateToken(needed) {
    if (!opts.session || !opts.session.page) return false;
    try {
      const frame = await findChartFrame(page, opts.session.username);
      if (!frame) return false;
      const keys = await frame.evaluate(() => ({
        workspaceKey: window.chartState?.workspaceKey || window.currentChartConfig?.workspaceKey,
        eventKey: window.chartState?.eventKey || window.currentChartConfig?.eventKey,
      })).catch(() => ({}));
      if (!keys.workspaceKey || !keys.eventKey) return false;
      const ok = await refreshHoldTokenIfSaturated(opts.session, needed, keys.workspaceKey, keys.eventKey);
      if (ok && opts.session.holdToken && opts.session.holdToken !== activeHoldToken) {
        activeHoldToken = opts.session.holdToken;
        return true;
      }
    } catch (e) {
      fileLog('WARN', `[${opts.username || ''}] tryRotateToken error: ${e.message}`);
    }
    return false;
  }

  // Try one batched hold first; it works when the server allows it and is much faster.
  state.queue.length = 0;
  try {
    const batchPayload = { action: 'hold-object', objects: wanted.map(objectId => ({ objectId })), token: activeHoldToken, tracing_id: tracingId };
    state.server.send(compressWsMessage(JSON.stringify(batchPayload)));
    fileLog('INFO', `sendHoldViaRoute sent batch hold for ${wanted.length} seats`);
    await waitFor(Math.min(150, Math.max(30, wanted.length * 2)));
    const batchErrors = collectWsErrors(state);
    if (looksLikeHoldTokenSaturated(batchErrors)) {
      emitStatus('seats-token-saturated', `Hold token is saturated/invalid (${batchErrors[0]?.message?.slice(0, 80) || ''}); trying to rotate token`, { account: opts.username || '', tokenPrefix: activeHoldToken.slice(0, 8) });
      if (await tryRotateToken(wanted.length - verifiedHeld.length)) {
        // retry batch with new token
        state.queue.length = 0;
        const rotatedPayload = { action: 'hold-object', objects: wanted.map(objectId => ({ objectId })), token: activeHoldToken, tracing_id: tracingId };
        state.server.send(compressWsMessage(JSON.stringify(rotatedPayload)));
        await waitFor(Math.min(150, Math.max(30, wanted.length * 2)));
      } else {
        return verifiedHeld;
      }
    }
    const batchVerified = await verifyHeldSeatsViaApi(page, activeHoldToken, wanted, { session: opts.session });
    if (batchVerified.length >= wanted.length) {
      fileLog('INFO', `sendHoldViaRoute batch hold succeeded: ${batchVerified.length}/${wanted.length}`);
      return batchVerified.slice(0, wanted.length);
    }
    verifiedHeld = batchVerified;
    fileLog('INFO', `sendHoldViaRoute batch hold partial: ${batchVerified.length}/${wanted.length}`);
  } catch (e) {
    fileLog('WARN', `sendHoldViaRoute batch hold failed: ${e.message}`);
  }

  // If batch did not satisfy everyone, send individual frames and verify progress
  // in chunks. The real SeatCloud client sends one frame per seat ~40-80 ms apart.
  let missing = wanted.filter(l => !verifiedHeld.includes(l));
  const startTime = Date.now();
  const deadline = startTime + timeoutMs;

  while (missing.length > 0 && Date.now() < deadline && !(opts.stopRequested)) {
    state.queue.length = 0;
    const chunk = missing.slice(0, fastMode ? 30 : 5);
    for (let i = 0; i < chunk.length; i++) {
      const oid = chunk[i];
      const payload = { action: 'hold-object', objects: [{ objectId: oid }], token: activeHoldToken, tracing_id: tracingId };
      try {
        state.server.send(compressWsMessage(JSON.stringify(payload)));
      } catch (e) {
        errors.push({ oid, error: e.message });
      }
      if (i < chunk.length - 1 && gapMs > 0) await waitFor(gapMs);
    }

    // Wait for acks / server broadcast, then verify with the API truth endpoint.
    await waitFor(Math.min(120, Math.max(25, chunk.length * 3)));
    const chunkErrors = collectWsErrors(state);
    if (looksLikeHoldTokenSaturated(chunkErrors)) {
      emitStatus('seats-token-saturated', `Hold token is saturated/invalid (${chunkErrors[0]?.message?.slice(0, 80) || ''}); trying to rotate token`, { account: opts.username || '', tokenPrefix: activeHoldToken.slice(0, 8) });
      if (!(await tryRotateToken(missing.length))) {
        break;
      }
      continue;
    }
    const chunkVerified = await verifyHeldSeatsViaApi(page, activeHoldToken, wanted, { retries: 1, retryDelay: 80, session: opts.session });

    // Detect server-imposed hard limit (commonly 5 per order context).
    if (chunkVerified.length > 0 && chunkVerified.length === verifiedHeld.length && chunkVerified.length < wanted.length) {
      const likelyLimit = chunkVerified.length;
      if (!serverLimits.includes(likelyLimit)) serverLimits.push(likelyLimit);
      fileLog('WARN', `sendHoldViaRoute detected possible server hold limit at ${likelyLimit}; will not hammer further`);
      if (serverLimits.length >= 2) break;
    }

    verifiedHeld = chunkVerified;
    missing = wanted.filter(l => !verifiedHeld.includes(l));
  }

  if (serverLimits.length) {
    emitStatus('seats-server-limit', `Server appears to enforce a ${Math.min(...serverLimits)} seat hold limit for this event`, { account: opts.username || '', limit: Math.min(...serverLimits) });
  }

  if (errors.length) {
    fileLog('WARN', `sendHoldViaRoute errors: ${JSON.stringify(errors.slice(0, 5))}`);
  }

  fileLog('TIMER', `[${opts.username || ''}] sendHoldViaRoute took ${Date.now() - routeStart}ms -> ${verifiedHeld.length}/${wanted.length}`);
  fileLog('INFO', `sendHoldViaRoute final verify: verified=${verifiedHeld.length}/${wanted.length}`);
  return verifiedHeld.slice(0, wanted.length);
}

async function sendBestAvailableViaRoute(page, count, categories = [], timeoutMs = 1_200, opts = {}) {
  const baStart = Date.now();
  const speed = getSpeedSettings(opts.speedSettings);
  const effectiveTimeout = timeoutMs || speed.sniperTimeoutMs;
  const state = wsRouteRegistry.get(page);
  if (!state || !state.server || state.closed || !state.ready) return [];

  const pageSlug = parseSlug(page.url());
  let activeHoldToken = opts.token || await readChartHoldToken(page, pageSlug);
  if (!activeHoldToken) {
    fileLog('WARN', `sendBestAvailableViaRoute skipped: no hold token for page`);
    return [];
  }

  emitStatus('seats-token', `bestAvailable with token ${activeHoldToken.slice(0, 8)}...${activeHoldToken.slice(-4)}${opts.token ? ' (forced)' : ''}`, { account: opts.username || '', tokenPrefix: activeHoldToken.slice(0, 8), forced: !!opts.token });

  // Helper: rotate token on saturation if we have a session reference.
  async function tryRotateToken(needed) {
    if (!opts.session || !opts.session.page) return false;
    try {
      const frame = await findChartFrame(page, opts.session.username);
      if (!frame) return false;
      const keys = await frame.evaluate(() => ({
        workspaceKey: window.chartState?.workspaceKey || window.currentChartConfig?.workspaceKey,
        eventKey: window.chartState?.eventKey || window.currentChartConfig?.eventKey,
      })).catch(() => ({}));
      if (!keys.workspaceKey || !keys.eventKey) return false;
      const ok = await refreshHoldTokenIfSaturated(opts.session, needed, keys.workspaceKey, keys.eventKey);
      if (ok && opts.session.holdToken && opts.session.holdToken !== activeHoldToken) {
        activeHoldToken = opts.session.holdToken;
        return true;
      }
    } catch (e) {
      fileLog('WARN', `[${opts.username || ''}] sendBestAvailableViaRoute tryRotateToken error: ${e.message}`);
    }
    return false;
  }

  // Prefer the chart's native bestAvailable method (uses the real WebSocket flow internally).
  // IMPORTANT: the native chart uses the iframe's own token, which may differ from the token we
  // want to hold under. If a forced token is supplied, skip the native path and use the WS route
  // so we can explicitly set the token in the payload.
  const frame = !opts.token ? await findChartFrame(page, '') : null;
  if (frame) {
    try {
      const nativeHeld = await frame.evaluate(async ({ count, categories }) => {
        const chart = window.chart || window.chartRender;
        if (!chart || typeof chart.bestAvailable !== 'function') return [];
        try {
          const res = await chart.bestAvailable({ number: count, categories });
          if (res && Array.isArray(res.objects)) return res.objects.map(o => o.label || o.id || o.objectId);
          if (res && Array.isArray(res)) return res.map(o => o.label || o.id || o.objectId);
          return [];
        } catch (e) {
          return { error: e.message };
        }
      }, { count, categories: categories.map(String) });
      if (Array.isArray(nativeHeld) && nativeHeld.length >= count) {
        fileLog('INFO', `sendBestAvailableViaRoute native chart held ${nativeHeld.length} seats`);
        const verified = await verifyHeldSeatsViaApi(page, activeHoldToken, nativeHeld, { session: opts.session });
        if (verified.length > 0) {
          fileLog('INFO', `sendBestAvailableViaRoute native API verified ${verified.length} seats`);
          return verified;
        }
      }
    } catch (e) {
      fileLog('WARN', `Native chart bestAvailable failed: ${e.message}`);
    }
  }

  // Discard stale messages before our request.
  state.queue.length = 0;

  const wsParams = await readChartWsParams(page);
  let payload = {
    action: 'hold-object',
    objects: [],
    bestAvailable: { number: count, categories: categories.map(String) },
    token: activeHoldToken,
    tracing_id: wsParams.tracingId || `svr_ba_${Date.now()}`,
  };
  try {
    state.server.send(compressWsMessage(JSON.stringify(payload)));
  } catch (e) {
    fileLog('WARN', `sendBestAvailableViaRoute send failed: ${e.message}`);
    return [];
  }

  const heldFromWs = [];
  const deadline = Date.now() + effectiveTimeout;
  while (Date.now() < deadline && heldFromWs.length < count) {
    const msg = state.queue.shift();
    if (!msg) {
      await waitFor(Math.min(50, effectiveTimeout / 20));
      continue;
    }

    // Detect saturation early from WS errors.
    if (msg.error && looksLikeHoldTokenSaturated([msg.error])) {
      if (await tryRotateToken(count - heldFromWs.length)) {
        state.queue.length = 0;
        payload = { ...payload, token: activeHoldToken, tracing_id: wsParams.tracingId || `svr_ba_${Date.now()}` };
        state.server.send(compressWsMessage(JSON.stringify(payload)));
        continue;
      }
    }

    // Direct acknowledgement: { action: 'hold-object', data: { objects: [...] } }
    if (msg.action === 'hold-object' && msg.data && Array.isArray(msg.data.objects)) {
      for (const o of msg.data.objects) {
        const oid = typeof o === 'string' ? o : (o.objectId || o.label || o.id);
        if (oid && !heldFromWs.includes(oid)) heldFromWs.push(oid);
      }
    }

    // Status broadcasts: { data: { status, objectId, objects, numHeldByCurrentToken } }
    const data = msg.data || {};
    const status = data.status;
    const numHeld = data.numHeldByCurrentToken || 0;
    const responseObjects = [];
    if (Array.isArray(data.objects)) responseObjects.push(...data.objects);
    if (data.objectId) responseObjects.push(data.objectId);
    if ((status === 'reservedByToken' || status === 'held' || (status === 'free' && numHeld > 0)) && responseObjects.length) {
      for (const o of responseObjects) {
        const oid = typeof o === 'string' ? o : (o.objectId || o.label || o.id);
        if (oid && !heldFromWs.includes(oid)) heldFromWs.push(oid);
      }
    }
  }

  fileLog('INFO', `sendBestAvailableViaRoute WS: requested=${count}, held=${heldFromWs.length}`);

  // Ultimate source of truth: ask the server which seats this token holds.
  // If we know which seats the WS acknowledged, verify those; otherwise ask for all held seats.
  const verifyTargets = heldFromWs.length ? heldFromWs : [];
  const verified = await verifyHeldSeatsViaApi(page, activeHoldToken, verifyTargets, { session: opts.session });
  if (verified.length > 0) {
    fileLog('INFO', `sendBestAvailableViaRoute API verified ${verified.length} seats`);
    fileLog('TIMER', `sendBestAvailableViaRoute took ${Date.now() - baStart}ms -> ${verified.length}/${count}`);
    return verified;
  }

  // Fallback to WS result only if every requested seat was explicitly acknowledged.
  if (heldFromWs.length >= count) {
    fileLog('TIMER', `sendBestAvailableViaRoute took ${Date.now() - baStart}ms (WS fallback) -> ${heldFromWs.length}/${count}`);
    return heldFromWs.slice(0, count);
  }

  fileLog('TIMER', `sendBestAvailableViaRoute took ${Date.now() - baStart}ms -> 0/${count}`);
  return [];
}

function fireBestAvailableViaRoute(page, count, categories = []) {
  const state = wsRouteRegistry.get(page);
  if (!state || !state.server || state.closed || !state.ready) return false;

  const { token: holdToken, tracingId } = state.url
    ? (() => { try { const u = new URL(state.url); return { token: u.searchParams.get('token') || u.searchParams.get('holdToken') || u.searchParams.get('hold_token') || null, tracingId: u.searchParams.get('tracingId') || u.searchParams.get('tracing_id') || null }; } catch { return {}; } })()
    : {};
  if (!holdToken) return false;

  const payload = {
    action: 'hold-object',
    objects: [],
    bestAvailable: { number: count, categories: categories.map(String) },
    token: holdToken,
    tracing_id: tracingId || `svr_fire_${Date.now()}`,
  };
  try {
    state.server.send(compressWsMessage(JSON.stringify(payload)));
    return true;
  } catch (e) {
    return false;
  }
}

async function readSelectedSeatLabels(page, targetSections, targetCount) {
  // STRATEGY 1: Read from the API-held seats (source of truth)
  try {
    const frame = await findChartFrame(page);
    if (frame) {
      const keys = await frame.evaluate(() => ({
        workspaceKey: window.chartState?.workspaceKey || window.currentChartConfig?.workspaceKey,
        eventKey: window.chartState?.eventKey || window.currentChartConfig?.eventKey,
      })).catch(() => ({}));
      if (keys.workspaceKey && keys.eventKey) {
        const holdToken = await readChartHoldToken(page);
        if (holdToken) {
          const held = await verifyHeldSeatsViaApi(page, holdToken, []);
          if (held.length >= targetCount) {
            return held.slice(0, targetCount);
          }
        }
      }
    }
  } catch (e) {
    fileLog('WARN', `readSelectedSeatLabels API read failed: ${e.message}`);
  }

  // STRATEGY 2: Try to read selected objects from the chart iframe state
  const frames = page.frames().filter(f => /seatcloud\.com/.test(f.url() || ''));
  for (const frame of frames) {
    try {
      const labels = await frame.evaluate(() => {
        const sel = window.chartState?.selectedObjects || window.chartRender?.selectedObjects || window.chart?.selectedObjects;
        if (Array.isArray(sel)) {
          return sel.map(o => typeof o === 'string' ? o : (o.label || o.objectId || o.id || '')).filter(Boolean);
        }
        return [];
      });
      if (labels.length >= targetCount) return labels.slice(0, targetCount);
    } catch {}
  }

  // STRATEGY 3: Fallback - look for seat patterns like A4-D-1 in page text
  try {
    const text = await page.evaluate(() => document.body.innerText || '');
    const matches = text.match(/\b[A-Z]\d+[-–][A-Z][-–]\d+\b/g) || [];
    if (matches.length >= targetCount) return matches.slice(0, targetCount);
  } catch {}

  return [];
}

async function attemptRouteHoldWithCartVerify(page, targetSections, targetCount, username, timeoutMs = 1_500) {
  const routeState = wsRouteRegistry.get(page);
  if (!routeState || !routeState.server || routeState.closed || !routeState.ready) return [];

  emitStatus('seats-route-try', 'Firing bestAvailable via intercepted route and verifying via API...', { account: username });

  const targetSet = targetSections && targetSections.length
    ? new Set(targetSections.map(s => String(s).toUpperCase()))
    : null;

  // sendBestAvailableViaRoute now verifies against the server API before returning.
  const wsHeld = await sendBestAvailableViaRoute(page, targetCount, [], timeoutMs);
  if (wsHeld.length < targetCount) {
    return [];
  }

  // Enforce target-section filter if we have real labels.
  if (targetSet) {
    const allInTarget = wsHeld.every(s => targetSet.has(String(s).split('-')[0].toUpperCase()));
    if (!allInTarget) {
      emitStatus('seats-route-wrong', `bestAvailable held ${wsHeld.length} seats but not all in target sections`, { account: username, seats: wsHeld });
      return [];
    }
  }

  emitStatus('seats-route-selected', `Route held ${wsHeld.length} seats (API verified)`, { account: username, seats: wsHeld });
  return wsHeld.slice(0, targetCount);
}

// ------------------------------------------------------------------
// API resilience: circuit breaker + idempotent retries
// ------------------------------------------------------------------
const API_BREAKERS = new Map();
const API_BREAKER_FAILURE_THRESHOLD = 5;
const API_BREAKER_RESET_MS = 30000;
const API_RETRY_MAX = 2;
const API_RETRY_DELAY_MS = 150;
const API_RETRY_STATUSES = new Set([408, 429, 500, 502, 503, 504]);

function getApiBreaker(key) {
  if (!API_BREAKERS.has(key)) {
    API_BREAKERS.set(key, { state: 'CLOSED', failures: 0, lastFailure: 0, halfOpenAttempts: 0 });
  }
  const b = API_BREAKERS.get(key);
  const now = Date.now();
  if (b.state === 'OPEN' && now - b.lastFailure > API_BREAKER_RESET_MS) {
    b.state = 'HALF_OPEN';
    b.failures = 0;
    b.halfOpenAttempts = 0;
  }
  return b;
}

function isApiBreakerOpen(key) {
  const b = getApiBreaker(key);
  if (b.state === 'OPEN') return true;
  if (b.state === 'HALF_OPEN' && b.halfOpenAttempts >= 1) return true;
  return false;
}

function recordApiBreakerResult(key, success) {
  const b = getApiBreaker(key);
  if (success) {
    if (b.state === 'HALF_OPEN') {
      b.state = 'CLOSED';
    }
    b.failures = Math.max(0, b.failures - 1);
    b.halfOpenAttempts = 0;
  } else {
    b.lastFailure = Date.now();
    if (b.state === 'HALF_OPEN') {
      b.state = 'OPEN';
      b.failures = API_BREAKER_FAILURE_THRESHOLD;
    } else {
      b.failures += 1;
      if (b.failures >= API_BREAKER_FAILURE_THRESHOLD) {
        b.state = 'OPEN';
      }
    }
  }
}

function getApiHostname(url) {
  try { return new URL(url).hostname; } catch { return 'default'; }
}

async function sessionFetch(url, options = {}, session = null) {
  // Use the session's Playwright request context when available so the call
  // inherits the user's cookies and proxy. Falls back to the global fetch.
  // Wraps every request with circuit-breaker + idempotency-key + limited retries.
  const resilience = options.__resilience || {};
  const maxRetries = typeof resilience.maxRetries === 'number' ? resilience.maxRetries : API_RETRY_MAX;
  const retryDelayMs = typeof resilience.retryDelayMs === 'number' ? resilience.retryDelayMs : API_RETRY_DELAY_MS;
  const retryStatuses = resilience.retryStatuses ? new Set(resilience.retryStatuses) : API_RETRY_STATUSES;
  const breakerKey = resilience.breakerKey || getApiHostname(url);
  const skipBreaker = !!resilience.skipBreaker;

  if (!skipBreaker && isApiBreakerOpen(breakerKey)) {
    fileLog('WARN', `[resilience] circuit breaker OPEN for ${breakerKey}; rejecting ${url}`);
    throw new Error(`Circuit breaker open for ${breakerKey}`);
  }

  const idempotencyKey = crypto.randomUUID();
  const baseOptions = { ...options };
  delete baseOptions.__resilience;
  baseOptions.headers = baseOptions.headers ? { ...baseOptions.headers } : {};
  baseOptions.headers['Idempotency-Key'] = idempotencyKey;

  let lastError = null;
  let lastRes = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      let res;
      if (session?.context?.request) {
        const pwOpts = { ...baseOptions, timeout: baseOptions.timeout || 15000 };
        if ('body' in pwOpts) {
          pwOpts.data = pwOpts.body;
          delete pwOpts.body;
        }
        // Playwright's request.fetch does not accept an AbortSignal; rely on its timeout.
        delete pwOpts.signal;
        res = await session.context.request.fetch(url, pwOpts);
        lastRes = {
          ok: res.ok(),
          status: res.status(),
          headers: res.headers(),
          text: () => res.text(),
          json: () => res.json(),
          arrayBuffer: () => res.body().then(b => Buffer.from(b)),
        };
      } else {
        res = await fetch(url, baseOptions);
        lastRes = res;
      }

      if (lastRes.ok || !retryStatuses.has(lastRes.status)) {
        if (!skipBreaker) recordApiBreakerResult(breakerKey, true);
        return lastRes;
      }

      lastError = new Error(`HTTP ${lastRes.status}`);
      if (attempt < maxRetries) {
        const delay = retryDelayMs * (2 ** attempt) + Math.floor(Math.random() * 100);
        fileLog('INFO', `[resilience] ${breakerKey} HTTP ${lastRes.status} attempt ${attempt + 1}/${maxRetries + 1}; retrying in ${delay}ms`);
        await waitFor(delay);
      }
    } catch (e) {
      lastError = e;
      if (attempt < maxRetries) {
        const delay = retryDelayMs * (2 ** attempt) + Math.floor(Math.random() * 100);
        fileLog('INFO', `[resilience] ${breakerKey} request error: ${e.message} attempt ${attempt + 1}/${maxRetries + 1}; retrying in ${delay}ms`);
        await waitFor(delay);
      }
    }
  }

  if (!skipBreaker) recordApiBreakerResult(breakerKey, false);
  if (lastRes) return lastRes;
  throw lastError;
}

async function getProxyIp(session) {
  // Ask a public IP echo service through the session's request context so we
  // report the IP seen by webook/seatcloud (i.e. the proxy IP).
  if (!session?.context?.request) return null;
  try {
    const res = await session.context.request.get('https://api.ipify.org?format=json', { timeout: 10000 });
    if (res.ok()) {
      const data = await res.json().catch(() => ({}));
      return data.ip || null;
    }
  } catch (e) {
    fileLog('WARN', `[${session.username}] Proxy IP check failed: ${e.message}`);
  }
  return null;
}

async function getHoldTokenFromApi(slug, webookEventId, session = null) {
  try {
    const traceId = makeTraceId();
    const url = `${WB_API_BASE}/event-detail/${slug}/hold-token?lang=ar&trace_id=${traceId}`;
    const authToken = session?.context && session?.username
      ? await getAuthTokenFromContext(session.context, session.username)
      : null;
    const headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Origin': WB_ORIGIN,
      'Referer': `${WB_ORIGIN}/`,
      'token': authToken || WB_API_TOKEN,
    };
    if (authToken) headers.Authorization = `Bearer ${authToken}`;

    const res = await sessionFetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ event_id: webookEventId, lang: 'ar' }),
    }, session);
    if (!res.ok) {
      fileLog('WARN', `getHoldTokenFromApi HTTP ${res.status}: ${await res.text().catch(() => '')}`);
      return null;
    }
    const data = await res.json();
    return extractHoldToken(data);
  } catch (e) {
    fileLog('WARN', `getHoldTokenFromApi error: ${e.message}`);
    return null;
  }
}

function extractHoldToken(payload) {
  if (!payload || typeof payload !== 'object') return null;
  const stack = [payload];
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

async function readChartHoldToken(page, slug = null, webookEventId = null) {
  // If a holdToken account explicitly forced a token for this page, use it.
  const forced = forcedHoldTokenRegistry.get(page);
  if (forced) {
    fileLog('DEBUG', `readChartHoldToken returning forced token ${forced.slice(0, 8)}...${forced.slice(-4)}`);
    return forced;
  }

  // The WebSocket URL token is the SeatCloud hold token for this session.
  // It is also the token used by the chart's own /items/held verification call.
  const routeState = wsRouteRegistry.get(page);
  if (routeState && routeState.url) {
    try {
      const url = new URL(routeState.url);
      for (const key of ['hold_token', 'holdToken', 'token']) {
        const v = url.searchParams.get(key);
        if (v) return v;
      }
    } catch {}
  }

  const frame = await findChartFrame(page);
  if (frame) {
    try {
      const url = new URL(frame.url());
      for (const key of ['hold_token', 'holdToken', 'token']) {
        const v = url.searchParams.get(key);
        if (v) return v;
      }
    } catch {}
    try {
      const tok = await frame.evaluate(() =>
        (window.chartState && window.chartState.holdToken) ||
        (window.currentChartConfig && window.currentChartConfig.holdToken) ||
        null
      );
      if (tok) return tok;
    } catch {}
  }
  try {
    const cookies = await page.context().cookies();
    for (const c of cookies) {
      if (c.name === 'holdToken' && c.value) return c.value;
    }
  } catch {}

  if (slug) {
    let eventId = webookEventId;
    if (!eventId) {
      try {
        const detail = await fetchEventDetail(slug);
        eventId = detail?._id || detail?.data?._id || null;
      } catch {}
    }
    if (eventId) {
      return await getHoldTokenFromApi(slug, eventId);
    }
  }
  return null;
}

async function readChartWsParams(page) {
  // Extract the hold token, tracingId and channel/allocation list from the chart WebSocket URL.
  const routeState = wsRouteRegistry.get(page);
  if (routeState && routeState.url) {
    try {
      const url = new URL(routeState.url);
      const token = url.searchParams.get('token') || url.searchParams.get('holdToken') || url.searchParams.get('hold_token') || null;
      const tracingId = url.searchParams.get('tracingId') || url.searchParams.get('tracing_id') || null;
      const channel = url.searchParams.get('channel') || 'NO_CHANNEL';
      if (token || tracingId) return { token, tracingId, channel };
    } catch {}
  }
  const frame = await findChartFrame(page);
  if (frame) {
    try {
      const url = new URL(frame.url());
      const token = url.searchParams.get('token') || url.searchParams.get('holdToken') || url.searchParams.get('hold_token') || null;
      const tracingId = url.searchParams.get('tracingId') || url.searchParams.get('tracing_id') || null;
      const channel = url.searchParams.get('channel') || 'NO_CHANNEL';
      if (token || tracingId) return { token, tracingId, channel };
    } catch {}
  }
  const token = await readChartHoldToken(page);
  return { token, tracingId: null, channel: 'NO_CHANNEL' };
}

async function waitForWsRouteReady(page, timeoutMs = 2500) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const state = wsRouteRegistry.get(page);
    if (state && state.ready && state.url) {
      const token = await readChartHoldToken(page);
      if (token) return true;
    }
    await waitFor(25);
  }
  return false;
}

async function waitForChartWebSocket(frame, timeoutMs = 30000) {
  const start = Date.now();
  // Periodically nudge the chart to encourage WebSocket creation
  let lastNudge = 0;
  while (Date.now() - start < timeoutMs) {
    const ok = await frame.evaluate(() => window.__chartWS && window.__chartWS.readyState === 1).catch(() => false);
    if (ok) return true;
    if (Date.now() - lastNudge > 2000) {
      try {
        await frame.evaluate(() => {
          // Trigger a harmless event to wake the chart
          window.dispatchEvent(new Event('resize'));
          if (window.chartRender && window.chartRender.redraw) window.chartRender.redraw();
        });
      } catch {}
      lastNudge = Date.now();
    }
    await waitFor(200);
  }
  return false;
}

function installChartDetectionHook(page, session) {
  if (!page || !session) return;
  session.__chartWsReady = false;
  session.__chartFrameAttached = false;
  session.__chartWsAttachedAt = 0;

  const onFrame = (frame) => {
    const url = frame.url() || '';
    if (url.includes('seatcloud') || url.includes('seats.io') || url.includes('chart.seatcloud')) {
      session.__chartFrameAttached = true;
      session.__chartFrameAttachedAt = Date.now();
    }
  };
  const onWebSocket = (ws) => {
    const url = ws.url() || '';
    if (url.includes('seatcloud') || url.includes('seats.io')) {
      session.__chartWsReady = true;
      session.__chartWsAttachedAt = Date.now();
      ws.on('close', () => {
        session.__chartWsReady = false;
      });
    }
  };
  page.on('frameattached', onFrame);
  page.on('frameready', onFrame);
  page.on('websocket', onWebSocket);
}

async function waitForChartAndStartImmediate(page, session, options = {}) {
  const timeoutMs = options.timeoutMs || 30000;
  const pollIntervalMs = options.pollIntervalMs || 200;
  const start = Date.now();
  const username = session?.username || 'unknown';

  while (Date.now() - start < timeoutMs) {
    const frame = await findChartFrame(page, username);
    if (frame) {
      const hasSvg = await frame.evaluate(() => !!document.querySelector('svg, [class*="seat" i], [class*="object" i], canvas')).catch(() => false);
      const wsReady = await frame.evaluate(() => window.__chartWS && window.__chartWS.readyState === 1).catch(() => false);
      if (hasSvg || wsReady || session?.__chartWsReady) {
        return { frame, chartFrame: frame, elapsed: Date.now() - start };
      }
    }
    if (session?.__chartFrameAttached || session?.__chartWsReady) {
      const maybeFrame = await findChartFrame(page, username);
      if (maybeFrame) return { frame: maybeFrame, chartFrame: maybeFrame, elapsed: Date.now() - start };
    }
    await waitFor(pollIntervalMs);
  }
  throw new Error(`Chart did not become ready within ${timeoutMs}ms for ${username}`);
}

function sha256Utf8(text) {
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest();
}

function tryAesGcmDecrypt(buf, passphrase) {
  try {
    if (buf.length < 12 + 16) return null;
    const key = sha256Utf8(passphrase);
    const iv = buf.slice(0, 12);
    const rest = buf.slice(12);
    const authTag = rest.slice(rest.length - 16);
    const ciphertext = rest.slice(0, rest.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plain;
  } catch {
    return null;
  }
}

function tryGunzip(buf) {
  try { return zlib.gunzipSync(buf); } catch { return null; }
}

function tryInflate(buf) {
  try { return zlib.inflateSync(buf); } catch { return null; }
}

function tryDecompress(buf) {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    const r = tryGunzip(buf);
    if (r) return r;
  }
  const r = tryInflate(buf);
  if (r) return r;
  return null;
}

function xorDecrypt(buf, key) {
  const keyBuf = Buffer.from(key, 'utf8');
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i] ^ keyBuf[i % keyBuf.length];
  }
  return out;
}

function decodeSeatcloudItems(rawBytes, { eventKey, holdToken } = {}) {
  // The SeatCloud API returns responses in several possible encodings.
  // Order of attempts matters because some binary payloads can accidentally
  // parse as other formats, so we start with the cheapest/safest checks.

  // 1. Plain JSON (e.g. empty held list "[]").
  try {
    const text = rawBytes.toString('utf8').trim();
    if (text.length > 0 && (text[0] === '[' || text[0] === '{')) {
      return JSON.parse(text);
    }
  } catch {}

  // 2. Already gzip-compressed JSON (rare, but possible).
  const decompressed = tryDecompress(rawBytes);
  if (decompressed) {
    try { return JSON.parse(decompressed.toString('utf8')); } catch {}
  }

  // 3. AES-256-GCM encrypted binary, key = SHA-256(holdToken).
  //    Used by /items/held when the token actually holds seats.
  if (holdToken) {
    const plain = tryAesGcmDecrypt(rawBytes, holdToken);
    if (plain) {
      const decompressed = tryDecompress(plain);
      const final = decompressed || plain;
      try { return JSON.parse(final.toString('utf8')); } catch {}
    }
  }

  // 4. XOR + gzip, key = eventKey. Used by /items (full seat map).
  if (eventKey) {
    const xored = xorDecrypt(rawBytes, eventKey);
    const decompressed = tryDecompress(xored);
    const final = decompressed || xored;
    try { return JSON.parse(final.toString('utf8')); } catch {}
  }

  // 5. Last resort: return whatever text we can extract.
  try {
    return JSON.parse(rawBytes.toString('utf8'));
  } catch {
    throw new Error(`decodeSeatcloudItems: unable to decode ${rawBytes.length} bytes`);
  }
}

async function fetchSeatcloudItemsRaw(workspaceKey, eventKey, session = null, channel = 'NO_CHANNEL', paramName = 'allocations', signal = null) {
  const url = `https://api.seatcloud.com/api/v2/${workspaceKey}/event/${eventKey}/items?${paramName}=${encodeURIComponent(channel)}&trace_id=${makeTraceId()}&plain=true`;
  const fetchOptions = {
    headers: {
      'Accept': 'application/json',
      'Accept-Encoding': 'identity',
      'Accept-Language': 'ar-SA,ar;q=0.9',
      'Origin': WB_ORIGIN,
      'Referer': `${WB_ORIGIN}/`,
    },
  };
  // Defensive: ensure a usable AbortSignal is always present.
  let effectiveSignal = signal;
  if (!effectiveSignal || typeof effectiveSignal !== 'object' || typeof effectiveSignal.aborted === 'undefined') {
    const controller = new AbortController();
    effectiveSignal = controller.signal;
  }
  fetchOptions.signal = effectiveSignal;
  const res = await sessionFetch(url, fetchOptions, session);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const items = decodeSeatcloudItems(buf, { eventKey });
  return { items, bytes: buf.length };
}

function totalAvailableCount(items) {
  if (!Array.isArray(items)) return 0;
  return items.reduce((sum, it) => sum + Math.max(0, it.availableCount || 0), 0);
}

function itemsHaveAvailability(items) {
  if (!Array.isArray(items) || items.length === 0) return false;
  return totalAvailableCount(items) > 0 || items.some(it => typeof it.availableCount === 'number');
}

async function fetchSeatcloudItems(workspaceKey, eventKey, session = null, explicitChannelKeys = null) {
  const lockKey = `${workspaceKey}:${eventKey}`;
  // Serialize concurrent fetches for the same event so N snipers do not hammer
  // the SeatCloud items endpoint at the exact same millisecond.
  while (SEATCLOUD_FETCH_LOCKS.has(lockKey)) {
    try { await SEATCLOUD_FETCH_LOCKS.get(lockKey); } catch {}
  }
  let release;
  const lockPromise = new Promise((resolve) => { release = resolve; });
  SEATCLOUD_FETCH_LOCKS.set(lockKey, lockPromise);

  try {
    const sessionChannel = getSeatcloudChannel(session, session?.page);
    const channelKeys = explicitChannelKeys || getSelectedTeamChannelKeys(session);
    // When explicit channel keys are passed (e.g. section pre-fetch without a
    // session) the best-guess channel is those keys, not NO_CHANNEL.
    const channel = explicitChannelKeys?.length
      ? channelKeys.join(',')
      : sessionChannel;

    // Build a list of candidate channel/param combinations. Sports/team events
    // expose availability per SeatCloud allocation channel (UUID), not per Webook
    // team id, so we must use the channel_keys UUIDs from the event detail.
    const candidates = [];
    candidates.push({ param: 'allocations', channel });
    if (channelKeys.length) {
      candidates.push({ param: 'allocations', channel: channelKeys.join(',') });
      candidates.push({ param: 'allocations', channel: ['NO_CHANNEL', ...channelKeys].join(',') });
      candidates.push({ param: 'channels', channel: channelKeys.join(',') });
      candidates.push({ param: 'channels', channel: ['NO_CHANNEL', ...channelKeys].join(',') });
      for (const ck of channelKeys) {
        candidates.push({ param: 'allocations', channel: ck });
        candidates.push({ param: 'channels', channel: ck });
      }
    }
    candidates.push({ param: 'channels', channel: 'NO_CHANNEL' });
    candidates.push({ param: 'allocations', channel: 'NO_CHANNEL' });

    let bestResult = null;
    let bestAvailable = -1;
    let lastError = null;

    // Run candidate channel/param combinations in parallel with a per-candidate
    // timeout so slow or invalid channels do not block the sniper.
    const CANDIDATE_TIMEOUT_MS = 5000;
    const candidateResults = await Promise.allSettled(
      candidates.map(async ({ param, channel: ch }) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), CANDIDATE_TIMEOUT_MS);
        try {
          const { items, bytes } = await fetchSeatcloudItemsRaw(workspaceKey, eventKey, session, ch, param, controller.signal);
          const avail = totalAvailableCount(items);
          const hasData = Array.isArray(items) && items.length > 0;
          fileLog('INFO', `[fetchSeatcloudItems] ${param}=${ch} => ${bytes} bytes, ${Array.isArray(items) ? items.length : 0} items, avail=${avail}`);
          return { items, param, channel: ch, avail, hasData };
        } finally {
          clearTimeout(timer);
        }
      })
    );

    for (const result of candidateResults) {
      if (result.status === 'rejected') {
        lastError = result.reason;
        fileLog('INFO', `[fetchSeatcloudItems] candidate failed: ${result.reason?.message || result.reason}`);
        continue;
      }
      const { items, param, channel: ch, avail, hasData } = result.value;
      if (hasData && (avail > bestAvailable || (!bestResult && avail === 0))) {
        bestResult = { items, param, channel: ch };
        bestAvailable = avail;
      }
    }

    if (bestResult) {
      if (session) {
        session.itemsParamName = bestResult.param;
        session.itemsChannel = bestResult.channel;
      }
      return bestResult.items;
    }

    if (lastError) throw lastError;
    return [];
  } finally {
    release();
    SEATCLOUD_FETCH_LOCKS.delete(lockKey);
  }
}

// Validate a SeatCloud hold token via the public /token endpoint. Returns token
// metadata (ttl, maxNumberOfHolds, teamKey) if valid, or null if invalid/expired.
async function validateHoldTokenViaSeatCloud(holdToken, session = null) {
  if (!holdToken) return { valid: false, reason: 'missing token' };
  try {
    const traceId = makeTraceId();
    const url = `https://api.seatcloud.com/api/v2/token/${encodeURIComponent(holdToken)}?trace_id=${traceId}`;
    const res = await sessionFetch(url, {
      headers: {
        'Accept': 'application/json',
        'Accept-Encoding': 'identity',
        'Accept-Language': 'ar-SA,ar;q=0.9',
        'Origin': WB_ORIGIN,
        'Referer': `${WB_ORIGIN}/`,
      },
    }, session);
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      return { valid: false, reason: `HTTP ${res.status}`, body: text.slice(0, 200) };
    }
    const data = await res.json().catch(() => null);
    if (!data || !data.token) return { valid: false, reason: 'invalid response' };
    return {
      valid: true,
      token: data.token,
      teamKey: data.teamKey,
      ttl: data.ttl,
      expiresAt: data.expiresAt,
      maxNumberOfHolds: data.maxNumberOfHolds,
      currentlyHeld: 0, // caller can fetch /items/held separately
    };
  } catch (e) {
    return { valid: false, reason: e.message };
  }
}

// Hold seats through the SeatCloud REST API. This is the reliable path when a
// hold token is provided (forced) because the WebSocket connection itself is
// bound to the logged-in user's token, so REST with the explicit token is the
// only way to hold under a different account.
async function holdSeatsViaRestApi(workspaceKey, eventKey, holdToken, objectIds, opts = {}) {
  const seats = [...new Set((objectIds || []).map(String).filter(Boolean))];
  if (!workspaceKey || !eventKey || !holdToken || seats.length === 0) return [];

  const session = opts.session || null;
  const channel = getSeatcloudChannel(session, session?.page);
  const paramName = getItemsParamName(session);
  const traceId = makeTraceId();
  const url = `https://api.seatcloud.com/api/v2/${workspaceKey}/event/${eventKey}/actions/hold`;

  async function tryHold(allocFieldName) {
    const body = {
      holdToken,
      objects: seats.map(objectId => ({ objectId })),
      [allocFieldName]: channel,
    };
    const res = await sessionFetch(`${url}?trace_id=${traceId}&plain=true`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Accept-Encoding': 'identity',
        'Accept-Language': 'ar-SA,ar;q=0.9',
        'Content-Type': 'application/json',
        'Origin': WB_ORIGIN,
        'Referer': `${WB_ORIGIN}/`,
      },
      body: JSON.stringify(body),
    }, session);

    const resText = await res.text().catch(() => '');
    fileLog('INFO', `[REST hold] ${url} (${allocFieldName}) HTTP ${res.status}: ${resText.slice(0, 300)}`);

    if (!res.ok) return [];

    let data = null;
    try {
      data = JSON.parse(resText);
    } catch {
      data = decodeSeatcloudItems(Buffer.from(resText, 'utf8'), { eventKey, holdToken });
    }

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

  try {
    fileLog('INFO', `[REST hold] Trying ${url} for ${seats.length} seat(s)`);
    let held = await tryHold(paramName === 'channels' ? 'channels' : 'allocations');
    if (held.length) {
      fileLog('INFO', `[REST hold] ${url} succeeded: ${held.length}/${seats.length}`);
      return held;
    }
    // Fallback to the alternate field name if the first attempt returned empty.
    const fallback = paramName === 'channels' ? 'allocations' : 'channels';
    held = await tryHold(fallback);
    if (held.length) {
      if (session) session.itemsParamName = fallback;
      fileLog('INFO', `[REST hold] ${url} succeeded with ${fallback}: ${held.length}/${seats.length}`);
      return held;
    }
  } catch (e) {
    fileLog('WARN', `[REST hold] error: ${e.message}`);
  }

  return [];
}

// Validate that a provided hold token is still accepted by SeatCloud.
async function validateHoldToken(workspaceKey, eventKey, holdToken, channel = 'NO_CHANNEL', session = null) {
  if (!workspaceKey || !eventKey || !holdToken) return { valid: false, reason: 'missing args' };
  const paramName = session?.itemsParamName || 'allocations';
  const url = `https://api.seatcloud.com/api/v2/${workspaceKey}/event/${eventKey}/items/held?hold_token=${encodeURIComponent(holdToken)}&${paramName}=${encodeURIComponent(channel)}&trace_id=${makeTraceId()}&plain=true`;
  try {
    const res = await sessionFetch(url, {
      headers: {
        'Accept': 'application/json',
        'Accept-Encoding': 'identity',
        'Accept-Language': 'ar-SA,ar;q=0.9',
        'Origin': WB_ORIGIN,
        'Referer': `${WB_ORIGIN}/`,
      },
    }, session);
    if (!res.ok) return { valid: false, reason: `HTTP ${res.status}` };
    const buf = Buffer.from(await res.arrayBuffer());
    const held = decodeSeatcloudItems(buf, { eventKey, holdToken });
    return { valid: true, currentlyHeld: Array.isArray(held) ? held.length : 0 };
  } catch (e) {
    return { valid: false, reason: e.message };
  }
}

// Verify which of the wanted seats are actually held on the server right now.
// This is the only reliable source of truth; cart counters and WS responses can lie.
async function verifyHeldSeatsViaApi(page, holdToken, wantedSeats, opts = {}) {
  const wantedSet = new Set(wantedSeats.map(String));
  const retries = opts.retries ?? 1;
  const retryDelay = opts.retryDelay ?? 80;
  let lastError = null;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      let workspaceKey = opts.session?.workspaceKey;
      let eventKey = opts.session?.eventKey;
      if (!workspaceKey || !eventKey) {
        const frame = await findChartFrame(page);
        if (!frame) { lastError = 'no chart frame'; continue; }
        const keys = await frame.evaluate(() => ({
          workspaceKey: window.chartState?.workspaceKey || window.currentChartConfig?.workspaceKey,
          eventKey: window.chartState?.eventKey || window.currentChartConfig?.eventKey,
        })).catch(() => ({}));
        workspaceKey = keys.workspaceKey;
        eventKey = keys.eventKey;
        if (workspaceKey && eventKey && opts.session) {
          opts.session.workspaceKey = workspaceKey;
          opts.session.eventKey = eventKey;
        }
      }
      if (!workspaceKey || !eventKey) { lastError = 'missing workspace/event keys'; continue; }

      // Fetch from Node.js to bypass the iframe CORS restrictions.
      // Match the browser's own call: include plain=true and decode the XOR+gzip payload.
      const channel = getSeatcloudChannel(opts.session, page);
      const paramName = getItemsParamName(opts.session);
      const traceId = makeTraceId();
      const heldUrl = `https://api.seatcloud.com/api/v2/${workspaceKey}/event/${eventKey}/items/held?hold_token=${encodeURIComponent(holdToken)}&${paramName}=${encodeURIComponent(channel)}&trace_id=${traceId}&plain=true`;
      const res = await sessionFetch(heldUrl, {
        headers: {
          'Accept': 'application/json',
          'Accept-Encoding': 'identity',
          'Accept-Language': 'ar-SA,ar;q=0.9',
          'Origin': WB_ORIGIN,
          'Referer': `${WB_ORIGIN}/`,
        },
      }, opts.session || null);
      if (!res.ok) {
        lastError = `HTTP ${res.status}`;
        fileLog('WARN', `verifyHeldSeatsViaApi HTTP ${res.status}: ${await res.text().catch(() => '')}`);
        continue;
      }

      let held;
      let buf = Buffer.alloc(0);
      try {
        buf = Buffer.from(await res.arrayBuffer());
        held = decodeSeatcloudItems(buf, { eventKey, holdToken });
      } catch (decodeErr) {
        lastError = `decode error: ${decodeErr.message}`;
        fileLog('WARN', `verifyHeldSeatsViaApi decode error: ${decodeErr.message}; bytes=${buf.length}`);
        continue;
      }

      if (!Array.isArray(held)) {
        lastError = 'non-array response';
        fileLog('WARN', `verifyHeldSeatsViaApi returned non-array: ${JSON.stringify(held).slice(0, 200)}`);
        continue;
      }

      const heldLabels = held
        .map(it => it.label || it.name || it.objectId || it.id)
        .filter(Boolean)
        .map(String);
      if (wantedSeats.length === 0) {
        fileLog('INFO', `verifyHeldSeatsViaApi: returning all ${heldLabels.length} held seats`);
        return heldLabels;
      }
      const verified = heldLabels.filter(l => wantedSet.has(l));
      fileLog('INFO', `verifyHeldSeatsViaApi attempt ${attempt}/${retries}: wanted=${wantedSeats.length}, held=${heldLabels.length}, verified=${verified.length}`);
      // If we verified something, return immediately; partial results are still useful.
      if (verified.length > 0 || attempt === retries) return verified;
      lastError = `verified 0/${wantedSeats.length}`;
    } catch (e) {
      lastError = e.message;
      fileLog('WARN', `verifyHeldSeatsViaApi attempt ${attempt}/${retries} error: ${e.message}`);
    }
    if (attempt < retries) await waitFor(retryDelay);
  }

  fileLog('WARN', `verifyHeldSeatsViaApi failed after ${retries} attempts: ${lastError}`);
  return [];
}

async function getTicketCount(page) {
  return page.evaluate(() => {
    const text = document.body.innerText || '';
    // Arabic and English ticket labels, prefer a number immediately before the word.
    const patterns = [
      /(\d+)\s*تذاكر/,
      /(\d+)\s*تذكرة/,
      /(\d+)\s*tickets/i,
      /(\d+)\s*ticket/i,
    ];
    for (const p of patterns) {
      const m = text.match(p);
      if (m) return parseInt(m[1], 10);
    }
    return 0;
  });
}

async function refreshPageToSyncCart(session) {
  // If the WeBook parent page still shows fewer tickets than the server holds,
  // reload the booking page with the hold token so the React cart rehydrates
  // from the SeatCloud held-items API. This fixes the common mismatch where the
  // chart iframe shows 30 held seats but the sticky cart summary shows 5.
  if (!session?.page || await isPageClosed(session.page) || !session.holdToken) return;
  const { page, username, holdToken, selectedSeats } = session;
  if (!selectedSeats?.length) return;
  try {
    const cartCount = await getTicketCount(page);
    if (cartCount >= selectedSeats.length) return;
    emitStatus('cart-refresh', `Cart shows ${cartCount} ticket(s) but ${selectedSeats.length} held; refreshing booking page to sync`, {
      account: username,
      cartCount,
      held: selectedSeats.length,
    });
    let refreshUrl = page.url();
    if (!refreshUrl.includes('/book')) {
      refreshUrl = refreshUrl.replace(/\/?$/, '/book');
    }
    refreshUrl = refreshUrl.replace(/([?&])hold_token=[^&]*/g, '$1');
    refreshUrl = refreshUrl.replace(/\?&/, '?').replace(/&&/g, '&').replace(/[?&]$/, '');
    refreshUrl += `${refreshUrl.includes('?') ? '&' : '?'}hold_token=${encodeURIComponent(holdToken)}`;
    await page.goto(refreshUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await waitFor(2500);
    await dismissAllBanners(page, username, 'post-cart-refresh');
    const frame = await findChartFrame(page, username);
    if (frame) {
      await syncChartSelection(frame, selectedSeats, { page, username });
      emitStatus('cart-refreshed', `Booking page refreshed; re-synced ${selectedSeats.length} seat(s) to chart`, { account: username, seats: selectedSeats });
    }
  } catch (e) {
    fileLog('WARN', `[${session.username}] refreshPageToSyncCart warning: ${e.message}`);
  }
}

async function extendHoldTokenViaRestApi(session, minutes = 15) {
  if (!session?.holdToken) return { success: false, reason: 'no-hold-token' };
  const token = session.holdToken;
  const endpoints = [
    `https://api.seatcloud.com/api/v2/hold-tokens/${encodeURIComponent(token)}`,
    `https://api.seatcloud.com/hold-tokens/${encodeURIComponent(token)}`,
    `https://api-eu.seatsio.net/hold-tokens/${encodeURIComponent(token)}`,
    `https://api-na.seatsio.net/hold-tokens/${encodeURIComponent(token)}`,
  ];
  const body = JSON.stringify({ expiresInMinutes: minutes });
  for (const url of endpoints) {
    try {
      const res = await sessionFetch(url, {
        method: 'POST',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', 'Origin': WB_ORIGIN, 'Referer': `${WB_ORIGIN}/` },
        body,
      }, session);
      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        fileLog('INFO', `[${session.username}] Hold token extended via REST: ${url}`);
        return { success: true, endpoint: url, expiresAt: data.expiresAt, expiresInSeconds: data.expiresInSeconds, newToken: data.holdToken || token };
      }
      const text = await res.text().catch(() => '');
      fileLog('INFO', `[${session.username}] Hold token REST extension attempt failed at ${url}: HTTP ${res.status} ${text.slice(0, 200)}`);
    } catch (e) {
      fileLog('INFO', `[${session.username}] Hold token REST extension attempt error at ${url}: ${e.message}`);
    }
  }
  return { success: false, reason: 'all-endpoints-failed' };
}

async function extendHoldToken(session) {
  if (!session || !session.page || await isPageClosed(session.page)) {
    return { success: false, error: 'No active session page' };
  }
  const oldToken = session.holdToken;
  const pageSlug = parseSlug(session.page.url());
  try {
    // Primary attempt: extend the existing token through the public REST API.
    // This works when SeatCloud/Seats.io exposes a public hold-token extension
    // endpoint; otherwise we fall back to refreshing the token via the chart.
    try {
      const restExt = await extendHoldTokenViaRestApi(session, HOLD_TOKEN_EXTENSION_MINUTES);
      if (restExt.success) {
        const serverExpiresAt = restExt.expiresAt || null;
        touchHoldToken(session, session.holdToken, HOLD_TOKEN_EXTENSION_MINUTES, serverExpiresAt);
        const verified = await verifyHeldSeatsViaApi(session.page, session.holdToken, session.selectedSeats, { session });
        emitStatus('token-extended', `Hold token extended via REST; verified ${verified.length}/${session.selectedSeats.length} seats`, {
          account: session.username,
          oldToken: oldToken ? `${oldToken.slice(0, 12)}...` : null,
          newToken: `${session.holdToken.slice(0, 12)}...`,
          seats: verified,
          viaRest: true,
        });
        return { success: true, oldToken, newToken: session.holdToken, verifiedSeats: verified, viaRest: true };
      }
    } catch (e) {
      fileLog('INFO', `[${session.username}] REST extension error: ${e.message}`);
    }

    // Fallback: obtain a fresh hold token from the chart state or API and re-hold seats.
    let newToken = await readChartHoldToken(session.page, pageSlug);
    if (!newToken && pageSlug) {
      try {
        const detail = await fetchEventDetail(pageSlug);
        const eventId = detail?._id || detail?.data?._id || null;
        if (eventId) newToken = await getHoldTokenFromApi(pageSlug, eventId, session);
      } catch {}
    }
    if (!newToken) {
      return { success: false, error: 'Could not retrieve a new hold token' };
    }
    if (newToken === oldToken) {
      // Even if the token did not change, the act of re-reading may have refreshed cookie state.
      // Re-send holds to extend the server-side expiry.
      touchHoldToken(session, newToken, HOLD_TOKEN_EXTENSION_MINUTES);
      await syncQueueTokenToCookie(session.context, null, newToken);
    } else {
      if (oldToken) unregisterHoldToken(oldToken);
      session.holdToken = newToken;
      touchHoldToken(session, newToken, HOLD_TOKEN_EXTENSION_MINUTES);
      registerHoldToken(session.username, newToken);
      await syncQueueTokenToCookie(session.context, null, newToken);
      fileLog('INFO', `[${session.username}] Hold token refreshed: ${oldToken?.slice(0, 12)}... -> ${newToken.slice(0, 12)}...`);
    }

    // Re-hold current seats through the chart WebSocket with the (possibly new) token.
    const frame = await findChartFrame(session.page, session.username);
    if (frame) {
      const wsParams = await readChartWsParams(session.page);
      await sendHoldViaFrame(frame, session.selectedSeats, { token: session.holdToken, tracingId: wsParams.tracingId, page: session.page, username: session.username });
    }

    let verified = await verifyHeldSeatsViaApi(session.page, session.holdToken, session.selectedSeats, { session });

    // If extension/rotation resulted in zero held seats, attempt immediate recovery.
    if (session.selectedSeats.length > 0 && (!verified || verified.length === 0)) {
      emitStatus('token-zero-held', `Hold token valid but zero seats held; attempting recovery`, { account: session.username });
      const frame = await findChartFrame(session.page, session.username);
      if (frame) {
        const wsParams = await readChartWsParams(session.page);
        await sendHoldViaFrame(frame, session.selectedSeats, { token: session.holdToken, tracingId: wsParams.tracingId, page: session.page, username: session.username });
        verified = await verifyHeldSeatsViaApi(session.page, session.holdToken, session.selectedSeats, { session });
      }
    }

    emitStatus('token-extended', `Hold token extended; verified ${verified.length}/${session.selectedSeats.length} seats`, {
      account: session.username,
      oldToken: oldToken ? `${oldToken.slice(0, 12)}...` : null,
      newToken: `${newToken.slice(0, 12)}...`,
      seats: verified,
    });
    return { success: true, oldToken, newToken, verifiedSeats: verified };
  } catch (e) {
    emitStatus('token-extend-failed', `Failed to extend hold token: ${e.message}`, { account: session.username });
    return { success: false, error: e.message };
  }
}

async function refreshHoldTokenIfSaturated(session, needed, workspaceKey, eventKey) {
  // If the current token has less capacity than needed, try to rotate it.
  if (!session || !session.holdToken) return false;
  try {
    const channel = getSeatcloudChannel(session, session?.page);
    const v = await validateHoldToken(workspaceKey, eventKey, session.holdToken, channel, session);
    const capacity = Math.max(0, MAX_HELD_SEATS - (v.currentlyHeld || 0));
    if (capacity >= needed) return true;
    emitStatus('token-saturated', `Token capacity ${capacity} < needed ${needed}; rotating...`, { account: session.username, currentlyHeld: v.currentlyHeld });
    const ext = await extendHoldToken(session);
    if (ext.success && ext.newToken) {
      const v2 = await validateHoldToken(workspaceKey, eventKey, session.holdToken, channel, session);
      const cap2 = Math.max(0, MAX_HELD_SEATS - (v2.currentlyHeld || 0));
      if (cap2 >= needed) return true;
    }
    const pageSlug = parseSlug(session.page.url());
    if (pageSlug) {
      try {
        const detail = await fetchEventDetail(pageSlug);
        const eventId = detail?._id || detail?.data?._id || null;
        if (eventId) {
          const newToken = await getHoldTokenFromApi(pageSlug, eventId, session);
          if (newToken && newToken !== session.holdToken) {
            session.holdToken = newToken;
            touchHoldToken(session, newToken, 15);
            await syncQueueTokenToCookie(session.context, null, newToken);
            const v3 = await validateHoldToken(workspaceKey, eventKey, session.holdToken, channel, session);
            const cap3 = Math.max(0, MAX_HELD_SEATS - (v3.currentlyHeld || 0));
            if (cap3 >= needed) return true;
          }
        }
      } catch {}
    }
    return false;
  } catch (e) {
    fileLog('WARN', `[${session?.username}] refreshHoldTokenIfSaturated error: ${e.message}`);
    return false;
  }
}

function startHoldKeepalive(session) {
  if (session.holdInterval) clearInterval(session.holdInterval);
  session.tokenExtensions = session.tokenExtensions || 0;
  session.holdInterval = setInterval(async () => {
    if (!session.page || session.stopRequested || session.isSelecting || session.keepalivePaused || session.isTransferring) return;
    if (await isPageClosed(session.page)) return;
    // Soft-stop (bookingPaused) still extends/re-holds current seats but never
    // spawns refills/snipers/watcher so the operator can proceed to payment.
    const paused = session.bookingPaused;

    let frame = null;
    try {
      frame = await findChartFrame(session.page, session.username, { emit: false });
      if (!frame) return;

      const timerSeconds = typeof session.lastPageTimerSeconds === 'number' ? session.lastPageTimerSeconds : null;
      const serverExpiry = session.holdTokenExpiresAt || 0;
      const msUntilExpiry = serverExpiry ? serverExpiry - Date.now() : Infinity;
      const shouldExtendByTimer = timerSeconds !== null && timerSeconds <= HOLD_TOKEN_RENEW_THRESHOLD_SECONDS;
      const shouldExtendByTime = msUntilExpiry !== Infinity && msUntilExpiry < 5 * 60 * 1000; // < 5 min proactive
      const shouldExtend = (shouldExtendByTimer || shouldExtendByTime) && !session.tokenExtensionMaxed;
      if (shouldExtend) {
        const lastExt = session.lastTokenExtension || 0;
        const minInterval = (timerSeconds !== null && timerSeconds <= 30) ? 5000 : 30000;
        if (Date.now() - lastExt > minInterval) {
          session.lastTokenExtension = Date.now();
          fileLog('INFO', `[${session.username}] Auto-extending hold token (timer=${timerSeconds}s, msUntilExpiry=${msUntilExpiry})`);
          const ext = await extendHoldToken(session);
          if (!ext.success) {
            session.tokenExtensionFailures = (session.tokenExtensionFailures || 0) + 1;
            if (session.tokenExtensionFailures >= 2) {
              session.tokenExtensionMaxed = true;
              emitStatus('token-extension-maxed', `Hold token reached maximum TTL; automatic extension stopped`, { account: session.username });
            }
          } else {
            session.tokenExtensionFailures = 0;
            // Hard ceiling: Seats.io max token lifetime is 2 hours.
            if (session.holdTokenFirstCreatedAt && Date.now() - session.holdTokenFirstCreatedAt >= 2 * 60 * 60 * 1000) {
              session.tokenExtensionMaxed = true;
              emitStatus('token-extension-maxed', `Hold token reached 2-hour absolute max`, { account: session.username });
            }
          }
        }
      }

      // Critical last-chance extension: if the timer is about to hit zero, force
      // a token refresh/re-hold immediately, bypassing the 30s cooldown.
      if (timerSeconds !== null && timerSeconds <= 15 && !session.tokenExtensionMaxed) {
        fileLog('INFO', `[${session.username}] Critical timer (${timerSeconds}s); forcing immediate hold token extension`);
        const ext = await extendHoldToken(session);
        if (ext.success) {
          session.tokenExtensionFailures = 0;
          session.lastTokenExtension = Date.now();
        }
      }

      // Refresh the hold token in case the chart rotated it.
      const refreshed = await readChartHoldToken(session.page);
      if (refreshed && refreshed !== session.holdToken) {
        if (session.holdToken) unregisterHoldToken(session.holdToken);
        session.holdToken = refreshed;
        registerHoldToken(session.username, refreshed);
      }

      // If another active session ended up with the same token, rotate now.
      await ensureUniqueHoldToken(session);

      // Re-hold the currently selected seats through the chart's own WebSocket.
      frame = await ensureChartFrame(session.page, session.username, frame, { attempts: 2, delayMs: 60 });
      if (!frame || !(await isFrameUsable(frame))) {
        emitStatus('keepalive-frame-missing', 'Chart iframe not available for keepalive', { account: session.username });
        return;
      }
      let wsOk = await frame.evaluate(() => window.__chartWS && window.__chartWS.readyState === 1).catch(() => false);
      if (!wsOk) {
        emitStatus('keepalive-ws-missing', 'Chart WebSocket not available; attempting reconnect', { account: session.username });
        try {
          // Re-install the WebSocket interception route and nudge the chart to reconnect.
          await setupWebSocketRoute(session.page);
          await waitFor(500);
          // Trigger a harmless resize/redraw to encourage the chart to reopen its WS.
          await frame.evaluate(() => {
            window.dispatchEvent(new Event('resize'));
            if (window.chartRender && window.chartRender.redraw) window.chartRender.redraw();
          }).catch(() => {});
          await waitFor(500);
          wsOk = await frame.evaluate(() => window.__chartWS && window.__chartWS.readyState === 1).catch(() => false);
        } catch (reconnectErr) {
          fileLog('WARN', `[${session.username}] keepalive WS reconnect error: ${reconnectErr.message}`);
        }
        if (!wsOk) {
          emitStatus('keepalive-ws-missing', 'Chart WebSocket still not available after reconnect attempt', { account: session.username });
          return;
        }
      }

      const wsParams = await readChartWsParams(session.page);
      const pageSlug = parseSlug(session.page.url());
      const refreshedToken = await readChartHoldToken(session.page, pageSlug);
      if (refreshedToken && refreshedToken !== session.holdToken) {
        if (session.holdToken) unregisterHoldToken(session.holdToken);
        session.holdToken = refreshedToken;
        registerHoldToken(session.username, refreshedToken);
        touchHoldToken(session, refreshedToken, 15);
      }
      await sendHoldViaFrame(frame, session.selectedSeats, { token: session.holdToken, tracingId: wsParams.tracingId, page: session.page, username: session.username });

      // Verify server-side; if the hold did not stick, try to refill.
      const verified = await verifyHeldSeatsViaApi(session.page, session.holdToken, session.selectedSeats, { session });
      if (paused) {
        emitStatus('keepalive-paused', `Hold extended while paused: ${verified.length}/${session.selectedSeats.length} seats still held`, { account: session.username, seats: verified });
      } else {
        emitStatus('keepalive', `Re-held ${verified.length}/${session.selectedSeats.length} seats (server verified)`, { account: session.username, seats: verified });
      }

      const cappedTarget = Math.min(session.targetSeatCount || 30, MAX_HELD_SEATS);
      if (verified.length < cappedTarget && !paused) {
        const lost = session.selectedSeats.filter(s => !verified.includes(s));
        if (lost.length) {
          emitStatus('keepalive-lost', `Seats lost on server: ${lost.join(', ')}`, { account: session.username, lost });
          // Remove visual markers for seats that are no longer held so the chart
          // does not keep showing them as selected after an external release.
          const clearFrame = await findChartFrame(session.page, session.username, { emit: false });
          if (clearFrame && await isFrameUsable(clearFrame)) {
            try { await clearChartVisualMarkers(clearFrame, lost); } catch {}
          }
          // Release only the lost seats so this account can try to reclaim them
          // before competing snipers see them as free.
          for (const s of lost) releaseSeatFromPool(s);
          session.selectedSeats = verified;
          reserveSeats(session.username, verified);
        }

        const needed = Math.min(cappedTarget - session.selectedSeats.length, MAX_HELD_SEATS - session.selectedSeats.length);
        if (needed > 0) {
          emitStatus('keepalive-refill', `Attempting to refill ${needed} seats...`, { account: session.username });
          session.isSelecting = true;
          const refill = await selectSeatsViaWebSocket(session.page, session.targetSections, needed, session.username, session);
          session.isSelecting = false;
          if (refill.length) {
            for (const s of refill) {
              if (!session.selectedSeats.includes(s)) session.selectedSeats.push(s);
            }
            reserveSeats(session.username, session.selectedSeats);
            emitStatus('keepalive-refilled', `Refilled seats: ${refill.join(', ')}`, { account: session.username, seats: session.selectedSeats });
          } else {
            emitStatus('keepalive-refill-failed', 'Could not refill lost seats', { account: session.username });
          }
        }
      }

      // Early detection: if we previously held seats but now hold none, attempt immediate recovery.
      if (session.selectedSeats.length > 0 && verified.length === 0) {
        emitStatus('token-lost-all-holds', `All seats lost; hold token may have expired`, { account: session.username });
        session.tokenExtensionFailures = 0;
        const ext = await extendHoldToken(session);
        if (ext.success) session.lastTokenExtension = Date.now();
      }
    } catch (e) {
      if (e && (e.message || '').includes('Target page, context or browser has been closed')) {
        // Expected when the user/browser closed the session; do not spam logs.
        return;
      }
      fileLog('WARN', `Keepalive error for ${session.username}: ${e.message || e}`);
    }
  }, KEEPALIVE_INTERVAL_MS);
}

function clearHoldKeepalive(session) {
  if (session.holdInterval) {
    clearInterval(session.holdInterval);
    session.holdInterval = null;
  }
}

function pauseKeepalive(session) {
  if (!session) return;
  session.keepalivePaused = true;
  fileLog('INFO', `[${session.username}] Keepalive paused`);
}

function resumeKeepalive(session) {
  if (!session) return;
  session.keepalivePaused = false;
  fileLog('INFO', `[${session.username}] Keepalive resumed`);
}

function pauseSnipersForSections(seats) {
  const set = new Set((seats || []).map(s => String(s).split('-')[0].toUpperCase()));
  for (const [u, s] of activeSessions.entries()) {
    if (u === s?.__transferTarget) continue; // do not pause the destination itself; it needs to capture
    if (!s.sniperInterval) continue;
    const monitored = (s.sniperSections || []).map(x => String(x).toUpperCase());
    if (monitored.some(m => set.has(m))) {
      stopActiveSniper(s);
      pausedSnipersForTransfer.set(u, { sections: s.sniperSections || [], wasActive: true });
    }
  }
}
function resumePausedTransferSnipers() {
  for (const [u, info] of pausedSnipersForTransfer.entries()) {
    const s = activeSessions.get(u);
    if (s && !s.stopRequested && info.wasActive) {
      startActiveSniper(s, info.sections || s.sniperSections || []);
    }
  }
  pausedSnipersForTransfer.clear();
}

function startHoldWatcher(session) {
  if (session.watchInterval) clearInterval(session.watchInterval);
  const targetSeatCount = Math.min(session.targetSeatCount || 30, MAX_HELD_SEATS);
  let lowCountStreak = 0;
  session.watchInterval = setInterval(async () => {
    if (!session.page || session.stopRequested || session.bookingPaused || session.isSelecting || await isPageClosed(session.page)) return;

    try {
      // Verify against the server, not the UI cart counter.
      const verified = await verifyHeldSeatsViaApi(session.page, session.holdToken, session.selectedSeats, { session });
      if (verified.length >= targetSeatCount) {
        lowCountStreak = 0;
        return;
      }
      lowCountStreak++;
      // Require two consecutive low readings to avoid a single blip triggering re-selection.
      if (lowCountStreak < 2) return;

      emitStatus('seats-lost', `Server-held seats dropped to ${verified.length}, re-selecting...`, { account: session.username, verified });
      session.isSelecting = true;

      const lost = session.selectedSeats.filter(s => !verified.includes(s));
      // Sync the chart UI: remove markers for seats released by another user/device.
      const frame = await findChartFrame(session.page, session.username, { emit: false });
      if (frame && await isFrameUsable(frame) && lost.length) {
        try { await clearChartVisualMarkers(frame, lost); } catch {}
      }
      // Release only the specific lost seats so this account can reclaim them
      // before another sniper sees them as available.
      for (const s of lost) releaseSeatFromPool(s);
      session.selectedSeats = verified;
      const needed = Math.min(targetSeatCount - session.selectedSeats.length, MAX_HELD_SEATS - session.selectedSeats.length);

      if (needed > 0) {
        const refilled = await selectSeatsViaWebSocket(session.page, session.targetSections, needed, session.username, session);
        for (const s of refilled) {
          if (!session.selectedSeats.includes(s)) session.selectedSeats.push(s);
        }
      }

      session.isSelecting = false;
      if (session.selectedSeats.length >= targetSeatCount) {
        session.selectedSeats = session.selectedSeats.slice(0, targetSeatCount);
        reserveSeats(session.username, session.selectedSeats);
        emitStatus('seats-reselected', `Re-selected seats: ${session.selectedSeats.join(', ')}`, { account: session.username, seats: session.selectedSeats });
        emitAccountUpdate(session.username, 'paused', { seats: session.selectedSeats });
      } else {
        emitStatus('seats-reselect-failed', 'Could not re-select enough seats', { account: session.username });
      }
    } catch (e) {
      session.isSelecting = false;
      if (e && (e.message || '').includes('Target page, context or browser has been closed')) {
        return;
      }
      fileLog('WARN', `Watcher error for ${session.username}: ${e.message || e}`);
    }
  }, 2_000);
}

function clearHoldWatcher(session) {
  if (session.watchInterval) {
    clearInterval(session.watchInterval);
    session.watchInterval = null;
  }
}

// ------------------------------------------------------------------
// Active sniper: persistent real-time monitor that grabs seats as soon
// as they become available in the target sections.
// ------------------------------------------------------------------
const sniperItemCache = new Map(); // key -> { ts, items }
const SNIPER_CACHE_TTL_MS = 250;
const SNIPER_CACHE_MAX_SIZE = 1000;
const SEATCLOUD_FETCH_LOCKS = new Map(); // key -> promise

function getCachedItems(key, fetcher, skipCache = false) {
  const now = Date.now();
  const cached = sniperItemCache.get(key);
  if (!skipCache && cached && now - cached.ts < SNIPER_CACHE_TTL_MS) return Promise.resolve(cached.items);
  return fetcher().then(items => {
    sniperItemCache.set(key, { ts: Date.now(), items });
    trimCache(sniperItemCache, SNIPER_CACHE_MAX_SIZE);
    return items;
  });
}

function startActiveSniper(session, sections) {
  if (session.sniperInterval) clearInterval(session.sniperInterval);
  const speed = getSpeedSettings(session?.speedSettings);
  if (!speed.sniperEnabled) {
    fileLog('INFO', `[${session.username}] Active sniper disabled by speed settings`);
    return;
  }
  session.sniperActive = true;
  session.sniperSections = (sections || []).map(s => String(s).trim().toUpperCase()).filter(Boolean);
  const targetSeats = Array.isArray(session.sniperTargetSeats) ? session.sniperTargetSeats : [];
  // Pre-compute target-seat mode once per tick; it must be known before the
  // isSelecting/isTransferring guard so the destination sniper keeps running
  // while it waits for released seats during a transfer.
  const targetSeatMode = targetSeats.length > 0;
  const targetSeatSet = targetSeatMode ? new Set(targetSeats.map(s => String(s).trim().toUpperCase())) : null;
  session.sniperLastItems = [];
  session.sniperLastAvailable = new Set();

  const run = async () => {
    let frame = null;
    try {
      if (session.stopRequested || session.bookingPaused || !session.page || await isPageClosed(session.page)) {
        stopActiveSniper(session);
        return;
      }
      // A separate in-progress hold attempt is already running (possibly fired by
      // the WebSocket release handler); skip this tick but stay alive.
      // In target-seat mode we are allowed to run even while isTransferring/isSelecting
      // because the destination is intentionally waiting for released seats.
      if (session.isSelecting && !targetSeatMode) return;
      if (session.isTransferring && !targetSeatMode) return;

      const loopStart = Date.now();
      const targetCount = Math.min(session.targetSeatCount || 30, MAX_HELD_SEATS);
      const current = session.selectedSeats || [];

      // ------------------------------------------------------------------
      // 1. Fetch the live seat map FIRST so we can react to releases instantly.
      //    We only use the cache when we are already at target and relaxed;
      //    otherwise we hit the server every tick.
      // ------------------------------------------------------------------
      const state = wsRouteRegistry.get(session.page);
      let skipCache = !!state?.skipItemCache;
      if (skipCache) state.skipItemCache = false;
      if (current.length < targetCount) skipCache = true; // hunting mode

      frame = await findChartFrame(session.page, session.username);
      const keys = frame ? await frame.evaluate(() => ({
        workspaceKey: window.chartState?.workspaceKey || window.currentChartConfig?.workspaceKey,
        eventKey: window.chartState?.eventKey || window.currentChartConfig?.eventKey,
      })).catch(() => ({})) : {};

      const workspaceKey = keys.workspaceKey || session.workspaceKey;
      const eventKey = keys.eventKey || session.eventKey;
      if (workspaceKey && eventKey && (!keys.workspaceKey || !keys.eventKey)) {
        session.workspaceKey = workspaceKey;
        session.eventKey = eventKey;
      }

      let items = [];
      if (workspaceKey && eventKey) {
        const fetchStart = Date.now();
        items = await getCachedItems(`${workspaceKey}:${eventKey}`, () => fetchSeatcloudItems(workspaceKey, eventKey, session), skipCache);
        fileLog('TIMER', `[${session.username}] sniper items fetch took ${Date.now() - fetchStart}ms -> ${items.length} items`);
      }
      session.sniperLastItems = items;

      // ------------------------------------------------------------------
      // 2. Build live availability and detect newly-free seats by label.
      // ------------------------------------------------------------------
      const availability = {};
      const newlyAvailable = [];
      const releasedSet = session?.releasedSeats || new Set();
      for (const item of items) {
        if (!item.section) continue;
        const sec = String(item.section).toUpperCase();
        if (item.availableCount > 0) {
          availability[sec] = (availability[sec] || 0) + item.availableCount;
          const label = String(item.label || item.name || item.objectId || item.id || '').trim();
          if (!label) continue;
          if (!current.includes(label) && !releasedSet.has(label.toUpperCase()) && !isSeatReserved(label, session.username)) {
            // Skip seats that belong to an active transfer source/destination.
            let belongsToTransfer = false;
            for (const [otherUser, otherSession] of activeSessions.entries()) {
              if (otherUser === session.username) continue;
              if (!otherSession.isTransferring && !isUsernameWhitelistedForTransfer(otherUser)) continue;
              if ((otherSession.selectedSeats || []).includes(label)) {
                belongsToTransfer = true;
                break;
              }
            }
            if (belongsToTransfer) continue;
            if (!session.sniperLastAvailable.has(label)) newlyAvailable.push(label);
            session.sniperLastAvailable.add(label);
          }
        }
      }

      for (const label of session.sniperLastAvailable) {
        const norm = String(label).toUpperCase();
        const stillAvail = items.some(i => {
          const l = String(i.label || i.name || i.objectId || i.id || '').trim().toUpperCase();
          return l === norm && i.availableCount > 0;
        });
        if (!stillAvail) session.sniperLastAvailable.delete(label);
      }

      const monitored = session.sniperSections.length ? session.sniperSections : Object.keys(availability);
      const safeMonitored = monitored.filter(s => !isSectionContested(s, session.username) && !isSectionBeingSelected(s, session.username));
      const hasAvailability = safeMonitored.some(sec => (availability[sec] || 0) > 0);

      // ------------------------------------------------------------------
      // 3. Instantly grab any newly released seat in a monitored section.
      //    Skip sections another account is actively selecting to avoid races.
      //    In target-seat mode only watch the assigned target seats.
      // ------------------------------------------------------------------
      let relevantNew = newlyAvailable.filter(l => {
        const sec = String(l).split('-')[0].toUpperCase();
        return safeMonitored.includes(sec);
      });
      if (targetSeatMode) {
        relevantNew = relevantNew.filter(l => targetSeatSet.has(String(l).trim().toUpperCase()));
      }

      if (relevantNew.length && current.length < targetCount) {
        const slots = Math.min(relevantNew.length, targetCount - current.length);
        const toHold = relevantNew.slice(0, slots);
        // Reserve newly released labels before attempting the hold to avoid races.
        reserveSeats(session.username, toHold);
        emitStatus('seats-monitoring', `Sniper sees ${toHold.length} newly available seat(s); capturing now`, { account: session.username, seats: toHold });
        session.isSelecting = true;
        try {
          const holdStart = Date.now();
          const held = await sendHoldViaRoute(session.page, toHold, { fastMode: true, gapMs: speed.sniperBurstGapMs, timeoutMs: speed.sniperTimeoutMs, username: session.username, token: session.holdToken, speedSettings: session?.speedSettings, session });
          fileLog('TIMER', `[${session.username}] sniper specific hold took ${Date.now() - holdStart}ms -> ${held.length}/${toHold.length}`);
          const heldSetResult = new Set(held.map(String));
          for (const s of toHold) {
            if (!heldSetResult.has(String(s))) releaseSeatFromPool(s);
          }
          if (held.length) {
            for (const s of held) if (!session.selectedSeats.includes(s)) session.selectedSeats.push(s);
            reserveSeats(session.username, session.selectedSeats);
            emitStatus('seats-grabbed', `Sniper instantly held ${held.length} newly available seat(s)`, { account: session.username, seats: held });
          }
        } finally {
          session.isSelecting = false;
        }
      }

      // ------------------------------------------------------------------
      // 4. If still below target, hold exact available labels rather than
      //    relying solely on bestAvailable (which can fail on partial blocks).
      //    In target-seat mode prioritize the assigned target seats.
      // ------------------------------------------------------------------
      let need = Math.max(0, targetCount - session.selectedSeats.length);
      if (need > 0 && (hasAvailability || targetSeatMode) && session.selectedSeats.length < targetCount) {
        const availableLabels = [];
        const seen = new Set();
        for (const item of items) {
          if (!item.section || item.availableCount <= 0) continue;
          const sec = String(item.section).toUpperCase();
          if (!safeMonitored.includes(sec) && !targetSeatMode) continue;
          const label = String(item.label || item.name || item.objectId || item.id || '').trim();
          if (!label) continue;
          const up = label.toUpperCase();
          if (session.selectedSeats.includes(label) || releasedSet.has(up) || seen.has(up) || isSeatReserved(label, session.username)) continue;
          if (targetSeatMode && !targetSeatSet.has(up)) continue;
          seen.add(up);
          availableLabels.push(label);
        }
        // In target-seat mode sort target seats first so we grab them in assignment order.
        if (targetSeatMode) {
          availableLabels.sort((a, b) => {
            const ai = targetSeats.indexOf(a);
            const bi = targetSeats.indexOf(b);
            if (ai !== -1 && bi !== -1) return ai - bi;
            if (ai !== -1) return -1;
            if (bi !== -1) return 1;
            return 0;
          });
        }
        const slots = Math.min(need, targetCount - session.selectedSeats.length, availableLabels.length);
        if (slots > 0) {
          // Per-account offset so concurrent snipers don't all grab the exact same labels.
          const accountOffset = targetSeatMode ? 0 : ((session.accountIndex || 0) % Math.max(1, availableLabels.length));
          const rotated = [...availableLabels.slice(accountOffset), ...availableLabels.slice(0, accountOffset)];
          const toHold = rotated.slice(0, slots);
          // Reserve exact labels before sending hold frames so another account does
          // not pick the same seats in the same millisecond.
          reserveSeats(session.username, toHold);
          emitStatus('seats-sniping', `Sniper holding ${toHold.length} exact available label(s) in monitored sections`, { account: session.username, need, seats: toHold });
          session.isSelecting = true;
          try {
            const holdStart = Date.now();
            const held = await sendHoldViaRoute(session.page, toHold, { fastMode: true, gapMs: speed.sniperBurstGapMs, timeoutMs: speed.sniperTimeoutMs, username: session.username, token: session.holdToken, speedSettings: session?.speedSettings, session });
            fileLog('TIMER', `[${session.username}] sniper exact hold took ${Date.now() - holdStart}ms -> ${held.length}/${toHold.length}`);
            // Release reservations for seats that did not actually get held.
            const heldSetResult = new Set(held.map(String));
            for (const s of toHold) {
              if (!heldSetResult.has(String(s))) releaseSeatFromPool(s);
            }
            if (held.length) {
              for (const s of held) if (!session.selectedSeats.includes(s)) session.selectedSeats.push(s);
              reserveSeats(session.username, session.selectedSeats);
              emitStatus('seats-grabbed', `Sniper held ${held.length} seat(s) via exact labels`, { account: session.username, seats: held });
            }
          } finally {
            session.isSelecting = false;
          }
        }
      }

      // ------------------------------------------------------------------
      // 5. Final fallback: bestAvailable only if exact labels did not help and
      //    the monitored sections are not contested by another active account.
      //    Skipped in target-seat mode because we only want the assigned seats.
      // ------------------------------------------------------------------
      need = Math.max(0, targetCount - session.selectedSeats.length);
      if (!targetSeatMode && need > 0 && safeMonitored.length > 0 && hasAvailability) {
        emitStatus('seats-sniping', `Sniper firing bestAvailable for ${need} seat(s) in non-contested sections`, { account: session.username, need, sections: safeMonitored });
        session.isSelecting = true;
        try {
          const baStart = Date.now();
          const held = await sendBestAvailableViaRoute(session.page, need, safeMonitored, 800, { token: session.holdToken, session });
          fileLog('TIMER', `[${session.username}] sniper bestAvailable took ${Date.now() - baStart}ms -> ${held.length}/${need}`);
          if (held.length) {
            for (const s of held) if (!session.selectedSeats.includes(s)) session.selectedSeats.push(s);
            reserveSeats(session.username, session.selectedSeats);
            emitStatus('seats-grabbed', `Sniper held ${held.length} seat(s) via bestAvailable`, { account: session.username, seats: held });
          }
        } finally {
          session.isSelecting = false;
        }
      } else if (need > 0 && monitored.length && !safeMonitored.length) {
        emitStatus('seats-sniping-skip', `Sniper skipping bestAvailable; all monitored sections are contested`, { account: session.username, monitored });
      }

      // ------------------------------------------------------------------
      // 6. Direct WebSocket fallback for holdToken/cookie accounts when the
      //    chart iframe is not usable. This keeps the sniper alive without a page.
      // ------------------------------------------------------------------
      need = Math.max(0, targetCount - session.selectedSeats.length);
      if (need > 0 && session.type === 'holdToken' && session.providedHoldToken && workspaceKey && eventKey) {
        emitStatus('seats-sniping', `Sniper direct WS fallback for ${need} seat(s)`, { account: session.username, need });
        session.isSelecting = true;
        try {
          const directStart = Date.now();
          const held = await holdSeatsViaDirectWebSocket(
            workspaceKey,
            eventKey,
            session.providedHoldToken,
            session.sniperSections,
            need,
            { username: session.username, session, releasedSeats: session.releasedSeats }
          );
          fileLog('TIMER', `[${session.username}] sniper direct WS took ${Date.now() - directStart}ms -> ${held.length}/${need}`);
          if (held.length) {
            for (const s of held) if (!session.selectedSeats.includes(s)) session.selectedSeats.push(s);
            reserveSeats(session.username, session.selectedSeats);
            emitStatus('seats-grabbed', `Sniper held ${held.length} seat(s) via direct WS`, { account: session.username, seats: held });
          }
        } catch (e) {
          fileLog('WARN', `[${session.username}] Sniper direct WS error: ${e.message}`);
        } finally {
          session.isSelecting = false;
        }
      }

      // ------------------------------------------------------------------
      // 7. Verify current holds in the background and clean up lost seats.
      // ------------------------------------------------------------------
      try {
        const verifyStart = Date.now();
        const verified = await verifyHeldSeatsViaApi(session.page, session.holdToken, session.selectedSeats, { session });
        fileLog('TIMER', `[${session.username}] sniper verify took ${Date.now() - verifyStart}ms -> ${verified.length}/${session.selectedSeats.length}`);
        if (verified.length < session.selectedSeats.length) {
          const lost = session.selectedSeats.filter(s => !verified.includes(s));
          // Only release the specific lost seats so other accounts can see them,
          // but this account's sniper can also try to reclaim them instantly.
          for (const s of lost) releaseSeatFromPool(s);
          session.selectedSeats = verified;
          reserveSeats(session.username, verified);
          if (frame && lost.length) {
            try { await clearChartVisualMarkers(frame, lost); } catch {}
          }
          emitStatus('seats-lost', `Sniper detected lost seats: ${lost.join(', ')}`, { account: session.username, lost, verified });
          // Immediate reclaim attempt for lost seats before competing snipers see them.
          if (lost.length > 0 && session.selectedSeats.length < targetCount) {
            const reclaimable = excludeReservedSeats(lost, session.username).slice(0, targetCount - session.selectedSeats.length);
            if (reclaimable.length > 0) {
              reserveSeats(session.username, reclaimable);
              try {
                session.isSelecting = true;
                const reclaimed = await sendHoldViaRoute(session.page, reclaimable, { fastMode: true, gapMs: speed.sniperBurstGapMs, timeoutMs: speed.sniperTimeoutMs, username: session.username, token: session.holdToken, speedSettings: session?.speedSettings, session });
                const reclaimedSet = new Set(reclaimed.map(String));
                for (const s of reclaimable) {
                  if (!reclaimedSet.has(String(s))) releaseSeatFromPool(s);
                }
                if (reclaimed.length) {
                  for (const s of reclaimed) if (!session.selectedSeats.includes(s)) session.selectedSeats.push(s);
                  reserveSeats(session.username, session.selectedSeats);
                  emitStatus('seats-grabbed', `Sniper reclaimed ${reclaimed.length} lost seat(s)`, { account: session.username, seats: reclaimed });
                }
              } finally {
                session.isSelecting = false;
              }
            }
          }
        }
      } catch (e) {
        fileLog('WARN', `[${session.username}] Sniper verify failed: ${e.message}`);
      }

      // Sync UI and emit update.
      if (session.selectedSeats.length) {
        if (frame) {
          try { await syncChartSelection(frame, session.selectedSeats, { page: session.page, username: session.username }); } catch {}
        }
        emitAccountUpdate(session.username, session.state || 'paused', { seats: session.selectedSeats });
      }

      fileLog('TIMER', `[${session.username}] sniper loop took ${Date.now() - loopStart}ms, held ${session.selectedSeats.length}/${targetCount}`);
    } catch (e) {
      fileLog('WARN', `[${session.username}] Active sniper error: ${e.message}`);
    } finally {
      session.isSelecting = false;
    }
  };

  // Run immediately, then on the configured polling loop. WebSocket release
  // events fire onWsSeatReleased directly for the real-time reaction path;
  // HTTP polling is the fallback to catch any missed WS messages.
  run();
  session.sniperInterval = setInterval(run, speed.sniperIntervalMs || 50);
}

function stopActiveSniper(session) {
  if (session.sniperInterval) {
    clearTimeout(session.sniperInterval);
    session.sniperInterval = null;
  }
  session.sniperActive = false;
}

async function releaseSingleSeat(session, seat) {
  const { page, username } = session;
  if (!page || await isPageClosed(page)) return false;

  const state = wsRouteRegistry.get(page);
  const frame = await findChartFrame(page, username);
  let released = false;

  // 1) Primary: send release through the intercepted WebSocket route using the
  // same hold token the chart uses (consistent with sendHoldViaRoute).
  if (state && state.server && state.ready && !state.closed) {
    try {
      const holdToken = await readChartHoldToken(page, parseSlug(page.url()));
      if (holdToken) {
        const wsParams = await readChartWsParams(page);
        const basePayload = {
          objects: [{ objectId: seat }],
          token: holdToken,
          tracing_id: wsParams.tracingId || `svr_rel_${Date.now()}`,
        };
        // SeatCloud has used both action names in different builds; fire both.
        for (const action of ['release-object', 'free-object']) {
          try {
            state.server.send(compressWsMessage(JSON.stringify({ ...basePayload, action })));
          } catch {}
        }
        released = true;
        fileLog('INFO', `[${username}] Sent WS release for ${seat}`);
      }
    } catch (e) {
      fileLog('WARN', `[${username}] releaseSingleSeat WS route error: ${e.message}`);
    }
  }

  // 2) Direct iframe WebSocket fallback (the chart's own socket knows the session).
  if (!released && frame) {
    try {
      const wsOk = await frame.evaluate(() => window.__chartWS && window.__chartWS.readyState === 1).catch(() => false);
      if (wsOk) {
        await frame.evaluate(async (seat) => {
          const ws = window.__chartWS;
          async function compressRaw(str) {
            const cs = new CompressionStream('deflate-raw');
            const writer = cs.writable.getWriter();
            writer.write(new TextEncoder().encode(str));
            writer.close();
            const chunks = [];
            const reader = cs.readable.getReader();
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              chunks.push(value);
            }
            let len = 0;
            chunks.forEach(c => (len += c.length));
            const out = new Uint8Array(len);
            let off = 0;
            chunks.forEach(c => { out.set(c, off); off += c.length; });
            return out;
          }
          for (const action of ['release-object', 'free-object']) {
            try {
              const payload = await compressRaw(JSON.stringify({ action, objects: [{ objectId: seat }] }));
              ws.send(payload);
            } catch {}
          }
        }, seat);
        released = true;
      }
    } catch (e) {
      fileLog('WARN', `[${username}] releaseSingleSeat iframe WS error: ${e.message}`);
    }
  }

  // 3) Chart API fallback: deselect the seat visually and internally.
  if (frame) {
    try {
      await frame.evaluate((seat) => {
        const chart = window.chartRender || window.chart || window.SeatsChart || (window.seatsio && window.seatsio.chart);
        // Official API
        try { if (chart && typeof chart.deselectObjects === 'function') chart.deselectObjects([seat]); } catch {}
        // State cleanup so the seat is no longer treated as selected/held.
        try {
          const rs = window.Bn?.renderState || window.renderState || chart?.state;
          if (rs?.selectedSeats instanceof Map) rs.selectedSeats.delete(seat);
          for (const arrName of ['selectedObjects', 'heldObjects', 'reservedObjects']) {
            const arr = chart?.state?.[arrName] || window.chartState?.[arrName];
            if (Array.isArray(arr)) {
              const idx = arr.findIndex(o => (o?.label || o?.objectId || o?.id || o) === seat);
              if (idx >= 0) arr.splice(idx, 1);
            }
          }
        } catch {}
        // DOM cleanup: remove our custom markers.
        const el = document.querySelector(`[data-object-id="${seat}"], [data-objectid="${seat}"], [data-label="${seat}"], [data-object-label="${seat}"], [id="${seat}"], [aria-label*="${seat}"], [title*="${seat}"]`);
        if (el) {
          el.classList.remove('kimiko-held');
          const check = (el.closest('g') || el.parentElement)?.querySelector('.kimiko-check');
          if (check) check.remove();
        }
        ['redraw','render','refresh','update','repaint','draw'].forEach(m => { try { if (typeof chart[m] === 'function') chart[m](); } catch {} });
        window.dispatchEvent(new Event('resize'));
      }, seat);
      released = true;
    } catch (e) {
      fileLog('WARN', `[${username}] releaseSingleSeat chart API error: ${e.message}`);
    }
  }

  if (released) {
    emitSeatEvent('seat-released', username, [seat], { source: 'releaseSingleSeat' });
  }
  return released;
}

async function releaseSeatsBatch(session, seats) {
  const { page, username } = session;
  if (!page || await isPageClosed(page)) return [];
  if (!Array.isArray(seats) || seats.length === 0) return [];

  const released = [];
  const state = wsRouteRegistry.get(page);
  const frame = await findChartFrame(page, username);

  // 1) Primary: send release through the intercepted WebSocket route in one message.
  if (state && state.server && state.ready && !state.closed) {
    try {
      const holdToken = await readChartHoldToken(page, parseSlug(page.url()));
      if (holdToken) {
        const wsParams = await readChartWsParams(page);
        const objects = seats.map(seat => ({ objectId: seat }));
        const basePayload = {
          objects,
          token: holdToken,
          tracing_id: wsParams.tracingId || `svr_rel_${Date.now()}`,
        };
        for (const action of ['release-object', 'free-object']) {
          try {
            state.server.send(compressWsMessage(JSON.stringify({ ...basePayload, action })));
          } catch {}
        }
        released.push(...seats);
        fileLog('INFO', `[${username}] Sent WS batch release for ${seats.length} seat(s)`);
      }
    } catch (e) {
      fileLog('WARN', `[${username}] releaseSeatsBatch WS route error: ${e.message}`);
    }
  }

  // 2) Direct iframe WebSocket fallback.
  if (released.length === 0 && frame) {
    try {
      const wsOk = await frame.evaluate(() => window.__chartWS && window.__chartWS.readyState === 1).catch(() => false);
      if (wsOk) {
        const iframeReleased = await frame.evaluate(async (seats) => {
          const ws = window.__chartWS;
          async function compressRaw(str) {
            const cs = new CompressionStream('deflate-raw');
            const writer = cs.writable.getWriter();
            writer.write(new TextEncoder().encode(str));
            writer.close();
            const chunks = [];
            const reader = cs.readable.getReader();
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              chunks.push(value);
            }
            let len = 0;
            chunks.forEach(c => (len += c.length));
            const out = new Uint8Array(len);
            let off = 0;
            chunks.forEach(c => { out.set(c, off); off += c.length; });
            return out;
          }
          const sent = [];
          for (const action of ['release-object', 'free-object']) {
            try {
              const payload = await compressRaw(JSON.stringify({ action, objects: seats.map(s => ({ objectId: s })) }));
              ws.send(payload);
              sent.push(...seats);
            } catch {}
          }
          return sent;
        }, seats);
        if (iframeReleased.length) released.push(...seats);
      }
    } catch (e) {
      fileLog('WARN', `[${username}] releaseSeatsBatch iframe WS error: ${e.message}`);
    }
  }

  // 3) Fallback: release one-by-one through chart API.
  if (released.length === 0 && frame) {
    for (const seat of seats) {
      try {
        if (await releaseSingleSeat(session, seat)) released.push(seat);
      } catch (e) {
        fileLog('WARN', `[${username}] releaseSeatsBatch fallback error for ${seat}: ${e.message}`);
      }
    }
  }

  if (released.length) {
    emitSeatEvent('seat-released', username, released, { source: 'releaseSeatsBatch' });
    emitStatus('seats-released-batch', `Released ${released.length} seat(s) in batch`, { account: username, seats: released });
  }
  return released;
}

async function releaseHold(session) {
  const { page, username, selectedSeats } = session;
  if (!page || await isPageClosed(page)) return false;

  let released = false;

  // 1. Try sending release-object via the chart WebSocket
  try {
    const frame = await findChartFrame(page, username);
    if (frame && selectedSeats && selectedSeats.length > 0) {
      const wsOk = await frame.evaluate(() => window.__chartWS && window.__chartWS.readyState === 1).catch(() => false);
      if (wsOk) {
        await frame.evaluate(async (seats) => {
          const ws = window.__chartWS;
          async function compressRaw(str) {
            const cs = new CompressionStream('deflate-raw');
            const writer = cs.writable.getWriter();
            writer.write(new TextEncoder().encode(str));
            writer.close();
            const chunks = [];
            const reader = cs.readable.getReader();
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              chunks.push(value);
            }
            let len = 0;
            chunks.forEach(c => (len += c.length));
            const out = new Uint8Array(len);
            let off = 0;
            chunks.forEach(c => { out.set(c, off); off += c.length; });
            return out;
          }
          const payload = await compressRaw(JSON.stringify({
            action: 'release-object',
            objects: seats.map(s => ({ objectId: s })),
          }));
          ws.send(payload);
        }, selectedSeats);
        released = true;
        emitStatus('hold-released-ws', 'Released seats via WebSocket', { account: username, seats: selectedSeats });
      }
    }
  } catch (e) {
    fileLog('WARN', `[${username}] releaseHold WebSocket error: ${e.message}`);
  }

  // 2. Try clearing selection in chart renderer
  try {
    const frame = await findChartFrame(page, username);
    if (frame) {
      await frame.evaluate(() => {
        if (window.chartRender && window.chartRender.clearSelection) window.chartRender.clearSelection();
      });
    }
  } catch (e) {
    fileLog('WARN', `[${username}] releaseHold clearSelection error: ${e.message}`);
  }

  // 3. Refresh the page to clear any server-side hold
  try {
    await page.reload({ waitUntil: 'domcontentloaded', timeout: 30000 });
    await waitFor(3000);
    emitStatus('hold-released-refresh', 'Refreshed page to clear hold', { account: username });
  } catch (e) {
    fileLog('WARN', `[${username}] releaseHold refresh error: ${e.message}`);
  }

  session.selectedSeats = [];
  clearHoldKeepalive(session);
  clearHoldWatcher(session);
  stopActiveSniper(session);
  return released || true;
}

async function stopSession(username, reason, soft = false) {
  const session = activeSessions.get(username);
  if (!session) return;
  if (soft) {
    // Soft stop: keep browser/context open and keep the hold-token extension
    // alive so currently held seats remain reserved for payment.
    // Do NOT resolve proceedResolve here, otherwise the bot would auto-click
    // the "Next: Payment" button. The user must explicitly press Proceed.
    session.bookingPaused = true;
    clearHoldWatcher(session);
    stopActiveSniper(session);
    emitStatus('stopped', `Session paused (${reason}); held seats remain active`, { account: username, heldSeats: session.selectedSeats || [] });
    emitAccountUpdate(username, 'paused', { seats: session.selectedSeats || [], reason });
    emitQueueStats();
    return;
  }
  session.stopRequested = true;
  // Resolve any pending proceed signal with 'stop' so the payment loop exits
  // cleanly instead of hanging forever.
  if (session.proceedResolve) session.proceedResolve('stop');
  clearHoldKeepalive(session);
  clearHoldWatcher(session);
  stopActiveSniper(session);
  releaseSeats(username);
  try { if (session.page && !await isPageClosed(session.page)) await session.page.close(); } catch {}
  try { await session.context?.close(); } catch {}
  activeSessions.delete(username);
  releaseProxyReservation(username);
  unregisterHoldToken(session.holdToken);
  await pruneOldContexts(true);
  emitStatus('stopped', `Session stopped (${reason})`, { account: username });
  emitAccountUpdate(username, 'idle');
  emitQueueStats();
  processQueue();
}

async function stopAll(reason, soft = false) {
  const usernames = Array.from(activeSessions.keys());
  for (const u of usernames) await stopSession(u, reason, soft);
  if (!soft) {
    pendingQueue = [];
    // Also stop any active pair-cycling sessions so held seats are released.
    try { await pairManager.stopAll(); } catch {}
  }
  emitQueueStats();
}

io.on('connection', socket => {
  socket.emit('status', { stage: 'idle', message: 'Connected to Kimiko booking assistant.' });
  socket.emit('queue-stats', {
    active: activeSessions.size,
    pending: pendingQueue.length,
    done: sessionCounter,
  });
});

// Clean shutdown: close all managed browser contexts on exit
async function closeAllSessions() {
  // Release pair-cycling holds before closing browsers.
  try { await pairManager.stopAll(); } catch {}
  for (const [username, session] of activeSessions) {
    clearHoldKeepalive(session);
    clearHoldWatcher(session);
    stopActiveSniper(session);
  }
  for (const [username, session] of activeSessions) {
    releaseProxyReservation(username);
    unregisterHoldToken(session.holdToken);
  }
  activeSessions.clear();
  // Close every context we ever opened, including errored-out ones
  for (const ctx of allContexts) {
    try { await ctx.close(); } catch {}
  }
  allContexts.clear();
  try { await globalBrowser?.close(); } catch {}
}

// Aggressive cleanup of leftover browser resources to avoid ERR_INSUFFICIENT_RESOURCES / OOM.
async function pruneOldContexts(keepActive = true) {
  const activeContexts = new Set();
  if (keepActive) {
    for (const session of activeSessions.values()) {
      if (session.context) activeContexts.add(session.context);
    }
  }
  const toClose = [];
  for (const ctx of allContexts) {
    if (keepActive && activeContexts.has(ctx)) continue;
    toClose.push(ctx);
  }
  for (const ctx of toClose) {
    try {
      await ctx.close();
    } catch {}
    allContexts.delete(ctx);
  }
  // Also close any loose pages inside active contexts if they are not the session page.
  if (keepActive) {
    for (const session of activeSessions.values()) {
      if (!session.context) continue;
      try {
        const pages = await session.context.pages();
        for (const p of pages) {
          if (p !== session.page) {
            try { await p.close(); } catch {}
          }
        }
      } catch {}
    }
  }
  fileLog('INFO', `Pruned ${toClose.length} stale browser contexts`);
}

process.on('SIGINT', async () => {
  fileLog('INFO', 'SIGINT received, closing all sessions...');
  await closeAllSessions();
  process.exit(0);
});
process.on('SIGTERM', async () => {
  fileLog('INFO', 'SIGTERM received, closing all sessions...');
  await closeAllSessions();
  process.exit(0);
});

const PORT = process.env.PORT || 3456;
const server = httpServer.listen(PORT, () => {
  console.log(`Kimiko Webook Booking Assistant running at http://localhost:${PORT}`);
  // Validate the first enabled 2captcha key asynchronously so the operator sees
  // immediately whether the key is usable.
  captcha2captcha.checkBalance().then(balance => {
    if (balance.ok) {
      fileLog('INFO', `2captcha key balance: ${balance.balance}`);
    } else {
      fileLog('WARN', `2captcha key check failed: ${balance.error}`);
    }
  }).catch(() => {});

  // Start periodic proxy health monitoring so dead proxies are detected and
  // replaced before they cause session failures.
  startProxyHealthMonitor();
});
server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n❌ Port ${PORT} is already in use.`);
    console.error(`   Run: npm run kill`);
    console.error(`   Or:  taskkill //F //IM node.exe\n`);
  } else {
    console.error(err);
  }
  process.exit(1);
});
