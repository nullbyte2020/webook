/**
 * 2captcha.com integration for active reCAPTCHA solving.
 *
 * The bot's primary captcha bypass methods (script injection, route patching,
 * token pre-loading) are tried first. This module is a fallback: when those
 * fail, we ask 2captcha to solve the challenge and inject the returned token.
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const KEYS_FILE = path.join(__dirname, '..', 'captcha-keys.json');
const DEFAULT_API_KEY = 'f56cdc81a2f0de0ec066a2f97d8ea8f6';

function loadKeys() {
  try {
    if (!fs.existsSync(KEYS_FILE)) return [];
    const raw = fs.readFileSync(KEYS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveKeys(keys) {
  try {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2), 'utf8');
  } catch {}
}

function ensureDefaultKey() {
  const keys = loadKeys();
  const hasDefault = keys.some(k => k.key === DEFAULT_API_KEY);
  if (!hasDefault) {
    keys.unshift({
      id: `default-${Date.now()}`,
      label: 'Default key',
      key: DEFAULT_API_KEY,
      enabled: true,
      createdAt: new Date().toISOString(),
    });
    saveKeys(keys);
  }
  return keys;
}

function getEnabledKeys() {
  return loadKeys().filter(k => k.enabled !== false && k.key && k.key.trim().length > 0);
}

function rotateKey() {
  const keys = getEnabledKeys();
  if (keys.length === 0) return null;
  // Simple round-robin: pick the least recently used key.
  keys.sort((a, b) => (a.lastUsedAt || 0) - (b.lastUsedAt || 0));
  const chosen = keys[0];
  chosen.lastUsedAt = Date.now();
  saveKeys(loadKeys());
  return chosen.key.trim();
}

/**
 * Check the 2captcha balance for the given (or rotated) key.
 * Returns { ok: boolean, balance: string|number|null, error: string|null }.
 */
async function checkBalance(apiKey) {
  const key = (apiKey || rotateKey())?.trim();
  if (!key) return { ok: false, balance: null, error: 'No enabled 2captcha API key configured' };
  const url = `https://2captcha.com/res.php?key=${encodeURIComponent(key)}&action=getbalance&json=1`;
  try {
    const res = await httpGet(url, 30000);
    let json;
    try { json = JSON.parse(res.body); } catch { json = null; }
    if (res.status === 200 && json && json.status === 1) {
      return { ok: true, balance: json.request, error: null };
    }
    return { ok: false, balance: null, error: json ? json.request : res.body.slice(0, 200) };
  } catch (e) {
    return { ok: false, balance: null, error: e.message || String(e) };
  }
}

function httpGet(url, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('timeout', () => req.destroy(new Error('Request timeout')));
    req.on('error', reject);
  });
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

/**
 * Submit a reCAPTCHA v2 challenge to 2captcha and poll for the token.
 *
 * @param {Object} opts
 * @param {string} opts.sitekey - The data-sitekey attribute value.
 * @param {string} opts.pageUrl - The URL where the captcha is rendered.
 * @param {string} [opts.apiKey] - Optional specific 2captcha key.
 * @returns {Promise<string|null>} The solved token or null.
 */
async function solveRecaptchaV2({ sitekey, pageUrl, apiKey }) {
  const key = (apiKey || rotateKey())?.trim();
  if (!key) throw new Error('No enabled 2captcha API key configured');
  if (!sitekey || !pageUrl) throw new Error('sitekey and pageUrl are required');

  const submitUrl = `https://2captcha.com/in.php?key=${encodeURIComponent(key)}&method=userrecaptcha&googlekey=${encodeURIComponent(sitekey)}&pageurl=${encodeURIComponent(pageUrl)}&json=1&enterprise=0`;
  const submit = await httpGet(submitUrl, 60000);
  if (submit.status !== 200) throw new Error(`2captcha submit HTTP ${submit.status}`);

  let submitJson;
  try { submitJson = JSON.parse(submit.body); } catch { submitJson = null; }
  if (!submitJson || submitJson.status !== 1 || !submitJson.request) {
    throw new Error(`2captcha submit failed: ${submit.body.slice(0, 200)}`);
  }

  const captchaId = submitJson.request;
  const resultUrl = `https://2captcha.com/res.php?key=${encodeURIComponent(key)}&action=get&id=${encodeURIComponent(captchaId)}&json=1`;

  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    await sleep(5000);
    const result = await httpGet(resultUrl, 60000);
    if (result.status !== 200) continue;
    let resultJson;
    try { resultJson = JSON.parse(result.body); } catch { resultJson = null; }
    if (!resultJson) continue;
    if (resultJson.status === 1 && resultJson.request) {
      return resultJson.request;
    }
    if (resultJson.request === 'CAPCHA_NOT_READY') continue;
    throw new Error(`2captcha solve failed: ${result.body.slice(0, 200)}`);
  }
  throw new Error('2captcha solve timed out after 120s');
}

/**
 * Try to detect the reCAPTCHA sitekey on the given page or frame.
 * @returns {Promise<string|null>}
 */
async function detectSitekey(pageOrFrame) {
  if (!pageOrFrame) return null;
  try {
    return await pageOrFrame.evaluate(() => {
      // data-sitekey attribute
      const el = document.querySelector('[data-sitekey]');
      if (el) return el.getAttribute('data-sitekey');
      // grecaptcha render params
      if (window.grecaptcha && window.grecaptcha.renderParams && window.grecaptcha.renderParams.sitekey) {
        return window.grecaptcha.renderParams.sitekey;
      }
      // Common webook key fallback
      return '6LcvYHooAAAAAC-G46bpymJKtIwfDQpg9DsHPMpL';
    });
  } catch {
    return '6LcvYHooAAAAAC-G46bpymJKtIwfDQpg9DsHPMpL';
  }
}

/**
 * Inject a solved reCAPTCHA token into the page so the site accepts it.
 */
async function injectRecaptchaToken(pageOrFrame, token) {
  if (!pageOrFrame || !token) return false;
  try {
    await pageOrFrame.evaluate((t) => {
      window.__kimikoRecaptchaToken = t;
      window.grecaptchaToken = t;
      document.querySelectorAll('[name="g-recaptcha-response"]').forEach(el => {
        el.value = t;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      });
      if (window.grecaptcha && window.grecaptcha.enterprise && window.grecaptcha.enterprise.ready) {
        window.grecaptcha.enterprise.ready(() => {
          window.grecaptcha.enterprise.execute('6LcvYHooAAAAAC-G46bpymJKtIwfDQpg9DsHPMpL', { action: 'submit' }).catch(() => {});
        });
      }
      return true;
    }, token);
    return true;
  } catch {
    return false;
  }
}

/**
 * Detect a Cloudflare Turnstile sitekey on the page or frame.
 * @returns {Promise<string|null>}
 */
async function detectTurnstileSitekey(pageOrFrame) {
  if (!pageOrFrame) return null;
  try {
    return await pageOrFrame.evaluate(() => {
      const el = document.querySelector('.cf-turnstile, [data-sitekey]');
      if (el) return el.getAttribute('data-sitekey') || null;
      const iframe = document.querySelector('iframe[src*="turnstile"], iframe[src*="challenges.cloudflare"], iframe[id^="cf-chl-widget-"]');
      if (iframe) {
        try {
          const url = new URL(iframe.src);
          return url.searchParams.get('sitekey') || null;
        } catch {
          const m = iframe.src.match(/[?&]sitekey=([^&]+)/);
          if (m) return decodeURIComponent(m[1]);
        }
      }
      return null;
    });
  } catch {
    return null;
  }
}

/**
 * Submit a Cloudflare Turnstile challenge to 2captcha and poll for the token.
 *
 * @param {Object} opts
 * @param {string} opts.sitekey - The data-sitekey attribute value.
 * @param {string} opts.pageUrl - The URL where the challenge is rendered.
 * @param {string} [opts.action] - Optional Turnstile action.
 * @param {string} [opts.apiKey] - Optional specific 2captcha key.
 * @returns {Promise<string|null>} The solved token or null.
 */
async function solveTurnstile({ sitekey, pageUrl, action, apiKey, invisible = true }) {
  const key = (apiKey || rotateKey())?.trim();
  if (!key) throw new Error('No enabled 2captcha API key configured');
  if (!sitekey || !pageUrl) throw new Error('sitekey and pageUrl are required');

  let submitUrl = `https://2captcha.com/in.php?key=${encodeURIComponent(key)}&method=turnstile&sitekey=${encodeURIComponent(sitekey)}&pageurl=${encodeURIComponent(pageUrl)}&json=1`;
  if (action) submitUrl += `&action=${encodeURIComponent(action)}`;
  if (invisible) submitUrl += '&invisible=1';

  const submit = await httpGet(submitUrl, 60000);
  if (submit.status !== 200) throw new Error(`2captcha Turnstile submit HTTP ${submit.status}: ${submit.body.slice(0, 200)}`);

  let submitJson;
  try { submitJson = JSON.parse(submit.body); } catch { submitJson = null; }
  if (!submitJson || submitJson.status !== 1 || !submitJson.request) {
    throw new Error(`2captcha Turnstile submit failed: ${submit.body.slice(0, 200)}`);
  }

  const captchaId = submitJson.request;
  const resultUrl = `https://2captcha.com/res.php?key=${encodeURIComponent(key)}&action=get&id=${encodeURIComponent(captchaId)}&json=1`;

  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    await sleep(5000);
    const result = await httpGet(resultUrl, 60000);
    if (result.status !== 200) continue;
    let resultJson;
    try { resultJson = JSON.parse(result.body); } catch { resultJson = null; }
    if (!resultJson) continue;
    if (resultJson.status === 1 && resultJson.request) {
      return resultJson.request;
    }
    if (resultJson.request === 'CAPCHA_NOT_READY') continue;
    throw new Error(`2captcha solve failed: ${result.body.slice(0, 200)}`);
  }
  throw new Error('2captcha solve timed out after 120s');
}

/**
 * Inject a solved Turnstile token into the page.
 */
async function injectTurnstileToken(pageOrFrame, token) {
  if (!pageOrFrame || !token) return false;
  try {
    await pageOrFrame.evaluate((t) => {
      window.__kimikoTurnstileToken = t;
      document.querySelectorAll('[name="cf-turnstile-response"]').forEach(el => {
        el.value = t;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      });
      // If Turnstile exposes a global callback, invoke it.
      if (window.turnstile && typeof window.turnstile.callback === 'function') {
        try { window.turnstile.callback(t); } catch {}
      }
      return true;
    }, token);
    return true;
  } catch {
    return false;
  }
}

module.exports = {
  loadKeys,
  saveKeys,
  ensureDefaultKey,
  getEnabledKeys,
  rotateKey,
  checkBalance,
  solveRecaptchaV2,
  detectSitekey,
  injectRecaptchaToken,
  detectTurnstileSitekey,
  solveTurnstile,
  injectTurnstileToken,
  DEFAULT_API_KEY,
};

