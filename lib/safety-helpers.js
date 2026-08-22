// Safety helpers extracted from server.js for testability.

const SENSITIVE_KEYS = new Set([
  'holdtoken', 'hold_token', 'token', 'queuetoken', 'queue_token',
  'providedholdtoken', 'providedqueuetoken', 'jwt', 'accesstoken', 'refreshtoken', 'idtoken',
  'password', 'secret', 'apikey', 'api_key', 'authorization', 'cookie', 'cookies',
]);

function isSensitiveKey(key) {
  if (!key || typeof key !== 'string') return false;
  const lower = key.toLowerCase();
  return SENSITIVE_KEYS.has(lower) || lower.includes('token') || lower.includes('password') || lower.includes('secret') || lower.includes('cookie');
}

function redactValue(value) {
  if (typeof value !== 'string' || value.length <= 8) return '[REDACTED]';
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

function safeJsonStringify(obj) {
  try {
    return JSON.stringify(obj);
  } catch {
    try {
      const seen = new WeakSet();
      return JSON.stringify(obj, (key, value) => {
        if (typeof value === 'object' && value !== null) {
          if (seen.has(value)) return '[Circular]';
          seen.add(value);
        }
        return value;
      });
    } catch {
      return '[unserializable]';
    }
  }
}

function safeRedactedStringify(obj) {
  try {
    const seen = new WeakSet();
    return JSON.stringify(obj, (key, value) => {
      if (typeof value === 'object' && value !== null) {
        if (seen.has(value)) return '[Circular]';
        seen.add(value);
      }
      if (isSensitiveKey(key) && typeof value === 'string') return redactValue(value);
      return value;
    });
  } catch {
    return '[unserializable]';
  }
}

function trimCache(map, maxSize) {
  if (map.size <= maxSize) return;
  const entries = Array.from(map.entries()).sort((a, b) => (a[1].ts || 0) - (b[1].ts || 0));
  const toRemove = entries.slice(0, entries.length - maxSize);
  for (const [key] of toRemove) map.delete(key);
}

function getProxyCacheKey(proxy) {
  if (!proxy || !proxy.server) return '';
  return `${proxy.server}|${proxy.username || ''}|${proxy.password || ''}`;
}

module.exports = {
  SENSITIVE_KEYS,
  isSensitiveKey,
  redactValue,
  safeJsonStringify,
  safeRedactedStringify,
  trimCache,
  getProxyCacheKey,
};
