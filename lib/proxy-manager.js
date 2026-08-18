const fs = require('fs');

function hashString(str) {
  let hash = 0;
  const value = String(str || '');
  for (let i = 0; i < value.length; i++) {
    hash = ((hash << 5) - hash) + value.charCodeAt(i);
    hash |= 0;
  }
  return hash;
}

function normalizeProxy(proxy) {
  if (!proxy || typeof proxy !== 'object') return null;

  let server = String(proxy.server || '').trim();
  const username = proxy.username != null ? String(proxy.username).trim() : undefined;
  const password = proxy.password != null ? String(proxy.password).trim() : undefined;

  if (!server) return null;

  const schemeMatch = server.match(/^(https?|socks4|socks5):\/\//i);
  const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : 'http';
  if (!schemeMatch) server = `${scheme}://${server}`;
  else server = `${scheme}://${server.slice(schemeMatch[0].length)}`;

  const result = { server };
  if (username) result.username = username;
  if (password) result.password = password;
  return result;
}

function parseProxyObject(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;

  if (obj.server || obj.proxy) {
    return normalizeProxy({
      server: obj.server || obj.proxy,
      username: obj.username,
      password: obj.password,
    });
  }

  if (obj.host && obj.port) {
    return normalizeProxy({
      server: `${obj.scheme || 'http'}://${obj.host}:${obj.port}`,
      username: obj.username,
      password: obj.password,
    });
  }

  return null;
}

function parseUserPassHostPort(line) {
  const text = String(line);
  // This parser is only for bare user:pass:host:port or host:port:user:pass forms.
  // Reject URLs that already contain a scheme or inline credentials marker.
  if (text.includes('://') || text.includes('@')) return null;
  const parts = text.split(':');
  if (parts.length !== 4) return null;
  const [first, second, third, fourth] = parts.map(p => p.trim());
  if (!first || !second || !third || !fourth) return null;

  if (/^\d+$/.test(fourth)) {
    return normalizeProxy({
      server: `${third}:${fourth}`,
      username: first,
      password: second,
    });
  }

  if (/^\d+$/.test(second)) {
    return normalizeProxy({
      server: `${first}:${second}`,
      username: third,
      password: fourth,
    });
  }

  return null;
}

function parseProxyLine(line) {
  if (!line || typeof line !== 'string') return null;
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;

  if (trimmed.startsWith('{')) {
    try {
      return parseProxyObject(JSON.parse(trimmed));
    } catch {
      return null;
    }
  }

  const fourPart = parseUserPassHostPort(trimmed);
  if (fourPart) return fourPart;

  const withAuthMatch = trimmed.match(/^(https?|socks4|socks5):\/\/(.+?):(.+?)@(.+)$/i);
  if (withAuthMatch) {
    return normalizeProxy({
      server: `${withAuthMatch[1]}://${withAuthMatch[4]}`,
      username: withAuthMatch[2],
      password: withAuthMatch[3],
    });
  }

  const noSchemeAuthIndex = trimmed.lastIndexOf('@');
  if (noSchemeAuthIndex > 0 && !trimmed.includes('://')) {
    const creds = trimmed.slice(0, noSchemeAuthIndex);
    const host = trimmed.slice(noSchemeAuthIndex + 1);
    const colonIndex = creds.indexOf(':');
    if (colonIndex > 0) {
      return normalizeProxy({
        server: host,
        username: creds.slice(0, colonIndex),
        password: creds.slice(colonIndex + 1),
      });
    }
  }

  return normalizeProxy({ server: trimmed });
}

function parseProxyJson(content) {
  try {
    const parsed = JSON.parse(content);
    if (Array.isArray(parsed)) {
      return parsed.map(parseProxyObject).filter(Boolean);
    }
    const one = parseProxyObject(parsed);
    return one ? [one] : [];
  } catch {
    return [];
  }
}

function parseProxyCsv(content) {
  const lines = String(content || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (lines.length < 2) return [];

  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const rows = [];

  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(',').map(c => c.trim());
    const row = {};
    headers.forEach((header, idx) => {
      row[header] = cols[idx];
    });
    rows.push(parseProxyObject(row));
  }

  return rows.filter(Boolean);
}

function dedupeProxies(list) {
  const seen = new Set();
  const result = [];

  for (const proxy of list || []) {
    const normalized = normalizeProxy(proxy);
    if (!normalized) continue;
    const key = `${normalized.server}|${normalized.username || ''}|${normalized.password || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(normalized);
  }

  return result;
}

function parseAnyContent(content) {
  const text = String(content || '').trim();
  if (!text) return [];

  if (text.startsWith('{') || text.startsWith('[')) {
    const jsonResults = parseProxyJson(text);
    if (jsonResults.length) return jsonResults;
  }

  if (/^(server|host|port|username|password|scheme)\s*,/i.test(text)) {
    const csvResults = parseProxyCsv(text);
    if (csvResults.length) return csvResults;
  }

  return text
    .split(/[\r\n;]+/)
    .map(parseProxyLine)
    .filter(Boolean);
}

function loadProxySources({ envValue, filePath, dataJsonPath } = {}) {
  const proxies = [];

  if (envValue) {
    proxies.push(...parseAnyContent(envValue));
  }

  if (filePath && fs.existsSync(filePath)) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      proxies.push(...parseAnyContent(content));
    } catch {
      // ignore file read errors in the generic helper
    }
  }

  // Support JSON files like data.json where proxies are objects with a `proxy` field.
  if (dataJsonPath && fs.existsSync(dataJsonPath)) {
    try {
      const content = fs.readFileSync(dataJsonPath, 'utf8');
      const data = JSON.parse(content);
      const arr = Array.isArray(data) ? data : data.proxies;
      if (Array.isArray(arr)) {
        for (const item of arr) {
          if (item && typeof item === 'object') {
            if (item.proxy) proxies.push(...parseAnyContent(item.proxy));
            else proxies.push(parseProxyObject(item));
          } else if (typeof item === 'string') {
            proxies.push(...parseAnyContent(item));
          }
        }
      }
    } catch {
      // ignore JSON read errors
    }
  }

  return dedupeProxies(proxies);
}

function proxyToString(proxy) {
  const p = normalizeProxy(proxy);
  if (!p) return '';
  let server = p.server;
  if (!server.includes('://')) server = `http://${server}`;
  if (p.username && p.password) {
    const end = server.indexOf('://');
    const protocol = server.slice(0, end + 3);
    const rest = server.slice(end + 3);
    const encodedUser = encodeURIComponent(p.username);
    const encodedPass = encodeURIComponent(p.password);
    return `${protocol}${encodedUser}:${encodedPass}@${rest}`;
  }
  return server;
}

function createProxyManager({ envValue, filePath, dataJsonPath } = {}) {
  let cache = null;
  let roundRobinIndex = 0;

  function getAll() {
    if (!cache) cache = loadProxySources({ envValue, filePath, dataJsonPath });
    return cache;
  }

  function reload() {
    cache = loadProxySources({ envValue, filePath, dataJsonPath });
    return cache;
  }

  function nextProxy() {
    const proxies = getAll();
    if (!proxies.length) return null;
    const proxy = proxies[roundRobinIndex % proxies.length];
    roundRobinIndex++;
    return proxy;
  }

  function resolveForAccount(username, strategy = 'stable-hash') {
    const proxies = getAll();
    if (!proxies.length) return null;
    if (strategy === 'round-robin') return nextProxy();
    const idx = Math.abs(hashString(username || '')) % proxies.length;
    return proxies[idx];
  }

  function parseInput(input) {
    if (typeof input === 'string') return parseAnyContent(input);
    if (Array.isArray(input)) {
      const result = [];
      for (const item of input) {
        if (typeof item === 'string') result.push(...parseAnyContent(item));
        else if (item && typeof item === 'object') {
          const parsed = parseProxyObject(item);
          if (parsed) result.push(parsed);
        }
      }
      return dedupeProxies(result);
    }
    if (input && typeof input === 'object') {
      const parsed = parseProxyObject(input);
      return parsed ? [parsed] : [];
    }
    return [];
  }

  function save(proxies) {
    const normalized = dedupeProxies(proxies);
    if (filePath) {
      const lines = normalized.map(proxyToString).filter(Boolean);
      fs.writeFileSync(filePath, lines.join('\n'), 'utf8');
    }
    cache = normalized;
    roundRobinIndex = 0;
    return normalized;
  }

  return {
    getAll,
    reload,
    nextProxy,
    resolveForAccount,
    parseInput,
    save,
  };
}

module.exports = {
  createProxyManager,
  dedupeProxies,
  hashString,
  loadProxySources,
  normalizeProxy,
  parseAnyContent,
  parseProxyCsv,
  parseProxyJson,
  parseProxyLine,
  parseProxyObject,
  proxyToString,
};
