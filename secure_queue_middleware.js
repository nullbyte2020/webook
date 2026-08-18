/**
 * Secure queue token validation middleware.
 *
 * Fixes the vulnerabilities described in webapp3/New Text Document.txt:
 *   - Missing or skipped JWT signature verification
 *   - alg=none / algorithm confusion acceptance
 *   - Direct booking without an active front-of-queue token
 *   - Token replay (same token used multiple times)
 *   - Race condition in queue position allocation
 *
 * Usage (Express):
 *   const {
 *     createQueueValidator,
 *     createAtomicQueue,
 *     requireFrontOfQueue,
 *   } = require('./secure_queue_middleware');
 *
 *   const queueStore = createAtomicQueue({ jwtSecret: process.env.QUEUE_JWT_SECRET });
 *
 *   app.post('/api/queue/join', queueStore.join);
 *   app.get('/api/queue/status', queueStore.status);
 *   app.post('/api/booking/create', requireFrontOfQueue(queueStore), bookingHandler);
 */

const crypto = require('crypto');

const ALG_HS256 = 'HS256';
const TOKEN_PREFIX = 'queue:';

function base64UrlDecode(str) {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + '==', 'base64');
}

function base64UrlEncode(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function signHs256(message, secret) {
  return base64UrlEncode(crypto.createHmac('sha256', secret).update(message).digest());
}

/**
 * Strictly verify a queue token.
 * Rejects alg=none, algorithm confusion, expired tokens, and malformed payloads.
 */
function verifyQueueToken(token, secret, expectedUserAgent) {
  if (typeof token !== 'string' || token.split('.').length !== 3) {
    return { ok: false, error: 'malformed_token' };
  }

  const [headerB64, payloadB64, signatureB64] = token.split('.');
  let header;
  let payload;
  try {
    header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
    payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  } catch {
    return { ok: false, error: 'decode_error' };
  }

  if (header.alg !== ALG_HS256) {
    return { ok: false, error: `disallowed_algorithm:${header.alg}` };
  }

  let actualSig;
  try {
    actualSig = base64UrlDecode(signatureB64);
  } catch {
    return { ok: false, error: 'malformed_signature' };
  }
  const expectedSig = crypto.createHmac('sha256', secret).update(`${headerB64}.${payloadB64}`).digest();
  if (actualSig.length !== expectedSig.length || !crypto.timingSafeEqual(actualSig, expectedSig)) {
    return { ok: false, error: 'invalid_signature' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.e && now > payload.e) {
    return { ok: false, error: 'token_expired' };
  }

  if (expectedUserAgent) {
    const embeddedUa = (payload.u || '').split('').reverse().join('');
    if (embeddedUa !== expectedUserAgent) {
      return { ok: false, error: 'user_agent_mismatch' };
    }
  }

  if (typeof payload.n !== 'number' || payload.n < 0) {
    return { ok: false, error: 'invalid_position' };
  }

  return { ok: true, payload };
}

/**
 * Factory for an atomic, in-memory queue store.
 * In production this should be backed by Redis (INCR/SET NX) or a database
 * with row-level locks.
 */
function createAtomicQueue({ jwtSecret, tokenTtlSeconds = 3600, maxActiveTokens = 10000 } = {}) {
  if (!jwtSecret) {
    throw new Error('jwtSecret is required');
  }

  // Map eventId -> { counter, served, tokens }
  const events = new Map();
  // Global set of consumed token jti/nonces to prevent replay
  const consumedTokens = new Set();

  function getEventState(eventId) {
    if (!events.has(eventId)) {
      events.set(eventId, {
        counter: 0,
        served: 0,
        tokens: new Map(), // token -> { position, used, issuedAt }
      });
    }
    return events.get(eventId);
  }

  function issueQueueToken(eventId, userAgent) {
    const state = getEventState(eventId);

    // Atomic increment (simulated; replace with Redis INCR in production)
    state.counter += 1;
    const position = state.counter;

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      e: now + tokenTtlSeconds,
      n: position,
      u: userAgent.split('').reverse().join(''),
      jti: crypto.randomUUID(), // one-time-use nonce
      event: eventId,
      iat: now,
    };

    const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify({ alg: ALG_HS256, typ: 'JWT' })));
    const payloadB64 = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
    const token = `${headerB64}.${payloadB64}.${signHs256(`${headerB64}.${payloadB64}`, jwtSecret)}`;

    state.tokens.set(token, { position, used: false, issuedAt: now });

    // Simple eviction if the store grows too large
    if (state.tokens.size > maxActiveTokens) {
      const oldest = state.tokens.keys().next().value;
      state.tokens.delete(oldest);
    }

    return { token, position };
  }

  function consumeToken(token, userAgent) {
    const verified = verifyQueueToken(token, jwtSecret, userAgent);
    if (!verified.ok) {
      return { ok: false, error: verified.error };
    }

    const { payload } = verified;
    if (!payload.jti) {
      return { ok: false, error: 'missing_nonce' };
    }
    if (consumedTokens.has(payload.jti)) {
      return { ok: false, error: 'token_already_used' };
    }

    const state = getEventState(payload.event);
    const record = state.tokens.get(token);
    if (!record) {
      return { ok: false, error: 'token_not_found' };
    }
    if (record.used) {
      return { ok: false, error: 'token_already_used' };
    }

    // Front-of-queue check: position must equal the next served number + 1.
    // This prevents direct booking with a back-of-queue token.
    if (record.position !== state.served + 1) {
      return { ok: false, error: 'not_front_of_queue' };
    }

    record.used = true;
    consumedTokens.add(payload.jti);
    state.served += 1;

    return { ok: true, position: record.position, event: payload.event };
  }

  function getStatus(token, userAgent) {
    const verified = verifyQueueToken(token, jwtSecret, userAgent);
    if (!verified.ok) {
      return { ok: false, error: verified.error };
    }
    const { payload } = verified;
    const state = getEventState(payload.event);
    const record = state.tokens.get(token);
    if (!record) {
      return { ok: false, error: 'token_not_found' };
    }
    return {
      ok: true,
      position: record.position,
      served: state.served,
      queued: record.position > state.served,
      ahead: Math.max(0, record.position - state.served - 1),
    };
  }

  // Express route handlers
  function join(req, res) {
    const eventId = req.body?.event_id || req.query?.event_id;
    const userAgent = req.headers['user-agent'] || '';
    if (!eventId) {
      return res.status(400).json({ error: 'event_id_required' });
    }
    const { token, position } = issueQueueToken(eventId, userAgent);
    return res.status(200).json({
      queue_token: token,
      position,
      estimated_wait_seconds: position * 5,
    });
  }

  function parseCookie(req, name) {
    const raw = req.headers.cookie || '';
    const match = raw.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
    return match ? decodeURIComponent(match[1]) : undefined;
  }

  function status(req, res) {
    const token = req.headers['queue-token'] || parseCookie(req, 'queue_session');
    const userAgent = req.headers['user-agent'] || '';
    if (!token) {
      return res.status(400).json({ error: 'queue_token_required' });
    }
    const result = getStatus(token, userAgent);
    if (!result.ok) {
      return res.status(401).json({ error: result.error });
    }
    return res.status(200).json({ _queue: result });
  }

  return {
    join,
    status,
    consumeToken,
    issueQueueToken,
    verifyQueueToken: (token) => verifyQueueToken(token, jwtSecret),
  };
}

/**
 * Express middleware: only allow booking if the queue token is at the front
 * and has not been used before.
 */
function requireFrontOfQueue(queueStore) {
  function parseCookie(req, name) {
    const raw = req.headers.cookie || '';
    const match = raw.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
    return match ? decodeURIComponent(match[1]) : undefined;
  }

  return (req, res, next) => {
    const token = req.headers['queue-token'] || parseCookie(req, 'queue_session');
    const userAgent = req.headers['user-agent'] || '';
    if (!token) {
      return res.status(400).json({ error: 'queue_token_required' });
    }
    const result = queueStore.consumeToken(token, userAgent);
    if (!result.ok) {
      return res.status(403).json({ error: result.error });
    }
    req.queuePosition = result.position;
    next();
  };
}

module.exports = {
  createAtomicQueue,
  requireFrontOfQueue,
};
