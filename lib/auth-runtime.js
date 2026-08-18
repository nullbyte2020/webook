const SESSION_STATES = {
  AUTH_PENDING: 'AUTH_PENDING',
  AUTH_READY: 'AUTH_READY',
  QUEUE_WAITING: 'QUEUE_WAITING',
  BOOKING_READY: 'BOOKING_READY',
  HOLDING: 'HOLDING',
  HANDOFF_PENDING: 'HANDOFF_PENDING',
  FAILED: 'FAILED',
};

function buildAccountRuntime(account, options = {}) {
  const accountType = account?.type === 'holdToken' ? 'holdToken' : 'credentials';
  const loginIdentity = accountType === 'credentials'
    ? {
        username: account?.username || null,
        password: account?.password || null,
      }
    : (account?.loginEmail && account?.loginPassword
      ? {
          username: account.loginEmail,
          password: account.loginPassword,
        }
      : null);

  return {
    accountType,
    accountIdentity: account?.username || null,
    sessionStorageKey: account?.username || null,
    runtimeAuthMode: accountType,
    loginIdentity,
    supportsInteractiveLogin: !!(loginIdentity?.username && loginIdentity?.password),
    supportsInjectedSession: accountType === 'holdToken',
    rawAccount: account || {},
    options,
  };
}

function createSessionFromRuntime(runtime, options = {}) {
  return {
    accountIdentity: runtime.accountIdentity,
    sessionStorageKey: runtime.sessionStorageKey,
    runtimeAuthMode: runtime.runtimeAuthMode,
    loginIdentity: runtime.loginIdentity,
    supportsInteractiveLogin: runtime.supportsInteractiveLogin,
    supportsInjectedSession: runtime.supportsInjectedSession,
    state: SESSION_STATES.AUTH_PENDING,
    stateMeta: { createdAt: Date.now(), ...options },
  };
}

function setSessionState(session, state, meta = {}) {
  session.state = state;
  session.stateMeta = {
    ...(session.stateMeta || {}),
    ...meta,
    updatedAt: Date.now(),
  };
  return session;
}

async function prepareCredentialSession(session) {
  return setSessionState(session, SESSION_STATES.AUTH_PENDING, { mode: 'credentials' });
}

async function prepareHoldTokenSession(session) {
  return setSessionState(session, SESSION_STATES.AUTH_PENDING, { mode: 'holdToken' });
}

async function ensureLoggedInForCredentials(session) {
  if (!session?.loginIdentity?.username || !session?.loginIdentity?.password) {
    return setSessionState(session, SESSION_STATES.FAILED, { reason: 'missing_login_identity' });
  }
  return setSessionState(session, SESSION_STATES.AUTH_READY, { authMode: 'credentials' });
}

async function ensureInjectedSessionReady(session) {
  return setSessionState(session, SESSION_STATES.AUTH_READY, { authMode: 'holdToken' });
}

async function ensureAuthForSession(session) {
  if (session.runtimeAuthMode === 'credentials') {
    return ensureLoggedInForCredentials(session);
  }
  if (session.runtimeAuthMode === 'holdToken') {
    return ensureInjectedSessionReady(session);
  }
  return setSessionState(session, SESSION_STATES.FAILED, { reason: 'unknown_runtime_auth_mode' });
}

module.exports = {
  SESSION_STATES,
  buildAccountRuntime,
  createSessionFromRuntime,
  setSessionState,
  prepareCredentialSession,
  prepareHoldTokenSession,
  ensureLoggedInForCredentials,
  ensureInjectedSessionReady,
  ensureAuthForSession,
};
