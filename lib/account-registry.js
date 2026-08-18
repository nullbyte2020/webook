function createAccountRegistry(initialAccounts = []) {
  const store = new Map();

  function normalizeAccount(account) {
    if (!account || typeof account !== 'object') return null;
    const username = account.username != null ? String(account.username).trim() : '';
    if (!username) return null;
    return { ...account, username };
  }

  function registerAccounts(accounts) {
    const list = Array.isArray(accounts) ? accounts : [accounts];
    const registered = [];
    for (const item of list) {
      const normalized = normalizeAccount(item);
      if (!normalized) continue;
      store.set(normalized.username, { ...normalized });
      registered.push(normalized.username);
    }
    return registered;
  }

  function getRegisteredAccount(username) {
    const key = String(username || '').trim();
    if (!key || !store.has(key)) return null;
    return { ...store.get(key) };
  }

  function hasAccount(username) {
    const key = String(username || '').trim();
    return !!key && store.has(key);
  }

  function removeAccount(username) {
    const key = String(username || '').trim();
    if (!key) return false;
    return store.delete(key);
  }

  function listAccounts() {
    return Array.from(store.values()).map(item => ({ ...item }));
  }

  function clear() {
    store.clear();
  }

  registerAccounts(initialAccounts);

  return {
    registerAccounts,
    getRegisteredAccount,
    hasAccount,
    removeAccount,
    listAccounts,
    clear,
  };
}

module.exports = {
  createAccountRegistry,
};
