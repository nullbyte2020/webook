const socket = io();

const els = {
  eventUrl: document.getElementById('eventUrl'),
  fetchBtn: document.getElementById('fetchBtn'),
  refreshAvailabilityBtn: document.getElementById('refreshAvailabilityBtn'),
  checkQueueBtn: document.getElementById('checkQueueBtn'),
  eventInfo: document.getElementById('eventInfo'),
  eventInfoTitle: document.getElementById('eventInfoTitle'),
  eventInfoBody: document.getElementById('eventInfoBody'),
  eventQueueBadge: document.getElementById('eventQueueBadge'),
  manualEmail: document.getElementById('manualEmail'),
  manualPassword: document.getElementById('manualPassword'),
  manualCookies: document.getElementById('manualCookies'),
  addAccountBtn: document.getElementById('addAccountBtn'),
  addDefaultAccountBtn: document.getElementById('addDefaultAccountBtn'),
  addByTokenOrCookiesBtn: document.getElementById('addByTokenOrCookiesBtn'),
  accountsFile: document.getElementById('accountsFile'),
  accountsList: document.getElementById('accountsList'),
  accountsSummary: document.getElementById('accountsSummary'),
  selectAllAccountsBtn: document.getElementById('selectAllAccountsBtn'),
  clearAccountsBtn: document.getElementById('clearAccountsBtn'),
  removeAllAccountsBtn: document.getElementById('removeAllAccountsBtn'),
  loadAccountsBtn: document.getElementById('loadAccountsBtn'),
  saveAccountsBtn: document.getElementById('saveAccountsBtn'),
  maxConcurrency: document.getElementById('maxConcurrency'),
  concurrencyHint: document.getElementById('concurrencyHint'),
  speedModeSelect: document.getElementById('speedModeSelect'),
  speedHint: document.getElementById('speedHint'),
  startBookingBtn: document.getElementById('startBookingBtn'),
  stopBookingBtn: document.getElementById('stopBookingBtn'),
  downloadLogsBtn: document.getElementById('downloadLogsBtn'),
  clearLogsBtn: document.getElementById('clearLogsBtn'),
  startPairCyclingBtn: document.getElementById('startPairCyclingBtn'),
  stopPairCyclingBtn: document.getElementById('stopPairCyclingBtn'),
  pairCyclesStatus: document.getElementById('pairCyclesStatus'),
  sectionsList: document.getElementById('sectionsList'),
  selectionHint: document.getElementById('selectionHint'),
  teamSelectionCard: document.getElementById('teamSelectionCard'),
  teamsList: document.getElementById('teamsList'),
  teamSelectionHint: document.getElementById('teamSelectionHint'),
  captchaKeysList: document.getElementById('captchaKeysList'),
  captchaKeyLabel: document.getElementById('captchaKeyLabel'),
  captchaKeyInput: document.getElementById('captchaKeyInput'),
  addCaptchaKeyBtn: document.getElementById('addCaptchaKeyBtn'),

  saveProxiesBtn: document.getElementById('saveProxiesBtn'),
  loadProxiesBtn: document.getElementById('loadProxiesBtn'),
  proxyList: document.getElementById('proxyList'),
  proxyFileInput: document.getElementById('proxyFileInput'),
  proxyFileName: document.getElementById('proxyFileName'),
  proxyModeSelect: document.getElementById('proxyModeSelect'),
  proxyModeStatus: document.getElementById('proxyModeStatus'),
  testAllProxiesBtn: document.getElementById('testAllProxiesBtn'),
  loadDataJsonBtn: document.getElementById('loadDataJsonBtn'),
  filterWorkingBtn: document.getElementById('filterWorkingBtn'),
  proxiesSummary: document.getElementById('proxiesSummary'),
  proxiesList: document.getElementById('proxiesList'),
  proxyHost: document.getElementById('proxyHost'),
  proxyPort: document.getElementById('proxyPort'),
  proxyUser: document.getElementById('proxyUser'),
  proxyPass: document.getElementById('proxyPass'),
  addProxyBtn: document.getElementById('addProxyBtn'),
  clearProxiesBtn: document.getElementById('clearProxiesBtn'),
  statusBadge: document.getElementById('statusBadge'),
  activeCount: document.getElementById('activeCount'),
  pendingCount: document.getElementById('pendingCount'),
  doneCount: document.getElementById('doneCount'),
  heldCount: document.getElementById('heldCount'),
  logs: document.getElementById('logs'),
  sniperPulse: document.getElementById('sniperPulse'),
  logSearch: document.getElementById('logSearch'),
  credentialsPanel: document.getElementById('credentialsPanel'),
  cookiesPanel: document.getElementById('cookiesPanel'),
};

let sectionsData = [];
let teamsData = [];
let allTeamIds = [];
let allChannelKeys = [];
let commonChannelKeys = [];
let selectedTeam = null;
let eventTitle = '';
let eventMaxPerOrder = 30;
let accounts = [];
let running = false;
let captchaKeys = [];

function log(message, type = 'info') {
  const time = new Date().toLocaleTimeString();
  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  entry.innerHTML = `<span class="time">[${time}]</span> ${escapeHtml(message)}`;
  els.logs.appendChild(entry);
  els.logs.scrollTop = els.logs.scrollHeight;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function parseSeatName(name) {
  const parts = name.split('-');
  if (parts.length < 3) return null;
  const seat = parts.pop();
  const row = parts.pop();
  const section = parts.join('-');
  return { section, row, seat };
}

function formatSeat(seatName) {
  const p = parseSeatName(seatName);
  if (!p) return escapeHtml(seatName);
  const section = sectionsData.find(s => s.label === p.section);
  const categoryTitle = section?.categories?.[0]?.title || p.section;
  const sec = escapeHtml(p.section);
  const row = escapeHtml(p.row);
  const seat = escapeHtml(p.seat);
  const cat = escapeHtml(categoryTitle);
  return `<span class="seat-chip">${cat} (القسم: ${sec} - الصف: ${row} - المقعد: ${seat})</span>`;
}

function formatSeatList(seats) {
  if (!seats || seats.length === 0) return '';
  return `<span class="seat-list">${seats.map(formatSeat).join('')}</span>`;
}

function renderSeatChips(username, seats) {
  if (!seats || seats.length === 0) return '';
  return `<div class="seat-chips">${seats.map(seatName => {
    const p = parseSeatName(seatName);
    const label = p ? `${p.section} ${p.row}-${p.seat}` : seatName;
    return `<span class="seat-chip-with-action">
      <span class="seat-chip">${escapeHtml(label)}</span>
      <button class="btn-release-seat" data-action="release-seat" data-seat="${escapeHtml(seatName)}" title="فك مسك هذا المقعد">×</button>
    </span>`;
  }).join('')}</div>`;
}

function setSniperActive(active) {
  const badge = els.statusBadge;
  const pulse = els.sniperPulse;
  if (!badge || !pulse) return;
  if (active) {
    badge.classList.add('sniper-active');
    pulse.classList.remove('hidden');
  } else {
    badge.classList.remove('sniper-active');
    pulse.classList.add('hidden');
  }
}

function setStatus(stage, message) {
  const badge = els.statusBadge;
  badge.className = 'badge';
  badge.textContent = stageLabel(stage).toUpperCase();
  if (stage === 'idle') badge.classList.add('idle');
  else if (['paused', 'holding', 'captcha', 'login-manual', 'seats-partial', 'queued'].includes(stage)) badge.classList.add('paused');
  else if (stage === 'error' || stage === 'failed') badge.classList.add('error');
  else if (['payment-ready', 'done', 'success'].includes(stage)) badge.classList.add('success');
  else badge.classList.add('running');

  const sniperStages = ['seats-monitoring', 'seats-sniping', 'direct-ws'];
  setSniperActive(sniperStages.includes(stage));

  log(`${stageLabel(stage)}: ${message}`);
}

socket.on('status', data => {
  setStatus(data.stage, `${data.account ? `[${data.account}] ` : ''}${data.message}`);
  if (data.account) updateAccountRow(data.account, data.stage, data);
  if (['idle', 'error', 'payment-ready'].includes(data.stage) && !data.account) {
    setLoading(false);
  }
});

socket.on('account-update', data => {
  updateAccountRow(data.account, data.stage, data);
});

socket.on('queue-stats', stats => {
  els.activeCount.textContent = stats.active || 0;
  els.pendingCount.textContent = stats.pending || 0;
  els.doneCount.textContent = stats.done || 0;
  if (running && stats.active === 0 && stats.pending === 0) {
    setLoading(false);
  }
  updateHeldCount();
});

socket.on('console', data => log(`Console ${data.type}: ${data.text}`, 'error'));
socket.on('network', data => log(`Network ${data.status}: ${data.url}`));

// Pair cycling status updates
socket.on('pair-cycle-status', data => {
  renderPairCyclesStatus(data.cycles || []);
});

socket.on('pair-cycle-event', data => {
  log(`[Pair ${data.pairId}] ${data.message}`, data.stage === 'error' || data.stage === 'failed' ? 'error' : 'info');
  refreshPairCyclesStatus();
});

function setLoading(loading) {
  running = loading;
  if (loading) window.__lastLoadingStart = Date.now();
  els.fetchBtn.disabled = loading;
  els.refreshAvailabilityBtn.disabled = loading;
  els.startBookingBtn.disabled = loading || getSelectedSections().length === 0 || !accounts.some(a => a.selected);
  els.accountsFile.disabled = loading;
  updateButtonStates();
}

function getSelectedSections() {
  return sectionsData.filter(s => s.selected).map(s => s.label);
}

function updateButtonStates() {
  const hasSelectedAccounts = accounts.some(a => a.selected);
  const hasSelectedSections = getSelectedSections().length > 0;
  els.startBookingBtn.disabled = running || !hasSelectedAccounts || !hasSelectedSections;

  const selected = getSelectedSections();
  if (els.selectionHint) {
    if (selected.length === 0) {
      els.selectionHint.textContent = 'اختر قسماً واحداً على الأقل ليتم تفعيل زر بدء الحجز';
    } else {
      els.selectionHint.textContent = `الأقسام المختارة: ${selected.join('، ')} (${selected.length})`;
    }
  }
}

// Sections / availability
async function loadSections() {
  const url = els.eventUrl.value.trim();
  if (!url) return alert('أدخل رابط الفعالية');
  setLoading(true);
  log('جاري جلب الأقسام والتوفر...');
  try {
    const [sectionsRes, queueRes] = await Promise.all([
      fetch(`/api/chart-sections?url=${encodeURIComponent(url)}`),
      fetch(`/api/check-queue?url=${encodeURIComponent(url)}`).catch(() => ({ ok: false })),
    ]);
    const json = await sectionsRes.json();
    if (!json.success) throw new Error(json.error || 'Unknown error');

    let queueStatus = null;
    if (queueRes.ok) {
      try { queueStatus = await queueRes.json(); } catch {}
    }

    eventTitle = json.event || '';
    eventMaxPerOrder = 30; // user requested: override platform limits to 30
    showEventInfo(json.event, json.chartSections, queueStatus);
    const previousSelected = new Set(getSelectedSections());
    sectionsData = (json.chartSections || []).map(s => ({
      ...s,
      selected: previousSelected.has(s.label),
    }));
    renderSections();

    // Handle team selection for special events (e.g. sports matches).
    teamsData = (json.teams || []).filter(t => t.id && t.name);
    allTeamIds = json.allTeamIds || teamsData.map(t => t.id);
    allChannelKeys = json.allChannelKeys || [];
    commonChannelKeys = json.commonChannelKeys || [];
    selectedTeam = teamsData.length > 0
      ? { ...teamsData[0], allTeamIds, allChannelKeys, commonChannelKeys }
      : null;
    renderTeams();

    log(`تم تحميل ${sectionsData.length} أقسام لـ "${eventTitle}". الحد الأقصى للطلب الواحد: ${eventMaxPerOrder} تذاكر.`);
    if (queueStatus && queueStatus.success) {
      log(`حالة الطابور: ${queueStatus.queued ? 'فعالية في الطابور' : 'حجز مباشر'} (ثقة: ${queueStatus.confidence || 'low'})`);
    }
  } catch (err) {
    log(`فشل جلب الأقسام: ${err.message}`, 'error');
    alert('فشل جلب الأقسام: ' + err.message);
  } finally {
    setLoading(false);
  }
}

async function checkQueueOnly() {
  const url = els.eventUrl.value.trim();
  if (!url) return alert('أدخل رابط الفعالية');
  setLoading(true);
  log('جاري فحص حالة الطابور والاتصال...');
  try {
    const res = await fetch(`/api/check-queue?url=${encodeURIComponent(url)}`);
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'Unknown error');
    updateQueueBadge(json);
    log(`حالة الطابور: ${json.queued ? 'فعالية في الطابور' : 'حجز مباشر'} (ثقة: ${json.confidence || 'low'})`);
  } catch (err) {
    log(`فشل فحص الطابور: ${err.message}`, 'error');
  } finally {
    setLoading(false);
  }
}

function updateQueueBadge(queueStatus) {
  if (!els.eventQueueBadge) return;
  // Badge is intentionally hidden per user request; keep it hidden.
  els.eventQueueBadge.className = 'event-badge hidden';
  els.eventQueueBadge.textContent = '';
}

function getSpeedSettings() {
  const mode = els.speedModeSelect ? els.speedModeSelect.value : 'fast';
  const base = {
    fastMode: true,
    sniperEnabled: true,
    sniperRestrictSections: true,
    sniperBurstGapMs: 0,
  };
  if (mode === 'turbo') {
    return { ...base, sniperIntervalMs: 50, sniperTimeoutMs: 1000, delayMultiplier: 0.3 };
  }
  if (mode === 'normal') {
    return { ...base, sniperIntervalMs: 250, sniperTimeoutMs: 2500, delayMultiplier: 0.9 };
  }
  // fast (default)
  return { ...base, sniperIntervalMs: 80, sniperTimeoutMs: 1200, delayMultiplier: 0.45 };
}

function showEventInfo(event, sections, queueStatus = null) {
  if (!event) {
    els.eventInfo.classList.add('hidden');
    return;
  }
  const totalAvailable = sections.reduce((sum, s) => sum + (s.availableCount || 0), 0);
  const availableSections = sections.filter(s => (s.availableCount || 0) > 0).length;
  if (els.eventInfoTitle) els.eventInfoTitle.textContent = event;
  if (els.eventInfoBody) {
    els.eventInfoBody.innerHTML = `
      <span>إجمالي المقاعد المتاحة: <b>${totalAvailable}</b></span>
      <span>الأقسام المتاحة: <b>${availableSections}</b> / ${sections.length}</span>
    `;
  }
  updateQueueBadge(queueStatus);
  els.eventInfo.classList.remove('hidden');
}

els.fetchBtn.addEventListener('click', loadSections);
els.refreshAvailabilityBtn.addEventListener('click', loadSections);
els.checkQueueBtn.addEventListener('click', checkQueueOnly);

function formatPrice(categories) {
  if (!categories || categories.length === 0) return '';
  const totals = categories.map(c => c.total).filter(Boolean);
  if (totals.length === 0) return '';
  const min = Math.min(...totals);
  const max = Math.max(...totals);
  if (min === max) return `${min.toFixed(2)} ر.س`;
  return `${min.toFixed(2)} - ${max.toFixed(2)} ر.س`;
}

function toggleSection(label) {
  const section = sectionsData.find(s => s.label === label);
  if (!section) return;
  section.selected = !section.selected;
  renderSections();
}

function renderTeams() {
  if (!els.teamSelectionCard || !els.teamsList) return;

  if (teamsData.length === 0) {
    els.teamSelectionCard.classList.add('hidden');
    return;
  }

  els.teamSelectionCard.classList.remove('hidden');
  els.teamsList.innerHTML = '';

  // Add an "All teams" pseudo-option so the user can load every section
  // without being restricted to one team's allocation.
  const allTeamsOption = { id: 'ALL_TEAMS', name: 'كل الفرق (كل الكراسي المتاحة)' };
  const displayTeams = [allTeamsOption, ...teamsData];

  displayTeams.forEach(team => {
    const item = document.createElement('div');
    item.className = 'team-item' + (selectedTeam && selectedTeam.id === team.id ? ' selected' : '');
    item.innerHTML = `
      <input type="radio" name="favoriteTeam" class="team-radio" value="${escapeHtml(team.id)}" ${selectedTeam && selectedTeam.id === team.id ? 'checked' : ''}>
      <div class="team-info">
        <div class="team-title">${escapeHtml(team.name)}</div>
      </div>
    `;

    const radio = item.querySelector('.team-radio');
    radio.addEventListener('change', () => {
      selectedTeam = { ...team, allTeamIds, allChannelKeys, commonChannelKeys };
      renderTeams();
    });
    item.addEventListener('click', e => {
      if (e.target === radio) return;
      selectedTeam = { ...team, allTeamIds, allChannelKeys, commonChannelKeys };
      renderTeams();
    });
    els.teamsList.appendChild(item);
  });

  if (els.teamSelectionHint) {
    els.teamSelectionHint.textContent = teamsData.length > 1
      ? 'اختر فريقاً واحداً أو "كل الفرق" لتحميل كل الكراسي'
      : 'تم اختيار الفريق الوحيد تلقائياً';
  }
}

function renderSections() {
  els.sectionsList.innerHTML = '';

  if (sectionsData.length === 0) {
    els.sectionsList.innerHTML = '<p style="color:var(--muted)">لا توجد أقسام متاحة. اضغط "جلب الأقسام".</p>';
    updateButtonStates();
    return;
  }

  sectionsData.forEach(section => {
    const price = formatPrice(section.categories);
    const categoriesText = (section.categories || []).map(c => c.title).join(' / ') || '';
    const isSoldOut = (section.availableCount || 0) === 0;
    const badge = isSoldOut
      ? '<span class="section-badge sold-out-badge">ممتلئ · متابعة</span>'
      : '';

    const item = document.createElement('div');
    item.className = 'section-item' + (section.selected ? ' selected' : '') + (isSoldOut ? ' sold-out' : '');
    item.innerHTML = `
      <input type="checkbox" class="section-checkbox" ${section.selected ? 'checked' : ''}>
      <div class="section-info">
        <div class="section-title">${escapeHtml(section.label)} ${categoriesText ? `<small>(${escapeHtml(categoriesText)})</small>` : ''} ${badge}</div>
        <div class="section-meta">مقاعد متاحة: <b>${section.availableCount || 0}</b></div>
      </div>
      <div class="section-price">${escapeHtml(price)}</div>
    `;

    const checkbox = item.querySelector('.section-checkbox');
    checkbox.addEventListener('change', e => {
      e.stopPropagation();
      toggleSection(section.label);
    });
    item.addEventListener('click', e => {
      if (e.target === checkbox) return;
      toggleSection(section.label);
    });
    els.sectionsList.appendChild(item);
  });

  updateButtonStates();
}

// Accounts
function upsertAccount(username, password, selected = true) {
  username = username.trim();
  password = password.trim();
  if (!username || !password) return;
  const existing = accounts.find(a => a.username === username);
  if (existing) {
    existing.password = password;
    existing.type = 'credentials';
    delete existing.holdToken;
    existing.selected = selected;
    if (typeof existing.useProxy !== 'boolean') existing.useProxy = false;
    if (typeof existing.ticketCount !== 'number') existing.ticketCount = 30;
  } else {
    accounts.push({
      id: `${Date.now()}-${username}`,
      username,
      password,
      type: 'credentials',
      selected,
      stage: 'idle',
      seats: [],
      queuePosition: null,
      useProxy: false,
      ticketCount: 30,
    });
  }
  renderAccounts();
}

function upsertHoldTokenAccount(holdToken, loginEmail, loginPassword, extras = {}, selected = true) {
  holdToken = holdToken.trim();
  loginEmail = (loginEmail || '').trim();
  loginPassword = (loginPassword || '').trim();
  if (!holdToken) return;
  const label = extras.cookiesSource
    ? `cookies:${holdToken.slice(0, 8)}...${holdToken.slice(-6)}`
    : `token:${holdToken.slice(0, 8)}...${holdToken.slice(-6)}`;
  const existing = accounts.find(a => a.type === 'holdToken' && a.holdToken === holdToken);
  if (existing) {
    existing.selected = selected;
    if (loginEmail) existing.loginEmail = loginEmail;
    if (loginPassword) existing.loginPassword = loginPassword;
    if (typeof existing.useProxy !== 'boolean') existing.useProxy = false;
    if (typeof existing.ticketCount !== 'number') existing.ticketCount = 30;
    Object.assign(existing, extras);
  } else {
    accounts.push({
      id: `${Date.now()}-${holdToken.slice(-8)}`,
      username: label,
      holdToken,
      loginEmail,
      loginPassword,
      type: 'holdToken',
      selected,
      stage: 'idle',
      seats: [],
      queuePosition: null,
      useProxy: false,
      ticketCount: 30,
      ...extras,
    });
  }
  renderAccounts();
}

// Kept for backwards compatibility; new code should use upsertAccount.
function addAccount(username, password, selected = true) {
  upsertAccount(username, password, selected);
}

async function loadAccountsFromServer() {
  try {
    const res = await fetch('/api/load-accounts');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const loaded = json.accounts || [];
    for (const a of loaded) {
      upsertAccount(a.username, a.password, true);
    }
    log(`تم تحميل ${loaded.length} حساب من الخادم`);
  } catch (err) {
    log(`فشل تحميل الحسابات من الخادم: ${err.message}`, 'error');
  }
}

async function saveAccountsToServer() {
  try {
    const payload = accounts.map(a => ({ username: a.username, password: a.password }));
    const res = await fetch('/api/save-accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accounts: payload }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    log(`تم حفظ ${json.count} حساب على الخادم`);
  } catch (err) {
    log(`فشل حفظ الحسابات على الخادم: ${err.message}`, 'error');
  }
}

els.addAccountBtn.addEventListener('click', () => {
  upsertAccount(els.manualEmail.value, els.manualPassword.value);
  els.manualEmail.value = '';
  els.manualPassword.value = '';
});

els.addDefaultAccountBtn.addEventListener('click', () => {
  upsertAccount('tariqibrahim20@hotmail.com', 'Dd112233@');
});

els.addByTokenOrCookiesBtn.addEventListener('click', () => {
  const rawCookies = els.manualCookies.value.trim();

  if (!rawCookies) {
    return alert('الصق الكوكيز أولاً.\n\nخطوات:\n1. نزل إضافة Cookies Extractor من Chrome Web Store\n2. سجل دخول في event webook\n3. اضغط على الإضافة واختر Copy as JSON أو Copy as Header\n4. الصق هنا');
  }

  const parsed = parseCookieInput(rawCookies);
  const cookies = parsed.map;
  const extractedHoldToken = cookies.holdToken || cookies.hold_token || '';
  const queueToken = cookies.queue_session || cookies['queue-token'] || '';
  const token = cookies.token || '';
  const refreshToken = cookies.refresh_token || '';
  const cfClearance = cookies.cf_clearance || '';
  const recaptchaToken = cookies._grecaptcha || cookies['grecaptcha-token'] || '';
  if (!extractedHoldToken && !token) return alert('لم يُعثر على holdToken أو token في الكوكيز. تأكد إنك نسخت الكوكيز بعد تسجيل الدخول.');
  const extras = {
    queueToken,
    token,
    refreshToken,
    cfClearance,
    recaptchaToken,
    rawCookies: parsed.header,
    structuredCookies: parsed.items,
    cookiesSource: true,
  };
  // لا نربط الحساب بإيميل/باسورد؛ الكوكيز كافية للحجز مباشرة.
  upsertHoldTokenAccount(extractedHoldToken || token.slice(0, 8), '', '', extras);
  els.manualCookies.value = '';
  log('تمت إضافة حساب من الكوكيز (بدون ربط يوزر/باسورد)');
});

function cookiesArrayToHeader(items) {
  if (!Array.isArray(items)) return '';
  return items
    .filter(c => c && typeof c === 'object' && typeof c.name === 'string' && c.value !== undefined)
    .map(c => `${c.name}=${encodeURIComponent(String(c.value))}`)
    .join('; ');
}

function parseCookieInput(str) {
  const empty = { header: '', map: {}, items: null };
  if (!str || typeof str !== 'string') return empty;
  const trimmed = str.trim();

  // Cookies Editor / JSON array export: [{name, value, domain, path, ...}, ...]
  if (trimmed.startsWith('[')) {
    try {
      const items = JSON.parse(trimmed);
      if (Array.isArray(items)) {
        const map = {};
        for (const c of items) {
          if (c && typeof c.name === 'string' && c.value !== undefined) {
            map[c.name] = String(c.value);
          }
        }
        return { header: cookiesArrayToHeader(items), map, items };
      }
    } catch {}
  }

  // Header string: name=value; name2=value2
  const map = {};
  str.split(/;\s*/).forEach(part => {
    const idx = part.indexOf('=');
    if (idx <= 0) return;
    const name = part.slice(0, idx).trim();
    let value = part.slice(idx + 1).trim();
    try { value = decodeURIComponent(value); } catch {}
    if (name) map[name] = value;
  });
  return { header: trimmed, map, items: null };
}

els.accountsFile.addEventListener('change', e => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const text = reader.result;
    let added = 0;
    text.split(/\r?\n/).forEach(line => {
      line = line.trim();
      if (!line || line.startsWith('#')) return;
      if (line.toLowerCase().startsWith('hold:')) {
        const parts = line.slice(5).split(':');
        const token = parts[0]?.trim();
        const email = parts[1]?.trim();
        const password = parts.slice(2).join(':').trim();
        if (token) {
          upsertHoldTokenAccount(token, email, password);
          added++;
        }
        return;
      }
      const sep = line.indexOf(':');
      if (sep === -1) return;
      const username = line.slice(0, sep).trim();
      const password = line.slice(sep + 1).trim();
      if (username && password) {
        upsertAccount(username, password);
        added++;
      }
    });
    log(`تم تحميل ${added} حسابات من ${file.name}`);
  };
  reader.readAsText(file);
});

function renderAccounts() {
  els.accountsList.innerHTML = '';
  if (accounts.length === 0) {
    els.accountsList.innerHTML = '<p style="color:var(--muted)">لم يتم تحميل حسابات</p>';
    els.accountsSummary.textContent = '0 حساب محمل';
    updateButtonStates();
    return;
  }

  accounts.forEach(acc => {
    const hasSeats = acc.seats && acc.seats.length > 0;
    const isHoldToken = acc.type === 'holdToken';
    // Any non-idle stage means the bot is doing something with this account.
    const isActive = acc.stage !== 'idle' && acc.stage !== 'error';
    // Holding = has seats OR is in a stage where it actually holds / can pay for seats.
    const isHolding = hasSeats || ['paused', 'payment-ready', 'holding', 'done', 'payment', 'seats-selected', 'seats-partial', 'seats-synced', 'cycle-holding', 'seats-grabbed', 'seats-monitoring', 'seats-sniping'].includes(acc.stage);
    // Stop should be enabled whenever the bot is actively working.
    // 'paused' means the user already stopped this account; keep the button disabled
    // until a new run is started.
    const isRunning = isActive || ['queued', 'queue-open', 'queue-waiting', 'queue-position', 'queue-detected', 'selecting', 'launching', 'navigating', 'logging-in', 'booking-ready', 'team-selection', 'direct-ws', 'direct-ws-hold', 'seats-holding', 'seats-monitoring', 'seats-sniping', 'seats-grabbed', 'cycle-holding', 'team-selecting', 'team-selected', 'captcha-detected', 'captcha-solving'].includes(acc.stage);
    const canStop = isRunning && acc.stage !== 'paused';
    const row = document.createElement('div');
    row.className = 'account-row' + (acc.selected ? ' selected' : '') + ` stage-${acc.stage}` + (isHoldToken ? ' holdtoken-row' : '');
    row.dataset.id = acc.id;
    const stage = stageLabel(acc.stage, acc.queuePosition);
    const seatsHtml = hasSeats ? renderSeatChips(acc.username, acc.seats) : '';
    const positionText = acc.queuePosition != null ? `طابور #${acc.queuePosition.toLocaleString('en-US')}${acc.queueTotal ? ` / ${acc.queueTotal.toLocaleString('en-US')}` : ''}` : '';
    const timerText = acc.queueTimerText ? `⏳ ${acc.queueTimerText}` : '';
    const queueBadge = (positionText || timerText)
      ? `<span class="queue-badge">${[positionText, timerText].filter(Boolean).join(' · ')}</span>`
      : '';
    const typeBadge = isHoldToken ? '<span class="type-badge holdtoken-badge">Hold Token</span>' : '';
    const loginHint = isHoldToken && acc.loginEmail ? `<div class="account-login-hint">تسجيل الدخول: ${escapeHtml(acc.loginEmail)}</div>` : '';
    const proxyBadge = acc.proxy ? `<span class="proxy-badge" title="${escapeHtml(acc.proxy)}">🌐 ${escapeHtml(acc.proxy.split('://')[1] || acc.proxy)}</span>` : '';
    row.innerHTML = `
      <input type="checkbox" ${acc.selected ? 'checked' : ''}>
      <div class="account-info">
        <div class="account-user">${escapeHtml(acc.username)} ${typeBadge}</div>
        ${loginHint}
        <div class="account-stage">${stage}</div>
        ${queueBadge}
        <div class="account-seats">${seatsHtml}</div>
        ${proxyBadge}
      </div>
      <div class="account-actions">
        <label class="proxy-toggle">
          <select data-action="proxy-mode">
            <option value="direct" ${acc.useProxy ? '' : 'selected'}>⛔ مباشر</option>
            <option value="proxy" ${acc.useProxy ? 'selected' : ''}>🌐 بروكسي</option>
          </select>
        </label>
        <label class="ticket-count-label" title="عدد التذاكر المطلوب لهذا الحساب (حد أقصى 30)">
          🎫
          <input type="number" class="ticket-count-input" data-action="ticket-count" value="${acc.ticketCount || 30}" min="1" max="30" />
        </label>
        <button class="btn-proceed" data-action="proceed" ${!isHolding ? 'disabled' : ''}>دفع</button>
        <button class="btn-release" data-action="release" ${!isHolding ? 'disabled' : ''}>فك الكل</button>
        <button class="btn-stop" data-action="stop" ${!canStop ? 'disabled' : ''}>إيقاف</button>
        <button class="btn-delete" data-action="delete">🗑️ حذف</button>
      </div>
    `;
    const selectCheckbox = row.querySelector('input');
    if (selectCheckbox) {
      selectCheckbox.addEventListener('change', () => {
        acc.selected = !acc.selected;
        renderAccounts();
      });
    }
    const proxySelect = row.querySelector('[data-action="proxy-mode"]');
    if (proxySelect) {
      proxySelect.addEventListener('change', (e) => {
        acc.useProxy = e.target.value === 'proxy';
        renderAccounts();
      });
    }
    const ticketInput = row.querySelector('[data-action="ticket-count"]');
    if (ticketInput) {
      ticketInput.addEventListener('change', (e) => {
        let val = parseInt(e.target.value, 10);
        if (isNaN(val) || val < 1) val = 1;
        if (val > 30) val = 30;
        acc.ticketCount = val;
        renderAccounts();
      });
    }
    const proceedBtn = row.querySelector('[data-action="proceed"]');
    if (proceedBtn) proceedBtn.addEventListener('click', () => proceedAccount(acc.username));
    const releaseBtn = row.querySelector('[data-action="release"]');
    if (releaseBtn) releaseBtn.addEventListener('click', () => releaseAccount(acc.username));
    const stopBtn = row.querySelector('[data-action="stop"]');
    if (stopBtn) stopBtn.addEventListener('click', () => stopAccount(acc.username));
    const deleteBtn = row.querySelector('[data-action="delete"]');
    if (deleteBtn) deleteBtn.addEventListener('click', () => deleteAccount(acc.username));
    // Bind per-seat release buttons.
    row.querySelectorAll('[data-action="release-seat"]').forEach(btn => {
      btn.addEventListener('click', () => releaseSeat(acc.username, btn.dataset.seat));
    });
    els.accountsList.appendChild(row);
  });

  const selectedCount = accounts.filter(a => a.selected).length;
  els.accountsSummary.textContent = `${accounts.length} حساب محمل · ${selectedCount} محدد`;
  updateButtonStates();
  updateHeldCount();
}

function stageLabel(stage, position = null) {
  const map = {
    idle: 'في الانتظار',
    queued: `في الطابور${position ? ` #${position}` : ''}`,
    'queue-open': 'حجز مباشر',
    'queue-waiting': 'في الطابور',
    'queue-position': `في الطابور${position ? ` #${position}` : ''}`,
    'queue-detected': 'تم كشف طابور',
    'queue-detected-post-login': 'طابور بعد الدخول',
    'queue-cleared': 'انتهى الطابور',
    launching: 'يتم التشغيل',
    navigating: 'تحميل الصفحة',
    login: 'تسجيل الدخول',
    'login-detected': 'كشف صفحة الدخول',
    chart: 'تحميل المقاعد',
    selecting: 'اختيار المقاعد',
    holding: 'حجز المقاعد',
    paused: 'جاهز للدفع',
    payment: 'صفحة الدفع',
    'payment-ready': 'جاهز للدفع',
    'seats-selected': 'تم المسك',
    'seats-partial': 'مسك جزئي',
    'seats-synced': 'تمت مزامنة الشارت',
    'cycle-holding': 'مسك في دورة تناوب',
    'seats-sniping': 'سنايبر',
    'seats-monitoring': 'مراقبة التوفر',
    'seats-grabbed': 'تم مسك مقعد',
    'seats-server-limit': 'حد خادم للمسك',
    logout: 'تسجيل خروج',
    'cookies-accepted': 'قبول الكوكيز',
    'modal-dismissed': 'إغلاق نافذة',
    'browser-context': 'جاهز',
    'queue-cleared': 'انتهى الطابور',
    returning: 'العودة للحجز',
    'seats-fast': 'مسك سريع',
    'seats-no-frame': 'لم يظهر الشارت',
    'ws-seat-released': 'مقعد أُطلق',
    'token-extended': 'تم تمديد التوكن',
    'token-extend-failed': 'فشل تمديد التوكن',
    'transfer-start': 'بدء النقل',
    'transfer-done': 'تم النقل',
    'transfer-failed': 'فشل النقل',
    'transfer-refill': 'إعادة تعبئة النقل',
    'hold-token-swap': 'تبديل توكن المسك',
    'seats-token': 'توكن المسك المستخدم',
    'iframe-token-patched': 'تحديث إطار الشارت بالتوكن',
    done: 'اكتمل الدفع',
    error: 'خطأ',
    failed: 'خطأ',
  };
  return map[stage] || stage;
}

function updateAccountRow(username, stage, data) {
  const acc = accounts.find(a => a.username === username);
  if (!acc) return;
  acc.stage = stage;
  if (data.seats && Array.isArray(data.seats)) acc.seats = data.seats;
  if (data.verifiedSeats && Array.isArray(data.verifiedSeats)) acc.seats = data.verifiedSeats;
  if (data.proxy) acc.proxy = data.proxy;
  if (data.proxyMode) acc.proxyMode = data.proxyMode;

  // Sniper indicator: active while monitoring/sniping, off when idle/error/stopped.
  if (stage === 'seats-monitoring' || stage === 'seats-sniping') {
    acc.sniperActive = true;
  } else if (stage === 'idle' || stage === 'error' || stage === 'stopped') {
    acc.sniperActive = false;
  }

  // Update queue position/timer for any queue-related status so it stays live.
  // Also keep the live hold countdown visible while the account is holding/paused.
  const isQueueStage = stage === 'queued' || stage === 'queue-waiting' || stage === 'queue-detected' || stage === 'queue-detected-post-login' || stage === 'queue-position' || stage === 'queue-timer';
  const isHoldTimerStage = stage === 'holding' || stage === 'cycle-holding' || stage === 'paused' || stage === 'payment-ready';
  if (isQueueStage || isHoldTimerStage) {
    if (typeof data.position === 'number') acc.queuePosition = data.position;
    if (typeof data.total === 'number') acc.queueTotal = data.total;
    if (typeof data.timer === 'number') {
      acc.queueTimer = data.timer;
      acc.queueTimerText = data.timerText || formatSeconds(data.timer);
    }
  } else {
    acc.queuePosition = null;
    acc.queueTotal = null;
    acc.queueTimer = null;
    acc.queueTimerText = null;
  }

  // Prefer lightweight DOM update over full re-render when only queue position/timer changed.
  if (stage === 'queue-position' || stage === 'queue-waiting' || stage === 'queue-timer') {
    updateAccountRowDom(acc);
  } else {
    renderAccounts();
  }
}

function formatSeconds(totalSeconds) {
  if (typeof totalSeconds !== 'number' || totalSeconds < 0) return '';
  const mm = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
  const ss = Math.floor(totalSeconds % 60).toString().padStart(2, '0');
  return `${mm}:${ss}`;
}

function updateAccountRowDom(acc) {
  const row = els.accountsList.querySelector(`.account-row[data-id="${acc.id}"]`);
  if (!row) {
    renderAccounts();
    return;
  }
  const stageEl = row.querySelector('.account-stage');
  if (stageEl) {
    stageEl.textContent = stageLabel(acc.stage, acc.queuePosition);
  }
  // Add/refresh queue badge (position + timer)
  let badge = row.querySelector('.queue-badge');
  if (acc.queuePosition != null || acc.queueTimer != null) {
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'queue-badge';
      const info = row.querySelector('.account-info');
      if (info) info.appendChild(badge);
    }
    const positionText = acc.queuePosition != null ? `طابور #${acc.queuePosition.toLocaleString('en-US')}${acc.queueTotal ? ` / ${acc.queueTotal.toLocaleString('en-US')}` : ''}` : '';
    const timerText = acc.queueTimerText ? `⏳ ${acc.queueTimerText}` : '';
    badge.textContent = [positionText, timerText].filter(Boolean).join(' · ');
  } else if (badge) {
    badge.remove();
  }
}

function updateHeldCount() {
  const total = accounts.reduce((sum, a) => sum + (a.seats?.length || 0), 0);
  els.heldCount.textContent = total;
}

els.selectAllAccountsBtn.addEventListener('click', () => {
  accounts.forEach(a => a.selected = true);
  renderAccounts();
});

els.clearAccountsBtn.addEventListener('click', () => {
  accounts.forEach(a => a.selected = false);
  renderAccounts();
});

els.removeAllAccountsBtn.addEventListener('click', () => {
  accounts = [];
  renderAccounts();
});

els.loadAccountsBtn.addEventListener('click', loadAccountsFromServer);
els.saveAccountsBtn.addEventListener('click', saveAccountsToServer);

function proxyToString(p) {
  let server = p.server || '';
  if (!server.includes('://')) server = `http://${server}`;
  if (p.username && p.password) {
    const end = server.indexOf('://');
    const protocol = server.slice(0, end + 3);
    const rest = server.slice(end + 3);
    return `${protocol}${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@${rest}`;
  }
  return server;
}

function parseProxiesTextarea() {
  const raw = els.proxyList.value.trim();
  if (!raw) return [];
  const proxies = [];
  for (const line of raw.split(/[\r\n;]+/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    try {
      if (trimmed.startsWith('{')) {
        const obj = JSON.parse(trimmed);
        if (obj.server) proxies.push({ server: obj.server, username: obj.username || '', password: obj.password || '' });
        continue;
      }
      // host:port:username:password
      const four = trimmed.match(/^([^:]+):(\d+):([^:]+):(.+)$/);
      if (four) {
        proxies.push({ server: `${four[1]}:${four[2]}`, username: four[3], password: four[4] });
        continue;
      }
      // protocol://user:pass@host:port
      const withAuth = trimmed.match(/^(https?|socks5|socks4):\/\/([^:]+):([^@]+)@(.+)$/);
      if (withAuth) {
        proxies.push({ server: `${withAuth[1]}://${withAuth[4]}`, username: decodeURIComponent(withAuth[2]), password: decodeURIComponent(withAuth[3]) });
        continue;
      }
      // user:pass@host:port
      const noSchemeAuth = trimmed.match(/^([^:]+):([^@]+)@(.+)$/);
      if (noSchemeAuth) {
        proxies.push({ server: noSchemeAuth[3], username: noSchemeAuth[1], password: noSchemeAuth[2] });
        continue;
      }
      // host:port or protocol://host:port
      proxies.push({ server: trimmed, username: '', password: '' });
    } catch {}
  }
  return proxies;
}

function parseProxiesFromText(text) {
  const proxies = [];
  for (const line of String(text || '').split(/[\r\n;]+/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    try {
      if (trimmed.startsWith('{')) {
        const obj = JSON.parse(trimmed);
        if (obj.proxy || obj.server) {
          proxies.push({ server: obj.server || obj.proxy, username: obj.username || '', password: obj.password || '' });
        }
        continue;
      }
      const p = parseProxyLineForFile(trimmed);
      if (p) proxies.push(p);
    } catch {}
  }
  return proxies;
}

function parseProxyLineForFile(line) {
  // host:port:username:password
  const four = line.match(/^([^:]+):(\d+):([^:]+):(.+)$/);
  if (four) return { server: `${four[1]}:${four[2]}`, username: four[3], password: four[4] };
  // protocol://user:pass@host:port
  const withAuth = line.match(/^(https?|socks5|socks4):\/\/([^:]+):([^@]+)@(.+)$/);
  if (withAuth) return { server: `${withAuth[1]}://${withAuth[4]}`, username: decodeURIComponent(withAuth[2]), password: decodeURIComponent(withAuth[3]) };
  // user:pass@host:port
  const noSchemeAuth = line.match(/^([^:]+):([^@]+)@(.+)$/);
  if (noSchemeAuth) return { server: noSchemeAuth[3], username: noSchemeAuth[1], password: noSchemeAuth[2] };
  // host:port or protocol://host:port
  return { server: line, username: '', password: '' };
}

function parseProxiesFromCsv(text) {
  const lines = String(text || '').split(/\r?\n/).filter(l => l.trim());
  if (lines.length === 0) return [];
  const header = lines[0].split(',').map(h => h.trim().toLowerCase());
  const proxyIdx = header.findIndex(h => h === 'proxy' || h === 'server' || h === 'host');
  const rows = proxyIdx >= 0 ? lines.slice(1) : lines;
  const colIdx = proxyIdx >= 0 ? proxyIdx : 0;
  const proxies = [];
  for (const row of rows) {
    const cols = row.split(',');
    const cell = cols[colIdx] || row;
    const trimmed = cell.trim();
    if (!trimmed) continue;
    const p = parseProxyLineForFile(trimmed);
    if (p) proxies.push(p);
  }
  return proxies;
}

function parseProxiesFromJson(text) {
  try {
    const data = JSON.parse(text);
    const arr = Array.isArray(data) ? data : (data.proxies || []);
    const proxies = [];
    for (const item of arr) {
      if (typeof item === 'string') {
        const p = parseProxyLineForFile(item.trim());
        if (p) proxies.push(p);
      } else if (item && typeof item === 'object') {
        const server = item.proxy || item.server || (item.host ? `${item.scheme || 'http'}://${item.host}:${item.port}` : '');
        if (server) proxies.push({ server, username: item.username || '', password: item.password || '' });
      }
    }
    return proxies;
  } catch {
    return [];
  }
}

async function handleProxyFileUpload(file) {
  if (!file) return;
  const text = await file.text();
  const name = file.name.toLowerCase();
  let proxies = [];
  if (name.endsWith('.json')) {
    proxies = parseProxiesFromJson(text);
  } else if (name.endsWith('.csv')) {
    proxies = parseProxiesFromCsv(text);
  } else {
    proxies = parseProxiesFromText(text);
  }
  if (proxies.length === 0) {
    log(`لم يتم العثور على بروكسيات فى الملف ${file.name}`, 'error');
    return;
  }
  const existing = parseProxiesTextarea();
  const merged = [...existing, ...proxies];
  syncTextareaFromProxies(merged);
  els.proxyFileName.textContent = `${file.name} (${proxies.length} بروكسي)`;
  log(`تم استيراد ${proxies.length} بروكسي من ${file.name}`);
}

function renderProxies() {
  const proxies = parseProxiesTextarea();
  els.proxiesList.innerHTML = '';
  if (proxies.length === 0) {
    els.proxiesList.innerHTML = '<p style="color:var(--muted)">لا يوجد بروكسيات</p>';
  } else {
    proxies.forEach((p, idx) => {
      const row = document.createElement('div');
      row.className = 'proxy-row';
      const display = p.username ? `${p.username}:${p.password}@${p.server}` : p.server;
      row.innerHTML = `
        <span class="proxy-text">${escapeHtml(display)}</span>
        <button class="btn-delete-proxy" data-idx="${idx}" title="حذف">×</button>
      `;
      row.querySelector('.btn-delete-proxy').addEventListener('click', () => deleteProxy(idx));
      els.proxiesList.appendChild(row);
    });
  }
  els.proxiesSummary.textContent = `${proxies.length} بروكسي محمل`;
}

function syncTextareaFromProxies(proxies) {
  els.proxyList.value = proxies.map(proxyToString).join('\n');
  renderProxies();
}

function deleteProxy(idx) {
  const proxies = parseProxiesTextarea();
  proxies.splice(idx, 1);
  syncTextareaFromProxies(proxies);
  log(`تم حذف بروكسي`);
}

function addProxyFromInputs() {
  const host = els.proxyHost.value.trim();
  const port = els.proxyPort.value.trim();
  const user = els.proxyUser.value.trim();
  const pass = els.proxyPass.value.trim();
  if (!host || !port) return alert('أدخل Host و Port');
  const server = `${host}:${port}`;
  const proxies = parseProxiesTextarea();
  proxies.push({ server, username: user, password: pass });
  syncTextareaFromProxies(proxies);
  els.proxyHost.value = '';
  els.proxyPort.value = '';
  els.proxyUser.value = '';
  els.proxyPass.value = '';
  log('تم إضافة بروكسي');
}

function clearAllProxies() {
  if (!confirm('هل تريد مسح كل البروكسيات من القائمة؟ (لن يتم حذفها من الخادم إلا بعد الضغط على حفظ)')) return;
  syncTextareaFromProxies([]);
}

async function loadProxiesFromServer() {
  try {
    const res = await fetch('/api/proxies');
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'Server error');
    const proxies = (json.proxies || []).map(p => ({
      server: p.server,
      username: p.username || '',
      password: p.password || '',
    }));
    syncTextareaFromProxies(proxies);
    log(`تم تحميل ${json.count} بروكسي من الخادم`);
  } catch (err) {
    log(`فشل تحميل البروكسيات: ${err.message}`, 'error');
  }
}

async function saveProxiesToServer() {
  try {
    const proxies = parseProxiesTextarea();
    const res = await fetch('/api/proxies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxies }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'Server error');
    const saved = (json.proxies || []).map(p => ({
      server: p.server,
      username: p.username || '',
      password: p.password || '',
    }));
    syncTextareaFromProxies(saved);
    log(`تم حفظ ${json.count} بروكسي على الخادم`);
  } catch (err) {
    log(`فشل حفظ البروكسيات: ${err.message}`, 'error');
  }
}

els.loadProxiesBtn.addEventListener('click', loadProxiesFromServer);
els.saveProxiesBtn.addEventListener('click', saveProxiesToServer);
els.addProxyBtn.addEventListener('click', addProxyFromInputs);
els.clearProxiesBtn.addEventListener('click', clearAllProxies);
els.proxyList.addEventListener('input', renderProxies);
els.proxyFileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) handleProxyFileUpload(file);
  e.target.value = '';
});

async function loadProxiesFromDataJson() {
  try {
    const res = await fetch('/api/proxies/data-json');
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'Server error');
    const existing = parseProxiesTextarea();
    const merged = [...existing, ...json.proxies];
    syncTextareaFromProxies(merged);
    log(`تم استيراد ${json.count} بروكسي من data.json`);
  } catch (err) {
    log(`فشل استيراد data.json: ${err.message}`, 'error');
  }
}

async function filterWorkingProxies() {
  const proxies = parseProxiesTextarea();
  if (proxies.length === 0) return alert('لا يوجد بروكسيات للاختبار');
  els.filterWorkingBtn.disabled = true;
  els.filterWorkingBtn.textContent = '⏳ جاري الاختبار والتصفية...';
  log(`جاري اختبار ${proxies.length} بروكسي والاحتفاظ بالشغال فقط...`);
  try {
    const res = await fetch('/api/proxies/test-and-filter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxies }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'Server error');
    syncTextareaFromProxies(json.proxies || []);
    log(`تم الاحتفاظ بـ ${json.kept}/${json.tested} بروكسي شغال`);
  } catch (err) {
    log(`فشل تصفية البروكسيات: ${err.message}`, 'error');
  } finally {
    els.filterWorkingBtn.disabled = false;
    els.filterWorkingBtn.textContent = '✅ اختبار + سيب الشغال بس';
  }
}

els.loadDataJsonBtn.addEventListener('click', loadProxiesFromDataJson);
els.filterWorkingBtn.addEventListener('click', filterWorkingProxies);

async function loadProxyMode() {
  try {
    const res = await fetch('/api/proxy-mode');
    const json = await res.json();
    if (json.success) {
      els.proxyModeSelect.value = json.mode;
      updateProxyModeStatus(json.mode);
    }
  } catch (err) {
    log(`فشل تحميل وضع البروكسي: ${err.message}`, 'error');
  }
}

function updateProxyModeStatus(mode) {
  const labels = { off: 'بدون بروكسي', test: 'اختبار + fallback', required: 'لازم بروكسي شغال' };
  els.proxyModeStatus.textContent = `الوضع الحالي: ${labels[mode] || mode}`;
}

els.proxyModeSelect.addEventListener('change', async () => {
  const mode = els.proxyModeSelect.value;
  try {
    const res = await fetch('/api/proxy-mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'Server error');
    updateProxyModeStatus(json.mode);
    log(`تم تغيير وضع البروكسي إلى ${json.mode}`);
  } catch (err) {
    log(`فشل تغيير وضع البروكسي: ${err.message}`, 'error');
    await loadProxyMode();
  }
});

els.testAllProxiesBtn.addEventListener('click', async () => {
  const proxies = parseProxiesTextarea();
  if (proxies.length === 0) return alert('لا يوجد بروكسيات للاختبار');
  els.testAllProxiesBtn.disabled = true;
  els.testAllProxiesBtn.textContent = '⏳ جاري الاختبار...';
  log(`جاري اختبار ${proxies.length} بروكسي...`);
  try {
    const res = await fetch('/api/proxies/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxies }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'Server error');
    const ok = json.results.filter(r => r.ok);
    const failed = json.results.filter(r => !r.ok);
    log(`نتيجة الاختبار: ${ok.length} شغال / ${failed.length} فاشل`);
    if (failed.length > 0) {
      log(`فاشل: ${failed.slice(0, 5).map(r => `${r.server} (${r.reason})`).join(' | ')}${failed.length > 5 ? '...' : ''}`, 'error');
    }
  } catch (err) {
    log(`فشل اختبار البروكسيات: ${err.message}`, 'error');
  } finally {
    els.testAllProxiesBtn.disabled = false;
    els.testAllProxiesBtn.textContent = '🧪 اختبار كل البروكسيات';
  }
});

function deleteAccount(username) {
  accounts = accounts.filter(a => a.username !== username);
  renderAccounts();
  log(`تم حذف الحساب: ${username}`);
}

function updateConcurrencyHint(val) {
  const v = parseInt(val, 10) || 0;
  if (v === 0) {
    els.concurrencyHint.textContent = 'سيتم حساب العدد المثالي تلقائياً حسب الرام والبروسيسور';
  } else if (v === 1) {
    els.concurrencyHint.textContent = 'سيفتح حساب واحد فقط في نفس الوقت (أنصح به لتجنب الأخطاء)';
  } else {
    els.concurrencyHint.textContent = `سيفتح ${v} متصفح كحد أقصى في نفس الوقت`;
  }
}

async function loadEstimatedConcurrency() {
  try {
    const res = await fetch('/api/estimate-concurrency');
    const json = await res.json();
    if (json.success) {
      // Default to a moderate concurrent count for speed; user can still override.
      const estimated = Math.max(1, Math.min(json.concurrency || 1, 4));
      els.maxConcurrency.value = estimated;
      updateConcurrencyHint(estimated);
    }
  } catch (err) {
    console.error('Failed to load concurrency estimate', err);
  }
}

els.maxConcurrency.addEventListener('input', () => updateConcurrencyHint(els.maxConcurrency.value));

// Start / Stop
els.startBookingBtn.addEventListener('click', async () => {
  try {
    const url = els.eventUrl.value.trim();
    const targetSections = getSelectedSections();
    const maxConcurrency = parseInt(els.maxConcurrency.value, 10) || 0;
    const mode = 'per-account';
    const selected = accounts.filter(a => a.selected).map(a => ({ ...a, ticketCount: a.ticketCount || 30 }));
    const speedSettings = getSpeedSettings();
    console.log('[startBooking] click', { url, targetSections, selectedCount: selected.length, running, disabled: els.startBookingBtn.disabled });
    if (!url) return alert('أدخل رابط الفعالية');
    if (targetSections.length === 0) return alert('اختر قسماً واحداً على الأقل');
    if (selected.length === 0) return alert('اختر حساب واحد على الأقل');

    // Detect shared provided hold tokens between selected accounts.
    const holdTokens = selected.filter(a => a.type === 'holdToken' && a.holdToken).map(a => a.holdToken);
    const uniqueTokens = new Set(holdTokens);
    if (holdTokens.length > uniqueTokens.size) {
      const proceed = confirm('⚠️ تحذير: حسابات Hold Token مختارة تشارك نفس التوكن. ده هيخلى واحد بس يمسك والباقى يتفك. هل تريد المتابعة؟');
      if (!proceed) return;
    }

    setLoading(true);
    const res = await fetch('/api/start-booking', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, targetSections, accounts: selected, maxConcurrency, mode, speedSettings, selectedTeam }),
    });
    let json;
    try {
      json = await res.json();
    } catch (parseErr) {
      const text = await res.text().catch(() => '');
      throw new Error(`Server returned invalid JSON. Status: ${res.status}. Body: ${text.substring(0, 200)}`);
    }
    if (!json.success) throw new Error(json.error || 'Unknown server error');
    const s = speedSettings;
    const ticketsText = json.minTickets === json.maxTickets ? json.minTickets : `${json.minTickets}-${json.maxTickets}`;
    log(`بدأ الحجز لـ ${selected.length} حساب. الأقسام: ${targetSections.join(', ')}. تذاكر/حساب: ${ticketsText}. التوازي: ${json.maxConcurrency}. FastMode=ON, Sniper=${s.sniperEnabled} (${s.sniperIntervalMs}ms).`);
  } catch (err) {
    console.error('[startBooking] error', err);
    log(`فشل بدء الحجز: ${err.message}`, 'error');
    setLoading(false);
  }
});

els.stopBookingBtn.addEventListener('click', async () => {
  try {
    await fetch('/api/stop-booking', { method: 'POST' });
    log('تم إرسال إشارة إيقاف الكل');
  } catch (err) {
    log(`فشل إرسال إيقاف الكل: ${err.message}`, 'error');
  }
  // Force-reset the UI loading state so the start button becomes clickable again
  // even if socket events were missed.
  setTimeout(() => {
    running = false;
    setLoading(false);
    log('تم إعادة تعيين حالة الزر؛ يمكنك بدء حجز جديد');
  }, 1500);
});

els.downloadLogsBtn.addEventListener('click', async () => {
  try {
    const res = await fetch('/api/logs');
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const blob = new Blob([json.logs], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kimiko-logs-${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    log('تم تحميل السجل');
  } catch (err) {
    log(`فشل تحميل السجل: ${err.message}`, 'error');
  }
});

els.clearLogsBtn.addEventListener('click', () => {
  els.logs.innerHTML = '';
});

async function proceedAccount(username) {
  try {
    const res = await fetch('/api/proceed-payment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    log(`تم إرسال أمر الدفع لـ ${username}`);
  } catch (err) {
    log(`فشل الدفع لـ ${username}: ${err.message}`, 'error');
  }
}

async function stopAccount(username) {
  const acc = accounts.find(a => a.username === username);
  if (acc) {
    acc.stage = 'paused';
    acc.sniperActive = false;
    renderAccounts();
  }
  try {
    const res = await fetch('/api/stop-account', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    log(`تم إرسال إيقاف لـ ${username}`);
  } catch (err) {
    log(`فشل الإيقاف لـ ${username}: ${err.message}`, 'error');
    if (acc) {
      acc.stage = 'error';
      renderAccounts();
    }
  }
}

async function releaseAccount(username) {
  try {
    const res = await fetch('/api/release-hold', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const acc = accounts.find(a => a.username === username);
    if (acc) {
      acc.seats = [];
      acc.stage = 'idle';
    }
    renderAccounts();
    log(`تم فك المسك لـ ${username}`);
  } catch (err) {
    log(`فشل فك المسك لـ ${username}: ${err.message}`, 'error');
  }
}

async function releaseSeat(username, seat) {
  try {
    const res = await fetch('/api/release-seat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, seat }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    const acc = accounts.find(a => a.username === username);
    if (acc && json.seats) {
      acc.seats = json.seats;
    }
    renderAccounts();
    log(`تم فك مسك المقعد ${seat} لـ ${username}`);
  } catch (err) {
    log(`فشل فك مسك المقعد ${seat} لـ ${username}: ${err.message}`, 'error');
  }
}

async function extendToken(username) {
  try {
    const res = await fetch('/api/extend-token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    log(`تم تمديد التوكن لـ ${username}؛ مقاعد مؤكدة: ${(json.verifiedSeats || []).length}`);
  } catch (err) {
    log(`فشل تمديد التوكن لـ ${username}: ${err.message}`, 'error');
  }
}

// Pair Cycling UI
let pairCyclesRefreshTimer = null;

function renderPairCyclesStatus(cycles) {
  if (!els.pairCyclesStatus) return;
  if (!cycles || cycles.length === 0) {
    els.pairCyclesStatus.classList.add('hidden');
    els.pairCyclesStatus.innerHTML = '';
    return;
  }

  els.pairCyclesStatus.classList.remove('hidden');
  const html = cycles.map(c => {
    const elapsedMin = Math.floor(c.elapsedMs / 60000);
    const elapsedSec = Math.floor((c.elapsedMs % 60000) / 1000);
    const timerText = typeof c.lastTimerSeconds === 'number' && c.lastTimerSeconds >= 0
      ? `${Math.floor(c.lastTimerSeconds / 60).toString().padStart(2, '0')}:${(c.lastTimerSeconds % 60).toString().padStart(2, '0')}`
      : '--:--';
    return `
      <div class="pair-cycle-card">
        <div class="pair-cycle-header">
          <strong>${escapeHtml(c.pairId)}</strong>
          <span class="pair-cycle-status status-${escapeHtml(c.status).toLowerCase()}">${escapeHtml(c.status)}</span>
        </div>
        <div class="pair-cycle-body">
          <div>موجة ${c.currentWave}/${c.maxWaves}</div>
          <div>الحالي: ${escapeHtml(c.activeUser)}</div>
          <div>مقاعد ممسوكة: ${c.seatCount}</div>
          <div>الوقت المتبقي للمسك: ${timerText}</div>
          <div>مرت منذ البدء: ${elapsedMin}m ${elapsedSec}s</div>
        </div>
      </div>
    `;
  }).join('');
  els.pairCyclesStatus.innerHTML = html;
}

async function refreshPairCyclesStatus() {
  try {
    const res = await fetch('/api/pair-cycles');
    const json = await res.json();
    if (json.success) {
      renderPairCyclesStatus(json.cycles);
      if (json.cycles && json.cycles.length > 0 && !pairCyclesRefreshTimer) {
        pairCyclesRefreshTimer = setInterval(refreshPairCyclesStatus, 5000);
      } else if ((!json.cycles || json.cycles.length === 0) && pairCyclesRefreshTimer) {
        clearInterval(pairCyclesRefreshTimer);
        pairCyclesRefreshTimer = null;
      }
    }
  } catch (err) {
    console.error('Failed to refresh pair cycles', err);
  }
}

if (els.startPairCyclingBtn) {
  els.startPairCyclingBtn.addEventListener('click', async () => {
    const url = els.eventUrl.value.trim();
    const targetSections = getSelectedSections();
    const selected = accounts.filter(a => a.selected).map(a => ({ ...a, ticketCount: a.ticketCount || 30 }));
    if (!url) return alert('أدخل رابط الفعالية');
    if (targetSections.length === 0) return alert('اختر قسماً واحداً على الأقل');
    if (selected.length < 2) return alert('اختر حسابين على الأقل للتناوب');

    setLoading(true);
    try {
      const res = await fetch('/api/start-pair-cycling', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, targetSections, accounts: selected, selectedTeam }),
      });
      const json = await res.json();
      if (!json.success) throw new Error(json.error || 'Unknown server error');
      log(`بدأ Pair Cycling لـ ${selected.length} حساب. الأزواج: ${json.pairCount}. Standby: ${json.standby || 'لا يوجد'}.`);
      refreshPairCyclesStatus();
    } catch (err) {
      log(`فشل بدء Pair Cycling: ${err.message}`, 'error');
      setLoading(false);
    }
  });
}

if (els.stopPairCyclingBtn) {
  els.stopPairCyclingBtn.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/stop-pair-cycling', { method: 'POST' });
      const json = await res.json();
      if (!json.success) throw new Error(json.error);
      log('تم إيقاف Pair Cycling وتحرير المقاعد');
      renderPairCyclesStatus([]);
      if (pairCyclesRefreshTimer) {
        clearInterval(pairCyclesRefreshTimer);
        pairCyclesRefreshTimer = null;
      }
    } catch (err) {
      log(`فشل إيقاف Pair Cycling: ${err.message}`, 'error');
    }
  });
}

// 2captcha key management
async function loadCaptchaKeys() {
  try {
    const res = await fetch('/api/captcha-keys');
    const json = await res.json();
    if (json.success) {
      captchaKeys = json.keys || [];
      renderCaptchaKeys();
    }
  } catch (err) {
    log(`فشل تحميل مفاتيح 2captcha: ${err.message}`, 'error');
  }
}

function renderCaptchaKeys() {
  if (!els.captchaKeysList) return;
  els.captchaKeysList.innerHTML = '';
  if (captchaKeys.length === 0) {
    els.captchaKeysList.innerHTML = '<p style="color:var(--muted)">لا توجد مفاتيح. المفتاح الافتراضي سيتم إضافته تلقائياً.</p>';
    return;
  }
  captchaKeys.forEach(key => {
    const item = document.createElement('div');
    item.className = 'captcha-key-item';
    const masked = key.key.length > 8 ? key.key.slice(0, 4) + '...' + key.key.slice(-4) : key.key;
    item.innerHTML = `
      <div class="captcha-key-info">
        <strong>${escapeHtml(key.label || 'مفتاح')}</strong>
        <span class="captcha-key-masked">${escapeHtml(masked)}</span>
        <span class="captcha-key-status ${key.enabled ? 'enabled' : 'disabled'}">${key.enabled ? 'مفعّل' : 'معطّل'}</span>
      </div>
      <div class="captcha-key-actions">
        <button class="btn-toggle-captcha" data-id="${escapeHtml(key.id)}" title="تفعيل/تعطيل">${key.enabled ? '⏸️' : '▶️'}</button>
        <button class="btn-delete-captcha" data-id="${escapeHtml(key.id)}" title="حذف">🗑️</button>
      </div>
    `;
    item.querySelector('.btn-toggle-captcha').addEventListener('click', () => toggleCaptchaKey(key.id));
    item.querySelector('.btn-delete-captcha').addEventListener('click', () => deleteCaptchaKey(key.id));
    els.captchaKeysList.appendChild(item);
  });
}

async function addCaptchaKey() {
  const label = els.captchaKeyLabel?.value.trim() || '';
  const key = els.captchaKeyInput?.value.trim() || '';
  if (!key || key.length < 10) return alert('أدخل API Key صحيح من 2captcha.com');
  try {
    const res = await fetch('/api/captcha-keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, key }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    captchaKeys = json.keys || [];
    renderCaptchaKeys();
    if (els.captchaKeyInput) els.captchaKeyInput.value = '';
    if (els.captchaKeyLabel) els.captchaKeyLabel.value = '';
    log('تم إضافة مفتاح 2captcha');
  } catch (err) {
    log(`فشل إضافة مفتاح 2captcha: ${err.message}`, 'error');
  }
}

async function toggleCaptchaKey(id) {
  const key = captchaKeys.find(k => k.id === id);
  if (!key) return;
  try {
    const res = await fetch(`/api/captcha-keys/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !key.enabled }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    captchaKeys = json.keys || [];
    renderCaptchaKeys();
  } catch (err) {
    log(`فشل تبديل حالة المفتاح: ${err.message}`, 'error');
  }
}

async function deleteCaptchaKey(id) {
  if (!confirm('هل أنت متأكد من حذف هذا المفتاح؟')) return;
  try {
    const res = await fetch(`/api/captcha-keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
    captchaKeys = json.keys || [];
    renderCaptchaKeys();
    log('تم حذف مفتاح 2captcha');
  } catch (err) {
    log(`فشل حذف المفتاح: ${err.message}`, 'error');
  }
}

if (els.addCaptchaKeyBtn) {
  els.addCaptchaKeyBtn.addEventListener('click', addCaptchaKey);
}

// Init
running = false;
setLoading(false);
renderAccounts();
loadEstimatedConcurrency();
loadAccountsFromServer();
loadProxiesFromServer();
loadProxyMode();
loadCaptchaKeys();
log('جاهز. أدخل رابط الفعالية، اجلب الأقسام، اختر الأقسام والحسابات، ثم اضغط بدء الحجز.');

// Safety net: if the loading state gets stuck (e.g. missed socket events),
// reset it after 90 seconds so the user can start a new run.
setInterval(() => {
  if (running && Date.now() - (window.__lastLoadingStart || 0) > 90_000) {
    console.warn('[ui] stuck loading state detected; resetting');
    running = false;
    setLoading(false);
    log('تم إعادة تعيين حالة الزر تلقائياً بعد التعليق');
  }
}, 10_000);

// Tab switching
function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  const targetTab = document.getElementById('tab-' + tabId);
  const targetBtn = document.querySelector('.tab-btn[data-tab="' + tabId + '"]');
  if (targetTab) targetTab.classList.add('active');
  if (targetBtn) targetBtn.classList.add('active');
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

// Add account method tabs
document.querySelectorAll('.add-account-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    const method = btn.dataset.method;
    document.querySelectorAll('.add-account-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    if (els.credentialsPanel) els.credentialsPanel.classList.toggle('active', method === 'credentials');
    if (els.cookiesPanel) els.cookiesPanel.classList.toggle('active', method === 'cookies');
  });
});

// Show Dashboard by default
switchTab('dashboard');

