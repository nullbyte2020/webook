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
  setAllProxyBtn: document.getElementById('setAllProxyBtn'),
  setAllDirectBtn: document.getElementById('setAllDirectBtn'),
  bulkTicketCount: document.getElementById('bulkTicketCount'),
  applyBulkTicketCountBtn: document.getElementById('applyBulkTicketCountBtn'),
  maxConcurrency: document.getElementById('maxConcurrency'),
  concurrencyHint: document.getElementById('concurrencyHint'),
  speedModeSelect: document.getElementById('speedModeSelect'),
  speedHint: document.getElementById('speedHint'),
  startBookingBtn: document.getElementById('startBookingBtn'),
  stopBookingBtn: document.getElementById('stopBookingBtn'),
  stopBookingHardBtn: document.getElementById('stopBookingHardBtn'),
  downloadLogsBtn: document.getElementById('downloadLogsBtn'),
  autoDetectMaxTickets: document.getElementById('autoDetectMaxTickets'),
  detectedMaxTicketsHint: document.getElementById('detectedMaxTicketsHint'),
  detectedMaxTicketsValue: document.getElementById('detectedMaxTicketsValue'),
  clearLogsBtn: document.getElementById('clearLogsBtn'),
  transferFromList: document.getElementById('transferFromList'),
  transferToList: document.getElementById('transferToList'),
  selectAllSourcesBtn: document.getElementById('selectAllSourcesBtn'),
  deselectAllSourcesBtn: document.getElementById('deselectAllSourcesBtn'),
  selectAllDestsBtn: document.getElementById('selectAllDestsBtn'),
  deselectAllDestsBtn: document.getElementById('deselectAllDestsBtn'),
  transferSeatsBtn: document.getElementById('transferSeatsBtn'),
  transferSeatsHeadlessBtn: document.getElementById('transferSeatsHeadlessBtn'),
  setAllTransferProxyBtn: document.getElementById('setAllTransferProxyBtn'),
  setAllTransferDirectBtn: document.getElementById('setAllTransferDirectBtn'),
  bulkTransferTicketCount: document.getElementById('bulkTransferTicketCount'),
  applyBulkTransferTicketCountBtn: document.getElementById('applyBulkTransferTicketCountBtn'),
  cancelTransferBtn: document.getElementById('cancelTransferBtn'),
  transferProgressWrapper: document.getElementById('transferProgressWrapper'),
  transferProgressText: document.getElementById('transferProgressText'),
  transferProgressCount: document.getElementById('transferProgressCount'),
  transferProgressFill: document.getElementById('transferProgressFill'),
  transferDistributionPreview: document.getElementById('transferDistributionPreview'),
  transferDistributionList: document.getElementById('transferDistributionList'),
  transferDestinationStatusList: document.getElementById('transferDestinationStatusList'),
  cachedSessionsCount: document.getElementById('cachedSessionsCount'),
  transferEngineStatus: document.getElementById('transferEngineStatus'),
  harvestSelectedSessionsBtn: document.getElementById('harvestSelectedSessionsBtn'),
  showCachedSessionsBtn: document.getElementById('showCachedSessionsBtn'),
  cachedSessionsList: document.getElementById('cachedSessionsList'),
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
let detectedEventType = 'GENERAL';
let detectedMaxTickets = 30;
let accounts = [];
let running = false;
let captchaKeys = [];

// Transfer progress tracking.
let transferProgress = {
  active: false,
  totalDestinations: 0,
  preparedDestinations: 0,
  totalSeats: 0,
  transferredSeats: 0,
  abortController: null,
};

// Per-destination transfer status tracking.
let transferDestinationStatuses = new Map(); // username -> { state, seats, transferred, missing, error }

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

// Throttle / debounce helpers to keep the UI responsive during heavy bot activity.
function throttle(fn, limitMs) {
  let lastCall = 0;
  let pending = false;
  return function (...args) {
    const now = Date.now();
    if (now - lastCall >= limitMs) {
      lastCall = now;
      fn.apply(this, args);
    } else if (!pending) {
      pending = true;
      setTimeout(() => {
        pending = false;
        lastCall = Date.now();
        fn.apply(this, args);
      }, limitMs - (now - lastCall));
    }
  };
}

function debounce(fn, waitMs) {
  let timer = null;
  return function (...args) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      fn.apply(this, args);
    }, waitMs);
  };
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
  if (data.account) {
    updateAccountRow(data.account, data.stage, data);
    scheduleUpdateTransferSelects();
  }
  if (['idle', 'error', 'payment-ready'].includes(data.stage) && !data.account) {
    setLoading(false);
  }
  // NOTE: hold-token extension is intentionally driven by the backend based on
  // the booking-page countdown timer. Do NOT trigger extension here on queue
  // pass or seat-selection events, because the token may not have any held
  // seats yet and premature renewal wastes time / may invalidate the token.
});

socket.on('account-update', data => {
  updateAccountRow(data.account, data.stage, data);
  scheduleUpdateTransferSelects();
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

socket.on('session-harvested', data => {
  log(`💾 تم حفظ جلسة ${data.username} تلقائياً (${data.cookiesCount || 0} كوكيز)`);
  refreshCachedSessionsCount();
  if (els.cachedSessionsList && !els.cachedSessionsList.classList.contains('hidden')) {
    showCachedSessions();
  }
});

// Real-time chart synchronization via backend events.
socket.on('seat-held', data => {
  const acc = accounts.find(a => a.username === data.account);
  if (acc) {
    acc.seats = Array.from(new Set([...(acc.seats || []), ...(data.seats || [])]));
    updateHeldCount();
    throttledRenderAccounts();
  }
  log(`${data.account}: مسك ${(data.seats || []).join(', ')}`);
});

socket.on('seat-released', data => {
  const acc = accounts.find(a => a.username === data.account);
  if (acc) {
    const released = new Set((data.seats || []).map(s => String(s).trim().toUpperCase()));
    acc.seats = (acc.seats || []).filter(s => !released.has(String(s).trim().toUpperCase()));
    updateHeldCount();
    throttledRenderAccounts();
  }
  log(`${data.account}: فك ${(data.seats || []).join(', ')}`);
});

socket.on('transfer-done', data => {
  log(`✅ تم نقل ${data.totalTransferred || 0} مقعد`);
  updateHeldCount();
  throttledRenderAccounts();
  scheduleUpdateTransferSelects();
});

socket.on('transfer-plan-built', data => {
  updateTransferProgress('plan-built', {
    totalDestinations: data.destinations?.length || 0,
    totalSeats: (data.destinations || []).reduce((s, d) => s + (d.count || 0), 0),
  });
  initTransferDestinationStatuses(data.destinations || []);
});

socket.on('transfer-distribution-preview', data => {
  renderTransferDistributionPreview(data.destinations || []);
  log(`📦 توزيع المقاعد: ${data.totalSeats || 0} مقعد على ${(data.destinations || []).length} وجهة`);
  // Refresh seats for each destination from the distribution preview.
  for (const d of data.destinations || []) {
    updateTransferDestinationStatus(d.username, 'planned', { seats: d.seats || d.assignedSeats || [] });
  }
});

socket.on('destination-preparing', data => {
  // Keep the running totals; the plan-built event already set them.
  if (data.totalDestinations && transferProgress.totalDestinations === 0) {
    transferProgress.totalDestinations = data.totalDestinations;
  }
  updateTransferProgress('destination-preparing', {
    totalDestinations: data.totalDestinations || transferProgress.totalDestinations,
    currentIndex: data.currentIndex || 1,
  });
  if (data.account) updateTransferDestinationStatus(data.account, 'preparing');
});

socket.on('destination-ready', data => {
  updateTransferProgress('destination-ready');
  if (data.account) updateTransferDestinationStatus(data.account, 'ready');
});

socket.on('destination-prepare-failed', data => {
  if (data.account) updateTransferDestinationStatus(data.account, 'failed', { error: data.error || 'فشل التحضير' });
});

socket.on('transfer-batch-start', data => {
  if (data.to) updateTransferDestinationStatus(data.to, 'transferring');
});

socket.on('transfer-batch-complete', data => {
  updateTransferProgress('batch-complete', { transferred: data.held?.length || 0 });
  if (data.to) {
    updateTransferDestinationStatus(data.to, 'transferring', {
      transferred: (data.held || []).length,
      missing: (data.missing || []).length,
    });
  }
});

socket.on('transfer-done', data => {
  updateTransferProgress('done', { totalTransferred: data.totalTransferred });
  log(`✅ تم نقل ${data.totalTransferred || 0} مقعد`);
  updateHeldCount();
  throttledRenderAccounts();
  scheduleUpdateTransferSelects();
  // Mark all still-active destinations as complete/failed based on whether seats arrived.
  for (const [username, status] of transferDestinationStatuses.entries()) {
    if (status.state === 'transferring' || status.state === 'ready') {
      updateTransferDestinationStatus(username, status.missing > 0 ? 'failed' : 'complete');
    }
  }
});

socket.on('transfer-failed', data => {
  updateTransferProgress('failed');
  log(`❌ فشل النقل: ${data.message || data.error || 'خطأ غير معروف'}`, 'error');
  for (const username of transferDestinationStatuses.keys()) {
    updateTransferDestinationStatus(username, 'failed', { error: data.error || data.message || 'فشل النقل' });
  }
  resetTransferProgress();
});

// Listen to seats.io postMessage events if the chart iframe is present in this page.
class SeatChartSync {
  constructor() {
    this.heldSeats = new Map();
    this.bookedSeats = new Set();
    this.listenForChartEvents();
  }

  listenForChartEvents() {
    window.addEventListener('message', (event) => {
      const origin = event.origin || '';
      if (origin.includes('seats.io') || origin.includes('seatcloud.com')) {
        this.handleSeatEvent(event.data);
      }
    });
  }

  handleSeatEvent(data) {
    if (!data || typeof data !== 'object') return;
    if (data.type === 'objectsSelected' || data.type === 'hold') {
      this.updateUI(data.account || 'chart', data.objects || [], 'held');
    } else if (data.type === 'objectsDeselected' || data.type === 'release') {
      this.updateUI(data.account || 'chart', data.objects || [], 'released');
    } else if (data.type === 'bookingCompleted') {
      for (const seat of data.objects || []) this.bookedSeats.add(seat);
      updateHeldCount();
    }
  }

  updateUI(account, seatIds, action) {
    seatIds = Array.isArray(seatIds) ? seatIds : [];
    if (action === 'held') {
      this.heldSeats.set(account, seatIds);
    } else if (action === 'released') {
      const current = this.heldSeats.get(account) || [];
      const removed = new Set(seatIds.map(s => String(s).trim().toUpperCase()));
      this.heldSeats.set(account, current.filter(s => !removed.has(String(s).trim().toUpperCase())));
    }
    // Sync the account row in the UI if this event belongs to a loaded account.
    const acc = accounts.find(a => a.username === account);
    if (acc) {
      acc.seats = seatIds;
      updateHeldCount();
      throttledRenderAccounts();
    } else {
      updateHeldCount();
    }
    log(`شارت: ${account} ${action === 'held' ? 'مسك' : 'فك'} ${seatIds.join(', ')}`);
  }
}

const seatChartSync = new SeatChartSync();

function setLoading(loading) {
  running = loading;
  if (loading) window.__lastLoadingStart = Date.now();
  els.fetchBtn.disabled = loading;
  els.refreshAvailabilityBtn.disabled = loading;
  els.startBookingBtn.disabled = loading || getSelectedSections().length === 0 || !accounts.some(a => a.selected);
  els.accountsFile.disabled = loading;
  if (els.transferSeatsBtn) els.transferSeatsBtn.disabled = loading;
  if (els.startPairCyclingBtn) els.startPairCyclingBtn.disabled = loading;
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
function detectEventType(url) {
  if (url.includes('/music-events/')) return 'MUSIC';
  if (url.includes('/sports-event/')) return 'SPORTS';
  if (url.includes('/theater/')) return 'THEATER';
  return 'GENERAL';
}

function applyDetectedMaxTickets(maxTickets) {
  detectedMaxTickets = Math.max(1, Math.min(parseInt(maxTickets, 10) || 30, 30));
  if (els.detectedMaxTicketsValue) els.detectedMaxTicketsValue.textContent = detectedMaxTickets;
  if (els.detectedMaxTicketsHint) els.detectedMaxTicketsHint.classList.remove('hidden');

  const autoDetect = els.autoDetectMaxTickets && els.autoDetectMaxTickets.checked;
  if (autoDetect) {
    // Update all accounts' ticket counts to the detected limit.
    accounts.forEach(a => { a.ticketCount = detectedMaxTickets; });
    eventMaxPerOrder = detectedMaxTickets;
    log(`اكتشاف تلقائي: نوع الفعالية ${detectedEventType}، الحد الأقصى للتذاكر ${detectedMaxTickets}. تم تحديث كل الحسابات.`);
  } else {
    eventMaxPerOrder = detectedMaxTickets;
    log(`اكتشاف تلقائي: نوع الفعالية ${detectedEventType}، الحد الأقصى للتذاكر ${detectedMaxTickets} (لم يُحدّث الحسابات لأن الاكتشاف التلقائي معطل).`);
  }
  renderAccounts();
}

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
    detectedEventType = detectEventType(url);
    eventMaxPerOrder = 30;
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

    // Auto-detect max tickets per user from event detail.
    if (typeof json.maxTicketsPerUser === 'number') {
      applyDetectedMaxTickets(json.maxTicketsPerUser);
    } else {
      applyDetectedMaxTickets(30);
    }

    log(`تم تحميل ${sectionsData.length} أقسام لـ "${eventTitle}". نوع الفعالية: ${detectedEventType}.`);
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
  if (!queueStatus) {
    els.eventQueueBadge.className = 'event-badge hidden';
    els.eventQueueBadge.textContent = '';
    return;
  }
  const queued = !!queueStatus.queued;
  els.eventQueueBadge.className = `event-badge ${queued ? 'queued' : 'open'}`;
  els.eventQueueBadge.textContent = queued ? 'في الطابور' : 'حجز مباشر';
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
  scheduleUpdateTransferSelects();
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
  scheduleUpdateTransferSelects();
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
    const proxyOptions = `<select data-action="proxy-mode">
          <option value="direct" ${acc.useProxy ? '' : 'selected'}>⛔ مباشر</option>
          <option value="proxy" ${acc.useProxy ? 'selected' : ''}>🌐 بروكسي</option>
        </select>`;
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
          ${proxyOptions}
        </label>
        <label class="ticket-count-label" title="عدد التذاكر المطلوب لهذا الحساب (حد أقصى 30)">
          🎫
          <input type="number" class="ticket-count-input" data-action="ticket-count" value="${acc.ticketCount || 30}" min="1" max="30" />
        </label>
        <button class="btn-proceed" data-action="proceed">دفع</button>
        <button class="btn-release" data-action="release">فك الكل</button>
        <button class="btn-stop" data-action="stop">إيقاف</button>
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

// Throttle full account-list re-renders so rapid socket updates do not freeze the UI.
const throttledRenderAccounts = throttle(renderAccounts, 300);

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
  const prevSeatCount = acc.seats?.length || 0;
  acc.stage = stage;
  if (data.seats && Array.isArray(data.seats)) acc.seats = data.seats;
  if (data.verifiedSeats && Array.isArray(data.verifiedSeats)) acc.seats = data.verifiedSeats;
  if (data.proxy) acc.proxy = data.proxy;
  if (data.proxyMode) acc.proxyMode = data.proxyMode;

  // Sync chart counters immediately when seat lists change.
  const newSeatCount = acc.seats?.length || 0;
  if (newSeatCount !== prevSeatCount) {
    updateHeldCount();
    scheduleUpdateTransferSelects();
  }

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
    throttledRenderAccounts();
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

if (els.setAllProxyBtn) {
  els.setAllProxyBtn.addEventListener('click', () => {
    accounts.forEach(a => { a.useProxy = true; });
    renderAccounts();
    log('🌐 تم تفعيل البروكسي لكل الحسابات');
  });
}
if (els.setAllDirectBtn) {
  els.setAllDirectBtn.addEventListener('click', () => {
    accounts.forEach(a => { a.useProxy = false; });
    renderAccounts();
    log('⛔ تم تفعيل الاتصال المباشر لكل الحسابات');
  });
}
if (els.applyBulkTicketCountBtn && els.bulkTicketCount) {
  els.applyBulkTicketCountBtn.addEventListener('click', () => {
    const count = parseInt(els.bulkTicketCount.value, 10);
    if (isNaN(count) || count < 1 || count > 30) {
      log('⚠️ عدد التذاكر يجب أن يكون بين 1 و 30', 'warning');
      return;
    }
    accounts.forEach(a => { a.ticketCount = count; });
    renderAccounts();
    log(`🎫 تم تطبيق ${count} تذكرة على كل الحسابات`);
  });
}

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
  scheduleUpdateTransferSelects();
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
    log('⏸️ تم إيقاف العمليات والسنايبر؛ المقاعد الممسوكة محتفظ بها في صفحة الحجز');
  } catch (err) {
    log(`فشل إيقاف الكل: ${err.message}`, 'error');
  }
  // Force-reset the UI loading state so the start button becomes clickable again
  // even if socket events were missed.
  setTimeout(() => {
    running = false;
    setLoading(false);
    log('تم إعادة تعيين حالة الزر؛ يمكنك بدء حجز جديد');
  }, 1500);
});

if (els.stopBookingHardBtn) {
  els.stopBookingHardBtn.addEventListener('click', async () => {
    try {
      await fetch('/api/stop-booking-hard', { method: 'POST' });
      log('🛑 تم إيقاف كل الجلسات وإغلاق المتصفحات');
    } catch (err) {
      log(`فشل الإيقاف الكامل: ${err.message}`, 'error');
    }
    setTimeout(() => {
      running = false;
      setLoading(false);
    }, 1000);
  });
}

async function extendAllTokens() {
  try {
    setLoading(true);
    const res = await fetch('/api/extend-all', { method: 'POST' });
    const json = await res.json();
    if (!json.success) throw new Error(json.error || 'Unknown error');
    log(`تم تمديد ${json.count}/${json.total} توكن نشط`);
  } catch (err) {
    log(`فشل تمديد التوكنز: ${err.message}`, 'error');
  } finally {
    setLoading(false);
  }
}

async function refreshAllAuthTokens() {
  let successCount = 0;
  let failCount = 0;
  const activeAccounts = accounts.filter(a => a.stage && a.stage !== 'idle' && a.stage !== 'error');
  if (activeAccounts.length === 0) {
    log('مفيش حسابات نشطة لتجديد الـ JWT');
    return;
  }
  setLoading(true);
  for (const acc of activeAccounts) {
    try {
      const res = await fetch('/api/refresh-auth-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: acc.username }),
      });
      const json = await res.json();
      if (json.success && json.refreshed) successCount++;
      else failCount++;
    } catch (err) {
      failCount++;
    }
  }
  setLoading(false);
  log(`تجديد JWT: ${successCount} نجح، ${failCount} فشل من ${activeAccounts.length}`);
}

// Token management is now automatic; legacy manual buttons removed.
// Automatic refresh loops are started at the bottom of this file.

class SessionManager {
  constructor() {
    this.sessionCheckInterval = 5 * 60 * 1000; // 5 minutes
    this.holdTokenTimestamps = new Map(); // username -> { createdAt, expiresAt }
    this.startMonitoring();
  }

  startMonitoring() {
    // Initial checks after a short delay so the UI is ready.
    setTimeout(() => this.checkAndRenew(), 5000);
    setInterval(() => this.checkAndRenew(), this.sessionCheckInterval);
    // NOTE: automatic hold-token renewal is intentionally driven by the backend
    // based on the booking-page countdown timer. The frontend no longer renews
    // tokens blindly every 8 minutes or based on a computed expiry timestamp.
  }

  async checkAndRenew() {
    if (accounts.length === 0) return;
    await this.refreshAuthTokens();
  }

  async refreshAuthTokens() {
    // Only refresh accounts that have an active/paused/holding session.
    const targets = accounts.filter(a => a.stage && a.stage !== 'idle' && a.stage !== 'error');
    if (targets.length === 0) return;
    let successCount = 0;
    let failCount = 0;
    for (const acc of targets) {
      try {
        const res = await fetch('/api/refresh-auth-token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: acc.username }),
        });
        const json = await res.json();
        if (json.success && json.refreshed) successCount++;
        else failCount++;
      } catch (err) {
        failCount++;
      }
    }
    if (successCount || failCount) {
      log(`تجديد JWT تلقائي: ${successCount} نجح، ${failCount} فشل من ${targets.length}`);
    }
  }

  async renewHoldTokens() {
    // Extend all active hold tokens in one call.
    if (accounts.length === 0) return;
    try {
      const res = await fetch('/api/extend-all', { method: 'POST' });
      const json = await res.json();
      if (json.success && json.count > 0) {
        log(`تمديد تلقائي للتوكنز: ${json.count}/${json.total} تم تمديده`);
      }
      // Refresh local expiry cache from results.
      for (const r of json.results || []) {
        if (r.success) this.updateExpiry(r.username, 15);
      }
    } catch (err) {
      // Silent failure; do not spam logs.
    }
  }

  updateExpiry(username, ttlMinutes = 15) {
    const now = Date.now();
    this.holdTokenTimestamps.set(username, {
      createdAt: now,
      expiresAt: now + ttlMinutes * 60 * 1000,
    });
  }

  async monitorHoldTokenExpiry() {
    // Fetch session info for active accounts and renew if expiry is near.
    const targets = accounts.filter(a => a.stage && a.stage !== 'idle' && a.stage !== 'error');
    const toRenew = [];
    for (const acc of targets) {
      try {
        const res = await fetch(`/api/session-info/${encodeURIComponent(acc.username)}`);
        const json = await res.json();
        if (!json.success) continue;
        if (json.holdTokenCreatedAt && json.holdTokenExpiresAt) {
          this.holdTokenTimestamps.set(acc.username, {
            createdAt: json.holdTokenCreatedAt,
            expiresAt: json.holdTokenExpiresAt,
          });
          const expiresIn = json.holdTokenExpiresAt - Date.now();
          if (expiresIn < this.renewalBufferMs) {
            toRenew.push(acc.username);
          }
        }
      } catch (err) {
        // Ignore; next cycle will retry.
      }
    }
    if (toRenew.length > 0) {
      log(`اكتشاف انتهاء قريب للـ holdToken لـ ${toRenew.length} حساب؛ جاري التمديد...`);
      for (const username of toRenew) {
        try {
          const res = await fetch('/api/extend-token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username }),
          });
          const json = await res.json();
          if (json.success) {
            this.updateExpiry(username, 15);
            log(`تم تمديد holdToken لـ ${username}`);
          }
        } catch (err) {
          log(`فشل تمديد holdToken لـ ${username}: ${err.message}`, 'error');
        }
      }
    }
  }

  async onQueuePass() {
    await this.renewHoldTokens();
  }

  async onSeatSelection() {
    // Seat selection usually generates/renews hold tokens; extend immediately.
    await this.renewHoldTokens();
  }
}

const sessionManager = new SessionManager();

function getSelectedTransferUsernames(listEl) {
  if (!listEl) return [];
  return Array.from(listEl.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value);
}

function renderTransferList(listEl, accountList, name, preserveChecked = true) {
  if (!listEl) return;
  const previouslyChecked = preserveChecked
    ? new Set(Array.from(listEl.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value))
    : new Set();
  listEl.innerHTML = accountList.map(a => {
    const label = `${escapeHtml(a.username)} (${a.stage || 'idle'})`;
    const checked = previouslyChecked.has(a.username) ? 'checked' : '';
    const proxySelected = a.useProxy === true ? 'selected' : '';
    const directSelected = a.useProxy !== true ? 'selected' : '';
    return `<label class="transfer-account-item" data-username="${escapeHtml(a.username)}">
      <input type="checkbox" name="${name}" value="${escapeHtml(a.username)}" ${checked} />
      <span>${label}</span>
      <select class="transfer-proxy-mode tiny" data-action="proxy-mode" title="بروكسي أو مباشر">
        <option value="direct" ${directSelected}>⛔ مباشر</option>
        <option value="proxy" ${proxySelected}>🌐 بروكسي</option>
      </select>
      <input type="number" class="transfer-ticket-count tiny" data-action="ticket-count" value="${a.transferTicketCount || a.ticketCount || 5}" min="1" max="30" title="عدد التذاكر" style="width:50px;padding:2px;">
    </label>`;
  }).join('');
}

function updateTransferSelects() {
  if (!els.transferFromList || !els.transferToList) return;

  // Read current selections before re-rendering.
  const previouslyCheckedSources = new Set(
    Array.from(els.transferFromList.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value)
  );
  const previouslyCheckedDests = new Set(
    Array.from(els.transferToList.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value)
  );

  // Destinations selected as sources must be removed from destinations.
  // Sources selected as destinations must be removed from sources.
  const selectedSources = new Set([...previouslyCheckedSources].filter(u => !previouslyCheckedDests.has(u)));
  const selectedDests = new Set([...previouslyCheckedDests].filter(u => !previouslyCheckedSources.has(u)));

  // Sources: all accounts except those selected as destinations.
  const sourceAccounts = accounts.filter(a => !selectedDests.has(a.username));
  renderTransferList(els.transferFromList, sourceAccounts, 'transferFrom', false);
  els.transferFromList.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    cb.checked = selectedSources.has(cb.value);
  });

  // Destinations: all accounts except those selected as sources.
  const destAccounts = accounts.filter(a => !selectedSources.has(a.username));
  renderTransferList(els.transferToList, destAccounts, 'transferTo', false);
  els.transferToList.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    cb.checked = selectedDests.has(cb.value);
  });

  // Re-attach listeners so checking/unchecking refreshes both lists.
  els.transferFromList.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', () => scheduleUpdateTransferSelects());
  });
  els.transferToList.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', () => scheduleUpdateTransferSelects());
  });

  attachTransferRowListeners();
}

// Debounce transfer-list re-renders so the user can interact with checkboxes during rapid updates.
const scheduleUpdateTransferSelects = debounce(updateTransferSelects, 500);

function setAllTransferChecked(listEl, checked) {
  if (!listEl) return;
  listEl.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = checked);
}

function attachTransferRowListeners() {
  // Per-row proxy mode and ticket count in transfer lists.
  [els.transferFromList, els.transferToList].forEach(listEl => {
    if (!listEl) return;
    listEl.querySelectorAll('.transfer-proxy-mode').forEach(sel => {
      sel.addEventListener('change', (e) => {
        const username = e.target.closest('.transfer-account-item')?.dataset.username;
        const acc = accounts.find(a => a.username === username);
        if (acc) {
          acc.useProxy = e.target.value === 'proxy';
          updateAccountRow(acc);
        }
      });
    });
    listEl.querySelectorAll('.transfer-ticket-count').forEach(inp => {
      inp.addEventListener('change', (e) => {
        const username = e.target.closest('.transfer-account-item')?.dataset.username;
        const acc = accounts.find(a => a.username === username);
        if (acc) {
          acc.transferTicketCount = Math.max(1, Math.min(30, parseInt(e.target.value, 10) || 5));
          updateAccountRow(acc);
        }
      });
    });
  });
}

function setAllTransferProxyMode(useProxy) {
  for (const acc of accounts) {
    acc.useProxy = useProxy;
  }
  updateTransferSelects();
  attachTransferRowListeners();
  for (const acc of accounts) updateAccountRow(acc);
  log(useProxy ? '🌐 كل الحسابات اتحولت لبروكسي' : '⛔ كل الحسابات اتحولت لمباشر');
}

function applyBulkTransferTicketCount() {
  const count = Math.max(1, Math.min(30, parseInt(els.bulkTransferTicketCount?.value, 10) || 5));
  for (const acc of accounts) {
    acc.transferTicketCount = count;
  }
  updateTransferSelects();
  attachTransferRowListeners();
  log(`🎫 عدد التذاكر لكل الحسابات اتحط على ${count}`);
}

function resetTransferProgress() {
  transferProgress = {
    active: false,
    totalDestinations: 0,
    preparedDestinations: 0,
    totalSeats: 0,
    transferredSeats: 0,
    abortController: null,
  };
  resetTransferDestinationStatuses();
  if (els.transferProgressWrapper) els.transferProgressWrapper.classList.add('hidden');
  if (els.transferProgressFill) els.transferProgressFill.style.width = '0%';
  if (els.cancelTransferBtn) els.cancelTransferBtn.classList.add('hidden');
  if (els.transferDistributionPreview) els.transferDistributionPreview.classList.add('hidden');
  if (els.transferDistributionList) els.transferDistributionList.innerHTML = '';
}

function renderTransferDistributionPreview(destinations) {
  if (!els.transferDistributionPreview || !els.transferDistributionList) return;
  if (!destinations.length) {
    els.transferDistributionPreview.classList.add('hidden');
    return;
  }
  els.transferDistributionList.innerHTML = destinations.map(d => {
    const seats = (d.seats || []).map(s => {
      const p = parseSeatName(s);
      return p ? `${p.section} ${p.row}-${p.seat}` : s;
    }).join('، ');
    return `<div class="transfer-distribution-item">
      <div class="transfer-distribution-user">${escapeHtml(d.username)}</div>
      <div class="transfer-distribution-seats">${escapeHtml(d.seats?.length + '')} مقعد: ${escapeHtml(seats)}</div>
    </div>`;
  }).join('');
  els.transferDistributionPreview.classList.remove('hidden');
}

function updateTransferProgress(stage, data = {}) {
  if (!transferProgress.active) return;
  if (stage === 'plan-built') {
    transferProgress.totalDestinations = data.totalDestinations || transferProgress.totalDestinations;
    transferProgress.totalSeats = data.totalSeats || transferProgress.totalSeats;
    transferProgress.preparedDestinations = 0;
    transferProgress.transferredSeats = 0;
  } else if (stage === 'destination-ready') {
    transferProgress.preparedDestinations = Math.min(transferProgress.preparedDestinations + 1, transferProgress.totalDestinations);
  } else if (stage === 'batch-complete') {
    transferProgress.transferredSeats = Math.min((transferProgress.transferredSeats || 0) + (data.transferred || 0), transferProgress.totalSeats);
  } else if (stage === 'done' || stage === 'failed') {
    transferProgress.transferredSeats = data.totalTransferred !== undefined ? data.totalTransferred : transferProgress.transferredSeats;
  }

  const pct = transferProgress.totalSeats > 0
    ? Math.round((transferProgress.transferredSeats / transferProgress.totalSeats) * 100)
    : (transferProgress.totalDestinations > 0
      ? Math.round((transferProgress.preparedDestinations / transferProgress.totalDestinations) * 100)
      : 0);

  if (els.transferProgressWrapper) els.transferProgressWrapper.classList.remove('hidden');
  if (els.transferProgressFill) els.transferProgressFill.style.width = `${pct}%`;
  if (els.transferProgressCount) els.transferProgressCount.textContent = `${transferProgress.transferredSeats} / ${transferProgress.totalSeats}`;

  const labels = {
    'plan-built': 'جاري بناء خطة النقل...',
    'trying-v3': '⚡ جاري النقل عبر محرك v3...',
    'trying-v2': '🔄 جاري النقل عبر محرك v2 الاحتياطي...',
    'destination-preparing': `جاري فتح المتصفح للوجهة ${data.currentIndex || 1}/${data.totalDestinations || transferProgress.totalDestinations}...`,
    'destination-ready': `جاهز ${transferProgress.preparedDestinations}/${transferProgress.totalDestinations} وجهة...`,
    'batch-complete': `تم نقل ${transferProgress.transferredSeats}/${transferProgress.totalSeats} مقعد...`,
    'done': `اكتمل: ${transferProgress.transferredSeats}/${transferProgress.totalSeats} مقعد`,
    'failed': 'فشل النقل',
  };
  if (els.transferProgressText) els.transferProgressText.textContent = labels[stage] || 'جاري النقل...';
}

function resetTransferDestinationStatuses() {
  transferDestinationStatuses.clear();
  if (els.transferDestinationStatusList) {
    els.transferDestinationStatusList.classList.add('hidden');
    els.transferDestinationStatusList.innerHTML = '';
  }
}

function initTransferDestinationStatuses(destinations) {
  transferDestinationStatuses.clear();
  for (const d of destinations) {
    transferDestinationStatuses.set(d.username, {
      state: 'planned',
      seats: d.seats || d.assignedSeats || [],
      transferred: 0,
      missing: 0,
      error: null,
    });
  }
  renderTransferDestinationStatusList();
}

function updateTransferDestinationStatus(username, state, data = {}) {
  const status = transferDestinationStatuses.get(username);
  if (!status) return;
  status.state = state;
  if (data.seats !== undefined) status.seats = data.seats;
  if (data.transferred !== undefined) status.transferred = data.transferred;
  if (data.missing !== undefined) status.missing = data.missing;
  if (data.error !== undefined) status.error = data.error;
  renderTransferDestinationStatusList();
}

function renderTransferDestinationStatusList() {
  if (!els.transferDestinationStatusList) return;
  if (transferDestinationStatuses.size === 0) {
    els.transferDestinationStatusList.classList.add('hidden');
    return;
  }

  const stateLabels = {
    planned: '📋 مخطط',
    preparing: '⏳ جاري التحضير',
    ready: '✅ جاهز',
    transferring: '🔄 جاري النقل',
    complete: '✅ اكتمل',
    failed: '❌ فشل',
  };

  const items = Array.from(transferDestinationStatuses.entries()).map(([username, status]) => {
    const seatChips = formatSeatList(status.seats || []);
    const resultLine = status.state === 'complete' || status.state === 'failed'
      ? `<div class="destination-status-result">نُقل ${status.transferred || 0} · فُقد ${status.missing || 0}</div>`
      : '';
    const errorLine = status.error
      ? `<div class="destination-status-error">${escapeHtml(status.error)}</div>`
      : '';
    return `<div class="destination-status-item destination-status-${status.state}">
      <div class="destination-status-header">
        <span class="destination-status-user">${escapeHtml(username)}</span>
        <span class="destination-status-state">${stateLabels[status.state] || status.state}</span>
      </div>
      <div class="destination-status-seats">${seatChips}</div>
      ${resultLine}
      ${errorLine}
    </div>`;
  }).join('');

  els.transferDestinationStatusList.innerHTML = `<h4>📊 حالة الوجهات</h4>${items}`;
  els.transferDestinationStatusList.classList.remove('hidden');
}

async function harvestSelectedSessions() {
  const selectedSources = getSelectedTransferUsernames(els.transferFromList);
  const selectedDests = getSelectedTransferUsernames(els.transferToList);
  const selected = [...new Set([...selectedSources, ...selectedDests])];
  if (selected.length === 0) return alert('اختر حساباً واحداً على الأقل من المصادر أو الوجهات');
  for (const username of selected) {
    try {
      setLoading(true);
      const res = await fetch('/api/harvest-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      const json = await res.json();
      if (json.success) {
        log(`✅ تم استخراج جلسة ${username}: ${json.cookiesCount} كوكيز, ${json.localStorageCount} LS, ${json.sessionStorageCount} SS`);
      } else {
        log(`❌ فشل استخراج جلسة ${username}: ${json.error}`, 'error');
      }
    } catch (err) {
      log(`❌ خطأ في استخراج جلسة ${username}: ${err.message}`, 'error');
    }
  }
  setLoading(false);
}

async function deleteSession(username) {
  if (!confirm(`هل تريد حذف الجلسة المحفوظة لـ ${username}؟`)) return;
  try {
    const res = await fetch(`/api/session/${encodeURIComponent(username)}`, { method: 'DELETE' });
    if (res.ok) {
      log(`🗑️ تم حذف جلسة ${username}`);
      showCachedSessions();
      refreshCachedSessionsCount();
    } else {
      const json = await res.json().catch(() => ({}));
      log(`❌ فشل حذف جلسة ${username}: ${json.error || res.statusText}`, 'error');
    }
  } catch (err) {
    log(`❌ خطأ في حذف جلسة ${username}: ${err.message}`, 'error');
  }
}

async function refreshCachedSessionsCount() {
  if (!els.cachedSessionsCount) return;
  try {
    const res = await fetch('/api/list-sessions');
    const sessions = await res.json();
    const count = Array.isArray(sessions) ? sessions.length : 0;
    els.cachedSessionsCount.textContent = `📦 جلسات محفوظة: ${count}`;
  } catch (err) {
    els.cachedSessionsCount.textContent = `📦 جلسات محفوظة: —`;
  }
}

async function showCachedSessions() {
  if (!els.cachedSessionsList) return;
  try {
    const res = await fetch('/api/list-sessions');
    const sessions = await res.json();
    refreshCachedSessionsCount();
    if (!Array.isArray(sessions) || sessions.length === 0) {
      els.cachedSessionsList.innerHTML = '<p class="no-sessions">مفيش جلسات محفوظة.</p>';
      return;
    }
    const now = Date.now();
    els.cachedSessionsList.innerHTML = sessions.map(s => {
      const exp = s.expiresAt ? new Date(s.expiresAt).toLocaleString() : 'غير معروف';
      const isValid = s.expiresAt ? s.expiresAt > now : true;
      const statusClass = isValid ? 'valid' : 'expired';
      const statusLabel = isValid ? '✅ صالحة' : '❌ منتهية';
      return `<div class="session-item ${statusClass}">
        <div class="session-header">
          <span class="session-username">${escapeHtml(s.username)}</span>
          <span class="session-status">${statusLabel}</span>
        </div>
        <div class="session-details">${s.cookiesCount || 0} كوكيز · ${s.localStorageCount || 0} LS · ${s.sessionStorageCount || 0} SS · تنتهي: ${exp}</div>
        <button class="btn-delete-session" data-username="${escapeHtml(s.username)}" title="حذف الجلسة">🗑️</button>
      </div>`;
    }).join('');
    els.cachedSessionsList.querySelectorAll('.btn-delete-session').forEach(btn => {
      btn.addEventListener('click', () => deleteSession(btn.dataset.username));
    });
  } catch (err) {
    els.cachedSessionsList.innerHTML = `<p class="no-sessions error">فشل تحميل الجلسات: ${escapeHtml(err.message)}</p>`;
  }
}

async function transferSeats() {
  const fromUsernames = getSelectedTransferUsernames(els.transferFromList);
  const toUsernames = getSelectedTransferUsernames(els.transferToList);
  if (fromUsernames.length === 0) return alert('اختر حساب مصدر واحد على الأقل');
  if (toUsernames.length === 0) return alert('اختر حساب وجهة واحد على الأقل');
  const overlap = fromUsernames.filter(u => toUsernames.includes(u));
  if (overlap.length) return alert(`لا يمكن أن يكون الحساب مصدراً ووجهةً معاً: ${overlap.join(', ')}`);
  // Transfer mode and batch size are now controlled automatically by the backend.
  const url = els.eventUrl?.value?.trim();
  if (!url) return alert('أدخل رابط الفعالية أولاً');
  const targetSections = getSelectedSections();
  // Build plan-based payload: each destination carries its ticket count (1-30)
  // and its proxy preference so the server does not force proxy testing when the
  // account is set to direct.
  // Distribution rule for transfers: every destination receives its configured
  // transferTicketCount (default 5, max 30). Any remaining seats stay on source.
  const destinations = toUsernames.map(u => {
    const acc = accounts.find(a => a.username === u);
    return { username: u, ticketCount: acc?.transferTicketCount || 5, useProxy: acc?.useProxy === true };
  });

  // Also send the full destination account objects (including credentials,
  // holdToken/cookies, and proxy preference) so the server can launch each
  // destination using the exact same settings the account would use in the
  // Accounts section. Transfer proxy logic is isolated from account proxy logic.
  const destinationAccounts = toUsernames.map(u => {
    const acc = accounts.find(a => a.username === u) || {};
    const base = {
      username: u,
      ticketCount: acc.transferTicketCount || 5,
      useProxy: acc.useProxy === true,
      url: acc.url || url,
      targetSections: acc.targetSections || targetSections,
    };
    if (acc.type === 'holdToken') {
      base.type = 'holdToken';
      base.holdToken = acc.holdToken;
      base.loginEmail = acc.loginEmail || '';
      base.loginPassword = acc.loginPassword || '';
      base.rawCookies = acc.rawCookies || '';
      base.structuredCookies = acc.structuredCookies || null;
      base.token = acc.token || '';
      base.refreshToken = acc.refreshToken || '';
      base.queueToken = acc.queueToken || '';
      base.cfClearance = acc.cfClearance || '';
      base.recaptchaToken = acc.recaptchaToken || '';
    } else {
      base.type = 'credentials';
      base.password = acc.password || '';
    }
    return base;
  });
  transferProgress.active = true;
  transferProgress.abortController = new AbortController();
  // Wait for the backend plan to report the real total seat count instead of
  // summing every destination's ticket count (which produced confusing labels
  // like "0 / 150" when only 30 seats were actually held).
  updateTransferProgress('plan-built', {
    totalDestinations: destinations.length,
    totalSeats: 0,
  });
  if (els.cancelTransferBtn) els.cancelTransferBtn.classList.remove('hidden');

  try {
    setLoading(true);
    const v3Body = {
      masterUsernames: fromUsernames,
      destinations,
      destinationAccounts,
      url,
      targetSections,
    };
    const v2Body = {
      masterUsernames: fromUsernames,
      destinations,
      destinationAccounts,
      url,
      targetSections,
      mode: 'auto',
      batchSize: 5,
      distribution: 'manual',
      sniperMode: true,
    };

    // Always try v3 first (session-based, fastest). Fall back to v2 on zero transfer or error.
    if (els.transferEngineStatus) els.transferEngineStatus.textContent = '⚡ جاري النقل عبر v3...';
    updateTransferProgress('trying-v3');
    let json;
    try {
      const v3Res = await fetch('/api/transfer-seats-v3', {
        method: 'POST',
        signal: transferProgress.abortController.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(v3Body),
      });
      json = await v3Res.json();
      if (json.error) throw new Error(json.error);
      if ((json.totalTransferred || 0) === 0 && (json.totalSeats || json.totalFailed || 0) > 0) {
        throw new Error('v3 transferred zero seats');
      }
    } catch (v3Err) {
      if (v3Err.name === 'AbortError') throw v3Err;
      log(`⚠️ v3 لم ينجح (${v3Err.message}); جاري التبديل إلى v2...`, 'warning');
      if (els.transferEngineStatus) els.transferEngineStatus.textContent = '⚡ v3 فشل، جاري v2...';
      updateTransferProgress('trying-v2');
      const v2Res = await fetch('/api/transfer-seats', {
        method: 'POST',
        signal: transferProgress.abortController.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(v2Body),
      });
      json = await v2Res.json();
      if (json.error) throw new Error(json.error);
    }

    updateTransferProgress('done', { totalTransferred: json.totalTransferred || 0 });
    log(`✅ تم نقل ${json.totalTransferred || 0} مقعد عبر ${json.details?.length || 0} وجهة`);
    for (const r of json.details || []) {
      log(`• ${r.destination}: ${r.transferred || 0} مقعد (${r.failed || 0} فُقد)`);
    }
  } catch (err) {
    if (err.name === 'AbortError') {
      log('تم إلغاء نقل المقاعد');
    } else {
      updateTransferProgress('failed');
      log(`فشل نقل المقاعد: ${err.message}`, 'error');
    }
  } finally {
    setLoading(false);
    resetTransferProgress();
    if (els.transferEngineStatus) els.transferEngineStatus.textContent = '⚡ النقل التلقائي: v3 ← v2';
  }
}

async function transferSeatsHeadless() {
  const fromUsernames = getSelectedTransferUsernames(els.transferFromList);
  const toUsernames = getSelectedTransferUsernames(els.transferToList);
  if (fromUsernames.length === 0) return alert('اختر حساب مصدر واحد على الأقل');
  if (fromUsernames.length > 1) return alert('النقل المباشر يدعم مصدر واحد فقط حالياً');
  if (toUsernames.length === 0) return alert('اختر حساب وجهة واحد على الأقل');
  const overlap = fromUsernames.filter(u => toUsernames.includes(u));
  if (overlap.length) return alert(`لا يمكن أن يكون الحساب مصدراً ووجهةً معاً: ${overlap.join(', ')}`);

  const url = els.eventUrl?.value?.trim();
  if (!url) return alert('أدخل رابط الفعالية أولاً');

  setLoading(true);
  if (els.transferEngineStatus) els.transferEngineStatus.textContent = '🚀 نقل مباشر Headless...';
  log(`🚀 بدء نقل مباشر من ${fromUsernames[0]} إلى ${toUsernames.length} وجهة`);

  try {
    const selectedAccounts = accounts.filter(a => a.selected);
    const res = await fetch('/api/transfer-seats-headless', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sourceUsername: fromUsernames[0],
        destUsernames: toUsernames,
        url,
        channel: 'NO_CHANNEL',
        accounts: selectedAccounts.map(a => ({
          username: a.username,
          password: a.password,
          type: a.type,
          useProxy: a.useProxy,
          holdToken: a.holdToken,
          loginEmail: a.loginEmail,
          loginPassword: a.loginPassword,
          rawCookies: a.rawCookies,
          structuredCookies: a.structuredCookies,
          token: a.token,
          refreshToken: a.refreshToken,
          queueToken: a.queueToken,
          cfClearance: a.cfClearance,
          recaptchaToken: a.recaptchaToken,
        })),
      }),
    });
    const json = await res.json();
    if (json.error) throw new Error(json.error);
    log(`✅ تم نقل ${json.totalTransferred || 0} مقعد عبر النقل المباشر`);
    for (const r of json.details || []) {
      log(`• ${r.destination}: ${r.held?.length || 0} مقعد (${r.missing?.length || 0} فُقد)`);
    }
  } catch (err) {
    log(`فشل النقل المباشر: ${err.message}`, 'error');
  } finally {
    setLoading(false);
    if (els.transferEngineStatus) els.transferEngineStatus.textContent = '⚡ النقل التلقائي: v3 ← v2';
  }
}

if (els.cancelTransferBtn) {
  els.cancelTransferBtn.addEventListener('click', () => {
    if (transferProgress.abortController) {
      transferProgress.abortController.abort();
    }
    resetTransferProgress();
  });
}

if (els.transferSeatsBtn) els.transferSeatsBtn.addEventListener('click', transferSeats);
if (els.transferSeatsHeadlessBtn) els.transferSeatsHeadlessBtn.addEventListener('click', transferSeatsHeadless);
if (els.harvestSelectedSessionsBtn) els.harvestSelectedSessionsBtn.addEventListener('click', harvestSelectedSessions);
if (els.showCachedSessionsBtn) els.showCachedSessionsBtn.addEventListener('click', showCachedSessions);
function selectAllSources() { setAllTransferChecked(els.transferFromList, true); scheduleUpdateTransferSelects(); }
function deselectAllSources() { setAllTransferChecked(els.transferFromList, false); scheduleUpdateTransferSelects(); }
function selectAllDestinations() { setAllTransferChecked(els.transferToList, true); scheduleUpdateTransferSelects(); }
function deselectAllDestinations() { setAllTransferChecked(els.transferToList, false); scheduleUpdateTransferSelects(); }

if (els.selectAllSourcesBtn) els.selectAllSourcesBtn.addEventListener('click', selectAllSources);
if (els.deselectAllSourcesBtn) els.deselectAllSourcesBtn.addEventListener('click', deselectAllSources);
if (els.selectAllDestsBtn) els.selectAllDestsBtn.addEventListener('click', selectAllDestinations);
if (els.deselectAllDestsBtn) els.deselectAllDestsBtn.addEventListener('click', deselectAllDestinations);
if (els.setAllTransferProxyBtn) els.setAllTransferProxyBtn.addEventListener('click', () => setAllTransferProxyMode(true));
if (els.setAllTransferDirectBtn) els.setAllTransferDirectBtn.addEventListener('click', () => setAllTransferProxyMode(false));
if (els.applyBulkTransferTicketCountBtn) els.applyBulkTransferTicketCountBtn.addEventListener('click', applyBulkTransferTicketCount);

function filterVisibleLogs(query) {
  if (!els.logs) return;
  const q = (query || '').trim().toLowerCase();
  Array.from(els.logs.children).forEach(entry => {
    entry.style.display = q && !entry.textContent.toLowerCase().includes(q) ? 'none' : '';
  });
}

if (els.logSearch) {
  els.logSearch.addEventListener('input', (e) => filterVisibleLogs(e.target.value));
}

els.downloadLogsBtn.addEventListener('click', async () => {
  try {
    let text = '';
    try {
      const res = await fetch('/api/logs');
      const json = await res.json();
      if (json.success && typeof json.logs === 'string') {
        text = json.logs;
      }
    } catch (fetchErr) {
      // Fallback to visible logs if the server endpoint fails.
      text = els.logs ? els.logs.innerText || '' : '';
    }
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kimiko-logs-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(url);
      a.remove();
    }, 2000);
    log('تم تحميل السجل');
  } catch (err) {
    log(`فشل تحميل السجل: ${err.message}`, 'error');
  }
});

els.clearLogsBtn.addEventListener('click', () => {
  els.logs.innerHTML = '';
});

function isAccountActiveSession(acc) {
  if (!acc) return false;
  return acc.stage !== 'idle' && acc.stage !== 'error';
}

async function proceedAccount(username) {
  const acc = accounts.find(a => a.username === username);
  if (!isAccountActiveSession(acc)) {
    log(`لا يوجد جلسة نشطة لـ ${username}؛ ابدأ الحجز أولاً`);
    return;
  }
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
  if (!isAccountActiveSession(acc)) {
    log(`لا يوجد جلسة نشطة لـ ${username} لإيقافها`);
    return;
  }
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
  const acc = accounts.find(a => a.username === username);
  if (!isAccountActiveSession(acc)) {
    if (acc) {
      acc.seats = [];
      acc.stage = 'idle';
      renderAccounts();
    }
    log(`تم مسح المقاعد المحلية لـ ${username}`);
    return;
  }
  try {
    const res = await fetch('/api/release-hold', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });
    const json = await res.json();
    if (!json.success) throw new Error(json.error);
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

if (els.autoDetectMaxTickets) {
  els.autoDetectMaxTickets.addEventListener('change', () => {
    if (els.autoDetectMaxTickets.checked && detectedMaxTickets) {
      applyDetectedMaxTickets(detectedMaxTickets);
    } else {
      log(els.autoDetectMaxTickets.checked
        ? 'الاكتشاف التلقائي للتذاكر مفعّل؛ سيتم التحديث عند جلب الفعالية التالية.'
        : 'الاكتشاف التلقائي للتذاكر معطّل.');
    }
  });
}

// Init
running = false;
setLoading(false);
renderAccounts();
updateTransferSelects();
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

