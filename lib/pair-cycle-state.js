const CYCLE_PHASES = {
  AUTH_PENDING: 'AUTH_PENDING',
  AUTH_READY: 'AUTH_READY',
  BOOKING_READY: 'BOOKING_READY',
  HOLDING: 'HOLDING',
  HANDOFF_PENDING: 'HANDOFF_PENDING',
  FAILED: 'FAILED',
};

function setCyclePhase(cycle, phase, meta = {}) {
  if (!cycle || typeof cycle !== 'object') {
    throw new Error('cycle object is required');
  }
  cycle.phase = phase;
  cycle.phaseMeta = {
    ...(cycle.phaseMeta || {}),
    ...meta,
    updatedAt: Date.now(),
  };
  return cycle;
}

function classifyCycleError(err) {
  const msg = String(err?.message || err || '').toLowerCase();

  if (!msg) return 'UNKNOWN';
  if (msg.includes('login button not found')) return 'AUTH_FAILURE';
  if (msg.includes('login') || msg.includes('auth')) return 'AUTH_FAILURE';
  if (msg.includes('queue')) return 'QUEUE_FAILURE';
  if (msg.includes('booking trigger') || msg.includes('booking not ready')) return 'BOOKING_NOT_READY';
  if (msg.includes('failed to hold seats') || msg.includes('hold timeout') || msg.includes('seat hold timeout')) return 'SEAT_HOLD_TIMEOUT';
  return 'UNKNOWN';
}

function createCycleSnapshot(cycle) {
  return {
    pairId: cycle?.pairId || null,
    phase: cycle?.phase || null,
    phaseMeta: cycle?.phaseMeta ? { ...cycle.phaseMeta } : null,
  };
}

module.exports = {
  CYCLE_PHASES,
  setCyclePhase,
  classifyCycleError,
  createCycleSnapshot,
};
