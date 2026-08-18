/**
 * Pair Cycling Manager (Hold Cycling / Seat Camping)
 *
 * Implements the pairing and wave lifecycle logic described in pairs.md,
 * adapted to the existing Kimiko booking bot architecture without requiring
 * Redis or an external queue. Uses in-memory state and Node.js timers.
 *
 * Each pair consists of a primary and secondary account. They alternate
 * holding the same set of seats every ~8 minutes (handoff at 7:55) so the
 * seats stay reserved beyond the normal 10-minute hold expiry.
 */

const HANDOFF_DELAY_MS = 7 * 60 * 1000 + 55 * 1000; // 7 minutes 55 seconds (fallback safety)
const HANDOFF_AT_SECONDS = 45; // handoff when page timer shows <= 45 seconds remaining (more time for transfer)
const DEFAULT_MAX_WAVES = 10;
const DEFAULT_MAX_DURATION_MINUTES = 60;
const MAX_HELD_SEATS = 30; // never exceed the SeatCloud hold-token limit

class PairCyclingManager {
  constructor(deps) {
    this.deps = deps;
    this.cycles = new Map(); // pairId -> cycle state
    this.timers = new Map(); // pairId -> timeout handle
    this.locks = new Set();  // pairIds currently performing handoff
  }

  /**
   * Pair accounts: [0,1], [2,3], ...
   * If odd number, the last account is standby/inactive.
   */
  createPairs(accounts) {
    const pairs = [];
    for (let i = 0; i + 1 < accounts.length; i += 2) {
      pairs.push({
        primary: { ...accounts[i] },
        secondary: { ...accounts[i + 1] },
      });
    }
    const standby = accounts.length % 2 === 1 ? { ...accounts[accounts.length - 1] } : null;
    return { pairs, standby };
  }

  /**
   * Start pair cycling for a list of accounts.
   * Returns immediately; cycles run in the background.
   */
  async startCycling({ url, targetSections, accounts, ticketCount = 30, maxWaves = DEFAULT_MAX_WAVES, maxDurationMinutes = DEFAULT_MAX_DURATION_MINUTES }) {
    if (!Array.isArray(accounts) || accounts.length === 0) {
      throw new Error('accounts array is required');
    }
    if (!url) {
      throw new Error('url is required');
    }

    const { pairs, standby } = this.createPairs(accounts);
    const baseId = Date.now();
    const startedPairIds = [];

    for (let i = 0; i < pairs.length; i++) {
      const pairId = `pair-${baseId}-${i}`;
      startedPairIds.push(pairId);
      // Preserve full account objects (type, holdToken, proxy prefs, chart keys, etc.).
      pairs[i].primary.original = accounts[i * 2];
      pairs[i].secondary.original = accounts[i * 2 + 1];
      this.startPair(pairId, pairs[i], {
        url,
        targetSections,
        ticketCount: Math.max(1, Math.min(parseInt(ticketCount, 10) || 30, MAX_HELD_SEATS)),
        maxWaves: Math.max(1, parseInt(maxWaves, 10) || DEFAULT_MAX_WAVES),
        maxDurationMs: Math.max(1, parseInt(maxDurationMinutes, 10) || DEFAULT_MAX_DURATION_MINUTES) * 60 * 1000,
      }).catch(err => {
        this.deps.fileLog('ERROR', `[PairCycling] startPair ${pairId} error: ${err.message}`);
      });
    }

    return {
      success: true,
      pairIds: startedPairIds,
      pairCount: pairs.length,
      standby: standby?.username || null,
      message: `Started ${pairs.length} pair cycle(s) for ${accounts.length} account(s)`,
    };
  }

  async startPair(pairId, pair, options) {
    const cycle = {
      pairId,
      primary: pair.primary,
      secondary: pair.secondary,
      activeUser: pair.primary,
      inactiveUser: pair.secondary,
      seats: [],
      currentWave: 1,
      maxWaves: options.maxWaves,
      startTime: Date.now(),
      maxDurationMs: options.maxDurationMs,
      status: 'RUNNING',
      url: options.url,
      targetSections: options.targetSections,
      ticketCount: options.ticketCount,
      sessions: {}, // username -> session object
    };

    this.cycles.set(pairId, cycle);
    this.deps.emitStatus('pair-cycle-started', `Pair ${pairId} started: ${pair.primary.username} + ${pair.secondary.username}`, {
      pairId,
      primary: pair.primary.username,
      secondary: pair.secondary.username,
      ticketCount: options.ticketCount,
    });

    // Ensure the inactive partner has no open browser before starting.
    this.deps.emitAccountUpdate(cycle.inactiveUser.username, 'queued', { seats: [] });
    await this.closeInactiveBrowser(cycle);

    await this.runWave(cycle);
  }

  async closeInactiveBrowser(cycle) {
    try {
      await this.deps.releaseHoldsForUser(cycle.inactiveUser.username);
      this.deps.fileLog('INFO', `[PairCycling] ${cycle.inactiveUser.username} browser closed (inactive)`);
    } catch (err) {
      this.deps.fileLog('WARN', `[PairCycling] closeInactiveBrowser ${cycle.inactiveUser.username}: ${err.message}`);
    }
  }

  async runWave(cycle) {
    if (cycle.status !== 'RUNNING') return;

    const user = cycle.activeUser;
    const isHandoff = cycle.seats.length > 0;

    this.deps.emitStatus('pair-wave-start', `Pair ${cycle.pairId} wave ${cycle.currentWave}: ${user.username} holding ${cycle.ticketCount} seats`, {
      pairId: cycle.pairId,
      wave: cycle.currentWave,
      account: user.username,
      isHandoff,
    });

    try {
      const session = await this.deps.runCycleSession({
        ...(user.original || {}),
        username: user.username,
        password: user.password,
        url: cycle.url,
        targetSections: cycle.targetSections,
        ticketCount: cycle.ticketCount,
        fixedSeats: isHandoff ? cycle.seats : undefined,
      });

      if (!session || !session.selectedSeats || session.selectedSeats.length === 0) {
        throw new Error('No seats held');
      }

      cycle.sessions[user.username] = session;
      cycle.seats = session.selectedSeats;

      this.deps.emitAccountUpdate(user.username, 'cycle-holding', { seats: session.selectedSeats });
      this.deps.emitAccountUpdate(cycle.inactiveUser.username, 'queued', { seats: [] });

      this.deps.emitStatus('pair-wave-held', `Pair ${cycle.pairId} wave ${cycle.currentWave}: ${user.username} holding ${session.selectedSeats.length} seats`, {
        pairId: cycle.pairId,
        wave: cycle.currentWave,
        account: user.username,
        seats: session.selectedSeats,
      });

      this.scheduleNextHandoff(cycle);
    } catch (err) {
      cycle.status = 'FAILED';
      this.deps.emitStatus('pair-wave-failed', `Pair ${cycle.pairId} wave ${cycle.currentWave} failed: ${err.message}`, {
        pairId: cycle.pairId,
        wave: cycle.currentWave,
        account: user.username,
        error: err.message,
      });
    }
  }

  /**
   * Decide when to handoff. The primary trigger is the live page countdown
   * (see onHoldTimer). This fallback schedules a handoff at 7:55 just in case
   * the timer watcher never fires.
   */
  scheduleNextHandoff(cycle) {
    if (cycle.status !== 'RUNNING') return;

    const elapsedMs = Date.now() - cycle.startTime;
    const wouldExceedDuration = elapsedMs + HANDOFF_DELAY_MS >= cycle.maxDurationMs;
    const wouldExceedWaves = cycle.currentWave >= cycle.maxWaves;

    if (wouldExceedWaves || wouldExceedDuration) {
      this.deps.emitStatus('pair-cycle-limit', `Pair ${cycle.pairId} reached limit (wave ${cycle.currentWave}/${cycle.maxWaves}, elapsed ${Math.round(elapsedMs / 1000)}s). Stopping.`, {
        pairId: cycle.pairId,
        wave: cycle.currentWave,
        elapsedMs,
      });
      this.stopPair(cycle.pairId).catch(() => {});
      return;
    }

    // If a timer-based handoff is already scheduled, don't double-book.
    if (this.timers.has(cycle.pairId)) return;

    this.deps.emitStatus('pair-handoff-scheduled', `Pair ${cycle.pairId}: fallback handoff in ${Math.round(HANDOFF_DELAY_MS / 1000)}s`, {
      pairId: cycle.pairId,
      wave: cycle.currentWave,
      account: cycle.inactiveUser.username,
      delayMs: HANDOFF_DELAY_MS,
    });

    const timer = setTimeout(() => {
      this.performHandoff(cycle.pairId).catch(err => {
        this.deps.fileLog('ERROR', `[PairCycling] handoff ${cycle.pairId} error: ${err.message}`);
      });
    }, HANDOFF_DELAY_MS);

    this.timers.set(cycle.pairId, timer);
  }

  /**
   * Live timer feed from the browser page. When the active user's countdown
   * reaches HANDOFF_AT_SECONDS or less, start the handoff immediately so the
   * inactive partner can grab the same seats before the hold expires.
   */
  onHoldTimer(username, seconds) {
    for (const cycle of this.cycles.values()) {
      if (cycle.status !== 'RUNNING') continue;
      if (cycle.activeUser.username !== username) continue;

      cycle.lastTimerSeconds = seconds;

      if (seconds > HANDOFF_AT_SECONDS) continue;
      if (this.locks.has(cycle.pairId)) {
        this.deps.fileLog('INFO', `[PairCycling] ${cycle.pairId} handoff already in progress (timer=${seconds}s)`);
        continue;
      }

      // Replace any fallback timer with an immediate handoff.
      const existing = this.timers.get(cycle.pairId);
      if (existing) {
        clearTimeout(existing);
        this.timers.delete(cycle.pairId);
      }

      this.deps.emitStatus('pair-handoff-timer', `Pair ${cycle.pairId}: timer at ${seconds}s — starting handoff`, {
        pairId: cycle.pairId,
        account: username,
        seconds,
      });

      const timer = setTimeout(() => {
        this.performHandoff(cycle.pairId).catch(err => {
          this.deps.fileLog('ERROR', `[PairCycling] timer handoff ${cycle.pairId} error: ${err.message}`);
        });
      }, 0);
      this.timers.set(cycle.pairId, timer);
      return;
    }
  }

  async performHandoff(pairId) {
    if (this.locks.has(pairId)) return; // already in handoff
    this.locks.add(pairId);

    try {
      const cycle = this.cycles.get(pairId);
      if (!cycle || cycle.status !== 'RUNNING') return;

      // Clear the scheduled timer reference (it already fired).
      this.timers.delete(pairId);

      const currentUser = cycle.activeUser;
      const nextUser = cycle.inactiveUser;
      const targetSeats = cycle.seats;

      this.deps.emitStatus('pair-handoff-start', `Pair ${pairId}: handoff from ${currentUser.username} to ${nextUser.username}`, {
        pairId,
        from: currentUser.username,
        to: nextUser.username,
        seats: targetSeats,
      });

      // 1. Have next user attempt the full target set BEFORE releasing current user.
      this.deps.emitAccountUpdate(currentUser.username, 'cycle-holding', { seats: targetSeats });
      this.deps.emitAccountUpdate(nextUser.username, 'launching', { seats: [] });

      let nextSession = null;
      let attempts = 0;
      const maxAttempts = 3;

      while (attempts < maxAttempts && (!nextSession || nextSession.selectedSeats.length < targetSeats.length)) {
        attempts++;
        try {
          // Always retry the full target set; runCycleSession will fall back to
          // whatever it can actually hold if the full set is no longer available.
          const fixedSeats = targetSeats;
          const sess = await this.deps.runCycleSession({
            ...(nextUser.original || {}),
            username: nextUser.username,
            password: nextUser.password,
            url: cycle.url,
            targetSections: cycle.targetSections,
            ticketCount: cycle.ticketCount,
            fixedSeats,
          });

          if (sess && sess.selectedSeats && sess.selectedSeats.length > 0) {
            if (!nextSession || sess.selectedSeats.length > nextSession.selectedSeats.length) {
              nextSession = sess;
            }
          }

          if (!nextSession) {
            throw new Error('No seats held by next user');
          }
        } catch (err) {
          this.deps.fileLog('WARN', `[PairCycling] handoff attempt ${attempts}/${maxAttempts} failed for ${pairId}: ${err.message}`);
          if (attempts < maxAttempts) await this.deps.waitFor(1500);
        }
      }

      if (!nextSession || nextSession.selectedSeats.length === 0) {
        this.deps.emitStatus('pair-handoff-failed', `Pair ${pairId}: handoff failed after ${maxAttempts} attempts, keeping ${currentUser.username}`, {
          pairId,
          account: currentUser.username,
          attempts,
        });
        // Try again sooner; don't lose the seats.
        const retryTimer = setTimeout(() => {
          this.performHandoff(pairId).catch(() => {});
        }, 30000);
        this.timers.set(pairId, retryTimer);
        return;
      }

      // 2. If the next user only got a partial hold, release the previous holder
      //    and immediately retry the full target set on the next user.
      if (nextSession.selectedSeats.length < targetSeats.length) {
        this.deps.emitStatus('pair-handoff-partial', `Pair ${pairId}: next user only held ${nextSession.selectedSeats.length}/${targetSeats.length}; releasing previous holder and retrying`, {
          pairId,
          held: nextSession.selectedSeats,
          target: targetSeats,
        });

        try {
          await this.deps.releaseHoldsForUser(currentUser.username);
          this.deps.emitStatus('pair-handoff-released', `Pair ${pairId}: released previous holder ${currentUser.username} for retry`, {
            pairId,
            account: currentUser.username,
          });
        } catch (err) {
          this.deps.fileLog('WARN', `[PairCycling] failed to release ${currentUser.username} for retry on ${pairId}: ${err.message}`);
        }

        try {
          const retrySession = await this.deps.runCycleSession({
            ...(nextUser.original || {}),
            username: nextUser.username,
            password: nextUser.password,
            url: cycle.url,
            targetSections: cycle.targetSections,
            ticketCount: cycle.ticketCount,
            fixedSeats: targetSeats,
          });
          if (retrySession && retrySession.selectedSeats && retrySession.selectedSeats.length > nextSession.selectedSeats.length) {
            nextSession = retrySession;
          }
        } catch (err) {
          this.deps.fileLog('WARN', `[PairCycling] post-release retry failed for ${pairId}: ${err.message}`);
        }
      }

      // 3. Commit the handoff: next user becomes active, previous becomes inactive.
      cycle.sessions[nextUser.username] = nextSession;
      cycle.seats = nextSession.selectedSeats;
      cycle.activeUser = nextUser;
      cycle.inactiveUser = currentUser;
      cycle.currentWave += 1;

      this.deps.emitAccountUpdate(currentUser.username, 'idle', { seats: [] });
      this.deps.emitAccountUpdate(nextUser.username, 'cycle-holding', { seats: nextSession.selectedSeats });

      this.deps.emitStatus('pair-handoff-success', `Pair ${pairId}: ${nextUser.username} now holding ${nextSession.selectedSeats.length} seats`, {
        pairId,
        wave: cycle.currentWave,
        account: nextUser.username,
        seats: nextSession.selectedSeats,
      });

      // 4. Release previous holder if we have not already done so.
      if (nextSession.selectedSeats.length >= targetSeats.length) {
        try {
          await this.deps.releaseHoldsForUser(currentUser.username);
          this.deps.emitStatus('pair-handoff-released', `Pair ${pairId}: released previous holder ${currentUser.username}`, {
            pairId,
            account: currentUser.username,
          });
        } catch (err) {
          this.deps.fileLog('WARN', `[PairCycling] failed to release ${currentUser.username} for ${pairId}: ${err.message}`);
        }
      }

      // 5. Schedule next handoff.
      this.scheduleNextHandoff(cycle);
    } finally {
      this.locks.delete(pairId);
    }
  }

  async stopPair(pairId) {
    const cycle = this.cycles.get(pairId);
    if (!cycle) return { success: false, error: 'Pair cycle not found' };

    cycle.status = 'STOPPING';

    if (this.timers.has(pairId)) {
      clearTimeout(this.timers.get(pairId));
      this.timers.delete(pairId);
    }

    // Release active holder.
    if (cycle.activeUser) {
      try {
        await this.deps.releaseHoldsForUser(cycle.activeUser.username);
      } catch (err) {
        this.deps.fileLog('WARN', `[PairCycling] stopPair ${pairId}: failed to release ${cycle.activeUser.username}: ${err.message}`);
      }
    }

    // Also clean up any session object we launched for the inactive user during handoff.
    if (cycle.inactiveUser && cycle.sessions[cycle.inactiveUser.username]) {
      try {
        await this.deps.releaseHoldsForUser(cycle.inactiveUser.username);
      } catch (err) {
        this.deps.fileLog('WARN', `[PairCycling] stopPair ${pairId}: failed to release inactive ${cycle.inactiveUser.username}: ${err.message}`);
      }
    }

    cycle.status = 'COMPLETED';
    this.deps.emitStatus('pair-cycle-stopped', `Pair ${pairId} stopped`, { pairId });
    return { success: true, pairId };
  }

  async stopAll() {
    const pairIds = Array.from(this.cycles.keys());
    const results = [];
    for (const pairId of pairIds) {
      results.push(await this.stopPair(pairId));
    }
    return { success: true, stopped: results.filter(r => r.success).length };
  }

  getStatus() {
    const cycles = [];
    for (const cycle of this.cycles.values()) {
      cycles.push({
        pairId: cycle.pairId,
        primary: cycle.primary.username,
        secondary: cycle.secondary.username,
        activeUser: cycle.activeUser.username,
        currentWave: cycle.currentWave,
        maxWaves: cycle.maxWaves,
        seatCount: cycle.seats.length,
        seats: cycle.seats,
        status: cycle.status,
        elapsedMs: Date.now() - cycle.startTime,
        lastTimerSeconds: cycle.lastTimerSeconds ?? null,
      });
    }
    return { cycles, count: cycles.length };
  }
}

function createPairCyclingManager(deps) {
  return new PairCyclingManager(deps);
}

module.exports = { createPairCyclingManager, PairCyclingManager };
