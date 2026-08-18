/**
 * Humanized pointer / keyboard input helpers for Playwright.
 *
 * Implements biomechanical models from the fingerprinting report:
 *   - Fitts' Law for movement duration
 *   - Minimum-jerk trajectory synthesis
 *   - Gaussian physiological tremor
 *   - Overshoot + corrective submovement
 *   - Variable typing cadence
 */

'use strict';

const DEFAULT_FITTS_A = 80;
const DEFAULT_FITTS_B = 150;
const DEFAULT_NOISE_PX = 1.2;

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function randNormal(mean = 0, std = 1) {
  const u1 = Math.random();
  const u2 = Math.random();
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return mean + z * std;
}

function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

function fittsDuration(distance, targetWidth, a = DEFAULT_FITTS_A, b = DEFAULT_FITTS_B) {
  const W = Math.max(targetWidth, 4);
  const A = Math.max(distance, 1);
  const id = Math.log2(A / W + 1);
  return Math.max(a + b * id + randNormal(0, a * 0.15), a);
}

function minimumJerk(t) { return 10 * t ** 3 - 15 * t ** 4 + 6 * t ** 5; }

function generatePath(x0, y0, x1, y1, options = {}) {
  const { curvature = 0.12, noisePx = DEFAULT_NOISE_PX, overshootProb = 0.65 } = options;
  const dx = x1 - x0;
  const dy = y1 - y0;
  const distance = Math.hypot(dx, dy);
  if (distance < 2) return [{ x: x1, y: y1, t: 1 }];

  const midX = (x0 + x1) / 2;
  const midY = (y0 + y1) / 2;
  const perpX = -dy / distance;
  const perpY = dx / distance;
  const arc = (Math.random() > 0.5 ? 1 : -1) * distance * curvature;
  const cpX = midX + perpX * arc;
  const cpY = midY + perpY * arc;

  const steps = Math.max(8, Math.floor((distance / 100) * 12));
  const points = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const mj = minimumJerk(t);
    const bx = (1 - mj) ** 2 * x0 + 2 * (1 - mj) * mj * cpX + mj ** 2 * x1;
    const by = (1 - mj) ** 2 * y0 + 2 * (1 - mj) * mj * cpY + mj ** 2 * y1;
    points.push({
      x: clamp(bx + randNormal(0, noisePx), 0, 99999),
      y: clamp(by + randNormal(0, noisePx), 0, 99999),
      t,
    });
  }

  if (Math.random() < overshootProb && distance > 30) {
    const overshootT = 0.92 + Math.random() * 0.06;
    const overshootMag = distance * (0.03 + Math.random() * 0.04);
    const angle = Math.atan2(dy, dx) + randNormal(0, 0.25);
    const overX = x1 + Math.cos(angle) * overshootMag;
    const overY = y1 + Math.sin(angle) * overshootMag;
    const correctionSteps = Math.max(4, Math.floor(steps * 0.25));
    for (let i = 1; i <= correctionSteps; i++) {
      const t = i / correctionSteps;
      const mx = overX + (x1 - overX) * minimumJerk(t);
      const my = overY + (y1 - overY) * minimumJerk(t);
      points.push({
        x: clamp(mx + randNormal(0, noisePx * 0.6), 0, 99999),
        y: clamp(my + randNormal(0, noisePx * 0.6), 0, 99999),
        t: overshootT + (1 - overshootT) * t,
      });
    }
  }
  return points;
}

async function getMousePosition(page) {
  try {
    return await page.evaluate(() => ({ x: window.__kimikoMouseX || 0, y: window.__kimikoMouseY || 0 }));
  } catch { return { x: 0, y: 0 }; }
}

async function resolveTarget(page, selectorOrElement) {
  let el = selectorOrElement;
  if (typeof selectorOrElement === 'string') el = await page.$(selectorOrElement);
  if (el && typeof el.elementHandle === 'function') el = await el.elementHandle();
  if (!el) return null;
  const box = await el.boundingBox();
  if (!box) return null;
  return {
    x: box.x + box.width / 2 + randNormal(0, box.width * 0.12),
    y: box.y + box.height / 2 + randNormal(0, box.height * 0.12),
    width: box.width,
    height: box.height,
  };
}

async function humanMove(page, x, y, options = {}) {
  const start = await getMousePosition(page);
  const path = generatePath(start.x, start.y, x, y, options);
  const duration = options.duration || fittsDuration(
    Math.hypot(x - start.x, y - start.y),
    options.targetWidth || 20
  );
  const t0 = Date.now();
  for (const pt of path) {
    const waitMs = Math.max(0, t0 + pt.t * duration - Date.now());
    await sleep(waitMs);
    await page.mouse.move(pt.x, pt.y);
    try {
      await page.evaluate(({ x, y }) => { window.__kimikoMouseX = x; window.__kimikoMouseY = y; }, { x: pt.x, y: pt.y });
    } catch {}
  }
}

async function humanClick(page, selectorOrElement, options = {}) {
  let target;
  if (typeof selectorOrElement === 'object' && selectorOrElement.x !== undefined) {
    target = selectorOrElement;
  } else {
    target = await resolveTarget(page, selectorOrElement);
  }
  if (!target) throw new Error(`humanClick: target not found ${selectorOrElement}`);
  await humanMove(page, target.x, target.y, { ...options, targetWidth: target.width || 20 });
  await sleep(randNormal(80, 25));
  await page.mouse.down();
  await sleep(randNormal(110, 35));
  await page.mouse.up();
  await sleep(randNormal(50, 15));
}

async function humanType(page, selectorOrElement, text, options = {}) {
  let el = selectorOrElement;
  if (typeof selectorOrElement === 'string') el = await page.$(selectorOrElement);
  if (el && typeof el.elementHandle === 'function') el = await el.elementHandle();
  if (!el) throw new Error(`humanType: element not found ${selectorOrElement}`);
  await humanClick(page, el, options);

  const baseDelay = options.baseDelay || 90;
  const errorRate = options.errorRate || 0.015;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const isBoundary = /[\s\.,;!?@]/.test(ch);
    const pause = isBoundary
      ? randNormal(baseDelay * 1.6, baseDelay * 0.4)
      : randNormal(baseDelay, baseDelay * 0.25);
    await sleep(Math.max(20, pause));

    if (Math.random() < errorRate && i > 0 && /[a-zA-Z0-9]/.test(ch)) {
      const wrong = String.fromCharCode(97 + Math.floor(Math.random() * 26));
      await el.type(wrong, { delay: 10 });
      await sleep(randNormal(180, 50));
      await el.press('Backspace');
      await sleep(randNormal(120, 30));
    }
    await el.type(ch, { delay: 10 });
  }
  await sleep(randNormal(250, 60));
}

async function humanScroll(page, deltaY, options = {}) {
  const steps = Math.max(1, Math.floor(Math.abs(deltaY) / 80));
  const step = deltaY / steps;
  for (let i = 0; i < steps; i++) {
    await page.mouse.wheel(0, step + randNormal(0, 3));
    await sleep(randNormal(60, 20));
  }
}

/**
 * Simulate a human-like mouse wander across the viewport before interacting
 * with the page. This helps behavioural checks (e.g. Cloudflare Turnstile)
 * see pointer activity without clicking anything.
 */
async function simulateMouseMovement(page, options = {}) {
  const { points = 5, duration = 2000, padding = 20 } = options;
  try {
    const viewport = await page.evaluate(() => ({
      width: window.innerWidth || 1280,
      height: window.innerHeight || 720,
    }));
    const availWidth = Math.max(100, viewport.width - padding * 2);
    const availHeight = Math.max(100, viewport.height - padding * 2);
    const stepDuration = Math.max(250, Math.floor(duration / points));

    for (let i = 0; i < points; i++) {
      const targetX = padding + Math.random() * availWidth;
      const targetY = padding + Math.random() * availHeight;
      await humanMove(page, targetX, targetY, { duration: stepDuration });
      await sleep(Math.max(50, randNormal(180, 60)));
    }
  } catch (e) {
    // Never fail the session because of a pointer simulation error.
    throw new Error(`simulateMouseMovement failed: ${e.message}`);
  }
}

module.exports = {
  fittsDuration,
  minimumJerk,
  generatePath,
  humanMove,
  humanClick,
  humanType,
  humanScroll,
  simulateMouseMovement,
  sleep,
};
