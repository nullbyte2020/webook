#!/usr/bin/env python3
"""Safely patch server.js with the required changes."""

import re

with open('D:/webook/kimiko/webapp3/server.js', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Replace patchChartLimits function
old_patch = '''async function patchChartLimits(frame) {
  return frame.evaluate(() => {
    const set100 = (obj, keys) => {
      if (!obj) return;
      for (const key of keys) {
        if (typeof obj[key] === 'number') obj[key] = 100;
      }
    };
    const keys = ['maxNumberOfHolds', 'maxSelectedObjects', 'maxNumberOfSelectedObjects', 'maxObjects', 'maxSeats'];
    set100(window.chartState, keys);
    set100(window.currentChartConfig, keys);
    if (window.chartRender) {
      set100(window.chartRender.state, keys);
      set100(window.chartRender.config, keys);
    }
    if (window.chart) {
      set100(window.chart.state, keys);
      set100(window.chart.config, keys);
    }
    return true;
  });
}'''

new_patch = '''async function patchChartLimits(frame) {
  return frame.evaluate(() => {
    const set100 = (obj, keys) => {
      if (!obj) return;
      for (const key of keys) {
        if (typeof obj[key] === 'number') obj[key] = 100;
        if (typeof obj[key] === 'string') obj[key] = '100';
      }
    };
    const keys = ['maxNumberOfHolds', 'maxSelectedObjects', 'maxNumberOfSelectedObjects', 'maxObjects', 'maxSeats', 'selectionLimit', 'holdLimit', 'maxHold', 'maxSelection', 'maxPerOrder', 'max_per_order', 'maxTickets', 'maxTicketCount', 'ticketLimit', 'purchaseLimit'];
    set100(window.chartState, keys);
    set100(window.currentChartConfig, keys);
    if (window.chartRender) {
      set100(window.chartRender.state, keys);
      set100(window.chartRender.config, keys);
      if (window.chartRender._config) set100(window.chartRender._config, keys);
      if (window.chartRender.options) set100(window.chartRender.options, keys);
    }
    if (window.chart) {
      set100(window.chart.state, keys);
      set100(window.chart.config, keys);
      if (window.chart._config) set100(window.chart._config, keys);
      if (window.chart.options) set100(window.chart.options, keys);
    }
    if (window.seatsio && window.seatsio.config) set100(window.seatsio.config, keys);
    if (window.seatsioConfig) set100(window.seatsioConfig, keys);
    try {
      const chart = window.chart || window.chartRender;
      if (chart && chart.state) {
        if (!chart.state.selectedObjects) chart.state.selectedObjects = [];
        if (chart.state._selectionCount) chart.state._selectionCount = 0;
        if (chart.state._holdCount) chart.state._holdCount = 0;
      }
    } catch (e) {}
    return true;
  });
}'''

if old_patch in content:
    content = content.replace(old_patch, new_patch)
    print("OK patchChartLimits updated")
else:
    print("FAIL patchChartLimits old pattern not found")

# 2. Replace readSelectedSeatLabels function
old_read = '''async function readSelectedSeatLabels(page, targetSections, targetCount) {
  // Try to read selected objects from the chart iframe
  const frames = page.frames().filter(f => /seatcloud\\.com/.test(f.url() || ''));
  for (const frame of frames) {
    try {
      const labels = await frame.evaluate(() => {
        const sel = window.chartState?.selectedObjects || window.chartRender?.selectedObjects || window.chart?.selectedObjects;
        if (Array.isArray(sel)) {
          return sel.map(o => typeof o === 'string' ? o : (o.label || o.objectId || o.id || '')).filter(Boolean);
        }
        return [];
      });
      if (labels.length >= targetCount) return labels.slice(0, targetCount);
    } catch {}
  }
  // Fallback: look for seat patterns like A4-D-1 in page text
  try {
    const text = await page.evaluate(() => document.body.innerText || '');
    // Match seat labels like A4-C-1, A4-C-12, B5-A-3
    const matches = text.match(/\\b[A-Z]\\d+[-–][A-Z][-–]\\d+\\b/g) || [];
    if (matches.length >= targetCount) return matches.slice(0, targetCount);
  } catch {}
  return [];
}'''

new_read = '''async function readSelectedSeatLabels(page, targetSections, targetCount) {
  // STRATEGY 1: Read from the API-held seats (source of truth)
  try {
    const frame = await findChartFrame(page);
    if (frame) {
      const keys = await frame.evaluate(() => ({
        workspaceKey: window.chartState?.workspaceKey || window.currentChartConfig?.workspaceKey,
        eventKey: window.chartState?.eventKey || window.currentChartConfig?.eventKey,
      })).catch(() => ({}));
      if (keys.workspaceKey && keys.eventKey) {
        const holdToken = await readChartHoldToken(page);
        if (holdToken) {
          const held = await verifyHeldSeatsViaApi(page, holdToken, []);
          if (held.length >= targetCount) {
            return held.slice(0, targetCount);
          }
        }
      }
    }
  } catch (e) {
    fileLog('WARN', `readSelectedSeatLabels API read failed: ${e.message}`);
  }

  // STRATEGY 2: Try to read selected objects from the chart iframe state
  const frames = page.frames().filter(f => /seatcloud\\.com/.test(f.url() || ''));
  for (const frame of frames) {
    try {
      const labels = await frame.evaluate(() => {
        const sel = window.chartState?.selectedObjects || window.chartRender?.selectedObjects || window.chart?.selectedObjects;
        if (Array.isArray(sel)) {
          return sel.map(o => typeof o === 'string' ? o : (o.label || o.objectId || o.id || '')).filter(Boolean);
        }
        return [];
      });
      if (labels.length >= targetCount) return labels.slice(0, targetCount);
    } catch {}
  }

  // STRATEGY 3: Fallback - look for seat patterns like A4-D-1 in page text
  try {
    const text = await page.evaluate(() => document.body.innerText || '');
    const matches = text.match(/\\b[A-Z]\\d+[-–][A-Z][-–]\\d+\\b/g) || [];
    if (matches.length >= targetCount) return matches.slice(0, targetCount);
  } catch {}

  return [];
}'''

if old_read in content:
    content = content.replace(old_read, new_read)
    print("OK readSelectedSeatLabels updated")
else:
    print("FAIL readSelectedSeatLabels old pattern not found")

# 3. Replace syncChartSelection function
old_sync = '''// Sync the chart UI so the bot's own browser shows seats it has successfully
// held on the server. The intercepted WebSocket route holds seats server-side,
// but the chart iframe may not update its internal selection state. This function
// pushes the held labels into the chart's selection state and triggers a redraw.
async function syncChartSelection(pageOrFrame, seats) {
  try {
    const frame = pageOrFrame && pageOrFrame.evaluate
      ? await findChartFrame(pageOrFrame)
      : pageOrFrame;
    if (!frame) return;

    const seatLabels = seats.map(String);
    const result = await frame.evaluate((labels) => {
      const log = [];
      const chart = window.chart || window.chartRender;

      // Helper to normalize a seat label to a selection object
      const toObj = (label) => {
        const o = { label, objectId: label, id: label };
        // seats.io sometimes expects an 'id' or a 'label' depending on config
        return o;
      };

      // Method 1: use the public seats.io selectObjects API
      if (chart && typeof chart.selectObjects === 'function') {
        try {
          chart.selectObjects(labels);
          log.push('selectObjects');
        } catch (e) {
          log.push('selectObjects-error:' + (e.message || e));
        }
      }

      // Method 2: push into internal selectedObjects array
      try {
        const target = chart || window.chartState;
        if (target) {
          if (!target.selectedObjects) target.selectedObjects = [];
          const existing = target.selectedObjects.map(o => typeof o === 'string' ? o : (o.label || o.objectId || o.id));
          for (const label of labels) {
            if (!existing.includes(label)) {
              target.selectedObjects.push(toObj(label));
              existing.push(label);
            }
          }
          log.push('forced-state:' + target.selectedObjects.length);
        }
      } catch (e) {
        log.push('force-error:' + (e.message || e));
      }

      // Trigger a redraw so the new selection becomes visible
      if (chart && typeof chart.redraw === 'function') {
        try { chart.redraw(); log.push('redraw'); } catch (e) {}
      }
      if (window.chartRender && typeof window.chartRender.redraw === 'function') {
        try { window.chartRender.redraw(); log.push('render-redraw'); } catch (e) {}
      }
      if (window.chart && typeof window.chart.rerender === 'function') {
        try { window.chart.rerender(); log.push('rerender'); } catch (e) {}
      }

      // Final verification: how many selected objects does the chart report?
      let reported = 0;
      try {
        const sel =
          (chart && chart.state && chart.state.selectedObjects) ||
          (window.chartState && window.chartState.selectedObjects) ||
          [];
        reported = sel.length;
      } catch {}
      log.push('reported=' + reported);
      return log;
    }, seatLabels);

    fileLog('INFO', `syncChartSelection: ${result.join(', ')}`);
  } catch (e) {
    fileLog('WARN', `syncChartSelection error: ${e.message}`);
  }
}'''

new_sync = '''// Sync the chart UI so the bot's own browser shows seats it has successfully
// held on the server. The intercepted WebSocket route holds seats server-side,
// but the chart iframe may not update its internal selection state. This function
// pushes the held labels into the chart's selection state and triggers a redraw.
async function syncChartSelection(pageOrFrame, seats) {
  try {
    const frame = pageOrFrame && pageOrFrame.evaluate
      ? await findChartFrame(pageOrFrame)
      : pageOrFrame;
    if (!frame) return;

    const seatLabels = seats.map(String);
    const result = await frame.evaluate((labels) => {
      const log = [];
      const chart = window.chart || window.chartRender;

      // Helper to normalize a seat label to a selection object
      const toObj = (label) => {
        const o = { label, objectId: label, id: label };
        return o;
      };

      // Method 1: use the public seats.io selectObjects API
      if (chart && typeof chart.selectObjects === 'function') {
        try {
          chart.selectObjects(labels);
          log.push('selectObjects');
        } catch (e) {
          log.push('selectObjects-error:' + (e.message || e));
        }
      }

      // Method 2: Force-add to internal selectedObjects array (bypasses UI limits)
      try {
        const target = chart || window.chartState;
        if (target) {
          if (!target.selectedObjects) target.selectedObjects = [];
          const existing = target.selectedObjects.map(o => typeof o === 'string' ? o : (o.label || o.objectId || o.id));
          for (const label of labels) {
            if (!existing.includes(label)) {
              target.selectedObjects.push(toObj(label));
              existing.push(label);
            }
          }
          log.push('forced-state:' + target.selectedObjects.length);
        }
      } catch (e) {
        log.push('force-error:' + (e.message || e));
      }

      // Method 3: Directly manipulate chart state if available
      try {
        if (chart && chart.state) {
          if (!chart.state.selectedObjects) chart.state.selectedObjects = [];
          const existing = chart.state.selectedObjects.map(o => typeof o === 'string' ? o : (o.label || o.objectId || o.id));
          for (const label of labels) {
            if (!existing.includes(label)) {
              chart.state.selectedObjects.push(toObj(label));
              existing.push(label);
            }
          }
          log.push('state-push:' + chart.state.selectedObjects.length);
        }
      } catch (e) {
        log.push('state-error:' + (e.message || e));
      }

      // Trigger a redraw so the new selection becomes visible
      if (chart && typeof chart.redraw === 'function') {
        try { chart.redraw(); log.push('redraw'); } catch (e) {}
      }
      if (window.chartRender && typeof window.chartRender.redraw === 'function') {
        try { window.chartRender.redraw(); log.push('render-redraw'); } catch (e) {}
      }
      if (window.chart && typeof window.chart.rerender === 'function') {
        try { window.chart.rerender(); log.push('rerender'); } catch (e) {}
      }

      // Final verification: how many selected objects does the chart report?
      let reported = 0;
      try {
        const sel =
          (chart && chart.state && chart.state.selectedObjects) ||
          (window.chartState && window.chartState.selectedObjects) ||
          [];
        reported = sel.length;
      } catch {}
      log.push('reported=' + reported);
      return log;
    }, seatLabels);

    fileLog('INFO', `syncChartSelection: ${result.join(', ')}`);
  } catch (e) {
    fileLog('WARN', `syncChartSelection error: ${e.message}`);
  }
}'''

if old_sync in content:
    content = content.replace(old_sync, new_sync)
    print("OK syncChartSelection updated")
else:
    print("FAIL syncChartSelection old pattern not found")

# 4. Add patchChartLimits calls before Strategy 1 and Strategy 2
old_strategy1 = '''  // ─────────────────────────────────────────────────────────────────
  // Strategy 1: bestAvailable via intercepted route (fastest)
  // ─────────────────────────────────────────────────────────────────
  try {
    emitStatus('seats-strategy', 'Strategy 1/4: bestAvailable via intercepted route', { account: username });
    const routeHeld = await sendBestAvailableViaRoute(page, targetCount, [], 10000);'''

new_strategy1 = '''  // ─────────────────────────────────────────────────────────────────
  // Strategy 1: bestAvailable via intercepted route (fastest)
  // ─────────────────────────────────────────────────────────────────
  try {
    emitStatus('seats-strategy', 'Strategy 1/4: bestAvailable via intercepted route', { account: username });
    try { await patchChartLimits(frame); } catch {}
    const routeHeld = await sendBestAvailableViaRoute(page, targetCount, [], 10000);'''

if old_strategy1 in content:
    content = content.replace(old_strategy1, new_strategy1)
    print("OK Strategy 1 patchChartLimits call added")
else:
    print("FAIL Strategy 1 old pattern not found")

old_strategy2 = '''  // ─────────────────────────────────────────────────────────────────
  // Strategy 2: specific contiguous groups via intercepted route
  // ─────────────────────────────────────────────────────────────────
  try {
    emitStatus('seats-strategy', 'Strategy 2/4: specific groups via intercepted route', { account: username });
    for (const sectionLabel of sections) {'''

new_strategy2 = '''  // ─────────────────────────────────────────────────────────────────
  // Strategy 2: specific contiguous groups via intercepted route
  // ─────────────────────────────────────────────────────────────────
  try {
    emitStatus('seats-strategy', 'Strategy 2/4: specific groups via intercepted route', { account: username });
    try { await patchChartLimits(frame); } catch {}
    for (const sectionLabel of sections) {'''

if old_strategy2 in content:
    content = content.replace(old_strategy2, new_strategy2)
    print("OK Strategy 2 patchChartLimits call added")
else:
    print("FAIL Strategy 2 old pattern not found")

# Write the patched file
with open('D:/webook/kimiko/webapp3/server.js', 'w', encoding='utf-8') as f:
    f.write(content)

print("\nDone. File written.")
