import re

filepath = r'D:/webook/kimiko/webapp3/server.js'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# The function to add
new_function = '''
// ------------------------------------------------------------------
// Seat selection via chart API (proven approach from ahlam-a4-bot.js)
// ------------------------------------------------------------------
async function selectSeatsViaWebSocket(page, targetSections, targetCount, username, session) {
  // Strategy 1: Try chart.selectObjects() API (proven working approach)
  const frame = await findChartFrame(page, username);
  if (frame) {
    // Patch limits first
    try { await patchChartLimits(frame); } catch {}

    // Wait for WebSocket to be ready
    const wsReady = await waitForChartWebSocket(frame, 10000);
    if (wsReady) {
      emitStatus('seats-ws-ready', 'Chart WebSocket connected', { account: username });
    }

    // Build section list: target sections first, then common fallbacks
    const sectionsToTry = [];
    if (targetSections && targetSections.length) {
      for (const s of targetSections) {
        const clean = String(s).trim();
        if (clean) sectionsToTry.push(clean);
      }
    }
    // Add fallback sections if no targets specified
    if (sectionsToTry.length === 0) {
      sectionsToTry.push('A2', 'B4', 'A3', 'A4', 'A5', 'B3', 'B5', 'B6');
    }

    emitStatus('seats-strategy', 'Strategy 1/3: chart.selectObjects API', { account: username });

    for (const sectionLabel of sectionsToTry) {
      if (session && session.stopRequested) break;

      // Format section label for chart API
      const fullLabel = sectionLabel.startsWith('Section ') ? sectionLabel : `Section ${sectionLabel}`;
      emitStatus('seats-selecting', `Selecting ${targetCount} seats in ${sectionLabel} via chart API...`, { account: username });

      try {
        // Clear any previous selection
        await frame.evaluate(() => {
          const chart = window.chartRender || window.chart;
          if (chart && typeof chart.clearSelection === 'function') chart.clearSelection();
        });
        await waitFor(500);

        // Select section multiple times to reach target count
        for (let i = 0; i < targetCount; i++) {
          const res = await frame.evaluate((lbl) => {
            const chart = window.chartRender || window.chart;
            if (!chart || typeof chart.selectObjects !== 'function') return { noChart: true };
            try {
              chart.selectObjects([lbl]);
              return { ok: true };
            } catch (e) {
              return { ok: false, error: e.message };
            }
          }, fullLabel);

          if (res.noChart) {
            emitStatus('seats-no-chart', 'chart.selectObjects not available', { account: username });
            break;
          }
          await waitFor(300);
        }

        // Wait for UI to update
        await waitFor(1200);

        // Verify selection by checking ticket count on page
        const count = await getTicketCount(page);
        emitStatus('seats-verify', `After chart API selection: cart shows ${count} tickets`, { account: username });

        if (count >= targetCount) {
          // Try to read actual seat labels from the page
          const seats = await readSelectedSeatLabels(page, targetSections, targetCount);
          if (seats.length >= targetCount) {
            emitStatus('seats-success', `Chart API selected ${seats.length} seats in ${sectionLabel}`, { account: username, seats });
            return seats.slice(0, targetCount);
          }
          // If we can't read labels but cart shows tickets, return placeholder
          emitStatus('seats-success', `Chart API selected ${count} tickets in ${sectionLabel} (labels unreadable)`, { account: username });
          return Array.from({ length: targetCount }, (_, i) => `${sectionLabel}-API-${i + 1}`);
        }
      } catch (e) {
        emitStatus('seats-api-error', `chart API error for ${sectionLabel}: ${e.message}`, { account: username });
      }
    }
  }

  // Strategy 2: Try intercepted WebSocket route (bestAvailable)
  emitStatus('seats-strategy', 'Strategy 2/3: bestAvailable via intercepted route', { account: username });
  try {
    const routeHeld = await attemptRouteHoldWithCartVerify(page, targetSections, targetCount, username, 8000);
    if (routeHeld.length >= targetCount) {
      emitStatus('seats-success', `Route held ${routeHeld.length} seats`, { account: username, seats: routeHeld });
      return routeHeld.slice(0, targetCount);
    }
  } catch (e) {
    emitStatus('seats-route-error', e.message, { account: username });
  }

  // Strategy 3: Try fast hold via route without cart verify
  emitStatus('seats-strategy', 'Strategy 3/3: fast hold via route', { account: username });
  try {
    const fastHeld = await tryFastHoldViaRoute(page, targetSections, targetCount, username);
    if (fastHeld.length >= targetCount) {
      emitStatus('seats-success', `Fast route held ${fastHeld.length} seats`, { account: username, seats: fastHeld });
      return fastHeld.slice(0, targetCount);
    }
  } catch (e) {
    emitStatus('seats-fast-error', e.message, { account: username });
  }

  emitStatus('seats-failed', 'All seat selection strategies failed', { account: username });
  return [];
}
'''

# Find the line "async function runSession(account) {" and insert before it
marker = 'async function runSession(account) {'
if marker in content:
    # Find the first occurrence of the marker
    pos = content.find(marker)
    # Insert the new function before it
    new_content = content[:pos] + new_function + content[pos:]
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"Function added successfully before '{marker}'")
else:
    print(f"Marker '{marker}' not found in file!")
