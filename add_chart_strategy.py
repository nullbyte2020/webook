import re

filepath = r'D:/webook/kimiko/webapp3/server.js'
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# The chart API strategy to insert before Strategy 1
chart_api_strategy = '''
  // ─────────────────────────────────────────────────────────────────
  // Strategy 0: chart.selectObjects() API (proven working approach from ahlam-a4-bot.js)
  // ─────────────────────────────────────────────────────────────────
  try {
    emitStatus('seats-strategy', 'Strategy 0/5: chart.selectObjects API', { account: username });
    
    // Build section list: target sections first, then common fallbacks
    const sectionsToTry = [];
    if (targetSections && targetSections.length) {
      for (const s of targetSections) {
        const clean = String(s).trim();
        if (clean) sectionsToTry.push(clean);
      }
    }
    if (sectionsToTry.length === 0) {
      sectionsToTry.push('A2', 'B4', 'A3', 'A4', 'A5', 'B3', 'B5', 'B6');
    }

    for (const sectionLabel of sectionsToTry) {
      if (session && session.stopRequested) break;

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
            reserveSeats(username, seats);
            return seats.slice(0, targetCount);
          }
          // If we can't read labels but cart shows tickets, use placeholders
          emitStatus('seats-success', `Chart API selected ${count} tickets in ${sectionLabel}`, { account: username });
          const placeholderSeats = Array.from({ length: targetCount }, (_, i) => `${sectionLabel}-API-${i + 1}`);
          reserveSeats(username, placeholderSeats);
          return placeholderSeats;
        }
      } catch (e) {
        emitStatus('seats-api-error', `chart API error for ${sectionLabel}: ${e.message}`, { account: username });
      }
    }
  } catch (e) {
    emitStatus('seats-strategy-warn', `Strategy 0 failed: ${e.message}`, { account: username });
  }
'''

# Find the marker: "// Strategy 1: bestAvailable via intercepted route (fastest)"
marker = "  // ─────────────────────────────────────────────────────────────────\n  // Strategy 1: bestAvailable via intercepted route (fastest)"

if marker in content:
    # Insert the chart API strategy before Strategy 1
    new_content = content.replace(marker, chart_api_strategy + "\n" + marker)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print("Chart API strategy added successfully before Strategy 1")
else:
    print("Marker not found! Trying alternative...")
    # Try with different whitespace
    marker2 = "Strategy 1: bestAvailable via intercepted route (fastest)"
    if marker2 in content:
        print(f"Found alternative marker: '{marker2}'")
    else:
        print("Alternative marker also not found!")
