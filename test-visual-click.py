#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Standalone test for the PyAutoGUI visual-click helper.

Usage:
    1. Put template images in this folder:
         - section_a4.png  (a crop of the A4 section box on the chart)
         - seat_empty.png  (a crop of one empty seat)
    2. Open the Webook event chart so it is visible on your primary monitor.
    3. Run:  python test-visual-click.py

Environment variables:
    SECTION_TEMPLATE    path to section image (default section_a4.png)
    SEAT_TEMPLATE       path to seat image (default seat_empty.png)
    VISUAL_CONFIDENCE   float 0-1 (default 0.8)
    TARGET_COUNT        number of seats to click (default 5)
    VISUAL_REGION       "left,top,width,height" search region (optional)
"""

import os
import sys
import time

import visual_click_helper as vch


def main():
    try:
        vch._check()
    except RuntimeError as e:
        print(e)
        sys.exit(1)

    section_template = os.environ.get("SECTION_TEMPLATE", "section_a4.png")
    seat_template = os.environ.get("SEAT_TEMPLATE", "seat_empty.png")
    confidence = float(os.environ.get("VISUAL_CONFIDENCE", "0.8"))
    target_count = int(os.environ.get("TARGET_COUNT", "5"))
    region_raw = os.environ.get("VISUAL_REGION")
    region = None
    if region_raw:
        try:
            region = tuple(int(p.strip()) for p in region_raw.split(","))
            if len(region) != 4:
                region = None
        except Exception:
            region = None

    print("Screen size:", vch.get_screen_size())
    print("Move mouse to top-left corner to abort at any time.")
    print(f"Config: section={section_template}, seat={seat_template}, confidence={confidence}, count={target_count}")

    # Countdown so user can focus the browser window.
    for i in range(3, 0, -1):
        print(f"Starting in {i}...")
        time.sleep(1)

    section_point = None
    if os.path.isfile(section_template):
        print(f"Looking for section template: {section_template}")
        section_point = vch.click_section(section_template, confidence=confidence, region=region)
        if section_point:
            print(f"Clicked section at {section_point}")
            time.sleep(1.5)
            region = vch.safe_region_around(section_point, width=500, height=500)
        else:
            print("Section template not found on screen.")
    else:
        print(f"Section template not found on disk: {section_template}")

    clicked_seats = []
    if os.path.isfile(seat_template):
        print(f"Looking for seat template: {seat_template}")
        clicked_seats = vch.click_seats(seat_template, target_count=target_count, confidence=confidence, region=region)
        print(f"Clicked {len(clicked_seats)} seats: {clicked_seats}")
    else:
        print(f"Seat template not found on disk: {seat_template}")

    # Save a screenshot for debugging.
    shot_path = "visual-click-test-result.png"
    vch.take_screenshot(shot_path)
    print(f"Screenshot saved: {shot_path}")


if __name__ == "__main__":
    main()
