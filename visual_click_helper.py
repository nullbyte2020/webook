#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyAutoGUI helper for visually clicking seats / sections on screen.

Use this as a fallback when Playwright API/WebSocket/iframe bridge approaches
do not work for a specific event (e.g. Ahlam visual map where the chart is a
canvas and only real mouse clicks on the rendered area are honored).

Prerequisites:
    pip install pyautogui opencv-python

How to capture template images:
    1. Open the event chart at the exact size/position you will run the bot.
    2. Use Snipping Tool / ShareX to crop a small image of the target.
       - For a section label like A4, crop just the green A4 box + a little
         surrounding background so PyAutoGUI can match it reliably.
       - For a seat, crop one empty/unselected seat circle/square.
    3. Save as PNG in the same folder as the bot, e.g.:
         section_a4.png
         seat_empty.png
    4. Pass the path to click_section() / click_seats().

Notes:
    - The browser window must be visible and not minimized.
    - The chart must be in the same position each run; otherwise use
      locateOnScreen with a region or re-capture the template.
    - confidence requires opencv-python. Without it, PyAutoGUI falls back to
      exact pixel matching which is very fragile.
"""

from __future__ import annotations

import os
import time
from typing import List, Optional, Tuple

# Optional dependency guard: bot can still import the module even if the user
# has not installed pyautogui yet; only the actual click functions fail loudly.
try:
    import pyautogui as pg
except Exception as _exc:  # pragma: no cover
    pg = None  # type: ignore


def _check():
    if pg is None:
        raise RuntimeError(
            "pyautogui is not installed. Run:  pip install pyautogui opencv-python"
        )


def take_screenshot(path: str) -> str:
    """Save a full-screen screenshot to *path*."""
    _check()
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    pg.screenshot(path)
    return path


def get_mouse_position() -> Tuple[int, int]:
    """Return current mouse (x, y)."""
    _check()
    return pg.position()  # type: ignore


def locate_center(
    image_path: str,
    confidence: float = 0.8,
    region: Optional[Tuple[int, int, int, int]] = None,
    grayscale: bool = True,
) -> Optional[Tuple[int, int]]:
    """
    Find *image_path* on screen and return the center point (x, y) or None.

    Args:
        image_path: path to a PNG/JPG template image.
        confidence: OpenCV match confidence (0.0 - 1.0). Requires opencv-python.
        region: optional (left, top, width, height) search region.
        grayscale: convert to grayscale for faster/more reliable matching.
    """
    _check()
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Template image not found: {image_path}")
    try:
        box = pg.locateOnScreen(
            image_path, confidence=confidence, region=region, grayscale=grayscale
        )
        if box is None:
            return None
        return pg.center(box)
    except Exception as exc:
        # Common failure: opencv not installed or confidence not supported.
        raise RuntimeError(f"locateOnScreen failed for {image_path}: {exc}")


def find_all_centers(
    image_path: str,
    confidence: float = 0.8,
    region: Optional[Tuple[int, int, int, int]] = None,
    grayscale: bool = True,
) -> List[Tuple[int, int]]:
    """Return centers of all occurrences of *image_path* on screen."""
    _check()
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Template image not found: {image_path}")
    try:
        boxes = list(
            pg.locateAllOnScreen(
                image_path, confidence=confidence, region=region, grayscale=grayscale
            )
        )
        return [pg.center(b) for b in boxes]
    except Exception as exc:
        raise RuntimeError(f"locateAllOnScreen failed for {image_path}: {exc}")


def click_point(
    x: int,
    y: int,
    clicks: int = 1,
    interval: float = 0.05,
    button: str = "left",
    duration: float = 0.2,
) -> None:
    """Move the mouse to (x, y) and click."""
    _check()
    pg.moveTo(x, y, duration=duration)
    time.sleep(0.05)
    pg.click(clicks=clicks, interval=interval, button=button)


def click_image(
    image_path: str,
    confidence: float = 0.8,
    region: Optional[Tuple[int, int, int, int]] = None,
    clicks: int = 1,
    interval: float = 0.05,
    grayscale: bool = True,
    move_duration: float = 0.2,
) -> Optional[Tuple[int, int]]:
    """
    Find *image_path* on screen and click its center.

    Returns the clicked point, or None if the image was not found.
    """
    center = locate_center(image_path, confidence, region, grayscale)
    if center is None:
        return None
    click_point(center[0], center[1], clicks, interval, move_duration=move_duration)
    return center


def click_all_images(
    image_path: str,
    confidence: float = 0.8,
    region: Optional[Tuple[int, int, int, int]] = None,
    max_clicks: int = 10,
    interval: float = 0.15,
    grayscale: bool = True,
) -> List[Tuple[int, int]]:
    """
    Find all occurrences of *image_path* and click each one once.

    Useful for clicking multiple empty seats in one go.
    """
    centers = find_all_centers(image_path, confidence, region, grayscale)
    clicked: List[Tuple[int, int]] = []
    for i, (x, y) in enumerate(centers):
        if i >= max_clicks:
            break
        click_point(x, y, move_duration=0.15)
        clicked.append((x, y))
        time.sleep(interval)
    return clicked


def click_section(
    section_image_path: str,
    confidence: float = 0.8,
    region: Optional[Tuple[int, int, int, int]] = None,
    double_click: bool = False,
) -> Optional[Tuple[int, int]]:
    """
    Click a section label/box on the chart (e.g. the green A4 box).

    Returns the clicked point or None.
    """
    center = locate_center(section_image_path, confidence, region)
    if center is None:
        return None
    _check()
    pg.moveTo(center[0], center[1], duration=0.2)
    time.sleep(0.05)
    if double_click:
        pg.doubleClick()
    else:
        pg.click()
    return center


def click_seats(
    seat_image_path: str,
    target_count: int = 5,
    confidence: float = 0.8,
    region: Optional[Tuple[int, int, int, int]] = None,
    interval: float = 0.15,
) -> List[Tuple[int, int]]:
    """
    Click up to *target_count* seats that match *seat_image_path*.

    The template should be an empty/unselected seat; after a seat is clicked it
    usually changes color, so it will no longer match the template.
    """
    return click_all_images(
        seat_image_path,
        confidence=confidence,
        region=region,
        max_clicks=target_count,
        interval=interval,
    )


def scroll_chart(x: int, y: int, clicks: int = 3, direction: str = "up") -> None:
    """Move the mouse to (x, y) and scroll the wheel."""
    _check()
    pg.moveTo(x, y, duration=0.2)
    amount = clicks if direction == "up" else -clicks
    pg.scroll(amount, x, y)


def safe_region_around(
    center: Tuple[int, int],
    width: int = 400,
    height: int = 400,
    screen_size: Optional[Tuple[int, int]] = None,
) -> Tuple[int, int, int, int]:
    """
    Build a region (left, top, width, height) around *center* clipped to screen.
    Useful for narrowing seat search to one section after the section label was
    found.
    """
    _check()
    if screen_size is None:
        screen_size = pg.size()
    sx, sy = screen_size
    left = max(0, center[0] - width // 2)
    top = max(0, center[1] - height // 2)
    # Ensure region does not exceed screen bounds; PyAutoGUI requires this.
    w = min(width, sx - left)
    h = min(height, sy - top)
    return (left, top, w, h)


def get_screen_size() -> Tuple[int, int]:
    """Return (width, height) of the primary monitor."""
    _check()
    return pg.size()


# Convenience helpers for the Ahlam A4 flow ---------------------------------

AHLAM_A4_DEFAULT_COORDS = (0.60, 0.58)  # viewport-relative fallback


def click_ahlam_a4_section(
    template_path: str = "section_a4.png",
    confidence: float = 0.8,
    fallback_relative: Tuple[float, float] = AHLAM_A4_DEFAULT_COORDS,
) -> Optional[Tuple[int, int]]:
    """
    Click the A4 section on the Ahlam chart.

    If *template_path* exists and is found, click it. Otherwise fall back to a
    fixed screen coordinate computed from the primary monitor size.
    """
    _check()
    if os.path.isfile(template_path):
        point = click_section(template_path, confidence=confidence)
        if point:
            return point
    # Fallback: fixed relative coordinate.
    sw, sh = pg.size()
    x = int(sw * fallback_relative[0])
    y = int(sh * fallback_relative[1])
    click_point(x, y)
    return (x, y)


def click_ahlam_a4_seats(
    seat_template_path: str = "seat_empty.png",
    target_count: int = 5,
    confidence: float = 0.8,
    region: Optional[Tuple[int, int, int, int]] = None,
) -> List[Tuple[int, int]]:
    """Click up to *target_count* empty seats inside section A4."""
    return click_seats(seat_template_path, target_count, confidence, region)


if __name__ == "__main__":
    # Simple CLI sanity check.
    print("PyAutoGUI available:", pg is not None)
    if pg:
        print("Screen size:", get_screen_size())
        print("Mouse position:", get_mouse_position())
        print("Move mouse to top-left corner to abort.")
