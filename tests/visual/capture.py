#!/usr/bin/python3 -OO
# Copyright 2007-2026 by The SABnzbd-Team (sabnzbd.org)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
tests.visual.capture - Turning a page into a comparable screenshot

Screenshots are only worth anything if the same page produces the same bytes twice, so
everything here exists to remove a source of difference: the viewports and themes are
fixed, animations and the caret are stopped, and the handful of elements that legitimately
change between two runs (clocks, speeds, free space) are painted over rather than fought.
"""

import os

from playwright.sync_api import Page, TimeoutError as PlaywrightTimeoutError

# Screenshots are captured at each of these, so a change is caught at the width where it
# happens. 375 is the phone layout glitter.mobile.css targets, 768 its breakpoint, 1280 desktop.
VIEWPORTS = {"mobile": (375, 812), "tablet": (768, 1024), "desktop": (1280, 1024)}

# "auto" is the default and follows the browser, so it is captured under both preferences
# to exercise the prefers-color-scheme path that the colorscheme stylesheet relies on.
THEMES = ("light", "dark")

# Content that legitimately differs between two runs of the same code. Painted over before
# the screenshot rather than excluded, so a layout change around them is still caught.
VOLATILE_SELECTORS = (
    # Free space and speed differ between two machines
    ".info-container",  # free space, both the figure and the text beside it
    "[data-bind*='speedText']",
    # "Next scan at <clock time>" on the RSS settings page
    "body.RSS span.config.narrow",
    # The table on the Config index: version and commit, uptime, paths, Python and OpenSSL
    # versions, which tools are installed
    "body.Config .padTable table",
)

STYLE_FREEZE = """
    *, *::before, *::after {
        animation: none !important;
        transition: none !important;
        caret-color: transparent !important;
    }
    html { scroll-behavior: auto !important; }
"""


def output_dir() -> str:
    """Where screenshots are written. Set by the workflow to keep the two captures apart."""
    path = os.environ.get("SAB_VISUAL_OUT", os.path.join("tests", "output", "screenshots"))
    os.makedirs(path, exist_ok=True)
    return path


def settle(page: Page, timeout: int = 5000):
    """Give in-flight requests a chance to finish, without depending on them finishing.

    Some pages never reach network-idle at all, so this is a best effort: waiting longer
    would only trade one page rendering late for the whole capture failing.
    """
    try:
        page.wait_for_load_state("networkidle", timeout=timeout)
    except PlaywrightTimeoutError:
        pass


def freeze(page: Page):
    """Stop the page moving under the camera.

    Called once per navigation rather than per screenshot: a dialog opened before the
    transitions are off will still be fading when it is captured.
    """
    page.add_style_tag(content=STYLE_FREEZE)
    # A focused field draws a caret and a focus ring, which differ between runs
    page.evaluate("document.activeElement && document.activeElement.blur()")


def capture(page: Page, name: str, viewport: str, theme: str):
    """Write one screenshot, masking whatever cannot be made deterministic"""
    # The pointer stays where the last click left it, so park it clear of the page and drop
    # anything it was hovering: a tooltip left open is a difference between two runs
    page.mouse.move(0, 0)
    page.evaluate("document.querySelectorAll('.tooltip, .popover').forEach(e => e.remove())")

    masks = [page.locator(sel) for sel in VOLATILE_SELECTORS]
    page.screenshot(
        path=os.path.join(output_dir(), "%s--%s--%s.png" % (name, viewport, theme)),
        full_page=True,
        animations="disabled",
        caret="hide",
        mask=masks,
        mask_color="#ff00ff",
    )
