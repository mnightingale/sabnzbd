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
tests.visual_regression - Capture every page so two builds can be compared

This module asserts nothing about how the interface looks. It drives the interface into a
fixed state and photographs it; the comparison happens between two runs of this module, on
the branch and on its merge base, so a change of appearance shows up as a diff instead of
as somebody's recollection. Marked "visual" and excluded from the default run.
"""

import os
import random
import re

import pytest
from playwright.sync_api import Page, expect

from tests.visual.capture import THEMES, VIEWPORTS, capture, freeze, settle
from sabnzbd.constants import DEF_ADMIN_DIR, DB_HISTORY_NAME, Status
from tests.testhelper import (
    SAB_CACHE_DIR,
    SAB_HOST,
    SAB_PORT,
    FakeHistoryDB,
    SABnzbdBaseTest,
    create_nzb,
    get_api_result,
)

INI_FILE = "sabnzbd.visual.ini"

# Config pages that render on a plain GET. The wizard and login are captured alongside them
# because they are as much a part of the interface as the settings pages.
STATIC_PAGES = (
    ("config", "config"),
    ("config-general", "config/general"),
    ("config-folders", "config/folders"),
    ("config-switches", "config/switches"),
    ("config-sorting", "config/sorting"),
    ("config-server", "config/server"),
    ("config-categories", "config/categories"),
    ("config-scheduling", "config/scheduling"),
    ("config-rss", "config/rss"),
    ("config-notify", "config/notify"),
    ("config-special", "config/special"),
    ("login", "login"),
    ("wizard-language", "wizard/"),
    ("wizard-server", "wizard/one"),
)

# Every dialog in include_overlays.tmpl. Several are opened from JavaScript with no markup
# that points at them, so they are shown through Bootstrap's own API rather than by hunting
# for a trigger: this is a photograph of how a dialog looks, not a test of what opens it.
GLITTER_MODALS = (
    "modal-options",
    "modal-add-nzb",
    "modal-item-files",
    "modal-delete-queue-job",
    "modal-delete-history-job",
    "modal-retry-job",
    "modal-help",
    "modal-purge-history",
    "modal-custom-pause",
)

# The options dialog is really four pages behind one shell. options-status is left out:
# it runs live diagnostics, so neither its readings nor its height settle between runs.
OPTIONS_TABS = ("options_connections", "options-orphans", "options-interface")


# Enough rows to show the shapes the queue and history render: a plain job, one with a
# category, one that failed. Named rather than generated, so two runs agree.
QUEUE_JOBS = ("Fake.Distro.Linux.ISO-Usenet", "Another.Distro.Linux.ISO-Usenet")
HISTORY_JOBS = (
    ("Completed.Distro.Linux.ISO-Usenet", Status.COMPLETED, "*"),
    ("Categorised.Distro.Linux.ISO-Usenet", Status.COMPLETED, "catA"),
    ("Failed.Distro.Linux.ISO-Usenet", Status.FAILED, "*"),
    ("Extracting.Distro.Linux.ISO-Usenet", Status.EXTRACTING, "catB"),
)
# add_fake_history_job randomises the size and the post-processing flags, which both show
# in the rows, so the sequence is pinned rather than left to chance
HISTORY_RANDOM_SEED = 20260830


def url(path: str = "") -> str:
    return "http://%s:%s/%s" % (SAB_HOST, SAB_PORT, path)


@pytest.fixture(scope="module", autouse=True)
def seed_jobs(run_sabnzbd):
    """Fill the queue and history once, so the rows are captured and not just the frame"""
    get_api_result("pause")
    for mode in ("queue", "history"):
        get_api_result(mode, extra_arguments={"name": "delete", "value": "all", "del_files": 1})

    for name in QUEUE_JOBS:
        nzb_path = create_nzb("basic_rar5")
        get_api_result("addlocalfile", extra_arguments={"name": nzb_path, "nzbname": name})
        os.remove(nzb_path)

    random.seed(HISTORY_RANDOM_SEED)
    with FakeHistoryDB(os.path.join(SAB_CACHE_DIR, DEF_ADMIN_DIR, DB_HISTORY_NAME)) as history:
        for name, status, category in HISTORY_JOBS:
            history.add_fake_history_job(name, status=status, category=category)


@pytest.mark.visual
@pytest.mark.parametrize("viewport", sorted(VIEWPORTS))
@pytest.mark.parametrize("theme", THEMES)
class TestVisual(SABnzbdBaseTest):
    @pytest.fixture(autouse=True)
    def _seed(self, page: Page, viewport, theme):
        """Put the instance into a fixed state and size the camera"""
        width, height = VIEWPORTS[viewport]
        page.set_viewport_size({"width": width, "height": height})
        page.emulate_media(color_scheme=theme)

        # Paused, so the seeded jobs stay where they are put instead of downloading away
        get_api_result("pause")

    def open_glitter(self):
        self.open_page(url("?skip_wizard=1"))
        # isLoaded is set once the first queue and history refresh have come back
        expect(self.page.locator(".main-content")).to_have_class(re.compile("main-content-loaded"))
        freeze(self.page)

    def test_static_pages(self, viewport, theme):
        for name, path in STATIC_PAGES:
            self.open_page(url(path))
            settle(self.page)
            freeze(self.page)
            capture(self.page, name, viewport, theme)

    def test_glitter(self, viewport, theme):
        """The queue, history and warnings all render on the one page in the default layout"""
        self.open_glitter()
        capture(self.page, "glitter", viewport, theme)

    def test_glitter_modals(self, viewport, theme):
        self.open_glitter()
        # Shown without the fade class so each dialog is fully opaque when captured
        self.page.evaluate("jQuery('.modal').removeClass('fade')")

        for modal in GLITTER_MODALS:
            self.page.evaluate("jQuery('#%s').modal('show')" % modal)
            expect(self.page.locator("#" + modal)).to_be_visible()

            if modal == "modal-options":
                for tab in OPTIONS_TABS:
                    self.page.locator("a[href='#%s']" % tab).click()
                    expect(self.page.locator("#" + tab)).to_be_visible()
                    capture(self.page, "%s--%s" % (modal, tab), viewport, theme)
            else:
                capture(self.page, modal, viewport, theme)

            self.page.evaluate("jQuery('#%s').modal('hide')" % modal)
            expect(self.page.locator("#" + modal)).to_be_hidden()
            # Bootstrap drops its backdrop on transitionend, which never arrives once
            # freeze() has turned transitions off, so clear it rather than let the
            # backdrops stack up and darken the page behind each following dialog
            self.page.evaluate("jQuery('.modal-backdrop').remove(); jQuery('body').removeClass('modal-open')")
            expect(self.page.locator(".modal-backdrop")).to_have_count(0)
