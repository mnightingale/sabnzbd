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
tests.test_directunpacker - Testing functions in directunpacker.py
"""

from types import SimpleNamespace

import pytest

import sabnzbd.newsunpack
from sabnzbd.directunpacker import DirectUnpacker


@pytest.mark.config({"direct_unpack": True})
class TestCheckRequirements:
    @staticmethod
    def make_unpacker(bytes_par2: int, par2packs: dict) -> DirectUnpacker:
        nzo = SimpleNamespace(
            first_articles=[], bytes_par2=bytes_par2, par2packs=par2packs, unpack=True, bad_articles=0
        )
        return DirectUnpacker(nzo)

    @pytest.fixture(autouse=True)
    def no_rar_problem(self, monkeypatch):
        monkeypatch.setattr(sabnzbd.newsunpack, "RAR_PROBLEM", False)

    def test_waits_for_par2(self):
        assert not self.make_unpacker(bytes_par2=1000, par2packs={}).check_requirements()

    def test_starts_once_par2_parsed(self):
        assert self.make_unpacker(bytes_par2=1000, par2packs={"set": {}}).check_requirements()

    def test_starts_without_par2(self):
        assert self.make_unpacker(bytes_par2=0, par2packs={}).check_requirements()
