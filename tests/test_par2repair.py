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
tests.test_par2repair - mapping article state onto par2 blocks
"""

import os
import sys
from unittest import mock

import pytest

import sabnzbd.cfg as cfg
from sabnzbd.constants import MEBI
from sabnzbd.par2repair import _blocks_from_articles, article_backed_blocks, par2_memory_limit


class FakeArticle:
    def __init__(self, data_begin, data_size, good=True, on_disk=True):
        self.data_begin = data_begin
        self.data_size = data_size
        # crc32 is None when the decoded data did not match the yEnc trailer
        self.crc32 = 0xDEADBEEF if good else None
        self.on_disk = on_disk


class FakeNzf:
    def __init__(self, articles):
        self.decodetable = articles


@pytest.fixture
def datafile(tmp_path):
    def _make(size):
        path = tmp_path / "data.bin"
        path.write_bytes(b"\0" * size)
        return str(path)

    return _make


BLOCKSIZE = 64


class TestBlocksFromArticles:
    def test_all_articles_good(self, datafile):
        # 4 articles of 160 bytes covering a 640 byte file, 10 blocks of 64
        articles = [FakeArticle(offset, 160) for offset in (0, 160, 320, 480)]
        blocks = _blocks_from_articles(FakeNzf(articles), BLOCKSIZE, 10, datafile(640))
        assert blocks == [True] * 10

    def test_missing_article_needs_no_size_guess(self, datafile):
        """A missing article has no data_begin, and does not need one.

        Offsets are absolute, so a gap between two good articles is simply uncovered
        and every block overlapping it is left for par2 to check. Nothing has to be
        inferred about the length of what is missing.
        """
        articles = [
            FakeArticle(0, 160),
            FakeArticle(None, None, good=False),  # never arrived
            FakeArticle(320, 160),
            FakeArticle(480, 160),
        ]
        blocks = _blocks_from_articles(FakeNzf(articles), BLOCKSIZE, 10, datafile(640))

        # Blocks 0-1 sit inside the first article, 5-9 inside the last two.
        # Blocks 2, 3 and 4 touch the hole at 160-320 and are not trusted.
        assert blocks == [True, True, False, False, False, True, True, True, True, True]

    def test_trailing_articles_missing(self, datafile):
        """Nothing after the last good article is trusted, however long the file is."""
        articles = [FakeArticle(0, 160), FakeArticle(160, 160), FakeArticle(None, None, good=False)]
        blocks = _blocks_from_articles(FakeNzf(articles), BLOCKSIZE, 10, datafile(640))
        assert blocks == [True] * 5 + [False] * 5

    def test_article_present_but_checksum_failed(self, datafile):
        """A decoded article whose CRC did not match is bad, not unknown."""
        articles = [FakeArticle(0, 160), FakeArticle(160, 160, good=False), FakeArticle(320, 320)]
        blocks = _blocks_from_articles(FakeNzf(articles), BLOCKSIZE, 10, datafile(640))
        assert blocks == [True, True, False, False, False, True, True, True, True, True]

    def test_article_not_on_disk(self, datafile):
        """Decoded and checksummed, but never written out."""
        articles = [FakeArticle(0, 320), FakeArticle(320, 320, on_disk=False)]
        blocks = _blocks_from_articles(FakeNzf(articles), BLOCKSIZE, 10, datafile(640))
        assert blocks == [True] * 5 + [False] * 5

    def test_block_spanning_two_articles(self, datafile):
        """Consecutive articles are merged, so a block across the join still counts."""
        # 96-byte articles against 64-byte blocks: every boundary is straddled
        articles = [FakeArticle(offset, 96) for offset in range(0, 640, 96)]
        articles[-1] = FakeArticle(576, 64)
        blocks = _blocks_from_articles(FakeNzf(articles), BLOCKSIZE, 10, datafile(640))
        assert blocks == [True] * 10

    def test_short_final_block(self, datafile):
        """par2 pads the last block, so only the bytes the file has need covering."""
        # 600 bytes: 10 blocks, the last holding only 24 bytes
        articles = [FakeArticle(0, 600)]
        blocks = _blocks_from_articles(FakeNzf(articles), BLOCKSIZE, 10, datafile(600))
        assert blocks == [True] * 10

    def test_no_good_articles(self, datafile):
        articles = [FakeArticle(None, None, good=False)]
        assert _blocks_from_articles(FakeNzf(articles), BLOCKSIZE, 10, datafile(640)) is None

    def test_missing_file(self, tmp_path):
        articles = [FakeArticle(0, 640)]
        assert _blocks_from_articles(FakeNzf(articles), BLOCKSIZE, 10, str(tmp_path / "gone.bin")) is None


class FakeRepairer:
    def __init__(self, block_size, files):
        self.block_size = block_size
        self.files = files
        self.recoverable_file_count = len(files)


class FakeNzo:
    def __init__(self, finished_files):
        self.finished_files = finished_files


class TestArticleBackedBlocks:
    @staticmethod
    def _setup(tmp_path, size=640):
        path = tmp_path / "alpha.bin"
        path.write_bytes(b"\0" * size)
        nzf = FakeNzf([FakeArticle(0, size)])
        nzf.filename = "alpha.bin"
        repairer = FakeRepairer(
            BLOCKSIZE,
            [{"name": "alpha.bin", "target": str(path), "exists": True, "blocks": size // BLOCKSIZE}],
        )
        return FakeNzo([nzf]), repairer

    def test_maps_files_by_name(self, tmp_path):
        nzo, repairer = self._setup(tmp_path)
        with (
            mock.patch.object(cfg.par2_quick_verify, "get", return_value=True),
            mock.patch.object(cfg.direct_write, "get", return_value=True),
        ):
            assert article_backed_blocks(nzo, repairer) == {"alpha.bin": [True] * 10}

    def test_disabled_by_config(self, tmp_path):
        nzo, repairer = self._setup(tmp_path)
        with (
            mock.patch.object(cfg.par2_quick_verify, "get", return_value=False),
            mock.patch.object(cfg.direct_write, "get", return_value=True),
        ):
            assert article_backed_blocks(nzo, repairer) == {}

    def test_requires_direct_write(self, tmp_path):
        """Without direct write the assembler packs articles in completion order, so
        data_begin no longer says where the bytes ended up."""
        nzo, repairer = self._setup(tmp_path)
        with (
            mock.patch.object(cfg.par2_quick_verify, "get", return_value=True),
            mock.patch.object(cfg.direct_write, "get", return_value=False),
        ):
            assert article_backed_blocks(nzo, repairer) == {}

    def test_skips_files_not_in_the_job(self, tmp_path):
        nzo, repairer = self._setup(tmp_path)
        nzo.finished_files = []
        with (
            mock.patch.object(cfg.par2_quick_verify, "get", return_value=True),
            mock.patch.object(cfg.direct_write, "get", return_value=True),
        ):
            assert article_backed_blocks(nzo, repairer) == {}

    def test_ignores_par2s_exists_flag(self, tmp_path):
        """par2 only sets targetexists while scanning source files, so it is false for
        every entry at the point this runs - right after load(), before verify()."""
        nzo, repairer = self._setup(tmp_path)
        repairer.files[0]["exists"] = False
        with (
            mock.patch.object(cfg.par2_quick_verify, "get", return_value=True),
            mock.patch.object(cfg.direct_write, "get", return_value=True),
        ):
            assert article_backed_blocks(nzo, repairer) == {"alpha.bin": [True] * 10}

    def test_skips_targets_not_on_disk(self, tmp_path):
        nzo, repairer = self._setup(tmp_path)
        os.unlink(repairer.files[0]["target"])
        with (
            mock.patch.object(cfg.par2_quick_verify, "get", return_value=True),
            mock.patch.object(cfg.direct_write, "get", return_value=True),
        ):
            assert article_backed_blocks(nzo, repairer) == {}


class TestPar2MemoryLimit:
    """par2 defaults to half the host's physical memory. We give it half of
    get_memory() instead, which is clamped by any cgroup limit."""

    def test_half_of_available_memory(self):
        with mock.patch("sabnzbd.par2repair.get_memory", return_value=int(8192 * MEBI)):
            assert par2_memory_limit() == int(4096 * MEBI)

    def test_respects_a_cgroup_limit(self):
        # get_memory() already returns min(physical, cgroup), so a container with a
        # 512MB budget must not be handed half of the host's 32GB
        with mock.patch("sabnzbd.par2repair.get_memory", return_value=int(512 * MEBI)):
            assert par2_memory_limit() == int(256 * MEBI)

    def test_falls_back_when_memory_is_unknown(self):
        # Same 256MB assumption par2 makes for itself
        with mock.patch("sabnzbd.par2repair.get_memory", return_value=0):
            assert par2_memory_limit() == int(128 * MEBI)

    def test_never_returns_zero(self):
        with mock.patch("sabnzbd.par2repair.get_memory", return_value=1024):
            assert par2_memory_limit() == int(MEBI)

    def test_capped_on_32bit(self):
        with mock.patch("sabnzbd.par2repair.get_memory", return_value=int(16384 * MEBI)):
            with mock.patch.object(sys, "maxsize", 2**31 - 1):
                assert par2_memory_limit() == int(1024 * MEBI)
            # 64-bit gets the full half
            assert par2_memory_limit() == int(8192 * MEBI)
