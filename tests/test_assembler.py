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
tests.test_assembler - Testing functions in assembler.py
"""

import errno
import os
import queue
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock
from zlib import crc32

import pytest

import sabnzbd
import sabnzbd.assembler
import sabnzbd.cfg as cfg
from sabnzbd.assembler import (
    IOV_CHUNK_SIZE,
    VECTORED_WRITE,
    Assembler,
    NzfWriteState,
    advance_buffers,
    write_vector,
)
from sabnzbd.constants import (
    ASSEMBLER_ARTICLE_SIZE,
    ASSEMBLER_EVICTION_FACTOR,
    ASSEMBLER_PENDING_BY_MEMORY,
    ASSEMBLER_MAX_PENDING_BYTES,
    ASSEMBLER_MIN_PENDING_BYTES,
    ASSEMBLER_MIN_CONCURRENT_FILES,
    DEF_MAX_ASSEMBLER_QUEUE,
    GIGI,
    MEBI,
)
from sabnzbd.filesystem import Diskspace
from sabnzbd.nzb import Article, NzbFile, NzbObject


class ArticlesWritten:
    """Counts articles written, whichever way they reached the disk.

    A contiguous run is issued as one vectored write, so counting calls to Assembler.write
    would report how many syscalls happened rather than how many articles were assembled.
    """

    def __init__(self, write_mock: mock.Mock, write_run_mock: mock.Mock):
        self.write = write_mock
        self.write_run = write_run_mock

    @property
    def call_count(self) -> int:
        count = self.write.call_count
        for call in self.write_run.call_args_list:
            run = call.args[2]
            if len(run) >= 2 and VECTORED_WRITE:
                # Vectored, so it did not delegate to Assembler.write and is not counted yet
                count += len(run)
        return count


class TestAssembler:
    @pytest.fixture
    def assembler(self, tmp_path):
        """Prepare a sabnzbd assembler, tmp_path is used because C libraries require a real filesystem."""

        try:
            sabnzbd.Downloader = SimpleNamespace(paused=False)
            sabnzbd.ArticleCache = SimpleNamespace()
            sabnzbd.Assembler = Assembler()

            # Create a minimal NzbObject / NzbFile
            self.nzo = NzbObject("test.nzb")

            admin_path = str(tmp_path / "admin")

            with mock.patch.object(
                NzbObject,
                "admin_path",
                new_callable=mock.PropertyMock,
            ) as admin_path_mock:
                admin_path_mock.return_value = admin_path
                self.nzo.download_path = str(tmp_path / "download")
                os.mkdir(self.nzo.download_path)
                os.mkdir(self.nzo.admin_path)

                # NzbFile requires some constructor args; use dummy but valid values
                self.nzf = NzbFile(
                    date=self.nzo.avg_date,
                    subject="test-file",
                    raw_article_db=[[None, None]],
                    file_bytes=0,
                    nzo=self.nzo,
                )
                self.nzo.files.append(self.nzf)
                self.nzf.type = "yenc"  # for writes from article cache
                assert self.nzf.prepare_filepath() is not None
                # Clear the state after prepare_filepath
                self.nzf.articles.clear()
                self.nzf.decodetable.clear()

                with (
                    mock.patch.object(Assembler, "write", wraps=Assembler.write) as mocked_write,
                    mock.patch.object(Assembler, "write_run", wraps=Assembler.write_run) as mocked_write_run,
                ):
                    yield ArticlesWritten(mocked_write, mocked_write_run)

                # All articles should be marked on_disk
                for article in self.nzf.decodetable:
                    assert article.on_disk is True

                # File should be marked assembled
                assert self.nzf.assembled is True
        finally:
            # Reset values after test
            del sabnzbd.Downloader
            del sabnzbd.ArticleCache
            del sabnzbd.Assembler

    def _make_article(
        self, nzf: NzbFile, offset: int, data: bytearray, decoded: bool = True, can_direct_write: bool = True
    ) -> tuple[Article, bytearray]:
        article = Article("msgid", len(data), nzf)
        article.decoded = decoded
        article.data_begin = offset
        article.data_size = len(data) if can_direct_write else None
        article.file_size = nzf.bytes
        article.decoded_size = len(data)
        article.crc32 = crc32(data)
        article.tries = 1  # force aborts if never tried
        return article, data

    def _make_request(
        self,
        nzf: NzbFile,
        articles: list[tuple[Article, bytearray]],
    ):
        article_data = {}
        for article, raw in articles:
            nzf.decodetable.append(article)
            article_data[article] = raw
        expected = b"".join(article_data.values())
        nzf.bytes = len(expected)
        sabnzbd.ArticleCache.load_article = mock.Mock(side_effect=lambda article: article_data.get(article))

        for article, _ in articles:
            article.file_size = nzf.bytes

        return article_data.values(), expected

    @staticmethod
    def _assert_expected_content(nzf: NzbFile, expected: bytes):
        with open(nzf.filepath, "rb") as f:
            content = f.read()
        assert content == expected
        assert nzf.assembler_next_index == len(nzf.decodetable)
        assert nzf.contiguous_offset() == nzf.decodetable[0].file_size
        # crc32 is finalized in post-processing, not during assembly. Once combined in decodetable
        # order it must match the file regardless of the order articles were written to disk
        nzf.finalize_crc32()
        assert nzf.crc32 == crc32(expected)

    def test_assemble_direct_write(self, assembler):
        """Pure direct write mode"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"hello"), can_direct_write=True),
                self._make_article(self.nzf, offset=5, data=bytearray(b"world"), can_direct_write=True),
            ],
        )
        assert self.nzf.contiguous_offset() == 0
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)

    def test_assemble_direct_write_aborted_to_append(self, assembler):
        """
        Start in direct_write, but encounter an article that cannot be direct-written.
        Assembler should abort direct_write and switch to append mode.
        """
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"hello"), can_direct_write=True),
                self._make_article(self.nzf, offset=5, data=bytearray(b"world"), can_direct_write=False),
                self._make_article(self.nzf, offset=10, data=bytearray(b"12345"), can_direct_write=True),
            ],
        )
        # [0] direct_write, [1] append, [2] append
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)

    def test_assemble_direct_append_direct_append(self, assembler):
        """Out-of-order direct write via cache, append fills the gap."""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"hello"), can_direct_write=True),
                self._make_article(self.nzf, offset=5, data=bytearray(b"world"), can_direct_write=False),
                self._make_article(
                    self.nzf, offset=10, data=bytearray(b"12345"), decoded=False, can_direct_write=False
                ),
                self._make_article(
                    self.nzf, offset=15, data=bytearray(b"abcde"), decoded=False, can_direct_write=True
                ),  # Cache direct
            ],
        )
        # [0] direct_write, [1] append
        Assembler.assemble(self.nzo, self.nzf, file_done=False, allow_non_contiguous=False, direct_write=True)
        assert assembler.call_count == 2
        assert self.nzf.contiguous_offset() == 10
        # [3] direct_write
        article = self.nzf.decodetable[3]
        article.decoded = True
        Assembler.assemble_article(article, sabnzbd.ArticleCache.load_article(article))
        assert assembler.call_count == 3
        assert self.nzf.contiguous_offset() == 10  # was not a sequential write
        # [3] append
        article = self.nzf.decodetable[2]
        article.decoded = True
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        assert assembler.call_count == 4
        self._assert_expected_content(self.nzf, expected)

    def test_assemble_direct_write_aborted_to_append_second_attempt(self, assembler):
        """Second attempt after initial partial assemble, including revert to append mode."""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"hello"), can_direct_write=True),
                self._make_article(self.nzf, offset=5, data=bytearray(b"world"), can_direct_write=False),
                self._make_article(
                    self.nzf, offset=10, data=bytearray(b"12345"), decoded=False, can_direct_write=False
                ),
            ],
        )
        # [0] direct_write, [1] append
        Assembler.assemble(self.nzo, self.nzf, file_done=False, allow_non_contiguous=False, direct_write=True)
        assert self.nzf.decodetable[2].on_disk is False
        self.nzf.decodetable[2].decoded = True
        # [2] append
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)

    def test_assemble_append_direct_second_attempt(self, assembler):
        """Second attempt after initial partial assemble"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"hello"), can_direct_write=False),
                self._make_article(self.nzf, offset=5, data=bytearray(b"world"), decoded=False, can_direct_write=True),
            ],
        )
        # [0] append
        Assembler.assemble(self.nzo, self.nzf, file_done=False, allow_non_contiguous=False, direct_write=False)
        self.nzf.decodetable[1].decoded = True
        # [1] append
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)

    def test_assemble_append_only(self, assembler):
        """Pure append mode"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"abcd"), can_direct_write=False),
                self._make_article(self.nzf, offset=0, data=bytearray(b"efg"), can_direct_write=False),
            ],
        )
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=False)
        self._assert_expected_content(self.nzf, expected)

    def test_assemble_append_second_attempt(self, assembler):
        """Pure append mode, second attempt"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"abcd"), can_direct_write=False),
                self._make_article(self.nzf, offset=0, data=bytearray(b"efg"), decoded=False, can_direct_write=False),
            ],
        )
        # [0] append
        Assembler.assemble(self.nzo, self.nzf, file_done=False, allow_non_contiguous=False, direct_write=False)
        assert self.nzf.assembled is False
        self.nzf.decodetable[1].decoded = True
        # [1] append
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=False)
        self._assert_expected_content(self.nzf, expected)

    def test_assemble_append_first_not_decoded(self, assembler):
        """Pure append mode, second attempt"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"abcd"), decoded=False, can_direct_write=False),
                self._make_article(self.nzf, offset=0, data=bytearray(b"efg"), can_direct_write=False),
            ],
        )
        # Nothing written
        Assembler.assemble(self.nzo, self.nzf, file_done=False, allow_non_contiguous=False, direct_write=False)
        assert not os.path.exists(self.nzf.filepath)
        self.nzf.decodetable[0].decoded = True
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=False)
        self._assert_expected_content(self.nzf, expected)

    def test_force_append(self, assembler):
        """Force in direct_write mode, then fill in gaps in append mode"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"hello")),
                self._make_article(self.nzf, offset=5, data=bytearray(b"world"), decoded=False, can_direct_write=False),
                self._make_article(self.nzf, offset=10, data=bytearray(b"12345")),
                self._make_article(self.nzf, offset=15, data=bytearray(b"abcd"), decoded=False, can_direct_write=False),
                self._make_article(self.nzf, offset=19, data=bytearray(b"efg")),
            ],
        )
        # [0] direct, [2] direct, [4], direct
        Assembler.assemble(self.nzo, self.nzf, file_done=False, allow_non_contiguous=True, direct_write=True)
        assert assembler.call_count == 3
        assert self.nzf.assembled is False
        # [1] append, [3], append
        self.nzf.decodetable[1].decoded = True
        self.nzf.decodetable[3].decoded = True
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=False)
        assert assembler.call_count == 5
        self._assert_expected_content(self.nzf, expected)

    def test_force_force_direct(self, assembler):
        """Force the first, then force the last, then direct the gap"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"hello")),
                self._make_article(self.nzf, offset=5, data=bytearray(b"world"), decoded=False),
                self._make_article(self.nzf, offset=10, data=bytearray(b"12345"), decoded=False),
            ],
        )
        # [0] direct
        Assembler.assemble(self.nzo, self.nzf, file_done=False, allow_non_contiguous=False, direct_write=True)
        assert assembler.call_count == 1
        assert self.nzf.assembler_next_index == 1
        # Client restart
        self.nzf.assembler_next_index = 0
        # force: [2] direct
        self.nzf.decodetable[2].decoded = True
        Assembler.assemble(self.nzo, self.nzf, file_done=False, allow_non_contiguous=True, direct_write=True)
        assert assembler.call_count == 2
        assert self.nzf.assembler_next_index == 1
        # [1] direct
        self.nzf.decodetable[1].decoded = True
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        assert assembler.call_count == 3
        self._assert_expected_content(self.nzf, expected)

    def test_crc32_correct_when_gap_filled_out_of_order(self, assembler):
        """Pausing flushes the cache non-contiguously, so later articles are written before an earlier gap article.
        The finalized crc32 must still match the file, which is combined in decodetable order."""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"hello")),
                self._make_article(self.nzf, offset=5, data=bytearray(b"world"), decoded=False),
                self._make_article(self.nzf, offset=10, data=bytearray(b"12345")),
            ],
        )
        # Forced flush writes [0] and [2], skipping the not-yet-decoded gap [1]
        Assembler.assemble(self.nzo, self.nzf, file_done=False, allow_non_contiguous=True, direct_write=True)
        assert self.nzf.crc32 is None  # not finalized until file_done
        # Gap article arrives last and the file completes
        self.nzf.decodetable[1].decoded = True
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)

    @pytest.mark.parametrize(
        "write_path",
        [
            pytest.param(
                {"_use_pwritev": True},
                id="pwritev",
                marks=pytest.mark.skipif(not hasattr(os, "pwritev"), reason="pwritev not available"),
            ),
            pytest.param(
                {"_use_pwritev": False},
                id="writev_lseek",
                marks=pytest.mark.skipif(not VECTORED_WRITE, reason="no vectored write on this platform"),
            ),
            pytest.param({"VECTORED_WRITE": False}, id="per_article"),
        ],
    )
    def test_write_paths_produce_identical_files(self, assembler, write_path):
        """pwritev, writev + lseek and the per-article loop must all produce the same file.

        macOS 10.15 has no pwritev and Windows has no vectored write at all, but CI has both,
        so the fallbacks only get exercised by forcing the binding.
        """
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=index * 5, data=bytearray(f"body{index:01d}", "utf-8"))
                for index in range(9)
            ],
        )
        with mock.patch.multiple("sabnzbd.assembler", **write_path):
            Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)

    def test_contiguous_run_is_written_as_one_vector(self, assembler):
        """The whole point of coalescing: fewer syscalls than articles"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=index * 5, data=bytearray(f"body{index:01d}", "utf-8"))
                for index in range(6)
            ],
        )
        with mock.patch("sabnzbd.assembler.write_vector", wraps=sabnzbd.assembler.write_vector) as mocked_vector:
            Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        assert mocked_vector.call_count == 1
        assert len(mocked_vector.call_args.args[2]) == 6
        assert assembler.call_count == 6
        self._assert_expected_content(self.nzf, expected)

    def test_run_is_split_at_the_chunk_boundary(self, assembler):
        """A vector is never longer than IOV_CHUNK_SIZE, whatever the run length"""
        article_count = IOV_CHUNK_SIZE * 2 + 3
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=index * 5, data=bytearray(f"{index:05d}", "utf-8"))
                for index in range(article_count)
            ],
        )
        with mock.patch("sabnzbd.assembler.write_vector", wraps=sabnzbd.assembler.write_vector) as mocked_vector:
            Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        assert mocked_vector.call_count == 3
        assert [len(call.args[2]) for call in mocked_vector.call_args_list] == [IOV_CHUNK_SIZE, IOV_CHUNK_SIZE, 3]
        assert assembler.call_count == article_count
        self._assert_expected_content(self.nzf, expected)

    def test_gap_breaks_the_run(self, assembler):
        """Articles either side of a not-yet-decoded gap are not adjacent, so must not share a vector"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"aaaaa")),
                self._make_article(self.nzf, offset=5, data=bytearray(b"bbbbb")),
                self._make_article(self.nzf, offset=10, data=bytearray(b"ccccc"), decoded=False),
                self._make_article(self.nzf, offset=15, data=bytearray(b"ddddd")),
                self._make_article(self.nzf, offset=20, data=bytearray(b"eeeee")),
            ],
        )
        with mock.patch("sabnzbd.assembler.write_vector", wraps=sabnzbd.assembler.write_vector) as mocked_vector:
            Assembler.assemble(self.nzo, self.nzf, file_done=False, allow_non_contiguous=True, direct_write=True)
        assert [len(call.args[2]) for call in mocked_vector.call_args_list] == [2, 2]

        self.nzf.decodetable[2].decoded = True
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)

    def test_short_write_in_the_middle_of_a_vector(self, assembler):
        """A vectored write may consume only part of one buffer, and must resume from there"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=index * 5, data=bytearray(f"body{index:01d}", "utf-8"))
                for index in range(7)
            ],
        )
        real_pwritev = os.pwritev

        def short_pwritev(fd, buffers, offset):
            # Stop partway through the second buffer, so recovery has to slice mid-buffer
            head = [buffers[0], memoryview(buffers[1])[:2]] if len(buffers) > 1 else buffers[:1]
            return real_pwritev(fd, head, offset)

        with mock.patch("os.pwritev", side_effect=short_pwritev):
            Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)

    def test_a_long_run_is_one_run_across_several_vectors(self, assembler, caplog):
        """Run length must measure contiguity on disk, not how the vector was chunked, or a
        perfectly sequential file reports a run length capped at IOV_CHUNK_SIZE"""
        count = IOV_CHUNK_SIZE * 3
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=index * 5, data=bytearray(f"{index:05d}", "utf-8"))
                for index in range(count)
            ],
        )
        with caplog.at_level("DEBUG", logger="root"):
            Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)

        written = next(r.getMessage() for r in caplog.records if "Wrote" in r.getMessage())
        assert f"{count} article(s) over 1 run(s) / 3 write(s)" in written
        assert f"{float(count):.1f} articles/run" in written

    def test_batch_size_is_logged(self, assembler, caplog):
        """The articles/run figure is the fragmentation signal when diagnosing write behaviour"""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=index * 5, data=bytearray(f"body{index:01d}", "utf-8"))
                for index in range(6)
            ],
        )
        with caplog.at_level("DEBUG", logger="root"):
            Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)

        written = [record.getMessage() for record in caplog.records if "Wrote" in record.getMessage()]
        assert len(written) == 1
        assert "6 article(s)" in written[0]
        assert "6 article(s) over 1 run(s)" in written[0]
        assert "6.0 articles/run" in written[0]

    def test_finalize_crc32_none_when_article_missing(self, assembler):
        """A file with a missing article crc cannot be verified, so crc32 is None."""
        _data, expected = self._make_request(
            self.nzf,
            [
                self._make_article(self.nzf, offset=0, data=bytearray(b"hello")),
                self._make_article(self.nzf, offset=5, data=bytearray(b"world")),
            ],
        )
        Assembler.assemble(self.nzo, self.nzf, file_done=True, allow_non_contiguous=False, direct_write=True)
        self._assert_expected_content(self.nzf, expected)
        # A missing per-article crc (e.g. article never decoded) makes the whole-file crc unverifiable
        self.nzf.decodetable[1].crc32 = None
        self.nzf.finalize_crc32()
        assert self.nzf.crc32 is None


class TestAdvanceBuffers:
    """Tests for short-write recovery on a partially consumed vector"""

    @staticmethod
    def _flatten(buffers: list) -> bytes:
        return b"".join(bytes(buffer) for buffer in buffers)

    def test_nothing_consumed_returns_the_same_buffers(self):
        buffers = [bytearray(b"aaa"), bytearray(b"bbb")]
        assert self._flatten(advance_buffers(buffers, 0)) == b"aaabbb"

    def test_whole_first_buffer_consumed(self):
        buffers = [bytearray(b"aaa"), bytearray(b"bbb")]
        assert self._flatten(advance_buffers(buffers, 3)) == b"bbb"

    def test_stopped_inside_a_buffer(self):
        buffers = [bytearray(b"aaa"), bytearray(b"bbb"), bytearray(b"ccc")]
        assert self._flatten(advance_buffers(buffers, 4)) == b"bbccc"

    def test_everything_consumed(self):
        buffers = [bytearray(b"aaa"), bytearray(b"bbb")]
        assert advance_buffers(buffers, 6) == []

    @pytest.mark.parametrize("consumed", range(10))
    def test_remainder_is_always_the_untouched_tail(self, consumed):
        buffers = [bytearray(b"abc"), bytearray(b"de"), bytearray(b"fghi")]
        assert self._flatten(advance_buffers(buffers, consumed)) == b"abcdefghi"[consumed:]


class TestWriteVector:
    """Tests for the vectored write helper itself"""

    @pytest.fixture
    def target(self, tmp_path):
        nzf = mock.Mock()
        nzf.file_lock = threading.RLock()
        nzf.filepath = str(tmp_path / "out.bin")
        fd = os.open(nzf.filepath, os.O_CREAT | os.O_WRONLY, 0o666)
        try:
            yield fd, nzf
        finally:
            os.close(fd)

    @staticmethod
    def _content(nzf) -> bytes:
        with open(nzf.filepath, "rb") as handle:
            return handle.read()

    def test_writes_buffers_back_to_back_at_offset(self, target):
        fd, nzf = target
        written = write_vector(fd, nzf, [bytearray(b"aaa"), bytearray(b"bbb")], 4)
        assert written == 6
        assert self._content(nzf) == b"\x00\x00\x00\x00aaabbb"

    def test_writev_fallback_matches_pwritev(self, target):
        fd, nzf = target
        with mock.patch("sabnzbd.assembler._use_pwritev", False):
            written = write_vector(fd, nzf, [bytearray(b"aaa"), bytearray(b"bbb")], 4)
        assert written == 6
        assert self._content(nzf) == b"\x00\x00\x00\x00aaabbb"

    def test_a_stalled_write_raises_rather_than_spinning(self, target):
        fd, nzf = target
        with mock.patch("os.pwritev", return_value=0), mock.patch("sabnzbd.assembler._use_pwritev", True):
            with pytest.raises(OSError):
                write_vector(fd, nzf, [bytearray(b"aaa")], 0)

    def test_missing_pwritev_demotes_to_writev(self, target):
        fd, nzf = target
        with (
            mock.patch("sabnzbd.assembler._use_pwritev", True),
            mock.patch("os.pwritev", side_effect=OSError(errno.ENOSYS, "nope")),
        ):
            written = write_vector(fd, nzf, [bytearray(b"aaa"), bytearray(b"bbb")], 0)
        assert written == 6
        assert self._content(nzf) == b"aaabbb"

    def test_real_errors_are_not_mistaken_for_a_missing_syscall(self, target):
        """ENOSPC must propagate, or a full disk would look like an unsupported platform"""
        fd, nzf = target
        with (
            mock.patch("sabnzbd.assembler._use_pwritev", True),
            mock.patch("os.pwritev", side_effect=OSError(errno.ENOSPC, "full")),
        ):
            with pytest.raises(OSError) as err:
                write_vector(fd, nzf, [bytearray(b"aaa")], 0)
        assert err.value.errno == errno.ENOSPC


class TestWriteSerialisation:
    """Tests for the per-NzbFile write claim that keeps one task in flight per file"""

    @pytest.fixture(autouse=True)
    def assembler(self):
        try:
            sabnzbd.Assembler = Assembler()
            # Bypass the trigger checks; these tests are about what happens once a file
            # is worth queueing, not about when it becomes worth queueing
            with mock.patch.object(Assembler, "should_queue_nzf", return_value="test"):
                yield sabnzbd.Assembler
        finally:
            del sabnzbd.Assembler

    @staticmethod
    def _nzf(nzf_id: str = "nzf_1"):
        nzf = mock.Mock()
        nzf.nzf_id = nzf_id
        nzf.type = "yenc"
        return nzf

    @staticmethod
    def _drain(assembler) -> list:
        tasks = []
        while not assembler.queue.empty():
            tasks.append(assembler.queue.get())
        return tasks

    def test_first_request_is_queued(self, assembler):
        nzf = self._nzf()
        assembler.process(mock.Mock(), nzf)
        assert assembler.is_busy() is True
        assert len(self._drain(assembler)) == 1

    def test_second_request_does_not_queue_a_second_task(self, assembler):
        nzf = self._nzf()
        assembler.process(mock.Mock(), nzf)
        assembler.process(mock.Mock(), nzf)
        assembler.process(mock.Mock(), nzf)
        assert len(self._drain(assembler)) == 1

    def test_ordinary_arrivals_during_a_write_do_not_chain_another_write(self, assembler):
        """The running pass walks to the end of the decodetable, so it already covers them.

        Re-queueing instead makes each write carry only what landed during the previous one,
        which degenerates into back-to-back writes of a few hundred KiB at high download rates.
        """
        nzo, nzf = mock.Mock(), self._nzf()
        assembler.process(nzo, nzf)
        self._drain(assembler)
        for _ in range(20):
            assembler.process(nzo, nzf)

        assembler.finish_write(nzo, nzf, file_done=False)
        assert self._drain(assembler) == []
        assert assembler.is_busy() is False

    def test_claim_released_when_nothing_pending(self, assembler):
        nzo, nzf = mock.Mock(), self._nzf()
        assembler.process(nzo, nzf)
        self._drain(assembler)

        assembler.finish_write(nzo, nzf, file_done=False)
        assert self._drain(assembler) == []
        assert assembler.is_busy() is False

    def test_file_done_arriving_during_a_write_is_not_lost(self, assembler):
        nzo, nzf = mock.Mock(), self._nzf()
        assembler.process(nzo, nzf)
        self._drain(assembler)

        # file_done used to bypass the dedupe and enqueue a second, concurrent task
        assembler.process(nzo, nzf, file_done=True)
        assert self._drain(assembler) == []

        assembler.finish_write(nzo, nzf, file_done=False)
        tasks = self._drain(assembler)
        assert len(tasks) == 1
        assert tasks[0].file_done is True

    def test_file_done_takes_priority_over_other_pending_work(self, assembler):
        nzo, nzf = mock.Mock(), self._nzf()
        assembler.process(nzo, nzf)
        self._drain(assembler)

        assembler.process(nzo, nzf, allow_non_contiguous=True)
        assembler.process(nzo, nzf)
        assembler.process(nzo, nzf, file_done=True)

        assembler.finish_write(nzo, nzf, file_done=False)
        tasks = self._drain(assembler)
        assert len(tasks) == 1
        assert tasks[0].file_done is True

    def test_non_contiguous_is_requeued_but_ordinary_work_is_not(self, assembler):
        """Eviction must survive: the running pass stops at the gap, so it cannot cover it"""
        nzo, nzf = mock.Mock(), self._nzf()
        assembler.process(nzo, nzf)
        self._drain(assembler)

        assembler.process(nzo, nzf)
        assembler.process(nzo, nzf, allow_non_contiguous=True)

        assembler.finish_write(nzo, nzf, file_done=False)
        tasks = self._drain(assembler)
        assert len(tasks) == 1
        assert tasks[0].allow_non_contiguous is True

        # Nothing else is owed, so the chain stops here
        assembler.finish_write(nzo, nzf, file_done=False)
        assert self._drain(assembler) == []
        assert assembler.is_busy() is False

    def test_completing_file_done_discards_pending_work(self, assembler):
        nzo, nzf = mock.Mock(), self._nzf()
        assembler.process(nzo, nzf, file_done=True)
        self._drain(assembler)
        assembler.process(nzo, nzf)

        assembler.finish_write(nzo, nzf, file_done=True)
        assert self._drain(assembler) == []
        assert assembler.is_busy() is False

    def test_different_files_are_queued_independently(self, assembler):
        nzo = mock.Mock()
        assembler.process(nzo, self._nzf("nzf_1"))
        assembler.process(nzo, self._nzf("nzf_2"))
        assert len(self._drain(assembler)) == 2

    def test_clear_ready_bytes_releases_the_claim(self, assembler):
        nzo, nzf = mock.Mock(), self._nzf()
        assembler.process(nzo, nzf)
        self._drain(assembler)

        assembler.clear_ready_bytes(nzf)
        assert assembler.is_busy() is False
        # A deleted or finished job must not leave a claim that blocks a retry
        assembler.process(nzo, nzf)
        assert len(self._drain(assembler)) == 1

    def test_finish_write_after_claim_cleared_is_a_no_op(self, assembler):
        nzo, nzf = mock.Mock(), self._nzf()
        assembler.process(nzo, nzf)
        self._drain(assembler)

        assembler.clear_ready_bytes(nzf)
        assembler.finish_write(nzo, nzf, file_done=False)
        assert self._drain(assembler) == []
        assert assembler.is_busy() is False

    def test_only_one_task_in_flight_per_file_under_concurrency(self, assembler):
        """Many producers and several workers must never put two tasks for one file in flight"""
        nzo = mock.Mock()
        nzf_ids = ["nzf_1", "nzf_2", "nzf_3"]
        nzfs = {nzf_id: self._nzf(nzf_id) for nzf_id in nzf_ids}

        in_flight = dict.fromkeys(nzf_ids, 0)
        in_flight_lock = threading.Lock()
        violations = []
        seen_file_done = set()
        stop = threading.Event()

        def worker():
            while not stop.is_set():
                try:
                    task = assembler.queue.get(timeout=0.05)
                except queue.Empty:
                    continue
                with in_flight_lock:
                    in_flight[task.nzf.nzf_id] += 1
                    if in_flight[task.nzf.nzf_id] > 1:
                        violations.append(task.nzf.nzf_id)
                if task.file_done:
                    seen_file_done.add(task.nzf.nzf_id)
                time.sleep(0.0005)
                with in_flight_lock:
                    in_flight[task.nzf.nzf_id] -= 1
                assembler.finish_write(nzo, task.nzf, task.file_done)

        def producer():
            for _ in range(200):
                for nzf in nzfs.values():
                    assembler.process(nzo, nzf)

        workers = [threading.Thread(target=worker) for _ in range(4)]
        producers = [threading.Thread(target=producer) for _ in range(4)]
        for thread in workers + producers:
            thread.start()
        for thread in producers:
            thread.join()

        # file_done arrives last, while writes for these files are still churning
        for nzf in nzfs.values():
            assembler.process(nzo, nzf, file_done=True)

        deadline = time.monotonic() + 10
        while assembler.is_busy() and time.monotonic() < deadline:
            time.sleep(0.01)
        stop.set()
        for thread in workers:
            thread.join()

        assert violations == []
        assert seen_file_done == set(nzf_ids)
        assert assembler.is_busy() is False


class TestPendingCap:
    """Tests for the per-file pending cap that replaced the share-of-cache trigger"""

    @pytest.fixture(autouse=True)
    def assembler(self):
        try:
            sabnzbd.Assembler = Assembler()
            sabnzbd.Assembler.max_queue_size = DEF_MAX_ASSEMBLER_QUEUE
            yield sabnzbd.Assembler
        finally:
            del sabnzbd.Assembler

    @staticmethod
    def _with_memory(total_bytes):
        return mock.patch("sabnzbd.misc.get_memory", return_value=total_bytes)

    @staticmethod
    def _server(threads: int, pipelining: int = 2, active: bool = True):
        return SimpleNamespace(threads=threads, pipelining_requests=lambda: pipelining, active=active)

    @contextmanager
    def _with_servers(self, *servers):
        sabnzbd.Downloader = SimpleNamespace(servers=list(servers))
        try:
            yield
        finally:
            del sabnzbd.Downloader

    def test_in_flight_articles_counts_active_connections(self, assembler):
        with self._with_servers(self._server(20), self._server(30, pipelining=1)):
            assert assembler.in_flight_articles() == 20 * 2 + 30

    def test_in_flight_articles_ignores_inactive_servers(self, assembler):
        with self._with_servers(self._server(20), self._server(500, active=False)):
            assert assembler.in_flight_articles() == 40

    def test_in_flight_articles_without_a_downloader(self, assembler):
        """Called during startup before the Downloader exists"""
        assert assembler.in_flight_articles() == 0

    def test_cap_covers_the_in_flight_window(self, assembler):
        """The window the write position can fall behind is connections x pipelining"""
        assembler.cache_limit = int(8 * GIGI)
        with self._with_servers(self._server(20)), self._with_memory(int(128 * GIGI)):
            assembler.calculate_pending_cap()
        assert assembler.pending_cap() == 40 * ASSEMBLER_ARTICLE_SIZE

    def test_memory_tier_caps_a_large_connection_count(self, assembler):
        """A machine can be configured with more connections than it has memory to batch for"""
        assembler.cache_limit = int(8 * GIGI)
        with self._with_servers(self._server(500)), self._with_memory(int(8 * GIGI)):
            assembler.calculate_pending_cap()
        assert assembler.pending_cap() == int(32 * MEBI)

    def test_bandwidth_is_not_an_input(self, assembler):
        """A slow link reorders over the same number of articles as a fast one"""
        assembler.cache_limit = int(8 * GIGI)
        caps = []
        for bandwidth in ("", "10M", "10G"):
            with (
                mock.patch.object(cfg.bandwidth_max, "get", return_value=bandwidth),
                self._with_servers(self._server(20)),
                self._with_memory(int(128 * GIGI)),
            ):
                assembler.calculate_pending_cap()
            caps.append(assembler.pending_cap())
        assert len(set(caps)) == 1

    @pytest.mark.parametrize(
        "cache_limit, expected",
        [
            (0, ASSEMBLER_MIN_PENDING_BYTES),
            (int(8 * MEBI), ASSEMBLER_MIN_PENDING_BYTES),
            (int(128 * MEBI), ASSEMBLER_MIN_PENDING_BYTES),
            (
                int(512 * MEBI),
                int(512 * MEBI * 0.5 / ASSEMBLER_MIN_CONCURRENT_FILES) // ASSEMBLER_EVICTION_FACTOR,
            ),
            (int(4 * GIGI), ASSEMBLER_MAX_PENDING_BYTES),
        ],
    )
    def test_cap_is_ceilinged_not_proportional(self, assembler, cache_limit, expected):
        """Large caches all land on the same cap, which is the point: memory stops tracking cache size"""
        assembler.cache_limit = cache_limit
        with self._with_memory(int(128 * GIGI)):
            assembler.calculate_pending_cap()
        assert assembler.pending_cap() == expected

    @pytest.mark.parametrize("total_memory, expected", ASSEMBLER_PENDING_BY_MEMORY)
    def test_cap_scales_with_installed_memory(self, assembler, total_memory, expected):
        """Bigger machines run more connections, so the batch has to cover a wider
        out-of-order arrival window before the write position unblocks"""
        assembler.cache_limit = int(4 * GIGI)
        with self._with_memory(int(total_memory)):
            assembler.calculate_pending_cap()
        assert assembler.pending_cap() == expected

    def test_unknown_memory_uses_the_top_tier(self, assembler):
        """get_memory returns 0 when it cannot tell; the cache share still bounds it"""
        assembler.cache_limit = int(4 * GIGI)
        with self._with_memory(0):
            assembler.calculate_pending_cap()
        assert assembler.pending_cap() == ASSEMBLER_MAX_PENDING_BYTES

    def test_cap_never_exceeds_its_share_of_a_small_cache(self, assembler):
        """Pending writes must not crowd out articles still being downloaded"""
        for megabytes in (16, 32, 64, 128, 256, 512):
            assembler.cache_limit = int(megabytes * MEBI)
            with self._with_memory(int(128 * GIGI)):
                assembler.calculate_pending_cap()
            peak = assembler.eviction_watermark() * ASSEMBLER_MIN_CONCURRENT_FILES
            floor_peak = ASSEMBLER_MIN_PENDING_BYTES * ASSEMBLER_EVICTION_FACTOR * ASSEMBLER_MIN_CONCURRENT_FILES
            assert peak <= max(int(assembler.cache_limit * 0.5), floor_peak)

    @pytest.mark.parametrize(
        "cache_limit, direct_write, expected",
        [
            # Values taken from the formula as it stood before the pending cap was introduced.
            # Backpressure must not move with the cap, or M2 would change throughput as well as
            # memory and a regression could not be attributed to either.
            (134217728, True, 120795955),
            (134217728, False, 67108864),
            (524288000, True, 471859200),
            (524288000, False, 262144000),
            (1073741824, True, 966367641),
            (1073741824, False, 536870912),
            (4294967296, True, 3865470566),
            (4294967296, False, 2147483648),
        ],
    )
    def test_delay_trigger_is_unchanged_by_the_new_cap(self, assembler, cache_limit, direct_write, expected):
        assembler.cache_limit = cache_limit
        assembler.direct_write = direct_write
        assembler.calculate_delay_trigger()
        assert assembler.delay_trigger == expected


class TestBatchSizeUnderLoad:
    """Writes must carry roughly a capful, not whatever landed during the previous write"""

    @pytest.fixture(autouse=True)
    def assembler(self):
        try:
            sabnzbd.Assembler = Assembler()
            sabnzbd.Assembler.cache_limit = int(GIGI)
            sabnzbd.Assembler.calculate_pending_cap()
            sabnzbd.Assembler.direct_write = True
            yield sabnzbd.Assembler
        finally:
            del sabnzbd.Assembler

    def test_arrivals_during_a_slow_write_do_not_shrink_the_next_batch(self, assembler):
        """Reproduces the regression seen on fast storage: a write completes, the arrivals it
        already covered trigger another, and batch size collapses towards a single article"""
        article_size = 760 * 1024
        nzf = mock.Mock()
        nzf.nzf_id = "nzf_1"
        nzf.type = "yenc"
        nzf.filename_checked = True
        nzf.import_finished = True
        nzf.assembler_next_article = mock.Mock(decoded=True, on_disk=False, failed=False)
        nzf.has_contiguous_ready_bytes.return_value = True
        # Push the interval trigger out of the way so only the cap can queue a write
        assembler.queued_next_time[nzf.nzf_id] = time.monotonic() + 3600

        # Fast storage: a write completes in the time it takes two more articles to arrive.
        # Those two are the ones that used to re-arm the trigger and shrink the next batch.
        articles_per_write = 2
        nzo = mock.Mock()
        batches = []
        in_flight, remaining = False, 0

        def start_write():
            nonlocal in_flight, remaining
            assembler.queue.get()
            in_flight, remaining = True, articles_per_write

        def complete_write():
            nonlocal in_flight
            written = assembler.ready_bytes.get(nzf.nzf_id, 0)
            batches.append(written)
            assembler.update_ready_bytes(nzf, -written)
            assembler.finish_write(nzo, nzf, file_done=False)
            in_flight = False

        for _ in range(400):
            assembler.process(nzo, nzf, article=mock.Mock(decoded_size=article_size, lowest_partnum=False))
            if in_flight:
                remaining -= 1
                if remaining <= 0:
                    complete_write()
            if not in_flight and not assembler.queue.empty():
                start_write()

        assert len(batches) > 1, "no writes completed, the simulation is not exercising anything"
        # Every write carries at least a capful, and never more than a capful plus the articles
        # that arrived while it ran
        assert min(batches) >= assembler.pending_cap()
        assert max(batches) <= assembler.pending_cap() + article_size * (articles_per_write + 1)


class TestNonContiguousEviction:
    """Tests for per-file eviction when the next article has not arrived"""

    @pytest.fixture(autouse=True)
    def assembler(self):
        try:
            sabnzbd.Assembler = Assembler()
            sabnzbd.Assembler.cache_limit = int(GIGI)
            sabnzbd.Assembler.calculate_pending_cap()
            sabnzbd.Assembler.direct_write = True
            yield sabnzbd.Assembler
        finally:
            del sabnzbd.Assembler

    @staticmethod
    def _nzf(nzf_id: str = "nzf_1", contiguous: bool = True):
        nzf = mock.Mock()
        nzf.nzf_id = nzf_id
        nzf.type = "yenc"
        nzf.filename_checked = True
        nzf.import_finished = True
        nzf.has_contiguous_ready_bytes.return_value = contiguous
        return nzf

    def _trigger(self, assembler, nzf, ready_bytes, next_ready=True):
        return assembler.should_queue_nzf(
            nzf,
            article_has_first_part=False,
            filename_checked=True,
            import_finished=True,
            file_done=False,
            allow_non_contiguous=False,
            ready_bytes=ready_bytes,
            next_ready=next_ready,
        )

    def test_queues_on_a_full_contiguous_run(self, assembler):
        nzf = self._nzf(contiguous=True)
        assembler.queued_next_time[nzf.nzf_id] = time.monotonic() + 3600
        assert self._trigger(assembler, nzf, assembler.pending_cap()) == "cap"

    def test_does_not_queue_when_the_pending_bytes_are_fragmented(self, assembler):
        """A capful of pending data whose contiguous prefix is one article would write one
        article, which is how a file ends up written in fragments"""
        nzf = self._nzf(contiguous=False)
        assembler.queued_next_time[nzf.nzf_id] = time.monotonic() + 3600
        assert self._trigger(assembler, nzf, assembler.pending_cap() * 4) == ""

    @property
    def _watermark(self) -> int:
        return sabnzbd.Assembler.eviction_watermark()

    @pytest.mark.parametrize(
        "cache_gb, file_mb",
        [(1, 100), (1, 250), (2, 500), (4, 500), (4, 1000)],
    )
    def test_a_large_cache_buys_patience_not_larger_batches(self, assembler, cache_gb, file_mb):
        """Typical files are 100-500 MB. A file smaller than the watermark is never written out
        of order, so spare cache has to raise the watermark without inflating the batch size"""
        assembler.cache_limit = int(cache_gb * GIGI)
        with mock.patch("sabnzbd.misc.get_memory", return_value=int(64 * GIGI)):
            assembler.calculate_pending_cap()
        assert assembler.eviction_watermark() >= file_mb * MEBI
        # The batch still only covers the in-flight window; patience and batch size are separate
        assert assembler.pending_cap() == min(assembler.pending_window, assembler.pending_tier)

    def test_watermark_never_exceeds_the_file_budget(self, assembler):
        """Or several files together would overrun the cache and trigger the spill path"""
        for megabytes in (64, 128, 256, 512, 1024, 4096):
            assembler.cache_limit = int(megabytes * MEBI)
            with mock.patch("sabnzbd.misc.get_memory", return_value=int(64 * GIGI)):
                assembler.calculate_pending_cap()
            floor = ASSEMBLER_MIN_PENDING_BYTES * ASSEMBLER_EVICTION_FACTOR
            assert assembler.eviction_watermark() <= max(assembler.file_budget(), floor)

    def test_forces_a_write_past_the_watermark(self, assembler):
        assert assembler.should_force_write(self._watermark) is True

    def test_does_not_force_a_write_on_the_first_gap(self, assembler):
        """Articles arrive out of order across many connections, so a short contiguous prefix is
        routine and usually transient. Waiting lets the run grow instead of writing it in pieces"""
        assert assembler.should_force_write(assembler.pending_cap()) is False
        assert assembler.should_force_write(self._watermark - 1) is False

    def test_evicts_only_when_the_write_position_is_blocked(self, assembler):
        assert assembler.should_evict_non_contiguous(self._nzf(), next_ready=False) is True

    def test_prefers_a_short_sequential_write_over_a_scattered_one(self, assembler):
        """The forced write still happens, it just stays contiguous"""
        assert assembler.should_evict_non_contiguous(self._nzf(), next_ready=True) is False

    def test_does_not_evict_in_append_mode(self, assembler):
        """Append has to write in order, so there is no out-of-order write to fall back on"""
        assembler.direct_write = False
        assert assembler.should_evict_non_contiguous(self._nzf(), next_ready=False) is False

    def test_does_not_evict_a_non_yenc_file(self, assembler):
        nzf = self._nzf()
        nzf.type = "uu"
        assert assembler.should_evict_non_contiguous(nzf, next_ready=False) is False

    def test_does_not_evict_twice_while_one_is_pending(self, assembler):
        nzf = self._nzf()
        state = NzfWriteState()
        state.pending_non_contiguous = True
        assembler.write_states[nzf.nzf_id] = state
        assert assembler.should_evict_non_contiguous(nzf, next_ready=False) is False

    def test_stalled_file_is_queued_out_of_order_rather_than_waiting_for_the_cache(self, assembler):
        """A file whose next article is missing would otherwise hold its backlog until the
        whole cache hit 90%, so one stalled article becomes a whole-cache problem"""
        nzf = self._nzf(contiguous=False)
        nzf.assembler_next_article = mock.Mock(decoded=False, on_disk=False, failed=False)
        assembler.queued_next_time[nzf.nzf_id] = time.monotonic() + 3600

        article = mock.Mock(decoded_size=self._watermark, lowest_partnum=False)
        assembler.process(mock.Mock(), nzf, article=article)

        task = assembler.queue.get_nowait()
        assert task.allow_non_contiguous is True
        assert task.nzf is nzf

    def test_forced_write_stays_contiguous_when_the_write_position_is_available(self, assembler):
        """Past the watermark with a short run: write it, but sequentially rather than scattered"""
        nzf = self._nzf(contiguous=False)
        nzf.assembler_next_article = mock.Mock(decoded=True, on_disk=False, failed=False)
        assembler.queued_next_time[nzf.nzf_id] = time.monotonic() + 3600

        article = mock.Mock(decoded_size=self._watermark, lowest_partnum=False)
        assembler.process(mock.Mock(), nzf, article=article)

        task = assembler.queue.get_nowait()
        assert task.allow_non_contiguous is False

    def test_append_mode_with_a_blocked_write_position_waits(self, assembler):
        """Nothing can be written in order, and append cannot skip the gap"""
        assembler.direct_write = False
        nzf = self._nzf(contiguous=False)
        nzf.assembler_next_article = mock.Mock(decoded=False, on_disk=False, failed=False)
        assembler.queued_next_time[nzf.nzf_id] = time.monotonic() + 3600

        article = mock.Mock(decoded_size=self._watermark, lowest_partnum=False)
        assembler.process(mock.Mock(), nzf, article=article)

        assert assembler.queue.empty()


class TestDiskspaceCheck:
    """Tests for Assembler.diskspace_check"""

    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        self.nzo = mock.Mock()
        self.nzo.bytes = int(2 * GIGI)
        self.nzo.bytes_tried = 0
        self.nzo.bytes_par2 = 0

        self.nzf = mock.Mock()
        self.nzf.bytes = int(0.5 * GIGI)

        self.mock_downloader = mock.Mock()
        self.mock_scheduler = mock.Mock()
        self.mock_notifier = mock.Mock()
        self.mock_emailer = mock.Mock()

        try:
            sabnzbd.Downloader = self.mock_downloader
            sabnzbd.Scheduler = self.mock_scheduler
            sabnzbd.notifier = self.mock_notifier
            sabnzbd.emailer = self.mock_emailer

            with (
                mock.patch("sabnzbd.assembler.diskspace") as self.mock_diskspace,
                mock.patch("sabnzbd.assembler.get_complete_directory") as self.mock_get_complete_dir,
                mock.patch("sabnzbd.assembler.cfg") as self.mock_cfg,
            ):
                # Defaults: plenty of space, no direct_unpack, autoresume on
                self.mock_get_complete_dir.return_value = ("/complete", None, True)
                self.mock_cfg.download_free.get_float.return_value = 1 * GIGI
                self.mock_cfg.complete_free.get_float.return_value = 2 * GIGI
                self.mock_cfg.direct_unpack.return_value = False
                self.mock_cfg.fulldisk_autoresume.return_value = True
                self.mock_cfg.download_dir.get_path.return_value = "/download"
                yield
        finally:
            del sabnzbd.Downloader
            del sabnzbd.Scheduler
            del sabnzbd.notifier
            del sabnzbd.emailer

    def _set_diskspace(self, download_free_gb: float, complete_free_gb: float, complete_path: str = "/complete"):
        self.mock_diskspace.return_value = (
            Diskspace(path="/download", free=download_free_gb),
            Diskspace(path=complete_path, free=complete_free_gb),
        )

    def test_download_dir_full(self):
        """Pause when download_dir has insufficient space"""
        # download_free=1GiB, nzf.bytes=0.5GiB => required = 1.5 GiB, free = 1.0 GiB
        self._set_diskspace(download_free_gb=1.0, complete_free_gb=50.0)
        Assembler.diskspace_check(self.nzo, self.nzf)

        expected_required = (1 * GIGI + self.nzf.bytes) / GIGI
        self.mock_downloader.pause.assert_called_once()
        self.mock_scheduler.plan_diskspace_resume.assert_called_once_with("/download", expected_required)

    def test_complete_dir_full_direct_unpack(self):
        """Pause when complete_dir is full during direct_unpack"""
        self._set_diskspace(download_free_gb=50.0, complete_free_gb=1.0)
        self.mock_cfg.direct_unpack.return_value = True

        Assembler.diskspace_check(self.nzo, self.nzf)

        expected_required = (2 * GIGI) / GIGI
        self.mock_downloader.pause.assert_called_once()
        self.mock_scheduler.plan_diskspace_resume.assert_called_once_with("/complete", expected_required)

    def test_complete_dir_full_near_completion(self):
        """Pause when complete_dir is full and download is >95% done"""
        self.nzo.bytes_tried = int(self.nzo.bytes * 0.96)
        self.nzo.bytes_par2 = 0
        self._set_diskspace(download_free_gb=50.0, complete_free_gb=1.0)

        Assembler.diskspace_check(self.nzo, self.nzf)

        expected_required = (2 * GIGI + self.nzo.bytes) / GIGI  # (complete_free + nzo.bytes)
        self.mock_downloader.pause.assert_called_once()
        self.mock_scheduler.plan_diskspace_resume.assert_called_once_with("/complete", expected_required)

    def test_complete_dir_no_check_below_95_percent(self):
        """No complete_dir check when download is below 95% and not direct_unpack"""
        self.nzo.bytes_tried = int(self.nzo.bytes * 0.50)
        self._set_diskspace(download_free_gb=50.0, complete_free_gb=0.1)

        Assembler.diskspace_check(self.nzo, self.nzf)

        self.mock_downloader.pause.assert_not_called()
        self.mock_scheduler.plan_diskspace_resume.assert_not_called()

    def test_complete_dir_custom_path(self):
        """full_dir is the actual path when complete_dir differs from default"""
        custom_path = "/custom/complete"
        self.mock_get_complete_dir.return_value = (custom_path, None, True)
        self._set_diskspace(download_free_gb=50.0, complete_free_gb=1.0, complete_path=custom_path)
        self.mock_cfg.direct_unpack.return_value = True

        Assembler.diskspace_check(self.nzo, self.nzf)

        self.mock_downloader.pause.assert_called_once()
        self.mock_scheduler.plan_diskspace_resume.assert_called_once_with(custom_path, mock.ANY)

    def test_enough_space(self):
        """No action when both dirs have sufficient space"""
        self._set_diskspace(download_free_gb=50.0, complete_free_gb=50.0)

        Assembler.diskspace_check(self.nzo, self.nzf)

        self.mock_downloader.pause.assert_not_called()
        self.mock_scheduler.plan_diskspace_resume.assert_not_called()
        self.mock_notifier.send_notification.assert_not_called()
        self.mock_emailer.diskfull_mail.assert_not_called()

    def test_autoresume_disabled(self):
        """plan_diskspace_resume not called when fulldisk_autoresume is off"""
        self._set_diskspace(download_free_gb=1.0, complete_free_gb=50.0)
        self.mock_cfg.fulldisk_autoresume.return_value = False

        Assembler.diskspace_check(self.nzo, self.nzf)

        self.mock_downloader.pause.assert_called_once()
        self.mock_scheduler.plan_diskspace_resume.assert_not_called()

    def test_download_dir_full_notifications(self):
        """Verify notifications and email are sent on disk full"""
        self._set_diskspace(download_free_gb=1.0, complete_free_gb=50.0)

        Assembler.diskspace_check(self.nzo, self.nzf)

        self.mock_notifier.send_notification.assert_called_once()
        self.mock_emailer.diskfull_mail.assert_called_once()
