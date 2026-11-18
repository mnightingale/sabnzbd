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
tests.test_nzbfile - Testing functions in nzb/file.py
"""

from collections import deque
from datetime import datetime
from unittest import mock

import pytest

from sabnzbd.nzb import NzbFile, NzbObject
from tests.testhelper import SAB_CACHE_DIR


@pytest.mark.usefixtures("clean_cache_dir")
class TestNzbFile:
    @pytest.mark.config({"download_dir": SAB_CACHE_DIR})
    @pytest.mark.parametrize(
        "filenames",
        [
            [
                "hello.world.par2",
                "hello.world.part01.rar",
                "hello.world.part02.rar",
                "hello.world.part03.rar",
                "hello.world.sample.mkv",
                "hello.world.sfv",
                "hello.world.nfo",
                "hello.world.vol000-001.par2",
                "hello.world.vol001-003.par2",
            ],
            [
                "a.s01e01.par2",
                "a.s01e01.vol000-001.par2",
                "a.s01e01.vol001-003.par2",
                "a.s01e02.par2",
                "a.s01e02.vol000-001.par2",
                "a.s01e02.rar",
                "a.s01e02.vol000-001.par2",
                "a.s01e03.rar",
                "a.s01e03.r00",
                "a.s01e01.rar",
                "a.s01e01.sfv",
                "a.s01e03.r01",
                "a.s01e02.r00",
                "a.s01e03.par2",
                "a.s01e01.sample.mkv",
                "a.s01e02.sample.mkv",
                "a.s01e03.sample.mkv",
            ],
        ],
    )
    def test_sort_is_consistent(self, filenames: list[str]):
        """Test sorting of nzb files is deterministic, this is that the order of input does not matter."""
        nzo = NzbObject("test")

        def make_nzf(filename: str):
            return NzbFile(
                date=datetime.now(),
                subject=filename,
                raw_article_db=[(filename, 0)],
                file_bytes=0,
                nzo=nzo,
            )

        files1 = [make_nzf(filename) for filename in filenames]
        files2 = [make_nzf(filename) for filename in reversed(filenames)]

        files1.sort()
        files2.sort()

        assert [f.filename for f in files1] == [f.filename for f in files2]


class Server:
    def __init__(self, server_id: str, priority: int = 0):
        self.id = server_id
        self.priority = priority
        self.active = True
        self.article_queue = deque()


@pytest.mark.usefixtures("clean_cache_dir")
@pytest.mark.config({"download_dir": SAB_CACHE_DIR})
class TestRemainingArticles:
    def make_nzf(self, count: int = 10) -> NzbFile:
        nzo = NzbObject("remaining")
        nzf = NzbFile(datetime.now(), "file.bin", [], 0, nzo)
        nzo.files.append(nzf)
        for index in range(count):
            nzf.add_article(("article-%d@test" % index, 100))
        return nzf

    def fetch(self, nzf: NzbFile, server: Server, fetch_limit: int) -> list[int]:
        server.article_queue.clear()
        nzf.reset_try_list()
        nzf.get_articles(server, [server], fetch_limit)
        return [nzf.decodetable.index(article) for article in server.article_queue]

    def test_articles_are_handed_out_in_order_skipping_those_in_flight(self):
        nzf = self.make_nzf()
        server = Server("s1")
        assert self.fetch(nzf, server, 3) == [0, 1, 2]
        assert self.fetch(nzf, server, 3) == [3, 4, 5]

    def test_a_returned_article_is_offered_before_new_ones(self):
        nzf = self.make_nzf()
        server = Server("s1")
        self.fetch(nzf, server, 4)
        nzf.decodetable[1].allow_new_fetcher()
        assert self.fetch(nzf, server, 2) == [1, 4]

    def test_an_article_a_server_has_tried_is_left_for_other_servers(self):
        nzf = self.make_nzf(3)
        primary = Server("s1")
        backup = Server("s2", priority=1)
        self.fetch(nzf, primary, 1)
        article = nzf.decodetable[0]
        article.add_to_try_list(primary)
        article.allow_new_fetcher(remove_fetcher_from_try_list=False)
        assert self.fetch(nzf, primary, 3) == [1, 2]
        backup.article_queue.clear()
        nzf.get_articles(backup, [primary, backup], 3)
        assert list(backup.article_queue) == [article]

    def test_removing_articles_in_any_state_completes_the_file(self):
        nzf = self.make_nzf(6)
        server = Server("s1")
        self.fetch(nzf, server, 3)
        nzf.decodetable[1].allow_new_fetcher()
        in_flight, waiting, fresh = nzf.decodetable[0], nzf.decodetable[1], nzf.decodetable[4]
        assert not nzf.remove_article(in_flight, True)
        assert not nzf.remove_article(waiting, False)
        assert not nzf.remove_article(fresh, True)
        assert nzf.articles_left == 3
        assert waiting.failed
        assert nzf.bytes_left == -200
        assert not nzf.remove_article(fresh, True)
        assert nzf.bytes_left == -200
        assert self.fetch(nzf, server, 5) == [3, 5]
        for index in (2, 3):
            assert not nzf.remove_article(nzf.decodetable[index], True)
        assert not nzf.completed
        assert nzf.remove_article(nzf.decodetable[5], True)
        assert nzf.completed
        assert nzf.articles_left == 0

    def reload(self, nzf: NzbFile, state: dict) -> NzbFile:
        loaded = NzbFile.__new__(NzbFile)
        with mock.patch("sabnzbd.Downloader", mock.Mock(servers=[]), create=True):
            loaded.__setstate__(state)
        for article in loaded.decodetable:
            article.nzf = loaded
            article.fetcher = None
        return loaded

    def test_articles_in_flight_when_saved_are_fetched_again_after_loading(self):
        nzf = self.make_nzf(5)
        server = Server("s1")
        self.fetch(nzf, server, 2)
        nzf.decodetable[1].allow_new_fetcher()
        nzf.remove_article(nzf.decodetable[0], True)
        nzf = self.reload(nzf, nzf.__getstate__())
        assert nzf.articles_left == 4
        assert self.fetch(nzf, server, 5) == [1, 2, 3, 4]

    def test_a_queue_saved_with_the_remaining_articles_dict_resumes(self):
        nzf = self.make_nzf(6)
        server, other = Server("s1"), Server("s2")
        state = nzf.__getstate__()
        del state["next_index"], state["waiting"]
        remaining = [nzf.decodetable[index] for index in (1, 3, 4, 5)]
        state["articles"] = {article: article for article in remaining}
        remaining[2].add_to_try_list(server)
        nzf = self.reload(nzf, state)
        assert nzf.articles_left == 4
        assert self.fetch(nzf, server, 6) == [1, 3, 5]
        assert self.fetch(nzf, other, 6) == [4]
        for article in remaining:
            nzf.remove_article(article, True)
        assert nzf.completed

    def test_resetting_try_lists_frees_articles_stuck_in_flight(self):
        nzf = self.make_nzf(3)
        server = Server("s1")
        self.fetch(nzf, server, 2)
        nzf.reset_all_try_lists()
        assert self.fetch(nzf, server, 3) == [0, 1, 2]
