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
tests.test_nzb_serializer - Round trip of the NzbObject graph
"""

import datetime
import os

import msgpack

import pytest

import sabnzbd
from sabnzbd.constants import ADMIN_EXT, NZO_FILE
from sabnzbd.filesystem import load_data, save_data
from sabnzbd.nzb import NzbObject
from sabnzbd.nzb.article import ArticleSaver
from sabnzbd.nzb.file import NzbFileSaver
from sabnzbd.nzb.object import NzbObjectSaver
from sabnzbd.nzb.serializer import ARTICLE_FIELDS, NZF_STRUCTURAL, NZO_STRUCTURAL, encode_nzo
from sabnzbd.par2file import FilePar2Info
from tests.test_nzbqueue import make_dummy_nzo, nzbqueue_env  # noqa: F401


def build_job(name: str = "job") -> NzbObject:
    """A job with every kind of reference the graph can hold"""
    nzo = make_dummy_nzo(name, files=3, articles=4)
    nzo.nzo_id = "nzo-" + name
    for nzf in nzo.files:
        nzf.finish_import()
        nzo.files_table[nzf.nzf_id] = nzf

    # A finished file, so both lists are populated
    finished = nzo.files.pop()
    finished.import_finished = True
    nzo.finished_files.append(finished)

    first, second = nzo.files
    nzo.first_articles = [first.decodetable[0], second.decodetable[0]]
    nzo.saved_articles = {first.decodetable[1], second.decodetable[2]}
    nzo.extrapars = {"setname": [second]}
    nzo.par2packs = {"setname": {"file.rar": FilePar2Info("file.rar", b"\x01\x02", 1234, 42, False)}}
    nzo.md5of16k = {b"\x03\x04": "file.rar"}
    nzo.avg_date = datetime.datetime(2024, 3, 1, 12, 30, 15)
    nzo.renames = {"obfuscated": "file.rar"}
    nzo.servercount = {"testserver1": 999}
    nzo.nzo_info = {"bad_articles": 2, "propername": "Some Name"}

    # A try-list on each level, and some article state
    server = sabnzbd.Downloader.servers[0]
    nzo.add_to_try_list(server)
    first.add_to_try_list(server)
    first.decodetable[0].add_to_try_list(server)
    first.decodetable[1].on_disk = True
    first.decodetable[1].crc32 = 0xDEADBEEF
    first.decodetable[2].failed = True
    return nzo


@pytest.mark.usefixtures("nzbqueue_env")
class TestSchemaCoverage:
    """A field added to a Saver tuple is encoded automatically, unless it holds an object
    reference or a type msgpack cannot carry. These pin that split so the miss is caught here
    rather than by silently dropping the msgpack copy."""

    def test_structural_names_still_exist(self):
        """A renamed field would leave a stale entry behind and start encoding a reference"""
        assert NZO_STRUCTURAL <= set(NzbObjectSaver)
        assert NZF_STRUCTURAL <= set(NzbFileSaver)
        assert set(ARTICLE_FIELDS) < set(ArticleSaver)

    def check_encodable(self, record, saver, structural, owner):
        for field in saver:
            if field in structural:
                continue
            try:
                msgpack.packb(record[field] if isinstance(record, dict) else getattr(record, field))
            except TypeError as err:
                pytest.fail(
                    "%s field %r cannot be carried by msgpack (%s). Add it to the structural set "
                    "and convert it in the encoder and decoder." % (owner, field, err)
                )

    def test_every_job_field_is_encodable(self):
        document = encode_nzo(build_job())
        self.check_encodable(document["nzo"], NzbObjectSaver, NZO_STRUCTURAL, "NzbObjectSaver")
        for record in document["files"] + document["finished_files"]:
            self.check_encodable(record, NzbFileSaver, NZF_STRUCTURAL, "NzbFileSaver")
        # The whole document has to pack, which also covers the hand-converted fields
        msgpack.packb(document)

    def test_every_job_field_round_trips(self, tmp_path):
        """Catches a field that encodes but is never read back"""
        nzo = build_job()
        save_data(nzo, NZO_FILE, str(tmp_path))
        os.remove(tmp_path / NZO_FILE)
        back = load_data(NZO_FILE, str(tmp_path), remove=False)

        for field in NzbObjectSaver:
            if field not in NZO_STRUCTURAL:
                assert getattr(back, field) == getattr(nzo, field), field
        for restored, original in zip(back.files, nzo.files):
            for field in NzbFileSaver:
                if field not in NZF_STRUCTURAL:
                    assert getattr(restored, field) == getattr(original, field), field
            for restored_article, original_article in zip(restored.decodetable, original.decodetable):
                for field in ARTICLE_FIELDS:
                    assert getattr(restored_article, field) == getattr(original_article, field), field


@pytest.mark.usefixtures("nzbqueue_env")
class TestNzoRoundTrip:
    def save_and_load(self, nzo, tmp_path, prefer):
        """Load back through only one of the two copies save_data writes"""
        save_data(nzo, NZO_FILE, str(tmp_path))
        drop = NZO_FILE if prefer == "msgpack" else NZO_FILE + ADMIN_EXT
        os.remove(tmp_path / drop)
        return load_data(NZO_FILE, str(tmp_path), remove=False)

    @pytest.mark.parametrize("prefer", ["msgpack", "pickle"])
    def test_graph_identity_is_restored(self, tmp_path, prefer):
        """Both readers must rebuild the same object graph, not just equal values"""
        nzo = build_job()
        back = self.save_and_load(nzo, tmp_path, prefer)

        assert isinstance(back, NzbObject)
        assert len(back.files) == 2 and len(back.finished_files) == 1

        for nzf in back.files + back.finished_files:
            assert nzf.nzo is back
            assert back.files_table[nzf.nzf_id] is nzf
            for index, article in enumerate(nzf.decodetable):
                assert article.nzf is nzf
                assert article.lock is nzf.lock
            # The outstanding articles are the very objects the decodetable holds
            for article in nzf.articles:
                assert nzf.articles[article] is article
                assert article is nzf.decodetable[nzf.decodetable.index(article)]

        first, second = back.files
        assert back.first_articles == [first.decodetable[0], second.decodetable[0]]
        assert back.saved_articles == {first.decodetable[1], second.decodetable[2]}
        assert back.extrapars["setname"] == [second]
        assert back.extrapars["setname"][0] is back.files_table[second.nzf_id]

    @pytest.mark.parametrize("prefer", ["msgpack", "pickle"])
    def test_values_are_restored(self, tmp_path, prefer):
        nzo = build_job()
        back = self.save_and_load(nzo, tmp_path, prefer)

        assert back.nzo_id == nzo.nzo_id
        assert back.final_name == nzo.final_name
        assert back.bytes == nzo.bytes
        assert back.avg_date == nzo.avg_date
        assert back.md5of16k == {b"\x03\x04": "file.rar"}
        assert back.renames == {"obfuscated": "file.rar"}
        assert back.servercount == {"testserver1": 999}
        assert back.nzo_info == {"bad_articles": 2, "propername": "Some Name"}
        assert back.par2packs["setname"]["file.rar"] == FilePar2Info("file.rar", b"\x01\x02", 1234, 42, False)

        original, restored = nzo.files[0], back.files[0]
        assert restored.date == original.date
        assert restored.filename == original.filename
        assert restored.bytes_left == original.bytes_left
        assert restored.decodetable[1].on_disk is True
        assert restored.decodetable[1].crc32 == 0xDEADBEEF
        assert restored.decodetable[2].failed is True
        assert [a.article for a in restored.decodetable] == [a.article for a in original.decodetable]

    @pytest.mark.parametrize("prefer", ["msgpack", "pickle"])
    def test_try_lists_are_restored(self, tmp_path, prefer):
        nzo = build_job()
        server = sabnzbd.Downloader.servers[0]
        back = self.save_and_load(nzo, tmp_path, prefer)

        assert back.server_in_try_list(server)
        assert back.files[0].server_in_try_list(server)
        assert back.files[0].decodetable[0].server_in_try_list(server)
        assert not back.files[1].server_in_try_list(server)

    @pytest.mark.parametrize("prefer", ["msgpack", "pickle"])
    def test_transient_state_is_reset(self, tmp_path, prefer):
        nzo = build_job()
        back = self.save_and_load(nzo, tmp_path, prefer)

        assert back.pp_active is False
        assert back.url_wait is None
        assert back.url_tries == 0
        assert back.to_be_removed is False
        assert back.direct_unpacker is None
        assert back.avg_stamp
        for nzf in back.files:
            assert nzf.assembler_next_index == 0
            assert nzf.writer is None
            for article in nzf.decodetable:
                assert article.fetcher is None
                assert article.tries == 0

    def test_both_copies_rebuild_the_same_job(self, tmp_path):
        """The two readers must not drift while both formats are written"""
        nzo = build_job()
        save_data(nzo, NZO_FILE, str(tmp_path))
        from_msgpack = load_data(NZO_FILE, str(tmp_path), remove=False)
        os.remove(tmp_path / (NZO_FILE + ADMIN_EXT))
        from_pickle = load_data(NZO_FILE, str(tmp_path), remove=False)

        # Re-encode both through the one canonical encoder, so attribute ordering cannot matter
        assert encode_nzo(from_msgpack) == encode_nzo(from_pickle)
