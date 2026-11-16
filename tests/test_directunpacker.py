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
tests.test_directunpacker - Direct Unpack through rars, fed volumes as they are assembled
"""

import os
import random
import types
from pathlib import Path
from unittest import mock

import pytest
import rars

from sabnzbd import directunpacker
from tests.testhelper import make_mock_nzo, wait_for


def write_set(directory: Path, setname: str, members: dict[str, bytes], fmt: str = "rar50") -> list[Path]:
    builder = rars.RarBuilder(version=fmt, level=0, volume_size=16384)
    for name, data in members.items():
        builder.add_bytes(data, name)
    directory.mkdir(parents=True, exist_ok=True)
    first = f"{setname}.part01.rar" if fmt == "rar50" else f"{setname}.rar"
    return builder.write(directory / first)


class Job:
    """Stands in for the assembler finishing one volume after another"""

    def __init__(self, tmp_path: Path, monkeypatch, flat_unpack: bool = False):
        self.made = tmp_path / "made"
        self.incoming = tmp_path / "incoming"
        self.incoming.mkdir()
        self.extraction_path = tmp_path / "complete"
        self.extraction_path.mkdir()
        self.nzo = make_mock_nzo(
            download_path=str(self.incoming),
            final_name="job",
            unpack=True,
            first_articles=[],
            finished_files=[],
            removed_from_queue=False,
        )
        monkeypatch.setattr(
            directunpacker,
            "cfg",
            mock.Mock(
                **{
                    "enable_unrar.return_value": True,
                    "direct_unpack.return_value": True,
                    "direct_unpack_tested.return_value": True,
                    "direct_unpack_threads.return_value": 3,
                    "flat_unpack.return_value": flat_unpack,
                }
            ),
        )
        monkeypatch.setattr(
            directunpacker,
            "prepare_extraction_path",
            lambda nzo: (str(self.extraction_path), str(self.extraction_path), None, flat_unpack, None),
        )
        monkeypatch.setattr(directunpacker, "ACTIVE_UNPACKERS", [])
        self.unpacker = directunpacker.DirectUnpacker(self.nzo)

    def queue(self, volumes: list[Path]):
        for volume in volumes:
            nzf = types.SimpleNamespace(filename=volume.name, setname=None, vol=None, assembled=False)
            self.nzo.files.append(nzf)

    def assemble(self, volume: Path):
        nzf = next(nzf for nzf in self.nzo.files if nzf.filename == volume.name)
        os.replace(volume, self.incoming / volume.name)
        nzf.assembled = True
        self.nzo.files.remove(nzf)
        self.nzo.finished_files.append(nzf)
        self.nzo.add_to_direct_unpacker(nzf)

    def finish(self):
        self.nzo.removed_from_queue = True
        with self.unpacker.next_file_lock:
            self.unpacker.next_file_lock.notify()
        self.unpacker.join(timeout=10)
        assert not self.unpacker.is_alive()


@pytest.fixture
def job(tmp_path, monkeypatch):
    job = Job(tmp_path, monkeypatch)
    job.nzo.add_to_direct_unpacker = job.unpacker.add
    return job


class TestDirectUnpacker:
    PAYLOAD = random.Random(7).randbytes(100_000)

    def test_extracts_while_volumes_arrive(self, job):
        volumes = write_set(job.made, "show", {"dir/show.mkv": self.PAYLOAD, "show.nfo": b"nfo"})
        assert len(volumes) > 3
        job.queue(volumes)

        for volume in volumes:
            job.assemble(volume)
            # The extraction has to be waiting on the next volume, not on the whole set
            wait_for(lambda: not job.unpacker.is_alive() or job.unpacker.cur_volume >= volumes.index(volume) + 1)
        job.finish()

        assert (job.extraction_path / "dir" / "show.mkv").read_bytes() == self.PAYLOAD
        assert (job.extraction_path / "show.nfo").read_bytes() == b"nfo"
        volume_paths, extracted = job.unpacker.success_sets["show"]
        assert [Path(p).name for p in volume_paths] == [v.name for v in volumes]
        assert str(job.extraction_path / "dir" / "show.mkv") in extracted

    @pytest.mark.parametrize("fmt", ["rar29", "rar20"])
    def test_extracts_old_style_volume_names(self, job, fmt):
        volumes = write_set(job.made, "show", {"show.mkv": self.PAYLOAD}, fmt=fmt)
        assert [v.name for v in volumes[:3]] == ["show.rar", "show.r00", "show.r01"]
        job.queue(volumes)
        for volume in volumes:
            job.assemble(volume)
        wait_for(lambda: "show" in job.unpacker.success_sets)
        job.finish()
        assert (job.extraction_path / "show.mkv").read_bytes() == self.PAYLOAD

    def test_moves_on_to_the_next_set(self, job):
        first = write_set(job.made / "a", "first", {"first.bin": self.PAYLOAD})
        second = write_set(job.made / "b", "second", {"second.bin": self.PAYLOAD[::-1]})
        job.queue(first + second)
        for volume in first + second:
            job.assemble(volume)
        wait_for(lambda: len(job.unpacker.success_sets) == 2)
        job.finish()
        assert (job.extraction_path / "first.bin").read_bytes() == self.PAYLOAD
        assert (job.extraction_path / "second.bin").read_bytes() == self.PAYLOAD[::-1]

    def test_abort_while_waiting_for_a_volume_removes_the_output(self, job):
        volumes = write_set(job.made, "show", {"show.mkv": self.PAYLOAD})
        job.queue(volumes)
        for volume in volumes[:3]:
            job.assemble(volume)
        wait_for(lambda: job.unpacker.cur_volume == 3)

        job.unpacker.abort()
        job.unpacker.join(timeout=10)

        assert not job.unpacker.is_alive()
        assert not job.unpacker.success_sets
        assert not job.extraction_path.exists()

    def test_missing_volume_fails_once_post_processing_starts(self, job):
        volumes = write_set(job.made, "show", {"show.mkv": self.PAYLOAD})
        job.queue(volumes)
        for volume in volumes[:2] + volumes[3:]:
            job.assemble(volume)
        wait_for(lambda: job.unpacker.cur_volume == 2)

        job.nzo.pp_active = True
        with job.unpacker.next_file_lock:
            job.unpacker.next_file_lock.notify()
        job.unpacker.join(timeout=10)

        assert not job.unpacker.is_alive()
        assert not job.unpacker.success_sets
        assert not job.extraction_path.exists()

    def test_wrong_password_aborts(self, job):
        builder = rars.RarBuilder(version="rar50", level=0, volume_size=16384, password="right")
        builder.add_bytes(self.PAYLOAD, "show.mkv")
        job.made.mkdir()
        volumes = builder.write(job.made / "show.part01.rar")
        job.nzo.password = "wrong"
        job.queue(volumes)
        for volume in volumes:
            job.assemble(volume)
        job.unpacker.join(timeout=10)
        assert not job.unpacker.success_sets
        assert not job.extraction_path.exists()

    def test_flat_unpack_moves_files_to_the_root(self, tmp_path, monkeypatch):
        job = Job(tmp_path, monkeypatch, flat_unpack=True)
        job.nzo.add_to_direct_unpacker = job.unpacker.add
        volumes = write_set(job.made, "show", {"deep/er/show.mkv": self.PAYLOAD})
        job.queue(volumes)
        for volume in volumes:
            job.assemble(volume)
        wait_for(lambda: "show" in job.unpacker.success_sets)
        job.finish()
        assert sorted(os.listdir(job.extraction_path)) == ["show.mkv"]
        assert job.unpacker.success_sets["show"][1] == [str(job.extraction_path / "show.mkv")]
