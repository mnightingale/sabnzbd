#!/usr/bin/python3 -OO
# Copyright 2007-2025 by The SABnzbd-Team (sabnzbd.org)
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
tests.test_nzbqueue - queue-manipulation behavior and micro-benchmarks
"""

import random

import pytest
from unittest.mock import Mock

import sabnzbd
from sabnzbd.nzb import NzbObject, NzbFile
from sabnzbd.nzbqueue import NzbQueue
from sabnzbd.constants import Status, LOW_PRIORITY, NORMAL_PRIORITY, HIGH_PRIORITY, FORCE_PRIORITY, REPAIR_PRIORITY


def make_dummy_nzo(name: str, priority: int) -> NzbObject:
    work_name = f"job-{name}"

    nzo = NzbObject(work_name, priority=priority)
    nzo.save_to_disk = Mock()
    nzo.files = [
        NzbFile(
            date=nzo.avg_date,
            subject="test-file",
            raw_article_db=[[None, None]],
            file_bytes=0,
            nzo=nzo,
        )
    ]

    return nzo


@pytest.fixture(autouse=True)
def dummy_env(monkeypatch, mocker, tmp_path):
    """
    Keep the benchmark focused on NzbQueue data-structure behavior:
    - Make Scheduler.analyse cheap.
    - Make Assembler a no-op.
    - Avoid writing queue admin to disk.
    """
    # Scheduler.analyse(False, priority) -> always "no schedule pause"
    sabnzbd.Scheduler = mocker.Mock()
    sabnzbd.Scheduler.analyse = mocker.Mock(return_value=False)
    sabnzbd.Assembler = mocker.Mock()
    sabnzbd.Downloader = mocker.Mock()
    sabnzbd.ArticleCache = mocker.Mock()
    monkeypatch.setattr(sabnzbd.filesystem, "save_admin", lambda *a, **k: None)
    monkeypatch.setattr(sabnzbd.filesystem, "save_data", lambda *a, **k: None)
    monkeypatch.setattr(sabnzbd.notifier, "send_notification", lambda *a, **k: None)
    monkeypatch.setattr(sabnzbd.cfg.admin_dir, "get_path", lambda: str(tmp_path))
    monkeypatch.setattr(sabnzbd.cfg.download_dir, "get_path", lambda: str(tmp_path))

    yield

    del sabnzbd.Scheduler
    del sabnzbd.Assembler
    del sabnzbd.Downloader
    del sabnzbd.ArticleCache


@pytest.fixture(params=[10, 100, 1000])
def queue_size(request):
    return request.param


class TestNzbQueueBenchmark:
    def test_bench_add(self, benchmark, queue_size):
        """
        Benchmark adding N dummy jobs with mixed priorities into an empty queue.
        Includes only add() cost (save=False).
        """
        priorities = [FORCE_PRIORITY, HIGH_PRIORITY, NORMAL_PRIORITY, LOW_PRIORITY]

        def run():
            q = NzbQueue()
            for i in range(queue_size):
                prio = random.choice(priorities)
                nzo = make_dummy_nzo(str(i), prio)
                q.add(nzo, save=False, quiet=True)

        benchmark(run)

    def test_bench_change_priority(self, benchmark, queue_size):
        """
        Benchmark changing priority of existing jobs.
        Queue is built once; each benchmark iteration performs queue_size
        random set_priority() calls on that fixed set.
        """
        priorities = [FORCE_PRIORITY, HIGH_PRIORITY, NORMAL_PRIORITY, LOW_PRIORITY]

        q = NzbQueue()
        for i in range(queue_size):
            prio = random.choice(priorities)
            nzo = make_dummy_nzo(str(i), prio)
            q.add(nzo, save=False, quiet=True)

        nzo_ids = list(q._NzbQueue__nzo_table.keys())

        def run():
            for _ in range(queue_size):
                nzo_id = random.choice(nzo_ids)
                new_prio = random.choice(priorities)
                q.set_priority([nzo_id], new_prio)

        benchmark(run)

    def test_bench_reorder_switch(self, benchmark, queue_size):
        """
        Benchmark reordering via switch() between random pairs of jobs.
        Queue is built once; each iteration performs queue_size switches.
        """
        priorities = [FORCE_PRIORITY, HIGH_PRIORITY, NORMAL_PRIORITY, LOW_PRIORITY]

        q = NzbQueue()
        for i in range(queue_size):
            prio = random.choice(priorities)
            nzo = make_dummy_nzo(str(i), prio)
            q.add(nzo, save=False, quiet=True)

        nzo_ids = list(q._NzbQueue__nzo_table.keys())

        def run():
            for _ in range(queue_size):
                a, b = random.sample(nzo_ids, 2)
                q.switch(a, b)

        benchmark(run)

    def test_bench_remove(self, benchmark, queue_size):
        """
        Benchmark removing all jobs from the queue (no cleanup/purge).
        Each benchmark iteration builds a fresh queue of size N and removes all jobs.
        """
        priorities = [REPAIR_PRIORITY, FORCE_PRIORITY, HIGH_PRIORITY, NORMAL_PRIORITY, LOW_PRIORITY]

        def run():
            q = NzbQueue()
            for i in range(queue_size):
                prio = random.choice(priorities)
                nzo = make_dummy_nzo(str(i), prio)
                q.add(nzo, save=False, quiet=True)

            nzo_ids = list(q._NzbQueue__nzo_table.keys())
            random.shuffle(nzo_ids)

            for nid in nzo_ids:
                q.remove(nid, cleanup=False, delete_all_data=False)

        benchmark(run)

    def test_bench_remove_top(self, benchmark, queue_size):
        """
        Benchmark removing all jobs from the queue (no cleanup/purge).
        Each benchmark iteration builds a fresh queue of size N and removes all jobs top to bottom.
        """
        priorities = [REPAIR_PRIORITY, FORCE_PRIORITY, HIGH_PRIORITY, NORMAL_PRIORITY, LOW_PRIORITY]

        def run():
            q = NzbQueue()
            for i in range(queue_size):
                prio = random.choice(priorities)
                nzo = make_dummy_nzo(str(i), prio)
                q.add(nzo, save=False, quiet=True)

            nzo_ids = list(q._NzbQueue__nzo_table.keys())

            for nid in nzo_ids:
                q.remove(nid, cleanup=False, delete_all_data=False)

        benchmark(run)


class TestNzbQueue:
    @pytest.fixture
    def queue(self, dummy_env):
        return NzbQueue()

    def test_add_inserts_and_tracks_jobs(self, queue):
        a = make_dummy_nzo("a", priority=NORMAL_PRIORITY)
        b = make_dummy_nzo("b", priority=LOW_PRIORITY)
        c = make_dummy_nzo("c", priority=FORCE_PRIORITY)

        ida = queue.add(a, save=False, quiet=True)
        idb = queue.add(b, save=False, quiet=True)
        idc = queue.add(c, save=False, quiet=True)

        # All ids registered
        assert queue.get_nzo(ida) is a
        assert queue.get_nzo(idb) is b
        assert queue.get_nzo(idc) is c

        # queue_info returns all three, first should be the forced job
        _, _, _, nzo_list, _, count = queue.queue_info()
        assert count == 3
        assert [n.final_name for n in nzo_list] == [c.final_name, a.final_name, b.final_name]

    def test_remove_removes_from_queue_and_table(self, queue):
        a = make_dummy_nzo("a", priority=0)
        b = make_dummy_nzo("b", priority=0)
        c = make_dummy_nzo("c", priority=0)

        ida = queue.add(a, save=False, quiet=True)
        idb = queue.add(b, save=False, quiet=True)
        idc = queue.add(c, save=False, quiet=True)

        removed = queue.remove(idb, cleanup=False, delete_all_data=False)
        assert removed is b
        assert queue.get_nzo(idb) is None

        _, _, _, nzo_list, _, count = queue.queue_info()
        assert count == 2
        assert [nzo.final_name for nzo in nzo_list] == ["job-a", "job-c"]

    def test_remove_multiple_and_remove_all(self, queue):
        jobs = [make_dummy_nzo(f"job-{i}", priority=0) for i in range(5)]
        ids = [queue.add(nzo, save=False, quiet=True) for nzo in jobs]

        # Remove two specific jobs
        subset = ids[1:3]
        removed_ids = queue.remove_multiple(subset, delete_all_data=False)
        assert set(removed_ids) == set(subset)

        # Remaining ids still there
        remaining_ids = {nid for nid in ids if nid not in subset}
        assert {nzo.nzo_id for nzo in queue.queue_info()[3]} == remaining_ids

        # remove_all with search pattern should remove the rest
        removed_all = queue.remove_all(search="job-")
        assert set(removed_all) == remaining_ids
        assert queue.queue_info()[5] == 0  # nzos_matched

    def test_change_opts_sets_pp(self, queue):
        a = make_dummy_nzo("a", priority=LOW_PRIORITY)
        ida = queue.add(a, save=False, quiet=True)

        changed = queue.change_opts([ida], pp=3)
        assert changed == 1
        assert a.pp == 3

    def test_change_script_only_when_valid(self, queue, monkeypatch):
        from sabnzbd import nzbqueue as nzbqueue_mod

        # Always accept given script
        monkeypatch.setattr(nzbqueue_mod, "is_valid_script", lambda s: True)

        a = make_dummy_nzo("a", priority=0)
        b = make_dummy_nzo("b", priority=0)
        ida = queue.add(a, save=False, quiet=True)
        idb = queue.add(b, save=False, quiet=True)

        changed = queue.change_script([ida, idb], script="myscript.py")
        assert changed == 2
        assert a.script == "myscript.py"
        assert b.script == "myscript.py"

        # Now mark scripts invalid; no changes should be made
        monkeypatch.setattr(nzbqueue_mod, "is_valid_script", lambda s: False)
        changed = queue.change_script([ida, idb], script="other.py")
        assert changed == 0
        assert a.script == "myscript.py"
        assert b.script == "myscript.py"

    def test_change_cat_updates_cat_pp_script_and_priority(self, queue, monkeypatch):
        from sabnzbd import nzbqueue as nzbqueue_mod

        # Fake cat_to_opts: (cat, pp, script, prio)
        def fake_cat_to_opts(cat):
            return f"{cat}-cat", 2, "cat_script.py", FORCE_PRIORITY

        monkeypatch.setattr(nzbqueue_mod, "cat_to_opts", fake_cat_to_opts)

        a = make_dummy_nzo("a", priority=0)
        ida = queue.add(a, save=False, quiet=True)

        changed = queue.change_cat([ida], cat="movies")
        assert changed == 1
        assert a.cat == "movies-cat"
        assert a.script == "cat_script.py"
        assert a.priority == FORCE_PRIORITY

    def test_change_name_updates_final_name(self, queue):
        a = make_dummy_nzo("a", priority=0)
        ida = queue.add(a, save=False, quiet=True)

        ok = queue.change_name(ida, "renamed")
        assert ok is True
        assert a.final_name == "renamed"

    @staticmethod
    def get_queue_order(queue):
        return [n.final_name for n in queue.queue_info()[3]]

    def test_set_priority_moves_job_to_forced_top(self, queue):
        a = make_dummy_nzo("a", priority=0)
        b = make_dummy_nzo("b", priority=0)
        c = make_dummy_nzo("c", priority=0)

        ida = queue.add(a, save=False, quiet=True)
        idb = queue.add(b, save=False, quiet=True)
        idc = queue.add(c, save=False, quiet=True)

        assert self.get_queue_order(queue) == ["job-a", "job-b", "job-c"]

        # Set b to FORCE_PRIORITY, should go to the top
        pos = queue.set_priority([idb], FORCE_PRIORITY)
        # pos is index; we just verify ordering
        assert self.get_queue_order(queue)[0] == "job-b"
        assert b.priority == FORCE_PRIORITY

    def test_switch_swaps_positions(self, queue):
        a = make_dummy_nzo("a", priority=NORMAL_PRIORITY)
        b = make_dummy_nzo("b", priority=NORMAL_PRIORITY)
        c = make_dummy_nzo("c", priority=NORMAL_PRIORITY)

        ida = queue.add(a, save=False, quiet=True)
        idb = queue.add(b, save=False, quiet=True)
        idc = queue.add(c, save=False, quiet=True)

        assert self.get_queue_order(queue) == ["job-a", "job-b", "job-c"]

        # Move a to c
        new_pos, _prio = queue.switch(ida, idc)
        assert new_pos != -1
        assert self.get_queue_order(queue) == ["job-b", "job-c", "job-a"]

    def test_has_forced_jobs_true_when_forced_and_active(self, queue):
        forced = make_dummy_nzo("forced", priority=FORCE_PRIORITY)
        normal = make_dummy_nzo("normal", priority=0)

        queue.add(forced, save=False, quiet=True)
        queue.add(normal, save=False, quiet=True)

        assert queue.has_forced_jobs() is True

        # If forced job is paused, it should no longer count
        forced.status = Status.PAUSED
        assert queue.has_forced_jobs() is False

    def test_has_forced_jobs_false_when_no_forced(self, queue):
        a = make_dummy_nzo("a", priority=0)
        b = make_dummy_nzo("b", priority=LOW_PRIORITY)
        queue.add(a, save=False, quiet=True)
        queue.add(b, save=False, quiet=True)

        assert queue.has_forced_jobs() is False
