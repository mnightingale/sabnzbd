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
tests.test_storage - Testing sabnzbd.storage
"""

import os

import pytest

import sabnzbd.storage as storage


@pytest.fixture(autouse=True)
def clear_cache():
    storage.forget()
    yield
    storage.forget()


class TestProbe:
    def test_measures_the_directory_it_is_given(self, tmp_path):
        profile = storage.probe(str(tmp_path))
        assert profile.measured, profile.error
        assert profile.ops >= storage.PROBE_MIN_OPS
        assert profile.iops > 0
        assert profile.mbps > 0
        assert profile.device == os.stat(tmp_path).st_dev

    def test_leaves_nothing_behind(self, tmp_path):
        """It writes into the user's download directory, so it has to clean up even
        though the file is sparse"""
        before = set(os.listdir(tmp_path))
        storage.probe(str(tmp_path))
        assert set(os.listdir(tmp_path)) == before

    def test_writes_are_bounded(self, tmp_path):
        """A probe that ran unbounded would write PROBE_SPAN to every destination"""
        storage.probe(str(tmp_path))
        assert storage.PROBE_MAX_OPS * storage.PROBE_BLOCK <= 16 * 1024 * 1024

    def test_a_missing_directory_is_unmeasured_rather_than_an_error(self, tmp_path):
        profile = storage.probe(str(tmp_path / "does_not_exist"))
        assert not profile.measured
        assert profile.error
        assert profile.supports_random_writes is False

    def test_an_unwritable_directory_is_unmeasured(self, tmp_path):
        if os.getuid() == 0:
            pytest.skip("root writes anywhere")
        locked = tmp_path / "locked"
        locked.mkdir()
        os.chmod(locked, 0o500)
        try:
            profile = storage.probe(str(locked))
            assert not profile.measured
            assert profile.supports_random_writes is False
        finally:
            os.chmod(locked, 0o700)

    def test_the_deadline_bounds_a_slow_device(self, tmp_path, monkeypatch):
        """On a spinning disk each write costs a seek, so the op count alone would let
        the probe run for the best part of a second"""
        real_fsync = os.fsync
        calls = []

        def slow(handle):
            calls.append(handle)
            real_fsync(handle)
            # Roughly one seek, so the budget runs out well before PROBE_MAX_OPS
            import time

            time.sleep(0.01)

        # The durable write is the whole per-operation cost, and its flush half is the
        # part that stalls on a seek, so that is where the delay belongs
        monkeypatch.setattr(storage.os, "fsync", slow)
        profile = storage.probe(str(tmp_path))

        assert len(calls) < storage.PROBE_MAX_OPS, "the deadline did not stop it"
        assert profile.seconds < storage.PROBE_TIME_BUDGET * 3


class TestClassification:
    """Misreading a solid state disk as slow costs nothing - writes stay ordered, as
    they are today. Misreading a spinning disk as fast costs a seek per article. The
    threshold is placed accordingly."""

    @staticmethod
    def profile(iops):
        return storage.DeviceProfile(device=1, path="/x", iops=iops, ops=storage.PROBE_MAX_OPS, seconds=1.0)

    def test_a_spinning_disk_is_not_fast(self):
        # 7200 rpm seeks in 7-12 ms, so this is the whole plausible range
        for iops in (50, 80, 130, 200):
            assert self.profile(iops).supports_random_writes is False

    def test_solid_state_is_fast(self):
        for iops in (1000, 8000, 50000):
            assert self.profile(iops).supports_random_writes is True

    def test_the_threshold_clears_a_spinning_disk_by_a_wide_margin(self):
        """Placed in the gap between the two populations rather than near either"""
        assert storage.FAST_RANDOM_WRITE_IOPS > 130 * 2

    def test_an_unmeasured_device_is_treated_as_slow(self):
        assert storage.DeviceProfile(device=1, path="/x", error="nope").supports_random_writes is False

    def test_too_few_samples_is_not_a_measurement(self):
        """A couple of lucky writes say nothing, and would divide into a huge rate"""
        thin = storage.DeviceProfile(device=1, path="/x", iops=99999, ops=storage.PROBE_MIN_OPS - 1, seconds=0.001)
        assert thin.measured is False
        assert thin.supports_random_writes is False


class TestCaching:
    def test_one_probe_per_device(self, tmp_path, monkeypatch):
        """download_dir and complete_dir on one disk must not pay twice"""
        probes = []
        real_probe = storage.probe
        monkeypatch.setattr(storage, "probe", lambda path: probes.append(path) or real_probe(path))

        first = tmp_path / "downloads"
        second = tmp_path / "complete"
        first.mkdir()
        second.mkdir()

        a = storage.profile_for(str(first))
        b = storage.profile_for(str(second))

        assert len(probes) == 1, "the second path shares a device and was probed again"
        assert a is b

    def test_repeat_requests_are_cached(self, tmp_path, monkeypatch):
        probes = []
        real_probe = storage.probe
        monkeypatch.setattr(storage, "probe", lambda path: probes.append(path) or real_probe(path))

        for _ in range(5):
            storage.profile_for(str(tmp_path))
        assert len(probes) == 1

    def test_forget_allows_reprobing(self, tmp_path, monkeypatch):
        probes = []
        real_probe = storage.probe
        monkeypatch.setattr(storage, "probe", lambda path: probes.append(path) or real_probe(path))

        storage.profile_for(str(tmp_path))
        storage.forget()
        storage.profile_for(str(tmp_path))
        assert len(probes) == 2

    def test_a_failing_path_does_not_poison_the_cache_for_others(self, tmp_path):
        missing = storage.profile_for(str(tmp_path / "gone"))
        assert not missing.measured
        assert storage.profile_for(str(tmp_path)).measured


class TestReporting:
    def test_str_says_what_it_will_do(self, tmp_path):
        fast = storage.DeviceProfile(device=1, path="/x", iops=8000, mbps=1000, ops=64, seconds=0.008)
        slow = storage.DeviceProfile(device=1, path="/x", iops=90, mbps=11, ops=45, seconds=0.5)
        assert "scattered writes" in str(fast)
        assert "sequential writes" in str(slow)
        assert "unmeasured" in str(storage.DeviceProfile(device=1, path="/x", error="boom"))


class TestHotPathAccessor:
    """article_sink() consults this while a connection waits, so it must never be the
    thing that runs a probe"""

    def test_cached_profile_does_not_probe(self, tmp_path, monkeypatch):
        monkeypatch.setattr(storage, "probe", lambda path: pytest.fail("probed on the hot path"))
        assert storage.cached_profile(str(tmp_path)) is None

    def test_cached_profile_returns_a_measured_one(self, tmp_path):
        measured = storage.profile_for(str(tmp_path))
        assert storage.cached_profile(str(tmp_path)) is measured

    def test_unknown_reads_as_no(self, monkeypatch):
        """Before the startup profile lands, the answer has to be the safe one"""
        monkeypatch.setattr(storage, "cached_profile", lambda path: None)
        assert storage.download_dir_supports_random_writes() is False

    def test_follows_the_measurement(self, monkeypatch):
        for iops, expected in ((90, False), (8000, True)):
            monkeypatch.setattr(
                storage,
                "cached_profile",
                lambda path, iops=iops: storage.DeviceProfile(
                    device=1, path="/x", iops=iops, ops=storage.PROBE_MAX_OPS, seconds=1.0
                ),
            )
            assert storage.download_dir_supports_random_writes() is expected

    def test_an_unmeasurable_device_reads_as_no(self, monkeypatch):
        monkeypatch.setattr(
            storage, "cached_profile", lambda path: storage.DeviceProfile(device=1, path="/x", error="boom")
        )
        assert storage.download_dir_supports_random_writes() is False
