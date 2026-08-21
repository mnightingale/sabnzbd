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

import pytest

import sabctools
import sabnzbd.storage as storage

MB = 1024 * 1024


class FakeWrites:

    def __init__(self):
        self.totals = [0, 0, 0]

    def add(self, count: int, written: int, nanos: int):
        self.totals = [self.totals[0] + count, self.totals[1] + written, self.totals[2] + nanos]

    def __call__(self) -> dict:
        count, written, nanos = self.totals
        return {"count": count, "bytes": written, "nanos": nanos, "max_nanos": nanos}


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds: float):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(storage.time, "monotonic", fake)
    return fake


@pytest.fixture
def writes(monkeypatch):
    fake = FakeWrites()
    monkeypatch.setattr(sabctools, "write_stats", fake)
    return fake


@pytest.fixture
def monitor(clock, writes, monkeypatch):
    monkeypatch.setattr(storage, "rotational", lambda path: None)
    instance = storage.WriteMonitor()
    instance.reset("/downloads")
    return instance


def feed(monitor, clock, writes, samples: int, count: int, written: int, nanos: int):
    for _ in range(samples):
        writes.add(count, written, nanos)
        clock.advance(storage.SAMPLE_INTERVAL)
        monitor.sample()


# Either side of SLOW_WRITE_MBPS
FAST = dict(count=64, written=45 * MB, nanos=3_200_000)
SLOW = dict(count=64, written=8 * MB, nanos=400_000_000)

assert 1e9 / (FAST["nanos"] / FAST["written"]) / MB > storage.SLOW_WRITE_MBPS
assert 1e9 / (SLOW["nanos"] / SLOW["written"]) / MB < storage.SLOW_WRITE_MBPS


class TestRotationalHint:
    def test_a_path_with_no_block_device_says_nothing(self, tmp_path):
        assert storage.rotational(str(tmp_path / "does_not_exist")) is None

    def test_it_never_raises(self, tmp_path):
        assert storage.rotational(str(tmp_path)) in (True, False, None)
        assert storage.rotational("") is None


class TestOpeningMode:
    def test_a_rotational_disk_starts_ordered(self, clock, writes, monkeypatch):
        monkeypatch.setattr(storage, "rotational", lambda path: True)
        monitor = storage.WriteMonitor()
        monitor.reset("/downloads")
        assert monitor.allows_streaming() is False

    def test_solid_state_starts_streaming(self, clock, writes, monkeypatch):
        monkeypatch.setattr(storage, "rotational", lambda path: False)
        monitor = storage.WriteMonitor()
        monitor.reset("/downloads")
        assert monitor.allows_streaming() is True

    def test_no_opinion_starts_streaming(self, monitor):
        assert monitor.allows_streaming() is True


class TestBackingOff:
    def test_writes_being_absorbed_keep_it_streaming(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=10, **FAST)
        assert monitor.allows_streaming() is True

    def test_a_run_of_slow_samples_backs_off(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        assert monitor.allows_streaming() is False

    def test_one_slow_sample_is_not_enough(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=1, **SLOW)
        assert monitor.allows_streaming() is True

    def test_recovering_clears_the_run(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF - 1, **SLOW)
        feed(monitor, clock, writes, samples=5, **FAST)
        assert monitor.slow_samples == 0

        feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF - 1, **SLOW)
        assert monitor.allows_streaming() is True

    def test_one_stall_does_not_outweigh_the_samples_around_it(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=5, **FAST)
        feed(monitor, clock, writes, samples=1, **SLOW)
        assert 1e9 / monitor.cost / MB < storage.SLOW_WRITE_MBPS


class TestSampleQuality:
    def test_too_few_writes_is_not_a_sample(self, monitor, clock, writes):
        feed(
            monitor,
            clock,
            writes,
            samples=10,
            count=storage.MIN_SAMPLE_WRITES - 1,
            written=8 * MB,
            nanos=400_000_000,
        )
        assert monitor.cost is None
        assert monitor.allows_streaming() is True

    def test_too_few_bytes_is_not_a_sample(self, monitor, clock, writes):
        feed(
            monitor,
            clock,
            writes,
            samples=10,
            count=64,
            written=storage.MIN_SAMPLE_BYTES - 1,
            nanos=400_000_000,
        )
        assert monitor.cost is None
        assert monitor.allows_streaming() is True

    def test_samples_faster_than_the_interval_are_ignored(self, monitor, clock, writes):
        ticks = int(2 * storage.SAMPLE_INTERVAL / 0.05)
        for _ in range(ticks):
            # Each tick is enough on its own to be a slow sample
            writes.add(**SLOW)
            clock.advance(0.05)
            monitor.sample()
        assert monitor.allows_streaming() is True

    def test_only_new_writes_count(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=1, **FAST)
        first = monitor.cost
        feed(monitor, clock, writes, samples=1, **FAST)
        assert monitor.cost == pytest.approx(first, rel=0.01)


class TestRetrying:
    def test_it_tries_again_after_the_wait(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        assert monitor.allows_streaming() is False

        clock.advance(storage.RETRY_AFTER)
        monitor.sample()
        assert monitor.allows_streaming() is True

    def test_it_does_not_try_before_the_wait_is_up(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        clock.advance(storage.RETRY_AFTER / 2)
        monitor.sample()
        assert monitor.allows_streaming() is False

    def test_each_refusal_waits_longer(self, monitor, clock, writes):
        waits = []
        for _ in range(3):
            feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
            waits.append(monitor.retry_at - clock.now)
            clock.advance(waits[-1])
            monitor.sample()

        assert waits == sorted(waits)
        assert waits[1] > waits[0]

    def test_the_wait_is_capped(self, monitor, clock, writes):
        for _ in range(20):
            feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
            clock.advance(monitor.retry_at - clock.now)
            monitor.sample()
        assert monitor.retry_after <= storage.RETRY_AFTER_MAX

    def test_the_ordered_path_is_not_measured(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        feed(monitor, clock, writes, samples=5, **FAST)
        assert monitor.cost is None

    def test_a_retry_does_not_inherit_the_ordered_path_writes(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)

        feed(monitor, clock, writes, samples=5, **FAST)

        clock.advance(storage.RETRY_AFTER)
        monitor.sample()

        feed(monitor, clock, writes, samples=1, **SLOW)
        assert monitor.slow_samples == 1

    def test_a_retry_starts_from_no_measurement(self, monitor, clock, writes):
        feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        clock.advance(storage.RETRY_AFTER)
        monitor.sample()
        assert monitor.cost is None
        assert monitor.slow_samples == 0


class TestReporting:
    def test_it_says_what_it_is_doing(self, monitor, clock, writes):
        assert "unknown" in str(monitor)
        assert "as they arrive" in str(monitor)

        feed(monitor, clock, writes, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        assert "held in the cache" in str(monitor)
