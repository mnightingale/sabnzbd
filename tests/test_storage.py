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

import sabnzbd
import sabnzbd.storage as storage

MB = 1024 * 1024


def counters(count: int, written: int, nanos: int) -> dict:
    return {"count": count, "bytes": written, "nanos": nanos, "max_nanos": nanos}


class FakeAssembler:
    """Stands in for the open-handle registry the monitor reads.

    Totals accumulate exactly as a real writer's do - for the life of the handle - so
    that a test which reads twice sees the second reading include the first.
    """

    def __init__(self):
        self.rows = []
        self.totals = [0, 0, 0]

    def add(self, writes: int, written: int, nanos: int, nzf_id: str = "nzf-1"):
        self.totals = [self.totals[0] + writes, self.totals[1] + written, self.totals[2] + nanos]
        self.rows = [(nzf_id, counters(*self.totals))]

    def write_stats(self):
        return list(self.rows)


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
def assembler(monkeypatch):
    fake = FakeAssembler()
    monkeypatch.setattr(sabnzbd, "Assembler", fake, raising=False)
    return fake


@pytest.fixture
def monitor(clock, assembler, monkeypatch):
    """A monitor started on a device the kernel says nothing about"""
    monkeypatch.setattr(storage, "rotational", lambda path: None)
    instance = storage.WriteMonitor()
    instance.reset("/downloads")
    return instance


def feed(monitor, clock, assembler, samples: int, writes: int, written: int, nanos: int):
    """Hand the monitor one reading per SAMPLE_INTERVAL, as the downloader would"""
    for _ in range(samples):
        assembler.add(writes, written, nanos)
        clock.advance(storage.SAMPLE_INTERVAL)
        monitor.sample()


# Comfortably either side of SLOW_WRITE_MBPS: absorbed by the page cache, and stalled
# behind writeback
FAST = dict(writes=64, written=45 * MB, nanos=3_200_000)
SLOW = dict(writes=64, written=8 * MB, nanos=400_000_000)

assert 1e9 / (FAST["nanos"] / FAST["written"]) / MB > storage.SLOW_WRITE_MBPS
assert 1e9 / (SLOW["nanos"] / SLOW["written"]) / MB < storage.SLOW_WRITE_MBPS


class TestRotationalHint:
    def test_a_path_with_no_block_device_says_nothing(self, tmp_path):
        assert storage.rotational(str(tmp_path / "does_not_exist")) is None

    def test_it_never_raises(self, tmp_path):
        """It runs during startup and during a config change, so a platform without
        sysfs, a container without /sys/dev/block, and a network share all have to come
        back as "no opinion" rather than as an exception."""
        assert storage.rotational(str(tmp_path)) in (True, False, None)
        assert storage.rotational("") is None


class TestOpeningMode:
    def test_a_rotational_disk_starts_ordered(self, clock, assembler, monkeypatch):
        monkeypatch.setattr(storage, "rotational", lambda path: True)
        monitor = storage.WriteMonitor()
        monitor.reset("/downloads")
        assert monitor.allows_streaming() is False

    def test_solid_state_starts_streaming(self, clock, assembler, monkeypatch):
        monkeypatch.setattr(storage, "rotational", lambda path: False)
        monitor = storage.WriteMonitor()
        monitor.reset("/downloads")
        assert monitor.allows_streaming() is True

    def test_no_opinion_starts_streaming(self, monitor):
        """Unknown is the common case - every platform but Linux, and most containers.
        Starting optimistic is what makes the measurement the thing that decides."""
        assert monitor.allows_streaming() is True


class TestBackingOff:
    def test_writes_being_absorbed_keep_it_streaming(self, monitor, clock, assembler):
        feed(monitor, clock, assembler, samples=10, **FAST)
        assert monitor.allows_streaming() is True

    def test_a_run_of_slow_samples_backs_off(self, monitor, clock, assembler):
        feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        assert monitor.allows_streaming() is False

    def test_one_slow_sample_is_not_enough(self, monitor, clock, assembler):
        feed(monitor, clock, assembler, samples=1, **SLOW)
        assert monitor.allows_streaming() is True

    def test_recovering_clears_the_run(self, monitor, clock, assembler):
        """A par2 repair or a copy on the same disk stalls writes for a while. Once it
        is over the count has to start again, or the stalls would add up across a whole
        session and demote a disk that is fine."""
        feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF - 1, **SLOW)
        feed(monitor, clock, assembler, samples=5, **FAST)
        assert monitor.slow_samples == 0

        feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF - 1, **SLOW)
        assert monitor.allows_streaming() is True

    def test_one_stall_does_not_outweigh_the_samples_around_it(self, monitor, clock, assembler):
        """The reason cost is averaged rather than throughput. Averaged the other way
        up, a single cached sample sits three orders of magnitude above the rest and
        holds the average clear of the threshold for the next dozen samples, whatever
        they say."""
        feed(monitor, clock, assembler, samples=5, **FAST)
        feed(monitor, clock, assembler, samples=1, **SLOW)
        assert 1e9 / monitor.cost / MB < storage.SLOW_WRITE_MBPS


class TestSampleQuality:
    def test_too_few_writes_is_not_a_sample(self, monitor, clock, assembler):
        feed(
            monitor,
            clock,
            assembler,
            samples=10,
            writes=storage.MIN_SAMPLE_WRITES - 1,
            written=8 * MB,
            nanos=400_000_000,
        )
        assert monitor.cost is None
        assert monitor.allows_streaming() is True

    def test_too_few_bytes_is_not_a_sample(self, monitor, clock, assembler):
        """A trickle of writes tells you nothing about a device under load, and a slow
        trickle least of all."""
        feed(
            monitor,
            clock,
            assembler,
            samples=10,
            writes=64,
            written=storage.MIN_SAMPLE_BYTES - 1,
            nanos=400_000_000,
        )
        assert monitor.cost is None
        assert monitor.allows_streaming() is True

    def test_samples_faster_than_the_interval_are_ignored(self, monitor, clock, assembler):
        """It hangs off the downloader's 50 ms tick, so most calls have to do nothing.

        Writes keep arriving throughout, so a monitor that acted on every call would
        see far more than the two intervals that have actually passed - and would back
        off inside them."""
        ticks = int(2 * storage.SAMPLE_INTERVAL / 0.05)
        for _ in range(ticks):
            # Enough on its own to be a slow sample, so acting on every call would back
            # off within the first few ticks
            assembler.add(**SLOW)
            clock.advance(0.05)
            monitor.sample()
        assert monitor.allows_streaming() is True

    def test_only_new_writes_count(self, monitor, clock, assembler):
        """The counters are cumulative for the life of the handle, so a sample that
        read them as the interval's work would see the whole file every time."""
        feed(monitor, clock, assembler, samples=1, **FAST)
        first = monitor.cost
        feed(monitor, clock, assembler, samples=1, **FAST)
        assert monitor.cost == pytest.approx(first, rel=0.01)

    def test_a_reopened_handle_counts_from_zero_again(self, monitor, clock, assembler):
        """The LRU drops a handle when 32 files are already open, so the same file can
        come back on a fresh writer whose counters start again. Subtracting the old
        totals from the new ones would report a negative interval."""
        feed(monitor, clock, assembler, samples=1, writes=500, written=350 * MB, nanos=25_000_000)

        # The handle was dropped and reopened, so its counters start again
        assembler.totals = [0, 0, 0]
        feed(monitor, clock, assembler, samples=1, **FAST)
        assert monitor.cost > 0
        assert monitor.allows_streaming() is True

    def test_a_finished_file_stops_being_tracked(self, monitor, clock, assembler):
        feed(monitor, clock, assembler, samples=1, **FAST)
        assert "nzf-1" in monitor.seen

        assembler.rows = []
        clock.advance(storage.SAMPLE_INTERVAL)
        monitor.sample()
        assert monitor.seen == {}


class TestRetrying:
    def test_it_tries_again_after_the_wait(self, monitor, clock, assembler):
        feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        assert monitor.allows_streaming() is False

        clock.advance(storage.RETRY_AFTER)
        monitor.sample()
        assert monitor.allows_streaming() is True

    def test_it_does_not_try_before_the_wait_is_up(self, monitor, clock, assembler):
        feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        clock.advance(storage.RETRY_AFTER / 2)
        monitor.sample()
        assert monitor.allows_streaming() is False

    def test_each_refusal_waits_longer(self, monitor, clock, assembler):
        """A disk that is genuinely wrong for this should be asked less and less often,
        because every retry costs it a few seconds of scattered writes."""
        waits = []
        for _ in range(3):
            feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
            waits.append(monitor.retry_at - clock.now)
            clock.advance(waits[-1])
            monitor.sample()

        assert waits == sorted(waits)
        assert waits[1] > waits[0]

    def test_the_wait_is_capped(self, monitor, clock, assembler):
        for _ in range(20):
            feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
            clock.advance(monitor.retry_at - clock.now)
            monitor.sample()
        assert monitor.retry_after <= storage.RETRY_AFTER_MAX

    def test_the_ordered_path_is_not_measured(self, monitor, clock, assembler):
        """Its writes are the runs the assembler gathered, not scattered ones, so they
        would look fast on any device and say nothing about what a retry would find."""
        feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        feed(monitor, clock, assembler, samples=5, **FAST)
        assert monitor.cost is None

    def test_a_retry_does_not_inherit_the_ordered_path_writes(self, monitor, clock, assembler):
        """The files open when it backed off are usually still open when it tries
        again, and their counters have gone on rising in the meantime. Carried across,
        the first sample after a retry would be the assembler's large ordered writes
        and would report a device that had never been tested."""
        feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)

        # Writes keep happening while it is on the ordered path, and look fast
        feed(monitor, clock, assembler, samples=5, **FAST)

        clock.advance(storage.RETRY_AFTER)
        monitor.sample()

        feed(monitor, clock, assembler, samples=1, **SLOW)
        assert monitor.slow_samples == 1

    def test_a_retry_starts_from_no_measurement(self, monitor, clock, assembler):
        """Otherwise the readings that demoted it would still be in the average and it
        would demote again on its first slow sample."""
        feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        clock.advance(storage.RETRY_AFTER)
        monitor.sample()
        assert monitor.cost is None
        assert monitor.slow_samples == 0


class TestReporting:
    def test_it_says_what_it_is_doing(self, monitor, clock, assembler):
        assert "unknown" in str(monitor)
        assert "as they arrive" in str(monitor)

        feed(monitor, clock, assembler, samples=storage.SLOW_SAMPLES_BEFORE_BACKOFF, **SLOW)
        assert "held in the cache" in str(monitor)
