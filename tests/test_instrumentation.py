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
tests.test_instrumentation - Testing sabnzbd.instrumentation
"""

import json
import os
import re
import threading
import time

import pytest

import sabnzbd
import sabnzbd.instrumentation as instrumentation


@pytest.fixture
def recording():
    """Enable recording for the duration of a test, and always turn it back off.

    Cleared on the way in as well as out, so a test that leaves recording on cannot
    leak into the next one.
    """
    instrumentation.reset()
    instrumentation.enable(True)
    yield instrumentation
    instrumentation.enable(False)
    instrumentation.reset()


@pytest.fixture
def not_recording():
    instrumentation.enable(False)
    instrumentation.reset()
    yield instrumentation
    instrumentation.reset()


class TestDisabled:
    """Call sites are left in place permanently, so nothing may be recorded while off"""

    def test_nothing_is_recorded(self, not_recording):
        not_recording.count("counter")
        not_recording.count_labelled("labelled", "label")
        not_recording.peak("peak", 100)
        not_recording.observe("timing", 1.0)
        not_recording.record_thread_cpu("role")

        snapshot = not_recording.snapshot()
        assert snapshot["enabled"] is False
        assert snapshot["counters"] == {}
        assert snapshot["labelled"] == {}
        assert snapshot["peaks"] == {}
        assert snapshot["timings"] == {}
        assert snapshot["thread_cpu_seconds"] == {}

    def test_decorator_passes_through(self, not_recording):
        @not_recording.instrument("passthrough")
        def add(first, second, keyword=0):
            return first + second + keyword

        assert add(1, 2, keyword=3) == 6
        assert not_recording.snapshot()["timings"] == {}

    def test_decorator_keeps_identity(self, not_recording):
        """Wrapping must not hide the name or docstring of what it wraps"""

        @not_recording.instrument("identity")
        def documented():
            """Original docstring"""

        assert documented.__name__ == "documented"
        assert documented.__doc__ == "Original docstring"


class TestRecording:
    def test_counters_accumulate(self, recording):
        recording.count("articles")
        recording.count("articles")
        recording.count("bytes", 500)
        assert recording.snapshot()["counters"] == {"articles": 2, "bytes": 500}

    def test_labels_are_kept_apart(self, recording):
        """The label breakdown is how a taxonomy is added without changing the schema"""
        recording.count_labelled("flushed", "cache-full", 2)
        recording.count_labelled("flushed", "first-part")
        recording.count_labelled("writes", "direct")
        snapshot = recording.snapshot()
        assert snapshot["labelled"]["flushed"] == {"cache-full": 2, "first-part": 1}
        assert snapshot["labelled"]["writes"] == {"direct": 1}

    def test_peak_keeps_the_highest(self, recording):
        for value in (100, 4096, 50, 2048):
            recording.peak("cache", value)
        assert recording.snapshot()["peaks"]["cache"] == 4096

    def test_timings_aggregate(self, recording):
        recording.observe("span", 0.001)
        recording.observe("span", 0.003)
        timing = recording.snapshot()["timings"]["span"]
        assert timing["count"] == 2
        assert timing["total_seconds"] == pytest.approx(0.004)
        assert timing["max_seconds"] == pytest.approx(0.003)
        assert timing["avg_seconds"] == pytest.approx(0.002)

    def test_decorator_records_and_returns(self, recording):
        @recording.instrument("wrapped")
        def work():
            return "result"

        assert work() == "result"
        assert recording.snapshot()["timings"]["wrapped"]["count"] == 1

    def test_decorator_records_when_raising(self, recording):
        """A span that raises is exactly the one worth having timed"""

        @recording.instrument("raises")
        def boom():
            raise ValueError("boom")

        with pytest.raises(ValueError):
            boom()
        assert recording.snapshot()["timings"]["raises"]["count"] == 1

    def test_enable_starts_a_fresh_window(self, recording):
        """A measurement must not carry data from an earlier enabled period"""
        recording.count("stale")
        recording.enable(False)
        recording.enable(True)
        assert recording.snapshot()["counters"] == {}

    def test_reset_clears_everything(self, recording):
        recording.count("counter")
        recording.count_labelled("labelled", "label")
        recording.peak("peak", 1)
        recording.observe("timing", 1.0)
        recording.reset()
        snapshot = recording.snapshot()
        assert not snapshot["counters"]
        assert not snapshot["labelled"]
        assert not snapshot["peaks"]
        assert not snapshot["timings"]


# Comfortably above both the ~15.6 ms Windows scheduler tick and the millisecond
# rounding that snapshot() applies to these totals
BURN_SECONDS = 0.05


def burn_cpu(seconds: float = BURN_SECONDS, timeout: float = 10.0):
    """Burn at least ``seconds`` of this thread's own CPU time.

    Two things make a fixed amount of work unreliable here. Windows measures per-thread
    CPU with GetThreadTimes at roughly a 15.6 ms scheduler tick, and snapshot() rounds
    these totals to milliseconds, so a short burst can legitimately report as exactly
    zero on either count. Burning against the same clock the code reads keeps the test
    about whether deltas accumulate rather than about the platform's resolution.

    Waiting for the clock merely to *change* does not work: reading it costs CPU, so on
    a fine-grained clock it has already moved by the first comparison and nothing is
    burned at all. The wall-clock timeout keeps a stalled clock from hanging the suite.
    """
    start = time.thread_time()
    deadline = time.monotonic() + timeout
    while time.thread_time() - start < seconds and time.monotonic() < deadline:
        sum(range(50000))


class TestThreadCpu:
    def test_first_report_only_sets_a_baseline(self, recording):
        """time.thread_time() is cumulative, so the first call has no delta to add"""
        threading.Thread(target=lambda: recording.record_thread_cpu("role")).start()
        # A single report from a thread must not invent CPU time
        assert recording.snapshot()["thread_cpu_seconds"].get("role") in (None, 0.0)

    def test_repeated_reports_accumulate(self, recording):
        def burn():
            recording.record_thread_cpu("worker")
            burn_cpu()
            recording.record_thread_cpu("worker")

        thread = threading.Thread(target=burn)
        thread.start()
        thread.join()
        assert recording.snapshot()["thread_cpu_seconds"]["worker"] > 0

    def test_threads_aggregate_into_one_role(self, recording):
        """Receive threads are unnamed and interchangeable, so they report as one role"""

        def burn():
            recording.record_thread_cpu("receive")
            burn_cpu()
            recording.record_thread_cpu("receive")

        threads = [threading.Thread(target=burn) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        cpu = recording.snapshot()["thread_cpu_seconds"]
        assert list(cpu) == ["receive"]
        assert cpu["receive"] > 0


class TestSummaryLine:
    def test_rates_are_averaged_over_the_log_interval(self, recording, caplog):
        """Thread CPU accumulates across the whole interval between summaries, so it has to
        be divided by that interval. Dividing by the sample interval instead reports every
        rate LOG_INTERVAL times too high."""
        sampler = recording.Sampler()
        # One second of CPU over a hundred second interval is one percent
        recording._thread_cpu["assembler"] = 1.0
        with caplog.at_level("DEBUG", logger="root"):
            sampler.log_summary(cpu_percent=2.0, rss=1024, elapsed=100.0)

        line = next(r.getMessage() for r in caplog.records if "Instrumentation:" in r.getMessage())
        assert "assembler=1.0%" in line
        assert "cpu=2.0%" in line

    def test_summary_reports_the_overflow_counters(self, recording, caplog):
        """The cache-full share and the amplification bytes are what S0 exists to answer"""
        recording.count("articlecache.held", 30)
        recording.count_labelled("articlecache.flushed", "cache-full", 10)
        recording.count("articlecache.flush_admin_file_bytes", 1024)
        recording.count("articlecache.reread_admin_file_bytes", 1024)

        sampler = recording.Sampler()
        with caplog.at_level("DEBUG", logger="root"):
            sampler.log_summary(cpu_percent=0.0, rss=1024, elapsed=60.0)

        line = next(r.getMessage() for r in caplog.records if "Instrumentation:" in r.getMessage())
        assert "saved=40 held=30 cache-full=10 (25.0%)" in line
        assert "amplification: +1 KB written +1 KB reread" in line

    def test_summary_states_the_counter_window(self, recording, caplog):
        """Percentages cover the log interval but counters are cumulative, so the line has
        to say which window the counts belong to"""
        sampler = recording.Sampler()
        with caplog.at_level("DEBUG", logger="root"):
            sampler.log_summary(cpu_percent=0.0, rss=1024, elapsed=60.0)
        line = next(r.getMessage() for r in caplog.records if "Instrumentation:" in r.getMessage())
        assert re.search(r"over \d+s: saved=", line)

    def test_idle_line_is_marked(self, recording, caplog):
        """The final summary has to be findable in a log, since it is the one carrying
        the totals for a completed run"""
        sampler = recording.Sampler()
        with caplog.at_level("DEBUG", logger="root"):
            sampler.log_summary(cpu_percent=0.0, rss=1024, elapsed=60.0, finished=True)
        line = next(r.getMessage() for r in caplog.records if "Instrumentation" in r.getMessage())
        assert line.startswith("Instrumentation (idle):")

    def test_summary_survives_an_empty_window(self, recording, caplog):
        """Logging must not divide by zero when nothing has been recorded yet"""
        sampler = recording.Sampler()
        with caplog.at_level("DEBUG", logger="root"):
            sampler.log_summary(cpu_percent=0.0, rss=0, elapsed=0.0)
        assert any("Instrumentation:" in r.getMessage() for r in caplog.records)


class TestIdleSuppression:
    """A SABnzbd with nothing to do must not fill the log, but a finished run must
    still be summarised once"""

    @staticmethod
    def run_samples(sampler, count, caplog):
        """Drive count samples and return the summary lines produced"""
        start = len(caplog.records)
        for _ in range(count):
            sampler.sample()
        return [r.getMessage() for r in caplog.records[start:] if "Instrumentation" in r.getMessage()]

    def test_idle_produces_no_logs_at_all(self, recording, caplog):
        """A SABnzbd that starts and does nothing must stay silent, including the line
        that would otherwise mark the transition into idle"""
        sampler = recording.Sampler()
        sampler.reset_baselines()
        # Pretend a whole log interval has elapsed, so only idleness can suppress it
        sampler._Sampler__next_log = 0
        with caplog.at_level("DEBUG", logger="root"):
            lines = self.run_samples(sampler, recording.IDLE_SAMPLES + 10, caplog)
        assert lines == []

    def test_work_is_logged_on_the_interval(self, recording, caplog):
        sampler = recording.Sampler()
        sampler.reset_baselines()
        with caplog.at_level("DEBUG", logger="root"):
            for _ in range(3):
                # Counter movement is what marks the pipeline as busy
                recording.count("decoder.articles")
                sampler._Sampler__next_log = 0
                sampler.sample()
            lines = [r.getMessage() for r in caplog.records if "Instrumentation" in r.getMessage()]
        assert len(lines) == 3
        assert not any("(idle)" in line for line in lines)

    def test_one_final_summary_after_work_stops(self, recording, caplog):
        """The run's totals are only complete once post-processing has finished, so the
        transition to idle has to produce exactly one more line"""
        sampler = recording.Sampler()
        sampler.reset_baselines()
        recording.count("decoder.articles")
        sampler.sample()

        with caplog.at_level("DEBUG", logger="root"):
            lines = self.run_samples(sampler, recording.IDLE_SAMPLES + 5, caplog)
        assert len(lines) == 1
        assert lines[0].startswith("Instrumentation (idle):")

    def test_intermittent_work_does_not_flap(self, recording, caplog):
        """Articles arriving with gaps must not settle into idle and re-report on every
        dip, which would log more than a fixed interval would"""
        sampler = recording.Sampler()
        sampler.reset_baselines()
        with caplog.at_level("DEBUG", logger="root"):
            for _ in range(6):
                recording.count("decoder.articles")
                sampler.sample()
                # A gap shorter than the idle threshold
                for _ in range(recording.IDLE_SAMPLES - 1):
                    sampler.sample()
            lines = [r.getMessage() for r in caplog.records if "Instrumentation" in r.getMessage()]
        assert not any("(idle)" in line for line in lines)

    def test_a_slow_transfer_is_not_idle_between_articles(self, recording, monkeypatch):
        """On a throttled link an article can take longer to arrive than the idle
        threshold. Judging on completed articles alone reports the run finished in every
        gap, so throughput has to count as work in its own right."""

        class Meter:
            bps = 40000.0

        monkeypatch.setattr(sabnzbd, "BPSMeter", Meter, raising=False)
        sampler = recording.Sampler()
        sampler.reset_baselines()
        # Far longer than the idle threshold with no article completing
        for _ in range(recording.IDLE_SAMPLES * 4):
            assert sampler.work_seen() is True

        Meter.bps = 0.0
        assert sampler.work_seen() is False

    def test_work_after_idle_starts_logging_again(self, recording, caplog):
        sampler = recording.Sampler()
        sampler.reset_baselines()
        recording.count("decoder.articles")
        sampler.sample()
        for _ in range(recording.IDLE_SAMPLES + 2):
            sampler.sample()

        with caplog.at_level("DEBUG", logger="root"):
            recording.count("decoder.articles")
            sampler._Sampler__next_log = 0
            sampler.sample()
            lines = [r.getMessage() for r in caplog.records if "Instrumentation" in r.getMessage()]
        assert len(lines) == 1
        assert "(idle)" not in lines[0]


class TestSnapshot:
    def test_is_json_serialisable(self, recording):
        """The snapshot goes straight out of the API, so it cannot contain anything exotic"""
        recording.count("counter")
        recording.count_labelled("labelled", "label")
        recording.peak("peak", 1)
        recording.observe("timing", 0.5)
        json.dumps(recording.snapshot())

    def test_process_is_present_while_not_recording(self, not_recording):
        """Process figures are read live, so they do not depend on recording being on.

        The "state" section needs the running singletons, so outside a started SABnzbd it
        is legitimately empty; that path is covered by the functional tests.
        """
        snapshot = not_recording.snapshot()
        assert snapshot["enabled"] is False
        assert snapshot["process"]["rss"] > 0
        assert isinstance(snapshot["state"], dict)

    def test_live_state_tolerates_an_unstarted_sabnzbd(self, not_recording):
        """Every section is guarded, so a missing singleton drops one key rather than raising"""
        assert not_recording.live_state() == {} or "cache" in not_recording.live_state()

    def test_rss_is_plausible(self, not_recording):
        rss = not_recording.current_rss()
        assert rss > 1024 * 1024
        # Peak can only ever be at least the current value
        assert not_recording.peak_rss() >= rss * 0.5

    def test_combined_rss_agrees_with_the_separate_accessors(self, not_recording):
        current, peak = not_recording.rss()
        assert current > 1024 * 1024
        assert peak >= current
        assert not_recording.peak_rss() == peak


@pytest.mark.skipif(not hasattr(os, "pread"), reason="os.pread is Unix only, so the statm reader cannot run here")
@pytest.mark.platform("linux")
class TestStatmDescriptor:
    """The Linux reader caches its descriptor, which is what made it 20x cheaper than
    reopening per call, and is also the only part of it that can go wrong.

    Faking the platform flags is not enough to run this on Windows: the reader calls
    os.pread, which does not exist there, so the whole class is skipped rather than
    pretending to cover a path that platform cannot execute.
    """

    @pytest.fixture
    def as_linux(self, monkeypatch, tmp_path):
        statm = tmp_path / "statm"
        statm.write_text("35190 4933 2626 2 0 8663 0\n")
        monkeypatch.setattr(instrumentation, "STATM_PATH", str(statm))
        instrumentation._drop_statm_descriptor()
        yield statm
        instrumentation._drop_statm_descriptor()

    def test_reads_the_resident_field(self, as_linux):
        """Resident pages are the second field of statm, not the first"""
        assert instrumentation.current_rss() == 4933 * instrumentation._page_size

    def test_the_descriptor_is_opened_once(self, as_linux, monkeypatch):
        opened = []
        real_open = os.open
        monkeypatch.setattr(os, "open", lambda *a, **kw: (opened.append(a[0]), real_open(*a, **kw))[1])
        for _ in range(10):
            instrumentation.current_rss()
        assert len(opened) == 1

    def test_a_stale_descriptor_is_recovered_from(self, as_linux):
        """Caching a descriptor that has gone bad would fail for the rest of the run"""
        assert instrumentation.current_rss() > 0
        os.close(instrumentation._statm_fd)
        assert instrumentation.current_rss() == 0
        assert instrumentation._statm_fd is None
        assert instrumentation.current_rss() == 4933 * instrumentation._page_size

    def test_unparsable_contents_do_not_raise(self, as_linux):
        as_linux.write_text("not a statm file\n")
        assert instrumentation.current_rss() == 0
