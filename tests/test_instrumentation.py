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
import re
import threading

import pytest

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


class TestThreadCpu:
    def test_first_report_only_sets_a_baseline(self, recording):
        """time.thread_time() is cumulative, so the first call has no delta to add"""
        threading.Thread(target=lambda: recording.record_thread_cpu("role")).start()
        # A single report from a thread must not invent CPU time
        assert recording.snapshot()["thread_cpu_seconds"].get("role") in (None, 0.0)

    def test_repeated_reports_accumulate(self, recording):
        def burn():
            recording.record_thread_cpu("worker")
            sum(range(400000))
            recording.record_thread_cpu("worker")

        thread = threading.Thread(target=burn)
        thread.start()
        thread.join()
        assert recording.snapshot()["thread_cpu_seconds"]["worker"] > 0

    def test_threads_aggregate_into_one_role(self, recording):
        """Receive threads are unnamed and interchangeable, so they report as one role"""

        def burn():
            recording.record_thread_cpu("receive")
            sum(range(400000))
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

    def test_summary_survives_an_empty_window(self, recording, caplog):
        """Logging must not divide by zero when nothing has been recorded yet"""
        sampler = recording.Sampler()
        with caplog.at_level("DEBUG", logger="root"):
            sampler.log_summary(cpu_percent=0.0, rss=0, elapsed=0.0)
        assert any("Instrumentation:" in r.getMessage() for r in caplog.records)


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
