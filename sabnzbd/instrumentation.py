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
sabnzbd.instrumentation - development instrumentation for the download hot path

Off by default and controlled by the ``instrumentation`` special. When off, every
entry point here is a module-global read and an immediate return, so call sites can
be left in place permanently. This is a development tool: the numbers it produces are
meant to be gathered deliberately, not collected from installations in the field.

Collected data is only reachable through ``mode=instrumentation`` on the API, plus a
periodic summary line at debug level. There is deliberately no UI.

Counters use a lock rather than bare ``+=``. Unlocked increments lose updates under
contention, which would bias the numbers low exactly when load is highest, and that is
the regime being measured. The lock costs ~170 ns and does not degrade with more
threads, since the GIL already serialises the increment.

Enabling starts a fresh window, so a measurement never carries data from an earlier
one. ``reset()`` (``reset=1`` on the API) starts a new window without toggling.

Extending this: ``count_labelled`` exists so a breakdown can be added without a schema
change, and the API groups everything under stable top-level keys. The assembler's
write-trigger reasons are the obvious next thing to feed into it - see
``feature/write_batching``, where ``should_queue_nzf`` returns a reason string
("file-done", "first-part", "cache-flush", "cap", "evicted", "forced", "requeued")
rather than a bool. One ``count_labelled("assembler.queued", reason)`` in
``Assembler.process`` picks the whole taxonomy up.
"""

import ctypes
import datetime
import functools
import logging
import os
import resource
import sys
import threading
import time
from collections import deque
from typing import Any, Callable

import sabnzbd
from sabnzbd.misc import to_units

# Recording is off unless the special is enabled. Read on every hot path, so it stays
# a plain module global rather than a config lookup.
ENABLED: bool = False

# How often the sampler wakes to record CPU and RSS
SAMPLE_INTERVAL = 1.0
# How often the summary line is written to the log, while there is work to report
LOG_INTERVAL = 60.0
# Consecutive quiet samples before work is considered finished. Enough to ride out the
# gaps between articles without delaying the final summary noticeably.
IDLE_SAMPLES = 5
# Roughly an hour of samples at SAMPLE_INTERVAL, bounded so nothing grows without limit
MAX_SAMPLES = 3600

_LOCK = threading.Lock()
_counters: dict[str, int] = {}
_labelled: dict[str, dict[str, int]] = {}
_peaks: dict[str, int] = {}
# name -> [count, total_seconds, max_seconds]
_timings: dict[str, list[float]] = {}
# role -> cumulative CPU seconds, summed across every thread reporting that role
_thread_cpu: dict[str, float] = {}
_samples: deque = deque(maxlen=MAX_SAMPLES)
_started_at: float = 0.0

# Each thread tracks its own last reading, so record_thread_cpu can be called at any
# interval and still add an accurate delta
_thread_local = threading.local()


##############################################################################
# Recording
##############################################################################
def enable(active: bool):
    """Callback for the instrumentation special.

    Enabling starts a fresh window, so a measurement never carries data from an
    earlier one.
    """
    global ENABLED
    if active == ENABLED:
        return
    if active:
        reset()
    ENABLED = active
    logging.debug("Instrumentation %s", "enabled" if active else "disabled")


def reset():
    """Discard everything recorded so far"""
    global _started_at
    with _LOCK:
        _counters.clear()
        _labelled.clear()
        _peaks.clear()
        _timings.clear()
        _thread_cpu.clear()
        _samples.clear()
        _started_at = time.monotonic()


def count(name: str, value: int = 1):
    """Add to a counter"""
    if not ENABLED:
        return
    with _LOCK:
        _counters[name] = _counters.get(name, 0) + value


def count_labelled(name: str, label: str, value: int = 1):
    """Add to a counter broken down by label, for example a reason or a mode"""
    if not ENABLED:
        return
    with _LOCK:
        _labelled.setdefault(name, {})
        _labelled[name][label] = _labelled[name].get(label, 0) + value


def peak(name: str, value: int):
    """Track the highest value seen"""
    if not ENABLED:
        return
    with _LOCK:
        if value > _peaks.get(name, 0):
            _peaks[name] = value


def observe(name: str, seconds: float):
    """Record how long something took.

    Aggregate only: count, total and maximum. Bucketed histograms are the upgrade
    when a distribution is actually needed, but the average and the worst case are
    enough to tell whether a span is worth looking at.
    """
    if not ENABLED:
        return
    with _LOCK:
        if entry := _timings.get(name):
            entry[0] += 1
            entry[1] += seconds
            if seconds > entry[2]:
                entry[2] = seconds
        else:
            _timings[name] = [1, seconds, seconds]


def instrument(name: str) -> Callable:
    """Decorator recording how long the wrapped callable takes"""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not ENABLED:
                return func(*args, **kwargs)
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                observe(name, time.perf_counter() - start)

        return wrapper

    return decorator


def record_thread_cpu(role: str):
    """Add this thread's CPU since its last report to the total for ``role``.

    time.thread_time() only ever reports the calling thread, so a sampler cannot
    collect this on everyone else's behalf: each thread has to report its own. Roles
    are used rather than thread names so that all the receive threads, which are
    unnamed, aggregate into one figure.
    """
    if not ENABLED:
        return
    now = time.thread_time()
    last = getattr(_thread_local, "cpu", None)
    _thread_local.cpu = now
    if last is None:
        # First report from this thread only establishes the baseline
        return
    with _LOCK:
        _thread_cpu[role] = _thread_cpu.get(role, 0.0) + (now - last)


##############################################################################
# Process CPU and memory
##############################################################################
class _MacTaskInfo(ctypes.Structure):
    """proc_taskinfo, as declared in <libproc.h>"""

    _fields_ = [
        ("pti_virtual_size", ctypes.c_uint64),
        ("pti_resident_size", ctypes.c_uint64),
        ("pti_total_user", ctypes.c_uint64),
        ("pti_total_system", ctypes.c_uint64),
        ("pti_threads_user", ctypes.c_uint64),
        ("pti_threads_system", ctypes.c_uint64),
        ("pti_policy", ctypes.c_int32),
        ("pti_faults", ctypes.c_int32),
        ("pti_pageins", ctypes.c_int32),
        ("pti_cow_faults", ctypes.c_int32),
        ("pti_messages_sent", ctypes.c_int32),
        ("pti_messages_received", ctypes.c_int32),
        ("pti_syscalls_mach", ctypes.c_int32),
        ("pti_syscalls_unix", ctypes.c_int32),
        ("pti_csw", ctypes.c_int32),
        ("pti_threadnum", ctypes.c_int32),
        ("pti_numrunning", ctypes.c_int32),
        ("pti_priority", ctypes.c_int32),
    ]


_libproc = None
_PROC_PIDTASKINFO = 4


def current_rss() -> int:
    """Resident set size of this process in bytes, or 0 if it cannot be determined"""
    global _libproc
    try:
        if sabnzbd.WINDOWS:
            import win32process

            return win32process.GetProcessMemoryInfo(win32process.GetCurrentProcess())["WorkingSetSize"]
        if sabnzbd.MACOS:
            if _libproc is None:
                _libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            info = _MacTaskInfo()
            if _libproc.proc_pidinfo(
                os.getpid(), _PROC_PIDTASKINFO, ctypes.c_uint64(0), ctypes.byref(info), ctypes.sizeof(info)
            ) == ctypes.sizeof(info):
                return info.pti_resident_size
            return 0
        # Second field of statm is the resident pages
        with open("/proc/self/statm") as statm:
            return int(statm.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except Exception:
        return 0


def peak_rss() -> int:
    """Highest resident set size reached, in bytes, or 0 if it cannot be determined"""
    try:
        if sabnzbd.WINDOWS:
            import win32process

            return win32process.GetProcessMemoryInfo(win32process.GetCurrentProcess())["PeakWorkingSetSize"]
        # ru_maxrss is bytes on macOS but kilobytes on Linux
        max_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return max_rss if sabnzbd.MACOS else max_rss * 1024
    except Exception:
        return 0


##############################################################################
# Sampler
##############################################################################
class Sampler(threading.Thread):
    """Samples process CPU and RSS, and writes a periodic summary to the debug log"""

    def __init__(self):
        super().__init__(name="Sampler", daemon=True)
        self.shutdown = False
        self.__last_cpu = 0.0
        self.__last_time = 0.0
        # The summary reports averages over the whole log interval, so it needs its own
        # baselines. Reusing the per-sample ones reports every rate LOG_INTERVAL times high.
        self.__last_log_cpu = 0.0
        self.__last_log_time = 0.0
        self.__last_thread_cpu: dict[str, float] = {}
        self.__next_log = 0.0
        # Idle tracking, so a SABnzbd with nothing to do does not fill the log. Starts
        # already idle: a sampler that has never seen work has nothing to summarise, and
        # counting up from zero would emit one line shortly after every startup.
        self.__last_counter_total = 0
        self.__idle_samples = IDLE_SAMPLES
        self.__was_idle = True

    def stop(self):
        self.shutdown = True

    def reset_baselines(self):
        now = time.monotonic()
        cpu = time.process_time()
        self.__last_cpu = self.__last_log_cpu = cpu
        self.__last_time = self.__last_log_time = now
        self.__next_log = now + LOG_INTERVAL

    def work_seen(self) -> bool:
        """Is anything happening, as of this sample?

        Completed articles alone are not enough to go on. On a slow or throttled link a
        500 KB article can take longer to arrive than the idle threshold, so a download
        in progress would look idle between articles and report itself finished over and
        over. Throughput is therefore checked as well, which covers the gaps and costs
        nothing to read.

        Post-processing is checked because it moves no article counters while being
        exactly when RSS and CPU peak, and the assembler because decoded bytes can still
        be waiting to be written after the last article has arrived.

        Deliberately not checked: whether jobs are queued. A paused or stalled queue has
        nothing happening in it and nothing to report.
        """
        with _LOCK:
            total = sum(_counters.values())
        moved = total != self.__last_counter_total
        self.__last_counter_total = total
        if moved:
            return True
        try:
            if sabnzbd.BPSMeter.bps:
                return True
            if len(sabnzbd.PostProcessor.history_queue):
                return True
            if sabnzbd.Assembler.total_ready_bytes():
                return True
        except Exception:
            # Not fully started, or already shutting down
            pass
        return False

    def run(self):
        logging.debug("Instrumentation sampler starting")
        self.reset_baselines()

        while not self.shutdown:
            time.sleep(SAMPLE_INTERVAL)
            if self.shutdown:
                break
            if not ENABLED:
                # Keep the baselines fresh so the first sample after enabling is not a
                # delta over the whole idle period
                self.reset_baselines()
                continue
            try:
                self.sample()
            except Exception:
                logging.debug("Instrumentation sampling failed", exc_info=True)
        logging.debug("Instrumentation sampler stopped")

    def sample(self):
        """Record one CPU/RSS sample and log the summary when due"""
        now = time.monotonic()
        cpu = time.process_time()
        elapsed = now - self.__last_time
        cpu_percent = 100.0 * (cpu - self.__last_cpu) / elapsed if elapsed > 0 else 0.0
        self.__last_cpu = cpu
        self.__last_time = now

        rss = current_rss()
        peak("process.rss", rss)

        try:
            bps = sabnzbd.BPSMeter.bps
        except Exception:
            # Not fully started, or torn down while the sampler was between ticks. An
            # exception here reaches run() and silently stops all further sampling.
            bps = 0.0

        with _LOCK:
            _samples.append(
                {
                    "time": time.time(),
                    "rss": rss,
                    "cpu_percent": round(cpu_percent, 2),
                    "bps": bps,
                }
            )

        # A few quiet samples are required before calling it idle. Articles arriving
        # every couple of seconds would otherwise flip in and out of idle and log a
        # summary on every dip, which is worse than logging on a fixed interval.
        self.__idle_samples = 0 if self.work_seen() else self.__idle_samples + 1
        idle = self.__idle_samples >= IDLE_SAMPLES
        finished = idle and not self.__was_idle
        self.__was_idle = idle

        # Log on the interval while there is work, plus exactly one final summary once
        # everything including post-processing has stopped. That last one is the whole
        # point: peak RSS and total CPU are only complete after unpacking and par2.
        if (not idle and now >= self.__next_log) or finished:
            self.__next_log = now + LOG_INTERVAL
            # Averaged over the log interval, not over the last sample, so the process
            # figure and the per-thread figures are on the same base and can be compared
            log_elapsed = now - self.__last_log_time
            log_cpu_percent = 100.0 * (cpu - self.__last_log_cpu) / log_elapsed if log_elapsed > 0 else 0.0
            self.__last_log_cpu = cpu
            self.__last_log_time = now
            self.log_summary(log_cpu_percent, rss, log_elapsed, finished)
        elif idle:
            # Nothing to report, so roll the baselines forward. Without this the first
            # summary after work resumes would average its rates over the idle stretch.
            self.__last_log_cpu = cpu
            self.__last_log_time = now
            self.__next_log = now + LOG_INTERVAL

    def log_summary(self, cpu_percent: float, rss: int, elapsed: float, finished: bool = False):
        """One compact line, at debug level, covering the metrics S0 exists to answer.

        Every percentage is an average over ``elapsed``, which is the log interval.
        ``finished`` marks the summary written once work has stopped.
        """
        threads = []
        with _LOCK:
            thread_cpu = dict(_thread_cpu)
            counters = dict(_counters)
            flushed = dict(_labelled.get("articlecache.flushed", {}))
        for role, total in sorted(thread_cpu.items()):
            delta = total - self.__last_thread_cpu.get(role, 0.0)
            self.__last_thread_cpu[role] = total
            threads.append("%s=%.1f%%" % (role, 100.0 * delta / elapsed if elapsed > 0 else 0.0))

        held = counters.get("articlecache.held", 0)
        cache_full = flushed.get("cache-full", 0)
        saved = held + sum(flushed.values())

        # The two halves of the cache-overflow round trip. Bytes counted here are written to
        # the download disk twice, so this is the write amplification figure S0 exists to get.
        extra_written = counters.get("articlecache.flush_admin_file_bytes", 0)
        extra_read = counters.get("articlecache.reread_admin_file_bytes", 0)

        # Sourced from live_state() because it already tolerates a partially initialised
        # SABnzbd. Reaching for the singletons directly makes the summary stop appearing
        # during startup and shutdown, which is when it is least obvious that it has.
        state = live_state()
        cache = state.get("cache", {})
        assembler = state.get("assembler", {})
        downloader = state.get("downloader", {})

        # The percentages cover the log interval, but the counters are cumulative over the
        # whole recording window, so the window is stated to keep the two apart
        logging.debug(
            "Instrumentation%s: cpu=%.1f%%%s rss=%s peak=%s | speed=%s/s cache=%s/%s (%s articles) "
            "pending=%s | over %.0fs: saved=%s held=%s cache-full=%s (%.1f%%) | "
            "amplification: +%s written +%s reread",
            " (idle)" if finished else "",
            cpu_percent,
            " [" + " ".join(threads) + "]" if threads else "",
            to_units(rss, "B"),
            to_units(peak_rss(), "B"),
            to_units(downloader.get("speed_bps", 0), "B"),
            to_units(cache.get("size", 0), "B"),
            to_units(cache.get("limit", 0), "B"),
            cache.get("articles", 0),
            to_units(assembler.get("ready_bytes", 0), "B"),
            time.monotonic() - _started_at,
            saved,
            held,
            cache_full,
            100.0 * cache_full / saved if saved else 0.0,
            to_units(extra_written, "B"),
            to_units(extra_read, "B"),
        )


##############################################################################
# Reporting
##############################################################################
def live_state() -> dict[str, Any]:
    """Current state of the download pipeline.

    Read straight from the running objects, so this is available whether or not
    recording is enabled.
    """
    state: dict[str, Any] = {}
    try:
        anfo = sabnzbd.ArticleCache.cache_info()
        state["cache"] = {
            "articles": anfo.article_sum,
            "size": anfo.cache_size,
            "limit": anfo.cache_limit,
        }
    except Exception:
        pass

    try:
        state["downloader"] = {
            "speed_bps": sabnzbd.BPSMeter.bps,
            "paused": bool(sabnzbd.Downloader.paused or sabnzbd.Downloader.paused_for_postproc),
            "bandwidth_limit": sabnzbd.Downloader.bandwidth_limit,
            "servers": [
                {
                    "id": server.id,
                    "active": server.active,
                    "threads": server.threads,
                    "busy_threads": len(server.busy_threads),
                    "articles_queued": len(server.article_queue),
                }
                for server in sabnzbd.Downloader.servers[:]
            ],
        }
    except Exception:
        pass

    try:
        state["assembler"] = {
            "queue_size": sabnzbd.Assembler.queue.qsize(),
            "ready_bytes": sabnzbd.Assembler.total_ready_bytes(),
            "delay": sabnzbd.Assembler.delay(),
        }
    except Exception:
        pass

    try:
        # limit=1 still walks the queue for the totals but avoids materialising every job
        bytes_total, bytes_left, _, _, q_size, total_jobs = sabnzbd.NzbQueue.queue_info(limit=1)
        state["queue"] = {
            "jobs": total_jobs,
            "downloading_jobs": q_size,
            "active_jobs": sabnzbd.NzbQueue.actives(),
            "bytes_left": bytes_left,
            "bytes_total": bytes_total,
        }
    except Exception:
        pass

    try:
        state["postproc"] = {
            "queue_length": len(sabnzbd.PostProcessor.history_queue),
            "paused": sabnzbd.PostProcessor.paused,
        }
    except Exception:
        pass

    return state


def snapshot() -> dict[str, Any]:
    """Everything recorded so far, plus the current pipeline state"""
    with _LOCK:
        timings = {
            name: {
                "count": int(entry[0]),
                # Nanosecond resolution: the spans of interest here run from a few
                # microseconds to a few milliseconds
                "total_seconds": round(entry[1], 9),
                "max_seconds": round(entry[2], 9),
                "avg_seconds": round(entry[1] / entry[0], 9) if entry[0] else 0.0,
            }
            for name, entry in _timings.items()
        }
        data: dict[str, Any] = {
            "enabled": ENABLED,
            # Seconds the counters cover: since recording started, or since the last reset
            "window_seconds": round(time.monotonic() - _started_at, 1) if _started_at else 0.0,
            "counters": dict(_counters),
            "labelled": {name: dict(labels) for name, labels in _labelled.items()},
            "peaks": dict(_peaks),
            "timings": timings,
            "thread_cpu_seconds": {role: round(total, 3) for role, total in _thread_cpu.items()},
            "samples": list(_samples),
        }

    data["process"] = {
        "pid": os.getpid(),
        "rss": current_rss(),
        "peak_rss": peak_rss(),
        "cpu_seconds": round(time.process_time(), 3),
        # Needed to read cpu_seconds as a rate. START is a datetime, not a timestamp.
        "uptime_seconds": round((datetime.datetime.now() - sabnzbd.START).total_seconds(), 1),
        "thread_count": threading.active_count(),
        "python_version": sys.version.split()[0],
    }
    data["state"] = live_state()
    return data
