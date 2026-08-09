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
instrumentation_poll - Record a measurement run from mode=instrumentation

Polls the instrumentation API and writes a CSV for plotting plus a JSONL of the raw
responses, and can serve the same data to Prometheus. Deliberately lives outside
SABnzbd: pointing Prometheus at this script rather than at the API keeps a
metric-naming compatibility promise out of SABnzbd itself.

The two outputs are shaped differently on purpose. The CSV carries per-interval rates,
because a spreadsheet has no rate() to call. Prometheus gets the cumulative counters
untouched, so the window is the dashboard's choice, counter resets across a restart are
detected, and the scrape interval no longer has to match the poll interval.

The run this is built for is fast machine, fast line, slow or exhausted disk. That is
the regime where the article cache cannot drain, fills, and starts writing articles to
the admin directory to be read back moments later - so the payload hits the download
disk twice. Two things follow from that:

  * Rates matter more than totals. A cumulative count over a whole run averages the
    onset away, and the onset - the point where cache_used reaches cache_limit and
    spill begins - is the event worth seeing.
  * The proof is device-side. SABnzbd can report how many bytes it handed to the admin
    directory, but only the kernel knows what actually reached the disk. Where it can,
    this reads the block device behind the download directory so the amplification can
    be shown rather than inferred.

Reproducing the regime without exotic hardware: shrink misc.cache_limit. Overflow is
just "cache_used + article > cache_limit", so a small limit reaches it at ordinary
speeds and exercises the same code. Dynamics differ from a genuinely disk-bound run,
but the amplification path is identical. To throttle the disk itself on Linux, run
SABnzbd under systemd-run with IOWriteBandwidthMax.

Usage:
    python tools/instrumentation_poll.py --apikey KEY --out run1
    python tools/instrumentation_poll.py --apikey KEY --out run1 --prometheus-port 9109
"""

import argparse
import csv
import json
import os
import plistlib
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from threading import Thread
from typing import Any, Optional

# Sectors in /proc/diskstats are always 512 bytes for this interface, whatever the
# physical sector size of the device
LINUX_SECTOR_SIZE = 512

CSV_COLUMNS = [
    "timestamp",
    "elapsed",
    "interval",
    # Throughput
    "speed_bps",
    "articles_per_sec",
    "decoded_bytes_per_sec",
    # Process
    "rss",
    "peak_rss",
    "cpu_percent",
    "cpu_downloader_percent",
    "cpu_receive_percent",
    "cpu_assembler_percent",
    # Article cache: how close to the limit, and what is spilling
    "cache_used",
    "cache_limit",
    "cache_percent",
    "cache_articles",
    "held_per_sec",
    "cache_full_per_sec",
    "first_part_per_sec",
    # Write amplification, the reason this run exists
    "admin_writes_per_sec",
    "admin_write_bytes_per_sec",
    "admin_rereads_per_sec",
    "admin_reread_bytes_per_sec",
    "direct_writes_per_sec",
    "amplification_ratio",
    # Assembler backpressure
    "assembler_ready_bytes",
    "assembler_queue_size",
    "assembler_delay",
    "assembler_bytes_per_sec",
    "assembler_direct_per_sec",
    "assembler_append_per_sec",
    # Device, from the kernel rather than from SABnzbd
    "disk_write_bytes_per_sec",
    "disk_read_bytes_per_sec",
    "disk_util_percent",
    # Timings
    "decode_avg_ms",
    "decode_max_ms",
    "save_article_avg_ms",
    "save_article_max_ms",
]


##############################################################################
# Device statistics
##############################################################################
class DiskStats:
    """Cumulative bytes read/written on the device behind a path.

    SABnzbd can only report what it handed to the filesystem. Whether the payload
    reached the platter once or twice is a question only the kernel can answer, and
    that difference is the whole point of the run.
    """

    def __init__(self, path: str, device: Optional[str] = None):
        self.device = device
        self.supported = True
        self.note = ""
        if sys.platform.startswith("linux"):
            self.device = device or self._linux_device(path)
            if not self.device:
                self.supported = False
                self.note = "could not map the download directory to a block device"
        elif sys.platform == "darwin":
            # ioreg reports per-driver totals with no path association, so a machine
            # with more than one disk needs to be told which one to watch
            self.note = "macOS: totals are summed over all block devices unless --disk-device is given"
        else:
            self.supported = False
            self.note = "device statistics are not implemented on this platform"

    @staticmethod
    def _linux_device(path: str) -> Optional[str]:
        """Map a path to its /proc/diskstats entry through the device number.

        This resolves to the partition or device-mapper node the filesystem actually
        sits on, which is the layer the writes pass through, rather than the parent
        disk.
        """
        try:
            st = os.stat(path)
            major, minor = os.major(st.st_dev), os.minor(st.st_dev)
            with open("/proc/diskstats") as diskstats:
                for line in diskstats:
                    fields = line.split()
                    if int(fields[0]) == major and int(fields[1]) == minor:
                        return fields[2]
        except Exception:
            pass
        return None

    def read(self) -> Optional[dict[str, int]]:
        """Cumulative counters, or None when they cannot be read"""
        if not self.supported:
            return None
        try:
            if sys.platform.startswith("linux"):
                return self._read_linux()
            if sys.platform == "darwin":
                return self._read_macos()
        except Exception:
            return None
        return None

    def _read_linux(self) -> Optional[dict[str, int]]:
        with open("/proc/diskstats") as diskstats:
            for line in diskstats:
                fields = line.split()
                if fields[2] != self.device:
                    continue
                return {
                    "read_bytes": int(fields[5]) * LINUX_SECTOR_SIZE,
                    "write_bytes": int(fields[9]) * LINUX_SECTOR_SIZE,
                    # Milliseconds during which any I/O was in flight, so the delta over
                    # a wall-clock interval is utilisation
                    "io_ticks": int(fields[12]),
                }
        return None

    def _read_macos(self) -> Optional[dict[str, int]]:
        output = subprocess.run(
            ["ioreg", "-a", "-r", "-c", "IOBlockStorageDriver", "-w0"],
            capture_output=True,
            timeout=10,
        ).stdout
        if not output:
            return None
        entries = plistlib.loads(output)
        totals = {"read_bytes": 0, "write_bytes": 0, "io_ticks": 0}
        for entry in entries:
            if self.device and self.device not in str(entry.get("BSD Name", "")):
                continue
            if statistics := entry.get("Statistics"):
                totals["read_bytes"] += statistics.get("Bytes (Read)", 0)
                totals["write_bytes"] += statistics.get("Bytes (Write)", 0)
        return totals


##############################################################################
# Polling
##############################################################################
def fetch(url: str, apikey: str, reset: bool = False) -> dict[str, Any]:
    params = {"mode": "instrumentation", "apikey": apikey, "output": "json"}
    if reset:
        params["reset"] = "1"
    with urllib.request.urlopen("%s/api?%s" % (url.rstrip("/"), urllib.parse.urlencode(params)), timeout=30) as reply:
        return json.loads(reply.read())


def rate(current: float, previous: float, interval: float) -> float:
    """Per-second rate from two cumulative readings.

    Counters only ever move forwards unless the window was reset underneath us, in
    which case the delta is meaningless and zero is the honest answer.
    """
    if interval <= 0 or current < previous:
        return 0.0
    return (current - previous) / interval


def counter(snapshot: dict[str, Any], name: str) -> int:
    return snapshot.get("counters", {}).get(name, 0)


def labelled(snapshot: dict[str, Any], name: str, label: str) -> int:
    return snapshot.get("labelled", {}).get(name, {}).get(label, 0)


def timing(snapshot: dict[str, Any], name: str, field: str) -> float:
    return snapshot.get("timings", {}).get(name, {}).get(field, 0.0) * 1000.0


def build_row(
    snapshot: dict[str, Any],
    previous: Optional[dict[str, Any]],
    disk: Optional[dict[str, int]],
    previous_disk: Optional[dict[str, int]],
    elapsed: float,
    interval: float,
) -> dict[str, Any]:
    state = snapshot.get("state", {})
    cache = state.get("cache", {})
    assembler = state.get("assembler", {})
    downloader = state.get("downloader", {})
    process = snapshot.get("process", {})
    thread_cpu = snapshot.get("thread_cpu_seconds", {})

    previous = previous or {}
    previous_threads = previous.get("thread_cpu_seconds", {})

    def delta_rate(name: str) -> float:
        return rate(counter(snapshot, name), counter(previous, name), interval)

    def delta_rate_labelled(name: str, label: str) -> float:
        return rate(labelled(snapshot, name, label), labelled(previous, name, label), interval)

    def cpu_percent(role: str) -> float:
        return 100.0 * rate(thread_cpu.get(role, 0.0), previous_threads.get(role, 0.0), interval)

    cache_used = cache.get("size", 0)
    cache_limit = cache.get("limit", 0)

    # Bytes that went to the admin directory had to be written and read again on top of
    # the write to the final file, so each one costs three trips instead of one
    admin_bytes = counter(snapshot, "articlecache.flush_admin_file_bytes")
    decoded_bytes = counter(snapshot, "decoder.bytes")

    row = {
        "timestamp": round(time.time(), 3),
        "elapsed": round(elapsed, 1),
        "interval": round(interval, 3),
        "speed_bps": round(downloader.get("speed_bps", 0.0)),
        "articles_per_sec": round(delta_rate("decoder.articles"), 2),
        "decoded_bytes_per_sec": round(delta_rate("decoder.bytes")),
        "rss": process.get("rss", 0),
        "peak_rss": process.get("peak_rss", 0),
        "cpu_percent": round(
            100.0
            * rate(process.get("cpu_seconds", 0.0), previous.get("process", {}).get("cpu_seconds", 0.0), interval),
            2,
        ),
        "cpu_downloader_percent": round(cpu_percent("downloader"), 2),
        "cpu_receive_percent": round(cpu_percent("receive"), 2),
        "cpu_assembler_percent": round(cpu_percent("assembler"), 2),
        "cache_used": cache_used,
        "cache_limit": cache_limit,
        "cache_percent": round(100.0 * cache_used / cache_limit, 2) if cache_limit else 0.0,
        "cache_articles": cache.get("articles", 0),
        "held_per_sec": round(delta_rate("articlecache.held"), 2),
        "cache_full_per_sec": round(delta_rate_labelled("articlecache.flushed", "cache-full"), 2),
        "first_part_per_sec": round(delta_rate_labelled("articlecache.flushed", "first-part"), 2),
        "admin_writes_per_sec": round(delta_rate("articlecache.flush_admin_file"), 2),
        "admin_write_bytes_per_sec": round(delta_rate("articlecache.flush_admin_file_bytes")),
        "admin_rereads_per_sec": round(delta_rate("articlecache.reread_admin_file"), 2),
        "admin_reread_bytes_per_sec": round(delta_rate("articlecache.reread_admin_file_bytes")),
        "direct_writes_per_sec": round(delta_rate("articlecache.flush_direct_write"), 2),
        "amplification_ratio": round((decoded_bytes + admin_bytes) / decoded_bytes, 4) if decoded_bytes else 1.0,
        "assembler_ready_bytes": assembler.get("ready_bytes", 0),
        "assembler_queue_size": assembler.get("queue_size", 0),
        "assembler_delay": assembler.get("delay", 0),
        "assembler_bytes_per_sec": round(delta_rate("assembler.bytes_written")),
        "assembler_direct_per_sec": round(delta_rate_labelled("assembler.writes", "direct"), 2),
        "assembler_append_per_sec": round(delta_rate_labelled("assembler.writes", "append"), 2),
        "disk_write_bytes_per_sec": 0,
        "disk_read_bytes_per_sec": 0,
        "disk_util_percent": 0.0,
        "decode_avg_ms": round(timing(snapshot, "decoder.decode", "avg_seconds"), 4),
        "decode_max_ms": round(timing(snapshot, "decoder.decode", "max_seconds"), 4),
        "save_article_avg_ms": round(timing(snapshot, "articlecache.save_article", "avg_seconds"), 4),
        "save_article_max_ms": round(timing(snapshot, "articlecache.save_article", "max_seconds"), 4),
    }

    if disk and previous_disk:
        row["disk_write_bytes_per_sec"] = round(rate(disk["write_bytes"], previous_disk["write_bytes"], interval))
        row["disk_read_bytes_per_sec"] = round(rate(disk["read_bytes"], previous_disk["read_bytes"], interval))
        # io_ticks counts milliseconds with I/O in flight, so its delta over the wall
        # clock is how busy the device was. Not available on macOS.
        busy_ms = disk["io_ticks"] - previous_disk["io_ticks"]
        if busy_ms > 0:
            row["disk_util_percent"] = round(min(100.0, 100.0 * busy_ms / (interval * 1000.0)), 2)

    return row


##############################################################################
# Prometheus
##############################################################################
def metric_name(name: str) -> str:
    """SABnzbd's dotted counter names into legal Prometheus metric names"""
    return "".join(character if character.isalnum() else "_" for character in name)


def escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class PrometheusState:
    """Latest snapshot, rendered on demand in the Prometheus text format.

    Cumulative counters are exported raw, as counters, rather than as the per-interval
    rates the CSV carries. The CSV needs its own deltas because a spreadsheet has no
    rate() to call, but handing Prometheus pre-computed rates throws away everything it
    is good at: rate() picks its own window, so smoothing is a dashboard decision rather
    than something baked in at collection time and needing the run repeated to change;
    counter resets across a SABnzbd restart are detected; and a scrape interval that
    does not match the poll interval stops mattering, because scraping an unchanged
    counter twice contributes nothing instead of duplicating a rate sample.

    New counters are picked up automatically, so a breakdown added to
    sabnzbd/instrumentation.py needs no change here.
    """

    def __init__(self):
        self.snapshot: dict[str, Any] = {}
        self.disk: Optional[dict[str, int]] = None

    def update(self, snapshot: dict[str, Any], disk: Optional[dict[str, int]]):
        self.snapshot, self.disk = snapshot, disk

    def render(self) -> bytes:
        snapshot = self.snapshot
        if not snapshot:
            return b"# no sample collected yet\n"

        lines: list[str] = []

        def emit(name: str, value: Any, kind: str, labels: str = ""):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return
            lines.append("# TYPE %s %s" % (name, kind))
            lines.append("%s%s %s" % (name, labels, value))

        # Counters, straight from the API. rate() turns these into whatever the
        # dashboard asks for.
        for name, value in sorted(snapshot.get("counters", {}).items()):
            emit("sabnzbd_%s_total" % metric_name(name), value, "counter")

        # Labelled counters become real Prometheus labels, so a breakdown can be summed
        # or split in the query rather than needing one metric per label
        for name, labels in sorted(snapshot.get("labelled", {}).items()):
            metric = "sabnzbd_%s_total" % metric_name(name)
            lines.append("# TYPE %s counter" % metric)
            for label, value in sorted(labels.items()):
                lines.append('%s{label="%s"} %s' % (metric, escape_label(label), value))

        # Cumulative CPU per role: rate() over these gives the fraction of a core, which
        # is what the pre-computed percentage was approximating
        thread_cpu = snapshot.get("thread_cpu_seconds", {})
        if thread_cpu:
            lines.append("# TYPE sabnzbd_thread_cpu_seconds_total counter")
            for role, value in sorted(thread_cpu.items()):
                lines.append('sabnzbd_thread_cpu_seconds_total{role="%s"} %s' % (escape_label(role), value))

        # Spans as a total and a count, so rate(total)/rate(count) is the mean latency
        # over the dashboard's window rather than over the whole run
        timings = snapshot.get("timings", {})
        if timings:
            lines.append("# TYPE sabnzbd_span_seconds_total counter")
            for name, entry in sorted(timings.items()):
                lines.append('sabnzbd_span_seconds_total{span="%s"} %s' % (escape_label(name), entry["total_seconds"]))
            lines.append("# TYPE sabnzbd_span_calls_total counter")
            for name, entry in sorted(timings.items()):
                lines.append('sabnzbd_span_calls_total{span="%s"} %s' % (escape_label(name), entry["count"]))
            lines.append("# TYPE sabnzbd_span_max_seconds gauge")
            for name, entry in sorted(timings.items()):
                lines.append('sabnzbd_span_max_seconds{span="%s"} %s' % (escape_label(name), entry["max_seconds"]))

        # Peaks are tracked in-process, so they catch bursts that fall between polls.
        # Named for the recording window to keep them apart from peak_rss_bytes below,
        # which is the OS figure for the whole process lifetime.
        for name, value in sorted(snapshot.get("peaks", {}).items()):
            emit("sabnzbd_window_peak_%s" % metric_name(name), value, "gauge")

        process = snapshot.get("process", {})
        emit("sabnzbd_rss_bytes", process.get("rss"), "gauge")
        emit("sabnzbd_peak_rss_bytes", process.get("peak_rss"), "gauge")
        emit("sabnzbd_process_cpu_seconds_total", process.get("cpu_seconds"), "counter")
        emit("sabnzbd_threads", process.get("thread_count"), "gauge")

        state = snapshot.get("state", {})
        cache = state.get("cache", {})
        emit("sabnzbd_cache_used_bytes", cache.get("size"), "gauge")
        emit("sabnzbd_cache_limit_bytes", cache.get("limit"), "gauge")
        emit("sabnzbd_cache_articles", cache.get("articles"), "gauge")

        assembler = state.get("assembler", {})
        emit("sabnzbd_assembler_ready_bytes", assembler.get("ready_bytes"), "gauge")
        emit("sabnzbd_assembler_queue_size", assembler.get("queue_size"), "gauge")
        emit("sabnzbd_assembler_delay_seconds", assembler.get("delay"), "gauge")

        downloader = state.get("downloader", {})
        emit("sabnzbd_speed_bytes_per_second", downloader.get("speed_bps"), "gauge")

        queue = state.get("queue", {})
        emit("sabnzbd_queue_jobs", queue.get("jobs"), "gauge")
        emit("sabnzbd_queue_bytes_left", queue.get("bytes_left"), "gauge")
        emit("sabnzbd_postproc_queue", state.get("postproc", {}).get("queue_length"), "gauge")

        # Device counters are cumulative by nature, so they need no special handling
        if self.disk:
            emit("sabnzbd_disk_read_bytes_total", self.disk.get("read_bytes"), "counter")
            emit("sabnzbd_disk_write_bytes_total", self.disk.get("write_bytes"), "counter")
            # Milliseconds with I/O in flight; as seconds, rate() is utilisation directly
            emit("sabnzbd_disk_io_seconds_total", self.disk.get("io_ticks", 0) / 1000.0, "counter")

        return ("\n".join(lines) + "\n").encode()


def serve_prometheus(port: int, state: PrometheusState):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = state.render()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("0.0.0.0", port), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    print("Prometheus metrics on http://127.0.0.1:%s/metrics" % port)


##############################################################################
# Summary
##############################################################################
def to_units(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024 or unit == "TB":
            return "%.1f %s" % (value, unit)
        value /= 1024
    return "%.1f TB" % value


def print_summary(first: dict[str, Any], last: dict[str, Any], rows: int):
    """The three questions the decision gate asks, answered from the run"""
    decoded = counter(last, "decoder.bytes")
    admin_written = counter(last, "articlecache.flush_admin_file_bytes")
    admin_reread = counter(last, "articlecache.reread_admin_file_bytes")
    held = counter(last, "articlecache.held")
    cache_full = labelled(last, "articlecache.flushed", "cache-full")
    first_part = labelled(last, "articlecache.flushed", "first-part")
    saved = held + cache_full + first_part

    print("\n" + "=" * 78)
    print("Measurement run: %s samples over %.0f seconds" % (rows, last.get("window_seconds", 0)))
    print("=" * 78)

    print("\nCache overflow")
    print("  articles saved          %s" % saved)
    print("  held in memory          %s (%.1f%%)" % (held, 100.0 * held / saved if saved else 0))
    print("  spilled, cache full     %s (%.1f%%)" % (cache_full, 100.0 * cache_full / saved if saved else 0))
    print("  spilled, first part     %s (%.1f%%)" % (first_part, 100.0 * first_part / saved if saved else 0))

    print("\nWrite amplification")
    print("  payload decoded         %s" % to_units(decoded))
    print("  extra written to admin  %s" % to_units(admin_written))
    print("  read back from admin    %s" % to_units(admin_reread))
    if decoded:
        print("  amplification           %.3fx of payload written to the download disk" % (1 + admin_written / decoded))
    if not admin_written:
        print("  -> the cache never overflowed, so S2 gains nothing here. Lower misc.cache_limit,")
        print("     throttle the download disk, or raise the line rate to reach the regime.")

    # Peaks are taken from the in-process trackers, not from the polled samples. A short
    # burst can pass entirely between two polls: the run above filled and drained the
    # cache inside one second and the sampled maximum was zero.
    peaks = last.get("peaks", {})
    process = last.get("process", {})
    print("\nMemory")
    print("  peak RSS in window      %s" % to_units(peaks.get("process.rss", 0)))
    print(
        "  peak RSS of process     %s (whole process lifetime, includes unpacking)"
        % to_units(process.get("peak_rss", 0))
    )
    print("  final RSS               %s" % to_units(process.get("rss", 0)))
    print("  peak cache used         %s" % to_units(peaks.get("articlecache.size", 0)))
    print("  cache limit             %s" % to_units(last.get("state", {}).get("cache", {}).get("limit", 0)))

    print("\nCPU, cumulative seconds")
    for role, seconds in sorted(last.get("thread_cpu_seconds", {}).items()):
        print("  %-22s  %.1f s" % (role, seconds))
    print("  %-22s  %.1f s" % ("process total", last.get("process", {}).get("cpu_seconds", 0)))

    if timings := last.get("timings"):
        print("\nSpans, milliseconds")
        for name, entry in sorted(timings.items()):
            print(
                "  %-30s n=%-8s avg=%.3f  max=%.3f"
                % (name, entry["count"], entry["avg_seconds"] * 1000, entry["max_seconds"] * 1000)
            )
    print()


##############################################################################
def main():
    parser = argparse.ArgumentParser(description="Record a SABnzbd instrumentation run")
    parser.add_argument("--url", default="http://127.0.0.1:8080", help="SABnzbd base URL")
    parser.add_argument("--apikey", default=os.environ.get("SAB_APIKEY"), help="API key, or set SAB_APIKEY")
    parser.add_argument("--out", default="instrumentation", help="Output prefix for the .csv and .jsonl")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between polls")
    parser.add_argument("--duration", type=float, default=0, help="Stop after this many seconds, 0 for no limit")
    parser.add_argument("--reset", action="store_true", help="Reset the counters before starting")
    parser.add_argument("--download-dir", help="Download directory, used to find the block device to watch")
    parser.add_argument("--disk-device", help="Block device to watch, overriding auto-detection")
    parser.add_argument("--prometheus-port", type=int, help="Serve the latest sample in Prometheus text format")
    args = parser.parse_args()

    if not args.apikey:
        parser.error("no API key: pass --apikey or set SAB_APIKEY")

    disk = DiskStats(args.download_dir or os.getcwd(), args.disk_device)
    if disk.note:
        print("Device statistics: %s" % disk.note)
    elif disk.supported:
        print("Device statistics: watching %s" % disk.device)

    prometheus = PrometheusState()
    if args.prometheus_port:
        serve_prometheus(args.prometheus_port, prometheus)

    csv_path, jsonl_path = args.out + ".csv", args.out + ".jsonl"

    try:
        snapshot = fetch(args.url, args.apikey, reset=args.reset)
    except Exception as err:
        sys.exit("Could not reach the instrumentation API: %s" % err)

    if not snapshot.get("enabled"):
        print("\nWARNING: the instrumentation special is off, so only live state will be recorded.")
        print("Enable it under Config > Special, or:")
        print("  curl '%s/api?mode=set_config&section=misc&keyword=instrumentation&value=1&apikey=KEY'\n" % args.url)

    print("Writing %s and %s, polling every %.1fs. Ctrl-C to stop.\n" % (csv_path, jsonl_path, args.interval))

    started = time.monotonic()
    previous: Optional[dict[str, Any]] = None
    previous_disk: Optional[dict[str, int]] = None
    previous_time = started
    first_snapshot: Optional[dict[str, Any]] = None
    rows = 0

    with open(csv_path, "w", newline="") as csv_file, open(jsonl_path, "w") as jsonl_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        try:
            while True:
                if rows or previous is not None:
                    time.sleep(args.interval)
                now = time.monotonic()
                try:
                    snapshot = fetch(args.url, args.apikey)
                except Exception as err:
                    # A restart or a blocked request should not end the run
                    print("poll failed: %s" % err)
                    time.sleep(args.interval)
                    continue

                disk_now = disk.read()
                interval = now - previous_time
                row = build_row(snapshot, previous, disk_now, previous_disk, now - started, interval)

                # Exported raw, so unlike the CSV it needs no previous sample to be useful
                prometheus.update(snapshot, disk_now)

                # The raw response goes to JSONL so anything not in CSV_COLUMNS, including
                # counters added later, is still recoverable after the run
                jsonl_file.write(json.dumps({"elapsed": row["elapsed"], "snapshot": snapshot}) + "\n")
                jsonl_file.flush()

                if previous is not None:
                    writer.writerow(row)
                    csv_file.flush()
                    rows += 1
                    print(
                        "%6.0fs  %8s/s  cache %5.1f%%  spill %5.1f/s  admin-w %8s/s  disk-w %8s/s  util %5.1f%%  rss %8s"
                        % (
                            row["elapsed"],
                            to_units(row["speed_bps"]),
                            row["cache_percent"],
                            row["cache_full_per_sec"],
                            to_units(row["admin_write_bytes_per_sec"]),
                            to_units(row["disk_write_bytes_per_sec"]),
                            row["disk_util_percent"],
                            to_units(row["rss"]),
                        )
                    )
                else:
                    first_snapshot = snapshot

                previous, previous_disk, previous_time = snapshot, disk_now, now
                if args.duration and now - started >= args.duration:
                    break
        except KeyboardInterrupt:
            print("\nstopped")

    if rows and first_snapshot:
        print_summary(first_snapshot, previous, rows)
    print("CSV:   %s\nJSONL: %s" % (csv_path, jsonl_path))


if __name__ == "__main__":
    main()
