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
sabnzbd.storage - is the destination keeping up?

Decides whether articles may be written where they belong as they arrive, or have to
be held in the cache until the gap in front of them is filled.

**The question is not what the disk is, it is whether it is coping.** An earlier
version of this module timed durable scattered writes at startup and classified the
device from the result. It cannot work. Every disk worth worrying about has a write
cache of 64-256 MB, and a probe short enough to run at startup writes single-digit
megabytes, so it measures the cache and not the disk: a USB spinning drive measured
1216 durable writes/s against 500-1000 for four real SSDs on the same machine, which
puts the two populations in the wrong order. Writing past the cache to defeat it takes
hundreds of megabytes and tens of seconds, which is not a startup cost anyone would
accept, and forcing the cache out with F_FULLFSYNC instead makes an SSD look slow.

So nothing here tries to identify the media. What it does instead is watch the writes
the download is already performing and notice when they stop being absorbed. That is a
better question in every way: it needs no probe, it is answered by the real workload
rather than a proxy for it, and it catches the cases a media check never could - a
disk that is fine until something else starts using it, an SMR drive that is fast
until its cache region fills, a network share, a machine under memory pressure.

**The signal is what a byte costs inside write().** A write that reaches the page
cache returns in tens of microseconds whatever is behind it - 700 KB in ~50 us, about
14 GB/s, on the machine this was written on. That number says nothing about the device
and everything about memory, which is the point: while it holds, the device is keeping
up by definition. It collapses only when writeback stops keeping pace and the kernel
makes the writer wait, and that collapse is what is being watched for. Three orders of
magnitude separate the two states, so the threshold does not have to be precise.

It is tracked as nanoseconds per byte rather than as bytes per second, which sounds
like the same thing averaged and is not. Averaging throughput lets one cached sample
at 14 GB/s outweigh a dozen stalled ones and hold the average above any threshold for
half a minute; averaging cost gives the stalled samples the weight they should have,
because a device that is slow half the time is slow.

**The decision is made on the samples, the average is only reported.** Each sample
already covers a couple of seconds and hundreds of writes, so it is not a spike, and
deciding on a smoothed value instead turns out to behave badly in the case that
matters most: the average takes several samples to come back down after a stall, and
anything arriving during that recovery counts against the device even though the disk
is by then keeping up perfectly well. So what is counted is consecutive samples that
were themselves slow, and the average exists to put a number in the log.

**The opening guess comes from rotational, and is only a guess.** /sys/block/<dev>/
queue/rotational is free to read and right often enough to be worth reading, but it is
absent in most containers and on every platform except Linux, and where it exists it
frequently describes the wrong thing - USB enclosures, hardware RAID, iSCSI, VM disks
and anything behind LVM, dm-crypt or ZFS report whatever the layer nearest the kernel
feels like. It is therefore used the way a hint should be: it picks which mode to open
with, and the measurement is free to overrule it in either direction.
"""

import logging
import os
import threading
import time
from typing import Optional

import sabnzbd
from sabnzbd.decorators import synchronized

# How often the writes are looked at. Long enough that a sample covers many writes,
# short enough that a disk that cannot cope is noticed within seconds.
SAMPLE_INTERVAL = 2.0
# Below this a sample is thrown away rather than acted on. A handful of writes says
# nothing, and neither does a trickle: a device is only worth judging while it is being
# asked for enough work to strain it.
MIN_SAMPLE_WRITES = 16
MIN_SAMPLE_BYTES = 4 * 1024 * 1024
# Weight of the newest sample in the reported average. Nothing is decided on it.
EMA_ALPHA = 0.3
# Throughput inside write(), below which the device is the thing holding the download
# up. A write absorbed by the page cache is three orders of magnitude above this, and a
# saturated SATA SSD still manages four times it, so this sits in the empty space
# between coping and not rather than close to either.
SLOW_WRITE_MBPS = 100
# The same figure as the nanoseconds per byte actually tracked
SLOW_WRITE_COST = 1e9 / (SLOW_WRITE_MBPS * 1024 * 1024)
# Consecutive slow samples before backing off, so a single stall - a snapshot, a
# competing copy, a par2 repair on the same disk - does not change the mode.
SLOW_SAMPLES_BEFORE_BACKOFF = 3
# How long to stay on the ordered path before trying again, and how far that grows each
# time the retry is refused. A device that failed once is asked again, because whatever
# made it slow is often temporary, but it is asked less and less often.
RETRY_AFTER = 600.0
RETRY_AFTER_MAX = 7200.0


def rotational(path: str) -> Optional[bool]:
    """Does the kernel say the disk behind this path seeks? None when it will not say.

    Linux only in practice, and deliberately not extended with the equivalents
    elsewhere: this is the opening guess and nothing more, so a platform that cannot
    answer simply starts optimistic and lets the measurement decide a few seconds
    later. No platform check is needed for that - everywhere else the sysfs path is
    simply not there.
    """
    try:
        device = os.stat(path).st_dev
        node = "/sys/dev/block/%d:%d" % (os.major(device), os.minor(device))
        # A partition has no queue of its own; the disk holding it does. Device mapper
        # and md targets do have one, so they are answered by the first branch.
        for candidate in (node, os.path.dirname(os.path.realpath(node))):
            try:
                with open(os.path.join(candidate, "queue", "rotational")) as flag:
                    return flag.read().strip() == "1"
            except OSError:
                continue
    except OSError:
        pass

    # Anything not backed by a block device - a network share above all - lands here
    return None


class WriteMonitor:
    """Whether the download directory is absorbing scattered writes.

    Starts from the rotational hint and then follows the measurement. Demotion is
    deliberately easier than promotion: writing in order is what SABnzbd has always
    done and is never badly wrong, so an uncertain answer resolves to it.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.path: Optional[str] = None
        self.streaming = False
        self.hint: Optional[bool] = None
        # Nanoseconds per byte spent inside write(), smoothed. Reported, not acted on.
        self.cost: Optional[float] = None
        # Consecutive samples in which the device did not keep up
        self.slow_samples = 0
        self.retry_after = RETRY_AFTER
        self.retry_at = 0.0
        self.sampled_at = 0.0
        # Last counters seen per open file, so each sample covers only new writes
        self.seen: dict[str, tuple[int, int, int]] = {}

    @synchronized()
    def reset(self, path: Optional[str] = None):
        """Start again for a directory, reading the hint but measuring nothing"""
        self.path = path if path is not None else sabnzbd.cfg.download_dir.get_path()
        self.hint = rotational(self.path) if self.path else None
        # A disk the kernel calls rotational opens on the ordered path, and gets its
        # first chance to prove otherwise once the retry comes round
        self.streaming = self.hint is not True
        self.retry_after = RETRY_AFTER
        self.retry_at = time.monotonic() + RETRY_AFTER
        self.rebaseline()

    def rebaseline(self):
        """Discard what was measured and start counting writes from this moment.

        Called on every mode change. The ordered path writes large runs the assembler
        has already gathered, so what it costs says nothing about how the device would
        handle the same bytes scattered, and carrying it across would let one mode's
        numbers decide the other's fate.

        The counters are cumulative for the life of a handle and the same handles are
        usually still open across the change, so this takes a fresh baseline rather
        than clearing it: cleared, the next sample would measure every write the file
        has ever taken instead of the ones made since.
        """
        self.cost = None
        self.slow_samples = 0
        self.seen = self.read_counters()

    @synchronized()
    def allows_streaming(self) -> bool:
        """May articles be written straight to their offset as they arrive?"""
        return self.streaming

    @synchronized()
    def sample(self):
        """Look at what the writes have cost since last time.

        Called from the downloader's existing tick, so it runs while there is something
        to measure and not at all while idle.
        """
        now = time.monotonic()
        if now - self.sampled_at < SAMPLE_INTERVAL:
            return
        self.sampled_at = now

        if not self.streaming:
            # Nothing to measure: the ordered path's writes describe the assembler's
            # batching, not the device's tolerance for scatter. Only the clock decides.
            if now >= self.retry_at:
                self.promote()
            return

        writes, written, nanos = self.consume_counters()
        if writes < MIN_SAMPLE_WRITES or written < MIN_SAMPLE_BYTES or nanos <= 0:
            return

        sample = nanos / written
        self.cost = sample if self.cost is None else EMA_ALPHA * sample + (1 - EMA_ALPHA) * self.cost

        if sample <= SLOW_WRITE_COST:
            self.slow_samples = 0
            return

        self.slow_samples += 1
        if self.slow_samples >= SLOW_SAMPLES_BEFORE_BACKOFF:
            self.demote()

    @staticmethod
    def read_counters() -> dict[str, tuple[int, int, int]]:
        """Write totals for every file with a handle open, keyed by file.

        Empty before the assembler exists, which is the case while the configuration is
        still being read.
        """
        assembler = getattr(sabnzbd, "Assembler", None)
        if assembler is None:
            return {}
        return {nzf_id: (stats["count"], stats["bytes"], stats["nanos"]) for nzf_id, stats in assembler.write_stats()}

    def consume_counters(self) -> tuple[int, int, int]:
        """Writes, bytes and nanoseconds since the previous sample.

        A file that closed between samples takes its last few writes with it, which
        costs an average nothing at these rates. A file whose handle was reopened
        counts from zero again, and is recognised by its counters having gone
        backwards.
        """
        writes = written = nanos = 0
        current = self.read_counters()

        for nzf_id, totals in current.items():
            previous = self.seen.get(nzf_id, (0, 0, 0))
            # Counters only ever rise, so a fall means this file was reopened and its
            # new handle is counting from zero
            if totals[0] < previous[0]:
                previous = (0, 0, 0)
            writes += totals[0] - previous[0]
            written += totals[1] - previous[1]
            nanos += totals[2] - previous[2]

        # Only files still open carry forward, so a finished job does not leak an entry
        self.seen = current
        return writes, written, nanos

    def demote(self):
        """Hold articles in the cache again, and wait longer before asking twice"""
        logging.info(
            "Writes to %s are not being absorbed (%s), holding articles in the cache for the next " "%.0f minutes",
            self.path,
            self.measured(),
            self.retry_after / 60,
        )
        self.streaming = False
        self.retry_at = time.monotonic() + self.retry_after
        self.retry_after = min(self.retry_after * 2, RETRY_AFTER_MAX)
        self.rebaseline()

    def promote(self):
        """Try streaming again. The next few samples decide whether it stays."""
        logging.info("Writing articles to %s as they arrive again, to see whether it keeps up", self.path)
        self.streaming = True
        self.rebaseline()

    def measured(self) -> str:
        """The smoothed cost, in the units a reader thinks in"""
        if self.cost is None:
            return "not measured yet"
        return "%.0f MB/s inside write" % (1e9 / self.cost / (1024 * 1024))

    @synchronized()
    def __str__(self) -> str:
        hint = {True: "rotational", False: "non-rotational", None: "unknown"}[self.hint]
        return "%s, %s -> %s" % (
            hint,
            self.measured(),
            "articles written as they arrive" if self.streaming else "articles held in the cache",
        )


MONITOR = WriteMonitor()


def initialize():
    """Pick the opening mode for the configured download directory"""
    MONITOR.reset()


def sample():
    """Hook for the downloader's tick"""
    MONITOR.sample()


def download_dir_supports_random_writes() -> bool:
    """May articles be written straight to their offset as they arrive?"""
    return MONITOR.allows_streaming()


def log_profile():
    """Report where the download directory started out"""
    logging.info("Storage profile for %s: %s", MONITOR.path, MONITOR)
