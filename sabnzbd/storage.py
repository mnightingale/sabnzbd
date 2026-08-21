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
sabnzbd.storage - whether the download directory keeps up with scattered writes
"""

import logging
import os
import threading
import time
from typing import Optional

import sabctools

import sabnzbd
from sabnzbd.decorators import synchronized

# Seconds between readings of the write counters
SAMPLE_INTERVAL = 2.0
# Smallest reading acted on rather than discarded
MIN_SAMPLE_WRITES = 16
MIN_SAMPLE_BYTES = 4 * 1024 * 1024
# Weight of the newest sample in the reported average
EMA_ALPHA = 0.3
# Throughput inside write() below which the destination counts as not keeping up
SLOW_WRITE_MBPS = 100
# The same figure as nanoseconds per byte, which is what is tracked
SLOW_WRITE_COST = 1e9 / (SLOW_WRITE_MBPS * 1024 * 1024)
# Consecutive slow samples before backing off to the cache
SLOW_SAMPLES_BEFORE_BACKOFF = 3
# Seconds on the cache before streaming is tried again, doubling on each refusal
RETRY_AFTER = 600.0
RETRY_AFTER_MAX = 7200.0


def rotational(path: str) -> Optional[bool]:
    """Does the kernel say the disk behind this path seeks? None when it will not say.

    Linux only: everywhere else the sysfs path is not there and the answer is None.
    """
    try:
        device = os.stat(path).st_dev
        node = "/sys/dev/block/%d:%d" % (os.major(device), os.minor(device))
        # A partition has no queue of its own; the disk holding it does
        for candidate in (node, os.path.dirname(os.path.realpath(node))):
            try:
                with open(os.path.join(candidate, "queue", "rotational")) as flag:
                    return flag.read().strip() == "1"
            except OSError:
                continue
    except OSError:
        pass

    return None


class WriteMonitor:
    """Whether the download directory is absorbing scattered writes"""

    def __init__(self):
        self.lock = threading.RLock()
        self.path: Optional[str] = None
        self.streaming = False
        self.hint: Optional[bool] = None
        # Nanoseconds per byte spent inside write(), smoothed
        self.cost: Optional[float] = None
        # Consecutive samples in which the device did not keep up
        self.slow_samples = 0
        self.retry_after = RETRY_AFTER
        self.retry_at = 0.0
        self.sampled_at = 0.0
        # Counters as of the previous sample
        self.seen = (0, 0, 0)

    @synchronized()
    def reset(self, path: Optional[str] = None):
        """Start again for a directory, reading the hint but measuring nothing"""
        self.path = path if path is not None else sabnzbd.cfg.download_dir.get_path()
        self.hint = rotational(self.path) if self.path else None
        self.streaming = self.hint is not True
        self.retry_after = RETRY_AFTER
        self.retry_at = time.monotonic() + RETRY_AFTER
        self.rebaseline()

    def rebaseline(self):
        """Discard what was measured and start counting writes from this moment"""
        self.cost = None
        self.slow_samples = 0
        self.seen = self.read_counters()

    @synchronized()
    def allows_streaming(self) -> bool:
        """May articles be written straight to their offset as they arrive?"""
        return self.streaming

    @synchronized()
    def sample(self):
        """Look at what the writes have cost since last time"""
        now = time.monotonic()
        if now - self.sampled_at < SAMPLE_INTERVAL:
            return
        self.sampled_at = now

        if not self.streaming:
            # Nothing to measure while the cache is batching the writes
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
    def read_counters() -> tuple[int, int, int]:
        """Writes, bytes and nanoseconds every file has cost since sabctools loaded"""
        stats = sabctools.write_stats()
        return stats["count"], stats["bytes"], stats["nanos"]

    def consume_counters(self) -> tuple[int, int, int]:
        """The same three, but only since the previous sample"""
        current = self.read_counters()
        interval = tuple(now - before for now, before in zip(current, self.seen))
        self.seen = current
        return interval

    def demote(self):
        """Hold articles in the cache again, and wait longer before trying once more"""
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
        """Write articles as they arrive again"""
        logging.info("Writing articles to %s as they arrive again, to see whether it keeps up", self.path)
        self.streaming = True
        self.rebaseline()

    def measured(self) -> str:
        """The smoothed cost as MB/s"""
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
    """Read the write counters, called from the downloader's tick"""
    MONITOR.sample()


def download_dir_supports_random_writes() -> bool:
    """May articles be written straight to their offset as they arrive?"""
    return MONITOR.allows_streaming()


def log_profile():
    """Log the mode the download directory is in"""
    logging.info("Storage profile for %s: %s", MONITOR.path, MONITOR)
