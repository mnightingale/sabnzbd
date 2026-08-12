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
sabnzbd.storage - what the destinations can actually do

Answers one question per directory: can this device absorb writes scattered across
a file, or does it want them in order? That decides whether articles may be written
where they belong as they arrive, or have to be held until the gap in front of them
is filled.

**Measured, not asked.** /sys/block/<dev>/queue/rotational is not consulted at all.
It is absent in most containers, and where it exists it describes the wrong thing:
a USB enclosure, a hardware RAID virtual disk, an iSCSI LUN, a VM disk and anything
behind LVM, dm-crypt or ZFS all report whatever the layer nearest the kernel feels
like, and none of it accounts for the stack in between. Timing the operation
through the whole stack is both simpler and harder to fool.

**Random writes, with fsync, not random reads.** The obvious probe - write a file,
read it back at random offsets - measures the page cache and not the disk, because
the file just written is still in memory. Defeating that portably means O_DIRECT
with its alignment rules on Linux, F_NOCACHE on macOS and FILE_FLAG_NO_BUFFERING on
Windows, three different mechanisms with three sets of constraints. A write followed
by fsync cannot be answered from cache by construction: it does not return until the
device says it is durable. It also happens to be the operation actually being gated.

The figure is therefore a floor rather than a benchmark. SABnzbd does not fsync every
article, so real throughput is higher than this reports. That is fine and deliberate:
it is used to tell two populations apart that differ by more than an order of
magnitude, not to predict a rate. Note also that macOS fsync pushes to the device
without flushing its cache - only F_FULLFSYNC does that, at a cost far beyond what a
startup probe should pay - so the barrier is weaker there. It still leaves the page
cache, which is all the measurement needs.

**The threshold errs towards sequential.** Calling a solid state disk slow costs
nothing: writes stay ordered, which is what happens today. Calling a spinning disk
fast costs a seek per article. So an unmeasurable device, a failed probe and a
borderline result all resolve the same way, and the threshold sits well above what a
spinning disk can reach rather than close to it.
"""

import logging
import os
import random
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Optional

import sabnzbd
from sabnzbd.filesystem import same_device

# Span the writes are scattered over. Preallocated as a hole, so it costs nothing to
# create; large enough that offsets within it are a real seek on a spinning disk.
PROBE_SPAN = 256 * 1024 * 1024
# Closer to the ~700 KB SABnzbd writes per article than a 4 KB block would be. Small
# enough that a whole probe writes single-digit megabytes.
PROBE_BLOCK = 128 * 1024
# Whichever comes first. The op count bounds the damage on fast devices, the deadline
# bounds the wait on slow ones - a disk managing 30 ops in half a second has already
# answered the question.
PROBE_MAX_OPS = 64
PROBE_TIME_BUDGET = 0.5
# At least this many before believing the result
PROBE_MIN_OPS = 8

# Durable random writes per second above which scattering writes is worth doing.
# A 7200 rpm disk seeks in 7-12 ms and so lands near 60-130; anything solid state is
# in the thousands even with a flush on every write. The gap is wide enough that the
# exact number here does not matter much, which is the point of choosing a threshold
# in the middle of a chasm rather than near either population.
FAST_RANDOM_WRITE_IOPS = 400


@dataclass(frozen=True, slots=True)
class DeviceProfile:
    """What a probe of one device found. iops is 0 when nothing could be measured."""

    device: int
    path: str
    iops: float = 0.0
    mbps: float = 0.0
    ops: int = 0
    seconds: float = 0.0
    error: Optional[str] = None

    @property
    def measured(self) -> bool:
        return self.ops >= PROBE_MIN_OPS and self.error is None

    @property
    def supports_random_writes(self) -> bool:
        """May articles be written where they belong as they arrive?

        Unmeasured means no. A device we could not time is one we know nothing about,
        and writing in order is the option that is never badly wrong.
        """
        return self.measured and self.iops >= FAST_RANDOM_WRITE_IOPS

    def __str__(self) -> str:
        if not self.measured:
            return "unmeasured (%s)" % (self.error or "too few samples")
        return "%.0f random writes/s, %.1f MB/s -> %s" % (
            self.iops,
            self.mbps,
            "scattered writes" if self.supports_random_writes else "sequential writes",
        )


_lock = threading.Lock()
# Keyed by path, not by st_dev. Two paths sharing a device share a profile, but whether
# they share one is filesystem.same_device's question to answer: st_dev alone is not
# reliable for network locations on Windows, where two different UNC shares can report
# the same value and would otherwise be collapsed into one measurement.
_profiles: dict[str, DeviceProfile] = {}


def probe(path: str) -> DeviceProfile:
    """Time durable writes scattered across a file in this directory.

    Never raises: a directory that cannot be written to is simply one we know nothing
    about, which callers read as "keep it sequential".
    """
    try:
        device = os.stat(path).st_dev
    except OSError as err:
        return DeviceProfile(device=0, path=path, error=str(err))

    handle = None
    probe_path = None
    try:
        handle, probe_path = tempfile.mkstemp(prefix=".sabnzbd-probe-", dir=path)

        # A hole rather than 256 MB of real writes. Also the same shape as a
        # direct-write download: preallocate, then fill pieces of it out of order.
        os.ftruncate(handle, PROBE_SPAN)

        block = os.urandom(PROBE_BLOCK)
        # Seeded, so two runs on one machine are comparable
        offsets = random.Random(0x5AB4).sample(range(PROBE_SPAN // PROBE_BLOCK), PROBE_MAX_OPS)

        ops = 0
        deadline = time.monotonic() + PROBE_TIME_BUDGET
        started = time.monotonic()
        for index in offsets:
            _write_at(handle, block, index * PROBE_BLOCK)
            # What makes this a measurement of the device rather than of memory
            os.fsync(handle)
            ops += 1
            if time.monotonic() >= deadline:
                break
        elapsed = time.monotonic() - started

        if elapsed <= 0:
            return DeviceProfile(device=device, path=path, ops=ops, error="no elapsed time")

        return DeviceProfile(
            device=device,
            path=path,
            iops=ops / elapsed,
            mbps=(ops * PROBE_BLOCK) / elapsed / (1024 * 1024),
            ops=ops,
            seconds=elapsed,
        )
    except Exception as err:
        return DeviceProfile(device=device, path=path, error=str(err))
    finally:
        if handle is not None:
            try:
                os.close(handle)
            except OSError:
                pass
        if probe_path:
            try:
                os.remove(probe_path)
            except OSError:
                logging.debug("Could not remove storage probe file %s", probe_path, exc_info=True)


def _write_at(handle: int, data: bytes, offset: int):
    """Positional write. os.pwrite is Unix only, and the probe is single threaded, so
    seek-and-write is an adequate stand-in on Windows."""
    if sabnzbd.WINDOWS:
        os.lseek(handle, offset, os.SEEK_SET)
        os.write(handle, data)
    else:
        os.pwrite(handle, data, offset)


def profile_for(path: str) -> DeviceProfile:
    """Profile of the device behind a path, probing it the first time it is asked for.

    A path sharing a device with one already profiled reuses its answer, so a download
    and complete directory on one disk cost one probe between them.
    """
    with _lock:
        if (cached := _profiles.get(path)) is not None:
            return cached
        for known, profile in _profiles.items():
            # Only a real measurement is shared. A failure says something about that
            # path, not about the device: same_device resolves a missing path to its
            # nearest existing parent, so a typo in one directory would otherwise mark
            # every other directory on the same disk unmeasurable.
            if profile.measured and same_device(path, known):
                _profiles[path] = profile
                return profile

    # Probing outside the lock: it takes up to PROBE_TIME_BUDGET, and two callers
    # racing to measure one device costs only the duplicated work
    measured = probe(path)

    with _lock:
        return _profiles.setdefault(path, measured)


def forget():
    """Drop cached profiles, so the next request probes again"""
    with _lock:
        _profiles.clear()


def profile_directories() -> dict[str, DeviceProfile]:
    """Profile every directory the pipeline writes to, one probe per distinct device.

    complete_dir may differ from download_dir, and either may be a different device or
    the same one; the caller gets a profile per path and pays for the devices behind
    them, not for the paths.
    """
    results: dict[str, DeviceProfile] = {}
    paths = [sabnzbd.cfg.download_dir.get_path(), sabnzbd.cfg.complete_dir.get_path()]

    for path in paths:
        if not path or path in results or not os.path.isdir(path):
            continue
        results[path] = profile_for(path)

    return results


def log_profiles():
    """Report what the destinations can do. Advisory for now: the numbers are logged
    and exposed, and nothing changes its behaviour because of them yet."""
    for path, profile in profile_directories().items():
        logging.info("Storage profile for %s: %s", path, profile)
