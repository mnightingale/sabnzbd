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
sabnzbd.memoryprofile - optional tracemalloc snapshots to diagnose memory leaks

Enabled by setting "tracemalloc_snapshots" in the misc-section of sabnzbd.ini.
Snapshots are written to a "tracemalloc" folder inside the log folder and can
be inspected afterwards using tracemalloc.Snapshot.load().
"""

import os
import gc
import time
import logging
import tracemalloc
from collections import deque
from threading import RLock
from types import FrameType, ModuleType
from typing import Optional

import sabnzbd
import sabnzbd.cfg as cfg
from sabnzbd.filesystem import create_all_dirs, globber_full, remove_file
from sabnzbd.misc import to_units

# Keep the noise of the profiler itself out of the results
SNAPSHOT_FILTERS = (
    tracemalloc.Filter(False, tracemalloc.__file__),
    tracemalloc.Filter(False, __file__),
    tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
    tracemalloc.Filter(False, "<frozen importlib._bootstrap_external>"),
    tracemalloc.Filter(False, "<unknown>"),
    tracemalloc.Filter(False, "*linecache.py"),
)

SNAPSHOT_DIR_NAME = "tracemalloc"
SNAPSHOT_EXTENSION = ".trace"
MAX_SNAPSHOTS_ON_DISK = 25
TOP_ENTRIES = 15
TRACEBACK_ENTRIES = 3

# Settings for the referrer-walk, which is bounded so it can never
# run away on a large heap with many interconnected objects
REFERRER_SAMPLE_SIZE = 3
REFERRER_MAX_DEPTH = 12
REFERRER_MAX_OBJECTS = 25000

# Attributes used to give the objects in a referrer-chain a recognizable name
IDENTIFYING_ATTRIBUTES = ("final_name", "filename", "article", "nzo_id", "nzf_id", "name")

MEMORY_PROFILE_LOCK = RLock()

# The very first snapshot is kept to spot slow, steady growth that
# is invisible in the diff against the previous snapshot
__FIRST_SNAPSHOT: Optional[tracemalloc.Snapshot] = None
__PREVIOUS_SNAPSHOT: Optional[tracemalloc.Snapshot] = None
__SNAPSHOT_COUNT = 0


def start():
    """Start tracing allocations, if enabled by the user. Should be called
    as early as possible, only allocations after this point are traced."""
    if not cfg.tracemalloc_snapshots() or tracemalloc.is_tracing():
        return
    tracemalloc.start(cfg.tracemalloc_frames())
    logging.info(
        "Started tracemalloc with %d frames, snapshots are written to %s",
        cfg.tracemalloc_frames(),
        snapshot_dir(),
    )


def snapshot_dir() -> str:
    """Folder where the snapshots are stored"""
    return os.path.join(cfg.log_dir.get_path(), SNAPSHOT_DIR_NAME)


def take_snapshot(label: str):
    """Store a snapshot on disk and log the diagnosis of the difference
    with the previous one. Safe to call when tracing is disabled."""
    if not tracemalloc.is_tracing():
        return

    global __FIRST_SNAPSHOT, __PREVIOUS_SNAPSHOT, __SNAPSHOT_COUNT
    with MEMORY_PROFILE_LOCK:
        try:
            snapshot = tracemalloc.take_snapshot().filter_traces(SNAPSHOT_FILTERS)
            __SNAPSHOT_COUNT += 1

            current, peak = tracemalloc.get_traced_memory()
            logging.info(
                "Tracemalloc snapshot %d (%s): %s traced, %s peak",
                __SNAPSHOT_COUNT,
                label,
                to_units(current, "B"),
                to_units(peak, "B"),
            )

            _save_snapshot(snapshot, label)

            if __PREVIOUS_SNAPSHOT:
                _log_difference(snapshot, __PREVIOUS_SNAPSHOT, "since previous snapshot")
            if __FIRST_SNAPSHOT and __FIRST_SNAPSHOT is not __PREVIOUS_SNAPSHOT:
                _log_difference(snapshot, __FIRST_SNAPSHOT, "since first snapshot")

            if not __FIRST_SNAPSHOT:
                __FIRST_SNAPSHOT = snapshot
            __PREVIOUS_SNAPSHOT = snapshot

            # Snapshot is dropped first, it references a lot of data itself
            del snapshot
            log_referrer_chains(cfg.tracemalloc_referrer_type())
        except Exception:
            # Never let diagnostics break post-processing
            logging.info("Failed to take tracemalloc snapshot", exc_info=True)


def log_referrer_chains(type_name: str, samples: int = REFERRER_SAMPLE_SIZE):
    """Log what is keeping objects of the given type alive. Tracemalloc only knows
    where an object was allocated, this shows who is still holding on to it."""
    if not type_name:
        return

    targets = []
    try:
        # The roots we hope to end up at, so the chain can be reported as complete
        roots = _global_roots()

        all_objects = gc.get_objects()
        try:
            matches = [obj for obj in all_objects if type(obj).__name__ == type_name]
        finally:
            # This list references every tracked object, it must not survive the walk
            del all_objects

        # Spread the samples over all matches, so we do not just get the
        # oldest job and can see whether they all share the same holder
        logging.info("Tracemalloc %d live %s objects", len(matches), type_name)
        stride = max(1, len(matches) // samples)
        targets = matches[::stride][:samples]
        del matches

        if not targets:
            logging.info("Tracemalloc no live %s objects found to trace referrers for", type_name)
            return

        logging.info("Tracemalloc tracing referrers of %d sampled %s objects", len(targets), type_name)
        for number, target in enumerate(targets, start=1):
            # The list of samples refers to the target itself, so it has to be ignored
            chain = _find_referrer_chain(target, roots, {id(targets)})
            logging.info("Tracemalloc referrer chain %d: %s", number, _describe(target))
            for depth, description in enumerate(chain, start=1):
                logging.info("Tracemalloc   %s<- %s", "  " * depth, description)
            if not chain:
                logging.info("Tracemalloc   <- nothing (only held by the sampling itself)")
    except Exception:
        logging.info("Failed to trace referrers", exc_info=True)
    finally:
        # Make sure the samples cannot keep the objects alive until the next collection
        targets = None


def _global_roots() -> dict[int, str]:
    """Map the id of every singleton on the sabnzbd module to its name, these
    are the interesting end-points of a referrer chain"""
    roots = {}
    for name in dir(sabnzbd):
        try:
            roots[id(getattr(sabnzbd, name))] = "sabnzbd.%s" % name
        except Exception:
            continue
    return roots


def _find_referrer_chain(target, roots: dict[int, str], ignore_ids: set[int]) -> list[str]:
    """Breadth-first walk over the referrers of the target, so the shortest
    path to a root is found. Returns the descriptions of that path."""
    # Anything we allocate here also refers to the target, so it has to be excluded
    own_ids = set(ignore_ids)
    visited = {id(target)}
    walk_queue = deque()
    own_ids.add(id(walk_queue))
    own_ids.add(id(visited))
    own_ids.add(id(own_ids))

    entry = (target, [])
    own_ids.add(id(entry))
    walk_queue.append(entry)

    longest_chain: list[str] = []
    while walk_queue and len(visited) < REFERRER_MAX_OBJECTS:
        obj, path = walk_queue.popleft()
        if len(path) >= REFERRER_MAX_DEPTH:
            continue

        referrers = gc.get_referrers(obj)
        own_ids.add(id(referrers))
        try:
            for referrer in referrers:
                # Skip our own bookkeeping and the stack frames we are running in
                if id(referrer) in visited or id(referrer) in own_ids or isinstance(referrer, FrameType):
                    continue
                visited.add(id(referrer))

                new_path = path + [_describe(referrer, roots)]
                if len(new_path) > len(longest_chain):
                    longest_chain = new_path

                # A module or one of the SABnzbd singletons means we are done
                if isinstance(referrer, ModuleType) or id(referrer) in roots:
                    return new_path

                new_entry = (referrer, new_path)
                own_ids.add(id(new_entry))
                walk_queue.append(new_entry)
        finally:
            del referrers

    # No root was reached within the limits, the deepest path is still informative
    return longest_chain


def _describe(obj, roots: Optional[dict[int, str]] = None) -> str:
    """Readable one-line description of an object in a referrer chain"""
    try:
        if roots and (root_name := roots.get(id(obj))):
            return "%s (%s)" % (root_name, type(obj).__name__)
        if isinstance(obj, ModuleType):
            return "module %s" % obj.__name__
        type_name = type(obj).__name__
        if isinstance(obj, (list, tuple, set, frozenset, dict)):
            return "%s[%d]" % (type_name, len(obj))
        # Try to give the SABnzbd objects a recognizable name
        for attribute in IDENTIFYING_ATTRIBUTES:
            try:
                if isinstance(value := getattr(obj, attribute, None), str) and value:
                    return "%s(%s=%s)" % (type_name, attribute, value[:60])
            except Exception:
                # Could be a property that throws in the current state
                continue
        return type_name
    except Exception:
        return "<undescribable object>"


def _save_snapshot(snapshot: tracemalloc.Snapshot, label: str):
    """Write the snapshot to disk and remove the oldest ones"""
    directory = snapshot_dir()
    create_all_dirs(directory)
    filename = "%s-%03d-%s%s" % (time.strftime("%Y%m%d_%H%M%S"), __SNAPSHOT_COUNT, label, SNAPSHOT_EXTENSION)
    snapshot.dump(os.path.join(directory, filename))
    logging.debug("Saved tracemalloc snapshot to %s", filename)

    # Only keep the most recent snapshots, they can be large
    snapshots = sorted(globber_full(directory, "*" + SNAPSHOT_EXTENSION))
    for old_snapshot in snapshots[:-MAX_SNAPSHOTS_ON_DISK]:
        remove_file(old_snapshot)


def _log_difference(snapshot: tracemalloc.Snapshot, reference: tracemalloc.Snapshot, description: str):
    """Log the largest growers between the two snapshots"""
    statistics = snapshot.compare_to(reference, "lineno")
    total_size_diff = sum(statistic.size_diff for statistic in statistics)
    total_count_diff = sum(statistic.count_diff for statistic in statistics)
    logging.info(
        "Tracemalloc difference %s: %s in %+d blocks",
        description,
        to_units(total_size_diff, "B"),
        total_count_diff,
    )

    # compare_to sorts on the absolute difference, but only the growth is of interest here
    for statistic in sorted(statistics, key=lambda statistic: statistic.size_diff, reverse=True)[:TOP_ENTRIES]:
        if statistic.size_diff <= 0:
            break
        logging.info(
            "Tracemalloc   %s in %+d blocks (now %s in %d blocks) at %s",
            to_units(statistic.size_diff, "B"),
            statistic.count_diff,
            to_units(statistic.size, "B"),
            statistic.count,
            statistic.traceback[0],
        )

    # For the biggest grower the full traceback tells us who is holding on to it.
    # Note that compare_to sorts on the absolute difference, so we cannot just take the first one.
    traceback_statistics = snapshot.compare_to(reference, "traceback")
    if traceback_statistics:
        biggest = max(traceback_statistics, key=lambda statistic: statistic.size_diff)
        if biggest.size_diff > 0:
            logging.info(
                "Tracemalloc allocation traceback of the biggest grower (%s):", to_units(biggest.size_diff, "B")
            )
            for line in biggest.traceback.format(limit=TRACEBACK_ENTRIES):
                logging.info("Tracemalloc   %s", line)
