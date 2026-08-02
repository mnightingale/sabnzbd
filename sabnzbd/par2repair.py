#!/usr/bin/python3 -OO
# Copyright 2007-2025 by The SABnzbd-Team (sabnzbd.org)
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
sabnzbd.par2repair - verify and repair par2 sets in-process

Wraps sabctools.Par2Repairer, which drives par2cmdline-turbo as a library. It replaces
the old approach of running the par2 binary and parsing its output: everything the
repair loop needs - the block shortfall, the rename map, whether repair is possible - is
read as typed data instead of scraped from prose.

A repairer is kept alive for as long as a set is being worked on, in RepairSession.
That matters for the "not enough recovery blocks" path: SABnzbd puts the job back in
the queue to fetch more par2 files, and when it comes back the retained repairer can
take the new blocks through load_more() and go straight to repairing. Verification -
the expensive part - happens once per set rather than once per attempt.

Sessions live here rather than on the NzbObject because NzbObject is pickled into
__ADMIN__ and a C extension object cannot be pickled. They are keyed by nzo_id and set
name, and dropped by discard() when a job leaves post-processing.
"""

import logging
import os
import time
from typing import Optional

import sabctools

import sabnzbd
from sabnzbd.constants import Status
from sabnzbd.misc import format_time_string
from sabnzbd.nzb.object import NzbObject

# Live sessions, keyed by (nzo_id, setname). See the module docstring for why these
# cannot simply hang off the NzbObject.
_SESSIONS: dict[tuple[str, str], "RepairSession"] = {}


class RepairSession:
    """A par2 set being verified and repaired, and the repairer working on it."""

    def __init__(self, nzo: NzbObject, setname: str, parfile: str):
        self.nzo = nzo
        self.setname = setname
        self.parfile = parfile
        self.repairer: Optional[sabctools.Par2Repairer] = None

        # Absolute paths already handed to par2, so a re-add only loads what is new
        self.loaded_parfiles: set[str] = set()
        self.verified = False

        # Progress bookkeeping, reset per stage
        self.stage_start = time.time()
        self.last_percent = -1
        self.files_seen = 0

    # -- lifecycle ---------------------------------------------------------------

    def open(self, extrafiles: list[str]) -> sabctools.Par2Result:
        """Create the repairer and read the par2 packets."""
        basepath = os.path.dirname(self.parfile)
        self.repairer = sabctools.Par2Repairer(
            self.parfile,
            extrafiles=extrafiles,
            basepath=basepath,
        )
        self.repairer.progress_callback = self._on_progress

        # par2 pulls in sibling volume files by name during load()
        self.loaded_parfiles.add(os.path.abspath(self.parfile))

        self.stage_start = time.time()
        result = self.repairer.load()
        if result == sabctools.Par2Result.SUCCESS:
            logging.info(
                "Loaded par2 set %s: %s recoverable files, %s source blocks, %s recovery blocks",
                self.setname,
                self.repairer.recoverable_file_count,
                self.repairer.source_block_count,
                self.repairer.recovery_block_count,
            )
        return result

    def add_parfiles(self, paths: list[str]) -> int:
        """Feed newly downloaded par2 files in without re-verifying.

        Returns the recovery block count afterwards.
        """
        fresh = []
        for path in paths:
            absolute = os.path.abspath(path)
            if absolute not in self.loaded_parfiles and os.path.exists(absolute):
                fresh.append(absolute)

        if not fresh:
            return self.repairer.recovery_block_count

        blocks = self.repairer.load_more(fresh)
        self.loaded_parfiles.update(fresh)
        logging.info(
            "Added %s par2 file(s) to set %s, now %s recovery blocks",
            len(fresh),
            self.setname,
            blocks,
        )
        return blocks

    def close(self):
        """Drop the repairer. Any in-flight verify or repair is asked to stop first."""
        if self.repairer is not None:
            self.repairer.cancel()
            self.repairer.progress_callback = None
            self.repairer = None

    # -- work --------------------------------------------------------------------

    def verify(self) -> sabctools.Par2Result:
        self.nzo.status = Status.VERIFYING
        self.stage_start = time.time()
        self.last_percent = -1
        self.files_seen = 0

        result = self.repairer.verify()
        self.verified = True

        elapsed = format_time_string(time.time() - self.stage_start)
        if result == sabctools.Par2Result.SUCCESS:
            self.nzo.set_unpack_info(
                "Repair", T("[%s] Verified in %s, all files correct") % (self.setname, elapsed)
            )
            logging.info("Verified %s in %s, all files correct", self.setname, elapsed)
        else:
            self.nzo.set_unpack_info(
                "Repair", T("[%s] Verified in %s, repair is required") % (self.setname, elapsed)
            )
            logging.info(
                "Verified %s in %s, repair required: %s damaged, %s missing, %s renamed, %s of %s blocks missing",
                self.setname,
                elapsed,
                self.repairer.damaged_file_count,
                self.repairer.missing_file_count,
                self.repairer.renamed_file_count,
                self.repairer.missing_block_count,
                self.repairer.source_block_count,
            )
        return result

    def repair(self) -> sabctools.Par2Result:
        self.nzo.status = Status.REPAIRING
        self.stage_start = time.time()
        self.last_percent = -1
        self.nzo.set_action_line(T("Repairing"), "%2d%%" % 0)

        # Read before repairing: repair() applies the renames and clears the state
        renames = self.repairer.renames

        result = self.repairer.repair()

        if renames:
            # renamed_file() wants {new_name: old_name} in bare filenames
            self.nzo.renamed_file({os.path.basename(new): os.path.basename(old) for old, new in renames.items()})

        if result == sabctools.Par2Result.SUCCESS:
            elapsed = format_time_string(time.time() - self.stage_start)
            self.nzo.set_unpack_info("Repair", T("[%s] Repaired in %s") % (self.setname, elapsed))
            logging.info("Repaired %s in %s", self.setname, elapsed)
        return result

    @property
    def block_shortfall(self) -> int:
        """How many more recovery blocks would make this repairable."""
        return max(0, self.repairer.missing_block_count - self.repairer.recovery_block_count)

    # -- progress ----------------------------------------------------------------

    def _on_progress(self, stage: str, filename: str, percent: int):
        """Called from par2's worker threads; keep it short.

        Mirrors the granularity the output parser used to produce: one update per file
        while scanning, and whole-percent updates while repairing.
        """
        try:
            if stage == "loading":
                return

            if filename:
                self.files_seen += 1
                self.last_percent = -1

            if stage == "verifying":
                if filename:
                    self.nzo.set_action_line(
                        T("Verifying"), "%02d/%02d" % (self.files_seen, self.repairer.recoverable_file_count)
                    )
            elif stage == "repairing":
                if percent > self.last_percent:
                    self.last_percent = percent
                    self.nzo.status = Status.REPAIRING
                    self.nzo.set_action_line(
                        T("Repairing"), "%2d%% %s" % (percent, sabnzbd.newsunpack.add_time_left(percent, self.stage_start))
                    )
            elif stage == "verifying_repair":
                if filename:
                    self.nzo.set_action_line(
                        T("Verifying repair"), "%02d/%02d" % (self.files_seen, self.repairer.recoverable_file_count)
                    )
        except Exception:
            # A progress update must never take down a repair
            logging.debug("Failed to report par2 progress", exc_info=True)


def get_session(nzo: NzbObject, setname: str, parfile: str) -> Optional[RepairSession]:
    """Return the live session for this set, if the parfile still matches."""
    session = _SESSIONS.get((nzo.nzo_id, setname))
    if session is not None and session.parfile == parfile and session.repairer is not None:
        return session
    if session is not None:
        # A different base par2 file means starting over
        discard(nzo.nzo_id, setname)
    return None


def create_session(nzo: NzbObject, setname: str, parfile: str) -> RepairSession:
    session = RepairSession(nzo, setname, parfile)
    _SESSIONS[(nzo.nzo_id, setname)] = session
    return session


def discard(nzo_id: str, setname: Optional[str] = None):
    """Drop sessions for a job, or for one of its sets."""
    for key in [k for k in _SESSIONS if k[0] == nzo_id and (setname is None or k[1] == setname)]:
        _SESSIONS.pop(key).close()


def cancel(nzo_id: str):
    """Ask any in-flight verify or repair for this job to stop.

    Called from PostProcessor.cancel_pp, where killing the par2 subprocess used to be.
    """
    for key, session in _SESSIONS.items():
        if key[0] == nzo_id and session.repairer is not None:
            logging.info("Cancelling par2 repair of %s", key[1])
            session.repairer.cancel()


def parfile_paths(nzo: NzbObject, setname: str) -> list[str]:
    """Every par2 file of this set currently on disk."""
    paths = []
    for nzf in nzo.extrapars.get(setname, []):
        path = os.path.join(nzo.download_path, nzf.filename)
        if os.path.exists(path):
            paths.append(path)
    return paths


def joinable_matches(session: RepairSession, joinables: list[str]) -> list[str]:
    """Joinables par2 used as a source, so par_cleanup can remove them.

    par2 reports a match against the file it found on disk; when that file is one of
    the .001/.002 parts, the whole joinable set was consumed.
    """
    if not joinables:
        return []

    used = []
    for entry in session.repairer.files:
        found = entry.get("found")
        if found and found in joinables and found not in used:
            used.append(found)
    return used
