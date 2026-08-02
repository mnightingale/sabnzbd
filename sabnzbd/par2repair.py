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

Sessions hang off the job as nzo.par2_sessions, keyed by set name, in the same way as
nzo.direct_unpacker: absent from NzbObjectSaver so they are never pickled, and reset by
NzbObject.__setstate__. Tying their lifetime to the job means a removed or abandoned
job cannot leak a repairer.
"""

import logging
import os
import time
from typing import Optional

import sabctools

import sabnzbd
import sabnzbd.cfg as cfg
from sabnzbd.constants import Status
from sabnzbd.filesystem import get_ext, globber_full
from sabnzbd.misc import format_time_string
from sabnzbd.nzb.object import NzbObject


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

        # Files par2 scanned and how many blocks it took from each, filled in by
        # file_done_callback. This is what identifies the files on disk that actually
        # contributed data - joinable .001/.002 parts in particular, which par2 consumes
        # without ever reporting them as a source file.
        self.blocks_from: dict[str, int] = {}

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
        self.repairer.file_done_callback = self._on_file_done

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
            self.repairer.file_done_callback = None
            self.repairer = None

    # -- work --------------------------------------------------------------------

    def apply_known_blocks(self):
        """Hand par2 the blocks the download already vouched for, if enabled.

        Purely an optimisation, so anything that goes wrong here is logged and dropped:
        par2 then reads and hashes the files itself, which is merely the slower answer
        rather than a wrong one.
        """
        try:
            known = article_backed_blocks(self.nzo, self.repairer)
            if not known:
                return
            self.repairer.set_known_blocks(known)
        except Exception:
            logging.info("Could not use article checksums for %s, verifying in full", self.setname, exc_info=True)
            return

        logging.info(
            "Quick verify: %s of %s files in set %s covered by verified articles",
            len(known),
            self.repairer.recoverable_file_count,
            self.setname,
        )

    def verify(self) -> sabctools.Par2Result:
        self.nzo.status = Status.VERIFYING
        self.stage_start = time.time()
        self.last_percent = -1
        self.files_seen = 0

        result = self.repairer.verify()
        self.verified = True

        elapsed = format_time_string(time.time() - self.stage_start)
        if result == sabctools.Par2Result.SUCCESS:
            self.nzo.set_unpack_info("Repair", T("[%s] Verified in %s, all files correct") % (self.setname, elapsed))
            logging.info(
                "Verified %s in %s, all files correct (%s file(s) taken from article checksums)",
                self.setname,
                elapsed,
                self.repairer.quick_verified_files,
            )
        else:
            self.nzo.set_unpack_info("Repair", T("[%s] Verified in %s, repair is required") % (self.setname, elapsed))
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

    def _on_file_done(self, filename: str, blocks_found: int, blocks_total: int):
        """One call per file par2 finishes scanning."""
        try:
            if blocks_found:
                self.blocks_from[filename] = blocks_found
        except Exception:
            logging.debug("Failed to record par2 block source", exc_info=True)

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
                        T("Repairing"),
                        "%2d%% %s" % (percent, sabnzbd.newsunpack.add_time_left(percent, self.stage_start)),
                    )
            elif stage == "verifying_repair":
                if filename:
                    self.nzo.set_action_line(
                        T("Verifying repair"), "%02d/%02d" % (self.files_seen, self.repairer.recoverable_file_count)
                    )
        except Exception:
            # A progress update must never take down a repair
            logging.debug("Failed to report par2 progress", exc_info=True)


def get_session(nzo: NzbObject, setname: str) -> Optional[RepairSession]:
    """Return the live session for this set, if there is one.

    Deliberately keyed on the set name alone, not on which par2 file par2_repair picked
    this time. That file is chosen from nzo.extrapars, which shrinks as par2 files
    finish downloading - handle_par2() removes them - so a resumed attempt often starts
    from a different member of the same set. Requiring it to match would throw the
    verification away for no reason.

    Set names are unique per set: handle_par2() falls back to the par2 set id when two
    sets would otherwise share a name.
    """
    session = nzo.par2_sessions.get(setname)
    if session is not None and session.repairer is not None:
        return session
    if session is not None:
        discard(nzo, setname)
    return None


def create_session(nzo: NzbObject, setname: str, parfile: str) -> RepairSession:
    session = RepairSession(nzo, setname, parfile)
    nzo.par2_sessions[setname] = session
    return session


def discard(nzo: NzbObject, setname: Optional[str] = None):
    """Drop sessions for a job, or for one of its sets."""
    for name in [setname] if setname else list(nzo.par2_sessions):
        if session := nzo.par2_sessions.pop(name, None):
            session.close()


def cancel(nzo: NzbObject):
    """Ask any in-flight verify or repair for this job to stop.

    Called from PostProcessor.cancel_pp, where killing the par2 subprocess used to be.
    """
    for setname, session in nzo.par2_sessions.items():
        if session.repairer is not None:
            logging.info("Cancelling par2 repair of %s", setname)
            session.repairer.cancel()


def article_backed_blocks(nzo: NzbObject, repairer: sabctools.Par2Repairer) -> dict[str, list[bool]]:
    """Which par2 blocks are already covered by articles that checked out on arrival.

    Every article is checksummed against its yEnc trailer as it is decoded, so for the
    parts of a file built from articles that matched, there is nothing on disk worth
    reading again. Handing those blocks to par2 lets it skip hashing them entirely.

    Requires direct write: only then does article.data_begin describe where the bytes
    actually landed. Without it the assembler packs articles in completion order, so a
    file with holes has offsets that do not line up with par2's blocks.
    """
    if not cfg.par2_quick_verify() or not cfg.direct_write():
        return {}

    blocksize = repairer.block_size
    if not blocksize:
        return {}

    by_name = {nzf.filename: nzf for nzf in nzo.finished_files}
    known = {}
    for entry in repairer.files:
        # Deliberately not filtered on entry["exists"]: par2 only sets that while
        # scanning the source files, so straight after load() it is false for
        # everything. _blocks_from_articles checks the file on disk instead.
        if nzf := by_name.get(entry["name"]):
            if blocks := _blocks_from_articles(nzf, blocksize, entry["blocks"], entry["target"]):
                known[entry["name"]] = blocks
    return known


def _blocks_from_articles(nzf, blocksize: int, blockcount: int, target: str) -> Optional[list[bool]]:
    """Mark the blocks of one file that good articles fully cover."""
    try:
        filesize = os.path.getsize(target)
    except OSError:
        return None

    # crc32 is None when the decoded data did not match the yEnc trailer, so it is a
    # positive statement that the article is bad rather than merely unknown
    ranges = sorted(
        (article.data_begin, article.data_begin + article.data_size)
        for article in nzf.decodetable
        if article.crc32 is not None and article.on_disk and article.data_begin is not None and article.data_size
    )
    if not ranges:
        return None

    # Merge, so a block spanning several consecutive articles still counts as covered
    merged = [list(ranges[0])]
    for start, end in ranges[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    good = []
    index = 0
    for block in range(blockcount):
        start = block * blocksize
        # par2 pads the final block, so only the bytes the file actually has must be covered
        end = min(start + blocksize, filesize)
        if start >= filesize:
            good.append(False)
            continue
        while index < len(merged) and merged[index][1] <= start:
            index += 1
        good.append(index < len(merged) and merged[index][0] <= start and merged[index][1] >= end)

    return good


def parfile_paths(nzo: NzbObject) -> list[str]:
    """Every par2 file for this job currently on disk.

    Deliberately taken from the download directory rather than nzo.extrapars. A par2
    file is dropped from extrapars the moment it finishes downloading - handle_par2()
    calls remove_extrapar() - which is precisely when we want to feed it to the
    repairer, so extrapars would come up empty exactly when it matters.

    Files belonging to another set in the same directory are harmless: par2 locks onto
    a set id during load() and gates every packet on it, so foreign packets are ignored.
    """
    return [path for path in globber_full(nzo.download_path) if get_ext(path) == ".par2"]


def joinable_matches(session: RepairSession, joinables: list[str]) -> list[str]:
    """Joinables par2 took data from, so par_cleanup can remove them.

    Driven by file_done_callback rather than the source-file list: when par2 rebuilds a
    file out of .001/.002 parts, those parts are extra files it read blocks from, never
    source files it matched by name, so they do not appear in repairer.files at all.
    """
    if not joinables:
        return []

    by_name = {os.path.basename(path): path for path in joinables}
    used = []
    for filename in session.blocks_from:
        if path := by_name.get(os.path.basename(filename)):
            if path not in used:
                used.append(path)
    return used
