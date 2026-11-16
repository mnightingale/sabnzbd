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
sabnzbd.directunpacker
"""

import os
import re
import time
import threading
import logging
from typing import Iterator, Optional

import rars

import sabnzbd
import sabnzbd.cfg as cfg
from sabnzbd.misc import int_conv, format_time_string
from sabnzbd.filesystem import remove_all, remove_file, get_basename, get_filename
from sabnzbd.nzb import NzbFile, NzbObject
from sabnzbd.decorators import synchronized
from sabnzbd.newsunpack import add_time_left
from sabnzbd.postproc import prepare_extraction_path
from sabnzbd.utils.diskspeed import diskspeedmeasure

# Need a lock to make sure start and stop is handled correctly
# Otherwise we could stop while the thread was still starting
START_STOP_LOCK = threading.RLock()

ACTIVE_UNPACKERS = []

RAR_NR = re.compile(r"(.*?)(\.part(\d*).rar|\.r(\d*))$", re.IGNORECASE)


class DirectUnpackAborted(Exception):
    pass


class DirectUnpacker(threading.Thread):
    def __init__(self, nzo: NzbObject):
        super().__init__()

        self.nzo: NzbObject = nzo
        self.active_instance: Optional[rars.RarFile] = None
        self.cancellation: Optional[rars.CancellationToken] = None
        self.extracting = threading.Event()
        self.killed: bool = False
        self.next_file_lock = threading.Condition(threading.RLock())

        self.unpack_dir_info = None
        self.rarfile_nzf: Optional[NzbFile] = None
        self.cur_setname: Optional[str] = None
        self.cur_volume: int = 0
        self.total_volumes: dict[str, int] = {}
        self.unpack_time: float = 0.0
        self.start_time: float = 0.0
        self.volumes: list[str] = []

        self.success_sets: dict[str, tuple[list[str], list[str]]] = {}
        self.next_sets: list[NzbFile] = []

        nzo.direct_unpacker = self

    def stop(self):
        pass

    def save(self):
        pass

    def reset_active(self):
        self.active_instance = None
        self.cancellation = None
        self.cur_setname = None
        self.cur_volume = 0
        self.rarfile_nzf = None
        self.volumes = []

    def check_requirements(self):
        if (
            not cfg.enable_unrar()
            or not cfg.direct_unpack()
            or self.killed
            or self.nzo.first_articles
            or not self.nzo.unpack
            or self.nzo.bad_articles
        ):
            return False
        return True

    def set_volumes_for_nzo(self):
        """Loop over all files to detect the names"""
        logging.debug("Parsing setname and volume information for %s" % self.nzo.final_name)
        none_counter = 0
        found_counter = 0
        for nzf in self.nzo.files + self.nzo.finished_files:
            nzf.setname, nzf.vol = analyze_rar_filename(nzf.filename)
            # We matched?
            if nzf.setname:
                found_counter += 1
                if nzf.setname not in self.total_volumes:
                    self.total_volumes[nzf.setname] = 0
                self.total_volumes[nzf.setname] = max(self.total_volumes[nzf.setname], nzf.vol)
            else:
                none_counter += 1

        # Too much not found? Obfuscated, ignore results
        if none_counter > found_counter:
            self.total_volumes = {}

    @synchronized(START_STOP_LOCK)
    def add(self, nzf: NzbFile):
        """Add jobs and start instance of DirectUnpack"""
        if not cfg.direct_unpack_tested():
            test_disk_performance()

        # Stop if something is wrong or we shouldn't start yet
        if not self.check_requirements():
            return

        # Is this the first set?
        if not self.cur_setname:
            self.set_volumes_for_nzo()
            self.cur_setname = nzf.setname

        # Analyze updated filenames
        nzf.setname, nzf.vol = analyze_rar_filename(nzf.filename)

        # Are we doing this set?
        if self.cur_setname and self.cur_setname == nzf.setname:
            logging.debug("DirectUnpack queued %s for %s", nzf.filename, self.cur_setname)
            # Is this the first one of the first set?
            if not self.is_alive() and not self.killed and self.have_next_volume():
                # Too many runners already?
                if len(ACTIVE_UNPACKERS) >= cfg.direct_unpack_threads():
                    logging.info("Too many DirectUnpackers currently to start %s", self.cur_setname)
                    return
                ACTIVE_UNPACKERS.append(self)
                self.start()
        elif not any(test_nzf.setname == nzf.setname for test_nzf in self.next_sets):
            # Need to store this for the future, only once per set!
            self.next_sets.append(nzf)

        # Wake up the thread to see if this is good to go
        with self.next_file_lock:
            self.next_file_lock.notify()

    def run(self):
        while not self.killed and self.unpack_set():
            with self.next_file_lock:
                logging.debug("Direct Unpack for %s waiting for more sets", self.nzo.final_name)
                self.next_file_lock.wait_for(lambda: self.nzo.removed_from_queue or self.next_sets or self.killed)

            logging.debug(
                "Direct Unpack for %s continuing: killed=%s, next_sets=%s",
                self.nzo.final_name,
                self.killed,
                self.next_sets,
            )
            if self.killed or not self.next_sets:
                break

            nzf = self.next_sets.pop(0)
            self.reset_active()
            self.cur_setname = nzf.setname
            # Wait for the 1st volume to appear
            self.wait_for_next_volume()

        with START_STOP_LOCK:
            # Set the thread to killed so it never gets restarted by accident
            self.killed = True
            self.reset_active()
            if self in ACTIVE_UNPACKERS:
                ACTIVE_UNPACKERS.remove(self)
            logging.debug("Closing DirectUnpack for %s", self.nzo.final_name)

    def unpack_set(self) -> bool:
        """Extract the current set, pulling each volume in as it is assembled"""
        with START_STOP_LOCK:
            if self.killed:
                return False
            if not self.unpack_dir_info:
                try:
                    self.unpack_dir_info = prepare_extraction_path(self.nzo)
                except Exception:
                    self.abort()
                    return False
            self.rarfile_nzf = self.have_next_volume()
            if not self.rarfile_nzf:
                return False
            extraction_path, _, _, one_folder, _ = self.unpack_dir_info
            first_volume = os.path.join(self.nzo.download_path, self.rarfile_nzf.filename)
            self.volumes = [first_volume]
            self.cur_volume = 1
            cancellation = rars.CancellationToken()
            self.cancellation = cancellation
            self.extracting.set()

        password = self.nzo.correct_password or self.nzo.password or None
        setname = self.cur_setname
        logging.info("DirectUnpacked volume %s for %s", self.cur_volume, setname)
        self.start_time = time.time()
        try:
            with rars.RarFile(first_volume, password=password, cancellation=cancellation) as rarfile:
                self.active_instance = rarfile
                written = rarfile.extractall(
                    extraction_path,
                    password=password,
                    overwrite=True,
                    cancellation=cancellation,
                    volumes=self.next_volumes(),
                    restore_times=not cfg.ignore_unrar_dates(),
                    in_place=True,
                    flatten=bool(one_folder or cfg.flat_unpack()),
                )
        except Exception as error:
            self.unpack_time += time.time() - self.start_time
            self.extracting.clear()
            if not self.killed:
                logging.info("Error in DirectUnpack of %s: %r", setname, error)
                self.abort()
            return False
        self.extracting.clear()
        self.unpack_time += time.time() - self.start_time
        written = [os.fspath(path) for path in written]

        # Take note of the correct password
        if self.nzo.password and not self.nzo.correct_password:
            self.nzo.correct_password = self.nzo.password

        self.success_sets[setname] = (self.volumes, written)
        logging.info("DirectUnpack completed for %s", setname)
        self.nzo.set_action_line(T("Direct Unpack"), T("Completed"))

        msg = T("Unpacked %s files/folders in %s") % (len(written), format_time_string(self.unpack_time))
        msg = "%s - %s" % (T("Direct Unpack"), msg)
        self.nzo.set_unpack_info("Unpack", msg, setname)
        return True

    def next_volumes(self) -> Iterator[str]:
        """The volumes after the first, each yielded once it is assembled, for rars to pull as it reaches them"""
        while True:
            # RAR 1.3 to 2.0 sets have no end block, so rars asks for one volume past the last
            if self.total_volumes.get(self.cur_setname, 0) == self.cur_volume:
                return
            self.unpack_time += time.time() - self.start_time
            self.nzo.set_action_line(T("Direct Unpack"), self.get_formatted_stats(include_time_left=True))
            self.wait_for_next_volume()
            self.start_time = time.time()
            if self.killed:
                raise DirectUnpackAborted
            if not (nzf := self.have_next_volume()):
                logging.info("DirectUnpack has no volume %s for %s", self.cur_volume + 1, self.cur_setname)
                return
            path = os.path.join(self.nzo.download_path, nzf.filename)
            self.volumes.append(path)
            self.cur_volume += 1
            logging.info("DirectUnpacked volume %s for %s", self.cur_volume, self.cur_setname)
            yield path

    def have_next_volume(self):
        """Check if next volume of set is available, start
        from the end of the list where latest completed files are
        Make sure that files are 100% written to disk by checking nzf.assembled
        and that they are still there, post-processing could have moved them away
        """
        for nzf_search in reversed(self.nzo.finished_files):
            if (
                nzf_search.setname == self.cur_setname
                and nzf_search.vol == (self.cur_volume + 1)
                and nzf_search.assembled
                and os.path.exists(os.path.join(self.nzo.download_path, nzf_search.filename))
            ):
                return nzf_search
        return False

    def wait_for_next_volume(self):
        """Wait for the correct volume to appear but stop if it was killed
        or the NZB is in post-processing and no new files will be downloaded.
        """
        with self.next_file_lock:
            self.next_file_lock.wait_for(lambda: self.have_next_volume() or self.killed or self.nzo.pp_active)

    @synchronized(START_STOP_LOCK)
    def abort(self):
        """Abort running extraction and delete generated files"""
        if not self.killed and self.cur_setname:
            logging.info("Aborting DirectUnpack for %s", self.cur_setname)
            self.killed = True

            rarfile_nzf = self.rarfile_nzf

            if self.cancellation:
                self.cancellation.cancel()

            # Wake up the thread
            with self.next_file_lock:
                self.next_file_lock.notify()

            # Let the extraction stop writing before its output is removed
            if threading.current_thread() is not self:
                deadline = time.time() + 5
                while self.extracting.is_set() and time.time() < deadline:
                    time.sleep(0.05)

            # No new sets
            self.next_sets = []
            self.success_sets = {}

            # Remove files
            if self.unpack_dir_info:
                extraction_path, _, _, one_folder, _ = self.unpack_dir_info
                # In case of flat-unpack we need to remove the files manually
                if one_folder:
                    try:
                        with rars.RarFile(os.path.join(self.nzo.download_path, rarfile_nzf.filename)) as rarfile:
                            for rm_file in rarfile.namelist():
                                remove_file(os.path.join(extraction_path, get_filename(rm_file)))
                    except Exception:
                        # The user will have to remove it themselves
                        logging.info(
                            "Failed to clean Direct Unpack after aborting %s", rarfile_nzf.filename, exc_info=True
                        )
                else:
                    # We can just remove the whole path
                    remove_all(extraction_path, recursive=True)
                # Remove dir-info
                self.unpack_dir_info = None

            # Reset settings
            self.reset_active()

    def get_formatted_stats(self, include_time_left: bool = False) -> str:
        """Get percentage or number of rar's done"""
        if self.cur_setname and self.cur_setname in self.total_volumes:
            # This won't work on obfuscated posts
            if self.total_volumes[self.cur_setname] >= self.cur_volume and self.cur_volume:
                formatted_stats = "%02d/%02d" % (self.cur_volume, self.total_volumes[self.cur_setname])
                if include_time_left:
                    formatted_stats += add_time_left(
                        (self.cur_volume / self.total_volumes[self.cur_setname]) * 100, time_used=self.unpack_time
                    )
                return formatted_stats
        return str(self.cur_volume)


def analyze_rar_filename(filename):
    """Extract volume number and setname from rar-filenames
    Both ".part01.rar" and ".r01"
    The filename can name a sub-directory of the job, the setname is always just the name so
    it matches what rar_unpack() derives from the path on disk with setname_from_path()
    """
    filename = get_filename(filename)
    if m := RAR_NR.search(filename):
        if m.group(4):
            # Special since starts with ".rar", ".r00"
            return m.group(1), int_conv(m.group(4)) + 2
        return m.group(1), int_conv(m.group(3))
    else:
        # Detect if first of "rxx" set
        if filename.endswith(".rar"):
            return get_basename(filename), 1
    return None, None


def abort_all():
    """Abort all running DirectUnpackers"""
    logging.info("Aborting all DirectUnpackers")
    for direct_unpacker in ACTIVE_UNPACKERS:
        direct_unpacker.abort()


def test_disk_performance():
    """Test the incomplete-dir performance and enable
    Direct Unpack if good enough (> 100MB/s)
    """
    if diskspeedmeasure(sabnzbd.cfg.download_dir.get_path()) > 100:
        cfg.direct_unpack.set(True)
        logging.warning(
            T("Direct Unpack was automatically enabled.")
            + " "
            + T(
                "Jobs will start unpacking during the downloading to reduce post-processing time. Only works for jobs that do not need repair."
            )
        )
    else:
        logging.info("Direct Unpack was not enabled, incomplete folder disk speed below 100MB/s")
    cfg.direct_unpack_tested.set(True)
    sabnzbd.config.save_config()
