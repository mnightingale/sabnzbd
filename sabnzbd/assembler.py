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
sabnzbd.assembler - threaded assembly of files
"""

import os
import queue
import logging
import re
import threading
import time
import weakref
from threading import Thread
import ctypes
from typing import Optional
import rarfile

import sabnzbd
from sabnzbd.misc import get_all_passwords, match_str, SABRarFile
from sabnzbd.filesystem import (
    set_permissions,
    clip_path,
    has_win_device,
    diskspace,
    get_filename,
    has_unwanted_extension,
    get_basename,
)
from sabnzbd.constants import Status, GIGI, SOFT_ASSEMBLER_QUEUE_LIMIT
import sabnzbd.cfg as cfg
from sabnzbd.nzbstuff import NzbObject, NzbFile
import sabnzbd.par2file as par2file


class Assembler(Thread):
    def __init__(self, idle_file_timeout: float = 5.0, queue_timeout: float = 1.0, max_open_files: int = 256):
        super().__init__()
        self.shutdown = False
        self.max_queue_size: int = cfg.assembler_max_queue_size()
        self.queue: queue.Queue[tuple[Optional[NzbObject], Optional[NzbFile], Optional[bool]]] = queue.Queue(
            maxsize=self.max_queue_size
        )
        self.open_files: dict[str, tuple[int, float]] = dict()
        self.idle_file_timeout: float = idle_file_timeout
        self.queue_timeout: float = queue_timeout
        self.max_open_files: int = max_open_files
        self.nzf_next_index: weakref.WeakKeyDictionary[NzbFile, int] = weakref.WeakKeyDictionary()
        # track which nzf objects are currently enqueued to avoid duplicate queue items
        self._queued_nzf = weakref.WeakSet()
        self._queued_lock = threading.Lock()
        self._queue_cv = threading.Condition()

    def stop(self):
        self.shutdown = True
        with self._queue_cv:
            self._queue_cv.notify_all()

    def flush(self):
        """Allow another thread to notify the assembler to close all files"""
        with self._queue_cv:
            self._queue_cv.notify_all()

    def process(self, nzo: NzbObject, nzf: Optional[NzbFile] = None, file_done: Optional[bool] = None):
        if (assembler_level := self.queue_level()) > SOFT_ASSEMBLER_QUEUE_LIMIT:
            time.sleep(min((assembler_level - SOFT_ASSEMBLER_QUEUE_LIMIT) / 4, 0.15))
            sabnzbd.BPSMeter.delayed_assembler += 1
            logged_counter = 0

            while not self.shutdown and self.queue_level() >= 0.75:
                # Only log/update once every second, to not waste any CPU-cycles
                if not logged_counter % 10:
                    # Make sure the BPS-meter is updated
                    sabnzbd.BPSMeter.update()

                    # Update who is delaying us
                    logging.debug(
                        "Delayed - %d seconds - Assembler queue: %d",
                        logged_counter / 10,
                        self.queue.qsize(),
                    )

                # Wait and update the queue sizes
                time.sleep(0.1)
                logged_counter += 1

        queue_item_added = False
        if nzf is None:
            self.queue.put((nzo, nzf, file_done))
            queue_item_added = True
        else:
            with self._queued_lock:
                if nzf not in self._queued_nzf:
                    # mark queued and put a single notification item
                    self._queued_nzf.add(nzf)
                    self.queue.put((nzo, nzf, file_done))
                    queue_item_added = True
                elif file_done:
                    # Already queued but need file_done
                    self.queue.put((nzo, nzf, file_done))
                    queue_item_added = True

        # notify assembler that there is work to do
        if queue_item_added:
            with self._queue_cv:
                self._queue_cv.notify()

    def queue_level(self) -> float:
        return self.queue.qsize() / self.max_queue_size

    def run(self):
        while not self.shutdown:
            # Flush any idle files
            self._flush_idle_files()

            # Set NzbObject and NzbFile objects to None so references
            # from this thread do not keep the objects alive (see #1628)
            nzo = nzf = None

            # Wait for either new items or idle flush timeout
            with self._queue_cv:
                if self.queue.empty() and not self.shutdown:
                    # Wait until notified or until next idle flush
                    self._queue_cv.wait(timeout=self.idle_file_timeout)

            # Process queue items
            while True:
                try:
                    nzo, nzf, file_done = self.queue.get_nowait()
                except queue.Empty:
                    break

                if nzf:
                    with self._queued_lock:
                        self._queued_nzf.discard(nzf)

                if nzf is None:
                    sabnzbd.NzbQueue.remove(nzo.nzo_id, cleanup=False)
                    sabnzbd.PostProcessor.process(nzo)
                    continue

                # We've popped an NZF notification; remove from queued set so future events can enqueue again.
                with self._queued_lock:
                    try:
                        self._queued_nzf.remove(nzf)
                    except KeyError:
                        # might not be present (weakset)
                        pass

                # Check if enough disk space is free after each file is done
                if file_done and not sabnzbd.Downloader.paused:
                    self.diskspace_check(nzo, nzf)

                # Prepare filepath
                filepath = nzf.prepare_filepath()
                if not filepath:
                    continue

                try:
                    logging.debug("Decoding part of %s", filepath)
                    self.assemble(nzo, nzf, file_done)

                    # Continue after partly written data
                    if not file_done:
                        continue

                    # Clean-up admin data
                    logging.info("Decoding finished %s", filepath)
                    nzf.remove_admin()

                    # Do rar-related processing
                    if rarfile.is_rarfile(filepath):
                        # Check for encrypted files, unwanted extensions and add to direct unpack
                        self.check_encrypted_and_unwanted(nzo, nzf)
                        nzo.add_to_direct_unpacker(nzf)

                    elif par2file.is_par2_file(filepath):
                        # Parse par2 files, cloaked or not
                        nzo.handle_par2(nzf, filepath)

                except IOError as err:
                    # If job was deleted/finished or in active post-processing, ignore error
                    if not nzo.pp_or_finished:
                        # 28 == disk full => pause downloader
                        if err.errno == 28:
                            logging.error(T("Disk full! Forcing Pause"))
                        else:
                            logging.error(T("Disk error on creating file %s"), clip_path(filepath))
                        # Log traceback
                        if sabnzbd.WINDOWS:
                            logging.info(
                                "Winerror: %s - %s",
                                err.winerror,
                                hex(ctypes.windll.ntdll.RtlGetLastNtStatus() + 2**32),
                            )
                        logging.info("Traceback: ", exc_info=True)
                        # Pause without saving
                        sabnzbd.Downloader.pause()
                    else:
                        logging.debug("Ignoring error %s for %s, already finished or in post-proc", err, filepath)
                except Exception:
                    logging.error(T("Fatal error in Assembler"), exc_info=True)
                    self.stop()
                    break

        logging.debug("Shutting down assembler")

        # Close open files on shutdown
        for path, (fd, _) in list(self.open_files.items()):
            try:
                os.close(fd)
            except Exception:
                logging.debug("Error closing file %s during shutdown", path)
        self.open_files.clear()
        logging.debug("All open files closed, assembler shutdown complete")

    def _open_fd_for_path(self, filepath: str) -> int:
        """Open file descriptor for append (O_APPEND) and record timestamp."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
        # ensure mode respects umask; 0o644 is reasonable default
        fd = os.open(filepath, flags, 0o644)
        self.open_files[filepath] = (fd, time.time())
        return fd

    def _get_fd(self, filepath: str) -> int:
        now = time.time()
        # Reuse FD if exists
        if entry := self.open_files.get(filepath):
            fd, _ = entry
            self.open_files[filepath] = (fd, now)
            return fd

        # Not open enforce max_open_files by closing oldest
        if len(self.open_files) >= self.max_open_files:
            self._close_oldest_open_file()

        return self._open_fd_for_path(filepath)

    def _close_oldest_open_file(self) -> None:
        """Close the oldest (least-recently-used) open file to keep fd count below limit."""
        if not self.open_files:
            return
        # find path with smallest timestamp
        oldest_path = min(self.open_files.items(), key=lambda kv: kv[1][1])[0]
        fd, _ = self.open_files.pop(oldest_path, (None, None))
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                logging.debug("Error closing LRU file %s", oldest_path)

    def _flush_idle_files(self) -> None:
        """Close open files that have been idle longer than idle_timeout."""
        now = time.time()
        to_close = [
            path
            for path, (fd, ts) in self.open_files.items()
            if sabnzbd.Downloader.paused or now - ts > self.idle_file_timeout
        ]
        for path in to_close:
            logging.info("Closing file %s", path)
            try:
                fd, _ = self.open_files.pop(path)
                os.close(fd)
            except KeyError:
                pass
            except Exception:
                logging.debug("Error closing idle file %s", path)

    @staticmethod
    def diskspace_check(nzo: NzbObject, nzf: NzbFile):
        """Check diskspace requirements.
        If not enough space left, pause downloader and send email"""
        freespace = diskspace(force=True)
        full_dir = None
        required_space = (cfg.download_free.get_float() + nzf.bytes) / GIGI
        if freespace["download_dir"][1] < required_space:
            full_dir = "download_dir"

        # Enough space in download_dir, check complete_dir
        complete_free = cfg.complete_free.get_float()
        if complete_free > 0 and not full_dir:
            required_space = 0
            if cfg.direct_unpack():
                # We unpack while we download, so we should check every time
                # if the unpack maybe already filled up the drive
                required_space = complete_free / GIGI
            elif nzo.bytes_tried > (nzo.bytes - nzo.bytes_par2) * 0.95:
                # Since only at 100% unpack is started, continue
                # downloading until 95% complete before checking
                required_space = (complete_free + nzo.bytes) / GIGI

            if required_space and freespace["complete_dir"][1] < required_space:
                full_dir = "complete_dir"

        if full_dir:
            logging.warning(T("Too little diskspace forcing PAUSE"))
            # Pause downloader, but don't save, since the disk is almost full!
            sabnzbd.Downloader.pause()
            if cfg.fulldisk_autoresume():
                sabnzbd.Scheduler.plan_diskspace_resume(full_dir, required_space)
            sabnzbd.notifier.send_notification("SABnzbd", T("Too little diskspace forcing PAUSE"), "disk_full")
            sabnzbd.emailer.diskfull_mail()

    def assemble(self, nzo: NzbObject, nzf: NzbFile, file_done: bool):
        """Assemble a NZF from its table of articles
        1) Partial write: write what we have
        2) Nothing written before: write all
        """

        status_deleted = Status.DELETED
        load_article = sabnzbd.ArticleCache.load_article
        update_crc32 = nzf.update_crc32
        nzf_next_index = self.nzf_next_index
        decodetable = nzf.decodetable
        open_files = self.open_files

        # starting index for this NZF
        next_idx = nzf_next_index.get(nzf, 0)
        total = len(decodetable)
        if next_idx >= total and not file_done:
            # nothing to do
            return

        filepath = nzf.filepath
        # ensure path exists and open FD (this updates last-used timestamp)
        fd = self._get_fd(filepath)

        for idx in range(next_idx, total):
            article = decodetable[idx]

            # Break if deleted during writing
            if nzo.status is status_deleted:
                break

            # Skip already written articles
            if article.on_disk:
                nzf_next_index[nzf] = idx + 1
                continue

            # Write all decoded articles
            if not article.decoded:
                # If the article was not decoded but the file
                # is done, it is just a missing piece, so keep writing
                if file_done:
                    nzf_next_index[nzf] = idx + 1
                    continue
                else:
                    # We reach an article that was not decoded
                    break

            # Could be empty in case nzo was deleted
            data = load_article(article)
            if not data:
                logging.info("No data found when trying to write %s", article)
                nzf_next_index[nzf] = idx + 1
                continue

            # write via os.write using a memoryview to avoid needless copies
            mv = memoryview(data)
            try:
                while mv:
                    written = os.write(fd, mv)
                    mv = mv[written:]
            finally:
                mv.release()
            update_crc32(article.crc32, len(data))
            article.on_disk = True

            # advance next index after successful write
            nzf_next_index[nzf] = idx + 1

            # Remove references
            mv = None
            data = None

            # Update last-used timestamp for the file
            open_files[filepath] = (fd, time.time())

        # Final steps
        if file_done:
            # close and cleanup
            fd_entry = open_files.pop(filepath, None)
            if fd_entry:
                try:
                    os.close(fd)
                except Exception:
                    logging.exception("Error closing fd for %s during finalization", filepath)
            # remove per-NZF state
            nzf_next_index.pop(nzf, None)
            set_permissions(nzf.filepath)
            nzf.assembled = True

    @staticmethod
    def check_encrypted_and_unwanted(nzo: NzbObject, nzf: NzbFile):
        """Encryption and unwanted extension detection"""
        rar_encrypted, unwanted_file = check_encrypted_and_unwanted_files(nzo, nzf.filepath)
        if rar_encrypted:
            if cfg.pause_on_pwrar() == 1:
                logging.warning(
                    T('Paused job "%s" because of encrypted RAR file (if supplied, all passwords were tried)'),
                    nzo.final_name,
                )
                nzo.pause()
            else:
                logging.warning(
                    T('Aborted job "%s" because of encrypted RAR file (if supplied, all passwords were tried)'),
                    nzo.final_name,
                )
                nzo.fail_msg = T("Aborted, encryption detected")
                sabnzbd.NzbQueue.end_job(nzo)

        if unwanted_file:
            # Don't repeat the warning after a user override of an unwanted extension pause
            if nzo.unwanted_ext == 0:
                logging.warning(
                    T('In "%s" unwanted extension in RAR file. Unwanted file is %s '),
                    nzf.nzo.final_name,
                    unwanted_file,
                )
            logging.debug(T("Unwanted extension is in rar file %s"), nzf.filename)
            if cfg.action_on_unwanted_extensions() == 1 and nzo.unwanted_ext == 0:
                logging.debug("Unwanted extension ... pausing")
                nzo.unwanted_ext = 1
                nzo.pause()
            if cfg.action_on_unwanted_extensions() == 2:
                logging.debug("Unwanted extension ... aborting")
                nzo.fail_msg = T("Aborted, unwanted extension detected")
                sabnzbd.NzbQueue.end_job(nzo)


RE_SUBS = re.compile(r"\W+sub|subs|subpack|subtitle|subtitles(?![a-z])", re.I)
SAFE_EXTS = (".mkv", ".mp4", ".avi", ".wmv", ".mpg", ".webm")


def is_cloaked(nzo: NzbObject, path: str, names: list[str]) -> bool:
    """Return True if this is likely to be a cloaked encrypted post"""
    fname = get_basename(get_filename(path.lower()))
    for name in names:
        name = get_filename(name.lower())
        name, ext = os.path.splitext(name)
        if (
            ext == ".rar"
            and fname.startswith(name)
            and (len(fname) - len(name)) < 8
            and len(names) < 3
            and not RE_SUBS.search(fname)
        ):
            # Only warn once
            if nzo.encrypted == 0:
                logging.warning(
                    T('Job "%s" is probably encrypted due to RAR with same name inside this RAR'), nzo.final_name
                )
                nzo.encrypted = 1
            return True
        elif "password" in name and ext not in SAFE_EXTS:
            # Only warn once
            if nzo.encrypted == 0:
                logging.warning(T('Job "%s" is probably encrypted: "password" in filename "%s"'), nzo.final_name, name)
                nzo.encrypted = 1
            return True
    return False


def check_encrypted_and_unwanted_files(nzo: NzbObject, filepath: str) -> tuple[bool, Optional[str]]:
    """Combines check for unwanted and encrypted files to save on CPU and IO"""
    encrypted = False
    unwanted = None

    if (cfg.unwanted_extensions() and cfg.action_on_unwanted_extensions()) or (
        nzo.encrypted == 0 and cfg.pause_on_pwrar()
    ):
        # These checks should not break the assembler
        try:
            # Rarfile freezes on Windows special names, so don't try those!
            if sabnzbd.WINDOWS and has_win_device(filepath):
                return encrypted, unwanted

            # Is it even a rarfile?
            if rarfile.is_rarfile(filepath):
                # Open the rar
                zf = SABRarFile(filepath, part_only=True)

                # Check for encryption
                if (
                    nzo.encrypted == 0
                    and cfg.pause_on_pwrar()
                    and (zf.needs_password() or is_cloaked(nzo, filepath, zf.namelist()))
                ):
                    # Load all passwords
                    passwords = get_all_passwords(nzo)

                    # Cloaked job?
                    if is_cloaked(nzo, filepath, zf.namelist()):
                        encrypted = True
                    elif not passwords:
                        # Only error when no password was set
                        nzo.encrypted = 1
                        encrypted = True
                    else:
                        # Lets test if any of the password work
                        password_hit = False

                        for password in passwords:
                            if password:
                                logging.info('Trying password "%s" on job "%s"', password, nzo.final_name)
                                try:
                                    zf.setpassword(password)
                                    zf.trigger_parse()
                                    password_hit = password
                                    break
                                except rarfile.RarWrongPassword:
                                    # This one really didn't work
                                    pass
                                except rarfile.RarCRCError as e:
                                    # CRC errors can be thrown for wrong password or
                                    # missing the next volume (with correct password)
                                    if match_str(str(e), ("cannot find volume", "unexpected end of archive")):
                                        # We assume this one worked!
                                        password_hit = password
                                        break
                                    # This one didn't work
                                    pass
                                except Exception:
                                    # All the other errors we skip, they might be fixable in post-proc.
                                    # For example starting from the wrong volume, or damaged files
                                    # This will cause the check to be performed again for the next rar, might
                                    # be disk-intensive! Could be removed later and just accept the password.
                                    return encrypted, unwanted

                        # Did any work?
                        if password_hit:
                            # Record the successful password
                            nzo.correct_password = password_hit
                            # Don't check other files
                            logging.info('Password "%s" matches for job "%s"', password_hit, nzo.final_name)
                            nzo.encrypted = -1
                            encrypted = False
                        else:
                            # Encrypted and none of them worked
                            nzo.encrypted = 1
                            encrypted = True

                # Check for unwanted extensions
                if cfg.unwanted_extensions() and cfg.action_on_unwanted_extensions():
                    for somefile in zf.namelist():
                        logging.debug("File contains: %s", somefile)
                        if has_unwanted_extension(somefile):
                            logging.debug("Unwanted file %s", somefile)
                            unwanted = somefile
                zf.close()
                del zf
        except rarfile.Error as e:
            logging.info("Error during inspection of RAR-file %s: %s", filepath, e)

    return encrypted, unwanted
