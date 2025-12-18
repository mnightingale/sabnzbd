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
import sys
import threading
import time
from dataclasses import dataclass
from threading import Thread
import ctypes
from typing import Optional
import rarfile
from concurrent.futures import ThreadPoolExecutor

import sabnzbd
from sabnzbd.misc import get_all_passwords, match_str, SABRarFile, from_units, to_units, acquire_timeout
from sabnzbd.filesystem import (
    set_permissions,
    clip_path,
    has_win_device,
    diskspace,
    get_filename,
    has_unwanted_extension,
    get_basename,
    write_at_offset,
)
from sabnzbd.constants import (
    Status,
    GIGI,
    ARTICLE_CACHE_MIN,
    ASSEMBLER_WRITE_THRESHOLD,
    ASSEMBLER_IDLE_FILE_TIMEOUT,
    ASSEMBLER_MAX_OPEN_FILES,
)
import sabnzbd.cfg as cfg
from sabnzbd.nzb import NzbFile, NzbObject, Article
import sabnzbd.par2file as par2file
from sabnzbd.utils.sparse import sparse


@dataclass
class AssemblerTask:
    nzo: NzbObject = None
    nzf: Optional[NzbFile] = None
    file_done: bool = False
    force: bool = False


class Assembler(Thread):
    def __init__(self):
        super().__init__()
        self.shutdown: bool = False
        self.max_queue_size: int = cfg.assembler_max_queue_size()
        self.assembler_write_trigger: int = 1
        self.queue: queue.Queue[AssemblerTask] = queue.Queue()
        self._open_files: dict[NzbFile, tuple[int, float]] = dict()
        self.nzf_next_index: dict[NzbFile, int] = dict()
        self.queued_lock = threading.Lock()
        self.queued_nzf: set[NzbFile] = set()
        self.queued_nzf_forced: set[NzbFile] = set()
        self._queued_cv: threading.Condition = threading.Condition()

    def stop(self):
        self.shutdown = True
        with self._queued_cv:
            self._queued_cv.notify_all()

    def new_limit(self, limit: int):
        """Called when cache limit changes"""
        limit = max(int(from_units(ARTICLE_CACHE_MIN)), limit)
        # Set assembler_write_trigger to be the equivalent of ASSEMBLER_WRITE_THRESHOLD %
        # of the total cache, assuming an article size of 750 000 bytes
        self.assembler_write_trigger = int(limit * ASSEMBLER_WRITE_THRESHOLD / 100 / 750_000) + 1
        logging.debug("Assembler trigger = %s", to_units(self.assembler_write_trigger))

    def queue_level(self) -> float:
        return self.queue.qsize() / self.max_queue_size

    def discard(self, nzo: NzbObject, timeout: float = 2.0) -> None:
        # Wait until NzbFiles leave the queue
        deadline = time.time() + timeout
        while True:
            with self.queued_lock:
                if not any(nzf in self.queued_nzf for nzf in nzo.files):
                    break
                if time.time() >= deadline:
                    logging.debug(
                        "Timeout waiting for NzbFile(s) of job %s",
                        nzo.final_name,
                    )
                    break
                time.sleep(0.01)
        for nzf in nzo.files:
            self.nzf_next_index.pop(nzf, None)
            with acquire_timeout(nzf.file_lock, 2.0) as acquired:
                if not acquired:
                    continue
                if fd_entry := self._open_files.pop(nzf, None):
                    fd, _ = fd_entry
                    try:
                        os.close(fd)
                    except Exception:
                        logging.debug("Error closing fd for discarded file %s", nzf.filepath)

    def process(
        self,
        task: AssemblerTask,
        article: Optional[Article] = None,
        articles_left: Optional[int] = None,
    ) -> None:
        """Notify the assembler that is can proceed with the given nzf"""
        nzf = task.nzf
        file_done = task.file_done
        force = task.force

        if nzf is None:
            # post-proc
            self.queue.put(task)
        else:
            # Ensure NzbFile is queued
            direct_write = bool(sabnzbd.cfg.direct_write.get())
            if (
                file_done
                or (
                    not direct_write
                    and nzf not in self.queued_nzf
                    and (
                        (article.lowest_partnum and nzf.filename_checked and not nzf.import_finished)
                        or (articles_left and (articles_left % self.assembler_write_trigger) == 0)
                    )
                )
                or (direct_write and force and nzf not in self.queued_nzf_forced)
            ):
                with self.queued_lock:
                    if force:
                        self.queued_nzf_forced.add(nzf)
                    self.queued_nzf.add(nzf)
                    self.queue.put(task)
                    with self._queued_cv:
                        self._queued_cv.notify()

    def run(self):
        while not self.shutdown:
            # Flush idle files first
            self._flush_idle_files()

            # Wait for new items or idle file timeout
            with self._queued_cv:
                self._queued_cv.wait(timeout=ASSEMBLER_IDLE_FILE_TIMEOUT)

            if self.shutdown:
                break

            while True:
                try:
                    task = self.queue.get_nowait()
                    self.assemble(task)
                    self.queue.task_done()
                except queue.Empty:
                    break
                except Exception:
                    logging.error("Fatal error in assembler loop", exc_info=True)
                    self.shutdown = True
                    break
                finally:
                    task = None

        # Close open files
        for nzf, (fd, _) in list(self._open_files.items()):
            with acquire_timeout(nzf.file_lock, 1.0) as acquired:
                if not acquired:
                    continue
                try:
                    os.close(fd)
                except Exception:
                    logging.debug("Error closing file %s during shutdown", nzf.filepath)
        self._open_files.clear()

    def assemble(self, task: AssemblerTask) -> None:
        nzo = task.nzo
        nzf = task.nzf
        file_done = task.file_done
        force = task.force

        # If nzf is None => NZB-level (post-processing) event
        if nzf is None:
            sabnzbd.NzbQueue.remove(nzo.nzo_id, cleanup=False)
            sabnzbd.PostProcessor.process(nzo)
            return

        # If file done, check diskspace
        if file_done and not sabnzbd.Downloader.paused:
            self.diskspace_check(nzo, nzf)

        try:
            # Prepare filepath
            if not (filepath := nzf.prepare_filepath()):
                # could not prepare path (e.g. job removed). Skip.
                return

            logging.debug("Decoding part of %s", filepath)
            self.assemble_nzf(nzo, nzf, file_done, force)

            # Continue after partly written data
            if not file_done:
                return

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
        finally:
            # Always remove from queued set after processing
            # If there are still pending articles, they'll re-queue when the gap is filled
            with self.queued_lock:
                self.queued_nzf.discard(nzf)
                if force:
                    self.queued_nzf_forced.discard(nzf)

    @staticmethod
    def __write_at_offset(fd: int, nzf: NzbFile, article: Article, data: bytes):
        mv = memoryview(data)
        written = 0
        while written < len(data):
            if sys.platform == "linux" or sys.platform == "darwin":
                written += write_at_offset(fd, mv[written:], article.data_begin + written)
            else:
                # Fallback to os.lseek + os.write
                with nzf.file_lock:
                    written += write_at_offset(fd, mv[written:], article.data_begin + written)
        nzf.update_crc32(article.crc32, len(data))
        article.on_disk = True

    def assemble_nzf(self, nzo: NzbObject, nzf: NzbFile, file_done: bool, force: bool) -> None:
        status_deleted = Status.DELETED
        load_article = sabnzbd.ArticleCache.load_article
        downloader = sabnzbd.Downloader
        direct_write = sabnzbd.cfg.direct_write.get() and nzf.type == "yenc"
        decodetable = nzf.decodetable

        fd = self.get_fd(nzf, direct_write)
        empty = direct_write and os.fstat(fd).st_size == 0
        skipped: bool = False

        # Resume assembly from where we got to previously
        with ThreadPoolExecutor(max_workers=cfg.io_threads.get() if direct_write else 1) as pool:
            for idx in range(self.nzf_next_index.get(nzf, 0), len(decodetable)):
                article = decodetable[idx]

                if nzo.status is status_deleted:
                    break

                # When forced stop once reached an untried article unless paused
                if force and not article.tries and not downloader.paused:
                    break

                if article.on_disk:
                    if not skipped:
                        self.nzf_next_index[nzf] = idx + 1
                    continue

                if empty and direct_write and article.file_size:
                    with nzf.file_lock:
                        if os.fstat(fd).st_size == 0:
                            try:
                                sparse(fd, article.file_size)
                            except OSError:
                                logging.debug("Sparse call failed for %s size %d", nzf.filename, article.file_size)
                                direct_write = False
                    empty = False

                # stop if next piece not yet decoded
                if not article.decoded:
                    # If the article was not decoded but the file
                    # is done, it is just a missing piece, so keep writing
                    if file_done:
                        self.nzf_next_index[nzf] = idx + 1
                        continue
                    # We reach an article that was not decoded
                    if force:
                        skipped = True
                        continue
                    break

                # load and write article
                data = load_article(article)
                if not data:
                    # no data present yet; don't remove pending, break unless finalizing
                    if file_done:
                        self.nzf_next_index[nzf] = idx + 1
                        continue
                    if force:
                        skipped = True
                        continue
                    break

                if direct_write:
                    pool.submit(Assembler.__write_at_offset, fd, nzf, article, data)
                else:
                    mv = memoryview(data)
                    written = 0
                    while written < len(data):
                        written += os.write(fd, mv[written:])
                    nzf.update_crc32(article.crc32, len(data))
                    article.on_disk = True

                if not skipped:
                    self.nzf_next_index[nzf] = idx + 1

        if file_done:
            # Close file descriptor
            with acquire_timeout(nzf.file_lock, 1.0) as acquired:
                if acquired:
                    fd, _ = self._open_files.pop(nzf, (None, None))
                    if fd is not None:
                        try:
                            os.close(fd)
                        except Exception:
                            logging.debug("Error closing fd for %s during finalization", nzf.filepath)
            self.nzf_next_index.pop(nzf, None)
            set_permissions(nzf.filepath)
            nzf.assembled = True

    def assemble_article(self, article: Article, data: bytes) -> bool:
        """Write a single article to disk"""
        nzf = article.nzf
        update_crc32 = nzf.update_crc32
        direct_write = sabnzbd.cfg.direct_write.get() and nzf.type == "yenc"

        if not direct_write:
            return False

        with nzf.file_lock:
            fd = self.get_fd(nzf, True)
            empty = os.fstat(fd).st_size == 0
            if empty and article.file_size:
                try:
                    sparse(fd, article.file_size)
                except OSError:
                    logging.debug("Sparse call failed for %s size %d", nzf.filename, article.file_size)
                    return False
            Assembler.__write_at_offset(fd, nzf, article, data)

        return True

    def get_fd(self, nzf: NzbFile, direct_write: bool) -> int:
        """Return an open fd for filepath, reusing if present; update timestamp."""
        with nzf.file_lock:
            entry = self._open_files.get(nzf)
            now = time.time()

            if entry is not None:
                fd, _ = entry
                self._open_files[nzf] = (fd, now)
                return fd

            # Not open, enforce max_open_files by closing oldest
            if len(self._open_files) >= ASSEMBLER_MAX_OPEN_FILES:
                self._close_oldest_open_file()

            # Open file descriptor and record timestamp
            if direct_write:
                flags = os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0)
            else:
                flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0)
            fd = os.open(nzf.filepath, flags, 0o644)
            self._open_files[nzf] = (fd, time.time())
            return fd

    def _close_oldest_open_file(self) -> None:
        """Close the oldest (least-recently-used) open file to keep fd count below limit."""
        if not self._open_files:
            return
        # find path with smallest timestamp
        oldest = min(self._open_files.items(), key=lambda kv: kv[1][1])[0]
        fd, _ = self._open_files.pop(oldest, (None, None))

        if fd is not None:
            with acquire_timeout(oldest.file_lock, 1.0) as acquired:
                if not acquired:
                    return
                try:
                    os.close(fd)
                except Exception:
                    logging.debug("Error closing LRU file %s", oldest.filepath)

    def _flush_idle_files(self) -> None:
        """
        Close open files that have been idle longer than idle_timeout.
        Should not be called while an assembly is in progress, it could close an active file.
        """
        now: float = time.time()
        to_close: list[NzbFile] = []

        for nzf, (fd, ts) in self._open_files.items():
            if sabnzbd.Downloader.paused or now - ts > ASSEMBLER_IDLE_FILE_TIMEOUT:
                to_close.append(nzf)

        for nzf in to_close:
            with acquire_timeout(nzf.file_lock, 1.0) as acquired:
                if not acquired:
                    continue
                fd, _ = self._open_files.pop(nzf, (None, None))
                if fd is not None:
                    try:
                        os.close(fd)
                    except Exception:
                        logging.debug("Error closing idle file %s", nzf.filepath, exc_info=True)

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
