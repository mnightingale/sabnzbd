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
sabnzbd.assembler - threaded assembly of files
"""

import errno
import os
import queue
import logging
import re
import threading
from threading import Thread
import ctypes
from dataclasses import dataclass
from typing import Optional, NamedTuple
import rarfile
import time

import sabctools
import sabnzbd
from sabnzbd.misc import get_all_passwords, match_str, SABRarFile, to_units
from sabnzbd.filesystem import (
    set_permissions,
    clip_path,
    has_win_device,
    diskspace,
    get_filename,
    has_unwanted_extension,
    get_basename,
)
from sabnzbd.constants import (
    Status,
    GIGI,
    SOFT_ASSEMBLER_QUEUE_LIMIT,
    ASSEMBLER_DELAY_FACTOR_DIRECT_WRITE,
    ARTICLE_CACHE_NON_CONTIGUOUS_FLUSH_PERCENTAGE,
    ASSEMBLER_WRITE_INTERVAL,
    ASSEMBLER_TRIGGER_PERCENTAGE,
    ASSEMBLER_VECTOR_CHUNK_SIZE,
)
import sabnzbd.cfg as cfg
from sabnzbd.nzb import NzbFile, NzbObject, Article
import sabnzbd.par2file as par2file
from sabnzbd.postproc import get_complete_directory


class AssemblerTask(NamedTuple):
    nzo: Optional[NzbObject] = None
    nzf: Optional[NzbFile] = None
    file_done: bool = False
    allow_non_contiguous: bool = False
    direct_write: bool = False


@dataclass(slots=True, eq=False)
class NzfWriteState:
    """Write state for a single NzbFile that has a task queued or in flight.

    Presence in Assembler.write_states is the claim itself: exactly one task exists per
    NzbFile at any time. Requests arriving while that task runs set a pending flag instead
    of enqueuing a second task, and are re-queued once it completes.

    Only requests that the running task cannot satisfy are recorded. An ordinary write is not
    one of them: assemble() walks to the end of the decodetable, so it already picks up
    articles that arrive while it runs, and queueing a second task for them chains small
    writes back to back instead of letting a batch accumulate.
    """

    pending_non_contiguous: bool = False
    pending_file_done: bool = False

    def mark_pending(self, file_done: bool, allow_non_contiguous: bool) -> None:
        if file_done:
            self.pending_file_done = True
        elif allow_non_contiguous:
            self.pending_non_contiguous = True

    def take_pending(self) -> Optional[tuple[bool, bool]]:
        """Claim the highest-priority pending request, as (file_done, allow_non_contiguous).

        file_done writes everything a normal pass would and finalizes, so it goes first.
        Returns None when nothing is pending.
        """
        if self.pending_file_done:
            self.pending_file_done = False
            return True, False
        if self.pending_non_contiguous:
            self.pending_non_contiguous = False
            return False, True
        return None


# A contiguous run of articles is contiguous on disk, so it can be written with one syscall
# instead of one per article. Not available on Windows, where WriteFileGather requires
# page-aligned single-page buffers that decoded articles cannot satisfy.
VECTORED_WRITE = hasattr(os, "writev")

# pwritev is positional; writev is not and needs the descriptor's file position.
# hasattr() reflects how CPython was built, which on macOS can differ from the OS it runs on:
# release builds target 10.15 but pwritev only arrived in 11.0. Demote permanently if the
# call turns out to be unavailable, rather than trusting the build-time answer.
_use_pwritev: bool = hasattr(os, "pwritev")

IOV_CHUNK_SIZE = ASSEMBLER_VECTOR_CHUNK_SIZE
if VECTORED_WRITE and "SC_IOV_MAX" in os.sysconf_names:
    # AIX and OpenBSD report lower values than Linux; exceeding IOV_MAX fails the call
    # outright rather than short-writing
    if (_iov_max := os.sysconf("SC_IOV_MAX")) > 0:
        IOV_CHUNK_SIZE = min(IOV_CHUNK_SIZE, _iov_max)


def advance_buffers(buffers: list, consumed: int) -> list:
    """Drop the buffers a short write fully consumed and slice the one it stopped inside"""
    for index, buffer in enumerate(buffers):
        if consumed < len(buffer):
            if consumed:
                return [memoryview(buffer)[consumed:], *buffers[index + 1 :]]
            return buffers[index:]
        consumed -= len(buffer)
    return []


def write_vector(fd: int, nzf: NzbFile, buffers: list, offset: int) -> int:
    """Write buffers back-to-back starting at offset, resuming on short writes"""
    global _use_pwritev

    written = 0
    while buffers:
        if _use_pwritev:
            try:
                chunk = os.pwritev(fd, buffers, offset)
            except (AttributeError, NotImplementedError, OSError) as err:
                # Anything other than "no such syscall" is a real error, most importantly ENOSPC
                if isinstance(err, OSError) and err.errno != errno.ENOSYS:
                    raise
                logging.info("os.pwritev is not available on this system, falling back to os.writev")
                _use_pwritev = False
                continue
        else:
            # Must lock since writev uses the file position, so the seek cannot be separated from it
            with nzf.file_lock:
                os.lseek(fd, offset, os.SEEK_SET)
                chunk = os.writev(fd, buffers)
        if not chunk:
            raise OSError(errno.EIO, "Vectored write made no progress", nzf.filepath)
        written += chunk
        offset += chunk
        buffers = advance_buffers(buffers, chunk)
    return written


class Assembler(Thread):
    def __init__(self):
        super().__init__()
        self.max_queue_size: int = cfg.assembler_max_queue_size()
        self.direct_write: bool = cfg.direct_write()
        self.cache_limit: int = 0
        # Total bytes required per file to trigger the assembler
        self.assembler_trigger: int = 0
        self.delay_trigger: int = 1
        self.queue: queue.Queue[AssemblerTask] = queue.Queue()
        self.queued_lock = threading.Lock()
        self.write_states: dict[str, NzfWriteState] = {}
        self.queued_next_time: dict[str, float] = {}
        self.ready_bytes_lock = threading.Lock()
        self.ready_bytes: dict[str, int] = {}

    def stop(self):
        self.queue.put(AssemblerTask())

    def new_limit(self, limit: int):
        """Called when cache limit changes"""
        self.cache_limit = limit
        self.assembler_trigger = max(1, int(self.cache_limit * ASSEMBLER_TRIGGER_PERCENTAGE))
        self.change_direct_write(cfg.direct_write())
        logging.debug(
            "Assembler trigger=%s, delay=%s",
            to_units(self.assembler_trigger),
            to_units(self.delay_trigger),
        )

    def change_direct_write(self, direct_write: bool) -> None:
        self.direct_write = direct_write
        self.calculate_delay_trigger()

    def calculate_delay_trigger(self):
        """Point at which downloader should start being delayed, recalculated when cache limit or direct write changes"""
        self.delay_trigger = int(
            max(
                (
                    750_000 * self.max_queue_size * ASSEMBLER_DELAY_FACTOR_DIRECT_WRITE
                    if self.direct_write
                    else 750_000 * self.max_queue_size
                ),
                (
                    self.cache_limit * ARTICLE_CACHE_NON_CONTIGUOUS_FLUSH_PERCENTAGE
                    if self.direct_write
                    else min(self.assembler_trigger * self.max_queue_size, int(self.cache_limit * 0.5))
                ),
            )
        )

    def is_busy(self) -> bool:
        """Returns True if the assembler thread has at least one NzbFile it is assembling"""
        return bool(self.write_states)

    def total_ready_bytes(self) -> int:
        with self.ready_bytes_lock:
            return sum(self.ready_bytes.values())

    def update_ready_bytes(self, nzf: NzbFile, delta: int) -> int:
        with self.ready_bytes_lock:
            cur = self.ready_bytes.get(nzf.nzf_id, 0) + delta
            if cur <= 0:
                self.ready_bytes.pop(nzf.nzf_id, None)
            else:
                self.ready_bytes[nzf.nzf_id] = cur
            return cur

    def clear_ready_bytes(self, *nzfs: NzbFile) -> None:
        with self.ready_bytes_lock:
            for nzf in nzfs:
                self.ready_bytes.pop(nzf.nzf_id, None)
                self.queued_next_time.pop(nzf.nzf_id, None)
        # Drop any write claim so a job that is deleted or finished mid-write cannot leave
        # a state behind that blocks the file being queued again if it is retried
        with self.queued_lock:
            for nzf in nzfs:
                self.write_states.pop(nzf.nzf_id, None)

    def process(
        self,
        nzo: NzbObject = None,
        nzf: Optional[NzbFile] = None,
        file_done: bool = False,
        allow_non_contiguous: bool = False,
        article: Optional[Article] = None,
    ) -> None:
        if nzf is None:
            # post-proc
            self.queue.put(AssemblerTask(nzo))
            return

        # Track bytes pending being written for this nzf
        if self.should_track_ready_bytes(article, allow_non_contiguous):
            ready_bytes = self.update_ready_bytes(nzf, article.decoded_size)
        else:
            ready_bytes = 0

        article_has_first_part = bool(article and article.lowest_partnum)
        if article_has_first_part:
            self.queued_next_time[nzf.nzf_id] = time.monotonic() + ASSEMBLER_WRITE_INTERVAL

        # Is the article the file needs next available, so a contiguous write can be made?
        next_ready = bool(
            (next_article := nzf.assembler_next_article)
            and (next_article.decoded or next_article.on_disk or next_article.failed)
        )

        if not self.should_queue_nzf(
            nzf,
            article_has_first_part=article_has_first_part,
            filename_checked=nzf.filename_checked,
            import_finished=nzf.import_finished,
            file_done=file_done,
            allow_non_contiguous=allow_non_contiguous,
            ready_bytes=ready_bytes,
            next_ready=next_ready,
        ):
            return

        with self.queued_lock:
            if (state := self.write_states.get(nzf.nzf_id)) is not None:
                # A task for this file is already queued or running. Record what arrived and let
                # the worker re-queue on completion, so only one task per file is ever in flight.
                state.mark_pending(file_done, allow_non_contiguous)
                return
            self.write_states[nzf.nzf_id] = NzfWriteState()
            self.queued_next_time[nzf.nzf_id] = time.monotonic() + ASSEMBLER_WRITE_INTERVAL
        self.queue.put(self.build_task(nzo, nzf, file_done, allow_non_contiguous))

    def build_task(self, nzo: NzbObject, nzf: NzbFile, file_done: bool, allow_non_contiguous: bool) -> AssemblerTask:
        can_direct_write = self.direct_write and nzf.type == "yenc"
        return AssemblerTask(nzo, nzf, file_done, allow_non_contiguous, can_direct_write)

    def finish_write(self, nzo: NzbObject, nzf: NzbFile, file_done: bool) -> None:
        """Release the write claim on nzf, re-queueing a single task if more work arrived while it ran"""
        with self.queued_lock:
            state = self.write_states.pop(nzf.nzf_id, None)
            if state is None or file_done:
                # file_done is the final pass, so anything recorded during it is redundant
                return
            if (next_request := state.take_pending()) is None:
                return
            self.write_states[nzf.nzf_id] = state
            self.queued_next_time[nzf.nzf_id] = time.monotonic() + ASSEMBLER_WRITE_INTERVAL
        self.queue.put(self.build_task(nzo, nzf, *next_request))

    def should_queue_nzf(
        self,
        nzf: NzbFile,
        *,
        article_has_first_part: bool,
        filename_checked: bool,
        import_finished: bool,
        file_done: bool,
        allow_non_contiguous: bool,
        ready_bytes: int,
        next_ready: bool,
    ) -> bool:
        # Always queue if done
        if file_done:
            return True
        # A task for this file is already queued or running. An ordinary write does not need a
        # second one: assemble() walks to the end of the decodetable, so it picks up whatever
        # arrives while it runs. Queueing anyway makes each write carry only what landed during
        # the previous one, which collapses into a chain of small writes at high download rates.
        if state := self.write_states.get(nzf.nzf_id):
            if not allow_non_contiguous or state.pending_non_contiguous:
                return False
        # Always write
        if article_has_first_part and filename_checked and not import_finished:
            return True
        # Trigger every 5 seconds if next article is decoded or on_disk
        if next_ready and time.monotonic() > self.queued_next_time.get(nzf.nzf_id, 0):
            return True
        # Append
        if not self.direct_write or nzf.type != "yenc":
            return (
                next_ready
                and ready_bytes >= self.assembler_trigger
                and nzf.has_contiguous_ready_bytes(self.assembler_trigger)
            )
        # Direct Write
        if allow_non_contiguous:
            return True
        # Direct Write ready bytes trigger if next is also ready
        if next_ready and ready_bytes >= self.assembler_trigger:
            return True
        return False

    @staticmethod
    def should_track_ready_bytes(article: Optional[Article], allow_non_contiguous: bool) -> bool:
        """"""
        return article and not allow_non_contiguous and article.decoded_size

    def delay(self) -> float:
        """Calculate how long if at all the downloader thread should sleep to allow the assembler to catch up"""
        ready_total = self.total_ready_bytes()
        # Below trigger: no delay possible
        if ready_total <= self.delay_trigger:
            return 0
        pressure = (ready_total - self.delay_trigger) / max(1.0, self.cache_limit - self.delay_trigger)
        if pressure <= SOFT_ASSEMBLER_QUEUE_LIMIT:
            return 0
        # 50-100%: 0-0.25 seconds, capped at 0.15
        sleep = min((pressure - SOFT_ASSEMBLER_QUEUE_LIMIT) / 2, 0.15)
        return max(0.001, sleep)

    def run(self):
        while 1:
            # Set NzbObject and NzbFile objects to None so references
            # from this thread do not keep the objects alive (see #1628)
            nzo = nzf = None
            nzo, nzf, file_done, allow_non_contiguous, direct_write = self.queue.get()
            if not nzo:
                logging.debug("Shutting down assembler")
                break

            if nzf:
                # Check if enough disk space is free after each file is done
                if file_done and not sabnzbd.Downloader.paused:
                    self.diskspace_check(nzo, nzf)

                try:
                    # Prepare filepath
                    if not (filepath := nzf.prepare_filepath()):
                        logging.debug("Prepare filepath failed for file %s in job %s", nzf.filename, nzo.final_name)
                        continue

                    try:
                        logging.debug("Decoding part of %s", filepath)
                        self.assemble(nzo, nzf, file_done, allow_non_contiguous, direct_write)
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
                        if file_done:
                            self.clear_ready_bytes(nzf)

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
                except Exception:
                    logging.error(T("Fatal error in Assembler"), exc_info=True)
                    break
                finally:
                    self.finish_write(nzo, nzf, file_done)
            else:
                sabnzbd.NzbQueue.remove(nzo.nzo_id, cleanup=False)
                sabnzbd.PostProcessor.process(nzo)
                self.clear_ready_bytes(*nzo.files)

    @staticmethod
    def diskspace_check(nzo: NzbObject, nzf: NzbFile):
        """Check diskspace requirements.
        If not enough space left, pause downloader and send email"""
        download_dir, complete_dir = diskspace(force=True, complete_dir=get_complete_directory(nzo)[0])
        full_dir: Optional[str] = None
        required_space = (cfg.download_free.get_float() + nzf.bytes) / GIGI
        if download_dir.free < required_space:
            full_dir = download_dir.path

        # Enough space in download_dir, check complete_dir
        if not full_dir:
            complete_free = cfg.complete_free.get_float()
            required_space = 0
            if cfg.direct_unpack():
                # We unpack while we download, so we should check every time
                # if the unpack maybe already filled up the drive
                required_space = complete_free / GIGI
            elif nzo.bytes_tried > (nzo.bytes - nzo.bytes_par2) * 0.90:
                # Since only at 100% unpack is started, continue
                # downloading until 95% complete before checking
                required_space = (complete_free + nzo.bytes) / GIGI

            if required_space and complete_dir.free < required_space:
                full_dir = complete_dir.path

        if full_dir:
            logging.warning(T("Too little diskspace forcing PAUSE"))
            # Pause downloader, but don't save, since the disk is almost full!
            sabnzbd.Downloader.pause()
            if cfg.fulldisk_autoresume():
                sabnzbd.Scheduler.plan_diskspace_resume(full_dir, required_space)
            sabnzbd.notifier.send_notification("SABnzbd", T("Too little diskspace forcing PAUSE"), "disk_full")
            sabnzbd.emailer.diskfull_mail()

    @staticmethod
    def assemble(nzo: NzbObject, nzf: NzbFile, file_done: bool, allow_non_contiguous: bool, direct_write: bool) -> None:
        """Assemble a NZF from its table of articles
        1) Partial write: write what we have
        2) Nothing written before: write all
        """
        load_article = sabnzbd.ArticleCache.load_article
        downloader = sabnzbd.Downloader
        decodetable = nzf.decodetable

        fd: Optional[int] = None
        skipped: bool = False  # have any articles been skipped
        offset: int = 0  # sequential offset for append writes

        # Articles waiting to be written as one vectored call, and the file offset they start at
        run: list[tuple[int, Article, bytearray]] = []
        run_offset: int = 0
        run_end: int = 0

        def flush_run():
            nonlocal run, run_end
            if run:
                Assembler.write_run(fd, nzf, run, run_offset)
                run = []
                run_end = 0

        try:
            # Resume assembly from where we got to previously
            for idx in range(nzf.assembler_next_index, len(decodetable)):
                article = decodetable[idx]

                # Break if deleted during writing
                if nzo.status is Status.DELETED:
                    break

                # allow_non_contiguous is when the cache forces the assembler to write all articles, even if it leaves gaps.
                # In most cases we can stop at the first article that has not been tried, because they are requested in order.
                # However, if we are paused then always consider the whole decodetable to ensure everything possible is written.
                if allow_non_contiguous and not article.tries and not downloader.paused:
                    break

                # Skip already written articles
                if article.on_disk or article.failed:
                    # The pending run holds lower indexes, so it has to commit before
                    # assembler_next_index can be advanced past this one
                    flush_run()
                    if fd is not None and article.decoded_size is not None:
                        # Move the file descriptor forward past this article
                        offset += article.decoded_size
                    if not skipped:
                        with nzf.lock:
                            if nzf.assembler_next_index == idx:
                                nzf.assembler_next_index = idx + 1
                    continue

                # stop if next piece not yet decoded
                if not article.decoded:
                    # If the article was not decoded but the file
                    # is done, it is just a missing piece, so keep writing
                    if file_done:
                        continue
                    # We reach an article that was not decoded
                    if allow_non_contiguous:
                        skipped = True
                        continue
                    break

                # Could be empty in case nzo was deleted or a previous write attempt failed and the data was removed
                # from the cache but could not be written to disk.
                data = load_article(article)
                if not data:
                    logging.info("No data found when trying to write %s", article)
                    continue

                # If required open the file
                if fd is None:
                    fd, offset, direct_write = Assembler.open(
                        nzf, direct_write and article.can_direct_write, article.file_size
                    )
                    if not direct_write and allow_non_contiguous:
                        # Can only be allow_non_contiguous if we wanted direct_write, file_done will always be queued separately
                        break

                if direct_write and article.can_direct_write:
                    position = article.data_begin
                else:
                    if direct_write and skipped and not file_done:
                        # If we have already skipped an article then need to abort, unless this is the final assemble
                        break
                    position = offset

                # Only articles landing exactly where the pending run ends can join it
                if run and (position != run_end or len(run) >= IOV_CHUNK_SIZE):
                    flush_run()
                if not run:
                    run_offset = position
                    run_end = position
                run.append((idx, article, data))
                run_end += len(data)
                offset += len(data)

            # Reached by break as well as by exhausting the decodetable, so a run pending at any
            # stop point still gets written. Deliberately not in the finally: if a write raised,
            # retrying it here would mark articles on_disk that never made it
            flush_run()
        finally:
            if fd is not None:
                os.close(fd)

            # Final steps
            if file_done:
                nzf.assembled = True

    @staticmethod
    def assemble_article(article: Article, data: bytearray) -> bool:
        """Write a single article to disk"""
        if not article.can_direct_write:
            return False
        nzf = article.nzf
        with nzf.file_lock:
            fd, _, direct_write = Assembler.open(nzf, True, article.file_size)
            try:
                if not direct_write:
                    cfg.direct_write.set(False)
                    return False
                Assembler.write(fd, None, nzf, article, data)
            except OSError:
                # nzo has probably been deleted or not enough disk space, ArticleCache tries the fallback and handles it
                return False
            finally:
                os.close(fd)
        return True

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

    @staticmethod
    def write_run(fd: int, nzf: NzbFile, run: list[tuple[int, Article, bytearray]], offset: int) -> None:
        """Write a run of articles that are contiguous on disk, starting at offset.

        A run of two or more is issued as a single vectored write, which releases the GIL once
        instead of once per article and lets the bookkeeping be done under one lock acquisition.
        """
        if len(run) < 2 or not VECTORED_WRITE:
            for nzf_index, article, data in run:
                offset += Assembler.write(fd, nzf_index, nzf, article, data, offset)
            return

        write_vector(fd, nzf, [data for _, _, data in run], offset)

        written = 0
        for _, article, data in run:
            article.on_disk = True
            written += len(data)
        sabnzbd.Assembler.update_ready_bytes(nzf, -written)

        with nzf.lock:
            # Advance past every article of the run that keeps the file sequential from the start,
            # stopping at the first index that is not the one still awaited
            for nzf_index, _, _ in run:
                if nzf.assembler_next_index != nzf_index:
                    break
                nzf.assembler_next_index = nzf_index + 1

    @staticmethod
    def write(
        fd: int, nzf_index: Optional[int], nzf: NzbFile, article: Article, data: bytearray, offset: Optional[int] = None
    ) -> int:
        """Write data at position in a file"""
        pos = article.data_begin if offset is None else offset
        written = Assembler._write(fd, nzf, data, pos)
        # In raw/non-buffered mode os.write may not write everything requested:
        # https://docs.python.org/3/library/io.html?highlight=write#io.RawIOBase.write
        if written < len(data) and (mv := memoryview(data)):
            while written < len(data):
                written += Assembler._write(fd, nzf, mv[written:], pos + written)

        article.on_disk = True
        sabnzbd.Assembler.update_ready_bytes(nzf, -len(data))
        with nzf.lock:
            # assembler_next_index is the lowest index that has not yet been written sequentially from the start of the file.
            # If this was the next required index to remain sequential, it can be incremented which allows the assembler to
            # resume without rechecking articles that are already known to be on disk.
            # If nzf_index is None, determine it now.
            if nzf_index is None:
                idx = nzf.assembler_next_index
                if idx < len(nzf.decodetable) and article == nzf.decodetable[idx]:
                    nzf_index = idx
            if nzf_index is not None and nzf.assembler_next_index == nzf_index:
                nzf.assembler_next_index += 1
        return written

    @staticmethod
    def _write(fd: int, nzf: NzbFile, data: bytearray | memoryview, offset: int) -> int:
        if sabnzbd.WINDOWS:
            # pwrite is not implemented on Windows so fallback to os.lseek and os.write
            # Must lock since it is possible to write from multiple threads (assembler + downloader)
            with nzf.file_lock:
                os.lseek(fd, offset, os.SEEK_SET)
                return os.write(fd, data)
        else:
            return os.pwrite(fd, data, offset)

    @staticmethod
    def open(nzf: NzbFile, direct_write: bool, file_size: int) -> tuple[int, int, bool]:
        """Open file for nzf

         Use direct_write if requested, with a fallback to setting the current file position for append mode
        :returns (file_descriptor, current_offset, can_direct_write)
        """
        with nzf.file_lock:
            fd = os.open(nzf.filepath, os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o666)
            offset = nzf.contiguous_offset()
            os.lseek(fd, offset, os.SEEK_SET)
            if direct_write:
                if not file_size:
                    direct_write = False
                if os.fstat(fd).st_size == 0:
                    set_permissions(nzf.filepath)
                    try:
                        sabctools.sparse(fd, file_size)
                    except OSError:
                        logging.debug("Sparse call failed for %s", nzf.filepath)
                        cfg.direct_write.set(False)
                        direct_write = False
            return fd, offset, direct_write


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
                                    password_hit = password
                                    break
                                except rarfile.RarWrongPassword:
                                    # This one really didn't work
                                    continue
                                except rarfile.RarCRCError as e:
                                    # CRC errors can be thrown for wrong password or
                                    # missing the next volume (with correct password)
                                    if match_str(str(e), ("cannot find volume", "unexpected end of archive")):
                                        # We assume this one worked!
                                        password_hit = password
                                        break
                                    # This one didn't work
                                    continue
                                except Exception as e:
                                    # Catch other suspicious errors
                                    if "wrong password" in str(e):
                                        # This one didn't work
                                        continue

                                    # All the other errors we skip, they might be fixable in post-proc.
                                    # For example starting from the wrong volume, or damaged files
                                    # This will cause the check to be performed again for the next rar, might
                                    # be disk-intensive! Could be removed later and just accept the password.
                                    logging.info('Could not try password "%s" on job "%s"', password, nzo.final_name)
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
                    # RARs using header encryption require the password to decrypt the file list
                    if nzo.correct_password and not zf.namelist():
                        try:
                            zf.setpassword(nzo.correct_password)
                        except Exception:
                            pass
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
