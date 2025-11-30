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
sabnzbd.articlecache - Article cache handling
"""

import logging
import threading
import struct
import time
from typing import Collection

import sabnzbd
from sabnzbd.assembler import AssemblerTask
from sabnzbd.decorators import synchronized
from sabnzbd.constants import GIGI, ANFO, ARTICLE_CACHE_MIN, ARTICLE_CACHE_FLUSH_PERCENTAGE
from sabnzbd.nzb import Article, NzbFile
from sabnzbd.misc import from_units, get_memory

# Operations on the article table are handled via try/except.
# The counters need to be made atomic to ensure consistency.
ARTICLE_COUNTER_LOCK = threading.RLock()

_SECONDS_BETWEEN_FLUSHES = 0.5


class ArticleCache(threading.Thread):
    def __init__(self):
        super().__init__()
        self.shutdown = False
        self.__cache_limit_org = 0
        self.__cache_limit = 0
        self.__cache_size = 0
        self.__article_table: dict[Article, bytes] = {}  # Dict of buffered articles
        self.__full_condition: threading.Condition = threading.Condition(ARTICLE_COUNTER_LOCK)
        self.__next_flush: float = 0
        self.__flush_requested: threading.Event = threading.Event()
        self.__flush_upper: int = 0
        self.__flush_lower: int = 0

        # On 32 bit we only allow the user to set 1GB
        # For 64 bit we allow up to 4GB, in case somebody wants that
        self.__cache_upper_limit = GIGI
        if sabnzbd.MACOS or sabnzbd.WINDOWS or (struct.calcsize("P") * 8) == 64:
            if (memory := get_memory()) > from_units("16G"):
                self.__cache_upper_limit = memory / 2
            else:
                self.__cache_upper_limit = 4 * GIGI

    def stop(self):
        self.shutdown = True
        with self.__full_condition:
            self.__full_condition.notify_all()

    def run(self):
        assembler = sabnzbd.Assembler.process

        while True:
            with self.__full_condition:
                self.__full_condition.wait_for(
                    lambda: self.shutdown
                    or self.__flush_requested.is_set()
                    or (sabnzbd.cfg.direct_write.get() and self.__cache_size > self.__flush_upper)
                )
            if self.shutdown:
                break

            if self.__cache_size <= self.__flush_lower:
                self.__flush_requested.clear()

            # Flush direct to file
            if time.monotonic() > self.__next_flush:
                self.__next_flush = time.monotonic() + _SECONDS_BETWEEN_FLUSHES
                nzfs: set[NzbFile] = set()
                with ARTICLE_COUNTER_LOCK:
                    for article in self.__article_table.keys():
                        if article.nzf.type == "yenc":
                            nzfs.add(article.nzf)
                for nzf in nzfs:
                    logging.debug("Forcing write for %s", nzf.nzo.final_name)
                    assembler(AssemblerTask(nzf.nzo, nzf, force=True))
            else:
                time.sleep(0.05)

    def cache_info(self):
        return ANFO(len(self.__article_table), abs(self.__cache_size), self.__cache_limit)

    def new_limit(self, limit: int):
        """Called when cache limit changes"""
        self.__cache_limit_org = limit
        if limit < 0:
            self.__cache_limit = self.__cache_upper_limit
        else:
            self.__cache_limit = min(max(from_units(ARTICLE_CACHE_MIN), limit), self.__cache_upper_limit)
        self.__flush_upper = self.__cache_limit * ARTICLE_CACHE_FLUSH_PERCENTAGE
        self.__flush_lower = self.__cache_limit * 0.5

    @synchronized(ARTICLE_COUNTER_LOCK)
    def reserve_space(self, data_size: int) -> bool:
        """Reserve space in the cache"""
        if (usage := self.__cache_size + data_size) > self.__cache_limit:
            self.__flush_requested.set()
            with self.__full_condition:
                self.__full_condition.notify_all()
            return False

        self.__cache_size = usage
        with self.__full_condition:
            self.__full_condition.notify_all()
        return True

    @synchronized(ARTICLE_COUNTER_LOCK)
    def free_reserved_space(self, data_size: int):
        """Remove previously reserved space"""
        self.__cache_size -= data_size
        with self.__full_condition:
            self.__full_condition.notify_all()

    @property
    @synchronized(ARTICLE_COUNTER_LOCK)
    def percentage(self):
        return self.__cache_size / self.__cache_limit

    def space_left(self) -> bool:
        """Is there space left in the set limit?"""
        return self.__cache_size < self.__cache_limit

    def save_article(self, article: Article, data: bytes):
        """Save article in cache, either memory or disk"""
        nzo = article.nzf.nzo
        # Skip if already post-processing or fully finished
        if nzo.pp_or_finished:
            return

        # Register article for bookkeeping in case the job is deleted
        nzo.saved_articles.add(article)

        if article.lowest_partnum and not (article.nzf.import_finished or article.nzf.filename_checked):
            # Write the first-fetched articles to temporary file unless downloading
            # of the rest of the parts has started or filename is verified.
            # Otherwise the cache could overflow.
            self.__flush_article_to_disk(article, data)
            return

        if self.__cache_limit:
            # Check if we exceed the limit
            data_size = len(data)
            if self.reserve_space(data_size):
                # Add new article to the cache
                self.__article_table[article] = data
            else:
                # Save to disk
                with self.__full_condition:
                    self.__flush_requested.set()
                    self.__full_condition.notify_all()
                self.__flush_article_to_disk(article, data)
        else:
            # No data saved in memory, direct to disk
            self.__flush_article_to_disk(article, data)

    def load_article(self, article: Article):
        """Load the data of the article"""
        data = None
        nzo = article.nzf.nzo

        if article in self.__article_table:
            try:
                data = self.__article_table.pop(article)
                self.free_reserved_space(len(data))
            except KeyError:
                # Could fail due the article already being deleted by purge_articles, for example
                # when post-processing deletes the job while delayed articles still come in
                logging.debug("Failed to load %s from cache, probably already deleted", article)
                return data
        elif article.art_id:
            data = sabnzbd.filesystem.load_data(
                article.art_id, nzo.admin_path, remove=True, do_pickle=False, silent=True
            )
        nzo.saved_articles.discard(article)
        return data

    def flush_articles(self):
        logging.debug("Saving %s cached articles to disk", len(self.__article_table))
        self.__cache_size = 0
        while self.__article_table:
            try:
                article, data = self.__article_table.popitem()
                self.__flush_article_to_disk(article, data)
            except KeyError:
                # Could fail if already deleted by purge_articles or load_data
                logging.debug("Failed to flush item from cache, probably already deleted or written to disk")

    def purge_articles(self, articles: Collection[Article]):
        """Remove all saved articles, from memory and disk"""
        logging.debug("Purging %s articles from the cache/disk", len(articles))
        for article in articles:
            if article in self.__article_table:
                try:
                    data = self.__article_table.pop(article)
                    self.free_reserved_space(len(data))
                except KeyError:
                    # Could fail if already deleted by flush_articles or load_data
                    logging.debug("Failed to flush %s from cache, probably already deleted or written to disk", article)
            elif article.art_id:
                sabnzbd.filesystem.remove_data(article.art_id, article.nzf.nzo.admin_path)

    def __flush_article_to_disk(self, article: Article, data):
        # Save data, but don't complain when destination folder is missing
        # because this flush may come after completion of the NZO.
        if self.__flush_requested.is_set():
            with self.__full_condition:
                self.__full_condition.wait_for(
                    lambda: self.shutdown or self.__cache_size < self.__flush_lower, timeout=2.0
                )

        if sabnzbd.cfg.direct_write.get() and article.nzf.type == "yenc" and article.nzf.prepare_filepath():
            if sabnzbd.Assembler.assemble_article(article, data):
                return

        # Fallback to disk cache
        sabnzbd.filesystem.save_data(
            data, article.get_art_id(), article.nzf.nzo.admin_path, do_pickle=False, silent=True
        )
