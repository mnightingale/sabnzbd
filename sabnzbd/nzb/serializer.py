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
sabnzbd.nzb.serializer - Convert the NzbObject graph to and from plain data

msgpack is a tree format, with no memo, no cycles and no shared identity, and the job graph has all
three. The fields holding object references are converted by hand and the graph is re-linked on load;
every other field comes from the Saver tuples, so adding a plain attribute stays a one-line change.
"""

import datetime
import threading
from typing import Any, Optional

from sabnzbd.constants import NZO_SCHEMA_VERSION
from sabnzbd.nzb.article import Article, ArticleSaver
from sabnzbd.nzb.file import NzbFile, NzbFileSaver
from sabnzbd.nzb.object import NzbObject, NzbObjectSaver
from sabnzbd.par2file import FilePar2Info

# Hold object references or a type msgpack cannot carry, so they are converted by hand
NZO_STRUCTURAL = frozenset(
    {
        "files",
        "files_table",
        "finished_files",
        "extrapars",
        "first_articles",
        "saved_articles",
        "par2packs",
        "avg_date",
    }
)
NZF_STRUCTURAL = frozenset({"nzo", "articles", "decodetable", "date"})

# The try-list leads the article record, so a new ArticleSaver field stays an append
ARTICLE_FIELDS = tuple(field for field in ArticleSaver if field != "nzf")
PAR2_FIELDS = ("filename", "hash16k", "filesize", "filehash", "has_duplicate")

EPOCH = datetime.datetime(1970, 1, 1)


def encode_date(value: Optional[datetime.datetime]) -> Optional[int]:
    """Whole seconds from the epoch, so the value does not move with the timezone"""
    if value is None:
        return None
    return int((value - EPOCH).total_seconds())


def decode_date(value: Optional[int]) -> Optional[datetime.datetime]:
    if value is None:
        return None
    return EPOCH + datetime.timedelta(seconds=value)


def encode_article(article: Article) -> list:
    record = [sorted(server.id for server in article.try_list)]
    record.extend(getattr(article, field) for field in ARTICLE_FIELDS)
    return record


def decode_article(record: list, nzf: NzbFile) -> Article:
    article = Article.__new__(Article)
    for field, value in zip(ARTICLE_FIELDS, record[1:]):
        setattr(article, field, value)
    # A field this version does not write yet reads as None
    for field in ARTICLE_FIELDS[len(record) - 1 :]:
        setattr(article, field, None)
    article.nzf = nzf
    article.lock = nzf.lock
    article.fetcher = None
    article.fetcher_priority = 0
    article.tries = 0
    article.restore_try_list(record[0])
    return article


def encode_nzf(nzf: NzbFile, article_positions: dict[int, list]) -> dict:
    record = {field: getattr(nzf, field) for field in NzbFileSaver if field not in NZF_STRUCTURAL}
    record["date"] = encode_date(nzf.date)
    record["try_list"] = sorted(server.id for server in nzf.try_list)
    record["decodetable"] = [encode_article(article) for article in nzf.decodetable]

    positions = {id(article): index for index, article in enumerate(nzf.decodetable)}
    # Only the outstanding articles, the rest are recovered from the decodetable
    record["articles"] = [positions[id(article)] for article in nzf.articles if id(article) in positions]
    for article_id, index in positions.items():
        article_positions[article_id] = [nzf.nzf_id, index]
    return record


def decode_nzf(record: dict, nzo: NzbObject) -> NzbFile:
    nzf = NzbFile.__new__(NzbFile)
    for field in NzbFileSaver:
        if field not in NZF_STRUCTURAL:
            setattr(nzf, field, record.get(field))
    nzf.nzo = nzo
    nzf.date = decode_date(record.get("date"))
    nzf.lock = threading.RLock()
    nzf.file_lock = threading.RLock()
    nzf.assembler_next_index = 0
    nzf.writer = None
    nzf.restore_try_list(record.get("try_list") or [])

    nzf.decodetable = [decode_article(article, nzf) for article in record.get("decodetable") or []]
    nzf.articles = {}
    for index in record.get("articles") or []:
        if index < len(nzf.decodetable):
            article = nzf.decodetable[index]
            nzf.articles[article] = article
    return nzf


def resolve_article(nzo: NzbObject, reference: list) -> Optional[Article]:
    """Turn a [nzf_id, index] reference back into the article the file already holds"""
    nzf = nzo.files_table.get(reference[0])
    if nzf and reference[1] < len(nzf.decodetable):
        return nzf.decodetable[reference[1]]
    return None


def encode_nzo(nzo: NzbObject) -> dict[str, Any]:
    """Convert a job to plain data, dropping the back-references that make it a graph"""
    article_positions: dict[int, list] = {}
    document = {
        "v": NZO_SCHEMA_VERSION,
        "nzo": {field: getattr(nzo, field) for field in NzbObjectSaver if field not in NZO_STRUCTURAL},
        "avg_date": encode_date(nzo.avg_date),
        "try_list": sorted(server.id for server in nzo.try_list),
        "files": [encode_nzf(nzf, article_positions) for nzf in nzo.files],
        "finished_files": [encode_nzf(nzf, article_positions) for nzf in nzo.finished_files],
        "extrapars": {setname: [nzf.nzf_id for nzf in nzfs] for setname, nzfs in (nzo.extrapars or {}).items()},
        "par2packs": {
            setname: {name: [getattr(info, field) for field in PAR2_FIELDS] for name, info in pack.items()}
            for setname, pack in (nzo.par2packs or {}).items()
        },
    }
    document["first_articles"] = [
        article_positions[id(article)] for article in nzo.first_articles if id(article) in article_positions
    ]
    # Sorted because it comes from a set, so two saves of the same job produce the same document
    document["saved_articles"] = sorted(
        article_positions[id(article)] for article in nzo.saved_articles if id(article) in article_positions
    )
    return document


def decode_nzo(document: dict[str, Any]) -> NzbObject:
    """Rebuild a job from plain data, re-linking the graph as it goes"""
    nzo = NzbObject.__new__(NzbObject)
    scalars = document.get("nzo") or {}
    for field in NzbObjectSaver:
        if field not in NZO_STRUCTURAL:
            setattr(nzo, field, scalars.get(field))
    nzo.lock = threading.RLock()
    nzo.avg_date = decode_date(document.get("avg_date")) or EPOCH
    nzo.restore_try_list(document.get("try_list") or [])

    nzo.files = [decode_nzf(record, nzo) for record in document.get("files") or []]
    nzo.finished_files = [decode_nzf(record, nzo) for record in document.get("finished_files") or []]
    nzo.files_table = {nzf.nzf_id: nzf for nzf in nzo.files + nzo.finished_files}

    nzo.extrapars = {
        setname: [nzo.files_table[nzf_id] for nzf_id in nzf_ids if nzf_id in nzo.files_table]
        for setname, nzf_ids in (document.get("extrapars") or {}).items()
    }
    nzo.par2packs = {
        setname: {name: FilePar2Info(*fields[: len(PAR2_FIELDS)]) for name, fields in pack.items()}
        for setname, pack in (document.get("par2packs") or {}).items()
    }
    nzo.first_articles = [
        article
        for article in (resolve_article(nzo, reference) for reference in document.get("first_articles") or [])
        if article
    ]
    nzo.saved_articles = {
        article
        for article in (resolve_article(nzo, reference) for reference in document.get("saved_articles") or [])
        if article
    }

    nzo.finalize_restored_job()
    return nzo
