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
sabnzbd.sessionstore - Async storage for web-UI login sessions
"""

import asyncio
import logging
import os
import sqlite3
import time
from typing import Any, Optional

import aiosqlite

import sabnzbd
import sabnzbd.cfg
from sabnzbd.constants import DB_SESSIONS_NAME, DB_SESSIONS_VERSION, MEBI
from sabnzbd.filesystem import remove_file

# Expired sessions are purged on first use and at most once per interval afterwards
PURGE_INTERVAL = 3600 * 24


class AsyncSessionStore:
    """Async store for web-UI login sessions, in its own database file
    (sessions.db), available as sabnzbd.session_store.

    Sessions deliberately live outside the history database:
     - This store is the only reader and writer of its file, so it needs no
       pooling or coordination with HistoryDBPool, and the auth path never
       contends with history writers or suffers from history corruption.
     - All queries run on aiosqlite's worker thread, so the event loop only
       ever awaits: per-request session checks cannot stall the loop the way
       a blocking sqlite call (or a pool-checkout wait) would.
     - The file is deliberately NOT in CONFIG_BACKUP_FILES: sessions are
       per-browser state that shouldn't move to a restored install, and a
       lost sessions database only means logging in again.

    The connection is opened lazily on the server's event loop and closed by
    the Starlette lifespan (see interface.create_app). All methods fail
    closed: on any database error the session is treated as absent and the
    error logged. A corrupt database file is discarded and recreated.
    """

    def __init__(self, db_path: Optional[str] = None):
        # Explicit path is for tests; normally resolved from admin_dir on first use
        self._db_path = db_path
        self._connection: Optional[aiosqlite.Connection] = None
        self._open_lock = asyncio.Lock()
        self._closed = False
        self._last_purge = 0.0

    @property
    def db_path(self) -> str:
        return self._db_path or os.path.join(sabnzbd.cfg.admin_dir.get_path(), DB_SESSIONS_NAME)

    async def _connect(self) -> Optional[aiosqlite.Connection]:
        """Return the open connection, opening and initializing it on first use.
        Returns None when the store has been closed (shutdown)."""
        if self._closed:
            return None
        if self._connection is not None:
            return self._connection

        async with self._open_lock:
            # Re-check: another coroutine may have opened it while we waited
            if self._closed or self._connection is not None:
                return self._connection

            # isolation_level=None: autocommit, matching the history database
            connection = await aiosqlite.connect(self.db_path, isolation_level=None)
            try:
                connection.row_factory = sqlite3.Row
                # Same journal settings as the history database; WAL also lets a
                # (hypothetical) second reader coexist with our writes
                await connection.execute("PRAGMA journal_mode=WAL;")
                await connection.execute("PRAGMA synchronous=NORMAL;")
                await connection.execute("PRAGMA busy_timeout=5000;")
                # Sessions are disposable, so a schema change resets them rather
                # than migrating: on any user_version mismatch (including a fresh
                # database, which reports 0) drop the old table and recreate it
                # below, then stamp the current generation.
                async with connection.execute("PRAGMA user_version") as cursor:
                    version_row = await cursor.fetchone()
                if not version_row or version_row[0] != DB_SESSIONS_VERSION:
                    await connection.execute("DROP TABLE IF EXISTS sessions")
                    await connection.execute("PRAGMA user_version = %d" % DB_SESSIONS_VERSION)
                await connection.execute("""CREATE TABLE IF NOT EXISTS sessions (
                        "token_hash" TEXT PRIMARY KEY,
                        "created" INTEGER NOT NULL,
                        "expires" INTEGER NOT NULL,
                        "cred_fingerprint" TEXT NOT NULL,
                        "last_ip" TEXT,
                        "user_agent" TEXT
                    )""")
                await connection.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires)")
            except Exception:
                await connection.close()
                raise
            self._connection = connection
        return self._connection

    async def _maybe_purge(self, connection: aiosqlite.Connection):
        """Opportunistically delete expired sessions, throttled to once per PURGE_INTERVAL.
        _last_purge starts at 0, so the first call after startup always purges."""
        now = time.time()
        if now - self._last_purge >= PURGE_INTERVAL:
            self._last_purge = now
            await connection.execute("DELETE FROM sessions WHERE expires < ?", (int(now),))

    async def _handle_error(self, error: BaseException):
        """Log a failed operation. Corruption-class errors discard the database
        file: sessions are low-value, a fresh start just means logging in again."""
        logging.info("Sessions database error: %s", error, exc_info=True)
        if isinstance(error, sqlite3.DatabaseError) and not isinstance(
            error, (sqlite3.OperationalError, sqlite3.IntegrityError, sqlite3.ProgrammingError)
        ):
            logging.warning("Damaged sessions database, creating empty replacement")
            connection, self._connection = self._connection, None
            if connection:
                try:
                    await connection.close()
                except Exception:
                    pass
            try:
                remove_file(self.db_path)
            except Exception:
                pass

    async def get_session(self, token_hash: str) -> Optional[dict[str, Any]]:
        """Return the session stored for token_hash, or None"""
        try:
            if connection := await self._connect():
                await self._maybe_purge(connection)
                async with connection.execute("SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)) as cursor:
                    if row := await cursor.fetchone():
                        return dict(row)
        except Exception as error:
            await self._handle_error(error)
        return None

    async def add_session(
        self,
        token_hash: str,
        created: int,
        expires: int,
        cred_fingerprint: str,
        last_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        """Store a new login session"""
        try:
            if connection := await self._connect():
                await connection.execute(
                    "INSERT INTO sessions (token_hash, created, expires, cred_fingerprint, last_ip, user_agent) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (token_hash, created, expires, cred_fingerprint, last_ip, user_agent),
                )
        except Exception as error:
            await self._handle_error(error)

    async def touch_session(self, token_hash: str, expires: int):
        """Extend the expiry of a session (sliding window)"""
        try:
            if connection := await self._connect():
                await connection.execute("UPDATE sessions SET expires = ? WHERE token_hash = ?", (expires, token_hash))
        except Exception as error:
            await self._handle_error(error)

    async def delete_session(self, token_hash: str):
        """Delete a single session"""
        try:
            if connection := await self._connect():
                await connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        except Exception as error:
            await self._handle_error(error)

    async def close(self):
        """Close the connection; called from the web app's lifespan shutdown.
        Later calls fail closed (get_session returns None) instead of reopening."""
        self._closed = True
        connection, self._connection = self._connection, None
        if connection:
            try:
                await connection.close()
            except Exception:
                logging.debug("Failed to close sessions database", exc_info=True)
