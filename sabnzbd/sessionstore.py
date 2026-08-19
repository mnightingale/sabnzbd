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

logging.getLogger("aiosqlite").setLevel(logging.INFO)

import sabnzbd
import sabnzbd.cfg
from sabnzbd.constants import DB_SESSIONS_NAME
from sabnzbd.filesystem import remove_file

# Expired sessions are purged on first use and at most once per interval afterwards
PURGE_INTERVAL = 3600 * 24

DB_SESSIONS_VERSION = 1


class AsyncSessionStore:
    """Async store for web-UI login sessions"""

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
                # Multiple readers can work simultaneously with one writer
                await connection.execute("PRAGMA journal_mode = WAL")
                # Sync to disk at critical moments, not every write
                await connection.execute("PRAGMA synchronous = NORMAL")
                # Wait for lock instead of failing at once
                await connection.execute("PRAGMA busy_timeout = 5000")
                # Keep up to ~1MiB in memory per connection
                await connection.execute("PRAGMA cache_size = -1000")
                # Stores temporary tables, indexes, and sorting operations in RAM
                await connection.execute("PRAGMA temp_store = MEMORY")
                # Reduce disk access
                await connection.execute("PRAGMA mmap_size = 1048576")
                # Sessions are disposable, so a user_version mismatch drops and
                # recreates the table rather than migrating it
                async with connection.execute("PRAGMA user_version") as cursor:
                    version_row = await cursor.fetchone()
                if not version_row or version_row[0] != DB_SESSIONS_VERSION:
                    if version_row and version_row[0]:
                        logging.info(
                            "Sessions database is generation %s, resetting to %s: logins will be required again",
                            version_row[0],
                            DB_SESSIONS_VERSION,
                        )
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
        """Opportunistically delete expired sessions, throttled to once per PURGE_INTERVAL"""
        now = time.time()
        if now - self._last_purge >= PURGE_INTERVAL:
            self._last_purge = now
            await connection.execute("DELETE FROM sessions WHERE expires < ?", (int(now),))

    async def _handle_error(self, error: BaseException):
        """Log a failed operation"""
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
    ) -> bool:
        """Store a new login session. Returns whether the row was written."""
        try:
            if connection := await self._connect():
                await connection.execute(
                    "INSERT INTO sessions (token_hash, created, expires, cred_fingerprint, last_ip, user_agent) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (token_hash, created, expires, cred_fingerprint, last_ip, user_agent),
                )
                return True
        except Exception as error:
            await self._handle_error(error)
        return False

    async def touch_session(
        self,
        token_hash: str,
        expires: int,
        last_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        """Extend the expiry of a session (sliding window) and record where it was last used,
        so the row describes the session as it is now rather than only as it was created."""
        try:
            if connection := await self._connect():
                await connection.execute(
                    "UPDATE sessions SET expires = ?, last_ip = COALESCE(?, last_ip), "
                    "user_agent = COALESCE(?, user_agent) WHERE token_hash = ?",
                    (expires, last_ip, user_agent, token_hash),
                )
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
        """Close the connection; called from the web app's lifespan shutdown"""
        self._closed = True
        connection, self._connection = self._connection, None
        if connection:
            try:
                await connection.close()
            except Exception:
                logging.debug("Failed to close sessions database", exc_info=True)
