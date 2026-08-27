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
tests.test_downloader - Test the downloader connection state machine
"""

import socket
import threading
import pytest
import time
from unittest import mock

import sabnzbd.cfg
from sabnzbd.downloader import Server, Downloader
from selectors import EVENT_READ

from sabnzbd.newswrapper import NewsWrapper
from sabnzbd.get_addrinfo import AddrInfo


class FakeNNTPServer:
    """Minimal NNTP server for testing connection state machine"""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host: str = host
        self.port: int = port
        self.server_socket = None
        self.connections = []
        self.commands = []
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.port = self.server_socket.getsockname()[1]  # Get assigned port
        self.server_socket.listen(5)
        self.server_socket.settimeout(0.5)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self.server_socket.accept()
                self.connections.append(conn)
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
            except OSError:
                pass

    def _handle_client(self, conn):
        try:
            conn.sendall(b"200 Welcome\r\n")
            # Keep connection alive until stop
            while not self._stop.is_set():
                conn.settimeout(0.5)
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                    self.commands.extend(line + b"\r\n" for line in data.split(b"\r\n") if line)
                    if data.startswith(b"QUIT"):
                        conn.sendall(b"205 Goodbye\r\n")
                        break
                    # Simple auth responses
                    if data.startswith(b"authinfo user"):
                        conn.sendall(b"381 More auth required\r\n")
                    elif data.startswith(b"authinfo pass"):
                        conn.sendall(b"281 Auth accepted\r\n")
                except TimeoutError:
                    continue
        except Exception:
            pass
        finally:
            conn.close()

    def stop(self):
        self._stop.set()
        for conn in self.connections:
            try:
                conn.close()
            except Exception:
                pass
        if self.server_socket:
            self.server_socket.close()
        if self._thread:
            self._thread.join(timeout=2)


@pytest.fixture
def fake_nntp_server(request):
    """Fixture that provides a fake NNTP server"""
    server = FakeNNTPServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def mock_downloader(mocker):
    """Create a minimal mock Downloader for testing"""
    import selectors

    downloader = mock.Mock(spec=Downloader)
    downloader.selector = selectors.DefaultSelector()
    downloader.shutdown = False
    downloader.paused = False
    downloader.paused_for_postproc = False

    # Use real implementations for socket management
    downloader.add_socket = lambda nw: Downloader.add_socket(downloader, nw)
    downloader.remove_socket = lambda nw: Downloader.remove_socket(downloader, nw)
    downloader.modify_socket = lambda nw, events: Downloader.modify_socket(downloader, nw, events)
    downloader.finish_connect_nw = lambda nw, resp: Downloader.finish_connect_nw(downloader, nw, resp)
    downloader.reset_nw = lambda nw, reset_msg=None, warn=False, wait=True, count_article_try=True, retry_article=True, article=None: Downloader.reset_nw(
        downloader, nw, reset_msg, warn, wait, count_article_try, retry_article, article
    )

    sabnzbd.Downloader = downloader
    yield downloader
    del sabnzbd.Downloader


@pytest.fixture
def test_server(request, fake_nntp_server, mocker):
    """Create a Server pointing to the fake NNTP server"""
    addrinfo = AddrInfo(
        *socket.getaddrinfo(fake_nntp_server.host, fake_nntp_server.port, socket.AF_INET, socket.SOCK_STREAM)[0]
    )

    params = getattr(request, "param", {})

    server = Server(
        server_id="test_server",
        displayname="Test Server",
        host=fake_nntp_server.host,
        port=fake_nntp_server.port,
        timeout=params.get("timeout", 5),
        threads=0,  # Don't auto-create connections
        priority=0,
        use_ssl=False,
        ssl_verify=0,
        ssl_ciphers="",
        pipelining_requests=mocker.Mock(return_value=params.get("pipelining_requests", 1)),
    )
    server.addrinfo = addrinfo
    return server


class TestConnectionStateMachine:
    """Test the init_connect / socket_connected / connected state transitions"""

    def test_socket_connected_set_after_successful_connect_no_auth(self, test_server, mock_downloader):
        """socket_connected should be True after NNTP.connect succeeds"""
        nw = NewsWrapper(test_server, thrdnum=1)
        test_server.idle_threads.add(nw)

        nw.init_connect()

        # Wait for async connect to complete
        for _ in range(50):
            if nw.connected:
                break
            time.sleep(0.1)

        assert nw.connected is True
        assert nw.ready is False
        assert nw.nntp is not None

        # Read the 200 Welcome
        nw.nntp.sock.setblocking(True)
        nw.nntp.sock.settimeout(2)

        try:
            nw.read()
        except Exception:
            pass

        # Server has no user/pass so finish_connect_nw goes directly to connected state
        assert nw.connected is True
        assert nw.ready is True
        assert nw.nntp is not None

    def test_socket_connected_enables_auth_flow(self, test_server, mock_downloader):
        """connected should be True after auth completes"""
        nw = NewsWrapper(test_server, thrdnum=1)
        test_server.idle_threads.add(nw)
        test_server.username = "user"
        test_server.password = "pass"

        nw.init_connect()

        # Wait for socket_connected
        for _ in range(50):
            if nw.connected:
                break
            time.sleep(0.1)

        assert nw.connected is True
        assert nw.ready is False
        assert nw.user_sent is False

        # Read the 200 Welcome
        nw.nntp.sock.setblocking(True)
        nw.nntp.sock.settimeout(2)

        try:
            nw.read()
        except Exception:
            pass

        # Auth should have started
        assert nw.user_sent is True
        assert nw.next_request is not None  # Auth command queued

    def test_hard_reset_clears_all_state(self, test_server, mock_downloader):
        """hard_reset should clear nntp, socket_connected, and connected"""
        nw = NewsWrapper(test_server, thrdnum=1)
        test_server.idle_threads.add(nw)

        nw.init_connect()

        # Wait for connection
        for _ in range(50):
            if nw.connected:
                break
            time.sleep(0.1)

        assert nw.nntp is not None
        assert nw.connected is True

        nw.hard_reset(wait=False)

        assert nw.nntp is None
        assert nw.connected is False
        assert nw.ready is False


class TestPipeliningDepth:
    """How many requests a connection is allowed to have in flight at once"""

    @staticmethod
    def ready_connection(server, timeout: float = 5.0) -> NewsWrapper:
        """A connected, authenticated NewsWrapper with the welcome banner consumed"""
        nw = NewsWrapper(server, thrdnum=1)
        server.idle_threads.add(nw)
        nw.init_connect()

        deadline = time.time() + timeout
        while not nw.connected and time.time() < deadline:
            time.sleep(0.01)
        assert nw.connected

        nw.nntp.sock.setblocking(True)
        nw.nntp.sock.settimeout(2)
        nw.read()
        assert nw.ready
        nw.nntp.sock.setblocking(False)
        # What the downloader loop does once a connection has work for it
        sabnzbd.Downloader.add_socket(nw)
        return nw

    @staticmethod
    def offer(nw: NewsWrapper, count: int):
        """Offer count requests, sending as many as the depth allows"""
        for index in range(count):
            nw.queue_command(b"DATE\r\n")
            nw.write()

    @staticmethod
    def wait_for_commands(fake_server, count: int, timeout: float = 2.0):
        deadline = time.time() + timeout
        while len(fake_server.commands) < count and time.time() < deadline:
            time.sleep(0.01)
        return fake_server.commands

    def test_welcome_banner_occupies_a_slot(self, test_server, mock_downloader):
        nw = NewsWrapper(test_server, thrdnum=1)
        test_server.idle_threads.add(nw)

        nw.init_connect()

        assert nw.decoder.expected == 1

    @pytest.mark.parametrize("test_server", [{"pipelining_requests": 1}], indirect=True)
    def test_depth_of_one_sends_one(self, test_server, fake_nntp_server, mock_downloader):
        nw = self.ready_connection(test_server)

        self.offer(nw, 4)

        self.wait_for_commands(fake_nntp_server, 1)
        assert fake_nntp_server.commands.count(b"DATE\r\n") == 1
        assert nw.decoder.expected == 1

    @pytest.mark.parametrize("test_server", [{"pipelining_requests": 3}], indirect=True)
    def test_sends_up_to_the_configured_depth(self, test_server, fake_nntp_server, mock_downloader):
        nw = self.ready_connection(test_server)

        self.offer(nw, 6)

        self.wait_for_commands(fake_nntp_server, 3)
        assert fake_nntp_server.commands.count(b"DATE\r\n") == 3
        assert nw.decoder.expected == 3

    @pytest.mark.parametrize("test_server", [{"pipelining_requests": 2}], indirect=True)
    def test_reaching_the_depth_stops_watching_for_write(self, test_server, fake_nntp_server, mock_downloader):
        """Otherwise the socket stays writable and the loop spins on it"""
        nw = self.ready_connection(test_server)

        self.offer(nw, 4)

        assert nw.selector_events == EVENT_READ

    @pytest.mark.parametrize("test_server", [{"pipelining_requests": 3}], indirect=True)
    def test_lowering_the_depth_stops_new_requests(self, test_server, fake_nntp_server, mock_downloader):
        nw = self.ready_connection(test_server)
        self.offer(nw, 1)
        self.wait_for_commands(fake_nntp_server, 1)

        test_server.effective_pipelining = 1
        self.offer(nw, 3)

        assert fake_nntp_server.commands.count(b"DATE\r\n") == 1

    @pytest.mark.parametrize("test_server", [{"pipelining_requests": 1}], indirect=True)
    def test_raising_the_depth_allows_more(self, test_server, fake_nntp_server, mock_downloader):
        nw = self.ready_connection(test_server)
        self.offer(nw, 2)
        self.wait_for_commands(fake_nntp_server, 1)
        assert fake_nntp_server.commands.count(b"DATE\r\n") == 1

        test_server.effective_pipelining = 3
        self.offer(nw, 2)

        self.wait_for_commands(fake_nntp_server, 3)
        assert fake_nntp_server.commands.count(b"DATE\r\n") == 3

    @pytest.mark.parametrize("test_server", [{"pipelining_requests": 1}], indirect=True)
    def test_failed_send_does_not_consume_a_slot(self, test_server, fake_nntp_server, mock_downloader, mocker):
        """A send that has to be retried must not leave the depth permanently spent,
        which at depth one would wedge the connection until it timed out"""
        nw = self.ready_connection(test_server)
        real_socket = nw.nntp.sock
        refused = []

        class RefuseFirstSend:
            def __getattr__(self, name):
                return getattr(real_socket, name)

            def send(self, data):
                if not refused:
                    refused.append(data)
                    raise BlockingIOError
                return real_socket.send(data)

        nw.nntp.sock = RefuseFirstSend()

        nw.queue_command(b"DATE\r\n")
        nw.write()

        assert refused
        assert nw.decoder.expected == 0
        nw.write()

        self.wait_for_commands(fake_nntp_server, 1)
        assert fake_nntp_server.commands.count(b"DATE\r\n") == 1
