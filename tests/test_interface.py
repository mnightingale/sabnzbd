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
tests.test_interface - Testing functions in interface.py

X-Forwarded-For handling is delegated to uvicorn's ProxyHeadersMiddleware,
configured with the trust-list from misc.xff_trusted_networks() (see the
uvicorn.Config in SABnzbd.py). These tests run requests through that
middleware to verify the combined behaviour matches the access rules that
interface.check_access previously implemented in-app.
"""

import asyncio
import inspect
import time
import pytest
from unittest.mock import Mock
from starlette.requests import Request
from starlette.datastructures import Headers, Address
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import sabnzbd
import sabnzbd.cfg as cfg
import sabnzbd.sessionstore as sessionstore
from sabnzbd import interface
from sabnzbd.misc import is_local_addr, is_loopback_addr, xff_trusted_networks


def create_mock_request(remote_ip: str = "127.0.0.1", headers: dict | None = None, remote_port: int = 12345):
    """Create a mock Starlette Request object for testing"""
    mock_request = Mock(spec=Request)
    mock_request.client = Address(remote_ip, remote_port)
    mock_request.headers = Headers(headers or {})
    return mock_request


def resolve_client(remote_ip: str, xff_header: str | None = None, remote_port: int = 12345) -> Address:
    """Pass a connection through uvicorn's ProxyHeadersMiddleware, configured
    exactly like SABnzbd.py does, and return the resulting effective client."""
    captured = {}

    async def asgi_app(scope, receive, send):
        captured["client"] = scope.get("client")

    middleware = ProxyHeadersMiddleware(asgi_app, trusted_hosts=xff_trusted_networks())
    headers = []
    if xff_header:
        headers.append((b"x-forwarded-for", xff_header.encode("latin1")))
    scope = {"type": "http", "client": (remote_ip, remote_port), "headers": headers}
    asyncio.run(middleware(scope, None, None))
    return Address(*captured["client"])


class TestInterfaceFunctions:
    @pytest.mark.parametrize(
        "remote_ip, local_ranges, xff_header, result_with_xff",
        [
            ("10.11.12.13", None, None, True),
            ("10.11.12.13", None, "127.0.0.1", True),
            ("10.11.12.13", None, "127.1.2.3", True),
            ("10.11.12.13", None, "127.0.0.1:8080", True),  # Port stripped from XFF, leaving loopback
            ("10.11.12.13", None, "::1", True),
            ("10.11.12.13", None, "[::1]", True),
            ("10.11.12.13", None, "[::1]:8080", True),  # Port stripped from XFF, leaving loopback
            ("10.11.12.13", None, "localhost", False),  # Hostname in XFF
            ("10.11.12.13", None, "example.org", False),  # Hostname in XFF
            ("10.11.12.13", None, "192.168.1.1", True),
            ("10.11.12.13", None, "10.11.12.99", True),
            ("10.11.12.13", None, "8.7.6.5", False),  # XFF IP isn't local
            ("10.11.12.13", None, "192.168.1.1, 10.11.12.13", True),
            ("10.11.12.13", None, "192.168.1.1, 10.11.12.13, 9.8.7.6", False),  # Last XFF IP isn't local
            ("10.11.12.13", None, "192.168.1.1, 10.11.12.13, ::1", True),
            ("10.11.12.13", None, "192.168.1.1, 10.11.12.13, sabrules.example.org", False),  # Hostname in XFF
            ("10.11.12.13", "192.168.1.0/24", None, False),  # Remote IP not part of local ranges
            ("10.11.12.13", "192.168.1.0/24", "192.168.1.23", False),
            ("10.11.12.13", "192.168.1.0/24", "192.168.1.23, 10.11.12.1", False),
            ("10.11.12.13", "192.168.1.0/24, 10.0.0.0/8", "192.168.1.23", True),
            ("10.11.12.13", "192.168.2.0/24, 10.0.0.0/8", "192.168.1.23", False),
            ("10.11.12.13", "192.168.1.0/24, 10.0.0.0/24", "192.168.1.23", False),
            ("10.11.12.13", "10.11.12.0/24", "192.168.1.23", False),
            ("10.11.12.13", "2001:ffff::/64", None, False),
            ("10.11.12.13", "2001:ffff::/64, 192.168.1.0/24", None, False),
            ("13.12.11.10", None, None, False),  # Public remote IP doesn't have access, XFF ignored altogether
            ("13.12.11.10", None, "127.0.0.1", False),
            ("13.12.11.10", None, "127.1.2.3", False),
            ("13.12.11.10", None, "::1", False),
            ("13.12.11.10", None, "[::1]", False),
            ("13.12.11.10", None, "localhost", False),
            ("13.12.11.10", None, "192.168.1.1", False),
            ("13.12.11.10", None, "192.168.1.1, 13.12.11.10", False),
            ("13.12.11.10", None, "192.168.1.1, 13.12.11.10, ::1", False),
            ("13.12.11.10", None, "2001::/16", False),
            ("13.12.11.10", None, "2001::/16, 13.12.11.10", False),
            ("13.12.11.10", None, "2001::/16, 13.0.0.0/9", False),
            ("13.12.11.10", "13.12.11.10", None, True),  # Local ranges include a public IP
            ("13.12.11.10", "13.12.11.10, 192.168.255.0/24", None, True),
            ("13.12.11.10", "13.12.11.10", "192.168.1.1", False),  # XFF not in local ranges
            ("13.12.11.10", "13.12.11.10, 192.168.255.0/24", "192.168.1.1", False),
            ("13.12.11.10", "13.12.11.10", "192.168.1.1, 9.8.7.6", False),
            ("13.12.11.10", "13.12.11.10, 192.168.255.0/24", "192.168.1.1, 9.8.7.6", False),
            ("13.12.11.10", "13.0.0.0/12", None, True),
            ("13.12.11.10", "13.0.0.0/12, 192.168.255.0/24", None, True),
            ("13.12.11.10", "13.0.0.0/12", "192.168.1.1", False),  # XFF not in local ranges
            ("13.12.11.10", "13.0.0.0/12, 192.168.255.0/24", "192.168.1.1", False),
            ("13.12.11.10", "13.0.0.0/12", "192.168.1.1, 9.8.7.6", False),
            ("13.12.11.10", "13.0.0.0/12, 192.168.255.0/24", "192.168.1.1, 9.8.7.6", False),
            ("127.6.6.6", None, None, True),
            ("127.6.6.6", None, "127.0.0.1", True),
            ("127.6.6.6", None, "127.1.2.3", True),
            ("127.6.6.6", None, "127.0.0.1:8080", True),  # Port stripped from XFF, leaving loopback
            ("127.6.6.6", None, "::1", True),
            ("127.6.6.6", None, "[::1]", True),
            ("127.6.6.6", None, "[::1]:8080", True),  # Port stripped from XFF, leaving loopback
            ("127.6.6.6", None, "localhost", False),  # Hostname in XFF
            ("127.6.6.6", None, "example.org", False),  # Hostname in XFF
            ("127.6.6.6", None, "192.168.1.1", True),
            ("127.6.6.6", None, "10.11.12.99", True),
            ("127.6.6.6", None, "8.7.6.5", False),  # XFF IP isn't local
            ("127.6.6.6", None, "192.168.1.1, 127.6.6.6", True),
            ("127.6.6.6", None, "192.168.1.1, 127.6.6.6, 9.8.7.6", False),  # Last XFF IP isn't local
            ("127.6.6.6", None, "192.168.1.1, 127.6.6.6, ::1", True),
            ("127.6.6.6", None, "192.168.1.1, 127.6.6.6, sabrules.example.org", False),  # Hostname in XFF
            ("127.6.6.6", "192.168.1.0/24", None, True),  # Remote IP is loopback, local ranges be damned
            ("127.6.6.6", "192.168.1.0/24", "192.168.1.23", True),
            ("127.6.6.6", "192.168.1.0/24", "192.168.1.23, 127.0.0.1", True),
            ("127.6.6.6", "192.168.1.0/24, 127.0.0.0/8", "192.168.1.23", True),
            ("127.6.6.6", "192.168.2.0/24, 127.0.0.0/8", "192.168.1.23", False),  # Access denied by XFF
            ("127.6.6.6", "192.168.2.0/24, 127.0.0.0/8", "5.6.7.8", False),  # Idem
            ("127.6.6.6", "192.168.1.0/24, 127.0.0.0/8", "192.168.1.23, 5.6.7.8", False),  # Idem
            ("127.6.6.6", "192.168.1.0/24, 10.0.0.0/24", "::1", True),
            ("127.6.6.6", "127.6.6.0/24", "192.168.1.23", False),  # Access denied by XFF
            ("127.6.6.6", "2001:ffff::/32", None, True),
            ("127.6.6.6", "2001:ffff::/32, 192.168.1.0/24", None, True),
            ("127.6.6.6", "2001:ffff::/32", "2001:ffff:a:b:c:d:e:f", True),
            ("127.6.6.6", "2001:ffff::/32, 192.168.1.0/24", "2001:ffff:a:b:c:d:e:f, 192.168.1.1", True),
            ("127.6.6.6", "2001:ffff::/32", "666:ffff:a:b:c:d:e:f", False),  # Access denied by XFF
            ("127.6.6.6", "2001:ffff::/32, 192.168.1.0/24", "666:ffff:a:b:c:d:e:f, 192.168.1.1", False),  # Idem
            ("DEAD:BEEF:2023:007::1", None, None, False),  # Back to ignoring XFF altogether
            ("DEAD:BEEF:2023:007::1", None, "127.0.0.1", False),  # XFF is loopback
            ("DEAD:BEEF:2023:007::1", None, "127.1.2.3", False),
            ("DEAD:BEEF:2023:007::1", None, "::1", False),
            ("DEAD:BEEF:2023:007::1", None, "[::1]", False),
            ("DEAD:BEEF:2023:007::1", None, "localhost", False),  # Hostname in XFF
            ("DEAD:BEEF:2023:007::1", None, "192.168.1.1", False),
            ("DEAD:BEEF:2023:007::1", None, "192.168.1.1, DEAD:BEEF:2023:0007::1", False),
            ("DEAD:BEEF:2023:007::1", None, "192.168.1.1, DEAD:BEEF:2023:0007::1, ::1", False),
            ("DEAD:BEEF:2023:007::1", None, "2001::/16", False),
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", None, True),  # Local ranges include a public IPv6
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", "127.0.0.1", True),  # XFF is loopback
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", "127.1.2.3", True),
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", "::1", True),
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", "[::1]", True),
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", "localhost", False),  # Hostname in XFF
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", "192.168.1.1", False),
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", "192.168.1.1, DEAD:BEEF:2023:0007::1", False),
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", "192.168.1.1, DEAD:BEEF:2023:0007::1, ::1", False),
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", "DEAD::/16", False),  # Netmask in XFF
            ("DEAD:BEEF:2023:007::1", "dead:beef::/32", "DEAD:BEEF:2023:7::42", True),  # XFF in local ranges
        ],
    )
    @pytest.mark.parametrize("access_type", [1, 2, 3, 4, 5, 6])
    @pytest.mark.parametrize("inet_exposure", [0, 1, 2, 3, 4, 5])
    @pytest.mark.parametrize("verify_xff_header", [False, True])
    @pytest.mark.config(
        lambda params: {
            "local_ranges": params["local_ranges"],
            "inet_exposure": params["inet_exposure"],
            "verify_xff_header": params["verify_xff_header"],
        }
    )
    def test_check_access(
        self, access_type, inet_exposure, local_ranges, remote_ip, xff_header, verify_xff_header, result_with_xff
    ):
        def _func():
            # With verify_xff_header enabled, SABnzbd.py runs uvicorn with
            # proxy_headers=True, so the XFF chain is resolved into the
            # effective client before check_access ever sees the request.
            # With it disabled the header is ignored entirely.
            if verify_xff_header:
                client = resolve_client(remote_ip=remote_ip, xff_header=xff_header)
                result = result_with_xff
            else:
                client = Address(remote_ip, 12345)
                # Without XFF, only the remote IP and the local ranges setting matter
                result = is_loopback_addr(remote_ip) or is_local_addr(remote_ip)

            request = create_mock_request(remote_ip=client.host, remote_port=client.port)

            if access_type <= inet_exposure:
                assert interface.check_access(request, access_type) is True
            else:
                assert interface.check_access(request, access_type) is result

        _func()

    @pytest.mark.parametrize(
        "local_ranges, xff_ips, expected_result",
        [
            ([], ["4.3.2.1"], "4.3.2.1"),  # Standard situation, single non-local XFF IP
            ([], ["42:1b5::beef"], "42:1b5::beef"),
            ([], ["10.10.10.10"], "10.10.10.10"),  # Only local XFF IPs, first entry wins
            ([], ["::1"], "::1"),
            ([], ["127.0.0.1"], "127.0.0.1"),
            ([], ["10.10.10.10", "192.168.0.1"], "10.10.10.10"),  # Only local XFF IPs, first entry wins
            ([], ["10.10.10.10", "192.168.0.1", "192.168.1.2"], "10.10.10.10"),  # Only local XFF IPs, first entry wins
            ([], ["4.3.2.1", "10.10.10.10"], "4.3.2.1"),  # First non-local entry wins
            ([], ["4.3.2.1", "192.168.0.1", "10.10.10.10"], "4.3.2.1"),
            ([], ["127.0.0.1", "4.3.2.1", "192.168.0.1", "10.10.10.10"], "4.3.2.1"),
            ([], ["4.3.2.1", "192.168.0.1", "10.10.10.10", "127.0.0.1"], "4.3.2.1"),
            ([], ["666::1", "4.3.2.1", "10.10.10.10"], "4.3.2.1"),
            ([], ["4.3.2.1", "666::1", "192.168.0.1", "10.10.10.10"], "666::1"),
            ([], ["127.0.0.1", "4.3.2.1", "666::1", "10.10.10.10"], "666::1"),
            ([], ["4.3.2.1", "192.168.0.1", "10.10.10.10", "127.0.0.1", "666::1"], "666::1"),
            ([], ["10.10.10.10", "4.3.2.1"], "4.3.2.1"),
            ([], ["192.168.0.1", "4.3.2.1", "10.10.10.10"], "4.3.2.1"),
            ([], ["127.0.0.1", "192.168.0.1", "4.3.2.1", "10.10.10.10"], "4.3.2.1"),
            ([], ["192.168.0.1", "4.3.2.1", "10.10.10.10", "127.0.0.1"], "4.3.2.1"),
            (["4.3.2.0/24"], ["4.3.2.1"], "4.3.2.1"),  # Only local IPs due to local_ranges, first entry wins
            (["666::/48"], ["666::1"], "666::1"),
            (["192.168.0.0/16", "4.3.2.0/24"], ["4.3.2.1"], "4.3.2.1"),
            (["666::/48", "192.168.0.0/16", "4.3.2.0/24"], ["4.3.2.1"], "4.3.2.1"),
            (["666::/48", "192.168.0.0/16", "4.3.2.0/24"], ["666::1"], "666::1"),
            (["192.168.0.0/16", "4.3.2.0/24"], ["10.10.10.10"], "10.10.10.10"),  # 10.x wins, outside local_ranges
            (["192.168.0.0/16", "4.3.2.0/24"], ["4.3.2.1", "10.10.10.10"], "10.10.10.10"),
            (["192.168.0.0/16", "4.3.2.0/24"], ["10.10.10.10", "4.3.2.1"], "10.10.10.10"),
            (["666::/48", "192.168.0.0/16", "4.3.2.0/24"], ["10.10.10.10"], "10.10.10.10"),
            (["666::/48", "192.168.0.0/16", "4.3.2.0/24"], ["4.3.2.1", "10.10.10.10"], "10.10.10.10"),
            (["666::/48", "192.168.0.0/16", "4.3.2.0/24"], ["10.10.10.10", "4.3.2.1"], "10.10.10.10"),
            (["8.8.8.8", "4.3.2.1"], ["4.3.2.1", "192.168.0.1", "10.10.10.10"], "10.10.10.10"),
            (["8.8.8.8", "4.3.2.1"], ["192.168.0.1", "4.3.2.1", "10.10.10.10"], "10.10.10.10"),
            (["8.8.8.8", "4.3.2.1"], ["192.168.0.1", "10.10.10.10", "4.3.2.1"], "10.10.10.10"),
            (["8.8.8.8"], ["192.168.0.1", "10.10.10.10", "4.3.2.1"], "4.3.2.1"),  # All XFF IPs non-local, last wins
            (["8.8.8.8"], ["4.3.2.1", "10.10.10.10", "192.168.0.1"], "192.168.0.1"),
            (["8.8.8.8"], ["4.3.2.1", "192.168.0.1", "10.10.10.10"], "10.10.10.10"),
            (["8.8.8.8"], ["127.0.0.1", "4.3.2.1", "10.10.10.10", "192.168.0.1"], "192.168.0.1"),
            (["666::/48"], ["192.168.0.1", "10.10.10.10", "4.3.2.1"], "4.3.2.1"),
            (["666::/48"], ["4.3.2.1", "10.10.10.10", "192.168.0.1"], "192.168.0.1"),
            (["666::/48"], ["4.3.2.1", "192.168.0.1", "10.10.10.10"], "10.10.10.10"),
            (["666::/48"], ["127.0.0.1", "4.3.2.1", "10.10.10.10", "192.168.0.1"], "192.168.0.1"),
            (["8.8.8.8"], ["4.3.2.1", "192.168.0.1", "10.10.10.10", "127.0.0.1"], "10.10.10.10"),  # Loopback as last
            (["666::/48"], ["4.3.2.1", "192.168.0.1", "10.10.10.10", "127.0.0.1"], "10.10.10.10"),
            (["8.8.8.8"], ["4.3.2.1", "192.168.0.1", "10.10.10.10", "::1"], "10.10.10.10"),
            (["666::/48"], ["4.3.2.1", "192.168.0.1", "10.10.10.10", "::1"], "10.10.10.10"),
            ([], ["4.3.2.1:56789"], "4.3.2.1"),  # Port stripped from XFF entry
        ],
    )
    @pytest.mark.config(
        lambda params: {
            "local_ranges": params["local_ranges"],
        }
    )
    def test_effective_client_from_xff(self, local_ranges, xff_ips, expected_result):
        def _func():
            # The effective client IP (used for login-cookie binding and access
            # checks) is selected by uvicorn's ProxyHeadersMiddleware: the last
            # XFF entry that is not a trusted (local) proxy, or the first entry
            # when the whole chain is trusted. Connect from loopback, which is
            # always a trusted peer.
            assert xff_ips
            client = resolve_client(remote_ip="127.0.0.1", xff_header=", ".join(xff_ips))
            assert client.host == expected_result

        _func()

    @pytest.mark.parametrize("access_type", [1, 2, 3, 4, 5, 6])
    @pytest.mark.parametrize("inet_exposure", [0, 2, 4])
    @pytest.mark.config(lambda params: {"inet_exposure": params["inet_exposure"], "api_warnings": True})
    def test_check_access_without_client(self, access_type, inet_exposure):
        # request.client can be None (e.g. unix sockets or some test clients);
        # this must not raise and must fail closed for restricted access types
        request = create_mock_request()
        request.client = None

        assert interface.check_access(request, access_type, warn_user=True) is (access_type <= inet_exposure)
        # The logging helpers must not raise either
        interface.log_warning_and_ip(request, "txt")

    @pytest.mark.parametrize(
        "local_ranges, expected_networks, unexpected_networks",
        [
            # Without local_ranges: loopback plus all private address space
            (None, ["127.0.0.0/8", "::1", "10.0.0.0/8", "192.168.0.0/16", "::ffff:10.0.0.0/104"], []),
            # With local_ranges: loopback plus the configured ranges only
            (
                "192.168.1.0/24",
                ["127.0.0.0/8", "::1", "192.168.1.0/24", "::ffff:192.168.1.0/120"],
                ["10.0.0.0/8", "172.16.0.0/12"],
            ),
        ],
    )
    @pytest.mark.config(lambda params: {"local_ranges": params["local_ranges"]})
    def test_xff_trusted_networks(self, local_ranges, expected_networks, unexpected_networks):
        def _func():
            networks = xff_trusted_networks()
            for network in expected_networks:
                assert network in networks
            for network in unexpected_networks:
                assert network not in networks

        _func()


def request_with_cookie(token: str | None = None, params: dict | None = None, remote_ip: str = "127.0.0.1"):
    """Mock request carrying an optional session cookie and merged API params"""
    request = create_mock_request(remote_ip=remote_ip)
    request.cookies = {interface.SESSION_COOKIE: token} if token else {}
    request.state.params = params or {}
    return request


class TestSessionAuth:
    """The auth path is async: session lookups run through the AsyncSessionStore
    (sessions1.db) so the event loop never blocks on database access"""

    @pytest.fixture
    def session_store(self, tmp_path, monkeypatch):
        """Wire sabnzbd.session_store to a fresh sessions database"""
        store = sessionstore.AsyncSessionStore(db_path=str(tmp_path / "sessions1.db"))
        monkeypatch.setattr(sabnzbd, "session_store", store)
        yield store
        asyncio.run(store.close())

    def _store_session(self, store, token: str, expires_offset: int = interface.SESSION_DURATION):
        now = int(time.time())
        asyncio.run(
            store.add_session(
                interface.hash_session_token(token),
                now,
                now + expires_offset,
                interface.credential_fingerprint(),
            )
        )

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_valid_session_authorizes(self, session_store):
        self._store_session(session_store, "good-token")
        assert asyncio.run(interface.validate_session(request_with_cookie("good-token"))) is True

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_no_cookie_rejected(self, session_store):
        assert asyncio.run(interface.validate_session(request_with_cookie(None))) is False

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_expired_session_rejected_and_deleted(self, session_store):
        self._store_session(session_store, "old-token", expires_offset=-10)
        assert asyncio.run(interface.validate_session(request_with_cookie("old-token"))) is False
        # The stale row is cleaned up on rejection
        assert asyncio.run(session_store.get_session(interface.hash_session_token("old-token"))) is None

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_credential_change_invalidates_session(self, session_store):
        self._store_session(session_store, "tok")
        assert asyncio.run(interface.validate_session(request_with_cookie("tok"))) is True
        # Changing the password changes the fingerprint, invalidating existing sessions
        cfg.password.set("newpass")
        assert asyncio.run(interface.validate_session(request_with_cookie("tok"))) is False

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_sliding_expiry_extends(self, session_store):
        # Store a session already past its refresh threshold so validation touches it
        self._store_session(session_store, "tok", expires_offset=interface.SESSION_REFRESH_THRESHOLD)
        token_hash = interface.hash_session_token("tok")
        before = asyncio.run(session_store.get_session(token_hash))["expires"]
        assert asyncio.run(interface.validate_session(request_with_cookie("tok"))) is True
        after = asyncio.run(session_store.get_session(token_hash))["expires"]
        assert after > before

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 0})
    def test_check_apikey_accepts_session_without_key(self, session_store):
        self._store_session(session_store, "browser-token")
        # A local browser call with a valid session and no apikey is authorized
        request = request_with_cookie("browser-token", params={"mode": "queue", "name": ""})
        assert asyncio.run(interface.check_apikey(request)) is None

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_auth_functions_are_async(self):
        """Guard against a sync regression: these run on the event loop inside
        secured_expose, so they must stay awaitable (blocking work belongs in
        the session store or a threadpool)"""
        for func in (
            interface.validate_session,
            interface.check_login,
            interface.check_apikey,
            interface.create_session,
            interface.clear_session,
        ):
            assert inspect.iscoroutinefunction(func)


class TestAnonymousSession:
    """Anonymous sessions are stateless (HMAC cookie), never database rows"""

    @pytest.mark.config({"username": "", "password": ""})
    def test_valid_tag_accepted(self):
        assert interface.validate_anonymous_session(request_with_cookie(interface.anonymous_session_tag())) is True

    @pytest.mark.config({"username": "", "password": ""})
    def test_missing_or_wrong_tag_rejected(self):
        assert interface.validate_anonymous_session(request_with_cookie(None)) is False
        assert interface.validate_anonymous_session(request_with_cookie("forged-tag")) is False

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_rejected_when_credentials_configured(self):
        # A tag minted while auth was off grants nothing once credentials are set
        assert interface.validate_anonymous_session(request_with_cookie(interface.anonymous_session_tag())) is False

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_check_apikey_accepts_anonymous_without_key(self):
        request = request_with_cookie(interface.anonymous_session_tag(), params={"mode": "queue", "name": ""})
        assert asyncio.run(interface.check_apikey(request)) is None

    @pytest.mark.config({"username": "", "password": ""})
    def test_create_sets_matching_cookie(self):
        request = Mock()
        response = Mock()
        interface.create_anonymous_session(request, response)
        assert response.set_cookie.call_args.args[1] == interface.anonymous_session_tag()
        assert response.set_cookie.call_args.args[0] == interface.SESSION_COOKIE


def run_response_middleware(middleware_cls, path: str = "/") -> Headers:
    """Run a minimal request through a response-header middleware and return the response headers"""
    captured = {}

    async def asgi_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/html")]})
        await send({"type": "http.response.body", "body": b"ok"})

    async def send(message):
        if message["type"] == "http.response.start":
            captured["headers"] = Headers(raw=message["headers"])

    asyncio.run(middleware_cls(asgi_app)({"type": "http", "path": path, "headers": []}, None, send))
    return captured["headers"]


class TestXFrameOptionsMiddleware:
    @pytest.mark.config({"x_frame_options": True})
    def test_header_added_when_enabled(self):
        assert run_response_middleware(interface.XFrameOptionsMiddleware).get("X-Frame-Options") == "SAMEORIGIN"

    @pytest.mark.config({"x_frame_options": False})
    def test_header_absent_when_disabled(self):
        assert run_response_middleware(interface.XFrameOptionsMiddleware).get("X-Frame-Options") is None


class TestApiCorsMiddleware:
    @pytest.mark.config({"api_cors": "*", "url_base": "/sabnzbd"})
    def test_header_added_on_api_routes_when_set(self):
        assert run_response_middleware(interface.ApiCorsMiddleware, "/api").get("Access-Control-Allow-Origin") == "*"
        assert (
            run_response_middleware(interface.ApiCorsMiddleware, "/sabnzbd/api").get("Access-Control-Allow-Origin")
            == "*"
        )

    @pytest.mark.config({"api_cors": "https://example.com"})
    def test_header_uses_configured_value(self):
        assert (
            run_response_middleware(interface.ApiCorsMiddleware, "/api").get("Access-Control-Allow-Origin")
            == "https://example.com"
        )

    @pytest.mark.config({"api_cors": "*"})
    def test_header_absent_on_other_routes(self):
        assert run_response_middleware(interface.ApiCorsMiddleware, "/").get("Access-Control-Allow-Origin") is None
        assert (
            run_response_middleware(interface.ApiCorsMiddleware, "/config").get("Access-Control-Allow-Origin") is None
        )

    @pytest.mark.config({"api_cors": ""})
    def test_header_absent_when_empty(self):
        assert run_response_middleware(interface.ApiCorsMiddleware, "/api").get("Access-Control-Allow-Origin") is None
