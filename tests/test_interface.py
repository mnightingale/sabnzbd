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
"""

import asyncio
import inspect
import logging
import logging.config
import time
from typing import Optional
import pytest
from unittest.mock import Mock, patch
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.datastructures import Headers, Address, State
import uvicorn
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from uvicorn.lifespan import on as lifespan_on
from uvicorn.protocols.http import h11_impl, httptools_impl
from uvicorn.server import ServerState

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
    # A real State, not the Mock's auto-created attributes: code under test asks state for
    # values that may be absent (getattr(..., default)), and a Mock answers every such
    # question with a truthy Mock instead of raising, which hides what the real object does
    mock_request.state = State({})
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
        self,
        access_type,
        inet_exposure,
        local_ranges,
        remote_ip,
        xff_header,
        verify_xff_header,
        result_with_xff,
        monkeypatch,
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


async def empty_app(scope, receive, send):
    """Minimal ASGI app, replying to anything that does reach it"""
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b""})


def is_client_error(record: logging.LogRecord) -> bool:
    """Was this record logged by uvicorn because of client behavior?"""
    return record.getMessage().startswith(interface.UvicornNoiseFilter.CLIENT_ERRORS)


def feed_raw_request(protocol_class, data: bytes):
    """Hand raw bytes to a real uvicorn HTTP protocol, so it logs whatever it
    makes of them, just like it would for an actual connection."""

    async def _run():
        # log_config=None: the logging setup under test is applied by the fixture
        config = uvicorn.Config(app=empty_app, log_config=None)
        config.load()
        protocol = protocol_class(config=config, server_state=ServerState(), app_state={})
        transport = Mock()
        transport.get_extra_info = lambda name, default=None: ("127.0.0.1", 12345) if name == "peername" else default
        protocol.connection_made(transport)
        protocol.data_received(data)

    asyncio.run(_run())


class TestUvicornLogging:
    @pytest.fixture(autouse=True)
    def uvicorn_logging(self):
        """Apply the logging configuration that SABnzbd hands to uvicorn and
        restore the previous state afterwards, so other tests are unaffected."""
        loggers = [logging.getLogger(name) for name in ("uvicorn", "uvicorn.error", "uvicorn.access")]
        saved = [(logger.level, logger.propagate, logger.handlers[:], logger.filters[:]) for logger in loggers]
        logging.config.dictConfig(interface.uvicorn_logging_config())
        yield
        for logger, (level, propagate, handlers, filters) in zip(loggers, saved):
            logger.setLevel(level)
            logger.propagate = propagate
            logger.handlers = handlers
            logger.filters = filters

    @pytest.mark.parametrize("protocol_class", [h11_impl.H11Protocol, httptools_impl.HttpToolsProtocol])
    @pytest.mark.parametrize(
        "raw_request",
        [
            # Not HTTP at all, as sent by port scanners and misdirected clients
            b"\x16\x03\x01\x00\xf4\x01\x00\x00\xf0\x03\x03",
            # Valid HTTP, but asking for an upgrade we do not support
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n",
        ],
    )
    def test_client_errors_are_not_warnings(self, protocol_class, raw_request, caplog):
        # A handler that only wants INFO and up, just like the console and logfile
        # handlers when debug logging is off, must not see the message at all
        caplog.set_level(logging.INFO)
        feed_raw_request(protocol_class, raw_request)
        assert not [record for record in caplog.records if record.levelno >= logging.WARNING]
        assert not [record for record in caplog.records if is_client_error(record)]

    @pytest.mark.parametrize("protocol_class", [h11_impl.H11Protocol, httptools_impl.HttpToolsProtocol])
    def test_client_errors_are_kept_for_debug_logging(self, protocol_class, caplog):
        caplog.set_level(logging.DEBUG)
        feed_raw_request(protocol_class, b"\x16\x03\x01\x00\xf4\x01\x00\x00\xf0\x03\x03")
        assert [
            record
            for record in caplog.records
            if record.levelname == "DEBUG" and record.getMessage() == "Invalid HTTP request received."
        ]

    def test_lifecycle_messages_are_not_logged(self, caplog):
        # Starting and stopping is already logged by SABnzbd itself
        caplog.set_level(logging.INFO)
        logging.getLogger("uvicorn.error").info("Application startup complete.")
        assert not caplog.records

    def test_lifecycle_messages_are_kept_for_debug_logging(self, caplog):
        caplog.set_level(logging.DEBUG)
        logging.getLogger("uvicorn.error").info("Application startup complete.")
        assert [record for record in caplog.records if record.levelname == "DEBUG"]

    def test_failures_reported_by_sabnzbd_are_not_logged_twice(self, caplog):
        # SABnzbd logs its own error, including the reason, when the
        # web-interface fails to start, so this summary adds nothing
        caplog.set_level(logging.INFO)
        logging.getLogger("uvicorn.error").error("Application startup failed. Exiting.")
        assert not caplog.records

    def test_reason_for_a_failed_start_still_propagates(self, caplog):
        caplog.set_level(logging.INFO)
        logging.getLogger("uvicorn.error").error("Exception in 'lifespan' protocol")
        assert [record for record in caplog.records if record.levelno == logging.ERROR]

    def test_real_warnings_still_propagate(self, caplog):
        caplog.set_level(logging.INFO)
        logging.getLogger("uvicorn.error").warning("Exceeded concurrency limit.")
        logging.getLogger("uvicorn.error").error("Exception in ASGI application")
        assert [record for record in caplog.records if record.levelno == logging.WARNING]
        assert [record for record in caplog.records if record.levelno == logging.ERROR]

    def test_filtered_messages_still_used_by_uvicorn(self):
        """Guard against uvicorn rewording the messages we filter on"""
        uvicorn_source = "".join(inspect.getsource(module) for module in (h11_impl, httptools_impl, lifespan_on))
        for message in interface.UvicornNoiseFilter.CLIENT_ERRORS + interface.UvicornNoiseFilter.REPORTED_FAILURES:
            assert message in uvicorn_source


class TestClientAddressInfo:
    """The client address goes into log lines as host:port, so an IPv6 address has to
    be bracketed: ::ffff:127.0.0.1:55170 gives no clue where the address stops."""

    @pytest.mark.config({"verify_xff_header": False})
    @pytest.mark.parametrize(
        "remote_ip, expected",
        [
            ("127.0.0.1", "127.0.0.1:55170"),
            ("10.11.12.13", "10.11.12.13:55170"),
            ("::1", "[::1]:55170"),
            # Dual-stack listener reporting an IPv4 client
            ("::ffff:127.0.0.1", "[::ffff:127.0.0.1]:55170"),
            ("2001:470:1:332::152", "[2001:470:1:332::152]:55170"),
            # Unknown client, request.client was None
            ("", ":55170"),
        ],
    )
    def test_brackets_ipv6(self, remote_ip, expected):
        request = create_mock_request(remote_ip=remote_ip, remote_port=55170)
        assert interface.client_address_info(request) == expected

    @pytest.mark.config({"verify_xff_header": True})
    def test_includes_forwarded_chain(self):
        request = create_mock_request(remote_ip="::1", remote_port=55170, headers={"X-Forwarded-For": "8.7.6.5, ::1"})
        assert interface.client_address_info(request) == "[::1]:55170 (X-Forwarded-For: 8.7.6.5, ::1)"

    @pytest.mark.config({"verify_xff_header": False})
    def test_omits_forwarded_chain_when_not_verified(self):
        """Without verify_xff_header the header is not trusted, so it is not reported"""
        request = create_mock_request(remote_ip="::1", remote_port=55170, headers={"X-Forwarded-For": "8.7.6.5"})
        assert interface.client_address_info(request) == "[::1]:55170"


class TestUseSecureCookies:
    """The Secure attribute must follow the connection the request actually arrived on,
    including TLS terminated by a trusted reverse proxy in front of SABnzbd."""

    @staticmethod
    def make_request(scheme: str, host: str | None = "sab.example.com", server=("127.0.0.1", 8080)) -> Request:
        headers = [(b"host", host.encode())] if host is not None else []
        return Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/",
                "query_string": b"",
                "scheme": scheme,
                "headers": headers,
                "client": ("127.0.0.1", 12345),
                "server": server,
            }
        )

    @pytest.mark.config({"enable_https": False})
    @pytest.mark.parametrize(
        "scheme, host, server, expected",
        [
            ("http", "sab.example.com", ("127.0.0.1", 8080), False),
            ("https", "sab.example.com", ("127.0.0.1", 8080), True),
            # No Host header: the scheme must still decide the flag
            ("https", None, ("127.0.0.1", 8080), True),
            # An IPv6 listen address leaves the URL unparseable, the scheme is unaffected
            ("https", None, ("::ffff:127.0.0.1", 8080), True),
            ("https", "1234:5678::1:8080", ("::1", 8080), True),
            # Neither a Host header nor an address: the URL is relative and has no
            # scheme at all, which must not silently drop the Secure attribute
            ("https", None, None, True),
            ("http", None, None, False),
        ],
    )
    def test_follows_request_scheme(self, scheme, host, server, expected):
        assert interface.use_secure_cookies(self.make_request(scheme, host, server)) is expected

    @pytest.mark.config({"enable_https": True})
    def test_https_enabled_always_secure(self):
        """Serving https ourselves is enough, whatever the request looks like"""
        assert interface.use_secure_cookies(self.make_request("http")) is True

    @pytest.mark.config({"enable_https": False})
    def test_scheme_from_trusted_proxy(self):
        """X-Forwarded-Proto from a trusted proxy is resolved into the scope by
        uvicorn, so a proxy terminating TLS still gets the Secure attribute."""

        captured = {}

        async def asgi_app(scope, receive, send):
            captured["secure"] = interface.use_secure_cookies(Request(scope))

        def run(remote_ip: str):
            middleware = ProxyHeadersMiddleware(asgi_app, trusted_hosts=xff_trusted_networks())
            scope = {
                "type": "http",
                "method": "GET",
                "path": "/",
                "query_string": b"",
                "scheme": "http",
                "client": (remote_ip, 12345),
                "server": ("127.0.0.1", 8080),
                "headers": [(b"host", b"sab.example.com"), (b"x-forwarded-proto", b"https")],
            }
            asyncio.run(middleware(scope, None, None))
            return captured["secure"]

        # Trusted proxy: the forwarded scheme is honoured
        assert run("127.0.0.1") is True
        # Untrusted peer: the header must be ignored, so no Secure on a plain connection
        assert run("8.7.6.5") is False


def request_with_cookie(
    token: Optional[str] = None,
    params: Optional[dict] = None,
    remote_ip: str = "127.0.0.1",
    csrf: Optional[str] = None,
):
    """Mock request carrying an optional session cookie and merged API params. csrf sets the
    CSRF header; pass csrf="" for a request that presents no token at all."""
    headers = {} if csrf is None else {interface.CSRF_HEADER: csrf}
    request = create_mock_request(remote_ip=remote_ip, headers=headers)
    request.cookies = {interface.SESSION_COOKIE: token} if token else {}
    request.state.params = params or {}
    return request


def api_request(token: Optional[str] = None, mode: str = "queue", with_token: bool = True, **kwargs):
    """Mock /api request authorized by session cookie, echoing that session's CSRF token
    in the header unless with_token is False"""
    csrf = interface.csrf_token_for(token or "") if with_token else None
    return request_with_cookie(token, params={"mode": mode, "name": "", **kwargs}, csrf=csrf)


@pytest.fixture
def session_store(tmp_path, monkeypatch):
    """Wire sabnzbd.session_store to a fresh sessions database"""
    store = sessionstore.AsyncSessionStore(db_path=str(tmp_path / "sessions.db"))
    monkeypatch.setattr(sabnzbd, "session_store", store)
    yield store
    asyncio.run(store.close())


def store_session(
    store,
    token: str,
    expires_offset: int = interface.SESSION_DURATION,
    created_offset: int = 0,
    last_ip: str = "127.0.0.1",
    user_agent: Optional[str] = None,
):
    """Add a login session for token, valid for the credentials configured right now.
    created_offset ages the session, for the absolute-deadline cases.

    last_ip defaults to the address request_with_cookie uses, because create_session always
    records one: a row with no address looks like a client that has moved, which would make
    every validation rewrite it."""
    now = int(time.time())
    asyncio.run(
        store.add_session(
            interface.hash_session_token(token),
            now + created_offset,
            now + expires_offset,
            interface.credential_fingerprint(),
            last_ip=last_ip,
            user_agent=user_agent,
        )
    )


class TestHostileTokenValues:
    """Every secret compared on the auth path arrives as text off the wire, and
    hmac.compare_digest refuses str holding any non-ASCII character. Comparing those values
    directly turned a rejection into a 500 that anyone could trigger with one request."""

    # Starlette decodes headers and cookies as latin-1, so those channels carry any byte above
    # 0x7F but nothing past U+00FF. A form body is UTF-8, so it can carry anything -- including
    # the U+FFFD an invalid sequence decodes to, and in principle a lone surrogate, which UTF-8
    # cannot encode back.
    WIRE_HOSTILE = ["\xff\xfe", "\xe9" * 64, "caf\xe9"]
    BODY_HOSTILE = [*WIRE_HOSTILE, "�", "\U0001f600", "\ud800"]

    def test_compare_helper_rejects_instead_of_raising(self):
        for value in self.BODY_HOSTILE:
            assert interface.constant_time_equals(value, "a" * 64) is False
            assert interface.constant_time_equals("a" * 64, value) is False
        # ...and still matches what it should
        assert interface.constant_time_equals("a" * 64, "a" * 64) is True

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_hostile_session_cookie_is_rejected(self, session_store):
        """The worst of the three: this path runs on a plain page GET with no credentials
        configured, so a 500 here needed no session and no authentication at all"""
        for value in self.WIRE_HOSTILE:
            assert interface.validate_anonymous_session(request_with_cookie(value)) is False
            assert asyncio.run(interface.validate_any_session(request_with_cookie(value))) is False

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_hostile_csrf_token_in_header_is_rejected(self, session_store):
        tag = interface.anonymous_session_tag()
        for value in self.WIRE_HOSTILE:
            assert interface.csrf_token_matches(request_with_cookie(tag, csrf=value)) is False
            assert asyncio.run(config_save_middleware().denied_response(page_post(tag, csrf=value))) is not None

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_hostile_csrf_token_in_form_field_is_rejected(self, session_store):
        tag = interface.anonymous_session_tag()
        for value in self.BODY_HOSTILE:
            request = request_with_cookie(tag, params={interface.CSRF_FIELD: value})
            assert interface.csrf_token_matches(request) is False
            assert asyncio.run(config_save_middleware().denied_response(page_post(tag, csrf_field=value))) is not None

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 0})
    def test_hostile_credentials_are_rejected(self, session_store):
        """The login comparison already encoded both sides, but with a codec that raises on a
        lone surrogate; the shared helper cannot fail on any string"""
        for value in self.BODY_HOSTILE:
            assert interface.constant_time_equals(value, "user") is False


class TestSessionStoreFailure:
    """A login whose session was never stored used to look like it worked, then send the user
    back to the form on the next request -- for as long as the database stayed unwritable"""

    @pytest.fixture
    def failing_store(self, monkeypatch):
        """A store whose writes fail the way a read-only or full admin_dir makes them fail"""
        store = sessionstore.AsyncSessionStore(db_path="/nonexistent-directory/sessions.db")
        monkeypatch.setattr(sabnzbd, "session_store", store)
        return store

    def test_add_session_reports_failure(self, failing_store):
        stored = asyncio.run(failing_store.add_session("hash1", 0, int(time.time()) + 1000, "fp"))
        assert stored is False

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_create_session_sets_no_cookie_when_it_cannot_store(self, failing_store):
        request = request_with_cookie()
        response = Mock()
        assert asyncio.run(interface.create_session(request, response)) is False
        # No cookie, because a cookie whose session does not exist authorizes nothing
        response.set_cookie.assert_not_called()

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_login_reports_the_failure_instead_of_looping(self, failing_store, monkeypatch):
        """Correct credentials, unwritable store: the response must not be the usual redirect
        carrying a cookie, or the client is sent round the login loop with no way to know why"""
        monkeypatch.setattr(sabnzbd, "WEB_DIR_CONFIG", "/nonexistent", raising=False)
        request = login_post(username="user", password="pass")

        with (
            patch("sabnzbd.interface.build_header", return_value={}),
            patch("sabnzbd.interface.template_filtered_response") as render,
        ):
            response = asyncio.run(interface.login_index(request))

        assert render.call_args.kwargs["status_code"] == 500
        assert "could not be stored" in render.call_args.kwargs["search_list"]["error"]
        assert not isinstance(response, RedirectResponse)


class TestSessionAuth:
    """The auth path is async: session lookups run through the AsyncSessionStore
    (sessions.db) so the event loop never blocks on database access"""

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_valid_session_authorizes(self, session_store):
        store_session(session_store, "good-token")
        assert asyncio.run(interface.validate_session(request_with_cookie("good-token"))) is True

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_no_cookie_rejected(self, session_store):
        assert asyncio.run(interface.validate_session(request_with_cookie(None))) is False

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_expired_session_rejected_and_deleted(self, session_store):
        store_session(session_store, "old-token", expires_offset=-10)
        assert asyncio.run(interface.validate_session(request_with_cookie("old-token"))) is False
        # The stale row is cleaned up on rejection
        assert asyncio.run(session_store.get_session(interface.hash_session_token("old-token"))) is None

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_credential_change_invalidates_session(self, session_store):
        store_session(session_store, "tok")
        assert asyncio.run(interface.validate_session(request_with_cookie("tok"))) is True
        # Changing the password changes the fingerprint, invalidating existing sessions
        cfg.password.set("newpass")
        assert asyncio.run(interface.validate_session(request_with_cookie("tok"))) is False

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_sliding_expiry_extends(self, session_store):
        # Store a session already past its refresh threshold so validation touches it
        store_session(session_store, "tok", expires_offset=interface.SESSION_REFRESH_THRESHOLD)
        token_hash = interface.hash_session_token("tok")
        before = asyncio.run(session_store.get_session(token_hash))["expires"]
        assert asyncio.run(interface.validate_session(request_with_cookie("tok"))) is True
        after = asyncio.run(session_store.get_session(token_hash))["expires"]
        assert after > before

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_recently_used_session_is_not_rewritten(self, session_store):
        """The slide is throttled: a session touched moments ago gains nothing from another
        write, so an active browser does not put one UPDATE behind every request"""
        store_session(session_store, "tok")
        token_hash = interface.hash_session_token("tok")
        before = asyncio.run(session_store.get_session(token_hash))["expires"]
        assert asyncio.run(interface.validate_session(request_with_cookie("tok"))) is True
        assert asyncio.run(session_store.get_session(token_hash))["expires"] == before


def login_post(username: str = "", password: str = "", remote_ip: str = "127.0.0.1"):
    """A POST of the login form"""
    request = request_with_cookie(params={"username": username, "password": password}, remote_ip=remote_ip)
    request.method = "POST"
    return request


class TestLoginRateLimiting:
    """Guessing the password over the network has to get expensive. Failures are counted per
    client address, and once the allowance is gone the client waits out a cooldown."""

    @pytest.fixture(autouse=True)
    def no_recorded_failures(self, monkeypatch):
        """The tracker is module state, so start and leave each test with it empty. The web
        dir is unset outside a running SABnzbd, and login_index builds a template path."""
        monkeypatch.setattr(sabnzbd, "WEB_DIR_CONFIG", "/nonexistent", raising=False)
        interface._login_attempts.clear()
        yield
        interface._login_attempts.clear()

    def test_allowance_before_lockout(self):
        request = login_post()
        for _ in range(interface.LOGIN_MAX_ATTEMPTS - 1):
            interface.record_login_failure(request)
            assert interface.login_locked_out(request) is False
        # The one that uses up the allowance
        interface.record_login_failure(request)
        assert interface.login_locked_out(request) is True

    def test_cooldown_expires(self):
        request = login_post()
        for _ in range(interface.LOGIN_MAX_ATTEMPTS):
            interface.record_login_failure(request)
        assert interface.login_locked_out(request) is True

        # Rewind the cooldown rather than sleeping through it
        failures, cooldown_expiry = interface._login_attempts["127.0.0.1"]
        interface._login_attempts["127.0.0.1"] = (failures, cooldown_expiry - interface.LOGIN_LOCKOUT_TIME - 1)
        assert interface.login_locked_out(request) is False

    def test_success_restores_the_allowance(self):
        request = login_post()
        for _ in range(interface.LOGIN_MAX_ATTEMPTS):
            interface.record_login_failure(request)
        assert interface.login_locked_out(request) is True
        interface.clear_login_failures(request)
        assert interface.login_locked_out(request) is False
        assert "127.0.0.1" not in interface._login_attempts

    def test_lockout_is_per_client(self):
        """Keyed on the address, so guessing from one host must not lock anyone else out --
        and keyed on the address rather than the username, so it cannot be used to lock a
        known account out of its own instance"""
        attacker = login_post(remote_ip="10.11.12.13")
        for _ in range(interface.LOGIN_MAX_ATTEMPTS):
            interface.record_login_failure(attacker)
        assert interface.login_locked_out(attacker) is True
        assert interface.login_locked_out(login_post(remote_ip="127.0.0.1")) is False

    def test_stale_entries_are_dropped(self):
        """A distributed attempt must not grow the tracker past the clients that failed
        inside the window, and a client whose cooldown passed starts over with a full
        allowance rather than one attempt short of a lockout"""
        old = login_post(remote_ip="10.11.12.13")
        for _ in range(interface.LOGIN_MAX_ATTEMPTS):
            interface.record_login_failure(old)
        failures, cooldown_expiry = interface._login_attempts["10.11.12.13"]
        interface._login_attempts["10.11.12.13"] = (failures, cooldown_expiry - interface.LOGIN_LOCKOUT_TIME - 1)

        interface.record_login_failure(login_post(remote_ip="127.0.0.1"))
        assert "10.11.12.13" not in interface._login_attempts

        # And that address is back to a clean slate, not still one away from a lockout
        interface.record_login_failure(old)
        assert interface._login_attempts["10.11.12.13"][0] == 1

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 0})
    def test_correct_credentials_are_refused_while_locked_out(self, session_store):
        """The point of the cooldown is to deny another guess, so the credentials must not be
        looked at while it is running -- otherwise a client willing to be told no keeps
        testing passwords. Answers 429 so the refusal is legible to a log watcher too."""
        request = login_post(username="user", password="pass")
        for _ in range(interface.LOGIN_MAX_ATTEMPTS):
            interface.record_login_failure(request)

        with (
            patch("sabnzbd.interface.build_header", return_value={}),
            patch("sabnzbd.interface.template_filtered_response") as render,
            patch("sabnzbd.interface.create_session") as create_session,
        ):
            asyncio.run(interface.login_index(request))

        # No session handed out, despite the credentials being exactly right
        create_session.assert_not_called()
        assert render.call_args.kwargs["status_code"] == 429
        assert "Too many" in render.call_args.kwargs["search_list"]["error"]

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 0})
    def test_failed_login_is_counted_and_success_clears_it(self, session_store):
        """Through the handler rather than the helpers, so the wiring is covered too"""
        wrong = login_post(username="user", password="nope")
        with (
            patch("sabnzbd.interface.build_header", return_value={}),
            patch("sabnzbd.interface.template_filtered_response") as render,
        ):
            asyncio.run(interface.login_index(wrong))
        assert render.call_args.kwargs["status_code"] == 200
        assert interface._login_attempts["127.0.0.1"][0] == 1

        right = login_post(username="user", password="pass")
        asyncio.run(interface.login_index(right))
        assert "127.0.0.1" not in interface._login_attempts


class TestSessionActivityDetails:
    """The row is meant to describe the session as it is, not only as it was created, so that
    a future list of active sessions can say where each one is being used from. Waiting for
    the daily expiry slide would leave that up to a day out of date, so a client that moves
    is written through immediately."""

    def _details(self, store, token: str = "tok") -> tuple:
        session = asyncio.run(store.get_session(interface.hash_session_token(token)))
        return session["last_ip"], session["user_agent"]

    def _validate_from(self, remote_ip: str, user_agent: Optional[str] = None, token: str = "tok") -> bool:
        request = request_with_cookie(token, remote_ip=remote_ip)
        if user_agent:
            request.headers = Headers({"User-Agent": user_agent})
        return asyncio.run(interface.validate_session(request))

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_moving_address_is_written_through_immediately(self, session_store):
        """No waiting for the slide: the expiry here was just set, so the throttle would
        otherwise skip the write and leave the old address on show"""
        store_session(session_store, "tok", last_ip="10.11.12.13", user_agent="some-browser")
        assert self._validate_from("192.168.1.5", "some-browser") is True
        assert self._details(session_store) == ("192.168.1.5", "some-browser")

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_changed_user_agent_is_written_through_immediately(self, session_store):
        store_session(session_store, "tok", last_ip="10.11.12.13", user_agent="some-browser")
        assert self._validate_from("10.11.12.13", "another-browser") is True
        assert self._details(session_store) == ("10.11.12.13", "another-browser")

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_unchanged_client_is_not_rewritten(self, session_store):
        """The whole point of the throttle: a client that has not moved must not put a write
        behind every request it makes"""
        store_session(session_store, "tok", last_ip="10.11.12.13", user_agent="some-browser")
        with patch.object(sabnzbd.session_store, "touch_session") as touch:
            assert self._validate_from("10.11.12.13", "some-browser") is True
        touch.assert_not_called()

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_missing_user_agent_is_not_a_change(self, session_store):
        """touch_session keeps the stored value when passed None, so a request with no
        User-Agent must not read as 'moved' -- that would rewrite the row on every request
        for the rest of the session's life"""
        store_session(session_store, "tok", last_ip="10.11.12.13", user_agent="some-browser")
        with patch.object(sabnzbd.session_store, "touch_session") as touch:
            assert self._validate_from("10.11.12.13") is True
        touch.assert_not_called()

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_details_survive_a_request_without_them(self, session_store):
        """A request that carries no User-Agent must not wipe the one already recorded, even
        when it does write because the address changed"""
        store_session(session_store, "tok", last_ip="10.11.12.13", user_agent="some-browser")
        assert self._validate_from("127.0.0.1") is True
        assert self._details(session_store) == ("127.0.0.1", "some-browser")

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_activity_write_never_shortens_the_expiry(self, session_store):
        """A row written before the window shrank to SESSION_DURATION carries a longer expiry
        than today's slide would grant, and moving must not claw that back"""
        long_expiry = interface.SESSION_DURATION * 2
        store_session(session_store, "tok", expires_offset=long_expiry, last_ip="10.11.12.13")
        token_hash = interface.hash_session_token("tok")
        before = asyncio.run(session_store.get_session(token_hash))["expires"]

        assert self._validate_from("192.168.1.5") is True
        assert asyncio.run(session_store.get_session(token_hash))["expires"] == before


class TestSessionAbsoluteDeadline:
    """Sliding expiry on its own means a session that keeps being used never ends, so a
    stolen cookie would stay good forever. SESSION_MAX_AGE, counted from the created stamp,
    is the backstop: past it the session is refused however active it has been."""

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_session_past_its_deadline_is_rejected_and_deleted(self, session_store):
        # Idle timeout still in the future, so only the absolute deadline can refuse this
        store_session(
            session_store,
            "old-tok",
            created_offset=-(interface.SESSION_MAX_AGE + 60),
            expires_offset=interface.SESSION_DURATION,
        )
        assert asyncio.run(interface.validate_session(request_with_cookie("old-tok"))) is False
        assert asyncio.run(session_store.get_session(interface.hash_session_token("old-tok"))) is None

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_session_just_inside_its_deadline_still_works(self, session_store):
        store_session(
            session_store,
            "tok",
            created_offset=-(interface.SESSION_MAX_AGE - 3600),
            expires_offset=interface.SESSION_REFRESH_THRESHOLD,
        )
        assert asyncio.run(interface.validate_session(request_with_cookie("tok"))) is True

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_slide_is_clamped_to_the_deadline(self, session_store):
        """Near the end of its life a session may only be extended up to created +
        SESSION_MAX_AGE, so using it cannot push the deadline out"""
        # Deadline half a window away, and idle-expiry close enough that the slide fires
        created_offset = -(interface.SESSION_MAX_AGE - interface.SESSION_DURATION // 2)
        store_session(session_store, "tok", created_offset=created_offset, expires_offset=3600)
        token_hash = interface.hash_session_token("tok")
        deadline = asyncio.run(session_store.get_session(token_hash))["created"] + interface.SESSION_MAX_AGE

        assert asyncio.run(interface.validate_session(request_with_cookie("tok"))) is True
        expires = asyncio.run(session_store.get_session(token_hash))["expires"]
        assert expires == deadline
        # ...and it really was clamped, not just left alone
        assert expires < int(time.time()) + interface.SESSION_DURATION

    @pytest.mark.config({"username": "user", "password": "pass"})
    def test_pinned_session_stops_being_rewritten(self, session_store):
        """A session whose expiry already sits on its deadline, with little time left, is the
        case an unclamped slide gets wrong twice over: it would push the expiry past the
        deadline, and it would rewrite it on every single request until then. There is
        nothing to gain from a write here, so there must not be one."""
        # created so that the deadline is an hour away, with expires already pinned to it
        store_session(
            session_store,
            "tok",
            created_offset=-(interface.SESSION_MAX_AGE - 3600),
            expires_offset=3600,
        )
        token_hash = interface.hash_session_token("tok")
        session = asyncio.run(session_store.get_session(token_hash))
        assert session["expires"] == session["created"] + interface.SESSION_MAX_AGE

        with patch.object(sabnzbd.session_store, "touch_session") as touch:
            assert asyncio.run(interface.validate_session(request_with_cookie("tok"))) is True
        touch.assert_not_called()
        assert asyncio.run(session_store.get_session(token_hash))["expires"] == session["expires"]

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 0})
    def test_check_apikey_accepts_session_without_key(self, session_store):
        store_session(session_store, "browser-token")
        # A local browser call with a valid session and its CSRF token, but no apikey
        assert asyncio.run(interface.check_apikey(api_request("browser-token"))) is None

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

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 0})
    def test_rejected_when_credentials_configured(self):
        # A tag minted while auth was off grants nothing once credentials are set
        assert interface.validate_anonymous_session(request_with_cookie(interface.anonymous_session_tag())) is False

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 5})
    def test_accepted_when_login_waived_for_local_client(self):
        # inet_exposure 5 waives the login for local clients even though credentials are
        # set, so those page loads get an anonymous cookie that has to validate: it is
        # what their POSTs present to the CSRF guard and their API calls to check_apikey
        assert interface.validate_anonymous_session(request_with_cookie(interface.anonymous_session_tag())) is True
        # An external client still needs to log in, so no tag is good enough
        external = request_with_cookie(interface.anonymous_session_tag(), remote_ip="9.8.7.6")
        assert interface.validate_anonymous_session(external) is False

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_check_apikey_accepts_anonymous_without_key(self):
        assert asyncio.run(interface.check_apikey(api_request(interface.anonymous_session_tag()))) is None

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 5})
    def test_check_apikey_accepts_anonymous_when_login_waived(self, session_store):
        """The apikey is no longer embedded in the pages, so a local client whose login is
        waived by inet_exposure 5 has only its anonymous cookie to authorize API calls.
        Rejecting it answers the frontend with a 401, which it handles by reloading the
        page — which authorizes nothing either, so it reloads again."""
        assert asyncio.run(interface.check_apikey(api_request(interface.anonymous_session_tag()))) is None

    @pytest.mark.config({"username": "", "password": ""})
    def test_create_sets_matching_cookie(self):
        request = Mock()
        response = Mock()
        interface.create_anonymous_session(request, response)
        assert response.set_cookie.call_args.args[1] == interface.anonymous_session_tag()
        assert response.set_cookie.call_args.args[0] == interface.SESSION_COOKIE


class TestApiCsrf:
    """A cookie-authorized API call must echo its session's CSRF token in a header. The
    header is what makes this a defence: it cannot be attached by a form, an image or a
    navigation, and a cross-origin fetch that sets it is preflighted, which SABnzbd
    answers with a bare 405. An apikey-authorized call is deliberately untouched."""

    def _status(self, request) -> Optional[int]:
        response = asyncio.run(interface.check_apikey(request))
        return response.status_code if response else None

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_cookie_with_token_authorizes(self, session_store):
        assert self._status(api_request(interface.anonymous_session_tag())) is None

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_cookie_without_token_is_forbidden(self, session_store):
        """403, not 401: the frontend reloads on a 401, and a reload cannot conjure up a
        header it never sends, so answering 401 here would loop forever"""
        assert self._status(api_request(interface.anonymous_session_tag(), with_token=False)) == 403

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_stale_token_asks_for_a_reload(self, session_store):
        """401, because a reload does fix this one: the page was rendered before a restart
        rotated the key. A login session survives that restart, so its cookie still
        validates while the token it holds no longer does."""
        request = request_with_cookie(
            interface.anonymous_session_tag(), params={"mode": "queue", "name": ""}, csrf="f0" * 32
        )
        assert self._status(request) == 401

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_apikey_still_works_alongside_a_cookie(self, session_store):
        """The compatibility guarantee. Every functional test and the test-suite teardown
        authenticate with the apikey over GET and send no token, and the config pages send
        both a cookie and a key — so the cookie check must fall through to the key, never
        reject on its own."""
        request = request_with_cookie(
            interface.anonymous_session_tag(),
            params={"mode": "queue", "name": "", "apikey": cfg.api_key()},
        )
        assert self._status(request) is None
        # ...and with no cookie at all, which is how 3rd-party clients call it
        assert self._status(request_with_cookie(params={"mode": "queue", "name": "", "apikey": cfg.api_key()})) is None

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_no_mode_is_exempt(self, session_store):
        """There is no carve-out list. The one mode that needed it, showlog, is served to the
        interface by the /log page route instead, so every cookie-authorized API call has to
        present a token — including showlog itself."""
        assert self._status(api_request(interface.anonymous_session_tag(), mode="showlog", with_token=False)) == 403
        assert self._status(api_request(interface.anonymous_session_tag(), mode="showlog")) is None

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_token_outside_the_header_is_not_accepted(self, session_store):
        """This route merges the query string into its params, so honouring a token parameter
        would accept one straight out of a URL -- which puts it in access logs and Referer
        headers and onto a channel an <img> can reach, losing the preflight guarantee that
        makes the header a CSRF defence in the first place. Page routes still take the field,
        because their params are the form body and a native form cannot send a header."""
        tag = interface.anonymous_session_tag()
        token = interface.csrf_token_for(tag)

        as_parameter = request_with_cookie(tag, params={"mode": "queue", "name": "", interface.CSRF_FIELD: token})
        assert self._status(as_parameter) == 403
        # The same token in the header is what the frontend sends, and it is accepted
        assert self._status(api_request(tag)) is None

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_keyless_and_cookieless_still_reports_missing_key(self, session_store):
        assert self._status(request_with_cookie(params={"mode": "queue", "name": ""})) == 403

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_version_and_auth_skip_the_check(self, session_store):
        for mode in ("version", "auth"):
            assert self._status(request_with_cookie(params={"mode": mode, "name": ""})) is None


class TestLogRoute:
    """The log is served to the interface by /log, which is what let the CSRF exemption list
    go away: a read-only GET page needs no token, where a cookie-authorized API call does."""

    def _route(self):
        return next(route for route in interface.INTERFACE_ROUTES if getattr(route, "path", None) == "/log")

    def test_registered_as_a_read_only_route(self):
        # No POST: nothing here changes state, so nothing here needs a token
        assert sorted(self._route().methods) == ["GET", "HEAD"]

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 0})
    def test_behind_the_login_check(self, session_store):
        """It hands out the log plus a copy of the ini, so it must not be reachable without
        the login when one is configured. Driven through the route as it is actually
        registered, so weakening the decorator fails here rather than passing quietly."""
        route = self._route()
        captured = {}

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            if message["type"] == "http.response.start":
                captured["status"] = message["status"]
                captured["headers"] = Headers(raw=message["headers"])

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/log",
            "query_string": b"",
            "headers": [(b"host", b"127.0.0.1:8080")],
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 8080),
            "scheme": "http",
        }
        asyncio.run(route.app(scope, receive, send))
        # Redirected to the login form, and the handler never ran to stream any of the log
        assert captured["status"] == 302
        assert captured["headers"]["location"].endswith("/login")


def page_post(
    cookie: Optional[str] = None,
    remote_ip: str = "127.0.0.1",
    csrf: Optional[str] = None,
    csrf_field: Optional[str] = None,
):
    """A page POST carrying an optional session cookie and CSRF token. A cross-site POST is
    modelled as carrying neither: SameSite=Strict makes the browser withhold SABnzbd's
    cookies on a request originating from another site, and a cross-site page can read
    neither the token out of a page (CORS) nor the httponly cookie."""
    params = {interface.CSRF_FIELD: csrf_field} if csrf_field is not None else None
    request = request_with_cookie(cookie, params=params, remote_ip=remote_ip, csrf=csrf)
    request.method = "POST"
    return request


def config_save_middleware() -> interface.SecurityMiddleware:
    """SecurityMiddleware as secured_expose attaches it to a config *_save route: a page
    route that changes state and, since these routes dropped check_api_key, has nothing
    but the session cookie between a cross-site form and the whole configuration"""
    return interface.SecurityMiddleware(
        Mock(), check_configlock=True, check_for_login=True, check_api_key=False, access_type=4
    )


# The kinds of session cookie a page POST can arrive with, resolved to a value once the
# test's credentials are in place (a login token has to match the current fingerprint)
COOKIE_NONE = "none"
COOKIE_ANONYMOUS = "anonymous"
COOKIE_LOGIN = "login"
COOKIE_FORGED = "forged"


def cookie_of_kind(kind: str, store) -> Optional[str]:
    if kind == COOKIE_NONE:
        return None
    if kind == COOKIE_ANONYMOUS:
        return interface.anonymous_session_tag()
    if kind == COOKIE_FORGED:
        return "f0" * 32
    store_session(store, "login-token")
    return "login-token"


# The CSRF token a page POST can arrive with, relative to the cookie it sends
TOKEN_NONE = "none"
TOKEN_MATCHING = "matching"
TOKEN_WRONG = "wrong"


def token_of_kind(kind: str, cookie_value: Optional[str]) -> Optional[str]:
    if kind == TOKEN_NONE:
        return None
    if kind == TOKEN_WRONG:
        return "f0" * 32
    return interface.csrf_token_for(cookie_value or "")


class TestPagePostCsrf:
    """Every state-changing page POST has to echo the CSRF token belonging to its session.
    A session cookie on its own is not enough, in either of login_bypassed's cases: where
    the login is waived the request carries no proof of origin at all, and where it is
    enforced the cookie only proves SameSite=Strict let it through — and SameSite is not
    origin-scoped, so a page served from another port on the same host is same-site and
    its forms do send the cookie. Only a value the attacker cannot read closes that."""

    @pytest.mark.parametrize(
        "credentials, inet_exposure, cookie, token, allowed",
        [
            # No credentials at all: check_login always passes, so this guard is all there is
            (("", ""), 0, COOKIE_NONE, TOKEN_NONE, False),
            (("", ""), 0, COOKIE_ANONYMOUS, TOKEN_MATCHING, True),
            (("", ""), 0, COOKIE_ANONYMOUS, TOKEN_NONE, False),
            (("", ""), 0, COOKIE_ANONYMOUS, TOKEN_WRONG, False),
            (("", ""), 0, COOKIE_FORGED, TOKEN_MATCHING, False),
            (("", ""), 5, COOKIE_NONE, TOKEN_NONE, False),
            # A token with no cookie must not pass: csrf_token_for("") is computable by anyone
            (("", ""), 0, COOKIE_NONE, TOKEN_MATCHING, False),
            # Credentials with the login enforced
            (("user", "pass"), 0, COOKIE_NONE, TOKEN_NONE, False),
            (("user", "pass"), 0, COOKIE_LOGIN, TOKEN_MATCHING, True),
            (("user", "pass"), 0, COOKIE_LOGIN, TOKEN_NONE, False),
            # Credentials with inet_exposure 5: the login is waived for a local client, so
            # check_login passes with no cookie and this guard carries the whole weight
            (("user", "pass"), 5, COOKIE_NONE, TOKEN_NONE, False),
            (("user", "pass"), 5, COOKIE_FORGED, TOKEN_MATCHING, False),
            (("user", "pass"), 5, COOKIE_ANONYMOUS, TOKEN_MATCHING, True),
            (("user", "pass"), 5, COOKIE_ANONYMOUS, TOKEN_NONE, False),
            # ...without locking out a local client who does hold a real login session
            (("user", "pass"), 5, COOKIE_LOGIN, TOKEN_MATCHING, True),
        ],
    )
    @pytest.mark.config(
        lambda params: {
            "username": params["credentials"][0],
            "password": params["credentials"][1],
            "inet_exposure": params["inet_exposure"],
        }
    )
    def test_config_save_post(self, session_store, credentials, inet_exposure, cookie, token, allowed):
        cookie_value = cookie_of_kind(cookie, session_store)
        request = page_post(cookie_value, csrf=token_of_kind(token, cookie_value))
        response = asyncio.run(config_save_middleware().denied_response(request))
        assert (response is None) is allowed

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_token_accepted_as_form_field(self, session_store):
        """The header covers every ajax call, but a form that navigates cannot set one, so
        the token is accepted from the body too (never from the query string, which a page
        POST discards outright — see get_request_params)"""
        tag = interface.anonymous_session_tag()
        allowed = page_post(tag, csrf_field=interface.csrf_token_for(tag))
        assert asyncio.run(config_save_middleware().denied_response(allowed)) is None
        denied = page_post(tag, csrf_field="f0" * 32)
        assert asyncio.run(config_save_middleware().denied_response(denied)) is not None

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 5})
    def test_token_is_bound_to_its_own_session(self, session_store):
        """A token minted for another session grants nothing, in either direction. This is
        what a shared or global token would fail, and why it is derived per cookie."""
        cookie_of_kind(COOKIE_LOGIN, session_store)
        anonymous_tag = interface.anonymous_session_tag()

        login_with_anonymous_token = page_post("login-token", csrf=interface.csrf_token_for(anonymous_tag))
        assert asyncio.run(config_save_middleware().denied_response(login_with_anonymous_token)) is not None

        anonymous_with_login_token = page_post(anonymous_tag, csrf=interface.csrf_token_for("login-token"))
        assert asyncio.run(config_save_middleware().denied_response(anonymous_with_login_token)) is not None

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 5})
    def test_external_client_still_needs_login(self, session_store):
        """The waiver is local-only: an external POST gets no help from the anonymous tag"""
        tag = interface.anonymous_session_tag()
        request = page_post(tag, remote_ip="9.8.7.6", csrf=interface.csrf_token_for(tag))
        assert asyncio.run(config_save_middleware().denied_response(request)) is not None

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 0})
    def test_session_is_looked_up_once_per_request(self, session_store):
        """The login check and the CSRF guard both need to know whether the session is good,
        and under inet_exposure 5 the cookie-issuing decision asks a third time. Repeating the
        lookup would repeat the row read and the expiry and activity writes under it."""
        store_session(session_store, "login-token")
        request = page_post("login-token", csrf=interface.csrf_token_for("login-token"))

        with patch.object(sabnzbd.session_store, "get_session", wraps=sabnzbd.session_store.get_session) as get_session:
            assert asyncio.run(config_save_middleware().denied_response(request)) is None
        assert get_session.call_count == 1

    @pytest.mark.config({"username": "", "password": "", "inet_exposure": 0})
    def test_get_is_not_guarded(self, session_store):
        """Only state-changing requests need a token; rendering a page must not require one,
        or a first visit could never obtain it"""
        request = request_with_cookie()
        request.method = "GET"
        assert asyncio.run(config_save_middleware().denied_response(request)) is None


def run_page_request(cookie: Optional[str] = None, remote_ip: str = "127.0.0.1") -> tuple[list[str], str]:
    """Drive a UI page route's SecurityMiddleware over a real ASGI scope (it builds its own
    Request from the scope, so a mock will not do) and return both the Set-Cookie values it
    injected into the response start and the CSRF token it published for the handler to
    render, which is what build_header reads."""

    rendered_token = ""

    async def asgi_app(scope, receive, send):
        # Stand in for a page handler: build_header reads the token off request.state here
        nonlocal rendered_token
        rendered_token = scope.get("state", {}).get("csrf_token", "")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = interface.SecurityMiddleware(asgi_app, check_for_login=True, check_api_key=False, access_type=4)

    headers = [(b"host", b"127.0.0.1:8080")]
    if cookie:
        headers.append((b"cookie", ("%s=%s" % (interface.SESSION_COOKIE, cookie)).encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/config/general",
        "query_string": b"",
        "headers": headers,
        "client": (remote_ip, 12345),
        "server": ("127.0.0.1", 8080),
        "scheme": "http",
    }
    captured: list[str] = []

    async def send(message):
        if message["type"] == "http.response.start":
            captured.extend(Headers(raw=message["headers"]).getlist("set-cookie"))

    asyncio.run(middleware(scope, None, send))
    return captured, rendered_token


def issued_session_cookies(cookie: Optional[str] = None, remote_ip: str = "127.0.0.1") -> list[str]:
    return run_page_request(cookie=cookie, remote_ip=remote_ip)[0]


class TestAnonymousSessionIssuing:
    """UI page routes hand out the anonymous session cookie exactly when the login is
    bypassed and the client has nothing usable yet, so that its POSTs and its API calls
    have something to present"""

    def _issued(self, **kwargs) -> bool:
        return any(value.startswith(interface.SESSION_COOKIE + "=") for value in issued_session_cookies(**kwargs))

    @pytest.mark.config({"username": "", "password": ""})
    def test_issued_without_credentials(self, session_store):
        assert self._issued() is True

    @pytest.mark.config({"username": "", "password": ""})
    def test_not_reissued_when_tag_already_held(self, session_store):
        assert self._issued(cookie=interface.anonymous_session_tag()) is False

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 5})
    def test_issued_when_login_waived_for_local_client(self, session_store):
        """Without this the local UI has no cookie at all: its POSTs are refused by the
        CSRF guard and its API calls 401, which the frontend answers with a reload"""
        assert self._issued() is True

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 5})
    def test_login_session_not_overwritten(self, session_store):
        """A client holding a login session (a laptop that was remote and is now on the
        local network) must not have it replaced by the anonymous tag"""
        store_session(session_store, "login-token")
        assert self._issued(cookie="login-token") is False


def session_cookie_value(set_cookie_headers: list[str], fallback: Optional[str]) -> str:
    """The session cookie the client is left holding after a response: the one it was just
    issued, or the one it already had if none was set"""
    for value in set_cookie_headers:
        if value.startswith(interface.SESSION_COOKIE + "="):
            return value.split("=", 1)[1].split(";", 1)[0]
    return fallback or ""


class TestRenderedTokenMatchesCookie:
    """The token a page renders must belong to the cookie its client ends up holding,
    otherwise the very next POST from that page is refused.

    This is easy to get subtly wrong: the anonymous cookie is injected into the response
    start by SecurityMiddleware *after* the handler has already rendered the page, so a
    token derived from request.cookies is right in the steady state and wrong on every
    first load — where the cookie is absent or stale. That failure hits hardest exactly
    where there is no ajax to paper over it: the wizard, a fresh install's first screen."""

    def _assert_token_matches(self, cookie: Optional[str]):
        set_cookies, rendered_token = run_page_request(cookie=cookie)
        held = session_cookie_value(set_cookies, cookie)
        assert rendered_token == interface.csrf_token_for(held)
        assert rendered_token, "a page rendered no usable token at all"

    @pytest.mark.config({"username": "", "password": ""})
    def test_first_load_with_no_cookie(self, session_store):
        self._assert_token_matches(None)

    @pytest.mark.config({"username": "", "password": ""})
    def test_load_with_stale_cookie(self, session_store):
        # A tag from before a restart rotated the key: a fresh cookie is issued, and the
        # token has to match that one rather than the dead value we were sent
        self._assert_token_matches("f0" * 32)

    @pytest.mark.config({"username": "", "password": ""})
    def test_steady_state_anonymous(self, session_store):
        self._assert_token_matches(interface.anonymous_session_tag())

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 0})
    def test_login_session(self, session_store):
        store_session(session_store, "login-token")
        self._assert_token_matches("login-token")

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 5})
    def test_login_session_while_login_waived(self, session_store):
        store_session(session_store, "login-token")
        self._assert_token_matches("login-token")

    @pytest.mark.config({"username": "", "password": ""})
    def test_rendered_token_authorizes_the_next_post(self, session_store):
        """End to end: take the token a page published and the cookie it was issued, and
        confirm the POST that page would make is actually allowed"""
        set_cookies, rendered_token = run_page_request()
        held = session_cookie_value(set_cookies, None)
        request = page_post(held, csrf=rendered_token)
        assert asyncio.run(config_save_middleware().denied_response(request)) is None


def run_xframe_middleware() -> Headers:
    """Run a minimal request through XFrameOptionsMiddleware and return the response headers"""
    captured = {}

    async def asgi_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/html")]})
        await send({"type": "http.response.body", "body": b"ok"})

    async def send(message):
        if message["type"] == "http.response.start":
            captured["headers"] = Headers(raw=message["headers"])

    asyncio.run(interface.XFrameOptionsMiddleware(asgi_app)({"type": "http", "headers": []}, None, send))
    return captured["headers"]


class TestXFrameOptionsMiddleware:
    @pytest.mark.config({"x_frame_options": True})
    def test_header_added_when_enabled(self):
        assert run_xframe_middleware().get("X-Frame-Options") == "SAMEORIGIN"

    @pytest.mark.config({"x_frame_options": False})
    def test_header_absent_when_disabled(self):
        assert run_xframe_middleware().get("X-Frame-Options") is None
