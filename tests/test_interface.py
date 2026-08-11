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
from unittest.mock import Mock
from starlette.requests import Request
from starlette.datastructures import Headers, Address
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


def request_with_cookie(token: Optional[str] = None, params: Optional[dict] = None, remote_ip: str = "127.0.0.1"):
    """Mock request carrying an optional session cookie and merged API params"""
    request = create_mock_request(remote_ip=remote_ip)
    request.cookies = {interface.SESSION_COOKIE: token} if token else {}
    request.state.params = params or {}
    return request


@pytest.fixture
def session_store(tmp_path, monkeypatch):
    """Wire sabnzbd.session_store to a fresh sessions database"""
    store = sessionstore.AsyncSessionStore(db_path=str(tmp_path / "sessions.db"))
    monkeypatch.setattr(sabnzbd, "session_store", store)
    yield store
    asyncio.run(store.close())


def store_session(store, token: str, expires_offset: int = interface.SESSION_DURATION):
    """Add a login session for token, valid for the credentials configured right now"""
    now = int(time.time())
    asyncio.run(
        store.add_session(
            interface.hash_session_token(token),
            now,
            now + expires_offset,
            interface.credential_fingerprint(),
        )
    )


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

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 0})
    def test_check_apikey_accepts_session_without_key(self, session_store):
        store_session(session_store, "browser-token")
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
        request = request_with_cookie(interface.anonymous_session_tag(), params={"mode": "queue", "name": ""})
        assert asyncio.run(interface.check_apikey(request)) is None

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 5})
    def test_check_apikey_accepts_anonymous_when_login_waived(self, session_store):
        """The apikey is no longer embedded in the pages, so a local client whose login is
        waived by inet_exposure 5 has only its anonymous cookie to authorize API calls.
        Rejecting it answers the frontend with a 401, which it handles by reloading the
        page — which authorizes nothing either, so it reloads again."""
        request = request_with_cookie(interface.anonymous_session_tag(), params={"mode": "queue", "name": ""})
        assert asyncio.run(interface.check_apikey(request)) is None

    @pytest.mark.config({"username": "", "password": ""})
    def test_create_sets_matching_cookie(self):
        request = Mock()
        response = Mock()
        interface.create_anonymous_session(request, response)
        assert response.set_cookie.call_args.args[1] == interface.anonymous_session_tag()
        assert response.set_cookie.call_args.args[0] == interface.SESSION_COOKIE


def page_post(cookie: Optional[str] = None, remote_ip: str = "127.0.0.1"):
    """A page POST carrying an optional session cookie. A cross-site POST is modelled as
    carrying no cookie at all, because SameSite=Strict makes the browser withhold
    SABnzbd's cookies on any request originating from another site."""
    request = request_with_cookie(cookie, remote_ip=remote_ip)
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


class TestPagePostCsrf:
    """Every state-changing page POST has to present a SameSite=Strict session cookie.
    check_login alone does not achieve that: it passes with no cookie whenever the login
    is bypassed, which is both of login_bypassed's cases, not just the credential-less
    one. Missing the inet_exposure 5 waiver left every config *_save route (and
    /shutdown) open to a blind cross-site POST once they stopped requiring the apikey."""

    @pytest.mark.parametrize(
        "credentials, inet_exposure, cookie, allowed",
        [
            # No credentials at all: check_login always passes, so the cookie is all there is
            (("", ""), 0, COOKIE_NONE, False),
            (("", ""), 0, COOKIE_ANONYMOUS, True),
            (("", ""), 0, COOKIE_FORGED, False),
            (("", ""), 5, COOKIE_NONE, False),
            # Credentials with the login enforced: check_login already demands the session
            (("user", "pass"), 0, COOKIE_NONE, False),
            (("user", "pass"), 0, COOKIE_LOGIN, True),
            # Credentials with inet_exposure 5: the login is waived for a local client, so
            # check_login passes with no cookie and this guard carries the whole weight
            (("user", "pass"), 5, COOKIE_NONE, False),
            (("user", "pass"), 5, COOKIE_FORGED, False),
            (("user", "pass"), 5, COOKIE_ANONYMOUS, True),
            # ...without locking out a local client who does hold a real login session
            (("user", "pass"), 5, COOKIE_LOGIN, True),
        ],
    )
    @pytest.mark.config(
        lambda params: {
            "username": params["credentials"][0],
            "password": params["credentials"][1],
            "inet_exposure": params["inet_exposure"],
        }
    )
    def test_config_save_post(self, session_store, credentials, inet_exposure, cookie, allowed):
        request = page_post(cookie_of_kind(cookie, session_store))
        response = asyncio.run(config_save_middleware().denied_response(request))
        assert (response is None) is allowed

    @pytest.mark.config({"username": "user", "password": "pass", "inet_exposure": 5})
    def test_external_client_still_needs_login(self, session_store):
        """The waiver is local-only: an external POST gets no help from the anonymous tag"""
        request = page_post(interface.anonymous_session_tag(), remote_ip="9.8.7.6")
        assert asyncio.run(config_save_middleware().denied_response(request)) is not None


def issued_session_cookies(cookie: Optional[str] = None, remote_ip: str = "127.0.0.1") -> list[str]:
    """Drive a UI page route's SecurityMiddleware over a real ASGI scope (it builds its own
    Request from the scope, so a mock will not do) and return the Set-Cookie values it
    injected into the response start"""

    async def asgi_app(scope, receive, send):
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
    return captured


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
