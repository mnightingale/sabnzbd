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
sabnzbd.interface - webinterface
"""

import contextlib
import os
import secrets
import threading
import time
import logging
import urllib.parse
import re
import hashlib
import hmac
import socket
import ssl
import functools
import copy

import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Address, MultiDict, MutableHeaders, QueryParams
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, PlainTextResponse, Response, FileResponse
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from Cheetah.Template import Template
from typing import Optional, Callable, Any, Collection
from guessit.api import properties as guessit_properties

import sabnzbd
from sabnzbd.misc import (
    to_units,
    from_units,
    time_format,
    calc_age,
    int_conv,
    get_base_url,
    is_ipv4_addr,
    is_ipv6_addr,
    is_lan_addr,
    is_local_addr,
    is_loopback_addr,
    recursive_html_escape,
    is_none,
    get_cpu_name,
)
from sabnzbd.filesystem import (
    real_path,
    globber,
    globber_full,
    clip_path,
    same_directory,
    setname_from_path,
)
from sabnzbd.encoding import utob
import sabnzbd.config as config
import sabnzbd.cfg as cfg
import sabnzbd.newsunpack
import sabnzbd.utils.ssdp
from sabnzbd.get_addrinfo import get_fastest_addrinfo
from sabnzbd.constants import (
    DEF_STD_CONFIG,
    DEFAULT_PRIORITY,
    CHEETAH_DIRECTIVES,
    EXCLUDED_GUESSIT_PROPERTIES,
    DEF_HTTPS_CERT_FILE,
    DEF_SORTER_RENAME_SIZE,
    GUESSIT_SORT_TYPES,
    VALID_NZB_FILES,
    VALID_ARCHIVES,
    DEF_NETWORKING_TEST_TIMEOUT,
)
from sabnzbd.lang import list_languages
from sabnzbd.api import (
    report,
    list_scripts,
    list_cats,
    del_from_section,
    api_handler,
    halt_and_shutdown,
    build_header,
    build_log_response,
    url_for,
    url_netloc,
    Ttemplate,
)
from sabnzbd.nzb import NzoInfo
from sabnzbd.rss import ResolvedEntry, RSSState

##############################################################################
# Security functions
##############################################################################
_MSG_ACCESS_DENIED = "External internet access denied - https://sabnzbd.org/access-denied"
_MSG_ACCESS_DENIED_CONFIG_LOCK = "Access denied - Configuration locked"
_MSG_ACCESS_DENIED_HOSTNAME = "Access denied - Hostname verification failed: https://sabnzbd.org/hostname-check"
_MSG_MISSING_AUTH = "Missing authentication"
_MSG_APIKEY_REQUIRED = "API Key Required"
_MSG_APIKEY_INCORRECT = "API Key Incorrect"
_MSG_MISSING_SESSION = "Access denied - Missing or invalid session token, reload the page and try again"
_MSG_APIKEY_NOT_ON_PAGES = (
    "Access denied - The apikey is only accepted on /api, use the matching api-call instead of this page"
)
_MSG_SESSION_EXPIRED = "Session expired, reload the page"

RE_HOST_PORT = re.compile(":[0-9]+$")

INTERFACE_ROUTES: list[Route | Mount] = []


def secured_expose(
    wrap_func: Optional[Callable] = None,
    route: Optional[str] = None,
    check_configlock: bool = False,
    check_for_login: bool = True,
    check_api_key: bool = False,
    check_csrf: bool = True,
    access_type: int = 4,
    methods: Collection = ("GET", "POST"),
) -> Callable:
    """Register a handler as a Starlette route and attach its access controls.

    check_api_key belongs to /api and nothing else, on purpose. The apikey is the credential
    for the documented, public API, and the interface's own pages are not that: they are for a
    browser holding a session, so they authorize on the session cookie plus its CSRF token.
    That is why an apikey no longer opens the config *_save routes -- automation that used to
    POST to them wants the equivalent api-call (mode=set_config and friends) instead."""
    if not wrap_func:
        return functools.partial(
            secured_expose,
            route=route,
            check_configlock=check_configlock,
            check_for_login=check_for_login,
            check_api_key=check_api_key,
            check_csrf=check_csrf,
            access_type=access_type,
            methods=methods,
        )

    if route:
        INTERFACE_ROUTES.append(
            Route(
                route,
                endpoint=wrap_func,
                methods=methods,
                middleware=[
                    Middleware(ParamsMiddleware, merge_query=check_api_key),
                    Middleware(
                        SecurityMiddleware,
                        check_configlock=check_configlock,
                        check_for_login=check_for_login,
                        check_api_key=check_api_key,
                        check_csrf=check_csrf,
                        access_type=access_type,
                    ),
                ],
            )
        )

    return wrap_func


def client_address(request: Request) -> Address:
    """Safe access to request.client, which can be None (e.g. when serving on a
    unix socket, or with some test clients). Treated as an unknown, non-local
    client, so access checks fail closed."""
    return request.client or Address("", 0)


def client_address_info(request: Request) -> str:
    """The client as host:port for logging, with the forwarding chain when there is one"""
    client = client_address(request)
    # Bracketed, so the port cannot be read as another group of an IPv6 address
    host = f"[{client.host}]" if ":" in client.host else client.host
    if cfg.verify_xff_header() and (xff_ips := request.headers.get("X-Forwarded-For")):
        return f"{host}:{client.port} (X-Forwarded-For: {xff_ips})"
    return f"{host}:{client.port}"


def check_access(request: Request, access_type: int = 4, warn_user: bool = False) -> bool:
    """Check if external address is allowed given access_type (Starlette version):
    1=nzb
    2=api
    3=full_api
    4=webui
    5=webui with login for external
    """
    # Easy, it's allowed
    if access_type <= cfg.inet_exposure():
        return True

    # X-Forwarded-For is resolved by uvicorn's ProxyHeadersMiddleware (see the
    # uvicorn.Config in SABnzbd.py): when verify_xff_header is enabled and the
    # connecting peer is a trusted local proxy, request.client already holds the
    # effective client address taken from the XFF chain.
    remote_ip = client_address(request).host

    # Check if the client IP is a loopback address or considered local
    is_allowed = is_loopback_addr(remote_ip) or is_local_addr(remote_ip)

    if not is_allowed and warn_user:
        log_warning_and_ip(request, T("Refused connection from:"))
    return is_allowed


def check_hostname(request: Request) -> bool:
    """Check if hostname is allowed, to mitigate DNS-rebinding attack (Starlette version).
    Similar to CVE-2019-5702, we need to add protection even
    if only allowed to be accessed via localhost.
    """
    # If login is enabled, no API-key can be deducted
    if cfg.username() and cfg.password():
        return True

    # Don't allow requests without Host
    host = request.headers.get("Host")
    if not host:
        return False

    # Remove the port-part (like ':8080'), if it is there, always on the right hand side.
    # Not to be confused with IPv6 colons (within square brackets)
    host = RE_HOST_PORT.sub("", host).lower()

    # Fine if localhost or IP. RFC 7230 requires an IPv6 literal in a Host header to be
    # bracketed, so brackets are required here too: without them there is no telling
    # where the address ends and the port begins, and a bare "1234:5678::1:8080" would
    # otherwise pass as an address after the port-stripping above took a guess at it.
    if host == "localhost" or is_ipv4_addr(host) or (host.startswith("[") and is_ipv6_addr(host)):
        return True

    # Check on the whitelist
    if host in cfg.host_whitelist():
        return True

    # Fine if ends with ".local" or ".local.", aka mDNS name
    # See rfc6762 Multicast DNS
    if host.endswith((".local", ".local.")):
        return True

    # Ohoh, bad
    log_warning_and_ip(request, T('Refused connection with hostname "%s" from:') % host)
    return False


# Name of the cookie holding the session token: a database-backed login token, or the
# stateless anonymous tag when no credentials are configured. Deliberately distinct
# from the Starlette SessionMiddleware cookie (COOKIE_SESSION below), which is an
# unrelated signed client-side cookie used only for transient RSS flash messages.
SESSION_COOKIE = "sabnzbd_user_session"
# Name of the Starlette SessionMiddleware (flash) cookie; see create_app and
# SecureSessionCookieMiddleware. Not authentication.
COOKIE_SESSION = "sabnzbd_flash"


def use_secure_cookies(request: Request) -> bool:
    """Whether cookies for this request should carry the Secure attribute"""
    # Taken from the scope, which is what the proxy headers are applied to and what
    # request.url is built from. The URL itself comes out relative, and its scheme
    # empty, when there is neither a Host header nor an address to fall back on.
    return request.scope.get("scheme") == "https" or bool(cfg.enable_https())


# How long a session survives without being used. Expiry slides forward on use, so this is
# an idle timeout rather than a lifetime.
SESSION_DURATION = 3600 * 24 * 14  # 14 days
# The lifetime, counted from the session's created stamp. Sliding expiry alone means a
# session that keeps being used never ends, so a stolen cookie would stay good indefinitely;
# past this deadline the session is refused and deleted however active it was, and the user
# logs in again. Expiry is clamped to it too, so the ordinary purge collects the row.
SESSION_MAX_AGE = 3600 * 24 * 90  # 90 days
# Only extend a session's expiry when doing so buys it more than this much extra time, so an
# active session triggers at most ~1 database write per day instead of one per request
SESSION_REFRESH_THRESHOLD = 3600 * 24  # 1 day

# Login rate limiting. A client gets LOGIN_MAX_ATTEMPTS failures, then has to sit out
# LOGIN_LOCKOUT_TIME before it may try again, which leaves an online guesser about a dozen
# attempts an hour while costing someone who mistypes their password one short wait.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_TIME = 300  # 5 minutes

# Failed attempts per client address, as {host: (failures, cooldown_expiry)}. Expiries are
# time.monotonic() stamps, not wall clock: this is a duration to sit out, and an NTP step or a
# manual clock change would otherwise clear an active cooldown or stretch it past its length.
#
# Deliberately in memory rather than in the sessions database: it is short-lived per-process
# state, and persisting it would mean a schema change -- which logs every remembered browser
# out -- to inconvenience an attacker who can already restart SABnzbd. Only ever touched from
# the event loop, so it needs no locking.
#
# Keyed on the address rather than the username, so that guessing at one account cannot lock
# its owner out. Note that behind a reverse proxy without verify_xff_header every client
# shares the proxy's address, and so shares one allowance.
_login_attempts: dict[str, tuple[int, float]] = {}


def _prune_login_attempts(now: float):
    """Forget clients whose cooldown has run out, both to give them their allowance back and
    to keep a distributed attempt from growing the table beyond the addresses currently in
    a cooldown. Called from every read and write of the table, so it is bounded by live
    traffic; entries left when traffic stops are a fixed set that waits for the restart."""
    for host in [host for host, (_, cooldown_expiry) in _login_attempts.items() if cooldown_expiry <= now]:
        del _login_attempts[host]


def login_cooldown_remaining(request: Request) -> int:
    """Whole seconds this client must sit out before another login attempt is considered,
    or 0 when it may try now"""
    _prune_login_attempts(time.monotonic())
    failures, cooldown_expiry = _login_attempts.get(client_address(request).host, (0, 0.0))
    remaining = cooldown_expiry - time.monotonic()
    if failures < LOGIN_MAX_ATTEMPTS or remaining <= 0:
        return 0
    # Rounded up, because a Retry-After of 0 would invite a retry that is still too early
    return int(remaining) + 1


def login_locked_out(request: Request) -> bool:
    """Whether this client has used up its login attempts and is still in the cooldown"""
    return login_cooldown_remaining(request) > 0


def record_login_failure(request: Request):
    """Count a failed login against this client"""
    now = time.monotonic()
    _prune_login_attempts(now)

    host = client_address(request).host
    failures = _login_attempts.get(host, (0, 0.0))[0]
    _login_attempts[host] = (failures + 1, now + LOGIN_LOCKOUT_TIME)


def clear_login_failures(request: Request):
    """Give a client its full allowance back, once it has proved it knows the password"""
    _login_attempts.pop(client_address(request).host, None)


def constant_time_equals(presented: str, expected: str) -> bool:
    """Constant-time comparison of two secrets that arrived as text.

    Both sides are encoded rather than handed to hmac.compare_digest as str, which refuses
    any string holding a non-ASCII character. These values come straight off the wire -- a
    cookie or header carrying a byte above 0x7F, which Starlette decodes as latin-1, would
    otherwise raise TypeError instead of simply failing to match, turning a rejection into a
    500. backslashreplace so the encode cannot fail either: UTF-8 has no representation for a
    lone surrogate, and what a body decoder hands back is not ours to depend on."""
    return hmac.compare_digest(
        presented.encode("utf-8", "backslashreplace"), expected.encode("utf-8", "backslashreplace")
    )


def credential_fingerprint() -> str:
    """Fingerprint of the current username/password. Stored with each session and
    compared on validation, so changing either credential invalidates all sessions."""
    return hashlib.sha256(utob("%s:%s" % (cfg.username(), cfg.password()))).hexdigest()


def hash_session_token(token: str) -> str:
    """Hash of the raw cookie token; only the hash is stored server-side"""
    return hashlib.sha256(utob(token)).hexdigest()


async def create_session(request: Request, response: Response, remember_me: bool = False) -> bool:
    """Create a new database-backed login session and set the session cookie on the response.

    Returns False when the session could not be stored, leaving the response untouched: a
    cookie whose session does not exist authorizes nothing, so handing one out would only
    send the client back to the login form on its next request."""
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    if not await sabnzbd.session_store.add_session(
        token_hash=hash_session_token(token),
        created=now,
        expires=now + SESSION_DURATION,
        cred_fingerprint=credential_fingerprint(),
        last_ip=client_address(request).host,
        user_agent=request.headers.get("User-Agent"),
    ):
        return False

    # remember_me yields a persistent cookie; a plain login without remember_me yields a
    # browser-session cookie, while the row lives on server-side either way. The cookie is
    # given the absolute deadline rather than the idle timeout, because the idle timeout
    # slides and the server is the one enforcing it: a cookie capped at SESSION_DURATION
    # would log an active user out after 14 days for no reason, and one that outlived
    # SESSION_MAX_AGE could never be honoured anyway.
    max_age = SESSION_MAX_AGE if remember_me else None
    response.set_cookie(
        SESSION_COOKIE,
        token,
        path="/",
        httponly=True,
        secure=use_secure_cookies(request),
        samesite="strict",
        max_age=max_age,
    )
    return True


def login_bypassed(request: Request) -> bool:
    """Return True when check_login lets this request through without a login session:
    either no credentials are configured at all, or inet_exposure 5 waives the login for
    local clients. The single definition of "no login needed", because every one of these
    requests arrives with no proof that it came from this instance's own UI: they are
    exactly the requests that must be issued an anonymous session cookie, and whose POSTs
    the CSRF guard has to check it on (see SecurityMiddleware)."""
    # No authentication required when no username/password is set
    if not cfg.username() or not cfg.password():
        return True

    # If we show login for external IP, by using access_type=6 we can check if IP match
    return cfg.inet_exposure() == 5 and check_access(request, access_type=6)


# Anonymous sessions (used when the login is bypassed, so the frontend can authenticate
# API calls by cookie without the apikey) are stateless: the cookie holds an HMAC tag
# instead of a database-backed token, so cookie-less clients (bots, scanners) cannot
# grow the sessions table by minting a row per request.
# The key is regenerated each run; after a restart the next page load simply
# receives a fresh cookie. All anonymous clients share the same tag: it carries
# no identity, it only proves the client loaded a UI page from this instance.
_ANONYMOUS_SESSION_KEY = secrets.token_bytes(32)


def anonymous_session_tag() -> str:
    """The stateless anonymous session cookie value for this run"""
    return hmac.new(_ANONYMOUS_SESSION_KEY, b"anonymous-session", hashlib.sha256).hexdigest()


def validate_anonymous_session(request: Request) -> bool:
    """Return True when the login is bypassed for this request and it carries a valid
    anonymous session cookie. Gated on login_bypassed rather than on the credentials
    alone: inet_exposure 5 waives the login for local clients while credentials are
    set, and those page loads are issued an anonymous cookie that has to validate."""
    if not login_bypassed(request):
        return False
    return constant_time_equals(request.cookies.get(SESSION_COOKIE, ""), anonymous_session_tag())


def create_anonymous_session(request: Request, response: Response):
    """Set the stateless anonymous session cookie on the response"""
    response.set_cookie(
        SESSION_COOKIE,
        anonymous_session_tag(),
        path="/",
        httponly=True,
        secure=use_secure_cookies(request),
        samesite="strict",
        max_age=SESSION_DURATION,
    )


# CSRF tokens are derived from the session cookie rather than stored: a session's token
# is hmac(_CSRF_KEY, cookie_value), so it is bound to that session, dies with it, and
# needs neither a column in the sessions database nor a lookup to compute. The key is
# regenerated each run like _ANONYMOUS_SESSION_KEY, so a page left open across a restart
# holds a stale token; check_apikey answers those with a 401 so the frontend reloads.
#
# Unlike the cookie, the token is NOT sent automatically by the browser: it is rendered
# into the page ($csrf_token) and echoed back in a form field or the header below. That
# is what makes it a CSRF defence, because a cross-site page can read neither the page
# (CORS) nor the httponly cookie. SameSite=Strict on its own cannot do this job: it is
# not origin-scoped, so a page served from another port on the same host counts as
# same-site and its forms do carry the session cookie.
#
# Login sessions get a token each; all anonymous clients share one, since anonymous
# sessions deliberately have no database row to hang a per-client value on. That is
# sound: reading the shared token means fetching a page from this instance, and anyone
# who can do that can make the request directly anyway.
_CSRF_KEY = secrets.token_bytes(32)
CSRF_HEADER = "X-SABnzbd-CSRF"
CSRF_FIELD = "csrf_token"


def csrf_token_for(cookie_value: str) -> str:
    """The CSRF token belonging to a session cookie value.

    Hex on purpose: recursive_html_escape escapes quotes and ampersands, and entities are
    not decoded inside a <script> block, so a token containing one would silently corrupt
    the JavaScript it is rendered into. Hex also matches api.LOG_HASH_RE, so the token is
    redacted from the log that /log hands out for users to post publicly."""
    return hmac.new(_CSRF_KEY, utob(cookie_value), hashlib.sha256).hexdigest()


def presented_csrf_token(request: Request, header_only: bool = False) -> str:
    """The CSRF token this request offers, from the header or a form field.

    The header covers every XHR (one $.ajaxSetup per skin) and cannot be set cross-site at
    all. The field additionally serves the handful of native form navigations, which cannot
    send headers, and on a page route it really is a field: those params are the form body
    only, so a ?csrf_token= is invisible here by design.

    header_only is for /api, the one route whose params are merged with the query string.
    Accepting a field there would accept a token from a URL, which puts it in access logs and
    Referer headers and drops it onto a channel an <img> can reach -- so the API takes it from
    the header alone, which is what lets it rely on the CORS preflight."""
    if header_only:
        return request.headers.get(CSRF_HEADER) or ""
    return request.headers.get(CSRF_HEADER) or request_params(request).get(CSRF_FIELD) or ""


def csrf_token_matches(request: Request, header_only: bool = False) -> bool:
    """Whether the request echoes the CSRF token belonging to the cookie it sent"""
    return constant_time_equals(
        presented_csrf_token(request, header_only=header_only),
        csrf_token_for(request.cookies.get(SESSION_COOKIE, "")),
    )


async def validate_csrf(request: Request) -> bool:
    """Return True when the request carries a valid session and the CSRF token belonging
    to it. Both halves are required: the token alone would let a client with no cookie
    present csrf_token_for(""), and the session alone is what this replaces."""
    return await validate_any_session(request) and csrf_token_matches(request)


async def clear_session(request: Request, response: Response):
    """Delete the request's session (if any) and clear the session cookie"""
    if token := request.cookies.get(SESSION_COOKIE):
        await sabnzbd.session_store.delete_session(hash_session_token(token))
    response.set_cookie(
        SESSION_COOKIE,
        "",
        path="/",
        httponly=True,
        secure=use_secure_cookies(request),
        samesite="strict",
        expires="Thu, 01 Jan 1970 00:00:00 GMT",
    )


async def validate_session(request: Request) -> bool:
    """Return True when the request carries a session cookie that is not past either of its
    two deadlines -- the sliding idle timeout and the absolute SESSION_MAX_AGE -- and whose
    credential fingerprint still matches the configured username/password. Sessions failing
    any of those are deleted, and a still-valid one slides its expiry forward.

    Answered once per request and then remembered: a single page POST asks through both the
    login check and the CSRF guard, and a POST whose login is bypassed asks a third time when
    SecurityMiddleware decides whether to issue an anonymous cookie. The answer cannot change
    while a request is in flight, so the repeats would only re-run the row lookup and the
    expiry and activity writes underneath it."""
    if (cached := getattr(request.state, "session_valid", None)) is None:
        cached = await _validate_session(request)
        request.state.session_valid = cached
    return cached


async def _validate_session(request: Request) -> bool:
    """The lookup behind validate_session. Call that instead, so a request pays for this once."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False

    token_hash = hash_session_token(token)
    now = int(time.time())
    session = await sabnzbd.session_store.get_session(token_hash)
    if not session:
        return False

    # Reject (and clean up) sessions that are idle-expired, past their absolute deadline, or
    # from before a credential change. The absolute check is not redundant with the clamp
    # below: it also covers rows written before this cap existed, or by an older version.
    if (
        session["expires"] < now
        or session["created"] + SESSION_MAX_AGE < now
        or session["cred_fingerprint"] != credential_fingerprint()
    ):
        await sabnzbd.session_store.delete_session(token_hash)
        return False

    # Slide the idle timeout forward, never past the absolute deadline, and never backwards:
    # a row written by an older version can carry a longer expiry than today's window, and
    # using a session should not shorten it.
    new_expires = max(session["expires"], min(now + SESSION_DURATION, session["created"] + SESSION_MAX_AGE))

    # Write when the slide gains real time, or when the client's address or browser changed.
    # The first keeps an idle-timeout refresh down to roughly one write a day per session --
    # and stops entirely once the expiry is pinned to the deadline, where sliding can gain
    # nothing. The second keeps the row describing where the session is actually being used
    # rather than lagging a day behind, which is what makes it worth showing to the user.
    #
    # Only a value we actually have counts as a change: touch_session keeps the stored one
    # when passed None, so treating a missing User-Agent as different would write on every
    # single request forever. A client whose address genuinely changes per request (a rotating
    # proxy pool in front of a trusted verify_xff_header) does pay a write per request.
    last_ip = client_address(request).host
    user_agent = request.headers.get("User-Agent")
    moved = (last_ip and session["last_ip"] != last_ip) or (user_agent and session["user_agent"] != user_agent)

    if moved or new_expires > session["expires"] + SESSION_REFRESH_THRESHOLD:
        await sabnzbd.session_store.touch_session(
            token_hash,
            new_expires,
            last_ip=last_ip,
            user_agent=user_agent,
        )

    return True


async def validate_any_session(request: Request) -> bool:
    """Return True when the request carries a session cookie this instance issued: the
    anonymous tag, or a database-backed login session. For the places that ask "did this
    client load a page from us" rather than "who is this client" — the CSRF guard, the
    anonymous-cookie issuing check and API authorization. The anonymous check comes
    first: it is a pure HMAC compare, and a request without a cookie never reaches the
    database either, so neither steady-state path pays for a lookup."""
    return validate_anonymous_session(request) or await validate_session(request)


async def check_login(request: Request) -> bool:
    """Check if user is logged in (Starlette version)"""
    # No authentication required, or waived for this client
    if login_bypassed(request):
        return True

    # Check the session cookie
    return await validate_session(request)


async def check_apikey(request: Request) -> Optional[Response]:
    """Check session cookie, API-key or NZB-key (Starlette version)
    Return None when OK, otherwise the error response to send
    """
    mode = request_params(request).get("mode", "")

    # Resolve the call once here and stash it on the request, so the /api route can
    # dispatch through api_handler without consulting the api table a second time.
    entry, argument = sabnzbd.api.resolve_api_call(request_params(request))
    request.state.api_call = (entry, argument)

    # The entry carries the access level required for this specific api-call
    req_access = entry.access_level
    if not check_access(request, access_type=req_access, warn_user=True):
        return forbidden(_MSG_ACCESS_DENIED)

    # Skip for auth and version calls
    if mode in ("version", "auth"):
        return None

    # A valid browser session (login or anonymous cookie) authorizes API calls without the
    # apikey, so the frontend no longer needs the key embedded in the page — but only when it
    # also echoes that session's CSRF token in the header, which no cross-site page can set.
    # That header is what protects the API: unlike the cookie it is neither sent automatically
    # nor settable by a form, an image or a navigation, and a cross-origin fetch that sets it
    # is preflighted, which SABnzbd answers with a bare 405. Header only, so that stays true:
    # this route merges the query string into its params, so honouring the field as well would
    # accept a token from a URL.
    cookie_ok = await validate_any_session(request)
    if cookie_ok and csrf_token_matches(request, header_only=True):
        return None

    # Deliberately no early return above: a request that carries both a cookie and a valid
    # apikey has to stay authorized here.
    key = request_params(request).get("apikey")
    if key:
        # Constant-time, like the login credentials: these are the other secrets a client can
        # guess at, and a byte-by-byte == leaks how far a guess got in the response time
        if req_access == 1 and constant_time_equals(key, cfg.nzb_key()):
            return None
        if constant_time_equals(key, cfg.api_key()):
            return None
        log_warning_and_ip(
            request, T("API Key incorrect, Use the api key from Config->General in your 3rd party program:")
        )
        return forbidden(_MSG_APIKEY_INCORRECT)

    if SESSION_COOKIE in request.cookies:
        # A cookie was presented, so this is a browser rather than a keyless 3rd-party
        # program and the apikey advice below would only mislead. It is still warned about:
        # staying silent whenever a cookie is present let anyone suppress the warning, and
        # any log-watching it feeds, by sending along a junk cookie.
        log_warning_and_ip(request, T("Refused connection from:"))
        # 401 only where reloading the page genuinely fixes it, because that is how the
        # frontend answers a 401: a session that no longer validates (a restart regenerated
        # the anonymous key, the login session expired, credentials changed), or a token from
        # before a restart rotated _CSRF_KEY. A valid session sending no token at all is not
        # something a reload repairs, so it gets a 403 instead of an endless reload loop.
        if not cookie_ok or presented_csrf_token(request, header_only=True):
            return PlainTextResponse(_MSG_SESSION_EXPIRED, status_code=401)
        return forbidden(_MSG_MISSING_SESSION)

    log_warning_and_ip(
        request, T("API Key missing, please enter the api key from Config->General into your 3rd party program:")
    )
    return forbidden(_MSG_APIKEY_REQUIRED)


def template_filtered_response(file: str, search_list: dict[str, Any], status_code: int = 200):
    """Wrapper for Cheetah response"""
    # We need a copy, because otherwise source-dicts might be modified
    search_list_copy = copy.deepcopy(search_list)
    # 'filters' is excluded because the RSS-filters are listed twice
    recursive_html_escape(search_list_copy, exclude_items=("webdir", "filters"))
    return HTMLResponse(
        Template(file=file, searchList=[search_list_copy], compilerSettings=CHEETAH_DIRECTIVES).respond(),
        status_code=status_code,
    )


def log_warning_and_ip(request: Request, txt: str):
    """Include the IP and the Proxy-IP for warnings (Starlette version)"""
    if cfg.api_warnings():
        logging.warning("%s %s", txt, client_address_info(request))


# CherryPy collapsed these API routing/scalar keys to their first value when a key
# was supplied more than once (e.g. ?mode=queue&mode=version resolved to "queue"),
# whereas Starlette's .get() would otherwise return the last. Dispatch and the
# handlers still assume a single value, so the merged API routes reproduce this.
# Genuinely multi-valued keys (keyword, file uploads) are left alone so getlist()
# still sees every value.
API_FIRST_WINS_KEYS = ("mode", "name", "value", "value2", "value3", "start", "limit", "search")


def is_form_post(request: Request) -> bool:
    return request.method == "POST" and request.headers.get("content-type", "").startswith(
        ("application/x-www-form-urlencoded", "multipart/form-data")
    )


async def get_request_params(request: Request, merge_query: bool = False) -> MultiDict | QueryParams:
    """Parse the request's parameters.

    A page GET renders a page and never changes state, so only the URL query
    string is used, returned as the request's immutable QueryParams. A page POST
    reads the form body only (urlencoded or multipart, with file uploads kept as
    UploadFile objects) into a mutable MultiDict; the query string is ignored, so
    parameters cannot be smuggled into form handlers via the URL. A POST without a
    form body yields an empty MultiDict.

    The merged API route (merge_query, i.e. /api, the only route left with
    check_api_key) keeps the CherryPy behavior instead: 3rd-party clients
    traditionally POST an NZB as a multipart body while passing mode/apikey/output
    in the query string, so the form body and query string are merged into a
    mutable MultiDict, the body winning per key. A key supplied only in the query
    string keeps all of its values. GET, form POST and bodyless POST all take this
    same path, so a duplicated key resolves identically regardless of method, and
    the API scalar keys collapse to their first value exactly as CherryPy did.

    ParamsMiddleware stores the result on request.state.params so that
    request_params(request) returns it in every handler without an extra await.
    """
    if not merge_query:
        if is_form_post(request):
            return MultiDict(await request.form())
        return MultiDict() if request.method == "POST" else request.query_params

    # Start from the form body (if any) so it wins per key, then add query-string
    # values for keys the body did not set.
    params = MultiDict(await request.form()) if is_form_post(request) else MultiDict()
    body_keys = set(params.keys())
    for key, value in request.query_params.multi_items():
        if key not in body_keys:
            params.append(key, value)

    # Collapse the API scalar keys to their first value
    for key in API_FIRST_WINS_KEYS:
        if len(values := params.getlist(key)) > 1:
            params[key] = values[0]
    return params


def request_params(request: Request) -> MultiDict | QueryParams:
    """The request's parameters, parsed once by ParamsMiddleware: the query
    string for a page GET, the form body for a page POST, or the form body
    merged with the query string for the API routes. See get_request_params
    for the exact rules and the returned types."""
    return request.state.params


class ParamsMiddleware:
    """Parse a request's parameters onto request.state.params before the handler
    runs, so request_params(request) returns them without a further await. Attached
    per route by secured_expose because the merge behavior is route-specific:
    merge_query follows check_api_key, so only /api accepts mode/apikey in the query
    string alongside a form body. Pure ASGI, and the request body is read once here;
    handlers only ever read the parsed params."""

    def __init__(self, app, merge_query: bool = False):
        self.app = app
        self.merge_query = merge_query

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            request = Request(scope, receive)
            request.state.params = await get_request_params(request, merge_query=self.merge_query)
        await self.app(scope, receive, send)


def _anonymous_session_sender(request: Request, send):
    """Wrap an ASGI send so the anonymous session cookie is added to the response start.
    SecurityMiddleware is pure ASGI, so there is no Response object to set the cookie on;
    create_anonymous_session builds it on a throwaway Response and its Set-Cookie header
    is injected into the http.response.start message."""
    carrier = Response()
    create_anonymous_session(request, carrier)
    cookie_headers = [(key, value) for key, value in carrier.raw_headers if key == b"set-cookie"]

    async def send_with_cookie(message):
        if message["type"] == "http.response.start":
            message["headers"] = list(message.get("headers", [])) + cookie_headers
        await send(message)

    return send_with_cookie


class SecurityMiddleware:
    """Enforce a route's access rules before its handler runs: config lock, local vs
    external access, login, and API key. Attached per route by secured_expose with
    that route's flags, and ordered after ParamsMiddleware so the API-key check can
    read the parsed request_params. Pure ASGI; a failed check answers with a 403 (or
    a redirect to /login) without ever invoking the handler."""

    def __init__(
        self,
        app,
        check_configlock: bool = False,
        check_for_login: bool = True,
        check_api_key: bool = False,
        check_csrf: bool = True,
        access_type: int = 4,
    ):
        self.app = app
        self.check_configlock = check_configlock
        self.check_for_login = check_for_login
        self.check_api_key = check_api_key
        self.check_csrf = check_csrf
        self.access_type = access_type

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            request = Request(scope, receive)
            if response := await self.denied_response(request):
                return await response(scope, receive, send)
            # Whenever the login is bypassed (see login_bypassed), issue a stateless anonymous
            # session cookie on the UI page routes so the frontend authenticates API calls by
            # cookie instead of the apikey, and POSTs pass the CSRF guard in denied_response.
            # Limited to check_for_login routes (the real UI pages) so bots hitting
            # robots.txt/favicon and the login/logout routes don't get one, and API routes never
            # set it: the browser always loads a page (and its cookie) first. Skipped when the
            # client already holds a usable session, so a login session created before the
            # bypass applied (a laptop that was remote and is now on the local network) is not
            # overwritten by the anonymous tag. Pure ASGI, so the cookie is injected into the
            # response start rather than onto a Response.
            if (
                self.check_for_login
                and not self.check_api_key
                and login_bypassed(request)
                and not await validate_any_session(request)
            ):
                send = _anonymous_session_sender(request, send)
                # The handler renders the page before that Set-Cookie reaches the client, so
                # the token it embeds has to belong to the cookie we are about to issue, not
                # to the absent or stale one this request arrived with. Getting this wrong
                # ships a token matching nothing on every first page load.
                request.state.csrf_token = csrf_token_for(anonymous_session_tag())
            else:
                request.state.csrf_token = csrf_token_for(request.cookies.get(SESSION_COOKIE, ""))
        await self.app(scope, receive, send)

    async def denied_response(self, request: Request) -> Optional[Response]:
        """Return the response to send when a check fails, or None when allowed."""
        # Check if config is locked
        if self.check_configlock and cfg.configlock():
            return forbidden(_MSG_ACCESS_DENIED_CONFIG_LOCK)

        # Check if external access and if it's allowed
        if not check_access(request, access_type=self.access_type, warn_user=True):
            return forbidden(_MSG_ACCESS_DENIED)

        # A client that presented an apikey to a route that does not take one is automation
        # reaching for the interface's own pages. Both refusals below then say so plainly
        # rather than sending it to the login form or talking about session tokens: it is not
        # a browser to redirect, and a client that followed the redirect would read the form's
        # 200 as success. Only consulted when the request is refused anyway, so a stray apikey
        # on a URL a logged-in browser opens still just gets the page.
        offered_apikey = not self.check_api_key and bool(
            request_params(request).get("apikey") or request.query_params.get("apikey")
        )

        # Verify login status, only for non-key pages
        if self.check_for_login and not self.check_api_key and not await check_login(request):
            if offered_apikey:
                log_warning_and_ip(request, T("Refused connection from:"))
                return forbidden(_MSG_APIKEY_NOT_ON_PAGES)
            return base_redirect_response("/login")

        # CSRF guard for state-changing requests: a page POST has to echo the token belonging
        # to its session, which only a page served by this instance could have read. Applies to
        # every such route unconditionally, rather than only where login_bypassed() holds:
        # check_login is not a CSRF defence in either case. Where it passes with no cookie the
        # request carries no proof of origin at all, and where it requires the login cookie it
        # is relying on SameSite=Strict, which is not origin-scoped — a page served from
        # another port on the same host is same-site and its forms do send the cookie.
        if self.check_csrf and request.method == "POST" and not await validate_csrf(request):
            log_warning_and_ip(request, T("Refused connection from:"))
            return forbidden(_MSG_APIKEY_NOT_ON_PAGES if offered_apikey else _MSG_MISSING_SESSION)

        # The /api route: session cookie or apikey (see check_apikey), which returns
        # the error response to send (403, or 401 for a stale frontend session)
        if self.check_api_key and (error_response := await check_apikey(request)):
            return error_response

        return None


def forbidden(message: str) -> PlainTextResponse:
    """403 response, carrying the reason only when api_warnings is enabled."""
    return PlainTextResponse(message if cfg.api_warnings() else "", status_code=403)


# Disable over-active logging for the form parser
logging.getLogger("python_multipart.multipart").setLevel(logging.WARNING)


##############################################################################
# Helper redirect functions
##############################################################################


def base_redirect_response(root: str = "", **kwargs) -> RedirectResponse:
    """Create a Starlette RedirectResponse with SABnzbd URL base and query parameters"""
    url = url_for(root, **kwargs)

    # Log the redirect if API logging is enabled
    if cfg.api_logging():
        logging.debug("Redirecting to %s", url)

    return RedirectResponse(url=url, status_code=302)


##############################################################################
# Page definitions - Main
##############################################################################


@secured_expose(route="/", methods=["GET"])
def main_index(request: Request):
    # Redirect to wizard if no servers are set
    if request_params(request).get("skip_wizard") or config.get_servers():
        info = build_header(request=request)

        info["have_rss_defined"] = bool(config.get_rss())
        info["have_watched_dir"] = bool(cfg.dirscan_dir())
        info["cpumodel"] = get_cpu_name()
        info["cpusimd"] = sabnzbd.decoder.SABCTOOLS_SIMD
        info["platform"] = sabnzbd.PLATFORM

        # Have logout only if inet=5, only when we are external
        info["have_logout"] = (
            cfg.username()
            and cfg.password()
            and (cfg.inet_exposure() < 5 or (cfg.inet_exposure() == 5 and not check_access(request, access_type=6)))
        )

        bytespersec_list = sabnzbd.BPSMeter.get_bps_list()
        info["bytespersec_list"] = ",".join([str(bps) for bps in bytespersec_list])

        return template_filtered_response(file=os.path.join(sabnzbd.WEB_DIR, "main.tmpl"), search_list=info)
    else:
        # Redirect to the setup wizard
        return base_redirect_response("/wizard")


@secured_expose(route="/shutdown")
async def shutdown(request: Request):
    """Shut down and show a goodbye page, for UI users; automation should use
    the mode=shutdown API-call. Only a POST shuts down: the UI submits it as a
    form, so the browser navigates to this response, and it is authorized like
    any other page POST — a SameSite=Strict session cookie (login or anonymous),
    which a cross-site page cannot send, so it cannot trigger a shutdown. A GET
    (stale bookmark, typed URL or pre-1.x link) must never shut down anything
    and is sent back to the main page."""
    if request.method != "POST":
        return base_redirect_response("/")

    await halt_and_shutdown()
    return PlainTextResponse(T("SABnzbd shutdown finished"))


# check_csrf=False: the API has its own rule, enforced in check_apikey, because only that
# function knows whether the cookie or the apikey authorized the call. Applying the page
# guard here as well would reject 3rd-party clients that send a valid key.
@secured_expose(route="/api", check_api_key=True, check_csrf=False, access_type=1)
async def api(request: Request):
    """Redirect to API-handler, we check the access_type in the API-handler"""
    return await api_handler(request_params(request), request.state.api_call)


@secured_expose(route="/log", methods=["POST"])
def log(request: Request):
    """Download the log plus a sanitized copy of the ini, for the Help window's log button.

    A page route rather than a link to the mode=showlog API-call because the interface reaches
    it by navigating: a navigation cannot carry the CSRF header a cookie-authorized API call
    requires, but a form can carry the token as a field, which page routes accept.

    POST rather than GET, even though it changes nothing, so that the rule stays plain --
    nothing sensitive is served without the token. This hands out the log and a copy of the
    ini, and a GET would be reachable as a cross-site navigation: the response is not readable
    cross-origin, but a victim could still be made to download their own log. Automation keeps
    using mode=showlog with an apikey."""
    return build_log_response()


@secured_expose(route="/scriptlog", methods=["GET"])
def scriptlog(request: Request):
    """Needed for all skins, URL is fixed due to postproc"""
    # The URL is fixed and stored in the history database, so it carries no apikey. It needs
    # no CSRF token either, being a read-only GET, and is behind the login like any other page.
    if name := request_params(request).get("name"):
        with sabnzbd.db_pool.connection() as history_db:
            return PlainTextResponse(history_db.get_script_log(name))
    return PlainTextResponse("")


@secured_expose(route="/robots.txt", check_for_login=False, methods=["GET"])
def robots_txt(request: Request):
    """Keep web crawlers out"""
    return PlainTextResponse("User-agent: *\nDisallow: /\n")


@secured_expose(route="/description.xml", check_for_login=False, methods=["GET"])
def description_xml(request: Request):
    """Provide the description.xml which was broadcast via SSDP"""
    if is_lan_addr(client_address(request).host):
        response = Response(content=sabnzbd.utils.ssdp.server_ssdp_xml(), media_type="application/xml")
        return response
    else:
        return Response(status_code=404)


@secured_expose(route="/favicon.ico", check_for_login=False, methods=["GET"])
def favicon_ico(request: Request):
    """Provide the favicon.ico"""
    return FileResponse(os.path.join(sabnzbd.WEB_DIR_CONFIG, "staticcfg", "ico", "favicon.ico"))


##############################################################################
# Page definitions - Wizard
##############################################################################


@secured_expose(route="/wizard", check_configlock=True, methods=["GET"])
def wizard_index(request: Request):
    """Show the language selection page"""
    if sabnzbd.WINDOWS:
        from sabnzbd.utils.apireg import get_install_lng

        cfg.language.set(get_install_lng())
        logging.debug('Installer language code "%s"', cfg.language())

    info = build_header(sabnzbd.WIZARD_DIR, request=request)
    info["languages"] = list_languages()

    return template_filtered_response(file=os.path.join(sabnzbd.WIZARD_DIR, "index.html"), search_list=info)


@secured_expose(route="/wizard/one", check_configlock=True, methods=["GET", "POST"])
def wizard_page_one(request: Request):
    """Accept language (POSTed by the index page form) and show server page.
    A GET only renders the page, e.g. when navigating back from page two."""
    if request.method == "POST" and request_params(request).get("lang"):
        cfg.language.set(request_params(request).get("lang"))

    info = build_header(sabnzbd.WIZARD_DIR, request=request)

    # Just in case, add server
    servers = config.get_servers()
    if not servers:
        info["server"] = ""
        info["host"] = ""
        info["port"] = ""
        info["username"] = ""
        info["password"] = ""
        info["connections"] = ""
        info["ssl"] = 1
        info["ssl_verify"] = 2
        info["pipelining_requests"] = sabnzbd.constants.DEF_PIPELINING_REQUESTS
    else:
        # Sort servers to get the first enabled one
        server_names = sorted(
            servers,
            key=lambda svr: "%d%02d%s"
            % (int(not servers[svr].enable()), servers[svr].priority(), servers[svr].displayname().lower()),
        )
        for server in server_names:
            # If there are multiple servers, just use the first enabled one
            s = servers[server]
            info["server"] = server
            info["host"] = s.host()
            info["port"] = s.port()
            info["username"] = s.username()
            info["password"] = s.password.get_stars()
            info["connections"] = s.connections()
            info["ssl"] = s.ssl()
            info["ssl_verify"] = s.ssl_verify()
            info["pipelining_requests"] = s.pipelining_requests()
            if s.enable():
                break
    return template_filtered_response(file=os.path.join(sabnzbd.WIZARD_DIR, "one.html"), search_list=info)


@secured_expose(route="/wizard/two", check_configlock=True, methods=["GET", "POST"])
def wizard_page_two(request: Request):
    """Accept server (POSTed by the page one form) and show the final page for restart.
    A GET only renders the page: handle_server mutates its parameters, which is
    only valid for the mutable form MultiDict of a POST, and saving state on GET
    would invite replays from the browser history."""
    # Save server details if submitted — no host means the user skipped server setup
    if request.method == "POST" and request_params(request).get("host"):
        handle_server(request_params(request))

    # Show Restart screen
    info = build_header(sabnzbd.WIZARD_DIR, request=request)

    info["urls"] = get_access_info(request)
    info["download_dir"] = cfg.download_dir.get_clipped_path()
    info["complete_dir"] = cfg.complete_dir.get_clipped_path()

    return template_filtered_response(file=os.path.join(sabnzbd.WIZARD_DIR, "two.html"), search_list=info)


def get_access_info(request: Optional[Request] = None) -> list[str]:
    """Build up a list of url's that sabnzbd can be accessed from"""
    web_host = cfg.web_host()
    host = socket.gethostname().lower()
    socks = [host]

    try:
        addresses = socket.getaddrinfo(host, None)
    except Exception:
        addresses = []

    if web_host == "0.0.0.0":
        # Grab a list of all ips for the hostname
        for addr in addresses:
            address = addr[4][0]
            # Filter out ipv6 addresses (should not be allowed)
            if ":" not in address and address not in socks:
                socks.append(address)
        socks.insert(0, "localhost")
    elif web_host == "::":
        # Grab a list of all ips for the hostname
        for addr in addresses:
            address = addr[4][0]
            # Only ipv6 addresses will work
            if ":" in address:
                address = "[%s]" % address
                if address not in socks:
                    socks.append(address)
        socks.insert(0, "localhost")
    elif web_host:
        socks = [web_host]

    # Lead with the URL this page was actually reached by, which is the one we know works.
    # Built from the origin rather than url_for() so it matches the bare "scheme://host+base"
    # shape of the entries below and dedupes against them.
    urls = set()
    if request:
        base_url = str(request.base_url).rstrip("/")
        url_base = cfg.url_base().lstrip("/")
        urls.add(f"{base_url}/{url_base}" if url_base else base_url)

    if cfg.enable_https():
        scheme = "https"
        port = cfg.https_port() or cfg.web_port()
    else:
        scheme = "http"
        port = cfg.web_port()

    for sock in socks:
        if sock:
            urls.add("%s://%s%s" % (scheme, url_netloc(sock, scheme, port), cfg.url_base()))

    # Return a unique list, with HTTPS URLs first
    return sorted(urls, key=lambda url: (not url.startswith("https://"), url))


##############################################################################
# Page definitions - Login
##############################################################################


# check_csrf=False: a login POST is the one state-changing request that can legitimately
# arrive from a client that has never held a session, so demanding a token would make
# logging in impossible. Login CSRF only lets an attacker log the victim in as themselves.
@secured_expose(route="/login", check_for_login=False, check_csrf=False)
async def login_index(request: Request):
    # Already logged in, or no username/password set at all
    if await check_login(request):
        return base_redirect_response("/")

    # Check login info
    error = None
    status_code = 200
    retry_after = 0
    if request.method == "POST":
        if retry_after := login_cooldown_remaining(request):
            # Refused without looking at what was submitted: the whole point is to deny this
            # client another guess, and checking anyway would let it keep testing passwords
            # for as long as it is willing to be told no.
            error = T("Too many failed login attempts, try again later.")
            status_code = 429
            logging.warning(T("Login attempt refused, too many failures from %s"), client_address_info(request))
        else:
            username = request_params(request).get("username")
            password = request_params(request).get("password")
            remember_me = bool(request_params(request).get("remember_me", False))

            # Constant-time comparison of submitted credentials against the configured
            # username/password. Both fields are always compared (no short-circuit), so
            # neither the comparison time nor an early exit leaks which field matched.
            username_ok = constant_time_equals(username or "", cfg.username())
            password_ok = constant_time_equals(password or "", cfg.password())
            if username_ok and password_ok:
                # Proved it knows the password
                clear_login_failures(request)
                # Create redirect response
                response = base_redirect_response("/")
                # Create a database-backed session and set the session cookie
                if await create_session(request, response, remember_me=remember_me):
                    # Log the success
                    logging.info("Successful login from %s", client_address_info(request))
                    return response
                # The session could not be stored
                error = T("The login session could not be stored, see the log for details.")
                status_code = 500
                logging.warning("Login from %s failed: the session could not be stored", client_address_info(request))
            elif username or password:
                error = T("Authentication failed, check username/password.")
                record_login_failure(request)
                # Warn about the potential security problem
                logging.warning(T("Unsuccessful login attempt from %s"), client_address_info(request))

    # Show login. Building the header and rendering the Cheetah template are
    # blocking work, so keep them off the event loop.
    def render_login_page():
        info = build_header(sabnzbd.WEB_DIR_CONFIG)
        info["error"] = error
        response = template_filtered_response(
            file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "login", "main.tmpl"),
            search_list=info,
            status_code=status_code,
        )
        if retry_after:
            # Say how long the cooldown has left, so an automated client waits it out instead
            # of hammering the form and filling the log with refusals
            response.headers["Retry-After"] = str(retry_after)
        return response

    return await run_in_threadpool(render_login_page)


@secured_expose(route="/logout", methods=["POST"])
async def logout(request: Request):
    """Clear the session and return to the main page. POST-only and the UI submits it
    as a form, like /shutdown, and authorized like any other page POST — the login
    check (or the CSRF guard when no credentials are set) requires the SameSite=Strict
    session cookie, which a cross-site page cannot send, so a stray GET (an <img> or
    link prefetch) or a forged cross-site form cannot log the user out."""
    response = base_redirect_response("/")
    await clear_session(request, response)
    return response


##############################################################################
# Page definitions - Config - General
##############################################################################


@secured_expose(route="/config", check_configlock=True, methods=["GET"])
def config_general_index(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)
    conf["configfn"] = clip_path(config.get_filename())
    conf["cmdline"] = sabnzbd.CMDLINE
    conf["build"] = sabnzbd.__baseline__[:7]

    conf["have_7zip"] = bool(sabnzbd.newsunpack.SEVENZIP_COMMAND)
    conf["have_sabctools"] = sabnzbd.decoder.SABCTOOLS_ENABLED
    conf["have_par2_turbo"] = sabnzbd.newsunpack.PAR2_TURBO
    conf["ssl_version"] = ssl.OPENSSL_VERSION

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config.tmpl"),
        search_list=conf,
    )


##############################################################################
# Page definitions - Config - Folders
##############################################################################
LIST_DIRPAGE = (
    "download_dir",
    "download_free",
    "complete_dir",
    "complete_free",
    "admin_dir",
    "nzb_backup_dir",
    "dirscan_dir",
    "dirscan_speed",
    "script_dir",
    "email_dir",
    "permissions",
    "log_dir",
    "backup_dir",
    "password_file",
)

LIST_BOOL_DIRPAGE = ("fulldisk_autoresume",)


@secured_expose(route="/config/folders", check_configlock=True, methods=["GET"])
def index_config_folders(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)
    conf["file_exts"] = ", ".join(VALID_NZB_FILES + VALID_ARCHIVES)

    for kw in LIST_DIRPAGE + LIST_BOOL_DIRPAGE:
        conf[kw] = config.get_config("misc", kw)()

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config_folders.tmpl"),
        search_list=conf,
    )


@secured_expose(route="/config/folders/save", check_configlock=True, methods=["POST"])
def config_folder_save(request: Request):
    for kw in LIST_DIRPAGE + LIST_BOOL_DIRPAGE:
        if msg := config.get_config("misc", kw).set(request_params(request).get(kw)):
            return report(request_params(request), error=msg)

    config.save_config()
    return report(request_params(request))


##############################################################################
# Page definitions - Config - Switches
##############################################################################
SWITCH_LIST = (
    "par_option",
    "top_only",
    "direct_unpack",
    "win_process_prio",
    "auto_sort",
    "propagation_delay",
    "auto_disconnect",
    "flat_unpack",
    "safe_postproc",
    "no_dupes",
    "replace_underscores",
    "replace_spaces",
    "replace_dots",
    "ignore_samples",
    "pause_on_post_processing",
    "nice",
    "ionice",
    "pre_script",
    "end_queue_script",
    "pause_on_pwrar",
    "sfv_check",
    "deobfuscate_final_filenames",
    "folder_rename",
    "quota_size",
    "quota_day",
    "quota_resume",
    "quota_period",
    "history_retention_option",
    "history_retention_number",
    "pre_check",
    "max_art_tries",
    "fail_hopeless_jobs",
    "enable_all_par",
    "enable_recursive",
    "no_smart_dupes",
    "dupes_propercheck",
    "script_can_fail",
    "unwanted_extensions",
    "action_on_unwanted_extensions",
    "unwanted_extensions_mode",
    "cleanup_list",
    "sanitize_safe",
)


@secured_expose(route="/config/switches", check_configlock=True, methods=["GET"])
def index_config_switches(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)
    conf["have_nice"] = bool(sabnzbd.newsunpack.NICE_COMMAND)
    conf["have_ionice"] = bool(sabnzbd.newsunpack.IONICE_COMMAND)

    for kw in SWITCH_LIST:
        conf[kw] = config.get_config("misc", kw)()
    conf["cleanup_list"] = cfg.cleanup_list.get_string()
    conf["unwanted_extensions"] = cfg.unwanted_extensions.get_string()

    conf["scripts"] = list_scripts() or ["None"]

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config_switches.tmpl"),
        search_list=conf,
    )


@secured_expose(route="/config/switches/save", check_configlock=True, methods=["POST"])
def config_switches_save(request: Request):
    for kw in SWITCH_LIST:
        if msg := config.get_config("misc", kw).set(request_params(request).get(kw)):
            return report(request_params(request), error=msg)

    config.save_config()
    return report(request_params(request))


##############################################################################
# Page definitions - Config - Special
##############################################################################
SPECIAL_BOOL_LIST = (
    "start_paused",
    "preserve_paused_state",
    "no_penalties",
    "ipv6_servers",
    "ipv6_staging",
    "fast_fail",
    "overwrite_files",
    "enable_par_cleanup",
    "process_unpacked_par2",
    "queue_complete_pers",
    "api_warnings",
    "helpful_warnings",
    "ampm",
    "enable_unrar",
    "enable_7zip",
    "enable_filejoin",
    "enable_tsjoin",
    "enable_tar",
    "ignore_unrar_dates",
    "tray_icon",
    "allow_incomplete_nzb",
    "rss_filenames",
    "ipv6_hosting",
    "keep_awake",
    "new_nzb_on_failure",
    "disable_archive",
    "wait_for_dfolder",
    "enable_broadcast",
    "warn_dupl_jobs",
    "backup_for_duplicates",
    "api_logging",
    "x_frame_options",
    "allow_old_ssl_tls",
    "enable_season_sorting",
    "verify_xff_header",
    "direct_write",
)
SPECIAL_VALUE_LIST = (
    "downloader_sleep_time",
    "size_limit",
    "nomedia_marker",
    "max_url_retries",
    "req_completion_rate",
    "wait_ext_drive",
    "max_foldername_length",
    "url_base",
    "receive_threads",
    "assembler_max_queue_size",
    "switchinterval",
    "direct_unpack_threads",
    "selftest_host",
    "ssdp_broadcast_interval",
    "unrar_parameters",
    "outgoing_nntp_ip",
)
SPECIAL_LIST_LIST = (
    "rss_odd_titles",
    "quick_check_ext_ignore",
    "host_whitelist",
    "local_ranges",
    "ext_rename_ignore",
)


@secured_expose(route="/config/special", check_configlock=True, methods=["GET"])
def index_config_special(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)
    conf["switches"] = [
        (kw, config.get_config("misc", kw)(), config.get_config("misc", kw).default) for kw in SPECIAL_BOOL_LIST
    ]
    conf["entries"] = [
        (kw, config.get_config("misc", kw)(), config.get_config("misc", kw).default) for kw in SPECIAL_VALUE_LIST
    ]
    conf["entries"].extend(
        [
            (kw, config.get_config("misc", kw).get_string(), config.get_config("misc", kw).default_string())
            for kw in SPECIAL_LIST_LIST
        ]
    )

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config_special.tmpl"),
        search_list=conf,
    )


@secured_expose(route="/config/special/save", check_configlock=True, methods=["POST"])
def config_special_save(request: Request):
    for kw in SPECIAL_BOOL_LIST + SPECIAL_VALUE_LIST + SPECIAL_LIST_LIST:
        if msg := config.get_config("misc", kw).set(request_params(request).get(kw)):
            return report(request_params(request), error=msg)

    config.save_config()
    return report(request_params(request))


##############################################################################
# Page definitions - Config - General
##############################################################################
GENERAL_LIST = (
    "host",
    "port",
    "username",
    "language",
    "cache_limit",
    "inet_exposure",
    "enable_https",
    "https_port",
    "https_cert",
    "https_key",
    "https_chain",
    "enable_https_verification",
    "socks5_proxy_url",
    "auto_browser",
    "check_new_rel",
    "bandwidth_max",
    "bandwidth_perc",
)


@secured_expose(route="/config/general", check_configlock=True, methods=["GET"])
def index_config_general(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)

    web_list = []
    for interface_dir in globber_full(sabnzbd.DIR_INTERFACES):
        # Ignore the config
        if not interface_dir.endswith(DEF_STD_CONFIG):
            # Check the available templates
            for colorscheme in globber(
                os.path.join(interface_dir, "templates", "static", "stylesheets", "colorschemes")
            ):
                web_list.append("%s - %s" % (setname_from_path(interface_dir), setname_from_path(colorscheme)))

    conf["web_list"] = web_list
    conf["web_dir"] = "%s - %s" % (cfg.web_dir(), cfg.web_color())
    conf["password"] = cfg.password.get_stars()

    conf["language"] = cfg.language()
    conf["lang_list"] = list_languages()
    conf["def_https_cert_file"] = DEF_HTTPS_CERT_FILE

    for kw in GENERAL_LIST:
        conf[kw] = config.get_config("misc", kw)()

    conf["nzb_key"] = cfg.nzb_key()

    # Config -> General is the one page that intentionally displays the user's apikey
    # (for 3rd-party programs); it is no longer part of build_header
    conf["apikey"] = cfg.api_key()

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config_general.tmpl"),
        search_list=conf,
    )


@secured_expose(route="/config/general/save", check_configlock=True, methods=["POST"])
def config_general_save(request: Request):
    # Handle general options
    for kw in GENERAL_LIST:
        if msg := config.get_config("misc", kw).set(request_params(request).get(kw)):
            return report(request_params(request), error=msg)

    # Handle special options
    cfg.password.set(request_params(request).get("password"))

    if web_dir := request_params(request).get("web_dir"):
        if msg := change_web_dir(web_dir):
            return report(request_params(request), error=msg)

    config.save_config()
    return report(request_params(request), data={"success": True, "restart_req": sabnzbd.RESTART_REQ})


@secured_expose(route="/config/general/upload_config", check_configlock=True, methods=["POST"])
async def config_upload_backup(request: Request):
    """Restore a config backup"""
    config_backup_file = request_params(request).get("config_backup_file")

    # Only accept the backup file if it can be opened as a zip archive and only contains a config file
    try:
        config_backup_data = await config_backup_file.read()
        if config.validate_config_backup(config_backup_data):
            sabnzbd.RESTORE_DATA = config_backup_data
            return report(request_params(request), data={"success": True, "restart_req": True})
    except Exception:
        pass
    return report(request_params(request), error=T("Invalid backup archive"))


def change_web_dir(web_dir: str) -> Optional[str]:
    web_dir, web_color = web_dir.split(" - ")
    web_dir_path = real_path(sabnzbd.DIR_INTERFACES, web_dir)

    if not os.path.exists(web_dir_path):
        logging.info("Cannot find web template: %s", web_dir_path)
        return "Cannot find web template: %s" % web_dir_path
    else:
        cfg.web_dir.set(web_dir)
        cfg.web_color.set(web_color)
        return None


##############################################################################
# Page definitions - Config - Server
##############################################################################


@secured_expose(route="/config/server", check_configlock=True, methods=["GET"])
def index_config_server(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)
    new = []
    servers = config.get_servers()
    server_names = sorted(
        servers,
        key=lambda svr: "%d%02d%s"
        % (int(not servers[svr].enable()), servers[svr].priority(), servers[svr].displayname().lower()),
    )
    for svr in server_names:
        new.append(servers[svr].get_dict(for_public_api=True))
        t, m, w, d, daily, articles_tried, articles_success = sabnzbd.BPSMeter.amounts(svr)
        if t:
            new[-1]["amounts"] = (
                to_units(t),
                to_units(m),
                to_units(w),
                to_units(d),
                daily,
                articles_tried,
                articles_success,
            )
        new[-1]["quota_left"] = to_units(
            servers[svr].quota.get_int() - sabnzbd.BPSMeter.grand_total.get(svr, 0) + servers[svr].usage_at_start()
        )

    conf["servers"] = new
    conf["cats"] = list_cats(default=True)

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config_server.tmpl"),
        search_list=conf,
    )


@secured_expose(route="/config/server/add_server", check_configlock=True, methods=["POST"])
def config_server_add(request: Request):
    return handle_server(request_params(request), new_svr=True)


@secured_expose(route="/config/server/save_server", check_configlock=True, methods=["POST"])
def config_server_save(request: Request):
    return handle_server(request_params(request))


@secured_expose(route="/config/server/delete_server", check_configlock=True, methods=["POST"])
def config_server_del(request: Request):
    kw = {"section": "servers", "keyword": request_params(request).get("server")}
    del_from_section(kw)
    return base_redirect_response("/config/server")


@secured_expose(route="/config/server/clear_server", check_configlock=True, methods=["POST"])
def config_server_clr(request: Request):
    server = request_params(request).get("server")
    if server:
        sabnzbd.BPSMeter.clear_server(server)
    return base_redirect_response("/config/server")


@secured_expose(route="/config/server/toggle_server", check_configlock=True, methods=["POST"])
def config_server_toggle(request: Request):
    server = request_params(request).get("server")
    if server:
        svr = config.get_config("servers", server)
        if svr:
            svr.enable.set(not svr.enable())
            config.save_config()
            sabnzbd.Downloader.update_server(server, server)
    return base_redirect_response("/config/server")


def unique_svr_name(server):
    """Return a unique variant on given server name"""
    num = 0
    svr = 1
    new_name = server
    while svr:
        if num:
            new_name = "%s@%d" % (server, num)
        else:
            new_name = "%s" % server
        svr = config.get_config("servers", new_name)
        num += 1
    return new_name


def handle_server(params, new_svr=False):
    """Internal server handler, always returns a JSON response"""
    host = params.get("host", "").strip()
    if not host:
        return report(params, error=T("Server address required"))

    port = params.get("port", "").strip()
    if not port:
        if not params.get("ssl", "").strip():
            port = "119"
        else:
            port = "563"
        params["port"] = port

    if params.get("connections", "").strip() == "":
        params["connections"] = "1"

    if params.get("enable") == "1":
        if not get_fastest_addrinfo(
            host, int_conv(port), int_conv(params.get("timeout"), default=DEF_NETWORKING_TEST_TIMEOUT)
        ):
            return report(params, error=T('Server address "%s:%s" is not valid.') % (host, port))

    # Default server name is just the host name
    server = host

    svr = None
    old_server = params.get("server")
    if old_server:
        svr = config.get_config("servers", old_server)
    if svr:
        server = old_server
    else:
        svr = config.get_config("servers", server)

    if new_svr:
        server = unique_svr_name(server)

    for kw in ("ssl", "enable", "required", "optional"):
        if kw not in params.keys():
            params[kw] = None
    if svr and not new_svr:
        svr.set_dict(params)
    else:
        old_server = None
        config.ConfigServer(server, params)

    config.save_config()
    sabnzbd.Downloader.update_server(old_server, server)
    return report(params)


##############################################################################
# Standalone RSS filter functions (used by both route handlers and api.py)
##############################################################################


def do_upd_rss_filter(kwargs):
    """Update or add an RSS filter. Called by route handler and api.py.

    Performs the config mutation and re-evaluates the feed against the new
    filters so the cached match log reflects the change. Holds no UI state.
    """
    try:
        feed_cfg = config.get_rss()[kwargs.get("feed")]
    except KeyError:
        return

    pp = kwargs.get("pp", "")
    if is_none(pp):
        pp = ""
    script = ConvertSpecials(kwargs.get("script"))
    cat = ConvertSpecials(kwargs.get("cat"))
    prio = ConvertSpecials(kwargs.get("priority"))
    filt = kwargs.get("filter_text")
    enabled = kwargs.get("enabled", "0")

    if filt:
        feed_cfg.filters.update(
            int(kwargs.get("index", 0)),
            [cat, pp, script, kwargs.get("filter_type"), filt, prio, enabled],
        )

        # Move filter if requested
        index = int_conv(kwargs.get("index", ""))
        new_index = kwargs.get("new_index", "")
        if new_index and int_conv(new_index) != index:
            feed_cfg.filters.move(int(index), int_conv(new_index))

        config.save_config()
    # Re-evaluate cached items against the updated filters (no network read-out)
    sabnzbd.RSSReader.process_feed(kwargs.get("feed"), readout=False)


def do_del_rss_filter(kwargs):
    """Delete an RSS filter. Called by route handler and api.py.

    Performs the config mutation and re-evaluates the feed. Holds no UI state.
    """
    try:
        feed_cfg = config.get_rss()[kwargs.get("feed")]
    except KeyError:
        return

    feed_cfg.filters.delete(int(kwargs.get("index", 0)))
    config.save_config()
    # Re-evaluate cached items against the remaining filters (no network read-out)
    sabnzbd.RSSReader.process_feed(kwargs.get("feed"), readout=False)


##############################################################################
# Config - RSS (standalone route functions)
##############################################################################


_RSS_ROOT = "/config/rss"


def _rss_redirect(feed: str = "") -> RedirectResponse:
    """Redirect back to the RSS page, optionally selecting a feed."""
    if feed:
        return base_redirect_response(_RSS_ROOT, feed=feed)
    return base_redirect_response(_RSS_ROOT)


def _rss_flash_redirect(request: Request, feed: str, msg: str = "") -> RedirectResponse:
    """Store a feed read-out result as a one-shot flash in the client session and
    redirect back to the RSS page. The flash lives in the per-client signed
    session cookie rather than shared module state, so concurrent requests (other
    tabs, the API path) can't clobber each other's result."""
    request.session["rss_flash"] = {"feed": feed, "msg": msg}
    return _rss_redirect(feed)


@secured_expose(route="/config/rss", check_configlock=True, methods=["GET"])
def config_rss_index(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)

    conf["scripts"] = list_scripts(default=True)
    pick_script = conf["scripts"] != []

    conf["categories"] = list_cats(default=True)
    pick_cat = conf["categories"] != []

    conf["rss_rate"] = cfg.rss_rate()

    rss = {}
    feeds = config.get_rss()
    for feed in feeds:
        rss[feed] = feeds[feed].get_dict()
        filters = feeds[feed].filters()
        rss[feed]["filters"] = filters
        rss[feed]["filter_states"] = [bool(sabnzbd.rss.convert_filter(f[4])) for f in filters]
        rss[feed]["filtercount"] = len(filters)

        rss[feed]["pick_cat"] = pick_cat
        rss[feed]["pick_script"] = pick_script
        rss[feed]["link"] = urllib.parse.quote_plus(feed)
        rss[feed]["baselink"] = [get_base_url(uri) for uri in rss[feed]["uri"]]
        rss[feed]["uris"] = feeds[feed].uri.get_string()

    active_feed = request_params(request).get("feed", "")
    conf["active_feed"] = active_feed
    conf["rss"] = rss
    conf["rss_next"] = time.strftime(time_format("%H:%M"), time.localtime(sabnzbd.RSSReader.next_run))

    if active_feed:
        # This is a plain GET: no feed processing happens here. Any read-out or
        # re-evaluation is performed by the POST action handler that redirected
        # us, which leaves its result message as a one-shot flash in the session.
        flash = request.session.pop("rss_flash", None)
        conf["error"] = flash["msg"] if flash and flash.get("feed") == active_feed else ""
        conf["downloaded"], conf["matched"], conf["unmatched"] = GetRssLog(active_feed)

    # Find a unique new Feed name
    unum = 1
    txt = T("Feed")  # : Used as default Feed name in Config->RSS
    while txt + str(unum) in feeds:
        unum += 1
    conf["feed"] = txt + str(unum)

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config_rss.tmpl"),
        search_list=conf,
    )


@secured_expose(route="/config/rss/save_rss_rate", check_configlock=True, methods=["POST"])
def config_rss_save_rss_rate(request: Request):
    """Save changed RSS automatic readout rate"""
    cfg.rss_rate.set(request_params(request).get("rss_rate"))
    config.save_config()
    sabnzbd.Scheduler.restart()
    return base_redirect_response(_RSS_ROOT)


@secured_expose(route="/config/rss/upd_rss_feed", check_configlock=True, methods=["POST"])
def config_rss_upd_rss_feed(request: Request):
    """Update Feed level attributes,
    legacy version: ignores 'enable' parameter
    """
    params = request_params(request)
    kwargs = dict(params)
    if params.get("enable") is not None:
        del kwargs["enable"]
    try:
        cf = config.get_rss()[params.get("feed")]
    except KeyError:
        cf = None
    uri = Strip(params.get("uri"))
    if cf and uri:
        kwargs["uri"] = uri
        cf.set_dict(kwargs)
        config.save_config()

    return _rss_redirect(params.get("feed"))


@secured_expose(route="/config/rss/save_rss_feed", check_configlock=True, methods=["POST"])
def config_rss_save_rss_feed(request: Request):
    """Update Feed level attributes"""
    params = request_params(request)
    kwargs = dict(params)
    feed_name = params.get("feed")
    try:
        cf = config.get_rss()[feed_name]
    except KeyError:
        cf = None
    if "enable" not in kwargs:
        kwargs["enable"] = 0
    uri = Strip(params.get("uri"))
    if cf and uri:
        kwargs["uri"] = uri
        cf.set_dict(kwargs)

        # Did we get a new name for this feed?
        new_name = params.get("feed_new_name")
        if new_name and new_name != feed_name:
            feed_name = cf.rename(new_name)

        config.save_config()

    return base_redirect_response(_RSS_ROOT, feed=feed_name) if feed_name else base_redirect_response(_RSS_ROOT)


@secured_expose(route="/config/rss/toggle_rss_feed", check_configlock=True, methods=["POST"])
def config_rss_toggle_rss_feed(request: Request):
    """Toggle automatic read-out flag of Feed"""
    params = request_params(request)
    try:
        item = config.get_rss()[params.get("feed")]
    except KeyError:
        item = None
    if item:
        item.enable.set(not item.enable())
        config.save_config()
    if params.get("table"):
        return base_redirect_response(_RSS_ROOT)
    else:
        feed = params.get("feed")
        return base_redirect_response(_RSS_ROOT, feed=feed) if feed else base_redirect_response(_RSS_ROOT)


@secured_expose(route="/config/rss/add_rss_feed", check_configlock=True, methods=["POST"])
def config_rss_add_rss_feed(request: Request):
    """Add one new RSS feed definition"""
    params = request_params(request)
    kwargs = dict(params)
    feed = Strip(params.get("feed", "")).strip("[]")
    uri = Strip(params.get("uri"))
    if feed and uri:
        try:
            rss_cfg = config.get_rss()[feed]
        except KeyError:
            rss_cfg = None
        if not rss_cfg and uri:
            kwargs["feed"] = feed
            kwargs["uri"] = uri
            config.ConfigRSS(feed, kwargs)
            # Clear out any existing reference to this feed name
            # Otherwise first-run detection can fail
            with sabnzbd.rss.rss_repository() as repo:
                repo.clear_feed(feed)
            config.save_config()
            # Read out the new feed now (this handler runs in the threadpool) and
            # carry the result message to the redirected page via the session flash.
            msg = sabnzbd.RSSReader.process_feed(feed, readout=True, ignore_first=True)
            return _rss_flash_redirect(request, feed, msg)
        else:
            return base_redirect_response(_RSS_ROOT)
    else:
        return base_redirect_response(_RSS_ROOT)


@secured_expose(route="/config/rss/upd_rss_filter", check_configlock=True, methods=["POST"])
def config_rss_upd_rss_filter(request: Request):
    """Save updated filter definition"""
    do_upd_rss_filter(dict(request_params(request)))
    return _rss_redirect(request_params(request).get("feed"))


@secured_expose(route="/config/rss/del_rss_feed", check_configlock=True, methods=["POST"])
def config_rss_del_rss_feed(request: Request):
    """Remove complete RSS feed"""
    feed = request_params(request).get("feed")
    kw = {"section": "rss", "keyword": feed}
    del_from_section(kw)
    with sabnzbd.rss.rss_repository() as repo:
        repo.clear_feed(feed)
    return base_redirect_response(_RSS_ROOT)


@secured_expose(route="/config/rss/del_rss_filter", check_configlock=True, methods=["POST"])
def config_rss_del_rss_filter(request: Request):
    """Remove one RSS filter"""
    do_del_rss_filter(dict(request_params(request)))
    return _rss_redirect(request_params(request).get("feed"))


@secured_expose(route="/config/rss/download_rss_feed", check_configlock=True, methods=["POST"])
def config_rss_download_rss_feed(request: Request):
    """Force download of all matching jobs in a feed"""
    feed = request_params(request).get("feed")
    if not feed:
        return _rss_redirect()
    # Network read-out with forced download; this handler runs in the threadpool.
    msg = sabnzbd.RSSReader.process_feed(feed, readout=True, download=True, force=True)
    return _rss_flash_redirect(request, feed, msg)


@secured_expose(route="/config/rss/clean_rss_jobs", check_configlock=True, methods=["POST"])
def config_rss_clean_rss_jobs(request: Request):
    """Remove processed RSS jobs from UI"""
    feed = request_params(request).get("feed")
    if feed:
        with sabnzbd.rss.rss_repository() as repo:
            repo.clear_downloaded(feed)
        # Re-evaluate cached items (no network read-out) so the log refreshes.
        sabnzbd.RSSReader.process_feed(feed, readout=False)
    return _rss_redirect(feed)


@secured_expose(route="/config/rss/test_rss_feed", check_configlock=True, methods=["POST"])
def config_rss_test_rss_feed(request: Request):
    """Read the feed content again and show results"""
    feed = request_params(request).get("feed")
    if not feed:
        return _rss_redirect()
    # Network read-out; this handler runs in the threadpool.
    msg = sabnzbd.RSSReader.process_feed(feed, readout=True, ignore_first=True)
    # This endpoint is only called via AJAX; the client navigates to the feed
    # page itself once we return. Returning a redirect here would make the XHR
    # follow it transparently and consume the one-shot session flash before the
    # browser navigation can read it, so store the flash and return a plain
    # response instead.
    request.session["rss_flash"] = {"feed": feed, "msg": msg}
    return PlainTextResponse(msg)


@secured_expose(route="/config/rss/eval_rss_feed", check_configlock=True, methods=["POST"])
def config_rss_eval_rss_feed(request: Request):
    """Re-apply the filters to the feed"""
    feed = request_params(request).get("feed")
    if feed:
        # Re-evaluate cached items against current filters (no network read-out).
        sabnzbd.RSSReader.process_feed(feed, readout=False)
    return _rss_redirect(feed)


@secured_expose(route="/config/rss/download", check_configlock=True, methods=["POST"])
def config_rss_download(request: Request):
    """Download NZB from provider (Download button)"""
    params = request_params(request)
    feed = params.get("feed")
    url = params.get("url")
    with sabnzbd.rss.rss_repository() as repo:
        if att := repo.find_job_by_url(feed, url):
            nzbname = params.get("nzbname")
            pp = att.pp
            cat = att.cat
            script = att.script
            priority = att.priority

            if url:
                logging.info("Adding %s (%s) to queue", url, nzbname)
                sabnzbd.urlgrabber.add_url(
                    url,
                    pp=pp,
                    script=script,
                    cat=cat,
                    priority=priority,
                    nzbname=nzbname,
                    nzo_info=NzoInfo(RSS=feed),
                )
            repo.flag_downloaded(feed, url)
    return _rss_redirect(feed)


@secured_expose(route="/config/rss/rss_now", check_configlock=True, methods=["POST"])
def config_rss_rss_now(request: Request):
    """Run an automatic RSS run now"""
    sabnzbd.Scheduler.force_rss()
    return base_redirect_response(_RSS_ROOT)


def ConvertSpecials(p):
    """Convert None to 'None' and 'Default' to ''"""
    if p is None:
        p = "None"
    elif p.lower() == T("Default").lower():
        p = ""
    return p


def Strip(txt):
    """Return stripped string, can handle None"""
    try:
        return txt.strip()
    except Exception:
        return None


##############################################################################
_SCHED_ACTIONS = (
    "resume",
    "pause",
    "pause_all",
    "shutdown",
    "restart",
    "speedlimit",
    "pause_post",
    "resume_post",
    "scan_folder",
    "rss_scan",
    "create_backup",
    "remove_failed",
    "remove_completed",
    "pause_all_low",
    "pause_all_normal",
    "pause_all_high",
    "resume_all_low",
    "resume_all_normal",
    "resume_all_high",
    "enable_quota",
    "disable_quota",
)


_SCHED_ROOT = "/config/scheduling"


@secured_expose(route="/config/scheduling", check_configlock=True, methods=["GET"])
def config_scheduling_index(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)

    actions = []
    actions.extend(_SCHED_ACTIONS)
    # Translated per request, so the names follow the currently active language
    day_names = {
        "*": T("Daily"),
        "1": T("Monday"),
        "2": T("Tuesday"),
        "3": T("Wednesday"),
        "4": T("Thursday"),
        "5": T("Friday"),
        "6": T("Saturday"),
        "7": T("Sunday"),
    }
    categories = list_cats(False)
    snum = 1
    conf["schedlines"] = []
    conf["taskinfo"] = []
    for ev in sabnzbd.scheduler.sort_schedules(all_events=False):
        line = ev[3]
        conf["schedlines"].append(line)
        try:
            enabled, m, h, day_numbers, action = line.split(" ", 4)
        except Exception:
            continue
        action = action.strip()
        try:
            action, value = action.split(" ", 1)
        except Exception:
            value = ""
        value = value.strip()
        if value and not value.lower().strip("0123456789kmgtp%."):
            if "%" not in value and from_units(value) < 1.0:
                value = T("off")  # : "Off" value for speedlimit in scheduler
            else:
                if "%" not in value and 1 < int_conv(value) < 101:
                    value += "%"
                value = value.upper()
        if action in actions:
            action = Ttemplate("sch-" + action)
        else:
            if action in ("enable_server", "disable_server"):
                try:
                    value = '"%s"' % config.get_servers()[value].displayname()
                except KeyError:
                    value = '"%s" <<< %s' % (value, T("Undefined server!"))
                action = Ttemplate("sch-" + action)
            if action in ("pause_cat", "resume_cat"):
                action = Ttemplate("sch-" + action)
                if value not in categories:
                    value = '"%s" <<< %s' % (value, T("Incorrect parameter"))
                else:
                    value = '"%s"' % value

        if day_numbers == "1234567":
            days_of_week = "Daily"
        elif day_numbers == "12345":
            days_of_week = "Weekdays"
        elif day_numbers == "67":
            days_of_week = "Weekends"
        else:
            days_of_week = ", ".join([day_names.get(i, "**") for i in day_numbers])

        item = (snum, "%02d" % int(h), "%02d" % int(m), days_of_week, "%s %s" % (action, value), enabled)

        conf["taskinfo"].append(item)
        snum += 1

    actions_lng = {}
    for action in actions:
        actions_lng[action] = Ttemplate("sch-" + action)

    actions_servers = {}
    servers = config.get_servers()
    for srv in servers:
        actions_servers[srv] = servers[srv].displayname()

    conf["actions_servers"] = actions_servers
    conf["actions"] = actions
    conf["actions_lng"] = actions_lng
    conf["categories"] = categories

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config_scheduling.tmpl"),
        search_list=conf,
    )


@secured_expose(route="/config/scheduling/add_schedule", check_configlock=True, methods=["POST"])
def config_scheduling_add(request: Request):
    params = request_params(request)
    servers = config.get_servers()
    minute = params.get("minute")
    hour = params.get("hour")
    days_of_week = "".join([str(x) for x in params.getlist("daysofweek")])
    if not days_of_week:
        days_of_week = "1234567"
    action = params.get("action")
    arguments = params.get("arguments")

    arguments = arguments.strip().lower()
    if arguments in ("on", "enable"):
        arguments = "1"
    elif arguments in ("off", "disable"):
        arguments = "0"

    if minute and hour and days_of_week and action:
        if action == "speedlimit":
            if not arguments or arguments.strip("0123456789kmgtp%."):
                arguments = 0
        elif action in _SCHED_ACTIONS:
            arguments = ""
        elif action in servers:
            if arguments == "1":
                arguments = action
                action = "enable_server"
            else:
                arguments = action
                action = "disable_server"

        elif action in ("pause_cat", "resume_cat"):
            # Need original category name, not lowercased
            arguments = arguments.strip()
        else:
            # Something else, leave empty
            action = None

        if action:
            sched = cfg.schedules()
            sched.append("%s %s %s %s %s %s" % (1, minute, hour, days_of_week, action, arguments))
            cfg.schedules.set(sched)

    config.save_config()
    sabnzbd.Scheduler.restart()
    return base_redirect_response(_SCHED_ROOT)


@secured_expose(route="/config/scheduling/del_schedule", check_configlock=True, methods=["POST"])
def config_scheduling_del(request: Request):
    schedules = cfg.schedules()
    line = request_params(request).get("line")
    if line and line in schedules:
        schedules.remove(line)
        cfg.schedules.set(schedules)
        config.save_config()
        sabnzbd.Scheduler.restart()
    return base_redirect_response(_SCHED_ROOT)


@secured_expose(route="/config/scheduling/toggle_schedule", check_configlock=True, methods=["POST"])
def config_scheduling_toggle(request: Request):
    schedules = cfg.schedules()
    line = request_params(request).get("line")
    if line:
        for i, schedule in enumerate(schedules):
            if schedule == line:
                # Toggle the schedule
                schedule_split = schedule.split()
                schedule_split[0] = "%d" % (schedule_split[0] == "0")
                schedules[i] = " ".join(schedule_split)
                break
        cfg.schedules.set(schedules)
        config.save_config()
        sabnzbd.Scheduler.restart()
    return base_redirect_response(_SCHED_ROOT)


##############################################################################
# Page definitions - Config - Categories
##############################################################################


@secured_expose(route="/config/categories", check_configlock=True, methods=["GET"])
def index_config_categories(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)

    conf["scripts"] = list_scripts(default=True)
    conf["defdir"] = cfg.complete_dir.get_clipped_path()

    categories = config.get_ordered_categories()
    new_cat_order = max(cat["order"] for cat in categories) + 1

    # Add empty line to add new categories
    empty = {
        "name": "",
        "order": str(new_cat_order),
        "pp": "-1",
        "script": "",
        "dir": "",
        "newzbin": "",
        "priority": DEFAULT_PRIORITY,
    }
    categories.insert(1, empty)
    conf["slotinfo"] = categories

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config_cat.tmpl"),
        search_list=conf,
    )


@secured_expose(route="/config/categories/delete", check_configlock=True, methods=["POST"])
def config_categories_delete(request: Request):
    kw = {
        "section": "categories",
        "keyword": request_params(request).get("name"),
    }
    del_from_section(kw)
    return base_redirect_response("/config/categories")


@secured_expose(route="/config/categories/save", check_configlock=True, methods=["POST"])
def config_categories_save(request: Request):
    name = request_params(request).get("name", "*")
    newname = request_params(request).get("newname", "")
    if name == "*":
        newname = name

    if newname:
        cat_params = dict(request_params(request))
        # Validate directory not under incomplete
        if same_directory(
            cfg.download_dir.get_path(),
            real_path(cfg.complete_dir.get_path(), cat_params.get("dir", "")),
        ):
            return report(
                request_params(request),
                error=T("Category folder cannot be a subfolder of the Temporary Download Folder."),
            )

        # Delete current one and replace with new one
        if name:
            config.delete("categories", name)
        config.ConfigCat(newname.lower(), cat_params)

    config.save_config()
    return base_redirect_response("/config/categories")


##############################################################################
# Config - Sorting (standalone route functions)
##############################################################################

_SORTING_ROOT = "/config/sorting"


@secured_expose(route="/config/sorting", check_configlock=True, methods=["GET"])
def config_sorting_index(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)

    sorters = config.get_ordered_sorters()
    # Add empty sorter entry, used as a template at the top of the page
    empty = {
        "is_active": "1",
        "name": "",
        "order": len(sorters),  # Last in line
        "min_size": DEF_SORTER_RENAME_SIZE,
        "sort_string": "",
        "sort_cats": "",
        "sort_type": "0,",
        "multipart_label": "",
    }
    sorters.insert(0, empty)
    conf["slotinfo"] = sorters
    conf["categories"] = list_cats(False)
    conf["guessit_properties"] = tuple(
        prop for prop in guessit_properties().keys() if prop not in EXCLUDED_GUESSIT_PROPERTIES
    )
    conf["sort_types"] = GUESSIT_SORT_TYPES

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config_sorting.tmpl"),
        search_list=conf,
    )


@secured_expose(route="/config/sorting/delete", check_configlock=True, methods=["POST"])
def config_sorting_delete(request: Request):
    kw = {"section": "sorters", "keyword": request_params(request).get("name")}
    del_from_section(kw)
    return base_redirect_response(_SORTING_ROOT)


@secured_expose(route="/config/sorting/save_sorter", check_configlock=True, methods=["POST"])
def config_sorting_save_sorter(request: Request):
    params = request_params(request)
    kwargs = dict(params)
    name = params.get("name", "*")
    newname = params.get("newname", "")
    newname = config.clean_section_name(newname)

    if name == "*":
        newname = name
    if newname:
        # Delete current one and replace with new one
        if name:
            config.delete("sorters", name)
        config.ConfigSorter(newname, kwargs)

    config.save_config()
    return base_redirect_response(_SORTING_ROOT)


@secured_expose(route="/config/sorting/toggle_sorter", check_configlock=True, methods=["POST"])
def config_sorting_toggle_sorter(request: Request):
    """Toggle is_active flag of a sorter"""
    try:
        sorter = config.get_sorters()[request_params(request).get("sorter")]
        sorter.is_active.set(not sorter.is_active())
        config.save_config()
    except Exception:
        pass

    return base_redirect_response(_SORTING_ROOT)


def GetRssLog(feed):
    def make_item(entry: ResolvedEntry):
        # Make a copy
        job: dict = {
            "url": entry.link,
            "rule": entry.rule,
            "title": entry.title,
            "skip": "*" if entry.is_starred else "",
            "cat": entry.cat or T("Default"),
            "size": entry.size,
            "infourl": entry.infourl,
        }

        # Auto-fetched jobs didn't have these fields set
        if entry.link:
            job["baselink"] = get_base_url(entry.link)
            if entry.is_special_rss_site:
                job["nzbname"] = ""
            else:
                job["nzbname"] = entry.title
        else:
            job["baselink"] = ""
            job["nzbname"] = entry.title

        if entry.size:
            job["size_units"] = to_units(entry.size)
        else:
            job["size_units"] = "-"

        # And we add extra fields for sorting
        if entry.age:
            job["age_ms"] = int(entry.age.timestamp())
            job["age"] = calc_age(entry.age, True)
        else:
            job["age_ms"] = ""
            job["age"] = ""

        if entry.downloaded_at:
            job["time_downloaded_ms"] = int(entry.downloaded_at.timestamp())
            job["time_downloaded"] = entry.downloaded_at.strftime(time_format("%H:%M %a %d %b"))
        else:
            job["time_downloaded_ms"] = ""
            job["time_downloaded"] = ""

        return job

    with sabnzbd.rss.rss_repository() as repo:
        good, bad, done = ([], [], [])
        for job in repo.get_feed_jobs(feed, states=[RSSState.GOOD, RSSState.BAD, RSSState.DOWNLOADED]):
            if job.is_good:
                good.append(make_item(job))
            elif job.is_bad:
                bad.append(make_item(job))
            elif job.is_downloaded:
                done.append(make_item(job))

    return done, good, bad


##############################################################################
NOTIFY_OPTIONS = {
    "misc": (
        "email_endjob",
        "email_cats",
        "email_full",
        "email_server",
        "email_to",
        "email_from",
        "email_account",
        "email_pwd",
        "email_rss",
    ),
    "ncenter": (
        "ncenter_enable",
        "ncenter_cats",
        "ncenter_prio_startup",
        "ncenter_prio_download",
        "ncenter_prio_pause_resume",
        "ncenter_prio_pp",
        "ncenter_prio_pp",
        "ncenter_prio_complete",
        "ncenter_prio_failed",
        "ncenter_prio_disk_full",
        "ncenter_prio_quota",
        "ncenter_prio_warning",
        "ncenter_prio_error",
        "ncenter_prio_queue_done",
        "ncenter_prio_other",
        "ncenter_prio_new_login",
    ),
    "acenter": (
        "acenter_enable",
        "acenter_cats",
        "acenter_prio_startup",
        "acenter_prio_download",
        "acenter_prio_pause_resume",
        "acenter_prio_pp",
        "acenter_prio_complete",
        "acenter_prio_failed",
        "acenter_prio_disk_full",
        "acenter_prio_quota",
        "acenter_prio_warning",
        "acenter_prio_error",
        "acenter_prio_queue_done",
        "acenter_prio_other",
        "acenter_prio_new_login",
    ),
    "ntfosd": (
        "ntfosd_enable",
        "ntfosd_cats",
        "ntfosd_prio_startup",
        "ntfosd_prio_download",
        "ntfosd_prio_pause_resume",
        "ntfosd_prio_pp",
        "ntfosd_prio_complete",
        "ntfosd_prio_failed",
        "ntfosd_prio_disk_full",
        "ntfosd_prio_quota",
        "ntfosd_prio_warning",
        "ntfosd_prio_error",
        "ntfosd_prio_queue_done",
        "ntfosd_prio_other",
        "ntfosd_prio_new_login",
    ),
    "prowl": (
        "prowl_enable",
        "prowl_cats",
        "prowl_apikey",
        "prowl_prio_startup",
        "prowl_prio_download",
        "prowl_prio_pause_resume",
        "prowl_prio_pp",
        "prowl_prio_complete",
        "prowl_prio_failed",
        "prowl_prio_disk_full",
        "prowl_prio_quota",
        "prowl_prio_warning",
        "prowl_prio_error",
        "prowl_prio_queue_done",
        "prowl_prio_other",
        "prowl_prio_new_login",
    ),
    "pushover": (
        "pushover_enable",
        "pushover_cats",
        "pushover_token",
        "pushover_userkey",
        "pushover_device",
        "pushover_prio_startup",
        "pushover_prio_download",
        "pushover_prio_pause_resume",
        "pushover_prio_pp",
        "pushover_prio_complete",
        "pushover_prio_failed",
        "pushover_prio_disk_full",
        "pushover_prio_quota",
        "pushover_prio_warning",
        "pushover_prio_error",
        "pushover_prio_queue_done",
        "pushover_prio_other",
        "pushover_prio_new_login",
        "pushover_emergency_retry",
        "pushover_emergency_expire",
    ),
    "pushbullet": (
        "pushbullet_enable",
        "pushbullet_cats",
        "pushbullet_apikey",
        "pushbullet_device",
        "pushbullet_prio_startup",
        "pushbullet_prio_download",
        "pushbullet_prio_pause_resume",
        "pushbullet_prio_pp",
        "pushbullet_prio_complete",
        "pushbullet_prio_failed",
        "pushbullet_prio_disk_full",
        "pushbullet_prio_quota",
        "pushbullet_prio_warning",
        "pushbullet_prio_error",
        "pushbullet_prio_queue_done",
        "pushbullet_prio_other",
        "pushbullet_prio_new_login",
    ),
    "apprise": (
        "apprise_enable",
        "apprise_cats",
        "apprise_urls",
        "apprise_target_startup",
        "apprise_target_startup_enable",
        "apprise_target_download",
        "apprise_target_download_enable",
        "apprise_target_pause_resume",
        "apprise_target_pause_resume_enable",
        "apprise_target_pp",
        "apprise_target_pp_enable",
        "apprise_target_complete",
        "apprise_target_complete_enable",
        "apprise_target_failed",
        "apprise_target_failed_enable",
        "apprise_target_disk_full",
        "apprise_target_disk_full_enable",
        "apprise_target_quota",
        "apprise_target_quota_enable",
        "apprise_target_warning",
        "apprise_target_warning_enable",
        "apprise_target_error",
        "apprise_target_error_enable",
        "apprise_target_queue_done",
        "apprise_target_queue_done_enable",
        "apprise_target_other",
        "apprise_target_other_enable",
        "apprise_target_new_login",
        "apprise_target_new_login_enable",
    ),
    "nscript": (
        "nscript_enable",
        "nscript_cats",
        "nscript_script",
        "nscript_parameters",
        "nscript_prio_startup",
        "nscript_prio_download",
        "nscript_prio_pause_resume",
        "nscript_prio_pp",
        "nscript_prio_complete",
        "nscript_prio_failed",
        "nscript_prio_disk_full",
        "nscript_prio_quota",
        "nscript_prio_warning",
        "nscript_prio_error",
        "nscript_prio_queue_done",
        "nscript_prio_other",
        "nscript_prio_new_login",
    ),
}


##############################################################################
# Page definitions - Config - Notify
##############################################################################


@secured_expose(route="/config/notify", check_configlock=True, methods=["GET"])
def index_config_notify(request: Request):
    conf = build_header(sabnzbd.WEB_DIR_CONFIG, request=request)
    conf["notify_types"] = sabnzbd.notifier.NOTIFICATION_TYPES
    conf["categories"] = list_cats(False)
    conf["have_ntfosd"] = sabnzbd.notifier.have_ntfosd()
    conf["have_ncenter"] = sabnzbd.MACOS and sabnzbd.FOUNDATION
    conf["scripts"] = list_scripts(default=False, none=True)

    for section in NOTIFY_OPTIONS:
        for option in NOTIFY_OPTIONS[section]:
            conf[option] = config.get_config(section, option)()

    # Use get_string to make sure lists are displayed correctly
    conf["email_to"] = cfg.email_to.get_string()

    return template_filtered_response(
        file=os.path.join(sabnzbd.WEB_DIR_CONFIG, "config_notify.tmpl"),
        search_list=conf,
    )


@secured_expose(route="/config/notify/save", check_configlock=True, methods=["POST"])
def config_notify_save(request: Request):
    for section in NOTIFY_OPTIONS:
        for option in NOTIFY_OPTIONS[section]:
            if msg := config.get_config(section, option).set(request_params(request).get(option)):
                return report(request_params(request), error=msg)
    config.save_config()
    return report(request_params(request))


##############################################################################
# New
##############################################################################


class XFrameOptionsMiddleware:
    """Add X-Frame-Options to every response when cfg.x_frame_options is enabled,
    mitigating clickjacking. Applied as middleware rather than in secured_expose so
    it also covers static file mounts, redirects, the login page and error responses.
    The setting is read per request, so toggling it needs no restart. Implemented as
    pure ASGI (not BaseHTTPMiddleware) to keep streaming responses untouched."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not cfg.x_frame_options():
            return await self.app(scope, receive, send)

        async def send_with_header(message):
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Frame-Options"] = "SAMEORIGIN"
            await send(message)

        await self.app(scope, receive, send_with_header)


class SecureSessionCookieMiddleware:
    """Add the Secure attribute to the session cookie when the connection warrants it.

    SessionMiddleware builds its cookie flags once at construction, so it cannot know
    that TLS was terminated at a reverse proxy, which is only visible per request. It
    is therefore mounted without https_only and wrapped by this middleware, which
    flags the cookie using the same rule as use_secure_cookies. Any other Set-Cookie
    header is passed through untouched: the login/session cookies are already flagged
    where they are set. Pure ASGI (not BaseHTTPMiddleware) to keep streaming responses
    untouched."""

    # Matches the cookie emitted by SessionMiddleware, which is mounted with
    # session_cookie=COOKIE_SESSION
    COOKIE_PREFIX = utob(COOKIE_SESSION + "=")

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_secure_cookie(message):
            # Runs after SessionMiddleware appended its Set-Cookie, since the send of
            # an inner middleware is called before that of the ones wrapping it
            if message["type"] == "http.response.start" and use_secure_cookies(Request(scope)):
                headers = message["headers"]
                for index, (key, value) in enumerate(headers):
                    # Append the Secure attribute to the session cookie, if not already set
                    if (
                        key.lower() == b"set-cookie"
                        and value.startswith(self.COOKIE_PREFIX)
                        and b"secure" not in value.lower().split(b"; ")
                    ):
                        headers[index] = (key, value + b"; secure")
            await send(message)

        await self.app(scope, receive, send_with_secure_cookie)


class HostnameCheckMiddleware:
    """Reject requests whose Host header is not allowed (DNS-rebinding mitigation).
    Applied as global middleware rather than in secured_expose so a single place
    guards every route, including the static mounts and error responses. The setting
    is read per request, and check_hostname short-circuits to allow when a
    username/password is configured. Pure ASGI, and no request body is consumed."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and not check_hostname(Request(scope, receive)):
            message = _MSG_ACCESS_DENIED_HOSTNAME if cfg.api_warnings() else ""
            response = PlainTextResponse(message, status_code=403)
            return await response(scope, receive, send)
        await self.app(scope, receive, send)


class RequestLoggingMiddleware:
    """Log every request when cfg.api_logging is enabled. The line is emitted after
    the handler runs, once the request's parameters have been parsed onto
    request.state; requests that never reach a secured handler (e.g. static files)
    have no parsed params and are skipped, matching the previous
    behavior. Pure ASGI to leave streaming responses untouched."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        try:
            await self.app(scope, receive, send)
        finally:
            # request.state stores params in scope["state"]; a missing key means the
            # request did not pass through secured_expose, so there is nothing to log.
            if cfg.api_logging() and (params := scope.get("state", {}).get("params")) is not None:
                request = Request(scope)
                logging.debug(
                    "Request %s %s from %s [%s] %s",
                    request.method,
                    request.url.path,
                    client_address_info(request),
                    request.headers.get("User-Agent"),
                    dict(params),
                )


class UvicornNoiseFilter(logging.Filter):
    """Log uvicorn messages that are not news to SABnzbd as debug messages.

    Three kinds of records get in the way. Its start-up and shutdown are logged
    at info level, repeating what we already log ourselves. It warns about
    clients sending a malformed request or asking for an upgrade we do not
    support, which says nothing about the state of SABnzbd, yet shows up in the
    web-interface and is sent out as a notification. And it reports a failed
    start-up twice, once with the reason and once as a bare summary, while we
    report it ourselves as well before giving up.

    They are demoted rather than dropped, so they are still there when debug
    logging is on: the missing half of a start-up sequence, or the reason a
    client fails to connect. The handlers take it from there, they all have a
    level, so the message only reaches the ones that want it. Warnings and
    errors about our own web-interface are left alone.
    """

    # Logged by uvicorn/protocols/http/{h11,httptools}_impl.py
    CLIENT_ERRORS = (
        "Invalid HTTP request received.",
        "Unsupported upgrade request.",
        "No supported WebSocket library detected.",
    )

    # Logged by uvicorn/lifespan/on.py, after the reason was logged separately
    REPORTED_FAILURES = ("Application startup failed. Exiting.",)

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if (
            record.levelno == logging.INFO
            or (record.levelno == logging.WARNING and message.startswith(self.CLIENT_ERRORS))
            or (record.levelno == logging.ERROR and message.startswith(self.REPORTED_FAILURES))
        ):
            record.levelno = logging.DEBUG
            record.levelname = logging.getLevelName(logging.DEBUG)
        return True


def uvicorn_logging_config(access_log_file: Optional[str] = None) -> dict[str, Any]:
    """Make uvicorn log through the SABnzbd handlers, so its output ends up in
    the regular logfile. Access logging goes to its own file, if requested.
    Format: https://github.com/encode/uvicorn/blob/d43afed1cfa018a85c83094da8a2dd29f656d676/uvicorn/config.py#L82-L114
    """
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(asctime)s::%(levelname)s::%(client_addr)s - "%(request_line)s" %(status_code)s',
                "use_colors": False,
            },
        },
        "filters": {
            "uvicorn_noise": {"()": "sabnzbd.interface.UvicornNoiseFilter"},
        },
        "handlers": {},
        "loggers": {
            "uvicorn": {"propagate": True},
            "uvicorn.error": {"propagate": True, "filters": ["uvicorn_noise"]},
            "uvicorn.access": {"propagate": False, "level": "INFO"},
        },
    }

    if access_log_file:
        logging_config["handlers"]["access_file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "access",
            "filename": access_log_file,
            "maxBytes": cfg.log_size(),
            "backupCount": cfg.log_backups(),
            "encoding": "utf-8",
        }
        logging_config["loggers"]["uvicorn.access"]["handlers"] = ["access_file"]

    return logging_config


class ThreadedServer(uvicorn.Server):
    """uvicorn server running in a background thread, so the main thread stays
    free for the SABnzbd main loop."""

    # Give up on a server that has not reached the serving state by then
    STARTUP_TIMEOUT = 30.0

    def __init__(self, *args, sockets: Optional[list[socket.socket]] = None, **kwargs):
        self.thread: Optional[threading.Thread] = None
        self._startup_exc: Optional[BaseException] = None
        # Pre-bound listening sockets, so the port cannot be taken between the
        # moment we claim it and the moment uvicorn starts serving on it
        self._sockets = sockets
        # Set once the server is either serving or done trying
        self._startup_done = threading.Event()
        super().__init__(*args, **kwargs)

    async def startup(self, sockets=None):
        await super().startup(sockets=sockets)
        # Only signal here on success, a failure is signalled by _run() so that
        # the exception is always recorded before run_in_thread() wakes up
        self._startup_done.set()

    def _run(self):
        # Capture any start-up failure (bad cert, bad host, etc.) so
        # run_in_thread() can report it. uvicorn raises SystemExit on a bind
        # error, so catch BaseException rather than Exception.
        try:
            self.run(sockets=self._sockets)
        except BaseException as exc:
            self._startup_exc = exc
        finally:
            # No-op after a successful start-up, but releases run_in_thread()
            # when the thread dies before it ever started serving
            self._startup_done.set()

    def run_in_thread(self):
        """Start the server in a background thread and block until it is serving.

        Raises RuntimeError if the server thread exits before signalling that it
        has started, or if it takes too long, so the caller can abort instead of
        waiting forever.
        """
        self.thread = threading.Thread(target=self._run, name="WebServer")
        self.thread.start()

        if not self._startup_done.wait(self.STARTUP_TIMEOUT):
            raise RuntimeError("Web server did not start within %s seconds" % self.STARTUP_TIMEOUT)

        if not self.started:
            raise RuntimeError("Web server failed to start") from self._startup_exc

    def stop(self):
        """Ask the server to shut down and wait for the thread to finish.
        Safe to call more than once and before the server was ever started."""
        self.should_exit = True
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join()

    def stop_accepting_connections(self):
        """Close the listening sockets so no new connections are accepted, while
        in-flight requests (including the caller's own response) still complete.

        Must be called from the event-loop thread, i.e. from within an async
        request handler, so touching the asyncio Server objects needs no
        cross-thread scheduling. Safe before start-up (uvicorn only sets `servers`
        once serving) and after a previous close (uvicorn's own shutdown closes
        them again, idempotently)."""
        for server in getattr(self, "servers", []):
            server.close()


async def not_found_redirect(request: Request, exc):
    """Catch-all for unknown URLs: redirect to the UI root"""
    return base_redirect_response("/")


@contextlib.asynccontextmanager
async def app_lifespan(app: Starlette):
    """Close the async session store when the server's event loop shuts down.
    The store is opened lazily on the first session lookup, so there is no
    startup counterpart."""
    yield
    await sabnzbd.session_store.close()


def create_app() -> Starlette:
    """Build the Starlette application"""
    interface_routes = [
        *INTERFACE_ROUTES,
        Mount("/static", app=StaticFiles(directory=os.path.join(sabnzbd.WEB_DIR, "static")), name="static"),
        Mount(
            "/staticcfg", app=StaticFiles(directory=os.path.join(sabnzbd.WEB_DIR_CONFIG, "staticcfg")), name="staticcfg"
        ),
        Mount(
            "/wizard/static",
            app=StaticFiles(directory=os.path.join(sabnzbd.WIZARD_DIR, "static")),
            name="wizard_static",
        ),
    ]

    # Always serve at the root, and when a URL base is configured (e.g. behind a
    # reverse proxy) additionally under that base.The base mount must come
    # first so it is matched before the catch-all root mount.
    routes = []
    if url_base := cfg.url_base():
        routes.append(Mount(url_base, routes=interface_routes))
    routes.append(Mount("/", routes=interface_routes))

    middleware = [
        Middleware(XFrameOptionsMiddleware),
        Middleware(HostnameCheckMiddleware),
        Middleware(RequestLoggingMiddleware),
        Middleware(GZipMiddleware, minimum_size=1000, compresslevel=2),
        Middleware(SecureSessionCookieMiddleware),
        # Signed session cookie, used for short-lived per-client UI state such as the
        # RSS read-out result message (flash). Secret key is regenerated each run,
        # so sessions naturally expire on restart, which is fine for flash messages.
        # This is NOT authentication: the authenticated-user session lives in a separate,
        # DB-backed cookie (SESSION_COOKIE = "sabnzbd_user_session").
        Middleware(
            SessionMiddleware,
            secret_key=secrets.token_hex(),
            session_cookie=COOKIE_SESSION,
            same_site="lax",
            https_only=False,
        ),
    ]

    return Starlette(
        middleware=middleware,
        routes=routes,
        exception_handlers={404: not_found_redirect},
        lifespan=app_lifespan,
    )
