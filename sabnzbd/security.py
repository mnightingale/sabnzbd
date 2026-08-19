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
sabnzbd.security - authentication, sessions and the per-route access checks
"""

import hashlib
import hmac
import logging
import re
import secrets
import time
from typing import Any, Optional

from starlette.datastructures import Address, MultiDict, QueryParams
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

import sabnzbd
import sabnzbd.api
import sabnzbd.cfg as cfg
from sabnzbd.api import base_redirect_response
from sabnzbd.encoding import utob
from sabnzbd.misc import is_ipv4_addr, is_ipv6_addr, is_local_addr, is_loopback_addr

# Disable over-active logging for the form parser
logging.getLogger("python_multipart.multipart").setLevel(logging.WARNING)

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

# Holds a database-backed login token, or the anonymous tag when the login is bypassed
SESSION_COOKIE_USER = "sabnzbd_user"
# The SessionMiddleware cookie, used for RSS flash messages only. Not authentication.
SESSION_COOKIE_FLASH = "sabnzbd_flash"
# How long a session survives without being used
SESSION_DURATION = 3600 * 24 * 14  # 14 days
# Lifetime from the created stamp, so a session that keeps being used still ends
SESSION_MAX_AGE = 3600 * 24 * 90  # 90 days
# Only extend a session's expiry when doing so buys it more than this much extra time
SESSION_REFRESH_THRESHOLD = 3600 * 24  # 1 day

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_TIME = 300  # 5 minutes

# {host: (failures, cooldown_expiry)} cooldown_expiry uses the monotonic clock
_login_attempts: dict[str, tuple[int, float]] = {}

# Anonymous sessions are issued where the login is bypassed, so the frontend can still authenticate by cookie.
_ANONYMOUS_SESSION_KEY = secrets.token_bytes(32)

# A token is hmac(_CSRF_KEY, cookie_value): bound to its session, dying with it, needing
# neither storage nor a lookup. The key is regenerated each run, so a page left open across
# a restart holds a stale token; check_apikey answers those with a 401 to reload.
#
# Unlike the cookie it is not sent automatically: it is rendered into the page and echoed
# back in the header or a field, and a cross-site page can read neither the page (CORS) nor
# the httponly cookie. SameSite=Strict cannot do this job alone because it is not
# origin-scoped - another port on the same host is same-site and its forms send the cookie.
_CSRF_KEY = secrets.token_bytes(32)
CSRF_HEADER = "X-SABnzbd-CSRF"
CSRF_FIELD = "csrf_token"

# CherryPy resolved a repeated key to its first value (?mode=queue&mode=version gave
# "queue") where Starlette's .get() returns the last, and the handlers still assume a single
# value. Multi-valued keys (keyword, file uploads) are left for getlist() to see in full.
API_FIRST_WINS_KEYS = ("mode", "name", "value", "value2", "value3", "start", "limit", "search")


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


def use_secure_cookies(request: Request) -> bool:
    """Whether cookies for this request should carry the Secure attribute"""
    return request.scope.get("scheme") == "https" or bool(cfg.enable_https())


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


def _prune_login_attempts(now: float):
    """Forget clients whose cooldown has run out"""
    for host in [host for host, (_, cooldown_expiry) in _login_attempts.items() if cooldown_expiry <= now]:
        del _login_attempts[host]


def login_cooldown_remaining(request: Request) -> int:
    """Whole seconds this client must sit out before another login attempt is considered"""
    _prune_login_attempts(time.monotonic())
    failures, cooldown_expiry = _login_attempts.get(client_address(request).host, (0, 0.0))
    remaining = cooldown_expiry - time.monotonic()
    if failures < LOGIN_MAX_ATTEMPTS or remaining <= 0:
        return 0
    # Rounded up, because a Retry-After of 0 would invite a retry that is still too early
    return int(remaining) + 1


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


def constant_time_equals(presented: Any, expected: str) -> bool:
    """Constant-time comparison of a secret.

    Both sides are encoded, because compare_digest refuses a str holding any non-ASCII
    character: a cookie or header carrying a byte above 0x7F would raise TypeError instead of
    failing to match, turning a rejection into a 500. backslashreplace so the encode cannot
    fail either, UTF-8 having no representation for a lone surrogate.

    Anything that is not text counts as nothing presented: a secret sent as a multipart file
    part arrives as an UploadFile, and str()-ing it would let a repr stand in for a secret."""
    if not isinstance(presented, str):
        presented = ""
    return hmac.compare_digest(
        presented.encode("utf-8", "backslashreplace"), expected.encode("utf-8", "backslashreplace")
    )


def credential_fingerprint() -> str:
    """Fingerprint of the current username/password. Stored with each session and
    compared on validation, so changing either credential invalidates all sessions.

    Unsalted deliberately: a session written weeks ago still has to compare equal, so the salt
    would have to be a stored one, and it would only guard a password sabnzbd.ini keeps in the
    clear anyway. Revisit if the ini ever stores them hashed."""
    return hashlib.sha256(utob("%s:%s" % (cfg.username(), cfg.password()))).hexdigest()


def hash_session_token(token: str) -> str:
    """Hash of the raw cookie token; only the hash is stored server-side"""
    return hashlib.sha256(utob(token)).hexdigest()


async def create_session(request: Request, response: Response, remember_me: bool = False) -> bool:
    """Create a new database-backed login session and set the session cookie on the response.

    Returns False when the session could not be stored"""
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    if not await sabnzbd.SessionStore.add_session(
        token_hash=hash_session_token(token),
        created=now,
        expires=now + SESSION_DURATION,
        cred_fingerprint=credential_fingerprint(),
        last_ip=client_address(request).host,
        user_agent=request.headers.get("User-Agent"),
    ):
        return False

    max_age = SESSION_MAX_AGE if remember_me else None
    response.set_cookie(
        SESSION_COOKIE_USER,
        token,
        path="/",
        httponly=True,
        secure=use_secure_cookies(request),
        samesite="strict",
        max_age=max_age,
    )
    return True


def login_bypassed(request: Request) -> bool:
    """Return True when check_login lets this request through without a login session"""
    # No authentication required when no username/password is set
    if not cfg.username() or not cfg.password():
        return True

    # If we show login for external IP, by using access_type=6 we can check if IP match
    return cfg.inet_exposure() == 5 and check_access(request, access_type=6)


def anonymous_session_tag() -> str:
    """The stateless anonymous session cookie value for this run"""
    return hmac.new(_ANONYMOUS_SESSION_KEY, b"anonymous-session", hashlib.sha256).hexdigest()


def validate_anonymous_session(request: Request) -> bool:
    """Return True when the login is bypassed for this request and it carries a valid
    anonymous session cookie."""
    if not login_bypassed(request):
        return False
    return constant_time_equals(request.cookies.get(SESSION_COOKIE_USER, ""), anonymous_session_tag())


def create_anonymous_session(request: Request, response: Response):
    """Set the stateless anonymous session cookie on the response"""
    response.set_cookie(
        SESSION_COOKIE_USER,
        anonymous_session_tag(),
        path="/",
        httponly=True,
        secure=use_secure_cookies(request),
        samesite="strict",
        max_age=SESSION_DURATION,
    )


def csrf_token_for(cookie_value: str) -> str:
    """The CSRF token belonging to a session cookie value"""
    return hmac.new(_CSRF_KEY, utob(cookie_value), hashlib.sha256).hexdigest()


def presented_csrf_token(request: Request, header_only: bool = False) -> str:
    """The CSRF token this request offers, from the header or a form field"""
    if header_only:
        return request.headers.get(CSRF_HEADER) or ""
    presented = request.headers.get(CSRF_HEADER) or request_params(request).get(CSRF_FIELD) or ""
    # A multipart part named csrf_token arrives as an UploadFile, which is not a token
    return presented if isinstance(presented, str) else ""


def csrf_token_matches(request: Request, header_only: bool = False) -> bool:
    """Whether the request echoes the CSRF token belonging to the cookie it sent"""
    return constant_time_equals(
        presented_csrf_token(request, header_only=header_only),
        csrf_token_for(request.cookies.get(SESSION_COOKIE_USER, "")),
    )


async def validate_csrf(request: Request) -> bool:
    """Return True when the request carries a valid session and the CSRF token belonging
    to it. Both halves are required: the token alone would let a client with no cookie
    present csrf_token_for(""), and the session alone is what this replaces."""
    return await validate_any_session(request) and csrf_token_matches(request)


async def clear_session(request: Request, response: Response):
    """Delete the request's session (if any) and clear the session cookie"""
    if token := request.cookies.get(SESSION_COOKIE_USER):
        await sabnzbd.SessionStore.delete_session(hash_session_token(token))
    response.set_cookie(
        SESSION_COOKIE_USER,
        "",
        path="/",
        httponly=True,
        secure=use_secure_cookies(request),
        samesite="strict",
        expires="Thu, 01 Jan 1970 00:00:00 GMT",
    )


async def validate_session(request: Request) -> bool:
    """
    Return True when the request carries a session cookie that is not past either of its
    two deadlines and whose credential fingerprint still matches the configured username/password.
    Sessions failing any of those are deleted, and a still-valid one slides its expiry forward.
    """
    if (cached := getattr(request.state, "session_valid", None)) is None:
        cached = await _validate_session(request)
        request.state.session_valid = cached
    return cached


async def _validate_session(request: Request) -> bool:
    """The lookup behind validate_session. Call that instead, so a request pays for this once."""
    token = request.cookies.get(SESSION_COOKIE_USER)
    if not token:
        return False

    token_hash = hash_session_token(token)
    now = int(time.time())
    session = await sabnzbd.SessionStore.get_session(token_hash)
    if not session:
        return False

    # Reject and clean up sessions that are idle-expired, past the deadline, or from before a
    # credential change. The deadline check also catches rows written before the cap existed.
    if (
        session["expires"] < now
        or session["created"] + SESSION_MAX_AGE < now
        or session["cred_fingerprint"] != credential_fingerprint()
    ):
        await sabnzbd.SessionStore.delete_session(token_hash)
        return False

    # Slide the idle timeout forward, never past the deadline and never backwards: an older
    # version's row can carry a longer expiry, and using a session should not shorten it.
    new_expires = max(session["expires"], min(now + SESSION_DURATION, session["created"] + SESSION_MAX_AGE))

    # Write when the slide gains real time, keeping refreshes to about one a day, or when the
    # client moved, so the row shows where the session is in use rather than lagging a day.
    # Only a value we have counts as a change: touch_session keeps the stored one when passed
    # None, so treating a missing User-Agent as different would write on every request.
    last_ip = client_address(request).host
    user_agent = request.headers.get("User-Agent")
    moved = (last_ip and session["last_ip"] != last_ip) or (user_agent and session["user_agent"] != user_agent)

    if moved or new_expires > session["expires"] + SESSION_REFRESH_THRESHOLD:
        await sabnzbd.SessionStore.touch_session(
            token_hash,
            new_expires,
            last_ip=last_ip,
            user_agent=user_agent,
        )

    return True


async def validate_any_session(request: Request) -> bool:
    """Return True when the request carries a session cookie this instance issued"""
    return validate_anonymous_session(request) or await validate_session(request)


async def check_login(request: Request) -> bool:
    """Check if user is logged in"""
    # No authentication required, or waived for this client
    if login_bypassed(request):
        return True

    # Check the session cookie
    return await validate_session(request)


async def check_apikey(request: Request) -> Optional[Response]:
    """Check session cookie, API-key or NZB-key
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

    # A session cookie authorizes the frontend without the apikey, but only when it also
    # echoes the session's CSRF token in the header. That header is what protects the API: it
    # is not sent automatically, a form or image cannot set it, and a cross-origin fetch that
    # does is preflighted, which SABnzbd answers with a bare 405. Header only, because this
    # route merges the query string in and a field would accept a token from a URL.
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

    if SESSION_COOKIE_USER in request.cookies:
        # A cookie was presented, so this is a browser
        stale_token = presented_csrf_token(request, header_only=True)
        if stale_token:
            logging.info(
                "Stale session token from %s, the page will reload for a fresh one", client_address_info(request)
            )
        else:
            log_warning_and_ip(request, T("Refused connection from:"))
        # The frontend answers a 401 by reloading, so only send one where that fixes it: a
        # session or token left stale by a restart, expiry or credential change. A valid
        # session sending no token at all gets a 403, or it would reload forever.
        if not cookie_ok or stale_token:
            return PlainTextResponse(_MSG_SESSION_EXPIRED, status_code=401)
        return forbidden(_MSG_MISSING_SESSION)

    log_warning_and_ip(
        request, T("API Key missing, please enter the api key from Config->General into your 3rd party program:")
    )
    return forbidden(_MSG_APIKEY_REQUIRED)


def log_warning_and_ip(request: Request, txt: str):
    """Include the IP and the Proxy-IP for warnings"""
    if cfg.api_warnings():
        logging.warning("%s %s", txt, client_address_info(request))


def is_form_post(request: Request) -> bool:
    return request.method == "POST" and request.headers.get("content-type", "").startswith(
        ("application/x-www-form-urlencoded", "multipart/form-data")
    )


async def get_request_params(request: Request, merge_query: bool = False) -> MultiDict | QueryParams:
    """Parse the request's parameters.

    A page GET uses the query string alone, as the request's immutable QueryParams. A page
    POST reads the form body only (urlencoded or multipart, file uploads kept as UploadFile)
    into a mutable MultiDict, so parameters cannot be smuggled into a form handler through
    the URL; without a body it gets an empty one.

    The merged API route (merge_query, i.e. /api) keeps the CherryPy behavior: clients POST
    an NZB as a multipart body while passing mode/apikey/output in the query string, so the
    two are merged with the body winning per key. Every method takes this same path, so a
    duplicated key resolves identically and the API scalar keys collapse to their first.

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
            # Where the login is bypassed, issue an anonymous cookie so the frontend can
            # authenticate by cookie and its POSTs pass the CSRF guard. UI pages only: bots
            # hitting robots.txt and the API get none, since a browser loads a page first.
            # Skipped when the client already holds a session, so a login session made before
            # the bypass applied is not overwritten. Injected into the response start, this
            # being pure ASGI.
            if (
                self.check_for_login
                and not self.check_api_key
                and login_bypassed(request)
                and not await validate_any_session(request)
            ):
                send = _anonymous_session_sender(request, send)
                # The page is rendered before that Set-Cookie reaches the client, so its
                # token has to belong to the cookie being issued, not the one that arrived,
                # or every first page load ships a token matching nothing.
                request.state.csrf_token = csrf_token_for(anonymous_session_tag())
            else:
                request.state.csrf_token = csrf_token_for(request.cookies.get(SESSION_COOKIE_USER, ""))
        await self.app(scope, receive, send)

    async def denied_response(self, request: Request) -> Optional[Response]:
        """Return the response to send when a check fails, or None when allowed."""
        # Check if config is locked
        if self.check_configlock and cfg.configlock():
            return forbidden(_MSG_ACCESS_DENIED_CONFIG_LOCK)

        # Check if external access and if it's allowed
        if not check_access(request, access_type=self.access_type, warn_user=True):
            return forbidden(_MSG_ACCESS_DENIED)

        # An apikey on a route that does not take one is automation reaching for the UI pages,
        # so the refusals below say that rather than redirecting to a login form it cannot use
        # and would read as success. Only consulted once the request is refused anyway.
        offered_apikey = not self.check_api_key and bool(
            request_params(request).get("apikey") or request.query_params.get("apikey")
        )

        # Verify login status, only for non-key pages
        if self.check_for_login and not self.check_api_key and not await check_login(request):
            if offered_apikey:
                log_warning_and_ip(request, T("Refused connection from:"))
                return forbidden(_MSG_APIKEY_NOT_ON_PAGES)
            return base_redirect_response("/login")

        # CSRF guard: a page POST has to echo its session's token, which only a page from this
        # instance could have read. Unconditional, because check_login is no CSRF defence
        # either way: bypassed it proves nothing, and otherwise it leans on SameSite=Strict,
        # which is not origin-scoped -- another port on this host is same-site.
        if self.check_csrf and request.method == "POST" and not await validate_csrf(request):
            # A token that simply does not match is a page left open across a restart
            if presented_csrf_token(request) and not offered_apikey:
                logging.info(
                    "Stale session token from %s, the page will reload for a fresh one", client_address_info(request)
                )
            else:
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


class SecureSessionCookieMiddleware:
    """Add the Secure attribute to the session cookie when the connection warrants it"""

    # Matches the cookie emitted by SessionMiddleware, which is mounted with
    # session_cookie=COOKIE_SESSION
    COOKIE_PREFIX = utob(SESSION_COOKIE_FLASH + "=")

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
    username/password is configured."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and not check_hostname(Request(scope, receive)):
            message = _MSG_ACCESS_DENIED_HOSTNAME if cfg.api_warnings() else ""
            response = PlainTextResponse(message, status_code=403)
            return await response(scope, receive, send)
        await self.app(scope, receive, send)
