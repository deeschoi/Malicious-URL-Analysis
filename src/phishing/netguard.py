"""Server-side request forgery guards for the live scanner.

The scanner exists to fetch URLs a stranger typed, so every outbound request is
attacker-controlled by design. Three separate holes have to stay closed:

1. **The literal target.** ``http://127.0.0.1/`` and friends are rejected before
   any socket is opened.
2. **Redirects.** A public host is free to answer ``302 Location:
   http://169.254.169.254/``. ``requests`` follows redirects itself and never
   re-checks the destination, so auto-redirects are disabled and each hop is
   validated here before it is followed.
3. **DNS rebinding.** Checking DNS and then letting ``requests`` resolve again
   at connect time is a time-of-check/time-of-use bug: a short-TTL name can
   answer ``93.184.216.34`` for the check and ``127.0.0.1`` for the connection.
   The only reliable fix is to validate the address the socket actually
   connected to, which is what :class:`GuardedHTTPAdapter` does.

"Unsafe" is ``not ip.is_global`` rather than a list of ORed ``is_private`` /
``is_loopback`` flags. Carrier-grade NAT (100.64.0.0/10) is neither private nor
global on current Python, so the flag list let it through.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.poolmanager import PoolManager

BLOCKED_SCHEMES = frozenset({"file", "javascript", "data", "ftp", "ftps", "mailto", "gopher"})
ALLOWED_SCHEMES = frozenset({"http", "https"})

# Hostnames that resolve to infrastructure rather than a website. DNS for these
# is often intercepted by the local resolver, so an IP check alone can miss them.
BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".home.arpa",
)
BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "instance-data",
    }
)

# Redundant with ``not is_global`` but named explicitly: these are the addresses
# that turn an SSRF into cloud credential theft, and they should be greppable.
METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),  # AWS / Azure / GCP / DO IMDS
        ipaddress.ip_address("169.254.170.2"),  # ECS task metadata
        ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud
        ipaddress.ip_address("fd00:ec2::254"),  # AWS IMDS over IPv6
    }
)


class UnsafeTargetError(ValueError):
    """The URL points at a local, private, or metadata address and will not be fetched."""


def is_unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for anything that is not a globally routable public address.

    ``is_global`` covers loopback, RFC1918, link-local, CGNAT, and unspecified
    in one predicate — CGNAT is the one a hand-rolled ``is_private`` list misses,
    since 100.64.0.0/10 is private=False, global=False. The explicit flags stay
    because IPv4 multicast is global=True, so ``is_global`` alone would allow
    224.0.0.0/4. IPv4-mapped and 6to4 addresses are unwrapped first so
    ``::ffff:127.0.0.1`` cannot smuggle loopback through.
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    sixtofour = getattr(ip, "sixtofour", None)
    if sixtofour is not None:
        ip = sixtofour
    return bool(
        ip in METADATA_IPS
        or not ip.is_global
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_private
    )


def is_unsafe_host_name(host: str) -> bool:
    """True for hostnames that name local infrastructure, before any DNS lookup."""
    lowered = (host or "").lower().rstrip(".")
    if not lowered:
        return True
    if lowered in BLOCKED_HOSTS:
        return True
    return any(lowered.endswith(suffix) for suffix in BLOCKED_HOST_SUFFIXES)


def strip_userinfo(url: str) -> str:
    """Rebuild the URL with ``user:password@`` removed from the authority.

    ``requests`` turns userinfo into an ``Authorization: Basic`` header, so
    leaving it in means the scanner replays someone's credentials at the target
    and then writes them into scan history.
    """
    parsed = urlparse(url)
    if "@" not in (parsed.netloc or ""):
        return url
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # urlparse strips IPv6 brackets
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urlunparse(parsed._replace(netloc=netloc))


def resolve_host(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address ``host`` resolves to, or ``[]`` when the name does not resolve.

    A name that does not resolve is not an SSRF risk — the fetch will fail with
    a DNS error, which the extractor reports as ``unreachable``.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, ValueError):
        return []
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except (ValueError, IndexError):
            continue
    return out


def assert_public_url(url: str) -> None:
    """Reject a URL whose scheme, hostname, or *any* resolved address is not public.

    Every address is checked, not just the first: a name with one public and one
    loopback A record must not be fetchable, because which one is used at
    connect time is not ours to choose.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme in BLOCKED_SCHEMES or scheme not in ALLOWED_SCHEMES:
        raise UnsafeTargetError(f"Scheme {scheme or '(none)'!r} is not allowed.")
    host = (parsed.hostname or "").lower().rstrip(".")
    if is_unsafe_host_name(host):
        raise UnsafeTargetError("Refusing to scan a local address.")
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None:
        if is_unsafe_ip(literal):
            raise UnsafeTargetError("Refusing to scan a private or local address.")
        return
    for ip in resolve_host(host):
        if is_unsafe_ip(ip):
            raise UnsafeTargetError("Refusing to scan a private or local address.")


def _assert_public_peer(sock: socket.socket) -> None:
    """Validate the address the socket actually reached.

    This is the rebinding fix. Whatever DNS said a moment ago, the peer of this
    socket is the machine bytes will be sent to.
    """
    try:
        peer = sock.getpeername()
        ip = ipaddress.ip_address(peer[0])
    except (OSError, ValueError, IndexError):
        return
    if is_unsafe_ip(ip):
        sock.close()
        raise UnsafeTargetError(f"Refusing to scan a private or local address ({ip}).")


class _GuardedHTTPConnection(HTTPConnection):
    def _new_conn(self) -> socket.socket:
        sock = super()._new_conn()
        _assert_public_peer(sock)
        return sock


class _GuardedHTTPSConnection(HTTPSConnection):
    def _new_conn(self) -> socket.socket:
        sock = super()._new_conn()
        _assert_public_peer(sock)
        return sock


class _GuardedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class _GuardedPoolManager(PoolManager):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # urllib3 copies these onto the instance precisely so subclasses can
        # swap the pool implementation.
        self.pool_classes_by_scheme = {
            "http": _GuardedHTTPConnectionPool,
            "https": _GuardedHTTPSConnectionPool,
        }


class GuardedHTTPAdapter(HTTPAdapter):
    """Requests adapter that drops any connection landing on a non-public IP."""

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = _GuardedPoolManager(
            num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs
        )


def guarded_session() -> requests.Session:
    """A session that cannot reach private address space, whatever DNS returns."""
    session = requests.Session()
    session.trust_env = False  # ignore ambient proxy env vars; a proxy defeats the IP guard
    adapter = GuardedHTTPAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
