"""Whether a live scan actually observed the host.

The phishing model scores a complete feature vector even when DNS, TLS, and
the page fetch all fail: missing values are filled with 0. That score is not
a live-site judgment. Reachability is classified from exception types and
probe flags, not from warning text, and sits above the model so an
unresolvable name cannot come back as legitimate.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

ReachabilityStatus = Literal["resolved", "unreachable", "fetch_failed", "not_probed"]
NetworkErrorKind = Literal["dns", "timeout", "connection", "ssl", "http", "other"]

# Headlines that are live-site risk, not reachability.
LIVE_RISK_VERDICTS = frozenset({"legitimate", "probably safe", "suspicious", "phishing"})


@dataclass(frozen=True)
class LiveProbe:
    """Structured outcome of DNS / TLS / HTTP probes for one URL."""

    status: ReachabilityStatus
    dns_ok: bool | None
    page_fetched: bool
    tls_inspected: bool

    def to_dict(self) -> dict[str, bool | str | None]:
        return {
            "status": self.status,
            "dns_ok": self.dns_ok,
            "page_fetched": self.page_fetched,
            "tls_inspected": self.tls_inspected,
        }


def _walk_exceptions(exc: BaseException) -> Iterator[BaseException]:
    """Yield ``exc`` and nested causes, including urllib3 ``reason`` links."""

    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        if current.__cause__ is not None:
            stack.append(current.__cause__)
        if current.__context__ is not None:
            stack.append(current.__context__)
        reason = getattr(current, "reason", None)
        if isinstance(reason, BaseException):
            stack.append(reason)
        for arg in getattr(current, "args", ()):
            if isinstance(arg, BaseException):
                stack.append(arg)


def _dns_types() -> tuple[type[BaseException], ...]:
    types: tuple[type[BaseException], ...] = (socket.gaierror,)
    try:
        from urllib3.exceptions import NameResolutionError

        types += (NameResolutionError,)
    except ImportError:
        pass
    try:
        from dns.exception import DNSException

        types += (DNSException,)
    except ImportError:
        pass
    return types


def classify_network_error(exc: BaseException) -> NetworkErrorKind:
    """Map a fetch/TLS exception to a coarse kind without reading error text."""

    dns_types = _dns_types()
    timeout_types: tuple[type[BaseException], ...] = (TimeoutError, socket.timeout)
    ssl_types: tuple[type[BaseException], ...] = ()
    connection_types: tuple[type[BaseException], ...] = (ConnectionError,)
    try:
        import ssl as ssl_mod

        ssl_types += (ssl_mod.SSLError,)
    except ImportError:
        pass
    try:
        import requests.exceptions as rex

        timeout_types += (rex.Timeout,)
        ssl_types += (rex.SSLError,)
        connection_types += (rex.ConnectionError,)
    except ImportError:
        pass

    found_dns = found_timeout = found_ssl = found_conn = False
    for err in _walk_exceptions(exc):
        if isinstance(err, dns_types) or type(err).__name__ == "NameResolutionError":
            found_dns = True
        if isinstance(err, timeout_types):
            found_timeout = True
        if ssl_types and isinstance(err, ssl_types):
            found_ssl = True
        if isinstance(err, connection_types):
            found_conn = True

    if found_dns:
        return "dns"
    if found_timeout:
        return "timeout"
    if found_ssl:
        return "ssl"
    if found_conn:
        return "connection"
    return "other"


def assess_reachability(
    *,
    probed: bool,
    dns_ok: bool | None,
    page_fetched: bool,
    tls_inspected: bool,
) -> LiveProbe:
    """Decide whether the host was seen, does not exist, or could not be fetched.

    Seeing the host means we downloaded a page or completed a TLS handshake.
    A failed DNS lookup with neither of those is ``unreachable``. A name that
    resolves (or that we connected far enough to rule out NXDOMAIN) but that
    we could not inspect is ``fetch_failed``.
    """

    if page_fetched or tls_inspected:
        return LiveProbe(
            status="resolved",
            dns_ok=True,
            page_fetched=page_fetched,
            tls_inspected=tls_inspected,
        )
    if not probed:
        return LiveProbe(
            status="not_probed",
            dns_ok=None,
            page_fetched=False,
            tls_inspected=False,
        )
    if dns_ok is False:
        return LiveProbe(
            status="unreachable",
            dns_ok=False,
            page_fetched=False,
            tls_inspected=False,
        )
    return LiveProbe(
        status="fetch_failed",
        dns_ok=True if dns_ok is None else dns_ok,
        page_fetched=False,
        tls_inspected=False,
    )
