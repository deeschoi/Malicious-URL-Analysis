"""Hardened HTTP fetch for hostile pages. HTML is parsed; JavaScript is never run."""

from __future__ import annotations

from dataclasses import dataclass, field

import requests
from bs4 import BeautifulSoup

from phishing.features.reachability import classify_network_error

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 8
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 8


@dataclass
class FetchResult:
    url: str
    final_url: str
    ok: bool
    status_code: int | None
    html: str
    soup: BeautifulSoup | None
    n_redirects: int
    history_urls: list[str] = field(default_factory=list)
    error: str | None = None
    error_kind: str | None = None
    content_type: str = ""


def fetch_page(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_BYTES,
) -> FetchResult:
    """GET ``url`` with a short timeout, size cap, and redirect accounting.

    JavaScript is not executed. Features that depend on runtime JS (status-bar
    spoofing, right-click handlers) are approximated from source text.
    """
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    try:
        resp = session.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )
        chunks: list[bytes] = []
        size = 0
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            size += len(chunk)
            if size > max_bytes:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        content_type = resp.headers.get("Content-Type", "")
        html = raw.decode(resp.encoding or "utf-8", errors="replace")
        soup = BeautifulSoup(html, "lxml")
        history = [r.url for r in resp.history]
        return FetchResult(
            url=url,
            final_url=resp.url,
            ok=True,
            status_code=resp.status_code,
            html=html,
            soup=soup,
            n_redirects=len(resp.history),
            history_urls=history,
            content_type=content_type,
        )
    except Exception as exc:  # noqa: BLE001 — extractor must never raise
        return FetchResult(
            url=url,
            final_url=url,
            ok=False,
            status_code=None,
            html="",
            soup=None,
            n_redirects=0,
            error=f"{type(exc).__name__}: {exc}",
            error_kind=classify_network_error(exc),
        )
    finally:
        session.close()
