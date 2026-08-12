"""Unit tests for URL-string (Tier A) and HTML (Tier B) extractors."""

from __future__ import annotations

from bs4 import BeautifulSoup

from phishing.config import FEATURE_COLUMNS, LEGITIMATE, PHISHING, SUSPICIOUS
from phishing.features.content_features import (
    extract_content_features,
    redirect_feature,
)
from phishing.features.fetch import FetchResult
from phishing.features.url_features import (
    double_slash_redirecting,
    extract_url_features,
    having_at_symbol,
    having_ip_address,
    having_sub_domain,
    https_token,
    prefix_suffix,
    shortening_service,
    url_length,
)


def test_ip_address_dotted_and_hex():
    assert having_ip_address("http://125.98.3.123/fake.html") == PHISHING
    assert having_ip_address("http://0x58.0xCC.0xCA.0x62/2/paypal.ca/index.html") == PHISHING
    assert having_ip_address("https://www.paypal.com/login") == LEGITIMATE


def test_url_length_thresholds():
    assert url_length("http://example.com/") == LEGITIMATE
    assert url_length("http://example.com/" + "a" * 40) == SUSPICIOUS  # 19+40=59
    assert url_length("http://example.com/" + "a" * 80) == PHISHING


def test_shortener_and_at_and_dash():
    assert shortening_service("http://bit.ly/19DXSk4") == PHISHING
    assert shortening_service("https://www.hud.ac.uk/") == LEGITIMATE
    assert having_at_symbol("http://legit.com@phishing.website.html") == PHISHING
    assert prefix_suffix("http://www.Confirme-paypal.com/") == PHISHING
    assert prefix_suffix("https://www.paypal.com/") == LEGITIMATE


def test_double_slash_position():
    assert double_slash_redirecting("http://www.legitimate.com//http://www.phishing.com") == PHISHING
    assert double_slash_redirecting("https://www.paypal.com/login") == LEGITIMATE


def test_subdomain_and_https_token():
    assert having_sub_domain("http://www.hud.ac.uk/students/") == LEGITIMATE
    assert having_sub_domain("http://login.paypal.com/") == SUSPICIOUS
    assert having_sub_domain("http://login.secure.update.paypal.example.com/") == PHISHING
    assert https_token("http://https-www-paypal-it-webapps-mpp-home.soft-hair.com/") == PHISHING
    assert https_token("https://www.paypal.com/") == LEGITIMATE


def test_extract_url_features_keys_match_tier_a():
    feats = extract_url_features("https://www.example.com/")
    from phishing.config import TIER_A

    assert set(feats) == set(TIER_A)


PHISHY_HTML = """
<html>
<head>
  <link rel="icon" href="https://evil.example/favicon.ico">
  <script src="https://cdn.evil.example/x.js"></script>
  <meta http-equiv="refresh" content="0;url=https://evil.example">
</head>
<body onmouseover="window.status='https://paypal.com';">
  <a href="#">empty</a>
  <a href="https://paypal.com/login">bank</a>
  <a href="/local">ok</a>
  <img src="https://evil.example/pixel.png">
  <img src="/logo.png">
  <form action="about:blank">
    <input type="password" name="pw">
  </form>
  <form action="mailto:phish@evil.example">
    <input type="text">
  </form>
  <iframe src="https://paypal.com" frameborder="0"></iframe>
  <script>
    document.oncontextmenu = function(){return false;};
    if (event.button==2) { return false; }
    window.open('http://popup.example', 'p');
  </script>
</body>
</html>
"""

CLEAN_HTML = """
<html>
<head>
  <link rel="icon" href="/favicon.ico">
  <script src="/app.js"></script>
</head>
<body>
  <a href="/about">About</a>
  <a href="/login">Login</a>
  <img src="/logo.png">
  <form action="/submit" method="post">
    <input type="text" name="q">
  </form>
</body>
</html>
"""


def _fetch(html: str, n_redirects: int = 0) -> FetchResult:
    soup = BeautifulSoup(html, "lxml")
    return FetchResult(
        url="https://example.com/",
        final_url="https://example.com/",
        ok=True,
        status_code=200,
        html=html,
        soup=soup,
        n_redirects=n_redirects,
    )


def test_content_features_on_phishy_html():
    fetch = _fetch(PHISHY_HTML, n_redirects=3)
    feats = extract_content_features(fetch, "https://example.com/")
    assert feats["Iframe"] == PHISHING
    assert feats["Submitting_to_email"] == PHISHING
    assert feats["SFH"] == PHISHING
    assert feats["RightClick"] == PHISHING
    assert feats["Favicon"] == PHISHING
    assert feats["Redirect"] == 1
    assert feats["URL_of_Anchor"] in (SUSPICIOUS, PHISHING)


def test_content_features_on_clean_html():
    fetch = _fetch(CLEAN_HTML, n_redirects=0)
    feats = extract_content_features(fetch, "https://example.com/")
    assert feats["Iframe"] == LEGITIMATE
    assert feats["Submitting_to_email"] == LEGITIMATE
    assert feats["SFH"] == LEGITIMATE
    assert feats["RightClick"] == LEGITIMATE
    assert feats["Favicon"] == LEGITIMATE
    assert feats["Redirect"] == 0
    assert feats["URL_of_Anchor"] == LEGITIMATE
    assert feats["Request_URL"] == LEGITIMATE


def test_redirect_matches_csv_binary_encoding():
    assert redirect_feature(0) == 0
    assert redirect_feature(1) == 0
    assert redirect_feature(2) == 1
    assert redirect_feature(4) == 1
    assert set([redirect_feature(n) for n in range(6)]).issubset({0, 1})
