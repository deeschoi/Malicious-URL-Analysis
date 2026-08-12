"""Project-wide constants. Feature order matches Training_Dataset.csv exactly."""

from pathlib import Path

RANDOM_STATE = 42
N_SPLITS = 5
TEST_SIZE = 0.20

# Repo root: src/phishing/config.py -> parents[2]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_PATH = PROJECT_ROOT / "Training_Dataset.csv"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
REPORTS_DIR = PROJECT_ROOT / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"

# 30 predictors in CSV column order. Models consume this order positionally.
FEATURE_COLUMNS = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

TARGET_COLUMN = "Result"

# URL-string features: computable offline from the URL text alone.
TIER_A = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "HTTPS_token",
]

# Page-content features: require fetching and parsing HTML (no JS execution).
TIER_B = [
    "Favicon",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
]

# Infrastructure features still obtainable in 2026 (TLS / WHOIS / DNS / port).
TIER_C = [
    "SSLfinal_State",
    "Domain_registeration_length",
    "port",
    "Abnormal_URL",
    "age_of_domain",
    "DNSRecord",
]

# Reputation features whose original data sources are gone or impractical.
UNAVAILABLE_2026 = [
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

DEPLOYABLE_FEATURES = [c for c in FEATURE_COLUMNS if c not in UNAVAILABLE_2026]

TIER_A_PLUS_B = TIER_A + TIER_B
TIER_A_PLUS_B_PLUS_C = TIER_A + TIER_B + TIER_C

assert len(FEATURE_COLUMNS) == 30
assert len(TIER_A) == 8
assert len(TIER_B) == 11
assert len(TIER_C) == 6
assert len(UNAVAILABLE_2026) == 5
assert len(DEPLOYABLE_FEATURES) == 25
assert set(TIER_A + TIER_B + TIER_C + UNAVAILABLE_2026) == set(FEATURE_COLUMNS)

# Encoding used throughout the UCI dataset and the live extractor.
PHISHING = -1
SUSPICIOUS = 0
LEGITIMATE = 1

# Recoded target: 1 = phishing (positive class), 0 = legitimate.
POSITIVE_CLASS = 1
NEGATIVE_CLASS = 0

# Default classification threshold before calibration / F1 search.
DEFAULT_THRESHOLD = 0.5

# Risk bands applied to calibrated phishing probability.
RISK_BANDS = [
    (0.00, 0.25, "low"),
    (0.25, 0.50, "medium"),
    (0.50, 0.75, "high"),
    (0.75, 1.01, "critical"),
]
