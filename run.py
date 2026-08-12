#!/usr/bin/env python3
"""Repo-root entry point so you do not have to set PYTHONPATH."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from phishing.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
