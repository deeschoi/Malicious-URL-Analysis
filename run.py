#!/usr/bin/env python3
"""Repo-root entry point. Equivalent to the installed ``phishing`` console script."""

from __future__ import annotations

from phishing.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
