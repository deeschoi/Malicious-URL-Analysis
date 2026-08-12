"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from phishing.data import load_raw, load_xy


@pytest.fixture(scope="session")
def raw_df():
    return load_raw()


@pytest.fixture(scope="session")
def xy():
    return load_xy()
