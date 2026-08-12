"""Shared types for extraction warnings and persisted model artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FeatureWarning:
    """A non-fatal extraction failure. The feature is filled with a fallback."""

    feature: str
    message: str
    fallback: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModelArtifact:
    """Metadata stored alongside a fitted sklearn/xgboost/lightgbm estimator."""

    model_name: str
    feature_names: list[str]
    threshold: float
    metrics: dict[str, float]
    trained_at: str
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
