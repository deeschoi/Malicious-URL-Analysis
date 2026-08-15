"""Create the scans table.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("url_hash", sa.String(length=64), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("probability", sa.Float(), nullable=False),
        sa.Column("model_name", sa.String(length=64), nullable=False),
        sa.Column("warn_threshold", sa.Float(), nullable=False),
        sa.Column("block_threshold", sa.Float(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("page_fetched", sa.Boolean(), nullable=False),
        sa.Column("tls_checked", sa.Boolean(), nullable=False),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("signals", sa.JSON(), nullable=False),
    )
    op.create_index("ix_scans_created_at", "scans", ["created_at"])
    op.create_index("ix_scans_url_hash", "scans", ["url_hash"])
    op.create_index("ix_scans_host", "scans", ["host"])
    op.create_index("ix_scans_verdict", "scans", ["verdict"])


def downgrade() -> None:
    op.drop_index("ix_scans_verdict", table_name="scans")
    op.drop_index("ix_scans_host", table_name="scans")
    op.drop_index("ix_scans_url_hash", table_name="scans")
    op.drop_index("ix_scans_created_at", table_name="scans")
    op.drop_table("scans")
