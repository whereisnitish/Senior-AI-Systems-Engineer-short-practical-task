"""record who controls the assigned mailbox

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-17 13:05:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('instagram_accounts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('company_email_control', sa.Enum('unknown', 'company_controlled', 'non_company', name='controlstatus', native_enum=False, length=40), server_default='unknown', nullable=False))


def downgrade() -> None:
    with op.batch_alter_table('instagram_accounts', schema=None) as batch_op:
        batch_op.drop_column('company_email_control')
