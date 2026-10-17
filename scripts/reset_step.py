"""Withdraw a completed pre-signup step (handle, email or phone) so its task is done again (admin, host shell).

    python -m scripts.reset_step --step handle_selected --reason "placeholder evidence; redo the check properly"

Allowed only before signup. The completed task stays in the history with a ``step_reset`` event; a fresh
task replaces it and its owner is notified.
"""

from __future__ import annotations

import argparse

from sqlalchemy import select

from app.enums import ProvisioningStep
from app.models import InstagramAccount
from app.security.authorization import SYSTEM_ACTOR
from scripts._common import cli_container


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--step", required=True, choices=["handle_selected", "company_email", "company_phone"])
    parser.add_argument("--reason", required=True, help="why the confirmed step is withdrawn (kept in the task history)")
    parser.add_argument("--account-id", help="defaults to the only non-synthetic account")
    args = parser.parse_args()
    container = cli_container("reset-step")
    with container.uow() as session:
        account_id = args.account_id
        if account_id is None:
            ids = list(session.scalars(select(InstagramAccount.id).where(InstagramAccount.is_synthetic.is_(False))))
            if len(ids) != 1:
                raise SystemExit(f"{len(ids)} live accounts exist: pass --account-id")
            account_id = ids[0]
        task = container.provisioning.reset_step(
            session, account_id, step=ProvisioningStep(args.step), reason=args.reason, actor=SYSTEM_ACTOR
        )
        account = container.provisioning.get_account(session, account_id)
        print(f"Step '{args.step}' reset on {account.brand_name}; account status is now {account.provisioning_status.value}.")
        if task is not None:
            print(f"New task {task.id}: '{task.title}', owner notified, due {task.due_at:%Y-%m-%d %H:%M} UTC.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
