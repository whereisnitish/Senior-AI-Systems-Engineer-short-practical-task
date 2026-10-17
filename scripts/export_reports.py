"""Export the account register, latest audit report, offboarding reports and the redacted run log.

    python -m scripts.export_reports
"""

from __future__ import annotations

import json

from scripts._common import cli_container


def main() -> None:
    container = cli_container("export")
    with container.uow() as session:
        written = container.reports.export_all(session)
    print(json.dumps(written, indent=2))


if __name__ == "__main__":
    main()
