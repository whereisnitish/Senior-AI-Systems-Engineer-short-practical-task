"""Run the server: ``python -m app``.

Uses uvicorn with its own access log disabled - the application middleware writes
a redacted access line (path, status, timing; never bodies or query strings).
"""

from __future__ import annotations

import uvicorn

from app.config import get_settings
from app.main import create_app


def main() -> None:
    settings = get_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, access_log=False, log_config=None, proxy_headers=False)


if __name__ == "__main__":
    main()
