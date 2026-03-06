from __future__ import annotations

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from services.web.app.config import CONFIG
from services.web.app.deps import archive_events_to_cold


def main() -> None:
    result = archive_events_to_cold(CONFIG.hot_retention_hours)
    print(result)


if __name__ == "__main__":
    main()
