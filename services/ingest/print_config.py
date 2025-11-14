"""
/home/siem/siem-solution/services/ingest/print_config.py

Назначение:
  - Диагностика загрузки конфигурации IngestSettings.
  - Запускается в том же окружении, что и systemd-сервис (через .env или /etc/siem/siem.env).
"""

from __future__ import annotations

from pprint import pprint

from .config import IngestSettings


def main() -> None:
    settings = IngestSettings.load()
    pprint(settings)


if __name__ == "__main__":
    main()
