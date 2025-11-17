from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

# Базовая директория модуля app (где лежит этот файл)
BASE_DIR = Path(__file__).resolve().parent

# Ожидаем, что HTML шаблоны лежат в каталоге:
#   /home/siem/siem-solution/services/web/app/templates/
# (т.е. рядом с этим файлом, но уже как папка с .html)
templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)
