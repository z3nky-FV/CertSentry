import os
from pathlib import Path

TELEGRAM_BOT_TOKEN: str | None = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID: str | None = os.getenv("TELEGRAM_CHAT_ID")
FRONTEND_ORIGINS: list[str] = [
    origin.strip() for origin in os.getenv("FRONTEND_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]
SCAN_TIMEOUT: int = max(1, int(os.getenv("SCAN_TIMEOUT", "10")))
SCAN_CONCURRENCY: int = min(256, max(1, int(os.getenv("SCAN_CONCURRENCY", "50"))))
NOTIFY_THRESHOLDS: list[int] = [int(x) for x in os.getenv("NOTIFY_THRESHOLDS", "60,30,14,7,1").split(",")]
DATABASE_PATH = Path(os.getenv("RADAR_DATABASE_PATH", str(Path(__file__).resolve().parents[1] / "data" / "certificates.sqlite3")))

THRESHOLD_OK: int = int(os.getenv("THRESHOLD_OK", "60"))
THRESHOLD_INFO: int = int(os.getenv("THRESHOLD_INFO", "30"))
THRESHOLD_WARNING: int = int(os.getenv("THRESHOLD_WARNING", "14"))
if not THRESHOLD_OK > THRESHOLD_INFO > THRESHOLD_WARNING >= 0:
    raise ValueError("Set thresholds so OK > INFO > WARNING >= 0")
