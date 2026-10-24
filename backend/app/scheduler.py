"""Run NVD feed refreshes continuously in the dedicated updater container."""

import logging
import os
import time
from datetime import datetime, timezone

from app.update_nvd import update_nvd

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("vulnx.scheduler")


def main() -> None:
    interval_hours = float(os.getenv("UPDATE_INTERVAL_HOURS", "24"))
    if interval_hours <= 0:
        raise ValueError("UPDATE_INTERVAL_HOURS must be greater than zero")
    interval_seconds = interval_hours * 60 * 60

    logger.info("NVD refresh worker started; interval is %s hours", interval_hours)
    while True:
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            logger.info("Starting scheduled NVD refresh at %s", started_at)
            update_nvd()
            logger.info("NVD refresh completed successfully")
        except Exception:
            logger.exception("NVD refresh failed; will retry after the configured interval")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    main()
