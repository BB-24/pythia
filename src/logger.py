from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

_CONFIGURED = False


def configure_logging(log_path: str | Path = "logs/scanner.log") -> logging.Logger:
    """Configure console INFO logging and rotating file DEBUG logging once."""
    global _CONFIGURED
    logger = logging.getLogger("container_scanner")
    if _CONFIGURED:
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    log_file = Path(log_path)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    _CONFIGURED = True
    return logger


logger = configure_logging()
