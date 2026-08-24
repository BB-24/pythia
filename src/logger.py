from __future__ import annotations

import logging
import logging.handlers
from contextlib import contextmanager
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


@contextmanager
def scan_logging(scan_id: str, log_dir: str | Path = "logs"):
    """Write one scan's records to a dedicated log file."""
    log_path = Path(log_dir) / f"{scan_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    ))
    logger.addHandler(handler)
    try:
        logger.info("Scan started: %s", scan_id)
        yield log_path
    finally:
        logger.info("Scan finished: %s", scan_id)
        logger.removeHandler(handler)
        handler.close()


@contextmanager
def quiet_console_logging(level: int = logging.WARNING):
    """Temporarily hide routine library logging from the interactive console."""
    console_handlers = [
        handler for handler in logger.handlers
        if isinstance(handler, logging.StreamHandler)
        and not isinstance(handler, logging.FileHandler)
    ]
    previous_levels = {handler: handler.level for handler in console_handlers}
    for handler in console_handlers:
        handler.setLevel(level)
    try:
        yield
    finally:
        for handler, previous_level in previous_levels.items():
            handler.setLevel(previous_level)
