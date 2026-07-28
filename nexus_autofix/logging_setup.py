"""Logging configuration for nexus-autofix runs.

Two sinks, deliberately at different levels:

* console — INFO by default (or DEBUG with --verbose), so a run narrates itself.
* file    — always DEBUG, so full request/response bodies land in the run's audit
            trail even when the console stays readable.

Credentials are never logged: the IQ client passes them via requests' ``auth=``
parameter and this module never logs request headers.
"""

from __future__ import annotations

import logging
from pathlib import Path

CONSOLE_FORMAT = "%(asctime)s %(levelname)-7s %(message)s"
FILE_FORMAT = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
_TIME_FORMAT = "%H:%M:%S"


def configure_logging(log_file: Path | None = None, verbose: bool = False) -> Path | None:
    """Attach console and (optionally) file handlers to the nexus_autofix logger.

    Returns the log file path actually used, or None if no file sink was configured.
    """
    root = logging.getLogger("nexus_autofix")
    root.setLevel(logging.DEBUG)
    # Re-configuring in the same process (e.g. a second run) must not double every line.
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter(CONSOLE_FORMAT, datefmt=_TIME_FORMAT))
    root.addHandler(console)

    if log_file is None:
        return None

    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(FILE_FORMAT))
    root.addHandler(file_handler)
    return log_file
