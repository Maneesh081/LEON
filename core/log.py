import logging
import sys

_LEVEL = logging.INFO
_configured = False


def get_logger(name: str) -> logging.Logger:
    global _configured
    if not _configured:
        fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        root = logging.getLogger("leon")
        root.setLevel(_LEVEL)
        root.addHandler(sh)
        _configured = True
    return logging.getLogger(f"leon.{name}")
