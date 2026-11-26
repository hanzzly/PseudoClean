"""Shared logging helpers (deterministic, local-only)."""

from __future__ import annotations

import config


def log(msg: str):
    try:
        import ida_kernwin
        ida_kernwin.msg("[PseudoClean] %s\n" % msg)
    except Exception:
        print("[PseudoClean] %s" % msg)


def debug(msg: str):
    if config.LOG_DEBUG:
        log("DBG: " + msg)


def warn(msg: str):
    log("WARNING: " + msg)