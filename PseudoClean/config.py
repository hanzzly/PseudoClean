"""PseudoClean configuration.

All tunable thresholds and feature switches live here.  Nothing in this
module imports IDA at module import time, so it can be unit-tested with
plain Python; the registry helpers import IDA lazily and are no-ops outside
IDA.
"""

from __future__ import annotations

import json

# ---------------------------------------------------------------------------
# Persistent settings
# ---------------------------------------------------------------------------

#: Registry value name used to persist user settings.
SETTINGS_VALUE = "settings"

#: Name of the IDA registry subkey used to persist user settings.
REGISTRY_SUBKEY = "PseudoClean"

#: Name of the IDA netnode used for change history persistence.
HISTORY_NODE = "$ pseudoclean history"

#: Max number of history entries retained.
HISTORY_LIMIT = 200

# ---------------------------------------------------------------------------
# Confidence thresholds
# ---------------------------------------------------------------------------

MIN_CONFIDENCE_REVIEW = 40  # suggestions below this are dropped entirely

MAX_SUGGESTIONS_PER_FUNC = 64

# ---------------------------------------------------------------------------
# Variable renamer heuristics
# ---------------------------------------------------------------------------

#: A variable must be referenced at least this many times to be renamed.
VAR_MIN_REFS = 1

#: Confidence contributions (0-100 each, combined via confidence.combine).
W_LEN_CALL = 80            # v = strlen(x)
W_MALLOC_CALL = 85         # v = malloc(n) / operator new
W_BYTE_BUFFER_TYPE = 70    # char[]/char* with indexed writes
W_LOOP_COUNTER = 78        # i += const inside loop, compared against bound
W_RESULT_VAR = 70          # written in every return statement
W_PRINTF_ARG = 45          # passed to printf-family (weak, format-dependent)
W_XOR_LOOP = 82            # buf[i] ^= key[i % k] pattern
W_XOR_COMPARE = 76         # (input[i] ^ k) != stored[i] check pattern
W_INPUT_CALL = 72          # buffer passed to scanf/fgets/read
W_MEMCPY_DEST = 72
W_MEMCPY_SRC = 70
W_BOOL_PATTERN = 65        # assigned only 0/1 from comparisons

# ---------------------------------------------------------------------------
# Function renamer heuristics
# ---------------------------------------------------------------------------

FN_W_CRYPTO_CONST = 45     # per strong crypto constant family found
FN_W_XOR_LOOP = 55
FN_W_CRC_TABLE = 70
FN_W_API_HINT = 60         # wraps exactly one import (memcpy wrapper, ...)
FN_W_STRING_HINT = 40      # format strings / distinctive literals
FN_W_CHECK_PATTERN = 55    # returns bool from comparisons of args
FN_W_WRAPPER = 50          # tail-call / single-call wrappers
FN_W_ALLOC = 60
FN_W_DECOMP = 65           # xor-decode loop over a buffer + return buffer

# ---------------------------------------------------------------------------
# Crypto detector constants
# ---------------------------------------------------------------------------

#: AES sbox first 16 bytes (little prefix, high signal together with table size)
AES_SBOX_PREFIX = (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                   0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76)

#: CRC32 polynomial (normal form)
CRC32_POLY = 0xEDB88320

#: Known hash constants -> name (single constants are only *hints*).
KNOWN_CONSTANTS = {
    0x67452301: "MD4/MD5/SHA1 init constant",
    0xEFCDAB89: "MD4/MD5/SHA1 init constant",
    0x98BADCFE: "MD4/MD5/SHA1 init constant",
    0x10325476: "MD4/MD5/SHA1 init constant",
    0xC3D2E1F0: "SHA1 init constant",
    0x243F6A88: "BLAKE2 IV / SHA3 round constant",
    0xEDB88320: "CRC32 (reflected poly)",
    0x04C11DB7: "CRC32 (normal poly)",
    0x9E3779B9: "TEA/XXTEA delta / golden ratio",
    0x9E3779B97F4A7C15: "splitmix64 / golden ratio 64",
    0x61C88647: "TEA delta (negative form)",
    0x5A827999: "SHA1 round constant K1",
    0x6ED9EBA1: "SHA1 round constant K2",
    0x8F1BBCDC: "SHA1 round constant K3",
    0xCA62C1D6: "SHA1 round constant K4",
    0x428A2F98: "SHA256 round constant K1",
    0x71374491: "SHA256 round constant K2",
    0x811C9DC5: "FNV offset basis (32)",
    0x01000193: "FNV 32 prime",
    0xC2B2AE3D: "XXHASH32 prime",
    0x2545F491: "mulberry/threadlike rng",
    0x100000001B3: "FNV-1a 64 prime",
}

#: Base64 alphabet prefixes (standard + URL-safe)
BASE64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BASE64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

# ---------------------------------------------------------------------------
# Expression simplifier
# ---------------------------------------------------------------------------

#: Max expression nodes visited per function before bailing out (safety valve).
EXPR_MAX_NODES = 200000

# ---------------------------------------------------------------------------
# Logging / optional microcode hook
# ---------------------------------------------------------------------------

LOG_DEBUG = False

#: The microcode optinsn_t hook is OFF by default.  Hex-Rays already folds
#: the identities it implements; the hook exists for unusual code generators.
MICROCODE_SIMPLIFIER = False


# ---------------------------------------------------------------------------
# Registry persistence
# ---------------------------------------------------------------------------

def settings_snapshot(auto_apply_high=None, min_confidence=None, debug=None,
                      microcode=None):
    """Return the settings dict that is written to the registry.

    ``auto_apply_high`` is accepted for backwards compatibility with older
    callers but is no longer stored: automatic application of changes is not
    a supported behaviour (review is mandatory).
    """
    del auto_apply_high  # obsolete option, intentionally not persisted
    return {
        "min_confidence": (MIN_CONFIDENCE_REVIEW
                           if min_confidence is None else int(min_confidence)),
        "debug": LOG_DEBUG if debug is None else bool(debug),
        "microcode_simplifier": (MICROCODE_SIMPLIFIER
                                 if microcode is None else bool(microcode)),
    }


def load_settings(apply=True):
    """Read persisted settings from the IDA registry.

    Returns the decoded dict (possibly empty) and, when *apply* is true,
    updates the module globals.  Outside IDA this returns an empty dict.
    """
    global MIN_CONFIDENCE_REVIEW, LOG_DEBUG, MICROCODE_SIMPLIFIER
    try:
        import ida_registry  # noqa: WPS433 - optional IDA dependency
    except Exception:
        return {}

    raw = None
    try:
        raw = ida_registry.reg_read_string(SETTINGS_VALUE, REGISTRY_SUBKEY)
    except Exception:
        return {}
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}

    try:
        if "min_confidence" in data:
            value = max(0, min(100, int(data["min_confidence"])))
            if apply:
                MIN_CONFIDENCE_REVIEW = value
        if "debug" in data:
            if apply:
                LOG_DEBUG = bool(data["debug"])
        if "microcode_simplifier" in data:
            if apply:
                MICROCODE_SIMPLIFIER = bool(data["microcode_simplifier"])
    except Exception:
        return {}
    return data


def save_settings(auto_apply_high=None, min_confidence=None, debug=None,
                  microcode=None):
    """Persist settings into the IDA registry (no-op outside IDA).

    Returns True when the value was written.  The registry signature is
    ``reg_write_string(name, utf8_value, subkey)`` — the value name and the
    serialized value must not be swapped.
    """
    data = settings_snapshot(auto_apply_high=auto_apply_high,
                             min_confidence=min_confidence,
                             debug=debug, microcode=microcode)
    try:
        import ida_registry  # noqa: WPS433 - optional IDA dependency
    except Exception:
        return False
    try:
        ida_registry.reg_write_string(SETTINGS_VALUE, json.dumps(data),
                                      REGISTRY_SUBKEY)
        return True
    except Exception:
        return False


def _load_registry_overrides():
    """Apply persisted settings at import time (best effort)."""
    load_settings(apply=True)


try:  # apply user overrides when running inside IDA
    _load_registry_overrides()
except Exception:
    pass
