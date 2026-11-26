"""Confidence scoring utilities.

Every suggestion produced by PseudoClean carries a confidence value in the
range [0, 100].  Suggestions below the auto-apply threshold are never applied
automatically; they are only presented for user review.

The scale is deliberately conservative: a rename backed by a single weak
signal must not score high even if nothing contradicts it.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Thresholds (configurable through config.py)
# ---------------------------------------------------------------------------

THRESHOLD_REVIEW = 40      # below this -> not even shown
THRESHOLD_APPLY_VAR = 75   # auto-apply variable rename (with user consent mode)
THRESHOLD_APPLY_FUNC = 85  # function renames require stronger evidence

GRADE_HIGH = "HIGH"
GRADE_MEDIUM = "MEDIUM"
GRADE_LOW = "LOW"
GRADE_REJECT = "REJECT"


def grade(confidence: int) -> str:
    if confidence >= 85:
        return GRADE_HIGH
    if confidence >= 60:
        return GRADE_MEDIUM
    if confidence >= THRESHOLD_REVIEW:
        return GRADE_LOW
    return GRADE_REJECT


def combine(*scores) -> int:
    """Combine independent evidence scores.

    Uses a weighted-noisy-or style combination: multiple independent weak
    signals can add up, but a single signal can never reach 100.
    """
    if not scores:
        return 0
    total = 0.0
    for s in scores:
        s = max(0, min(100, int(s)))
        total = 1.0 - (1.0 - total) * (1.0 - s / 100.0 * 0.92)
    return int(round(total * 100))


class Suggestion:
    """A single reviewable change suggestion."""

    KIND_VAR = "var"
    KIND_FUNC = "func"
    KIND_EXPR = "expr"
    KIND_INFO = "info"       # report-only observation, no mutation

    def __init__(self, kind: str, original: str, suggested: str,
                 confidence: int, reason: str, ea: int = 0,
                 func_ea: int = 0, payload=None, annotate: bool = True):
        self.kind = kind
        self.original = original
        self.suggested = suggested
        self.confidence = max(0, min(100, int(confidence)))
        self.reason = reason
        self.ea = ea              # target address (func start for KIND_FUNC)
        self.func_ea = func_ea    # owning function
        self.payload = payload    # module-specific data (e.g. varref index)
        #: whether this observation is worth a persistent code comment.
        #: Pure statistics ("loops=1 ifs=4") are useful in the report table
        #: but read as noise in the pseudocode, so they are not annotated.
        self.annotate = annotate
        self.grade = grade(self.confidence)
        self.selected = self.confidence >= THRESHOLD_REVIEW and \
            self.grade in (GRADE_HIGH, GRADE_MEDIUM)

    def __repr__(self):
        return ("Suggestion(%s %r -> %r conf=%d%% grade=%s reason=%r)"
                % (self.kind, self.original, self.suggested,
                   self.confidence, self.grade, self.reason))


def unique_name(base: str, taken) -> str:
    """Return `base` or `base_N` so it does not collide with `taken`."""
    taken = set(taken)
    if base not in taken:
        return base
    i = 2
    while "%s_%d" % (base, i) in taken:
        i += 1
    return "%s_%d" % (base, i)
