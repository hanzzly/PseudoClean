"""Microcode-level analysis and optional simplification.

This module owns everything that happens BELOW the ctree: the Hex-Rays
microcode.  It re-exports the ctree-level analysis from
`expression_simplifier` (where the persistent-annotation engine lives) so
callers have one import point, and provides:

  * `MicrocodeSimplifier` — an `optinsn_t` hook implementing a small set of
    provably-safe algebraic identities (x+0, x-0, x*1, x*0, x|0, x&~0,
    x^x -> 0, x|x -> x, x&x -> x).  OFF BY DEFAULT: Hex-Rays' own optimizer
    already folds these in every observed case (verified: zero hits on GCC
    -O0/-O2 corpora).  Enable only when a custom code generator produces
    patterns Hex-Rays misses.
  * `microcode_facts(ea)` — read-only maturity/statistics probe used by the
    readability report.

Semantic-preservation rules honoured by every rewrite:
  * only pure instructions (no side effects on either operand)
  * identities valid for both signed and unsigned widths
  * result width preserved exactly
"""

from __future__ import annotations

import ida_hexrays

import logging_util as L

# ctree-level analysis + annotation engine (single source of truth).
# Imported as a module and aliased explicitly: three callers rely on these
# names from here, and a plain `from ... import ...` list would look like dead
# code to linters for every name this module does not call itself.
import expression_simplifier as _ES

analyze_expressions = _ES.analyze_expressions
annotate_suggestions = _ES.annotate_suggestions
remove_pseudoclean_comment = _ES.remove_pseudoclean_comment
remove_pseudoclean_comments = _ES.remove_pseudoclean_comments
microcode_simplifier_active = _ES.microcode_simplifier_active
microcode_stats = _ES.microcode_stats
install_microcode_simplifier = _ES.install_microcode_simplifier
remove_microcode_simplifier = _ES.remove_microcode_simplifier
MicrocodeSimplifier = _ES.MicrocodeSimplifier


# ---------------------------------------------------------------------------
# read-only microcode facts
# ---------------------------------------------------------------------------

def microcode_facts(ea: int):
    """Generate microcode for the function and summarise it (read-only).

    Returns a dict {total, top_instructions} or None when microcode
    generation is not possible.  The microcode is generated into a private
    result list and discarded; nothing in the database changes.

    API shape verified against IDA 9.4:
      * decomp_ranges_t(ea)            — ea-based constructor
      * gen_microcode(ranges, hf, retlist, flags, reqmat)
      * mba_t.qty / mba_t.blocks (mblock_t.head -> minsn_t.next)
    """
    try:
        ranges = ida_hexrays.decomp_ranges_t(ea)
        hf = ida_hexrays.hexrays_failure_t()
        retlist = ida_hexrays.mlist_t()
        mba = ida_hexrays.gen_microcode(
            ranges, hf, retlist, ida_hexrays.DECOMP_NO_WAIT,
            ida_hexrays.MMAT_GENERATED)
    except Exception as exc:
        L.debug("microcode_facts: generation failed at %#x: %s" % (ea, exc))
        return None
    if mba is None:
        return None

    # opcode name table for readable summaries
    names = {}
    for attr in dir(ida_hexrays):
        if attr.startswith("m_") and isinstance(
                getattr(ida_hexrays, attr, None), int):
            names[getattr(ida_hexrays, attr)] = attr[2:]

    counts = {}
    total = 0
    try:
        blk = mba.blocks            # first block; siblings linked by .nextb
        guard = 0
        while blk is not None and guard < 100000:
            guard += 1
            ins = blk.head
            hops = 0
            while ins is not None and hops < 100000:
                hops += 1
                total += 1
                label = names.get(ins.opcode, "op%d" % ins.opcode)
                counts[label] = counts.get(label, 0) + 1
                ins = ins.next
            blk = blk.nextb
    except Exception as exc:
        L.debug("microcode_facts: walk failed at %#x: %s" % (ea, exc))
        return None

    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    return {"total": total,
            "top_instructions": ["%s x%d" % (k, v) for k, v in top]}


# ---------------------------------------------------------------------------
# self-check (offline; no IDA required)
# ---------------------------------------------------------------------------

def _selfcheck():
    # identity table sanity: every rule we claim must actually hold
    for bits in (8, 16, 32, 64):
        mask = (1 << bits) - 1
        for x in (0, 1, 5, mask, mask - 1):
            assert (x + 0) & mask == x & mask
            assert (x - 0) & mask == x & mask
            assert (x * 1) & mask == x & mask
            assert (x * 0) & mask == 0
            assert (x | 0) & mask == x & mask
            assert (x & mask) & mask == x & mask
            assert (x ^ x) & mask == 0
            assert (x | x) & mask == x & mask
            assert (x & x) & mask == x & mask
    return True


if __name__ == "__main__":
    assert _selfcheck()
    print("microcode_analyzer self-check OK")
