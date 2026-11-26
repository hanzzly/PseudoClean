"""Expression simplification — analysis + persistent annotations.

HONEST LIMITATION (verified against IDA 9.4, kernel 9.4, Hex-Rays 9.4.0.260714):

Hex-Rays' own optimizer already folds trivial identities (`x+0`, `x*1`,
`x^x`, `x&~0`, ...) before the ctree reaches the decompiler output.  An
empirical test confirmed that even at `-O0` GCC output containing such
identities, the produced pseudocode already shows the folded forms and an
`optinsn_t` hook that implements those identities records zero hits.

Ctree objects in IDA 9.4 are transient: they are rebuilt on every
decompilation, so direct `cexpr_t` edits do not persist and are not visible
after the user closes and re-opens the pseudocode view.  Hex-Rays explicitly
forbids ctree mutation at `func_printed` time.

Therefore, this module:
  1. ANALYZES the ctree and reports simplification opportunities that the
     Hex-Rays optimizer did *not* already apply (redundant casts of the same
     type, `x*2 + x*2`-style algebra, nested casts, redundant boolean
     comparisons, tautologies).
  2. ANNOTATES the pseudocode with persistent ctree user-comments at the
     exact item addresses of those opportunities, when the user opts in.
     These comments persist in the IDA database and survive decompiler
     cache invalidation.
  3. Ships a microcode `optinsn_t` simplifier implementing algebraic
     identities that is OFF by default: Hex-Rays already applies them, so
     the hook is provided for educational purposes and for the rare case
     where a custom compiler produces patterns Hex-Rays misses.
"""

from __future__ import annotations

import ida_hexrays

import config
import ast_analyzer as A
import logging_util as L
from confidence import Suggestion

# Verified opcode values (IDA 9.4)
_COT_CAST = ida_hexrays.cot_cast
_COT_NUM = ida_hexrays.cot_num
_COT_ADD = ida_hexrays.cot_add
_COT_MUL = ida_hexrays.cot_mul
_COT_BAND = ida_hexrays.cot_band
_COT_BOR = ida_hexrays.cot_bor
_COT_XOR = ida_hexrays.cot_xor
_COT_EQ = ida_hexrays.cot_eq
_COT_NE = ida_hexrays.cot_ne

_COMMENT_PREFIX = "PseudoClean:"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _expr_str(e) -> str:
    return A.expr_str(e)


def _same_text(a, b) -> bool:
    try:
        return _expr_str(a) == _expr_str(b)
    except Exception:
        return False


def _const_value(e):
    try:
        if e.op == _COT_NUM:
            return True, e.numval()
        if e.op == _COT_CAST and e.x is not None:
            return _const_value(e.x)
    except Exception:
        pass
    return False, 0


def _type_str(tif) -> str:
    try:
        return tif.dstr() or ""
    except Exception:
        return ""


def _type_size(tif) -> int:
    try:
        return tif.get_size() or 0
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------

def _analyze_node(e, out):
    """Collect observations on one cexpr_t subtree (read-only)."""
    if e is None or not hasattr(e, "op"):
        return
    try:
        op = e.op
    except Exception:
        return

    # -- redundant comparison of a boolean against 0/1 ---------------
    #     pattern:  ((a == b) == 0) / ((a == b) != 0)
    if op in (_COT_EQ, _COT_NE):
        inner = e.x
        y = e.y
        if inner is not None and y is not None and \
                inner.op in (_COT_EQ, _COT_NE):
            is_zero, yv = _const_value(y)
            if is_zero and yv == 0:
                out.append({
                    "kind": "redundant_bool_cmp",
                    "ea": e.ea,
                    "text": _expr_str(e),
                    "fix": "comparison against boolean already yields a "
                           "boolean; simplify to %s" % _expr_str(inner),
                    "conf": 90,
                })

    # -- identity casts ------------------------------------------------
    if op == _COT_CAST:
        inner = e.x
        if inner is not None and inner.op == _COT_CAST:
            out.append({
                "kind": "nested_cast",
                "ea": e.ea,
                "text": _expr_str(e),
                "fix": "two nested casts of the same value",
                "conf": 70,
            })
        elif inner is not None and not _has_call(inner):
            try:
                ot, it = e.type, inner.type
                if ot is not None and it is not None and \
                        _type_str(ot) == _type_str(it) and \
                        _type_size(ot) == _type_size(it) and _type_size(ot):
                    out.append({
                        "kind": "same_type_cast",
                        "ea": e.ea,
                        "text": _expr_str(e),
                        "fix": "identity cast (same type both sides)",
                        "conf": 80,
                    })
            except Exception:
                pass

    # -- repeated arithmetic:  e + e   (e.g. x*2 + x*2) --------------
    if op in (_COT_ADD, _COT_MUL):
        x, y = getattr(e, "x", None), getattr(e, "y", None)
        if x is not None and y is not None and op == _COT_ADD and \
                x.op == _COT_MUL and y.op == _COT_MUL:
            if _same_text(x, y):
                out.append({
                    "kind": "repeated_arith",
                    "ea": e.ea,
                    "text": _expr_str(e),
                    "fix": "`e + e` where e is identical: can be written as "
                           "`e * 2` (same value for unsigned; verify signed "
                           "overflow semantics)",
                    "conf": 65,
                })

    # -- tautologies ---------------------------------------------------
    if op in (_COT_BAND, _COT_BOR, _COT_XOR):
        x, y = getattr(e, "x", None), getattr(e, "y", None)
        if x is not None and y is not None and _same_text(x, y):
            fixes = {_COT_BAND: "`x & x` = `x`",
                     _COT_BOR: "`x | x` = `x`",
                     _COT_XOR: "`x ^ x` = `0`"}
            out.append({
                "kind": "tautology",
                "ea": e.ea,
                "text": _expr_str(e),
                "fix": fixes[op],
                "conf": 85,
            })

    # NOTE: multiplication-by-power-of-two -> shift advice was removed.
    # It is only equivalent when operand widths and signedness match and no
    # signed-overflow UB is introduced; the ctree does not carry enough
    # information here to prove that, so no such suggestion is emitted.


def _has_call(e) -> bool:
    """True if the expression subtree contains a function call."""
    if e is None or not hasattr(e, "op"):
        return False
    try:
        if e.op == ida_hexrays.cot_call:
            return True
    except Exception:
        return False
    for sub in (getattr(e, "x", None), getattr(e, "y", None),
                getattr(e, "z", None)):
        if sub is not None and _has_call(sub):
            return True
    return False


def analyze_expressions(ea: int, cfunc=None, prof: A.FuncProfile = None):
    """Return list[Suggestion] describing simplification opportunities."""
    if cfunc is None:
        cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        return []

    out = []
    visited = [0]

    class W(ida_hexrays.ctree_parentee_t):
        def _budget_ok(self):
            visited[0] += 1
            if visited[0] > config.EXPR_MAX_NODES:
                L.debug("expression walk budget exceeded at %#x" % ea)
                return False
            return True

        def visit_insn(self, i):
            return 0 if self._budget_ok() else 1

        def visit_expr(self, e):
            if not self._budget_ok():
                return 1
            try:
                _analyze_node(e, out)
            except Exception as exc:
                L.debug("expr analyzer error: %s" % exc)
            return 0

    try:
        W(ida_hexrays.CV_FAST).apply_to(cfunc.body, None)
    except Exception as exc:
        L.debug("expression walker error at %#x: %s" % (ea, exc))

    suggestions = []
    seen = set()
    for item in out:
        # Collapse identical observations: the visitor can reach the same
        # expression through different paths and the same text can occur at
        # several addresses.  Keep the first address as the anchor.
        key = (item["kind"], item["text"])
        if key in seen:
            continue
        seen.add(key)
        suggestions.append(Suggestion(
            Suggestion.KIND_INFO,
            item["text"],
            item["fix"],
            item["conf"],
            item["kind"].replace("_", " "),
            ea=item["ea"], func_ea=ea))
    return suggestions


# ---------------------------------------------------------------------------
# annotation (persistent, opt-in)
# ---------------------------------------------------------------------------

def _inline_anchors(cfunc):
    """Addresses that a persistent comment renders inline at, in order.

    Measured on IDA 9.4 over 21 probe placements on two functions:

      * treeloc on a statement-level expression address (``cit_expr``):
        15/15 rendered inline;
      * treeloc on an `if`/`block`/`for`/`goto` insn address: 0/6 rendered
        inline — they appear in an ``Orphan comments`` block after the
        function instead.

    So this list is the *only* set of addresses an annotation may use.
    """
    anchors = []
    try:
        class W(ida_hexrays.ctree_visitor_t):
            def visit_insn(self, i):
                try:
                    if i.op == ida_hexrays.cit_expr and i.ea:
                        anchors.append(i.ea)
                except Exception:
                    pass
                return 0

        W(ida_hexrays.CV_FAST).apply_to(cfunc.body, None)
    except Exception as exc:
        L.debug("anchor scan failed: %s" % exc)
    return anchors


def _pick_anchor(cfunc, want_ea):
    """Closest inline-capable address to `want_ea`, or `want_ea` if none."""
    anchors = _inline_anchors(cfunc)
    if not anchors:
        return want_ea
    if want_ea in anchors:
        return want_ea
    before = [a for a in anchors if want_ea and a < want_ea]
    if before:
        return max(before)
    return anchors[0]


def _first_stmt_ea(cfunc):
    """Address of the first statement inside the body, or 0.

    An annotation placed at the function-entry address is rendered by Hex-Rays
    as an ``Orphan comments`` block *after* the function instead of inside it
    (measured on IDA 9.4).  The first body statement carries a real
    treeloc, so the same comment renders inline there.
    """
    try:
        blk = cfunc.body
        if blk is None or blk.op != ida_hexrays.cit_block:
            return 0
        block = blk.cblock
        if block is None:
            return 0
        for ins in block:
            ea = getattr(ins, "ea", 0)
            if ea:
                return ea
    except Exception as exc:
        L.debug("first statement lookup failed: %s" % exc)
    return 0


def annotate_suggestions(cfunc, suggestions, func_ea: int):
    """Attach persistent ctree user-comments for accepted suggestions.

    Only suggestions that refer to a valid item address are annotated, and
    every comment is snapped to an inline-capable anchor
    (`_pick_anchor`): a treeloc on an insn address (`if`/`block`/`for`)
    renders as an ``Orphan comments`` block after the function — measured
    0/6 inline — while a statement-level expression anchor renders inline
    15/15.  Returns (applied, failed).
    """
    applied, failed = [], []
    seen_locs = set()
    for s in suggestions:
        if not s.selected or s.ea in (0, idaapi_badaddr()):
            continue
        if not getattr(s, "annotate", True):
            continue          # pure statistics are report-only, not comments
        item_ea = _pick_anchor(cfunc, s.ea)
        loc = ida_hexrays.treeloc_t()
        loc.ea = item_ea
        loc.itp = ida_hexrays.ITP_SEMI
        key = (loc.ea, loc.itp)
        if key in seen_locs:
            continue
        seen_locs.add(key)
        try:
            existing = cfunc.get_user_cmt(loc, ida_hexrays.RETRIEVE_ALWAYS) or ""
            if _COMMENT_PREFIX in existing:
                continue  # do not duplicate
            new_cmt = "%s %s" % (_COMMENT_PREFIX, s.suggested)
            cmt = (existing + "\n" + new_cmt) if existing else new_cmt
            cfunc.set_user_cmt(loc, cmt)
            applied.append(s)
        except Exception as exc:
            failed.append((s, str(exc)))
    try:
        cfunc.save_user_cmts()
    except Exception as exc:
        L.debug("save_user_cmts failed: %s" % exc)
        for s in applied:
            failed.append((s, "save_user_cmts failed: %s" % exc))
        return [], failed
    return applied, failed


def remove_pseudoclean_comment(func_ea: int, ea=None, text=None):
    """Remove the PseudoClean annotation created at `func_ea`/`ea`.

    Returns True when an annotation was removed, False when the annotation is
    already absent, and None when the function could not be decompiled (so the
    caller can distinguish "nothing to do" from "temporarily failed").

    Matching both the item address and the text lets the revert remove exactly
    the comment the change manager recorded; a changed item address falls back
    to a text-only match in the same function.
    """
    import idaapi
    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc is None:
        return None
    removed = [0]

    def _strip(cf, item_ea):
        for itp in (ida_hexrays.ITP_SEMI, ida_hexrays.ITP_COLON,
                    ida_hexrays.ITP_CURLY1, ida_hexrays.ITP_CURLY2,
                    ida_hexrays.ITP_BLOCK1, ida_hexrays.ITP_BLOCK2):
            loc = ida_hexrays.treeloc_t()
            loc.ea = item_ea
            loc.itp = itp
            try:
                cmt = cf.get_user_cmt(loc, ida_hexrays.RETRIEVE_ALWAYS) or ""
            except Exception:
                continue
            if _COMMENT_PREFIX not in cmt:
                continue
            keep = []
            for line in cmt.split("\n"):
                if _COMMENT_PREFIX not in line:
                    keep.append(line)
                    continue
                if text and text.strip() and text.strip() not in line:
                    keep.append(line)      # different annotation, leave it
                    continue
                removed[0] += 1
            new = "\n".join(keep).strip()
            try:
                cf.set_user_cmt(loc, new)
            except Exception:
                pass

    try:
        if ea is not None and ea not in (0, idaapi.BADADDR):
            _strip(cfunc, ea)
        if removed[0] == 0:
            # fall back: the item address may have changed after the edit
            class W(ida_hexrays.ctree_parentee_t):
                def visit_insn(self, i):
                    _strip(cfunc, i.ea)
                    return 0

                def visit_expr(self, e):
                    _strip(cfunc, e.ea)
                    return 0

            W(ida_hexrays.CV_FAST).apply_to(cfunc.body, None)
        cfunc.save_user_cmts()
    except Exception as exc:
        L.debug("comment removal error at %#x: %s" % (func_ea, exc))
        return None
    return removed[0] > 0


def idaapi_badaddr():
    import idaapi
    return idaapi.BADADDR


def _strip_pseudoclean_at(cfunc, item_ea, removed):
    """Remove PseudoClean lines from every comment slot at `item_ea`.

    Returns the number of comment lines removed, accumulated into `removed`
    (a one-element list so callers can share a counter).
    """
    import idaapi
    if not item_ea or item_ea == idaapi.BADADDR:
        return
    for itp in (ida_hexrays.ITP_SEMI, ida_hexrays.ITP_COLON,
                ida_hexrays.ITP_CURLY1, ida_hexrays.ITP_CURLY2,
                ida_hexrays.ITP_BLOCK1, ida_hexrays.ITP_BLOCK2):
        loc = ida_hexrays.treeloc_t()
        loc.ea = item_ea
        loc.itp = itp
        try:
            cmt = cfunc.get_user_cmt(loc, ida_hexrays.RETRIEVE_ALWAYS) or ""
        except Exception:
            continue
        if _COMMENT_PREFIX not in cmt:
            continue
        keep = [line for line in cmt.split("\n")
                if _COMMENT_PREFIX not in line]
        try:
            cfunc.set_user_cmt(loc, "\n".join(keep).strip())
            removed[0] += 1
        except Exception:
            pass


def remove_pseudoclean_comments(ea: int):
    """Remove all PseudoClean annotations in the function at `ea`.

    Both slots that PseudoClean can have used are checked, because both were
    verified against real IDA 9.4 data:

    * the **function-entry** slot (`treeloc_t.ea == ea`) is where older
      versions of this plugin anchored control-flow observations.  It is *not*
      reachable by a ctree walk (verified: no visited item carries the
      function's entry address, so a walk-only remover silently removed
      nothing), and it renders as an ``Orphan comments`` block;
    * **item-level** slots are reachable only by walking the body, and items
      with `BADADDR` must be skipped.  Current annotations live here, on the
      first body statement.

    Returns count removed.
    """
    cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        return 0
    removed = [0]
    try:
        _strip_pseudoclean_at(cfunc, ea, removed)
        body_ea = _first_stmt_ea(cfunc)
        if body_ea:
            _strip_pseudoclean_at(cfunc, body_ea, removed)

        class W(ida_hexrays.ctree_parentee_t):
            def visit_insn(self, i):
                _strip_pseudoclean_at(cfunc, i.ea, removed)
                return 0

            def visit_expr(self, e):
                _strip_pseudoclean_at(cfunc, e.ea, removed)
                return 0

        W(ida_hexrays.CV_FAST).apply_to(cfunc.body, None)
        cfunc.save_user_cmts()
    except Exception as exc:
        L.debug("remove comments error at %#x: %s" % (ea, exc))
    return removed[0]


# ---------------------------------------------------------------------------
# Optional microcode hook (off by default — see module docstring)
# ---------------------------------------------------------------------------

class MicrocodeSimplifier(ida_hexrays.optinsn_t):
    """Algebraic identities on microcode.

    Hex-Rays already applies these, so this hook normally makes no changes.
    Provided for education and as a fallback for unusual code generators.
    """

    def __init__(self):
        ida_hexrays.optinsn_t.__init__(self)
        self.stats = {"add0": 0, "sub0": 0, "mul1": 0, "mul0": 0,
                      "or0": 0, "and_all": 0, "xor_self": 0,
                      "band_self": 0, "bor_self": 0}

    def func(self, blk, ins, optflags):
        try:
            return self._optimize(ins)
        except Exception as exc:
            L.debug("microcode simplify error: %s" % exc)
            return 0

    @staticmethod
    def _is_const(mop, val):
        try:
            return (mop.t == ida_hexrays.mop_n and mop.size > 0 and
                    mop.unsigned_value() == val)
        except Exception:
            return False

    @staticmethod
    def _same(a, b):
        try:
            return a.equal_mops(b, ida_hexrays.EQ_IGNSIZE)
        except Exception:
            return False

    def _to_mov(self, ins, src):
        """Turn an arithmetic instruction into ``mov src, dst``.

        Hex-Rays operand layout (verified in the IDA 9.4 SDK and with real
        microcode objects):
            * ``ins.d`` is the **destination** operand
            * ``ins.l`` is the **source** (left operand)
            * ``ins.r`` is unused for ``m_mov``
        The destination is therefore copied verbatim and never overwritten.
        """
        try:
            if src is None or ins.d.size <= 0:
                return 0
            ins.opcode = ida_hexrays.m_mov
            if src is not ins.l:
                ins.l.assign(src)
            ins.r.erase()
            return 1
        except Exception:
            return 0

    def _to_zero(self, ins):
        """Turn an instruction into ``mov #0, dst`` (destination preserved)."""
        try:
            if ins.d.size <= 0:
                return 0
            ins.opcode = ida_hexrays.m_mov
            ins.l.make_number(0, ins.d.size)
            ins.r.erase()
            return 1
        except Exception:
            return 0

    def _optimize(self, ins):
        op = ins.opcode
        l, r = ins.l, ins.r

        # skip anything with side effects — semantic preservation first
        if l.has_side_effects() or r.has_side_effects():
            return 0

        if op in (ida_hexrays.m_add, ida_hexrays.m_or, ida_hexrays.m_xor,
                  ida_hexrays.m_sub):
            if self._is_const(r, 0):
                key = {ida_hexrays.m_add: "add0", ida_hexrays.m_or: "or0",
                       ida_hexrays.m_xor: "xor_self",
                       ida_hexrays.m_sub: "sub0"}[op]
                n = self._to_mov(ins, l)
                if n:
                    self.stats[key] += 1
                return n
            if op == ida_hexrays.m_xor and self._same(l, r):
                n = self._to_zero(ins)
                if n:
                    self.stats["xor_self"] += 1
                return n

        if op == ida_hexrays.m_mul:
            if self._is_const(r, 1):
                n = self._to_mov(ins, l)
                if n:
                    self.stats["mul1"] += 1
                return n
            if self._is_const(r, 0):
                n = self._to_zero(ins)
                if n:
                    self.stats["mul0"] += 1
                return n

        if op == ida_hexrays.m_and:
            try:
                all_ones = (1 << (r.size * 8)) - 1
                if r.t == ida_hexrays.mop_n and r.unsigned_value() == all_ones:
                    n = self._to_mov(ins, l)
                    if n:
                        self.stats["and_all"] += 1
                    return n
            except Exception:
                pass
            if self._same(l, r):
                n = self._to_mov(ins, l)
                if n:
                    self.stats["band_self"] += 1
                return n

        if op == ida_hexrays.m_or and self._same(l, r):
            n = self._to_mov(ins, l)
            if n:
                self.stats["bor_self"] += 1
            return n

        return 0


_MICROCODE_SIMPLIFIER = None


def install_microcode_simplifier():
    global _MICROCODE_SIMPLIFIER
    if _MICROCODE_SIMPLIFIER is not None:
        return True
    try:
        _MICROCODE_SIMPLIFIER = MicrocodeSimplifier()
        _MICROCODE_SIMPLIFIER.install()
        L.log("microcode simplifier installed (opt-in)")
        return True
    except Exception as exc:
        L.warn("failed to install microcode simplifier: %s" % exc)
        _MICROCODE_SIMPLIFIER = None
        return False


def remove_microcode_simplifier():
    global _MICROCODE_SIMPLIFIER
    if _MICROCODE_SIMPLIFIER is None:
        return True
    try:
        _MICROCODE_SIMPLIFIER.remove()
        _MICROCODE_SIMPLIFIER = None
        L.log("microcode simplifier removed")
        return True
    except Exception as exc:
        L.warn("failed to remove microcode simplifier: %s" % exc)
        return False


def microcode_simplifier_active():
    return _MICROCODE_SIMPLIFIER is not None


def microcode_stats():
    if _MICROCODE_SIMPLIFIER is None:
        return {}
    return dict(_MICROCODE_SIMPLIFIER.stats)
