"""Control-flow pattern analysis.

Everything here is STRUCTURAL and read-only: the walker never mutates the
ctree.  Findings that would require rewriting control flow (flattening,
dead code) are reported for manual reconstruction instead, because rewriting
control flow cannot be proven semantics-preserving in general.

Patterns:

  * early returns / deep nesting / goto density / large switches
  * control-flow flattening: a loop whose condition compares one variable
    against a constant while the body assigns that variable several distinct
    constants (the dispatcher state machine).  Hex-Rays devirtualises the
    original `switch` into an if-chain, so the state variable is the
    reliable signal, not the switch statement.
  * switch inside a loop (classic dispatcher shape)
  * parity-style opaque predicate candidates: a condition that compares
    `(expr & small_mask)` against a constant, where `expr` is a bitwise or
    arithmetic operation over a single variable applied to itself.  These are
    reported as candidates ("verify manually") at low confidence, never as
    proven dead code.
"""

from __future__ import annotations

import ida_hexrays

import ast_analyzer as A
import logging_util as L
from confidence import Suggestion


_CMP_OPS = frozenset((
    ida_hexrays.cot_eq, ida_hexrays.cot_ne,
    ida_hexrays.cot_sge, ida_hexrays.cot_uge,
    ida_hexrays.cot_sle, ida_hexrays.cot_ule,
    ida_hexrays.cot_sgt, ida_hexrays.cot_ugt,
    ida_hexrays.cot_slt, ida_hexrays.cot_ult,
))

_LOOP_OPS = frozenset((
    ida_hexrays.cit_for, ida_hexrays.cit_while, ida_hexrays.cit_do,
))

#: Mask values small enough to be a parity/bit-test predicate
_SMALL_MASKS = frozenset((1, 2, 3, 7, 0xF, 0x1F, 0x3F, 0x7F, 0xFF))


def _const_value(e):
    if e is None:
        return None
    try:
        if e.op == ida_hexrays.cot_num:
            return int(e.numval())
        if e.op == ida_hexrays.cot_cast and e.x is not None:
            return _const_value(e.x)
    except Exception:
        pass
    return None


class _CFWalker(ida_hexrays.ctree_visitor_t):
    def __init__(self, prof):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.p = prof
        self.depth = 0
        self.loop_depth = 0
        self.max_depth = 0
        self.if_count = 0
        self.loop_count = 0
        self.switch_count = 0
        self.switch_cases = []
        self.return_positions = []
        self.early_returns = 0
        self.goto_count = 0
        self.loop_with_break = 0
        self.loop_with_continue = 0
        self.dispatcher_switches = 0
        self.nested_switch = 0
        self.opaque_candidates = []

    # -- instructions ---------------------------------------------
    def visit_insn(self, i):
        op = i.op
        if op == ida_hexrays.cit_if:
            self.if_count += 1
            self.depth += 1
            if self.depth > self.max_depth:
                self.max_depth = self.depth
            try:
                cond = i.cif.expr
                if cond is not None and cond.op in (ida_hexrays.cot_land,
                                                    ida_hexrays.cot_lor):
                    self._count_complex_cond(cond)
                self._check_opaque_predicate(cond)
            except Exception as exc:
                L.debug("condition analysis failed: %s" % exc)
        elif op in _LOOP_OPS:
            self.loop_count += 1
            self.loop_depth += 1
            self._check_loop_body(i)
        elif op == ida_hexrays.cit_switch:
            self.switch_count += 1
            if self.loop_depth > 0:
                self.dispatcher_switches += 1
            self._check_switch(i)
        elif op == ida_hexrays.cit_return:
            self.return_positions.append(i.ea)
            if self.depth > 0:
                self.early_returns += 1
        elif op == ida_hexrays.cit_goto:
            self.goto_count += 1
        return 0

    def leave_insn(self, i):
        if i.op == ida_hexrays.cit_if:
            self.depth -= 1
        elif i.op in _LOOP_OPS:
            self.loop_depth -= 1
        return 0

    # -- helpers ---------------------------------------------------
    @staticmethod
    def _loop_body(loop_ins):
        from ast_analyzer import loop_parts
        _, body = loop_parts(loop_ins)
        return body

    def _count_complex_cond(self, cond, depth=0):
        if depth > 8:
            return
        try:
            for sub in (cond.x, cond.y):
                if sub is None:
                    continue
                if sub.op in (ida_hexrays.cot_land, ida_hexrays.cot_lor):
                    self._count_complex_cond(sub, depth + 1)
                elif sub.op in _CMP_OPS:
                    self.p.complex_conds += 1
        except Exception:
            pass

    def _check_loop_body(self, loop_ins):
        body = self._loop_body(loop_ins)
        if body is None:
            return
        if self._contains(body, ida_hexrays.cit_break):
            self.loop_with_break += 1
        if self._contains(body, ida_hexrays.cit_continue):
            self.loop_with_continue += 1

    def _contains(self, item, op, depth=0):
        if depth > 10 or item is None:
            return False
        try:
            if item.op == op:
                return True
            if item.op == ida_hexrays.cit_block:
                return any(self._contains(sub, op, depth + 1)
                           for sub in item.cblock)
            if item.op == ida_hexrays.cit_if:
                cf = item.cif
                if self._contains(cf.ithen, op, depth + 1):
                    return True
                if cf.ielse is not None:
                    return self._contains(cf.ielse, op, depth + 1)
                return False
            if item.op in _LOOP_OPS:
                return self._contains(self._loop_body(item), op, depth + 1)
            if item.op == ida_hexrays.cit_switch:
                cs = item.cswitch
                for idx in range(len(cs.cases)):
                    if self._contains(cs.cases[idx], op, depth + 1):
                        return True
            return False
        except Exception:
            return False

    def _check_switch(self, sw_ins):
        try:
            cs = sw_ins.cswitch
            n = len(cs.cases)
            self.switch_cases.append(n)
            for idx in range(n):
                case = cs.cases[idx]
                for sub in case.cblock:
                    if sub.op == ida_hexrays.cit_switch:
                        self.nested_switch += 1
        except Exception:
            pass

    # -- opaque predicate candidates -------------------------------
    def _var_names(self, e, depth=0):
        """Names of the variables referenced by `e` (depth-limited)."""
        names = set()
        if e is None or depth > 10:
            return names
        try:
            op = e.op
            if op == ida_hexrays.cot_var:
                try:
                    names.add(self.p.vars[e.v.idx].name)
                except Exception:
                    names.add("#%d" % e.v.idx)
                return names
            for attr in ("x", "y", "z"):
                sub = getattr(e, attr, None)
                if sub is not None and hasattr(sub, "op"):
                    names |= self._var_names(sub, depth + 1)
            if op == ida_hexrays.cot_idx:
                names |= self._var_names(e.y, depth + 1)
        except Exception:
            pass
        return names

    def _mentions(self, e, name, depth=0):
        return name in self._var_names(e, depth)

    def _self_applied(self, e, name, depth=0):
        """True if both operands of a bitwise/arith op use `name`."""
        if e is None or depth > 6:
            return False
        try:
            if e.op not in (ida_hexrays.cot_band, ida_hexrays.cot_bor,
                             ida_hexrays.cot_xor, ida_hexrays.cot_mul,
                             ida_hexrays.cot_add, ida_hexrays.cot_sub):
                return False
            return (self._mentions(e.x, name) and self._mentions(e.y, name))
        except Exception:
            return False

    def _check_opaque_predicate(self, cond):
        """Report parity-style opaque predicate candidates (not proven)."""
        try:
            if cond is None or cond.op not in _CMP_OPS:
                return
            lhs, rhs = cond.x, cond.y
            if lhs is None or rhs is None:
                return
            lc, rc = _const_value(lhs), _const_value(rhs)
            if (lc is None) == (rc is None):
                return                       # exactly one constant side
            side = rhs if lc is not None else lhs
            if side is None or side.op != ida_hexrays.cot_band:
                return
            mask = _const_value(side.y)
            inner = side.x
            if mask is None:
                mask, inner = _const_value(side.x), side.y
            if mask is None or mask not in _SMALL_MASKS or inner is None:
                return
            names = self._var_names(inner)
            if len(names) != 1:
                return
            name = next(iter(names))
            if not self._self_applied(inner, name):
                return
            if name not in self.opaque_candidates:
                self.opaque_candidates.append(name)
        except Exception:
            pass

    # -- flattening ------------------------------------------------
    def detect_dispatcher(self, prof):
        """Control-flow flattening signature.

        A flattened function is a loop whose condition compares one variable
        against a constant while the loop body assigns that same variable
        several distinct constants (the state transitions).  Returns the list
        of (variable name, sorted states) pairs found.
        """
        found = []
        try:
            for v in prof.vars:
                if not v.loop_cond_cmp:
                    continue
                if v.is_state_variable():
                    found.append((v.name, v.distinct_const_states()))
        except Exception:
            pass
        return found


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_control_flow(ea: int, cfunc=None, prof: A.FuncProfile = None):
    """Return (list[Suggestion], walker) of control-flow observations."""
    if prof is None:
        prof = A.build_profile(ea, cfunc)
    cfunc = prof.cfunc

    # extend profile with control-flow-specific counters
    prof.complex_conds = 0

    w = _CFWalker(prof)
    try:
        w.apply_to(cfunc.body, None)
    except Exception as exc:
        L.debug("control flow walker error at %#x: %s" % (ea, exc))

    suggestions = []

    # -- control-flow flattening / state machines --------------------
    for name, states in w.detect_dispatcher(prof):
        shown = ", ".join(str(s) for s in states[:8])
        suggestions.append(Suggestion(
            Suggestion.KIND_INFO,
            "state variable `%s` (%d states)" % (name, len(states)),
            "control-flow flattening: dispatcher loop cycling `%s` through "
            "{%s} — reconstruct as a switch/branch ladder"
            % (name, shown), 88,
            "loop-condition variable assigned %d distinct constants"
            % len(states), ea=ea, func_ea=ea))

    if w.dispatcher_switches > 0:
        suggestions.append(Suggestion(
            Suggestion.KIND_INFO,
            "switch inside loop",
            "dispatcher shape: a switch inside a loop is typical of a state "
            "machine or flattened control flow", 80,
            "switch inside loop", ea=ea, func_ea=ea))

    # -- opaque predicate candidates --------------------------------
    for name in w.opaque_candidates:
        suggestions.append(Suggestion(
            Suggestion.KIND_INFO,
            "predicate over `%s` masked to a small constant" % name,
            "possible opaque predicate (parity-style, verify manually): the "
            "branch condition applies a bitwise operation to `%s` against "
            "itself, then masks the result" % name, 55,
            "single-variable masked predicate", ea=ea, func_ea=ea))

    # Measured on a real CrackMe: a two-branch `switch (i & 1)` renders as an
    # if/else ladder and pushed the depth counter to 4 on a body that holds
    # only two real comparisons.  The advisory therefore also requires a
    # meaningful branch count before it calls the structure "deep".
    if w.max_depth >= 4 and w.if_count >= 6:
        suggestions.append(Suggestion(
            Suggestion.KIND_INFO,
            "nested if depth %d" % w.max_depth,
            "consider extracting inner conditions into a helper function "
            "(manual review suggested)", 70,
            "deep nesting (max depth %d, %d ifs)" % (w.max_depth, w.if_count),
            ea=ea, func_ea=ea))

    if w.goto_count >= 3:
        suggestions.append(Suggestion(
            Suggestion.KIND_INFO,
            "%d goto statements" % w.goto_count,
            "heavy goto usage: manual control-flow reconstruction advised",
            75, "goto count >= 3", ea=ea, func_ea=ea))

    for n in w.switch_cases:
        if n >= 16:
            suggestions.append(Suggestion(
                Suggestion.KIND_INFO,
                "switch with %d cases" % n,
                "large switch; possibly a jump table or state machine",
                65, "large switch", ea=ea, func_ea=ea))
            break

    if w.nested_switch >= 1:
        suggestions.append(Suggestion(
            Suggestion.KIND_INFO,
            "nested switch",
            "switch inside switch: consider splitting into helper functions",
            60, "nested switch", ea=ea, func_ea=ea))

    if prof.complex_conds >= 4:
        suggestions.append(Suggestion(
            Suggestion.KIND_INFO,
            "%d complex boolean conditions" % prof.complex_conds,
            "many `&&`/`||` combinations; consider introducing named flags",
            55, "complex conditions", ea=ea, func_ea=ea))

    # loop/return shape
    shape = ("loops=%d ifs=%d switches=%d returns=%d "
             "(%d early)" % (w.loop_count, w.if_count, w.switch_count,
                             len(w.return_positions), w.early_returns))
    suggestions.append(Suggestion(
        Suggestion.KIND_INFO, "function shape", shape, 100,
        "control-flow summary", ea=ea, func_ea=ea, annotate=False))

    return suggestions, w
