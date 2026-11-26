"""Deterministic variable renaming engine.

Uses the profile from ast_analyzer to suggest new variable names based on
concrete, locally verifiable evidence.  Never renames based on a guess
without evidence, never renames user-named variables, never renames the
same target twice.
"""

from __future__ import annotations

import re

import ida_hexrays

import config
import ast_analyzer as A
import logging_util as L
from confidence import Suggestion, unique_name, combine


# ---------------------------------------------------------------------------
# Name-candidate generation
# ---------------------------------------------------------------------------

#: role -> base name candidates, tried in order
ROLE_NAMES = {
    "counter":     ("idx", "i", "counter"),
    "string":      ("str", "s"),
    "dest":        ("dst", "out"),
    "src":         ("src", "in"),
    "buffer":      ("buf", "buffer"),
    "encoded_data": ("encoded", "data", "buf"),
    "input":       ("input", "user_input", "entered"),
    "result":      ("result", "ret"),
    "flag":        ("flag", "is_valid"),
    "count":       ("len", "count"),
    "size":        ("size", "n"),
    "maxlen":      ("maxlen",),
    "format":      ("fmt", "format"),
    "path":        ("path",),
    "mode":        ("mode",),
    "stream":      ("stream", "fp"),
    "fd":          ("fd",),
    "socket":      ("sock", "socket"),
    "handle":      ("handle", "h"),
    "ptr":         ("ptr",),
    "value":       ("value",),
}

#: Names that carry no information beyond the variable's width.  A suggestion
#: whose base name is one of these is never emitted at all (the audit found
#: ``qword_val``/``value`` noise coming from this fallback path).
GENERIC_NAMES = frozenset((
    "value", "qword_val", "dword_val", "word_val", "byte_val",
))

#: Role names that are honest but uninformative.  They are still offered, but
#: never pre-checked in the review table: the user must opt in explicitly.
WEAK_NAMES = frozenset((
    "ptr", "arr", "var", "tmp",
))

#: width (bytes) -> generic integer fallback.  Only width placeholders live
#: here: a fallback name is never emitted (GENERIC_NAMES), it only documents
#: that no evidence-based name exists for that width.
WIDTH_NAMES = {
    1: ("byte_val",),
    2: ("word_val",),
    4: ("value", "dword_val"),
    8: ("qword_val", "value"),
}

_LEN_CALLEES = A.STRLEN_FAMILY
_ALLOC_CALLEES = A.ALLOC_FAMILY
_MEMCPY_DEST_CALLEES = frozenset(("memcpy", "memmove", "strcpy", "strncpy",
                                  "strcat", "strncat", "sprintf", "snprintf",
                                  "memset"))
_MEMCPY_SRC_CALLEES = frozenset(("memcpy", "memmove", "strcpy", "strncpy",
                                 "strcmp", "strncmp", "printf", "puts"))
_PRINT_CALLEES = A.PRINT_FAMILY


def _base_from_type(vu: A.VarUse):
    """Type-based candidates (weak signal)."""
    tn = (vu.type_name() or "").strip()
    if not tn or tn == "?":
        return None
    if vu.is_char():
        if vu.is_ptr():
            return "str"
        if vu.is_array():
            return "buffer"
    if tn.startswith("const char *"):
        return "str"
    if vu.is_ptr():
        return "ptr"
    if vu.is_array():
        return "arr"
    if vu.is_result:
        return "result"
    return None


def _is_generic(name: str, vu: A.VarUse = None) -> bool:
    """True for names that Hex-Rays generated, which we may rename.

    Besides the obvious ``v1``/``a3`` placeholders, Hex-Rays also *derives*
    lvar names from a format specifier: ``scanf("%49s", s)`` yields a variable
    literally called ``s``.  That is still an auto name, but it is
    indistinguishable from a short user name unless we check the evidence, so
    a single lowercase letter only counts as auto when the variable is
    actually the destination of an input-family call.
    """
    if not name:
        return False
    if re.fullmatch(r"v\d+", name):
        return True
    if re.fullmatch(r"a\d+", name):
        return True
    if vu is not None and re.fullmatch(r"[a-z]", name):
        # Evidence that the letter came from a format specifier or a decoder
        # shape: input-family destination, or the user-supplied side of a
        # comparison-style XOR check.
        if any(fname in A.INPUT_FAMILY for fname, _role in vu.call_roles):
            return True
        return vu.xor_uses > 0 and vu.total_mem_access() > 0
    return False


def _evidence(vu: A.VarUse, prof: A.FuncProfile):
    """Return (role, base_names, [scores]) for one variable, or None."""
    roles = set()
    scores = []

    # -- strlen-family result --------------------------------------
    if any(c in _LEN_CALLEES for c in vu.asg_sources):
        roles.add("count")
        scores.append(config.W_LEN_CALL)

    # -- allocation result -----------------------------------------
    if any(c in _ALLOC_CALLEES for c in vu.asg_sources):
        roles.add("buffer")
        scores.append(config.W_MALLOC_CALL)

    # -- string/buffer usage --------------------------------------
    if vu.is_char() and vu.total_mem_access() > 0:
        roles.add("buffer")
        scores.append(config.W_BYTE_BUFFER_TYPE)
    if vu.mem_dest > 0:
        roles.add("dest")
        scores.append(config.W_MEMCPY_DEST)
        if vu.is_char():
            roles.add("buffer")   # char-typed destinations are buffers
    if vu.mem_src > 0:
        roles.add("src")
        scores.append(config.W_MEMCPY_SRC)

    # -- result of a named call ------------------------------------
    user_calls = [c for c in vu.asg_sources
                  if c not in ("const", "var", "none", "call", "expr",
                               "arith", "cmp", "elem", "deref", "global",
                               "strlit", "shift", "bitop", "cast") and
                  c not in _LEN_CALLEES and c not in _ALLOC_CALLEES and
                  not c.startswith("(*") and not c.startswith(".")]
    if user_calls and not vu.is_arg:
        base_call = sorted(user_calls)[0]
        roles.add("call:" + base_call)
        scores.append(config.W_RESULT_VAR - 5)

    # -- loop counter ---------------------------------------------
    if vu.is_loop_counter():
        roles.add("counter")
        scores.append(config.W_LOOP_COUNTER)

    # -- result variable ------------------------------------------
    if vu.is_result or (vu.return_uses >= max(1, prof.returns) and
                        prof.returns >= 2 and vu.writes >= 1):
        roles.add("result")
        scores.append(config.W_RESULT_VAR)

    # -- printf argument ------------------------------------------
    if vu.print_args > 0 and not vu.mem_dest:
        roles.add("value")
        scores.append(config.W_PRINTF_ARG)

    # -- bool / flag ----------------------------------------------
    if vu.boolish and vu.writes > 0 and vu.total_mem_access() == 0:
        roles.add("flag")
        scores.append(config.W_BOOL_PATTERN)

    # -- xor target ------------------------------------------------
    # Two distinct shapes, and they deserve different names:
    #   * `buf[i] ^= k`   -> the buffer is being encoded in place
    #   * `(buf[i] ^ k) != other[i]` -> the buffer is user input being checked
    if vu.xor_self > 0 and vu.total_mem_access() > 0:
        roles.add("encoded_data")
        scores.append(config.W_XOR_LOOP)
    if vu.xor_uses > 0 and vu.total_mem_access() > 0:
        # comparison-style decoder: this buffer is the user-supplied side
        roles.add("input")
        scores.append(config.W_XOR_COMPARE)
    if any(fname in A.INPUT_FAMILY for fname, _role in vu.call_roles):
        roles.add("input")
        scores.append(config.W_INPUT_CALL)

    if not roles:
        return None

    # pick the strongest role (priority order below)
    priority = ["counter", "count", "input", "buffer", "dest", "src",
                "string", "encoded_data", "result", "flag", "value"]
    role = None
    for cand in priority:
        if cand in roles:
            role = cand
            break
    call_role = None
    for cand in sorted(roles):
        if cand.startswith("call:"):
            call_role = cand[len("call:"):]
            break
    if role is None and call_role is None:
        role = sorted(roles)[0]

    bases = list(ROLE_NAMES.get(role, ())) if role else []
    if call_role:
        bases.insert(0, call_role.lower().lstrip("_") or "result")
    tb = _base_from_type(vu)
    if tb and tb not in bases:
        bases.append(tb)
    if not bases:
        wb = WIDTH_NAMES.get(vu.width, ("value",))
        bases = list(wb)

    return role, bases, scores


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def suggest_variable_names(ea: int, cfunc=None, prof: A.FuncProfile = None):
    """Return list[Suggestion] of variable renames for the function at `ea`."""
    if prof is None:
        prof = A.build_profile(ea, cfunc)
    if prof.truncated:
        L.debug("profile truncated; variable suggestions limited")

    suggestions = []
    taken = set(prof.var_by_name.keys())
    # also reserve names we are about to suggest to avoid collisions
    reserved = set(taken)

    for vu in prof.vars:
        if not vu.name or not _is_generic(vu.name, vu):
            continue
        if vu.refs < config.VAR_MIN_REFS and vu.total_mem_access() == 0:
            continue
        ev = _evidence(vu, prof)
        if ev is None:
            continue
        role, bases, scores = ev
        if not scores:
            continue
        # A variable that is merely printed has no better name than "value";
        # emitting it would only add noise to the review table.
        if role == "value":
            continue
        conf = combine(*scores)
        if conf < config.MIN_CONFIDENCE_REVIEW:
            continue
        new_name = None
        chosen_base = None
        for base in bases:
            if not base or base in GENERIC_NAMES:
                continue          # never emit width-only / placeholder names
            cand = unique_name(base, reserved)
            if cand and cand != vu.name:
                new_name = cand
                chosen_base = base
                break
        if new_name is None:
            continue
        reason = _describe_reason(vu, role)
        derived_auto = bool(re.fullmatch(r"[a-z]", vu.name)) and _is_generic(
            vu.name, vu)
        s = Suggestion(Suggestion.KIND_VAR, vu.name, new_name, conf, reason,
                       ea=vu.first_ea if vu.first_ea != 0x1000000000000000 else ea,
                       func_ea=ea,
                       payload={"idx": vu.idx, "role": role,
                                "derived_auto": derived_auto})
        # Generic/weak names are never pre-checked, even when the confidence
        # grade reaches MEDIUM.  The user must opt in explicitly.
        if chosen_base in WEAK_NAMES or conf < 60:
            s.selected = False
        suggestions.append(s)
        reserved.add(new_name)
        if len(suggestions) >= config.MAX_SUGGESTIONS_PER_FUNC:
            break

    return suggestions


def _describe_reason(vu: A.VarUse, role: str) -> str:
    bits = []
    if role.startswith("call:"):
        bits.append("holds result of %s()" % role[5:])
    if vu.asg_sources:
        callees = sorted(set(c for c in vu.asg_sources if c not in
                             ("const", "var", "none", "call", "expr",
                              "arith", "cmp", "elem", "deref", "global",
                              "strlit", "shift", "bitop", "cast")))
        if callees:
            bits.append("assigned from %s" % ", ".join(callees[:3]))
    if vu.is_loop_counter():
        bits.append("incremented in loop and compared against a bound")
    if vu.total_mem_access():
        bits.append("%d indexed/deref accesses" % vu.total_mem_access())
    if vu.mem_dest:
        bits.append("used as destination in %s" %
                    ", ".join(sorted(vu.callees)[:2]))
    if vu.mem_src:
        bits.append("used as source/argument")
    if vu.boolish:
        bits.append("only ever assigned boolean results")
    if vu.return_uses:
        bits.append("returned %d time(s)" % vu.return_uses)
    if vu.xor_self:
        bits.append("XOR-transformed %d time(s)" % vu.xor_self)
    if vu.print_args:
        bits.append("printed %d time(s)" % vu.print_args)
    if not bits:
        bits.append("role: %s" % role)
    return "%s (%s)" % (role, "; ".join(bits[:3]))


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

def apply_variable_renames(suggestions):
    """Apply accepted variable rename suggestions.  Returns (applied, failed)."""
    applied, failed = [], []
    by_func = {}
    for s in suggestions:
        if s.kind != Suggestion.KIND_VAR or not s.selected:
            continue
        by_func.setdefault(s.func_ea, []).append(s)

    for fea, items in by_func.items():
        try:
            cfunc = ida_hexrays.decompile(fea)
        except Exception as exc:
            L.warn("decompile failed for %#x: %s" % (fea, exc))
            for s in items:
                failed.append((s, str(exc)))
            continue
        if cfunc is None:
            for s in items:
                failed.append((s, "no cfunc"))
            continue
        for s in items:
            try:
                # Safety: never clobber a meaningful name and never rename a
                # variable that no longer exists in the current decompilation.
                # `_is_generic` is re-checked here against the *live* state;
                # derived names (a single letter from a format specifier) are
                # accepted only when the suggestion itself carried the
                # evidence — recorded as payload["derived_auto"] at suggestion
                # time.
                if not _is_generic(s.original) and \
                        not s.payload.get("derived_auto"):
                    failed.append((s, "target is no longer an auto name"))
                    continue
                live = {lv.name for lv in cfunc.get_lvars()}
                if s.original not in live:
                    failed.append((s, "variable no longer exists"))
                    continue
                ok = ida_hexrays.rename_lvar(fea, s.original, s.suggested)
                if ok:
                    applied.append(s)
                else:
                    failed.append((s, "rename_lvar returned False"))
            except Exception as exc:
                failed.append((s, str(exc)))
    return applied, failed


def revert_variable_renames(suggestions):
    """Undo variable renames recorded in `suggestions` (applied ones)."""
    reverted, failed = [], []
    seen = set()
    for s in suggestions:
        key = (s.func_ea, s.original, s.suggested)
        if key in seen:
            continue
        seen.add(key)
        try:
            ok = ida_hexrays.rename_lvar(s.func_ea, s.suggested, s.original)
            if ok:
                reverted.append(s)
            else:
                failed.append((s, "rename back failed"))
        except Exception as exc:
            failed.append((s, str(exc)))
    return reverted, failed
