"""Library and API recognition.

Deliberately thin: IDA already ships FLIRT signatures, type libraries and
import names.  This module does not duplicate that work; it *consumes* those
results to produce naming hints and readability annotations.
"""

from __future__ import annotations

import ida_funcs
import ida_name
import ida_nalt
import idaapi

import ast_analyzer as A
import logging_util as L


# ---------------------------------------------------------------------------
# Import enumeration (uses IDA's own loader data)
# ---------------------------------------------------------------------------

_import_cache = None


def all_imports():
    """Return dict {ea: "module!name"} of imported functions."""
    global _import_cache
    if _import_cache is not None:
        return _import_cache

    result = {}
    try:
        nmods = ida_nalt.get_import_module_qty()
        for m in range(nmods):
            modname = ida_nalt.get_import_module_name(m) or "?"

            def _cb(ea, name, ordinal):
                if name:
                    result[ea] = "%s!%s" % (modname, name)
                elif ordinal:
                    result[ea] = "%s!ord_%d" % (modname, ordinal)
                return True

            ida_nalt.enum_import_names(m, _cb)
    except Exception as exc:
        L.debug("import enumeration failed: %s" % exc)

    _import_cache = result
    return result


def is_import(ea: int) -> bool:
    return ea in all_imports()


def is_thunk(ea: int) -> bool:
    """True for functions that are simple import thunks."""
    try:
        f = ida_funcs.get_func(ea)
        if f is None:
            return False
        if f.flags & ida_funcs.FUNC_THUNK:
            return True
        name = ida_funcs.get_func_name(ea) or ""
        return name.startswith("j_") or name.startswith(".bnd_")
    except Exception:
        return False


def is_library_function(ea: int) -> bool:
    """True when IDA flagged the function as library code (FLIRT/type info)."""
    try:
        f = ida_funcs.get_func(ea)
        if f is None:
            return False
        return bool(f.flags & ida_funcs.FUNC_LIB)
    except Exception:
        return False


def function_display_name(ea: int) -> str:
    """Human-friendly name for a function, preferring imports/FLIRT names."""
    try:
        f = ida_funcs.get_func(ea)
        if f is None:
            return ida_name.get_ea_name(ea) or ""
        name = ida_funcs.get_func_name(f.start_ea) or ""
        if is_thunk(ea):
            # resolve thunk target
            tgt = _thunk_target(ea)
            if tgt:
                return ida_name.get_ea_name(tgt) or name
        return name
    except Exception:
        return ""


def _thunk_target(ea: int):
    import ida_ua
    try:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            return None
        # jmp near [mem] or jmp near rel
        if insn.itype not in ():
            for op in insn.ops:
                if op.type == 7:  # o_near
                    return op.addr
                if op.type == 2:  # o_mem
                    return op.addr
    except Exception:
        pass
    return None


def callee_summary(ea: int, prof: A.FuncProfile = None, limit: int = 8):
    """Return a short list of names this function calls (for the report)."""
    if prof is None:
        try:
            prof = A.build_profile(ea)
        except Exception:
            return []
    seen = []
    for n in prof.called_names:
        if not n or n in seen:
            continue
        seen.append(n)
        if len(seen) >= limit:
            break
    return seen


def signature_hint(ea: int) -> str:
    """Return IDA's applied function prototype as a string, if any."""
    import ida_typeinf
    try:
        tif = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(tif, ea):
            return tif.dstr()
    except Exception:
        pass
    return ""


def readability_facts(ea: int, prof: A.FuncProfile = None):
    """Collect identity facts used by the readability report."""
    facts = {
        "name": function_display_name(ea),
        "is_import": is_import(ea),
        "is_thunk": is_thunk(ea),
        "is_library": is_library_function(ea),
        "signature": signature_hint(ea),
        "callees": callee_summary(ea, prof),
        "strings": [],
        "imports": [],
    }
    if prof is not None:
        facts["strings"] = [t for _, t in prof.strings[:10]]
        facts["imports"] = sorted(prof.imports)
    return facts
