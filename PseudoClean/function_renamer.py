"""Deterministic function renaming engine.

Every candidate name is derived from concrete structural evidence:

  * single-import wrappers            (call_count == 1, callee known)
  * XOR-decode / CRC loops            (from crypto_detector findings)
  * string API + memory writes        (strlen/strcpy family + loop + stores)
  * allocation patterns               (malloc/calloc/new family)
  * validation shape                  (bool return, arg comparisons, no side
                                       effects on memory)
  * pure printf-family functions      (output formatting)
  * distinctive string literals        (error / key / licence wording)

Each hypothesis collects its own independent evidence scores; the strongest
hypothesis wins.  Scores are never mixed between competing hypotheses — a
weak XOR hint and a weak wrapper hint must not add up into a confident name.

Only functions whose current name is an IDA auto name (`sub_*`, `nullsub_*`,
`unknown_*`, `j_sub_*`) are ever renamed.  A meaningful name supplied by the
user or by a library signature is never touched.
"""

from __future__ import annotations

import re

import ida_funcs
import ida_name

import config
import ast_analyzer as A
import crypto_detector as C
import logging_util as L
from confidence import Suggestion, combine, unique_name


# ---------------------------------------------------------------------------
# Auto-name detection
# ---------------------------------------------------------------------------

_AUTO_NAME_RE = re.compile(
    r"^(?:j_)?(?:sub_[0-9A-Fa-f]+|nullsub_[0-9A-Fa-f]+|"
    r"unknown_[0-9A-Fa-f]+|unknown_libname_[0-9A-Fa-f]+)$")


def is_auto_name(name: str) -> bool:
    """True when the name is an IDA-generated placeholder."""
    if not name:
        return False
    return bool(_AUTO_NAME_RE.match(name))


#: Backwards-compatible private alias
_is_auto_name = is_auto_name


# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------

def _imports_of(prof: A.FuncProfile):
    return set(prof.imports)


def _modifies_buffer_in_loop(prof: A.FuncProfile) -> bool:
    """True when the function stores through a pointer/array inside a loop."""
    if not prof.loops:
        return False
    return any((v.idx_writes or v.deref_writes) for v in prof.vars)


def _writes_memory(prof: A.FuncProfile) -> bool:
    return any((v.idx_writes or v.deref_writes or v.mem_dest)
               for v in prof.vars)


def _called_import_set(prof: A.FuncProfile):
    """Callees that are known C runtime functions (imports)."""
    return {n for n in prof.called_names if n in A.ARG_ROLES}


def _is_pseudo_callee(name: str) -> bool:
    """True for JUMPOUT/intrinsic/macro-like callees that are not real APIs."""
    if not name:
        return True
    raw = name.strip()
    # Import thunks carry __imp_/_imp__ prefixes but are real APIs: strip them
    # before the intrinsic test, otherwise __imp_strlen would look like __ROL4__.
    for prefix in ("__imp__", "__imp_", "_imp__", "_imp_"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            break
    # Compiler intrinsics and Hex-Rays pseudo-functions start with "__"
    # (__ROL4__, __PAIR__) or are ALL-CAPS macros (JUMPOUT, HIBYTE, LOBYTE).
    if raw.startswith("__"):
        return True
    if re.fullmatch(r"[A-Z0-9_]+", raw) and any(ch.isalpha() for ch in raw):
        return True
    low = A.normalize_callee(raw).lower().lstrip("_")
    if low.endswith("__"):
        return True
    if low in ("jumpout", "jumpout_qword", "hibyte", "lobyte", "hiword",
               "loword", "bswap", "byteswap", "byte", "word", "dword",
               "qword"):
        return True
    if re.match(r"^ro[lr]\d*$", low):
        return True
    return False


def _wrapper_name(callee: str):
    """Derive a wrapper function name from a single callee."""
    if not callee:
        return None
    if _is_pseudo_callee(callee):
        return None
    if is_auto_name(callee):
        # sub_1020 / j_sub_1020 / nullsub_7: a call to another unnamed
        # function says nothing about what this function does.
        return None
    c = A.normalize_callee(callee).lower().lstrip("_")
    c = re.sub(r"@@?.*$", "", c)          # strip C++ decorations
    if not re.match(r"^[a-z][a-z0-9_]*$", c):
        return None
    if is_auto_name(c):
        return None
    if c.endswith("__"):
        return None
    if len(c) > 24:
        return None
    return c


_WRAPPER_SPECIAL = {
    "memcpy": "copy_memory",
    "memmove": "move_memory",
    "memset": "fill_memory",
    "memcmp": "compare_memory",
    "strlen": "get_length",
    "strcpy": "copy_string",
    "strncpy": "copy_string",
    "strcmp": "compare_string",
    "malloc": "allocate_buffer",
    "calloc": "allocate_buffer",
    "free": "release_buffer",
    "printf": "print_message",
    "puts": "print_message",
}


# ---------------------------------------------------------------------------
# Hypotheses
# ---------------------------------------------------------------------------

def _candidates(prof: A.FuncProfile, crypto_findings):
    """Return a list of candidate dicts: {name, scores, reasons}."""
    out = []
    callees = set(prof.called_names)
    called_imports = _called_import_set(prof)
    imports = _imports_of(prof)

    # -- 1. single-import wrapper ---------------------------------
    # Only a call to a *known imported API* counts as wrapper evidence.
    # A single call to an arbitrary local helper is incidental and must not
    # produce a function name.
    if prof.call_count == 1 and len(callees) == 1:
        callee = next(iter(callees))
        if callee in called_imports:
            base = _wrapper_name(callee)
            if base:
                out.append({
                    "name": _WRAPPER_SPECIAL.get(base, base),
                    "scores": [config.FN_W_WRAPPER],
                    "reasons": ["single call to %s() (wrapper)" % callee],
                })

    # -- 2. crypto / bitwise patterns -----------------------------
    for finding in crypto_findings or ():
        algo = (finding.get("algo") or "").lower()
        if not algo:
            continue

        if "xor" in algo:
            scores = [config.FN_W_XOR_LOOP]
            reasons = ["XOR loop over data"]
            if _modifies_buffer_in_loop(prof):
                scores.append(config.FN_W_DECOMP)
                reasons.append("writes transformed bytes back into a buffer")
                name = "xor_decode"
            else:
                name = "xor_transform"
            out.append({"name": name, "scores": scores, "reasons": reasons})

        elif algo == "mba":
            out.append({
                "name": "mba_arithmetic",
                "scores": [config.FN_W_CRYPTO_CONST],
                "reasons": ["mixed boolean-arithmetic identity found"],
            })

        elif "crc" in algo:
            out.append({
                "name": "crc32_checksum",
                "scores": [config.FN_W_CRC_TABLE],
                "reasons": ["CRC polynomial / table-shift loop"],
            })

        elif "base64" in algo:
            out.append({
                "name": "base64_transform",
                "scores": [config.FN_W_CRYPTO_CONST],
                "reasons": ["base64 alphabet table referenced"],
            })

        elif algo in ("md5", "sha1", "sha256", "sha512", "sha3", "blake",
                      "aes", "des", "rc4", "tea", "xxtea", "fnv", "xxhash"):
            scores = [config.FN_W_CRYPTO_CONST]
            reasons = ["%s constants present" % algo]
            if prof.loops:
                scores.append(35)
                reasons.append("block-processing loop")
            out.append({"name": "%s_hash" % algo if algo in
                        ("md5", "sha1", "sha256", "sha512", "sha3", "blake",
                         "fnv", "xxhash") else "%s_transform" % algo,
                        "scores": scores, "reasons": reasons})

        elif "swap" in algo or "bswap" in algo:
            out.append({
                "name": "byteswap",
                "scores": [config.FN_W_CRYPTO_CONST],
                "reasons": ["byte-swap pattern"],
            })

        elif "rotate" in algo:
            out.append({
                "name": "rotate_bits",
                "scores": [config.FN_W_CRYPTO_CONST // 2],
                "reasons": ["paired shift pattern (rotate)"],
            })

    # -- 3. string manipulation -----------------------------------
    if called_imports & {"strlen", "strcpy", "strncpy", "strcat", "strncat",
                         "strcmp", "strncmp", "strchr", "strstr", "strtok"}:
        if prof.loops and _writes_memory(prof):
            out.append({
                "name": "string_manipulate",
                "scores": [config.FN_W_STRING_HINT],
                "reasons": ["string API + loop + memory writes"],
            })
        elif not prof.loops and called_imports & {"strcmp", "strncmp"}:
            out.append({
                "name": "compare_string",
                "scores": [config.FN_W_STRING_HINT],
                "reasons": ["string comparison without loops"],
            })

    # -- 4. allocation -------------------------------------------
    if imports & A.ALLOC_FAMILY or called_imports & A.ALLOC_FAMILY:
        scores = [config.FN_W_ALLOC]
        reasons = ["allocation API called"]
        if "free" in called_imports:
            scores.append(config.FN_W_ALLOC // 2)
            reasons.append("paired with free()")
        name = "allocate_buffer"
        if "memset" in called_imports:
            name = "allocate_zeroed_buffer"
        out.append({"name": name, "scores": scores, "reasons": reasons})

    # -- 5. validation shape -------------------------------------
    if 1 <= prof.returns <= 2 and prof.ifs >= 1 and prof.loops == 0 and \
            not _writes_memory(prof):
        if any(v.cmp_count > 0 and v.is_arg for v in prof.vars):
            out.append({
                "name": "validate_input",
                "scores": [config.FN_W_CHECK_PATTERN],
                "reasons": ["returns a boolean from argument comparisons"],
            })

    # -- 6. pure output function ---------------------------------
    if prof.call_count >= 1 and called_imports and \
            called_imports <= A.PRINT_FAMILY:
        out.append({
            "name": "print_message",
            "scores": [config.FN_W_STRING_HINT],
            "reasons": ["only calls printf-family functions"],
        })

    # -- 7. free-only teardown -----------------------------------
    if prof.call_count == 1 and called_imports == {"free"}:
        out.append({
            "name": "release_buffer",
            "scores": [config.FN_W_WRAPPER],
            "reasons": ["single call to free()"],
        })

    # -- 8. string literal hints ---------------------------------
    for _, txt in prof.strings[:8]:
        t = txt.lower()
        if any(k in t for k in ("error", "fail", "invalid", "corrupt",
                                "bad ", "cannot", "denied", "not allowed")):
            out.append({
                "name": "handle_error",
                "scores": [config.FN_W_STRING_HINT],
                "reasons": ["error-style literal %r" % txt[:40]],
            })
            break
        if any(k in t for k in ("key", "password", "secret", "token",
                                "licence", "license", "serial")):
            out.append({
                "name": "check_key",
                "scores": [config.FN_W_STRING_HINT],
                "reasons": ["key/licence-style literal %r" % txt[:40]],
            })
            break

    return out


def _choose(candidates):
    """Return (name, confidence, reason) for the strongest hypothesis."""
    best = None
    for cand in candidates:
        conf = combine(*cand["scores"])
        if best is None or conf > best[1]:
            best = (cand["name"], conf, cand["reasons"])
    if best is None:
        return None, 0, ""
    return best[0], best[1], "; ".join(best[2][:3])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def suggest_function_names(ea: int, cfunc=None, prof: A.FuncProfile = None,
                           crypto_findings=None):
    """Return list[Suggestion] holding at most one function name change."""
    # Library bodies are never renamed, regardless of how this function was
    # reached (bulk pass or a direct per-function call).
    if A.is_library_function(ea):
        return []
    if prof is None:
        try:
            prof = A.build_profile(ea, cfunc)
        except Exception as exc:
            L.debug("function naming: profile failed at %#x: %s" % (ea, exc))
            return []
    if crypto_findings is None:
        try:
            crypto_findings = C.analyze_function(prof)
        except Exception:
            crypto_findings = []

    old_name = ida_funcs.get_func_name(ea) or ""
    if not is_auto_name(old_name):
        return []                       # never touch meaningful names

    if not prof.called_names and not prof.strings and not prof.loops:
        return []                       # not enough evidence to name anything

    base, conf, reason = _choose(_candidates(prof, crypto_findings))
    if not base or conf < config.MIN_CONFIDENCE_REVIEW:
        return []

    new_name = unique_name(base, _taken_names(old_name))
    if new_name == old_name:
        return []
    return [Suggestion(Suggestion.KIND_FUNC, old_name, new_name, conf,
                       reason or "behavioral pattern", ea=ea, func_ea=ea)]


def _taken_names(extra=None):
    """Collect existing symbol names to avoid collisions."""
    taken = set()
    try:
        import idautils
        for _, name in idautils.Names():
            taken.add(name)
    except Exception:
        pass
    if extra:
        taken.add(extra)
    return taken


def suggest_function_names_all(progress=None, limit=None, skip_library=True):
    """Run function naming over every decompilable function."""
    import idautils
    suggestions = []
    funcs = list(idautils.Functions())
    if limit:
        funcs = funcs[:limit]
    total = len(funcs)
    for i, fea in enumerate(funcs):
        if progress is not None and i % 25 == 0:
            if not progress(i, total):
                break
        if skip_library and not A.is_decompilable(fea, skip_library=True):
            continue
        try:
            suggestions.extend(suggest_function_names(fea))
        except Exception as exc:
            L.debug("function naming failed at %#x: %s" % (fea, exc))
    return suggestions


# ---------------------------------------------------------------------------
# Application / revert
# ---------------------------------------------------------------------------

def apply_function_renames(suggestions):
    """Apply accepted function rename suggestions.

    Returns (applied, failed); `failed` items are (suggestion, reason) pairs.
    """
    applied, failed = [], []
    for s in suggestions:
        if s.kind != Suggestion.KIND_FUNC or not s.selected:
            continue
        try:
            old = ida_funcs.get_func_name(s.ea) or ""
            if old != s.original:
                failed.append((s, "name changed externally (now %r)" % old))
                continue
            if not is_auto_name(old):
                failed.append((s, "target is no longer an auto name"))
                continue
            ok = ida_name.set_name(s.ea, s.suggested,
                                   ida_name.SN_NOWARN | ida_name.SN_FORCE)
            if ok:
                applied.append(s)
            else:
                failed.append((s, "set_name failed"))
        except Exception as exc:
            failed.append((s, str(exc)))
    return applied, failed


def revert_function_renames(suggestions):
    """Undo previously applied function renames."""
    reverted, failed = [], []
    for s in suggestions:
        try:
            cur = ida_funcs.get_func_name(s.ea) or ""
            if cur != s.suggested:
                failed.append((s, "current name differs (%r)" % cur))
                continue
            ok = ida_name.set_name(s.ea, s.original,
                                   ida_name.SN_NOWARN | ida_name.SN_FORCE)
            if ok:
                reverted.append(s)
            else:
                failed.append((s, "set_name failed"))
        except Exception as exc:
            failed.append((s, str(exc)))
    return reverted, failed
