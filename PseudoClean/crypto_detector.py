"""Cryptographic and bitwise pattern detection.

Deterministic constant- and structure-based detection.  A single constant
match is reported as a HINT only; algorithm claims require corroborating
structure (loops, rotations, table access patterns).
"""

from __future__ import annotations

import ida_hexrays

import config
import ast_analyzer as A
import logging_util as L


# ---------------------------------------------------------------------------
# Constant tables
# ---------------------------------------------------------------------------

_AES_SBOX_PREFIX = config.AES_SBOX_PREFIX

_CRC_POLYS = {config.CRC32_POLY: "CRC32",
              0x04C11DB7: "CRC32(normal)"}

#: Base64 alphabet as 16 leading bytes; table detection scans string/rodata
_BASE64_STD_PREFIX = config.BASE64_STD[:16]
_BASE64_URL_PREFIX = config.BASE64_URL[:16]


# ---------------------------------------------------------------------------
# Structure-based detectors
# ---------------------------------------------------------------------------

def _xor_operand_constants(prof: A.FuncProfile):
    """[(value, xor_ea, anchor_ea)] for every constant XOR operand.

    This is what turns a generic ``xor`` finding into something a reader can
    act on: ``(input[i] ^ 0x08) != buf[i]`` tells the analyst which key
    schedule the binary uses, and the address tells them where to look.

    ``anchor_ea`` is an address a persistent comment can actually use.
    Measured on IDA 9.4 with this exact binary:

      * treeloc on an insn address (`if`, `block`, `for`, `goto`) renders as
        an ``Orphan comments`` block *after* the function;
      * treeloc on a statement-level expression address (`cit_expr`) renders
        inline, every time (13/13 statements tested).

    The anchor is therefore the last expression statement before the loop
    that performs the check — which is also where the reader wants the note:
    directly above the loop.
    """
    found = []
    cfunc = getattr(prof, "cfunc", None)
    if cfunc is None:
        return found

    stmt_expr_eas = []
    loop_ops = (ida_hexrays.cit_for, ida_hexrays.cit_while,
                ida_hexrays.cit_do)

    class W(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.stack = []

        def visit_insn(self, i):
            try:
                if i.op == ida_hexrays.cit_expr:
                    stmt_expr_eas.append(i.ea)
                self.stack.append((i.op, i.ea))
            except Exception:
                pass
            return 0

        def leave_insn(self, i):
            if self.stack:
                self.stack.pop()
            return 0

        def visit_expr(self, e):
            try:
                if e.op != ida_hexrays.cot_xor:
                    return 0
                keys = [side.numval() for side in (e.x, e.y)
                        if side is not None
                        and side.op == ida_hexrays.cot_num]
                if not keys:
                    return 0
                # the loop that owns this XOR, else the innermost if
                bound = 0
                for op, ea in reversed(self.stack):
                    if op in loop_ops:
                        bound = ea
                        break
                if not bound:
                    for op, ea in reversed(self.stack):
                        if op == ida_hexrays.cit_if:
                            bound = ea
                            break
                before = [se for se in stmt_expr_eas if bound and se < bound]
                anchor = max(before) if before else 0
                for key in keys:
                    found.append((key, e.ea, anchor))
            except Exception:
                pass
            return 0

    try:
        W().apply_to(cfunc.body, None)
    except Exception as exc:
        L.debug("xor operand scan failed at %#x: %s" % (prof.ea, exc))
    return found


def format_xor_keys(consts):
    """`0x08, 0x10` — keys as the analyst writes them.

    Accepts both the raw ``_xor_operand_constants`` tuples (key, xor_ea,
    anchor_ea) and a plain list of keys.
    """
    vals = []
    for item in consts:
        val = item[0] if isinstance(item, (tuple, list)) else item
        if val not in vals:
            vals.append(val)
    return ", ".join(("0x%02X" if v <= 0xFF else "0x%X") % v for v in vals)


def _detect_xor_loop(prof: A.FuncProfile):
    """Classify XOR usage: decode / encode / transform / incidental.

    A single scalar ``x ^= constant`` is not a decoder.  Buffer
    classification requires evidence that the XOR target is actually
    addressed through memory (indexed or dereferenced), and the "decode"
    label additionally requires a loop or several XOR operations.
    Evidence comes in two forms: ``^=`` writes (`xor_self`) and
    non-assigning XOR reads (``xor_uses`` — the signature of a
    comparison-style decoder like ``(input[i] ^ key) != stored[i]``).
    """
    findings = []
    xor_vars = [v for v in prof.vars if v.xor_self > 0 or v.xor_uses > 0]
    xor_count = sum(v.xor_self for v in xor_vars)
    xor_reads = sum(v.xor_uses for v in xor_vars)
    if xor_count == 0 and xor_reads == 0:
        return findings

    # memory-traffic evidence: the XOR operand is indexed or dereferenced
    buffer_vars = [v for v in xor_vars
                   if (v.idx_writes or v.deref_writes
                       or v.idx_reads or v.deref_reads)]
    targets = sorted({v.name for v in xor_vars})

    # Incidental: no memory traffic on the XOR target at all.
    if not buffer_vars:
        findings.append({
            "kind": "incidental",
            "algo": "xor",
            "confidence": 30,
            "targets": targets,
            "detail": "%d scalar xor op(s); no buffer transformation"
                      % (xor_count + xor_reads),
        })
        return findings

    strong = bool(buffer_vars) and (prof.loops > 0
                                    or xor_count + xor_reads >= 2)
    name = (getattr(prof, "name", "") or "").lower()
    if "encrypt" in name or "encode" in name:
        kind = "encode"
    elif "decrypt" in name or "decode" in name:
        kind = "decode"
    elif strong:
        kind = "decode"
    else:
        kind = "transform"

    confidence = 45 + min(24, (xor_count + xor_reads) * 8)
    if prof.loops:
        confidence += 10
    if buffer_vars:
        confidence += 10
    confidence = min(confidence, 92)

    if xor_reads and not xor_count:
        algo = "xor-compare"      # comparison-style check, not in-place decode
    elif xor_count >= 2 and prof.loops:
        algo = "xor-loop"
    else:
        algo = "xor"

    keys = _xor_operand_constants(prof)
    detail = ("%d xor-assign op(s), %d xor-read op(s), %d loop(s), "
              "%d buffer target(s)" % (xor_count, xor_reads, prof.loops,
                                       len(buffer_vars)))
    finding = {
        "kind": kind,
        "algo": algo,
        "confidence": confidence,
        "targets": targets,
        "detail": detail,
    }
    if keys:
        finding["keys"] = sorted({v for v, _ea, _a in keys})
        # the anchor is where a comment can actually render (see
        # `_xor_operand_constants`); the XOR's own address goes in the text.
        finding["key_ea"] = keys[0][2] or keys[0][1]
        finding["xor_ea"] = keys[0][1]
        finding["note"] = (
            "XOR check at %#x: each input byte is XORed with a key and "
            "compared against a stored copy; keys used: %s — a password/flag "
            "check, not real encryption"
            % (keys[0][1], format_xor_keys(keys)))
    findings.append(finding)
    return findings


def _detect_rotation(prof: A.FuncProfile):
    """Detect rotates from structural ``(x << n) | (x >> m)`` pairs.

    A bare count of shift instructions is not evidence of a rotation; it was
    the source of false positives on byte-swap and ordinary shift code.
    ``ast_analyzer`` records only genuine OR-of-opposite-shifts patterns over
    the same base variable.
    """
    count = int(getattr(prof, "rotate_patterns", 0) or 0)
    if count <= 0:
        return []
    return [{
        "kind": "transform",
        "algo": "rotate",
        "confidence": min(85, 72 + 5 * count),
        "targets": [],
        "detail": "%d paired shl/shr-OR expression(s)" % count,
    }]


def _detect_crc_like(prof: A.FuncProfile):
    """Detect CRC-like loop: table[...] ^ data with 8 iterations of shifts."""
    findings = []
    has_poly = any(v in _CRC_POLYS for v, _ in prof.constants)
    shift_heavy = sum(v.shift_uses for v in prof.vars) >= 2
    xor_heavy = prof.xor_assign_count >= 1 or any(
        v.xor_self for v in prof.vars)
    if has_poly and (shift_heavy or xor_heavy):
        algo = _CRC_POLYS[[v for v, _ in prof.constants
                           if v in _CRC_POLYS][0]]
        findings.append({
            "kind": "hash",
            "algo": algo,
            "confidence": 88,
            "targets": [],
            "detail": "CRC polynomial constant + shift/xor loop",
        })
    return findings


def _detect_hash_constants(prof: A.FuncProfile):
    """Match known hash/crypto constants."""
    findings = []
    matched = {}
    for val, ea in prof.constants:
        name = config.KNOWN_CONSTANTS.get(val)
        if name:
            matched.setdefault(name, []).append(val)
    for name, vals in matched.items():
        algo = None
        low = name.lower()
        if "md5" in low or "md4" in low:
            algo = "md5"
        elif "sha1" in low:
            algo = "sha1"
        elif "sha256" in low:
            algo = "sha256"
        elif "crc32" in low:
            algo = "crc32"
        elif "tea" in low:
            algo = "tea"
        elif "fnv" in low:
            algo = "fnv"
        elif "xxh" in low:
            algo = "xxhash"
        elif "blake" in low:
            algo = "blake"
        conf = 50 + 10 * len(vals)
        conf = min(conf, 80)
        if algo:
            findings.append({
                "kind": "hash-hint",
                "algo": algo,
                "confidence": conf,
                "targets": [],
                "detail": "%s: %d constant(s) matched %s"
                          % (algo, len(vals),
                             ", ".join("0x%X" % v for v in vals[:4])),
            })
    return findings


def _detect_aes_sbox(prof: A.FuncProfile, read_bytes=None):
    """Detect AES sbox prefix in referenced global data."""
    findings = []
    if read_bytes is None:
        read_bytes = _read_bytes_default
    for ea, txt in prof.strings:
        pass  # string literals are not sbox material
    # scan constants that point to global objects
    seen_eas = set()
    for op_ea, _ in prof.constants:
        if op_ea in seen_eas:
            continue
        seen_eas.add(op_ea)
        data = read_bytes(op_ea, 16)
        if data and tuple(data[:16]) == _AES_SBOX_PREFIX:
            findings.append({
                "kind": "crypto-table",
                "algo": "aes",
                "confidence": 85,
                "targets": [hex(op_ea)],
                "detail": "AES S-box prefix at %#x" % op_ea,
            })
            break
    return findings


def _read_bytes_default(ea, n):
    import ida_bytes
    try:
        raw = ida_bytes.get_bytes(ea, n)
        return raw if raw else None
    except Exception:
        return None


def _detect_base64(prof: A.FuncProfile):
    findings = []
    for ea, txt in prof.strings:
        if len(txt) >= 16:
            head = txt[:16]
            if head == _BASE64_STD_PREFIX:
                findings.append({
                    "kind": "encoding-table",
                    "algo": "base64",
                    "confidence": 82,
                    "targets": [hex(ea)],
                    "detail": "standard base64 alphabet at %#x" % ea,
                })
                break
            if head == _BASE64_URL_PREFIX:
                findings.append({
                    "kind": "encoding-table",
                    "algo": "base64url",
                    "confidence": 82,
                    "targets": [hex(ea)],
                    "detail": "URL-safe base64 alphabet at %#x" % ea,
                })
                break
    # also scan raw bytes via constants (some tables are not marked strings)
    if not findings:
        import ida_bytes
        seen = set()
        for cval, cea in prof.constants:
            if cval in seen:
                continue
            seen.add(cval)
            if 0x400000 <= cval < 0x7FFFFFFF or 0x140000000 <= cval < 0x180000000:
                try:
                    raw = ida_bytes.get_bytes(cval, 16)
                except Exception:
                    raw = None
                if raw and raw.decode("latin-1") in (
                        _BASE64_STD_PREFIX, _BASE64_URL_PREFIX):
                    findings.append({
                        "kind": "encoding-table",
                        "algo": "base64",
                        "confidence": 75,
                        "targets": [hex(cval)],
                        "detail": "base64 alphabet referenced at %#x" % cval,
                    })
                    break
    return findings


def _detect_bitmask(prof: A.FuncProfile):
    """Report interesting bitmasks (0xFF, 0xFFFF, 0xFF00, 0x80000000...)."""
    findings = []
    masks = set()
    common = {0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0xFF00, 0xFF0000,
              0x80000000, 0x7FFFFFFF, 0xF0, 0x0F, 0x33, 0x55, 0xAA}
    for val, _ in prof.constants:
        if val in common:
            masks.add(val)
    if len(masks) >= 3:
        findings.append({
            "kind": "info",
            "algo": "bitmask-heavy",
            "confidence": 40,
            "targets": [],
            "detail": "%d common bit masks used: %s"
                      % (len(masks), ", ".join("0x%X" % m for m in sorted(masks)[:5])),
        })
    return findings


def _detect_byteswap(prof: A.FuncProfile):
    """Detect byteswap patterns through helper calls."""
    findings = []
    for name in prof.called_names:
        low = name.lower()
        if "bswap" in low or "_byteswap" in low or "hton" in low or "ntoh" in low:
            findings.append({
                "kind": "transform",
                "algo": "bswap",
                "confidence": 80,
                "targets": [],
                "detail": "byte-swap helper %s called" % name,
            })
            break
    return findings


def _detect_mba(prof: A.FuncProfile):
    """Report mixed boolean-arithmetic rewrites found by the AST walker.

    Each pattern is an exact structural identity match (see
    ast_analyzer.identify_mba), so the reported simplification is sound.
    """
    findings = []
    seen = set()
    for pat in getattr(prof, "mba_patterns", ()) or ():
        key = (pat.get("form"), pat.get("simplified"))
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "kind": "obfuscation",
            "algo": "mba",
            "confidence": 88,
            "targets": [],
            "detail": "mixed boolean-arithmetic: %s (equivalent to `%s`)"
                      % (pat.get("detail", ""), pat.get("simplified", "")),
        })
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_function(prof: A.FuncProfile):
    """Return list of crypto/obfuscation findings for a profiled function."""
    findings = []
    try:
        findings.extend(_detect_xor_loop(prof))
        findings.extend(_detect_crc_like(prof))
        findings.extend(_detect_hash_constants(prof))
        findings.extend(_detect_aes_sbox(prof))
        findings.extend(_detect_base64(prof))
        findings.extend(_detect_bitmask(prof))
        findings.extend(_detect_byteswap(prof))
        findings.extend(_detect_rotation(prof))
        findings.extend(_detect_mba(prof))
    except Exception as exc:
        L.debug("crypto detector error at %#x: %s" % (prof.ea, exc))
    return findings


def summarize_findings(findings):
    """Human-readable one-line summary of findings."""
    if not findings:
        return "no crypto patterns"
    parts = []
    for f in findings:
        parts.append("%s(%s) %d%%" % (f.get("algo", "?"),
                                      f.get("kind", "?"),
                                      f.get("confidence", 0)))
    return "; ".join(parts)
