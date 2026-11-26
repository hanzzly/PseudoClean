"""AST-level analysis of Hex-Rays ctree.

Builds a per-function *profile* describing how each local variable and
expression node is used.  All heuristics (variable/function naming, crypto
detection, control-flow reporting) consume this profile.

Design note — why an explicit recursive walker instead of ctree_visitor_t:

`ctree_parentee_t` exposes parents, but SWIG wraps ctree items in fresh
Python proxies on every access, so `is`-identity comparisons against a
parent's child pointers are unreliable (verified empirically on IDA 9.4:
`e.x is parent.x` evaluates False).  Precise read/write classification needs
to know *which child slot* we descended through.  An explicit recursion
carrying that context is both simpler and exactly correct.

Everything here is read-only with respect to the IDA database.
"""

from __future__ import annotations

import re

import ida_hexrays
import ida_bytes
import ida_name
import ida_funcs
import idaapi

import logging_util as L


# ---------------------------------------------------------------------------
# Opcode sets (values verified against IDA 9.4 / Hex-Rays 9.4.0.260714)
# ---------------------------------------------------------------------------

CMP_OPS = frozenset((
    ida_hexrays.cot_eq, ida_hexrays.cot_ne,
    ida_hexrays.cot_sge, ida_hexrays.cot_uge,
    ida_hexrays.cot_sle, ida_hexrays.cot_ule,
    ida_hexrays.cot_sgt, ida_hexrays.cot_ugt,
    ida_hexrays.cot_slt, ida_hexrays.cot_ult,
))

SHIFT_OPS = frozenset((
    ida_hexrays.cot_sshr, ida_hexrays.cot_ushr, ida_hexrays.cot_shl,
))

LOGIC_OPS = frozenset((
    ida_hexrays.cot_land, ida_hexrays.cot_lor, ida_hexrays.cot_lnot,
))

INC_OPS = frozenset((
    ida_hexrays.cot_postinc, ida_hexrays.cot_postdec,
    ida_hexrays.cot_preinc, ida_hexrays.cot_predec,
))

COMPOUND_ASG = frozenset((
    ida_hexrays.cot_asgadd, ida_hexrays.cot_asgsub, ida_hexrays.cot_asgmul,
    ida_hexrays.cot_asgbor, ida_hexrays.cot_asgband, ida_hexrays.cot_asgxor,
    ida_hexrays.cot_asgshl, ida_hexrays.cot_asgsshr, ida_hexrays.cot_asgushr,
    ida_hexrays.cot_asgsdiv, ida_hexrays.cot_asgudiv,
    ida_hexrays.cot_asgsmod, ida_hexrays.cot_asgumod,
))

ARITH_OPS = frozenset((
    ida_hexrays.cot_add, ida_hexrays.cot_sub, ida_hexrays.cot_mul,
    ida_hexrays.cot_sdiv, ida_hexrays.cot_udiv,
    ida_hexrays.cot_smod, ida_hexrays.cot_umod,
))


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def ctype_name(op) -> str:
    """Return the `cot_*`/`cit_*` name for an opcode constant."""
    for name in dir(ida_hexrays):
        if name.startswith("cot_") or name.startswith("cit_"):
            try:
                if getattr(ida_hexrays, name) == op:
                    return name
            except Exception:
                pass
    return "op_%d" % op


def expr_str(e) -> str:
    """Best-effort textual form of a cexpr_t (never raises)."""
    if e is None:
        return "<none>"
    try:
        return e.dstr()
    except Exception:
        return "<expr op=%d>" % getattr(e, "op", -1)


def tif_name(tif) -> str:
    if tif is None:
        return "?"
    try:
        return tif.dstr()
    except Exception:
        return "?"


def type_size(tif) -> int:
    if tif is None:
        return 0
    try:
        return tif.get_size()
    except Exception:
        return 0


def type_is_ptr(tif) -> bool:
    if tif is None:
        return False
    try:
        return bool(tif.is_ptr() or tif.is_funcptr())
    except Exception:
        return False


def type_is_array(tif) -> bool:
    if tif is None:
        return False
    try:
        return bool(tif.is_array())
    except Exception:
        return False


#: Type names (after cv-qualifier stripping) that belong to the char family.
_CHARLIKE_NAMES = frozenset((
    "char", "signed char", "unsigned char",
    "__int8", "unsigned __int8", "signed __int8",
    "_BYTE", "_BOOL", "bool", "_Bool",
))

_CV_WORDS = ("const", "volatile", "restrict", "__restrict", "__restrict__",
             "signed", "unsigned")


def _base_type(tif):
    """Strip pointers and arrays, returning the innermost element type."""
    seen = 0
    while tif is not None and seen < 32:
        seen += 1
        try:
            if tif.is_ptr():
                tif = tif.get_ptrarr_object()
                continue
            if tif.is_array():
                tif = tif.get_array_element()
                continue
        except Exception:
            return None
        break
    return tif


def _charish_type_name(tif) -> bool:
    """String-based character-family check (cv-qualifier tolerant).

    The type is tokenised first: substring replacement is unsafe because
    ``"unsigned char".replace("signed", " ")`` would corrupt the token into
    ``"un char"``.  Qualifier/word tokens are dropped, then the remaining
    token sequence is matched against the char family.
    """
    try:
        text = (tif.dstr() or "").strip()
    except Exception:
        return False
    if not text:
        return False
    tokens = [tok for tok in re.split(r"[^A-Za-z0-9_]+", text)
              if tok and tok not in _CV_WORDS]
    return " ".join(tokens) in _CHARLIKE_NAMES


def is_char_like(tif) -> bool:
    """True for char / int8 / uint8 / bool, including pointer/array of them.

    ``const char`` and ``volatile unsigned char`` must be recognised too:
    the raw ``get_decltype()`` value carries cv-qualifier bits, so the
    decltype comparison alone silently rejects ``const char *``.  The IDA
    type predicates (``is_decl_char`` etc.) do handle qualifiers, and a
    normalized type-name check is kept as a fallback.
    """
    tif = _base_type(tif)
    if tif is None:
        return False

    # Preferred: IDA predicates understand cv-qualifiers and typedefs.
    for pred in ("is_decl_char", "is_decl_uchar", "is_decl_bool"):
        fn = getattr(tif, pred, None)
        if fn is None:
            continue
        try:
            if fn():
                return True
        except Exception:
            pass

    # Fallback: normalized type name.  Covers toolchains/type libraries
    # where the predicates are unavailable or return false for qualified
    # spellings.
    return _charish_type_name(tif)


def get_strlit(ea: int, maxlen: int = 4096):
    """Return the string literal text at `ea`, or None."""
    if not ea or ea == idaapi.BADADDR:
        return None
    try:
        raw = ida_bytes.get_strlit_contents(ea, -1, 0)
        if raw is None:
            return None
        if isinstance(raw, str):
            return raw[:maxlen]
        try:
            return raw.decode("utf-8", "replace")[:maxlen]
        except Exception:
            return None
    except Exception:
        return None


def normalize_callee(name: str) -> str:
    """Normalize a callee name to its bare API name.

    ELF import thunks appear as '.memcpy'; PE ones as 'j_memcpy' or
    '__imp_memcpy'.  C++ decorations are stripped too.
    """
    if not name:
        return ""
    n = name.strip()
    if n.startswith("(*"):
        return n                     # indirect call, leave as-is
    n = n.lstrip(".")
    if n.startswith("__imp_"):
        n = n[len("__imp_"):]
    if n.startswith("j_"):
        n = n[len("j_"):]
    if n.startswith("_imp__"):
        n = n[len("_imp__"):]
    n = n.split("@")[0]
    return n


def resolve_call_name(call_e, lvars=None) -> str:
    """Resolve the callee name of a cot_call expression (normalized)."""
    callee = getattr(call_e, "x", None)
    if callee is None:
        return ""
    try:
        op = callee.op
        if op == ida_hexrays.cot_obj:
            raw = ida_name.get_ea_name(callee.obj_ea) or ""
            return normalize_callee(raw)
        if op == ida_hexrays.cot_helper:
            return normalize_callee(callee.helper or "")
        if op == ida_hexrays.cot_var:
            idx = callee.v.idx
            if lvars is not None and 0 <= idx < len(lvars):
                return "(*%s)" % lvars[idx].name
            return "(*fnptr)"
        if op in (ida_hexrays.cot_ptr, ida_hexrays.cot_cast):
            return "*fnptr"
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Argument role table
# ---------------------------------------------------------------------------

ARG_ROLES = {
    "strlen": ("string",),
    "strnlen": ("string", "maxlen"),
    "wcslen": ("string",),
    "strcpy": ("dest", "src"),
    "strncpy": ("dest", "src", "count"),
    "strcat": ("dest", "src"),
    "strncat": ("dest", "src", "count"),
    "strcmp": ("lhs", "rhs"),
    "strncmp": ("lhs", "rhs", "count"),
    "strchr": ("string", "char"),
    "strrchr": ("string", "char"),
    "strstr": ("haystack", "needle"),
    "strtok": ("string", "delim"),
    "sprintf": ("dest", "format"),
    "swprintf": ("dest", "format"),
    "snprintf": ("dest", "size", "format"),
    "vsnprintf": ("dest", "size", "format", "va"),
    "printf": ("format",),
    "fprintf": ("stream", "format"),
    "vprintf": ("format",),
    "puts": ("string",),
    "fputs": ("string", "stream"),
    "putchar": ("char",),
    "memcpy": ("dest", "src", "count"),
    "memmove": ("dest", "src", "count"),
    "memset": ("dest", "value", "count"),
    "memcmp": ("lhs", "rhs", "count"),
    "malloc": ("size",),
    "calloc": ("count", "size"),
    "realloc": ("ptr", "size"),
    "free": ("ptr",),
    "read": ("fd", "buffer", "count"),
    "write": ("fd", "buffer", "count"),
    "fread": ("buffer", "size", "count", "stream"),
    "fwrite": ("buffer", "size", "count", "stream"),
    "recv": ("socket", "buffer", "len", "flags"),
    "send": ("socket", "buffer", "len", "flags"),
    "open": ("path", "flags"),
    "fopen": ("path", "mode"),
    "atoi": ("string",),
    "atol": ("string",),
    "strtol": ("string", "endptr", "base"),
    "strtoul": ("string", "endptr", "base"),
    "getenv": ("name",),
    "system": ("command",),
    "GetModuleHandleA": ("module",),
    "GetModuleHandleW": ("module",),
    "LoadLibraryA": ("module",),
    "LoadLibraryW": ("module",),
    "GetProcAddress": ("module", "proc_name"),
    "VirtualAlloc": ("addr", "size", "alloctype", "protect"),
    "VirtualProtect": ("addr", "size", "newprotect", "oldprotect"),
    "CreateFileA": ("filename", "access", "share", "security", "creation",
                    "flags", "template"),
    "CreateFileW": ("filename", "access", "share", "security", "creation",
                    "flags", "template"),
    "ReadFile": ("handle", "buffer", "bytes_to_read", "bytes_read",
                 "overlapped"),
    "WriteFile": ("handle", "buffer", "bytes_to_write", "bytes_written",
                  "overlapped"),
    "RegOpenKeyExA": ("hkey", "subkey", "options", "sam", "result"),
    "RegSetValueExA": ("hkey", "value_name", "reserved", "type", "data",
                       "data_size"),
}

#: print-family callees (format handling differs from plain args)
PRINT_FAMILY = frozenset((
    "printf", "fprintf", "sprintf", "snprintf", "vsnprintf", "vprintf",
    "wprintf", "swprintf", "puts", "fputs", "_printf", "_snprintf",
))

ALLOC_FAMILY = frozenset((
    "malloc", "calloc", "realloc", "operator new", "operator new[]",
    "VirtualAlloc", "HeapAlloc", "LocalAlloc", "GlobalAlloc", "_malloc",
    "_calloc", "_realloc",
))

STRLEN_FAMILY = frozenset((
    "strlen", "strnlen", "wcslen", "lstrlenA", "lstrlenW", "_strlen",
    "__strlen",
))

#: input-family callees: a buffer handed to one of these is user input, not
#: scratch data (measured on a real CrackMe: `__isoc99_scanf("%49s", s)`).
INPUT_FAMILY = frozenset((
    "scanf", "__isoc99_scanf", "fscanf", "sscanf", "gets", "fgets",
    "getline", "read", "fread", "recv", "recvfrom", "ReadFile", "getline",
    "std::getline",
))


# ---------------------------------------------------------------------------
# Variable usage profile
# ---------------------------------------------------------------------------

class VarUse:
    """Aggregated evidence about one local variable."""

    __slots__ = (
        "idx", "name", "width", "tif", "is_arg", "is_result", "defblk",
        "refs", "reads", "writes", "addr_taken",
        "idx_reads", "idx_writes", "deref_reads", "deref_writes",
        "call_args", "call_roles", "inc_count", "loop_bound_cmp",
        "zero_assign", "nonzero_assign", "cmp_count", "mul_uses",
        "xor_self", "xor_uses", "shift_uses", "callees", "asg_sources",
        "first_ea", "return_uses", "boolish",
        "print_args", "fmt_arg", "mem_dest", "mem_src", "index_uses",
        "const_assigns", "loop_cond_cmp",
    )

    def __init__(self, idx, lvar):
        self.idx = idx
        self.name = lvar.name
        self.width = lvar.width
        try:
            self.tif = lvar.type()
        except Exception:
            self.tif = None
        self.is_arg = bool(lvar.is_arg_var)
        self.is_result = bool(lvar.is_result_var)
        self.defblk = getattr(lvar, "defblk", -1)
        self.refs = 0
        self.reads = 0
        self.writes = 0
        self.addr_taken = 0
        self.idx_reads = 0
        self.idx_writes = 0
        self.deref_reads = 0
        self.deref_writes = 0
        self.call_args = 0
        self.call_roles = []
        self.inc_count = 0
        self.loop_bound_cmp = 0
        self.zero_assign = 0
        self.nonzero_assign = 0
        self.cmp_count = 0
        self.mul_uses = 0
        self.xor_self = 0
        # non-assigning XOR reads (e.g. `(input[i] ^ key) != encoded[i]`):
        # evidence for comparison-style decoders that never use `^=`.
        self.xor_uses = 0
        self.shift_uses = 0
        self.callees = set()
        self.asg_sources = []
        self.first_ea = idaapi.BADADDR
        self.return_uses = 0
        self.boolish = False
        self.print_args = 0
        self.fmt_arg = 0
        self.mem_dest = 0
        self.mem_src = 0
        self.index_uses = 0
        self.const_assigns = []      # constant values assigned to this var
        self.loop_cond_cmp = 0       # compared inside a loop condition

    def __repr__(self):
        return ("VarUse(%r w=%d r=%d w=%d idx=%d/%d call=%d inc=%d)"
                % (self.name, self.width, self.reads, self.writes,
                   self.idx_reads, self.idx_writes, self.call_args,
                   self.inc_count))

    # -- helpers ---------------------------------------------------
    def type_name(self) -> str:
        return tif_name(self.tif)

    def is_char(self) -> bool:
        return is_char_like(self.tif)

    def is_ptr(self) -> bool:
        return type_is_ptr(self.tif)

    def is_array(self) -> bool:
        return type_is_array(self.tif)

    def total_mem_access(self) -> int:
        return (self.idx_reads + self.idx_writes +
                self.deref_reads + self.deref_writes)

    def is_loop_counter(self) -> bool:
        return self.inc_count > 0 and self.loop_bound_cmp > 0

    def is_state_variable(self) -> bool:
        """True for dispatcher/state-machine variables.

        Signature: the variable is compared inside a loop condition and is
        assigned at least three *distinct* constants across the function,
        each assignment acting as a state transition.
        """
        if not self.loop_cond_cmp:
            return False
        try:
            distinct = {int(v) for v in self.const_assigns}
        except Exception:
            return False
        return len(distinct) >= 3

    def distinct_const_states(self):
        try:
            return sorted({int(v) for v in self.const_assigns})
        except Exception:
            return []

    def total_writes(self) -> int:
        return self.writes + self.idx_writes + self.deref_writes


class FuncProfile:
    """Per-function analysis results."""

    def __init__(self, ea: int, cfunc):
        self.ea = ea
        self.cfunc = cfunc
        self.vars = []
        self.var_by_name = {}
        self.call_count = 0
        self.called_names = []
        self.strings = []
        self.constants = []
        self.imports = set()
        self.loops = 0
        self.switches = 0
        self.ifs = 0
        self.returns = 0
        self.gotos = 0
        self.xor_assign_count = 0
        self.loop_insns = []
        self.nodes = 0
        self.truncated = False
        self.return_exprs = []
        self.mba_patterns = []
        self.rotate_patterns = 0

    def var_name(self, idx: int) -> str:
        if 0 <= idx < len(self.vars):
            return self.vars[idx].name
        return ""

    def total_refs(self) -> int:
        return sum(v.refs for v in self.vars)

    def has_memory_writes(self) -> bool:
        return any(v.idx_writes or v.deref_writes for v in self.vars)

    def returns_buffer(self) -> bool:
        """True when the function returns a pointer to written memory."""
        for v in self.vars:
            if v.return_uses and v.is_ptr() and v.is_char() and \
                    (v.idx_writes or v.deref_writes):
                return True
        return False


# ---------------------------------------------------------------------------
# Explicit recursive walker
# ---------------------------------------------------------------------------

_CTX_READ = 0
_CTX_WRITE = 1        # direct assignment target
_CTX_WRITE_MEM = 2    # deref/index target of an assignment (write through)
_CTX_READ_MEM = 3     # deref/index used as a value
_CTX_ADDR = 4         # address-of operand


class _Walker:
    """Recursive ctree walker with precise child-slot context."""

    MAX_NODES = 400000

    def __init__(self, prof: FuncProfile):
        self.p = prof
        self.depth = 0
        self.lvars = None
        try:
            self.lvars = prof.cfunc.get_lvars()
        except Exception:
            self.lvars = None
        self.nvars = len(prof.vars)

    # -- variable lookup ------------------------------------------
    def _vu(self, idx):
        if 0 <= idx < self.nvars:
            return self.p.vars[idx]
        return None

    # -- entry -----------------------------------------------------
    def run(self):
        try:
            self.walk_insn(self.p.cfunc.body)
        except Exception as exc:
            L.debug("walker failed on %#x: %s" % (self.p.ea, exc))

    # -- instructions ----------------------------------------------
    def walk_insn(self, i):
        if i is None or self.p.nodes > self.MAX_NODES:
            if self.p.nodes > self.MAX_NODES:
                self.p.truncated = True
            return
        self.depth += 1
        if self.depth > 64:
            self.depth -= 1
            return
        try:
            op = i.op
        except Exception:
            self.depth -= 1
            return

        if op == ida_hexrays.cit_block:
            try:
                for item in i.cblock:
                    self.walk_insn(item)
            except Exception:
                pass

        elif op == ida_hexrays.cit_expr:
            try:
                self.walk_expr(i.cexpr, _CTX_READ)
            except Exception:
                pass

        elif op == ida_hexrays.cit_if:
            self.p.ifs += 1
            try:
                cf = i.cif
                self.walk_expr(cf.expr, _CTX_READ)
                self.walk_insn(cf.ithen)
                if cf.ielse is not None:
                    self.walk_insn(cf.ielse)
            except Exception:
                pass

        elif op in (ida_hexrays.cit_for, ida_hexrays.cit_while,
                    ida_hexrays.cit_do):
            self.p.loops += 1
            self.p.loop_insns.append(i)
            body = None
            try:
                if op == ida_hexrays.cit_for:
                    cfor = i.cfor
                    self.walk_expr(cfor.init, _CTX_READ)
                    self.walk_expr(cfor.expr, _CTX_READ)
                    self.walk_expr(cfor.step, _CTX_READ)
                    body = cfor.body
                else:
                    cond, body = loop_parts(i)
                    if cond is not None:
                        self.walk_expr(cond, _CTX_READ)
            except Exception as exc:
                L.debug("loop head walk failed at %#x: %s" % (i.ea, exc))
            try:
                self._mark_loop_counter(i)
            except Exception as exc:
                L.debug("loop counter detect failed: %s" % exc)
            if body is not None:
                self.walk_insn(body)

        elif op == ida_hexrays.cit_switch:
            self.p.switches += 1
            try:
                cs = i.cswitch
                self.walk_expr(cs.expr, _CTX_READ)
                for idx in range(len(cs.cases)):
                    self.walk_insn(cs.cases[idx])
            except Exception as exc:
                L.debug("switch walk failed at %#x: %s" % (i.ea, exc))

        elif op == ida_hexrays.cit_return:
            self.p.returns += 1
            try:
                expr = i.creturn.expr
            except Exception:
                expr = None
            if expr is not None:
                self.p.return_exprs.append(expr)
                tgt = _bare_var_index(expr)
                if tgt >= 0:
                    v = self._vu(tgt)
                    if v is not None:
                        v.return_uses += 1
                self.walk_expr(expr, _CTX_READ)

        elif op == ida_hexrays.cit_goto:
            self.p.gotos += 1

        elif op == ida_hexrays.cit_try:
            try:
                ctry = i.ctry
                self.walk_insn(getattr(ctry, "m_try", None))
                for h in (getattr(ctry, "m_catch", None) or []):
                    self.walk_insn(h)
            except Exception as exc:
                L.debug("try walk failed: %s" % exc)

        self.depth -= 1

    # -- expressions ------------------------------------------------
    def walk_expr(self, e, ctx):
        if e is None:
            return
        self.p.nodes += 1
        if self.p.nodes > self.MAX_NODES:
            self.p.truncated = True
            return
        if self.depth > 128:
            return
        self.depth += 1
        try:
            self._walk_expr_inner(e, ctx)
        except Exception as exc:
            L.debug("walk_expr error: %s" % exc)
        finally:
            self.depth -= 1

    def _walk_expr_inner(self, e, ctx):
        op = e.op

        # ---------------- constants -------------------------------
        if op == ida_hexrays.cot_num:
            try:
                self.p.constants.append((e.numval(), e.ea))
            except Exception:
                pass
            return

        # ---------------- string literals / globals ---------------
        if op == ida_hexrays.cot_obj:
            txt = get_strlit(e.obj_ea)
            if txt:
                self.p.strings.append((e.obj_ea, txt))
            return

        # ---------------- local variable --------------------------
        if op == ida_hexrays.cot_var:
            v = self._vu(e.v.idx)
            if v is None:
                return
            v.refs += 1
            if e.ea and e.ea < v.first_ea:
                v.first_ea = e.ea
            if ctx == _CTX_WRITE:
                v.writes += 1
            elif ctx == _CTX_ADDR:
                v.addr_taken += 1
                v.reads += 1
            else:
                v.reads += 1
            return

        # ---------------- assignment ------------------------------
        if op == ida_hexrays.cot_asg:
            self._record_assignment(e)
            self.walk_expr(e.x, _CTX_WRITE)
            self.walk_expr(e.y, _CTX_READ)
            return

        if op in COMPOUND_ASG:
            self.p.xor_assign_count += (1 if op == ida_hexrays.cot_asgxor
                                        else 0)
            if op == ida_hexrays.cot_asgxor:
                self._mark_xor(e.x)
            self.walk_expr(e.x, _CTX_WRITE)
            self.walk_expr(e.y, _CTX_READ)
            return

        # ---------------- xor binop (non-assign) ------------------
        # `(input[i] ^ key) != encoded[i]` never forms an asgxor, but it is
        # exactly the pattern of a comparison-style decoder.  Record which
        # operands participate so the crypto detector can classify it.
        if op == ida_hexrays.cot_xor:
            self._mark_xor_read(e.x)
            self._mark_xor_read(e.y)
            self.walk_expr(e.x, _CTX_READ)
            self.walk_expr(e.y, _CTX_READ)
            return

        if op in INC_OPS:
            self.walk_expr(e.x, _CTX_WRITE)
            return

        # ---------------- index v[i] ------------------------------
        if op == ida_hexrays.cot_idx:
            base = e.x
            idxe = e.y
            bidx = _resolve_base_var(base, self.p)
            if bidx >= 0:
                v = self._vu(bidx)
                if v is not None:
                    v.index_uses += 1
                    if ctx in (_CTX_WRITE, _CTX_WRITE_MEM):
                        v.idx_writes += 1
                    else:
                        v.idx_reads += 1
                    v.refs += 1
                    self._mark_index_var(idxe)
                    if base is not None and base.op != ida_hexrays.cot_var:
                        self.walk_expr(base, _CTX_READ)
                    self.walk_expr(idxe, _CTX_READ)
                    return
            self.walk_expr(base, _CTX_READ)
            self.walk_expr(idxe, _CTX_READ)
            return

        # ---------------- dereference *p --------------------------
        if op == ida_hexrays.cot_ptr:
            inner = e.x
            bidx = _resolve_base_var(inner, self.p)
            if bidx >= 0:
                v = self._vu(bidx)
                if v is not None:
                    if ctx in (_CTX_WRITE, _CTX_WRITE_MEM):
                        v.deref_writes += 1
                    else:
                        v.deref_reads += 1
                    v.refs += 1
                    # the address computation still reads the base pointer
                    if inner is not None and inner.op != ida_hexrays.cot_var:
                        self.walk_expr(inner, _CTX_READ)
                        return
            self.walk_expr(inner, _CTX_READ)
            return

        # ---------------- address-of ------------------------------
        if op == ida_hexrays.cot_ref:
            self.walk_expr(e.x, _CTX_ADDR)
            return

        # ---------------- member access ---------------------------
        if op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
            inner_ctx = ctx if ctx in (_CTX_WRITE, _CTX_WRITE_MEM,
                                       _CTX_READ_MEM, _CTX_READ) else _CTX_READ
            if ctx in (_CTX_WRITE, _CTX_WRITE_MEM):
                bidx = _resolve_base_var(e.x, self.p)
                if bidx >= 0:
                    v = self._vu(bidx)
                    if v is not None:
                        if op == ida_hexrays.cot_memptr:
                            v.deref_writes += 1
                        else:
                            v.writes += 1
                        v.refs += 1
                        inner_ctx = _CTX_READ
            self.walk_expr(e.x, inner_ctx)
            return

        # ---------------- calls -----------------------------------
        if op == ida_hexrays.cot_call:
            self.p.call_count += 1
            fname = resolve_call_name(e, self.lvars)
            if fname:
                self.p.called_names.append(fname)
                if fname in ARG_ROLES:
                    self.p.imports.add(fname)
            self._record_call_args(e, fname)
            self.walk_expr(e.x, _CTX_READ)
            try:
                for arg in e.a:
                    self.walk_expr(arg, _CTX_READ)
            except Exception:
                pass
            return

        # ---------------- mixed boolean-arithmetic ----------------
        if op in (ida_hexrays.cot_add, ida_hexrays.cot_sub):
            mba = identify_mba(e, self.p)
            if mba:
                self.p.mba_patterns.append(mba)

        # ---------------- rotate pattern --------------------------
        if op == ida_hexrays.cot_bor and self._is_rotate(e):
            self.p.rotate_patterns += 1

        # ---------------- shifts ----------------------------------
        if op in SHIFT_OPS:
            lhs = e.x
            if lhs is not None and lhs.op == ida_hexrays.cot_var:
                v = self._vu(lhs.v.idx)
                if v is not None:
                    v.shift_uses += 1
            self.walk_expr(e.x, _CTX_READ)
            self.walk_expr(e.y, _CTX_READ)
            return

        # ---------------- comparisons -----------------------------
        if op in CMP_OPS:
            lhs = e.x
            if lhs is not None and lhs.op == ida_hexrays.cot_var:
                v = self._vu(lhs.v.idx)
                if v is not None:
                    v.cmp_count += 1
            self.walk_expr(e.x, _CTX_READ)
            self.walk_expr(e.y, _CTX_READ)
            return

        # ---------------- multiplication --------------------------
        if op == ida_hexrays.cot_mul:
            for side in (e.x, e.y):
                if side is not None and side.op == ida_hexrays.cot_var:
                    v = self._vu(side.v.idx)
                    if v is not None:
                        v.mul_uses += 1
            self.walk_expr(e.x, _CTX_READ)
            self.walk_expr(e.y, _CTX_READ)
            return

        # ---------------- generic binary/unary --------------------
        for attr in ("x", "y", "z"):
            sub = getattr(e, attr, None)
            if sub is not None:
                try:
                    if hasattr(sub, "op"):
                        self.walk_expr(sub, _CTX_READ)
                except Exception:
                    pass

    # -- bookkeeping helpers ---------------------------------------
    def _record_assignment(self, asg):
        lhs, rhs = asg.x, asg.y
        target = _bare_var_index(lhs)
        if target < 0:
            return
        v = self._vu(target)
        if v is None:
            return
        if rhs is None:
            return
        src = _rhs_kind(rhs)
        v.asg_sources.append(src)
        if src == "call":
            fname = resolve_call_name(rhs, self.lvars)
            if fname:
                v.asg_sources.append(fname)
                v.callees.add(fname)
        # flag-like detection
        if rhs.op in CMP_OPS or rhs.op in LOGIC_OPS:
            v.boolish = True
        elif rhs.op == ida_hexrays.cot_num:
            try:
                val = rhs.numval()
                v.const_assigns.append(val)
                if val == 0:
                    v.zero_assign += 1
                else:
                    v.nonzero_assign += 1
            except Exception:
                pass

    def _mark_index_var(self, idxe):
        """Record a read on the variable used as an index expression."""
        if idxe is None:
            return
        try:
            op = idxe.op
            if op == ida_hexrays.cot_var:
                v = self._vu(idxe.v.idx)
            elif op == ida_hexrays.cot_cast and idxe.x is not None:
                v = self._vu(_bare_var_index(idxe.x))
            else:
                v = None
        except Exception:
            v = None
        if v is not None:
            v.reads += 1
            v.refs += 1

    def _is_rotate(self, e):
        """True for ``(x << n) | (x >> m)`` over the same base variable."""
        try:
            for shl, shr in ((e.x, e.y), (e.y, e.x)):
                if shl is None or shr is None:
                    continue
                if shl.op != ida_hexrays.cot_shl:
                    continue
                if shr.op not in (ida_hexrays.cot_ushr,
                                  ida_hexrays.cot_sshr):
                    continue
                left = _bare_var_index(getattr(shl, "x", shl))
                right = _bare_var_index(getattr(shr, "x", shr))
                if left >= 0 and left == right:
                    return True
        except Exception:
            pass
        return False

    def _mark_xor(self, lhs):
        v = None
        if lhs is not None:
            if lhs.op == ida_hexrays.cot_var:
                v = self._vu(lhs.v.idx)
            else:
                bidx = _resolve_base_var(lhs, self.p)
                if bidx >= 0:
                    v = self._vu(bidx)
        if v is not None:
            v.xor_self += 1

    def _mark_xor_read(self, operand):
        """Record a non-assigning XOR operand (comparison-style decoder)."""
        if operand is None:
            return
        v = None
        if operand.op == ida_hexrays.cot_var:
            v = self._vu(operand.v.idx)
        else:
            bidx = _resolve_base_var(operand, self.p)
            if bidx >= 0:
                v = self._vu(bidx)
        if v is not None:
            v.xor_uses += 1

    def _record_call_args(self, call_e, fname):
        arglist = getattr(call_e, "a", None)
        if arglist is None:
            return
        try:
            args = list(arglist)
        except Exception:
            return
        roles = ARG_ROLES.get(fname, ())
        is_print = fname in PRINT_FAMILY
        for pos, arg in enumerate(args):
            vidx = _bare_var_index(arg)
            if vidx < 0:
                continue
            vu = self._vu(vidx)
            if vu is None:
                continue
            vu.call_args += 1
            role = roles[pos] if pos < len(roles) else "arg%d" % pos
            vu.call_roles.append((fname, role))
            if fname:
                vu.callees.add(fname)
            if role in ("dest", "buffer"):
                vu.mem_dest += 1
            elif role in ("src", "string"):
                vu.mem_src += 1
            if is_print:
                if pos == 0 and fname not in ("puts", "fputs"):
                    vu.fmt_arg += 1
                elif pos > 0 or fname in ("puts", "fputs"):
                    vu.print_args += 1

    def _mark_loop_counter(self, loop_ins):
        """Detect canonical loop counters: for (i = 0; i < n; i += k)."""
        try:
            op = loop_ins.op
            cond = init = step = None
            if op == ida_hexrays.cit_for:
                cfor = loop_ins.cfor
                init, cond, step = cfor.init, cfor.expr, cfor.step
            else:
                cond, _body_unused = loop_parts(loop_ins)
                init = step = None

            # counter from the condition: i < bound
            node = cond
            hops = 0
            while node is not None and hops < 8:
                hops += 1
                if node.op in CMP_OPS:
                    target = _bare_var_index(node.x)
                    if target < 0:
                        # allow `bound > i`
                        target = _bare_var_index(node.y)
                    if target >= 0:
                        v = self._vu(target)
                        if v is not None:
                            v.loop_bound_cmp += 1
                            v.loop_cond_cmp += 1
                    break
                if node.op in (ida_hexrays.cot_land, ida_hexrays.cot_lor):
                    node = node.x
                    continue
                break

            for expr in (init, step):
                self._detect_increment(expr)
            # increments inside the body
            body = None
            if op == ida_hexrays.cit_for:
                body = loop_ins.cfor.body
            else:
                _, body = loop_parts(loop_ins)
            self._scan_increments(body, 0)
        except Exception:
            pass

    def _detect_increment(self, expr):
        if expr is None:
            return
        try:
            op = expr.op
            if op in INC_OPS:
                target = _bare_var_index(expr.x)
                if target >= 0:
                    v = self._vu(target)
                    if v is not None:
                        v.inc_count += 1
                return
            if op in (ida_hexrays.cot_asgadd, ida_hexrays.cot_asgsub):
                target = _bare_var_index(expr.x)
                if target >= 0:
                    v = self._vu(target)
                    if v is not None:
                        v.inc_count += 1
                return
            if op == ida_hexrays.cot_asg:
                rhs = expr.y
                if rhs is not None and rhs.op in (ida_hexrays.cot_add,
                                                  ida_hexrays.cot_sub):
                    target = _bare_var_index(expr.x)
                    if target >= 0:
                        v = self._vu(target)
                        if v is not None:
                            v.inc_count += 1
                return
            if op in (ida_hexrays.cot_comma,) and expr.y is not None:
                self._detect_increment(expr.y)
        except Exception:
            pass

    def _scan_increments(self, item, depth):
        if item is None or depth > 3:
            return
        try:
            op = item.op
            if op == ida_hexrays.cit_block:
                for sub in item.cblock:
                    self._scan_increments(sub, depth + 1)
            elif op == ida_hexrays.cit_expr:
                self._detect_increment(item.cexpr)
            elif op == ida_hexrays.cit_if:
                self._scan_increments(item.cif.ithen, depth + 1)
                if item.cif.ielse is not None:
                    self._scan_increments(item.cif.ielse, depth + 1)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Expression helpers
# ---------------------------------------------------------------------------

def _bare_var_index(e) -> int:
    """Variable index if `e` is a bare (possibly cast) local variable."""
    if e is None:
        return -1
    try:
        if e.op == ida_hexrays.cot_var:
            return e.v.idx
        if e.op == ida_hexrays.cot_cast and e.x is not None:
            return _bare_var_index(e.x)
    except Exception:
        return -1
    return -1


def _valid_var_index(prof, idx: int) -> int:
    """Return `idx` when it refers to a variable present in the profile."""
    if idx < 0:
        return -1
    if prof is None:
        return idx
    try:
        n = len(prof.vars)
    except Exception:
        return idx
    if n and idx >= n:
        return -1
    return idx


def _resolve_base_var(e, prof, prefer_ptr=False) -> int:
    """Resolve the *base object* variable of an address expression.

    Handles the shapes Hex-Rays produces for pointer/array addressing:
        v                      -> v
        (cast) v               -> v
        (cast) (i + v)         -> v   (address-sized side preferred)
        (cast) (v + i)         -> v
        (cast) (v + i*4)       -> v
        (cast) (&v)            -> v
        *(cast) (i + v)        -> v

    When several variables appear, the pointer/array-typed one wins; if
    neither is pointer-like the wider (address-sized) one wins, so
    `*(_BYTE *)(i + base)` resolves to `base`, not to the index `i`.  This
    rule is deterministic and matches how compiler code generators emit
    base+index addressing.  Returns -1 when nothing can be resolved or the
    resolved index is not a variable of the profile.
    """
    return _valid_var_index(prof, _resolve_base_var_raw(e, prof, prefer_ptr))


def _resolve_base_var_raw(e, prof, prefer_ptr=False) -> int:
    """Recursive worker for _resolve_base_var (indexes not range-checked)."""
    if e is None:
        return -1
    try:
        op = e.op
        if op == ida_hexrays.cot_var:
            return e.v.idx

        if op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref,
                  ida_hexrays.cot_ptr, ida_hexrays.cot_memptr,
                  ida_hexrays.cot_memref):
            return _resolve_base_var_raw(e.x, prof, prefer_ptr)

        if op == ida_hexrays.cot_idx:
            return _resolve_base_var_raw(e.x, prof, prefer_ptr)

        if op in (ida_hexrays.cot_add, ida_hexrays.cot_sub):
            left = _resolve_base_var_raw(e.x, prof, prefer_ptr)
            right = _resolve_base_var_raw(e.y, prof, prefer_ptr)
            if left < 0:
                return right
            if right < 0:
                return left
            # both resolve: prefer the pointer/array-typed variable
            lv = prof.vars[left] if 0 <= left < len(prof.vars) else None
            rv = prof.vars[right] if 0 <= right < len(prof.vars) else None
            lp = bool(lv and (lv.is_ptr() or lv.is_array()))
            rp = bool(rv and (rv.is_ptr() or rv.is_array()))
            if lp and not rp:
                return left
            if rp and not lp:
                return right
            # Neither (or both) pointer-like: the base object is normally
            # address-sized while an index is narrower, so prefer the wider.
            lw = lv.width if lv is not None else 0
            rw = rv.width if rv is not None else 0
            if lw != rw:
                return left if lw > rw else right
            # fall back to the left-hand operand (stable ordering)
            return left
    except Exception:
        pass
    return -1


def loop_parts(insn):
    """Return (cond_expr, body_insn) for a while/do/for loop instruction.

    The Hex-Rays SDK exposes `cfor`, `cwhile` and `cdo` — there is no
    generic `cloop` accessor (a wrong attribute name raises and silently
    kills every loop-body walk).  `for` loops report their condition
    expression in `cfor.expr`.

    Returns (None, None) for anything that is not a loop.
    """
    if insn is None:
        return None, None
    try:
        op = insn.op
        if op == ida_hexrays.cit_for:
            cfor = insn.cfor
            return cfor.expr, cfor.body
        if op == ida_hexrays.cit_while:
            cwhile = insn.cwhile
            return cwhile.expr, cwhile.body
        if op == ida_hexrays.cit_do:
            cdo = insn.cdo
            return cdo.expr, cdo.body
    except Exception:
        pass
    return None, None


def _mba_var_key(e, prof):
    """Canonical variable name for an MBA operand, or None."""
    idx = _resolve_base_var(e, prof)
    if idx < 0:
        return None
    try:
        return prof.vars[idx].name
    except Exception:
        return "#%d" % idx


def _mba_const(e):
    """Integer value of a constant expression, or None."""
    if e is None:
        return None
    try:
        if e.op == ida_hexrays.cot_num:
            return int(e.numval())
        if e.op == ida_hexrays.cot_cast and e.x is not None:
            return _mba_const(e.x)
    except Exception:
        pass
    return None


def identify_mba(e, prof):
    """Recognise a mixed boolean-arithmetic rewrite of a simple operation.

    Only three identities are claimed, each requiring an exact structural
    match on variable identity — never on a single constant:

        (a ^ b) + 2 * (a & b)   ==  a + b
        (~a) + b + 1            ==  b - a
        (a | b) - (a & b)       ==  a ^ b

    Returns a dict {form, simplified, detail} or None.
    """
    if e is None or prof is None:
        return None
    try:
        op = e.op

        if op == ida_hexrays.cot_add:
            # (a ^ b) + 2 * (a & b)  ==  a + b
            for xor_side, mul_side in ((e.x, e.y), (e.y, e.x)):
                if xor_side is None or mul_side is None:
                    continue
                if xor_side.op != ida_hexrays.cot_xor:
                    continue
                if mul_side.op != ida_hexrays.cot_mul:
                    continue
                ka = _mba_var_key(xor_side.x, prof)
                kb = _mba_var_key(xor_side.y, prof)
                if not ka or not kb or ka == kb:
                    continue
                f1, f2 = mul_side.x, mul_side.y
                if _mba_const(f1) != 2:
                    f1, f2 = f2, f1
                if _mba_const(f1) != 2 or f2 is None:
                    continue
                if f2.op != ida_hexrays.cot_band:
                    continue
                ba = _mba_var_key(f2.x, prof)
                bb = _mba_var_key(f2.y, prof)
                if not ba or not bb or {ba, bb} != {ka, kb}:
                    continue
                return {"form": "add",
                        "simplified": "%s + %s" % (ka, kb),
                        "detail": "`(a ^ b) + 2 * (a & b)` is `a + b`"}

            # (~a) + b + 1  ==  b - a
            for inner, one in ((e.x, e.y), (e.y, e.x)):
                if inner is None or one is None:
                    continue
                if _mba_const(one) != 1:
                    continue
                if inner.op != ida_hexrays.cot_add:
                    continue
                not_side, other = inner.x, inner.y
                if not_side is None or not_side.op != ida_hexrays.cot_bnot:
                    not_side, other = inner.y, inner.x
                if not_side is None or not_side.op != ida_hexrays.cot_bnot:
                    continue
                ka = _mba_var_key(not_side.x, prof)
                kb = _mba_var_key(other, prof)
                if not ka or not kb or ka == kb:
                    continue
                return {"form": "sub",
                        "simplified": "%s - %s" % (kb, ka),
                        "detail": "`(~a) + b + 1` is `b - a`"}

        if op == ida_hexrays.cot_sub:
            # (a | b) - (a & b)  ==  a ^ b
            x, y = e.x, e.y
            if x is not None and y is not None and \
                    x.op == ida_hexrays.cot_bor and \
                    y.op == ida_hexrays.cot_band:
                ka = _mba_var_key(x.x, prof)
                kb = _mba_var_key(x.y, prof)
                if ka and kb and ka != kb:
                    ba = _mba_var_key(y.x, prof)
                    bb = _mba_var_key(y.y, prof)
                    if {ba, bb} == {ka, kb}:
                        return {"form": "xor",
                                "simplified": "%s ^ %s" % (ka, kb),
                                "detail": "`(a | b) - (a & b)` is `a ^ b`"}
    except Exception:
        pass
    return None


def _rhs_kind(rhs) -> str:
    """Classify an assignment RHS for provenance tracking."""
    if rhs is None:
        return "none"
    try:
        op = rhs.op
        if op == ida_hexrays.cot_num:
            return "const"
        if op == ida_hexrays.cot_str:
            return "strlit"
        if op == ida_hexrays.cot_obj:
            return "global"
        if op == ida_hexrays.cot_call:
            return "call"
        if op == ida_hexrays.cot_var:
            return "var"
        if op == ida_hexrays.cot_idx:
            return "elem"
        if op == ida_hexrays.cot_ptr:
            return "deref"
        if op == ida_hexrays.cot_cast:
            return "cast"
        if op in CMP_OPS:
            return "cmp"
        if op in ARITH_OPS:
            return "arith"
        if op in (ida_hexrays.cot_band, ida_hexrays.cot_bor,
                  ida_hexrays.cot_xor):
            return "bitop"
        if op in SHIFT_OPS:
            return "shift"
    except Exception:
        pass
    return "expr"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CACHE = {}


def build_profile(ea: int, cfunc=None) -> FuncProfile:
    """Analyze the function at `ea` and return its profile.

    Raises RuntimeError when decompilation is unavailable.
    """
    if cfunc is None:
        cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        raise RuntimeError("decompilation failed for %#x" % ea)

    prof = FuncProfile(ea, cfunc)
    try:
        lvars = cfunc.get_lvars()
    except Exception:
        lvars = []

    for i in range(len(lvars)):
        try:
            lv = lvars[i]
        except Exception:
            continue
        vu = VarUse(i, lv)
        prof.vars.append(vu)
        if vu.name and vu.name not in prof.var_by_name:
            prof.var_by_name[vu.name] = vu

    _Walker(prof).run()
    return prof


def is_library_function(ea: int) -> bool:
    """True when IDA marks the function as a library (FLIRT/type-lib) body."""
    try:
        f = ida_funcs.get_func(ea)
        return bool(f is not None and (f.flags & ida_funcs.FUNC_LIB))
    except Exception:
        return False


def is_decompilable(ea: int, skip_library: bool = True) -> bool:
    """Cheap guard: skip imports, externs, thunks and library bodies.

    ``skip_library`` defaults to True so every bulk pass honours the
    documented safety rule: suggestions are never produced for ``FUNC_LIB``
    functions.  Explicit single-function analysis (``analyze_function``)
    does not consult this helper and therefore still works on a function the
    user deliberately selected.
    """
    try:
        f = ida_funcs.get_func(ea)
        if f is None:
            return False
        if skip_library and (f.flags & ida_funcs.FUNC_LIB):
            return False
        name = ida_funcs.get_func_name(ea) or ""
        if name.startswith(".") or name.startswith("j_"):
            return False
        if f.flags & ida_funcs.FUNC_THUNK:
            return False
        if f.size() < 4:
            return False
        # import stubs live in loader-defined PLT/IAT segments
        try:
            import ida_segment
            seg = ida_segment.getseg(ea)
            if seg is not None:
                sname = ida_segment.get_segm_name(seg) or ""
                if sname in (".plt", ".plt.sec", ".plt.got", ".got", ".got.plt",
                             "extern", "EXTERNAL"):
                    return False
        except Exception:
            pass
        return True
    except Exception:
        return False
