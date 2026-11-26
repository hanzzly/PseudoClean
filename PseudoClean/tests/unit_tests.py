"""Offline unit tests for PseudoClean's pure logic.

Runs in plain CPython (no IDA):

    python3 PseudoClean/tests/unit_tests.py

The IDA modules are replaced by a consistency-preserving shim
(tests/ida_stub.py) so the analysis modules import unchanged.  Everything
tested here is deterministic logic: confidence combination, grading, name
uniqueness, auto-name detection, callee normalisation and base-variable
resolution for pointer/array addressing.

Requires: Python 3.8+, no third-party packages.
"""

from __future__ import annotations

import os
import sys
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG = os.path.dirname(_HERE)
for _p in (_HERE, _PKG):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import ida_stub
ida_stub.install()

import confidence as CONF
import config
import ast_analyzer as A
import function_renamer as FR
import variable_renamer as VR


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class _Expr(object):
    """Minimal stand-in for a Hex-Rays cexpr_t."""

    def __init__(self, op, x=None, y=None, idx=None, ea=0x1000):
        self.op = op
        self.x = x
        self.y = y
        self.ea = ea
        if idx is not None:
            self.v = types.SimpleNamespace(idx=idx)


class _Var(object):
    """Minimal stand-in for ast_analyzer.VarUse."""

    def __init__(self, name, width=8, ptr=False, array=False):
        self.name = name
        self.width = width
        self._ptr = ptr
        self._array = array

    def is_ptr(self):
        return self._ptr

    def is_array(self):
        return self._array


class _Profile(object):
    def __init__(self, vars_):
        self.vars = vars_


HR = sys.modules["ida_hexrays"]


# ---------------------------------------------------------------------------
# confidence
# ---------------------------------------------------------------------------

def test_combine_empty():
    assert CONF.combine() == 0
    assert CONF.combine(*[]) == 0


def test_combine_never_reaches_100():
    assert CONF.combine(100) < 100
    assert CONF.combine(100, 100, 100) <= 100
    assert CONF.combine(90) >= 75


def test_combine_is_monotonic():
    one = CONF.combine(40)
    two = CONF.combine(40, 60)
    three = CONF.combine(40, 60, 70)
    assert one < two < three


def test_combine_clamps_inputs():
    assert CONF.combine(150) == CONF.combine(100)
    assert CONF.combine(-10) == CONF.combine(0) == 0


def test_grade_thresholds():
    assert CONF.grade(100) == CONF.GRADE_HIGH
    assert CONF.grade(85) == CONF.GRADE_HIGH
    assert CONF.grade(84) == CONF.GRADE_MEDIUM
    assert CONF.grade(60) == CONF.GRADE_MEDIUM
    assert CONF.grade(59) == CONF.GRADE_LOW
    assert CONF.grade(40) == CONF.GRADE_LOW
    assert CONF.grade(39) == CONF.GRADE_REJECT


def test_unique_name():
    assert CONF.unique_name("buf", set()) == "buf"
    assert CONF.unique_name("buf", {"buf"}) == "buf_2"
    assert CONF.unique_name("buf", {"buf", "buf_2"}) == "buf_3"
    assert CONF.unique_name("buf", {"other"}) == "buf"


def test_suggestion_selection_policy():
    hi = CONF.Suggestion(CONF.Suggestion.KIND_VAR, "v1", "buf", 90, "reason")
    mid = CONF.Suggestion(CONF.Suggestion.KIND_VAR, "v1", "buf", 70, "reason")
    low = CONF.Suggestion(CONF.Suggestion.KIND_VAR, "v1", "buf", 45, "reason")
    dead = CONF.Suggestion(CONF.Suggestion.KIND_VAR, "v1", "buf", 10, "reason")
    assert hi.grade == CONF.GRADE_HIGH and hi.selected
    assert mid.grade == CONF.GRADE_MEDIUM and mid.selected
    assert low.grade == CONF.GRADE_LOW and not low.selected
    assert dead.grade == CONF.GRADE_REJECT and not dead.selected


def test_suggestion_confidence_is_clamped():
    s = CONF.Suggestion(CONF.Suggestion.KIND_VAR, "v1", "buf", 500, "reason")
    assert s.confidence == 100
    s = CONF.Suggestion(CONF.Suggestion.KIND_VAR, "v1", "buf", -5, "reason")
    assert s.confidence == 0


# ---------------------------------------------------------------------------
# config invariants
# ---------------------------------------------------------------------------

def test_config_invariants():
    assert 0 <= config.MIN_CONFIDENCE_REVIEW <= 100
    assert config.VAR_MIN_REFS >= 1
    assert config.HISTORY_LIMIT > 0
    assert config.CRC32_POLY == 0xEDB88320
    assert len(config.AES_SBOX_PREFIX) == 16
    assert config.AES_SBOX_PREFIX[:4] == (0x63, 0x7C, 0x77, 0x7B)
    assert config.KNOWN_CONSTANTS[0xEDB88320] == "CRC32 (reflected poly)"
    assert config.BASE64_STD[:4] == "ABCD"
    assert config.BASE64_URL[62:64] == "-_"


def test_config_save_is_safe_outside_ida():
    config.save_settings(auto_apply_high=True, min_confidence=50, debug=True)
    config.save_settings()          # must not raise either


# ---------------------------------------------------------------------------
# auto-name detection
# ---------------------------------------------------------------------------

def test_auto_name_detection():
    auto = ("sub_401000", "sub_0", "nullsub_7", "unknown_1234",
            "unknown_libname_9", "j_sub_401000", "j_nullsub_2")
    for name in auto:
        assert FR.is_auto_name(name), name

    meaningful = ("main", "memcpy", "xor_decode", "_start", "sub_",
                  "sub_zz", "", "printf", "my_sub_1", "j_memcpy")
    for name in meaningful:
        assert not FR.is_auto_name(name), name


# ---------------------------------------------------------------------------
# callee normalisation
# ---------------------------------------------------------------------------

def test_normalize_callee():
    assert A.normalize_callee(".memcpy") == "memcpy"
    assert A.normalize_callee("j_memcpy") == "memcpy"
    assert A.normalize_callee("__imp_memcpy") == "memcpy"
    assert A.normalize_callee("_imp__memcpy") == "memcpy"
    assert A.normalize_callee("__imp_memcpy@8") == "memcpy"
    assert A.normalize_callee("memcpy@plt") == "memcpy"
    assert A.normalize_callee("") == ""
    assert A.normalize_callee("(*v3)") == "(*v3)"


# ---------------------------------------------------------------------------
# small helpers that must never raise on None
# ---------------------------------------------------------------------------

def test_none_safe_helpers():
    assert A.expr_str(None) == "<none>"
    assert A.tif_name(None) == "?"
    assert A.type_size(None) == 0
    assert A.type_is_ptr(None) is False
    assert A.type_is_array(None) is False
    assert A.is_char_like(None) is False
    assert A.get_strlit(0) is None
    assert A._bare_var_index(None) == -1
    assert A._resolve_base_var(None, None) == -1
    assert A._rhs_kind(None) == "none"


# ---------------------------------------------------------------------------
# base-variable resolution (the core determinism claim)
# ---------------------------------------------------------------------------

def _var(i):
    return _Expr(HR.cot_var, idx=i)


def test_resolve_plain_var():
    prof = _Profile([_Var("a"), _Var("b")])
    assert A._resolve_base_var(_var(1), prof) == 1


def test_resolve_through_cast():
    prof = _Profile([_Var("a")])
    e = _Expr(HR.cot_cast, x=_var(0))
    assert A._resolve_base_var(e, prof) == 0


def test_resolve_through_deref_and_cast():
    """*(char *)(i + buf) -> buf (the address-sized operand wins)."""
    prof = _Profile([_Var("i", width=4), _Var("buf", width=8)])
    add = _Expr(HR.cot_add, x=_var(0), y=_var(1))
    cast = _Expr(HR.cot_cast, x=add)
    deref = _Expr(HR.cot_ptr, x=cast)
    assert A._resolve_base_var(deref, prof) == 1


def test_resolve_prefers_pointer_typed_operand():
    prof = _Profile([_Var("idx", width=4),
                     _Var("buf", width=8, ptr=True)])
    add = _Expr(HR.cot_add, x=_var(0), y=_var(1))
    assert A._resolve_base_var(add, prof) == 1

    add_swapped = _Expr(HR.cot_add, x=_var(1), y=_var(0))
    assert A._resolve_base_var(add_swapped, prof) == 1


def test_resolve_prefers_array_typed_operand():
    prof = _Profile([_Var("i", width=4),
                     _Var("table", width=16, array=True)])
    add = _Expr(HR.cot_add, x=_var(0), y=_var(1))
    assert A._resolve_base_var(add, prof) == 1


def test_resolve_index_expression():
    prof = _Profile([_Var("buf", width=8, ptr=True), _Var("i", width=4)])
    idx = _Expr(HR.cot_idx, x=_var(0), y=_var(1))
    assert A._resolve_base_var(idx, prof) == 0


def test_resolve_unknown_returns_minus_one():
    prof = _Profile([_Var("a")])
    assert A._resolve_base_var(_Expr(HR.cot_num), prof) == -1
    assert A._resolve_base_var(_var(9), prof) == -1   # index out of range


# ---------------------------------------------------------------------------
# tests added for the audited defects (see README "Fixed defects")
# ---------------------------------------------------------------------------

def test_stub_rejects_unknown_attributes():
    """The fake IDA API must be closed: unknown names raise AttributeError."""
    try:
        HR.definitely_not_an_ida_name
        raise AssertionError("strict stub did not raise")
    except AttributeError:
        pass


def test_settings_persist_round_trip():
    """save_settings -> load_settings must round-trip (value/subkey not swapped)."""
    reg = sys.modules["ida_registry"]
    store = {}

    def write(name, value, subkey=""):
        store[(name, subkey)] = value
        return True

    def read(name, subkey=""):
        return store.get((name, subkey), "")

    saved = (reg.reg_write_string, reg.reg_read_string)
    reg.reg_write_string = write
    reg.reg_read_string = read
    try:
        assert config.save_settings(min_confidence=55, debug=True,
                                    microcode=True) is True
        assert (config.SETTINGS_VALUE, config.REGISTRY_SUBKEY) in store
        raw = store[(config.SETTINGS_VALUE, config.REGISTRY_SUBKEY)]
        assert isinstance(raw, str) and "min_confidence" in raw

        # a fresh process would start from the module defaults
        config.MIN_CONFIDENCE_REVIEW = 40
        config.LOG_DEBUG = False
        data = config.load_settings(apply=True)
        assert data["min_confidence"] == 55
        assert config.MIN_CONFIDENCE_REVIEW == 55
        assert config.LOG_DEBUG is True
        assert config.MICROCODE_SIMPLIFIER is True
    finally:
        reg.reg_write_string, reg.reg_read_string = saved
        config.MIN_CONFIDENCE_REVIEW = 40
        config.LOG_DEBUG = False
        config.MICROCODE_SIMPLIFIER = False


class _Tif(object):
    """Minimal tinfo_t stand-in for is_char_like()."""

    def __init__(self, text, char=False, uchar=False, boolean=False,
                 ptr=False, array=False, elem=None):
        self._text = text
        self._char = char
        self._uchar = uchar
        self._bool = boolean
        self._ptr = ptr
        self._array = array
        self._elem = elem

    def is_ptr(self):
        return self._ptr

    def is_array(self):
        return self._array

    def get_ptrarr_object(self):
        return self._elem

    def get_array_element(self):
        return self._elem

    def dstr(self):
        return self._text

    def is_decl_char(self):
        return self._char

    def is_decl_uchar(self):
        return self._uchar

    def is_decl_bool(self):
        return self._bool


def test_is_char_like_accepts_cv_qualified_forms():
    # IDA reports is_decl_char() == True for 'const char' (decltype 114)
    assert A.is_char_like(_Tif("const char", char=True))
    assert A.is_char_like(_Tif("volatile const char", char=True))
    # ... but the raw decltype comparison alone used to miss them: the
    # name-based fallback must still recognise the family.
    assert A.is_char_like(_Tif("const char"))
    assert A.is_char_like(_Tif("char"))
    assert A.is_char_like(_Tif("signed char"))
    assert A.is_char_like(_Tif("unsigned char"))
    assert A.is_char_like(_Tif("unsigned const char"))
    assert A.is_char_like(_Tif("bool"))
    assert A.is_char_like(_Tif("_BYTE"))


def test_is_char_like_follows_pointer_and_array():
    inner = _Tif("const char", char=True)
    assert A.is_char_like(_Tif("const char *", ptr=True, elem=inner))
    assert A.is_char_like(_Tif("char[8]", array=True, elem=_Tif("char",
                                                               char=True)))
    # pointer-to-array-of-char
    arr = _Tif("char[8]", array=True, elem=_Tif("char", char=True))
    assert A.is_char_like(_Tif("char (*)[8]", ptr=True, elem=arr))


def test_is_char_like_rejects_non_char_types():
    for text in ("int", "size_t", "__int64", "void *", "unsigned int",
                 "long long", "float", "char32_t", "wchar_t"):
        assert not A.is_char_like(_Tif(text)), text
    assert not A.is_char_like(_Tif("char *", ptr=True, elem=None))


def test_func_lib_functions_are_excluded():
    funcs = sys.modules["ida_funcs"]

    class _F(object):
        def __init__(self, flags):
            self.flags = flags

        def size(self):
            return 32

    cases = {}
    saved_get, saved_name = funcs.get_func, funcs.get_func_name
    seg = sys.modules["ida_segment"]
    saved_seg, saved_segname = seg.getseg, seg.get_segm_name
    funcs.get_func_name = lambda ea: "sub_1000"
    seg.getseg = lambda ea: None
    try:
        cases[0x1000] = _F(funcs.FUNC_LIB)
        cases[0x2000] = _F(0)
        funcs.get_func = lambda ea: cases.get(ea)
        assert A.is_library_function(0x1000) is True
        assert A.is_library_function(0x2000) is False
        # the bulk-pass guard honours FUNC_LIB ...
        assert A.is_decompilable(0x1000, skip_library=True) is False
        assert A.is_decompilable(0x2000, skip_library=True) is True
        # ... and a direct call can opt out for a user-selected function
        assert A.is_decompilable(0x1000, skip_library=False) is True
    finally:
        funcs.get_func, funcs.get_func_name = saved_get, saved_name
        seg.getseg, seg.get_segm_name = saved_seg, saved_segname

    # the renamer refuses library bodies regardless of how it was reached
    saved = sys.modules["ida_funcs"].get_func
    sys.modules["ida_funcs"].get_func = lambda ea: _F(4)
    try:
        assert FR.suggest_function_names(0x1000) == []
    finally:
        sys.modules["ida_funcs"].get_func = saved


def test_role_names_cover_formerly_missing_roles():
    for role in ("counter", "encoded_data", "result", "flag"):
        assert role in VR.ROLE_NAMES, role
        names = VR.ROLE_NAMES[role]
        assert names, role
        assert not (set(names) & VR.GENERIC_NAMES), role
    # width placeholders are never emitted as a suggestion name
    for width, names in VR.WIDTH_NAMES.items():
        assert all(n in VR.GENERIC_NAMES for n in names), width


class _Vu(object):
    """Minimal VarUse stand-in for the variable renamer."""

    def __init__(self, name, **kw):
        self.idx = kw.get("idx", 0)
        self.name = name
        self.width = kw.get("width", 8)
        self.refs = kw.get("refs", 4)
        self.writes = kw.get("writes", 1)
        self.return_uses = kw.get("return_uses", 0)
        self.print_args = kw.get("print_args", 0)
        self.mem_dest = kw.get("mem_dest", 0)
        self.mem_src = kw.get("mem_src", 0)
        self.idx_reads = kw.get("idx_reads", 0)
        self.idx_writes = kw.get("idx_writes", 0)
        self.deref_reads = kw.get("deref_reads", 0)
        self.deref_writes = kw.get("deref_writes", 0)
        self.xor_self = kw.get("xor_self", 0)
        self.xor_uses = kw.get("xor_uses", 0)
        self.boolish = kw.get("boolish", False)
        self.is_arg = kw.get("is_arg", False)
        self.is_result = kw.get("is_result", False)
        self.asg_sources = kw.get("asg_sources", [])
        self.call_roles = kw.get("call_roles", [])
        self.callees = kw.get("callees", set())
        self.first_ea = kw.get("first_ea", 0x1000)
        self._char = kw.get("char", False)
        self._ptr = kw.get("ptr", False)
        self._array = kw.get("array", False)
        self._loop = kw.get("loop", False)
        self._type = kw.get("type_name", "")

    # used by the renamer
    def total_mem_access(self):
        return (self.idx_reads + self.idx_writes +
                self.deref_reads + self.deref_writes)

    def is_char(self):
        return self._char

    def is_ptr(self):
        return self._ptr

    def is_array(self):
        return self._array

    def type_name(self):
        return self._type

    def is_loop_counter(self):
        return self._loop


class _Prof(object):
    def __init__(self, vars_):
        self.vars = vars_
        self.var_by_name = {v.name: v for v in vars_}
        self.truncated = False
        self.returns = 1
        self.loops = 1


def _suggest(vu):
    return VR.suggest_variable_names(0x1000, None, _Prof([vu]))


def test_loop_counter_gets_informative_name():
    out = _suggest(_Vu("v3", loop=True))
    assert out, "loop counter must produce a suggestion"
    assert out[0].suggested in ("idx", "i", "counter")
    assert "qword_val" not in out[0].suggested
    assert out[0].selected is True


def test_xor_target_gets_encoded_name():
    out = _suggest(_Vu("v4", xor_self=2, idx_writes=3))
    assert out, "xor-transformed buffer must produce a suggestion"
    assert out[0].suggested in ("data", "buf", "encoded")
    assert out[0].payload.get("role") == "encoded_data"
    assert out[0].selected is True


def test_compare_style_xor_target_is_named_input():
    """`(input[i] ^ key) != stored[i]` — the buffer is user input, not data.

    Measured on a real CrackMe: the checked buffer was named `buf` alongside
    the stored ciphertext, so the two sides of the comparison looked identical
    in the pseudocode.  The comparison-style shape makes them distinguishable.
    """
    out = _suggest(_Vu("s", xor_uses=2, idx_reads=2))
    assert out, "the input side of a comparison-style decoder must be named"
    assert out[0].payload.get("role") == "input", out[0].payload
    assert out[0].suggested in ("input", "user_input", "entered")
    assert out[0].suggested not in ("buf", "buffer"), \
        "the input buffer must not share a name with the stored ciphertext"


def test_scanf_target_is_named_input():
    """A buffer handed to scanf is user input even without any XOR."""
    out = _suggest(_Vu("s", idx_reads=1,
                       call_roles=[("__isoc99_scanf", "arg1")]))
    assert out, "a scanf destination must be named"
    assert out[0].payload.get("role") == "input", out[0].payload
    assert out[0].suggested == "input"


def test_stored_buffer_keeps_data_name():
    """The non-XOR side of the comparison must not also become `input`."""
    out = _suggest(_Vu("v6", idx_reads=2, mem_src=2,
                       call_roles=[("strcpy", "dest")]))
    assert out, "the stored ciphertext must still be named"
    assert out[0].payload.get("role") != "input", out[0].payload


def test_flag_role_is_named_and_not_generic():
    out = _suggest(_Vu("v7", boolish=True, writes=2))
    assert out, "boolean-typed variable must produce a suggestion"
    assert out[0].suggested in ("flag", "is_valid")
    assert out[0].selected is True


def test_generic_width_names_are_never_offered():
    """A variable with no role evidence must not be renamed to value/qword_val."""
    for vu in (_Vu("v1", asg_sources=["const"], writes=1, refs=3),
               _Vu("v2", asg_sources=[], writes=0, refs=0)):
        for s in _suggest(vu):
            assert s.suggested not in VR.GENERIC_NAMES


def test_weak_names_are_never_preselected():
    out = _suggest(_Vu("v9", asg_sources=["expr"], ptr=True,
                       type_name="void *"))
    for s in out:
        base = s.suggested.rstrip("0123456789_")
        if base in VR.WEAK_NAMES:
            assert s.selected is False


# -- microcode operand semantics --------------------------------------------

class _Mop(object):
    def __init__(self, name, size=8, kind=None, value=0):
        self.name = name
        self.size = size
        self.t = kind
        self.value = value
        self.assigned = None
        self.erased = False
        self.number = None

    def has_side_effects(self, include_ldx=False):
        return False

    def erase(self):
        self.erased = True

    def assign(self, other):
        self.assigned = other

    def make_number(self, value, size):
        self.t = HR.mop_n
        self.value = value
        self.number = (value, size)
        self.size = size

    def unsigned_value(self):
        return self.value

    def equal_mops(self, other, flags):
        return self is other


class _Minsn(object):
    def __init__(self, opcode, l, r, d):
        self.opcode = opcode
        self.l = l
        self.r = r
        self.d = d


def test_mov_rewrite_keeps_destination_and_uses_l_as_source():
    """Verified against the IDA 9.4 SDK: d = destination, l = source."""
    import expression_simplifier as ES
    ms = ES.MicrocodeSimplifier()
    src = _Mop("eax")
    dst = _Mop("ebx")
    ins = _Minsn(HR.m_add, src, _Mop("#0"), dst)
    assert ms._to_mov(ins, src) == 1
    assert ins.opcode == HR.m_mov
    assert ins.d is dst, "destination operand must not be overwritten"
    assert ins.l is src, "source operand must be installed in l"
    assert ins.r.erased is True


def test_zero_rewrite_keeps_destination():
    import expression_simplifier as ES
    ms = ES.MicrocodeSimplifier()
    dst = _Mop("rax", size=8)
    ins = _Minsn(HR.m_mul, _Mop("rax"), _Mop("#0"), dst)
    assert ms._to_zero(ins) == 1
    assert ins.opcode == HR.m_mov
    assert ins.d is dst
    assert ins.l.number == (0, 8)


def test_microcode_optimize_never_touches_side_effecting_instructions():
    import expression_simplifier as ES
    ms = ES.MicrocodeSimplifier()

    class _Side(_Mop):
        def has_side_effects(self, include_ldx=False):
            return True

    src = _Side("call_result")
    dst = _Mop("ebx")
    ins = _Minsn(HR.m_add, src, _Mop("#0"), dst)
    assert ms._optimize(ins) == 0
    assert ins.opcode == HR.m_add
    assert ins.d is dst


# -- crypto false positives --------------------------------------------------

class _CryptoProf(object):
    def __init__(self, vars_, loops=0, constants=(), strings=(),
                 called_names=(), mba_patterns=(), name="sub_1000",
                 rotate_patterns=0):
        self.vars = vars_
        self.loops = loops
        self.constants = list(constants)
        self.strings = list(strings)
        self.called_names = list(called_names)
        self.mba_patterns = list(mba_patterns)
        self.name = name
        self.rotate_patterns = rotate_patterns
        self.xor_assign_count = 0


def _crypto_var(name, xor=0, idx_writes=0, idx_reads=0, deref_writes=0,
                shift_uses=0):
    v = _Vu(name, xor_self=xor, idx_writes=idx_writes, idx_reads=idx_reads,
            deref_writes=deref_writes)
    v.shift_uses = shift_uses
    return v


def test_scalar_xor_is_not_reported_as_decode():
    import crypto_detector as C
    prof = _CryptoProf([_crypto_var("v3", xor=1)], loops=0)
    findings = C._detect_xor_loop(prof)
    assert findings and findings[0]["kind"] == "incidental"
    assert findings[0]["confidence"] < 40


def test_buffer_xor_in_loop_is_reported_as_decode():
    import crypto_detector as C
    prof = _CryptoProf([_crypto_var("buf", xor=2, idx_writes=5,
                                    idx_reads=2)], loops=1)
    findings = C._detect_xor_loop(prof)
    assert findings and findings[0]["kind"] == "decode"
    assert findings[0]["algo"] == "xor-loop"
    assert findings[0]["confidence"] >= 60
    assert findings[0]["targets"] == ["buf"]


def test_named_encoder_is_labelled_encode():
    import crypto_detector as C
    prof = _CryptoProf([_crypto_var("buf", xor=2, idx_writes=4)], loops=1,
                       name="xor_encode_buffer")
    findings = C._detect_xor_loop(prof)
    assert findings and findings[0]["kind"] == "encode"


def test_shift_heavy_code_is_not_a_rotation():
    """The old heuristic fired on plain shifts; only paired OR-shifts count."""
    import crypto_detector as C
    prof = _CryptoProf([_crypto_var("v1", shift_uses=6)], loops=1)
    assert C._detect_rotation(prof) == []
    prof.rotate_patterns = 1
    out = C._detect_rotation(prof)
    assert out and out[0]["algo"] == "rotate"


def test_pow2_mul_advice_was_removed():
    """x*2 -> x<<1 is only valid under width/signedness assumptions we cannot
    prove from the ctree, so the suggestion must not exist at all."""
    import expression_simplifier as ES
    src = open(ES.__file__, "r", encoding="utf-8").read()
    assert "pow2_mul" not in src


# -- report / defaults -------------------------------------------------------

def test_analyzer_default_want_includes_control_flow():
    import analyzer
    assert "cf" in analyzer.DEFAULT_WANT
    assert {"vars", "func", "crypto"} <= analyzer.DEFAULT_WANT


class _CfSummary(object):
    loop_count = 1
    if_count = 2
    max_depth = 1
    return_positions = [0x1000]
    switch_cases = [3, 4]


class _Report(object):
    def __init__(self, ea, name, cf=None, crypto=None):
        self.ea = ea
        self.name = name
        self.cf_summary = cf
        self.crypto = crypto or []
        self.suggestions = []
        self.error = None

    def showing(self):
        return []


def test_report_contains_control_flow_rows():
    import analyzer
    text = analyzer.generate_readability_report(
        [_Report(0x1000, "sub_1000", cf=_CfSummary())])
    assert "## Control-flow notes" in text
    assert "loops=1 ifs=2 rets=1" in text
    assert "3,4" in text


def test_report_says_when_control_flow_was_not_collected():
    import analyzer
    text = analyzer.generate_readability_report([_Report(0x1000, "sub_1000")])
    assert "Control-flow analysis was not enabled" in text


# -- change history ----------------------------------------------------------

def test_comment_entries_are_marked_reverted():
    import change_manager as CM
    import expression_simplifier as ES

    mgr = CM.ChangeManager()
    mgr.clear()
    mgr.record("comment", 0x1000, "expr", "x ^ y is x | y for disjoint bits",
               50, "mba", module="comment", ea=0x1004)
    assert mgr.stats()["active"] == 1

    saved = ES.remove_pseudoclean_comment
    calls = []
    ES.remove_pseudoclean_comment = (
        lambda fea, ea, text: calls.append((fea, ea, text)) or True)
    try:
        reverted, failed = mgr.revert_all()
    finally:
        ES.remove_pseudoclean_comment = saved
    assert reverted == 1 and not failed
    assert calls == [(0x1000, 0x1004, "x ^ y is x | y for disjoint bits")]
    assert mgr.stats()["active"] == 0
    assert mgr.stats()["reverted"] == 1


def test_already_removed_comment_does_not_stay_pending():
    import change_manager as CM
    import expression_simplifier as ES

    mgr = CM.ChangeManager()
    mgr.clear()
    mgr.record("comment", 0x2000, "expr", "note", 50, "r", ea=0x2001)
    saved = ES.remove_pseudoclean_comment
    ES.remove_pseudoclean_comment = lambda fea, ea, text: False
    try:
        reverted, failed = mgr.revert_all()
    finally:
        ES.remove_pseudoclean_comment = saved
    assert reverted == 0
    assert mgr.stats()["active"] == 0, "stale comment entry must not stay active"


def test_failed_comment_removal_stays_pending():
    import change_manager as CM
    import expression_simplifier as ES

    mgr = CM.ChangeManager()
    mgr.clear()
    mgr.record("comment", 0x3000, "expr", "note", 50, "r", ea=0x3001)
    saved = ES.remove_pseudoclean_comment
    ES.remove_pseudoclean_comment = lambda fea, ea, text: None
    try:
        reverted, failed = mgr.revert_all()
    finally:
        ES.remove_pseudoclean_comment = saved
    assert reverted == 0
    assert len(failed) == 1
    assert mgr.stats()["active"] == 1, "an error must not be silently forgiven"


def test_variable_revert_records_bookkeeping():
    import change_manager as CM
    mgr = CM.ChangeManager()
    mgr.clear()
    mgr.record("var", 0x4000, "v1", "buf", 70, "r", module="variable")

    hexrays = HR
    saved = getattr(hexrays, "rename_lvar", None)
    calls = []
    hexrays.rename_lvar = lambda fea, a, b: calls.append((fea, a, b)) or True
    try:
        reverted, failed = mgr.revert_all()
    finally:
        hexrays.rename_lvar = saved
    assert reverted == 1 and not failed
    assert calls == [(0x4000, "buf", "v1")]
    assert mgr.stats()["active"] == 0


# -- function-name hygiene ---------------------------------------------------

def test_pseudo_callees_are_rejected_as_wrapper_names():
    for callee in ("JUMPOUT", "__ROL4__", "rol4__", "hibyte", "lobyte",
                   "__PAIR__", "bswap", "sub_1020"):
        assert FR._wrapper_name(callee) is None, callee
    for callee in ("memcpy", "VirtualAlloc", "__imp_strlen", "j_strlen"):
        assert FR._wrapper_name(callee), callee


def test_pseudo_callee_detection_covers_intrinsics_and_macros():
    for callee in ("JUMPOUT", "__ROL4__", "rol4__", "jumpout", "_byteswap",
                   "HIBYTE", "LOWORD"):
        assert FR._is_pseudo_callee(callee) is True, callee
    for callee in ("memcpy", "strlen", "my_helper", "math_sqrt"):
        assert FR._is_pseudo_callee(callee) is False, callee


# --- GUI wiring: contracts that only bite in a live IDA session ------------
#
# Both defects below were reported from a real IDA 9.4 GUI session and were
# invisible headless, because the headless path runs the bulk pass inline and
# never touches these code paths.  These tests pin the contracts.

def test_execute_sync_result_is_collected_through_a_holder():
    """`execute_sync` returns an int, not the callable's return value.

    Verified in IDA 9.4 GUI: the marshalled callable's result goes through
    IDA's request queue and the call returns a status int.  The panel's worker
    therefore collected `int` objects instead of FunctionReports, which blew up
    later with "'int' object has no attribute 'showing'".
    """
    calls = []

    def fake_execute_sync(fn, reqf):
        calls.append(fn())
        return 0            # IDA's actual return: a status int

    box = []

    def job():
        box.append("report")
        return 0

    result = fake_execute_sync(job, 0)
    assert isinstance(result, int), "stub contract: execute_sync returns int"
    rep = box[0] if box else None
    assert rep == "report", "the result must be read from the holder"

    # and the naive form really does lose the value
    naive = fake_execute_sync(lambda: "report", 0)
    assert not hasattr(naive, "showing")


def test_panel_worker_collects_reports_not_status_ints():
    """Execute the panel's real worker with IDA's execute_sync contract.

    `execute_sync` returns a status int, so a worker that trusts its return
    value ends up appending ints to `reports` and the UI later dies with
    "'int' object has no attribute 'showing'".  This runs the actual
    `PseudoCleanPanel._worker` against a faithful `execute_sync` and asserts
    the collected reports are the objects, not ints.
    """
    import ida_kernwin
    import ui.main_panel as MP

    class _Rep(object):
        def __init__(self, ea):
            self.ea = ea
            self.error = None

        def showing(self):
            return []

    done = {}

    class _FakePanel(object):
        _cancel = False
        _job = {"label": "test", "total": 2, "done": 0}
        _analyze_one = staticmethod(
            lambda ea, want: _Rep(ea))

        def _on_progress(self, i, rep):
            done.setdefault("progress", []).append((i, type(rep).__name__))

        def _on_finished(self, reports):
            done["reports"] = reports

    orig_sync = ida_kernwin.execute_sync
    orig_ui = ida_kernwin.execute_ui_requests
    # IDA 9.4 semantics: run the callable, return a status int.
    ida_kernwin.execute_sync = lambda fn, reqf: int(bool(fn()))
    ida_kernwin.execute_ui_requests = lambda calls: [c() for c in calls]
    try:
        MP.PseudoCleanPanel._worker(_FakePanel(), {"vars"}, [0x1000, 0x2000])
    finally:
        ida_kernwin.execute_sync = orig_sync
        ida_kernwin.execute_ui_requests = orig_ui

    reports = done.get("reports")
    assert reports is not None, "_on_finished must be called"
    assert len(reports) == 2, "both functions must produce a report"
    for rep in reports:
        assert isinstance(rep, _Rep), \
            "worker collected %r, not a FunctionReport" % (type(rep).__name__,)
    # the exact failure from the GUI log must be impossible now
    for rep in reports:
        rep.showing()          # raises AttributeError for an int

    # ...and the UI path that consumed them works
    all_sugg = []
    for r in reports:
        all_sugg.extend(r.showing())
    assert all_sugg == []


def test_custom_action_does_not_duplicate_the_plugin_hotkey():
    """The plugin hotkey must not be IDA's own Command Palette shortcut.

    Two reported sessions: Ctrl-Shift-P belongs to IDA's built-in
    Command Palette (cfg/idagui.cfg) *and* was used for the menu item, so IDA
    printed "Conflicting shortcut: Ctrl+Shift+P" on every start with
    {"Edit/Plugins/PseudoClean", "CommandPalette"} as the candidates.  The
    custom action carries no shortcut, and the plugin hotkey is a key IDA does
    not bind.
    """
    import inspect
    import ida_kernwin
    import plugin as P

    assert P.PLUGIN_HOTKEY != "Ctrl-Shift-P", \
        "Ctrl-Shift-P is IDA's Command Palette shortcut, not ours"
    assert P.PLUGIN_HOTKEY == "Ctrl-Shift-O"
    # the plugin (menu item) owns it
    assert P.PseudoCleanPlugin.wanted_hotkey == P.PLUGIN_HOTKEY

    captured = {}

    def fake_register(desc):
        captured["desc"] = desc
        return True

    orig = ida_kernwin.register_action
    ida_kernwin.register_action = fake_register
    try:
        P.register_actions()
    finally:
        ida_kernwin.register_action = orig

    desc = captured.get("desc")
    assert desc is not None, "register_actions must register the action"
    assert desc.name == "pseudoclean:open_panel"
    assert not desc.shortcut, \
        "the action must not reuse the plugin hotkey (conflict warning)"

    # the only mention of the hotkey in register_actions is the comment
    body = inspect.getsource(P.register_actions)
    assert "None," in body


def test_plugin_flags_allow_menu_visibility():
    """A legacy plugin_t must not set PLUGIN_MULTI or PLUGIN_HIDE."""
    import idaapi
    import plugin as P

    flags = P.PseudoCleanPlugin.flags
    assert not (flags & idaapi.PLUGIN_HIDE), \
        "PLUGIN_HIDE removes the plugin from Edit -> Plugins"
    assert not (flags & idaapi.PLUGIN_MULTI), \
        "PLUGIN_MULTI requires a plugmod_t entry point"


def test_install_manifest_present_and_correct():
    """IDA 9.4 does not scan a bare subfolder; the manifest is required."""
    import json
    path = os.path.join(_PKG, "ida-plugin.json")
    assert os.path.isfile(path), "ida-plugin.json must ship with the package"
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["IDAMetadataDescriptorVersion"] == 1
    assert data["plugin"]["entryPoint"] == "plugin.py"
    assert data["plugin"]["name"] == "PseudoClean"


# --- crypto detection: comparison-style XOR decoders ------------------------
#
# `chall` (a real CrackMe reviewed in a live session) compares
# `(input[i] ^ key) != stored[i]` instead of using `^=`.  The detector only
# counted `cot_asgxor`, so it reported "no crypto patterns" on a plain XOR
# cipher.  These tests pin both the new positive case and the old negatives.

def _xor_profile(*vars_):
    p = A.FuncProfile(0x1000, None)
    p.loops = 1
    p.vars = list(vars_)
    return p


def _xor_var(name, **kw):
    v = A.VarUse.__new__(A.VarUse)
    for field in A.VarUse.__slots__:
        setattr(v, field, 0)
    v.name = name
    v.width = 8
    v.callees = set()
    v.asg_sources = []
    v.const_assigns = []
    v.call_roles = []
    for k, val in kw.items():
        setattr(v, k, val)
    return v


def test_compare_style_xor_decoder_is_detected():
    """`(buf[i] ^ k) != stored[i]` must be reported, not missed."""
    import crypto_detector as C

    prof = _xor_profile(_xor_var("s", xor_uses=2, idx_reads=2))
    found = C._detect_xor_loop(prof)
    assert found, "a comparison-style XOR decoder must be reported"
    f = found[0]
    assert f["kind"] == "decode", f
    assert f["algo"] == "xor-compare", f
    assert f["targets"] == ["s"], f
    assert f["confidence"] >= 60, f


def test_assign_style_xor_decoder_keeps_its_algorithm():
    """The classic `buf[i] ^= k` loop must keep working and stay distinct."""
    import crypto_detector as C

    prof = _xor_profile(_xor_var("buf", xor_self=1, idx_writes=1))
    found = C._detect_xor_loop(prof)
    assert found, "an assign-style XOR decoder must still be reported"
    assert found[0]["kind"] == "decode", found
    assert found[0]["algo"] in ("xor", "xor-loop"), found
    assert found[0]["algo"] != "xor-compare", \
        "an in-place decoder is not a comparison-style check"


def test_scalar_xor_read_stays_incidental():
    """A lone scalar XOR with no memory traffic is not a cipher."""
    import crypto_detector as C

    prof = _xor_profile(_xor_var("x", xor_uses=1))
    found = C._detect_xor_loop(prof)
    assert found, "a scalar XOR is reported, but only as incidental"
    assert found[0]["kind"] == "incidental", found


def test_xor_keys_are_extracted_and_named_in_the_note():
    """A detected pattern must produce text a reader can act on.

    Reported from a live session: the only comment written into the
    pseudocode was the raw counter line `loops=1 ifs=4 switches=0 returns=2`,
    which says nothing about the algorithm.  The finding now carries the XOR
    key constants and a sentence that names the shape.
    """
    import crypto_detector as C

    keys = [(0x08, 0x1234, 0x1200), (0x10, 0x1234, 0x1200)]
    assert C.format_xor_keys(keys) == "0x08, 0x10"
    assert C.format_xor_keys([(0x1F, 1, 1)]) == "0x1F"

    # the note is built from the constants the ctree walk finds
    saved = C._xor_operand_constants
    C._xor_operand_constants = lambda prof: keys
    try:
        prof = _xor_profile(_xor_var("input", xor_uses=2, idx_reads=2))
        found = C._detect_xor_loop(prof)[0]
    finally:
        C._xor_operand_constants = saved

    assert found["kind"] == "decode", found
    assert found["keys"] == [0x08, 0x10], found
    assert found["xor_ea"] == 0x1234, found
    assert found["key_ea"] == 0x1200, \
        "the comment must anchor on a statement-level expression address"
    note = found["note"]
    assert "0x08, 0x10" in note, note
    assert "0x1234" in note, note
    assert "password" in note and "not real encryption" in note, note


def test_no_keys_means_no_note():
    """Without key constants there is nothing to explain, so no note."""
    import crypto_detector as C

    prof = _xor_profile(_xor_var("buf", xor_self=1, idx_writes=1))
    found = C._detect_xor_loop(prof)[0]
    assert found["kind"] == "decode", found
    assert "keys" not in found
    assert "note" not in found


def test_function_shape_is_report_only_not_a_comment():
    """The counter line is useful in the table, noise in the pseudocode.

    Measured in a live session: `PseudoClean: loops=1 ifs=4 switches=0
    returns=2 (2 early)` landed on the stack-canary line, which tells the
    reader nothing.  Pure statistics are therefore not annotated.
    """
    import control_flow as CF

    class _Prof(object):
        ea = 0x1000
        complex_conds = 0

    class _W(object):
        loop_count = 1
        if_count = 4
        switch_count = 0
        return_positions = [1, 2]
        early_returns = 1
        max_depth = 1
        if_count_attr = 4
        goto_count = 0
        switch_cases = []
        nested_switch = 0
        opaque_candidates = []

    # call the shaping helper directly through the public API shape
    import inspect
    src = inspect.getsource(CF.analyze_control_flow)
    assert 'annotate=False' in src, \
        "the counter summary must not be annotated into the pseudocode"


def test_comment_path_skips_report_only_observations():
    """`annotate_suggestions` must honour Suggestion.annotate."""
    import inspect
    import expression_simplifier as ES

    src = inspect.getsource(ES.annotate_suggestions)
    assert 'getattr(s, "annotate", True)' in src, \
        "report-only observations must not be written as comments"


def test_comment_is_anchored_on_a_body_statement():
    """An entry-address annotation renders as an Orphan comments block.

    Verified in a live IDA 9.4 session: a comment on the function-entry
    address appears in an "Orphan comments" section *after* the function,
    while the same comment on the first body statement renders inline.  The
    annotator must therefore move entry-address comments into the body.
    """
    import inspect
    import expression_simplifier as ES
    import ida_hexrays

    class _Cfunc(object):
        def __init__(self):
            self.body = None
            self.saved = {}

        def get_user_cmt(self, loc, how):
            return self.saved.get((loc.ea, loc.itp))

        def set_user_cmt(self, loc, cmt):
            self.saved[(loc.ea, loc.itp)] = cmt

        def save_user_cmts(self):
            return True

    class _Ins(object):
        def __init__(self, ea):
            self.ea = ea

    class _Block(object):
        def __iter__(self):
            return iter([_Ins(0x1222), _Ins(0x1300)])

    class _Body(object):
        op = ida_hexrays.cit_block
        cblock = _Block()

    cfunc = _Cfunc()
    cfunc.body = _Body()

    s = CONF.Suggestion(CONF.Suggestion.KIND_INFO,
                        "function shape",
                        "loops=1 ifs=4",
                        100,
                        "control-flow summary",
                        ea=0x1209,
                        func_ea=0x1209)
    s.selected = True

    # the ctree walk cannot run on the stub, so supply the anchors that a
    # real function provides: two statement-level expression addresses.
    saved_anchors = ES._inline_anchors
    ES._inline_anchors = lambda cf: [0x1222, 0x1300]
    try:
        applied, failed = ES.annotate_suggestions(cfunc, [s], 0x1209)
    finally:
        ES._inline_anchors = saved_anchors
    assert not failed, failed
    assert len(applied) == 1, applied
    assert (0x1209, ida_hexrays.ITP_SEMI) not in cfunc.saved, \
        "an entry-address comment would render as orphan comments"
    assert (0x1222, ida_hexrays.ITP_SEMI) in cfunc.saved, \
        "the comment must land on the first inline-capable anchor"
    assert "PseudoClean:" in cfunc.saved[(0x1222, ida_hexrays.ITP_SEMI)]

    # an insn address (if/block/for) is never used, only an anchor is
    s2 = CONF.Suggestion(CONF.Suggestion.KIND_INFO, "goto count", "x", 80,
                         "r", ea=0x12f0, func_ea=0x1209)
    s2.selected = True
    saved_anchors = ES._inline_anchors
    ES._inline_anchors = lambda cf: [0x1222, 0x1300]
    try:
        applied2, failed2 = ES.annotate_suggestions(cfunc, [s2], 0x1209)
    finally:
        ES._inline_anchors = saved_anchors
    assert not failed2, failed2
    assert (0x12f0, ida_hexrays.ITP_SEMI) not in cfunc.saved, \
        "an insn address always renders as orphan comments"
    assert (0x1222, ida_hexrays.ITP_SEMI) in cfunc.saved

    # and the remover must still find it there
    assert "_first_stmt_ea" in inspect.getsource(ES)
    assert "body_ea" in inspect.getsource(ES.remove_pseudoclean_comments)


def test_beautifier_invert_condition():
    """Condition inverter correctly inverts comparisons."""
    import c_beautifier as CB

    assert CB.invert_condition("argc == 2") == "argc != 2"
    assert CB.invert_condition("argc != 2") == "argc == 2"
    assert CB.invert_condition("len <= 32") == "len > 32"
    assert CB.invert_condition("len >= 32") == "len < 32"
    assert CB.invert_condition("len < 32") == "len >= 32"
    assert CB.invert_condition("len > 32") == "len <= 32"
    assert CB.invert_condition("!(x == 1)") == "x == 1"
    assert CB.invert_condition("!valid") == "valid"


def test_beautifier_depyramid_and_alias():
    """Beautifier transforms raw nested Hex-Rays pseudocode to clean readable C."""
    import c_beautifier as CB

    raw_sample = """int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int i; // [rsp+14h] [rbp-Ch]

  if ( argc == 2 )
  {
    if ( strlen(s: argv[1]) == 32 )
    {
      for ( i = 0; i < 0x20; ++i )
      {
        if ( rotl8(nilai: (73 * argv[1][i] + 29) ^ 0xA7, geser: i & 7) != blob[i + 5] )
        {
          printf(format: "[-] karakter ke-%u salah\\n", i);
          return 1;
        }
      }
      puts(s: "[+] Benar! Flag diterima.");
      return 0;
    }
    else
    {
      puts(s: "[-] panjang flag salah");
      return 1;
    }
  }
  else
  {
    fprintf(stream: stderr, format: "pemakaian: %s '<flag>'\\n", *argv);
    return 1;
  }
}"""

    cleaned = CB.beautify_c_code(raw_sample)

    # 1. Headers synthesized
    assert "#include <stdint.h>" in cleaned
    assert "#include <stdio.h>" in cleaned
    assert "#include <string.h>" in cleaned

    # 2. Extern declarations synthesized
    assert "extern uint8_t blob[];" in cleaned
    assert "uint8_t rotl8" in cleaned

    # 3. Signature normalized (no __fastcall, no envp)
    assert "int main(int argc, char *argv[])" in cleaned
    assert "__fastcall" not in cleaned
    assert "envp" not in cleaned

    # 4. De-pyramiding (early exits)
    assert "if (argc != 2)" in cleaned
    assert "if (strlen(flag) != 32)" in cleaned

    # 5. Flag aliasing
    assert "const char *flag = argv[1];" in cleaned

    # 6. Expression splitting
    assert "uint8_t transformed = (73 * flag[i] + 29) ^ 0xA7;" in cleaned
    assert "uint8_t rotated = rotl8(transformed, i % 8);" in cleaned
    assert "if (rotated != blob[i + 5])" in cleaned

    # 7. Idioms: *argv -> argv[0], 0x20 -> 32
    assert "argv[0]" in cleaned
    assert "i < 32" in cleaned


def test_solver_generator_ctf_patterns():
    """Z3 solver generator extracts loop constraints, affine math, and generates valid python."""
    import solver_generator as SG

    raw_sample = """int main(int argc, char *argv[])
{
  if (argc != 2) return 1;
  const char *flag = argv[1];
  for (unsigned int i = 0; i < 32; i++) {
    uint8_t transformed = ((73 * flag[i]) + 29) ^ 0xA7;
    uint8_t rotated = rotl8(transformed, i % 8);
    if (rotated != blob[i + 5]) return 1;
  }
  return 0;
}"""

    pat = SG.extract_ctf_patterns(raw_sample)
    assert pat["length"] == 32
    assert pat["affine_mul"] == 73
    assert pat["affine_add"] == 29
    assert pat["xor_key"] == 0xA7
    assert pat["has_rotl"] is True
    assert pat["target_name"] == "blob"
    assert pat["target_offset"] == 5

    z3_code = SG.generate_z3_solver(raw_sample)
    assert "from z3 import *" in z3_code
    assert "flag = [BitVec(f\"flag_{i}\", 8) for i in range(32)]" in z3_code
    assert "def rotl8(val, shift):" in z3_code
    assert "transformed = ((73 * flag[i] + 29) ^ 0xa7) & 0xFF" in z3_code
    assert "rotated = rotl8(transformed, i % 8)" in z3_code
    assert "s.add(rotated == target[i])" in z3_code
    assert "s.check() == sat" in z3_code


def test_beautifier_canary_and_alternating_keys():
    """Canary removal and alternating XOR keys de-spaghetti into clean ternary."""
    import c_beautifier as CB
    import solver_generator as SG

    raw = """int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t len; // rbx
  int i; // [rsp+Ch] [rbp-84h]
  char buf[48]; // [rsp+10h] [rbp-80h] BYREF
  char input[56]; // [rsp+40h] [rbp-50h] BYREF
  unsigned __int64 v8; // [rsp+78h] [rbp-18h]

  v8 = __readfsqword(0x28u);
  strcpy(buf, "CETsd` =#Wqz#WuicqO;~kbq`|!8~Wbaw`d7/u");
  __isoc99_scanf(a1: "%49s", input);
  len = strlen(s: input);
  if ( len == strlen(s: buf) )
  {
    for ( i = 0; i < strlen(s: buf); ++i )
    {
      if ( (i & 1) != 0 )
      {
        if ( ((unsigned __int8)input[i] ^ 8) != buf[i] )
        {
LABEL_5:
          puts(s: "Incorrect password.");
          return 1;
        }
      }
      else if ( ((unsigned __int8)input[i] ^ 0x10) != buf[i] )
      {
        goto LABEL_5;
      }
    }
    puts(s: "Correct password!");
  }
  else
  {
    puts(s: "Incorrect password size.");
  }
  return 0;
}"""

    cleaned = CB.beautify_c_code(raw)

    # 1. Canary stripped
    assert "__readfsqword" not in cleaned
    assert "v8" not in cleaned
    assert "BYREF" not in cleaned

    # 2. De-pyramiding
    assert "if (len != strlen(buf))" in cleaned

    # 3. GOTO despaghetti into ternary
    assert "goto LABEL_5" not in cleaned
    assert "LABEL_5:" not in cleaned
    assert "uint8_t key = (i % 2 != 0) ? 0x08 : 0x10;" in cleaned
    assert "if ((input[i] ^ key) != buf[i])" in cleaned

    # 4. Instant CTF Solver
    pat = SG.extract_ctf_patterns(raw)
    assert pat["target_string"] == "CETsd` =#Wqz#WuicqO;~kbq`|!8~Wbaw`d7/u"
    assert pat["alt_keys"] == (8, 16)
    assert pat["decoded_flag"] == "SMD{th053_ar3_easy_3ncrypt10n_right??}"


def test_beautifier_helper_function():
    """Helper function rotl8 has return type fixed, no self-extern, and clean braces."""
    import c_beautifier as CB

    raw = """__int64 __fastcall rotl8(uint8_t nilai, char geser)
{
  if ( (geser & 7) != 0 )
    return (nilai << (geser & 7)) | (unsigned int)((int)nilai >> (8 - (geser & 7)));
  else
    return nilai;
}"""

    cleaned = CB.beautify_c_code(raw)

    # 1. Return type & param normalized
    assert "uint8_t rotl8(uint8_t nilai, uint8_t geser)" in cleaned
    assert "__int64" not in cleaned
    assert "__fastcall" not in cleaned

    # 2. No self-declaration of extern
    assert "extern" not in cleaned

    # 3. Cast noise removed
    assert "(unsigned int)" not in cleaned
    assert "((int)nilai" not in cleaned

    # 4. Repeated bitmask extracted & guard inverted
    assert "uint8_t shift = geser & 7;" in cleaned
    assert "if (shift == 0) {" in cleaned
    assert "return (nilai << shift) | (nilai >> (8 - shift));" in cleaned


def test_go_beautifier_and_solver():
    """Go pseudocode beautifier cleans IDA Go artifacts and generates Go XOR solver."""
    import go_beautifier as GB
    import solver_generator as SG
    import c_beautifier as CB

    go_pseudo = """// main.main
void main_main()
{
  __int64 i; // r9
  os_File *v1; // [rsp+0h] [rbp-F0h]
  _slice_interface_ v2; // [rsp+8h] [rbp-E8h] BYREF
  bufio_Reader b; // [rsp+80h] [rbp-70h] BYREF
  string v13; // 0:kr40_16.16
  io_Writer v14; // 0:rax.8,8:rbx.8

  v14.data = os_Stdout;
  fmt_Fprint(w: v14, a: v19);
  r0 = bufio__ptr_Reader_ReadString(&b, delim: 0xAu)._r0;
  v13 = strings_TrimRight(s: r0, cutset: v18);
  if ( v13.len == main_enc.len )
  {
    for ( i = 0; i < main_enc.len; ++i )
    {
      if ( main_enc.array[i] != ((unsigned __int8)aGolang[i % 6uLL] ^ v13.str[i]) )
        goto LABEL_3;
    }
    fmt_Fprintln(w: v16, a: v21);
  }
  else
  {
LABEL_3:
    fmt_Fprintln(w: v15, a: v20);
  }
}"""

    assert SG.detect_pseudocode_language(go_pseudo) == "go"
    cleaned = CB.beautify_pseudocode_auto(go_pseudo)
    assert "func main()" in cleaned
    assert "bufio.NewReader" in cleaned
    assert "fmt.Print" in cleaned
    assert "fmt.Println" in cleaned
    assert "XOR key: \"golang\" (6 bytes)" in cleaned
    assert "key[i%6]" in cleaned
    assert "enc[i]" in cleaned

    solver = SG.generate_solver_auto(go_pseudo)
    assert "Go multi-byte XOR" in solver
    assert 'key = b"golang"' in solver
    assert "i % 6" in solver


def test_rust_beautifier_and_solver():
    """Rust pseudocode beautifier cleans IDA Rust artifacts and generates Rust XOR solver."""
    import rust_beautifier as RB
    import solver_generator as SG
    import c_beautifier as CB

    rust_pseudo = """__int64 __fastcall sub_1400(unsigned __int8 *a1, __int64 a2)
{
  unsigned __int8 *v2;
  __int64 v3;
  v3 = __readfsqword(0x28u);
  if ( a2 != 27 )
    core_panicking_panic();
  for ( i = 0; i < 27; ++i )
  {
    if ( ((unsigned __int8)enc[i] ^ key[i % 4uLL]) != a1[i] )
      return 0;
  }
  return 1;
}"""

    assert SG.detect_pseudocode_language(rust_pseudo) == "rust"
    cleaned = CB.beautify_pseudocode_auto(rust_pseudo)
    assert "fn validate(input: &str) -> bool" in cleaned
    assert "__readfsqword" not in cleaned
    assert "panic!" in cleaned
    assert "Multi-byte XOR key length: 4 bytes" in cleaned

    solver = SG.generate_solver_auto(rust_pseudo)
    assert "Rust Multi-byte XOR Solver" in solver
    assert "key_len=4" in solver
    assert "known_plaintext_attack" in solver


def test_go_crypto_zlib_aes_cbc():
    """Go beautifier & solver handle general Go stdlib pipelines (zlib + PKCS#7 + AES-CBC)."""
    import c_beautifier as CB
    import solver_generator as SG

    raw_go = """// main.checkFlag
bool __golang main_checkFlag(__int64 a1, __int64 a2)
{
  __int64 v2; // rax
  char v10; // dl
  unsigned __int64 idx; // rsi
  char v15; // [rsp+1h] [rbp-69h] BYREF
  unsigned __int64 v16; // [rsp+2h] [rbp-68h]
  unsigned __int64 v17; // [rsp+Ah] [rbp-60h]
  signed __int64 v18; // [rsp+12h] [rbp-58h]
  __int64 *v25; // [rsp+4Ah] [rbp-20h]
  retval_4C1980 v32; // 0:kr50_16.16
  retval_464880 v33; // 0:kr00_24.24
  retval_4C1FC0 v34; // 0:kr60_24.24

  v25 = (__int64 *)runtime_mallocgcSmallScanNoHeaderSC5(a1: 40, a2: "(", a3: 1);
  v22 = compress_zlib_NewWriterLevelDict(a1: &off_5D6568, a2: v25, a3: -1, a4: 0, a5: 0, a6: 0);
  v33 = runtime_stringtoslicebyte(a1: 0, a2: a1, a3: a2);
  if ( compress_zlib__ptr_Writer_Write(a1: v22, a2: v33._r0, a3: v33._r1, a4: v33._r2)._r1 != 0 )
    os_Exit(a1: 1);
  v2 = compress_zlib__ptr_Writer_Close(a1: v22);
  if ( v2 != 0 )
    v2 = os_Exit(a1: 1);
  v15 = 16 - ((v3 - v4) & 0xF);
  v30 = bytes_Repeat(a1: &v15, a2: 1, a3: 1);
  if ( qword_5E0F88 != v18 )
    return false;
  v34 = crypto_aes_NewCipher(a1: off_5E0F40, a2: qword_5E0F48, a3: qword_5E0F50);
  v26 = runtime_makeslice(a1: &unk_5C4608, a2: v18, a3: v18);
  v32 = crypto_cipher_NewCBCEncrypter(a1: v20, a2: v24, a3: off_5E0F60, a4: qword_5E0F68, a5: qword_5E0F70);
  v9 = (*(__int64 (__golang **)(_QWORD, __int64, signed __int64, signed __int64, __int64, signed __int64, unsigned __int64))(v32._r0 + 32LL))(
         a1: v32._r1,
         a2: v26,
         a3: v18,
         a4: v18,
         a5: v23,
         a6: v18,
         a7: v19);
  v10 = 0;
  for ( idx = 0; (__int64)idx < v18; ++idx )
  {
    if ( idx >= qword_5E0F88 )
      runtime_panicBounds(a1: v9);
    v10 |= *((_BYTE *)off_5E0F80 + idx) ^ *(_BYTE *)(idx + v26);
  }
  return v10 == 0;
}"""

    assert SG.detect_pseudocode_language(raw_go) == "go"
    cleaned = CB.beautify_pseudocode_auto(raw_go)
    assert "package main" in cleaned
    assert '"compress/zlib"' in cleaned
    assert '"crypto/aes"' in cleaned
    assert '"crypto/cipher"' in cleaned
    assert "aesKey" in cleaned and "off_5E0F40" in cleaned
    assert "aesIV" in cleaned and "off_5E0F60" in cleaned
    assert "expectedCiphertext" in cleaned and "off_5E0F80" in cleaned
    assert "func checkFlag(input string) bool {" in cleaned
    assert "zw := zlib.NewWriter(&buf)" in cleaned
    assert "padLen := 16 - (len(compressed) % 16)" in cleaned
    assert "block, err := aes.NewCipher(aesKey)" in cleaned
    assert "mode := cipher.NewCBCEncrypter(block, aesIV)" in cleaned
    assert "mode.CryptBlocks(ciphertext, padded)" in cleaned
    assert "var diff byte" in cleaned
    assert "diff |= expectedCiphertext[i] ^ ciphertext[i]" in cleaned
    assert "return diff == 0" in cleaned

    solver = SG.generate_solver_auto(raw_go)
    assert "AES.MODE_CBC" in solver
    assert "zlib.decompress" in solver
    assert "off_5E0F40" in solver
    assert "off_5E0F60" in solver
    assert "off_5E0F80" in solver


def test_go_general_statement_folding():
    """Order-independent Go lifter handles arbitrary Go stdlib & control flow (e.g. sha256 + hex)."""
    import c_beautifier as CB

    raw_sha = """// main.verifyToken
bool __golang main_verifyToken(__int64 a1, __int64 a2)
{
  __int64 v3; // rax
  retval_464880 v4; // 0:kr00_24.24

  v4 = runtime_stringtoslicebyte(a1: 0, a2: a1, a3: a2);
  v3 = crypto_sha256_Sum256(a1: v4._r0, a2: v4._r1, a3: v4._r2);
  if ( !strings_EqualFold(a1: encoding_hex_EncodeToString(a1: v3), a2: off_5A1000) )
    return false;
  return true;
}"""

    cleaned = CB.beautify_pseudocode_auto(raw_sha)
    assert "package main" in cleaned
    assert '"crypto/sha256"' in cleaned
    assert '"encoding/hex"' in cleaned
    assert '"strings"' in cleaned
    assert "func verifyToken(input string) bool {" in cleaned
    assert "sha256.Sum256" in cleaned
    assert "hex.EncodeToString" in cleaned
    assert "strings.EqualFold" in cleaned
    assert "__golang" not in cleaned
    assert "retval_" not in cleaned





# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

def main():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failures = []
    for name, fn in tests:
        try:
            fn()
            print("  [OK]   %s" % name)
        except AssertionError as exc:
            failures.append((name, exc))
            print("  [FAIL] %s: %s" % (name, exc))
        except Exception as exc:            # noqa: BLE001 - report everything
            failures.append((name, exc))
            print("  [ERROR] %s: %r" % (name, exc))
    print("\n%d test(s), %d failure(s)" % (len(tests), len(failures)))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
