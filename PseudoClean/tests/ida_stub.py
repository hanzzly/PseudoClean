"""Strict stand-ins for IDA modules, used by the offline unit tests.

The analysis modules import IDA modules at import time (constants and base
classes).  The unit tests run in plain CPython, so this shim registers fake
modules first.

The shim is STRICT: every attribute a fake module exposes is listed here
explicitly, and reading any other attribute raises AttributeError.  That makes
the offline suite a real guard against typos and SDK drift — if production
code starts using an IDA name this file does not know, the test fails instead
of silently reading a made-up integer.

This shim is only ever imported by tests/unit_tests.py.  It must never be
imported inside IDA: real modules then already exist in sys.modules.
"""

from __future__ import annotations

import sys
import types


class _Fake(types.ModuleType):
    """Module with an explicit, closed attribute set."""

    def __init__(self, name, attrs):
        super().__init__(name)
        self.__dict__["_vals"] = dict(attrs)

    def __getattr__(self, attr):
        if attr.startswith("__"):
            raise AttributeError(attr)
        try:
            return self.__dict__["_vals"][attr]
        except KeyError:
            raise AttributeError(
                "ida_stub: %s.%s is not part of the fake IDA API; add it to "
                "tests/ida_stub.py if production code legitimately needs it"
                % (self.__name__, attr)) from None

    def __setattr__(self, attr, value):
        self.__dict__["_vals"][attr] = value


# -- base classes used at definition time ------------------------------------

def _cls(name):
    return type(name, (object,), {"__module__": __name__})


class _ActionDesc(object):
    """Faithful action_desc_t: positional (name, label, handler, shortcut,
    tooltip, icon, flags), attributes readable (real IDA exposes them)."""

    def __init__(self, name, label, handler, shortcut=None,
                 tooltip=None, icon=-1, flags=0):
        self.name = name
        self.label = label
        self.handler = handler
        self.shortcut = shortcut
        self.tooltip = tooltip
        self.icon = icon
        self.flags = flags


def _ints(prefix, names, start=0x2000):
    """Distinct integer constants (the analysis code compares them)."""
    return {name: start + i for i, name in enumerate(names)}


#: Hex-Rays ctree / microcode opcodes and enums that production code reads.
_HEXRAYS_CONSTS = _ints("cot", ((
    "cot_add cot_asg cot_asgadd cot_asgband cot_asgbor cot_asgmul "
    "cot_asgsdiv cot_asgshl cot_asgsmod cot_asgsshr cot_asgsub cot_asgudiv "
    "cot_asgumod cot_asgushr cot_asgxor cot_band cot_bnot cot_bor cot_call "
    "cot_cast cot_comma cot_eq cot_helper cot_idx cot_land cot_lnot cot_lor "
    "cot_memptr cot_memref cot_mul cot_ne cot_num cot_obj cot_postdec "
    "cot_postinc cot_predec cot_preinc cot_ptr cot_ref cot_sdiv cot_sge "
    "cot_sgt cot_shl cot_sle cot_slt cot_smod cot_sshr cot_str cot_sub "
    "cot_udiv cot_uge cot_ugt cot_ule cot_ult cot_umod cot_ushr cot_var "
    "cot_xor "
    "cit_block cit_break cit_continue cit_do cit_expr cit_for cit_goto "
    "cit_if cit_return cit_switch cit_try cit_while "
    "m_add m_and m_mov m_mul m_or m_sub m_xor "
    "mop_n mop_d mop_b mop_r "
    "ITP_SEMI ITP_COLON ITP_CURLY1 ITP_CURLY2 ITP_BLOCK1 ITP_BLOCK2 "
    "RETRIEVE_ALWAYS EQ_IGNSIZE "
    "CV_FAST CV_PARENTS DECOMP_NO_WAIT MMAT_GENERATED"
).split()))

_HEXRAYS_CLASSES = {
    name: _cls(name) for name in (
        "optinsn_t ctree_visitor_t ctree_parentee_t cfunc_t qstring_printer_t "
        "treeloc_t mop_t minsn_t mblock_t mba_t lvar_t vc_printer_t "
        "decomp_ranges_t hexrays_failure_t mlist_t"
    ).split()
}


def _ida_hexrays_attrs():
    attrs = dict(_HEXRAYS_CONSTS)
    attrs.update(_HEXRAYS_CLASSES)
    attrs.update({
        "decompile": lambda ea, *a, **k: None,
        "gen_microcode": lambda *a, **k: None,
        "get_widget_vdui": lambda widget: None,
        "init_hexrays_plugin": lambda *a, **k: False,
        "mark_cfunc_dirty": lambda ea, *a, **k: False,
        "rename_lvar": lambda *a, **k: False,
    })
    return attrs


def _module_attrs():
    """Return {module name: {attribute: value}} — the complete fake API."""
    attrs = {}

    attrs["ida_hexrays"] = _ida_hexrays_attrs()

    attrs["idaapi"] = {
        "BADADDR": 0xFFFFFFFFFFFFFFFF,
        "PLUGIN_MULTI": 0x1,
        "PLUGIN_HIDE": 0x4,
        "PLUGIN_KEEP": 0x10,
        "PLUGIN_SKIP": 0x0,
        "plugin_t": _cls("plugin_t"),
        "get_tinfo": lambda ea: None,
    }

    attrs["ida_name"] = {
        "SN_NOWARN": 0x100,
        "SN_FORCE": 0x800,
        "get_ea_name": lambda ea, *a: "",
        "set_name": lambda ea, name, flags=0: False,
    }

    attrs["ida_funcs"] = {
        "FUNC_LIB": 0x4,
        "FUNC_THUNK": 0x80,
        "get_func": lambda ea: None,
        "get_func_name": lambda ea: "",
        "get_func_start": lambda ea: 0xFFFFFFFFFFFFFFFF,
    }

    attrs["ida_bytes"] = {
        "get_bytes": lambda ea, n: None,
        "get_strlit_contents": lambda ea, *a: None,
    }

    attrs["ida_typeinf"] = {
        "tinfo_t": _cls("tinfo_t"),
    }

    attrs["ida_nalt"] = {
        "get_import_module_qty": lambda: 0,
        "get_import_module_name": lambda i: "",
        "enum_import_names": lambda i, cb: True,
    }

    attrs["ida_segment"] = {
        "getseg": lambda ea: None,
        "get_segm_name": lambda seg: "",
    }

    attrs["ida_registry"] = {
        "reg_read_string": lambda name, subkey="": "",
        "reg_write_string": lambda name, utf8, subkey="": True,
    }

    attrs["ida_kernwin"] = {
        "AST_ENABLE_ALWAYS": 0x1,
        "MFF_READ": 0x2,
        "SETMENU_APP": 0x1,
        "PluginForm": _cls("PluginForm"),
        "action_handler_t": _cls("action_handler_t"),
        "action_desc_t": _ActionDesc,
        "attach_action_to_menu": lambda *a, **k: False,
        "detach_action_from_menu": lambda *a, **k: False,
        # real IDA semantics: execute_sync marshals the callable's result
        # through the request queue and returns an int status, NOT the
        # callable's return value (measured in IDA 9.4 GUI: the return is
        # always an int, so the result must be collected via a holder).
        "execute_sync": lambda fn, reqf: int(fn() is not None),
        "execute_ui_requests": lambda calls: True,
        "get_current_widget": lambda: None,
        "get_screen_ea": lambda: 0xFFFFFFFFFFFFFFFF,
        "is_idaq": lambda: True,
        "msg": lambda text: None,
        "refresh_idaview_anyway": lambda: None,
        "register_action": lambda desc: True,
        "unregister_action": lambda name: None,
    }

    attrs["ida_diskio"] = {
        "get_user_idadir": lambda: ".",
    }

    attrs["ida_auto"] = {}
    attrs["ida_ua"] = {"insn_t": _cls("insn_t"),
                        "decode_insn": lambda ea: False}
    attrs["ida_graph"] = {}
    attrs["ida_idp"] = {}
    attrs["ida_ida"] = {}

    attrs["idautils"] = {
        "Functions": lambda: iter(()),
        "Names": lambda: iter(()),
    }

    attrs["ida_netnode"] = {
        "netnode": _cls("netnode"),
    }

    attrs["ida_range"] = {}
    return attrs


_MODULES = ("ida_hexrays", "idaapi", "ida_name", "ida_funcs", "ida_bytes",
            "ida_typeinf", "ida_nalt", "ida_segment", "ida_registry",
            "ida_kernwin", "ida_diskio", "ida_auto", "ida_ua", "ida_graph",
            "idautils", "ida_idp", "ida_ida", "ida_netnode", "ida_range")


def install():
    """Register the fake modules (idempotent)."""
    attrs = _module_attrs()
    for name in _MODULES:
        if name in sys.modules:
            continue
        sys.modules[name] = _Fake(name, attrs[name])
    return sys.modules


def uninstall():
    for name in _MODULES:
        sys.modules.pop(name, None)
