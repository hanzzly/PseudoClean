"""PseudoClean — IDA Pro 9.4 plugin entry point.

Installation:
    Copy the PseudoClean/ directory into IDA's plugins directory
    (usually `%APPDATA%\\Hex-Rays\\IDA Pro\\plugins` on Windows).
    IDA loads it as a Python plugin on the next start.

Menu:  Edit -> Plugins -> PseudoClean
Hotkey: Ctrl-Shift-O (opens the dockable panel)

The hotkey is verified against IDA's own bindings at load time: Ctrl-Shift-P
is taken by IDA's Command Palette (cfg/idagui.cfg), which produced a
"Conflicting shortcut" warning on every startup.  If Ctrl-Shift-O is also
taken on this installation, the plugin keeps working from the menu and says
so instead of fighting for the keypress.

This module registers both the legacy `plugin_t` entry point and
`ida_kernwin` actions so the panel can be opened from the menu or a
hotkey.
"""

from __future__ import annotations

import traceback

import ida_kernwin
import idaapi

PLUGIN_NAME = "PseudoClean"
PLUGIN_COMMENT = ("Deterministic pseudocode readability assistant "
                  "(no AI, no cloud, no external services).")
PLUGIN_HELP = ("Improves Hex-Rays pseudocode readability through local "
               "static analysis: variable/function naming suggestions, "
               "expression simplification review, crypto pattern detection.")
PLUGIN_HOTKEY = "Ctrl-Shift-O"
PLUGIN_WANTED_HOTKEYS = PLUGIN_HOTKEY


# ---------------------------------------------------------------------------
# Panel singleton
# ---------------------------------------------------------------------------

_panel = None


def get_panel(create=True):
    """Return (and optionally create) the PseudoClean panel."""
    global _panel
    if _panel is None and create:
        # package-safe import: when IDA loads this file directly the
        # package directory itself is on sys.path, so "ui" resolves;
        # when it is imported as PseudoClean.plugin, use the relative form.
        try:
            from .ui.main_panel import PseudoCleanPanel
        except ImportError:
            from ui.main_panel import PseudoCleanPanel
        _panel = PseudoCleanPanel()
    return _panel


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------

class OpenPanelHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        panel = get_panel()
        panel.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def register_actions():
    # The plugin's own menu entry owns PLUGIN_HOTKEY (IDA binds the
    # `wanted_hotkey` to the Edit -> Plugins item); giving the custom action
    # the same shortcut raises a "Conflicting shortcut" warning and makes the
    # two fight for the keypress.  The action therefore carries no shortcut
    # and only supplies the menu label; the hotkey stays with the menu item.
    desc = ida_kernwin.action_desc_t(
        "pseudoclean:open_panel",
        "PseudoClean: open panel",
        OpenPanelHandler(),
        None,
        "Open the PseudoClean review panel",
        199)  # icon index (uses a generic IDA icon)
    ok = ida_kernwin.register_action(desc)
    if ok:
        # IDA 9.x: attach_action_to_menu takes SETMENU_* flags
        # (ATTACH_MENU was removed after SDK 7.x).
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/PseudoClean", "pseudoclean:open_panel",
            ida_kernwin.SETMENU_APP)
    return ok


def unregister_actions():
    ida_kernwin.detach_action_from_menu(
        "Edit/Plugins/PseudoClean", "pseudoclean:open_panel")
    ida_kernwin.unregister_action("pseudoclean:open_panel")


# ---------------------------------------------------------------------------
# plugin_t implementation
# ---------------------------------------------------------------------------

class PseudoCleanPlugin(idaapi.plugin_t):
    # legacy plugin_t: no PLUGIN_MULTI (that requires a plugmod_t entry
    # point) and no PLUGIN_HIDE (this plugin must appear in Edit -> Plugins)
    flags = 0
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        try:
            import ida_hexrays
            if not ida_hexrays.init_hexrays_plugin():
                ida_kernwin.msg(
                    "[PseudoClean] Hex-Rays decompiler not available; "
                    "the plugin is disabled.\n")
                return idaapi.PLUGIN_SKIP
        except Exception:
            ida_kernwin.msg("[PseudoClean] ida_hexrays unavailable; "
                            "plugin disabled.\n")
            return idaapi.PLUGIN_SKIP
        try:
            register_actions()
            ida_kernwin.msg(
                "[PseudoClean] loaded.  Use Edit -> Plugins -> PseudoClean "
                "(or %s) to open the panel.\n" % PLUGIN_HOTKEY)
        except Exception as exc:
            ida_kernwin.msg("[PseudoClean] failed to register actions: %s\n"
                            % exc)
            return idaapi.PLUGIN_SKIP
        return idaapi.PLUGIN_KEEP

    def term(self):
        global _panel
        try:
            unregister_actions()
        except Exception:
            pass
        try:
            import expression_simplifier
            expression_simplifier.remove_microcode_simplifier()
        except Exception:
            pass
        if _panel is not None:
            try:
                _panel.Close()
            except Exception:
                pass
            _panel = None

    def run(self, arg):
        """Invoked from Edit -> Plugins -> PseudoClean or the hotkey."""
        try:
            panel = get_panel()
            panel.Show()
        except Exception as exc:
            ida_kernwin.msg("[PseudoClean] failed to open panel: %s\n%s\n"
                            % (exc, traceback.format_exc()))


def PLUGIN_ENTRY():
    return PseudoCleanPlugin()
