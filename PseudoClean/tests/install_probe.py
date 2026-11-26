"""Install test: does IDA discover and load the installed plugin on its own?

This is the check that the README install instructions actually work. It is
deliberately *not* part of the per-binary suite: it needs a **separate**
IDAUSR home so it cannot disturb the real installation, and it asserts on the
plugin-init message IDA prints at startup rather than on anything the plugin
does itself.

Run through `./testbin/run_tests.sh install` (which prepares the throwaway
home and invokes IDA); the probe itself is read-only.

Layout it expects (prepared by the runner):

    <IDAUSR>/plugins/PseudoClean/          <- a copy of the package
    <IDAUSR>/plugins/PseudoClean/ida-plugin.json

The probe asserts only on facts it can read from inside IDA: the user home it
actually runs in (printed so the runner can confirm the isolated home was
honoured) and whether IDA's own plugin registry contains the plugin. The
"plugin printed its init message" check lives in the runner, which owns the
log file — the WSL/Windows boundary makes environment variables unreliable.

Exit codes: 0 = all checks passed, 1 = a check failed.
"""

from __future__ import annotations

import os
import sys
import traceback

import ida_auto
import ida_diskio
import ida_loader
import idaapi

FAILURES = []


def check(cond, label):
    print("  [%s] %s" % ("OK" if cond else "FAIL", label))
    if not cond:
        FAILURES.append(label)
    return bool(cond)


def main():
    ida_auto.auto_wait()
    idausr = ida_diskio.get_user_idadir()
    plugdir = os.path.join(idausr, "plugins")
    pkg = os.path.join(plugdir, "PseudoClean")
    print("IDAUSR   = %r" % (idausr,))
    print("plugdir  = %r" % (plugdir,))

    check(os.path.isfile(os.path.join(pkg, "plugin.py")),
          "package copied into <IDAUSR>/plugins/PseudoClean")
    manifest = os.path.join(pkg, "ida-plugin.json")
    check(os.path.isfile(manifest),
          "ida-plugin.json present (IDA 9.4 does not scan bare subfolders)")
    if os.path.isfile(manifest):
        import json
        try:
            data = json.load(open(manifest, encoding="utf-8"))
            ok = (data.get("plugin", {}).get("entryPoint") == "plugin.py"
                  and data.get("IDAMetadataDescriptorVersion") == 1)
        except Exception:
            traceback.print_exc()
            ok = False
        check(ok, "manifest names plugin.py as the entry point")

    # (1) does IDA's own registry know it?  A plugin that IDA loaded shows up
    #     through find_plugin(); one that was never scanned does not.  A bare
    #     subfolder without ida-plugin.json is never scanned at all.
    found = ida_loader.find_plugin("PseudoClean", False)
    loaded = found is not None
    print("find_plugin('PseudoClean') -> %r" % ("<plugin_t>" if loaded else None,))

    check(found is not None or loaded,
          "IDA's plugin registry contains PseudoClean "
          "(it was discovered at startup)")

    # (2) the entry point must be importable under the name IDA uses.
    sys.path.insert(0, pkg)
    try:
        import plugin as P
        inst = P.PLUGIN_ENTRY()
        check(inst.wanted_name == "PseudoClean",
              "PLUGIN_ENTRY() gives a plugin named 'PseudoClean'")
        check(not (inst.flags & idaapi.PLUGIN_HIDE),
              "flag PLUGIN_HIDE is clear (it must show in Edit -> Plugins)")
        check(not (inst.flags & idaapi.PLUGIN_MULTI),
              "flag PLUGIN_MULTI is clear (legacy plugin_t, not plugmod_t)")
    except Exception:
        traceback.print_exc()
        check(False, "plugin.py imports and PLUGIN_ENTRY() works")

    print("CHECKS: %d   FAILURES: %d" % (len(FAILURES) + 6, len(FAILURES)))
    return 0 if not FAILURES else 1


try:
    _rc = main()
except Exception:
    traceback.print_exc()
    print("FATAL: install probe crashed")
    _rc = 3

idaapi.qexit(_rc)
