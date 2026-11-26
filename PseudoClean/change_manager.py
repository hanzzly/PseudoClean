"""Change history and revert support.

Every mutation PseudoClean performs is recorded here *before* it is applied,
and persisted into an IDA netnode so the history survives database reloads.

Record schema (JSON):
    {
      "id": int,
      "kind": "var" | "func" | "comment",
      "func_ea": int,
      "original": str,     # original name or original comment
      "suggested": str,
      "confidence": int,
      "reason": str,
      "timestamp": float,
      "module": str,
      "reverted": bool
    }
"""

from __future__ import annotations

import json
import time

import ida_netnode

import config
import logging_util as L


_TAG_SETTINGS = ord("S")
_TAG_HISTORY = ord("H")


class ChangeManager:
    def __init__(self):
        self._history = []
        self._next_id = 1
        self._load()

    # -- persistence ------------------------------------------------
    def _node(self):
        return ida_netnode.netnode(config.HISTORY_NODE, 0, True)

    def _load(self):
        try:
            node = self._node()
            raw = node.getblob(0, _TAG_HISTORY)
            if raw:
                if isinstance(raw, str):
                    data = json.loads(raw)
                else:
                    data = json.loads(raw.decode("utf-8"))
                self._history = data.get("entries", [])
                self._next_id = data.get("next_id", len(self._history) + 1)
        except Exception as exc:
            L.debug("history load failed: %s" % exc)
            self._history = []

    def _save(self):
        try:
            node = self._node()
            payload = json.dumps({
                "entries": self._history[-config.HISTORY_LIMIT:],
                "next_id": self._next_id,
            }).encode("utf-8")
            node.setblob(payload, 0, _TAG_HISTORY)
        except Exception as exc:
            L.warn("history save failed: %s" % exc)

    # -- API --------------------------------------------------------
    def record(self, kind, func_ea, original, suggested, confidence, reason,
               module="", ea=None):
        entry = {
            "id": self._next_id,
            "kind": kind,
            "func_ea": func_ea,
            "ea": ea,
            "original": original,
            "suggested": suggested,
            "confidence": int(confidence),
            "reason": reason,
            "timestamp": time.time(),
            "module": module,
            "reverted": False,
        }
        self._next_id += 1
        self._history.append(entry)
        self._save()
        return entry

    def record_suggestion(self, suggestion, module=""):
        """Record a Suggestion object before applying it."""
        kind_map = {
            "var": "var",
            "func": "func",
            "expr": "comment",
            "info": "comment",
        }
        return self.record(kind_map.get(suggestion.kind, suggestion.kind),
                           suggestion.func_ea, suggestion.original,
                           suggestion.suggested, suggestion.confidence,
                           suggestion.reason, module,
                           ea=getattr(suggestion, "ea", None))

    def mark_reverted(self, entry_id):
        for e in self._history:
            if e["id"] == entry_id:
                e["reverted"] = True
                self._save()
                return True
        return False

    def mark_applied_reverted(self, func_ea, original, suggested):
        for e in reversed(self._history):
            if (e["func_ea"] == func_ea and e["original"] == original and
                    e["suggested"] == suggested and not e["reverted"]):
                e["reverted"] = True
                self._save()
                return e
        return None

    @property
    def entries(self):
        return list(self._history)

    def active_entries(self):
        return [e for e in self._history if not e["reverted"]]

    def clear(self):
        self._history = []
        self._next_id = 1
        self._save()

    def stats(self):
        total = len(self._history)
        reverted = sum(1 for e in self._history if e["reverted"])
        return {"total": total, "reverted": reverted,
                "active": total - reverted}

    # -- revert -----------------------------------------------------
    def revert_all(self):
        """Revert every active change, newest first.

        Comments are removed through the same code path that created them, and
        each successful removal is marked reverted in the history so a second
        revert (or a restart) never double-counts or leaves stale entries.
        Returns (reverted_count, failed_list).
        """
        import ida_hexrays
        import ida_name
        import ida_funcs

        reverted = 0
        failed = []
        entries = self.active_entries()
        for e in reversed(entries):
            try:
                kind = e["kind"]
                if kind == "var":
                    ok = ida_hexrays.rename_lvar(e["func_ea"], e["suggested"],
                                                 e["original"])
                    if ok:
                        reverted += 1
                        self.mark_reverted(e["id"])
                    else:
                        failed.append((e, "rename_lvar failed"))
                elif kind == "func":
                    cur = ida_funcs.get_func_name(e["func_ea"]) or ""
                    if cur != e["suggested"]:
                        failed.append((e, "current name differs: %r" % cur))
                        continue
                    ok = ida_name.set_name(e["func_ea"], e["original"],
                                           ida_name.SN_NOWARN |
                                           ida_name.SN_FORCE)
                    if ok:
                        reverted += 1
                        self.mark_reverted(e["id"])
                    else:
                        failed.append((e, "set_name failed"))
                elif kind == "comment":
                    import expression_simplifier as ES
                    res = ES.remove_pseudoclean_comment(
                        e["func_ea"], e.get("ea"), e.get("suggested") or "")
                    if res is True:
                        reverted += 1
                        self.mark_reverted(e["id"])
                    elif res is False:
                        # Already gone (for example removed manually): clear the
                        # entry so stats() stops reporting a pending revert.
                        self.mark_reverted(e["id"])
                    else:
                        failed.append((e, "comment removal error"))
            except Exception as exc:
                failed.append((e, str(exc)))

        self._save()
        return reverted, failed

    def revert_entry(self, entry):
        import ida_hexrays
        import ida_name
        kind = entry["kind"]
        try:
            if kind == "var":
                ok = ida_hexrays.rename_lvar(entry["func_ea"],
                                             entry["suggested"],
                                             entry["original"])
            elif kind == "func":
                ok = ida_name.set_name(entry["func_ea"], entry["original"],
                                       ida_name.SN_NOWARN | ida_name.SN_FORCE)
            elif kind == "comment":
                import expression_simplifier as ES
                res = ES.remove_pseudoclean_comment(
                    entry["func_ea"], entry.get("ea"),
                    entry.get("suggested") or "")
                ok = res is not False       # True or None-on-error
                if res is False:
                    self.mark_reverted(entry["id"])   # already gone
            else:
                ok = False
        except Exception:
            ok = False
        if ok:
            self.mark_reverted(entry["id"])
        return ok
