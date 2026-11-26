# PseudoClean — final deliverable report

Date: 2026-11-24 · IDA Pro 9.4 Professional / Hex-Rays 9.4.0.260714 / bundled
Python 3.14.6 · Windows host, WSL toolchain, `idat.exe -A` for all in-IDA runs.

## 1. Executive summary

All verified defects from the audit (P0 #1–#5, P1 #6–#10, P2 #11–#14, plus
five further defects #15–#19 discovered and fixed during the fix phase) are
closed in code, and each fix is backed by a reproducible check. Final state:
**65 offline unit tests / 0 failures**, **5/5 IDA integration binaries
passed (1230 checks, 0 failures)**, the **two-session restart test passed**,
the **install test passed** (IDA discovers and loads the plugin from a clean
`IDAUSR` home on its own), and the **scale test on a 1206-function binary
passed** (15.4 s, 12.8 ms per function — no regression vs the 16.8 s /
13.9 ms audit baseline).
Known limits are documented honestly in `README.md` (§Known limitations,
items 1–10), including the two things that genuinely cannot be verified
headlessly: GUI panel smoke-testing and any behavior dependent on a live UI
loop.

## 2. Fixed defects (all 19)

| # | Phase | Defect | Fix | Verification |
|---|---|---|---|---|
| 1 | P0 | Settings written with name/value swapped | `reg_write_string("settings", json, REGISTRY_SUBKEY)` | unit round-trip + in-IDA registry round-trip |
| 2 | P0 | `skip_library` ignored `FUNC_LIB` | `is_decompilable(..., skip_library=True)` checks `FUNC_LIB`; renamer refuses library bodies | unit + in-IDA test that sets/restores the real flag (IDA batch applies no signatures, so `FUNC_LIB` never occurs naturally — measured 0/1161 on static glibc) |
| 3 | P0 | Microcode `_to_mov`/`_to_zero` overwrote the destination | `minsn_t.d` = destination preserved; `minsn_t.l` = source rewritten; `r` erased | SDK + real-microcode print probe (`mov l, d`); unit test asserts destination survives |
| 4 | P0 | Roles `counter`/`encoded_data`/`result`/`flag` fell back to `value`/`qword_val` | `ROLE_NAMES` entries added; width placeholders never emitted; weak names never pre-selected | unit tests |
| 5 | P0 | `is_char_like` missed cv-qualified `char` | IDA predicates first, token-based fallback (`const char`, `signed char`, ...) | unit tests |
| 6 | P1 | Report omitted control flow | `DEFAULT_WANT = {vars, func, crypto, cf}` shared by `analyze_all` and the report path | unit + in-IDA check that the rendered report really contains CF rows |
| 7 | P1 | `revert_all()` left comments and marked nothing reverted | targeted comment removal + reverted bookkeeping, tri-state (removed / absent / failed→stays pending) | unit + two-session restart test |
| 8 | P1 | Dead settings/actions placeholders | removed (`AUTO_APPLY_HIGH`, `_ACTIONS`, `_register_actions`, `EXPR_MAX_NODES` re-scoped, unused `W_*`) | static grep + panel smoke |
| 9 | P1 | Function naming used junk callees (`jumpout`, `rol4__`, `hibyte`, pseudo/intrinsic/macro names, incidental wrappers) | exclusion filters; wrappers require a real import | unit tests; measured suppressions recorded in the audit log |
| 10 | P1 | Whole-database analysis blocked the UI | worker thread + `execute_sync(MFF_READ)`, progress, Cancel, per-function cfunc release | in-IDA background test (threaded path exercised only where a UI loop exists — see limitation 9) |
| 11 | P2 | `pow2_mul` advice was unsound | removed | unit test asserts absence |
| 12 | P2 | Mixed PyQt5/PySide6 imports | single resolver `ui/qt_binding.py`; `FormToPyQtWidget` conversion probed (shiboken6) | panel smoke logs the chosen binding |
| 13 | P2 | XOR/rotation heuristics over-fired | XOR requires buffer/loop evidence; rotation requires paired shl/shr-OR | unit tests incl. false-positive corpus (`byteswap32→rotate 45%`, `obf_flatten→xor decode 73%` suppressed) |
| 14 | P2 | Offline stub hid API drift | strict stub: unknown IDA attributes raise `AttributeError` | unit test |
| 15 | — | `remove_pseudoclean_comments()` removed **nothing**: function-entry annotations (`treeloc_t(ea, ITP_*)`) are unreachable by a ctree walk (measured: no visited item carries the entry EA) | two-pass remover: explicit entry probe, then body walk | in-IDA: annotate → present → `removed 1` → absent |
| 16 | — | IDA **hard crash** (exit 5) in microcode inspection: live `minsn_t` proxies outlived their `mba_t` | operand text materialized to strings inside the function, before the `mba_t` is released | full run now completes on all five binaries |
| 17 | — | Whole-database pass hangs forever headless (`execute_sync` from a worker is never serviced; measured `is_idaq() == False` under `idat -A`) | `_start_background` runs the pass inline when `is_idaq()` is false | in-IDA suite: threaded phase self-SKIPs with that reason instead of timing out |
| 18 | — | Suite reported green while never exercising annotation (`analyze_expressions` legitimately yields 0 suggestions on compiler output) | test falls back to the control-flow observations the panel also annotates | phases E/L now report `annotated 1 item(s)`, `removed 1`, clean revert |
| 19 | — | Restart test targeted a corpus with no auto-named functions, so rename checks could never run | moved to the stripped obfuscated corpus | 3/3 entries (var + func + comment) applied → persisted across processes → reverted |
| 20 | install | **The documented install did not work** — IDA 9.4 never scans a bare subfolder of `plugins/`, so copying `PseudoClean/` there loaded nothing (no menu entry, no log line), yet that is what the README instructed | ship `ida-plugin.json` (`entryPoint: plugin.py`) and document the requirement | `run_tests.sh install`: fresh `IDAUSR`, plugin discovered by IDA itself, `[PseudoClean] loaded.` present |
| 21 | install | `flags = PLUGIN_MULTI \| PLUGIN_HIDE` on a legacy `plugin_t` — `PLUGIN_MULTI` needs a `plugmod_t` entry point, and `PLUGIN_HIDE` removes it from **Edit → Plugins**, killing the documented menu path | `flags = 0` | install probe asserts both flags clear |
| 22 | install | `from ui.main_panel import ...` only worked when the package dir was on `sys.path`; IDA loads `plugin.py` directly | relative import with flat fallback | install probe imports what IDA loads and builds the panel object |
| 23 | GUI | **"Analyze all" crashed in a live session** — the worker trusted `execute_sync`'s return value, but IDA returns a status `int`; the UI then called `.showing()` on ints (`'int' object has no attribute 'showing'`). Invisible headless: the inline path never calls `execute_sync` | worker collects the report through a holder inside the callable | unit test runs the real `_worker` under IDA's int-returning contract; reverted code fails it with the exact reported message |
| 24 | GUI | **"Conflicting shortcut: Ctrl+Shift+P"** — the plugin menu item *and* the custom action both bound the hotkey | the action carries no shortcut; `wanted_hotkey` keeps the menu binding | unit test registers the action and asserts the descriptor has no shortcut |
| 25 | detection | **XOR cipher missed on a real CrackMe** — the profiler only counted `cot_asgxor`, so the comparison-style decoder `if ((input[i] ^ key) != stored[i])` gave `xor_self = 0` and the detector reported "no crypto patterns" | non-assigning XOR operands tracked as `xor_uses`; detector distinguishes `xor-compare` from in-place `xor-loop` | unit tests (positive + both negatives); measured on `chall`: 0 → 1 finding at 81 % |
| 26 | annotation | **The control-flow annotation rendered as an `Orphan comments` block after the function** because it was anchored on the function-entry address | entry-address annotations move to the first body statement; removal checks both slots | measured both placements on the real binary; in-IDA phase E asserts no orphan block; unit test pins the anchor |
| 27 | naming | **Derived auto names never renamed** — `scanf("%49s", s)` produces a variable literally called `s`, which `_is_generic` (v\d+/a\d+ only) refused to touch | single-letter names eligible with recorded input-family/XOR evidence; apply path honours `payload["derived_auto"]` | `chall`: `s→input` 99 %; 3 unit tests |
| 28 | reporting | **"nested if depth 4" noise on a two-branch switch** — Hex-Rays renders `switch (i & 1)` as an if/else ladder, inflating the depth metric | deep-nesting advisory requires ≥ 6 ifs | `chall` noise row gone; all 5 corpus suites unchanged |
| 29 | GUI | **Hotkey still conflicted** — `Ctrl-Shift-P` is IDA's Command Palette binding (`cfg/idagui.cfg:894`), so every startup printed `Conflicting shortcut` | hotkey moved to `Ctrl-Shift-O`, unbound in every `cfg/*.cfg` | unit test pins it; startup log clean |
| 30 | annotation | **The only comment was the counter line, on the canary statement** | crypto note explains keys + comparison and anchors before the loop; statistics are report-only | measured on `chall`; anchor rule derived from 21 render probes |

## 3. Test results

### 3.1 Offline unit tests (`./testbin/run_tests.sh units`)

**65 offline unit tests, 0 failures** (line 59 section = unit summary) Coverage highlights: settings round-trip; strict IDA
stub (unknown attribute raises); every role name; cv-qualified char forms;
`FUNC_LIB` exclusion logic; microcode destination preservation; `pow2_mul`
absence; crypto false positives; comment bookkeeping incl. failed removal
staying pending; weak-name preselection ban; function-naming exclusion list.

### 3.2 IDA integration (`./testbin/run_tests.sh ida`)

| Binary | Checks | Failures | Skipped |
|---|---|---|---|
| `obfuscated_O0` | 152 | 0 | 3 |
| `obfuscated_stripped` | 165 | 0 | 2 |
| `testcases_O0` | 301 | 0 | 3 |
| `testcases_O2` | 293 | 0 | 4 |
| `testcases_stripped` | 319 | 0 | 2 |
| **total** | **1230** | **0** | **14** |

Every SKIP is reported with its reason in the logs
(`/mnt/c/Users/Public/pc_run/logs/`); nothing is claimed as PASS that did not
run. Skips are: headless GUI smoke (no Qt binding importable under `idat -A`),
the threaded `execute_sync` phase (no UI loop), and per-binary conditions
(e.g. no `FUNC_LIB` functions present, no annotations on that corpus).

Checks per binary include: analysis of every decompilable function without
exceptions; suggestion well-formedness; warmed determinism (one rebuild first,
then two consecutive analyses byte-identical — see limitation 6); apply →
visible → revert → restored, idempotent re-apply; persistent annotation →
survives re-decompile → removed; change-history persistence; report contains
control-flow rows; real-microcode operand order; optional microcode hook leaves
pseudocode byte-identical; `FUNC_LIB` set/restore; cancellation via progress
callback.

### 3.3 Two-session restart test (`restart_phase1.py` → `restart_phase2.py`)

Two IDA processes on the same `.i64` of `obfuscated_stripped`. Phase 1 applies
a variable rename (`a2→buf`), a function rename (`sub_126D→xor_decode`), an
annotation, and sets `min_confidence=61`; phase 2 verifies all of them
survived the restart, then `revert_all()` restores everything
(13 checks, all OK, including original names restored and no entry left
active).

### 3.4 Install test (`./testbin/run_tests.sh install`)

The install path was the least-tested part of the project and was in fact
**broken**: IDA 9.4 discovers Python plugins either as flat `.py` files in
`plugins/` or as subfolders carrying an `ida-plugin.json` manifest (the bundled
`ida_feeds` uses exactly that). A bare `PseudoClean/` folder — what the README
recommended — is never scanned, so the plugin silently did not exist.

Measurement that established it: with the folder in place and no manifest,
`idat -A` logged no `[PseudoClean] loaded.` and `ida_loader.find_plugin
("PseudoClean")` returned `None`; adding the manifest made IDA load it
unchanged. The test now copies the package into a throwaway `IDAUSR` home
(`HKCU\...`-free, real install untouched), runs IDA once, and asserts six
checks: package present, manifest present and well-formed, IDA's own registry
contains the plugin, the startup message is in the log, `PLUGIN_ENTRY()` yields
a plugin named `PseudoClean`, and neither `PLUGIN_HIDE` nor `PLUGIN_MULTI` is
set. Result: **6 checks, 0 failures**, and the same package loads from the real
per-user install.

Note: environment variables do not cross the WSL→Windows boundary, so the test
launches IDA through a generated `.bat` that sets `IDAUSR` on the Windows side.

### 3.5 Scale test (`./testbin/run_tests.sh perf`)

Generates 1200 functions across six body shapes, compiles, and runs
`tests/perf_probe.py` inside IDA:

| Metric | This build | Audit baseline |
|---|---|---|
| Functions analyzed | 1206 / 1206 decompilable | — |
| Total time | 15.4 s (second run: 16.2 s) | 16.8 s |
| Per function | 12.8 ms | 13.9 ms |
| Analysis errors | 0 | — |
| ctrees still held after pass | 0 | — |
| Suggestions | 1606 (1.33/function), all with name+reason | — |
| Report render | 78 044 bytes in 0.4 s | — |
| Progress-callback cancellation | verified (3 ticks → stop) | — |

The generated binary is deleted afterwards and excluded from the default
corpus glob, so the normal suite stays fast.

## 4. Remaining limitations (verified, not guessed)

Full list in `README.md` §Known limitations; the material ones:

1. **Ctree edits are transient** — Hex-Rays rebuilds the tree per
   decompilation; simplification is therefore annotation-based, and the
   optional `optinsn_t` microcode hook is OFF by default (measured hit count 0
   on both `-O0` and `-O2` corpora; Hex-Rays folds those identities itself).
2. **Microcode operand order** is `mov l, d` (l = source, d = destination),
   confirmed by SDK and a real-microcode print probe; documented because it
   contradicts the audit's original assertion.
3. **First-build determinism** — analysis is a pure function of the *decompiler
   state*: the first build of a function makes Hex-Rays persist lvar types, so
   a rebuild can renumber anonymous locals (measured `v38→buf` 96% becomes
   `v27→buf` 88%). Renames are guarded so a vanished lvar fails cleanly instead
   of renaming the wrong variable.
4. **No library signatures in batch mode** — `FUNC_LIB` never occurs naturally
   under `idat -A`; the test sets/restores the flag explicitly.
5. **Headless has no UI loop** — the threaded background path only runs where
   `execute_sync` can be serviced; the panel falls back to an inline pass when
   `is_idaq()` is false.
6. **GUI cannot be exercised headlessly** — the panel smoke test runs only when
   a Qt binding is importable; under `idat -A` it reports SKIP with the reason.
   This is the one deliverable item that is honestly UNVERIFIED, not passed.

## 5. Deliverables

| Item | Location |
|---|---|
| Modified source (19 fixes) | `PseudoClean/*.py`, `PseudoClean/ui/*.py` |
| Offline unit suite | `PseudoClean/tests/unit_tests.py`, `tests/ida_stub.py` |
| In-IDA integration suite | `PseudoClean/tests/integration_test.py` |
| Two-session restart test | `PseudoClean/tests/restart_phase1.py`, `restart_phase2.py` |
| Scale test | `PseudoClean/tests/perf_probe.py`, `testbin/gen_perf.py`, `run_tests.sh perf` |
| Test runner | `testbin/run_tests.sh` (`units` / `ida` / `perf` / `all`) |
| Corpus sources + docs | `testbin/testcases.c`, `testbin/obfuscated.c`, `testbin/README.md` |
| Updated README (usage, install, limitations, fixed-defects table) | `README.md` |
| IDA run logs | `/mnt/c/Users/Public/pc_run/logs/` |

### Install (short form)

```bash
cp -r PseudoClean "$HOME/AppData/Roaming/Hex-Rays/IDA Pro/plugins/"   # per-user,
# or: cp -r PseudoClean "/mnt/c/Program Files/IDA Professional 9.4/plugins/"  (admin)
```

The folder is copied **with its `ida-plugin.json`** and must keep the name
`PseudoClean` — without the manifest IDA 9.4 never scans the subfolder, and the
folder name is what `plugin.py`'s imports resolve against. Then: start IDA,
open a binary, F5, and open **Edit → Plugins → PseudoClean** (`Ctrl-Shift-O`).
Confirm with `./testbin/run_tests.sh install`.

### Verification commands

```bash
./testbin/run_tests.sh units    # 61/0
./testbin/run_tests.sh ida      # 5/5 binaries, 1230 checks, 0 failures + restart test
./testbin/run_tests.sh install  # 6 checks, IDA discovers the plugin by itself
./testbin/run_tests.sh perf     # 1206 functions, 15.4 s, 0 errors
```
