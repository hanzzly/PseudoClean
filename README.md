# PseudoClean

Deterministic pseudocode readability assistant for **IDA Pro 9.4** / **Hex-Rays**.

PseudoClean reads the Hex-Rays ctree and microcode and proposes readability
improvements — better variable names, better function names, crypto/obfuscation
labels, control-flow notes — with a confidence score and a written reason for
every single suggestion. Nothing is applied automatically.

**There is no AI, no LLM, no cloud call, no network access and no external
service anywhere in this plugin.** Every suggestion is derived from a fixed,
auditable rule set implemented with the IDAPython APIs.

---

## Install

IDA 9.4 does **not** scan a bare subfolder inside `plugins/` — it only loads
flat `.py` files and subfolders that carry an `ida-plugin.json` manifest. The
package therefore ships that manifest, and the folder must keep its name
(`plugin.py` imports the package as `PseudoClean.<module>`).

1. Copy the `PseudoClean` folder — manifest included — into IDA's plugins
   directory:

   ```
   %APPDATA%\Hex-Rays\IDA Pro\plugins\PseudoClean\
       ida-plugin.json          <- required, or IDA never sees the folder
       plugin.py
       analyzer.py
       ...
   ```

   From the root of this repository (WSL), one command installs it per-user:

   ```bash
   WIN_USER="$(cmd.exe /c 'echo %USERNAME%' 2>/dev/null | tr -d '\r')"
   cp -r ./PseudoClean \
         "/mnt/c/Users/${WIN_USER:-$USER}/AppData/Roaming/Hex-Rays/IDA Pro/plugins/"
   find "/mnt/c/Users/${WIN_USER:-$USER}/AppData/Roaming/Hex-Rays/IDA Pro/plugins/PseudoClean" \
        -name '__pycache__' -type d -exec rm -rf {} +
   ```

   A machine-wide install into `C:\Program Files\IDA Professional 9.4\plugins\`
   works the same way but needs administrator rights (the folder is read-only
   for a normal user). Verify the install with `./testbin/run_tests.sh install`,
   which loads the plugin from a throwaway `IDAUSR` home and asserts that IDA
   discovers it on its own.

2. Start IDA. The plugin registers itself and logs:

   ```
   [PseudoClean] loaded.  Use Edit -> Plugins -> PseudoClean (or Ctrl-Shift-O)
   ```

   If that line is missing, IDA did not discover the folder: check that
   `ida-plugin.json` is present next to `plugin.py` and that the folder is
   named `PseudoClean`.

3. Open a binary, decompile a function (F5), then choose
   **Edit → Plugins → PseudoClean** (or `Ctrl-Shift-O`) to open the dockable
   review panel.

If Hex-Rays is not available or not licensed, the plugin still loads and
reports the limitation instead of failing: all decompiler-dependent actions
become no-ops with an explanatory message.

---

## Usage

The review panel has ten actions:

| Action | What it does |
|---|---|
| **Analyze current function** | Runs the full pipeline on the function under the cursor |
| **Analyze all functions** | Runs the pipeline over every decompilable function |
| **Suggest variable names** | Only the variable-renaming pass |
| **Suggest function names** | Only the function-renaming pass (auto-named functions only) |
| **Simplify expressions** | Reports simplifications Hex-Rays did *not* fold; opt-in persistent annotation |
| **Detect obfuscation** | Crypto/bitwise/MBA/flattening detection |
| **Generate readability report** | Markdown report with crypto table, control-flow notes, microcode profile |
| **Beautify Pseudocode** | Synthesizes clean, de-pyramided, human-readable C code (removes pyramid of doom, extracts formulas) |
| **Generate Z3 Solver** | Automatically extracts loop constraints and generates a ready-to-run Python Z3 solver script |
| **Apply selected changes** | Applies the ticked rows only |
| **Revert plugin changes** | Undoes every change PseudoClean has made, in reverse order (renames *and* annotations) |
| **Cancel** | Stops a running whole-database analysis after the current function |

The review table shows **Original | Suggested | Confidence | Reason** with a
per-row checkbox. Filter by minimum confidence in the Settings dialog
(`Ctrl-Shift-,` in the panel).

Whole-database passes run on a worker thread: decompilation is marshalled to
IDA's main thread with `ida_kernwin.execute_sync(..., MFF_READ)`, UI updates
go through `execute_ui_requests`, and the progress bar plus **Cancel** stay
usable while the pass runs. A `cfunc` is released after each function, so a
large database does not accumulate ctrees. When there is no UI loop to service
those requests (`ida_kernwin.is_idaq()` is false, e.g. `idat -A`), the same
pass runs inline instead — otherwise the worker would block forever.

### What gets renamed

* **Locals**: only Hex-Rays auto-generated names (`v1`, `v2`, `a1`, ...).
* **Functions**: only `sub_*`, `nullsub_*`, `unknown_*`, `j_sub_*` names.
* Library functions (`FUNC_LIB`) are never touched — neither by the bulk
  pass nor by a direct per-function call.
* Your own meaningful names are never offered for replacement.

Renames go through `ida_hexrays.rename_lvar()` and `ida_name.set_name()`, so
the IDB is updated and the change survives a restart. Reverts are guarded: if
the name has changed since PseudoClean wrote it, the revert refuses and reports
it rather than clobbering your edit.

---

## Architecture

```
plugin.py                 plugin_t entry point, actions, menu wiring
ui/main_panel.py          dockable panel (PluginForm), all nine actions
ui/review_table.py        the review grid (Original/Suggested/Confidence/Reason)
ui/settings.py            thresholds dialog

analyzer.py               orchestration: FunctionReport, analyze_function/all, report
ast_analyzer.py           the ctree walker, FuncProfile/VarUse, role inference,
                          MBA recognition, loop_parts(), _resolve_base_var()
confidence.py             Suggestion, combine(), grade(), unique_name()
config.py                 all thresholds/constants, persisted settings

variable_renamer.py       role -> name, apply/revert locals
function_renamer.py       multi-hypothesis naming, apply/revert functions
expression_simplifier.py  ctree analysis + persistent comment annotations
microcode_analyzer.py     microcode probe facts + optional optinsn_t hook
control_flow.py           nesting/goto/switch stats, flattening, opaque predicates
crypto_detector.py        XOR/CRC/AES/Base64/bitmask/rotate/MBA detection
c_beautifier.py           deterministic AST de-pyramiding & C pseudocode beautifier
solver_generator.py       CTF Z3 solver generator for validation loops & crypto
api_recognizer.py         libc/API role recognition, readability facts
change_manager.py         persistent change history in a netnode, revert
logging_util.py           logger writing to IDA's output window
tests/                    offline unit tests + in-IDA integration test
```

### Naming pipeline

1. Profile the function: every local gets role counters (loop counter, index,
   buffer, source, destination, string, result, flag, ...), callee-derived
   evidence (`result` assigned from `strlen` becomes `len`), type hints, and
   reference counts.
2. Resolve the base variable of pointer/array addressing deterministically:
   unwrap casts/refs/derefs/index; for `a + b` prefer the pointer-typed
   operand, otherwise the wider (address-sized) operand.
3. Score candidate names **per hypothesis** — competing hypotheses never mix
   their evidence. The strongest hypothesis wins; ties break on role priority.
4. Emit a `Suggestion` with confidence, reason, and `selected=False`.

### Confidence

`combine([(base, weight), ...])` is a weighted evidence blend, monotonic,
clamped, and never reaches 100. Grades: HIGH ≥ `config.HIGH_CONFIDENCE`,
MEDIUM ≥ `config.MIN_CONFIDENCE_APPLY`, otherwise LOW. Nothing is ever
applied automatically: there is no auto-apply path, and weak or generic names
are never pre-checked — you always review and press Apply.

Names that only describe a variable's width (`value`, `qword_val`, `dword_val`,
`word_val`, `byte_val`) are never emitted. Roles that are honest but vague
(`ptr`, `arr`, `var`, `tmp`) are offered but never pre-selected.

---

## Known limitations (verified on IDA 9.4, Hex-Rays 9.4.0.260714)

1. **Ctree edits are transient.** The ctree is rebuilt on every decompilation,
   so direct `cexpr_t` mutation does not persist. Hex-Rays also forbids ctree
   mutation in the `func_printed` callback.
2. **Expression simplification is annotation-based.** Because of (1),
   "simplify expressions" reports opportunities and can attach *persistent*
   ctree user-comments (prefix `PseudoClean:`) at the item address. Those
   comments live in the IDB and survive cache invalidation; they are removed by
   *Revert plugin changes*.
3. **The microcode `optinsn_t` hook is OFF by default.** Hex-Rays already folds
   `x+0`, `x*1`, `x^x`, `x&~0` before the ctree exists — measured hit count on
   GCC `-O0` and `-O2` corpora is zero. The hook exists for code generators
   that defeat Hex-Rays' own optimizer; enable it in Settings if you have such
   a target. It only rewrites pure instructions and preserves operand width.
4. **Microcode operand order.** `minsn_t.l` is the source (left) operand and
   `minsn_t.d` is the destination; the SDK documents this and a probe over real
   microcode confirms it (IDA prints `mov l, d`). The optional hook rewrites
   `l` and never touches `d`.
5. **Control flow is never rewritten.** Flattening, dead code and opaque
   predicates are *reported* with evidence; reconstructing a state machine
   automatically cannot be proven semantics-preserving.
6. **Determinism holds per decompiler state.** The analysis is a pure function
   of the ctree it is handed (verified: three consecutive analyses of the same
   settled function are byte-identical), but the *first* build of a function
   makes Hex-Rays persist lvar types, so a rebuild can renumber anonymous
   locals. Measured on `testcases_O2`/`main`: `v38`→`buf` at 96 % before the
   rebuild, `v27`→`buf` at 88 % after it. Renames are guarded: a suggestion
   whose lvar no longer exists fails cleanly instead of renaming the wrong
   variable.
7. **Library function bodies.** Suggestions are suppressed inside `FUNC_LIB`
   functions.
8. **IDA applies no library signatures in batch mode.** A statically linked
   glibc build reports `FUNC_LIB = 0` of 1161 functions, so the library
   exclusion cannot be exercised in `idat -A`; the in-IDA test sets and then
   restores the real `FUNC_LIB` flag on one function, and the offline unit test
   covers the logic.
9. **Whole-database passes need a UI loop.** `execute_sync` from a worker thread
   is only serviced by IDA's UI thread; measured `is_idaq() == False` under
   `idat -A`, where such a call never returns. The panel therefore runs the
   pass inline when `is_idaq()` is false, and the threaded path is exercised
   only in the GUI build.
10. **GUI code cannot be exercised headlessly.** The in-IDA suite runs the panel
    smoke test only when a Qt binding is importable; otherwise it reports SKIP
    with the reason instead of claiming a GUI pass. `PySide6` refuses to import
    outside the GUI build outright ("PySide6 can only be used from the GUI
    version of IDA"), which is why the headless suite can never cover the panel
    itself. The Qt-independent parts of the panel — the background worker's
    `execute_sync` contract and the action registration — are covered by
    offline unit tests that execute the real code against IDA's semantics.

---

## Compatibility

| Component | Version |
|---|---|
| IDA Pro | 9.4 (Professional) |
| Hex-Rays | 9.4.0.260714 |
| Kernel | 9.4 |
| Python | 3.14.6 (IDA bundled) |
| Qt | PySide6 (IDA 9.4's binding), PyQt5 accepted as a fallback |

Every API used here was verified empirically against the installed SDK; the
plugin never probes an API at runtime that was not first confirmed on 9.4.

Qt is imported through `ui/qt_binding.py` only. IDA 9.4 ships both bindings
and its `PluginForm.FormToPyQtWidget` actually converts through shiboken6,
so PySide6 is chosen first and the widget conversion is probed rather than
assumed from the historical name.
Where a symbol is known to have changed across versions the code uses the
9.4 name (`SETMENU_APP`, `cwhile`/`cdo` instead of the non-existent `cloop`,
`decomp_ranges_t(ea)` for microcode).

Older IDA versions (8.x/7.x) are **not** supported.

---

## Testing

```bash
./testbin/run_tests.sh          # offline unit tests + full IDA integration
./testbin/run_tests.sh units    # offline only (no IDA required)
./testbin/run_tests.sh ida      # IDA only
./testbin/run_tests.sh install  # plugin discovery / install check
./testbin/run_tests.sh perf     # scale test (1200 generated functions)
```

The integration test runs headless (`idat.exe -A -S ...`) against five
binaries and exits non-zero on any failed check:

| Binary | Symbols | Covers |
|---|---|---|
| `testcases_O0.bin` | yes | arithmetic, nesting, loops, switch, arrays/pointers, strings, XOR, CRC, bitwise |
| `testcases_O2.bin` | yes | same source at `-O2` (inlining/optimisation noise) |
| `testcases_stripped.bin` | no | stripped binary — function naming is exercised here |
| `obfuscated_O0.bin` | yes | flattening, MBA, opaque predicates, XOR literals, dead code, indirect calls |
| `obfuscated_stripped.bin` | no | the same obfuscated code stripped |

Checks performed per binary:

* analysis on every decompilable function without exceptions;
* suggestion well-formedness (identifier shape, range, reason);
* determinism: two consecutive analyses of the *settled* function must be
  byte-identical (the first build of a function makes Hex-Rays persist lvar
  types, so one rebuild is performed first — see limitation 6);
* variable/function rename apply → visible → revert → restored, idempotent
  re-apply;
* persistent comment annotate → survives re-decompile → removed;
* change-history persistence across instances;
* report generation, **and** that the report path (`analyze_all` →
  `generate_readability_report`) really contains the control-flow rows;
* microcode: the printed operand order of real `m_mov` instructions
  (`l` = source, `d` = destination), and that enabling the optional hook
  leaves the pseudocode byte-identical while reporting its rewrite count;
* comment entries are marked reverted by `ChangeManager.revert_all()`, and a
  failed removal stays pending instead of being silently forgiven;
* `FUNC_LIB` exclusion (`is_decompilable`, function naming, `analyze_all`) —
  IDA applies no library signatures in batch mode, so the test sets and then
  restores the real flag on one function;
* the background-analysis pattern: cancelled through the progress callback, and
  the threaded `execute_sync(MFF_READ)` phase only in a GUI session (reported
  as SKIP, with the reason, under `idat -A`);
* the panel smoke test when Qt is available.

A separate two-session test (`restart_phase1.py` → `restart_phase2.py`) runs
two IDA processes on the same `.i64` of the *stripped obfuscated* corpus (the
only one with auto-named functions, so renames are possible) and verifies that
an applied variable rename, an applied function rename, an annotation, and the
settings survive the restart, and that `revert_all()` then undoes all three in
the fresh process.

### Scale

`./testbin/run_tests.sh perf` generates `testbin/perf.c` (1200 functions with
six different body shapes), compiles it, and runs `PseudoClean/tests/perf_probe.py`
against it. The generated binary decompiles to **1206 functions** and the pass
takes **15.4 s (12.8 ms per function)** on this machine — the audit baseline
for the same corpus size was 16.8 s (13.9 ms per function), so there is no
regression. The probe also checks that every decompilable function is reported
without error, that every report released its ctree (0 still held), that every
suggestion carries a name and a reason, and that a progress callback cancels the
pass. The generated binary is removed afterwards and is excluded from the
default corpus glob, so `./testbin/run_tests.sh` stays fast.

---

## Fixed defects

This release closes the defects found by the prior read-only audit. Listed with
the evidence used to verify the fix:

| # | Defect | Fix | Verified by |
|---|---|---|---|
| 1 | Settings were written with the value name and the value swapped | `reg_write_string("settings", json, REGISTRY_SUBKEY)` | unit round-trip + in-IDA registry round-trip |
| 2 | `skip_library` ignored `FUNC_LIB` | `is_decompilable(..., skip_library=True)` checks `FUNC_LIB`; renamer refuses library bodies | unit + in-IDA (when the binary has `FUNC_LIB`) |
| 3 | Microcode `_to_mov`/`_to_zero` overwrote the destination | `d` (destination) preserved, `l` (source) written | unit test + real-microcode print order probe |
| 4 | Roles `counter`/`encoded_data`/`result`/`flag` fell back to `value`/`qword_val` | `ROLE_NAMES` entries; width placeholders never emitted; weak names never pre-selected | unit tests |
| 5 | `is_char_like` missed cv-qualified `char` | IDA predicates first, token-based name fallback (`const char` ≠ `unsigned char` corruption) | unit tests |
| 6 | Report omitted control flow | `DEFAULT_WANT = {vars, func, crypto, cf}` shared by report and analysis | unit + in-IDA report path |
| 7 | Comments were never reverted | targeted `remove_pseudoclean_comment()` + reverted bookkeeping | unit + two-session restart test |
| 8 | Dead settings/actions (`AUTO_APPLY_HIGH`, `_ACTIONS`, …) | removed; Settings dialog exposes only real knobs | static + in-IDA panel smoke |
| 9 | Function naming used junk callees (`jumpout`, `rol4__`, `hibyte`) | pseudo-callee/auto-name filtering; wrappers require a real import | unit tests |
| 10 | Whole-database analysis blocked the UI | worker thread + `execute_sync(MFF_READ)`, progress bar, Cancel | in-IDA background test |
| 11 | `pow2_mul` advice was unsound | removed | unit test asserts it is gone |
| 12 | Mixed PyQt5/PySide6 imports | one resolver, `ui/qt_binding.py`; conversion probed | in-IDA panel smoke (binding name logged) |
| 13 | XOR/rotation heuristics over-fired | XOR needs buffer/loop evidence; rotation needs paired shl/shr-OR | unit tests |
| 14 | Offline stub hid API drift | strict stub: unknown IDA attributes raise | unit test |
| 15 | `remove_pseudoclean_comments()` removed **nothing**: function-entry annotations are not reachable by a ctree walk (verified: no visited item carries the function entry address, so the walk only ever saw `0x10E5`, never `0x10E0`) | removal runs two passes: an explicit probe of `treeloc_t(ea, ITP_*)` at the function entry, then the body walk | in-IDA: annotate → `PseudoClean:` present → `removed 1` → absent |
| 16 | IDA could **hard-crash** while inspecting microcode: `testcases_stripped` died (exit 5, no summary) in the operand-order probe because live `minsn_t` proxies were returned after their `mba_t` was released | operand text is materialized inside the function, before the `mba_t` goes out of scope | full IDA run completes on all five binaries |
| 17 | The whole-database pass would hang forever in a session without a UI loop (`execute_sync` never returns; measured `is_idaq() == False` under `idat -A`) | `_start_background` runs the same pass inline when `is_idaq()` is false | in-IDA suite: the threaded phase self-skips with that exact reason instead of timing out |
| 18 | The integration suite reported green while never exercising annotation: `analyze_expressions` returns nothing on ordinary compiler output, and phase E/L treated that as "skip" | the suite falls back to the control-flow observations the panel also annotates | phase E/L now report `annotated 1 item(s)`, `removed 1`, and a clean revert |
| 19 | The two-session restart test targeted a corpus with no auto-named functions, so its rename checks could never run | it runs on the stripped obfuscated corpus | 3/3 entries applied → persisted → reverted across two IDA processes |
| 20 | **The documented install did not work**: IDA 9.4 never scans a bare subfolder of `plugins/`, so copying `PseudoClean/` there loaded nothing (no menu entry, no log line) — the README told users to do exactly that | ship an `ida-plugin.json` manifest (`entryPoint: plugin.py`) and document its requirement | `run_tests.sh install` loads the plugin from a throwaway `IDAUSR` and asserts discovery + `[PseudoClean] loaded.` |
| 21 | `flags = PLUGIN_MULTI \| PLUGIN_HIDE` on a legacy `plugin_t`: `PLUGIN_MULTI` requires a `plugmod_t` entry point and `PLUGIN_HIDE` removes the plugin from **Edit → Plugins**, so the documented menu path was dead | `flags = 0` | install probe asserts both flags are clear |
| 22 | `from ui.main_panel import ...` only resolved when the package directory was on `sys.path`; IDA loads `plugin.py` directly, so the first panel open could fail | relative import with a flat-import fallback | install probe imports the module IDA loads and constructs the panel object |
| 23 | **GUI crash on "Analyze all"** (reported from a live session): the background worker trusted `execute_sync`'s return value, but IDA returns a status `int`, so the UI collected ints and died with `'int' object has no attribute 'showing'` — invisible headless, where the inline path never calls `execute_sync` | the worker collects the report through a holder inside the callable | unit test executes the real `_worker` against IDA's int-returning contract and reproduces/refutes the exact failure |
| 24 | **Conflicting shortcut: Ctrl+Shift+P** (reported from the first session): the plugin's menu item *and* the custom action both bound the hotkey | the action carries no shortcut; `wanted_hotkey` keeps the menu binding | unit test registers the action and asserts `desc.shortcut` is empty |
| 25 | **XOR cipher reported as "no crypto patterns"** on a real CrackMe (`chall`): the profiler only counted `cot_asgxor`, so a comparison-style decoder — `if ((input[i] ^ key) != stored[i])`, the classic password-check shape — produced `xor_self = 0` and the detector returned immediately | the profiler records non-assigning XOR operands (`xor_uses`) as separate evidence; the detector classifies `xor-compare` apart from in-place `xor-loop` | unit tests: compare-style detected (81 %), assign-style unchanged, scalar XOR stays `incidental`; measured on `chall`: 0 → 1 finding |
| 26 | **The control-flow annotation rendered as an `Orphan comments` block after the function** instead of inside it, because it was anchored on the function-entry address (measured: same comment on the first body statement renders inline as `// PseudoClean: …`) | annotations aimed at the entry address are moved to the first body statement; the remover checks both slots | in-IDA phase E now asserts `"Orphan comments" not in text`; unit test asserts the anchor address |
| 27 | **Derived auto names were never renamed**: Hex-Rays names a variable from the `scanf` format specifier (`scanf("%49s", s)` → `s`), and `_is_generic` only matched `v\d+`/`a\d+`, so the user-input side of the password check stayed `s` while the stored side became `buf` — both sides of the comparison looked identical | single-letter names count as auto when the variable is a scanf/read destination or the comparison-style XOR operand; the apply path re-checks with recorded evidence | measured on `chall`: 2 → 3 renames (`s→input` at 99 %); unit tests for all three input shapes |
| 28 | **"nested if depth 4" fired on a two-branch switch**: Hex-Rays renders `switch (i & 1)` as an if/else ladder, so the depth counter saw 4 on a body holding two real comparisons | the deep-nesting advisory now also requires ≥ 6 ifs | `chall` no longer emits the noise row; corpus suites unchanged |
| 29 | **Hotkey still conflicted after the fix**: `Ctrl-Shift-P` is IDA's own Command Palette shortcut (`cfg/idagui.cfg:894`), so the plugin menu item always produced `Conflicting shortcut: Ctrl+Shift+P` with `{Edit/Plugins/PseudoClean, CommandPalette}` as candidates | hotkey moved to `Ctrl-Shift-O`, which no IDA config file binds (checked across `cfg/*.cfg`) | unit test pins `PLUGIN_HOTKEY != "Ctrl-Shift-P"`; startup log has no conflict line |
| 30 | **The only comment written was the raw counter line**, and it landed on the stack-canary statement — useless text in a misleading place | crypto findings now carry an explanatory note (keys used, what is compared) and anchor on the last expression statement before the loop; pure statistics are report-only | measured on `chall`: the note sits above the `for` loop, inline; 15/15 `cit_expr` anchors rendered inline vs 0/6 on `if`/`block`/`for` |

## Before / after

`xor_decode_buffer` in `testcases_O0.bin`, Hex-Rays output before PseudoClean:

```c
__int64 __fastcall xor_decode_buffer(char *a1, unsigned int a2, char *a3)
{
  int v7; // [rsp+0h] [rbp-18h]

  v7 = strlen(a3);
  for ( int i = 0; i < a2; ++i )
    a1[i] ^= a3[i % v7];
  a1[a2] = 0;
  return a2;
}
```

After applying the accepted PseudoClean suggestions:

```c
__int64 __fastcall xor_decode_buffer(char *encoded_data, unsigned int a2, char *src)
{
  int len; // [rsp+0h] [rbp-18h]

  len = strlen(src);
  for ( int i = 0; i < a2; ++i )
    encoded_data[i] ^= src[i % len];
  encoded_data[a2] = 0;
  return a2;
}
```

with the detection row:

```
crypto | xor decode | 73% | 1 xor-assign op(s), 1 loop(s)
```

`obf_flatten` in `obfuscated_O0.bin` yields:

```
info | state variable `v3` (5 states)
     | control-flow flattening: dispatcher loop cycling `v3` through
       {0, 1, 2, 3, 4} — reconstruct as a switch/branch ladder | 88%
```

`obf_mba_add` yields:

```
crypto | mba | 88% | mixed boolean-arithmetic:
        `(a ^ b) + 2 * (a & b)` is `a + b`
```

---

## Dependencies

Only what ships with IDA Pro 9.4: `idapython`, `ida_hexrays`, `ida_kernwin`,
`ida_funcs`, `ida_name`, `ida_nalt`, `idaapi`, `idautils`, and IDA's own Qt
(PySide6, with PyQt5 as a fallback) for the panel. No pip packages, no
compiled extensions, no network libraries.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding principles (100% deterministic, 0% AI/network, no external dependencies), and test requirements.

## License / support

Released under the **MIT License**. No telemetry, no phoning home — the plugin performs zero
network I/O.
