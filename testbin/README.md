# Test corpus

Reproducible sources and prebuilt binaries used by `run_tests.sh` and the
in-IDA integration test.

## Sources

| File | Purpose |
|---|---|
| `testcases.c` | Every feature category: arithmetic, nested if/else, loops (for/while/do-while), arrays and pointer walking, strings, XOR crypto, CRC32, bitwise ops (rotl/byteswap/popcount), switch, calls, structs, bitfields |
| `obfuscated.c` | Hand-written obfuscation: control-flow flattening, MBA rewrites (`(a^b) + 2*(a&b)`, `(~a)+b+1`), parity-style opaque predicate, XOR-encrypted string literal, dead code, indirect call, nested loops |

## Binaries

Built binaries are committed so the suite runs without a compiler. Rebuild
them at any time (the runner does this automatically when `gcc` is available):

```bash
gcc -O0 -fno-inline -o testcases_O0.bin       testcases.c
gcc -O2 -fno-inline -o testcases_O2.bin       testcases.c
strip -o testcases_stripped.bin               testcases_O0.bin
gcc -O0 -fno-inline -o obfuscated_O0.bin      obfuscated.c
strip -o obfuscated_stripped.bin              obfuscated_O0.bin
```

| Binary | Symbols | What it stresses |
|---|---|---|
| `testcases_O0.bin` | 28 | unoptimised pseudocode: many locals, explicit loops, clean array code |
| `testcases_O2.bin` | 28 | optimised: folded constants, merged loops, hint-free variables |
| `testcases_stripped.bin` | 0 | random names: exercises function naming and the auto-name guard |
| `obfuscated_O0.bin` | 13 | flattening, MBA, opaque predicates, encrypted literals |
| `obfuscated_stripped.bin` | 0 | the same obfuscation with no symbols |

## In-tree targets and their expected detections

`testcases.c`:

| Function | Expected |
|---|---|
| `xor_decode_buffer` | `xor decode` crypto row; `a1` renamed to a buffer-ish name, `v7` from `strlen` to a length name |
| `xor_encrypt_inplace` | `xor decode` (xor-assign in a loop) |
| `crc32_compute` | `CRC32` 88% plus `crc32` constant hint 60% |
| `copy_block` | `a1 -> dst`, `a2 -> src` (memcpy roles) |
| `build_greeting` | `a1 -> buf`, `v4 -> len` |
| `byteswap32` | `rotate` candidate at low confidence |
| `dispatcher` | large-switch note, deep-nesting note |
| `sum_until` | result variable naming (`v3 -> value`) |

`obfuscated.c`:

| Function | Expected |
|---|---|
| `obf_flatten` | state-variable / control-flow-flattening report at 88% |
| `obf_mba_add` | MBA `(a ^ b) + 2 * (a & b)` → `a + b` at 88% |
| `obf_mba_sub` | MBA `(~a) + b + 1` → `b - a` at 88% |
| `obf_mba_xor` | nothing (the expression is already minimal after GCC) |
| `obf_opaque` | opaque-predicate candidate at 55%, `xor decode` for the literal decryption |

`obf_mba_xor` deliberately produces no finding: GCC emits `a ^ b` directly, so
there is no rewrite to report. That is the correct answer, and the suite
asserts only that analysis completes without error.

## Scale corpus

`gen_perf.py` generates `perf.c` with 1200 functions across six body shapes
(branching arithmetic, array-walk loops, XOR decode loops, nested conditions,
state-machine switches, bit twiddling). It is compiled on demand by
`./run_tests.sh perf` and removed afterwards; the generated binary is excluded
from the default corpus glob so the normal suite stays fast.

```bash
python3 gen_perf.py 1200 perf.c
gcc -O0 -fno-inline -o testcases_perf.bin perf.c
```

IDA reports 1206 functions for it (1200 generated plus the CRT glue) and the
whole-database pass takes 15.4 s (12.8 ms per function) on the audit machine.

## Running

```bash
./run_tests.sh          # everything
./run_tests.sh units    # no IDA needed
./run_tests.sh ida      # IDA integration across all five binaries
./run_tests.sh install  # plugin discovery from a throwaway IDAUSR home
./run_tests.sh perf     # scale test over 1200 generated functions
```

The `install` mode answers the question "will IDA actually load this plugin
after the README install steps?". It copies the package into a fresh
`IDAUSR` home with `ida-plugin.json` in place, runs IDA once, and fails unless
IDA discovered the plugin by itself and printed its startup message. (IDA 9.4
only scans flat `.py` files or manifest-carrying subfolders — a bare
`PseudoClean/` directory is invisible to it.)

The IDA phase copies the package to `C:\Users\Public\pc_run` (native Windows
path — IDA refuses to write `.i64` databases next to a WSL path), runs one
headless session per binary, and prints a per-binary summary with the failure
list from each log.
