#!/usr/bin/env bash
# PseudoClean test runner.
#
#   ./testbin/run_tests.sh              # offline unit tests + IDA integration
#   ./testbin/run_tests.sh units        # offline unit tests only
#   ./testbin/run_tests.sh ida          # IDA integration tests only
#
# Environment overrides:
#   IDA_DIR   IDA installation directory
#   IDA_EXE   idat executable name inside IDA_DIR
#
# The IDA part copies the package to a native Windows directory (IDA refuses
# to write .i64 databases next to WSL paths) and runs one headless session per
# test binary, then prints a per-binary pass/fail summary.

set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$REPO/PseudoClean"
TESTBIN="$REPO/testbin"

IDA_DIR="${IDA_DIR:-/mnt/c/Program Files/IDA Professional 9.4}"
IDA_EXE="${IDA_EXE:-idat.exe}"
WIN_WORK="${WIN_WORK:-/mnt/c/Users/Public/pc_run}"
WIN_WORK_WIN='C:\Users\Public\pc_run'

MODE="${1:-all}"

fail=0

# --------------------------------------------------------------------------
# locate a python interpreter
# --------------------------------------------------------------------------
PY=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done

# --------------------------------------------------------------------------
# 1. offline unit tests
# --------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "units" ]; then
    echo "=============================================================="
    echo "offline unit tests"
    echo "=============================================================="
    if [ -z "$PY" ]; then
        echo "no python interpreter found; skipping unit tests"
        fail=1
    else
        "$PY" "$PKG/tests/unit_tests.py" || fail=1
    fi
    echo
fi

# --------------------------------------------------------------------------
# 2. IDA integration tests
# --------------------------------------------------------------------------
if [ "$MODE" = "all" ] || [ "$MODE" = "ida" ]; then
    echo "=============================================================="
    echo "IDA integration tests"
    echo "=============================================================="

    if [ ! -x "$IDA_DIR/$IDA_EXE" ]; then
        echo "IDA not found at '$IDA_DIR/$IDA_EXE'"
        echo "set IDA_DIR (and optionally IDA_EXE) and re-run"
        exit 1
    fi

    rm -rf "$WIN_WORK"
    mkdir -p "$WIN_WORK/plug" "$WIN_WORK/logs" "$WIN_WORK/db"
    cp -r "$PKG"/* "$WIN_WORK/plug/" || exit 1
    # strip local scratch scripts so they never shadow the real package
    find "$WIN_WORK/plug" -name '_*.py' -delete 2>/dev/null
    find "$WIN_WORK/plug" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null
    # regenerate the test corpus so results always match the sources
    if command -v gcc >/dev/null 2>&1; then
        ( cd "$TESTBIN" && gcc -O0 -fno-inline -o testcases_O0.bin testcases.c \
            && gcc -O2 -fno-inline -o testcases_O2.bin testcases.c \
            && strip -o testcases_stripped.bin testcases_O0.bin \
            && gcc -O0 -fno-inline -o obfuscated_O0.bin obfuscated.c \
            && strip -o obfuscated_stripped.bin obfuscated_O0.bin ) \
            || echo "warning: could not rebuild the test corpus"
    fi

    declare -a names=()
    declare -a codes=()
    for bin in "$TESTBIN"/*.bin; do
        [ -e "$bin" ] || continue
        case "$bin" in *_perf.bin) continue ;; esac
        base="$(basename "$bin" .bin)"
        cp "$bin" "$WIN_WORK/db/$base.bin"
        log="$WIN_WORK/logs/$base.log"
        rm -f "$WIN_WORK/db/$base.bin.i64" "$WIN_WORK/db/$base.i64"
        echo "--- $base"
        ( cd "$WIN_WORK/db" && "$IDA_DIR/$IDA_EXE" -A \
            -S"$WIN_WORK_WIN\\plug\\tests\\integration_test.py" \
            -L"$WIN_WORK_WIN\\logs\\$base.log" "$base.bin" >/dev/null 2>&1 )
        code=$?
        names+=("$base")
        codes+=("$code")
    done

    # ----------------------------------------------------------------------
    # 2b. two-session restart test (same .i64, two IDA processes)
    # ----------------------------------------------------------------------
    # the only corpus with auto-named functions (so renames are possible)
    RESTART_BIN="obfuscated_stripped"
    if [ -f "$WIN_WORK/db/$RESTART_BIN.bin" ]; then
        echo "--- $RESTART_BIN (restart phase 1/2)"
        rm -f "$WIN_WORK/db/$RESTART_BIN.bin.i64" \
              "$WIN_WORK/db/$RESTART_BIN.bin.restart_expect"
        ( cd "$WIN_WORK/db" && "$IDA_DIR/$IDA_EXE" -A \
            -S"$WIN_WORK_WIN\\plug\\tests\\restart_phase1.py" \
            -L"$WIN_WORK_WIN\\logs\\restart_phase1.log" \
            "$RESTART_BIN.bin" >/dev/null 2>&1 )
        code1=$?
        ( cd "$WIN_WORK/db" && "$IDA_DIR/$IDA_EXE" -A \
            -S"$WIN_WORK_WIN\\plug\\tests\\restart_phase2.py" \
            -L"$WIN_WORK_WIN\\logs\\restart_phase2.log" \
            "$RESTART_BIN.bin" >/dev/null 2>&1 )
        code2=$?
        echo "  phase1 exit=$code1  phase2 exit=$code2"
        grep -aE '^  \[(OK|FAIL|SKIP)\] ' \
            "$WIN_WORK/logs/restart_phase2.log" 2>/dev/null | sed 's/^/    /'
        if [ "$code1" != "0" ] || [ "$code2" != "0" ]; then
            fail=1
            echo "  restart test FAILED"
            grep -a '^  \[FAIL\]' "$WIN_WORK/logs/restart_phase1.log" \
                2>/dev/null | sed 's/^/    phase1 /'
            grep -a '^  \[FAIL\]' "$WIN_WORK/logs/restart_phase2.log" \
                2>/dev/null | sed 's/^/    phase2 /'
        else
            echo "  restart test PASSED (apply + persist + revert across processes)"
        fi
    fi

    echo
    echo "=============================================================="
    echo "results"
    echo "=============================================================="
    total=0
    passed=0
    for i in "${!names[@]}"; do
        base="${names[$i]}"
        code="${codes[$i]}"
        log="$WIN_WORK/logs/$base.log"
        summary=""
        if [ -f "$log" ]; then
            summary="$(grep -a '^CHECKS:' "$log" | tail -1)"
        fi
        [ -z "$summary" ] && summary="no summary (IDA did not finish)"
        total=$((total + 1))
        if [ "$code" = "0" ]; then
            passed=$((passed + 1))
            printf '  %-26s exit=%-3s %s\n' "$base" "$code" "$summary"
        else
            printf '  %-26s exit=%-3s %s\n' "$base" "$code" "$summary"
            grep -a '^  FAILED :' "$log" 2>/dev/null | head -10 | sed 's/^/      /'
            fail=1
        fi
    done
    echo
    echo "  $passed/$total binaries fully passed"
    echo "  logs: $WIN_WORK/logs/"
    echo
fi

# --------------------------------------------------------------------------
# 3. scale / performance test (1200 generated functions)
# --------------------------------------------------------------------------
if [ "$MODE" = "perf" ]; then
    echo "=============================================================="
    echo "scale test (1200 generated functions)"
    echo "=============================================================="
    if [ ! -x "$IDA_DIR/$IDA_EXE" ]; then
        echo "IDA not found at '$IDA_DIR/$IDA_EXE'"
        exit 1
    fi
    if ! command -v gcc >/dev/null 2>&1; then
        echo "gcc not found; cannot generate the performance corpus"
        exit 1
    fi
    rm -rf "$WIN_WORK"
    mkdir -p "$WIN_WORK/plug" "$WIN_WORK/logs" "$WIN_WORK/db"
    cp -r "$PKG"/* "$WIN_WORK/plug/" || exit 1
    find "$WIN_WORK/plug" -name '_*.py' -delete 2>/dev/null
    find "$WIN_WORK/plug" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null
    "$PY" "$TESTBIN/gen_perf.py" 1200 "$TESTBIN/perf.c" || exit 1
    ( cd "$TESTBIN" && gcc -O0 -fno-inline -o testcases_perf.bin perf.c ) \
        || exit 1
    rm -f "$TESTBIN/perf.c"
    cp "$TESTBIN/testcases_perf.bin" "$WIN_WORK/db/"
    ( cd "$WIN_WORK/db" && "$IDA_DIR/$IDA_EXE" -A \
        -S"$WIN_WORK_WIN\\\\plug\\\\tests\\\\perf_probe.py" \
        -L"$WIN_WORK_WIN\\\\logs\\\\perf.log" testcases_perf.bin \
        >/dev/null 2>&1 )
    code=$?
    grep -aE '^(decompilable|analyze_all|suggestions|report):|^  \[' \
        "$WIN_WORK/logs/perf.log" 2>/dev/null | sed 's/^/  /'
    rm -f "$TESTBIN/testcases_perf.bin"
    summary="$(grep -a '^CHECKS:' "$WIN_WORK/logs/perf.log" | tail -1)"
    echo "  exit=$code  ${summary:-no summary (IDA did not finish)}"
    [ "$code" = "0" ] || fail=1
    echo
fi

# --------------------------------------------------------------------------
# 4. install test: does IDA discover the plugin on its own?
# --------------------------------------------------------------------------
if [ "$MODE" = "install" ]; then
    echo "=============================================================="
    echo "install test (fresh IDAUSR home, plugin discovery)"
    echo "=============================================================="
    if [ ! -x "$IDA_DIR/$IDA_EXE" ]; then
        echo "IDA not found at '$IDA_DIR/$IDA_EXE'"
        exit 1
    fi
    INSTALL_HOME="$WIN_WORK/install_home"
    INSTALL_LOG="$WIN_WORK/logs/install.log"
    INSTALL_HOME_WIN='C:\Users\Public\pc_run\install_home'
    INSTALL_LOG_WIN='C:\Users\Public\pc_run\logs\install.log'
    rm -rf "$WIN_WORK"
    mkdir -p "$INSTALL_HOME/plugins" "$WIN_WORK/logs" "$WIN_WORK/db" "$WIN_WORK/plug"
    cp -r "$PKG" "$INSTALL_HOME/plugins/PseudoClean" || exit 1
    find "$INSTALL_HOME" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null
    cp -r "$PKG"/* "$WIN_WORK/plug/"
    find "$WIN_WORK/plug" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null
    cp "$TESTBIN/testcases_O0.bin" "$WIN_WORK/db/"
    # IDA reads IDAUSR only from the Windows environment; env vars set in WSL
    # do not cross the WSL/Windows boundary, so launch through a .bat.
    {
        printf '@echo off\r\n'
        printf 'set "IDAUSR=%s"\r\n' "$INSTALL_HOME_WIN"
        printf '"C:\\Program Files\\IDA Professional 9.4\\%s" -A -S%s\\plug\\tests\\install_probe.py -L%s testcases_O0.bin\r\n' \
            "$IDA_EXE" "$WIN_WORK_WIN" "$INSTALL_LOG_WIN"
    } > "$WIN_WORK/run_install.bat"
    ( cd "$WIN_WORK/db" && rm -f testcases_O0.bin.i64 && \
        /mnt/c/Windows/System32/cmd.exe /c "C:\\Users\\Public\\pc_run\\run_install.bat" \
        >/dev/null 2>&1 )
    code=$?
    grep -aE '^  \[|^CHECKS:|^IDAUSR|^plugdir|^find_plugin' \
        "$INSTALL_LOG" 2>/dev/null | sed 's/^/  /'
    summary="$(grep -a '^CHECKS:' "$INSTALL_LOG" | tail -1)"
    if grep -aq '\[PseudoClean\] loaded\.' "$INSTALL_LOG" 2>/dev/null; then
        printf '  %s\n' "  [OK] IDA printed the plugin init message at startup"
    else
        printf '  %s\n' "  [FAIL] no '[PseudoClean] loaded.' in the startup log"
        fail=1
    fi
    echo "  exit=$code  ${summary:-no summary (IDA did not finish)}"
    [ "$code" = "0" ] || fail=1
    rm -rf "$INSTALL_HOME"
    echo
fi

if [ "$fail" = "0" ]; then
    echo "ALL TESTS PASSED"
else
    echo "FAILURES PRESENT (see output above)"
fi
exit "$fail"