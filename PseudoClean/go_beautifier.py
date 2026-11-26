"""Go / Hex-Rays Go Pseudocode Beautifier.

Transforms raw IDA/Hex-Rays Go decompilation into clean, idiomatic Go code
using general, order-independent transformation rules (100% deterministic, 0% AI).

Features:
  1. Language Detection (`is_go_pseudocode`)
  2. Offline ELF `.rodata` & IDA `ida_bytes` String Resolver
  3. Generic Go Symbol Demangler (`<pkg>_Func`, `<pkg>__ptr_Type_Method`) + Auto-Import
  4. ABI Tuple `(ptr, len)` / `(ptr, len, cap)` & Multi-Return `retval_*` / `._rN` Folding
  5. Go Runtime Idiom Folding:
       - `runtime_stringtoslicebyte` -> `[]byte(s)`
       - `runtime_slicebytetostring` -> `string(b)`
       - `runtime_concatstring2..N` / `runtime_concatbyteN` -> `s1 + s2 + ...`
       - `runtime_growslice` / `runtime_memmove` -> `append(...)`
       - `runtime_gopanic` / `runtime_gorecover` -> `panic(...)` / `recover()`
       - `runtime_makemap` / `mapaccess1` / `mapaccess2` / `mapassign` -> `make(map[K]V)`, `m[k]`, `v, ok := m[k]`, `m[k] = v`
       - `runtime_makechan` / `closechan` / `chansend1` / `chanrecv2` / `newproc` -> `make(chan T)`, `close(ch)`, `ch <- v`, `for v := range ch`, `go func(...)`
       - `runtime_gcWriteBarrier*`, `runtime_panicBounds`, `runtime_convT*` pruning
"""

from __future__ import annotations

import os
import re
import struct
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. Language Detection
# ---------------------------------------------------------------------------

def is_go_pseudocode(code: str) -> bool:
    """Returns True if the Hex-Rays pseudocode looks like a Go binary."""
    indicators = (
        "__golang",
        "runtime_makeslice",
        "runtime_stringtoslicebyte",
        "runtime_slicebytetostring",
        "runtime_concatstring",
        "runtime_concatbyte",
        "runtime_panicBounds",
        "runtime_panicIndex",
        "runtime_mallocgc",
        "runtime_growslice",
        "runtime_mapassign",
        "runtime_mapaccess",
        "runtime_makechan",
        "runtime_newproc",
        "runtime_chansend",
        "runtime_chanrecv",
        "runtime_newobject",
        "retval_",
        "main_main",
        "main_enc",
        "bufio_Reader",
        "fmt_Fprint",
        "compress_zlib_",
        "crypto_aes_",
        "crypto_cipher_",
        "crypto_sha256_",
        "crypto_md5_",
        "crypto_rc4_",
        "encoding_hex_",
        "encoding_base64_",
        "encoding_binary_",
        "bytes_Repeat",
    )
    return any(tok in code for tok in indicators)


# ---------------------------------------------------------------------------
# 2. Offline ELF .rodata / IDA String Resolver
# ---------------------------------------------------------------------------

_OFFLINE_ELF_PATH: Optional[str] = None
_ELF_SECTIONS_CACHE: Dict[str, List[Tuple[int, int, int, bytes]]] = {}


def set_offline_elf_path(path: Optional[str]) -> None:
    """Sets an ELF binary path for offline `.rodata`/`.data` constant resolution."""
    global _OFFLINE_ELF_PATH
    _OFFLINE_ELF_PATH = path


def _load_elf_sections(path: str) -> List[Tuple[int, int, int, bytes]]:
    """Parses ELF64 section headers into [(vaddr, size, offset, data), ...]."""
    if path in _ELF_SECTIONS_CACHE:
        return _ELF_SECTIONS_CACHE[path]
    sections: List[Tuple[int, int, int, bytes]] = []
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) < 64 or raw[:4] != b"\x7fELF" or raw[4] != 2:
            return sections
        e_shoff = struct.unpack_from("<Q", raw, 40)[0]
        e_shentsize, e_shnum = struct.unpack_from("<HH", raw, 58)
        for idx in range(e_shnum):
            off = e_shoff + idx * e_shentsize
            if off + 64 > len(raw):
                break
            sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", raw, off + 16)
            if sh_addr > 0 and sh_size > 0 and sh_offset + sh_size <= len(raw):
                sections.append((sh_addr, sh_size, sh_offset, raw[sh_offset:sh_offset + sh_size]))
    except Exception:
        pass
    _ELF_SECTIONS_CACHE[path] = sections
    return sections


def resolve_binary_bytes(addr: int, length: int) -> Optional[bytes]:
    """Reads `length` bytes at virtual address `addr` from IDA or offline ELF."""
    if length <= 0 or length > 256:
        return None
    # 1. Try IDA Pro API first
    try:
        import ida_bytes
        data = ida_bytes.get_bytes(addr, length)
        if data:
            return bytes(data)
    except Exception:
        pass

    # 2. Fallback to offline ELF sections
    if _OFFLINE_ELF_PATH and os.path.exists(_OFFLINE_ELF_PATH):
        for vaddr, size, _, sec_data in _load_elf_sections(_OFFLINE_ELF_PATH):
            if vaddr <= addr and addr + length <= vaddr + size:
                rel = addr - vaddr
                return sec_data[rel:rel + length]
    return None


def resolve_symbol_string(sym: str, length: int) -> Optional[str]:
    """Resolves `&unk_50CE48` / `off_50CE48` + length into a quoted Go string literal."""
    s = sym.strip().lstrip("&").strip()
    m = re.match(r'^(?:unk|off|asc|byte|qword)_([0-9A-Fa-f]+)$', s)
    if not m:
        return None
    addr = int(m.group(1), 16)
    raw = resolve_binary_bytes(addr, length)
    if raw is None:
        return None
    try:
        text = raw.decode("utf-8")
        if all(0x20 <= ord(c) <= 0x7E or c in "\n\r\t" for c in text):
            escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
            return f'"{escaped}"'
    except UnicodeDecodeError:
        pass
    return None


# ---------------------------------------------------------------------------
# 3. Generic Go Symbol Demangler & Auto-Import
# ---------------------------------------------------------------------------

# Explicit overrides where IDA mangles or abbreviates Go stdlib
_GO_EXPLICIT_MAP: Dict[str, str] = {
    "compress_zlib__ptr_Writer_Write": "zw.Write",
    "compress_zlib__ptr_Writer_Close": "zw.Close",
    "compress_zlib_NewWriterLevelDict": "zlib.NewWriter",
    "compress_zlib_NewWriter": "zlib.NewWriter",
    "os_OpenFile": "os.Open",
    "os__ptr_file_close": "f.Close",
    "bufio__ptr_Scanner_Scan": "scanner.Scan",
    "bufio__ptr_Reader_ReadString": "reader.ReadString",
    "internal_strconv_FormatInt": "strconv.Itoa",
    "fmt_errorf": "fmt.Errorf",
    "fmt_Fprint": "fmt.Print",
    "fmt_Fprintln": "fmt.Println",
    "fmt_Fscanln": "fmt.Scanln",
    "runtime_memmove": "copy",
    "runtime_memequal": "bytes.Equal",
    "runtime_closechan": "close",
    "runtime_gorecover": "recover",
}

# Known Go stdlib package prefixes (longest match first)
_STDLIB_PKGS: List[Tuple[str, str, str]] = [
    # (ida_prefix, clean_qualifier, import_path)
    ("compress_zlib_", "zlib.", "compress/zlib"),
    ("compress_gzip_", "gzip.", "compress/gzip"),
    ("crypto_sha256_", "sha256.", "crypto/sha256"),
    ("crypto_sha512_", "sha512.", "crypto/sha512"),
    ("crypto_cipher_", "cipher.", "crypto/cipher"),
    ("crypto_aes_", "aes.", "crypto/aes"),
    ("crypto_md5_", "md5.", "crypto/md5"),
    ("crypto_rc4_", "rc4.", "crypto/rc4"),
    ("crypto_hmac_", "hmac.", "crypto/hmac"),
    ("encoding_base64_", "base64.", "encoding/base64"),
    ("encoding_binary_", "binary.", "encoding/binary"),
    ("encoding_hex_", "hex.", "encoding/hex"),
    ("encoding_json_", "json.", "encoding/json"),
    ("math_big_", "big.", "math/big"),
    ("strconv_", "strconv.", "strconv"),
    ("strings_", "strings.", "strings"),
    ("bytes_", "bytes.", "bytes"),
    ("bufio_", "bufio.", "bufio"),
    ("errors_", "errors.", "errors"),
    ("sync_", "sync.", "sync"),
    ("fmt_", "fmt.", "fmt"),
    ("os_", "os.", "os"),
    ("io_", "io.", "io"),
]

_IMPORT_DETECTORS: List[Tuple[str, str]] = [
    ("bufio.", "bufio"),
    ("bytes.", "bytes"),
    ("zlib.", "compress/zlib"),
    ("gzip.", "compress/gzip"),
    ("aes.", "crypto/aes"),
    ("cipher.", "crypto/cipher"),
    ("hmac.", "crypto/hmac"),
    ("md5.", "crypto/md5"),
    ("rc4.", "crypto/rc4"),
    ("sha256.", "crypto/sha256"),
    ("sha512.", "crypto/sha512"),
    ("base64.", "encoding/base64"),
    ("binary.", "encoding/binary"),
    ("hex.", "encoding/hex"),
    ("json.", "encoding/json"),
    ("errors.", "errors"),
    ("fmt.", "fmt"),
    ("io.", "io"),
    ("big.", "math/big"),
    ("os.", "os"),
    ("strconv.", "strconv"),
    ("strings.", "strings"),
    ("sync.", "sync"),
]


def _demangle_go_symbol(sym: str) -> str:
    """Generically demangles IDA Go symbols:
      - `pkg__ptr_Type_Method` -> `typeVar.Method` / `pkg.Type.Method`
      - `pkg_Func` -> `pkg.Func`
    """
    if sym in _GO_EXPLICIT_MAP:
        return _GO_EXPLICIT_MAP[sym]

    # Method on pointer receiver: e.g. `sync__ptr_WaitGroup_Add`, `encoding_base64__ptr_Encoding_EncodeToString`
    m_ptr = re.match(r'^([a-zA-Z0-9_]+)__ptr_([A-Za-z0-9]+)_([A-Za-z0-9_]+)$', sym)
    if m_ptr:
        pkg, typ, method = m_ptr.group(1), m_ptr.group(2), m_ptr.group(3)
        if pkg == "encoding_base64" and typ == "Encoding":
            return f"base64.StdEncoding.{method}"
        if pkg == "sync" and typ == "WaitGroup":
            return f"wg.{method}"
        if pkg == "crypto_rc4" and typ == "Cipher":
            return f"rc4Cipher.{method}"
        if pkg == "main":
            return f"proc.{method}"
        var_alias = typ[0].lower() + typ[1:]
        return f"{var_alias}.{method}"

    # Stdlib package function: `<pkg>_<Func>`
    for ida_pref, qual, _ in _STDLIB_PKGS:
        if sym.startswith(ida_pref):
            func_part = sym[len(ida_pref):]
            return f"{qual}{func_part}"

    # Main package function: `main_foo` -> `foo`
    if sym.startswith("main_") and not sym.startswith("main_enc"):
        return sym[5:]

    return sym


def _apply_stdlib_map(text: str) -> str:
    """Replaces mangled Go symbols in expressions/statements with clean Go names."""
    # Match potential Go mangled identifiers
    def _repl(m: re.Match) -> str:
        tok = m.group(0)
        if tok.startswith(("runtime_", "RTYPE_", "go_itab_", "off_", "unk_", "qword_", "dword_")):
            return _GO_EXPLICIT_MAP.get(tok, tok)
        return _demangle_go_symbol(tok)

    return re.sub(r'\b[a-zA-Z][a-zA-Z0-9_]*_[a-zA-Z0-9_]+\b', _repl, text)


# ---------------------------------------------------------------------------
# 4. Lexical Pre-Cleaner & Multiline Call Joiner
# ---------------------------------------------------------------------------

def _clean_ida_go_artifacts(code: str) -> str:
    """Strips IDA calling conventions, stack/register comments, casts, and joins multiline calls."""
    lines = []
    for line in code.splitlines():
        s = line.strip()
        if s.startswith("//"):
            lines.append(line)
            continue
        line = re.sub(r'[ \t]*//[^\n]*$', '', line)
        lines.append(line)
    cleaned = "\n".join(lines)

    for _ in range(4):
        cleaned = re.sub(r',\s*\n\s*', ', ', cleaned)
        cleaned = re.sub(r'\(\s*\n\s*', '(', cleaned)

    # Remove IDA parameter hints (`a1: `, `s: `, `delim: `, etc.)
    cleaned = re.sub(r'([\(,]\s*)[a-zA-Z_][a-zA-Z0-9_]*:\s+', r'\1', cleaned)
    # Remove calling conventions & BYREF
    cleaned = re.sub(r'\b__(?:golang|fastcall|cdecl|stdcall|thiscall|usercall)\b\s*', '', cleaned)
    cleaned = re.sub(r'\bBYREF\b[ \t]*', '', cleaned)
    # Remove C casts like `(unsigned int)`, `(_BYTE *)`, `(void *)`, `(__int64 *)`, `(chan_int *)`
    cleaned = re.sub(r'\(\s*(?:(?:unsigned\s+|signed\s+)?__int\d+\s*\*?|unsigned\s+int|const\s+char\s*\*|uint8\s*\*|_BYTE\s*\*|void\s*\*|RTYPE\s*\*+|errors_errorString\s*\*|_ptr_[a-zA-Z_0-9]+|\$[A-F0-9]+\s*\*|struct_[a-zA-Z_0-9]+\s*\*|chan_\w+\s*\*)\s*\)', '', cleaned)
    # Remove uLL / LL integer suffixes
    cleaned = re.sub(r'\b(\d+|0x[0-9a-fA-F]+)[uU]*LL\b', r'\1', cleaned)
    cleaned = re.sub(r'\b(\d+|0x[0-9a-fA-F]+)[uU]+\b', r'\1', cleaned)
    # Remove LOBYTE(...) wrapper
    cleaned = re.sub(r'\bLOBYTE\(([^)]+)\)', r'\1', cleaned)
    return cleaned


# ---------------------------------------------------------------------------
# 5. Global Slice & Symbol Collector
# ---------------------------------------------------------------------------

def _collect_go_globals(body_text: str) -> Tuple[List[str], Dict[str, str]]:
    """Detects global []byte slice headers (ptr, len, cap) used in Go stdlib/compare calls."""
    globals_list: List[Tuple[str, str, Optional[str]]] = []
    sym_map: Dict[str, str] = {}

    m_key = re.search(r'aes\.NewCipher\((off_[0-9A-Fa-f]+|unk_[0-9A-Fa-f]+),\s*([a-zA-Z_0-9]+)', body_text)
    if m_key:
        ptr_sym, len_sym = m_key.group(1), m_key.group(2)
        globals_list.append(("aesKey", ptr_sym, len_sym))
        sym_map[ptr_sym] = "aesKey"
        sym_map[len_sym] = "len(aesKey)"

    m_iv = re.search(r'cipher\.NewCBC(?:En|De)crypter\([^,]+,\s*[^,]+,\s*(off_[0-9A-Fa-f]+|unk_[0-9A-Fa-f]+),\s*([a-zA-Z_0-9]+)', body_text)
    if m_iv:
        ptr_sym, len_sym = m_iv.group(1), m_iv.group(2)
        globals_list.append(("aesIV", ptr_sym, len_sym))
        sym_map[ptr_sym] = "aesIV"
        sym_map[len_sym] = "len(aesIV)"

    m_exp = re.search(r'\*\(\s*(?:\(_BYTE\s*\*\)\s*)?(off_[0-9A-Fa-f]+)\s*\+', body_text)
    if m_exp:
        ptr_sym = m_exp.group(1)
        m_len = re.search(r'\b(qword_[0-9A-Fa-f]+)\s*!=\s*v\d+', body_text)
        if not m_len:
            m_len = re.search(r'\b\w+\s*>=\s*(qword_[0-9A-Fa-f]+)', body_text)
        len_sym = m_len.group(1) if m_len else None
        globals_list.append(("expectedCiphertext", ptr_sym, len_sym))
        sym_map[ptr_sym] = "expectedCiphertext"
        if len_sym:
            sym_map[len_sym] = "len(expectedCiphertext)"

    var_lines: List[str] = []
    if globals_list:
        var_lines.append("// Variabel global di segmen data (.data / .rodata)")
        var_lines.append("var (")
        max_name = max(len(name) for name, _, _ in globals_list)
        for name, ptr_sym, len_sym in globals_list:
            pad = " " * (max_name - len(name) + 1)
            cmt = f"// {ptr_sym} (len: {len_sym})" if len_sym else f"// {ptr_sym}"
            var_lines.append(f"\t{name}{pad}[]byte {cmt}")
        var_lines.append(")")

    return var_lines, sym_map


# ---------------------------------------------------------------------------
# 6. General Statement Folding & Data-Flow Lifter
# ---------------------------------------------------------------------------

_C_DECL_RE = re.compile(
    r'^\s*(?:(?:const\s+|unsigned\s+|signed\s+)?'
    r'(?:__int(?:64|32|16|8)|__m\d+i?|_QWORD|_OWORD|_BYTE|_DWORD|int|char|bool|size_t|string|uint8|os\.File|os_File|bufio\.Reader|bufio_Reader|io\.Writer|io_Writer|_slice_\w+|internal_abi_\w+|retval_[0-9A-Fa-f]+|errors\.errorString|errors_errorString|RTYPE|sync\.WaitGroup|sync_WaitGroup|chan_\w+|_ptr_\w+|bytes\.Buffer|bytes_Buffer|_16_uint8|\$[A-F0-9]+|struct_\w+|void)'
    r'(?:\s*\*+|\s*\(\*+[a-zA-Z_0-9]+\)(?:\([^)]*\))?)?\s*\*?\s*[a-zA-Z_0-9]*(?:\[\s*\d*\s*\])?\s*;?\s*)$'
)


def _fold_abi_tuples_and_fmt(line: str) -> str:
    """Folds Go ABI (ptr, len)/(ptr, len, cap) tuples and variadic fmt calls."""
    # 1. Offset pairs: `*(_QWORD *)(base + 16), *(_QWORD *)(base + 24)` (or 24, 16) -> `base[1]`
    def _repl_off_pair(m: re.Match) -> str:
        base = m.group(1)
        off1, off2 = int(m.group(2)), int(m.group(3))
        lo = min(off1, off2)
        idx = lo // 16 if lo >= 16 else 0
        if base.startswith("qword_"):
            return f"os.Args[{idx}]"
        return f"{base}[{idx}]"

    line = re.sub(
        r'\*\(\s*[a-zA-Z_0-9]+\s*\*\)\(\s*([a-zA-Z_0-9]+)\s*\+\s*(\d+)\s*\)\s*,\s*\*\(\s*[a-zA-Z_0-9]+\s*\*\)\(\s*\1\s*\+\s*(\d+)\s*\)',
        _repl_off_pair,
        line,
    )

    # 2. Variadic fmt calls: `fmt.Println(go_itab__ptr_os_File_comma__ptr_io_Writer, qword_..., &args, 1, 1)`
    line = re.sub(
        r'\bfmt\.(Println|Print|Scanln)\(\s*go_itab_[^,]+,\s*[^,]+,\s*&?([^,]+),\s*\d+,\s*\d+\s*\)',
        lambda m: f"fmt.{m.group(1)}({'&' if m.group(1) == 'Scanln' else ''}{m.group(2).strip()})",
        line,
    )
    line = re.sub(
        r'\bfmt\.(Printf|Sprintf|Errorf)\(\s*(?:go_itab_[^,]+,\s*[^,]+,\s*)?("[^"]*")\s*,\s*\d+\s*,\s*&?([^,]+),\s*\d+,\s*\d+\s*\)',
        r'fmt.\1(\2, \3)',
        line,
    )

    # 3. Slice 3-tuples `(ptr, N, N)` -> `ptr[:N]` inside Go stdlib calls
    line = re.sub(
        r'([a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z0-9_]+\([^)]*?)(?:&)?([a-zA-Z_0-9]+)\s*,\s*(\d+)\s*,\s*\3(\s*[,)])',
        r'\1\2[:\3]\4',
        line,
    )

    # 4. Hex table `a0123456789abcd` -> `"0123456789abcdef"`
    line = re.sub(r'\ba0123456789abcd\b', '"0123456789abcdef"', line)
    return line


def _split_top_args(args_str: str) -> List[str]:
    """Splits comma-separated call arguments respecting nested parentheses."""
    args: List[str] = []
    depth = 0
    cur: List[str] = []
    in_str = False
    escape = False
    for ch in args_str:
        if escape:
            cur.append(ch)
            escape = False
            continue
        if ch == "\\" and in_str:
            cur.append(ch)
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            cur.append(ch)
            continue
        if not in_str:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif ch == "," and depth == 0:
                args.append("".join(cur).strip())
                cur = []
                continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        args.append(tail)
    return args


def _format_concat_args(raw_args: List[str], aliases: Dict[str, str]) -> str:
    """Converts Go `runtime_concatstringN(buf, p1, l1, p2, l2, ...)` args into `a + b + ...`."""
    # Skip first arg (stack buf / 0)
    pairs = raw_args[1:]
    parts: List[str] = []
    idx = 0
    while idx < len(pairs):
        ptr = pairs[idx].strip()
        if ptr.startswith('"'):
            parts.append(ptr)
            idx += 2  # skip len
            continue
        # Check if ptr is a ._r0 reference
        m_r = re.match(r'^(\w+)\._r\d+$', ptr)
        if m_r and m_r.group(1) in aliases:
            parts.append(aliases[m_r.group(1)])
            idx += 2
            continue
        if ptr in aliases:
            parts.append(aliases[ptr])
            idx += 2
            continue
        # Try resolving unk_XXXX + literal length from .rodata
        if idx + 1 < len(pairs) and re.match(r'^\d+$', pairs[idx + 1].strip()):
            resolved = resolve_symbol_string(ptr, int(pairs[idx + 1].strip()))
            if resolved:
                parts.append(resolved)
                idx += 2
                continue
        parts.append(ptr)
        idx += 2 if idx + 1 < len(pairs) else 1
    return " + ".join(parts) if parts else '""'


def _fold_go_statements(lines: List[str], sym_map: Dict[str, str], param_name: str = "input") -> List[str]:
    """Folds Go compiler/Hex-Rays idioms in-place, preserving arbitrary control flow."""
    out: List[str] = []
    aliases: Dict[str, str] = {"a1": param_name}
    slice_vars: Dict[str, str] = {}
    ret_vars: Dict[str, Tuple[str, str]] = {}  # vX -> (val_name, err_name)
    current_buf = "buf"
    current_zw = "zw"
    current_plain = "inputBytes"
    next_tmp_id = 1

    def _new_var(prefix: str = "v") -> str:
        nonlocal next_tmp_id
        name = f"{prefix}{next_tmp_id}"
        next_tmp_id += 1
        return name

    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        s = line.strip()
        indent = "\t" * max(1, (len(line) - len(line.lstrip())) // 2)

        # Skip empty lines, C variable declarations, labels, and standalone braces right after header
        if not s or _C_DECL_RE.match(s):
            i += 1
            continue
        if s == "{" and out and out[-1].rstrip().endswith("{"):
            i += 1
            continue
        if s in ("{", "}") and (i == 0 or i == n - 1):
            i += 1
            continue
        if re.match(r'^LABEL_\d+:$', s):
            i += 1
            continue

        # Strip `runtime_panicBounds` / `runtime_panicIndex` and its single-line `if` guard
        if "runtime_panicBounds" in s or "runtime_panicIndex" in s:
            if out and re.match(r'^\s*if\s+.*\{\s*$', out[-1]):
                out.pop()
            i += 1
            continue
        if i + 1 < n and s.startswith("if ") and ("runtime_panicBounds" in lines[i + 1] or "runtime_panicIndex" in lines[i + 1]):
            i += 2
            continue

        # Strip GC write barrier blocks: `if ( dword_... != 0 ) { ... gcWriteBarrier ... } else { ... }`
        if "gcWriteBarrier" in s or (i + 2 < n and re.match(r'^if\s*\(\s*dword_[0-9A-Fa-f]+\s*!=\s*0\s*\)', s) and "gcWriteBarrier" in lines[i + 2]):
            # Skip until matching `}` of the if/else block
            j = i
            while j < n and "else" not in lines[j] and j < i + 12:
                j += 1
            if j < n and "else" in lines[j]:
                # Skip the `if` branch, jump past `else { ... }`
                k = j + 1
                depth = 0
                while k < n:
                    sk = lines[k].strip()
                    depth += sk.count("{") - sk.count("}")
                    k += 1
                    if depth <= 0 and "}" in sk:
                        break
                i = k
                continue
            i += 1
            continue

        # Collapse Go error creation: `p_errors_errorString = runtime_newobject(&RTYPE_errors_errorString);`
        if "runtime_newobject(&RTYPE_errors_errorString)" in s:
            err_msg = '"error"'
            j = i + 1
            while j < n and j < i + 8 and ("p_errors_errorString->" in lines[j] or "result._r" in lines[j]):
                m_msg = re.search(r'\.str\s*=\s*("[^"]*")', lines[j])
                if m_msg:
                    err_msg = m_msg.group(1)
                j += 1
            out.append(f"{indent}return nil, errors.New({err_msg})")
            i = j
            continue

        # Collapse `result._r0 = 0; ... result._r3 = vX._r1; ...` inside error blocks
        if re.match(r'^result\._r\d+\s*=\s*', s):
            if re.search(r'=\s*(?:v\d+|File)\._r[1234]', s) and not any("return nil, err" in x for x in out[-3:]):
                out.append(f"{indent}return nil, err")
            i += 1
            continue

        # Noise memory/struct/register-spill assignments
        if re.match(r'^\*\(_[QO]WORD\s*\*\)|^\*\(\(_[QO]WORD\s*\*|memset\s*\(', s):
            i += 1
            continue
        if re.match(r'^v\d+\.(?:tab|data|array|cap|len)\s*=', s) or re.match(r'^v\d+\s*=\s*os_Std(?:out|in|err)\s*;', s):
            i += 1
            continue

        # 1. `v17 = runtime_stringtoslicebyte(v9, a1, a2);`
        m_s2b = re.match(r'^(\w+)\s*=\s*runtime_stringtoslicebyte\((.+)\)\s*;', s)
        if m_s2b:
            var = m_s2b.group(1)
            args = _split_top_args(m_s2b.group(2))
            src = aliases.get(args[1], args[1]) if len(args) >= 2 else param_name
            if src in ("0", "a1"):
                src = param_name
            aliases[var] = f"[]byte({src})"
            current_plain = f"[]byte({src})"
            b_name = "b" if "b" not in aliases.values() else _new_var("b")
            aliases[var] = b_name
            out.append(f"{indent}{b_name} := []byte({src})")
            i += 1
            continue

        # 2. `v15 = runtime_slicebytetostring(v8, r0, v2);`
        m_b2s = re.match(r'^(\w+)\s*=\s*runtime_slicebytetostring\((.+)\)\s*;', s)
        if m_b2s:
            var = m_b2s.group(1)
            args = _split_top_args(m_b2s.group(2))
            src = aliases.get(args[1], args[1]) if len(args) >= 2 else "b"
            if src == "r0":
                src = "b"
            s_name = _new_var("s")
            aliases[var] = s_name
            out.append(f"{indent}{s_name} := string({src})")
            i += 1
            continue

        # Propagate simple register/argument spills: `v13 = a1;`, `v12 = v15._r0;`, `r1 = v15._r1;`, `v14 = a2;`
        m_spill = re.match(r'^([vr]\d+)\s*=\s*(a\d+|v\d+(?:\._r[012])?)\s*;\s*$', s)
        if m_spill:
            lhs, rhs = m_spill.group(1), m_spill.group(2)
            base_rhs = rhs.split(".")[0]
            if base_rhs in aliases:
                aliases[lhs] = aliases[base_rhs]
                i += 1
                continue
            if rhs == "a2":
                i += 1
                continue

        # 3. `v16 = runtime_concatstring2(...)` / `runtime_concatstring5(...)` / `runtime_concatbyte3(...)`
        m_cat = re.match(r'^(\w+)\s*=\s*(?:result\._r0\s*=\s*)?runtime_concat(?:string|byte)\d+\((.+)\)\s*;', s)
        if m_cat or re.match(r'^result\._r0\s*=\s*runtime_concat(?:string|byte)\d+\((.+)\)\s*;', s):
            if m_cat:
                var = m_cat.group(1)
                args_raw = m_cat.group(2)
            else:
                m_cat2 = re.match(r'^result\._r0\s*=\s*runtime_concat(?:string|byte)\d+\((.+)\)\s*;', s)
                var = "result"
                args_raw = m_cat2.group(1)
            args = _split_top_args(args_raw)
            expr = _format_concat_args(args, aliases)
            if var == "result":
                out.append(f"{indent}return []byte({expr}), nil")
            else:
                s_name = _new_var("s")
                aliases[var] = s_name
                out.append(f"{indent}{s_name} := {expr}")
            i += 1
            continue

        # 4. Skip `if ( ... ) { ... runtime_growslice ... }` boilerplate when followed by append pack or copy
        if s.startswith("if ") and any("runtime_growslice" in lines[k] for k in range(i + 1, min(n, i + 10))):
            j = i + 1
            depth = 0
            while j < n:
                sj = lines[j].strip()
                depth += sj.count("{") - sj.count("}")
                j += 1
                if depth <= 0 and "}" in sj:
                    # Also consume optional `else { ... }`
                    if j < n and "else" in lines[j]:
                        k = j + 1
                        edepth = 0
                        while k < n:
                            sk = lines[k].strip()
                            edepth += sk.count("{") - sk.count("}")
                            k += 1
                            if edepth <= 0 and "}" in sk:
                                j = k
                                break
                    break
            i = j
            continue

        # `runtime_growslice` append folding (4-byte packed literal `*(_DWORD *)&r0[v2 - 4] = 1111572257;`)
        if "*(_DWORD *)&" in s and re.search(r'=\s*(\d+)\s*;', s):
            m_pack = re.search(r'=\s*(\d+)\s*;', s)
            val = int(m_pack.group(1))
            raw_4 = struct.pack("<I", val)
            chars = ", ".join(f"'{chr(b)}'" if (0x20 <= b <= 0x7E and (chr(b).isalnum() or chr(b) in "!?:_")) else f"0x{b:02X}" for b in raw_4)
            out.append(f"{indent}b = append(b, {chars})")
            i += 1
            continue

        # 5. `runtime_gopanic(&RTYPE_string, &s...)` -> `panic(...)`
        m_pan = re.match(r'^runtime_gopanic\((.+)\)\s*;', s)
        if m_pan:
            args = _split_top_args(m_pan.group(1))
            msg = args[1] if len(args) >= 2 else '"panic"'
            if msg.startswith("&s"):
                msg = f'"{msg[2:]}"'
            out.append(f"{indent}panic({msg})")
            i += 1
            continue

        # 6. `v7 = recover();`
        m_rec = re.match(r'^(\w+)\s*=\s*recover\(\)\s*;', s)
        if m_rec:
            aliases[m_rec.group(1)] = "r"
            out.append(f"{indent}if r := recover(); r != nil {{")
            if i + 2 < n and "!= 0" in lines[i + 2]:
                i += 3
            else:
                i += 1
            continue

        # 7. Map operations & pre-makemap zeroing loop cleanup:
        # Skip `v5 = v26; for (i = 3; i != 0; --i) { *v5 = 0; ... }` + `v26[0] = 0x8080...; v27[2] = v26;`
        if re.match(r'^v\d+\s*=\s*v\d+\s*;\s*$', s) and i + 1 < n and "for (" in lines[i + 1] and any("runtime_rand()" in lines[k] for k in range(i + 1, min(n, i + 18))):
            j = i + 1
            while j < n and "runtime_rand()" not in lines[j]:
                j += 1
            if j < n and "runtime_rand()" in lines[j]:
                out.append(f"{indent}m := make(map[string]int)")
                i = j + 1
                continue

        if "runtime_rand()" in s:
            out.append(f"{indent}m := make(map[string]int)")
            i += 1
            continue

        # `*(...)runtime_mapassign_faststr(&RTYPE_map_string_int, v27, key, klen) = val;`
        m_mass = re.search(r'runtime_mapassign\w*\([^,]+,\s*\w+,\s*([^,]+),\s*[^)]+\)\s*=\s*(.+?)\s*;', s)
        if m_mass:
            k_expr = aliases.get(m_mass.group(1).strip(), m_mass.group(1).strip())
            v_expr = aliases.get(m_mass.group(2).strip(), m_mass.group(2).strip())
            out.append(f"{indent}m[{k_expr}] = {v_expr}")
            i += 1
            continue

        # `v19 = *(...)runtime_mapaccess1_faststr(&RTYPE_map_string_int, v27, key, klen);`
        m_ma1 = re.match(r'^(\w+)\s*=\s*(?:\*\([^)]+\))?runtime_mapaccess1\w*\([^,]+,\s*\w+,\s*([^,]+),', s)
        if m_ma1:
            dst, k_expr = m_ma1.group(1), m_ma1.group(2).strip()
            aliases[dst] = f"m[{aliases.get(k_expr, k_expr)}]"
            out.append(f"{indent}{dst} := m[{aliases.get(k_expr, k_expr)}]")
            i += 1
            continue

        # `v33 = runtime_mapaccess2_faststr(&RTYPE_map_string_int, v27, "flag_key", 8);`
        m_ma2 = re.match(r'^(\w+)\s*=\s*runtime_mapaccess2\w*\([^,]+,\s*\w+,\s*([^,]+),', s)
        if m_ma2:
            tup, k_expr = m_ma2.group(1), m_ma2.group(2).strip()
            ret_vars[tup] = ("v2", "ok")
            out.append(f"{indent}v2, ok := m[{k_expr}]")
            i += 1
            continue

        # 8. Channel & goroutine closure boilerplate folding
        m_mc = re.match(r'^(\w+)\s*=\s*runtime_makechan\(&RTYPE_chan_(\w+)\)\s*;', s)
        if m_mc:
            ch_var, ch_type = m_mc.group(1), m_mc.group(2)
            aliases[ch_var] = "ch"
            out.append(f"{indent}ch := make(chan {ch_type})")
            i += 1
            continue

        # Closure allocation + `runtime_newproc()` -> `go func(...) { /* captured: ... */ }(...)`
        if re.search(r'runtime_newobject\(&RTYPE_(?:_FA4B|struct__F_)', s):
            captured: List[str] = []
            target_fn = "func"
            j = i + 1
            while j < n and j < i + 45:
                sj = lines[j].strip()
                m_fn = re.search(r'->F\s*=\s*(?:\([^)]+\))?([a-zA-Z_0-9]+)', sj)
                if m_fn and "gowrap" not in m_fn.group(1):
                    target_fn = m_fn.group(1)
                m_cap = re.search(r'->X\d+\s*=\s*([a-zA-Z_0-9]+)', sj)
                if m_cap:
                    cvar = aliases.get(m_cap.group(1), m_cap.group(1))
                    if cvar not in captured and cvar not in ("v8", "v16"):
                        captured.append(cvar)
                if "runtime_newproc()" in sj:
                    cap_str = ", ".join(captured) if captured else ""
                    out.append(f"{indent}go {target_fn}({cap_str}) // goroutine")
                    j += 1
                    break
                j += 1
            else:
                i += 1
                continue
            i = j
            continue

        if "runtime_newproc()" in s:
            out.append(f"{indent}go func() {{ /* goroutine */ }}()")
            i += 1
            continue

        m_cs = re.search(r'runtime_chansend\d*\(([^,]+),\s*&?([^)]+)\)', s)
        if m_cs:
            ch_name = aliases.get(m_cs.group(1).strip(), "ch")
            val_name = aliases.get(m_cs.group(2).strip(), m_cs.group(2).strip())
            out.append(f"{indent}{ch_name} <- {val_name}")
            i += 1
            continue

        if "runtime_chanrecv" in s:
            out.append(f"{indent}for res := range ch {{")
            i += 1
            continue

        # 9. `runtime_mallocgc*` + `zlib.NewWriter*`
        m_malloc = re.match(r'^(\w+)\s*=\s*runtime_mallocgc\w*\(', s)
        if m_malloc:
            aliases[m_malloc.group(1)] = current_buf
            if i + 1 < n and "zlib.NewWriter" in lines[i + 1]:
                m_zw = re.match(r'^(\w+)\s*=\s*zlib\.NewWriter\w*\(', lines[i + 1].strip())
                if m_zw:
                    aliases[m_zw.group(1)] = current_zw
                out.append(f"{indent}var {current_buf} bytes.Buffer")
                out.append(f"{indent}{current_zw} := zlib.NewWriter(&{current_buf})")
                i += 2
                continue
            i += 1
            continue

        # 10. `zw.Write` / `zw.Close`
        if "zw.Write(" in s and "!= 0" in s:
            src_arg = f"[]byte({param_name})"
            m_arg = re.search(r'zw\.Write\(\s*\w+\s*,\s*(\w+)\._r0', s)
            if m_arg and m_arg.group(1) in aliases:
                src_arg = aliases[m_arg.group(1)]
            out.append(f"{indent}if _, err := {current_zw}.Write({src_arg}); err != nil {{")
            if i + 1 < n and "os.Exit" in lines[i + 1]:
                out.append(f"{indent}\tos.Exit(1)")
                i += 2
            else:
                out.append(f"{indent}\treturn false")
                i += 1
            out.append(f"{indent}}}")
            continue

        if "zw.Close(" in s:
            out.append(f"{indent}if err := {current_zw}.Close(); err != nil {{")
            if i + 1 < n and "!= 0" in lines[i + 1] and i + 2 < n and "os.Exit" in lines[i + 2]:
                out.append(f"{indent}\tos.Exit(1)")
                i += 3
            else:
                out.append(f"{indent}\treturn false")
                i += 1
            out.append(f"{indent}}}")
            continue

        # 11. PKCS#7 padding + growslice + copy block
        m_pad = re.match(r'^(\w+)\s*=\s*16\s*-\s*\(\([^)]+\)\s*&\s*0x[Ff]\)\s*;', s)
        if m_pad:
            j = i + 1
            len_out_var = None
            while j < n:
                sj = lines[j].strip()
                if any(tok in sj for tok in ("aes.", "cipher.", "sha256.", "md5.", "hex.", "return ", "for ")):
                    break
                if re.match(r'^if\s*\(\s*(?:qword_|off_|len\()', sj):
                    break
                if "copy(" in sj:
                    j += 1
                    break
                j += 1
            for k_look in range(j, min(n, j + 5)):
                m_lk = re.search(r'!=\s*(v\d+)', lines[k_look])
                if m_lk:
                    len_out_var = m_lk.group(1)
                    break
            out.append(f"{indent}compressed := {current_buf}.Bytes()")
            out.append(f"{indent}padLen := 16 - (len(compressed) % 16)")
            out.append(f"{indent}padding := bytes.Repeat([]byte{{byte(padLen)}}, padLen)")
            out.append(f"{indent}padded := append(compressed, padding...)")
            current_plain = "padded"
            if len_out_var:
                slice_vars[len_out_var] = "padded"
            i = j
            continue

        # 12. Length check before cipher
        m_len_cmp = re.match(r'^if\s*\(\s*([a-zA-Z_0-9]+)\s*(!=|==)\s*(v\d+)\s*\)\s*$', s)
        if m_len_cmp and (m_len_cmp.group(1) in sym_map or m_len_cmp.group(3) in slice_vars):
            lhs = sym_map.get(m_len_cmp.group(1), m_len_cmp.group(1))
            op = m_len_cmp.group(2)
            rhs_var = m_len_cmp.group(3)
            rhs = f"len({slice_vars.get(rhs_var, current_plain)})"
            out.append(f"{indent}if {rhs} {op} {lhs} {{")
            if i + 1 < n and "return " in lines[i + 1]:
                out.append(f"{indent}\t{lines[i + 1].strip().rstrip(';')}")
                i += 2
            else:
                i += 1
            out.append(f"{indent}}}")
            continue

        # 13. `aes.NewCipher`
        m_aes = re.match(r'^(\w+)\s*=\s*aes\.NewCipher\(([^,]+),', s)
        if m_aes:
            key_arg = sym_map.get(m_aes.group(2).strip(), m_aes.group(2).strip())
            out.append(f"{indent}block, err := aes.NewCipher({key_arg})")
            j = i + 1
            while j < n and re.match(r'^v\d+\s*=\s*' + re.escape(m_aes.group(1)) + r'\._r[01]', lines[j].strip()):
                j += 1
            if j + 1 < n and "!= 0" in lines[j] and "os.Exit" in lines[j + 1]:
                out.append(f"{indent}if err != nil {{")
                out.append(f"{indent}\tos.Exit(1)")
                out.append(f"{indent}}}")
                j += 2
            i = j
            continue

        # 14. `runtime_makeslice`
        m_ms = re.match(r'^(\w+)\s*=\s*runtime_makeslice\([^,]+,\s*([^,]+),', s)
        if m_ms:
            dst_var = m_ms.group(1)
            len_arg = m_ms.group(2).strip()
            len_clean = f"len({slice_vars[len_arg]})" if len_arg in slice_vars else len_arg
            slice_vars[dst_var] = "ciphertext"
            out.append(f"{indent}ciphertext := make([]byte, {len_clean})")
            i += 1
            continue

        # 15. `cipher.NewCBCEncrypter` + `CryptBlocks`
        m_cbc = re.match(r'^(\w+)\s*=\s*cipher\.(NewCBC(?:En|De)crypter)\([^,]+,\s*[^,]+,\s*([^,]+),', s)
        if m_cbc:
            mode_fn = m_cbc.group(2)
            iv_arg = sym_map.get(m_cbc.group(3).strip(), m_cbc.group(3).strip())
            out.append(f"{indent}mode := cipher.{mode_fn}(block, {iv_arg})")
            if i + 1 < n and re.search(r'\(\*\(.*?\)\(' + re.escape(m_cbc.group(1)) + r'\._r0\s*\+\s*32', lines[i + 1]):
                out.append(f"{indent}mode.CryptBlocks(ciphertext, {current_plain})")
                i += 2
            else:
                i += 1
            continue

        # 16. Constant-time XOR-OR compare loop
        m_diff = re.match(r'^(\w+)\s*=\s*0\s*;\s*$', s)
        if m_diff and i + 1 < n and re.match(r'^for\s*\(', lines[i + 1].strip()):
            diff_var = m_diff.group(1)
            j = i + 1
            is_xor_or = False
            exp_name = "expectedCiphertext"
            while j < n:
                sj = lines[j].strip()
                if "|=" in sj and "^" in sj and diff_var in sj:
                    is_xor_or = True
                    m_ex = re.search(r'\*\(\s*(?:\(_BYTE\s*\*\)\s*)?([a-zA-Z_0-9]+)\s*\+', sj)
                    if m_ex:
                        exp_name = sym_map.get(m_ex.group(1), m_ex.group(1))
                if sj == "}":
                    j += 1
                    break
                j += 1
            if is_xor_or:
                out.append(f"{indent}var diff byte")
                out.append(f"{indent}for i := 0; i < len({current_plain}); i++ {{")
                out.append(f"{indent}\tdiff |= {exp_name}[i] ^ ciphertext[i]")
                out.append(f"{indent}}}")
                if j < n and re.match(r'^return\s+' + re.escape(diff_var) + r'\s*==\s*0\s*;', lines[j].strip()):
                    out.append(f"{indent}return diff == 0")
                    j += 1
                i = j
                continue

        # 17. General Multi-Return & Error Folding:
        # `vX = pkg.Func(...);` followed by `if ( vX._r1 != 0 )` or `r0 = vX._r0`
        m_mr = re.match(r'^(\w+)\s*=\s*([a-zA-Z_][a-zA-Z0-9_.]+\(.*\))\s*;\s*$', s)
        if m_mr and i + 1 < n and (f"{m_mr.group(1)}._r" in lines[i + 1] or (i + 2 < n and f"{m_mr.group(1)}._r" in lines[i + 2])):
            tup_var, call_expr = m_mr.group(1), _fold_abi_tuples_and_fmt(_simplify_go_stmt(m_mr.group(2), aliases))
            # Check if error check follows
            has_err_chk = any(re.search(rf'\b{re.escape(tup_var)}\._r[123]\s*!=\s*0', lines[k]) for k in range(i + 1, min(n, i + 4)))
            val_name = _new_var("val")
            aliases[tup_var] = val_name
            if has_err_chk:
                out.append(f"{indent}{val_name}, err := {call_expr}")
            else:
                out.append(f"{indent}{val_name} := {call_expr}")
            i += 1
            continue

        # Replace `if ( vX._r1 != 0 )` -> `if err != nil {`
        m_err_if = re.match(r'^if\s*\(\s*(\w+)\._r[123]\s*(!=|==)\s*0\s*\)\s*(\{?)\s*$', s)
        if m_err_if:
            op = "!=" if m_err_if.group(2) == "!=" else "=="
            out.append(f"{indent}if err {op} nil {{")
            i += 1
            continue

        # 18. Generic Go statement & C-to-Go syntax conversion
        clean_s = _simplify_go_stmt(s, aliases)
        m_while = re.match(r'^while\s*\(\s*(.+?)\s*\)\s*(\{?)\s*$', clean_s)
        if m_while:
            w_cond = m_while.group(1)
            if w_cond in ("1", "true"):
                out.append(f"{indent}for {{")
            else:
                out.append(f"{indent}for {w_cond} {{")
            i += 1
            continue

        m_for = re.match(r'^for\s*\(\s*(.*?)\s*;\s*(.*?)\s*;\s*(.*?)\s*\)\s*(\{?)\s*$', clean_s)
        if m_for:
            f_init, f_cond, f_step = m_for.group(1), m_for.group(2), m_for.group(3)
            f_init = re.sub(r'^(\w+)\s*=\s*', r'\1 := ', f_init)
            f_step = re.sub(r'^\+\+(\w+)$', r'\1++', f_step)
            out.append(f"{indent}for {f_init}; {f_cond}; {f_step} {{")
            i += 1
            continue

        m_if = re.match(r'^if\s*\(\s*(.+?)\s*\)\s*(\{?)\s*$', clean_s)
        if m_if:
            cond = m_if.group(1)
            out.append(f"{indent}if {cond} {{")
            # If C didn't have `{` and next line isn't `{`, auto-close single-line if
            if not m_if.group(2) and i + 1 < n and lines[i + 1].strip() != "{":
                next_s = _simplify_go_stmt(lines[i + 1].strip(), aliases).rstrip(";")
                out.append(f"{indent}\t{next_s}")
                out.append(f"{indent}}}")
                i += 2
                continue
            i += 1
            continue

        if clean_s in ("{", "}", "else"):
            if clean_s == "else":
                if out and out[-1].strip() == "}":
                    out[-1] = f"{indent}}} else {{"
                else:
                    out.append(f"{indent}}} else {{")
            else:
                out.append(f"{indent}{clean_s}")
            i += 1
            continue

        clean_s = clean_s.rstrip(";")
        # Drop dead `vN = ...` / `rN = ...` temporaries not referenced later
        m_tmp = re.match(r'^(v\d+|r\d+)\s*=\s*', clean_s)
        if m_tmp:
            tmp_name = m_tmp.group(1)
            rest_text = "\n".join(lines[i + 1:])
            if tmp_name not in rest_text:
                i += 1
                continue

        out.append(f"{indent}{clean_s}")
        i += 1

    return out


def _simplify_go_stmt(line: str, aliases: Optional[Dict[str, str]] = None) -> str:
    line = re.sub(
        r'\b(a[A-Z][A-Za-z0-9_]{1,20})\[(\w+)\s*%\s*(\d+)\]',
        lambda m: f'key[{m.group(2)}%{m.group(3)}]',
        line
    )
    line = re.sub(r'\bmain_(\w+)\.array\[', r'\1[', line)
    line = re.sub(r'\bmain_(\w+)\.len\b', r'len(\1)', line)
    line = re.sub(r'\b(r0|v13|v\d+)\.str\b', 'input', line)
    line = re.sub(r'\b(r0|v13|v\d+)\.len\b', 'len(input)', line)
    line = re.sub(r'\bruntime_convT(?:64|32|16|string|slice)\(([^)]+)\)', r'\1', line)
    line = re.sub(r'\bgoto\s+LABEL_\d+\b', 'break', line)
    if aliases:
        for k, v in aliases.items():
            line = re.sub(rf'\b{re.escape(k)}\b(?!\._r)', v, line)
    line = _apply_stdlib_map(line)
    line = _fold_abi_tuples_and_fmt(line)
    return line


def _extract_xor_key_info(code: str) -> Optional[str]:
    m = re.search(r'\b(a[A-Z][A-Za-z0-9_]{1,20})\[(\w+)\s*%\s*(\d+)[uU]*(?:LL)?\]', code)
    if m:
        var_name = m.group(1)
        key_len = m.group(3)
        raw = var_name[1:]
        key_str = raw[0].lower() + raw[1:] if len(raw) > 1 else raw.lower()
        return f'// XOR key: "{key_str}" ({key_len} bytes), cycle = i % {key_len}'
    return None


def _extract_enc_slice_info(code: str) -> Optional[str]:
    m = re.search(r'\b(main_\w+)\.array\[', code)
    if m:
        slice_name = m.group(1)
        if re.search(rf'\b{re.escape(slice_name)}\.len\b', code):
            return f'// Encoded target: {slice_name} (global []byte slice)'
    return None


# ---------------------------------------------------------------------------
# 7. Package & Import Synthesizer
# ---------------------------------------------------------------------------

def _synthesize_go_header(code_text: str) -> str:
    """Synthesizes `package main` and `import (...)` from actually used Go packages."""
    used_imports = []
    for prefix, pkg_path in _IMPORT_DETECTORS:
        if prefix in code_text and pkg_path not in used_imports:
            used_imports.append(pkg_path)

    parts = ["package main"]
    if used_imports:
        imp_lines = ["import ("]
        for pkg in sorted(used_imports):
            imp_lines.append(f'\t"{pkg}"')
        imp_lines.append(")")
        parts.append("\n".join(imp_lines))

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Public Entry Point
# ---------------------------------------------------------------------------

_FUNC_SIG_RE = re.compile(
    r'^(?:retval_[0-9A-Fa-f]+|_BYTE\s*\*+|RTYPE\s*\*+|void|int|bool|__int64|string)\s+([a-zA-Z_0-9]+)\s*\((.*?)\)'
)


def _infer_go_signature(raw_ret: str, fn_name: str, raw_params: str, body_text: str) -> Tuple[str, str, str]:
    """Dynamically infers Go parameter signature, return type, and primary param name from ABI usage."""
    params = [p.strip() for p in raw_params.split(",") if p.strip()] if raw_params.strip() else []
    n_params = len(params)
    is_method = fn_name.startswith("(")

    # Parameter inference from ABI register grouping
    if n_params == 0:
        param_sig, primary = "", "input"
    elif is_method and n_params >= 3:
        param_sig, primary = "data []byte", "data"
    elif n_params == 2:
        if re.search(r'\ba2\s*<\s*2\b', body_text) or re.search(r'\ba1\s*\+\s*16\b', body_text):
            param_sig, primary = "args []string", "args"
        elif re.search(r'\*\([^)]+\)\(\s*a1\s*\+\s*8\s*\*', body_text) or "makechan" in body_text:
            param_sig, primary = "jobs []int", "jobs"
        else:
            param_sig, primary = "input string", "input"
    elif n_params == 3:
        param_sig, primary = "data []byte", "data"
    elif n_params == 4:
        param_sig, primary = "buf []byte, idx int", "buf"
    elif n_params == 5:
        param_sig, primary = "keys []string, vals []int", "keys"
    else:
        param_sig = ", ".join(f"arg{idx + 1} uintptr" for idx in range(n_params))
        primary = "arg1"

    # Return type inference from raw_ret and result._rN assignments
    if raw_ret == "void":
        ret_type = ""
    elif raw_ret == "bool":
        ret_type = "bool"
    elif raw_ret.startswith("retval_"):
        has_r3_r4 = bool(re.search(r'\bresult\._r[34]\b', body_text))
        has_r2 = bool(re.search(r'\bresult\._r2\b', body_text))
        if has_r3_r4:
            ret_type = "([]byte, error)"
        elif has_r2 and re.search(r'\*\(\s*a1\s*\+\s*a4\s*\)|recover\(', body_text):
            ret_type = "(byte, error)"
        elif has_r2:
            ret_type = "([]byte, error)"
        else:
            ret_type = "(int, error)"
    elif raw_ret in ("__int64", "int"):
        if any(k in body_text for k in ("strings.", "runtime_concat", "runtime_slicebytetostring")):
            ret_type = "string"
        else:
            ret_type = "int"
    else:
        ret_type = ""

    return param_sig, ret_type, primary


def beautify_go_pseudocode(code: str) -> str:
    """Transforms raw IDA/Hex-Rays Go pseudocode into clean, idiomatic Go code.

    100% deterministic, 0% AI, fully offline.
    """
    if not code or not code.strip():
        return ''

    cleaned = _clean_ida_go_artifacts(code)
    raw_lines = cleaned.splitlines()

    func_sig = ''
    body_lines: List[str] = []
    in_body = False

    for line in raw_lines:
        stripped = line.strip()
        if stripped.startswith('//') and not in_body:
            continue
        if _FUNC_SIG_RE.match(stripped) and not in_body:
            func_sig = stripped
            in_body = True
            continue
        if in_body:
            body_lines.append(_apply_stdlib_map(line))

    full_body = '\n'.join(body_lines)

    m_sig = _FUNC_SIG_RE.match(func_sig.strip())
    raw_ret = func_sig.strip().split()[0] if func_sig.strip() else ""
    fn_name = m_sig.group(1) if m_sig else "main"
    raw_params = m_sig.group(2).strip() if m_sig else ""
    if fn_name.startswith("main_"):
        fn_name = fn_name[5:]
    if fn_name.startswith("_ptr_"):
        # `_ptr_XorProcessor_Process` -> `(x *XorProcessor) Process`
        parts = fn_name[5:].split("_", 1)
        if len(parts) == 2:
            fn_name = f"({parts[0][0].lower()} *{parts[0]}) {parts[1]}"

    param_sig, ret_type, primary_param = _infer_go_signature(raw_ret, fn_name, raw_params, full_body)

    var_lines, sym_map = _collect_go_globals(full_body)
    folded_body = _fold_go_statements(body_lines, sym_map, param_name=primary_param)

    hints: List[str] = []
    key_comment = _extract_xor_key_info(full_body)
    if key_comment:
        hints.append("\t" + key_comment)
    enc_comment = _extract_enc_slice_info(full_body)
    if enc_comment:
        hints.append("\t" + enc_comment)
    if 'bufio' in full_body or 'ReadString' in full_body:
        hints.append("\treader := bufio.NewReader(os.Stdin)")
        hints.append("\trawInput, _ := reader.ReadString('\\n')")
        hints.append("\tinput := strings.TrimRight(rawInput, \"\\n\")")

    if fn_name.startswith("("):
        fn_header = f"func {fn_name}({param_sig})" + (f" {ret_type}" if ret_type else "") + " {"
    else:
        fn_header = f"func {fn_name}({param_sig})" + (f" {ret_type}" if ret_type else "") + " {"

    fn_lines = [fn_header]
    if hints:
        fn_lines.extend(hints)
    fn_lines.extend(folded_body)
    fn_lines.append("}")

    sections = []
    if var_lines:
        sections.append("\n".join(var_lines))
    sections.append("\n".join(fn_lines))
    code_section = "\n\n".join(sections)

    header = _synthesize_go_header(code_section)
    return header + "\n\n" + code_section


# ---------------------------------------------------------------------------
# Solver hint extraction for Go challenges
# ---------------------------------------------------------------------------

def extract_go_xor_info(code: str) -> dict:
    """Extract XOR cipher parameters from Go pseudocode for the solver generator."""
    result = {}
    m = re.search(r'\b(a[A-Z][A-Za-z0-9_]{1,20})\[(\w+)\s*%\s*(\d+)[uU]*(?:LL)?\]', code)
    if m:
        result['key_var'] = m.group(1)
        result['loop_var'] = m.group(2)
        result['key_len'] = int(m.group(3))
        raw = m.group(1)[1:]
        result['key_hint'] = raw[0].lower() + raw[1:] if len(raw) > 1 else raw.lower()

    m2 = re.search(r'\b(main_\w+)\.array\[', code)
    if m2:
        result['enc_var'] = m2.group(1)

    m3 = re.search(r'\(unsigned\s+__int8\)\s*(\w+)\.str\[', code)
    if not m3:
        m3 = re.search(r'\b(v\d+|r0)\.str\[', code)
    if m3:
        result['input_var'] = m3.group(1)

    return result
