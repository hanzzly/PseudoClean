"""Rust / Hex-Rays Rust Pseudocode Beautifier.

Transforms raw IDA/Hex-Rays Rust decompilation into clean, readable Rust-style pseudocode.
100% deterministic, 0% AI, fully offline.

Handles common Rust decompilation artefacts:
  - pthread / libc boilerplate noise removal
  - unsigned __int8 / __int64 type annotation cleanup
  - Rust panic strings / unwrap noise removal
  - XOR loop detection and normalization
  - Multi-byte XOR key extraction hints
  - Iterator-style loop reconstruction
  - Result/Option unwrap simplification
  - str::from_utf8 / as_bytes patterns
"""

from __future__ import annotations

import re
from typing import List, Optional


# ---------------------------------------------------------------------------
# Pattern Tables
# ---------------------------------------------------------------------------

# IDA Rust runtime → clean Rust equivalents
_RUST_FUNC_MAP = [
    (r'core_panicking_panic\b',                 'panic!'),
    (r'core_panicking_panic_fmt\b',             'panic!'),
    (r'core_str_\w*_from_utf8\b',               'str::from_utf8'),
    (r'core_slice_\w*_iter\b',                  '.iter()'),
    (r'std_io_stdio_stdin\b',                   'std::io::stdin()'),
    (r'std_io_stdio_stdout\b',                  'std::io::stdout()'),
    (r'std_io_BufRead_read_line\b',             '.read_line(&mut input)'),
    (r'std_io_Write_write_all\b',               '.write_all('),
    (r'<alloc::string::String as std::fmt::Write>::write_str\b', 'write!('),
    (r'alloc_string_String_new\b',              'String::new()'),
    (r'alloc_string_String_push_str\b',         '.push_str('),
    (r'alloc_string_String_as_bytes\b',         '.as_bytes()'),
    (r'alloc_string_String_trim\b',             '.trim()'),
    (r'core_result_Result_\w+_unwrap\b',        '.unwrap()'),
    (r'core_option_Option_\w+_unwrap\b',        '.unwrap()'),
    (r'println\s*!\s*\(',                       'println!('),
    (r'print\s*!\s*\(',                         'print!('),
    (r'eprintln\s*!\s*\(',                      'eprintln!('),
]

# Lines to drop entirely (Rust binary noise)
_RUST_NOISE_PATTERNS = [
    r'pthread_key_(?:create|delete)',
    r'called\s+`Result::unwrap\(\)`\s+on\s+an\s+`Err`',
    r'internal\s+error:\s+entered\s+unreachable\s+code',
    r'unsafe\s+precondition',
    r'fatal\s+runtime\s+error',
    r'__readfsqword',
    r'prctl\s*\(',
    r'setbuf\s*\(',
    r'CC\s+CC\s+CC',                     # padding bytes shown as int3/CC
    r'^\s*//\s*REVM\s*::\s*m\d+',       # challenge banner already in comment
    r'This\s+indicates\s+a\s+bug',
]

# Rust IDA type noise declarations
_RUST_NOISE_DECLS = [
    r'^\s*unsigned\s+__int8\s+\*\s*v\d+;',
    r'^\s*__int64\s+v\d+;',
    r'^\s*char\s+\*\s*v\d+;',
    r'^\s*void\s*\*\s*v\d+;',
    r'^\s*size_t\s+v\d+;',
    r'^\s*int\s+v\d+;',
    r'^\s*bool\s+v\d+;',
    r'^\s*unsigned\s+int\s+v\d+;',
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apply_rust_func_map(line: str) -> str:
    for pat, repl in _RUST_FUNC_MAP:
        line = re.sub(pat, repl, line)
    return line


def _is_rust_noise(line: str) -> bool:
    s = line.strip()
    for pat in _RUST_NOISE_PATTERNS:
        if re.search(pat, s, re.IGNORECASE):
            return True
    return False


def _is_rust_noise_decl(line: str) -> bool:
    for pat in _RUST_NOISE_DECLS:
        if re.match(pat, line):
            return True
    return False


def _simplify_rust_types(line: str) -> str:
    """Replace C-style types with Rust equivalents in expressions."""
    line = re.sub(r'\(unsigned\s+__int8\)\s*\*?', '', line)
    line = re.sub(r'\(unsigned\s+__int16\)\s*\*?', '', line)
    line = re.sub(r'\(unsigned\s+__int32\)\s*\*?', '', line)
    line = re.sub(r'\(unsigned\s+__int64\)\s*\*?', '', line)
    line = re.sub(r'\(__int8\)\s*', '', line)
    line = re.sub(r'\(__int64\)\s*', '', line)
    line = re.sub(r'\b__int8\b', 'i8', line)
    line = re.sub(r'\b__int16\b', 'i16', line)
    line = re.sub(r'\b__int32\b', 'i32', line)
    line = re.sub(r'\b__int64\b', 'i64', line)
    line = re.sub(r'\bunsigned\s+__int8\b', 'u8', line)
    line = re.sub(r'\bunsigned\s+__int16\b', 'u16', line)
    line = re.sub(r'\bunsigned\s+__int32\b', 'u32', line)
    line = re.sub(r'\bunsigned\s+__int64\b', 'u64', line)
    return line


def _detect_xor_loop(code: str) -> Optional[str]:
    """
    Detect multi-byte XOR validation loop pattern:
      enc[i] != (input[i] ^ key[i % N])
    Returns a clean Rust code snippet or None.
    """
    # Pattern: cipher_byte != (input_byte ^ key_byte)
    m = re.search(
        r'(\w+)\[(\w+)\]\s*!=\s*\(\s*(?:[\w\[\]]+\^)?\s*(\w+)\[(\w+)\s*%\s*(\d+)\]\s*\^?\s*(?:[\w\[\]]+)?\s*\)',
        code
    )
    if m:
        enc   = m.group(1)
        idx   = m.group(2)
        key   = m.group(3)
        klen  = m.group(5)
        return (
            f'// XOR validation: enc[{idx}] != (input[{idx}] ^ {key}[{idx} % {klen}])\n'
            f'// key length = {klen} bytes\n'
            f'for ({idx}, (&enc_byte, &inp_byte)) in {enc}.iter().zip(input.as_bytes().iter()).enumerate() {{\n'
            f'    if enc_byte != inp_byte ^ key[{idx} % {klen}] {{\n'
            f'        // validation failed\n'
            f'    }}\n'
            f'}}'
        )
    return None


def _build_rust_prelude(code: str) -> List[str]:
    """Build prelude comments for a Rust validation function."""
    lines = []

    # Detect XOR key length from % N pattern
    m = re.search(r'%\s*(\d+)[uU]*(?:LL)?', code)
    if m:
        klen = int(m.group(1))
        lines.append(f'// Multi-byte XOR key length: {klen} bytes')

    # Detect ciphertext stored inline
    if 'benar' in code.lower() or 'salah' in code.lower():
        lines.append('// Challenge: REVM series - ciphertext stored in binary')
        lines.append('// Solve: brute-force XOR key or use known-plaintext attack')

    # Detect stdin read
    if 'stdin' in code or 'read_line' in code or 'scanf' in code:
        lines.append('let mut input = String::new();')
        lines.append('std::io::stdin().read_line(&mut input).unwrap();')
        lines.append('let input = input.trim();')

    return lines


# ---------------------------------------------------------------------------
# Main Beautifier
# ---------------------------------------------------------------------------

def beautify_rust_pseudocode(code: str) -> str:
    """
    Main entry: transform IDA/Hex-Rays Rust pseudocode into clean, readable form.

    100% deterministic, 0% AI, fully offline.
    """
    if not code or not code.strip():
        return ''

    raw_lines = code.splitlines()
    output: List[str] = []

    func_sig = ''
    body_lines: List[str] = []
    in_body = False

    for line in raw_lines:
        stripped = line.strip()

        # Pass through comment lines
        if stripped.startswith('//'):
            output.append(line)
            continue

        # Function header detection (strip optional calling convention like __fastcall)
        sig_check = re.sub(r'\b__(?:fastcall|cdecl|stdcall|thiscall|usercall)\b\s*', '', stripped)
        if re.match(r'^(?:__int64|void|int|bool|char\s*\*|unsigned(?:\s+__int\d+)?)\s+\w+\s*\(', sig_check) and not in_body:
            func_sig = sig_check
            in_body = True
            continue

        if in_body:
            body_lines.append(line)

    # Build clean function signature
    if func_sig:
        # Normalize common patterns
        clean_sig = re.sub(r'^__int64\s+sub_[0-9A-Fa-f]+\s*\(.*?\)',
                           'fn validate(input: &str) -> bool', func_sig)
        clean_sig = re.sub(r'^void\s+main\s*\(.*?\)',
                           'fn main()', clean_sig)
        clean_sig = _simplify_rust_types(clean_sig)
        output.append(clean_sig + ' {')

    # Prelude
    full_code = '\n'.join(body_lines)
    prelude = _build_rust_prelude(full_code)
    if prelude:
        output.append('')
        for pl in prelude:
            output.append('    ' + pl)
        output.append('')

    # Body transformation
    for line in body_lines:
        stripped = line.strip()

        # Skip noise
        if _is_rust_noise(line):
            continue
        if _is_rust_noise_decl(line):
            continue

        # Opening brace of function body
        if stripped == '{':
            continue
        # Last closing brace
        if stripped == '}' and line == body_lines[-1]:
            output.append('}')
            continue

        # Apply type simplification
        line = _simplify_rust_types(line)

        # Apply func name map
        line = _apply_rust_func_map(line)

        # Normalize XOR operator spacing
        line = re.sub(r'\s*\^\s*', ' ^ ', line)

        # Remove redundant casts: (u8)var → var
        line = re.sub(r'\(u8\)', '', line)
        line = re.sub(r'\(u64\)', '', line)

        # Normalize uLL integer literals
        line = re.sub(r'(\d+)[uU]+(?:LL)?(?=\s*[\)\],;\s])', r'\1', line)

        # goto LABEL_N → break
        line = re.sub(r'\bgoto\s+LABEL_\d+\b', 'break', line)

        # LABEL_N: → (skip)
        if re.match(r'^LABEL_\d+:', stripped):
            continue

        output.append(line)

    return '\n'.join(output)


# ---------------------------------------------------------------------------
# Solver hint extraction for Rust XOR challenges
# ---------------------------------------------------------------------------

def extract_rust_xor_info(code: str) -> dict:
    """
    Extract XOR cipher parameters from Rust pseudocode for the solver generator.

    Returns dict with keys:
      key_len     : XOR key cycle length (int)
      enc_len     : ciphertext length (int, if detectable)
      has_stdin   : bool
    """
    result = {}

    # Key length from modulo
    m = re.search(r'%\s*(\d+)[uU]*(?:LL)?', code)
    if m:
        result['key_len'] = int(m.group(1))

    # Ciphertext length from comparison
    m2 = re.search(r'==\s*(\d+)', code)
    if m2:
        result['enc_len'] = int(m2.group(1))

    result['has_stdin'] = bool(re.search(r'(stdin|read_line|scanf)', code, re.I))

    return result
