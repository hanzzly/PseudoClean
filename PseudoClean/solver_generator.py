"""Deterministic CTF Z3 Solver Generator.

Automatically extracts flag validation constraints, loop bounds, rotation/XOR/affine
transformations, and target buffer references from Hex-Rays pseudocode or IDB,
and generates a ready-to-run Python Z3 script.

Supports: C (Hex-Rays), Go (IDA Go decompilation), Rust (IDA Rust decompilation).
100% deterministic, 0% AI, fully offline.
"""

from __future__ import annotations

import re


def extract_ctf_patterns(code: str) -> dict:
    """Extracts loop bounds, input variable, target array, string literals, and transform from code."""
    data = {
        "length": 32,
        "input_var": "flag",
        "target_name": "blob",
        "target_offset": 0,
        "target_bytes": None,
        "target_string": None,
        "transform_expr": None,
        "has_rotl": False,
        "has_rotr": False,
        "affine_mul": None,
        "affine_add": None,
        "xor_key": None,
        "alt_keys": None,  # (k_odd, k_even)
        "decoded_flag": None,
    }

    # 1. Check for inlined target string literal (e.g. `strcpy(buf, "...")` or `char buf[...] = "..."`)
    m_str = re.search(r'(?:strcpy\s*\(\s*[a-zA-Z0-9_]+\s*,\s*|char\s+[a-zA-Z0-9_\[\]]+\s*=\s*)"([^"\\]*(?:\\.[^"\\]*)*)"', code)
    if m_str:
        s_raw = m_str.group(1)
        data["target_string"] = s_raw
        data["target_bytes"] = [ord(c) for c in s_raw]
        data["length"] = len(data["target_bytes"])

    # 2. Alternating keys:
    # Check PseudoClean comment first: `keys used: 0x08, 0x10`
    m_cmt = re.search(r'keys\s+used:\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)', code)
    if m_cmt:
        k1_s, k2_s = m_cmt.groups()
        k1 = int(k1_s, 16) if k1_s.startswith("0x") else int(k1_s)
        k2 = int(k2_s, 16) if k2_s.startswith("0x") else int(k2_s)
        data["alt_keys"] = (k1, k2)
    else:
        m_alt = re.search(r'key\s*=\s*\([a-zA-Z0-9_]+\s*%\s*2\s*!=\s*0\)\s*\?\s*(0x[0-9a-fA-F]+|\d+)\s*:\s*(0x[0-9a-fA-F]+|\d+)', code)
        if not m_alt:
            m_alt = re.search(
                r'if\s*\(\s*\(\s*([a-zA-Z0-9_]+)\s*&\s*1\s*\)\s*!=\s*0\s*\).*?'
                r'\^\s*(0x[0-9a-fA-F]+|\d+)\s*\).*?'
                r'else\s+if.*?\^\s*(0x[0-9a-fA-F]+|\d+)\s*\)',
                code, re.DOTALL
            )
        if m_alt:
            groups = [g for g in m_alt.groups() if g is not None]
            if len(groups) >= 2:
                k1_s = groups[-2]
                k2_s = groups[-1]
                k_odd = int(k1_s, 16) if k1_s.startswith("0x") else int(k1_s)
                k_even = int(k2_s, 16) if k2_s.startswith("0x") else int(k2_s)
                data["alt_keys"] = (k_odd, k_even)

    # 3. Loop length fallback: e.g. `i < 32` or `i < 0x20`
    m_len = re.search(r'<\s*(?:0x([0-9a-fA-F]+)|(\d+))\b', code)
    if m_len and not data["target_string"]:
        if m_len.group(1):
            data["length"] = int(m_len.group(1), 16)
        elif m_len.group(2):
            data["length"] = int(m_len.group(2))

    # 4. Input variable name
    if "flag[" in code:
        data["input_var"] = "flag"
    elif "input[" in code:
        data["input_var"] = "input"
    elif "argv[1][" in code:
        data["input_var"] = "argv1"

    # 5. Target array and offset: e.g. `blob[i + 5]` or `target[i]`
    m_tgt = re.search(r'(!=|==)\s*([a-zA-Z_0-9]+)\s*\[\s*i(?:\s*\+\s*(?:0x([0-9a-fA-F]+)|(\d+)))?\s*\]', code)
    if m_tgt:
        data["target_name"] = m_tgt.group(2)
        if m_tgt.group(3):
            data["target_offset"] = int(m_tgt.group(3), 16)
        elif m_tgt.group(4):
            data["target_offset"] = int(m_tgt.group(4))

    # 6. Rotation detection
    if "rotl8" in code:
        data["has_rotl"] = True
    elif "rotr8" in code:
        data["has_rotr"] = True

    # 7. Affine multiplier & addition: e.g. `(73 * argv[1][i] + 29)` or `((73 * flag[i]) + 29)`
    m_aff = re.search(r'(?:0x([0-9a-fA-F]+)|(\d+))\s*\*\s*([a-zA-Z0-9_\[\]]+)\s*\)?\s*\+\s*(?:0x([0-9a-fA-F]+)|(\d+))', code)
    if m_aff:
        mul = int(m_aff.group(1), 16) if m_aff.group(1) else int(m_aff.group(2))
        add = int(m_aff.group(4), 16) if m_aff.group(4) else int(m_aff.group(5))
        data["affine_mul"] = mul
        data["affine_add"] = add

    # 8. Single XOR key fallback: e.g. `^ 0xA7`
    if not data["alt_keys"]:
        m_xor = re.search(r'\^\s*(?:0x([0-9a-fA-F]+)|(\d+))\b', code)
        if m_xor:
            k = int(m_xor.group(1), 16) if m_xor.group(1) else int(m_xor.group(2))
            data["xor_key"] = k

    # 9. If target bytes and XOR keys are known, directly compute flag!
    if data["target_bytes"] and data["alt_keys"]:
        k_odd, k_even = data["alt_keys"]
        chars = [chr(c ^ (k_odd if i % 2 != 0 else k_even)) for i, c in enumerate(data["target_bytes"])]
        data["decoded_flag"] = "".join(chars)
    elif data["target_bytes"] and data["xor_key"] and not data["has_rotl"] and not data["affine_mul"]:
        k = data["xor_key"]
        chars = [chr(c ^ k) for c in data["target_bytes"]]
        data["decoded_flag"] = "".join(chars)

    return data


def read_target_bytes_from_idb(symbol_name: str, offset: int, length: int) -> list[int] | None:
    """If running inside IDA, reads target bytes from the database."""
    try:
        import ida_name
        import ida_bytes
        import idaapi

        ea = ida_name.get_name_ea(idaapi.BADADDR, symbol_name)
        if ea != idaapi.BADADDR:
            buf = ida_bytes.get_bytes(ea + offset, length)
            if buf:
                return list(buf)
    except Exception:
        pass
    return None


def generate_z3_solver(code: str, target_bytes: list[int] | None = None) -> str:
    """Generates a complete, ready-to-run Python Z3 solver script."""
    pat = extract_ctf_patterns(code)
    length = pat["length"]
    offset = pat["target_offset"]
    tgt_name = pat["target_name"]

    # Target bytes representation
    if target_bytes is None:
        if pat["target_bytes"]:
            target_bytes = pat["target_bytes"]
        else:
            target_bytes = read_target_bytes_from_idb(tgt_name, offset, length)

    if target_bytes:
        hex_bytes_str = ", ".join(f"0x{b:02X}" for b in target_bytes)
        if pat["target_string"]:
            target_block = f'# Extracted target string: "{pat["target_string"]}"\ntarget = [\n    {hex_bytes_str}\n]'
        else:
            target_block = f'# Extracted target bytes from {tgt_name}[{offset}:{offset+length}]\ntarget = [\n    {hex_bytes_str}\n]'
    else:
        target_block = f'# TODO: Copy {length} bytes from {tgt_name}[i + {offset}] in IDA View\ntarget = [0x00] * {length}  # Replace with actual bytes'

    # Direct solved flag header
    instant_solve_header = ""
    if pat["decoded_flag"]:
        instant_solve_header = (
            f"# =====================================================================\n"
            f"# [PseudoClean Instant Decryption]\n"
            f"# Flag solved directly from static ciphertext & keys:\n"
            f"# -> {pat['decoded_flag']}\n"
            f"# =====================================================================\n\n"
        )

    # Helper functions
    helpers = []
    if pat["has_rotl"]:
        helpers.append(
            "def rotl8(val, shift):\n"
            "    shift = shift % 8\n"
            "    return ((val << shift) | LShR(val, 8 - shift)) & 0xFF"
        )
    if pat["has_rotr"]:
        helpers.append(
            "def rotr8(val, shift):\n"
            "    shift = shift % 8\n"
            "    return (LShR(val, shift) | (val << (8 - shift))) & 0xFF"
        )

    # Build loop body transformation (8 spaces indent)
    transform_lines = []
    if pat["alt_keys"]:
        k_odd, k_even = pat["alt_keys"]
        transform_lines.append(f"        key = If(i % 2 != 0, BitVecVal(0x{k_odd:02X}, 8), BitVecVal(0x{k_even:02X}, 8))")
        transform_lines.append("        transformed = (flag[i] ^ key) & 0xFF")
    elif pat["affine_mul"] is not None and pat["affine_add"] is not None:
        m = pat["affine_mul"]
        a = pat["affine_add"]
        if pat["xor_key"] is not None:
            k = hex(pat["xor_key"])
            transform_lines.append(f"        transformed = (({m} * flag[i] + {a}) ^ {k}) & 0xFF")
        else:
            transform_lines.append(f"        transformed = ({m} * flag[i] + {a}) & 0xFF")
    elif pat["xor_key"] is not None:
        k = hex(pat["xor_key"])
        transform_lines.append(f"        transformed = (flag[i] ^ {k}) & 0xFF")
    else:
        transform_lines.append("        transformed = flag[i]")

    if pat["has_rotl"]:
        transform_lines.append("        rotated = rotl8(transformed, i % 8)")
        transform_lines.append("        s.add(rotated == target[i])")
    elif pat["has_rotr"]:
        transform_lines.append("        rotated = rotr8(transformed, i % 8)")
        transform_lines.append("        s.add(rotated == target[i])")
    else:
        transform_lines.append("        s.add(transformed == target[i])")

    script = f'''#!/usr/bin/env python3

from z3 import *

{instant_solve_header}{target_block}

{chr(10).join(helpers)}

def solve():
    s = Solver()
    flag = [BitVec(f"flag_{{i}}", 8) for i in range({length})]

    for i in range({length}):
        s.add(flag[i] >= 0x20, flag[i] <= 0x7E)

    for i in range({length}):
{chr(10).join(transform_lines)}

    print("[*] Solving constraints with Z3...")
    if s.check() == sat:
        m = s.model()
        solution = bytes([m[flag[i]].as_long() for i in range({length})])
        try:
            flag_str = solution.decode('utf-8')
        except UnicodeDecodeError:
            flag_str = solution.decode('latin1', 'replace')
        print(f"[+] SUCCESS! Flag: {{flag_str}}")
        return flag_str
    else:
        print("[-] UNSATISFIABLE: No valid solution found for constraints.")
        return None

if __name__ == "__main__":
    solve()
'''
    return script


def generate_solver_for_function(ea: int = 0) -> str:
    """Extracts pseudocode and generates Z3 solver for function at ea."""
    try:
        import ida_hexrays
        import ida_lines
        import ida_kernwin

        if ea == 0:
            ea = ida_kernwin.get_screen_ea()
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            return "# Hex-Rays decompile returned None for %#x\n" % ea

        raw_lines = []
        for sl in cfunc.get_pseudocode():
            raw_lines.append(ida_lines.tag_remove(sl.line))
        raw_code = "\n".join(raw_lines)
        return generate_solver_auto(raw_code)
    except Exception as exc:
        return f"# Solver generation failed: {exc}\n"


# ---------------------------------------------------------------------------
# Go XOR Solver Generator
# ---------------------------------------------------------------------------

def generate_go_xor_solver(code: str, cipher_bytes: list = None) -> str:
    """
    Generate a Python solver for Go multi-byte XOR challenges.

    Detects: main_enc global slice, aXxx key variable, XOR loop pattern.
    If cipher_bytes provided (from IDB read), generates instant-solve script.

    Example Go pseudocode pattern handled:
        for i < main_enc.len:
            if main_enc.array[i] != (aGolang[i%6] ^ v13.str[i]):
                goto LABEL_3
    """
    from go_beautifier import extract_go_xor_info
    info = extract_go_xor_info(code)

    key_len  = info.get('key_len', 4)
    key_hint = info.get('key_hint', 'unknown')
    enc_var  = info.get('enc_var', 'main_enc')
    loop_var = info.get('loop_var', 'i')

    if cipher_bytes:
        enc_len = len(cipher_bytes)
        hex_bytes_str = ", ".join(f"0x{b:02X}" for b in cipher_bytes)
        cipher_block = f"# Ciphertext extracted from {enc_var} ({enc_len} bytes)\ncipher = [\n    {hex_bytes_str}\n]"
    else:
        enc_len = 32
        cipher_block = (
            f"# TODO: Extract {enc_var}.array bytes from IDA (copy {enc_len} bytes)\n"
            f"cipher = [0x00] * {enc_len}  # Replace with actual ciphertext"
        )

    # Instant solve if cipher_bytes known and key_hint is a readable string
    instant = ""
    if cipher_bytes and key_hint and key_hint.isalpha():
        key_bytes = [ord(c) for c in key_hint]
        try:
            decrypted = "".join(
                chr(cipher_bytes[i] ^ key_bytes[i % len(key_bytes)])
                for i in range(len(cipher_bytes))
            )
            if all(0x20 <= ord(c) <= 0x7E for c in decrypted):
                instant = (
                    f"# ============================================================\n"
                    f"# [PseudoClean Go XOR Instant Solve]\n"
                    f"# Key hint = \"{key_hint}\" ({key_len} bytes)\n"
                    f"# Decrypted: {decrypted}\n"
                    f"# ============================================================\n\n"
                )
        except Exception:
            pass

    return f'''#!/usr/bin/env python3
"""Auto-generated Go XOR Solver by PseudoClean.

Challenge type : Go multi-byte XOR (REVM-style)
Key variable   : a{key_hint.capitalize()} (IDA name), cycle = {key_len} bytes
Encoder slice  : {enc_var}
"""

{instant}{cipher_block}

# XOR key - replace with actual key bytes from binary
# Hint: IDA names it "a{key_hint.capitalize()}" → likely key = b"{key_hint}"
key = b"{key_hint}"  # {key_len} bytes, cycle with i % {key_len}

def solve_instant():
    """Instant solve when key is known."""
    result = bytes(cipher[i] ^ key[i % len(key)] for i in range(len(cipher)))
    try:
        flag = result.decode("utf-8")
    except UnicodeDecodeError:
        flag = result.decode("latin1", "replace")
    print(f"[+] Flag: {{flag}}")
    return flag


def solve_bruteforce(charset=None):
    """Brute-force key if instant solve fails (single-byte key only)."""
    if charset is None:
        charset = range(0x20, 0x7F)
    for k in charset:
        result = bytes(b ^ k for b in cipher)
        try:
            s = result.decode("ascii")
            if s.startswith("SMD{{") or s.startswith("flag{{"):
                print(f"[+] key=0x{{k:02X}} ({{chr(k)!r}}): {{s}}")
        except Exception:
            pass


if __name__ == "__main__":
    solve_instant()
    # Uncomment to brute-force single-byte key:
    # solve_bruteforce()
'''


# ---------------------------------------------------------------------------
# Rust XOR Solver Generator
# ---------------------------------------------------------------------------

def generate_rust_xor_solver(code: str, cipher_bytes: list = None) -> str:
    """
    Generate a Python solver for Rust multi-byte XOR challenges (REVM m04 style).

    Detects: multi-byte XOR loop, key length from modulo, ciphertext from binary.
    """
    from rust_beautifier import extract_rust_xor_info
    info = extract_rust_xor_info(code)

    key_len = info.get('key_len', 4)
    enc_len = info.get('enc_len', len(cipher_bytes) if cipher_bytes else 27)

    if cipher_bytes:
        hex_bytes_str = ", ".join(f"0x{b:02X}" for b in cipher_bytes)
        cipher_block = f"# Ciphertext ({enc_len} bytes) embedded in binary\ncipher = [\n    {hex_bytes_str}\n]"
    else:
        cipher_block = (
            f"# TODO: Extract ciphertext bytes from binary\n"
            f"# Hint: bytes appear after '[+] benar\\n' string in .rodata\n"
            f"cipher = [0x00] * {enc_len}  # Replace with actual bytes"
        )

    return f'''#!/usr/bin/env python3
"""Auto-generated Rust Multi-byte XOR Solver by PseudoClean.

Challenge type : Rust multi-byte XOR (REVM m04 style)
Key length     : {key_len} bytes (cycle = i % {key_len})
Cipher length  : {enc_len} bytes
"""

{cipher_block}

# Flag format assumed: SMD{{...}} or similar
FLAG_PREFIX = b"SMD{{"  # Adjust if challenge uses different format


def known_plaintext_attack():
    """
    Known-plaintext attack: derive key bytes from flag prefix.
    Requires knowing first 4+ chars of plaintext (e.g. "SMD{{").
    """
    key = bytearray(b"\\x00" * {key_len})
    for i, plain_byte in enumerate(FLAG_PREFIX):
        if i < len(cipher):
            key[i % {key_len}] = cipher[i] ^ plain_byte
    print(f"[*] Derived key (from prefix): {{key.hex()}} = {{key!r}}")

    # Try decrypting with derived key
    result = bytes(cipher[i] ^ key[i % {key_len}] for i in range(len(cipher)))
    try:
        flag = result.decode("utf-8")
    except UnicodeDecodeError:
        flag = result.decode("latin1", "replace")
    print(f"[*] Decrypted: {{flag}}")
    return flag


def bruteforce_key(key_len={key_len}):
    """
    Exhaustive brute-force over all possible key combinations.
    Practical only for key_len <= 4 with known prefix constraint.
    Uses SMD{{ prefix to verify candidates.
    """
    from itertools import product
    prefix = FLAG_PREFIX
    hits = []
    for combo in product(range(0x20, 0x7F), repeat=key_len):
        key = bytes(combo)
        # Quick prefix check
        ok = all(cipher[i] ^ key[i % key_len] == prefix[i]
                 for i in range(min(len(prefix), len(cipher))))
        if ok:
            result = bytes(cipher[i] ^ key[i % key_len] for i in range(len(cipher)))
            if all(0x20 <= b <= 0x7E for b in result):
                s = result.decode("ascii", "replace")
                print(f"[+] key={{key!r}}: {{s}}")
                hits.append((key, s))
    return hits


if __name__ == "__main__":
    print("[*] Known-plaintext attack:")
    known_plaintext_attack()
    # Uncomment for brute-force (slow for key_len > 3):
    # print("\\n[*] Brute-force:")
    # bruteforce_key()
'''


# ---------------------------------------------------------------------------
# Go AES-CBC (+ Zlib) Solver Generator
# ---------------------------------------------------------------------------

def generate_go_crypto_solver(code: str) -> str:
    """Generates a Python decryptor for Go AES-CBC (+ optional zlib + PKCS#7) checks."""
    m_key = re.search(r'crypto_aes_NewCipher\s*\(\s*(?:[a-zA-Z0-9_]+:\s*)?([a-zA-Z_0-9]+)', code)
    key_sym = m_key.group(1) if m_key else "off_AES_KEY"

    m_iv = re.search(r'crypto_cipher_NewCBCEncrypter\s*\([^,]+,\s*[^,]+,\s*(?:[a-zA-Z0-9_]+:\s*)?([a-zA-Z_0-9]+)', code)
    iv_sym = m_iv.group(1) if m_iv else "off_AES_IV"

    m_exp = re.search(r'\*\(\(_BYTE\s*\*\)\s*([a-zA-Z_0-9]+)\s*\+', code)
    exp_sym = m_exp.group(1) if m_exp else "off_EXPECTED"

    has_zlib = "compress_zlib_" in code or "zlib" in code.lower()
    has_pkcs7 = ("& 0xF" in code or "& 15" in code) and "bytes_Repeat" in code

    # Try reading symbols directly from IDA if available
    key_bytes = read_target_bytes_from_idb(key_sym, 0, 32)
    iv_bytes = read_target_bytes_from_idb(iv_sym, 0, 16)
    exp_bytes = read_target_bytes_from_idb(exp_sym, 0, 64)

    key_repr = repr(bytes(key_bytes)) if key_bytes else f'b"\\x00" * 16  # TODO: read bytes from {key_sym} in IDA'
    iv_repr = repr(bytes(iv_bytes)) if iv_bytes else f'b"\\x00" * 16  # TODO: read 16 bytes from {iv_sym} in IDA'
    exp_repr = repr(bytes(exp_bytes)) if exp_bytes else f'b"\\x00" * 32  # TODO: read target bytes from {exp_sym} in IDA'

    unpad_step = (
        "    # Unpad PKCS#7\n"
        "    pad_len = padded[-1]\n"
        "    compressed = padded[:-pad_len]\n"
        if has_pkcs7 else
        "    compressed = padded\n"
    )
    zlib_step = (
        "    # Decompress zlib\n"
        "    flag = zlib.decompress(compressed).decode('utf-8', 'replace')\n"
        if has_zlib else
        "    flag = compressed.decode('utf-8', 'replace')\n"
    )

    return f'''#!/usr/bin/env python3
"""Auto-generated Go AES-CBC{' + Zlib' if has_zlib else ''} Solver by PseudoClean.

Requires: pip install pycryptodome
"""

import zlib
from Crypto.Cipher import AES

# Symbols detected from binary:
#   Key      : {key_sym}
#   IV       : {iv_sym}
#   Expected : {exp_sym}
key = {key_repr}
iv = {iv_repr}
expected = {exp_repr}


def solve():
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(expected)
{unpad_step}{zlib_step}    print(f"[+] Flag: {{flag}}")
    return flag


if __name__ == "__main__":
    solve()
'''


# ---------------------------------------------------------------------------
# Auto-detect language and dispatch
# ---------------------------------------------------------------------------

def detect_pseudocode_language(code: str) -> str:
    """
    Auto-detect pseudocode language from content.
    Returns: 'go', 'rust', or 'c'
    """
    import go_beautifier
    if go_beautifier.is_go_pseudocode(code):
        return 'go'
    # Rust indicators
    if any(x in code for x in ('core_panicking', 'alloc_string', 'pthread_key',
                                 'str::from_utf8', '__readfsqword')):
        return 'rust'
    return 'c'


def generate_solver_auto(code: str, cipher_bytes: list = None) -> str:
    """
    Auto-detect language and generate appropriate solver.
    Dispatches to generate_z3_solver (C), generate_go_crypto_solver /
    generate_go_xor_solver (Go), or generate_rust_xor_solver (Rust).
    """
    lang = detect_pseudocode_language(code)
    if lang == 'go':
        if 'crypto_aes_NewCipher' in code or 'crypto_cipher_NewCBCEncrypter' in code:
            return generate_go_crypto_solver(code)
        return generate_go_xor_solver(code, cipher_bytes)
    elif lang == 'rust':
        return generate_rust_xor_solver(code, cipher_bytes)
    else:
        return generate_z3_solver(code)
