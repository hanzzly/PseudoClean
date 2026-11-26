"""Deterministic C Pseudocode Beautifier & AST De-pyramiding Engine.

Transforms raw, deeply-nested compiler decompilation (Hex-Rays output) into
clean, idiomatic, human-readable C code without using any AI or network calls.

Architecture:
  AST Node Representation -> Multi-Pass AST Transformations -> Pretty Printer
  Pass 1: Semantic Canary & Noise Pruning
  Pass 2: Universal Guard Inversion (De-Pyramid)
  Pass 3: GOTO & Alternating Key Folding (De-Spaghetti)
  Pass 4: Sub-Expression Extraction (Breakdown Formulas)
  Pass 5: Flag / Input Aliasing
  Pass 6: Idiom & Signature Normalization
"""

from __future__ import annotations

import re
from typing import List, Optional


# ---------------------------------------------------------------------------
# AST Node Definitions
# ---------------------------------------------------------------------------

class ASTNode:
    """Base class for all C AST nodes."""
    pass


class StmtNode(ASTNode):
    pass


class ExprStmt(StmtNode):
    def __init__(self, expr: str):
        self.expr = expr.strip()

    def __repr__(self):
        return f"ExprStmt({self.expr})"


class DeclStmt(StmtNode):
    def __init__(self, type_str: str, name: str, init: Optional[str] = None):
        self.type_str = type_str.strip()
        self.name = name.strip()
        self.init = init.strip() if init else None

    def __repr__(self):
        return f"DeclStmt({self.type_str} {self.name} = {self.init})"


class ReturnStmt(StmtNode):
    def __init__(self, expr: Optional[str] = None):
        self.expr = expr.strip() if expr else None

    def __repr__(self):
        return f"ReturnStmt({self.expr})"


class GotoStmt(StmtNode):
    def __init__(self, label: str):
        self.label = label.strip()

    def __repr__(self):
        return f"GotoStmt({self.label})"


class LabelStmt(StmtNode):
    def __init__(self, name: str):
        self.name = name.strip()

    def __repr__(self):
        return f"LabelStmt({self.name}:)"


class Block(ASTNode):
    def __init__(self, stmts: Optional[List[StmtNode]] = None):
        self.stmts: List[StmtNode] = stmts or []

    def __repr__(self):
        return f"Block(count={len(self.stmts)})"


class IfStmt(StmtNode):
    def __init__(self, cond: str, then_body: Block, else_body: Optional[Block] = None):
        self.cond = cond.strip()
        self.then_body = then_body
        self.else_body = else_body

    def __repr__(self):
        return f"IfStmt({self.cond})"


class ForStmt(StmtNode):
    def __init__(self, init: str, cond: str, step: str, body: Block):
        self.init = init.strip()
        self.cond = cond.strip()
        self.step = step.strip()
        self.body = body

    def __repr__(self):
        return f"ForStmt({self.init}; {self.cond}; {self.step})"


class WhileStmt(StmtNode):
    def __init__(self, cond: str, body: Block):
        self.cond = cond.strip()
        self.body = body

    def __repr__(self):
        return f"WhileStmt({self.cond})"


class FunctionDef(ASTNode):
    def __init__(self, ret_type: str, name: str, params: str, body: Block):
        self.ret_type = ret_type.strip()
        self.name = name.strip()
        self.params = params.strip()
        self.body = body

    def __repr__(self):
        return f"FunctionDef({self.ret_type} {self.name}({self.params}))"


# ---------------------------------------------------------------------------
# Condition Inversion
# ---------------------------------------------------------------------------

def invert_condition(cond: str) -> str:
    """Deterministically inverts a C boolean expression."""
    c = cond.strip()
    if c.startswith("(") and c.endswith(")"):
        depth = 0
        balanced = True
        for ch in c[:-1]:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    balanced = False
                    break
        if balanced:
            c = c[1:-1].strip()

    if c.startswith("!"):
        inner = c[1:].strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1].strip()
        return inner

    if " && " not in c and " || " not in c:
        if " == " in c:
            parts = c.split(" == ", 1)
            return f"{parts[0].strip()} != {parts[1].strip()}"
        if " != " in c:
            parts = c.split(" != ", 1)
            return f"{parts[0].strip()} == {parts[1].strip()}"
        if " <= " in c:
            parts = c.split(" <= ", 1)
            return f"{parts[0].strip()} > {parts[1].strip()}"
        if " >= " in c:
            parts = c.split(" >= ", 1)
            return f"{parts[0].strip()} < {parts[1].strip()}"
        if " < " in c:
            parts = c.split(" < ", 1)
            return f"{parts[0].strip()} >= {parts[1].strip()}"
        if " > " in c:
            parts = c.split(" > ", 1)
            return f"{parts[0].strip()} <= {parts[1].strip()}"

    return f"!({c})"


# ---------------------------------------------------------------------------
# Lexical Pre-Cleaner
# ---------------------------------------------------------------------------

def clean_ida_artifacts(code: str) -> str:
    """Removes IDA parameter tags, stack comments, calling conventions, and redundant casts."""
    cleaned = code
    # Remove parameter name hints like `s: argv[1]`, `format: "..."`, `nilai: ...`, `option: 4`, `a1: ...`
    cleaned = re.sub(r'([\(,]\s*)[a-zA-Z_][a-zA-Z0-9_]*:\s+', r'\1', cleaned)
    # Remove calling conventions
    cleaned = re.sub(r'\b__(?:fastcall|cdecl|stdcall|thiscall|usercall)\b\s*', '', cleaned)
    # Remove register comments in declarations: `// rbx`, `// r12`
    cleaned = re.sub(r'[ \t]*//[ \t]*(?:r[a-z0-9]+|e[a-z0-9]+)\b', '', cleaned)
    # Remove stack comments: e.g. `// [rsp+14h] [rbp-Ch]` (only within the same line)
    cleaned = re.sub(r'[ \t]*//[ \t]*\[[^\n]*\]', '', cleaned)
    # Remove BYREF
    cleaned = re.sub(r'\bBYREF\b[ \t]*', '', cleaned)
    # Remove __isoc99_ prefix
    cleaned = re.sub(r'\b__isoc99_([a-zA-Z_0-9]+)\b', r'\1', cleaned)
    # Remove redundant casts like `(unsigned __int8)` or `(_BYTE)` on array indexing
    cleaned = re.sub(r'\(\s*(?:unsigned\s+__int8|_BYTE|uint8_t)\s*\)', '', cleaned)
    # Remove compound or redundant casts like `(unsigned int)((int)x)` or `(unsigned int)` on expressions
    cleaned = re.sub(r'\(\s*(?:unsigned\s+int|int|unsigned\s+__int64|__int64)\s*\)(?=\s*[\(\w])', '', cleaned)
    cleaned = re.sub(r'\(\s*(?:unsigned\s+int|int|unsigned\s+__int64|__int64)\s*\)(?=\s*[\(\w])', '', cleaned)

    # Wrap braceless if/else statements with braces for structural consistency
    pattern_if_else = re.compile(
        r'if\s*\((.+?)\)\s*\n\s*([^\{\n;]+;)\s*\n\s*else\s*\n\s*([^\{\n;]+;)',
        re.DOTALL
    )
    cleaned = pattern_if_else.sub(r'if (\1) {\n    \2\n}\nelse {\n    \3\n}', cleaned)

    pattern_if_only = re.compile(
        r'if\s*\((.+?)\)\s*\n\s*([^\{\n;]+;)(?!\s*else\b)',
        re.DOTALL
    )
    cleaned = pattern_if_only.sub(r'if (\1) {\n    \2\n}', cleaned)

    return cleaned


# ---------------------------------------------------------------------------
# Parser: C Code to AST
# ---------------------------------------------------------------------------

def _find_matching_brace(lines: List[str], start_line: int) -> int:
    depth = 0
    for idx in range(start_line, len(lines)):
        depth += lines[idx].count("{") - lines[idx].count("}")
        if depth == 0:
            return idx
    return len(lines) - 1


def parse_block_lines(lines: List[str]) -> Block:
    """Parses a list of statement lines inside a block into AST StmtNodes."""
    block = Block()
    i = 0

    while i < len(lines):
        raw_line = lines[i]
        line = raw_line.strip()
        if not line:
            i += 1
            continue

        # 1. Labels: e.g. `LABEL_5:`
        m_lbl = re.match(r'^([a-zA-Z_0-9]+):\s*$', line)
        if m_lbl:
            block.stmts.append(LabelStmt(m_lbl.group(1)))
            i += 1
            continue

        # 2. Goto: e.g. `goto LABEL_5;`
        m_goto = re.match(r'^goto\s+([a-zA-Z_0-9]+)\s*;\s*$', line)
        if m_goto:
            block.stmts.append(GotoStmt(m_goto.group(1)))
            i += 1
            continue

        # 3. Return: e.g. `return 1;` or `return;`
        m_ret = re.match(r'^return(?:\s+(.+?))?\s*;\s*$', line)
        if m_ret:
            block.stmts.append(ReturnStmt(m_ret.group(1)))
            i += 1
            continue

        # 4. If statements: `if (cond) { ... } else { ... }`
        m_if = re.match(r'^if\s*\((.+)\)\s*\{?\s*$', line)
        if m_if:
            cond = m_if.group(1).strip()
            then_open = i if "{" in line else -1
            if then_open == -1:
                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines) and "{" in lines[j]:
                    then_open = j

            if then_open != -1:
                then_close = _find_matching_brace(lines, then_open)
                then_lines = lines[then_open + 1:then_close]
                then_block = parse_block_lines(then_lines)

                # Check for else
                k = then_close + 1
                while k < len(lines) and not lines[k].strip():
                    k += 1

                else_block = None
                next_idx = then_close + 1

                if k < len(lines) and lines[k].strip().startswith("else"):
                    el_line = lines[k].strip()
                    if re.match(r'^else\s+if\s*\(', el_line):
                        # Parse `else if (...) { ... }` as a nested IfStmt inside else_block
                        sub_lines = [re.sub(r'^else\s+', '', el_line)]
                        sub_open = -1
                        if "{" in el_line:
                            sub_open = k
                        else:
                            l = k + 1
                            while l < len(lines) and not lines[l].strip():
                                l += 1
                            if l < len(lines) and "{" in lines[l]:
                                sub_open = l
                        if sub_open != -1:
                            else_close = _find_matching_brace(lines, sub_open)
                            sub_lines.extend(lines[k + 1:else_close + 1])
                            else_block = parse_block_lines(sub_lines)
                            next_idx = else_close + 1
                    else:
                        else_open = k if "{" in el_line else -1
                        if else_open == -1:
                            l = k + 1
                            while l < len(lines) and not lines[l].strip():
                                l += 1
                            if l < len(lines) and "{" in lines[l]:
                                else_open = l

                        if else_open != -1:
                            else_close = _find_matching_brace(lines, else_open)
                            else_lines = lines[else_open + 1:else_close]
                            else_block = parse_block_lines(else_lines)
                            next_idx = else_close + 1

                block.stmts.append(IfStmt(cond, then_block, else_block))
                i = next_idx
                continue

        # 5. For loops: `for (init; cond; step) { ... }`
        m_for = re.match(r'^for\s*\((.*?);(.*?);(.*?)\)\s*\{?\s*$', line)
        if m_for:
            f_init, f_cond, f_step = m_for.group(1), m_for.group(2), m_for.group(3)
            for_open = i if "{" in line else -1
            if for_open == -1:
                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines) and "{" in lines[j]:
                    for_open = j

            if for_open != -1:
                for_close = _find_matching_brace(lines, for_open)
                body_lines = lines[for_open + 1:for_close]
                body_block = parse_block_lines(body_lines)
                block.stmts.append(ForStmt(f_init, f_cond, f_step, body_block))
                i = for_close + 1
                continue

        # 6. While loops: `while (cond) { ... }`
        m_while = re.match(r'^while\s*\((.+)\)\s*\{?\s*$', line)
        if m_while:
            w_cond = m_while.group(1)
            while_open = i if "{" in line else -1
            if while_open == -1:
                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines) and "{" in lines[j]:
                    while_open = j

            if while_open != -1:
                while_close = _find_matching_brace(lines, while_open)
                body_lines = lines[while_open + 1:while_close]
                body_block = parse_block_lines(body_lines)
                block.stmts.append(WhileStmt(w_cond, body_block))
                i = while_close + 1
                continue

        # 7. Local declarations: e.g. `char buf[48];` or `int x = 5;`
        m_decl = re.match(
            r'^(const\s+)?(char|int|size_t|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t|unsigned\s+int|unsigned\s+__int64|__int64)\s+(\*+)?([a-zA-Z_0-9]+(?:\[\s*\d*\s*\])?)(?:\s*=\s*(.+?))?\s*;\s*$',
            line
        )
        if m_decl:
            t_const = m_decl.group(1) or ""
            t_base = m_decl.group(2)
            t_ptr = m_decl.group(3) or ""
            v_name = m_decl.group(4)
            v_init = m_decl.group(5)
            full_type = f"{t_const}{t_base} {t_ptr}".strip()
            block.stmts.append(DeclStmt(full_type, v_name, v_init))
            i += 1
            continue

        # 8. Generic expression statements: `printf(...);`
        if line.endswith(";"):
            block.stmts.append(ExprStmt(line[:-1].strip()))
            i += 1
            continue

        # Fallback
        block.stmts.append(ExprStmt(line))
        i += 1

    return block


def parse_function(code: str) -> FunctionDef:
    """Parses a full C function string into a FunctionDef AST."""
    cleaned = clean_ida_artifacts(code)
    lines = cleaned.splitlines()

    fn_open = -1
    for idx, l in enumerate(lines):
        if "{" in l:
            fn_open = idx
            break

    if fn_open == -1:
        # Fallback single block
        return FunctionDef("void", "unknown", "", parse_block_lines(lines))

    fn_close = _find_matching_brace(lines, fn_open)
    header_text = " ".join(lines[:fn_open + (1 if lines[fn_open].strip() != "{" else 0)])

    # Extract signature: ret_type name(params)
    m_sig = re.search(r'([a-zA-Z0-9_\*\s]+)\s+([a-zA-Z_0-9]+)\s*\((.*?)\)', header_text)
    if m_sig:
        ret_type = m_sig.group(1).strip()
        fn_name = m_sig.group(2).strip()
        params = m_sig.group(3).strip()
    else:
        ret_type = "int"
        fn_name = "main"
        params = ""

    body_lines = lines[fn_open + 1:fn_close]
    body_block = parse_block_lines(body_lines)
    return FunctionDef(ret_type, fn_name, params, body_block)


# ---------------------------------------------------------------------------
# AST Transformation Passes
# ---------------------------------------------------------------------------

def pass_prune_canaries_and_noise(fn: FunctionDef):
    """Pass 1: Prunes stack canaries (__readfsqword) and useless compiler noise."""
    new_stmts = []
    canary_names = set()

    for stmt in fn.body.stmts:
        # Detect canary assignment: `v8 = __readfsqword(0x28u);`
        if isinstance(stmt, ExprStmt) and "__readfsqword" in stmt.expr:
            m = re.match(r'^([a-zA-Z_0-9]+)\s*=', stmt.expr)
            if m:
                canary_names.add(m.group(1))
            continue

        # Detect canary declaration: `unsigned __int64 v8;`
        if isinstance(stmt, DeclStmt) and stmt.name in canary_names:
            continue

        # Detect canary check: `if (v8 != __readfsqword(0x28u)) ...`
        if isinstance(stmt, IfStmt) and "__readfsqword" in stmt.cond:
            continue

        new_stmts.append(stmt)

    # Second pass over declarations to remove declarations of identified canaries
    fn.body.stmts = [
        s for s in new_stmts
        if not (isinstance(s, DeclStmt) and s.name in canary_names)
    ]


def pass_despaghetti_gotos(block: Block):
    """Pass 2: Transforms alternating-key XOR goto-label ladders into clean ternary expressions."""
    new_stmts = []

    for stmt in block.stmts:
        if isinstance(stmt, ForStmt):
            pass_despaghetti_gotos(stmt.body)
        elif isinstance(stmt, WhileStmt):
            pass_despaghetti_gotos(stmt.body)
        elif isinstance(stmt, IfStmt):
            if stmt.then_body:
                pass_despaghetti_gotos(stmt.then_body)
            if stmt.else_body:
                pass_despaghetti_gotos(stmt.else_body)

            # Check if this IfStmt is an alternating key check: `if ((i & 1) != 0)`
            m_alt = re.search(r'\b([a-zA-Z0-9_]+)\s*&\s*1\b', stmt.cond)
            if m_alt and stmt.then_body and stmt.else_body:
                idx_var = m_alt.group(1)
                # Check then_body has `if ((input[i] ^ k1) != target[i])`
                if len(stmt.then_body.stmts) >= 1 and isinstance(stmt.then_body.stmts[0], IfStmt):
                    inner_if = stmt.then_body.stmts[0]
                    m_k1 = re.search(r'\^\s*(0x[0-9a-fA-F]+|\d+)', inner_if.cond)

                    # Check else_body has `goto` or check with `k2`
                    k2_val = None
                    if len(stmt.else_body.stmts) >= 1:
                        first_else = stmt.else_body.stmts[0]
                        if isinstance(first_else, IfStmt):
                            m_k2 = re.search(r'\^\s*(0x[0-9a-fA-F]+|\d+)', first_else.cond)
                            if m_k2:
                                k2_val = m_k2.group(1)

                    if m_k1 and k2_val:
                        k1_str = m_k1.group(1)
                        k1_num = int(k1_str, 16) if k1_str.startswith("0x") else int(k1_str)
                        k2_num = int(k2_val, 16) if k2_val.startswith("0x") else int(k2_val)
                        k1_fmt = f"0x{k1_num:02X}" if k1_num < 256 else hex(k1_num)
                        k2_fmt = f"0x{k2_num:02X}" if k2_num < 256 else hex(k2_num)

                        # Extract base comparison: replace `^ k1` with `^ key`
                        new_cond = re.sub(r'\^\s*(?:0x[0-9a-fA-F]+|\d+)', '^ key', inner_if.cond)

                        # Clean error block (remove labels)
                        err_stmts = [
                            s for s in inner_if.then_body.stmts
                            if not isinstance(s, LabelStmt)
                        ]

                        new_stmts.append(DeclStmt("uint8_t", "key", f"({idx_var} % 2 != 0) ? {k1_fmt} : {k2_fmt}"))
                        new_stmts.append(IfStmt(new_cond, Block(err_stmts), None))
                        continue

        new_stmts.append(stmt)

    block.stmts = new_stmts


def _is_error_exit_block(block: Optional[Block]) -> bool:
    """Returns True if block terminates with exit/return or prints error."""
    if not block or not block.stmts:
        return False
    # Check last statements
    for s in block.stmts[-2:]:
        if isinstance(s, ReturnStmt) or isinstance(s, GotoStmt):
            return True
        if isinstance(s, ExprStmt):
            txt = s.expr.lower()
            if any(term in txt for term in ("exit(", "abort(", "incorrect", "invalid", "error", "wrong", "fail", "[-]")):
                return True
    return False


def pass_depyramid_guard_inverter(block: Block):
    """Pass 3: Inverts error-checking if-else branches into early exits (guard clauses)."""
    new_stmts = []
    i = 0

    while i < len(block.stmts):
        stmt = block.stmts[i]

        if isinstance(stmt, ForStmt):
            pass_depyramid_guard_inverter(stmt.body)
            new_stmts.append(stmt)
            i += 1
            continue
        if isinstance(stmt, WhileStmt):
            pass_depyramid_guard_inverter(stmt.body)
            new_stmts.append(stmt)
            i += 1
            continue

        if isinstance(stmt, IfStmt):
            is_trivial_two_way_return = (
                stmt.then_body and len(stmt.then_body.stmts) == 1
                and isinstance(stmt.then_body.stmts[0], ReturnStmt)
                and stmt.else_body and len(stmt.else_body.stmts) == 1
                and isinstance(stmt.else_body.stmts[0], ReturnStmt)
                and not any(op in (stmt.then_body.stmts[0].expr or "") for op in ("<<", ">>", "|", "^", "&"))
            )
            if stmt.else_body and not is_trivial_two_way_return and _is_error_exit_block(stmt.else_body):
                # INVERT: if (!cond) { error; return 1; }
                inv_cond = invert_condition(stmt.cond)
                else_stmts = list(stmt.else_body.stmts)
                # Ensure return 1; if not present
                if not any(isinstance(s, ReturnStmt) for s in else_stmts):
                    else_stmts.append(ReturnStmt("1"))

                new_stmts.append(IfStmt(inv_cond, Block(else_stmts), None))

                # Unpack then_body statements sequentially!
                pass_depyramid_guard_inverter(stmt.then_body)
                for s in stmt.then_body.stmts:
                    new_stmts.append(s)

                i += 1
                continue

            # Recurse inside both blocks
            if stmt.then_body:
                pass_depyramid_guard_inverter(stmt.then_body)
            if stmt.else_body:
                pass_depyramid_guard_inverter(stmt.else_body)

        new_stmts.append(stmt)
        i += 1

    block.stmts = new_stmts


def _extract_repeated_bitmasks(block: Block):
    """Extracts repeated `(var & mask)` expressions (e.g. `geser & 7`) into a local variable."""
    body_text = "\n".join(emit_block(block))
    matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*&\s*(7|0x7|15|0x[fF]|31|0x1[fF]|63|0x3[fF])\b', body_text)
    if not matches:
        return

    from collections import Counter
    counts = Counter(matches)
    (var_name, mask), freq = counts.most_common(1)[0]
    if freq < 2:
        return

    is_shift = "<<" in body_text or ">>" in body_text
    alias_name = "shift" if (is_shift and "shift" not in body_text) else ("masked" if "masked" not in body_text else None)
    if not alias_name:
        return

    pat_paren = re.compile(rf'\(\s*{re.escape(var_name)}\s*&\s*{re.escape(mask)}\s*\)')
    pat_bare = re.compile(rf'\b{re.escape(var_name)}\s*&\s*{re.escape(mask)}\b')

    def _repl_expr(expr: str) -> str:
        expr = pat_paren.sub(alias_name, expr)
        expr = pat_bare.sub(alias_name, expr)
        return expr

    def _walk(b: Block):
        for s in b.stmts:
            if isinstance(s, ExprStmt):
                s.expr = _repl_expr(s.expr)
            elif isinstance(s, DeclStmt) and s.init:
                s.init = _repl_expr(s.init)
            elif isinstance(s, ReturnStmt) and s.expr:
                s.expr = _repl_expr(s.expr)
            elif isinstance(s, IfStmt):
                s.cond = _repl_expr(s.cond)
                _walk(s.then_body)
                if s.else_body:
                    _walk(s.else_body)
            elif isinstance(s, ForStmt):
                s.cond = _repl_expr(s.cond)
                _walk(s.body)
            elif isinstance(s, WhileStmt):
                s.cond = _repl_expr(s.cond)
                _walk(s.body)

    _walk(block)
    block.stmts.insert(0, DeclStmt("uint8_t", alias_name, f"{var_name} & {mask}"))


def pass_subexpression_splitting(block: Block):
    """Pass 4: Breaks down complex nested crypto / math expressions into intermediate steps."""
    _extract_repeated_bitmasks(block)
    new_stmts = []

    for stmt in block.stmts:
        if isinstance(stmt, ForStmt):
            pass_subexpression_splitting(stmt.body)
        elif isinstance(stmt, WhileStmt):
            pass_subexpression_splitting(stmt.body)
        elif isinstance(stmt, IfStmt):
            # Check for rotl / rotr in condition
            rot_match = re.search(
                r'(rotl(?:8|16|32|64)|rotr(?:8|16|32|64))\s*\(\s*(.+?)\s*,\s*(.+?)\s*\)\s*(!=|==)\s*(.+)',
                stmt.cond
            )
            if rot_match:
                fn_name = rot_match.group(1)
                arg1 = rot_match.group(2).strip()
                arg2 = rot_match.group(3).strip()
                op = rot_match.group(4)
                target = rot_match.group(5).strip()

                if re.match(r'^[a-zA-Z0-9_]+\s*&\s*7$', arg2):
                    var_sh = arg2.split("&")[0].strip()
                    arg2_clean = f"{var_sh} % 8"
                else:
                    arg2_clean = arg2

                new_stmts.append(DeclStmt("uint8_t", "transformed", arg1))
                new_stmts.append(DeclStmt("uint8_t", "rotated", f"{fn_name}(transformed, {arg2_clean})"))
                stmt.cond = f"rotated {op} {target}"

            if stmt.then_body:
                pass_subexpression_splitting(stmt.then_body)
            if stmt.else_body:
                pass_subexpression_splitting(stmt.else_body)

        new_stmts.append(stmt)

    block.stmts = new_stmts


def pass_input_aliasing(fn: FunctionDef):
    """Pass 5: Synthesizes clean input aliases like `const char *flag = argv[1];`."""
    body_text = "\n".join(emit_block(fn.body))
    if "argv[1]" in body_text:
        is_flag = "strlen" in body_text or "argv[1][" in body_text
        var_name = "flag" if is_flag else "input"

        # Find position after argc guard check
        insert_idx = 0
        for idx, stmt in enumerate(fn.body.stmts):
            if isinstance(stmt, IfStmt) and "argc" in stmt.cond:
                insert_idx = idx + 1
                break

        fn.body.stmts.insert(insert_idx, DeclStmt("const char *", var_name, "argv[1]"))

        # Replace argv[1] in subsequent statements
        def _replace_in_block(b: Block):
            for s in b.stmts:
                if isinstance(s, ExprStmt):
                    s.expr = s.expr.replace("argv[1]", var_name)
                elif isinstance(s, DeclStmt):
                    if s.init and s.name != var_name:
                        s.init = s.init.replace("argv[1]", var_name)
                elif isinstance(s, IfStmt):
                    s.cond = s.cond.replace("argv[1]", var_name)
                    _replace_in_block(s.then_body)
                    if s.else_body:
                        _replace_in_block(s.else_body)
                elif isinstance(s, ForStmt):
                    s.cond = s.cond.replace("argv[1]", var_name)
                    _replace_in_block(s.body)
                elif isinstance(s, WhileStmt):
                    s.cond = s.cond.replace("argv[1]", var_name)
                    _replace_in_block(s.body)

        _replace_in_block(fn.body)


def pass_normalize_signatures_and_idioms(fn: FunctionDef):
    """Pass 6: Normalizes function signatures and loop constructs."""
    # Main function signature
    if fn.name == "main":
        body_text = repr(fn.body)
        if "envp" not in body_text:
            fn.params = "int argc, char *argv[]"
        fn.ret_type = "int"

    # Rotate helper return & param types
    if fn.name in ("rotl8", "rotr8"):
        fn.ret_type = "uint8_t"
        fn.params = re.sub(r'\bchar\s+([a-zA-Z_0-9]+)\b', r'uint8_t \1', fn.params)
    elif fn.name in ("rotl16", "rotr16"):
        fn.ret_type = "uint16_t"
    elif fn.name in ("rotl32", "rotr32"):
        fn.ret_type = "uint32_t"

    # Inlining loop variables `for (unsigned int i = 0; i < N; i++)` and `*argv` -> `argv[0]`
    def _clean_loops(b: Block):
        for s in b.stmts:
            if isinstance(s, ExprStmt):
                s.expr = re.sub(r'(?<=[,\(\s])\*argv\b', 'argv[0]', s.expr)
            elif isinstance(s, ReturnStmt) and s.expr:
                s.expr = re.sub(r'(?<=[,\(\s])\*argv\b', 'argv[0]', s.expr)
            elif isinstance(s, ForStmt):
                # *argv -> argv[0]
                s.cond = re.sub(r'(?<=[,\(\s])\*argv\b', 'argv[0]', s.cond)
                # 0x20 -> 32
                s.cond = re.sub(r'(<|<=|==)\s*0x([0-9a-fA-F]+)\b', lambda m: f"{m.group(1)} {int(m.group(2), 16)}", s.cond)
                # inline i declaration
                if re.match(r'^i\s*=\s*0$', s.init):
                    s.init = "unsigned int i = 0"
                if "++i" in s.step:
                    s.step = s.step.replace("++i", "i++")
                _clean_loops(s.body)
            elif isinstance(s, IfStmt):
                s.cond = re.sub(r'(?<=[,\(\s])\*argv\b', 'argv[0]', s.cond)
                _clean_loops(s.then_body)
                if s.else_body:
                    _clean_loops(s.else_body)
            elif isinstance(s, WhileStmt):
                s.cond = re.sub(r'(?<=[,\(\s])\*argv\b', 'argv[0]', s.cond)
                _clean_loops(s.body)

    _clean_loops(fn.body)

    # Remove redundant empty declarations of loop variable `i`
    fn.body.stmts = [
        s for s in fn.body.stmts
        if not (isinstance(s, DeclStmt) and s.name == "i" and not s.init)
    ]


# ---------------------------------------------------------------------------
# Pretty Printer (AST -> Clean C Code)
# ---------------------------------------------------------------------------

def emit_block(block: Block, indent: int = 1) -> List[str]:
    """Pretty prints a Block into indented C statements."""
    lines = []
    sp = "    " * indent

    for stmt in block.stmts:
        if isinstance(stmt, DeclStmt):
            sep = "" if stmt.type_str.endswith("*") else " "
            if stmt.init:
                lines.append(f"{sp}{stmt.type_str}{sep}{stmt.name} = {stmt.init};")
            else:
                lines.append(f"{sp}{stmt.type_str}{sep}{stmt.name};")
        elif isinstance(stmt, ExprStmt):
            lines.append(f"{sp}{stmt.expr.rstrip(';')};")
        elif isinstance(stmt, ReturnStmt):
            if stmt.expr:
                lines.append(f"{sp}return {stmt.expr};")
            else:
                lines.append(f"{sp}return;")
        elif isinstance(stmt, LabelStmt):
            lines.append(f"{stmt.name}:")
        elif isinstance(stmt, GotoStmt):
            lines.append(f"{sp}goto {stmt.label};")
        elif isinstance(stmt, ForStmt):
            if lines:
                lines.append("")
            lines.append(f"{sp}for ({stmt.init}; {stmt.cond}; {stmt.step}) {{")
            lines.extend(emit_block(stmt.body, indent + 1))
            lines.append(f"{sp}}}")
        elif isinstance(stmt, WhileStmt):
            if lines:
                lines.append("")
            lines.append(f"{sp}while ({stmt.cond}) {{")
            lines.extend(emit_block(stmt.body, indent + 1))
            lines.append(f"{sp}}}")
        elif isinstance(stmt, IfStmt):
            if lines:
                lines.append("")
            lines.append(f"{sp}if ({stmt.cond}) {{")
            lines.extend(emit_block(stmt.then_body, indent + 1))
            if stmt.else_body and stmt.else_body.stmts:
                lines.append(f"{sp}}} else {{")
                lines.extend(emit_block(stmt.else_body, indent + 1))
            lines.append(f"{sp}}}")

    return lines


def emit_c_code(fn: FunctionDef) -> str:
    """Pretty prints a FunctionDef with headers and externs."""
    body_lines = emit_block(fn.body, indent=1)

    # Detect needed headers
    all_text = f"{fn.ret_type} {fn.name} {fn.params} " + "\n".join(body_lines)
    headers = []
    if any(k in all_text for k in ("uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int32_t")):
        headers.append("#include <stdint.h>")
    if any(k in all_text for k in ("printf", "fprintf", "puts", "stderr", "stdout", "scanf")):
        headers.append("#include <stdio.h>")
    if any(k in all_text for k in ("strlen", "memcpy", "memset", "strcpy", "strcmp")):
        headers.append("#include <string.h>")

    # Detect externs (never self-declare)
    externs = []
    if "blob[" in all_text and fn.name != "blob":
        externs.append("extern uint8_t blob[];")
    if "rotl8(" in all_text and fn.name != "rotl8":
        externs.append("uint8_t rotl8(uint8_t nilai, uint8_t geser);")
    elif "rotr8(" in all_text and fn.name != "rotr8":
        externs.append("uint8_t rotr8(uint8_t nilai, uint8_t geser);")

    prefix_parts = []
    if headers:
        prefix_parts.append("\n".join(headers))
    if externs:
        prefix_parts.append("// Deklarasi simbol eksternal dari binary\n" + "\n".join(externs))

    fn_lines = [
        f"{fn.ret_type} {fn.name}({fn.params})",
        "{"
    ]
    fn_lines.extend(body_lines)
    fn_lines.append("}")

    full_code = "\n".join(fn_lines)
    if prefix_parts:
        return "\n\n".join(prefix_parts) + "\n\n" + full_code
    return full_code


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def beautify_c_code(code: str, profile=None) -> str:
    """Transforms raw Hex-Rays pseudocode to clean C via multi-pass AST transformations.

    100% deterministic, 0% AI, fully offline.
    """
    if not code or not code.strip():
        return ""

    # Parse into AST
    fn = parse_function(code)

    # Pass 1: Semantic Canary & Noise Pruning
    pass_prune_canaries_and_noise(fn)

    # Pass 2: GOTO & Alternating Key Folding
    pass_despaghetti_gotos(fn.body)

    # Pass 3: Universal Guard Inversion (De-Pyramid)
    pass_depyramid_guard_inverter(fn.body)

    # Pass 4: Complexity Limiter (Sub-Expression Splitting)
    pass_subexpression_splitting(fn.body)

    # Pass 5: Flag / Input Aliasing
    pass_input_aliasing(fn)

    # Pass 6: Signatures & Idiom Normalization
    pass_normalize_signatures_and_idioms(fn)

    # Emit clean C
    return emit_c_code(fn)


def beautify_pseudocode_auto(code: str, profile=None) -> str:
    """Auto-detects pseudocode language (C, Go, Rust) and dispatches to the right beautifier."""
    if not code or not code.strip():
        return ""
    import go_beautifier
    if go_beautifier.is_go_pseudocode(code):
        return go_beautifier.beautify_go_pseudocode(code)
    if any(x in code for x in ("core_panicking", "alloc_string", "pthread_key", "str::from_utf8")):
        import rust_beautifier
        return rust_beautifier.beautify_rust_pseudocode(code)
    return beautify_c_code(code, profile=profile)


def beautify_function(ea: int = 0) -> str:
    """Extracts pseudocode from IDA for function at ea, and beautifies it."""
    try:
        import ida_hexrays
        import ida_lines
        import ida_kernwin

        if ea == 0:
            ea = ida_kernwin.get_screen_ea()
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            return "// Hex-Rays decompile returned None for %#x\n" % ea

        raw_lines = []
        for sl in cfunc.get_pseudocode():
            raw_lines.append(ida_lines.tag_remove(sl.line))
        raw_code = "\n".join(raw_lines)
        return beautify_pseudocode_auto(raw_code)
    except Exception as exc:
        return f"// Beautify failed: {exc}\n"
