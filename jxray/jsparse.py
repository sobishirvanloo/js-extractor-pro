"""
Lightweight, linear-time helpers for reading JavaScript without a parser.

They are deliberately approximate (no full tokenizer: regex literals are not
recognised) but bounded, so hostile multi-megabyte input cannot make callers
quadratic. Shared by the chunk discovery, endpoint/param extraction and DOM
taint analysis in cli.py / dom.py.
"""
import re

_LITERAL_TERM_RE = re.compile(
    r'''"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\$]|\\.|\$(?!\{))*`'''
    r'''|-?\d+(?:\.\d+)?|null|undefined|true|false|!0|!1''')

IDENT_RE = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*")


# Jump straight to the characters that matter instead of walking every char
# in Python; string bodies are skipped by a single C-level regex match.
_EXPR_SPECIAL = re.compile(r"""["'`()\[\]{};,]""")
_STRING_BODY = {q: re.compile(q + r"(?:[^" + q + r"\\]|\\.)*" + q, re.S) for q in "\"'`"}


def scan_js_expr_span(code: str, start: int, limit: int = 2_000_000) -> tuple[str, int]:
    """
    The JS expression starting at `start`, up to the first top-level
    `;` `,` `}` or `)` (quote- and bracket-aware), and the index where it ended.
    """
    depth, i, end = 0, start, min(len(code), start + limit)
    while True:
        m = _EXPR_SPECIAL.search(code, i, end)
        if not m:
            i = end
            break
        ch, j = m.group(), m.start()
        if ch in "\"'`":
            sm = _STRING_BODY[ch].match(code, j, end)
            if not sm:                      # unterminated within the limit
                i = end
                break
            i = sm.end()
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                i = j
                break
            depth -= 1
        elif depth == 0:                    # ; or ,
            i = j
            break
        i = j + 1
    return code[start:i].strip(), i


def scan_js_expr(code: str, start: int, limit: int = 2_000_000) -> str:
    return scan_js_expr_span(code, start, limit)[0]


def split_top_level(expr: str, sep: str = "+") -> list[str]:
    """Split on `sep` at bracket depth 0, outside string literals."""
    special = re.compile(r"""["'`()\[\]{}]|""" + re.escape(sep))
    parts, depth, last, i, n = [], 0, 0, 0, len(expr)
    while True:
        m = special.search(expr, i)
        if not m:
            break
        ch, j = m.group(), m.start()
        if ch in "\"'`":
            sm = _STRING_BODY[ch].match(expr, j)
            i = sm.end() if sm else n
            continue
        if ch == sep and depth == 0:
            parts.append(expr[last:j].strip())
            last = j + 1
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        i = j + 1
    parts.append(expr[last:].strip())
    return parts


def strip_parens(term: str) -> str:
    """Remove parentheses that wrap the whole term: '((a))' -> 'a'."""
    while term.startswith("(") and term.endswith(")"):
        depth = 0
        for i, ch in enumerate(term):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0 and i < len(term) - 1:
                return term                       # '(a)+(b)' — not one wrapper
        term = term[1:-1].strip()
    return term


def is_constant_expr(expr: str) -> bool:
    """True if the expression is only string/number literals (concatenated)."""
    expr = strip_parens(expr.strip())
    if not expr:
        return True
    return all(_LITERAL_TERM_RE.fullmatch(strip_parens(t)) for t in split_top_level(expr))


def call_args_span(code: str, start: int, limit: int = 5000, max_args: int = 16) -> tuple[list[str], int]:
    """Arguments of a call whose '(' ends just before `start`, and where scanning stopped."""
    args, pos = [], start
    for _ in range(max_args):
        arg, nxt = scan_js_expr_span(code, pos, limit)
        args.append(arg)
        while nxt < len(code) and code[nxt] in " \t\r\n":
            nxt += 1
        if nxt >= len(code) or code[nxt] != ",":
            return args, nxt
        pos = nxt + 1
    return args, pos


def call_args(code: str, start: int, limit: int = 5000) -> list[str]:
    return call_args_span(code, start, limit)[0]


_BRACE_SPECIAL = re.compile(r"""["'`{}]|/[/*]""")
_LINE_STRING = {q: re.compile(q + r"(?:[^" + q + r"\\\n]|\\.)*(?:" + q + r"|\n|$)") for q in "\"'"}
_TEMPLATE = re.compile(r"`(?:[^`\\]|\\.)*(?:`|$)", re.S)


def brace_map(code: str) -> dict:
    """
    One linear pass: position of every '{' → position of its matching '}'.
    Skips '...', "...", `...` (not counting braces inside ${} — approximate)
    and // / /* */ comments. Unmatched braces are simply absent.
    """
    pairs, stack, i, n = {}, [], 0, len(code)
    while True:
        m = _BRACE_SPECIAL.search(code, i)
        if not m:
            break
        tok, j = m.group(), m.start()
        if tok in ("\"", "'"):
            i = _LINE_STRING[tok].match(code, j).end()     # plain strings can't span lines
        elif tok == "`":
            i = _TEMPLATE.match(code, j).end()
        elif tok == "//":
            k = code.find("\n", j)
            i = n if k < 0 else k
        elif tok == "/*":
            k = code.find("*/", j + 2)
            i = n if k < 0 else k + 2
        elif tok == "{":
            stack.append(j)
            i = j + 1
        else:                                               # "}"
            if stack:
                pairs[stack.pop()] = j
            i = j + 1
        if i <= j:
            i = j + 1
    return pairs


def word_re(name: str) -> re.Pattern:
    """Whole-identifier match for `name` (not a property of something else)."""
    return re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])")
