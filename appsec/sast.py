"""Local pattern review only: parse text/AST, never import or execute source."""

import ast
import io
import os
import re
import tokenize
from pathlib import Path

from .models import finding, location

SQL_WORD = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", re.I)
SECRET_NAME = re.compile(
    r"(?:password|passwd|secret|secret_key|api_?key|access_?token|auth_?token|token)$", re.I
)
JS_LEX = re.compile(
    r"""(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)"""
)
JS_SECRET = re.compile(
    r"""(?:\b(?:const|let|var)\s+)?["']?(?P<name>[A-Za-z_$][\w$]*)["']?\s*[:=]\s*(?P<literal>"(?:\\.|[^"\\])+"|'(?:\\.|[^'\\])+'|`(?:\\.|[^`\\])+`)"""
)
IGNORE_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
RULES = {
    "sql-construction": (
        "Dynamic SQL string construction",
        "high",
        "A03:2021",
        "Injection",
        "A SQL keyword occurs in a constructed string. Data origin and database execution are not proven.",
        "Use bound query parameters for values and allowlist any dynamic identifiers.",
    ),
    "eval": (
        "Use of eval",
        "high",
        "A03:2021",
        "Injection",
        "An eval call may interpret executable input. Whether input is attacker-controlled requires manual review.",
        "Replace eval with explicit parsing or a fixed allowlist of operations; do not execute untrusted text.",
    ),
    "hardcoded-secret": (
        "Possible hardcoded secret",
        "high",
        "A07:2021",
        "Identification and Authentication Failures",
        "A secret-like name has a literal value. Determine whether it is an active credential or a harmless fixture.",
        "Remove active credentials from source, rotate any exposed value, and load secrets from an appropriate environment or secret store.",
    ),
}


def blank(value):
    return "".join("\n" if c == "\n" else " " for c in value)


def safe_source_lines(text, python):
    """Mask complete string spans before selecting lines, including multiline literals."""
    offsets, cursor = [], 0
    for line in text.splitlines(keepends=True):
        offsets.append(cursor)
        cursor += len(line)
    offsets.append(cursor)
    spans = []
    if python:
        lines = text.splitlines(keepends=True)
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.JoinedStr) or (
                isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))
            ):
                # AST columns are UTF-8 byte offsets; convert to character offsets.
                start = offsets[node.lineno - 1] + len(
                    lines[node.lineno - 1].encode()[: node.col_offset].decode()
                )
                end = offsets[node.end_lineno - 1] + len(
                    lines[node.end_lineno - 1].encode()[: node.end_col_offset].decode()
                )
                spans.append((start, end))
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                spans.append(
                    (offsets[token.start[0] - 1] + token.start[1], offsets[token.end[0] - 1] + token.end[1])
                )
    else:
        spans = [(m.start(), m.end()) for m in JS_LEX.finditer(text)]
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    for start, end in reversed(merged):
        text = text[:start] + '"[REDACTED]"' + "\n" * text[start:end].count("\n") + text[end:]
    return text.splitlines()


def literal_secret(value):
    return (
        isinstance(value, str)
        and len(value) >= 4
        and not re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", value)
    )


def python_patterns(text):
    tree = ast.parse(text)
    matches = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
            matches.add((node.lineno, "eval"))
        dynamic = (
            (isinstance(node, ast.JoinedStr) and any(isinstance(c, ast.FormattedValue) for c in node.values))
            or (isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)))
            or (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
            )
        )
        if dynamic and any(
            isinstance(c, ast.Constant) and isinstance(c.value, str) and SQL_WORD.search(c.value)
            for c in ast.walk(node)
        ):
            matches.add((node.lineno, "sql-construction"))
        pairs = []
        if isinstance(node, ast.Assign):
            pairs = [(target.id, node.value) for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            pairs = [(node.target.id, node.value)]
        elif isinstance(node, ast.Dict):
            pairs = [
                (key.value, value)
                for key, value in zip(node.keys, node.values)
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            ]
        for name, value in pairs:
            if SECRET_NAME.search(name) and isinstance(value, ast.Constant) and literal_secret(value.value):
                matches.add((value.lineno, "hardcoded-secret"))
    return matches


def javascript_patterns(text):
    no_comments = JS_LEX.sub(lambda m: blank(m[0]) if m.lastgroup == "comment" else m[0], text)
    no_strings = JS_LEX.sub(lambda m: blank(m[0]), no_comments)
    matches = set()
    for match in re.finditer(r"(?<![\w$])eval\s*\(", no_strings):
        matches.add((text.count("\n", 0, match.start()) + 1, "eval"))
    for match in JS_SECRET.finditer(no_comments):
        if (
            SECRET_NAME.search(match["name"])
            and "${" not in match["literal"]
            and literal_secret(match["literal"][1:-1])
        ):
            matches.add((text.count("\n", 0, match.start()) + 1, "hardcoded-secret"))
    for match in JS_LEX.finditer(no_comments):
        if match.lastgroup != "string" or not SQL_WORD.search(match[0]):
            continue
        tail = no_comments[match.end() :].lstrip()
        before = no_comments[: match.start()].rstrip()
        if (match[0].startswith("`") and "${" in match[0]) or tail.startswith("+") or before.endswith("+"):
            matches.add((text.count("\n", 0, match.start()) + 1, "sql-construction"))
    return matches


def source_files(root):
    if root.is_file():
        yield root
        return

    def fail(error):
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS and not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            if Path(name).suffix.lower() in (".py", ".js", ".mjs", ".cjs"):
                yield Path(directory) / name


def run_source_scan(
    source, repository, *, max_files=500, max_file_bytes=1_000_000, max_total_bytes=10_000_000
):
    supplied = Path(source).expanduser()
    if supplied.is_symlink() or not supplied.exists() or not (supplied.is_file() or supplied.is_dir()):
        raise ValueError("Source must be an explicit existing regular file or directory, not a symlink")
    root = supplied.resolve()
    if root.is_file() and root.suffix.lower() not in (".py", ".js", ".mjs", ".cjs"):
        raise ValueError("Source files must be Python or JavaScript")
    if (
        not 1 <= max_files <= 10_000
        or not 1 <= max_file_bytes <= 10_000_000
        or not 1 <= max_total_bytes <= 100_000_000
    ):
        raise ValueError("Invalid source scan bounds")
    scan_id = repository.start_scan(str(supplied), "SAST")
    errors, limitations, scanned, total = [], [], 0, 0
    try:
        for index, path in enumerate(source_files(root)):
            if index >= max_files:
                limitations.append("Source file count limit reached.")
                break
            relative = path.relative_to(root if root.is_dir() else root.parent).as_posix()
            if (
                path.is_symlink()
                or not path.is_file()
                or not path.resolve().is_relative_to(root if root.is_dir() else root.parent)
            ):
                limitations.append(f"Skipped symlink/nonregular source: {relative}")
                continue
            try:
                if path.stat().st_size > max_file_bytes:
                    limitations.append(f"Skipped oversized source: {relative}")
                    continue
                with path.open("rb") as stream:
                    raw = stream.read(max_file_bytes + 1)
                if len(raw) > max_file_bytes:
                    limitations.append(f"Source grew beyond byte limit: {relative}")
                    continue
                total += len(raw)
                if total > max_total_bytes:
                    limitations.append("Source total byte limit reached.")
                    break
                text = raw.decode("utf-8")
                patterns = (
                    python_patterns(text) if path.suffix.lower() == ".py" else javascript_patterns(text)
                )
                lines = safe_source_lines(text, path.suffix.lower() == ".py")
                # Gather snippets only after matching. Literal values are always masked.
                for line, rule in sorted(patterns):
                    title, severity, category, name, explanation, remediation = RULES[rule]
                    repository.add_finding(
                        scan_id,
                        finding(
                            "sast." + rule,
                            title,
                            location("SAST", file_path=relative, line=line, pattern_id=rule),
                            severity=severity,
                            confidence="suspected",
                            category=category,
                            name=name,
                            description=explanation
                            + " Suspected indicator; manual review required. No data-flow analysis was performed.",
                            remediation=remediation,
                            reproduction_steps=[
                                f"Review {relative} at line {line} without executing the source.",
                                "Trace data origin and usage manually; determine exploitability in the application's context.",
                            ],
                            evidence={
                                "source": lines[line - 1].strip()[:350],
                                "observations": [
                                    explanation,
                                    "Quoted source literals are withheld from evidence.",
                                ],
                                "verification": {
                                    "method": "static-pattern",
                                    "pattern_id": rule,
                                    "language": "python" if path.suffix.lower() == ".py" else "javascript",
                                    "executed": False,
                                    "data_flow_analysis": False,
                                },
                            },
                        ),
                    )
                scanned += 1
            except (
                OSError,
                UnicodeError,
                SyntaxError,
                RecursionError,
                ValueError,
                tokenize.TokenError,
            ) as exc:
                # SyntaxError text may contain entire lines and hardcoded secrets.
                errors.append(f"Cannot analyze {relative}: {type(exc).__name__}; source detail withheld.")
        if not scanned and not errors:
            limitations.append("No supported source files were analyzed.")
    except KeyboardInterrupt:
        errors.append("Source scan interrupted by operator.")
    except OSError as exc:
        errors.append(f"Source traversal failed: {type(exc).__name__}")
    finally:
        status = (
            ("partial" if scanned else "failed") if errors else ("partial" if limitations else "completed")
        )
        repository.finish_scan(scan_id, status, errors=errors, limitations=limitations)
    return scan_id
