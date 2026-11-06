"""Conservative reference diagnostics for the pinned SkillSpector report."""

import posixpath
import re


_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
_TOKEN = re.compile(r"[0-9]?(?:>>|>|<)|[A-Za-z0-9_./:=,+%-]+|'[A-Za-z0-9_./:=,+% -]*'|\"[A-Za-z0-9_./:=,+% -]*\"")
_RESERVED = {"case", "do", "done", "elif", "else", "esac", "fi", "for", "function", "if", "in", "select", "then", "time", "until", "while"}


def _shell_outputs(lines):
    """Accept only closed, top-level shell fences containing simple commands.

    Do not infer roles from prose, option names, substitutions, here documents,
    compound commands, or other languages. Reject the entire block on ambiguity.
    """
    outputs, block, fence, shell = {}, [], None, False
    for number, line in enumerate(lines, 1):
        if fence is None:
            # HTML blocks and comments can make apparent fences literal text.
            if line.lstrip().startswith("<") or "<!--" in line:
                return {}
            opening = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", line)
            if opening and (opening[1][0] == "~" or "`" not in opening[2]):
                fence = opening[1]
                shell = opening[2].strip() in {"sh", "bash", "shell", "zsh"}
                block = []
            continue
        if re.fullmatch(r" {0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*", line):
            candidates, valid = {}, shell and sum(len(text) for _, text in block) <= 16384
            for row, text in block:
                tokens, end = [], 0
                for token in _TOKEN.finditer(text):
                    if text[end:token.start()].strip():
                        valid = False
                        break
                    if (tokens and token.start() == end
                            and not re.fullmatch(r"[0-9]?(?:>>|>|<)", tokens[-1][0])
                            and not re.fullmatch(r"[0-9]?(?:>>|>|<)", token[0])):
                        valid = False
                    tokens.append(token)
                    end = token.end()
                if text[end:].strip():
                    valid = False
                if not tokens:
                    continue
                command = tokens[0][0]
                if command in _RESERVED or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_./-]*", command):
                    valid = False
                index = 1
                while index < len(tokens):
                    token = tokens[index]
                    if re.fullmatch(r"[0-9]?(?:>>|>|<)", token[0]):
                        index += 1
                        if index == len(tokens):
                            valid = False
                            break
                        target = tokens[index]
                        value = target[0].strip("'\"")
                        if not _PATH.fullmatch(value):
                            valid = False
                        elif ">" in token[0]:
                            column = target.start() + 1 + int(target[0][0] in "'\"")
                            candidates[row, column] = value
                    index += 1
            if valid:
                outputs.update(candidates)
            fence = None
        else:
            block.append((number, line))
    return outputs


def reference_details(coverage, source_files):
    """Return bounded metadata and whether all reference gaps are proven outputs.

    Source bytes are transient. Never return evidence snippets or commands.
    Missing coordinates, unsupported syntax, and unknown reports fail closed.
    """
    references = coverage.get("references", [])
    if not isinstance(references, list) or len(references) > 1024:
        return {}, False
    sources, details, only_outputs = {}, {}, True
    for reference in references:
        if reference.get("status") not in ("missing", "ambiguous"):
            only_outputs &= reference.get("status") in ("resolved", "rejected")
            continue
        source, line, column = (reference.get(key) for key in ("source_path", "line", "column"))
        if not isinstance(source, str) or type(line) is not int or type(column) is not int:
            only_outputs = False
            continue
        if source not in sources:
            content = source_files.get(source, b"")
            try:
                lines = [line.rstrip("\r") for line in content.decode("utf-8").split("\n")] if len(content) <= 1_000_000 else []
            except UnicodeError:
                lines = []
            sources[source] = lines, _shell_outputs(lines)
        lines, outputs = sources[source]
        target, literal = "", ""
        if 0 < line <= len(lines) and 0 < column <= len(lines[line - 1]):
            text = lines[line - 1]
            candidate = _PATH.match(text, column - 1)
            if candidate and len(candidate[0]) <= 2048 and (
                candidate.end() == len(text) or text[candidate.end()] in " \t`'\")<>]"
            ):
                literal = candidate[0]
                target = posixpath.normpath(posixpath.join(posixpath.dirname(source), literal))
                if target in (".", "..") or target.startswith("../"):
                    target = ""
        generated = bool(target and reference["status"] == "missing"
                         and outputs.get((line, column)) == literal)
        only_outputs &= generated
        if generated:
            code, message = "reference_generated_output", "Generated output: this shell redirection creates the file at runtime."
        elif reference["status"] == "ambiguous":
            code, message = "reference_unresolved", "Ambiguous reference: multiple bundled files match this path."
        elif target.startswith(("node_modules/", "site-packages/")):
            code, message = "reference_external_dependency", "Dependency path is not bundled; its contents were not assessed."
        elif reference.get("reference_kind") in ("markdown_link", "markdown_image", "inline_command"):
            code, message = "reference_missing_input", "Referenced input is missing from the bundle."
        else:
            code, message = "reference_missing", "Unresolved local reference: the scanner cannot confirm whether this is an input or a generated file."
        details.setdefault((source, line), []).append({
            "code": code, "message": message, "file": source, "line": line, "target": target,
        })
    exceptions = coverage.get("ledger_exceptions", [])
    expected = set(details)
    for exception in exceptions:
        key = (exception.get("path"), exception.get("start_line"))
        if (exception.get("reason_code") != "reference_missing"
                or exception.get("phase") != "reference_resolution"
                or exception.get("outcome") != "partial" or exception.get("fatal") is not False
                or exception.get("end_line") != key[1] or key not in details):
            only_outputs = False
        expected.discard(key)
    # Reconcile the complete public accounting, not merely the reason codes.
    count = len(source_files)
    complete = bool(only_outputs and details and exceptions and not expected and count
                    and coverage.get("is_complete") is False
                    and coverage.get("status") == "partial"
                    and coverage.get("execution_successful") is True
                    and all(type(coverage.get(key)) is int and coverage[key] == count for key in (
                        "total_components", "scanned_components", "fully_inspected_files"))
                    and coverage.get("coverage_percent") == 100
                    and all(type(coverage.get(key)) is int and coverage[key] == 0 for key in (
                        "partially_inspected_files", "entirely_uninspected_files"))
                    and coverage.get("limitations") == [] and coverage.get("scope_exclusions") == [])
    return details, complete
