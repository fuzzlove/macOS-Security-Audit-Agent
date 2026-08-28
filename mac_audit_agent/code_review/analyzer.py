from __future__ import annotations

import ast
import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyst_explanations import build_explanation
from .findings import CodeReviewFinding, CodeReviewReport
from .language_rules import LANGUAGES, language_for_path, scan_text
from .severity import severity_for_score, validate_cvss
from .vulnerability_db import VulnerabilityKnowledge, load_knowledge, validate_cve

IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "dist", "build",
    "__pycache__", ".mypy_cache", ".pytest_cache",
}
VENDORED_DIRECTORIES = {"MacRootKit", "BlockBlock", "OverSight", "nuclei"}
SECRET_NAME = re.compile(r"(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)", re.I)
PLACEHOLDER = re.compile(r"^(changeme|example|placeholder|test|dummy|none|null|<.*>|\$\{.*\})$", re.I)

RULES = {
    "PY-CMD-001": ("OS Command Injection Risk", "CWE-78", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PY-SQL-001": ("SQL Injection Risk", "CWE-89", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "PY-SECRET-001": ("Hardcoded Credential Material", "CWE-798", 9.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "PY-CRYPTO-001": ("Risky Cryptographic Algorithm", "CWE-327", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "PY-TLS-001": ("TLS Certificate Verification Disabled", "CWE-295", 8.1, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "PY-DESER-001": ("Unsafe Deserialization", "CWE-502", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "DEP-PIN-001": ("Dependency Version Is Not Reproducibly Pinned", "CWE-1395", 5.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"),
    "GEN-CMD-001": ("OS Command Injection Risk", "CWE-78", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "GEN-SQL-001": ("SQL Injection Risk", "CWE-89", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "GEN-SECRET-001": ("Hardcoded Credential Material", "CWE-798", 9.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "GEN-TLS-001": ("TLS Certificate Verification Disabled", "CWE-295", 8.1, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "GEN-DESER-001": ("Unsafe Deserialization", "CWE-502", 8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "GEN-CRYPTO-001": ("Risky Cryptographic Algorithm", "CWE-327", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "GEN-PATH-001": ("Path Traversal Review Candidate", "CWE-22", 8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "GEN-XSS-001": ("Cross-Site Scripting Review Candidate", "CWE-79", 8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "C-MEM-001": ("Unbounded Memory Operation", "CWE-120", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SHELL-EVAL-001": ("Dynamic Code Evaluation Risk", "CWE-78", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
}


class CodeReviewAnalyzer:
    def __init__(
        self,
        *,
        knowledge: VulnerabilityKnowledge | None = None,
        max_files: int = 5000,
        max_file_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        self.knowledge = knowledge or load_knowledge()
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes

    def scan_project(self, project_path: Path, *, cancelled=None) -> CodeReviewReport:
        project = Path(project_path).expanduser().resolve(strict=True)
        if not project.is_dir():
            raise ValueError("Code review target must be a directory.")
        started_at = datetime.now(timezone.utc).isoformat()
        findings: list[CodeReviewFinding] = []
        limitations: list[str] = [
            "Static analysis reports review candidates and does not prove attacker-controlled data reaches a sink.",
            "CVE fields remain empty unless a separate authoritative advisory match is available.",
            "Pattern rules supplement language-aware parsing and require analyst validation of data flow and reachability.",
            "Supported source languages: " + ", ".join(profile.name for profile in LANGUAGES) + ", and Python.",
            "Bundled third-party source trees are excluded when reviewing the MSAA repository root; select one directly to review it separately.",
        ]
        files_reviewed = 0
        for path in self._files(project):
            if cancelled and cancelled():
                limitations.append("Scan cancelled before all eligible files were reviewed.")
                break
            if files_reviewed >= self.max_files:
                limitations.append(f"File limit reached ({self.max_files}).")
                break
            files_reviewed += 1
            if path.suffix == ".py":
                findings.extend(self._scan_python(path, project))
            elif language_for_path(path):
                findings.extend(self._scan_language(path, project))
            elif path.name.lower() in {"requirements.txt", "requirements-dev.txt", "requirements-test.txt"}:
                findings.extend(self._scan_requirements(path, project))
        findings.sort(key=lambda item: (-item.cvss_score, item.affected_file, item.line, item.rule_id))
        return CodeReviewReport.create(
            project, started_at=started_at, files_reviewed=files_reviewed,
            findings=findings, limitations=limitations,
        )

    def _files(self, project: Path):
        for root, directories, filenames in os.walk(project, followlinks=False):
            directories[:] = [
                name for name in directories
                if name not in IGNORED_DIRECTORIES
                and name not in VENDORED_DIRECTORIES
                and not name.startswith((".venv", "venv."))
                and not (Path(root) / name).is_symlink()
            ]
            for filename in filenames:
                path = Path(root) / filename
                try:
                    if path.is_symlink() or path.stat().st_size > self.max_file_bytes:
                        continue
                except OSError:
                    continue
                if path.suffix == ".py" or language_for_path(path) or path.name.lower().startswith("requirements") and path.suffix == ".txt":
                    yield path

    def _scan_language(self, path: Path, project: Path) -> list[CodeReviewFinding]:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return []
        return [
            self._finding(
                rule_id=str(item["rule_id"]), path=path, project=project,
                line=int(item["line"]), evidence=str(item["evidence"]),
                detection_reason=str(item["reason"]), confidence=str(item["confidence"]),
                language=str(item["language"]),
            )
            for item in scan_text(path, source)
        ]

    def _scan_python(self, path: Path, project: Path) -> list[CodeReviewFinding]:
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            return []
        relative = path.relative_to(project)
        visitor = _PythonVisitor(source, suppress_fixture_secrets=("tests" in relative.parts or path.name.startswith("test_")))
        visitor.visit(tree)
        return [
            self._finding(
                rule_id=item["rule_id"], path=path, project=project, line=item["line"],
                evidence=item["evidence"], detection_reason=item["reason"], confidence=item["confidence"],
            )
            for item in visitor.matches
        ]

    def _scan_requirements(self, path: Path, project: Path) -> list[CodeReviewFinding]:
        output: list[CodeReviewFinding] = []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            return output
        for number, line in enumerate(lines, 1):
            value = line.strip()
            if not value or value.startswith(("#", "-", "git+", "https://", "file:")):
                continue
            if "==" not in value or "*" in value:
                output.append(self._finding(
                    rule_id="DEP-PIN-001", path=path, project=project, line=number,
                    evidence=value[:300],
                    detection_reason="the dependency declaration does not select an exact reproducible version. This is not a claim that the dependency has a CVE",
                    confidence="high",
                ))
        return output

    def _finding(
        self,
        *,
        rule_id: str,
        path: Path,
        project: Path,
        line: int,
        evidence: str,
        detection_reason: str,
        confidence: str,
        language: str = "Python",
    ) -> CodeReviewFinding:
        title, cwe, score, vector = RULES[rule_id]
        validate_cvss(score, vector)
        enrichment = build_explanation(
            cwe=cwe, title=title, detection_reason=detection_reason, knowledge=self.knowledge,
        )
        references = list(enrichment["references"])
        for reference in (
            {"source": "FIRST CVSS v3.1", "url": "https://www.first.org/cvss/v3-1/specification-document"},
            {"source": "NVD vulnerability and CVE context", "url": "https://nvd.nist.gov/"},
            {"source": "NIST Secure Software Development Framework", "url": "https://csrc.nist.gov/pubs/sp/800/218/final"},
            {"source": "CISA Secure by Design", "url": "https://www.cisa.gov/securebydesign"},
        ):
            if reference["url"] not in {item["url"] for item in references}:
                references.append(reference)
        relative = str(path.relative_to(project))
        digest = hashlib.sha256(f"{rule_id}:{relative}:{line}:{evidence}".encode()).hexdigest()[:16]
        return CodeReviewFinding(
            finding_id=f"CODE-{digest}", rule_id=rule_id, title=title,
            severity=severity_for_score(score), cvss_score=score, cvss_vector=vector,
            confidence=confidence, cwe=cwe, cve=validate_cve(None),
            mitre_attack=tuple(enrichment["mitre_attack"]),
            description=enrichment["description"],
            analyst_explanation=enrichment["analyst_explanation"],
            impact=dict(enrichment["impact"]),
            exploitability=dict(enrichment["exploitability"]),
            detection_reason=detection_reason,
            remediation=dict(enrichment["remediation"]),
            references=tuple(references),
            affected_file=relative, line=line, evidence=evidence[:500],
            compliance=dict(enrichment["compliance"]),
            language=language,
        )


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, source: str, *, suppress_fixture_secrets: bool = False) -> None:
        self.source = source
        self.matches: list[dict[str, Any]] = []
        self._tainted: list[set[str]] = [set()]
        self.suppress_fixture_secrets = suppress_fixture_secrets

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        parameters = {item.arg for item in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
        if node.args.vararg: parameters.add(node.args.vararg.arg)
        if node.args.kwarg: parameters.add(node.args.kwarg.arg)
        self._tainted.append(parameters)
        for statement in node.body: self.visit(statement)
        self._tainted.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if name in {"os.system", "os.popen"} and node.args and not _literal(node.args[0]):
            self._add(node, "PY-CMD-001", "a non-literal value reaches an operating-system command API", "high")
        if name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}:
            shell_true = any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
            if shell_true:
                self._add(node, "PY-CMD-001", "subprocess enables shell interpretation, so metacharacters in constructed input may become directives", "high")
        if (name.endswith((".execute", ".executemany")) and node.args
                and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp))
                and _expression_is_tainted(node.args[0], self._tainted[-1])):
            self._add(node, "PY-SQL-001", "SQL text is constructed dynamically instead of being passed with bound parameters", "high")
        if name in {"hashlib.md5", "hashlib.sha1"}:
            self._add(node, "PY-CRYPTO-001", f"{name} is used and may be unsuitable for a security-sensitive integrity or credential purpose", "medium")
        if name in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads"}:
            self._add(node, "PY-DESER-001", f"{name} can construct attacker-influenced objects from serialized content", "high")
        if name == "yaml.load" and not any(keyword.arg == "Loader" for keyword in node.keywords):
            self._add(node, "PY-DESER-001", "yaml.load is used without an explicit safe loader", "high")
        if name.startswith(("requests.", "httpx.")) and any(
            keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            for keyword in node.keywords
        ):
            self._add(node, "PY-TLS-001", "the request explicitly disables TLS certificate verification", "high")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        value = _string_literal(node.value)
        if not self.suppress_fixture_secrets and value and len(value) >= 8 and not PLACEHOLDER.fullmatch(value):
            for target in node.targets:
                if isinstance(target, ast.Name) and SECRET_NAME.search(target.id):
                    self._add(node, "PY-SECRET-001", f"a string literal is assigned to credential-like variable '{target.id}'", "high")
                    break
        tainted = _expression_is_tainted(node.value, self._tainted[-1])
        for target in node.targets:
            if isinstance(target, ast.Name):
                if tainted: self._tainted[-1].add(target.id)
                else: self._tainted[-1].discard(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        value = _string_literal(node.value)
        if not self.suppress_fixture_secrets and isinstance(node.target, ast.Name) and value and len(value) >= 8 and SECRET_NAME.search(node.target.id) and not PLACEHOLDER.fullmatch(value):
            self._add(node, "PY-SECRET-001", f"a string literal is assigned to credential-like variable '{node.target.id}'", "high")
        self.generic_visit(node)

    def _add(self, node: ast.AST, rule_id: str, reason: str, confidence: str) -> None:
        segment = ast.get_source_segment(self.source, node) or node.__class__.__name__
        self.matches.append({
            "rule_id": rule_id, "line": int(getattr(node, "lineno", 1)),
            "evidence": segment.replace("\n", " ")[:500], "reason": reason, "confidence": confidence,
        })


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _string_literal(node: ast.AST | None) -> str:
    return str(node.value) if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _expression_is_tainted(node: ast.AST, tainted: set[str]) -> bool:
    if isinstance(node, ast.Call) and _call_name(node.func).endswith("_sql_identifier"):
        return False
    return any(isinstance(item, ast.Name) and item.id in tainted for item in ast.walk(node))


__all__ = ["CodeReviewAnalyzer", "RULES"]
