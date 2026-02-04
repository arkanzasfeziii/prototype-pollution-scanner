#!/usr/bin/env python3
"""
Prototype Pollution Scanner - Static analysis tool for detecting Prototype Pollution in Node.js.

This tool performs comprehensive static analysis of JavaScript/TypeScript code to identify
prototype pollution vulnerabilities, unsafe patterns, and vulnerable dependencies.

Author: arkanzasfeziii
License: MIT
"""

# === Imports ===
import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, field_validator
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

# === Constants ===
VERSION = "1.0.0"
AUTHOR = "arkanzasfeziii"
TOOL_NAME = "Prototype Pollution Scanner"

# Legal and security warning
SECURITY_WARNING = """
⚠️  SECURITY NOTICE ⚠️

This tool performs STATIC ANALYSIS only and may produce false positives/negatives.
It is designed for authorized security testing and code review ONLY.

Important limitations:
- Static analysis cannot detect all runtime vulnerabilities
- Manual review and dynamic testing are essential
- Always combine with comprehensive security auditing

By using this tool, you acknowledge that:
- This is for authorized code review and security testing
- You understand its limitations
- The author (arkanzasfeziii) assumes NO LIABILITY for misuse or undetected vulnerabilities

"""

# File extensions to scan
SCANNABLE_EXTENSIONS = {'.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'}

# Default ignore patterns
DEFAULT_IGNORE_PATTERNS = [
    r'node_modules',
    r'\.git',
    r'dist',
    r'build',
    r'coverage',
    r'\.min\.js$',
    r'\.bundle\.js$',
]

# Known vulnerable packages and versions
VULNERABLE_PACKAGES = {
    'lodash': {
        'vulnerable_versions': '<4.17.12',
        'cve': ['CVE-2019-10744', 'CVE-2020-8203'],
        'description': 'Prototype pollution in defaultsDeep, merge, etc.'
    },
    'minimist': {
        'vulnerable_versions': '<1.2.6',
        'cve': ['CVE-2020-7598', 'CVE-2021-44906'],
        'description': 'Prototype pollution via constructor/proto payloads'
    },
    'yargs-parser': {
        'vulnerable_versions': '<13.1.2 || >=14.0.0 <15.0.1 || >=16.0.0 <18.1.1',
        'cve': ['CVE-2020-7608'],
        'description': 'Prototype pollution in setKey function'
    },
    'merge': {
        'vulnerable_versions': '<2.1.1',
        'cve': ['CVE-2020-28499'],
        'description': 'Prototype pollution in merge function'
    },
    'deep-extend': {
        'vulnerable_versions': '<0.5.1',
        'cve': ['CVE-2018-3750'],
        'description': 'Prototype pollution in deep-extend'
    },
    'assign-deep': {
        'vulnerable_versions': '<1.0.1',
        'cve': ['CVE-2020-28282'],
        'description': 'Prototype pollution in assign-deep'
    },
    'merge-options': {
        'vulnerable_versions': '<3.0.3',
        'cve': ['CVE-2020-28281'],
        'description': 'Prototype pollution via constructor payload'
    },
    'dot-prop': {
        'vulnerable_versions': '<5.1.1',
        'cve': ['CVE-2020-8116'],
        'description': 'Prototype pollution in set function'
    },
    'set-value': {
        'vulnerable_versions': '<2.0.1 || >=3.0.0 <4.0.1',
        'cve': ['CVE-2021-23440'],
        'description': 'Prototype pollution in setPath function'
    },
}

# Dangerous patterns for prototype pollution
DANGEROUS_PATTERNS = {
    'direct_proto_assignment': {
        'pattern': r'(__proto__|constructor\.prototype|\[(["\'])__proto__\2\])\s*=',
        'severity': 'CRITICAL',
        'description': 'Direct __proto__ or constructor.prototype assignment',
        'examples': ['obj.__proto__ = {}', 'obj["__proto__"] = value']
    },
    'object_assign_user_input': {
        'pattern': r'Object\.assign\([^,]+,\s*(?:req\.|user\.|input\.|params\.|query\.|body\.)',
        'severity': 'HIGH',
        'description': 'Object.assign with potential user input',
        'examples': ['Object.assign({}, req.body)', 'Object.assign(config, userInput)']
    },
    'unsafe_merge': {
        'pattern': r'(merge|extend|deepExtend|assign)\([^)]*(?:req\.|user\.|input\.|params\.|query\.|body\.)',
        'severity': 'HIGH',
        'description': 'Unsafe merge/extend operation with user input',
        'examples': ['merge(obj, req.body)', '_.extend(config, userInput)']
    },
    'lodash_merge_vulnerable': {
        'pattern': r'_\.(merge|mergeWith|defaultsDeep)\s*\(',
        'severity': 'MEDIUM',
        'description': 'Lodash merge operations (check version for vulnerabilities)',
        'examples': ['_.merge(obj, data)', '_.defaultsDeep(target, source)']
    },
    'json_parse_reviver_proto': {
        'pattern': r'JSON\.parse\([^,]+,\s*function.*__proto__',
        'severity': 'HIGH',
        'description': 'JSON.parse with reviver accessing __proto__',
        'examples': ['JSON.parse(str, (k, v) => k === "__proto__" ? v : undefined)']
    },
    'recursive_merge_no_check': {
        'pattern': r'function\s+\w*merge\w*\s*\([^)]*\)\s*{[^}]*for\s*\([^)]*in[^)]*\)',
        'severity': 'MEDIUM',
        'description': 'Custom merge function without prototype pollution checks',
        'examples': ['function merge(a, b) { for (let key in b) { a[key] = b[key]; } }']
    },
    'bracket_notation_proto': {
        'pattern': r'\[["\'](__proto__|constructor|prototype)["\']\]',
        'severity': 'MEDIUM',
        'description': 'Bracket notation accessing dangerous properties',
        'examples': ['obj["__proto__"]', 'target["constructor"]']
    },
    'vm_context_pollution': {
        'pattern': r'vm\.(createContext|runInContext|runInNewContext)',
        'severity': 'MEDIUM',
        'description': 'VM context usage (potential for pollution)',
        'examples': ['vm.runInContext(code, context)']
    },
}

# Safe coding patterns (for recommendations)
SAFE_PATTERNS = {
    'object_create_null': r'Object\.create\(null\)',
    'map_usage': r'new Map\(\)',
    'has_own_property_check': r'hasOwnProperty\(',
    'object_freeze': r'Object\.freeze\(',
    'object_seal': r'Object\.seal\(',
}

# === Enums ===
class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnerabilityType(Enum):
    """Types of prototype pollution vulnerabilities."""
    DIRECT_POLLUTION = "Direct Prototype Pollution"
    UNSAFE_MERGE = "Unsafe Merge Operation"
    VULNERABLE_DEPENDENCY = "Vulnerable Dependency"
    UNSAFE_JSON_PARSE = "Unsafe JSON Parsing"
    MISSING_SAFEGUARDS = "Missing Safeguards"
    GADGET_CHAIN = "Potential Gadget Chain"

# === Data Models ===
@dataclass
class Finding:
    """Represents a security finding."""
    title: str
    severity: Severity
    vuln_type: VulnerabilityType
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: int = 0  # 0-100
    mitigation: Optional[str] = None
    cve: Optional[List[str]] = None
    references: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "vulnerability_type": self.vuln_type.value,
            "description": self.description,
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "confidence": self.confidence,
            "mitigation": self.mitigation,
            "cve": self.cve,
            "references": self.references,
            "timestamp": self.timestamp.isoformat()
        }

@dataclass
class ScanResult:
    """Container for all scan results."""
    scan_path: str
    scan_start: datetime
    scan_end: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    vulnerable_dependencies: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to results."""
        self.findings.append(finding)

    def get_summary(self) -> Dict[str, int]:
        """Get summary statistics."""
        summary = {
            "total": len(self.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "files_scanned": self.files_scanned,
            "vulnerable_deps": len(self.vulnerable_dependencies)
        }
        for finding in self.findings:
            severity_key = finding.severity.value.lower()
            if severity_key in summary:
                summary[severity_key] += 1
        return summary

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "scan_path": self.scan_path,
            "scan_start": self.scan_start.isoformat(),
            "scan_end": self.scan_end.isoformat() if self.scan_end else None,
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings],
            "vulnerable_dependencies": self.vulnerable_dependencies,
            "files_scanned": self.files_scanned,
            "metadata": self.metadata
        }

# === Utility Functions ===
def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Configure logging for the application.

    Args:
        verbose: Enable verbose logging

    Returns:
        Configured logger instance
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('prototypepollutionscan.log'),
            logging.StreamHandler(sys.stderr) if verbose else logging.NullHandler()
        ]
    )
    return logging.getLogger(__name__)

def should_ignore_path(path: Path, ignore_patterns: List[str]) -> bool:
    """
    Check if path should be ignored based on patterns.

    Args:
        path: Path to check
        ignore_patterns: List of regex patterns to ignore

    Returns:
        True if should be ignored
    """
    path_str = str(path)
    for pattern in ignore_patterns:
        if re.search(pattern, path_str):
            return True
    return False

def parse_version(version_str: str) -> Optional[Tuple[int, ...]]:
    """
    Parse semantic version string.

    Args:
        version_str: Version string (e.g., "1.2.3")

    Returns:
        Tuple of version numbers or None
    """
    try:
        # Remove ^ ~ >= etc.
        clean_version = re.sub(r'[^0-9.]', '', version_str.split()[0])
        parts = clean_version.split('.')
        return tuple(int(p) for p in parts if p.isdigit())
    except Exception:
        return None

def is_version_vulnerable(current: str, vulnerable_spec: str) -> bool:
    """
    Check if current version matches vulnerable specification.

    Args:
        current: Current version string
        vulnerable_spec: Vulnerability specification (e.g., "<4.17.12")

    Returns:
        True if version is vulnerable
    """
    current_ver = parse_version(current)
    if not current_ver:
        return False

    # Simple comparison for common patterns
    if vulnerable_spec.startswith('<'):
        target_ver = parse_version(vulnerable_spec[1:])
        if target_ver:
            return current_ver < target_ver
    elif vulnerable_spec.startswith('>='):
        target_ver = parse_version(vulnerable_spec[2:])
        if target_ver:
            return current_ver >= target_ver
    elif vulnerable_spec.startswith('<='):
        target_ver = parse_version(vulnerable_spec[2:])
        if target_ver:
            return current_ver <= target_ver

    # For complex ranges, be conservative
    return True

# === Vulnerability Detection ===
class CodeAnalyzer:
    """Analyzes code for prototype pollution vulnerabilities."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize code analyzer.

        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """
        Analyze a single file for vulnerabilities.

        Args:
            file_path: Path to file to analyze

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # Check each dangerous pattern
            for pattern_name, pattern_info in DANGEROUS_PATTERNS.items():
                regex = re.compile(pattern_info['pattern'], re.MULTILINE)
                for match in regex.finditer(content):
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    code_line = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    # Calculate confidence
                    confidence = self._calculate_confidence(pattern_name, code_line, content)

                    finding = Finding(
                        title=f"Prototype Pollution: {pattern_info['description']}",
                        severity=Severity[pattern_info['severity']],
                        vuln_type=self._get_vuln_type(pattern_name),
                        description=pattern_info['description'],
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=code_line,
                        confidence=confidence,
                        mitigation=self._get_mitigation(pattern_name),
                        references=[
                            "https://portswigger.net/web-security/prototype-pollution",
                            "https://owasp.org/www-community/vulnerabilities/Prototype_Pollution"
                        ]
                    )
                    findings.append(finding)

        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")

        return findings

    def _calculate_confidence(self, pattern_name: str, code_line: str, full_content: str) -> int:
        """
        Calculate confidence score for a finding.

        Args:
            pattern_name: Name of the detected pattern
            code_line: The code line with the issue
            full_content: Full file content

        Returns:
            Confidence score (0-100)
        """
        confidence = 50  # Base confidence

        # Increase confidence for direct proto assignment
        if pattern_name == 'direct_proto_assignment':
            confidence = 95

        # Check for safe patterns nearby
        safe_pattern_count = sum(
            1 for pattern in SAFE_PATTERNS.values()
            if re.search(pattern, full_content)
        )

        if safe_pattern_count > 0:
            confidence -= 10

        # Check for validation/sanitization keywords
        validation_keywords = ['validate', 'sanitize', 'check', 'filter', 'whitelist']
        if any(keyword in full_content.lower() for keyword in validation_keywords):
            confidence -= 15

        # Ensure confidence is in valid range
        return max(10, min(100, confidence))

    def _get_vuln_type(self, pattern_name: str) -> VulnerabilityType:
        """
        Get vulnerability type based on pattern name.

        Args:
            pattern_name: Pattern name

        Returns:
            Vulnerability type
        """
        type_mapping = {
            'direct_proto_assignment': VulnerabilityType.DIRECT_POLLUTION,
            'object_assign_user_input': VulnerabilityType.UNSAFE_MERGE,
            'unsafe_merge': VulnerabilityType.UNSAFE_MERGE,
            'lodash_merge_vulnerable': VulnerabilityType.UNSAFE_MERGE,
            'json_parse_reviver_proto': VulnerabilityType.UNSAFE_JSON_PARSE,
            'recursive_merge_no_check': VulnerabilityType.MISSING_SAFEGUARDS,
        }
        return type_mapping.get(pattern_name, VulnerabilityType.DIRECT_POLLUTION)

    def _get_mitigation(self, pattern_name: str) -> str:
        """
        Get mitigation recommendation.

        Args:
            pattern_name: Pattern name

        Returns:
            Mitigation string
        """
        mitigations = {
            'direct_proto_assignment': (
                "Never directly assign to __proto__ or constructor.prototype. "
                "Use Object.create(null) for objects without prototype, "
                "or use Map instead of plain objects for user-controlled keys."
            ),
            'object_assign_user_input': (
                "Validate and sanitize user input before using with Object.assign. "
                "Use Object.create(null) for the target, check for dangerous keys (__proto__, constructor, prototype), "
                "or use a safe merge library with pollution protection."
            ),
            'unsafe_merge': (
                "Use a safe merge/extend function that checks for __proto__, constructor, and prototype. "
                "Update vulnerable libraries to patched versions. "
                "Consider using Object.assign with Object.create(null) or implement strict key validation."
            ),
            'lodash_merge_vulnerable': (
                "Update lodash to version 4.17.12 or later. "
                "Use _.mergeWith with a customizer that blocks dangerous keys, "
                "or use Object.assign with validated inputs."
            ),
            'json_parse_reviver_proto': (
                "Do not access __proto__ in JSON.parse reviver functions. "
                "If you need to filter properties, use Object.create(null) and copy safe properties explicitly."
            ),
            'recursive_merge_no_check': (
                "Add checks in custom merge functions: "
                "if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue; "
                "Consider using Object.hasOwnProperty to avoid prototype chain iteration."
            ),
        }
        return mitigations.get(pattern_name, "Review code and implement prototype pollution protection.")

class DependencyAnalyzer:
    """Analyzes project dependencies for known vulnerabilities."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize dependency analyzer.

        Args:
            logger: Logger instance
        """
        self.logger = logger or logging.getLogger(__name__)

    def analyze_package_json(self, package_json_path: Path) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Analyze package.json for vulnerable dependencies.

        Args:
            package_json_path: Path to package.json

        Returns:
            Tuple of (findings, vulnerable_deps_dict)
        """
        findings = []
        vulnerable_deps = {}

        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)

            all_deps = {}
            all_deps.update(package_data.get('dependencies', {}))
            all_deps.update(package_data.get('devDependencies', {}))

            for pkg_name, version in all_deps.items():
                if pkg_name in VULNERABLE_PACKAGES:
                    vuln_info = VULNERABLE_PACKAGES[pkg_name]

                    if is_version_vulnerable(version, vuln_info['vulnerable_versions']):
                        vulnerable_deps[pkg_name] = {
                            'current_version': version,
                            'vulnerable_spec': vuln_info['vulnerable_versions'],
                            'cve': vuln_info['cve'],
                            'description': vuln_info['description']
                        }

                        finding = Finding(
                            title=f"Vulnerable Dependency: {pkg_name}",
                            severity=Severity.HIGH,
                            vuln_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                            description=vuln_info['description'],
                            file_path=str(package_json_path),
                            line_number=0,
                            code_snippet=f'"{pkg_name}": "{version}"',
                            confidence=90,
                            mitigation=f"Update {pkg_name} to a non-vulnerable version. Check npm audit or Snyk for recommended versions.",
                            cve=vuln_info['cve'],
                            references=[
                                f"https://security.snyk.io/package/npm/{pkg_name}",
                                "https://github.com/advisories"
                            ]
                        )
                        findings.append(finding)

        except FileNotFoundError:
            self.logger.warning(f"package.json not found at {package_json_path}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in package.json: {e}")
        except Exception as e:
            self.logger.error(f"Error analyzing package.json: {e}")

        return findings, vulnerable_deps

# === Core Scanner ===
class PrototypePollutionScanner:
    """Main scanner class."""

    def __init__(
        self,
        scan_path: Path,
        include_node_modules: bool = False,
        deep_scan: bool = False,
        ignore_patterns: Optional[List[str]] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize scanner.

        Args:
            scan_path: Path to scan
            include_node_modules: Include node_modules in scan
            deep_scan: Enable deep scanning
            ignore_patterns: Additional ignore patterns
            logger: Logger instance
        """
        self.scan_path = scan_path
        self.include_node_modules = include_node_modules
        self.deep_scan = deep_scan
        self.logger = logger or logging.getLogger(__name__)

        self.ignore_patterns = DEFAULT_IGNORE_PATTERNS.copy()
        if not include_node_modules and 'node_modules' not in str(self.ignore_patterns):
            self.ignore_patterns.append(r'node_modules')
        if ignore_patterns:
            self.ignore_patterns.extend(ignore_patterns)

        self.result = ScanResult(scan_path=str(scan_path), scan_start=datetime.now())
        self.code_analyzer = CodeAnalyzer(logger=logger)
        self.dep_analyzer = DependencyAnalyzer(logger=logger)

    def find_files_to_scan(self) -> List[Path]:
        """
        Find all files to scan.

        Returns:
            List of file paths
        """
        files_to_scan = []

        if self.scan_path.is_file():
            if self.scan_path.suffix in SCANNABLE_EXTENSIONS:
                files_to_scan.append(self.scan_path)
        else:
            for ext in SCANNABLE_EXTENSIONS:
                for file_path in self.scan_path.rglob(f'*{ext}'):
                    if not should_ignore_path(file_path, self.ignore_patterns):
                        files_to_scan.append(file_path)

        return files_to_scan

    def scan(self, console: Console) -> ScanResult:
        """
        Run the scan.

        Args:
            console: Rich console for output

        Returns:
            Scan results
        """
        console.print("[cyan]Starting prototype pollution scan...[/cyan]\n")

        # Find files
        console.print("[cyan]Discovering files...[/cyan]")
        files_to_scan = self.find_files_to_scan()
        self.result.files_scanned = len(files_to_scan)

        console.print(f"[cyan]Found {len(files_to_scan)} files to scan[/cyan]\n")

        # Scan package.json for vulnerable dependencies
        package_json = self.scan_path / 'package.json' if self.scan_path.is_dir() else None
        if package_json and package_json.exists():
            console.print("[cyan]Analyzing dependencies...[/cyan]")
            dep_findings, vulnerable_deps = self.dep_analyzer.analyze_package_json(package_json)
            for finding in dep_findings:
                self.result.add_finding(finding)
            self.result.vulnerable_dependencies = vulnerable_deps

        # Scan code files
        console.print("[cyan]Scanning code files...[/cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Analyzing files...", total=len(files_to_scan))

            for file_path in files_to_scan:
                findings = self.code_analyzer.analyze_file(file_path)
                for finding in findings:
                    self.result.add_finding(finding)

                progress.advance(task)

        self.result.scan_end = datetime.now()
        return self.result

# === Reporting ===
class Reporter:
    """Handles result reporting."""

    @staticmethod
    def print_console_report(result: ScanResult, console: Console) -> None:
        """
        Print results to console.

        Args:
            result: Scan results
            console: Rich console instance
        """
        console.print()
        duration = (result.scan_end - result.scan_start).total_seconds() if result.scan_end else 0

        console.print(Panel.fit(
            f"[bold cyan]Scan Complete[/bold cyan]\n"
            f"Path: {result.scan_path}\n"
            f"Duration: {duration:.2f}s\n"
            f"Files Scanned: {result.files_scanned}",
            border_style="cyan"
        ))

        # Summary
        summary = result.get_summary()
        console.print()
        console.print("[bold]Summary:[/bold]")

        summary_table = Table(show_header=True, header_style="bold magenta")
        summary_table.add_column("Severity", style="cyan", width=12)
        summary_table.add_column("Count", justify="right", style="yellow", width=8)

        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "green"
        }

        for severity in ["critical", "high", "medium", "low", "info"]:
            count = summary.get(severity, 0)
            color = severity_colors.get(severity, "white")
            summary_table.add_row(
                f"[{color}]{severity.upper()}[/{color}]",
                f"[{color}]{count}[/{color}]"
            )

        console.print(summary_table)

        # Vulnerable dependencies
        if result.vulnerable_dependencies:
            console.print(f"\n[bold red]Vulnerable Dependencies: {len(result.vulnerable_dependencies)}[/bold red]")
            for pkg, info in result.vulnerable_dependencies.items():
                console.print(f"  • {pkg} ({info['current_version']}) - {', '.join(info['cve'])}")

        # Detailed findings
        if result.findings:
            console.print()
            console.print("[bold]Detailed Findings:[/bold]")
            console.print()

            # Group by file
            findings_by_file = {}
            for finding in result.findings:
                if finding.file_path not in findings_by_file:
                    findings_by_file[finding.file_path] = []
                findings_by_file[finding.file_path].append(finding)

            for file_path, findings in sorted(findings_by_file.items()):
                console.print(f"[bold cyan]{file_path}[/bold cyan]")

                for finding in sorted(findings, key=lambda x: x.line_number):
                    severity_color = severity_colors.get(finding.severity.value.lower(), "white")

                    console.print(f"  [{severity_color}][{finding.severity.value}][/{severity_color}] Line {finding.line_number}: {finding.title}")
                    console.print(f"     Confidence: {finding.confidence}%")
                    console.print(f"     [dim]{finding.code_snippet}[/dim]")

                    if finding.mitigation:
                        console.print(f"     [green]Fix: {finding.mitigation[:100]}...[/green]" if len(finding.mitigation) > 100 else f"     [green]Fix: {finding.mitigation}[/green]")

                    console.print()
        else:
            console.print("\n[green]No prototype pollution vulnerabilities detected.[/green]")

        # Recommendations
        console.print("\n[bold]Recommendations:[/bold]")
        console.print("  • Use Object.create(null) for objects with user-controlled keys")
        console.print("  • Use Map instead of plain objects when possible")
        console.print("  • Always validate/sanitize user input before merge operations")
        console.print("  • Keep dependencies updated (run: npm audit fix)")
        console.print("  • Implement Object.freeze() on critical prototypes")
        console.print("  • Add hasOwnProperty checks in for...in loops")

    @staticmethod
    def export_json(result: ScanResult, output_path: Path) -> None:
        """Export results to JSON."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

    @staticmethod
    def export_html(result: ScanResult, output_path: Path) -> None:
        """Export results to HTML."""
        summary = result.get_summary()

        findings_html = ""
        for finding in result.findings:
            findings_html += f"""
            <div class="finding {finding.severity.value.lower()}">
                <h3>[{finding.severity.value}] {finding.title}</h3>
                <p><strong>File:</strong> {finding.file_path} (Line {finding.line_number})</p>
                <p><strong>Confidence:</strong> {finding.confidence}%</p>
                <p><strong>Code:</strong> <code>{finding.code_snippet}</code></p>
                <p><strong>Description:</strong> {finding.description}</p>
                {f'<p><strong>Mitigation:</strong> {finding.mitigation}</p>' if finding.mitigation else ''}
                {f'<p><strong>CVE:</strong> {", ".join(finding.cve)}</p>' if finding.cve else ''}
            </div>
            """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Prototype Pollution Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; }}
                .finding {{ background: white; padding: 20px; margin: 20px 0; border-radius: 10px; border-left: 4px solid #ccc; }}
                .finding.critical {{ border-left-color: #DC3545; }}
                .finding.high {{ border-left-color: #FD7E14; }}
                .finding.medium {{ border-left-color: #FFC107; }}
                .finding.low {{ border-left-color: #0dcaf0; }}
                code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Prototype Pollution Scan Report</h1>
                <p>Generated by {TOOL_NAME} v{VERSION} by {AUTHOR}</p>
            </div>
            <h2>Scan Path: {result.scan_path}</h2>
            <p>Files Scanned: {result.files_scanned}</p>
            <p>Total Findings: {summary['total']} | Critical: {summary['critical']} | High: {summary['high']} | Medium: {summary['medium']}</p>
            {findings_html}
        </body>
        </html>
        """

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

# === CLI ===
def print_banner(console: Console) -> None:
    """Print application banner."""
    try:
        import pyfiglet
        banner = pyfiglet.figlet_format("ProtoPollute", font="slant")
        console.print(f"[bold cyan]{banner}[/bold cyan]")
    except ImportError:
        console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
        console.print("[bold cyan]Prototype Pollution Scanner[/bold cyan]")
        console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")

    console.print(f"[dim]Version {VERSION} | Author: {AUTHOR}[/dim]")
    console.print()

def show_examples(console: Console) -> None:
    """Display usage examples."""
    console.print("[bold cyan]Usage Examples:[/bold cyan]\n")

    examples = [
        ("Scan current directory", "python prototypepollutionscan.py ."),
        ("Scan specific project", "python prototypepollutionscan.py /path/to/nodejs-project"),
        ("Deep scan with node_modules", "python prototypepollutionscan.py . --deep --include-node-modules"),
        ("Generate JSON report", "python prototypepollutionscan.py . --output report.json"),
        ("Generate HTML report", "python prototypepollutionscan.py . --output report.html"),
        ("Custom ignore patterns", "python prototypepollutionscan.py . --ignore 'test' --ignore '*.spec.js'"),
        ("Verbose logging", "python prototypepollutionscan.py . --verbose"),
    ]

    for title, command in examples:
        console.print(f"[bold]{title}:[/bold]")
        console.print(f"  [green]{command}[/green]\n")

def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - Static analysis for Prototype Pollution in Node.js",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Author: {AUTHOR}
Use --examples for detailed usage examples.
        """
    )

    parser.add_argument('path', nargs='?', help='Path to scan (file or directory)')
    parser.add_argument('--deep', action='store_true', help='Enable deep scanning')
    parser.add_argument('--include-node-modules', action='store_true', help='Include node_modules in scan')
    parser.add_argument('--ignore', action='append', help='Additional ignore patterns (can be used multiple times)')
    parser.add_argument('--output', help='Output file (.json or .html)')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--examples', action='store_true', help='Show detailed examples')
    parser.add_argument('--version', action='version', version=f'{TOOL_NAME} v{VERSION} by {AUTHOR}')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner')

    args = parser.parse_args()

    console = Console()

    if args.examples:
        if not args.no_banner:
            print_banner(console)
        show_examples(console)
        return 0

    if not args.path:
        console.print("[red]Error: Path is required[/red]")
        parser.print_help()
        return 1

    if not args.no_banner:
        print_banner(console)

    # Display security warning
    console.print(Panel(Text(SECURITY_WARNING, style="yellow"), title="[yellow]SECURITY NOTICE[/yellow]", border_style="yellow"))
    console.print()

    logger = setup_logging(args.verbose)

    scan_path = Path(args.path)
    if not scan_path.exists():
        console.print(f"[red]Error: Path does not exist: {scan_path}[/red]")
        return 1

    # Display config
    console.print("[bold]Scan Configuration:[/bold]")
    console.print(f"  Path: [cyan]{scan_path}[/cyan]")
    console.print(f"  Deep Scan: {'[yellow]Yes[/yellow]' if args.deep else '[green]No[/green]'}")
    console.print(f"  Include node_modules: {'[yellow]Yes[/yellow]' if args.include_node_modules else '[green]No[/green]'}")
    console.print()

    # Run scan
    try:
        scanner = PrototypePollutionScanner(
            scan_path=scan_path,
            include_node_modules=args.include_node_modules,
            deep_scan=args.deep,
            ignore_patterns=args.ignore,
            logger=logger
        )

        result = scanner.scan(console)

        # Display results
        Reporter.print_console_report(result, console)

        # Export if requested
        if args.output:
            output_path = Path(args.output)
            if output_path.suffix.lower() == '.json':
                Reporter.export_json(result, output_path)
                console.print(f"\n[green]✓[/green] JSON report saved to: {output_path}")
            elif output_path.suffix.lower() == '.html':
                Reporter.export_html(result, output_path)
                console.print(f"\n[green]✓[/green] HTML report saved to: {output_path}")

        summary = result.get_summary()
        if summary['critical'] > 0 or summary['high'] > 0:
            return 1
        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")
        return 1
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        logger.exception("Fatal error")
        return 1

if __name__ == "__main__":
    sys.exit(main())
