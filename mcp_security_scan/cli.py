"""CLI entry point for mcp-security-scan."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone

from mcp_security_scan.scan import ScanResult, scan_repo

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# Exit codes
EXIT_SUCCESS = 0
EXIT_FINDINGS = 1  # Findings above threshold
EXIT_ERROR = 2


def _result_to_dict(r: ScanResult) -> dict:
    """Convert ScanResult to a JSON-serializable dict."""
    return {
        "repo": r.repo,
        "stars": r.stars,
        "description": r.description,
        "framework": r.framework,
        "primary_language": r.primary_language,
        "files_scanned": r.files_scanned,
        "has_readme": r.has_readme,
        "has_license": r.has_license,
        "has_tests": r.has_tests,
        "trust_score": r.trust_score,
        "error": r.error,
        "findings_count": len(r.findings),
        "critical_count": r.critical_count,
        "high_count": r.high_count,
        "medium_count": r.medium_count,
        "positive_signals": list(set(r.positive_signals)),
        "findings": [
            {
                "category": f.category,
                "name": f.name,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "snippet": f.snippet,
            }
            for f in r.findings
        ],
    }


def _print_summary(result: ScanResult) -> None:
    """Print a human-readable summary to stderr."""
    if result.error:
        print(f"\n  ERROR: {result.error}", file=sys.stderr)
        return

    print(f"\n  Trust Score: {result.trust_score}/100", file=sys.stderr)
    print(f"  Files Scanned: {result.files_scanned}", file=sys.stderr)
    print(f"  Language: {result.primary_language}", file=sys.stderr)
    print(
        f"  Findings: {len(result.findings)} "
        f"(critical={result.critical_count}, "
        f"high={result.high_count}, "
        f"medium={result.medium_count})",
        file=sys.stderr,
    )

    if result.positive_signals:
        signals = ", ".join(sorted(set(result.positive_signals)))
        print(f"  Positive Signals: {signals}", file=sys.stderr)

    if result.findings:
        print("\n  Findings:", file=sys.stderr)
        for f in result.findings[:20]:
            print(
                f"    [{f.severity.upper():>8}] {f.name}",
                file=sys.stderr,
            )
            print(
                f"             {f.file_path}:{f.line_number}",
                file=sys.stderr,
            )
        if len(result.findings) > 20:
            print(
                f"    ... and {len(result.findings) - 20} more",
                file=sys.stderr,
            )


def _format_github_comment(result: ScanResult) -> str:
    """Format scan results as a GitHub PR/Action comment."""
    if result.error:
        return f"## MCP Security Scan\n\n:x: Error: {result.error}"

    # Emoji based on score
    if result.trust_score >= 80:
        badge = ":white_check_mark:"
        grade = "Good"
    elif result.trust_score >= 50:
        badge = ":warning:"
        grade = "Needs Attention"
    else:
        badge = ":x:"
        grade = "Concern"

    lines = [
        "## MCP Security Scan Results",
        "",
        f"{badge} **Trust Score: {result.trust_score}/100** ({grade})",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Files scanned | {result.files_scanned} |",
        f"| Critical findings | {result.critical_count} |",
        f"| High findings | {result.high_count} |",
        f"| Medium findings | {result.medium_count} |",
        f"| Language | {result.primary_language} |",
    ]

    if result.positive_signals:
        signals = ", ".join(sorted(set(result.positive_signals)))
        lines.append(f"| Positive signals | {signals} |")

    if result.findings:
        lines.append("")
        lines.append("<details>")
        lines.append(f"<summary>Findings ({len(result.findings)})</summary>")
        lines.append("")
        lines.append("| Severity | Category | Name | File | Line |")
        lines.append("|----------|----------|------|------|------|")
        for f in result.findings[:50]:
            lines.append(
                f"| {f.severity} | {f.category} | {f.name} "
                f"| `{f.file_path}` | {f.line_number} |"
            )
        if len(result.findings) > 50:
            lines.append(f"| ... | ... | {len(result.findings) - 50} more | ... | ... |")
        lines.append("")
        lines.append("</details>")

    lines.append("")
    lines.append(
        "*Scanned by [mcp-security-scan]"
        "(https://github.com/agentgraph-co/mcp-security-scan)*"
    )

    return "\n".join(lines)


async def _run(args: argparse.Namespace) -> int:
    """Run the scan."""
    token = args.token or os.environ.get("GITHUB_TOKEN")
    repo = args.repo

    # If no repo specified, try to detect from git remote
    if not repo:
        try:
            import subprocess

            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True, text=True, check=True,
            )
            url = result.stdout.strip()
            # Parse github.com/owner/repo from SSH or HTTPS URL
            if "github.com" in url:
                parts = url.split("github.com")[-1]
                parts = parts.lstrip(":/").rstrip(".git")
                repo = parts
        except Exception:
            pass

    if not repo:
        print("Error: No repo specified. Use --repo owner/repo or run from a git repo.",
              file=sys.stderr)
        return EXIT_ERROR

    print(f"Scanning {repo}...", file=sys.stderr)

    scan_result = await scan_repo(
        full_name=repo,
        token=token,
    )

    # Output based on format
    if args.format == "json":
        output = _result_to_dict(scan_result)
        output["scan_date"] = datetime.now(timezone.utc).isoformat()
        print(json.dumps(output, indent=2))
    elif args.format == "github":
        print(_format_github_comment(scan_result))
    else:
        _print_summary(scan_result)

    # Also write to file if requested
    if args.output:
        output = _result_to_dict(scan_result)
        output["scan_date"] = datetime.now(timezone.utc).isoformat()
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nReport written to {args.output}", file=sys.stderr)

    # Set exit code based on findings
    if scan_result.error:
        return EXIT_ERROR
    if args.fail_on:
        threshold = args.fail_on
        if threshold == "critical" and scan_result.critical_count > 0:
            return EXIT_FINDINGS
        if threshold == "high" and (scan_result.critical_count + scan_result.high_count) > 0:
            return EXIT_FINDINGS
        if threshold == "medium" and len(scan_result.findings) > 0:
            return EXIT_FINDINGS

    return EXIT_SUCCESS


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="mcp-security-scan",
        description="Security scanner for MCP servers",
    )
    parser.add_argument(
        "repo", nargs="?", default=None,
        help="GitHub repo to scan (owner/repo). Auto-detects from git remote if omitted.",
    )
    parser.add_argument(
        "--token", default=None,
        help="GitHub API token (or set GITHUB_TOKEN env var)",
    )
    parser.add_argument(
        "--format", choices=["text", "json", "github"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Write JSON report to this file",
    )
    parser.add_argument(
        "--fail-on", choices=["critical", "high", "medium"],
        default=None,
        help="Exit with code 1 if findings at or above this severity",
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
