# MCP Security Scan

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-MCP%20Security%20Scan-blue?logo=github)](https://github.com/marketplace/actions/mcp-security-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Security scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. Finds hardcoded secrets, unsafe execution patterns, data exfiltration risks, filesystem access issues, code obfuscation, and missing authentication.

Available as a **GitHub Action** and a **CLI tool**.

---

## Why?

We scanned 28 of the most popular MCP servers on GitHub. The results:

| Finding | % of repos |
|---------|-----------|
| Unsafe shell/exec patterns | **92.9%** |
| Filesystem access without sandboxing | 85.7% |
| No authentication checks | 25.0% |
| Hardcoded secrets | **17.9%** |
| **Average trust score** | **25.8/100** |

MCP servers run on your machine with access to your files, shell, and API keys. Most have no security review process.

---

## Quick Start

### GitHub Action (recommended)

Add this to `.github/workflows/mcp-security.yml`:

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: agentgraph-co/mcp-security-scan@v1
        with:
          fail-on: critical
```

That's it. The action will:
- Scan your repository for security issues
- Post a detailed comment on pull requests
- Fail the check if critical findings are detected

### CLI

```bash
pip install mcp-security-scan

# Scan any MCP server repo on GitHub
mcp-security-scan owner/repo

# Scan the current repo (auto-detects from git remote)
mcp-security-scan

# JSON output for programmatic use
mcp-security-scan owner/repo --format json

# Fail CI on critical findings
mcp-security-scan owner/repo --fail-on critical
```

---

## Advanced Usage

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `repo` | GitHub repo to scan (`owner/repo`). Defaults to the current repository. | Current repo |
| `token` | GitHub token for API access | `${{ github.token }}` |
| `fail-on` | Fail the check if findings at or above this severity: `critical`, `high`, or `medium` | `critical` |
| `format` | Output format: `text`, `json`, `github` | `github` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `trust-score` | Trust score from 0-100 |
| `findings-count` | Total number of security findings |
| `critical-count` | Number of critical-severity findings |
| `report` | Full scan report as JSON |

### Using Outputs in Your Workflow

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: agentgraph-co/mcp-security-scan@v1
        id: scan
        with:
          fail-on: high

      - name: Check trust score
        if: steps.scan.outputs.trust-score < 50
        run: echo "Trust score is below 50 — review findings"
```

### Scanning a Different Repository

```yaml
- uses: agentgraph-co/mcp-security-scan@v1
  with:
    repo: some-org/their-mcp-server
    token: ${{ secrets.GITHUB_TOKEN }}
```

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `repo` | GitHub repo (`owner/repo`) | Auto-detect from git remote |
| `--token` | GitHub API token | `$GITHUB_TOKEN` env var |
| `--format` | Output format: `text`, `json`, `github` | `text` |
| `--output`, `-o` | Write JSON report to file | -- |
| `--fail-on` | Exit code 1 if findings at this severity or above: `critical`, `high`, `medium` | -- |

---

## What It Scans

The scanner checks for **6 categories** of security issues:

### :key: Hardcoded Secrets (critical/high)
- AWS access keys and secret keys
- OpenAI, Anthropic, Google API keys
- GitHub tokens, Slack tokens, Stripe keys
- Private key blocks (RSA, etc.)
- Generic API key and password assignments

### :warning: Unsafe Execution (critical/high)
- `subprocess.run()`, `os.system()`, `os.popen()` (Python)
- `shell=True` in subprocess calls (Python -- critical)
- `eval()`, `exec()` (Python/JS)
- `child_process`, `execSync` (Node.js)
- `Command::new` (Rust), `exec.Command` (Go)

### :file_folder: Filesystem Access (medium/high)
- Unrestricted file read/write operations
- Path traversal patterns (`../`)
- Recursive delete (`shutil.rmtree`, `rimraf`)

### :satellite: Data Exfiltration (high/critical)
- Outbound HTTP requests with sensitive data
- Encoded data transmission patterns
- Suspicious network calls in unexpected contexts

### :detective: Code Obfuscation (high)
- Base64-encoded code execution
- Dynamic code generation patterns
- Obfuscated variable names and control flow

### :white_check_mark: Positive Security Signals (reduce risk)
- Authentication and authorization checks
- Input validation (Zod, Pydantic, JSON Schema)
- Rate limiting
- CORS configuration
- Security headers (Helmet, CSP)

---

## Example PR Comment

When the action runs on a pull request, it posts a comment like this:

> ## MCP Security Scan Results
>
> :white_check_mark: **Trust Score: 85/100** (Good)
>
> - :white_check_mark: **Credential Theft** -- Clear
> - :white_check_mark: **Data Exfiltration** -- Clear
> - :warning: **Unsafe Execution** -- 2 findings
> - :white_check_mark: **Filesystem Access** -- Clear
> - :white_check_mark: **Code Obfuscation** -- Clear
>
> | Metric | Value |
> |--------|-------|
> | Files scanned | 45 |
> | Language | Python |
> | Positive signals | Input validation, Rate limiting |
>
> <details>
> <summary>Findings (2)</summary>
>
> | Severity | Category | Name | File | Line |
> |----------|----------|------|------|------|
> | high | unsafe_exec | subprocess.run | `src/tools.py` | 42 |
> | medium | unsafe_exec | os.popen | `src/utils.py` | 18 |
>
> </details>

---

## Trust Score

Each scanned repo receives a score from 0 to 100:

| Factor | Impact |
|--------|--------|
| Base score | **70** |
| Critical finding | **-15** each |
| High finding | **-8** each |
| Medium finding | **-3** each |
| Positive security signal | **+5** each |
| Has README | **+5** |
| Has LICENSE | **+5** |
| Has tests | **+5** |

---

## Contributing

Found a false positive? Missing a detection pattern? PRs welcome.

**Good first issues:**
- Add detection for more secret patterns (Twilio, SendGrid, etc.)
- Reduce false positives on path traversal in test files
- Add support for local directory scanning (not just GitHub repos)
- Add SARIF output format for GitHub Code Scanning integration

---

## License

MIT -- see [LICENSE](LICENSE).

---

Built by [AgentGraph](https://agentgraph.co) -- trust infrastructure for AI agents.
