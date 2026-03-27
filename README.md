# MCP Security Scan

Security scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. Finds hardcoded secrets, unsafe execution patterns, missing authentication, and filesystem access risks.

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

## Quick Start

### Scan a repo

```bash
pip install mcp-security-scan

# Scan any MCP server repo
mcp-security-scan owner/repo

# Scan the current repo (auto-detects from git remote)
mcp-security-scan

# JSON output
mcp-security-scan owner/repo --format json

# Fail CI on critical findings
mcp-security-scan owner/repo --fail-on critical
```

### GitHub Action

Add to `.github/workflows/security.yml`:

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: agentgraph-co/mcp-security-scan@v1
        with:
          fail-on: critical  # or "high", "medium"
```

The action posts a comment on PRs with the scan results:

> ## MCP Security Scan Results
>
> :white_check_mark: **Trust Score: 85/100** (Good)
>
> | Metric | Value |
> |--------|-------|
> | Files scanned | 45 |
> | Critical findings | 0 |
> | High findings | 0 |
> | Medium findings | 2 |

## What It Scans

### Hardcoded Secrets (critical/high)
- AWS access keys and secret keys
- OpenAI, Anthropic, Google API keys
- GitHub tokens, Slack tokens, Stripe keys
- Private key blocks (RSA, etc.)
- Generic API key/password assignments

### Unsafe Execution (critical/high)
- `subprocess.run()`, `os.system()`, `os.popen()` (Python)
- `shell=True` (Python — critical)
- `eval()`, `exec()` (Python/JS)
- `child_process`, `execSync` (Node.js)
- `Command::new` (Rust), `exec.Command` (Go)

### Filesystem Access (medium/high)
- Unrestricted file read/write
- Path traversal patterns (`../`)
- Recursive delete (`shutil.rmtree`, `rimraf`)

### Positive Signals (reduce risk score)
- Authentication checks
- Authorization/role checks
- Input validation (Zod, Pydantic, etc.)
- Rate limiting
- CORS configuration
- Security headers (Helmet, CSP)

## Trust Score

Each repo gets a score from 0-100:

- Starts at **70** (neutral)
- **-15** per critical finding
- **-8** per high finding
- **-3** per medium finding
- **+5** per positive security signal
- **+5** each for README, LICENSE, tests

## Output Formats

### Text (default)
```
Trust Score: 85/100
Files Scanned: 45
Findings: 2 (critical=0, high=0, medium=2)
Positive Signals: Input validation, Rate limiting
```

### JSON (`--format json`)
Full structured output for programmatic use.

### GitHub Comment (`--format github`)
Markdown table formatted for PR comments.

## Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `repo` | GitHub repo (owner/repo) | Auto-detect from git remote |
| `--token` | GitHub API token | `$GITHUB_TOKEN` |
| `--format` | Output format: text, json, github | text |
| `--output` | Write JSON report to file | — |
| `--fail-on` | Exit 1 if findings at this severity+ | — |

## Contributing

Found a false positive? Missing a pattern? PRs welcome.

**Good first issues:**
- Add detection for more secret patterns (Twilio, SendGrid, etc.)
- Reduce false positives on path traversal in test files
- Add support for local directory scanning (not just GitHub repos)
- Add SARIF output format for GitHub Code Scanning integration

## License

MIT — see [LICENSE](LICENSE).

---

Built by [AgentGraph](https://agentgraph.co) — trust infrastructure for AI agents.
