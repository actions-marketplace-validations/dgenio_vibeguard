# VibeGuard Workflow Examples

Copy these workflow files into your repository's `.github/workflows/` directory to use them.

## Available Workflows

| File | Description |
|---|---|
| `basic-scan.yml` | Simple scan on every push and PR with artifact upload |
| `pr-gate.yml` | PR diff gate that fails on blocking findings |
| `sarif-upload.yml` | SARIF generation and GitHub Code Scanning upload |
| `pr-comment.yml` | PR comment with findings summary |
| `baseline-management.yml` | Create/update baseline on main, use in PRs |
| `publish-check.yml` | Pre-release packaging safety check |

## Usage

1. Copy the desired `.yml` file(s) into `.github/workflows/` in your repository.
2. Adjust inputs (path, fail-on threshold, Python version) as needed.
3. Commit and push — workflows will activate on matching triggers.

## Notes

- All workflows use minimal permissions (principle of least privilege).
- Action versions are pinned for reproducibility.
- VibeGuard is installed from PyPI (`vibeguard-gate` package).
