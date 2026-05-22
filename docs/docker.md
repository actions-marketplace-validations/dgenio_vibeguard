# Running VibeGuard via Docker

VibeGuard ships a [`Dockerfile`](../Dockerfile) so any CI environment with
Docker — even ones that don't have Python — can run the gate with a single
`docker run`.

## Build the image locally

```bash
docker build -t vibeguard:dev .
```

The build uses a two-stage [`python:3.12-slim`](https://hub.docker.com/_/python)
layout:

1. **Build stage** — installs `build`, runs `python -m build --wheel`, and
   produces a single wheel that matches the source tree exactly.
2. **Runtime stage** — installs only the wheel and its runtime
   dependencies, then drops to a non-root `vibeguard` user (UID 1000).

The resulting image:

- Runs as a non-root user (`useradd vibeguard`, UID 1000).
- Has `WORKDIR /scan` so a single bind-mount lands at the obvious path.
- Sets `ENTRYPOINT ["vibeguard"]` so the container behaves like the CLI.
- Carries OCI labels (`org.opencontainers.image.{title,description,source,licenses,version}`).

## Run

Show the help banner:

```bash
docker run --rm vibeguard:dev
```

Scan a local directory:

```bash
docker run --rm -v "$PWD:/scan:ro" vibeguard:dev scan --path /scan
```

Gate a local directory (exits non-zero on findings at or above `high`):

```bash
docker run --rm -v "$PWD:/scan:ro" vibeguard:dev gate --path /scan --fail-on high
```

Emit JSON to a file on the host:

```bash
docker run --rm \
  -v "$PWD:/scan:ro" \
  vibeguard:dev scan --path /scan --json > findings.json
```

Use a config file mounted alongside the source tree:

```bash
docker run --rm \
  -v "$PWD:/scan:ro" \
  vibeguard:dev gate --path /scan --config /scan/vibeguard.yaml
```

> **Why read-only?** VibeGuard only reads files. Mounting the source as
> `:ro` makes that contract explicit and prevents an accidental write
> inside the container from leaking back to the host.

## Use as a GitHub Actions container job

```yaml
name: VibeGuard (container)
on:
  pull_request:

permissions:
  contents: read

jobs:
  gate:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/dgenio/vibeguard:0.6.0
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # needed for --diff mode
      - run: vibeguard gate --path . --fail-on high
```

> The example above assumes a published image. As of v0.6 the project
> intentionally does **not** push to any container registry — the
> `.github/workflows/docker.yml` workflow only builds and smoke-tests the
> image. Maintainers can layer registry credentials on top once they've
> picked a destination (GHCR, Docker Hub, etc.).

If you don't want to wait for a published image, use the first-party
GitHub Action ([`docs/github-actions.md`](github-actions.md)) instead —
it installs VibeGuard via pip in the runner.

## Use in non-GitHub CI

The image is a drop-in replacement for the `vibeguard` CLI in any
container-friendly pipeline. Sketch for GitLab CI:

```yaml
vibeguard:
  image: ghcr.io/dgenio/vibeguard:0.6.0
  script:
    - vibeguard gate --path . --fail-on high
```

## Image hygiene

| Concern        | What the image does                                                                 |
| -------------- | ----------------------------------------------------------------------------------- |
| Base image     | `python:3.12-slim` (Debian-based, no compilers in the runtime layer).               |
| User           | Non-root `vibeguard` (UID 1000).                                                    |
| Network        | No outbound calls. VibeGuard is fully offline.                                      |
| Writes         | Only writes to whatever `--output` / shell redirect the caller pointed at.          |
| Secrets        | The scanner never logs the secret values it finds — only locations and rule IDs.    |
| Image surface  | Two-stage build keeps `build` / compilers out of the published image.               |

## Troubleshooting

- **`Permission denied` writing output**: the container runs as UID 1000.
  Either redirect stdout on the host side (`docker run ... > file.json`)
  or `chown` the target directory to UID 1000.
- **`fatal: not a git repository`**: VibeGuard's `--diff` mode shells out
  to `git`. Inside a container the working tree only sees what you
  mounted — bind-mount the `.git/` directory along with the source.
- **`No module named vibeguard`** when extending the image: the runtime
  stage installs the wheel into the system Python; subclasses must not
  add a separate Python install that shadows it.

## Related

- [`pre-commit.md`](pre-commit.md) — run the same gate locally before commit.
- [`github-actions.md`](github-actions.md) — first-party GitHub Action.
