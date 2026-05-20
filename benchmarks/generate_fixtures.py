"""Synthetic-repo generator for benchmark runs (#52).

Deterministic given a ``--seed``. Produces a tree of files in a mix of
``.py``, ``.js``, ``.ts``, ``.go``, ``.yaml``, ``.json``, and ``.md`` with
a configurable fraction of "finding bait" files so the rules have real
work to do.

The generator is pure stdlib and does no network I/O.
"""

from __future__ import annotations

import argparse
import random
import shutil
from dataclasses import dataclass
from pathlib import Path

SIZES = {
    "small": 50,
    "medium": 500,
    "large": 2000,
}

# Roughly equal contribution per extension so the benchmark exercises
# every rule that gates on suffix.
_EXTENSIONS: list[tuple[str, str]] = [
    (".py", "python"),
    (".js", "javascript"),
    (".ts", "typescript"),
    (".go", "go"),
    (".yaml", "yaml"),
    (".json", "json"),
    (".md", "markdown"),
]


@dataclass(frozen=True)
class GenConfig:
    n_files: int
    target_size_kb: int = 10
    bait_ratio: float = 0.15  # fraction of files that contain a planted finding
    seed: int = 0


_PY_BAIT = """\
# fixture file
import os

API_KEY = "AKIAIOSFODNN7EXAMPLE"  # planted: SEC-AWSACCESSKEY


def run(cmd: str) -> None:
    os.system(cmd)  # planted: RISK-SUBPROCESSSHELL
"""

_JS_BAIT = """\
// fixture file
const cors = require("cors");
app.use(cors({ origin: "*" })); // planted: RISK-CORSCONFIG / AI-CORSWILDCARD

function evaluate(expr) {
  return eval(expr); // planted: RISK-EVALEXEC
}
"""

_YAML_BAIT = """\
# fixture
database_url: "postgres://admin:supersecret@db.example.com:5432/prod"  # planted: SEC-DATABASEURL
"""

_JSON_BAIT = """\
{
  "dependencies": {
    "axios": "git+https://github.com/axios/axios.git#master"
  }
}
"""

_FILLER_BY_KIND = {
    "python": "def f_{i}(x):\n    return x + {i}\n",
    "javascript": "export function f_{i}(x) {{ return x + {i}; }}\n",
    "typescript": "export function f_{i}(x: number): number {{ return x + {i}; }}\n",
    "go": "package pkg\n\nfunc F_{i}(x int) int {{ return x + {i} }}\n",
    "yaml": "key_{i}: value_{i}\n",
    "json": '{{\n  "k_{i}": {i}\n}}\n',
    "markdown": "# Section {i}\n\nLorem ipsum body {i}.\n",
}


def _filler(kind: str, target_size: int, rng: random.Random) -> str:
    """Produce filler text of approximately ``target_size`` bytes."""
    template = _FILLER_BY_KIND[kind]
    chunks: list[str] = []
    size = 0
    i = 0
    while size < target_size:
        i = rng.randint(0, 10_000_000)
        chunks.append(template.format(i=i))
        size += len(chunks[-1])
    return "".join(chunks)


def _bait_for(kind: str) -> str:
    if kind == "python":
        return _PY_BAIT
    if kind in ("javascript", "typescript"):
        return _JS_BAIT
    if kind == "yaml":
        return _YAML_BAIT
    if kind == "json":
        return _JSON_BAIT
    return ""  # markdown/go: no bait, just filler


def generate(out_dir: Path, cfg: GenConfig, *, overwrite: bool = True) -> Path:
    """Generate a deterministic synthetic repo under ``out_dir``."""
    if out_dir.exists():
        if not overwrite:
            return out_dir
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    rng = random.Random(cfg.seed)
    target_bytes = cfg.target_size_kb * 1024
    bait_count = int(cfg.n_files * cfg.bait_ratio)
    # Spread files across a handful of directories so path-based rules
    # (e.g. test detection) see realistic structure.
    subdirs = ["src", "lib", "app", "pkg", "internal", "tools"]

    for i in range(cfg.n_files):
        ext, kind = _EXTENSIONS[i % len(_EXTENSIONS)]
        subdir = subdirs[i % len(subdirs)]
        path = out_dir / subdir / f"file_{i:04d}{ext}"
        path.parent.mkdir(parents=True, exist_ok=True)

        body_parts: list[str] = []
        if i < bait_count:
            body_parts.append(_bait_for(kind))
        body_parts.append(_filler(kind, target_bytes - sum(len(p) for p in body_parts), rng))
        path.write_text("".join(body_parts), encoding="utf-8")

    return out_dir


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic benchmark repo.")
    parser.add_argument("--size", choices=list(SIZES), default="small")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--target-kb", type=int, default=10)
    parser.add_argument("--bait-ratio", type=float, default=0.15)
    args = parser.parse_args(argv)

    cfg = GenConfig(
        n_files=SIZES[args.size],
        target_size_kb=args.target_kb,
        bait_ratio=args.bait_ratio,
        seed=args.seed,
    )
    out = generate(args.out, cfg)
    print(f"Generated {cfg.n_files} files under {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
