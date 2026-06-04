# Vendored weaver-spec contracts

These JSON Schemas are **vendored copies** of contracts published by
[weaver-spec](https://github.com/dgenio/weaver-spec) (the canonical spec for
the Weaver Stack). They are checked in here only so VibeGuard's tests can
validate its `--weaver` export **offline**, with no network access and no
runtime dependency on any sibling project.

| File | Upstream `$id` |
|------|----------------|
| `artifact_safety_report.schema.json` | `https://weaver-spec.dev/contracts/v0/extended/artifact_safety_report.schema.json` |
| `lesson_card.schema.json` | `https://weaver-spec.dev/contracts/v0/extended/lesson_card.schema.json` |

Both live in weaver-spec's `contracts/json/extended/` directory — the
**optional** (non-core) tier. The `$id` of each vendored file is preserved
verbatim so it can be diffed against upstream.

**Keeping these in sync:** if weaver-spec revises a contract, update the
vendored copy here and re-run `pytest tests/test_reporters_weaver.py`. The
export and the field mapping are documented in
[`../interop-lessons.md`](../interop-lessons.md).

> Note: weaver-spec has **no** `FailureCaseArtifact` contract (the name used
> in issue #120). `ArtifactSafetyReport` is the canonical contract for the
> output of an artifact safety gate, which is exactly what VibeGuard is, so
> the export targets that instead.
