# Interop example: findings → reviewed lessons

A runnable demonstration of how repeated VibeGuard findings can feed
[lessonweaver](https://github.com/dgenio/lessonweaver) (or any consumer) as
candidate **lessons** — through serialized output only, with no runtime
dependency on any sibling project.

See [`docs/interop-lessons.md`](../../docs/interop-lessons.md) for the design
note, the field mapping, and the `--weaver` export contract.

## Run it

```bash
python examples/interop/findings_to_lessons.py
```

The script:

1. scans each `examples/pr-scenarios/` directory, treating each as a separate
   PR context;
2. emits a weaver-spec `ArtifactSafetyReport` per scenario (the `--weaver`
   export);
3. aggregates findings by **rule category** across contexts;
4. mints a candidate weaver-spec `LessonCard` (`lifecycle_state: in_review`)
   for every category seen across two or more PRs, and lists the rest as
   one-offs.

With the bundled fixtures, categories such as `ai_footprints` and `auth` recur
across scenarios (e.g. `01-tls-verify-disabled` and `02-auth-bypass-left-in`),
so each repeated category yields one candidate lesson; categories seen in only
a single PR (e.g. `secrets`, `sql`, `prompt_injection`) stay one-offs and mint
no lesson.

## The same export from the CLI

```bash
vibeguard scan --path examples/pr-scenarios/01-tls-verify-disabled --weaver
```

emits the `ArtifactSafetyReport` JSON directly — the script just aggregates
several of these and proposes lessons.
