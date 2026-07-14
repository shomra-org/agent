# Contributing to Shomra Agent

Thanks for helping make AI tooling safer. This package is the **local-first**
engine behind Shomra: the CLI, the editor extension, the CI gate, and the
runtime firewall all run these same analyzers on-machine.

## Ground rules

- **Zero runtime dependencies.** The CLI must run with nothing but Node's
  standard library. Do not add anything to `dependencies`. If you reach for a
  package, we almost certainly want a small vendored helper instead — open an
  issue first.
- **Node 18+**, ES modules (`.mjs`).
- **Local-first.** Detection must work fully offline. Network calls (to a Shomra
  backend) are strictly optional enrichment and must degrade gracefully when the
  backend is absent, slow, or down — never hang or fail closed by default.
- **Low false positives.** A noisy scanner gets turned off. New rules must be
  justified against real attack patterns and must not fire on benign code.

## Project layout

| File | What it holds |
|------|---------------|
| `shomra.mjs` | CLI entrypoint — command dispatch, output, backend client |
| `guard-signals.mjs` | Shell / injection / secret / PII / egress rules + local gate |
| `code-sast.mjs` | Python / JS / config static-analysis rules (CWE-tagged) |
| `model-refs.mjs` | Detects AI-model loads in source (`from_pretrained`, etc.) |
| `discovery.mjs` | Discovers local AI tooling / runtimes / keys on a machine |
| `tests/` | `node --test` suites (zero-dep) |

## Development

```bash
node --test "tests/**/*.test.mjs"   # run the test suite
node shomra.mjs help                # run the CLI from source
node --check shomra.mjs             # syntax check
```

## Adding or changing a detection rule

1. Add the rule to the right file (`guard-signals.mjs` / `code-sast.mjs` /
   `model-refs.mjs`).
2. **Add a test both ways:** a positive case (a payload it must catch) *and* a
   negative case (benign code it must NOT flag). False-positive tests are as
   important as detections here.
3. Include the reference for the pattern in a comment (CWE, CVE, advisory, or a
   public write-up) so reviewers can verify it.

## Pull requests

- Keep PRs focused; one rule family or one fix per PR.
- Run the tests and `node --check` before pushing.
- Describe the attack the change defends against and the false-positive risk.
- By contributing, you agree your contribution is licensed under
  [Apache-2.0](./LICENSE).

## Security issues

Please **do not** file security problems as public issues — see
[SECURITY.md](./SECURITY.md) for private reporting.
