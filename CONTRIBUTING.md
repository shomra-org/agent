# Contributing to Shomra Agent

Thanks for helping make AI tooling safer. This package is the **local-first**
engine behind Shomra: the CLI, the editor extension, the CI gate, and the
runtime firewall all run these same analyzers on-machine.

## Ground rules

- **Zero runtime dependencies.** The CLI must run with nothing but Node's
  standard library. Do not add anything to `dependencies`. If you reach for a
  package, we almost certainly want a small vendored helper instead - open an
  issue first.
- **Node 18+**, ES modules (`.mjs`).
- **Local-first.** Detection must work fully offline. Network calls (to a Shomra
  backend) are strictly optional enrichment and must degrade gracefully when the
  backend is absent, slow, or down - never hang or fail closed by default.
- **Low false positives.** A noisy scanner gets turned off. New rules must be
  justified against real attack patterns and must not fire on benign code.

## Project layout

`shomra.mjs` at the repo root is only the executable entrypoint. Everything else
lives under `src/`, grouped by what it is responsible for:

| Directory | What it holds |
|-----------|---------------|
| `src/cli/` | Argument parsing, the command registry, help text, `main()` |
| `src/commands/` | One module per user-facing command (`check`, `gate`, `fix`, …) |
| `src/core/` | Config, terminal colours, exit codes, backend client, circuit breaker |
| `src/detect/` | The analyzers. `signals/` is the local gate; `sast/` is source scanning |
| `src/gate/` | Turning analyzer output into a gate result: policy, suppression, SARIF |
| `src/guard/` | The runtime firewall hook handlers (`tool-guard`, `result-guard`, …) |
| `src/agents/` | Per-agent hook installation (Claude Code, Cursor, Gemini, …) |
| `src/inventory/` | Discovering AI tooling, artifacts and keys on a machine |
| `src/mcp/` | The MCP server Shomra exposes, and the stdio shim that guards others |
| `src/models/` | Model reference collection and Model Index lookup |
| `src/rules/` | Generating the agent rules block written into `CLAUDE.md` etc. |
| `src/corpus/`, `src/artifacts/`, `src/scaffold/` | RAG screening, artifact walking, `shomra new` templates |
| `tests/` | `node --test` suites (zero-dep) |

Two conventions worth knowing before you move code:

- The path to the CLI entrypoint is baked into installed agent hooks. Take it
  from `src/core/package-root.mjs` (`CLI_ENTRY_PATH`), never from
  `import.meta.url` in a nested module.
- `src/detect/guard-signals.mjs`, `code-sast.mjs` and `src/inventory/*.mjs` are
  facades that re-export a directory of focused modules. Add new rules to the
  focused module and export them through the facade so importers stay stable.

## Development

```bash
node --test                # run the test suite
node shomra.mjs help       # run the CLI from source
node --check shomra.mjs    # syntax check
```

## Adding or changing a detection rule

1. Add the rule to the right module: `src/detect/signals/` for gate signals
   (shell, injection, secrets, egress, memory), `src/detect/sast/` for source
   scanning, `src/detect/model-refs.mjs` for model loads.
2. **Add a test both ways:** a positive case (a payload it must catch) *and* a
   negative case (benign code it must NOT flag). False-positive tests are as
   important as detections here.
3. Name the rule so the reference is obvious from the code, and cite the CWE,
   CVE, advisory or write-up in the PR description so reviewers can verify it.

## Pull requests

- Keep PRs focused; one rule family or one fix per PR.
- Run the tests and `node --check` before pushing.
- Describe the attack the change defends against and the false-positive risk.
- By contributing, you agree your contribution is licensed under
  [Apache-2.0](./LICENSE).

## Security issues

Please **do not** file security problems as public issues - see
[SECURITY.md](./SECURITY.md) for private reporting.
