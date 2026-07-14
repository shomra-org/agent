# Changelog

All notable changes to `@shomra/agent` are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Relicensed to **Apache-2.0** and prepared the package for public release
  (added `LICENSE`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, `.gitignore`,
  `CODEOWNERS`).

### Notes
- No functional CLI changes in this entry — packaging and governance only.

## [0.2.0]

- Local-first scanner and runtime firewall for AI artifacts (skills, slash
  commands, subagents, hooks, MCP configs, rules/instruction files, memory).
- `check` / `gate` / `gate --all` with `--json` and `--sarif` output and
  CI-friendly exit codes (0 allowed / 1 blocked / 2 flagged with `--strict`).
- `models` — detects AI-model loads in source and looks them up in the Shomra
  Model Security Index (enrichment; degrades offline).
- `install-hook` / `tool-guard` / `result-guard` — tiered runtime firewall for
  coding agents (local Tier-0 block, optional backend escalation).
- `secrets`, `doctor`, `protect`, `new`, `mcp add`, `why`, `pr` (GitHub PR bot),
  `install-precommit`.
- `discovery.mjs` machine scan for local AI tooling, runtimes, and exposed keys.
