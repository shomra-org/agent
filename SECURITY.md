# Security Policy

Shomra is a security tool, so we hold ourselves to the standard we ask of others.
If you find a security issue in the `@shomra/agent` CLI, please tell us privately
first so we can fix it before it is public.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Instead, use one of:

- **GitHub private advisory** — the "Report a vulnerability" button under this
  repository's **Security** tab (preferred).
- **Email** — hello@shomra.ai

Please include:

- the version (`shomra --version` or the `package.json` version),
- your OS and Node version,
- a minimal repro (a sample artifact / command / input),
- what you expected vs. what happened, and the impact you see.

If you can, avoid including real secrets in your report — a redacted or synthetic
repro is enough.

## What to expect

- We aim to acknowledge a report within **3 business days**.
- We will confirm the issue, agree on a severity, and share a rough timeline.
- We will credit you in the release notes unless you ask us not to.
- Please give us a reasonable window to release a fix before any public
  disclosure (coordinated disclosure).

## Scope

In scope: the CLI and its bundled analyzers/rules in this repository —
for example, a malicious input that causes the scanner to execute code, leak
data, crash in a way that breaks a CI gate, or silently pass content it should
have flagged (a detection bypass).

Out of scope: the hosted Shomra platform and backend APIs (report those through
your account / the platform's own channel), and issues that require a
already-compromised machine or a modified copy of the CLI.

## Supported versions

Security fixes land on the latest released minor version. Please upgrade to the
latest `@shomra/agent` before reporting.