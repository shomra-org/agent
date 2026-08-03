# Shomra Dev Container Feature

Installs the Shomra CLI and wires the runtime firewall into every coding agent in
the container, at provision time.

```jsonc
// .devcontainer/devcontainer.json
{
  "features": {
    "ghcr.io/devcontainers/features/node:1": {},
    "ghcr.io/shomra-org/agent/shomra:0": {
      "protect": true
    }
  }
}
```

## Why provisioning

Every other install path covers the developers who already knew they needed it.
Provisioning is the one moment where coverage is total and nobody had to opt in —
Codespaces, Gitpod, and a local rebuild all pass through it.

## Options

| Option | Default | What it does |
|---|---|---|
| `version` | `latest` | Which `@shomra/agent` to install |
| `protect` | `true` | Runs `shomra protect` after create — wires the tool-call, tool-result and prompt guards into the agents present in the container |
| `rules` | `false` | Runs `shomra rules --write` after create |

`rules` is **off by default on purpose**: it writes into the developer's
workspace, and a feature that edits committed files without being asked is a
surprise rather than a convenience. Turn it on when the team has decided the
managed block belongs in the repo.

## What runs when

`install.sh` runs at **image build** time, as root, and only installs the CLI.
`shomra protect` needs the workspace mount and the user's own agent config
directories, neither of which exists at build time, so it is deferred to
`postCreateCommand`.

Every post-create step is best-effort and non-fatal. A security tool that stops a
dev container from coming up gets deleted from the dev container.

## There is no `curl … | sh` installer, deliberately

Shomra's own Tier-0 guard blocks piping a downloaded script into a shell, and the
rules block it writes tells coding agents never to do it. Shipping a one-liner
that does exactly that would mean the product contradicting its own control in
its own README. Use `npm install -g @shomra/agent`, this feature, or the
[GitHub Action](../action.yml).
