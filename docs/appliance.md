# The Rostor appliance

Self-hosted single-node mode (spec §11) on a plain Debian 12/13 or Ubuntu
24.04 box. One command installs it; updates come from a signed release
channel checked from inside Rostor. Nothing is pulled from git and nothing is
compiled on the box.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/rostor-org/app/main/deploy/install.sh | sudo sh
```

For a private repository, export `ROSTOR_CHANNEL_TOKEN=<GitHub token with
read access>` first; the installer stores it in `/etc/rostor/env` for the
updater. Optional: `ROSTOR_TENANT=<name>` (default `rostor`),
`ROSTOR_CHANNEL=beta`.

What it does, in order: installs `postgresql` and `curl`; creates the
`rostor` system user, `/var/lib/rostor` and the `rostor` database; pins the
release public key at `/etc/rostor/release.pub` (and refuses to change it
silently later); fetches the channel manifest, downloads the binary for the
architecture, checks its SHA-256 against the manifest, verifies the
manifest's Ed25519 signature; installs `/usr/local/bin/rostor` and the systemd
units; runs `rostor bootstrap` once (prints the admin token, also kept in
`/var/lib/rostor/bootstrap.out` until you delete it); starts everything.
Re-running is safe: it upgrades and repairs, never re-bootstraps.

Layout:

| Path | Purpose |
|---|---|
| `/usr/local/bin/rostor` (+ `.previous`) | the binary and the last one, for rollback |
| `/etc/rostor/env` | listeners, channel URL/token, trusted proxies (`ROSTOR_TRUSTED_PROXIES=<proxy ip>`) |
| `/etc/rostor/release.pub` | pinned release signing key |
| `/var/lib/rostor/` | master key, CA, server cert, update state |
| `rostor.service` | the core: `:8443` mutual TLS for devices, `:8080` plain HTTP for a reverse proxy |
| `rostor-update-check.timer` | hourly `rostor update check` → `update-state.json` |
| `rostor-update.path` → `rostor-update.service` | runs `rostor update apply` as root when the core drops `update.request` |

Put a TLS-terminating proxy (NGINX Proxy Manager, Caddy…) in front of
`:8080` for humans and the admin CLI. Devices must reach `:8443` directly:
mutual TLS cannot pass through a terminating proxy.

## Updates

Spec §13 "Staged" class: deliberate and visible, never silent.

- `rostor admin update status` — what is running, what the channel offers.
- `rostor admin update apply` — asks the appliance to install the available
  version. The core, which runs unprivileged, writes a request file; the
  systemd path unit runs the privileged updater, which downloads, verifies,
  swaps the binary atomically (keeping `.previous`) and restarts the service.
  The new binary migrates the database on start. The request is audited.
- `sudo rostor update apply` does the same from a shell. Rollback:
  `mv /usr/local/bin/rostor.previous /usr/local/bin/rostor && systemctl restart rostor`
  (schema migrations are forward-only; take a `pg_dump` before big jumps).

## Releasing (operator's machine)

The signing key never leaves the operator's machine.

```bash
bin/rostor-release keygen --out ~/.rostor/release-signing.key > deploy/release.pub   # once
make release VERSION=v0.1.1 NOTES="what changed"
```

`make release` builds `linux-amd64`, `linux-arm64` and the Windows agent,
creates the GitHub release, uploads the binaries, signs a manifest whose file
URLs are the GitHub asset API URLs (they work for private and public repos),
uploads it, and commits the manifest as `deploy/channels/stable.json`, which is
the URL every appliance polls. Publishing to the channel is therefore a git
push; the appliance still trusts only the signature, not the repo.
