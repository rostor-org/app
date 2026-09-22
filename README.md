# Rostor

A modular, people-first directory and auth service for organisations.
Conceptually: Active Directory rebuilt from first principles, with the
accumulated confusion removed. One authorisation model, one approval
primitive, one credential model, one policy engine, one offline contract.

Status: early MVP. What works today is the "Windows logon" slice: a member
in Rostor signs in at a Windows lock screen through a Rostor credential
provider, verified by the core over mutual TLS, with every attempt audited
in a hash-chained log. It runs as a single-binary appliance on Debian or
Ubuntu with signed in-product updates.

- [docs/core-dev.md](docs/core-dev.md) — run the core locally, admin CLI
- [docs/appliance.md](docs/appliance.md) — one-line install, updates, releasing
- [docs/windows-logon-build.md](docs/windows-logon-build.md) — the Windows agent and credential provider
- [docs/contracts/windows-logon.md](docs/contracts/windows-logon.md) — the wire contract between core, agent and provider

The design authority is the Agent Build Spec in the separate `project`
repository; code follows it, and where they disagree the spec wins.

## Licence

[PolyForm Noncommercial 1.0.0](LICENSE): free to use, modify and share for
noncommercial purposes, which includes non-profits, schools, clubs,
makerspaces and personal use. Commercial use is not licensed yet. The
intent is to relicense under MIT once the project matures; the licence
in this repository is what applies until then.
