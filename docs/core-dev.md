# Running the Rostor core (MVP)

Prerequisites: Go 1.22+, PostgreSQL 15+.

```bash
createdb rostor_dev
go build -o bin/rostor ./cmd/rostor
./bin/rostor bootstrap --tenant myorg      # one-shot: migrates, creates tenant, CA, admin token
export ROSTOR_TOKEN=rst_...                # printed once by bootstrap
./bin/rostor serve                          # https://localhost:8443
```

Environment:

| Variable | Default | Meaning |
|---|---|---|
| `ROSTOR_DATABASE_URL` | `postgres:///rostor_dev?sslmode=disable` | Postgres DSN |
| `ROSTOR_DATA_DIR` | `~/.rostor` | master key, server cert, `ca.crt` |
| `ROSTOR_LISTEN` | `:8443` | TLS listen address |
| `ROSTOR_TLS_HOSTS` | all local IPv4s + hostname | SANs for the server certificate (comma-separated) |
| `ROSTOR_URL` / `ROSTOR_CA` | `https://localhost:8443` / `$ROSTOR_DATA_DIR/ca.crt` | admin CLI target |

Admin CLI examples (the CLI is a plain client of the HTTP API):

```bash
bin/rostor admin user create --username dan --display "Dan Evans"
bin/rostor admin user password --user dan --password '...'
bin/rostor admin group create --name members
bin/rostor admin group add --group members --user dan
bin/rostor admin grant create --group members --role user --resource-type workstations --resource-id all
bin/rostor admin device token                # enrollment token for one workstation
bin/rostor admin why --user dan --resource-type workstation --resource-id DESKTOP-XYZ
bin/rostor admin user suspend --user dan
bin/rostor admin audit --limit 20
bin/rostor admin audit verify                # recompute the hash chain
```

Tests need a database of their own (they create a tenant):

```bash
createdb rostor_test
make test
```

## What this slice implements (and what it does not)

Implements, per spec §0.3 M0/M1 and the parts of M2/M4 the Windows logon
contract needs: tenant-ID in every table; hash-chained append-only audit;
six-object model minus Decisions; grants with CEL conditions classified at
write time; `Check`/`Why`; authenticator bindings with a sealed store;
password method behind the §7.6 contract; core-owned lockout; ceremonies;
sessions; device enrollment with a core CA; `Verify`; a policy table with
priority merge; a string catalog with codes-not-sentences.

Not implemented yet (stubbed or absent, deliberately): Decisions; dynamic
groups; WebAuthn/OIDC; snapshots and revocation deltas; the plugin runtime
(the password method is compiled in behind the contract); read replicas and
the Priority channel (single node, suspension is Immediate); the crypto
provider is the default only, pending the M0 spike (spec §18 OQ4).
