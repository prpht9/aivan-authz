# Start here

Picking this project up in a fresh session: read this page, then one document.

## If you are changing the gate's runtime

`doc/schema-handover.md` — what leaves this project, the two-binary split, the
statement changes, the boot probe. It is the current instruction set, and it has
been implemented: the two binaries exist, the schema has moved, and the boot
probe asserts the absences it names.

The short version: this project keeps the algorithm (canonical strings,
signatures, policy, the verify path) and gives up the schema and the
administration.

## Two binaries, one module

| Binary | Where it runs | What it does |
|---|---|---|
| `cmd/authz-gate` | the pod, from `deploy/Dockerfile` | `serve` only |
| `cmd/authz-admin` | a workstation, never an image | `enroll-new`, `list-devices`, `revoke`, `purge`, `service` |

`rake build` produces both in `bin/`. `rake build:image` builds an image
containing only the gate; `TestGateBinaryHasNoAdminCommands` and
`TestDockerfileBuildsOnlyTheGate` are what keep it that way.

## Where the schema lives

`aivan-hud/db/migration/`. This repository contains no DDL and no migration
runner. The integration harness applies hud's migrations to a scratch database,
so the tests run against the schema an install actually has:

```console
$ rake testdb        # needs a Postgres the test user can create roles in
```

`AIVAN_TEST_SUPERUSER_URL` defaults to `postgres://postgres@localhost/postgres`.
The harness skips rather than fails when no cluster is reachable or when the
`aivan-hud` checkout is absent.

## Reference, not instruction

| Document | What it is |
|---|---|
| `doc/aivan-initial-spec.md` | what the service must be. §6.3 came amended on 2026-11-14 |
| `doc/aivan-initial-plan.md` | how it was built, phase by phase. §4.1 and §9 are superseded |
| `doc/design-notes.md` | the reasoning behind the decisions |
| `doc/runbook.md` | the operator procedure, amended 2026-11-14 for the handover |
| `doc/phase-*-record.md` | what each phase actually produced |
| `implementation-phase-*.md` | the standalone work files for phases A–G |

Read the spec for intent. Read the plan only to understand how something got
its shape; where the plan and the handover disagree, the handover wins.

## The one thing not to break

`internal/proof` must stay the single implementation of the canonical strings
and the signature checks. The operator binary and the gate both link it. Two
implementations drift, and a drifted canonical string is an authentication
bypass.

## Companion documents in aivan-hud

- `aivan-hud/doc/schema-ownership.md` — roles, grants, the definer functions,
  and who performs which action.
- `aivan-hud/doc/plan-approvals.md` — the phone approval flow, which is the
  reason this gate exists.
- `aivan-hud/doc/auth.md` — how the application consumes the gate's headers.

# Command examples

```

export SUPW="$(kubectl -n aivan-core get secret aivan-core-superuser -o jsonpath='{.data.password}' | base64 -d)"
export AIVAN_DB_URL="postgres://postgres:${SUPW}@127.0.0.1:5433/aivan_core?sslmode=disable"
./bin/authz-admin revoke --device 62aa0ecf-c79c-3792-fec6-5dd72c70a5ec
./bin/authz-admin enroll-new --username alice --origin aivan-hud.home.arpa --kind browser
```
