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

## Shipping it

| Task | What it does |
|---|---|
| `rake push` | builds the image, pushes it, and confirms the registry's config digest is the one just built |
| `rake deploy` | `push`, then applies `deploy/k8s.yaml`, rolls the Deployment, and verifies the running bytes |
| `rake deploy:apply` | applies the manifest only, for a policy or env change (`DRY_RUN=1` validates) |
| `rake deploy:verify` | read-only: the ready pod runs the image the registry serves, and that image was built from `HEAD` |

`AIVAN_NS` names the namespace (default `hermes-agent`); `IMAGE` overrides the
tag. `deploy` refuses to apply when a Secret the manifest mounts is absent,
because the pod would sit pending on the mount. The purge CronJob is not in this
manifest; it lives in aivan-hud's chart with the schema it reads.

`deploy:verify` exists because the deployed image was once seven commits behind
the tree and nothing in the build noticed (`doc/pentest-evidence/a.md` PA1). It
reads the revision out of the running binary's own build stamp, so a tag that
moved underneath a pod is caught rather than assumed.

## Minting a code, and the square a phone scans

`authz-admin enroll-new` prints a code once. At a terminal it also draws a QR
square that encodes the enrollment URL with the code in it, so a phone camera
opens the page with the field filled. `--qr` chooses the drawing (`auto` by
default, `blocks`, `ascii`, `none`); redirected output gets no square, so
scripts see exactly what they saw before.

`doc/enrollment-qr.md` is the contract for the mobile app: the payload, the
claim the app posts, and what it must send afterwards.

## Where the schema lives

`aivan-hud/db/migration/`. This repository contains no DDL and no migration
runner. The integration harness applies hud's migrations to a scratch database,
so the tests run against the schema an install actually has:

```console
$ rake testdb        # needs a Postgres the test user can create roles in
```

The tests read libpq's own environment, the same five variables `psql` reads.
`PGUSER` (or the OS user when unset) must be able to create roles and databases,
and `PGDATABASE` names the maintenance database the scratch ones are created in
(the harness uses `postgres`):

```console
$ PGHOST=127.0.0.1 PGPORT=55432 PGUSER=postgres rake testdb
```

`testdb` passes `-p 1`, because the packages create cluster-wide roles and would
race each other in parallel. The harness skips rather than fails when no cluster
is reachable or when the `aivan-hud` checkout is absent.

## The database connection

There is no connection URL. The gate, `authz-admin`, the tests and the load
seeder all take their connection from `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`
and `PGDATABASE`, exactly as `psql` does, so one shell reaches one database
whichever of them you run. The Secret the Deployment mounts carries those five
names, one key each.

## Reference, not instruction

| Document | What it is |
|---|---|
| `doc/policy-configmap.md` | for the owner of another application: how to write the gate's policy ConfigMap and wire the Traefik side |
| `doc/aivan-initial-spec.md` | what the service must be. §6.3 came amended on 2026-11-14 |
| `doc/aivan-initial-plan.md` | how it was built, phase by phase. §4.1 and §9 are superseded |
| `doc/design-notes.md` | the reasoning behind the decisions |
| `doc/runbook.md` | the operator procedure, amended 2026-11-14 for the handover |
| `doc/pentest-plan.md` | the pentest: scope, cases, tooling, and what reconnaissance already found |
| `doc/pentest-report.md` | what the run found: 25 findings, the coverage matrix, and what stayed unproven |
| `doc/pentest-evidence/` | the case-by-case notes each finding traces to |
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
export CNPG_PRIMARY=$(kubectl get pods -n aivan-core -l cnpg.io/cluster=aivan-core,role=primary -o json|jq -r '.items[0].metadata.name')
kubectl exec -it $CNPG_PRIMARY -n aivan-core -- psql -U postgres
```

```
export PGHOST=127.0.0.1 PGPORT=5433 PGUSER=postgres PGDATABASE=aivan_core PGSSLMODE=disable
export PGPASSWORD="$(kubectl -n aivan-core get secret aivan-core-superuser -o jsonpath='{.data.password}' | base64 -d)"
./bin/authz-admin revoke --device 62aa0ecf-c79c-3792-fec6-5dd72c70a5ec
./bin/authz-admin enroll-new --username alice --origin aivan-hud.home.arpa --kind browser --qr
```
