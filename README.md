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
| `cmd/authz-admin` | a workstation, never an image | `enroll-new`, `list-devices`, `revoke`, `purge`, `service`, `relay-keygen`, `relay-register`, `relay-retire` |

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

## Registering a phone with the approval service

A phone that approves requests has to be known to `aivan-approval` as well as to
this gate. The relay holds a routing row with the phone's public key, so it can
address a hint to it and verify the signature it posts. A registered *service*
writes that row; the phone never registers itself.

**Run every command here as hud's credential.** `aivan_core` is the role the hud
pod uses, and it holds the whole operator surface; the gate's `aivan_authz` login
holds only the claim path and answers `permission denied` for everything else:

```console
$ source ~/work/personal/dotfiles/.functions_aivan
$ cnpg_setup aivan_hud
$ export AIVAN_HOSTS=aivan-hud.home.arpa
```

The connection is libpq's own environment (`PGHOST`, `PGPORT`, `PGUSER`,
`PGPASSWORD`, `PGDATABASE`), which `cnpg_setup` already exports, so the tool and
`psql` reach the same database with no second variable. The split is
`aivan-hud/db/migration/202611190100_operator_surface_grants.rb`;
`doc/runbook.md` states it for an operator.

The service key is the credential that signs a registration, and it lives in
the operator config directory, `~/.config/aivan/keys`. The path does not depend
on the working directory, so the same command works from `aivan-hud` and from
this checkout. `AIVAN_SERVICE_KEY_DIR` overrides the directory; `--dir` overrides
both.

```console
$ ./bin/authz-admin relay-keygen
created /Users/chris/.config/aivan/keys/aivan-authz.key (0600) and /Users/chris/.config/aivan/keys/aivan-authz.pub
fingerprint: 8d6408ae…
```

That key is **the tool's**, not a phone's. A phone's key is a different key with
a different algorithm: the Android Keystore produces P-256, so every phone
registers as `es256` whatever the service key is.

The gate's own pod carries the same five variables, so its Secret
`aivan-authz-db` needs `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD` and
`PGDATABASE` rather than the single `AIVAN_DB_URL` an older install has. A pod
whose Secret still holds only the old key fails to start with
`CreateContainerConfigError`, and once started it refuses with `PGDATABASE is
required`.

The private half is written `0600` in a `0700` directory. Register the public
half with the relay, on a host that can reach its database, then copy the
private half to a Secret or a `pass` entry. The workstation copy is the one
`authz-admin` signs with, so deleting it means the next registration has no key:

```console
$ cd ../aivan-approval
$ rake "service:register[aivan-authz]" KEY=~/.config/aivan/keys/aivan-authz.pub ALG=ed25519
```

`service:register` prints the same fingerprint the keygen did. If the two
disagree, one of them is a different key.

**Enrollment and registration are one flow.** The phone's key is created in its
Keystore when it claims the code, so no tool can know the public key before then.
`--register-relay` mints the code, waits for the claim, and registers the device
the claim produced:

```console
$ ./bin/authz-admin enroll-new --username chris --origin aivan-hud.home.arpa \
    --kind phone --register-relay
```

The wait ends at the code's expiry. If the relay is down, the device is still
live at home and the registration is one later command:

```console
$ ./bin/authz-admin relay-register --device <uuid>
$ ./bin/authz-admin relay-retire   --device <uuid>
```

`AIVAN_APPROVAL_URL` names the relay (default `https://approval-dev.cincyaivan.com`);
`AIVAN_APPROVAL_CA` is a PEM bundle for a CA the workstation does not trust yet.
`config/README.md` states the key's lifetime and why the private half never
reaches the cluster.

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
