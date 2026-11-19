# Schema handover

What leaves this project, what stays, and what the gate should look like when
the handover is finished.

Status: decided 2026-11-14. Amends `doc/aivan-initial-plan.md` §4.1 and §9, and
supersedes its bootstrap order.

This project keeps the **algorithm**. It gives up the **schema** and the
**administration**.

## 1. Why

The gate is an edge service. A compromise should cost an attacker the ability
to read identity and spend authority that already exists — not the ability to
create or destroy credentials.

The trigger was a concrete observation: `cmd/authz/main.go` imports
`internal/console`, so `authz revoke`, `authz enroll-new`, and
`authz list-devices` all compile into the single binary the pod runs. A
compromised *process* can therefore run them. That is a control distinct from
database grants, and it covers the realistic compromise: someone gets code
execution in the gate and can only run what is in the binary.

Verified in the current build: one binary, `go build -o /authz ./cmd/authz`,
copied into a distroless image with no shell. The commands are present.

## 2. What moves out

| Item | From | To |
|---|---|---|
| `internal/store/schema/*.sql` | here | `aivan-hud/db/migration/` |
| `authz migrate` subcommand | here | `rake db:migrate` |
| `authz.schema_migrations` | the database | dropped; one history in hud |
| schema ownership | `aivan_migrations` | `aivan_core`'s migration role |
| `enroll-new` (mint a code) | the gate binary | `authz-admin` binary, and later hud |
| `revoke` | the gate binary | `aivan_core` via `authz.revoke_device()` |
| `list-devices` | the gate binary | hud `/admin` |
| service key registration | — | hud `rake service:register` |

The definitions of the tables, functions, and grants are in
`aivan-hud/doc/schema-ownership.md`. This document does not repeat them; it
records what happens on this side.

## 3. What stays

The crypto, because it must be byte-identical in the gate and in the operator
commands. Two implementations of a canonical string drift, and a drifted
canonical string is an authentication bypass.

| Package | Why it stays |
|---|---|
| `internal/proof` | canonical strings, Ed25519, ES256, test vectors |
| `internal/policy` | host and prefix to route class |
| `internal/gate` | verify, nonce, session, enroll claim |
| `internal/httpx` | router, health, middleware |
| `internal/audit` | decision records and reason codes |
| `internal/config` | env parse, fail-fast |
| `internal/store` | pools and prepared statements — **statements change**, see §5 |
| `internal/console` | stays in the repo, leaves the image (§4) |

## 4. Two binaries

`cmd/authz/` splits into two main packages in one module.

```
cmd/authz-gate/main.go     serve only
cmd/authz-admin/main.go    enroll-new, revoke (break-glass), list-devices,
                           service register/retire, purge
internal/console/          shared by the admin binary only
```

The Dockerfile copies **only** `authz-gate`:

```dockerfile
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/authz ./cmd/authz-gate
COPY --from=build /out/authz /authz
ENTRYPOINT ["/authz"]
CMD ["serve"]
```

`cmd/authz-admin` is built on a workstation and never enters an image. It is a
break-glass tool for when hud is down; the primary paths are hud actions.

**A test must assert this.** After the split, add a check that the built image
contains no admin subcommand. The cheapest form: a Go test that reads the image
manifest, or a build step that fails if `cmd/authz-admin` is referenced by the
Dockerfile. Without a test, someone will add the binary back for convenience.

## 5. Statement changes

The SQL in `internal/store/queries.go` is rewritten against the new grants. The
shapes change in five places:

| Statement | Change |
|---|---|
| `VerifySQL` | unchanged in shape; `devices` is now in the app's schema, still read-only |
| `NonceSQL` | unchanged |
| `SessionMintSQL` | unchanged; `update ... set last_seen_at` is now a column grant |
| `SessionReadSQL` | unchanged |
| `SessionDeleteSQL` | unchanged |
| `PurgeSQL`, `PurgeSessionsSQL` | **removed**; the purge moves to the admin binary, run as a CronJob |
| `EnrollClaimSQL`, `EnrollDeviceSQL` | **replaced** by one call to `authz.enroll_device(...)` |
| `EnrollAuditSQL` | unchanged; still insert-only, still no `returning` |

The two enrollment statements collapsing into one function call is the largest
change, and it is a simplification: the atomicity that was a transaction is now
a property of the function.

`NonceCountSQL` stays, since the table cap still needs a count.

## 6. Boot probe

`internal/store/probe.go` holds the startup privilege probe, which refuses to
start the gate unless the grants are exactly as narrow as intended. It already
does this for two assertions (S16, S20); it grows to the full list below. The
probe asserts **absence** as well as presence:

```
must hold:     usage on schema authz
               select on authz.devices, authz.services, authz.approvals
               execute on authz.enroll_device
               insert on authz.audit_log, usage on its sequence
               DML on authz.nonces, authz.sessions
must not hold: insert on authz.devices
               update on authz.devices (beyond last_seen_at)
               delete on authz.devices
               select on authz.audit_log
               insert or update on authz.approvals
               insert on authz.services
               create on schema authz, or any DDL
```

A gate that can write `devices` or read `audit_log` is a misconfigured gate, and
it should fail to start rather than serve. That error should name the offending
grant, so an operator can fix it without reading this document.

## 7. Deployment

Unchanged except for the environment:

- No `migrate` step at boot. The gate starts, probes, serves.
- The connection is libpq's own environment: `PGHOST`, `PGPORT`, `PGUSER`,
  `PGPASSWORD` and `PGDATABASE`, as `psql` reads them. `PGUSER` names a credential
  with only the grants in §6, and the Secret `aivan-authz-db` carries one key per
  variable. There is no connection URL.
- The operator credential is not mounted into the gate. It belongs to the admin
  binary, the CronJob, and `kubectl exec`.

The three IngressRouters, the `forwardAuth` middleware, and the network policy
in `deploy/` are unaffected.

## 8. What this project keeps documenting

- `doc/aivan-initial-spec.md` — amend §6.3 to name aivan-hud as the verifier of
  grants, and §7.1 to reflect that `devices` and `approvals` are read-only here.
- `doc/aivan-initial-plan.md` — §4.1 and §9 are superseded by this document and
  by `aivan-hud/doc/schema-ownership.md`. Mark them rather than deleting them,
  so the reasoning stays visible.
- `doc/runbook.md` — §1b's port-forward and local binary are replaced by
  `kubectl exec`, and the bootstrap order changes to the two-step form in
  `aivan-hud/doc/schema-ownership.md` §6.
- The phase records stay as history. They describe what was built, and that
  remains true of the phases as they were executed.

## 9. Order of work

1. Add the two definer functions and the narrow grants as a migration in
   aivan-hud.
2. Rewrite `queries.go` against them; run the existing integration tests with
   the narrowed credential. Most failures should be grant errors, which is the
   point.
3. Split the binaries; make the Dockerfile copy only the gate.
4. Add the boot probe's absence assertions.
5. Delete `internal/store/schema/`, the `migrate` subcommand, and
   `schema_migrations`.
6. Move the purge to the admin binary and add a CronJob.
7. Update the documents in §8.

Steps 1 and 2 can land before 3, and probably should: narrowing the credential
proves the statements are right before the binary split makes debugging harder.

## 10. What is not decided here

The approval endpoints on this side — `POST /__aivan/verify-signature` — are
specified in `aivan-hud/doc/plan-approvals.md` §8.2. It is one endpoint on the
gate, and it returns claims, never authority.

Whether the gate keeps serving `/__aivan/enroll` for browsers is unchanged. The
page and the claim stay; only the minting of the code moves out.
