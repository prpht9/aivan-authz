# AIVan Authz Service

This project is for building the Ingress Auth service.

it must have extremely low latency, read-only access to the data and be hardened.

Start with `README.md`, then `doc/schema-handover.md`. The short version: this
project keeps the algorithm (canonical strings, signatures, policy, the verify
path) and gives up the schema and the administration. The schema lives in
`aivan-hud/db/migration/`.

## The database connection

Typical flow is for user to cnpg_setup aivan_hud before entering ai client cli. Recommended sql execution form in this project since all the env vars should be already set: `echo "select * from users;" |psql`  Using this form will reduce looking up how to execute sql for this project's database.  So try this form first before other methods.

**The connection is libpq's own environment.** `PGHOST`, `PGPORT`, `PGUSER`,
`PGPASSWORD` and `PGDATABASE` are what `psql` reads, and `pgx` reads the same
five names, so a shell that reaches a database with `psql` reaches it with the
gate, `authz-admin`, the tests and the load seeder. There is no URL variable in
this project: no `AIVAN_DB_URL`, no `DATABASE_URL`, no private test variable. Do
not add one.

- `internal/config/config.go`'s `DatabaseName` reads `PGDATABASE` and refuses a
  blank one, so the gate and the console fail with a sentence rather than
  connecting to a database named after the OS user.
- `store.Open(ctx, "")` passes an empty connection string to pgxpool.
  `pgconn.ParseConfig("")` then takes host, port, user, password, sslmode and
  database entirely from the environment. That is the same precedence psql uses.
  A test harness passes an explicit `user=… dbname=…` string instead, naming the
  scratch database it just created while the rest still comes from the
  environment.
- `PGSSLMODE` matters on an install: `deploy/k8s.yaml` sets `require`, because
  the in-cluster service has its own certificate.

```bash
# the pod's own credential, exported the way an operator would:
export PGHOST=aivan-core-rw.aivan-core.svc.cluster.local PGPORT=5432 \
       PGUSER=aivan_authz PGPASSWORD='<pw>' PGDATABASE=aivan_core PGSSLMODE=require

# from a workstation, over a port-forward (sslmode=disable: the tunnel is local TCP)
export PGHOST=127.0.0.1 PGPORT=15432 PGUSER=aivan_migrations \
       PGPASSWORD='<pw>' PGDATABASE=aivan_core PGSSLMODE=disable
./bin/authz-admin list-devices --username chris
psql -c "select count(*) from authz.nonces"
```

`deploy/k8s.yaml` mounts the five names from the Secret `aivan-authz-db`, one key
per variable, so exporting that Secret reaches the same database with `psql`.
`rake deploy` refuses to apply when a key is missing.

The integration suite uses the same environment. `PGUSER` (or the OS user when it
is unset) must be able to create roles and databases; `PGDATABASE` is the
maintenance database the scratch ones are created in, and the harness names
`postgres` for that. Run `rake testdb`, which passes `-p 1`: the packages create
cluster-wide roles and would race each other in parallel.

```bash
PGHOST=127.0.0.1 PGPORT=55432 PGUSER=postgres rake testdb
```

## The two binaries

| Binary | Where it runs | What it does |
|---|---|---|
| `cmd/authz-gate` | the pod, from `deploy/Dockerfile` | `serve` only |
| `cmd/authz-admin` | a workstation, never an image | `enroll-new`, `list-devices`, `revoke`, `purge`, `service`, `relay-keygen`, `relay-register`, `relay-retire` |

Both take their connection from the environment above and nothing else.
`cmd/authz-gate/main.go` opens the pool with `store.Open(ctx, "")`;
`cmd/authz-admin/main.go` checks `PGDATABASE` first, then does the same.

## Working rules

- `internal/proof` stays the single implementation of the canonical strings and
  the signature checks. Two implementations drift, and a drifted canonical string
  is an authentication bypass.
- `cmd/authz-admin` is never in an image. `TestGateBinaryHasNoAdminCommands` and
  `TestDockerfileBuildsOnlyTheGate` pin that.
- The gate never migrates. `rake db:migrate` in `aivan-hud`, as the schema owner,
  from a workstation over a port-forward.
- Connect through libpq's `PG*` variables. Never add a URL variable, and never
  parse or build a connection string in application code.
- Leave `config/` and anything holding a key untracked. `.gitignore` says why.
- `rake lint` runs `go vet` and fails if `gofmt` would rewrite anything.
