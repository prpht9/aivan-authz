# Implementation phases

One file per phase, each self-contained: read it, finish it, clear context, move
on. The parent plan (`doc/aivan-initial-plan.md`) stays as the whole picture and
is not required reading for any single phase.

| Phase | File | Produces |
|---|---|---|
| A | `implementation-phase-a.md` | `doc/traefik-contract.md` — observed proxy behaviour |
| B | `implementation-phase-b.md` | A binary that starts under the right database role and reports health |
| C | `implementation-phase-c.md` | A nonce-verified request in one statement, with every denial tested |
| D | `implementation-phase-d.md` | Cookie sessions, immediate revoke, CSRF |
| E | `implementation-phase-e.md` | aivan-hud behind the gate; forged headers impossible |
| F | `implementation-phase-f.md` | Browser enrollment with no open path |
| G | `implementation-phase-g.md` | Purge, `413`, load proof, failure drills, runbook |

## How to use these

Start at A. Each file names its own preconditions, its exit criteria, and what
the next phase needs from it, so nothing is lost when context is cleared.

Two rules that matter across all of them:

1. **A security test must be shown to fail without its guard.** Each phase names
   the requirement numbers it satisfies; delete the guard, watch the test fail,
   restore it, and say so in the commit.
2. **Do not start a phase with a failing exit criterion behind you.** The phases
   are ordered by dependency, and E depends on C and D being actually green
   rather than nearly green.

Ordering that is not obvious from the sequence: E lands before F on purpose.
Proving the whole proxy loop with a console-minted session, then building
enrollment, keeps the two hardest-to-debug things apart.

## Where each phase sits against the specification

| Phase | Spec sections | Requirements |
|---|---|---|
| A | §8.1 | S6 (observed) |
| B | §7, §8.4 | S16, S20 |
| C | §5.1, §5.1.1, §6.1, §6.2 | S1–S4, S7, S8, S14, S15, S17, S19, S21 |
| D | §5.4 | S5, S13 |
| E | §6.1, §8.1, §8.2 | acceptance 1, 3, 4, 10 |
| F | §6.4, §6.5 | S9, S10, S11, acceptance 2 |
| G | §8.2, §8.3 | S18, acceptance 5–9 |

S12 is withdrawn (there is no password path). S21 is split: the in-process test
is in C, the two-host proof is in E.

## Status

Update this table as phases complete. It is the only place progress is recorded
outside the phase files themselves.

| Phase | Status | Commit |
|---|---|---|
| A | complete — `doc/traefik-contract.md`, spec revision 3 | |
| B | complete — `doc/phase-b-record.md` | |
| C | complete — `doc/phase-c-record.md` | |
| D | complete — `doc/phase-d-record.md` | |
| E | complete — `doc/phase-e-record.md` | `ce361f2`, hud `6ae58a5` |
| F | complete — `doc/phase-f-record.md` | `8c7f851` |
| G | not started | |

## Checked while writing these files

Not implementation, but worth knowing so nobody re-derives it:

- The DDL in `aivan-initial-plan.md` §4 applies cleanly to PostgreSQL 18.
- The privilege probe behaves as Phase B claims: as a superuser,
  `has_schema_privilege('public','CREATE')` is true and `password_digest` reads
  succeed; as `aivan_authz` after `0002_grants.sql`, both fail with SQLSTATE
  `42501`.
- The verify statement returns the right user and sorted roles, and a second run
  of the same nonce returns zero rows — S1 holds at the SQL level.
- The session statement returns identity through the device join, so a revoke is
  visible on the next request without a second query.
- The enrollment `update … returning` claims once and returns zero rows for a
  wrong origin.
- The partial unique index refuses a second `browser` device on the same origin
  and accepts a `phone` beside it.
- `sha256("")` and `sha256("hello")` in Phase C's vectors are correct.
- The Phase A echo service parses as Ruby, runs on `ruby:4.0.5-slim-trixie`
  (which has no WEBrick in the stdlib — it uses `TCPServer`), and each of its
  auth modes returns the expected status when driven directly and through
  Traefik.

Not checked: the browser-side WebCrypto behaviour in Phase F, which needs a real
browser. Everything involving Traefik is now checked; see
`doc/traefik-contract.md`.