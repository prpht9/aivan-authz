# Start here

Picking this project up in a fresh session: read this page, then one document.

## If you are changing the gate's runtime

`doc/schema-handover.md` — what leaves this project, the two-binary split, the
statement changes, the boot probe. It is the current instruction set.

The short version: this project keeps the algorithm (canonical strings,
signatures, policy, the verify path) and gives up the schema and the
administration. Schema and DDL move to aivan-hud.

## Reference, not instruction

| Document | What it is |
|---|---|
| `doc/aivan-initial-spec.md` | what the service must be. §6.3 came amended on 2026-11-14 |
| `doc/aivan-initial-plan.md` | how it was built, phase by phase. §4.1 and §9 are superseded |
| `doc/design-notes.md` | the reasoning behind the decisions |
| `doc/runbook.md` | the operator procedure as executed in November 2026 |
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
