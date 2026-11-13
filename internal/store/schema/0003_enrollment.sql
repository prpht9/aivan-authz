-- Phase F: enrollment.
--
-- 0001 already created authz.pending_enrollments with every column the claim
-- needs. This migration adds what the console's refusals and the audit trail
-- need, and one constraint that makes a second live record for the same
-- person, origin and kind impossible rather than merely refused by the console.
--
-- The console refuses a duplicate before it inserts, because that is where the
-- message can name the existing expiry. The index is the guard that holds when
-- two operators run the command at once, and it is what makes "one pending
-- enrollment per kind per origin" a property of the database.

-- At most one *live* record per (user, origin, kind). Claimed rows are history
-- and may accumulate: the console's audit trail depends on them staying. A
-- partial index on "unclaimed" is exactly that.
--
-- A partial index cannot name now(), so an unclaimed row that has merely
-- expired would still occupy the slot. The mint therefore deletes expired
-- unclaimed rows for the same (user, origin, kind) in the same transaction
-- before it inserts. An expired record cannot be claimed by anyone, so
-- removing it loses nothing the audit_log row for the mint does not record.
create unique index pending_enrollments_live
  on authz.pending_enrollments (user_id, origin, kind)
  where claimed_at is null;

-- The claim looks a record up by the digest of the code it was sent. The
-- update's predicates are the digest and the origin; the expiry and claim
-- state are filters on the one row the digest finds. A unique index on the
-- digest says one code names at most one record, which is also what makes the
-- lookup an equality on a 32-byte value rather than a scan.
create unique index pending_enrollments_code_hash
  on authz.pending_enrollments (code_hash);

-- What an operator-facing action was: who ran the console command, and the
-- subject it acted on. The audit_log row the claim writes names the record it
-- consumed; the console's row names the record it minted. Existing rows keep
-- null, which reads as "written before this column existed".
alter table authz.audit_log
  add column actor text,
  add column subject_id uuid;

-- An index for the operator's own question: what has happened to this person,
-- most recent first. The audit table is append-only and read by hand.
create index audit_log_user_at on authz.audit_log (user_id, at desc);

-- The console re-reads a record for its refusals; this is the index for "what
-- is live for this person on this origin".
create index pending_enrollments_expiry
  on authz.pending_enrollments (expires_at);