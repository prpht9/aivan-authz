package store

// Prepared statement names. They are exported so tests can assert that the
// gate executes them by name rather than by re-sending SQL.
const (
	StmtVerify        = "aivan_verify"
	StmtNonce         = "aivan_nonce_insert"
	StmtPurge         = "aivan_nonce_purge"
	StmtPurgeSessions = "aivan_session_purge"
	StmtCountID       = "aivan_nonce_count"
	StmtSessionMint   = "aivan_session_mint"
	StmtSessionRead   = "aivan_session_read"
	StmtSessionDelete = "aivan_session_delete"
	StmtEnrollClaim   = "aivan_enroll_claim"
	StmtEnrollDevice  = "aivan_enroll_device"
)

// VerifySQL consumes a nonce and returns everything the gate needs to decide,
// in one statement. The delete is the consume: a second use of the same nonce
// deletes nothing, so it returns no row and loses the race rather than being
// filtered out afterwards.
//
// The device id is a predicate on the nonce, not a filter on the result, so the
// plan is one index probe on authz.nonces_pkey followed by a primary-key join.
//
// Roles come from the same statement. A second query per role would be a second
// round trip on the hot path, and S7 has to hold without one.
//
// d.kind is selected because X-Aivan-Device-Kind is part of the output
// contract; the plan's statement text omits it.
const VerifySQL = `
with consumed as (
  delete from authz.nonces
   where nonce_hash = $1
     and device_id  = $2
     and expires_at > now()
  returning device_id, issued_at
)
select d.id, d.public_key, d.alg, d.kind, d.revoked_at, d.user_id, d.origin,
       u.username, u.active, c.issued_at,
       coalesce(array_agg(g.name order by g.name)
                filter (where g.name is not null), '{}') as roles
  from consumed c
  join authz.devices d on d.id = c.device_id
  join public.users u  on u.id = d.user_id
  left join public.groups_users gu on gu.user_id = u.id
  left join public.groups g        on g.id = gu.group_id
 group by d.id, d.public_key, d.alg, d.kind, d.revoked_at, d.user_id, d.origin,
          c.issued_at, u.username, u.active`

// NonceSQL inserts a nonce. It intentionally touches no device row: the handler
// must not learn whether the claimed device exists (S14), so there is no read
// of authz.devices on this path and no insert ... select from it.
//
// The TTL is bound as an interval value, not interpolated and not passed as a
// duration string, so the statement has one meaning whichever client sends it.
const NonceSQL = `
insert into authz.nonces (nonce_hash, device_id, issued_at, expires_at)
values ($1, $2, now(), now() + $3)
returning expires_at`

// PurgeSQL removes every nonce that has been expired for longer than the purge
// grace. The grace is not about validity — the verify predicate already
// refuses an expired nonce — it is about the race: a nonce row is deleted by a
// request's own `delete ... returning`, and deleting it out from under that
// statement would turn a valid in-flight request into a replay.
//
// One hour is far longer than any request can take (the gate answers within
// five seconds), so nothing can still be racing a row this removes.
const PurgeSQL = `delete from authz.nonces where expires_at < now() - interval '1 hour'`

// PurgeSessionsSQL removes sessions that are idle-expired or past their
// absolute cap. The idle rule gets the same grace as the nonce rule, for the
// same race: the read statement slides idle_expires_at, and a row removed
// between that read and its commit would refuse a request that had already
// passed. An absolutely expired session is past any grace by construction, so
// it is removed as soon as it is seen.
const PurgeSessionsSQL = `
delete from authz.sessions
 where idle_expires_at < now() - interval '1 hour'
    or absolute_expires_at < now()`

// NonceCountSQL counts the nonce table, for the table cap.
const NonceCountSQL = `select count(*) from authz.nonces`

// SessionMintSQL inserts one session and stamps the device's last_seen_at in
// the same statement, so the one write per session lifetime also answers "when
// was this device last used".
//
// The device row is the source of the insert. A device that is missing, bound
// to another origin, or revoked between the proof check and this statement
// produces no update, so the insert selects nothing and the statement returns
// no row. That is a denial on the same path as a failed lookup.
const SessionMintSQL = `
with device as (
  update authz.devices
     set last_seen_at = now()
   where id = $2
     and origin = $3
     and revoked_at is null
  returning id
)
insert into authz.sessions (token_hash, device_id, idle_expires_at, absolute_expires_at)
select $1, d.id, now() + $4, now() + $5
  from device d
returning idle_expires_at, absolute_expires_at`

// SessionReadSQL authenticates one cookie and returns everything the decision
// needs, in one statement.
//
// The idle expiry is pushed forward only when it would move by more than the
// window, so a busy session writes once a minute at most and a quiet one never
// writes. An expired session updates no row, so it returns no row.
//
// The join is through authz.devices, which is what makes a revoke effective on
// the next request (S5): the row still exists, revoked_at is set, and the
// caller denies. The origin predicate keeps a session minted on one host from
// authenticating another even though the __Host- cookie already cannot cross
// hosts.
const SessionReadSQL = `
with touched as (
  update authz.sessions s
     set idle_expires_at = case
           when now() + $2 > s.idle_expires_at + interval '60 seconds'
           then now() + $2 else s.idle_expires_at end
   where s.token_hash = $1
     and s.idle_expires_at > now()
     and s.absolute_expires_at > now()
  returning s.device_id
)
select d.id, d.revoked_at, d.user_id, d.kind,
       u.username, u.active,
       coalesce(array_agg(g.name order by g.name)
                filter (where g.name is not null), '{}') as roles
  from touched t
  join authz.devices d on d.id = t.device_id and d.origin = $3
  join public.users u  on u.id = d.user_id
  left join public.groups_users gu on gu.user_id = u.id
  left join public.groups g        on g.id = gu.group_id
 group by d.id, d.revoked_at, d.user_id, d.kind, u.username, u.active`

// SessionDeleteSQL removes one session by the hash of its cookie. It is
// idempotent: a token that matches no row deletes nothing and is not an error.
const SessionDeleteSQL = `delete from authz.sessions where token_hash = $1`

// EnrollClaimSQL consumes a pending enrollment and names the user it was
// minted for. It is the whole authorization decision for a claim: the code
// digest, the origin and "not yet claimed, not yet expired" are all predicates,
// and the update returns a row only when every one held.
//
// The device id is passed in because the row records who claimed it, and the
// device is inserted in the same transaction. A concurrent second claim updates
// nothing — claimed_at is no longer null — so it returns no row and inserts no
// device (S9, S10, S11).
//
// user_id lives here and nowhere in the request. The claiming device never
// asserts its identity; the record names it. The record id is returned so the
// audit row can name the record the claim consumed.
const EnrollClaimSQL = `
update authz.pending_enrollments
   set claimed_at = now(), claimed_device_id = $1
 where code_hash = $2
   and origin    = $3
   and claimed_at is null
   and expires_at > now()
returning id, user_id, origin, kind`

// EnrollDeviceSQL inserts the device a claim produced. The origin, kind and
// user come from the claimed record rather than from the request, so the device
// cannot be created for a user or host the console did not name.
//
// The partial unique index on (user_id, origin, kind) refuses a second live
// device of one kind. That is a console refusal at mint time, but a race
// between two claims for two different records of the same kind could still
// reach it; the caller maps the unique violation to a refusal.
const EnrollDeviceSQL = `
insert into authz.devices (id, user_id, origin, name, kind, public_key, alg)
values ($1, $2, $3, $4, $5, $6, $7)
returning created_at`

// EnrollAuditSQL records a claim. The actor is the device it created; the
// console's mint writes the operator's OS user in the same columns.
const EnrollAuditSQL = `
insert into authz.audit_log (user_id, device_id, host, route, decision, reason, request_id, subject_id)
values ($1, $2, $3, '/__aivan/enroll', 'enroll', 'claimed', $4, $5)`

// GateStatements is the list NewConnection prepares. Ordering is irrelevant;
// the names are the contract.
func GateStatements() []Statement {
	return []Statement{
		{Name: StmtVerify, SQL: VerifySQL},
		{Name: StmtNonce, SQL: NonceSQL},
		{Name: StmtPurge, SQL: PurgeSQL},
		{Name: StmtPurgeSessions, SQL: PurgeSessionsSQL},
		{Name: StmtCountID, SQL: NonceCountSQL},
		{Name: StmtSessionMint, SQL: SessionMintSQL},
		{Name: StmtSessionRead, SQL: SessionReadSQL},
		{Name: StmtSessionDelete, SQL: SessionDeleteSQL},
		{Name: StmtEnrollClaim, SQL: EnrollClaimSQL},
		{Name: StmtEnrollDevice, SQL: EnrollDeviceSQL},
	}
}
