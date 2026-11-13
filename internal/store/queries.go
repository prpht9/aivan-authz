package store

// Prepared statement names. They are exported so tests can assert that the
// gate executes them by name rather than by re-sending SQL.
const (
	StmtVerify  = "aivan_verify"
	StmtNonce   = "aivan_nonce_insert"
	StmtPurge   = "aivan_nonce_purge"
	StmtCountID = "aivan_nonce_count"
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

// PurgeSQL removes every nonce past its expiry. Phase G adds a ticker for it;
// until then the nonce handler runs it on its own once-a-minute schedule.
const PurgeSQL = `delete from authz.nonces where expires_at < now()`

// NonceCountSQL counts the nonce table, for the table cap.
const NonceCountSQL = `select count(*) from authz.nonces`

// GateStatements is the list NewConnection prepares. Ordering is irrelevant;
// the names are the contract.
func GateStatements() []Statement {
	return []Statement{
		{Name: StmtVerify, SQL: VerifySQL},
		{Name: StmtNonce, SQL: NonceSQL},
		{Name: StmtPurge, SQL: PurgeSQL},
		{Name: StmtCountID, SQL: NonceCountSQL},
	}
}
