package store

// Prepared statement names. They are exported so tests can assert that the
// gate executes them by name rather than by re-sending SQL.
const (
	StmtVerify        = "aivan_verify"
	StmtNonce         = "aivan_nonce_insert"
	StmtPurge         = "aivan_nonce_purge"
	StmtCountID       = "aivan_nonce_count"
	StmtSessionMint   = "aivan_session_mint"
	StmtSessionRead   = "aivan_session_read"
	StmtSessionDelete = "aivan_session_delete"
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

// GateStatements is the list NewConnection prepares. Ordering is irrelevant;
// the names are the contract.
func GateStatements() []Statement {
	return []Statement{
		{Name: StmtVerify, SQL: VerifySQL},
		{Name: StmtNonce, SQL: NonceSQL},
		{Name: StmtPurge, SQL: PurgeSQL},
		{Name: StmtCountID, SQL: NonceCountSQL},
		{Name: StmtSessionMint, SQL: SessionMintSQL},
		{Name: StmtSessionRead, SQL: SessionReadSQL},
		{Name: StmtSessionDelete, SQL: SessionDeleteSQL},
	}
}
