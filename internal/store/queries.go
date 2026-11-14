package store

// Prepared statement names. They are exported so tests can assert that the
// gate executes them by name rather than by re-sending SQL.
const (
	StmtVerify        = "aivan_verify"
	StmtNonce         = "aivan_nonce_insert"
	StmtCountID       = "aivan_nonce_count"
	StmtSessionMint   = "aivan_session_mint"
	StmtSessionRead   = "aivan_session_read"
	StmtSessionDelete = "aivan_session_delete"
	// StmtEnrollDevice is the call to authz.enroll_device(), the definer
	// function that replaces the two statements this package used to run.
	StmtEnrollDevice = "aivan_enroll_device"

	// The signature-verification statements. They read the key a signature is
	// checked against, and (for an approval) the hash the signed bytes must
	// match. Both are reads the grant matrix allows and nothing more.
	StmtServiceKey   = "aivan_service_key"
	StmtDeviceKey    = "aivan_device_key"
	StmtApprovalHash = "aivan_approval_hash"
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
//
// The device row is read and never written here. The only write the gate may
// make to authz.devices is the last_seen_at stamp in SessionMintSQL, which the
// column grant allows.
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

// NonceCountSQL counts the nonce table, for the table cap. The count is the
// only thing the gate does on a schedule now: the purge of expired rows is the
// admin binary's job (doc/schema-handover.md §5), so the cap is measured here
// and the rows are removed elsewhere.
const NonceCountSQL = `select count(*) from authz.nonces`

// SessionMintSQL inserts one session and stamps the device's last_seen_at in
// the same statement, so the one write per session lifetime also answers "when
// was this device last used".
//
// The device row is the source of the insert. A device that is missing, bound
// to another origin, or revoked between the proof check and this statement
// produces no update, so the insert selects nothing and the statement returns
// no row. That is a denial on the same path as a failed lookup.
//
// last_seen_at is the one column the gate may update on authz.devices, which
// is why the stamp is here rather than a second statement: the column grant
// bounds the write to this column alone.
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

// EnrollDeviceSQL completes an enrollment through the definer function. The
// function consumes the pending record, inserts the device, and returns the
// identity it created; the gate may not do any of those three things directly.
//
// Every predicate in the consume is part of the authorization: the digest, the
// origin, "not yet claimed" and "not yet expired" are all inside the function,
// and a call that matches none of them returns no row. The caller supplies the
// device id it generated; user, origin and kind come from the record.
//
// It returns no audit row and needs no `returning` on the audit table: the gate
// holds INSERT on authz.audit_log and no SELECT, so the evidence is written and
// discarded. The record id is in the result so the audit row can name the
// pending record the claim spent, without reading pending_enrollments back.
const EnrollDeviceSQL = `
select user_id, kind, username, record_id
  from authz.enroll_device($1, $2, $3, $4, $5)`

// EnrollAuditSQL records a claim. The actor is the device it created; the
// console's mint writes the operator's OS user in the same columns.
//
// No returning clause: the gate may not read authz.audit_log, so an insert that
// tried to read back would be a grant error rather than a result.
const EnrollAuditSQL = `
insert into authz.audit_log (user_id, device_id, host, route, decision, reason, request_id, subject_id)
values ($1, $2, $3, '/__aivan/enroll', 'enroll', 'claimed', $4, $5)`

// ServiceKeySQL resolves a service's public key by id. retired_at is selected
// rather than filtered, so the caller can tell a refusal reason apart in the
// decision log without a second statement.
const ServiceKeySQL = `
select public_key, alg, retired_at is not null
  from authz.services
 where id = $1`

// DeviceKeySQL resolves a device's public key and its owner. It is the same
// row the proof path reads, narrowed to what a signature check needs; the
// column grant on devices already allows every one of these.
const DeviceKeySQL = `
select public_key, alg, origin, revoked_at, user_id
  from authz.devices
 where id = $1`

// ApprovalHashSQL reads the stored request hash and the person an approval is
// for. The hash is what the signed decision must name, so a signature cannot be
// spent against a payload that was swapped after approval.
const ApprovalHashSQL = `
select request_hash, subject_user_id
  from authz.approvals
 where id = $1`

// GateStatements is the list NewConnection prepares. Ordering is irrelevant;
// the names are the contract.
//
// The purge statements are gone: expired nonces and idle sessions are removed
// by `authz-admin purge`, run as a CronJob, because removing them is
// administration rather than serving.
func GateStatements() []Statement {
	return []Statement{
		{Name: StmtVerify, SQL: VerifySQL},
		{Name: StmtNonce, SQL: NonceSQL},
		{Name: StmtCountID, SQL: NonceCountSQL},
		{Name: StmtSessionMint, SQL: SessionMintSQL},
		{Name: StmtSessionRead, SQL: SessionReadSQL},
		{Name: StmtSessionDelete, SQL: SessionDeleteSQL},
		{Name: StmtEnrollDevice, SQL: EnrollDeviceSQL},
		{Name: StmtServiceKey, SQL: ServiceKeySQL},
		{Name: StmtDeviceKey, SQL: DeviceKeySQL},
		{Name: StmtApprovalHash, SQL: ApprovalHashSQL},
	}
}
