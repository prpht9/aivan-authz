-- The gate's schema. Copied from doc/aivan-initial-plan.md §4.
--
-- apply order: this migration references public.users, so the application's
-- schema has to exist first. That is the same dependency 0002 records, and it
-- is why both migrations are applied by the install step after the application
-- database is in place (Phase E).
create schema authz;

create table authz.schema_migrations (
  version    integer primary key,
  applied_at timestamptz not null default now()
);

create table authz.devices (
  id           uuid primary key,
  user_id      bigint not null references public.users(id),
  origin       text   not null,          -- the one host this key belongs to
  name         text   not null,
  kind         text   not null check (kind in ('phone','tablet','browser')),
  public_key   bytea  not null,
  alg          text   not null check (alg in ('ed25519','es256')),
  proof        text   not null default 'nonce' check (proof in ('nonce','mtls')),
  fingerprint  bytea,
  created_at   timestamptz not null default now(),
  last_seen_at timestamptz,
  revoked_at   timestamptz
);

-- One device per person, per origin, per kind. See the notes in the plan.
create unique index on authz.devices (user_id, origin, kind)
  where revoked_at is null;

-- No foreign key on device_id on purpose: a nonce may only ever be issued for
-- a device id the client claims without revealing whether that device exists
-- (S14). The verify query enforces the binding, and the purge job keeps the
-- table small. issued_at is stored rather than derived from expires_at minus
-- the TTL, so a configuration change does not retroactively move the issuance
-- time of nonces already in flight.
create table authz.nonces (
  nonce_hash bytea primary key,
  device_id  uuid  not null,
  issued_at  timestamptz not null default now(),
  expires_at timestamptz not null
);
create index on authz.nonces (expires_at);

create table authz.sessions (
  token_hash          bytea primary key,
  device_id           uuid  not null references authz.devices(id) on delete cascade,
  created_at          timestamptz not null default now(),
  idle_expires_at     timestamptz not null,
  absolute_expires_at timestamptz not null
);
create index on authz.sessions (idle_expires_at);

create table authz.pending_enrollments (
  id                uuid primary key default gen_random_uuid(),
  user_id           bigint not null references public.users(id),
  origin            text   not null,   -- the host this enrollment is valid on
  kind              text   not null,
  code_hash         bytea  not null,
  created_at        timestamptz not null default now(),
  expires_at        timestamptz not null,
  claimed_at        timestamptz,
  claimed_device_id uuid
);

create table authz.audit_log (
  id         bigserial primary key,
  at         timestamptz not null default now(),
  user_id    bigint,
  device_id  uuid,
  host       text not null,
  route      text not null,
  decision   text not null,
  reason     text not null,
  request_id text
);