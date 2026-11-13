-- Roles and grants for aivan-authz.
--
-- Run once, as a superuser or the database owner, against the application's
-- database. It is not a migration: the gate's own migrations run afterwards as
-- aivan_migrations, and this file is what makes that possible.
--
-- Two roles, because one is not enough:
--
--   aivan_authz       the runtime credential. No CREATE, no password_digest,
--                     no write outside schema authz. The gate refuses to start
--                     if this role holds more than 0002_grants.sql intends.
--   aivan_migrations  owns schema authz and applies the gate's migrations. It
--                     is never put in a pod: the image is distroless, and
--                     `authz migrate` runs from a workstation with a
--                     port-forward.
--
-- Passwords are not in this file. Set them here before applying, or run the
-- statements by hand with a generated value:
--
--   create role aivan_authz login nosuperuser nocreatedb nocreaterole
--     password '<authz pw>';
--
-- Substitute the two placeholders, then:
--
--   psql "$DATABASE_URL" -f deploy/roles.sql
--
-- Safe to run twice only if the CREATE ROLE lines are commented out on the
-- second run; PostgreSQL has no CREATE ROLE IF NOT EXISTS.

-- 1. The two roles.
create role aivan_authz      login nosuperuser nocreatedb nocreaterole password 'REPLACE_AUTHZ_PW';
create role aivan_migrations login nosuperuser nocreatedb nocreaterole password 'REPLACE_MIGRATIONS_PW';

-- 2. CREATE on schema public.
--
-- PostgreSQL 14 grants CREATE on public to PUBLIC, so every new role inherits
-- it. PostgreSQL 15 removed that default for exactly this reason. Revoking it
-- reproduces the modern behaviour, and it is what the gate's boot probe checks.
-- The application's owner keeps it explicitly so its own migrations still run.
revoke create on schema public from public;
grant  create on schema public to aivan_migrations;
-- Keep the application's owner able to run its own migrations. aivan_core is
-- this install's owner; change the name if yours differs.
grant  create on schema public to aivan_core;

-- 3. The gate's schema.
--
-- The runtime role may use it and nothing more; ownership stays with the
-- migration role, so a bug in the gate cannot alter its own schema.
create schema if not exists authz;
alter schema authz owner to aivan_migrations;
grant usage on schema authz to aivan_authz;

-- 4. What the migrations need to reference and to re-grant.
--
-- 0001_init.sql puts a foreign key on public.users, so the migration role
-- needs REFERENCES. 0002_grants.sql grants column-level SELECT to aivan_authz,
-- which the migration role can only do if it holds those columns with the
-- grant option. It holds no row-level read of its own beyond that.
grant usage on schema public to aivan_migrations;
grant references on public.users to aivan_migrations;
grant select (id, username, active) on public.users  to aivan_migrations with grant option;
grant select (id, name)             on public.groups to aivan_migrations with grant option;
grant select                        on public.groups_users to aivan_migrations with grant option;

-- 5. Verify. Every line must read as the comment says.
select 'authz cannot CREATE on public'   as check, not has_schema_privilege('aivan_authz','public','CREATE') as ok
union all select 'authz cannot read password_digest', not has_column_privilege('aivan_authz','public.users','password_digest','SELECT')
union all select 'authz can read users.id',            has_column_privilege('aivan_authz','public.users','id','SELECT')
union all select 'authz cannot insert users',         not has_table_privilege('aivan_authz','public.users','INSERT')
union all select 'migrations own schema authz',       ((select nspowner::regrole::text from pg_namespace where nspname='authz')='aivan_migrations')
union all select 'migrations can CREATE on public',    has_schema_privilege('aivan_migrations','public','CREATE')
union all select 'migrations can reference users',     has_table_privilege('aivan_migrations','public.users','REFERENCES');

-- On an existing database the schema and its objects were created by whoever
-- ran the first migration. Hand them to the migration role before step 3:
--
--   alter schema authz owner to aivan_migrations;
--   alter table authz.schema_migrations    owner to aivan_migrations;
--   alter table authz.devices              owner to aivan_migrations;
--   alter table authz.nonces               owner to aivan_migrations;
--   alter table authz.sessions             owner to aivan_migrations;
--   alter table authz.pending_enrollments  owner to aivan_migrations;
--   alter table authz.audit_log            owner to aivan_migrations;
--   alter sequence authz.audit_log_id_seq  owner to aivan_migrations;
--
-- and grant the database-level CREATE the migration needs to make objects:
--
--   grant create on database aivan_core to aivan_migrations;
--
-- Two more facts this file cannot express, because they belong to the roles'
-- own setup:
--
--   * aivan_authz must be able to CONNECT to the database.
--   * the application's owner role must keep CREATE on schema public. Step 2
--     grants it to aivan_core, which is this install's owner; use your own
--     name if it differs.