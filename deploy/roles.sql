-- Roles and grants for aivan-authz.
--
-- Run once, as a superuser or the database owner, against the application's
-- database. It is not a migration: schemas public and authz belong to
-- aivan-hud's migration history now (doc/schema-handover.md §2), so
-- `rake db:migrate` in that project runs afterwards and describes the authz
-- grant matrix itself.
--
-- This file does the half a migration cannot: role creation, and the grants on
-- schema public, which belongs to the application rather than to the migration
-- role.
--
-- Two roles:
--
--   aivan_authz       the gate's runtime credential. It reads identity, appends
--                     evidence, drives its own nonces and sessions, and
--                     completes an enrollment through a definer function. It
--                     cannot create or destroy a credential, read the audit
--                     log, or approve anything.
--   aivan_migrations  owns schemas public and authz and applies both projects'
--                     migrations. It is never put in a pod: the gate's image is
--                     distroless and the operator binary runs from a
--                     workstation.
--
-- Passwords are not in this file. Set them here before applying, or run the
-- statements by hand with a generated value:
--
--   create role aivan_authz login nosuperuser nocreatedb nocreaterole
--     password '<authz pw>';
--
-- Substitute the two placeholders, then:
--
--   PGDATABASE=aivan_core psql -f deploy/roles.sql
--
-- psql reads PGHOST, PGPORT, PGUSER, PGPASSWORD and PGDATABASE from the
-- environment, so the run is the same one that reaches the database with a rake
-- task in aivan-hud.
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

-- 3. What the migration role needs in order to create schema authz.
--
-- The schema itself is created by aivan-hud's 202611140100_authz_schema.rb, and
-- that migration hands ownership to aivan_migrations. This is only what makes
-- the handover possible.
grant create on database aivan_core to aivan_migrations;

-- 4. What the migrations need to reference and to re-grant.
--
-- authz.devices, authz.pending_enrollments and authz.approvals put foreign keys
-- on public.users, so the migration role needs REFERENCES. The grant migration
-- grants column-level SELECT to aivan_authz, which the migration role can only
-- do if it holds those columns with the grant option. The definer functions
-- read public.users.username from inside a SECURITY DEFINER body, so the role
-- that owns them has to be able to read that column.
grant usage on schema public to aivan_migrations;
grant references on public.users to aivan_migrations;
grant select (id, username, active) on public.users  to aivan_migrations with grant option;
grant select (id, name)             on public.groups to aivan_migrations with grant option;
grant select                        on public.groups_users to aivan_migrations with grant option;

-- 5. What the gate reads on the public side. It never sees password_digest.
grant usage on schema public to aivan_authz;
grant select (id, username, active) on public.users  to aivan_authz;
grant select (id, name)             on public.groups to aivan_authz;
grant select                        on public.groups_users to aivan_authz;
revoke create on schema public from aivan_authz;

-- 6. Verify. Every line must read as the comment says.
select 'authz cannot CREATE on public'   as check, not has_schema_privilege('aivan_authz','public','CREATE') as ok
union all select 'authz cannot read password_digest', not has_column_privilege('aivan_authz','public.users','password_digest','SELECT')
union all select 'authz can read users.id',            has_column_privilege('aivan_authz','public.users','id','SELECT')
union all select 'authz cannot insert users',         not has_table_privilege('aivan_authz','public.users','INSERT')
union all select 'migrations can CREATE on public',    has_schema_privilege('aivan_migrations','public','CREATE')
union all select 'migrations can reference users',     has_table_privilege('aivan_migrations','public.users','REFERENCES');

-- After `rake db:migrate` in aivan-hud, these must also read as the comment
-- says. They are checked by aivan-hud's script/check_authz_grants.rb
-- (`rake db:check_grants`), which asserts the whole matrix by name — presence
-- and absence — and probes the denials by switching into each role:
--
--   migrations own schema authz
--   authz cannot insert, update or delete on authz.devices
--   authz cannot read authz.audit_log
--   authz cannot execute authz.revoke_device
--   authz can execute authz.enroll_device
--   authz cannot mint, read or delete authz.pending_enrollments
--   authz cannot insert or update authz.services
--   core can mint an enrollment and register or retire a service
--
-- The last three are 202611190100_operator_surface_grants.rb. The split it
-- draws: the gate completes a claim inside a request, and the operator's
-- credential — hud's — mints the code, registers a service identity, and
-- appends the audit row that says an operator did it. So `authz-admin` holds one
-- credential for every subcommand instead of two halves of one tool.
--
-- Two more facts this file cannot express, because they belong to the roles'
-- own setup:
--
--   * aivan_authz must be able to CONNECT to the database.
--   * the application's owner role must keep CREATE on schema public. Step 2
--     grants it to aivan_core, which is this install's owner; use your own
--     name if it differs.
