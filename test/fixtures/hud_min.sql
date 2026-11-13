-- Minimal aivan-hud schema, applied only by the integration harness.
-- A gateway deployed before the application cannot apply 0002_grants.sql,
-- because it grants column-level SELECT on tables the application owns.
-- Phase E is the first time both exist; until then the test database fakes
-- the least that makes the grants and the privilege probe real.
create table if not exists public.users (
  id bigint primary key, email text, username text, active boolean default true,
  password_digest text
);
create table if not exists public.groups (id bigint primary key, name text);
create table if not exists public.groups_users (group_id bigint, user_id bigint);