-- Role creation is the install step's job, not this migration's.
grant usage on schema authz to aivan_authz;
grant select, insert, update, delete on all tables in schema authz to aivan_authz;
grant usage on sequence authz.audit_log_id_seq to aivan_authz;
grant usage on schema public to aivan_authz;
grant select (id, username, active) on public.users  to aivan_authz;
grant select (id, name)             on public.groups to aivan_authz;
grant select                        on public.groups_users to aivan_authz;
revoke create on schema public from aivan_authz;