-- Run this entire file in the Supabase SQL editor.
-- It creates a non-login role for least-privilege table grants. Enable login
-- and set its password with the ALTER ROLE command documented in README.md.

do $role$
begin
  if not exists (select 1 from pg_catalog.pg_roles where rolname = 'patchguard_backend') then
    execute 'create role patchguard_backend nologin nosuperuser nocreatedb nocreaterole noinherit';
  end if;
end
$role$;

create table if not exists public.patchguard_jobs (
  id uuid primary key,
  state text not null,
  created_at timestamptz not null,
  expires_at timestamptz not null,
  payload jsonb not null,
  updated_at timestamptz not null default now()
);

create index if not exists patchguard_jobs_pending_idx
  on public.patchguard_jobs (created_at)
  where state in ('queued', 'validating');

alter table public.patchguard_jobs enable row level security;
revoke all on public.patchguard_jobs from anon, authenticated;

-- Grant only access to this application's table.
grant connect on database postgres to patchguard_backend;
grant usage on schema public to patchguard_backend;
grant select, insert, update, delete on public.patchguard_jobs to patchguard_backend;
drop policy if exists patchguard_backend_jobs on public.patchguard_jobs;
create policy patchguard_backend_jobs on public.patchguard_jobs
  for all to patchguard_backend using (true) with check (true);
