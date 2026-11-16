do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;
create schema auth;
create function auth.uid() returns uuid language sql stable as $$ select null::uuid $$;
grant usage on schema public to anon, authenticated;
alter default privileges in schema public grant all on tables to anon, authenticated;
create table public.notes (id int primary key, user_id uuid);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
-- K10 clean: users may only add the member role for themselves
create type public.app_role as enum ('admin', 'member');
create table public.user_roles (id int primary key, user_id uuid, role public.app_role not null);
alter table public.user_roles enable row level security;
create policy "add own member role" on public.user_roles for insert to authenticated
  with check ((select auth.uid()) = user_id and role = 'member');
-- K11 clean: bank numbers kept out of reach by column grants; the table itself is a deliberate directory
create table public.sellers (id int primary key, name text, payout_iban text);
alter table public.sellers enable row level security;
create policy "sellers directory" on public.sellers for select to authenticated using (true);
revoke select on public.sellers from anon, authenticated;
grant select (id, name) on public.sellers to authenticated;
-- K06 clean: a SECURITY DEFINER trigger function (the usual sign-up trigger) cannot be called through /rpc
create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = ''
  as $$ begin return new; end $$;
