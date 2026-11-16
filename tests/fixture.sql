-- Minimal Supabase-like setup for testing check.sql
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
end $$;
create schema auth;
create function auth.uid() returns uuid language sql stable as $$ select null::uuid $$;
create function auth.jwt() returns jsonb language sql stable as $$ select '{}'::jsonb $$;
create schema storage;
create table storage.buckets (id text primary key, public boolean default false);
insert into storage.buckets values ('avatars', true), ('invoices', false);
grant usage on schema public to anon, authenticated;
alter default privileges in schema public grant all on tables to anon, authenticated;
alter default privileges in schema public grant all on functions to anon, authenticated;

-- K01: RLS off
create table public.profiles (id uuid primary key, email text);
-- clean table: RLS + good policy (wrapped) -> should produce nothing
create table public.orders (id int primary key, user_id uuid);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
-- K02: RLS on, no policy
create table public.secrets (id int);
alter table public.secrets enable row level security;
-- K03 + K08: write all, bare auth.uid
create table public.posts (id int, user_id uuid);
alter table public.posts enable row level security;
create policy "anyone insert" on public.posts for insert to anon with check (true);
create policy "own update" on public.posts for update to authenticated using (auth.uid() = user_id);
-- K04: public read
create policy "public read" on public.posts for select using (true);
-- K05: user_metadata
create table public.admin_notes (id int);
alter table public.admin_notes enable row level security;
create policy "admins" on public.admin_notes for select to authenticated using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
-- K06: security definer
create function public.get_all_emails() returns setof text language sql security definer as $$ select email from public.profiles $$;
create function public.safe_fn() returns int language sql security definer set search_path = '' as $$ select 1 $$;
revoke execute on function public.safe_fn() from public, anon, authenticated;
-- K07: views
create view public.v_profiles as select * from public.profiles;
create view public.v_orders with (security_invoker = true) as select * from public.orders;
create materialized view public.mv_stats as select count(*) from public.orders;
grant select on public.mv_stats to anon;
-- K10: users add their own role rows, and the check ignores the role
create type public.app_role as enum ('admin', 'member');
create table public.user_roles (id int primary key, user_id uuid, role public.app_role not null);
alter table public.user_roles enable row level security;
create policy "add own role" on public.user_roles for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "admins manage roles" on public.user_roles for all to authenticated
  using ((auth.jwt() ->> 'is_admin') = 'true') with check ((auth.jwt() ->> 'is_admin') = 'true');
-- K11: bank numbers on a publicly readable table; contact data for every logged-in user
create table public.sellers (id int primary key, name text, payout_iban text);
alter table public.sellers enable row level security;
create policy "sellers public" on public.sellers for select using (true);
create table public.members (id int primary key, display_name text, email text);
alter table public.members enable row level security;
create policy "members visible" on public.members for select to authenticated using (true);
