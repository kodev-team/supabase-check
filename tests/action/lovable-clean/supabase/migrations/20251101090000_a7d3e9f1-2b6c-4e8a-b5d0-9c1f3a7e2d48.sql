-- Test data for supabase-check: the same app with the problems fixed. No config.toml on purpose
-- (the action must create one).
create table public.profiles (
  id uuid not null references auth.users on delete cascade primary key,
  full_name text,
  email text,
  phone text,
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
create policy "Users can view their own profile" on public.profiles for select to authenticated
  using ((select auth.uid()) = id);
create policy "Users can update their own profile" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, email) values (new.id, new.email);
  return new;
end;
$$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute procedure public.handle_new_user();

create type public.app_role as enum ('admin', 'moderator', 'user');
create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users on delete cascade not null,
  role public.app_role not null,
  unique (user_id, role)
);
alter table public.user_roles enable row level security;
create policy "Users can view their own roles" on public.user_roles for select to authenticated
  using ((select auth.uid()) = user_id);

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users on delete cascade,
  amount_cents integer not null,
  created_at timestamptz not null default now()
);
alter table public.invoices enable row level security;
create policy "Users can view their own invoices" on public.invoices for select to authenticated
  using ((select auth.uid()) = user_id);

insert into storage.buckets (id, name, public) values ('documents', 'documents', false);
