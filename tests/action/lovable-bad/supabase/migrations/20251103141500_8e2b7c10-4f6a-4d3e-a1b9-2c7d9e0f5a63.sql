-- Test data for supabase-check: every problem below is planted on purpose.
create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users on delete cascade,
  amount_cents integer not null,
  created_at timestamptz not null default now()
);

insert into storage.buckets (id, name, public) values ('documents', 'documents', true);
