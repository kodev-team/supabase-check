-- KODEV Supabase self-check, v0.2
-- Run it in the SQL Editor of YOUR OWN Supabase project (Dashboard -> SQL Editor -> New query -> paste -> Run).
-- It only reads the database catalog. It changes nothing in your tables, policies or settings.
-- It complements Supabase's Security Advisor; it does not replace a review of what your policies mean.
-- Results say what was checked and what was found. No result does not mean the app is "secure".
-- https://github.com/kodev-team/supabase-check

create temp table if not exists kodev_findings (
  severity text,   -- high, medium, low, info
  check_id text,
  object   text,
  finding  text,
  fix      text
) on commit preserve rows;
truncate kodev_findings;

do $kodev$
declare
  r record;
  exposed text[] := array['public'];   -- add your other API-exposed schemas here
  api_roles text[] := array['anon', 'authenticated'];
begin
  ------------------------------------------------------------------------------------------------
  -- K01 Tables without RLS that the API roles can reach
  for r in
    select n.nspname as s, c.relname as t,
           array_remove(array[
             case when has_table_privilege('anon', c.oid, 'SELECT') then 'anon can read' end,
             case when has_table_privilege('anon', c.oid, 'INSERT,UPDATE,DELETE') then 'anon can write' end,
             case when has_table_privilege('authenticated', c.oid, 'INSERT,UPDATE,DELETE') then 'any logged-in user can write' end
           ], null) as what
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where c.relkind in ('r', 'p') and n.nspname = any(exposed) and not c.relrowsecurity
      and (has_table_privilege('anon', c.oid, 'SELECT,INSERT,UPDATE,DELETE')
           or has_table_privilege('authenticated', c.oid, 'SELECT,INSERT,UPDATE,DELETE'))
  loop
    insert into kodev_findings values ('high', 'K01', format('%I.%I', r.s, r.t),
      'Row Level Security is off and the table is reachable through the API (' || array_to_string(r.what, ', ') || ').',
      format('alter table %I.%I enable row level security; then add policies for who may read and write which rows.', r.s, r.t));
  end loop;

  ------------------------------------------------------------------------------------------------
  -- K02 RLS on, but no policy at all (table is locked for the API; fine if intended)
  for r in
    select n.nspname as s, c.relname as t
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where c.relkind in ('r', 'p') and n.nspname = any(exposed) and c.relrowsecurity
      and not exists (select 1 from pg_policy p where p.polrelid = c.oid)
  loop
    insert into kodev_findings values ('info', 'K02', format('%I.%I', r.s, r.t),
      'RLS is on but there is no policy, so the API cannot read or write this table.',
      'Nothing to do if that is intended. If the app needs the table, add policies for the exact rows each user may use.');
  end loop;

  ------------------------------------------------------------------------------------------------
  -- K03 Policies that let anyone (or any logged-in user) write any row
  for r in
    select schemaname as s, tablename as t, policyname as p, cmd, roles, qual, with_check
    from pg_policies
    where schemaname = any(exposed)
      and permissive = 'PERMISSIVE'
      and cmd in ('INSERT', 'UPDATE', 'DELETE', 'ALL')
      and (roles && array['public', 'anon', 'authenticated']::name[])
      and (coalesce(trim(qual), '') in ('true', '(true)') or coalesce(trim(with_check), '') in ('true', '(true)'))
  loop
    insert into kodev_findings values ('high', 'K03', format('%I.%I · policy "%s"', r.s, r.t, r.p),
      format('%s policy for %s allows every row (true). Any %s can %s any row.',
             r.cmd, array_to_string(r.roles, ', '),
             case when r.roles && array['public', 'anon']::name[] then 'visitor' else 'logged-in user' end,
             lower(case when r.cmd = 'ALL' then 'read and change' else r.cmd end)),
      'Replace true with an ownership check, for example (select auth.uid()) = user_id, in USING and WITH CHECK.');
  end loop;

  ------------------------------------------------------------------------------------------------
  -- K04 Public read policies (often intended, worth a second look)
  for r in
    select schemaname as s, tablename as t, policyname as p, roles
    from pg_policies
    where schemaname = any(exposed) and permissive = 'PERMISSIVE' and cmd = 'SELECT'
      and (roles && array['public', 'anon']::name[])
      and coalesce(trim(qual), '') in ('true', '(true)')
  loop
    insert into kodev_findings values ('low', 'K04', format('%I.%I · policy "%s"', r.s, r.t, r.p),
      'Anyone, even without logging in, can read every row of this table.',
      'Fine for public content. If the table holds personal or business data, limit the policy to the owner or team.');
  end loop;

  ------------------------------------------------------------------------------------------------
  -- K05 Policies that trust user_metadata (each user can edit their own)
  for r in
    select schemaname as s, tablename as t, policyname as p
    from pg_policies
    where schemaname = any(exposed)
      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~* '(user_metadata|raw_user_meta_data)'
  loop
    insert into kodev_findings values ('high', 'K05', format('%I.%I · policy "%s"', r.s, r.t, r.p),
      'The policy reads user_metadata. Every user can change their own user_metadata from the browser, so they can give themselves this access (for example a role or a team id).',
      'Keep roles and team membership in a table only the server writes, or in app_metadata, and check that instead.');
  end loop;

  ------------------------------------------------------------------------------------------------
  -- K06 SECURITY DEFINER functions the API roles can call
  for r in
    select n.nspname as s, p.proname as f, pg_get_function_identity_arguments(p.oid) as args,
           exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c where c like 'search_path=%') as pinned
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = any(exposed) and p.prosecdef and p.prokind = 'f'
      and p.prorettype <> 'trigger'::regtype   -- trigger functions cannot be called through /rpc
      and (has_function_privilege('anon', p.oid, 'EXECUTE') or has_function_privilege('authenticated', p.oid, 'EXECUTE'))
  loop
    insert into kodev_findings values ('medium', 'K06', format('%I.%I(%s)', r.s, r.f, r.args),
      'SECURITY DEFINER function that the API roles can call (POST /rest/v1/rpc/' || r.f || '). It runs with its owner''s rights and skips RLS.'
        || case when r.pinned then '' else ' Its search_path is not pinned.' end,
      'Check that the function verifies who is calling. Move helpers that need no API access to a private schema, or revoke execute from anon, authenticated'
        || case when r.pinned then '.' else '; add set search_path = '''' to the function.' end);
  end loop;

  ------------------------------------------------------------------------------------------------
  -- K07 Views and materialized views that skip RLS
  for r in
    select n.nspname as s, c.relname as v, c.relkind as k,
           coalesce(c.reloptions::text[] && array['security_invoker=true', 'security_invoker=on'], false) as invoker
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where c.relkind in ('v', 'm') and n.nspname = any(exposed)
      and (has_table_privilege('anon', c.oid, 'SELECT') or has_table_privilege('authenticated', c.oid, 'SELECT'))
  loop
    if r.k = 'm' then
      insert into kodev_findings values ('medium', 'K07', format('%I.%I', r.s, r.v),
        'Materialized view readable through the API. Materialized views have no RLS, so every row is visible to the API roles.',
        format('revoke select on %I.%I from anon, authenticated; and read it through a function or view that filters rows.', r.s, r.v));
    elsif not r.invoker then
      insert into kodev_findings values ('medium', 'K07', format('%I.%I', r.s, r.v),
        'View readable through the API that runs with its owner''s rights, so the RLS of the tables behind it is skipped.',
        format('alter view %I.%I set (security_invoker = true);  (Postgres 15 or later)', r.s, r.v));
    end if;
  end loop;

  ------------------------------------------------------------------------------------------------
  -- K08 Policies that call auth functions per row (performance)
  for r in
    select schemaname as s, tablename as t, policyname as p
    from pg_policies
    where schemaname = any(exposed)
      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~* 'auth\.(uid|jwt|role)\(\)'
      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) !~* 'select\s+auth\.(uid|jwt|role)\(\)'
  loop
    insert into kodev_findings values ('low', 'K08', format('%I.%I · policy "%s"', r.s, r.t, r.p),
      'The policy calls auth.uid() or auth.jwt() for every row, which slows down large tables.',
      'Write (select auth.uid()) instead of auth.uid(), and index the column it is compared with.');
  end loop;

  ------------------------------------------------------------------------------------------------
  -- K10 Users can choose their own role when they add a row (for example to a user_roles table)
  for r in
    select pol.schemaname as s, pol.tablename as t, pol.policyname as p, a.attname as col
    from pg_policies pol
    join pg_namespace n on n.nspname = pol.schemaname
    join pg_class c on c.relnamespace = n.oid and c.relname = pol.tablename
    join pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
    where pol.schemaname = any(exposed) and pol.permissive = 'PERMISSIVE' and pol.cmd in ('INSERT', 'ALL')
      and (pol.roles && array['public', 'anon', 'authenticated']::name[])
      and a.attname ~* '^(role|roles|user_role|app_role|access_level|permission|permissions|is_admin)$'
      and (has_column_privilege('authenticated', c.oid, a.attnum, 'INSERT')
           or has_column_privilege('anon', c.oid, a.attnum, 'INSERT'))
      -- a self-service insert (the row is the caller's own), whose check never looks at the role column
      and coalesce(pol.with_check, pol.qual, '') ~* 'auth\.uid\(\)'
      and coalesce(pol.with_check, pol.qual, '') !~* ('\m' || a.attname || '\M')
      and coalesce(pol.with_check, pol.qual, '') !~* 'admin'
  loop
    insert into kodev_findings values ('high', 'K10', format('%I.%I · policy "%s"', r.s, r.t, r.p),
      format('Users may add rows for themselves, and the policy never checks %s. Any logged-in user can insert a row with %s = ''admin'' (or any other value) and pass every check that reads it.', r.col, r.col),
      format('Limit the check to the one value users may take themselves, for example with check ((select auth.uid()) = user_id and %s = ''member''), or grant roles only from server code or a security definer function that checks the real condition.', r.col));
  end loop;

  ------------------------------------------------------------------------------------------------
  -- K11 Bank, identity or contact columns that everyone (or every logged-in user) can read
  for r in
    select pol.schemaname as s, pol.tablename as t, pol.policyname as p,
           case when pol.roles && array['public', 'anon']::name[] then 'anyone, even without logging in'
                else 'every logged-in user' end as who,
           array_agg(a.attname::text order by a.attnum) filter (
             where a.attname ~* '(^|_)(iban|bic|swift|account_number|bank_account|sort_code|routing_number|card_number|tax_id|vat_number|ssn|national_id|passport|passport_number|id_number)($|_)'
           ) as money_cols,
           array_agg(a.attname::text order by a.attnum) filter (
             where a.attname ~* '(^|_)(email|phone|phone_number|mobile|address|street|postcode|zip|birth_date|date_of_birth|dob)($|_)'
           ) as contact_cols
    from pg_policies pol
    join pg_namespace n on n.nspname = pol.schemaname
    join pg_class c on c.relnamespace = n.oid and c.relname = pol.tablename
    join pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
    where pol.schemaname = any(exposed) and pol.permissive = 'PERMISSIVE' and pol.cmd in ('SELECT', 'ALL')
      and (pol.roles && array['public', 'anon', 'authenticated']::name[])
      and coalesce(trim(pol.qual), '') in ('true', '(true)')
      and ((pol.roles && array['public', 'anon']::name[] and has_column_privilege('anon', c.oid, a.attnum, 'SELECT'))
           or has_column_privilege('authenticated', c.oid, a.attnum, 'SELECT'))
    group by pol.schemaname, pol.tablename, pol.policyname, pol.roles
  loop
    if r.money_cols is not null then
      insert into kodev_findings values ('high', 'K11', format('%I.%I · policy "%s"', r.s, r.t, r.p),
        format('The policy lets %s read every row, including bank or identity numbers (%s). Your screens may never show them, but anyone with your project''s public key can request these columns directly.',
               r.who, array_to_string(r.money_cols, ', ')),
        format('Move these columns to a table only the owner (and admins) can read, or revoke column access: revoke select on %I.%I from anon, authenticated; then grant select (<public columns>) on %I.%I to anon, authenticated;', r.s, r.t, r.s, r.t));
    elsif r.contact_cols is not null then
      insert into kodev_findings values ('medium', 'K11', format('%I.%I · policy "%s"', r.s, r.t, r.p),
        format('The policy lets %s read every row, including personal contact data (%s), which can be collected in bulk through the API.',
               r.who, array_to_string(r.contact_cols, ', ')),
        'If these columns are not meant to be public, limit the policy to the owner or team, or grant select only on the public columns.');
    end if;
  end loop;

  ------------------------------------------------------------------------------------------------
  -- K09 Public storage buckets
  if to_regclass('storage.buckets') is not null then
    for r in execute 'select id from storage.buckets where public' loop
      insert into kodev_findings values ('medium', 'K09', 'storage bucket "' || r.id || '"',
        'Public bucket: anyone who knows or guesses a file path can download the file, with no login and no policy check.',
        'Fine for logos and public images. For user uploads (documents, IDs, invoices), make the bucket private and serve files through signed URLs.');
    end loop;
  end if;
end
$kodev$;

select severity, check_id, object, finding, fix
from kodev_findings
order by case severity when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end, check_id, object;
