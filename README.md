# supabase-check

[![test](https://github.com/kodev-team/supabase-check/actions/workflows/test.yml/badge.svg)](https://github.com/kodev-team/supabase-check/actions/workflows/test.yml)
[![release](https://img.shields.io/github/v/release/kodev-team/supabase-check)](https://github.com/kodev-team/supabase-check/releases)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

A free, read-only check for the most common data-access mistakes in Supabase projects, including apps built with
Lovable, Bolt, Replit or Cursor. One SQL file, no install, nothing leaves your project.

## Run it (2 minutes)
1. Open your own Supabase project: **Dashboard → SQL Editor → New query**.
2. Paste the whole of [`check.sql`](check.sql) and press **Run**.
3. Read the table it returns, from `high` down.

The script only reads the database catalog (tables, policies, functions, views, buckets). It does not read your
users' rows and does not change anything. It creates one temporary table for its own results, which disappears when
the session ends.

## What it checks
| ID | Severity | What it looks for |
|---|---|---|
| K01 | high | Tables in `public` with Row Level Security off that `anon` or `authenticated` can reach |
| K03 | high | Insert, update or delete policies for visitors or any logged-in user that allow every row (`true`) |
| K05 | high | Policies that trust `user_metadata`, which every user can change for themselves |
| K06 | medium | `SECURITY DEFINER` functions callable through `/rest/v1/rpc`, and whether their `search_path` is pinned |
| K07 | medium | Views without `security_invoker` and materialized views readable through the API (both skip RLS) |
| K09 | medium | Public storage buckets |
| K04 | low | Policies that let anyone read every row (often intended, worth a second look) |
| K08 | low | Policies that call `auth.uid()` or `auth.jwt()` per row instead of `(select auth.uid())` (speed) |
| K02 | info | Tables with RLS on but no policy (locked for the API) |

Each result says what was found and how to fix it. Only `public` is checked by default; add other schemas you
expose to the `exposed` list at the top of the script.

## Example output
From the test project in [`tests/fixture.sql`](tests/fixture.sql), where every problem is planted on purpose
(5 of its 11 rows; the `fix` column is shortened here):

| severity | check_id | object | finding | fix |
|---|---|---|---|---|
| high | K01 | public.profiles | Row Level Security is off and the table is reachable through the API (anon can read, anon can write, any logged-in user can write). | `alter table public.profiles enable row level security;` then add policies… |
| high | K03 | public.posts · policy "anyone insert" | INSERT policy for anon allows every row (true). Any visitor can insert any row. | Replace `true` with an ownership check… |
| high | K05 | public.admin_notes · policy "admins" | The policy reads user_metadata. Every user can change their own user_metadata from the browser, so they can give themselves this access (for example a role or a team id). | Keep roles in a table only the server writes, or in `app_metadata`… |
| medium | K09 | storage bucket "avatars" | Public bucket: anyone who knows or guesses a file path can download the file, with no login and no policy check. | Fine for logos; make buckets with user uploads private… |
| info | K02 | public.secrets | RLS is on but there is no policy, so the API cannot read or write this table. | Nothing to do if intended… |

## What it does not tell you
- Whether a policy matches what your app should allow. `user_id = (select auth.uid())` passes this check even
  on a table where team members should see each other's rows, or on one where they must not.
- Anything about your frontend, edge functions, secrets in code, payments or third-party services.
- An empty result means none of these patterns were found on the date you ran it. It does not mean the app is
  secure.

Supabase's own **Security Advisor** and **Performance Advisor** (Dashboard → Advisors) check related things;
run both.

## Tests
`tests/run.sh` builds two throwaway databases on a local PostgreSQL 15+: one with every problem planted, one clean.
It passes when every planted problem is found and the clean one returns nothing. CI runs it on every push.
See [CONTRIBUTING.md](CONTRIBUTING.md) to add a check, and [CHANGELOG.md](CHANGELOG.md) for changes.

## About
Made by [KODEV](https://kodev.dev). If you want a person to review what your policies actually allow, fix what
matters and retest it, that is our fixed-price Launch Review & Fix. The check itself is free and MIT-licensed.
Questions or a wrong result: [open an issue](https://github.com/kodev-team/supabase-check/issues/new/choose), or
write to hello@kodev.dev. A problem in the script itself: see [SECURITY.md](SECURITY.md).
