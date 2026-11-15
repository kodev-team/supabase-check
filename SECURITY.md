# Security policy

## Report a problem in this tool
If you find a problem in `check.sql` itself, please tell us privately first:

- **GitHub:** the **Security** tab of this repository → **Report a vulnerability** (a private advisory), or
- **Email:** hello@kodev.dev

Examples: a check that changes data or settings, a way the script could expose rows or secrets, or a result that
hides a real problem.

Please do not open a public issue for these, and do not include real user data, keys or passwords in a report.
A short SQL setup that shows the problem on a throwaway database is the most useful thing you can send.

We aim to answer within 5 working days. Fixes are listed in `CHANGELOG.md`, with credit to the reporter unless
they prefer not to be named.

## Supported versions
Only the latest release gets fixes.

## Out of scope
- A wrong or missing result for your own project: open a normal issue with the **Wrong or missing result** form,
  without real data.
- Supabase itself: report those to Supabase.
