# Contributing

Thanks for helping. Wrong results, missing checks and clearer wording are all welcome.

## Report a wrong or missing result
Open an issue with the **Wrong or missing result** form. Include the check ID (for example `K03`), your
PostgreSQL version, and the smallest SQL that recreates the table, policy or function. **Never paste real user
data, keys, passwords or your project URL.**

## Change or add a check
1. Edit `check.sql`. Each check is one block with its ID in a comment.
2. Plant the problem in `tests/fixture.sql` and add the expected line to `tests/expected.txt`.
3. Make sure `tests/clean.sql` still produces no findings (add a correct example there if useful).
4. Run the tests on a local PostgreSQL 15 or later where you can create databases:

   ```sh
   bash tests/run.sh
   ```

   It prints two `PASS` lines. CI runs the same script on every push and pull request.
5. Add a line to `CHANGELOG.md` under **Unreleased**.

## Rules for checks
- Read the catalog only (`pg_catalog`, `pg_policies`, `information_schema`, `storage.buckets`). Never read rows
  of user tables and never change anything outside the script's own temporary table.
- No extensions, no network calls, no new dependencies. The whole check stays one file that runs in the
  Supabase SQL Editor.
- Every finding says what was found and how to fix it, in plain words. Never say a project is "secure".

## License
By contributing you agree that your contribution is licensed under the MIT License of this repository.
