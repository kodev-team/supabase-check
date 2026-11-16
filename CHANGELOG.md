# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-16
- New check K10 (high): insert policies that let users add rows for themselves without checking the role column,
  so anyone can give themselves `admin` in a `user_roles` table.
- New check K11 (high or medium): read-all policies on tables whose bank, identity or contact columns the API roles
  can read, even when the app's screens never show them.
- K06 no longer reports trigger functions, which cannot be called through `/rest/v1/rpc`.
- Docs: security policy, contributing guide, code of conduct, issue and pull request templates, example output and
  badges in the README, Dependabot for the CI actions.

## [0.1.0] - 2026-11-15
- First public release: nine read-only checks (K01–K09) on tables, policies, functions, views and storage
  buckets, with tests on a planted and a clean database.

[Unreleased]: https://github.com/kodev-team/supabase-check/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kodev-team/supabase-check/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kodev-team/supabase-check/releases/tag/v0.1.0
