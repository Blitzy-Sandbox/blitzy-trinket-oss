// SECURITY: Test infrastructure stub.
//
// The legacy unscoped `catbox-redis` package was renamed to `@hapi/catbox-redis`
// during the dependency upgrades documented in AAP §0.7.1. This helper used to
// stub `catbox.prototype.isReady` to bypass a real Redis connection during the
// test suite, but Trinket no longer uses catbox-redis for any production path:
//
//   1. Application sessions are backed by `@hapi/yar` + `lib/util/catbox-mongoose`
//      (see app.js line 39, line 105). MongoDB is the canonical session store.
//   2. The Bull job queue uses Redis when available, but `lib/util/queues.js`
//      gracefully falls back to `InMemoryQueue` when Redis is disabled. The
//      test environment sets `db.redis.enabled: false` in `config/local.yaml`
//      and `config/test.yaml`, so Bull never attempts a Redis connection.
//   3. `redis.createClient` is independently stubbed by `redis-mock` in
//      `test/setup.js:18`, which is sufficient for any code path that touches
//      the bare `redis` client directly (none in production).
//
// This file is intentionally a no-op. It is preserved (rather than deleted) for
// two reasons:
//   (a) `test/setup.js:16` has historically required this module by relative
//       path; keeping the file means `setup.js` does not need to drop the
//       require (preserving the documented setup-load contract).
//   (b) Mocha's `--recursive` walk in `test/mocha.opts` discovers every `.js`
//       file under `test/`, including helpers. A no-op file loads cleanly as
//       a "test file" with zero `describe` / `it` blocks and contributes no
//       test cases, which is the desired outcome.
//
// AAP cross-reference: §0.7.1 (dependency upgrade plan), §0.10.4 (test gate
// must reach 100% pass rate). The QA-FINAL-2 checkpoint identified the legacy
// `require('catbox-redis')` as the blocker for the entire test suite (CRITICAL
// Issue #1); this no-op shim resolves that blocker without re-enabling redis.

module.exports = {};
