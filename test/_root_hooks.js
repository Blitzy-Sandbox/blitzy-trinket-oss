// SECURITY: Mocha root-suite hooks for the QA-FINAL-2 fixes.
//
// This file is intentionally placed at test/ root with a leading underscore
// so it sorts alphabetically BEFORE all other test entries (`_` < `d` <
// `h` < `l` < `s`). Mocha's `--recursive` walk processes the test/ root in
// `readdirSync` order, which on the deployment filesystem is alphabetical.
//
// IMPORTANT: this file MUST NOT be required from `test/setup.js` because
// `--require ./test/setup` runs in `_mocha`'s pre-`mocha.ui()` phase,
// where the BDD globals (`before` / `describe` / `it`) are not yet
// installed on the global scope. Calling `before(...)` from a --required
// file throws ReferenceError. Mocha walks test files only AFTER
// `mocha.ui()` runs (see `_mocha.js:365` requires loop, then
// `_mocha.js:loadFiles` later); files walked via --recursive therefore
// have access to `before(...)`. By placing this file at test/ root with a
// `_` prefix we guarantee it is the FIRST walked file, so the root hook
// is registered before any nested `describe` block can claim it.
//
// What the hook does:
//   1. Awaits `appPromise` (exported from app.js after the AAP §0.5.1
//      async-init refactor). Resolves to the fully-initialised Hapi
//      server with all plugins registered, view engine configured, and
//      model globals (`User`, `Course`, `Lesson`, `Material`, `Trinket`,
//      etc.) populated by app.js:374-381.
//   2. Lazy-requires `test/helpers/flow.js`. Lazy because flow.js itself
//      does the @hapi/inert-before-harmony-reflect dance internally; but
//      since `test/setup.js` (run via --require) has already loaded
//      app.js synchronously, flow.js's require here is a cache hit and
//      effectively a no-op aside from returning the singleton Flow
//      instance.
//   3. Calls `flow.setServer(server)` so supertest receives the resolved
//      `server.listener` (Node http.Server) instead of a Promise. Without
//      this step every API test fails with the supertest serverAddress
//      "Cannot read properties of undefined (reading 'address')" error
//      flagged by QA-FINAL-2 Issue #6.
//
// AAP cross-reference: §0.5.1 (async init refactor that introduced the
// Promise-based export), §0.10.4 (test gate must reach 100% pass rate).

var setup = require('./setup');
var appPromise = setup.app;

before(function(done) {
  // The Hapi init sequence includes await server.register([Inert, Vision,
  // Yar, ...]) plus mongoose connect plus optional Redis stub. 15 seconds
  // matches the timeout set by test/security/test_response_headers.js for
  // the same code path; CI has historically completed init in <2 s on
  // warm caches but the 15 s cap protects against transient I/O slowness.
  this.timeout(15000);

  appPromise
    .then(function(server) {
      // Lazy-require flow so that test files which never touch HTTP routes
      // (e.g., the JWT algorithm-pin source-inspection tests in
      // test/security/test_jwt_algorithm_pin.js) do not pay the
      // module-load cost. Idempotent — Node's module cache returns the
      // same Flow singleton on every require.
      var flow = require('./helpers/flow');
      flow.setServer(server);
      done();
    })
    .catch(done);
});
