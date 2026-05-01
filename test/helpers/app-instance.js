// SECURITY: Test-only holder for the resolved Hapi server instance.
// SECURITY: ----------------------------------------------------------------------------
// SECURITY: app.js exports an unresolved `serverPromise` (Hapi 17+ async init pattern at
// SECURITY: app.js line 622: `module.exports = serverPromise;`). The test harness used to
// SECURITY: read `app.listener` synchronously inside `test/helpers/flow.js`, which yields
// SECURITY: `undefined` because the export is a Promise — supertest then crashes with
// SECURITY: `TypeError: Cannot read properties of undefined (reading 'address')` at the
// SECURITY: first request. This holder breaks that load-order trap by allowing the
// SECURITY: per-suite `before` hook (defined inside the test file's describe() block —
// SECURITY: e.g. test/security/index.js — where Mocha globals are accessible) to await
// SECURITY: the server promise and stash the resolved instance, which `flow.js` reads
// SECURITY: lazily on the first HTTP request.
// SECURITY:
// SECURITY: Note: the `before` hook cannot live in test/setup.js because that file is
// SECURITY: loaded via mocha's `--require` flag, and Mocha 3 does not expose the
// SECURITY: `before`/`after`/`describe`/`it` globals at --require time (they only
// SECURITY: become available once Mocha begins discovering test files via --recursive
// SECURITY: traversal). The pattern is therefore: setup.js pre-loads app.js → suite
// SECURITY: before() hook awaits → flow.js reads.
// SECURITY:
// SECURITY: This is a test-only fixture; it does not change runtime behavior, the
// SECURITY: production export contract, or any Hapi route/plugin/Joi schema. It exists
// SECURITY: solely to bridge the synchronous test-helper code paths to the asynchronous
// SECURITY: server initialization path documented in AAP §0.5.4 R10 (zero functional
// SECURITY: regression) and §0.6.1 (Phase 1 mandate that test/security/* must execute).
// SECURITY: Closes QA Issue #3 (test/security/* suite cannot execute) per the FINAL
// SECURITY: SECURITY checkpoint findings; AAP §0.5.2 Strategy I / R9 mapping.
module.exports = {
  // The fully-initialized Hapi v20 server (after plugins + routes + onPreResponse
  // extensions are registered). Populated by the per-suite `before` hook in
  // test/security/index.js (and any other suite that follows the same pattern);
  // remains `null` until that hook fires. Read via `getListener()` below.
  server : null,

  // The unresolved server promise stashed by test/setup.js so per-suite hooks can
  // `await` it inside a Mocha-aware before() block. Set in setup.js;
  // null when setup.js was not loaded.
  promise : null,

  // Lazy listener accessor. Throws a clear diagnostic error if invoked before
  // a `before` hook has resolved the server instance, which would indicate a
  // missing `--require ./test/setup.js` flag in the mocha invocation OR a missing
  // resolution `before` hook in the suite's describe() block. Production code
  // never calls this — it is reachable only from test/helpers/flow.js.
  getListener : function () {
    if (!this.server) {
      throw new Error(
        'test/helpers/app-instance: Hapi server not yet resolved. ' +
        'Ensure test/setup.js is loaded via `--require ./test/setup.js` AND ' +
        'that the suite has a `before` hook awaiting `appInstance.promise` ' +
        '(see test/security/index.js for the canonical pattern).'
      );
    }
    return this.server.listener;
  }
};
