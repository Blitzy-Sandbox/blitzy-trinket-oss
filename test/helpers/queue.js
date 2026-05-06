// SECURITY: Test infrastructure stub.
//
// This helper used to call `require('../../lib/util/queues').snapshots()` to
// obtain the Bull-backed snapshot queue and stub its `add` method so that
// tests would not enqueue real jobs. Two reasons that approach no longer
// applies:
//
//   1. After the AAP §0.7.1 dependency upgrades (`bull@^4.16.4`),
//      `lib/util/queues.js` exports queue getters dynamically based on
//      `config.db.redis.bullqueues`. The default `bullqueues` value is
//      `['exports']` (see `config/default.yaml:385-387`), so only
//      `module.exports.exports()` is exposed. The legacy `snapshots()`
//      getter is not part of the current contract.
//
//   2. The single consumer of this helper in `test/lib/api/trinket.js:4`
//      imports the binding but never calls `queue.stub()` or accesses
//      `queue.snapshotQueue`. The helper is dead code in the current test
//      suite.
//
// Maintaining a backwards-compatible export shape (`snapshotQueue` + `stub`)
// keeps any future test that expects the old API able to `require()` the
// file without crashing. The `stub()` function is a no-op that registers
// empty `before` / `after` hooks so call sites that wrap the helper in a
// describe scope still see consistent behavior.
//
// AAP cross-reference: §0.7.1 (bull upgrade), §0.10.4 (test gate must reach
// 100% pass rate). The QA-FINAL-2 checkpoint surfaced this file as the next
// load-time blocker once the catbox-redis stub was neutralized; this no-op
// preserves the public test-helper shape without re-introducing the broken
// snapshots queue accessor.

module.exports = {
  snapshotQueue: {
    add: function() {
      // No-op: returns a thenable for backward compatibility with the original
      // helper, which itself stubbed `add` to return a `then(f)` shim.
      return { then: function(f) { return f && f(); } };
    }
  },
  stub: function() {
    // Empty before/after hooks preserve the original lifecycle contract for
    // any test that does call `queue.stub()`. With no real queue to stub the
    // hooks become no-ops.
    if (typeof before === 'function') {
      before(function() {});
    }
    if (typeof after === 'function') {
      after(function() {});
    }
  }
};
