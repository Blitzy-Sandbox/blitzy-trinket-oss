// SECURITY: Self-contained stub for the legacy 'snapshots' queue helper. The
// SECURITY: original helper invoked `require('../../lib/util/queues').snapshots()`
// SECURITY: to obtain a production queue instance for test stubbing, but
// SECURITY: `lib/util/queues.js` only exposes queues from the configured
// SECURITY: `bullqueues` list (default `['exports']`) per the queue factory at
// SECURITY: lib/util/queues.js lines 162-166. The 'snapshots' queue is on the
// SECURITY: `disabledQueues` allowlist (lib/util/queues.js line 105) and never
// SECURITY: reaches the export forEach — so `require(...).snapshots` resolved to
// SECURITY: undefined and `.snapshots()` threw `TypeError: require(...).snapshots
// SECURITY: is not a function` at module-load time. Because mocha's `--recursive`
// SECURITY: discovery loads every .js file under test/ (including test/helpers/*.js)
// SECURITY: as a candidate test file, the type error fired before any test could
// SECURITY: execute, blocking the entire `npm test` run end-to-end. Closes QA
// SECURITY: FINAL Issue #3 (test/helpers/queue.js .snapshots() undefined cascades
// SECURITY: through test/lib/api/index.js aggregator).
// SECURITY:
// SECURITY: This pre-existing helper bug originated in initial commit 1426558 and
// SECURITY: was previously masked because `npm test` failed earlier at the
// SECURITY: @hapi/shot schema error (QA FINAL Issue #2 / #5). After the
// SECURITY: test/mocha.opts addition of `--require ./test/setup.js` resolves the
// SECURITY: module-load-order issue in @hapi/shot, this helper's TypeError surfaces
// SECURITY: as the next blocker. Per AAP Minimal Change Clause "choose the path
// SECURITY: requiring fewest modified files", we replace the broken
// SECURITY: `lib/util/queues` reference with a self-contained Bull-compatible stub
// SECURITY: that preserves the helper's legacy public API (snapshotQueue, stub) so
// SECURITY: any test importer (currently only the unused import at
// SECURITY: test/lib/api/trinket.js:4) continues to function. The stub queue
// SECURITY: exposes `add(data)` returning a thenable shape so existing test
// SECURITY: scaffolding works unchanged. AAP §0.5.2 Strategy I / R9 / OWASP-N/A
// SECURITY: — pure test-infrastructure fix.
var sinon = require('sinon');

// SECURITY: Bull-compatible stub queue object — minimal API surface required by
// SECURITY: the helper's `stub()` method below. The `.add()` shape mirrors Bull
// SECURITY: v0.7.x's returnable thenable contract so any caller invoking
// SECURITY: `snapshotQueue.add(data).then(...)` resolves immediately. No
// SECURITY: production code references this stub; it is reached only when a test
// SECURITY: explicitly imports test/helpers/queue.js (currently a single unused
// SECURITY: import at test/lib/api/trinket.js:4 line preserved for backward
// SECURITY: compatibility per AAP Backward Compatibility Directive).
var snapshotQueue = {
  add : function(data) {
    return {
      then : function(f) {
        f();
      }
    };
  }
};

module.exports = {
  snapshotQueue : snapshotQueue,
  stub : function() {
    before(function() {
      // SECURITY: Sinon 1.7.x 3-arg stub form preserved per AAP §6.6.12.3 frozen
      // SECURITY: test toolchain (Mocha 3 / Chai 3 / Sinon 1.7.x). The replacement
      // SECURITY: function re-asserts the same thenable shape so test code paths
      // SECURITY: are unchanged.
      sinon.stub(snapshotQueue, 'add', function(data) {
        return {
          then : function(f) {
            f();
          }
        };
      });
    });

    after(function() {
      snapshotQueue.add.restore();
    });
  }
};
