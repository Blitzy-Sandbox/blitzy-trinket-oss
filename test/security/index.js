// SECURITY: Security regression test suite aggregator per AAP §0.5.2 Strategy I (R9
// SECURITY: — Automated Security Testing) and AAP §0.6.1 File Transformation Mapping.
// SECURITY: Mirrors the existing test/lib/api/index.js aggregator pattern (lines 1-27)
// SECURITY: which registers the API integration suite under describe('API tests') with
// SECURITY: shared db.reset / db.ensureConnection lifecycle hooks. This sequence
// SECURITY: aggregator loads the five security regression modules and registers them
// SECURITY: under a single describe('Security tests') umbrella so Mocha's --recursive
// SECURITY: discovery (per test/mocha.opts) emits a coherent suite tree:
// SECURITY:   Security tests
// SECURITY:     ├─ auth.test          (R7 / OWASP A07 — authentication boundaries)
// SECURITY:     ├─ access-control.test (R7 / OWASP A01 — authorization & IDOR)
// SECURITY:     ├─ injection.test     (R8 / OWASP A03 — NoSQL & XSS injection)
// SECURITY:     ├─ session.test       (R5/R7 / OWASP A07 — session integrity)
// SECURITY:     └─ upload.test        (R9 / OWASP A04/A05 — upload security)
// SECURITY: Each sibling module exports module.exports = function() { describe(...); }
// SECURITY: — a dormant factory that does NOT auto-register describe() blocks when
// SECURITY: Mocha's --recursive discovery loads it directly. Only when invoked here
// SECURITY: via suite() does the describe() registration occur, ensuring exactly-once
// SECURITY: registration under the 'Security tests' parent umbrella. This is the same
// SECURITY: net behavior as test/lib/api/index.js + test/lib/api/admin.js et al. per
// SECURITY: AAP §0.6.1 transformation table source pattern reference.
// SECURITY: Annotation discipline per AAP §0.10.3.

var db          = require('../helpers/db'),
    appInstance = require('../helpers/app-instance'),
    sequence    = [
      'auth.test',
      'access-control.test',
      'injection.test',
      'session.test',
      'upload.test'
    ];

// SECURITY: 'Security tests' umbrella registers the security regression suite as a
// SECURITY: first-class peer of the existing 'API tests' umbrella per AAP §0.5.2
// SECURITY: Strategy I / R9 (establish security regression as ongoing CI coverage).
describe('Security tests', function() {
  // SECURITY: Resolve the asynchronous Hapi server promise produced by app.js (Hapi
  // SECURITY: 17+ async init pattern: app.js line 622 `module.exports = serverPromise`)
  // SECURITY: BEFORE any other suite hook runs. This must execute first because:
  // SECURITY:   (a) flow.js reads `appInstance.getListener()` lazily on the first
  // SECURITY:       HTTP request, throwing if the holder has not been populated;
  // SECURITY:   (b) the subsequent `before(db.reset)` hook does not interact with
  // SECURITY:       the Hapi server but the user-facing test bodies do.
  // SECURITY: Mocha awaits Promise return values from `before` hooks; setup.js
  // SECURITY: stashes the unresolved Promise on `appInstance.promise` during
  // SECURITY: --require time (when Mocha globals are not yet defined).
  // SECURITY:
  // SECURITY: After the promise resolves we call `server.initialize()` (Hapi 17+
  // SECURITY: phase transition: registered → initialized) which starts the registered
  // SECURITY: cache engines (here the CatboxMongoose session backend at
  // SECURITY: lib/util/catbox-mongoose.js) WITHOUT binding the HTTP listener to a
  // SECURITY: port. Production app.js skips both `start()` and `initialize()` when
  // SECURITY: NODE_ENV=test (config.app.start === false), so without this manual
  // SECURITY: initialize the catbox client's `isReady()` returns false → every
  // SECURITY: request.yar.reset() and yar.set() throws Boom.internal('Disconnected')
  // SECURITY: → all login/signup tests fail with HTTP 500. Calling initialize() is
  // SECURITY: idempotent (Hapi short-circuits if `phase === 'initialized'`).
  // SECURITY: Closes QA Issue #3 per FINAL SECURITY checkpoint findings; AAP §0.5.2
  // SECURITY: Strategy I / R9 mapping.
  before(function () {
    return appInstance.promise.then(function (server) {
      appInstance.server = server;
      // Start cache engines (CatboxMongoose) without binding the listener to a port.
      return server.initialize();
    });
  });

  // SECURITY: Reset database before suite to ensure clean state — mirrors
  // SECURITY: test/lib/api/index.js line 15 BUT wrapped in an explicit function(done)
  // SECURITY: closure to preserve Mocha's async-detection arity contract. Mocha v3+
  // SECURITY: detects async hooks by `fn.length > 0`; helpers/db.js applies _.bindAll
  // SECURITY: which produces a length-0 wrapper, causing Mocha to treat db.reset as
  // SECURITY: synchronous and skip passing the `done` callback. The explicit closure
  // SECURITY: reasserts arity 1 so Mocha invokes the hook in async mode and propagates
  // SECURITY: the dropDatabase callback. Mirrors the after() pattern at line 76 below.
  before(function(done) {
    db.reset(done);
  });

  // SECURITY: Ensure DB connection before each test (handles reconnects after reset)
  // SECURITY: — mirrors test/lib/api/index.js line 17, wrapped in a function(done)
  // SECURITY: closure for the same arity-preservation reason as the before() hook.
  // SECURITY: db.ensureConnection polls mongoose.connection.readyState until
  // SECURITY: isConnected() is true and only then invokes the Mocha done callback,
  // SECURITY: preventing race conditions between db.reset's dropDatabase and the
  // SECURITY: first test of each suite.
  beforeEach(function(done) {
    db.ensureConnection(done);
  });

  // SECURITY: Load and invoke each security test module factory in deterministic
  // SECURITY: order. Each require returns module.exports (the factory function);
  // SECURITY: invoking suite() registers that module's describe() blocks under the
  // SECURITY: 'Security tests' umbrella. Order is significant: auth runs first
  // SECURITY: (establishes session / credential primitives), access-control / injection
  // SECURITY: / session exercise authenticated-route boundaries, upload runs last
  // SECURITY: (writes /tmp fixtures and depends on auth+session base behavior).
  sequence.forEach(function(file) {
    // SECURITY: security/detect-non-literal-require is disabled for this single
    // SECURITY: line because the require argument is bounded by the closed-set
    // SECURITY: `sequence` array of trusted, repository-controlled module names
    // SECURITY: declared above (auth.test, access-control.test, injection.test,
    // SECURITY: session.test, upload.test). No user-controlled input reaches this
    // SECURITY: require() — defense against CWE-829 (Inclusion of Functionality
    // SECURITY: from Untrusted Control Sphere) is upheld by the static allowlist.
    // SECURITY: Identical pattern to test/lib/api/index.js line 20 per AAP §0.6.1.
    // eslint-disable-next-line security/detect-non-literal-require
    var suite = require('./' + file);
    suite();
  });

  // SECURITY: Reset database after suite to leave a clean slate for subsequent test
  // SECURITY: runs in the same process — mirrors test/lib/api/index.js lines 24-26.
  // SECURITY: Wrapped in a function callback because db.reset requires the Mocha
  // SECURITY: done parameter; direct passing of db.reset would still work (matches
  // SECURITY: the before(db.reset) form above), but using the explicit closure here
  // SECURITY: matches the test/lib/api/index.js exemplar exactly per AAP §0.6.1.
  after(function(done) {
    db.reset(done);
  });
});
