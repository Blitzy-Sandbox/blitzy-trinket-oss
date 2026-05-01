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

var db       = require('../helpers/db'),
    sequence = [
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
  // SECURITY: Reset database before suite to ensure clean state — mirrors
  // SECURITY: test/lib/api/index.js line 15. db.reset accepts a Mocha done callback;
  // SECURITY: passing the helper directly delegates the callback contract to Mocha.
  before(db.reset);

  // SECURITY: Ensure DB connection before each test (handles reconnects after reset)
  // SECURITY: — mirrors test/lib/api/index.js line 17. db.ensureConnection polls
  // SECURITY: mongoose.connection.readyState until isConnected() is true and only
  // SECURITY: then invokes the Mocha done callback, preventing race conditions
  // SECURITY: between db.reset's dropDatabase and the first test of each suite.
  beforeEach(db.ensureConnection);

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
