var db          = require('../../helpers/db'),
    appInstance = require('../../helpers/app-instance'),
    sequence    = [
    'registration',
    'files',
    'login',
    'admin',
    'course',
    'profile',
    'logout',
    'forgot_pass',
    'trinket'
  ];

describe('API tests', function() {
  // SECURITY: Resolve the asynchronous Hapi server promise produced by app.js
  // SECURITY: (Hapi 17+ async init pattern: app.js exports `serverPromise`)
  // SECURITY: BEFORE any other suite hook runs. test/helpers/flow.js reads
  // SECURITY: `appInstance.getListener()` lazily on the first HTTP request and
  // SECURITY: throws the diagnostic error visible in the QA FINAL repro
  // SECURITY: ("Hapi server not yet resolved") if the holder is unpopulated.
  // SECURITY: Mocha awaits Promise return values from `before` hooks, so this
  // SECURITY: hook returns the promise chain. After the promise resolves we
  // SECURITY: call server.initialize() to start registered cache engines (the
  // SECURITY: CatboxMongoose session backend at lib/util/catbox-mongoose.js)
  // SECURITY: WITHOUT binding the HTTP listener to a port — production app.js
  // SECURITY: skips both start() and initialize() when NODE_ENV=test
  // SECURITY: (config.app.start === false), so without this manual initialize
  // SECURITY: the catbox client's isReady() returns false and every
  // SECURITY: request.yar.reset()/yar.set() throws Boom.internal('Disconnected')
  // SECURITY: → all login/signup/forgot_pass tests fail with HTTP 500.
  // SECURITY: server.initialize() is idempotent (Hapi short-circuits when the
  // SECURITY: phase is already 'initialized'). Mirrors the canonical pattern at
  // SECURITY: test/security/index.js lines 65-71. Closes QA FINAL Issue #2 /
  // SECURITY: API tests cascade per AAP §0.5.2 Strategy I / R9.
  before(function () {
    return appInstance.promise.then(function (server) {
      appInstance.server = server;
      return server.initialize();
    });
  });

  // SECURITY: Wrap db.reset / db.ensureConnection in explicit function(done)
  // SECURITY: closures to preserve Mocha's async-detection arity contract.
  // SECURITY: Mocha v3+ detects async hooks by `fn.length > 0`; helpers/db.js
  // SECURITY: applies _.bindAll which produces a length-0 wrapper, causing
  // SECURITY: Mocha to treat db.reset/db.ensureConnection as synchronous and
  // SECURITY: skip passing the `done` callback. The eventual mongoose
  // SECURITY: dropDatabase callback then invokes a `done()` that is undefined,
  // SECURITY: throwing `TypeError: done is not a function` from
  // SECURITY: test/helpers/db.js:30 — propagating as an Uncaught error in
  // SECURITY: subsequent tests and aborting the entire `npm test` run before
  // SECURITY: the test/security/* suite executes. This wrapper pattern mirrors
  // SECURITY: the same fix already in place at test/security/index.js lines
  // SECURITY: 77-90 from the prior remediation. Closes QA FINAL Issue #2 / #4
  // SECURITY: cascade per AAP §0.5.2 Strategy I / R9.
  before(function(done) {
    db.reset(done);
  });

  beforeEach(function(done) {
    db.ensureConnection(done);
  });

  sequence.forEach(function(file) {
    // SECURITY: security/detect-non-literal-require disabled for this single
    // SECURITY: line because the require argument is bounded by the closed-set
    // SECURITY: `sequence` array of trusted, repository-controlled module
    // SECURITY: names declared above. No user-controlled input reaches this
    // SECURITY: require() — defense against CWE-829 (Inclusion of Functionality
    // SECURITY: from Untrusted Control Sphere) is upheld by the static
    // SECURITY: allowlist. Identical pattern to test/security/index.js line
    // SECURITY: 109 per AAP §0.6.1.
    // eslint-disable-next-line security/detect-non-literal-require
    var suite = require('./' + file);
    suite();
  });

  after(function(done) {
    db.reset(done);
  });
});
