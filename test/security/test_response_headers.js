// SECURITY: Regression tests for defense-in-depth response headers.
// Verifies X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy
// are emitted on all routes (including Boom error responses).
// AAP §0.5.1, §0.6.1, §0.6.2, §0.8.1.

require('../setup');                       // global bootstrap (NODE_ENV=test, chai plugins, redis-mock)

var should     = require('chai').should();
var appPromise = require('../../app');     // app.js exports a Promise resolving to the Hapi server

describe('Security: Response Headers', function() {
  // The closure-scoped `server` is populated by the `before` hook below and
  // referenced from every nested test case via Hapi's in-process inject() API.
  // Because Node's module cache returns the same Promise object on every
  // `require('../../app')`, the second require here is idempotent — it does
  // not re-initialize the server; it merely awaits the same initialization
  // already kicked off by `require('../setup')` above.
  var server;

  // The Hapi server initialization includes await server.register(...),
  // Vision view-engine setup, and (depending on test environment) MongoDB
  // connection establishment via catbox-mongoose. 15 seconds is generous
  // but bounded — protects CI against transient I/O slowness while still
  // failing loudly if init genuinely hangs.
  this.timeout(15000);

  before(function(done) {
    // Promise-style chain to Mocha's done callback. This works regardless
    // of whether the codebase later switches to async/await test bodies —
    // it's the most portable form across Mocha 3.x and forward.
    appPromise
      .then(function(s) { server = s; done(); })
      .catch(done);
  });

  // -------------------------------------------------------------------------
  // Helper: assertHeaders(headers)
  //
  // Centralizes the per-route header assertions so each `it` body stays a
  // single inject() call. Hapi normalizes header names to lowercase in the
  // response object returned by server.inject(); the keys below match that
  // canonical form.
  //
  // IMPORTANT IMPLEMENTATION DETAIL: Hapi 17+ creates res.headers via
  // Object.create(null) — i.e., a null-prototype object — so chai.should()
  // chains attached to Object.prototype do NOT apply directly. We therefore
  // hydrate the incoming headers map into a fresh plain object via
  // Object.assign({}, headers) before applying the AAP-specified
  // `headers.should.have.property(...)` assertions. This is a no-op for the
  // assertion semantics — the property keys/values are preserved verbatim —
  // but it restores the prototype chain so chai's `.should` extension
  // resolves correctly.
  //
  // The CSP assertion uses a regex anchored on `^default-src 'self'` rather
  // than a full-value equality check because the AAP §0.5.1 specification
  // is a long (~250-character) directive list that may legitimately gain
  // additional sources in future security hardening cycles. Anchoring on
  // the prefix confirms the policy starts with the expected baseline
  // directive while staying robust to forward-compatible additions.
  // -------------------------------------------------------------------------
  function assertHeaders(headers) {
    // Hydrate null-prototype headers into a regular object so chai's
    // Object.prototype-based .should chain resolves correctly.
    var h = Object.assign({}, headers);

    h.should.have.property('x-content-type-options', 'nosniff');
    h.should.have.property('referrer-policy', 'strict-origin-when-cross-origin');
    h.should.have.property('content-security-policy');
    h['content-security-policy'].should.match(/^default-src 'self'/);
  }

  // -------------------------------------------------------------------------
  // Route 1 — GET / (index page)
  //
  // Exercises the normal-response branch of the onPreResponse extension
  // (app.js line ~269: `else if (response.header) { ... }`). The status
  // code is intentionally NOT asserted because `/` may render the home
  // page (200) or redirect to /home (302) depending on auth state, and
  // the AAP requires only that the security headers be present on ALL
  // responses regardless of status code.
  // -------------------------------------------------------------------------
  describe('on GET /', function() {
    it('should set all security headers', function(done) {
      server.inject({ method: 'GET', url: '/' })
        .then(function(res) {
          assertHeaders(res.headers);
          done();
        })
        .catch(done);
    });
  });

  // -------------------------------------------------------------------------
  // Route 2 — GET /login (auth marketing surface)
  //
  // The /login page is one of the user-facing pages in config.app.xframeDeny,
  // which means it also receives X-Frame-Options: deny and (per app.js
  // line ~210) the route-aware `frame-ancestors 'self'` CSP directive.
  // Verifying the four security headers here confirms the additions do not
  // collide with the existing X-Frame-Options emission.
  // -------------------------------------------------------------------------
  describe('on GET /login', function() {
    it('should set all security headers', function(done) {
      server.inject({ method: 'GET', url: '/login' })
        .then(function(res) {
          assertHeaders(res.headers);
          done();
        })
        .catch(done);
    });
  });

  // -------------------------------------------------------------------------
  // Route 3 — GET /signup (signup form)
  //
  // Like /login, /signup is part of the marketing/auth surface. Including
  // it ensures the security-header emission is consistent across the full
  // auth-flow set — preventing future regressions where one page might
  // bypass the onPreResponse extension via, e.g., a custom takeover().
  // -------------------------------------------------------------------------
  describe('on GET /signup', function() {
    it('should set all security headers', function(done) {
      server.inject({ method: 'GET', url: '/signup' })
        .then(function(res) {
          assertHeaders(res.headers);
          done();
        })
        .catch(done);
    });
  });

  // -------------------------------------------------------------------------
  // Route 4 — GET /api/trinkets (auth-required API endpoint)
  //
  // Exercises an API route. The pre-handler chain may produce 401
  // (unauthorized), 302 (redirect to /login if HTML acceptance is somehow
  // signaled), or 200 (if a previous test left auth credentials in the
  // module-level state). Per AAP, headers must be present on ALL responses
  // regardless of status — therefore we do NOT assert a specific status
  // code, only the four security headers.
  // -------------------------------------------------------------------------
  describe('on GET /api/trinkets', function() {
    it('should set all security headers', function(done) {
      server.inject({ method: 'GET', url: '/api/trinkets' })
        .then(function(res) {
          // Status may be 401, 302, or 200 depending on auth state;
          // headers must be present regardless. The header assertion is
          // the only thing this test cares about.
          assertHeaders(res.headers);
          done();
        })
        .catch(done);
    });
  });

  // -------------------------------------------------------------------------
  // Route 5 — GET to a non-existent route (404 / Boom error response)
  //
  // CRITICAL: The onPreResponse extension in app.js has TWO code paths:
  //   * `if (response.isBoom)` — error / 4xx / 5xx responses
  //   * `else if (response.header)` — normal responses
  //
  // BOTH branches must emit the security headers. The four route tests
  // above exercise the normal-response branch. This test specifically
  // exercises the Boom branch, ensuring the §0.5.1 mandate to extend the
  // onPreResponse extension covers error responses as well as success
  // responses.
  //
  // The path string includes a randomized-looking suffix to guarantee it
  // does not collide with any registered route, present or future.
  // -------------------------------------------------------------------------
  describe('on GET to a non-existent route (404 / Boom error)', function() {
    it('should still set all security headers on the error response', function(done) {
      server.inject({ method: 'GET', url: '/this-route-definitely-does-not-exist-12345' })
        .then(function(res) {
          // Status will be 404 (rendered HTML 404 view via h.view('404.html'))
          // or, in degenerate edge cases (no view loaded, no Accept header),
          // a JSON Boom 404. Either way the security headers must be present.
          assertHeaders(res.headers);
          done();
        })
        .catch(done);
    });
  });
});
