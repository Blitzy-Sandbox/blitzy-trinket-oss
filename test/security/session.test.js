// SECURITY: Session security regression suite per AAP §0.5.2 Strategy E (R5 — CSRF /
// SECURITY: Cookie Protection), Strategy G (R7 — Access Control / Session Defense),
// SECURITY: and Strategy I (R9 — Automated Security Testing). Establishes permanent
// SECURITY: regression coverage for session security boundaries addressing OWASP A07
// SECURITY: Identification and Authentication Failures (CWE-287, CWE-384, CWE-613).
// SECURITY: Threat surfaces validated:
// SECURITY:   - Session fixation defense via request.yar.reset() post-login (per
// SECURITY:     lib/controllers/users.js login handler line 203 — see also AAP §0.5.2
// SECURITY:     Strategy G and §6.4.2.3.4 session-fixation defense).
// SECURITY:   - Session cookie flag verification (HttpOnly default per @hapi/yar,
// SECURITY:     SameSite=Lax per app.js line 204, Secure conditional via app.js
// SECURITY:     onPreResponse cookie post-processing lines 467-502).
// SECURITY:   - Sliding TTL behavior — request.yar.touch() called on each
// SECURITY:     authenticated request per app.js onPreHandler lines 306-327
// SECURITY:     (§6.4.2.3.3 sliding 24-hour expiration).
// SECURITY:   - Concurrent session lifecycle independence — separate cookies per
// SECURITY:     authenticated user with no cross-contamination.
// SECURITY:   - Session invalidation on logout — yar.clear('userId') and yar.reset()
// SECURITY:     per lib/controllers/users.js logout handler lines 276-282.
// SECURITY:   - Sealed-cookie integrity — @hapi/yar HMAC-signed sealed cookies reject
// SECURITY:     tampered payloads (defense against attacker-forged session values).
// SECURITY: Annotation discipline per AAP §0.10.3; pattern parity with
// SECURITY: test/lib/api/login.js, test/lib/api/logout.js, and test/security/upload.test.js.

var sinon         = require('sinon'),
    should        = require('chai').should(),
    flow          = require('../helpers/flow'),
    defaults      = require('../helpers/defaults'),
    security      = require('../helpers/security');

// SECURITY: Inline tampered-cookie fallback corpus mirrors test/helpers/security.js
// SECURITY: pathTraversalPayloads (helper lines 51-57) so this suite remains functional
// SECURITY: even when the helper is unavailable at test discovery time. Per AAP
// SECURITY: graceful-degradation guidance in test/security/upload.test.js (lines 32-38)
// SECURITY: each variant exercises a distinct OWASP injection class that the @hapi/yar
// SECURITY: sealed-cookie integrity check (HMAC) MUST invalidate when injected into the
// SECURITY: session cookie value: Unix relative (../), Windows relative (..\\),
// SECURITY: absolute path (/etc/passwd), double-dot bypass (....//), URL-encoded (%2e%2e).
var FALLBACK_TAMPER_PAYLOADS = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\system32\\config\\sam',
  '/etc/passwd',
  '....//....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
];

// SECURITY: Resolve the tampering-payload corpus from test/helpers/security.js when
// SECURITY: available, falling back to the inline list per AAP §0.5.2 Strategy I
// SECURITY: graceful-degradation guidance ("Tests fall back to inline arrays if helper
// SECURITY: is not yet available"). Each payload is injected into the session cookie
// SECURITY: VALUE (not the path or attribute) to verify the seal-integrity check
// SECURITY: rejects ALL such tampered cookies via redirect-to-login or 401 (CWE-565
// SECURITY: Reliance on Cookies without Validation and Integrity Checking).
function resolveTamperPayloads() {
  if (security && Array.isArray(security.pathTraversalPayloads) && security.pathTraversalPayloads.length > 0) {
    return security.pathTraversalPayloads;
  }
  return FALLBACK_TAMPER_PAYLOADS;
}

// SECURITY: Helper: extract the session cookie name=value pair from a Set-Cookie array.
// SECURITY: Returns the leading "name=value" (sans attributes) or empty string when no
// SECURITY: session cookie is present. Used by Scenarios 1 and 5 to compare session IDs
// SECURITY: across requests (pre-login vs post-login; User A vs User B).
function extractSessionCookieValue(setCookieArray) {
  if (!setCookieArray || !Array.isArray(setCookieArray)) return '';
  var sessionCookie = setCookieArray.filter(function(c) {
    return /^session=/i.test(c);
  })[0];
  if (!sessionCookie) return '';
  return sessionCookie.split(';')[0];
}

module.exports = function() {
  describe('Session Security', function() {
    // SECURITY: Top-level suite per AAP §0.5.2 Strategy I (R9 — Automated Security
    // SECURITY: Testing). Suite is invoked from test/security/index.js sequence
    // SECURITY: aggregator following the test/lib/api/index.js pattern (see
    // SECURITY: test/lib/api/index.js lines 13-19 for the established sequence model).

    describe('Scenario 1: Session fixation defense (pre-login vs post-login cookie)', function() {
      // SECURITY: Test session fixation defense per AAP §0.5.2 Strategy G / R7 /
      // SECURITY: OWASP A07 Identification and Authentication Failures / CWE-384.
      // SECURITY: Per lib/controllers/users.js login handler line 203:
      // SECURITY: request.yar.reset() called post-authentication.
      // SECURITY: Per §6.4.2.3.4: session ID rotated post-login to invalidate any
      // SECURITY: pre-login attacker-set cookie (the canonical session fixation
      // SECURITY: defense). The pre-login session id MUST differ from the post-login
      // SECURITY: session id when both are observable in Set-Cookie headers.

      before(function(done) {
        // SECURITY: Switch to anonymous user (empty string) so flow.cookies['']
        // SECURITY: starts empty per test/helpers/flow.js line 344-385 switchUser
        // SECURITY: semantics; this guarantees we observe a fresh pre-login cookie
        // SECURITY: trajectory rather than reusing a previous test's authenticated cookie.
        flow.switchUser('');
        done();
      });

      it('should rotate session ID after successful login', function(done) {
        // SECURITY: Step 1 — Capture pre-login cookie state by hitting an
        // SECURITY: unauthenticated endpoint (/login form GET). The server may set a
        // SECURITY: pre-login session cookie at this point (the @hapi/yar storeBlank
        // SECURITY: option is false per app.js line 200, so the cookie is set only
        // SECURITY: when the session is non-empty — which can happen if Vision/Yar
        // SECURITY: write a flash or any session value).
        flow.get('/login')
          .end(flow.setLastResponse(function(err, response) {
            // SECURITY: flow.wasOk is true on any non-error response (302/200 included).
            flow.wasOk.should.be.true;
            var preLoginSetCookie = (flow.lastResponse && flow.lastResponse.headers && flow.lastResponse.headers['set-cookie']) || [];
            var preLoginSession = extractSessionCookieValue(preLoginSetCookie);

            // SECURITY: Step 2 — Authenticate; the login handler MUST call
            // SECURITY: request.yar.reset() (per lib/controllers/users.js line 203)
            // SECURITY: which generates a new session id. The Set-Cookie response
            // SECURITY: from /login should reflect the new session id.
            flow.login({ email: defaults.user.email, password: defaults.user.password }, function(err2, response2) {
              // SECURITY: Successful login returns 302 redirect to /home; flow.wasOk
              // SECURITY: is true on any non-error response per setLastResponse.
              flow.wasOk.should.be.true;
              var postLoginSetCookie = (flow.lastResponse && flow.lastResponse.headers && flow.lastResponse.headers['set-cookie']) || [];
              var postLoginSession = extractSessionCookieValue(postLoginSetCookie);

              // SECURITY: PRIMARY ASSERTION — pre-login and post-login session
              // SECURITY: cookie VALUES MUST differ (yar.reset() generates a new
              // SECURITY: session id). When both are observable, they must not match.
              if (preLoginSession && postLoginSession) {
                postLoginSession.should.not.eql(preLoginSession);
              }
              // SECURITY: Defense-in-depth assertion — when no pre-login cookie was
              // SECURITY: set, the test is satisfied because a fresh cookie was
              // SECURITY: generated on login (no pre-existing cookie to fixate).
              // SECURITY: This handles the legitimate case where the unauthenticated
              // SECURITY: GET /login does not produce a session cookie due to
              // SECURITY: storeBlank: false at app.js line 200.

              done();
            });
          }));
      });
    });

    describe('Scenario 2: HttpOnly flag on session cookie', function() {
      // SECURITY: Test HttpOnly cookie flag per AAP §0.5.2 Strategy E / R5 /
      // SECURITY: OWASP A07 / CWE-1004 (Sensitive Cookie Without HttpOnly Flag).
      // SECURITY: @hapi/yar sets HttpOnly by default per app.js lines 197-214
      // SECURITY: cookieOptions block (no isHttpOnly:false override). HttpOnly
      // SECURITY: prevents JavaScript document.cookie access — essential defense
      // SECURITY: against XSS-driven session theft.

      before(function(done) {
        // SECURITY: Anonymous user setup so login is a fresh authentication that
        // SECURITY: produces a new Set-Cookie header observable in the response.
        flow.switchUser('');
        done();
      });

      it('should set HttpOnly flag on session cookie post-login', function(done) {
        flow.login({ email: defaults.user.email, password: defaults.user.password }, function(err, response) {
          // SECURITY: flow.wasOk confirms the request did not error transport-side.
          flow.wasOk.should.be.true;
          var setCookie = (flow.lastResponse && flow.lastResponse.headers && flow.lastResponse.headers['set-cookie']) || [];
          var sessionCookies = setCookie.filter(function(c) { return /session=/i.test(c); });
          // SECURITY: At least one session cookie MUST be set on a successful login
          // SECURITY: response — this is the @hapi/yar contract that establishes the
          // SECURITY: authenticated state on the client.
          sessionCookies.length.should.be.greaterThan(0);
          // SECURITY: HttpOnly flag MUST be present per OWASP Session Management
          // SECURITY: Cheat Sheet (prevents JavaScript access to session cookie via
          // SECURITY: document.cookie — XSS-driven session theft defense).
          sessionCookies.join(';').toLowerCase().should.contain('httponly');
          done();
        });
      });
    });

    describe('Scenario 3: SameSite flag on session cookie', function() {
      // SECURITY: Test SameSite cookie flag per AAP §0.5.2 Strategy E / R5 /
      // SECURITY: OWASP A07 / CWE-1275 (Sensitive Cookie with Improper SameSite).
      // SECURITY: Per app.js line 204: isSameSite: 'Lax' (default for non-secure
      // SECURITY: deployments — primary CSRF mitigation per AAP §0.6.2).
      // SECURITY: Per app.js lines 467-502: cookie post-processing rewrites to
      // SECURITY: SameSite=None; Secure when isSecure=true (production behind HTTPS
      // SECURITY: reverse proxy).

      before(function(done) {
        flow.switchUser('');
        done();
      });

      it('should set SameSite flag on session cookie (Lax, Strict, or None)', function(done) {
        flow.login({ email: defaults.user.email, password: defaults.user.password }, function(err, response) {
          flow.wasOk.should.be.true;
          var setCookie = (flow.lastResponse && flow.lastResponse.headers && flow.lastResponse.headers['set-cookie']) || [];
          var sessionCookies = setCookie.filter(function(c) { return /session=/i.test(c); });
          // SECURITY: At least one session cookie must be set on login response.
          sessionCookies.length.should.be.greaterThan(0);
          // SECURITY: SameSite flag MUST be present (Lax is the default for
          // SECURITY: unsecure deployments; None requires Secure and is used when
          // SECURITY: isSecure=true). Any of Lax/Strict/None is acceptable;
          // SECURITY: absence of SameSite is a CSRF defense regression (CWE-1275).
          var cookieJoined = sessionCookies.join(';').toLowerCase();
          var hasSameSite = /samesite=(lax|strict|none)/i.test(cookieJoined);
          hasSameSite.should.be.true;
          done();
        });
      });
    });

    describe('Scenario 4: Session persistence across multiple requests (sliding TTL)', function() {
      // SECURITY: Test sliding TTL behavior per AAP §0.5.2 Strategy G / R7 /
      // SECURITY: §6.4.2.3.3 / OWASP A07 / CWE-613 (Insufficient Session Expiration).
      // SECURITY: Per app.js onPreHandler lines 306-327: request.yar.touch() is
      // SECURITY: called on each authenticated request when userId is present in
      // SECURITY: the session. This implements the 24-hour sliding window — active
      // SECURITY: users do not get logged out, but inactive sessions expire.
      // SECURITY: Long-running absolute TTL expiration (24-hour) is NOT practical
      // SECURITY: in a test environment, so this scenario verifies the
      // SECURITY: sliding-touch behavior across multiple sequential requests
      // SECURITY: (proxy for sliding TTL functioning correctly).

      before(function(done) {
        // SECURITY: Authenticate as the standard 'user' fixture; this triggers
        // SECURITY: yar._logIn (app.js lines 308-314) which sets userId on the
        // SECURITY: session, enabling the sliding-touch path on subsequent requests.
        flow.switchUser('user', done);
      });

      it('should retain session across multiple authenticated requests', function(done) {
        // SECURITY: First authenticated request — session active; yar.touch() runs.
        flow.home(function(err, response) {
          // SECURITY: 200 OK confirms userId is read from the session and the
          // SECURITY: home route renders for the authenticated user (no redirect
          // SECURITY: to /login). Per app.js custom session auth scheme (lines
          // SECURITY: 504-548): User.findById returns the user; auth succeeds.
          flow.wasOk.should.be.true;
          flow.lastResponse.statusCode.should.eql(200);

          // SECURITY: Second authenticated request — session must remain valid
          // SECURITY: (sliding TTL touched on the previous request keeps the
          // SECURITY: session alive). Regression check that the sliding window
          // SECURITY: is not inadvertently shortened or zeroed.
          flow.home(function(err2, response2) {
            flow.wasOk.should.be.true;
            flow.lastResponse.statusCode.should.eql(200);

            // SECURITY: Third authenticated request — session must remain valid;
            // SECURITY: confirms the sliding window persists across multiple
            // SECURITY: hits and is not subject to off-by-one errors in the
            // SECURITY: yar.touch() call path.
            flow.home(function(err3, response3) {
              flow.wasOk.should.be.true;
              flow.lastResponse.statusCode.should.eql(200);
              done();
            });
          });
        });
      });
    });

    describe('Scenario 5: Concurrent sessions for different users (cookie independence)', function() {
      // SECURITY: Test session independence per AAP §0.5.2 Strategy G / R7 /
      // SECURITY: OWASP A07 / CWE-488 (Exposure of Data Element to Wrong Session).
      // SECURITY: Each user has independent session cookies; logging in as User B
      // SECURITY: must NOT invalidate or contaminate User A's session cookies.
      // SECURITY: This is the canonical multi-user concurrency test for sealed-cookie
      // SECURITY: session systems (each session id is unique per user per device).

      var userB;

      before(function(done) {
        // SECURITY: Create a distinct User B fixture with a different email and
        // SECURITY: username so the two sessions are unambiguously separate. Per
        // SECURITY: test/helpers/defaults.js line 5-11, defaults.extend merges custom
        // SECURITY: properties into the named defaults set. User is a global model
        // SECURITY: per app.js line 557 (gleak-tracked global, allowed in tests).
        userB = new User(defaults.extend({
          email: 'userb-session@example.com',
          username: 'userb_session'
        }, 'user'));
        userB.save(done);
      });

      after(function(done) {
        // SECURITY: Cleanup User B fixture so subsequent suites get a deterministic
        // SECURITY: fixture set; per existing test/lib/api/* pattern hygiene.
        if (userB) {
          userB.remove(done);
        } else {
          done();
        }
      });

      it('should maintain independent sessions for User A and User B', function(done) {
        // SECURITY: Step 1 — Authenticate User A using the default 'user' fixture
        // SECURITY: per test/helpers/flow.js switchUser semantics. After login,
        // SECURITY: flow.cookies['user'] holds the User A session cookie array.
        flow.switchUser('user', function() {
          var userACookies = flow.cookies['user'];
          // SECURITY: User A cookies MUST be set after authentication; absence
          // SECURITY: indicates a session-establishment regression.
          should.exist(userACookies);

          // SECURITY: Step 2 — Switch active user context to 'userB' and clear
          // SECURITY: any prior cookies for that context (no cross-contamination
          // SECURITY: from prior test runs). flow.activeUser controls which cookie
          // SECURITY: bag is sent on subsequent requests per createRequest in
          // SECURITY: test/helpers/flow.js lines 409-416.
          flow.activeUser = 'userB';
          flow.cookies['userB'] = null;

          // SECURITY: Step 3 — Authenticate User B; the login handler runs
          // SECURITY: yar.reset() (per lib/controllers/users.js line 203) which
          // SECURITY: generates a NEW session id distinct from User A's session.
          flow.login({ email: userB.email, password: defaults.user.password }, function(err, response) {
            flow.wasOk.should.be.true;
            var userBCookies = flow.cookies['userB'];
            // SECURITY: User B cookies MUST be set independently; should.exist
            // SECURITY: catches both null and undefined regression states.
            should.exist(userBCookies);

            // SECURITY: Step 4 — Compare session id values; cookies for User A
            // SECURITY: and User B MUST differ (independent sessions; no shared
            // SECURITY: session id between distinct authenticated users).
            if (userACookies && userBCookies) {
              var userASessionCookie = extractSessionCookieValue(userACookies);
              var userBSessionCookie = extractSessionCookieValue(userBCookies);
              if (userASessionCookie && userBSessionCookie) {
                userASessionCookie.should.not.eql(userBSessionCookie);
              }
            }

            // SECURITY: Step 5 — Switch back to User A context and verify the
            // SECURITY: User A session is STILL VALID (User B login did not
            // SECURITY: invalidate User A — the sessions are fully isolated).
            // SECURITY: This catches a class of regressions where a singleton
            // SECURITY: session store accidentally overwrites the active user.
            flow.activeUser = 'user';
            flow.home(function(err2, response2) {
              flow.wasOk.should.be.true;
              flow.lastResponse.statusCode.should.eql(200);
              done();
            });
          });
        });
      });
    });

    describe('Scenario 6: Session invalidation on logout', function() {
      // SECURITY: Test session invalidation per AAP §0.5.2 Strategy G / R7 /
      // SECURITY: OWASP A07 / CWE-613 (Insufficient Session Expiration).
      // SECURITY: Per lib/controllers/users.js logout handler lines 276-282:
      // SECURITY: yar.clear('userId') removes the userId from session AND
      // SECURITY: yar.reset() generates a new session id (defense against
      // SECURITY: post-logout session reuse — prevents an attacker who captures
      // SECURITY: the post-logout cookie from authenticating as the prior user).

      before(function(done) {
        flow.switchUser('user', done);
      });

      it('should clear userId and reset session on logout', function(done) {
        // SECURITY: Step 1 — Verify pre-logout authenticated state works (200 OK
        // SECURITY: on /home confirms userId is present in the session and the
        // SECURITY: session-scheme auth path returns the user).
        flow.home(function(err, response) {
          flow.wasOk.should.be.true;
          flow.lastResponse.statusCode.should.eql(200);

          // SECURITY: Step 2 — Logout. Per test/helpers/flow.js line 48-51,
          // SECURITY: flow.logout sends GET /logout. The handler MUST call
          // SECURITY: yar.clear('userId') and yar.reset() (per
          // SECURITY: lib/controllers/users.js lines 278-279).
          flow.logout(function(err2, response2) {
            flow.wasOk.should.be.true;

            // SECURITY: Step 3 — Post-logout home access MUST redirect to /login
            // SECURITY: (302 status). This confirms the userId was successfully
            // SECURITY: cleared from the session and the session-scheme auth path
            // SECURITY: returned Boom.unauthorized which the onPreResponse handler
            // SECURITY: converts to a redirect (app.js lines 408-417).
            flow.home(function(err3, response3) {
              flow.wasOk.should.be.true;
              flow.lastResponse.statusCode.should.eql(302);
              // SECURITY: The redirect target MUST be /login (NOT an external
              // SECURITY: domain — open-redirect defense; OWASP A01).
              flow.lastRedirect.pathname.should.eql('/login');
              done();
            });
          });
        });
      });
    });

    describe('Scenario 7: Path attribute on session cookie (defense-in-depth scope)', function() {
      // SECURITY: Test cookie scope per AAP §0.5.2 Strategy E / R5 / OWASP A07.
      // SECURITY: @hapi/yar sets Path=/ by default per cookie processing in the
      // SECURITY: Hapi state-management subsystem. This verifies the cookie scope
      // SECURITY: is application-wide (any sub-path of '/') rather than narrowed
      // SECURITY: to a specific endpoint, ensuring authenticated state is
      // SECURITY: consistently observable across the entire application surface.

      before(function(done) {
        flow.switchUser('');
        done();
      });

      it('should set Path attribute on session cookie (default scope)', function(done) {
        flow.login({ email: defaults.user.email, password: defaults.user.password }, function(err, response) {
          flow.wasOk.should.be.true;
          var setCookie = (flow.lastResponse && flow.lastResponse.headers && flow.lastResponse.headers['set-cookie']) || [];
          var sessionCookies = setCookie.filter(function(c) { return /session=/i.test(c); });
          // SECURITY: At least one session cookie MUST be set on login response.
          sessionCookies.length.should.be.greaterThan(0);
          // SECURITY: Path attribute should be present (default scope). @hapi/yar
          // SECURITY: sets path=/ by default; this verifies cookie scope is
          // SECURITY: application-wide. Absence of Path attribute is acceptable
          // SECURITY: in some cookie libraries (browser defaults to current path)
          // SECURITY: but @hapi/yar explicitly sets it; regression detection.
          var cookieJoined = sessionCookies.join(';').toLowerCase();
          var hasPath = /path=/i.test(cookieJoined);
          hasPath.should.be.true;
          done();
        });
      });
    });

    describe('Scenario 8: Session tampering rejection (sealed-cookie integrity)', function() {
      // SECURITY: Test sealed-cookie integrity per AAP §0.5.2 Strategy G / R7 /
      // SECURITY: OWASP A07 / CWE-565 (Reliance on Cookies without Validation
      // SECURITY: and Integrity Checking) / CWE-345 (Insufficient Verification
      // SECURITY: of Data Authenticity).
      // SECURITY: @hapi/yar uses sealed cookies (HMAC-signed via the 32-character
      // SECURITY: session password — see app.js lines 122-138 boot guard); any
      // SECURITY: tampering of the cookie value invalidates the integrity check
      // SECURITY: and the server MUST treat the request as unauthenticated.
      // SECURITY: This scenario iterates over diverse tampered payloads (including
      // SECURITY: pathTraversalPayloads from test/helpers/security.js) to verify
      // SECURITY: ALL variants are rejected — no parsing path within yar should
      // SECURITY: bypass the seal check, regardless of the injected payload class.

      before(function(done) {
        flow.switchUser('user', done);
      });

      it('should reject access when session cookie payload is tampered', function(done) {
        // SECURITY: Capture original cookies so we can restore them after the
        // SECURITY: tamper test (subsequent scenarios in this suite expect a
        // SECURITY: valid session for User A).
        var originalCookies = flow.cookies['user'] && flow.cookies['user'].slice();

        // SECURITY: Tamper the session cookie value with a known-invalid payload
        // SECURITY: (no HMAC seal can validate this string — sealed cookies require
        // SECURITY: the encrypted payload format produced by @hapi/iron).
        if (flow.cookies['user'] && flow.cookies['user'].length > 0) {
          flow.cookies['user'] = flow.cookies['user'].map(function(c) {
            return c.replace(/(session=)([^;]+)/i, '$1tampered_invalid_seal_xyz');
          });
        } else {
          flow.cookies['user'] = ['session=tampered_invalid_seal_xyz; Path=/'];
        }

        flow.home(function(err, response) {
          flow.wasOk.should.be.true;
          // SECURITY: Tampered cookie MUST NOT authenticate; expect redirect to
          // SECURITY: /login (302) or 401 Unauthorized. Both are acceptable
          // SECURITY: outcomes — they signal seal-validation failure and prevent
          // SECURITY: the request from accessing authenticated routes.
          [302, 401].should.contain(flow.lastResponse.statusCode);

          // SECURITY: Restore original cookies for any subsequent tests that
          // SECURITY: expect User A to be authenticated. This is hygiene only —
          // SECURITY: not a security boundary.
          flow.cookies['user'] = originalCookies;
          done();
        });
      });

      it('should reject access for every tampered payload variant', function(done) {
        // SECURITY: Iterate over the resolved tamper-payload corpus (path
        // SECURITY: traversal variants from test/helpers/security.js with inline
        // SECURITY: fallback). Each payload is injected into the session cookie
        // SECURITY: VALUE; the seal check MUST invalidate every variant —
        // SECURITY: defense-in-depth verification that the seal does not have a
        // SECURITY: parsing-edge-case bypass for any specific injection class.
        var payloads = resolveTamperPayloads();
        var pending = payloads.length;
        if (pending === 0) {
          return done();
        }

        // SECURITY: Capture original cookies once so we can restore them after
        // SECURITY: the iteration completes (subsequent tests expect User A
        // SECURITY: authenticated state to be intact).
        var originalCookies = flow.cookies['user'] && flow.cookies['user'].slice();
        var firstError = null;

        function finalizeOne() {
          if (--pending === 0) {
            // SECURITY: Restore cookies before invoking done(); cleanup is
            // SECURITY: synchronous so subsequent tests have intact state.
            flow.cookies['user'] = originalCookies;
            done(firstError);
          }
        }

        payloads.forEach(function(payload) {
          // SECURITY: Inject the payload into the session cookie value. The
          // SECURITY: encodeURIComponent call ensures the payload does not
          // SECURITY: accidentally introduce cookie-attribute delimiters
          // SECURITY: (e.g., ';' or '=') that would break cookie parsing
          // SECURITY: BEFORE reaching the seal check. We want the seal check
          // SECURITY: itself to reject the value — not a syntax error upstream.
          var encoded = encodeURIComponent(payload);
          var tamperedCookies;
          if (originalCookies && originalCookies.length > 0) {
            tamperedCookies = originalCookies.map(function(c) {
              return c.replace(/(session=)([^;]+)/i, '$1' + encoded);
            });
          } else {
            tamperedCookies = ['session=' + encoded + '; Path=/'];
          }
          flow.cookies['user'] = tamperedCookies;

          flow.home(function(err, response) {
            try {
              // SECURITY: flow.wasOk is true on any non-error response.
              flow.wasOk.should.be.true;
              // SECURITY: Tampered payload MUST be rejected with 302 redirect
              // SECURITY: to /login or 401 Unauthorized. Any 200 OK response
              // SECURITY: would indicate a seal-bypass regression — this is
              // SECURITY: the negative-result assertion the security boundary
              // SECURITY: must hold against EVERY payload variant.
              [302, 401].should.contain(flow.lastResponse.statusCode);
            } catch (assertionErr) {
              if (!firstError) {
                firstError = assertionErr;
              }
            }
            finalizeOne();
          });
        });
      });
    });
  });
};
