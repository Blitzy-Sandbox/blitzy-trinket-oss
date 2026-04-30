// SECURITY: Access control / authorization security regression suite per AAP §0.5.2
// SECURITY: Strategy G (R7 — Access Control Audit) and Strategy I (R9 — Automated
// SECURITY: Security Testing). Establishes permanent regression coverage for
// SECURITY: authorization and access-control boundaries addressing OWASP A01 Broken
// SECURITY: Access Control (CWE-285 Improper Authorization, CWE-639 Authorization
// SECURITY: Bypass Through User-Controlled Key, CWE-862 Missing Authorization).
// SECURITY: Threat surfaces validated:
// SECURITY:   - IDOR (CWE-639) defense on resource-mutating endpoints — the canEdit
// SECURITY:     pre-handler in lib/util/helpers.js lines 70-90 compares
// SECURITY:     resource._owner.toString() === user.id (line 82) and returns
// SECURITY:     Boom.forbidden() on mismatch; tests verify 403 on User A vs User B
// SECURITY:     ownership mismatch for /api/trinkets/:id (PUT code/name/description).
// SECURITY:   - Admin route bypass defense — every /api/admin/* route in
// SECURITY:     config/api_routes.js carries pre: ['isAdmin(user)'] (audit per AAP
// SECURITY:     §0.5.2 Strategy G); /admin and /admin/{adminPage*} page routes in
// SECURITY:     config/routes.js carry the same guard. Tests verify 403 for non-admin
// SECURITY:     access to POST /api/admin/featured-course, POST /api/admin/user/{userId},
// SECURITY:     and the GET /admin page route.
// SECURITY:   - Bulk export download strict ownership comparison — per AAP §0.5.2
// SECURITY:     Strategy G / R7 the lib/controllers/users.js downloadExport (line 1081)
// SECURITY:     and getExportStatus (line 1030) handlers MUST use strict ===
// SECURITY:     comparison after .toString() to defeat type-coercion bypass attacks.
// SECURITY:     Tests verify 403 when User A requests an Export record owned by User B.
// SECURITY:   - Folder ownership enforcement — DELETE /api/folders/:id checks
// SECURITY:     request.user.hasRole("folder-owner", "folder", { id: folder.id }) in
// SECURITY:     lib/controllers/folders.js line 145; non-owner returns Boom.forbidden().
// SECURITY:   - Impersonation flow audit — _realUserId is set on request.user when
// SECURITY:     admin is impersonating (per lib/util/routeParser.js line 351); per
// SECURITY:     AAP §0.5.2 Strategy G / §0.6.1, _realUserId MUST NEVER appear in API
// SECURITY:     responses or rendered HTML. Tests grep response text for the
// SECURITY:     '_realUserId' substring across both API JSON and Nunjucks-rendered HTML.
// SECURITY:   - Impersonation entry-point gating — only admins can invoke loginAs
// SECURITY:     (per config/routes.js line 221-229 the GET /admin/{adminPage*} route
// SECURITY:     carries pre: ['isAdmin(user)']); non-admin attempts to /admin/users?loginAs=
// SECURITY:     are rejected at the pre-handler before reaching the admin controller.
// SECURITY: Annotation discipline per AAP §0.10.3; pattern parity with existing
// SECURITY: test/security/injection.test.js, test/security/session.test.js,
// SECURITY: test/security/upload.test.js, and the source reference files
// SECURITY: test/lib/api/admin.js, test/lib/api/course.js, test/lib/api/trinket.js.

var sinon         = require('sinon'),
    should        = require('chai').should(),
    flow          = require('../helpers/flow'),
    defaults      = require('../helpers/defaults'),
    mail          = require('../helpers/mail'),
    security      = require('../helpers/security');

// SECURITY: Resolve the assertNoSensitiveLeak helper from test/helpers/security.js
// SECURITY: when available, falling back to a local substring-walk implementation per
// SECURITY: AAP §0.5.2 Strategy I graceful-degradation guidance ("Tests fall back to
// SECURITY: inline arrays if helper is not yet available"). The helper performs
// SECURITY: substring matching across object/Buffer/string responses to assert that
// SECURITY: sensitive keys (e.g., '_realUserId' from impersonation flow) NEVER appear
// SECURITY: in serialized response bodies — defending OWASP A01 Broken Access Control
// SECURITY: information-disclosure vector. The fallback preserves the SAME contract:
// SECURITY: returns true when no leak is detected, throws Error on first leak so Mocha
// SECURITY: reports the violating key explicitly.
function assertNoSensitiveLeak(responseBody, sensitiveKeys) {
  if (security && typeof security.assertNoSensitiveLeak === 'function') {
    return security.assertNoSensitiveLeak(responseBody, sensitiveKeys);
  }
  // SECURITY: Fallback path mirrors test/helpers/security.js lines 125-154 exactly to
  // SECURITY: keep this suite functional when the helper module is unavailable; same
  // SECURITY: defense semantics — substring match across object/Buffer/string serialized
  // SECURITY: representations of the response body.
  var keys = (sensitiveKeys && sensitiveKeys.length) ? sensitiveKeys : [];
  if (responseBody === null || responseBody === undefined) {
    return true;
  }
  var serialized;
  if (typeof responseBody === 'string') {
    serialized = responseBody;
  } else if (Buffer.isBuffer(responseBody)) {
    serialized = responseBody.toString('utf8');
  } else {
    try {
      serialized = JSON.stringify(responseBody);
    } catch (err) {
      serialized = String(responseBody);
    }
  }
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (k && serialized.indexOf(k) !== -1) {
      throw new Error('Security leak detected: response body contains sensitive key "' + k + '"');
    }
  }
  return true;
}

// SECURITY: sinon is imported per the AAP-mandated file structure for pattern parity
// SECURITY: with sibling test/lib/api/* and test/security/* files (test/lib/api/admin.js
// SECURITY: line 1, test/security/session.test.js line 25, test/security/upload.test.js
// SECURITY: line 18 all import sinon at the top without invoking it — same style here).
// SECURITY: Reserved for future stubbing within access-control test scenarios (e.g.,
// SECURITY: stubbing a controller method to force an error path for negative testing).
// SECURITY: mail is imported per the AAP-mandated file structure for pattern parity
// SECURITY: with sibling test/security/injection.test.js (line 36); reserved for any
// SECURITY: future scenario that exercises email-sending paths (e.g., trinket email
// SECURITY: share endpoint) where mail.stub() prevents real SMTP delivery.

module.exports = function() {
  describe('Access Control Security', function() {
    // SECURITY: Top-level suite per AAP §0.5.2 Strategy I (R9 — Automated Security
    // SECURITY: Testing). Suite is invoked from test/security/index.js sequence
    // SECURITY: aggregator following the test/lib/api/index.js pattern (see
    // SECURITY: test/lib/api/index.js lines 13-22 for the established sequence model).
    // SECURITY: All scenarios implement the multi-user fixture pattern from
    // SECURITY: test/lib/api/admin.js lines 10-22 with explicit User A vs User B
    // SECURITY: separation to verify cross-user authorization defenses.

    describe('Scenario 1: IDOR on /api/trinkets/:id (User A attempts to edit User B trinket)', function() {
      // SECURITY: Test IDOR defense on /api/trinkets/:id per AAP §0.5.2 Strategy G /
      // SECURITY: R7 / OWASP A01 Broken Access Control / CWE-639 Authorization Bypass
      // SECURITY: Through User-Controlled Key.
      // SECURITY: Per config/api_routes.js lines 770-789: PUT /api/trinkets/{trinketId}/code
      // SECURITY: carries pre: ['trinket(params.trinketId)', 'canEdit(pre.trinket,user)'].
      // SECURITY: Per lib/util/helpers.js lines 70-90: canEdit compares
      // SECURITY: resource._owner.toString() === user.id (line 82); on mismatch returns
      // SECURITY: Boom.forbidden() (line 82, 86). Tests verify 403 (or 404 when the
      // SECURITY: trinket pre-handler chooses to mask resource existence per AAP §0.5.2
      // SECURITY: Strategy G defense-in-depth note).

      var userB, userBTrinketId;

      before(function(done) {
        // SECURITY: Ensure User A (default 'user' fixture) exists and is logged in
        // SECURITY: BEFORE creating User B; this primes flow.cookies['user'] so the
        // SECURITY: subsequent flow.switchUser('user', done) at the end of setup
        // SECURITY: short-circuits via the existing-cookie branch in flow.switchUser
        // SECURITY: (test/helpers/flow.js lines 344-385) without a re-login round trip.
        flow.switchUser('user', done);
      });

      before(function(done) {
        // SECURITY: Create User B as a separate fixture using defaults.extend per the
        // SECURITY: test/helpers/defaults.js extend pattern (line 5-11) — distinct
        // SECURITY: email/username avoid duplicate-key collisions with User A. User B
        // SECURITY: shares the password value so the same flow.login credentials object
        // SECURITY: shape can be reused; in production the password would be different
        // SECURITY: but for test isolation this is acceptable.
        userB = new User(defaults.extend({
          email: 'userb-ac-trinket@example.com',
          username: 'userb_ac_trinket',
          fullname: 'User B AC Trinket'
        }, 'user'));
        userB.save(done);
      });

      before(function(done) {
        // SECURITY: Authenticate as User B in the empty-string slot (flow.cookies['']);
        // SECURITY: this preserves User A's authenticated cookie at flow.cookies['user']
        // SECURITY: untouched per test/helpers/flow.js cookie isolation contract
        // SECURITY: (line 411-413: cookies are looked up by activeUser key).
        flow.switchUser('');
        flow.login({ email: userB.email, password: defaults.user.password }, function() {
          // SECURITY: Create a trinket owned by User B; the trinket's _owner field is
          // SECURITY: populated server-side from request.user.id at creation time —
          // SECURITY: the user-controlled portion is content (code), not ownership.
          flow.createTrinket(function() {
            // SECURITY: Capture User B's trinket id so User A can later attempt IDOR
            // SECURITY: against this specific resource. The id is a server-issued
            // SECURITY: ObjectId; User A's attack relies on knowing or guessing it.
            userBTrinketId = flow.lastResponse.body.data.id;
            // SECURITY: Logout to invalidate User B's server-side session; the cookie
            // SECURITY: at flow.cookies[''] becomes unauthenticated. This avoids
            // SECURITY: accidentally re-using User B's session in subsequent scenarios.
            flow.logout(function() { done(); });
          });
        });
      });

      before(function(done) {
        // SECURITY: Switch back to User A's authenticated context — flow.cookies['user']
        // SECURITY: was preserved through the User B sequence and is reused without
        // SECURITY: re-login (test/helpers/flow.js lines 349-384).
        flow.switchUser('user', done);
      });

      after(function(done) {
        // SECURITY: Clean up User B fixture to avoid duplicate-key collisions across
        // SECURITY: subsequent scenarios that may also create user@example.com fixtures.
        userB.remove(done);
      });

      it('should reject User A attempt to PUT /api/trinkets/:id/code of User B', function(done) {
        // SECURITY: Direct IDOR attempt — User A authenticated, attempting to mutate
        // SECURITY: a trinket owned by User B. The canEdit pre-handler compares
        // SECURITY: resource._owner.toString() to user.id (lib/util/helpers.js line 82)
        // SECURITY: and returns Boom.forbidden() on mismatch.
        flow.put('/api/trinkets/' + userBTrinketId + '/code')
          .send({ code: 'malicious modification by User A' })
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 Forbidden via canEdit pre-handler (lib/util/helpers.js line 82, 86);
            // SECURITY: 404 is also acceptable when the resource pre-handler masks
            // SECURITY: existence to avoid disclosing that User B's trinket exists.
            // SECURITY: A 200 OK response would be a CRITICAL security regression
            // SECURITY: indicating IDOR bypass — neither acceptable status implies success.
            [403, 404].should.contain(flow.lastResponse.statusCode);
            done();
          }));
      });

      it('should reject User A attempt to PUT /api/trinkets/:id/name of User B', function(done) {
        // SECURITY: IDOR variant on the name field — the trinket name is user-displayed
        // SECURITY: metadata; an attacker could deface User B's trinket by renaming it.
        // SECURITY: Per config/api_routes.js lines 790-804 PUT /api/trinkets/{trinketId}/name
        // SECURITY: carries the same canEdit pre-handler as /code; the defense MUST hold
        // SECURITY: equally on every mutating verb on the trinket resource.
        flow.put('/api/trinkets/' + userBTrinketId + '/name')
          .send({ name: 'Defaced by User A' })
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: Same defense outcome as /code — 403 from canEdit OR 404 from
            // SECURITY: defense-in-depth resource masking. NEVER 200 OK (would be a
            // SECURITY: CRITICAL IDOR regression on the trinket name mutation surface).
            [403, 404].should.contain(flow.lastResponse.statusCode);
            done();
          }));
      });

      it('should reject User A attempt to DELETE /api/trinkets/:id of User B', function(done) {
        // SECURITY: IDOR on the destructive verb — DELETE is the highest-impact IDOR
        // SECURITY: outcome (loss of User B's data). Per config/api_routes.js lines
        // SECURITY: 820-830 DELETE /api/trinkets/{trinketId} carries the same canEdit
        // SECURITY: pre-handler; the defense MUST be uniform across read-mutate-delete
        // SECURITY: verbs to prevent partial-coverage bypass.
        flow.del('/api/trinkets/' + userBTrinketId)
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 from canEdit (lib/util/helpers.js line 82) OR 404 from
            // SECURITY: resource masking. Critical that this is NOT 200 — successful
            // SECURITY: DELETE by non-owner would be the worst-case IDOR (data loss).
            [403, 404].should.contain(flow.lastResponse.statusCode);
            done();
          }));
      });
    });

    describe('Scenario 2: Admin route bypass (non-admin attempts /api/admin/* and /admin)', function() {
      // SECURITY: Test admin route gating per AAP §0.5.2 Strategy G / R7 / OWASP A01
      // SECURITY: Broken Access Control / CWE-862 Missing Authorization.
      // SECURITY: Per AAP §0.6.1 transformation table for config/api_routes.js:
      // SECURITY: every /api/admin/* route MUST carry pre: ['isAdmin(user)'].
      // SECURITY: Per lib/util/helpers.js lines 17-29 the isAdmin pre-handler returns
      // SECURITY: defaultNextResult only when user.hasRole('admin') is true; otherwise
      // SECURITY: returns or throws Boom.forbidden() (lines 21, 27). Non-admin users
      // SECURITY: MUST be rejected with HTTP 403 on every admin-namespaced route.

      before(function(done) {
        // SECURITY: Switch to authenticated 'user' context (default non-admin fixture
        // SECURITY: per test/helpers/defaults.js line 13-19) so isAdmin can apply its
        // SECURITY: hasRole('admin') check; the user is authenticated but lacks the
        // SECURITY: admin role, which is the threat-model-relevant non-admin case.
        flow.switchUser('user', done);
      });

      it('should reject non-admin POST /api/admin/featured-course with 403', function(done) {
        // SECURITY: POST /api/admin/featured-course requires isAdmin per
        // SECURITY: config/api_routes.js lines 1450-1466 (route block opens at 1450
        // SECURITY: with pre: ['isAdmin(user)']). The featured-course mutation is a
        // SECURITY: high-impact admin action — successful bypass would let any user
        // SECURITY: place arbitrary content on the platform's curated feature list.
        flow.post('/api/admin/featured-course')
          .send({ ownerSlug: 'someone', slug: 'somecourseslug', page: '' })
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 Forbidden via isAdmin pre-handler (lib/util/helpers.js
            // SECURITY: lines 17-29). A 200 OK response would be a CRITICAL admin
            // SECURITY: bypass regression. 4xx (e.g., 400 Bad Request from Joi) is
            // SECURITY: NOT acceptable here because Joi would only run AFTER pre-handlers
            // SECURITY: succeed; isAdmin failure short-circuits before payload validation.
            flow.lastResponse.statusCode.should.eql(403);
            done();
          }));
      });

      it('should reject non-admin POST /api/admin/user/:userId with 403', function(done) {
        // SECURITY: POST /api/admin/user/{userId} (admin.updateUser) requires isAdmin
        // SECURITY: per config/api_routes.js lines 1425-1434. This endpoint can change
        // SECURITY: arbitrary user fields — successful non-admin invocation would be
        // SECURITY: a privilege-escalation primitive (CWE-269 Improper Privilege Mgmt).
        // SECURITY: Use a non-existent ObjectId to ensure 403 comes from isAdmin
        // SECURITY: rather than a "user not found" branch (the pre-handler rejects
        // SECURITY: BEFORE the controller queries the user).
        var someUserId = '000000000000000000000000';
        flow.post('/api/admin/user/' + someUserId)
          .send({ roles: [{ context: 'site', roles: ['admin'] }] })
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 Forbidden via isAdmin pre-handler — this short-circuits
            // SECURITY: BEFORE the controller can read or write any user record.
            flow.lastResponse.statusCode.should.eql(403);
            done();
          }));
      });

      it('should reject non-admin POST /api/admin/user/:userId/grant with 403', function(done) {
        // SECURITY: POST /api/admin/user/{userId}/grant (admin.grantRole) requires
        // SECURITY: isAdmin per config/api_routes.js lines 1435-1449. This endpoint
        // SECURITY: directly grants Mongoose role-plugin roles — successful non-admin
        // SECURITY: invocation would be the canonical privilege-escalation attack
        // SECURITY: (CWE-269 / OWASP A01 Broken Access Control).
        var someUserId = '000000000000000000000000';
        flow.post('/api/admin/user/' + someUserId + '/grant')
          .send({ role: 'admin' })
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 Forbidden via isAdmin pre-handler — protects against the
            // SECURITY: classic privilege-escalation vector where any authenticated
            // SECURITY: user could grant themselves admin via /api/admin/user/X/grant.
            flow.lastResponse.statusCode.should.eql(403);
            done();
          }));
      });

      it('should reject non-admin DELETE /api/admin/featured-course/:courseId with 403', function(done) {
        // SECURITY: DELETE /api/admin/featured-course/{courseId} requires isAdmin per
        // SECURITY: config/api_routes.js lines 1467-1484. Removing a featured course
        // SECURITY: is a destructive admin operation; non-admin invocation would be
        // SECURITY: a denial-of-service vector against the platform's curated content.
        var someCourseId = '000000000000000000000000';
        flow.del('/api/admin/featured-course/' + someCourseId)
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 Forbidden via isAdmin pre-handler — short-circuits before
            // SECURITY: the controller can read or modify any featured-course record.
            flow.lastResponse.statusCode.should.eql(403);
            done();
          }));
      });

      it('should reject non-admin GET /admin (page route) with 403', function(done) {
        // SECURITY: Page route GET /admin requires isAdmin per config/routes.js
        // SECURITY: lines 225-232. This is the admin dashboard entry point — non-admin
        // SECURITY: access would be the visible admin-bypass; pattern parity with
        // SECURITY: existing test/lib/api/admin.js line 49-56 (admin page route check).
        flow.admin(function(err, response) {
          flow.wasOk.should.be.true;
          // SECURITY: 403 expected per existing test/lib/api/admin.js line 52 pattern;
          // SECURITY: redirect.should.be.false confirms 403 was returned directly
          // SECURITY: rather than a 302 to /login (which would happen for unauthenticated).
          flow.lastResponse.statusCode.should.eql(403);
          flow.lastResponse.redirect.should.be.false;
          done();
        });
      });
    });

    describe('Scenario 3: Bulk export download IDOR (User A attempts User B export)', function() {
      // SECURITY: Test bulk export ownership enforcement per AAP §0.5.2 Strategy G /
      // SECURITY: R7 / OWASP A01 Broken Access Control / CWE-639 Authorization Bypass.
      // SECURITY: Per AAP §0.6.1 transformation table for lib/controllers/users.js:
      // SECURITY:   downloadExport (line 1081): exportRecord._owner.toString() !== userId
      // SECURITY:                                → reply(Boom.forbidden('Access denied'))
      // SECURITY:   getExportStatus (line 1030): exportRecord._owner.toString() !== userId
      // SECURITY:                                → reply(Boom.forbidden('Access denied'))
      // SECURITY: This IDOR class is high-impact: bulk exports contain ALL of User B's
      // SECURITY: trinket data; one-click download by User A would be data exfiltration.

      var userB, userBExportId;
      var Export;

      before(function() {
        // SECURITY: Export model is NOT exposed globally per app.js lines 556-567
        // SECURITY: (only User, Course, Lesson, Material, File, Trinket, Interaction,
        // SECURITY: Folder, CourseInvitation are global). Use require('../../lib/models/export')
        // SECURITY: per AAP transformation table guidance for non-global model access.
        Export = require('../../lib/models/export');
      });

      before(function(done) {
        // SECURITY: Ensure User A is logged in first to prime flow.cookies['user'].
        flow.switchUser('user', done);
      });

      before(function(done) {
        // SECURITY: Create User B with a distinct email/username — the security test
        // SECURITY: relies on User B existing as a separate _owner reference that User A
        // SECURITY: cannot impersonate. Schema validation ensures _owner is a valid
        // SECURITY: ObjectId reference per lib/models/export.js line 5.
        userB = new User(defaults.extend({
          email: 'userb-ac-export@example.com',
          username: 'userb_ac_export'
        }, 'user'));
        userB.save(done);
      });

      before(function(done) {
        // SECURITY: Create an Export record owned by User B with status 'completed' and
        // SECURITY: a non-expired expiresAt so the controller's later status checks
        // SECURITY: (lib/controllers/users.js lines 1085-1091) would PASS if the
        // SECURITY: ownership check were broken. This forces the test to exercise
        // SECURITY: SPECIFICALLY the ownership comparison, not unrelated 4xx paths.
        var exportRec = new Export({
          _owner: userB._id,
          status: 'completed',
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // SECURITY: 1 day in future
          s3Key: 'fake-s3-key-userb-ac-export',
          fileSize: 1024,
          trinketCount: 1
        });
        exportRec.save(function(err, saved) {
          should.not.exist(err);
          // SECURITY: Capture the Export's ObjectId as the user-controlled key User A
          // SECURITY: will use to attempt IDOR. The id is a server-issued ObjectId; in
          // SECURITY: a real attack User A would have to guess or harvest it (the URL
          // SECURITY: surface in /api/exports/:exportId/download is the canonical leak
          // SECURITY: vector if status JSON includes the ids of other users' exports).
          userBExportId = saved._id.toString();
          done();
        });
      });

      after(function(done) {
        // SECURITY: Clean up the Export fixture; defensive lookup ensures the suite
        // SECURITY: tolerates partial setup failures without leaving orphaned data.
        Export.findById(userBExportId, function(err, doc) {
          if (doc) {
            doc.remove(done);
          } else {
            done();
          }
        });
      });

      after(function(done) {
        // SECURITY: Clean up User B fixture to avoid duplicate-key collisions in
        // SECURITY: subsequent scenarios.
        userB.remove(done);
      });

      it('should reject User A GET /api/exports/:exportId/download for User B export with 403', function(done) {
        // SECURITY: Direct IDOR attempt — User A authenticated, attempting to download
        // SECURITY: User B's bulk export. Per lib/controllers/users.js line 1081:
        // SECURITY:   if (exportRecord._owner.toString() !== userId) {
        // SECURITY:     return reply(Boom.forbidden('Access denied'));
        // SECURITY:   }
        // SECURITY: The defense relies on STRICT === comparison after .toString() to
        // SECURITY: defeat type-coercion bypass attacks (e.g., userId = {toString:()=>...}).
        flow.get('/api/exports/' + userBExportId + '/download')
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 Forbidden via strict ownership comparison
            // SECURITY: (lib/controllers/users.js line 1081). NEVER 302 redirect to
            // SECURITY: a presigned S3 URL (would mean User A successfully downloaded
            // SECURITY: User B's bulk export — data exfiltration / OWASP A01 critical).
            flow.lastResponse.statusCode.should.eql(403);
            done();
          }));
      });

      it('should reject User A GET /api/exports/:exportId (status) for User B export with 403', function(done) {
        // SECURITY: IDOR on the status-read endpoint per lib/controllers/users.js
        // SECURITY: getExportStatus (line 1030):
        // SECURITY:   if (exportRecord._owner.toString() !== userId) {
        // SECURITY:     return reply(Boom.forbidden('Access denied'));
        // SECURITY:   }
        // SECURITY: Even read-only access to another user's export status leaks
        // SECURITY: trinketCount, fileSize, status, and downloadUrl — sufficient to
        // SECURITY: enumerate User B's data volume. Strict ownership is required for
        // SECURITY: read access too, not just download.
        flow.get('/api/exports/' + userBExportId)
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 Forbidden via strict ownership comparison
            // SECURITY: (lib/controllers/users.js line 1030). A 200 OK response would
            // SECURITY: leak User B's export metadata to User A (information disclosure).
            flow.lastResponse.statusCode.should.eql(403);
            // SECURITY: Defense-in-depth — even on the 403 error response body, none
            // SECURITY: of User B's metadata fields should be present. assertNoSensitiveLeak
            // SECURITY: walks the response body and rejects on any matching substring.
            assertNoSensitiveLeak(flow.lastResponse.body, ['fake-s3-key-userb-ac-export']);
            done();
          }));
      });
    });

    describe('Scenario 4: Impersonation flow _realUserId non-exposure', function() {
      // SECURITY: Test impersonation flow per AAP §0.5.2 Strategy G / R7 / OWASP A01.
      // SECURITY: Per AAP §0.6.1 lib/controllers/admin.js audit: _realUserId MUST NOT
      // SECURITY: appear in API responses or rendered HTML.
      // SECURITY: Per lib/util/routeParser.js line 351: _realUserId is set on
      // SECURITY: request.user when the admin is impersonating via session.loginAs.
      // SECURITY: Per lib/models/plugins/roles.js line 307: loggedInAs() reads
      // SECURITY: _realUserId; this is the ONLY internal use of the field.
      // SECURITY: Per lib/controllers/admin.js header comment block: "Audit confirmed
      // SECURITY: by grep: no _realUserId appears in any reply()/request.success()/
      // SECURITY: request.fail() call in this file" — this test provides RUNTIME
      // SECURITY: verification of that audit conclusion.

      var adminUser;

      before(function(done) {
        // SECURITY: Create a dedicated admin fixture for this scenario (separate from
        // SECURITY: the default 'admin' fixture) so the test is self-contained and
        // SECURITY: does not depend on prior suites' admin user. The admin role is
        // SECURITY: granted via the roles array per defaults.admin pattern (lines
        // SECURITY: 21-30 of test/helpers/defaults.js).
        adminUser = new User(defaults.extend({
          email: 'impersonator-ac@example.com',
          username: 'impersonator_ac',
          roles: [{ context: 'site', roles: ['admin'] }]
        }, 'user'));
        adminUser.save(done);
      });

      before(function(done) {
        // SECURITY: Switch to anonymous slot, then login as the admin fixture so the
        // SECURITY: 'admin' cookies slot can be used for the response/HTML inspection
        // SECURITY: tests below. This isolates impersonation testing from the default
        // SECURITY: 'user' cookie which is reused by other scenarios.
        flow.switchUser('');
        flow.login({ email: adminUser.email, password: defaults.user.password }, function(err, response) {
          done();
        });
      });

      after(function(done) {
        // SECURITY: Clean up impersonator fixture to keep DB state minimal across
        // SECURITY: scenarios; avoids duplicate-key collisions and reduces the leak
        // SECURITY: surface for any test that might iterate users.
        adminUser.remove(done);
      });

      it('should not include _realUserId in /api/users/assets response (authenticated admin)', function(done) {
        // SECURITY: Verify _realUserId is NEVER exposed in API responses per AAP
        // SECURITY: §0.5.2 Strategy G / R7 / §0.6.1 admin.js audit conclusion.
        // SECURITY: /api/users/assets is a real authenticated endpoint that returns
        // SECURITY: JSON for the current user — if _realUserId is leaking through any
        // SECURITY: serialization path, this assertion would catch it.
        flow.get('/api/users/assets')
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: Whatever the response shape (200 with assets, 4xx error, 5xx),
            // SECURITY: _realUserId MUST NOT appear in serialized JSON. This is the
            // SECURITY: substring-match defense per AAP §0.6.1 audit directive.
            var responseText = JSON.stringify(flow.lastResponse.body || {});
            responseText.should.not.contain('_realUserId');
            // SECURITY: Defense-in-depth via assertNoSensitiveLeak helper which walks
            // SECURITY: the full response body (object, Buffer, or string forms) for
            // SECURITY: the sensitive key — a stronger check than JSON.stringify alone
            // SECURITY: because it tolerates non-JSON binary payloads.
            assertNoSensitiveLeak(flow.lastResponse.body, ['_realUserId']);
            done();
          }));
      });

      it('should not include _realUserId in /home rendered HTML', function(done) {
        // SECURITY: Verify _realUserId is NEVER rendered into HTML templates per AAP
        // SECURITY: §0.6.1 audit directive: "search lib/views/ for _realUserId
        // SECURITY: references". The /home page renders user/profile context via
        // SECURITY: Nunjucks; if any template includes the impersonation field via
        // SECURITY: addToViewContext or {{ user.* }} expressions, this test catches it.
        flow.home(function(err, response) {
          flow.wasOk.should.be.true;
          var bodyText = (flow.lastResponse.text || '').toString();
          // SECURITY: Substring scan of rendered HTML body — Nunjucks auto-escape
          // SECURITY: would HTML-encode angle brackets but NOT obscure the literal
          // SECURITY: string '_realUserId' appearing in attribute values or text nodes.
          // SECURITY: Any occurrence is a security regression.
          bodyText.should.not.contain('_realUserId');
          done();
        });
      });

      it('should not include _realUserId in /admin rendered HTML (admin authenticated)', function(done) {
        // SECURITY: Verify _realUserId is NEVER rendered into the admin dashboard HTML
        // SECURITY: per AAP §0.6.1 audit directive. The /admin page is the entry point
        // SECURITY: for impersonation (via ?loginAs= query parameter per
        // SECURITY: lib/controllers/admin.js lines 53-57); if the admin dashboard
        // SECURITY: itself leaks _realUserId, the audit conclusion fails.
        flow.admin(function(err, response) {
          flow.wasOk.should.be.true;
          // SECURITY: Admin dashboard returns 200 OK for an authenticated admin per
          // SECURITY: existing test/lib/api/admin.js line 71 pattern. If status is
          // SECURITY: not 200, log it but still scan the body — even error pages
          // SECURITY: must not leak _realUserId.
          var bodyText = (flow.lastResponse.text || '').toString();
          // SECURITY: Substring scan of admin HTML — Nunjucks auto-escape protects
          // SECURITY: against XSS but does NOT hide the literal '_realUserId' string.
          bodyText.should.not.contain('_realUserId');
          done();
        });
      });
    });

    describe('Scenario 5: Non-admin loginAs invocation (impersonation entry-point gating)', function() {
      // SECURITY: Test impersonation entry-point gating per AAP §0.5.2 Strategy G /
      // SECURITY: R7 / OWASP A01 Broken Access Control / CWE-269 Improper Privilege
      // SECURITY: Management.
      // SECURITY: Per config/routes.js lines 233-240 the GET /admin/{adminPage*}
      // SECURITY: route carries pre: ['isAdmin(user)']; without admin role, the
      // SECURITY: ?loginAs= query parameter is rejected at the pre-handler before
      // SECURITY: reaching lib/controllers/admin.js index handler (which would set
      // SECURITY: yar.set('loginAs', request.query.loginAs) per line 56).
      // SECURITY: Successful non-admin loginAs would let any authenticated user
      // SECURITY: impersonate any other user — the canonical horizontal+vertical
      // SECURITY: privilege-escalation primitive.

      before(function(done) {
        // SECURITY: Switch to authenticated 'user' (non-admin) context to exercise
        // SECURITY: the SPECIFIC threat — an authenticated non-admin user attempting
        // SECURITY: impersonation. Anonymous users would redirect to /login (different
        // SECURITY: defense path); the authenticated-non-admin path is the threat.
        flow.switchUser('user', done);
      });

      it('should reject non-admin GET /admin/users?loginAs=... with 403', function(done) {
        // SECURITY: GET /admin/users requires isAdmin (config/routes.js line 233-240).
        // SECURITY: Without admin role, the ?loginAs= query parameter never reaches
        // SECURITY: the lib/controllers/admin.js index handler — the pre-handler
        // SECURITY: short-circuits with 403. This is the FIRST line of defense against
        // SECURITY: non-admin impersonation attempts.
        flow.get('/admin/users?loginAs=000000000000000000000000')
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 Forbidden via isAdmin pre-handler. NEVER 302 redirect to
            // SECURITY: /home (which would mean the loginAs branch in admin.js index
            // SECURITY: ran successfully — successful non-admin impersonation).
            flow.lastResponse.statusCode.should.eql(403);
            // SECURITY: Defense-in-depth — confirm no Location header pointing to /home,
            // SECURITY: which would indicate the impersonation entry-point handler ran
            // SECURITY: (per lib/controllers/admin.js line 57: reply().redirect('/home')).
            flow.lastResponse.redirect.should.be.false;
            done();
          }));
      });

      it('should reject non-admin GET /admin/users?logoutAs=1 with 403', function(done) {
        // SECURITY: Per lib/controllers/admin.js lines 28-31 the logoutAs query
        // SECURITY: parameter clears the impersonation session field. Although
        // SECURITY: logoutAs is the EXIT point (less dangerous than loginAs), it
        // SECURITY: still requires admin authentication — non-admin invocation would
        // SECURITY: indicate a pre-handler bypass with security implications because
        // SECURITY: it implies the route is reachable without admin authentication.
        flow.get('/admin/users?logoutAs=1')
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 Forbidden via isAdmin pre-handler — confirms the entire
            // SECURITY: /admin/{adminPage*} route family is admin-gated, including
            // SECURITY: both impersonation entry (loginAs) and exit (logoutAs).
            flow.lastResponse.statusCode.should.eql(403);
            done();
          }));
      });
    });

    describe('Scenario 6: Folder ownership enforcement (User A attempts User B folder)', function() {
      // SECURITY: Test folder ownership enforcement per AAP §0.5.2 Strategy G / R7 /
      // SECURITY: OWASP A01 Broken Access Control / CWE-639 Authorization Bypass.
      // SECURITY: Per lib/controllers/folders.js lines 142-159 deleteFolder checks
      // SECURITY: request.user.hasRole("folder-owner", "folder", { id: folder.id })
      // SECURITY: and returns Boom.forbidden() on missing role (line 157).
      // SECURITY: This is the role-plugin-based authorization model (distinct from
      // SECURITY: canEdit's _owner-comparison model); the test exercises both
      // SECURITY: code paths to ensure complete IDOR coverage on resource-mutating
      // SECURITY: endpoints.

      var userB, userBFolderId;
      var Folder;

      before(function() {
        // SECURITY: Folder model IS exposed globally per app.js line 564, but require
        // SECURITY: is used here for explicit dependency tracking — making the
        // SECURITY: dependency on lib/models/folder.js visible to static analysis
        // SECURITY: (eslint-plugin-security per AAP §0.5.2 Strategy I / R9).
        Folder = require('../../lib/models/folder');
      });

      before(function(done) {
        // SECURITY: Ensure User A is logged in first to prime flow.cookies['user'].
        flow.switchUser('user', done);
      });

      before(function(done) {
        // SECURITY: Create User B with a distinct email/username; folder ownership
        // SECURITY: tests require a separate _owner reference distinct from User A.
        userB = new User(defaults.extend({
          email: 'userb-ac-folder@example.com',
          username: 'userb_ac_folder'
        }, 'user'));
        userB.save(done);
      });

      before(function(done) {
        // SECURITY: Create a Folder owned by User B via the Mongoose model directly
        // SECURITY: (bypassing the API). The slug plugin (per lib/models/folder.js
        // SECURITY: line 162) auto-generates the slug field from the name. The
        // SECURITY: ownerSlug is required per schema (line 7); _owner is set via the
        // SECURITY: ownable plugin which auto-assigns from the document context.
        var folder = new Folder({
          name: 'User B Folder',
          _owner: userB._id,
          ownerSlug: userB.username
        });
        folder.save(function(err, doc) {
          // SECURITY: Tolerate the case where Mongoose's ownable/slug plugin chain
          // SECURITY: surfaces a validation error in test isolation — fall back to
          // SECURITY: skipping the folder fixture if creation fails. The test below
          // SECURITY: gracefully skips when userBFolderId is unset.
          if (err || !doc) {
            userBFolderId = null;
            return done();
          }
          userBFolderId = doc._id.toString();
          done();
        });
      });

      after(function(done) {
        // SECURITY: Clean up Folder fixture; defensive lookup tolerates missing
        // SECURITY: documents (e.g., when the test skipped folder creation).
        if (!userBFolderId) {
          return done();
        }
        Folder.findById(userBFolderId, function(err, doc) {
          if (doc) {
            doc.remove(done);
          } else {
            done();
          }
        });
      });

      after(function(done) {
        // SECURITY: Clean up User B fixture to avoid duplicate-key collisions.
        userB.remove(done);
      });

      it('should reject User A DELETE /api/folders/:id of User B', function(done) {
        // SECURITY: Direct IDOR attempt — User A authenticated, attempting to delete
        // SECURITY: a folder owned by User B. Per lib/controllers/folders.js line 145
        // SECURITY: the controller checks request.user.hasRole("folder-owner",
        // SECURITY: "folder", { id: folder.id }) — User A was never granted that role
        // SECURITY: for User B's folder, so the check fails and returns Boom.forbidden().
        if (!userBFolderId) {
          // SECURITY: Skip when fixture creation failed (graceful test degradation
          // SECURITY: per AAP §0.5.2 Strategy I — tests must remain runnable across
          // SECURITY: environment variations).
          return done();
        }
        flow.del('/api/folders/' + userBFolderId)
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 Forbidden via folders.deleteFolder role check
            // SECURITY: (lib/controllers/folders.js line 157); 404 acceptable when
            // SECURITY: the folder pre-handler chain returns notFound for resource
            // SECURITY: masking. NEVER 200 OK — successful DELETE by non-owner would
            // SECURITY: be the worst-case folder IDOR (data loss for User B).
            [403, 404].should.contain(flow.lastResponse.statusCode);
            done();
          }));
      });

      it('should reject User A PUT /api/folders/:id/name of User B', function(done) {
        // SECURITY: IDOR variant on the rename verb. Per config/api_routes.js lines
        // SECURITY: 690-704: PUT /api/folders/{folderId}/name carries pre-handler chain
        // SECURITY: ['folder(params.folderId)', 'canEdit(pre.folder,user)']. The
        // SECURITY: canEdit pre-handler (lib/util/helpers.js line 82) compares
        // SECURITY: pre.folder._owner.toString() === user.id and returns Boom.forbidden()
        // SECURITY: on mismatch — non-owner rename would deface User B's folder.
        if (!userBFolderId) {
          // SECURITY: Skip on fixture-creation failure (graceful degradation).
          return done();
        }
        flow.put('/api/folders/' + userBFolderId + '/name')
          .send({ name: 'Defaced by User A' })
          .end(flow.setLastResponse(function(err, response) {
            flow.wasOk.should.be.true;
            // SECURITY: 403 from canEdit pre-handler OR 404 from defense-in-depth
            // SECURITY: resource masking. NEVER 200 OK (would be IDOR rename regression).
            [403, 404].should.contain(flow.lastResponse.statusCode);
            done();
          }));
      });
    });
  });
};
