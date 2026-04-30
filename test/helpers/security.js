// SECURITY: Shared test helpers for test/security/* security regression suite.
// SECURITY: Implements R9 (Automated Security Testing) per AAP §0.5.2 Strategy I and
// SECURITY: §0.6.1 File Transformation Mapping; annotation discipline per §0.10.3.
// SECURITY: Consumers: test/security/auth.test.js, test/security/access-control.test.js,
// SECURITY: test/security/injection.test.js, test/security/session.test.js,
// SECURITY: test/security/upload.test.js, and test/security/index.js (sequence aggregator).
// SECURITY: Provides payload corpora (XSS, NoSQL operator injection, path traversal,
// SECURITY: malformed ObjectId) and stateless utilities (malformed JWT, expired cookie,
// SECURITY: case-insensitive header lookup, sensitive-leak assertion, large-payload
// SECURITY: builder) used to assert defenses against OWASP Top 10 (A01/A03/A04/A05/A07).

var _ = require('underscore');

// SECURITY: XSS payload corpus per OWASP A03 (Injection) / CWE-79 (Cross-site Scripting).
// SECURITY: Each payload exercises a distinct DOM/HTML injection sink to verify Nunjucks
// SECURITY: server-side auto-escape (lib/util/nunjucks.js) and per-template `| e` filter
// SECURITY: usage in lib/views/*.html. Consumed by test/security/injection.test.js
// SECURITY: Scenario 7 (XSS in user-controlled fields rendered server-side).
var xssPayloads = [
  '<script>alert(1)</script>',
  '<script>alert("xss")</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '<iframe src="javascript:alert(1)"></iframe>',
  'javascript:alert(1)',
  '"><script>alert(String.fromCharCode(88,83,83))</script>',
  '<body onload=alert(1)>',
  '<a href="javascript:alert(1)">click</a>'
];

// SECURITY: NoSQL operator injection payloads per OWASP A03 (Injection) / CWE-89 analog.
// SECURITY: $where enables JavaScript execution inside MongoDB; $gt/$ne enable
// SECURITY: authentication bypass (e.g., {email:{$gt:''},password:{$gt:''}}); $regex
// SECURITY: enables ReDoS; $exists/$or enable enumeration. Used by
// SECURITY: test/security/injection.test.js Scenario 8 to assert Joi schemas reject
// SECURITY: operator-prefixed keys and Mongoose schema typing coerces user input.
var nosqlInjectionPayloads = [
  { $where: 'sleep(1000)' },
  { $gt: '' },
  { $ne: null },
  { $regex: '.*' },
  { $exists: true },
  { $or: [ { a: 1 }, { b: 2 } ] }
];

// SECURITY: Path traversal payload corpus per OWASP A04 (Insecure Design) / CWE-22.
// SECURITY: Includes Unix-style (../), Windows-style (..\\), absolute-path (/etc/passwd),
// SECURITY: double-dot bypass (....//), and URL-encoded (%2e%2e) variants per OWASP path
// SECURITY: traversal cheat sheet. Used by test/security/upload.test.js Scenario 5 to
// SECURITY: verify hash-based filename storage in lib/util/file.js neutralizes traversal.
var pathTraversalPayloads = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\system32\\config\\sam',
  '/etc/passwd',
  '....//....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
];

// SECURITY: Malformed Mongoose ObjectId corpus per OWASP A03 (Injection).
// SECURITY: Includes non-hex strings, wrong-length strings, empty/null/undefined, and
// SECURITY: an operator-injection ObjectId ({$eq:'foo'}) to assert that Mongoose
// SECURITY: findById/findOne reject malformed input via CastError and Joi schemas
// SECURITY: reject operator-prefixed values rather than passing them to the query.
var malformedObjectIds = [
  'not-an-objectid',
  '1234',
  'gggggggggggggggggggggggg',
  '',
  null,
  undefined,
  { $eq: 'foo' }
];

// SECURITY: Generates a syntactically broken three-segment JWT for testing jwt.verify
// SECURITY: failure paths in lib/util/helpers.js verifyEmailToken pre-handler. Per
// SECURITY: AAP §0.6.1, that pre-handler must return Boom.forbidden() rather than
// SECURITY: leaking JWT error details (information-disclosure defense; OWASP A07).
function generateMalformedJwt() {
  return 'fakeheader.fakebody.fakesig';
}

// SECURITY: Builds a Set-Cookie-style header value with a Unix-epoch (guaranteed past)
// SECURITY: Expires timestamp. Used by test/security/session.test.js to assert that
// SECURITY: the server clears expired session cookies on subsequent requests rather
// SECURITY: than treating them as valid (session-fixation/replay defense; OWASP A07).
// SECURITY: Defaults cookie name to 'session' (matches @hapi/yar default) when omitted.
function generateExpiredCookie(name) {
  var cookieName = name || 'session';
  return cookieName + '=expired-value; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly';
}

// SECURITY: Case-insensitive lookup for response security headers. Used by
// SECURITY: test/security/auth.test.js and test/security/access-control.test.js to
// SECURITY: assert presence of X-Content-Type-Options, Referrer-Policy,
// SECURITY: Content-Security-Policy, and X-Frame-Options per AAP §0.5.2 Strategy D
// SECURITY: (R4 / OWASP A05 Security Misconfiguration). Node normalizes incoming
// SECURITY: response headers to lowercase, but this helper defensively iterates the
// SECURITY: header map to tolerate any case variation seen in older Hapi/Supertest pairs.
function hasSecurityHeader(response, headerName) {
  if (!response || !response.headers || !headerName) {
    return false;
  }
  var target = String(headerName).toLowerCase();
  // SECURITY: Direct lowercase lookup first (Node http normalizes header keys).
  if (response.headers[target] !== undefined) {
    return true;
  }
  // SECURITY: Defensive iteration for any case-mismatched keys seen in legacy clients.
  var found = false;
  _.each(response.headers, function(value, key) {
    if (key && key.toLowerCase() === target) {
      found = true;
    }
  });
  return found;
}

// SECURITY: Walks a response body (object, Buffer, or string) and asserts that none of
// SECURITY: sensitiveKeys appear as substrings. Used by test/security/access-control.test.js
// SECURITY: to verify per AAP §0.6.1: '_realUserId never returned in API responses' and
// SECURITY: 'search lib/views/ for _realUserId references' (OWASP A01 Broken Access Control;
// SECURITY: impersonation flow audit per lib/controllers/admin.js loginAs/logoutAs). Throws
// SECURITY: Error on first leak so Mocha reports the violating key explicitly; returns true
// SECURITY: when no leak is detected so callers can chain assertions in expect().to.be.true.
function assertNoSensitiveLeak(responseBody, sensitiveKeys) {
  // SECURITY: Coerce undefined/non-array sensitiveKeys to [] so the helper is a no-op
  // SECURITY: rather than throwing TypeError when callers pass malformed arguments.
  var keys = _.isArray(sensitiveKeys) ? sensitiveKeys : [];
  if (responseBody === null || responseBody === undefined) {
    return true;
  }
  var serialized;
  if (typeof responseBody === 'string') {
    serialized = responseBody;
  } else if (Buffer.isBuffer(responseBody)) {
    // SECURITY: Decode Buffer responses (e.g., binary export downloads) as UTF-8 so
    // SECURITY: substring matching catches sensitive keys serialized into binary blobs.
    serialized = responseBody.toString('utf8');
  } else {
    try {
      serialized = JSON.stringify(responseBody);
    } catch (err) {
      // SECURITY: Fall back to String(...) for circular references rather than masking
      // SECURITY: the leak by returning true when JSON.stringify throws.
      serialized = String(responseBody);
    }
  }
  _.each(keys, function(k) {
    if (k && serialized.indexOf(k) !== -1) {
      throw new Error('Security leak detected: response body contains sensitive key "' + k + '"');
    }
  });
  return true;
}

// SECURITY: Generates a zero-filled Buffer of approximately sizeMb megabytes. Used by
// SECURITY: test/security/upload.test.js Scenario 3 to test Hapi route payload.maxBytes
// SECURITY: enforcement (10MB cap on /file, 5MB on /file/avatar) and to confirm rejection
// SECURITY: with HTTP 413 rather than crash. Buffer.alloc zero-fills (Node 6+ API) and
// SECURITY: never leaks process heap contents — preferred over deprecated `new Buffer(n)`
// SECURITY: per Node.js Security WG guidance and AAP §0.5.2 Strategy F (Node 20 base).
function buildLargePayload(sizeMb) {
  var mb = (typeof sizeMb === 'number' && sizeMb > 0) ? sizeMb : 1;
  return Buffer.alloc(mb * 1024 * 1024);
}

// SECURITY: Object-literal export matches the existing test/helpers/* pattern (store.js
// SECURITY: lines 4–22, mail.js lines 5–16, queue.js lines 4–21). Vertical alignment of
// SECURITY: the `:` mirrors store.js / mail.js for readability. Key names match the
// SECURITY: exact contract consumed by test/security/* modules.
module.exports = {
  xssPayloads:            xssPayloads,
  nosqlInjectionPayloads: nosqlInjectionPayloads,
  pathTraversalPayloads:  pathTraversalPayloads,
  malformedObjectIds:     malformedObjectIds,
  generateMalformedJwt:   generateMalformedJwt,
  generateExpiredCookie:  generateExpiredCookie,
  hasSecurityHeader:      hasSecurityHeader,
  assertNoSensitiveLeak:  assertNoSensitiveLeak,
  buildLargePayload:      buildLargePayload
};
