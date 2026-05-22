// SECURITY: Regression tests for JWT algorithm-confusion (CVE-2022-23540 / CVE-2022-23541).
// Verifies jsonwebtoken@9 upgrade and explicit `algorithms: ['HS256']` pinning at every
// call site (lib/util/helpers.js:264 verify; lib/controllers/trinket.js:368, 421, 693 sign).
// AAP §0.5.1, §0.6.1, §0.8.1.

require('../setup');                       // global bootstrap (NODE_ENV=test, chai plugins, redis-mock)

var fs       = require('fs');
var path     = require('path');
var should   = require('chai').should();
var jwt      = require('jsonwebtoken');

describe('Security: JWT algorithm pinning', function() {

  // -------------------------------------------------------------------------
  // Group A — Source-Code Inspection
  //
  // Verifies that the algorithm-pinning security fixes are present in the
  // actual source code at the call sites enumerated in AAP §0.6.1. This
  // catches regressions where a future agent might inadvertently remove the
  // `algorithms: ['HS256']` option from `jwt.verify` or the
  // `algorithm: 'HS256', expiresIn: '7d'` options from `jwt.sign`.
  //
  // The defense-in-depth rationale: even after the library upgrade to
  // jsonwebtoken@9 (which itself rejects 'none' tokens by default when the
  // verifier specifies algorithms), the explicit pin is required so the
  // verifier never falls back to permissive defaults.
  // -------------------------------------------------------------------------

  describe('lib/util/helpers.js source inspection', function() {
    var helpersSource;

    before(function() {
      // __dirname resolves to <repo-root>/test/security; navigating up two
      // levels lands at <repo-root>, from which lib/util/helpers.js is
      // reachable. Reading once in `before` avoids per-test I/O overhead.
      helpersSource = fs.readFileSync(
        path.join(__dirname, '..', '..', 'lib', 'util', 'helpers.js'),
        'utf8'
      );
    });

    it('should pin algorithms: [HS256] on jwt.verify (CVE-2022-23540)', function() {
      // Match `jwt.verify(<args>algorithms: ['HS256']...` with flexible whitespace
      // and accepting either single or double quotes. The `[^)]*` quantifier
      // bounds the scan to the verify call body so we don't accidentally match
      // a different verify call or a comment elsewhere in the file.
      helpersSource.should.match(
        /jwt\.verify\([^)]*algorithms\s*:\s*\[\s*['"]HS256['"]\s*\]/
      );
    });

    it('should carry the SECURITY annotation citing CVE-2022-23540', function() {
      // The AAP §0.10.4 mandates inline `// SECURITY:` annotations for every
      // Critical/High fix. This test ensures the annotation is preserved and
      // serves as the audit-trail anchor a future reviewer will grep for.
      helpersSource.should.match(/\/\/\s*SECURITY:[^\n]*CVE-2022-23540/);
    });
  });

  describe('lib/controllers/trinket.js source inspection', function() {
    var trinketSource;

    before(function() {
      trinketSource = fs.readFileSync(
        path.join(__dirname, '..', '..', 'lib', 'controllers', 'trinket.js'),
        'utf8'
      );
    });

    it('should pin algorithm: HS256 and expiresIn: 7d on every jwt.sign call', function() {
      // Capture every jwt.sign(...) invocation. The non-greedy `[\s\S]*?\}\)`
      // span matches from `jwt.sign(` up to the first closing brace+paren,
      // which is reliably the end of the options-object argument when the
      // call follows the canonical `jwt.sign(payload, secret, { ... })`
      // shape used at all three AAP §0.6.1 call sites.
      var signCalls = trinketSource.match(/jwt\.sign\([\s\S]*?\}\)/g) || [];

      // AAP §0.6.1 explicitly enumerates three jwt.sign call sites at
      // lines 368, 421, 693. The `at.least(3)` assertion is robust to
      // future additions but enforces the documented minimum.
      signCalls.should.have.length.at.least(3);

      signCalls.forEach(function(call) {
        // Each sign call must explicitly set the algorithm to HS256 to
        // prevent algorithm-confusion attacks (CVE-2022-23540) and must
        // bound the token lifetime to 7 days as defense-in-depth for the
        // email-share token surface.
        call.should.match(/algorithm\s*:\s*['"]HS256['"]/);
        call.should.match(/expiresIn\s*:\s*['"]7d['"]/);
      });
    });

    it('should carry the SECURITY annotation citing the email-share JWT', function() {
      // Per AAP §0.10.4, every Critical/High fix carries a `// SECURITY:`
      // inline annotation. The signing call sites include the marker
      // "explicit algorithm + expiry for email-share JWT" — verify it
      // remains in place across all changes.
      trinketSource.should.match(/\/\/\s*SECURITY:[^\n]*email-share JWT/);
    });
  });

  // -------------------------------------------------------------------------
  // Group B — jsonwebtoken@9 Library Behavior Verification
  //
  // Exercises the upgraded jsonwebtoken@^9.0.2 library directly to confirm
  // the runtime guarantees:
  //
  //   1. Tokens with `alg: 'none'` are rejected when algorithms is pinned.
  //   2. HS256-signed tokens are rejected when algorithms = ['RS256'].
  //   3. Properly HS256-signed tokens are accepted when algorithms = ['HS256'].
  //   4. Expired tokens (past `exp` claim) are rejected.
  //
  // These tests would have failed against jsonwebtoken@^5.0.5 (the pre-
  // remediation pin), which permitted the `none` algorithm by default.
  // -------------------------------------------------------------------------

  describe('jsonwebtoken@9 library behavior', function() {
    // 32-character minimum mirrors the entropy guard the application enforces
    // on session-cookie passwords and email-share JWT secrets.
    var secret = 'test-secret-min-32-chars-for-entropy-guard';

    it('should reject a token signed with the none algorithm when algorithms is pinned', function() {
      // Construct a "none" token manually: header.payload.<empty signature>.
      // Node 16+ supports the 'base64url' encoding directly (the AAP mandates
      // node:20-bookworm-slim, so this encoding is reliably available).
      var header  = Buffer.from(JSON.stringify({alg: 'none', typ: 'JWT'})).toString('base64url');
      var payload = Buffer.from(JSON.stringify({shortCode: 'abc', iat: Math.floor(Date.now() / 1000)})).toString('base64url');
      var noneToken = header + '.' + payload + '.';

      // jsonwebtoken@9 surfaces different messages for different failure
      // modes when faced with a 'none' token:
      //   - "jwt signature is required"   (empty signature segment)
      //   - "invalid algorithm"           (signature segment present but alg mismatched)
      //   - "invalid signature"           (HMAC re-compute mismatch)
      //   - "jwt malformed"               (structurally invalid token)
      // The disjunction makes the test resilient to internal library
      // changes while still definitively rejecting the bypass.
      (function() {
        jwt.verify(noneToken, secret, { algorithms: ['HS256'] });
      }).should.throw(/invalid algorithm|jwt malformed|invalid signature|jwt signature is required/i);
    });

    it('should reject an HS256-signed token when verifier pins algorithms: [RS256]', function() {
      // The classic algorithm-confusion class: a token legitimately signed
      // with HS256 must still be rejected if the verifier expects RS256.
      // jsonwebtoken@9 enforces this when `algorithms` is explicitly set,
      // unlike pre-9 versions which could fall back to header-driven choice.
      var hs256Token = jwt.sign({shortCode: 'abc'}, secret, { algorithm: 'HS256' });

      (function() {
        jwt.verify(hs256Token, secret, { algorithms: ['RS256'] });
      }).should.throw(/invalid algorithm/i);
    });

    it('should accept a properly HS256-signed token when algorithms includes HS256', function() {
      // Positive path: a token signed with HS256 + expiresIn: '7d' (matching
      // the AAP §0.6.1 canonical shape) must be accepted by a verifier
      // that pins algorithms: ['HS256']. The decoded payload must include
      // both the application-level claim (shortCode) and the
      // library-injected `exp` claim from `expiresIn`.
      var hs256Token = jwt.sign({shortCode: 'abc'}, secret, { algorithm: 'HS256', expiresIn: '7d' });
      var decoded = jwt.verify(hs256Token, secret, { algorithms: ['HS256'] });

      decoded.should.have.property('shortCode', 'abc');
      decoded.should.have.property('exp');           // expiresIn produces an exp claim
      decoded.should.have.property('iat');           // sign always emits iat
    });

    it('should reject expired tokens', function() {
      // Negative path: a token whose `exp` claim is in the past must be
      // rejected even when the algorithm pin matches. expiresIn: '-1s'
      // produces a token that is already expired at issue time.
      var expiredToken = jwt.sign({shortCode: 'abc'}, secret, { algorithm: 'HS256', expiresIn: '-1s' });

      (function() {
        jwt.verify(expiredToken, secret, { algorithms: ['HS256'] });
      }).should.throw(/jwt expired/i);
    });
  });

  // -------------------------------------------------------------------------
  // Group C — Asymmetric-Key Confusion Regression (CVE-2022-23541)
  //
  // The classic CVE-2022-23541 attack: an adversary tries to forge an
  // HS256-signed token using the verifier's PUBLIC key as the HMAC secret.
  // If the verifier doesn't pin algorithms, the library could be tricked
  // into using HS256 with the public key as the symmetric secret, allowing
  // forged tokens to verify successfully.
  //
  // With jsonwebtoken@9 + algorithms: ['HS256'] pin + a high-entropy unique
  // server-side secret, the forged token cannot match the signature the
  // verifier recomputes, so it is rejected with `invalid signature`.
  // -------------------------------------------------------------------------

  describe('asymmetric-key confusion attack', function() {
    it('should reject a token forged with the public key as HS256 secret', function() {
      // Simulate the attack: attacker signs with HS256 using what would be
      // the verifier's public key as the "secret". For this regression test
      // the exact PEM contents are irrelevant — what matters is that
      // attackerSecret !== realSecret, so the HMAC recompute by the verifier
      // produces a different signature than the attacker's, triggering the
      // `invalid signature` rejection.
      var fakePublicKey  = '-----BEGIN PUBLIC KEY-----\nABC123\n-----END PUBLIC KEY-----';
      var attackerSecret = fakePublicKey;                              // attacker's HMAC secret
      var realSecret     = 'real-application-secret-min-32-chars';     // server-side secret
      var forgedToken    = jwt.sign({admin: true}, attackerSecret, { algorithm: 'HS256' });

      (function() {
        jwt.verify(forgedToken, realSecret, { algorithms: ['HS256'] });
      }).should.throw(/invalid signature/i);
    });

    it('should reject a token signed with one secret but verified with another', function() {
      // Generalised form of the same attack: any mismatch between the
      // signing secret and the verifying secret must yield `invalid
      // signature`. This protects against secret-rotation slippage where an
      // old secret could be used to forge tokens against a new secret.
      var oldSecret = 'previous-application-secret-32-chars';
      var newSecret = 'rotated-application-secret-32-chars';
      var oldToken  = jwt.sign({shortCode: 'abc'}, oldSecret, { algorithm: 'HS256', expiresIn: '7d' });

      (function() {
        jwt.verify(oldToken, newSecret, { algorithms: ['HS256'] });
      }).should.throw(/invalid signature/i);
    });
  });
});
