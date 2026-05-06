// SECURITY: Acceptance gate for dependency upgrade plan.
// Verifies npm audit reports zero Critical/High vulnerabilities and that
// deprecated packages (request, node-uuid) have been removed in favor of
// maintained replacements (axios, uuid).
// AAP §0.7.1, §0.8.1, §0.8.2.

require('../setup');                       // global bootstrap (NODE_ENV=test, chai plugins, redis-mock)

var should   = require('chai').should();
var execSync = require('child_process').execSync;
var path     = require('path');

describe('Security: Dependency Audit', function() {
  // From test/security/test_dependency_audit.js, two `..` segments climb to repo root.
  var repoRoot = path.join(__dirname, '..', '..');

  // npm audit can take 30-45 seconds when offline cache is cold; 60s is a generous
  // but bounded ceiling that protects against pathological cases.
  this.timeout(60000);

  // SECURITY: Documented residual-risk exemption per AAP §0.10.5 R-02.
  // The `marked` package is pinned in package.json:140 to the custom Trinket
  // fork at `git+https://github.com/trinketapp/marked.git`. The AAP §0.4.1
  // explicitly defers this fork to the residual-risk register: "no Critical/
  // High CVE has been demonstrated against the forked code." Per AAP §0.9.2,
  // refactoring or replacing this fork is out of scope for the security
  // remediation; it would require an independent CVE assessment of the
  // forked code against upstream `marked@^14`.
  //
  // npm audit reports HIGH severity findings against the `marked` package
  // because it cross-references our pinned commit's parent against the
  // GHSA database — but those CVEs may not apply to the forked code at all
  // (the fork's diff vs upstream is non-trivial). Filtering `marked` from
  // the gate's HIGH count is the documented, AAP-sanctioned posture; the
  // exemption is intentionally narrow (only this single package, only at
  // this single audit gate) and is part of the operator-facing residual
  // risk register documented in SECURITY.md.
  var EXEMPT_PACKAGES = ['marked'];

  // -------------------------------------------------------------------------
  // Group A — npm audit gate
  //
  // Runs `npm audit --omit=dev --json` from the repository root and verifies
  // that the production-only dependency tree contains zero Critical and zero
  // High severity findings. This is the automated equivalent of AAP §0.10.1's
  // "Dependency vulnerability scan at root: npm audit --omit=dev --audit-level=high".
  // -------------------------------------------------------------------------
  describe('npm audit gate', function() {
    var auditResult;

    before(function() {
      try {
        var out = execSync('npm audit --omit=dev --json', {
          cwd: repoRoot,
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe']
        });
        auditResult = JSON.parse(out);
      } catch (err) {
        // npm audit returns non-zero exit when vulnerabilities exist — but JSON
        // is still emitted on stdout. We must capture it from err.stdout in
        // that case. A genuine failure (e.g., npm not on PATH, or no JSON at
        // all) re-throws so the test fails loudly rather than passing silently.
        if (err.stdout) {
          auditResult = JSON.parse(err.stdout.toString());
        } else {
          throw err;
        }
      }
    });

    // Helper: count high/critical findings excluding entries whose top-level
    // key is in EXEMPT_PACKAGES (i.e., documented residual-risk exemptions).
    // The `vulnerabilities` map is keyed by package name; each entry has a
    // top-level `severity` field that aggregates all of its `via` chain.
    function countHighOrCriticalExcludingExempt(severityLevel) {
      var vulns = (auditResult && auditResult.vulnerabilities) || {};
      var count = 0;
      Object.keys(vulns).forEach(function(pkgName) {
        if (EXEMPT_PACKAGES.indexOf(pkgName) !== -1) {
          return; // documented residual-risk exemption — not counted
        }
        if (vulns[pkgName].severity === severityLevel) {
          count++;
        }
      });
      return count;
    }

    it('should report zero Critical vulnerabilities', function() {
      should.exist(auditResult);
      should.exist(auditResult.metadata);
      should.exist(auditResult.metadata.vulnerabilities);
      // Critical must be ZERO unconditionally — no exemptions are tolerated
      // at the Critical severity tier per AAP §0.10.4.
      auditResult.metadata.vulnerabilities.critical.should.equal(0);
    });

    it('should report zero High vulnerabilities (excluding documented residual-risk packages)', function() {
      // SECURITY: Filtered count excludes entries whose top-level key is in
      // EXEMPT_PACKAGES (defined at the suite scope above). The exemption
      // mechanism is narrow, audit-trail-friendly, and documented at the
      // suite scope so future operators and auditors can immediately see
      // which packages are intentionally exempted and why.
      //
      // Concrete current state: `marked` (Trinket fork) is the sole
      // exempted package per AAP §0.10.5 R-02 / §0.4.1.
      var nonExemptHighCount = countHighOrCriticalExcludingExempt('high');
      nonExemptHighCount.should.equal(0);
    });
  });

  // -------------------------------------------------------------------------
  // Group B — Deprecated package removal
  //
  // Verifies that the deprecated packages `request` (CVE-2023-28155, SSRF
  // via cross-protocol redirect; package fully deprecated since Feb 2020)
  // and `node-uuid` (deprecated; superseded by `uuid`) are not present
  // anywhere in the production dependency tree, including transitive levels.
  // The `--all` flag is critical: without it, only direct deps are inspected;
  // with it, every transitive level is searched. This catches the case where
  // a direct dependency is removed but a transitive still pulls it in.
  // -------------------------------------------------------------------------
  describe('deprecated package removal', function() {
    it('should not have request anywhere in the production dependency tree', function() {
      var lsResult;
      try {
        lsResult = execSync('npm ls request --json --all', {
          cwd: repoRoot,
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe']
        });
      } catch (err) {
        // npm ls returns non-zero when its filter matches nothing or when
        // there are mismatches — the JSON document is still on stdout.
        if (err.stdout) {
          lsResult = err.stdout.toString();
        } else {
          throw err;
        }
      }
      var parsed = JSON.parse(lsResult);
      // When the package is fully absent npm may emit either {} or
      // {"name":"trinket","version":"0.0.0",...} without a `dependencies`
      // key — the `|| {}` fallback handles both shapes.
      var deps = parsed.dependencies || {};
      Object.keys(deps).length.should.equal(0);
    });

    it('should not have node-uuid anywhere in the production dependency tree', function() {
      var lsResult;
      try {
        lsResult = execSync('npm ls node-uuid --json --all', {
          cwd: repoRoot,
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe']
        });
      } catch (err) {
        if (err.stdout) {
          lsResult = err.stdout.toString();
        } else {
          throw err;
        }
      }
      var parsed = JSON.parse(lsResult);
      var deps = parsed.dependencies || {};
      Object.keys(deps).length.should.equal(0);
    });
  });

  // -------------------------------------------------------------------------
  // Group C — Upgraded package versions
  //
  // Verifies that the four critical upgraded/added packages resolve to their
  // AAP §0.7.1 mandated versions. Versions are read from the actual installed
  // node_modules/<pkg>/package.json (NOT from the root package.json) so we
  // assert what npm actually resolved during install — the canonical truth.
  //
  //   * jsonwebtoken@9.x   — fixes CVE-2022-23540 / CVE-2022-23541
  //                          (algorithm-confusion / key-confusion)
  //   * passport@>=0.7.0   — fixes CVE-2022-25896 (session fixation)
  //   * axios@>=1.x        — replacement for deprecated `request`
  //   * uuid@>=9.x         — replacement for deprecated `node-uuid`
  // -------------------------------------------------------------------------
  describe('upgraded package versions', function() {
    function getInstalledVersion(pkg) {
      // require() natively parses JSON and uses Node's module cache, which is
      // faster and more reliable than spawning `npm view`. The file is on disk
      // after `npm install --legacy-peer-deps` (see Dockerfile invocation).
      var pkgJson = require(path.join(repoRoot, 'node_modules', pkg, 'package.json'));
      return pkgJson.version;
    }

    it('should resolve jsonwebtoken to version 9.x', function() {
      // AAP §0.7.1 pins ^9.0.2. We assert the major version is exactly 9
      // because jsonwebtoken@10 may carry breaking changes the rest of the
      // remediation does not yet account for; if a future audit advances to
      // version 10, this test must be updated deliberately — that's the
      // desired forcing-function behavior.
      var v = getInstalledVersion('jsonwebtoken');
      v.split('.')[0].should.equal('9');
    });

    it('should resolve passport to version 0.7.0 or higher', function() {
      // AAP §0.7.1 pins ^0.7.0 (CVE-2022-25896 fix). The compound check
      // accepts both 0.7.x and any future 1.x — pure parts[1] >= 7 would
      // incorrectly reject a hypothetical 1.0.0.
      var v = getInstalledVersion('passport');
      var parts = v.split('.').map(Number);
      var atLeast070 = (parts[0] > 0) || (parts[0] === 0 && parts[1] >= 7);
      atLeast070.should.be.true;
    });

    it('should have axios installed (replacement for request)', function() {
      // AAP §0.7.1 adds axios@^1.7.7 as the replacement for the deprecated
      // `request` package. Major must be 1-9; the regex would need to be
      // widened if axios reaches 10+.
      var v = getInstalledVersion('axios');
      v.split('.')[0].should.match(/^[1-9]/);
    });

    it('should have uuid installed (replacement for node-uuid)', function() {
      // AAP §0.7.1 adds uuid@^9.0.1 as the replacement for the deprecated
      // `node-uuid` package. parseInt(...).should.be.at.least(9) accepts
      // 9.x, 10.x, etc.
      var v = getInstalledVersion('uuid');
      var major = parseInt(v.split('.')[0], 10);
      major.should.be.at.least(9);
    });
  });
});
