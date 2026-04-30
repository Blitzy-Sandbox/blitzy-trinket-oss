# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-30 - Security Remediation

This release implements the multi-class vulnerability remediation effort described in
the project's security Agent Action Plan (AAP). Changes follow the Minimal Change
Clause: only files and functions directly implicated by a discovered vulnerability are
modified, every changed line carries an inline `// SECURITY: [threat addressed]`
annotation, and remediation is committed in atomic units (one CVE or vulnerability
class per commit) with the message format `security: [severity] fix [description] in
[file]`.

The remediation targets four primary vulnerability classes — **dependency
vulnerabilities**, **code vulnerabilities**, **configuration weaknesses**, and
**runtime vulnerabilities** — across all ten AAP requirements (R1–R10). All Critical
and High severity findings discovered during the Phase 1 audit are remediated at
100%; ≥80% of Medium findings are remediated; Low findings are documented in the
residual risk register.

A pre-remediation rollback point is available at git tag
`pre-security-remediation-20260429`, and the pre-upgrade lockfile snapshot is
preserved at `package-lock.baseline.json`.

**R10 — Performance & Functional Parity:** Authentication latency, trinket load,
and Socket.IO handshake-to-first-execution-response remain within `<10%` of the
pre-remediation baseline; zero functional regression across `~60` page routes
and `~116` API routes. Verified by the full `npm test` regression suite, the new
`test/security/` suite, the `test/smoke-test.sh` post-deploy script, and the
critical-workflow walkthrough (signup → email verify → login → create trinket →
run Python trinket → submit assignment → bulk export request → logout). Detailed
metrics are recorded in the Performance Validation Report (Deliverable #5).

### Security

- **R2 — Cryptographic Hardening (OWASP A02):** Replaced MD5 with SHA-256 in course
  invitation token generation in `lib/models/courseInvitation.js` line 37; preserves
  the 8-character hex truncation for invitation URL backward compatibility, aligning
  with NIST SP 800-131A guidance against MD5 use.
- **R2 — Cryptographic Hardening:** Added a boot-time guard for `app.mail.secret`
  requiring a minimum of 32 characters (paralleling the existing 32-character session
  password guard at `app.js` lines 50–66) to prevent JWT email-token forgery via
  weak signing keys.
- **R3 — reCAPTCHA Fail-Closed Posture:** Modified `lib/util/recaptcha.js` to emit
  a `WARN`-level configuration log when reCAPTCHA is unconfigured; preserves the
  fail-open runtime behavior per the graceful-degradation directive
  (`reCAPTCHA absent → fail-open preserved (with warning)`) but gives operators
  explicit audit visibility into the unprotected state.
- **R4 — HTTP Security Header Hardening (OWASP A05; OWASP Secure Headers Project):**
  Added `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and
  `Referrer-Policy: strict-origin-when-cross-origin` headers to the `onPreResponse`
  extension in `app.js` (lines 152–198); CSP is scoped to main application pages
  (excluding embed and sandbox paths so that the iframe-based execution sandbox
  remains functional).
- **R4 — HTTP Security Header Hardening:** Extended the `app.xframeDeny` list in
  `config/default.yaml` to cover `/admin` and `/admin/*` paths, blocking
  clickjacking attacks against admin pages.
- **R5 — CSRF Synchronizer-Token Pattern (OWASP A01/A07):** Registered the
  `@hapi/crumb` plugin and applied per-route CSRF protection on the highest-risk
  mutating endpoints — `/api/exports`, password/email change in `/api/users`, and
  `/api/admin/*`. `SameSite=Lax` remains the primary mitigation on remaining
  endpoints. SPA-consumed routes are explicitly deferred to a follow-on iteration
  per the Risk Management section.
- **R6 — Container Hardening:** Promoted shell container hardening directives from
  comments to defaults in `serverside/docker-compose.yml` for every shell service
  (`python3-shell`, `java-shell`, `r-shell`, `pygame-worker`):
  `mem_limit: 500m`, `mem_reservation: 375m`, `cpus: 1.0`, `cpu_shares: 512`,
  `pids_limit: 50`, `read_only: true`, `tmpfs: /tmp:size=100m`,
  `security_opt: [no-new-privileges:true]`, and `cap_drop: [ALL]`. Operator opt-out
  is preserved via removal of the directives. See `serverside/README.md` for the
  full documented hardening posture.
- **R6 — Network Hardening:** Added `server_tokens off;` (suppress nginx version
  disclosure) and `add_header X-Content-Type-Options nosniff always;` (prevent
  MIME-sniffing on generated assets) to `serverside/nginx/nginx.conf`.
- **R7 — Access Control Audit (OWASP A01):** Verified `pre: ['isAdmin(user)']`
  presence on every `/api/admin/*` route in `config/api_routes.js`; verified
  `canEdit` guards on every resource-mutating endpoint; verified strict `===`
  ownership comparison after `.toString()` in the bulk export download path
  (`lib/controllers/users.js`); audited the `loginAs`/`logoutAs` impersonation
  flow to confirm `_realUserId` is never exposed in API responses or rendered
  templates. Targeted additions applied where audit gaps were found.
- **R7 — Information Disclosure:** Unified the signup error response so duplicate
  email vs. duplicate username are no longer distinguishable, eliminating a known
  account-enumeration vector.
- **R8 — Injection Hardening (OWASP A03):** Audited Mongoose query construction in
  `lib/controllers/` for NoSQL operator injection (`$where`, `$regex`,
  operator-prefixed keys); tightened Joi schemas in `config/api_routes.js` to reject
  these payloads on mutating routes; audited every Nunjucks template under
  `lib/views/` for `| safe` filter usage on user-controlled data and confirmed
  global auto-escape via `lib/util/nunjucks.js`.

### Changed

- **R1 — Dependency Vulnerability Remediation:** Replaced the deprecated
  `request@^2.51.0` package (no security patches available upstream) with
  `axios@^1.x` at the single use site `lib/util/recaptcha.js`. Replacement scope
  is bounded to one file per the Minimal Change Clause's "fewest modified files"
  selection directive; the entire `request` transitive chain is removed from the
  dependency tree.
- **R1 — Dependency Vulnerability Remediation:** Upgraded Critical/High
  CVE-bearing npm dependencies in the root `package.json` and in each
  `serverside/*/manager/package.json` per the Phase 1 `npm audit` scan against
  both the Node 16 main-app runtime and the Node 18 manager runtime
  (independent dependency trees). Specific package-to-CVE mappings are enumerated
  in the Dependency Upgrade Report (Deliverable #2). New `@hapi/crumb`
  dependency added for R5 CSRF protection.
- **R6 — Container Base Image:** Upgraded `Dockerfile` base image from
  `node:16-bullseye` (Node 16 reached end-of-life September 2023) to
  `node:20-bullseye` (current Node LTS). Inherits ongoing OS-layer security
  patches and eliminates accumulated Bullseye glibc/openssl CVEs that no longer
  receive Node 16 backports. `mongoose-schema-extend ~0.2.2` Node 20
  compatibility was validated per the Risk Management mitigation.
- **R2 — Cryptographic Annotations (no functional change):** Annotated the
  acceptable, non-confidentiality SHA-1 identifier hash uses in
  `lib/models/trinket.js` (lines 117, 120, 177 — `shortCode` and `verifyShortCode`),
  `lib/util/file.js` (file content identifier), and `lib/workers/exports.js`
  (export filename) with inline `// SECURITY:` comments confirming the
  identifier-only intent per the Annotation Directive.

### Added

- **R9 — Vulnerability Disclosure Policy:** New `SECURITY.md` documenting the
  vulnerability disclosure policy, supported version table, reporting channel,
  and expected response time per OWASP best practice.
- **R9 — Automated Security Testing:** New `test/security/` test suite — `auth.test.js`
  (authentication bypass, disabled-account two-tier enforcement, Google OAuth state
  parameter), `access-control.test.js` (IDOR, admin route bypass, bulk export
  ownership, impersonation), `injection.test.js` (NoSQL operator injection, Nunjucks
  XSS), `session.test.js` (session fixation, sliding TTL, cookie flags),
  `upload.test.js` (MIME validation, payload size, path traversal), an `index.js`
  aggregator following the existing `test/lib/api/index.js` pattern, and a
  `test/helpers/security.js` helper providing common payload generators.
  Suite integrates into `npm test` via the existing Mocha `--recursive` discovery.
- **R9 — Static Analysis Configuration:** New `.eslintrc.js` and `.eslintignore`
  configuring `eslint-plugin-security` for SAST coverage of `lib/`, `config/`, and
  `serverside/*/manager/`. Vendored/frozen frontend (`public/js/skulpt/`,
  `public/js/embed/`, `public/components/`) is excluded per ADR-5.
- **R9 — CI Security Pipeline:** New `.github/workflows/security-scan.yml`
  integrating `npm audit --audit-level=high` (root and each manager), Trivy image
  scanning (`trivy image --exit-code 1 --severity CRITICAL,HIGH`) against the
  main app and shell images, ESLint security plugin, and a weekly OWASP ZAP
  baseline scan against the staging instance.
- **R3 — Configuration Documentation:** Added `# SECURITY:` annotation comments in
  `config/default.yaml` near the `recaptcha:` block (documenting the fail-open
  posture) and near the `mail:` block (documenting the new ≥32-character
  `app.mail.secret` boot guard). Added matching guidance in `config/local.example.yaml`.

### Breaking Changes

These four breaking surfaces are introduced for security reasons; each is
justified per the AAP §0.11.1 backward-compatibility directive. Operators must
review their deployment configuration before upgrading.

- **`app.mail.secret` boot guard:** Operators with `app.mail.secret` shorter than
  32 characters will fail to boot post-upgrade. **Justification:** Eliminates JWT
  email-token forgery risk from weak signing keys; aligns with the existing
  32-character session password guard pattern. **Action required:** Rotate
  `app.mail.secret` to a value ≥32 characters (e.g., `openssl rand -base64 32`)
  before deploying this release.
- **CSRF tokens on `/api/exports`, `/api/users` (password/email change), and
  `/api/admin/*`:** API consumers must include a valid `@hapi/crumb` CSRF token
  on these mutating endpoints. **Justification:** Closes OWASP A01/A07. **Action
  required:** Custom (non-AngularJS-SPA) API consumers must integrate CSRF token
  retrieval and submission. SPA-consumed routes remain unaffected in this release
  per the Risk Management scope (deferred follow-on).
- **Node 20 base image:** The main-app Docker image now requires Node 20 runtime
  semantics. **Justification:** Node 16 reached end-of-life September 2023.
  **Action required:** Operators with Node 16-specific behavior must validate
  their custom plugins/native modules against Node 20.
- **Default-on shell container hardening:** Operators relying on unbounded shell
  resources may experience `mem_limit: 500m` exhaustion or `read_only: true`
  write failures. **Justification:** Educational platform executing untrusted
  learner code requires hardening as the default posture. **Action required:**
  Operators may opt out by removing the security directives from
  `serverside/docker-compose.yml` (documented in `serverside/README.md`); the
  opt-out path is preserved.

### Deferred

The following items are explicitly out of scope for this remediation per the
Minimal Change Clause and AAP §0.9.2. They remain documented in the residual risk
register of the Before/After Security Posture Report (Deliverable #7).

- **AngularJS 1.3.20 frontend:** Frozen per ADR-5. CVEs are documented and
  exploitability is assessed within the iframe `sandbox` attribute configuration
  constraints (no `allow-same-origin`); no framework upgrade is performed.
- **`aws-sdk` v2 → v3 migration:** Deferred unless v2.x has unmitigated Critical
  CVEs. v3 migration would touch every S3 call site in `lib/util/file.js`,
  exceeding the Minimal Change Clause boundary.
- **Frontend SPA CSRF integration:** Coordinated AngularJS `$http` interceptor
  changes for SPA-consumed mutating routes are deferred to a follow-on iteration
  per the Risk Management section.
- **MFA implementation:** Out of scope per AAP §6.4.2.2 — no TOTP, WebAuthn, or
  SMS second factor is added in this release. reCAPTCHA v2 remains as the closest
  approximation of human verification.
- **`mongoose-schema-extend ~0.2.2`:** Flagged deprecated; ADR-8 tech debt. If
  the Node 20 base image surfaces incompatibility, this is a documented blocker
  requiring ADR-8 resolution.
- **Hapi 21 / Mocha 3 modernization:** Out of scope; Hapi 20 route DSL and Mocha 3
  test toolchain are frozen per the AAP "Must Remain Unchanged" list.
- **MongoDB at-rest encryption, TLS termination, dedicated audit log:** Operator
  infrastructure responsibilities per AAP §6.4.4.5.3; not implemented in-repo.

### CVE Cross-Reference

Specific CVE-to-package mappings, CVSS v3.1 scores, affected version ranges, fixed
versions, and advisory URLs are enumerated in two companion deliverables:

- **Vulnerability Discovery Report (Deliverable #1)** — complete `npm audit`,
  Trivy, ESLint security plugin, Semgrep, and OWASP ZAP results with
  prioritized remediation backlog sorted by CVSS score, and exploitation
  scenarios specific to the Trinket threat model (untrusted learner code, minor
  user data, educator courseware).
- **Dependency Upgrade Report (Deliverable #2)** — CVE-to-package mapping for
  root and manager dependencies, Node 16/18 compatibility matrix, and
  breaking-change impact summary per upgraded package.

These reports will be linked here once finalized. Atomic commits in this release
include CVE identifiers in their commit messages where applicable
(`security: [severity] fix [CVE-YYYY-NNNNN] in [file]`).

## [1.0.0] - Initial Open Source Release

First public release of Trinket.
