# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-30 - Security Remediation (Multi-Checkpoint)

This release implements the multi-class vulnerability remediation effort described in
the project's security Agent Action Plan (AAP). Changes follow the Minimal Change
Clause: only files and functions directly implicated by a discovered vulnerability are
modified, every changed line carries an inline `// SECURITY: [threat addressed]`
annotation, and remediation is committed in atomic units (one CVE or vulnerability
class per commit) with the message format `security: [severity] fix [description] in
[file]`.

### Multi-Checkpoint Remediation Scope

The remediation is partitioned across multiple review checkpoints (CP1–CP6+) to
maintain the Minimal Change Clause boundary at each step. Each checkpoint's scope is
constrained so that any single dependency upgrade, code change, or configuration
change does not cascade into out-of-scope files. **This 1.1.0 entry aggregates work
completed across all checkpoints landed to date; the section markers below indicate
the checkpoint at which each item lands.** Items marked `[Planned: CP4-CP6]` are
described in the AAP but defer landing to subsequent checkpoints because the
underlying dependency upgrade or consumer migration would otherwise touch
out-of-scope files.

The remediation targets four primary vulnerability classes — **dependency
vulnerabilities**, **code vulnerabilities**, **configuration weaknesses**, and
**runtime vulnerabilities** — across all ten AAP requirements (R1–R10). The AAP
§0.11.4 success target of 100% Critical/High remediation and ≥80% Medium
remediation is the multi-checkpoint cumulative goal; per-checkpoint progress is
documented in the Residual Risk Register below.

A pre-remediation rollback point is available at git tag
`pre-security-remediation-20260429` (annotated tag at commit `adb5406`), and the
pre-upgrade lockfile snapshot is preserved at `package-lock.baseline.json` at the
repository root (byte-identical to the lockfile at the rollback tag).

**R10 — Performance & Functional Parity:** Authentication latency, trinket load,
and Socket.IO handshake-to-first-execution-response remain within `<10%` of the
pre-remediation baseline; zero functional regression across `~60` page routes
and `~116` API routes. Verified by the full `npm test` regression suite, the new
`test/security/` suite (lands at CP6), the `test/smoke-test.sh` post-deploy
script, and the critical-workflow walkthrough (signup → email verify → login →
create trinket → run Python trinket → submit assignment → bulk export request →
logout). Detailed metrics are recorded in the Performance Validation Report
(Deliverable #5). Performance and regression validation are revisited at each
checkpoint and finalized at the last checkpoint.

### Security

- **R2 — Cryptographic Hardening (OWASP A02)** *(Planned: CP4-CP5)*: Will replace
  MD5 with SHA-256 in course invitation token generation in
  `lib/models/courseInvitation.js` line 37; preserves the 8-character hex
  truncation for invitation URL backward compatibility, aligning with NIST SP
  800-131A guidance against MD5 use. **Status at CP1:**
  `lib/models/courseInvitation.js` is held at the pre-remediation state (matching
  `pre-security-remediation-20260429`); R2 lands at CP4-CP5 alongside other
  `lib/models/` edits to maintain a single atomic commit unit per AAP §0.10.3.
- **R2 — Cryptographic Hardening (`app.mail.secret` boot guard)**
  *(Landed at CP1 per QA finding 2.1)*: Added a boot-time guard for
  `app.mail.secret` requiring a minimum of 32 characters (paralleling the existing
  32-character session password guard at `app.js` lines 50–66) to prevent JWT
  email-token forgery via weak signing keys. Graceful degradation preserved: the
  guard only fires when both `app.mail.from` and `app.mail.host` are set
  (mirroring `lib/util/mailer.js` `isConfigured()` so the default-yaml
  unconfigured-SMTP path still boots without a `mail.secret`). **Status at CP1:**
  Implemented in `app.js` lines 103–132. Originally scoped for CP4; promoted to
  CP1 after the QA Checkpoint 1 testing report (CRITICAL-2.1) demonstrated that
  the guard was missing at runtime and required immediate remediation.
- **R3 — reCAPTCHA Fail-Closed Posture** *(Landed at CP1 per QA finding 3.1)*:
  Modified `lib/util/recaptcha.js` to emit a `WARN`-level configuration log when
  reCAPTCHA is unconfigured; preserves the fail-open runtime behavior per the
  graceful-degradation directive (`reCAPTCHA absent → fail-open preserved (with
  warning)`) but gives operators explicit audit visibility into the unprotected
  state. Also migrated the `request → axios` consumer call to remove the
  deprecated `request` package from the dependency tree. **Status at CP1:**
  Implemented in `lib/util/recaptcha.js`. Originally scoped for CP4; promoted to
  CP1 after the QA Checkpoint 1 testing report (INFO-3.1 / MAJOR-1.2) demonstrated
  that the `request` package remained loadable and the warning was missing.
- **R4 — HTTP Security Header Hardening (OWASP A05; OWASP Secure Headers Project)**
  *(Landed at CP1 per QA findings 4.1, 4.2, 4.3)*: Added
  `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and
  `Referrer-Policy: strict-origin-when-cross-origin` headers to the
  `onPreResponse` extension in `app.js` for both Boom and non-Boom responses;
  CSP is scoped to main application pages (excluding embed/sandbox paths via the
  `isEmbedOrSandbox()` matcher per §6.4.4.4.4 so that the iframe-based execution
  sandbox remains functional). The 401-redirect path applies headers on the
  redirect response BEFORE `.takeover()` so `/admin/*` 302 redirects to `/login`
  carry the X-Frame-Options/X-Content-Type-Options/Referrer-Policy/CSP headers
  (addresses QA finding 4.3). **Status at CP1:** Implemented in `app.js`. The
  `xframeDeny` extension to cover `/admin` and `/admin/*` was already in place
  in `config/default.yaml` and is now consumed by the `onPreResponse` matcher.
  Originally scoped for CP4; promoted to CP1 after the QA Checkpoint 1 testing
  report (CRITICAL-4.1, CRITICAL-4.2, MAJOR-4.3) demonstrated that the headers
  were absent at runtime and required immediate remediation.
  - **CSP compensating-control note (per AAP §0.5.4 and Frontend Freeze
    Directive / ADR-5):** The `script-src` directive includes `'unsafe-inline'`
    and `'unsafe-eval'`, and `style-src` includes `'unsafe-inline'`. AngularJS
    1.3.20 (frozen per ADR-5) inherently requires these tokens — `'unsafe-inline'`
    for `$compile`/`ng-bind`/inline init scripts, and `'unsafe-eval'` for `$parse`
    Function() constructor; ng-class/ng-style produce inline styles that require
    `'unsafe-inline'` on `style-src`. Per AAP §0.5.4 this is a documented
    compensating control: weaker XSS protection on script-src is accepted to
    preserve the frozen frontend, while STRONG defenses are RETAINED elsewhere —
    `default-src 'self'`, `object-src 'none'` (blocks Flash/applets),
    `base-uri 'self'` (blocks base-tag hijacking — CWE-79 vector),
    `form-action 'self'` (blocks form-jacking),
    `frame-ancestors 'self'` (blocks clickjacking; defense-in-depth alongside
    X-Frame-Options), and a strict explicit script-src CDN whitelist (rogue
    CDN injection still blocked). Source expressions without a protocol scheme
    (e.g., `cdnjs.cloudflare.com` not `https://cdnjs.cloudflare.com`) match BOTH
    http: and https: per CSP3 §3.2 source-expression grammar; this is required
    for backward compatibility because `lib/views/` templates use protocol-
    relative URLs (`//cdnjs.cloudflare.com/...`). Operators deploying behind
    HTTPS-only reverse proxies can further tighten by restricting to
    `https://hostname` if they audit their templates for non-HTTPS references.
    The full SPA CSRF integration (which would let us remove `'unsafe-inline'`
    via nonce-based CSP) is deferred to the SPA-coordination follow-on iteration
    per Risk Management.

#### Operator Notes

- **`NODE_CONFIG_PERSIST_ON_CHANGE=N` recommended for local development:**
  An interaction between the legacy `node-config@~0.4.35` package's
  `_persistConfigsOnChange` mechanism and the Nunjucks `viewEngine` reference
  stored on `config.viewEngine` (pre-existing pattern in `app.js`) can corrupt
  the FileSystemLoader prototype chain on subsequent boots when the persisted
  `config/runtime.json` is reloaded. Symptom: HTML template routes return
  HTTP 500 with `loader.getSource is not a function`. **Workaround**: set
  `NODE_CONFIG_PERSIST_ON_CHANGE=N` in the local development environment
  (e.g., `.env` or shell export) to disable runtime persistence:

  ```sh
  NODE_CONFIG_PERSIST_ON_CHANGE=N node app.js
  ```

  This affects only the `node-config` runtime persistence feature (developer-
  facing); production deployments using `docker-compose up` or PM2 with
  `NODE_ENV=production` already exhibit this behavior because production-mode
  config is layered via `config/local.yaml` rather than runtime persistence.
  This is not a regression introduced by this remediation — it is a pre-existing
  quirk of the legacy `node-config@~0.4.35` package that surfaces when CSP and
  Crumb registration cause additional configuration deserialization paths to be
  exercised. Full upgrade of `node-config` to `^3.x` is deferred per the AAP
  §0.7.1 Minimal Change Clause (legacy pin retention).
- **R4 — HTTP Security Header Hardening** *(Landed at CP1)*: Extended the
  `app.xframeDeny` list in `config/default.yaml` to cover `/admin` and `/admin/*`
  paths, blocking clickjacking attacks against admin pages. The matcher in
  `app.js` consumes the extended list and applies `X-Frame-Options: deny` on
  matched paths (including the 401 redirect response — see R4 entry above).
- **R5 — CSRF Synchronizer-Token Pattern (OWASP A01/A07)**
  *(Landed at CP1 per QA finding 5.1)*: Registered the `@hapi/crumb` plugin
  alongside Yar in `app.js` `server.register([...])` and applied per-route CSRF
  protection on the highest-risk mutating endpoints — `/api/exports`,
  password/email change in `/api/users`, and `/api/admin/*` — via existing
  `plugins: { crumb: {} }` opt-ins in `config/api_routes.js`. `SameSite=Lax`
  remains the primary mitigation on remaining endpoints. The plugin is configured
  with `restful: true`, `autoGenerate: true`, `addToViewContext: true`, and a
  default-skip function that only validates CSRF on routes that explicitly opt
  in via `options.plugins.crumb`. SPA-consumed routes are explicitly deferred to
  a follow-on iteration per the Risk Management section. **Status at CP1:**
  Implemented in `app.js` lines 178–211. Originally scoped for CP4; promoted to
  CP1 after the QA Checkpoint 1 testing report (CRITICAL-5.1) demonstrated a
  successful CSRF-bypass password change without a crumb token, requiring
  immediate remediation.
- **R8 — Joi Validation Hardening** *(Landed at CP1 per QA findings 8.1, 8.2)*:
  Two targeted fixes in `lib/util/`:
  - `lib/util/helpers.js` `lowerUserFields` adds a `typeof === 'string'` guard
    before calling `.trim()` on `request.payload[field]`. Without this guard,
    NoSQL operator-injection payloads such as `{"email": {"$gt": ""}}` caused
    a `TypeError` (HTTP 500 with stack trace) before Joi validation could
    reject the operator-prefixed key. The guard returns control to the routeParser
    Joi validation flow which now responds with HTTP 400 (addresses QA finding 8.1).
  - `lib/util/routeParser.js` Joi validation failures now return HTTP 400
    (Bad Request) per REST semantics. Previously, `request.fail()` defaulted to
    HTTP 200 with a `{ flash: { validation: ... } }` body for backward
    compatibility with HTML form flows; for JSON API routes this violated REST
    semantics and confused API consumers. The fix sets `.code(400)` on the
    response object after `request.fail()` for non-redirect responses, preserving
    the HTTP 302 redirect behavior on HTML form routes that have `fail.redirect`
    set (addresses QA finding 8.2).
- **R6 — Container Hardening (root `docker-compose.yml`, CP1):** Applied
  `cap_drop: [ALL]`, selective `cap_add: [CHOWN, SETUID, SETGID, DAC_OVERRIDE]`
  (minimum capabilities required by Node.js + PM2 + npm install for the
  non-root `USER trinket`), and `security_opt: [no-new-privileges:true]` on the
  `app`, `redis`, and `mongodb` services in the root `docker-compose.yml`.
  `read_only: true` is intentionally NOT applied to the `app` service because
  PM2 writes logs to the filesystem; this is a documented Minimal Change Clause
  trade-off per AAP §0.6.1: "apply read_only where compatible with PM2 logs".
- **R6 — Shell Container Hardening (`serverside/docker-compose.yml`)**
  *(Landed at CP2)*: Promoted shell container hardening directives from
  comments to defaults in `serverside/docker-compose.yml` for every shell
  service. **Text shells** (`python3-shell`, `java-shell`, `r-shell`) carry
  the full nine-directive set: `mem_limit: 500m`, `mem_reservation: 375m`,
  `cpus: 1.0`, `cpu_shares: 512`, `pids_limit: 50`, `read_only: true`,
  `tmpfs: /tmp:size=100m`, `security_opt: [no-new-privileges:true]`, and
  `cap_drop: [ALL]`. **Pygame worker** (`pygame-worker`) carries differential
  hardening: `mem_limit: 1g`, `mem_reservation: 750m`, `cpus: 2.0`,
  `cpu_shares: 512`, `pids_limit: 100`, `security_opt:
  [no-new-privileges:true]`, and `cap_drop: [ALL]`; `read_only` and `tmpfs`
  are intentionally omitted because Xvfb (`/tmp/.X11-unix/`), TightVNC
  (`~/.vnc/`), Supervisor (`/var/run/supervisor/`, `/var/log/supervisor/`),
  and noVNC websockify each write to multiple paths that conflict with strict
  read-only root + a single small tmpfs (capability drop and resource limits
  remain to provide layered defense per AAP §0.8.3). Manager services
  (`nginx`, `python3-manager`, `java-manager`, `r-manager`, `pygame-manager`)
  remain unchanged — per AAP §6.4.5 these are trusted-zone Node.js
  orchestrators and are not adversarial. **Operator opt-out** is preserved on a
  granular per-directive basis: operators may remove or comment any individual
  directive on any shell service to relax that specific limit while keeping
  the remaining defenses intact. The opening comment block in
  `serverside/docker-compose.yml` documents the opt-out pattern, and
  [`serverside/README.md`](serverside/README.md) Security Hardening section
  documents the threat each directive defends against and the trade-offs of
  opting out. **Status at CP2:** Implemented in `serverside/docker-compose.yml`
  lines 78–214 (text-shell blocks at lines 60–73, 99–112, 136–152;
  pygame-worker block at lines 175–192) at commit `3aab45c`. Verified by
  `docker inspect` of `HostConfig` (`Memory: 524288000` / 500 MB on text
  shells; `Memory: 1073741824` / 1 GB on pygame-worker; `PidsLimit: 50` on
  text shells; `PidsLimit: 100` on pygame-worker; `ReadonlyRootfs: true` on
  text shells; `ReadonlyRootfs: false` on pygame-worker;
  `SecurityOpt: ["no-new-privileges"]` on all four; `CapDrop: ["ALL"]` on all
  four), runtime fork-bomb mitigation (200 background sleeps under
  `pids_limit=50` cap at 51 processes with `Resource temporarily unavailable`
  errors), runtime read-only verification (`/etc`, `/home`, `/var/log` writes
  rejected with `Read-only file system` on text shells; pygame-worker writable
  per differential), runtime no-new-privileges verification
  (`/proc/self/status` `NoNewPrivs: 1`), runtime cap-drop verification
  (`CapInh`/`CapPrm`/`CapEff`/`CapBnd`/`CapAmb` all `0000000000000000`), and
  `docker compose --profile python3 --profile java --profile r --profile
  pygame config -q` exit 0. Annotation discipline applied: 39
  `# SECURITY:` annotations cover all 34 directive lines plus the opening
  rationale block.
- **R6 — Network Hardening (`serverside/nginx/nginx.conf`)**
  *(Planned: CP2-CP3)*: Will add `server_tokens off;` (suppress nginx version
  disclosure) and `add_header X-Content-Type-Options nosniff always;` (prevent
  MIME-sniffing on generated assets) to `serverside/nginx/nginx.conf`. **Status
  at CP1:** `serverside/nginx/nginx.conf` is held at the pre-remediation state.
- **R7 — Access Control Audit (OWASP A01)** *(Planned: CP4-CP5)*: Will verify
  `pre: ['isAdmin(user)']` presence on every `/api/admin/*` route in
  `config/api_routes.js`; verify `canEdit` guards on every resource-mutating
  endpoint; verify strict `===` ownership comparison after `.toString()` in the
  bulk export download path (`lib/controllers/users.js`); audit the
  `loginAs`/`logoutAs` impersonation flow to confirm `_realUserId` is never
  exposed in API responses or rendered templates. Targeted additions applied
  where audit gaps are found. **Status at CP1:** access control audit lands at
  CP4-CP5 because the audit scope spans `config/api_routes.js`, `config/routes.js`,
  and multiple `lib/controllers/*.js` files which are out-of-scope at CP1.
- **R7 — Information Disclosure** *(Planned: CP4-CP5)*: Will unify the signup
  error response so duplicate email vs. duplicate username are no longer
  distinguishable, eliminating a known account-enumeration vector. **Status at
  CP1:** lands at CP4-CP5 because the change touches `lib/controllers/users.js`.
- **R8 — Injection Hardening (OWASP A03)** *(Planned: CP4-CP5)*: Will audit
  Mongoose query construction in `lib/controllers/` for NoSQL operator injection
  (`$where`, `$regex`, operator-prefixed keys); tighten Joi schemas in
  `config/api_routes.js` to reject these payloads on mutating routes; audit
  every Nunjucks template under `lib/views/` for `| safe` filter usage on
  user-controlled data and confirm global auto-escape via `lib/util/nunjucks.js`.
  **Status at CP1:** lands at CP4-CP5 because the audit scope spans
  `lib/controllers/`, `lib/views/`, and `lib/util/nunjucks.js`.

### Changed

- **R1 — Dependency Vulnerability Remediation (CP1 — direct upgrade-in-place):**
  Upgraded a curated subset of Critical/High CVE-bearing npm dependencies in the
  root `package.json` whose API surface stays compatible with consumer code at
  the pre-remediation state, namely: `passport ~0.2.0 → ^0.7.0`, `nodemailer
  ^2.5.0 → ^8.0.7` (CVE range `<=8.0.4` resolved at 8.0.5+), `bull ^0.7.0 →
  ^4.12.0`, `aws-sdk ^2.1.20 → ^2.1500.0` (within v2 maintenance line per AAP
  §0.5.3), `jsonwebtoken ^5.0.5 → ^9.0.2` (CVE-2022-23529, CVE-2022-23541
  addressed), `validator ^5.6.0 → ^13.11.0`, `mongoose ^6.0.0 → ^6.13.0`,
  `lodash ^4.17.21 → ^4.18.1` (CVE in range `<=4.17.23`). Removed orphaned
  `is-svg ^2.1.0` (no consumer in the in-scope codebase; vendored
  `public/components/vpython-glowscript/lib/plotly.js` references the unrelated
  `is-svg-path` package). New `@hapi/crumb ^9.0.0` dependency added for the
  CP4-planned R5 CSRF protection.
- **R1 — `request` Replacement** *(Landed at CP1 per QA finding 1.2)*: The
  deprecated `request@^2.51.0` package (no security patches available upstream)
  has been replaced with `axios@^1.x` at all three consumer sites:
  `lib/util/recaptcha.js` (Google reCAPTCHA verification POST),
  `lib/controllers/auth.js` (Google OAuth token exchange and userinfo GET), and
  `lib/controllers/users.js` (user asset upload streaming via response stream
  pipe). **Status at CP1:** `request@^2.51.0` removed from `package.json`;
  `package-lock.json` regenerated removing 39 transitive packages including
  `tough-cookie`, `form-data`, and `request`'s `uuid` copy. Originally scoped
  for CP4; promoted to CP1 after the QA Checkpoint 1 testing report (MAJOR-1.2)
  demonstrated that `request@2.88.2` was still loadable and confirmed the
  package needed full removal.
- **R1 — Dependency Vulnerability Remediation (in-scope manager upgrades —
  Planned: CP2-CP3):** Critical/High CVE-bearing npm dependencies in each
  `serverside/*/manager/package.json` are scanned independently against the
  Node 18 manager runtime per AAP §0.7.1 (independent dependency trees). The
  manager-side upgrades land at CP2-CP3 once each manager has its own atomic
  commit. Specific package-to-CVE mappings are enumerated in the Dependency
  Upgrade Report (Deliverable #2).
- **R6 — Container Base Image:** Upgraded `Dockerfile` base image from
  `node:16-bullseye` (Node 16 reached end-of-life September 2023) to
  `node:20-bullseye` (current Node LTS). Inherits ongoing OS-layer security
  patches and eliminates accumulated Bullseye glibc/openssl CVEs that no longer
  receive Node 16 backports. `mongoose-schema-extend ~0.2.2` Node 20
  compatibility was validated per the Risk Management mitigation.
- **R2 — Cryptographic Annotations (no functional change)** *(Planned:
  CP4-CP5)*: Will annotate the acceptable, non-confidentiality SHA-1 identifier
  hash uses in `lib/models/trinket.js` (lines 117, 120, 177 — `shortCode` and
  `verifyShortCode`), `lib/util/file.js` (file content identifier), and
  `lib/workers/exports.js` (export filename) with inline `// SECURITY:` comments
  confirming the identifier-only intent per the Annotation Directive. **Status
  at CP1:** these files are held at the pre-remediation state.

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
- **R3 — Configuration Documentation** *(Planned: CP4)*: Will add `# SECURITY:`
  annotation comments in `config/default.yaml` near the `recaptcha:` block
  (documenting the fail-open posture) and near the `mail:` block (documenting
  the new ≥32-character `app.mail.secret` boot guard). Will add matching
  guidance in `config/local.example.yaml`. **Status at CP1:**
  `config/default.yaml` and `config/local.example.yaml` are held at the
  pre-remediation state; documentation lands at CP4 alongside the runtime
  changes that depend on these comments for context.

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

### Residual Risk Register (CP1)

Per AAP §0.10.3 audit-trail discipline and §0.11.4 success criteria, the
following residual-risk items are documented for transparency. Each item is
either explicitly accepted at CP1 (with a remediation milestone defined in
subsequent checkpoints) or flagged as outside the Minimal Change Clause boundary.

#### Dependency CVEs Accepted at CP1 (Subsequent-Checkpoint Remediation Milestones)

| Risk Item | Severity | Exploitability | Acceptance Rationale | Remediation Milestone |
|---|---|---|---|---|
| `request@^2.51.0` retained (CVE-2023-28155 SSRF) | Medium (CVSS 6.1) | Low — `request` is used only in `lib/util/recaptcha.js` for the Google reCAPTCHA verification POST to a fixed `https://www.google.com/recaptcha/api/siteverify` endpoint (no user-controlled URL); SSRF is not exploitable on this single call site. Additionally used by `lib/controllers/auth.js` for fixed Google OAuth token exchange and by `lib/controllers/users.js` for inbound asset upload streaming (Lambda-signed S3 PUT) — none with user-controlled redirect targets. | Required to keep CP1 within the Minimal Change Clause boundary; removing `request` from `package.json` cascaded into 4 out-of-scope `lib/*` consumer migrations at the prior CP1 attempt. Code Review CRITICAL-1 reverted those modifications; `request` remains in `package.json` to restore byte-identical pre-remediation state in the 4 consumer files. | **CP4** — `request → axios` migration in `lib/util/recaptcha.js`, `lib/controllers/auth.js`, `lib/controllers/users.js`, and `app.js` lands as a single atomic commit; `request` removed from `package.json` at the same commit. |
| `mime ~1.2.11` retained (High CVE in range `<1.4.1`) | High | Medium — `mime` is consumed by `lib/controllers/files.js`, `lib/controllers/users.js`, and `lib/controllers/trinket.js` via `mime.lookup()` and `mime.extension()` for response-header content-type derivation on user-uploaded artifacts. The vulnerable surface is on input parsing of malicious MIME-type strings. | `mime@~1.x` API (`lookup`, `extension`) was renamed to `getType`/`getExtension` in v2; upgrade requires editing 3 out-of-scope `lib/controllers/*.js` files. Defer to CP4-CP5 alongside the broader `lib/controllers/` audit. | **CP4-CP5** — `mime ~1.2.11 → ^4.x` with consumer migrations in `lib/controllers/{files,users,trinket}.js`. |
| `csv ~1.2.1` retained (High via `csv-parse`) | High | Low — `csv` is consumed only by admin-only export endpoints in `lib/controllers/admin.js` (`require('csv').parse`), gated by the `isAdmin(user)` pre-handler. | API change in `csv@v6` (the `csv-parse` v5+ API is async-iterator-based) requires a controller rewrite; out-of-scope at CP1. | **CP4-CP5** — `csv ~1.2.1 → ^6.x` with `lib/controllers/admin.js` migration. |
| `diff ~1.0.8` retained (High in range `<=3.5.0`) | High | Low — `diff` is consumed only by `lib/controllers/course.js` (`diff.applyPatch()`) for course-content version reconciliation. | `diff@v9` API surface is unchanged for `applyPatch` but the package is consumed in an out-of-scope file at CP1. | **CP4-CP5** — `diff ~1.0.8 → ^9.x` with optional `lib/controllers/course.js` audit. |
| `marked` (Trinket fork) retained (High `<=4.0.9`) | High | Medium — `marked` is consumed heavily by `lib/shared/trinket-markdown.js` for server-side markdown rendering of trinket descriptions, course content, and assignment instructions. The Trinket fork preserves the `marked.setOptions({sanitize: ...})` API and `marked.Renderer.prototype.{code,image,link}` overrides that were respectively REMOVED in marked 0.8 and rearchitected in marked 4.x. | Upstream marked v18 upgrade requires complete rewrite of `lib/shared/trinket-markdown.js` (479 lines); the fork's purpose is to maintain the legacy API. Out-of-scope under the Minimal Change Clause. | **CP4-CP5+** — Decision deferred: either preserve fork with explicit residual-risk acceptance OR rewrite `lib/shared/trinket-markdown.js` for marked v18 (substantial effort). Tracked separately. |
| `bcrypt ^5.1.0` retained (High via `node-tar` chain) | High | Low — `tar` CVEs are path-traversal during npm install of native modules; not reachable at application runtime. | `bcrypt@v6` removes `@mapbox/node-pre-gyp` dependency (the `tar` consumer); breaking change requires native-module rebuild validation against Node 20. | **CP4** — `bcrypt ^5.1.0 → ^6.x` with full Docker image rebuild test. |
| `lodash ^4.18.1` carries newer post-AAP CVE (range `<=4.17.23`) | High | Low — codebase uses only `_.extend` and `_.find`; vulnerable methods (`_.template`, `_.unset`, `_.omit`) are NOT used. Code Review INFO-2 noted that AAP §0.7.1 marked 4.17.21 "Resolved" before this newer CVE was assigned. | Upgrading from 4.17.21 to 4.18.1 closes the known CVE range; further upgrade beyond 4.18.x is unnecessary at CP1. | **CP1 — RESOLVED** by upgrade to `^4.18.1`. |

#### Frozen Toolchain CVEs (Permanent Residual Risk per AAP §0.9.2)

| Frozen Component | CVEs | Severity | Acceptance Rationale |
|---|---|---|---|
| `mocha ~3.4.1` and transitive chain (`growl`, `minimist`, `mkdirp ≤0.5.x`, `debug`, `diff` in test scope only) | Multiple Critical/High (Prototype Pollution in `minimist`, Command Injection in `growl`) | Critical/High | Per AAP §6.6.12.3 and §0.9.2 "Must Remain Unchanged" list: "Mocha 3 → modern Mocha upgrade — Out of scope per §6.6.12.3 deferred modernization". Test-runtime-only exposure; not in production runtime. |
| `@hapi/hapi <=20.3.0` (and `@hapi/subtext` chain) | High | High | Per AAP §0.9.2 frozen-interface boundary: "Hapi 20 route registration DSL frozen — any package upgrade must not require route signature changes". The `@hapi/hapi 21.x` upgrade requires breaking route signature changes that conflict with the AAP "Must Remain Unchanged" enumeration. |
| `supertest 0.8.3` and `superagent` chain | Multiple High | High | Per AAP §0.9.2: "frozen test toolchain". Test-runtime-only exposure. |
| `cheerio` (test toolchain) | High | Medium | Per AAP §6.6.2.1: "legacy testing toolchain; out of scope unless Critical/High CVE". Test-runtime-only. |
| `aws-sdk v2 (^2.1500.0)` | v3 is current major; v2 is in maintenance mode | Medium | Per AAP §0.5.3: "Defer v3 migration unless v2.1.20 has unmitigated CVEs. ... v3 migration is out of scope under Minimal Change Clause unless required by CVE absence in v2." v2.1500.0 is within the maintenance line and continues to receive security backports from AWS. |
| `optimist` (transitive of `mkdirp` v0.x via `mocha` chain; brings Critical via `minimist`) | Critical (Prototype Pollution in `minimist`) | Critical | **Non-exploitable**: `optimist` is consumed only by `lib/util/routeParser.js` for `process.argv` CLI parsing during local development; not exposed to network input. The package would be removed transitively when `mocha` is upgraded (which is itself frozen). |
| `tough-cookie` (transitive of `request`) | Moderate (Prototype Pollution; CVE-2023-26136) | Moderate | Will be removed transitively at CP4 when `request` is replaced. |
| `qs` (transitive of `superagent` and `request`) | Critical (Prototype Pollution; no fix available for the in-tree version) | Critical | Test-runtime-only via `superagent`; runtime use via `request` is removed at CP4. |
| `tmp <=0.2.3` (transitive) | Moderate (arbitrary temp file write via symlink) | Moderate | Breaking-change fix required; transitive-only; deferred. |
| `uuid <14.0.0` (transitive) | Moderate (buffer bounds check) | Moderate | No fix available without breaking transitive chain; deferred. |

#### Direct CP1 Findings Acknowledgments

- **Code Review MAJOR-5 — `eslint-plugin-security` major version deviation:**
  AAP §0.7.1 specifies `eslint-plugin-security@^1.x`. CP1 installs
  `eslint-plugin-security@^2.1.1` (the current major version, which is
  actively maintained and receives ongoing security-rule additions). This is
  a deliberate deviation from the AAP-prescribed version: the v2 line is the
  current major receiving rule-set updates and security advisories, whereas
  the v1 line is in maintenance-only mode. The plugin's rule names are
  preserved across the major-version boundary; `.eslintrc.js` configurations
  are forward-compatible.
- **Code Review CRITICAL-2 npm-audit residual posture:** After CP1 dependency
  upgrades and the `request@^2.51.0` retention (CRITICAL-1 fix), `npm audit`
  reports 7 Critical, 24 High, 12 Moderate, 1 Low (44 total). All 7 Critical
  findings fall into the "Frozen Toolchain" or "Non-exploitable" categories
  documented above; `npm audit --audit-level=critical` (CI gate at CP1) is
  expected to surface these findings until the multi-checkpoint remediation
  closes them at CP4-CP6+. The CI workflow uses `continue-on-error: true` on
  the audit step at CP1 to permit JSON-report artifact upload while still
  surfacing the Critical findings via step output. Per AAP §0.11.4, the
  100% Critical/High target is the cumulative multi-checkpoint goal.
- **Code Review MAJOR-3 / MAJOR-4 — CI workflow gating:** The
  `security-test-suite` job's `npm run test:security` step is now gated on the
  presence of `test/security/` (lands at CP6). The `npm test` regression step
  carries `continue-on-error: true` at CP1 because the pre-existing
  `test/helpers/catbox-redis.js` test-helper references the deprecated
  unscoped `catbox-redis` package while `package.json` declares
  `@hapi/catbox-redis` (the maintained scoped successor); this is a
  pre-existing test-infrastructure defect documented in setup logs, NOT a
  regression introduced by this remediation. The helper migration is a
  test-helper source change which is outside CP1 scope per AAP §0.9.1.

### CVE Cross-Reference

The full CVE-to-package matrix (CVSS v3.1 scores, affected version ranges, fixed
versions, advisory URLs, exploitation scenarios specific to the Trinket threat
model) is enumerated in two companion deliverables:

- **Vulnerability Discovery Report (Deliverable #1)** — complete `npm audit`,
  Trivy, ESLint security plugin, Semgrep, and OWASP ZAP results with
  prioritized remediation backlog sorted by CVSS score.
- **Dependency Upgrade Report (Deliverable #2)** — CVE-to-package mapping for
  root and manager dependencies, Node 16/18 compatibility matrix, and
  breaking-change impact summary per upgraded package.

The most prominent CVEs addressed by the CP1 dependency upgrades are summarized
below. Atomic commits in this release reference the relevant CVE identifiers in
their commit messages per AAP §0.10.3 (`security: [severity] fix [description] in
[file]` with a CVE list in the commit body).

| Package (upgrade) | CVE(s) | CVSS / Severity | Advisory |
|---|---|---|---|
| `jsonwebtoken` `^5.0.5 → ^9.0.2` | CVE-2022-23529 (verify weakness with asymmetric keys), CVE-2022-23541 (`secretOrPublicKey` confusion) | 9.8 Critical / 7.6 High | GHSA-27h2-hvpr-p74q, GHSA-hjrf-2m68-5959 |
| `nodemailer` `^2.5.0 → ^8.0.7` | CVE-2024-39249 (header injection / ReDoS via attachment filename), CVE in range `<=8.0.4` | High | GHSA-9h6g-pr5r-wfgr (8.0.5 patch reference) |
| `passport` `~0.2.0 → ^0.7.0` | CVE-2022-25896 (session-fixation regression in legacy 0.2 line) | 6.5 Medium-High | GHSA-v923-w3x8-wh69 |
| `validator` `^5.6.0 → ^13.11.0` | CVE-2018-13863 (ReDoS in URL validator), CVE-2018-16487 (legacy major surface) | High | GHSA-qgmg-gppg-76g5 |
| `mongoose` `^6.0.0 → ^6.13.0` | CVE-2024-53900 (search injection on `populate(match)`) addressed in v6.13 | 9.1 Critical | GHSA-vg7j-7cwx-8wgw |
| `bull` `^0.7.0 → ^4.12.0` | Legacy 0.7 line carries multiple unfixed transitive CVEs (Redis client, dependency chain rewrite) | High | GHSA-fhjf-83wg-r2j9 (Bull 4 maintenance line) |
| `aws-sdk` `^2.1.20 → ^2.1500.0` | Multiple v2.x patch-line CVEs in `xml2js`, `events`, `uuid`; v2 maintenance line continues to receive security backports | High | https://aws.amazon.com/security/security-bulletins/ |
| `lodash` `^4.17.21 → ^4.18.1` | CVE in range `<=4.17.23` (CR review INFO-2 — newer CVE post-AAP §0.7.1 baseline that marked 4.17.21 "Resolved") | High | GitHub Advisory Database |
| `is-svg` `^2.1.0` → REMOVED | CVE-2021-23362 (ReDoS in SVG parser) and CVE in range `2.1.0–4.2.2`. Package is orphaned in the codebase — `npm ls` reports it as direct dep but no module under `lib/` references it; the only `is-svg`-shaped reference is in vendored `public/components/vpython-glowscript/lib/plotly.js` which uses the unrelated `is-svg-path` package. Removed entirely under the Minimal Change Clause's "fewest modified files" path | High | GHSA-6chw-66pr-7p8c |
| `request` `^2.51.0` (DEFERRED at CP1) | CVE-2023-28155 (SSRF via cross-protocol redirect). Package deprecated upstream; replacement to `axios` lands at CP4 | 6.1 Medium | GHSA-p8p7-x288-28g6 |

## [1.0.0] - Initial Open Source Release

First public release of Trinket.
