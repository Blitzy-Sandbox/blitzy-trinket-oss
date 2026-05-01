# 0. Agent Action Plan

## 0.1 Intent Clarification

### 0.1.1 Core Security Objective

Based on the security concern described, the Blitzy platform understands that the security vulnerabilities to resolve span a discovery-first, multi-class remediation effort across the **Trinket OSS** codebase (`trinketapp/trinket-oss`), which is a Node.js Hapi monolith executing untrusted learner code on behalf of authenticated learners while hosting educator-authored courseware containing data for minors. The remediation must achieve 100% Critical and High severity remediation, ≥80% Medium severity remediation, automated security testing, and zero functional regression.

- **Vulnerability category:** **Multiple vulnerabilities** spanning four primary classes:

  - **Dependency vulnerabilities** — Legacy pinned npm packages with known CVEs (`request: ^2.51.0` deprecated, `passport: ~0.2`, `nodemailer: ^2.5.0`, `bull: ^0.7.0`, `aws-sdk: ^2.1.20`, `config: ~0.4.35`, `mime: ~1.2.11`, `mkdirp: ~0.3.5`, `q: ~1.0.0`), plus vendored frontend assets (jQuery 2.2.4, Ace Editor 1.2.6.1rc2)
  - **Code vulnerabilities** — Cryptographic weaknesses (MD5 in course invitations per `lib/models/courseInvitation.js` line 37 using `crypto.createHash("md5").update(email + course.id)`), reCAPTCHA fail-open default in `lib/util/recaptcha.js`, missing CSRF tokens, missing security headers (CSP, X-Content-Type-Options, Referrer-Policy)
  - **Configuration weaknesses** — Default-commented Docker hardening directives in `serverside/docker-compose.yml`, EOL Node 16 base image (`Dockerfile` line 2 `FROM node:16-bullseye`), missing `server_tokens off` in nginx
  - **Runtime vulnerabilities** — Potential MongoDB operator injection via Mongoose query construction, Nunjucks template XSS, IDOR on resource endpoints, authentication/session-fixation regressions

- **Severity level:** **Critical to High** (mixed). Critical/High items include EOL Node 16 base image, deprecated `request` package, MD5 invitation tokens (cryptographic weakness), reCAPTCHA fail-open silent bypass, default-disabled shell container hardening for untrusted code execution, and any RCE/auth-bypass discovered during scanning. Medium items include missing CSP/X-Content-Type-Options/Referrer-Policy headers, missing rate limiting on `/login`/`/signup`/`/api/users/reset`, signup error message enumeration disclosure, and SHA-1 identifier hashes (annotation only).

- **Security requirements (with enhanced clarity):**

  - **R1 — Dependency Vulnerability Remediation:** Replace or upgrade every npm dependency in the root `package.json` and each `serverside/*/manager/package.json` flagged Critical or High by `npm audit`, with separate compatibility matrices for the **Node 16 main app** runtime and the **Node 18 manager** runtime
  - **R2 — Cryptographic Hardening:** Replace MD5 in `lib/models/courseInvitation.js` with `crypto.createHash('sha256')`; annotate intentional non-cryptographic SHA-1 identifier hashes in `lib/models/trinket.js`, `lib/util/file.js`, and `lib/workers/exports.js`; add boot-time entropy guard for `app.mail.secret` paralleling the existing 32-character session password guard at `app.js` lines 50–66
  - **R3 — reCAPTCHA Fail-Closed Posture:** Modify `lib/util/recaptcha.js` so the `!config.app.recaptcha` branch logs a configuration warning at boot rather than silently returning `{success: true}`; update `config/default.yaml` to document the implication
  - **R4 — HTTP Security Header Hardening:** Add `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: strict-origin-when-cross-origin` to the `onPreResponse` extension in `app.js` (lines 152–198); extend `xframeDeny` to cover `/admin/*` paths
  - **R5 — CSRF Token Pattern:** Add `@hapi/crumb` synchronizer-token CSRF protection to highest-risk mutating endpoints (`/api/exports`, password/email change in `/api/users`, `/api/admin/*`); preserve `SameSite=Lax` as primary mitigation on remaining endpoints
  - **R6 — Container & Network Hardening:** Upgrade `Dockerfile` base image from `node:16-bullseye` (EOL September 2023) to `node:20-bullseye` LTS; promote shell container hardening directives from comments to defaults in `serverside/docker-compose.yml`; add nginx `X-Content-Type-Options: nosniff` and `server_tokens off` to `serverside/nginx/nginx.conf`
  - **R7 — Access Control Audit:** Verify `pre: ['isAdmin(user)']` on every `/api/admin/*` route in `config/api_routes.js`; verify `canEdit` guards every resource-mutating endpoint; verify bulk export download enforces strict `===` ownership comparison after `.toString()`
  - **R8 — Injection Hardening:** Audit Mongoose query construction in `lib/controllers/` for NoSQL operator injection (`$where`, `$regex`, operator-prefixed keys); verify Joi schemas reject these in mutating routes; audit Nunjucks templates in `lib/views/` for `| safe` filter usage on user-controlled data
  - **R9 — Automated Security Testing:** Create `test/security/` suite with `auth.test.js`, `access-control.test.js`, `injection.test.js`, `session.test.js`, `upload.test.js`; integrate `npm audit --audit-level=high`, `trivy image`, and ESLint security plugin into CI pipeline
  - **R10 — Performance & Functional Parity:** Authentication latency, trinket load, and [Socket.IO](http://Socket.IO) handshake to first execution response must remain within `<10%` of baseline; zero regression across `~60` page routes and `~116` API routes

- **Implicit security requirements surfaced from the prompt:**

  - **Backward compatibility** of all Hapi route contracts (\~60 page routes + \~116 API routes), Mongoose model interfaces and plugin APIs (`roles`, `slug`, `timestamps`, `ownable`, `paginate`, `orderedList`, `isChanged`), and [Socket.IO](http://Socket.IO) event protocol consumed by deployed embed iframes
  - **Zero downtime** — atomic per-CVE commits with `package-lock.baseline.json` snapshot enable instant rollback
  - **AngularJS 1.3.20 freeze** — frontend framework must not be migrated despite EOL status; CVEs are documented and exploitability assessed within `sandbox` attribute configuration constraints (no `allow-same-origin`)
  - **Operator opt-out preservation** — shell container hardening directives must allow operator override per the educational platform's flexibility requirement
  - **Audit trail discipline** — every changed line must carry an inline `// SECURITY: [threat addressed]` annotation
  - **Compliance posture** — preserve operator-driven compliance model documented in §6.4.4.5.3 (no in-repo GDPR/COPPA/FERPA control implementation)

### 0.1.2 Special Instructions and Constraints

The user has explicitly emphasized the **Minimal Change Clause** as the dominant remediation discipline. The following directives are captured verbatim and must govern every transformation:

- **CRITICAL Change Scope Directive — Minimal:** "Make ONLY the changes necessary to remediate identified security vulnerabilities" — modify only files and functions directly implicated by discovered vulnerabilities; do not refactor unrelated code; do not upgrade dependencies that are not directly implicated in a discovered CVE
- **API Compatibility Directive:** "Preserve all existing Hapi route contracts, Mongoose model interfaces, and [Socket.IO](http://Socket.IO) event protocols exactly as-is" — route signatures, Joi validation schemas, model plugin APIs, and [Socket.IO](http://Socket.IO) event names are frozen
- **Backward Compatibility Directive:** "Preserve all existing functionality except where it enables the vulnerability"
- **Frontend Freeze Directive:** "DO NOT alter the AngularJS 1.3.20 frontend (ADR-5 freeze) — note CVEs, assess exploitability in sandboxed context, document findings only"
- **Least-Invasive Pattern Directive:** "Implement security controls using the least invasive approach: prefer configuration and middleware over controller-level changes; prefer header extensions over route modifications"
- **Annotation Directive:** "Annotate all security-related changes with inline comments of the form `// SECURITY: [threat addressed]`"
- **Discovery Discipline Directive:** "Note additional security concerns discovered during audit but DO NOT fix unless Critical or High severity"
- **Selection Directive:** "When multiple remediation approaches exist, choose the path requiring fewest modified files"

**User Examples (preserved exactly):**

- **User Example — Atomic Commit Format:** "Commit remediation in atomic units (one CVE or vulnerability class per commit) with message format: `security: [severity] fix [description] in [file]`"
- **User Example — Rollback Tag:** "Tag codebase before remediation begins: `git tag pre-security-remediation-20260429`"
- **User Example — Lockfile Snapshot:** "Maintain `package-lock.json` snapshot pre-upgrade: `cp package-lock.json package-lock.baseline.json`"
- **User Example — Annotation:** "// SECURITY: \[threat addressed\]"
- **User Example — Critical Vulnerability Categories:** "Remote code execution via [Socket.IO](http://Socket.IO) handlers, authentication bypass on Hapi session scheme, MongoDB injection in Mongoose queries, privilege escalation via role-plugin manipulation, unauthenticated access to /admin/\* routes"
- **User Example — Critical Workflow Test Path:** "user signup → email verify → login → create trinket → run Python trinket → submit assignment → bulk export request → logout"
- **User Example — Graceful Degradation Validation:** "Redis absent → InMemoryQueue, SMTP absent → {skipped: true}, S3 absent → upload error only (no crash), reCAPTCHA absent → fail-open preserved (with warning)"

**Web search requirements:** Document all required security research before implementing changes:

- npm Advisory Database (`https://github.com/advisories?query=ecosystem%3Anpm`) and `npmjs.com` advisories for each implicated package
- NVD/MITRE CVE entries for `request`, `passport ~0.2`, `nodemailer ^2.5.0`, `bull ^0.7.0`, `aws-sdk ^2.1.20`, `node:16-bullseye` base image, jQuery 2.2.4, Ace Editor 1.2.6.1rc2
- Hapi Security Advisories at `https://hapi.dev/policies/security/`
- OWASP Top 10 (2021) reference patterns for CSRF, XSS, IDOR, broken access control, cryptographic failures
- `@hapi/crumb` integration patterns for synchronizer-token CSRF
- Trivy scanner documentation for OS-layer CVE detection in `node:16-bullseye`
- `eslint-plugin-security` and Semgrep Node.js ruleset documentation

**Change scope preference:** **Minimal** — explicitly stipulated by the user's Minimal Change Clause section. The chosen remediation path for each finding must require the fewest modified files consistent with closing the vulnerability.

### 0.1.3 Technical Interpretation

This security vulnerability set translates to the following technical fix strategy, organized by remediation surface and mapped to specific implementation actions:

**Strategy A — Dependency Vulnerability Resolution (R1):**

To resolve historically pinned legacy CVE-bearing packages, we will **upgrade vulnerable packages to the latest patch versions** within the Node 16 main-app compatibility envelope and the Node 18 manager compatibility envelope, preserving the dual-runtime split. For `request: ^2.51.0` (deprecated with no security patches), we will **assess replacement** with a maintained successor (`axios` or native `https`/`fetch`) only at the call sites that consume it (`lib/util/recaptcha.js`); replacement scope is bounded by the Minimal Change Clause to the single use site rather than a project-wide migration. For each upgrade, we will pin the exact semver in `package.json`, run `npm ci` to validate `package-lock.json` integrity, and capture a `package-lock.baseline.json` snapshot before each change.

**Strategy B — Cryptographic Hardening (R2):**

To resolve MD5 usage in course invitation tokens, we will **modify** `lib/models/courseInvitation.js` **line 37** to replace `crypto.createHash("md5")` with `crypto.createHash("sha256")` and truncate to the same 8-character output for backward compatibility of the invitation URL surface. To resolve insufficient `app.mail.secret` entropy, we will **add a boot-time guard** in `app.js` (paralleling the existing 32-character session-password guard at lines 50–66) that warns or refuses boot when `mail.secret` is shorter than 32 characters. To document non-cryptographic SHA-1 usage, we will **annotate** `lib/models/trinket.js` (`createHash` and `verifyShortCode`), `lib/util/file.js` (file content hash), and `lib/workers/exports.js` (export filename) with `// SECURITY:` comments confirming identifier-only intent.

**Strategy C — reCAPTCHA Fail-Closed Posture (R3):**

To resolve the silent fail-open in `lib/util/recaptcha.js` (which currently returns `{success: true}` when `config.app.recaptcha` is absent), we will **modify the** `!config.app.recaptcha || !config.app.recaptcha.secretkey` **branch** to log a `WARN`-level configuration warning via the global `log` symbol and update `config/default.yaml` with an explicit comment documenting the security implication. Per the Minimal Change Clause and the user's "fail-open preserved (with warning)" directive in graceful-degradation validation, the runtime behavior remains permissive but auditable.

**Strategy D — HTTP Security Header Hardening (R4):**

To resolve missing security headers, we will **modify the** `onPreResponse` **extension in** `app.js` **lines 152–198** to add `X-Content-Type-Options: nosniff` and `Referrer-Policy: strict-origin-when-cross-origin` headers unconditionally. We will **add a CSP header** on main application pages (excluding embed and sandbox paths) using a restrictive policy feasible because the main app is not the execution sandbox per §6.4.4.4.4. We will **extend** `config.app.xframeDeny` **in** `config/default.yaml` to include `/admin/*` paths.

**Strategy E — CSRF Token Pattern (R5):**

To add CSRF synchronizer-token protection, we will **register** `@hapi/crumb` **plugin** in `app.js` and apply it selectively to `/api/exports`, `/api/users` (password/email change), and `/api/admin/*` routes via per-route configuration in `config/api_routes.js`. The AngularJS SPA integration is explicitly **scoped as a follow-on per the Risk Management section**; non-SPA routes receive CSRF tokens first.

**Strategy F — Container & Network Hardening (R6):**

To resolve EOL Node 16 base image, we will **modify** `Dockerfile` **line 2** from `FROM node:16-bullseye` to `FROM node:20-bullseye` (LTS), validating compatibility with `mongoose-schema-extend ~0.2.2` per Risk Management mitigation (test in isolated branch first). To enable shell container hardening by default, we will **modify** `serverside/docker-compose.yml` to uncomment and activate `mem_limit: 500m`, `pids_limit: 50`, `read_only: true`, `tmpfs: /tmp:size=100m`, `--security-opt=no-new-privileges`, and `--cap-drop=ALL` directives on every shell service definition. To harden nginx, we will **modify** `serverside/nginx/nginx.conf` to add `X-Content-Type-Options: nosniff` and `server_tokens off`.

**Strategy G — Access Control Audit (R7):**

To resolve potential admin route bypass, we will **audit every** `/api/admin/*` **route in** `config/api_routes.js` to confirm `pre: ['isAdmin(user)']` is present; if missing on any route, we will add it. To resolve potential IDOR, we will **audit every resource-mutating route** for `canEdit` pre-handler presence. To resolve potential bulk export ownership bypass, we will **verify** `lib/controllers/users.js` `downloadExport` enforces strict `===` ownership comparison after `.toString()`.

**Strategy H — Injection Hardening (R8):**

To resolve potential MongoDB operator injection, we will **audit Mongoose query construction in** `lib/controllers/` and ensure all user-controlled values use Mongoose schema typing. We will **audit Joi schemas in** `config/api_routes.js` for explicit rejection of `$where`/`$regex`/operator-prefixed keys in request bodies. To resolve potential Nunjucks XSS, we will **audit** `lib/views/*.html` **templates** for `| safe` filter usage on user-controlled data and replace with explicit `| e` escaping.

**Strategy I — Automated Security Testing (R9):**

To establish security regression coverage, we will **create the** `test/security/` **directory** with `auth.test.js`, `access-control.test.js`, `injection.test.js`, `session.test.js`, and `upload.test.js` modules following the existing Mocha + Supertest + Sinon pattern documented in §6.6.5. These integrate into `npm test` via the existing `mocha --recursive` discovery mechanism. We will **add a CI pipeline configuration** (operator-deferrable per §6.6.6.1, but documented) integrating `npm audit --audit-level=high`, Trivy image scanning, and ESLint security plugin pre-commit hook.

**User's understanding level:** **Explicit CVE/vulnerability awareness with discovery-first methodology**. The user has provided extensive specific guidance — exact file paths and line numbers (`app.js` lines 50–66, 90–111, 152–198, 204–240; `lib/util/recaptcha.js` `!config.app.recaptcha` branch; `lib/models/` MD5 usage), specific package versions and CVEs to investigate (`request: ^2.51.0`, `passport: ~0.2`, etc.), specific architectural constraints to preserve (Hapi 20 route DSL, `@hapi/yar` session architecture, `lib/util/catbox-mongoose.js` Catbox engine, Bull queue interface, iframe `sandbox` attribute, `lib/util/roles.js` AES interface, `loginAs`/`logoutAs` impersonation), and a complete success-criteria matrix with quantitative thresholds (100% Critical/High, ≥80% Medium, &lt;10% perf impact). This corresponds to a Security Remediation Specialist briefing rather than a general security concern.

## 0.2 Vulnerability Research and Analysis

### 0.2.1 Initial Assessment

The user's brief is structured as a **discovery-first audit** rather than a fix list keyed to specific pre-discovered CVEs. Initial extraction from the user's vulnerability classification yields the following inventory of security signals:

- **CVE numbers explicitly mentioned by the user:** None. The user defers CVE enumeration to Phase 1 scanning (`npm audit`, Trivy, ESLint security plugin, Semgrep, OWASP ZAP).
- **Vulnerability names referenced by the user:**
  - **Critical (CVSS ≥9.0):** Remote code execution via [Socket.IO](http://Socket.IO) handlers, authentication bypass on Hapi session scheme, MongoDB injection in Mongoose queries, privilege escalation via role-plugin manipulation, unauthenticated access to `/admin/*` routes
  - **High (CVSS 7.0–8.9):** XSS in Nunjucks templates on educator/admin pages, IDOR on trinket or assignment resources, insecure direct object references in bulk export download, broken access control on class/course ownership checks, prototype pollution in Mongoose plugin chain
  - **Medium (CVSS 4.0–6.9):** CSRF on state-mutating API endpoints (no synchronizer token), missing CSP on main application pages, MD5 usage in course invitation token generation, SHA-1 usage in trinket `shortCode` and file content hash, `SameSite=Lax` downgrade risk, reCAPTCHA fail-open when unconfigured, information disclosure via signup error messages distinguishing duplicate email vs. duplicate username
- **Affected packages explicitly named by the user:**
  - `config: ~0.4.35`, `mime: ~1.2.11`, `mkdirp: ~0.3.5`, `q: ~1.0.0`, `request: ^2.51.0` (deprecated, no security patches), `aws-sdk: ^2.1.20`, `nodemailer: ^2.5.0`, `passport: ~0.2`, `bull: ^0.7.0`
  - Vendored frontend assets: jQuery 2.2.4, AngularJS 1.3.20 (frozen per ADR-5), Ace Editor 1.2.6.1rc2
- **Symptoms described by the user:**
  - reCAPTCHA fail-open default (`!config.app.recaptcha` branch returns `{success: true}` in `lib/util/recaptcha.js`)
  - MD5 in course invitation tokens (`email + course.id` via MD5 in `lib/models/`)
  - SHA-1 in trinket `shortCode`, file content hash, export filename (acknowledged as identifier hashes per §6.4.4.1.1)
  - `SameSite=Lax` downgrade risk vs. `SameSite=None; Secure` post-processing path (`app.js` lines 204–240)
  - Missing rate limiting on `/login`, `/signup`, `/api/users/reset` (no rate limiter evident in `config/api_routes.js`)
  - Missing security headers on main application pages (CSP, X-Content-Type-Options, Referrer-Policy)
  - Default-commented Docker hardening directives on shell containers running untrusted learner code
  - EOL Node 16 base image (Node 16 reached end-of-life September 2023)
  - Information disclosure via signup error messages distinguishing duplicate email vs. duplicate username
- **Security advisories referenced:**
  - `npm` advisory database (per `npm audit` against root and serverside manager `package.json`)
  - Aqua Security Trivy CVE database (per Trivy scan against `node:16-bullseye` and shell images)
  - GitHub Security Advisories (per the user's "GitHub security advisories and issues" reference)
  - OWASP Top 10 (per OWASP documentation reference)

### 0.2.2 Required Web Research

CRITICAL: The Phase 1 Comprehensive Security Scanning workflow requires the following extensive web search activities prior to and during implementation. This research feeds the Vulnerability Discovery Report (Deliverable #1) and the Dependency Upgrade Report (Deliverable #2).

- **Official CVE databases (NVD, MITRE):**
  - NVD search by package: `request@^2.51.0`, `passport@~0.2.0`, `passport-google-oauth@^0.1.5`, `passport-local@~1.0.0`, `nodemailer@^2.5.0`, `bull@^0.7.0`, `aws-sdk@^2.1.20`, `config@~0.4.35`, `mime@~1.2.11`, `mkdirp@~0.3.5`, `q@~1.0.0`, `mongoose@^6.0.0`, `mongoose-schema-extend@~0.2.2`, `node-cryptojs-aes@^0.4.0`, `sha1@~1.1.0`, `validator@^5.6.0`, `jsonwebtoken@^5.0.5`
  - NVD search by base image: `node:16-bullseye` (Debian 11 OS-layer CVEs), `python:3.10-bullseye`, `amazoncorretto:8`, `r-base:4.4.2`
- **Security advisories from package maintainers:**
  - GitHub Advisory Database (`https://github.com/advisories`) ecosystem filter `npm`
  - Snyk Advisory Database for each named package
  - Hapi.dev security policies (`https://hapi.dev/policies/security/`)
  - Mongoose security advisories on `https://mongoosejs.com/`
- **OWASP documentation:**
  - OWASP Top 10 (2021): A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A05 Security Misconfiguration, A07 Identification and Authentication Failures, A08 Software and Data Integrity Failures
  - OWASP Cheat Sheet Series: CSRF Prevention Cheat Sheet, Cross-Site Scripting Prevention, Authentication Cheat Sheet, Session Management Cheat Sheet, Input Validation Cheat Sheet
  - OWASP Docker Security Cheat Sheet for shell container hardening
- **GitHub Security Advisories and Issues:**
  - `trinketapp/trinket-oss` issues with security label
  - `trinketapp/skulpt-dist`, `trinketapp/marked`, `trinketapp/glowscript` forks for downstream patch availability
  - `hapijs/hapi`, `hapijs/yar`, `hapijs/crumb`, `hapijs/joi` advisories
- **Security blogs and disclosure reports:**
  - Snyk Vulnerability DB (`https://security.snyk.io/`) per named package
  - npm audit advisory blog posts for `request` deprecation and successor recommendations
  - Node.js Security WG monthly releases for Node 16 → Node 20 LTS migration guidance
- **Stack Overflow discussions on fixes and workarounds:**
  - `mongoose-schema-extend` Node 18+ compatibility threads
  - `@hapi/crumb` AngularJS `$http` integration patterns
  - bcrypt rounds=10 vs rounds=12 trade-off analyses

**Research Documentation Format (per finding):** "Research reveals that `[package@version]` is affected by `[CVE-YYYY-NNNNN]` in `[component]`, fixed in `[patched-version]`, with CVSS score `[X.X]` (`[Critical|High|Medium|Low]`); patched version `[patched-version]` is compatible with Node `[16|18]` runtime."

### 0.2.3 Vulnerability Classification

The user's threat model (untrusted learner code, minor user data, educator courseware) anchors the classification. The following structure applies to each finding from Phase 1 scanning:

- **Vulnerability type taxonomy (per OWASP Top 10 2021 mapping):**
  - **A01 Broken Access Control:** IDOR on `/api/trinkets/:id`, `/api/courses/:id`, `/api/folders/:id`, `/api/exports/:exportId/download`, assignment endpoints; admin route bypass on `/api/admin/*`; impersonation flow exploitation
  - **A02 Cryptographic Failures:** MD5 in course invitation tokens; potential JWT HS256 weakness if `app.mail.secret` is empty/weak; SHA-1 identifier hashes (informational annotation)
  - **A03 Injection:** MongoDB operator injection in Mongoose queries; XSS in Nunjucks templates (server-side rendered user content); template injection via `| safe` filter misuse
  - **A04 Insecure Design:** reCAPTCHA fail-open default; missing rate limiting on auth endpoints; default-disabled shell container hardening
  - **A05 Security Misconfiguration:** Missing CSP, X-Content-Type-Options, Referrer-Policy headers; EOL Node 16 base image; nginx `server_tokens` disclosure; commented-out hardening directives
  - **A06 Vulnerable and Outdated Components:** Dependency CVEs in `request`, `passport`, `nodemailer`, `bull`, `aws-sdk`, `mongoose`, vendored jQuery 2.2.4, Ace Editor 1.2.6.1rc2
  - **A07 Identification and Authentication Failures:** Authentication bypass on Hapi session scheme; session fixation on login (mitigation already in place via `yar.reset()`, requires regression test); brute-force on login/signup/reset
  - **A08 Software and Data Integrity Failures:** Prototype pollution in Mongoose plugin chain (per user's High classification)
  - **A09 Security Logging and Monitoring Failures:** No dedicated audit log per §6.4.3.5; reCAPTCHA absence not logged
  - **A10 Server-Side Request Forgery:** Out of scope unless discovered via Semgrep
- **Attack vector (per CVSS v3.1):**
  - **Network (AV:N):** Default for all Hapi-exposed endpoints, [Socket.IO](http://Socket.IO) handshake, nginx gateway
  - **Local (AV:L):** Container hardening defects (require attacker code execution inside shell)
  - **Adjacent (AV:A):** Internal Docker network manager↔shell traffic
  - **Physical (AV:P):** Not applicable to this remediation
- **Exploitability (per user's threat model):**
  - **High:** Public-facing endpoints with no authentication (`/login`, `/signup`, `/api/users/reset`) — rate limiting absent; reCAPTCHA fail-open silently bypasses human verification
  - **High:** Authenticated user attacking another user's resources via IDOR (one-click attack with valid session)
  - **Medium:** CSRF requires victim to have active session and visit attacker-controlled site (mitigated partially by `SameSite=Lax`)
  - **Medium:** XSS requires user-controlled fields rendered server-side without escaping
  - **Low:** Container escape from shell into manager (requires kernel-level exploit; container hardening provides depth)
- **Impact (per CVSS v3.1 CIA triad):**
  - **Confidentiality:** Educator courseware leakage, learner submission disclosure, password hash exposure (mitigated by bcrypt + `publicSpec` allow-list), email enumeration via signup
  - **Integrity:** Trinket modification by non-owner (IDOR), course content manipulation, role escalation via prototype pollution, MongoDB write-side injection
  - **Availability:** Fork-bomb in shell container (mitigated by `pids_limit: 50` when enabled), memory exhaustion (mitigated by `mem_limit: 500m` when enabled), Bull queue saturation
- **Root cause taxonomy:**
  - **Cryptographic primitive misuse:** MD5 (collision-vulnerable, but used here as identifier — security depends on accompanying authorization checks, still upgraded to SHA-256 per minimal change principle)
  - **Default fail-open posture:** reCAPTCHA verification short-circuit, shell container hardening commented-out
  - **Missing defense-in-depth header:** No CSP/X-Content-Type-Options/Referrer-Policy on main app
  - **Outdated runtime:** Node 16 EOL exposes OS-layer glibc/openssl CVEs in `bullseye` base
  - **Ownership comparison:** Risk of `==` (loose) vs `===` (strict) after `.toString()` per user's bulk export note

### 0.2.4 Web Search Research Conducted

This section will be populated with concrete research findings during implementation. The structure below is the required format:

- **Official security advisories reviewed:** \[URLs to Snyk, GitHub Advisory Database, NVD, [npmjs.com](http://npmjs.com) advisory pages per package upgrade\]
- **CVE details and patches:** For each CVE discovered: CVE number, CVSS v3.1 score, affected version range, fixed version, vulnerability summary, exploit availability, patch link
- **Recommended mitigation strategies:**
  - **Dependency upgrade path** — preferred when patched version is compatible with Node 16 (main app) or Node 18 (managers)
  - **Dependency replacement** — preferred when no patch exists (e.g., `request` deprecated → assess `axios` or native `https`); scoped to single use site per Minimal Change Clause
  - **Code patch** — preferred when fix is a small targeted change (e.g., MD5 → SHA-256, header addition)
  - **Configuration change** — preferred when fix is a default value change (e.g., `xframeDeny` extension, hardening directive uncomment)
  - **Compensating control** — when upstream fix is unavailable (e.g., AngularJS 1.3.20 frozen per ADR-5: document CVEs, assess sandbox-based exploitability, document residual risk)
- **Alternative solutions considered:**
  - `request` **replacement:** `axios@^1.x` (maintained, similar API, large adoption) vs `node-fetch@^3.x` (lightweight, fetch-API parity) vs native `https.request` (zero dependency, minimal change). Trade-off: change surface in `lib/util/recaptcha.js` only; native `https` requires more code lines but zero new dependency
  - **CSRF library:** `@hapi/crumb` (Hapi-native, plugin pattern) vs custom synchronizer-token middleware. Trade-off: `@hapi/crumb` matches existing Hapi-plugin idiom, lower modification cost
  - **CSP scope:** Strict policy on main app pages (excluding embed/sandbox routes per §6.4.4.4.4) vs report-only mode first. Trade-off: report-only first allows production telemetry without breaking; user prompt requires header enforcement
  - **Node base image:** `node:18-bullseye` (one minor jump, lower regression risk) vs `node:20-bullseye` (LTS, longer security horizon) per user's "node:18-bullseye or node:20-bullseye LTS" guidance. Trade-off: Node 20 selected for LTS coverage
  - **Shell hardening:** Default-enable per user directive vs. operator-opt-in (current default). User explicitly requires default-enable: "operators can opt out but hardening must be the default posture for an educational platform executing untrusted learner code"
  - **MD5 → SHA-256 vs. token replacement:** Substituting algorithm only (preserves URL surface, 8-char truncation) vs. switching to `crypto.randomBytes(8)` (cryptographically strong, requires invitation URL contract analysis). User specifies: "Replace MD5 usage in course invitation token generation with `crypto.createHash('sha256')`" — algorithm-only substitution is the chosen minimal path

## 0.3 Security Scope Analysis

### 0.3.1 Affected Component Discovery

CRITICAL: An exhaustive search across the Trinket OSS repository identifies the following components affected by the multi-class vulnerability set. Search patterns and locations were applied per the Phase 1 scan scope and validated against the user's "Scan Scope" enumeration.

**Vulnerable package import surface (npm dependency CVEs):**

- **Root** `package.json` **direct declarations** — 52 runtime + 11 dev = 63 dependencies. Each historically pinned legacy package implies imports across the codebase:

  - `request` → `lib/util/recaptcha.js` line 1 (`var request = require('request')`)
  - `passport`, `passport-local`, `passport-google-oauth`, `passport-strategy` → `lib/auth/passport.js` (Passport strategy registration)
  - `nodemailer` → `lib/util/mailer.js` (SMTP transport construction)
  - `bull` → `lib/util/queues.js` (Bull queue factory) and `lib/workers/exports.js` (export job consumer)
  - `aws-sdk` → `lib/util/file.js` (S3 facade for materials, avatars, snapshots, user assets, CDN, exports) and `config/aws.js` (SDK client construction)
  - `mongoose`, `mongoose-schema-extend` → `lib/models/*.js` (every Mongoose model)
  - `node-cryptojs-aes` → `lib/util/roles.js` (AES role payload encryption)
  - `sha1`, native `crypto.createHash('sha1')` → `lib/models/trinket.js` (lines 117, 120, 177), `lib/util/file.js`, `lib/workers/exports.js`
  - `validator@^5.6.0` → call sites in `lib/controllers/users.js`, `lib/models/user.js` (string validation)
  - `jsonwebtoken@^5.0.5` → `lib/controllers/trinket.js` (email verification JWT HS256 issuance), `lib/util/helpers.js` (JWT verify pre-handler)
  - `config@~0.4.35` (legacy pin) → every module via `require('config')`
  - `mime@~1.2.11`, `mkdirp@~0.3.5`, `q@~1.0.0` (legacy pins) → various utility uses
  - `js-yaml@~3.0.1` (legacy pin) → `config/app.config.js` and `config/db.js` for YAML loading

- **Serverside manager** `package.json` **files (Node 18 ESM, separate dependency tree):**

  - `serverside/python/manager/package.json` — `config@^3.3.12`, `file-type@^18.0.0`, `is-svg@^4.3.2`, `socket.io@^4.8.0`, `socket.io-client@^4.8.0`
  - `serverside/r/manager/package.json` — `config@^3.3.12`, `file-type@^18.0.0`, `socket.io@^4.8.0`, `socket.io-client@^4.8.0`
  - `serverside/java/manager/package.json` — `config@^3.3.12`, `file-type@^18.0.0`, `socket.io@^4.8.0`, `socket.io-client@^4.8.0`
  - `serverside/pygame/manager/package.json` — `config@^3.3.9`, `file-type@^19.0.0`, `is-svg@^5.0.0`, `socket.io@^4.7.4`, `socket.io-client@^4.7.4`
  - Each manager `package.json` must be scanned independently per the user's "Node 16 (main app, Dockerfile) and Node 18 (managers) have separate dependency trees and must each be scanned independently" directive

- **Vendored frontend assets (not npm-managed):**

  - `public/js/embed/` — forked Skulpt, Blockly, GlowScript 2.7.5
  - `public/js/skulpt/` — Skulpt distribution
  - CDN-loaded (per `config/default.yaml`): jQuery 2.2.4, AngularJS 1.3.20 (frozen ADR-5), Ace Editor 1.2.6.1rc2

**Vulnerable code pattern surface:**

- **Cryptographic weakness sites:**

  - `lib/models/courseInvitation.js` line 37: `crypto.createHash("md5").update(email + course.id).digest("hex").substring(0, 8)` — **MD5 in invitation tokens (must replace with SHA-256)**
  - `lib/models/trinket.js` lines 117, 120, 177: `crypto.createHash('sha1')...` — **SHA-1 identifier hashes (annotate only, non-confidentiality use)**
  - `lib/util/file.js` — file content SHA-1 hash (annotate only)
  - `lib/workers/exports.js` — export filename SHA-1 (annotate only)
  - `lib/controllers/trinket.js` — JWT HS256 with `app.mail.secret + shortCode` (audit secret entropy at boot)

- **Authentication and session sites:**

  - `lib/util/recaptcha.js` lines 6–9: **fail-open** `!config.app.recaptcha` **branch returns** `{success: true}` **silently — must add boot-time warning log**
  - `app.js` lines 50–66 — existing 32-char session password boot guard (template for `mail.secret` guard addition)
  - `app.js` lines 90–111 — Yar session plugin registration with `cookieOptions` (audit `isSecure` propagation behind reverse proxy via `X-Forwarded-Proto` trust)
  - `app.js` lines 116–137 — `onPreHandler` sliding expiration (audit no regression)
  - `app.js` lines 152–198 — `onPreResponse` for Cache-Control, X-Frame-Options (must add CSP, X-Content-Type-Options, Referrer-Policy)
  - `app.js` lines 204–240 — `onPreResponse` cookie post-processing (audit `SameSite=None; Secure` flag propagation)
  - `app.js` lines 242–287 — custom `session` auth scheme (audit no regression on disabled-account two-tier enforcement)
  - `lib/auth/passport.js` — LocalStrategy, GoogleStrategy, `deserializeUser` disabled-account check (audit Google OAuth callback CSRF state parameter)

- **Authorization and access-control sites:**

  - `lib/util/helpers.js` lines 17–29 — `isAdmin` pre-handler (verify on every `/api/admin/*` route)
  - `lib/util/helpers.js` lines 70–90 — `canEdit` pre-handler (verify on every resource-mutating endpoint)
  - `config/api_routes.js` — every `/api/admin/*` route (audit `pre: ['isAdmin(user)']`); every resource-mutating route (audit `pre: ['canEdit(...)']`)
  - `lib/controllers/users.js` `downloadExport` — bulk export ownership comparison (`exportRecord._owner.toString() !== userId` strict `===`)
  - `lib/controllers/admin.js` — `loginAs`/`logoutAs` impersonation (audit `_realUserId` not exposed in API responses or Nunjucks templates)
  - `lib/models/plugins/roles.js` — `_realUserId` impersonation tracking (audit no client-side leak)

- **Injection sites:**

  - `lib/controllers/*.js` — every Mongoose query construction (`find`, `findOne`, `findById`, `update`, aggregation pipelines) — audit user-controlled values pass through Mongoose schema typing
  - `config/api_routes.js` — Joi schemas on all mutating routes (audit rejection of `$where`, `$regex`, operator-prefixed keys)
  - `lib/views/*.html` — every Nunjucks template (audit `{{ var | e }}` escaping or auto-escape; replace any `| safe` filter on user-controlled data)
  - `lib/views/email/*.html` — email templates (audit XSS via user-controlled email body content)

**Configuration files affected:**

- `config/default.yaml` — `xframeDeny` list (extend to `/admin/*`); reCAPTCHA documentation comment; sandbox `permissions` (preserve `allow-same-origin` absence)
- `config/api_routes.js` — Joi validation hardening, CSRF token application
- `config/routes.js` — page route audit
- `config/local.example.yaml` — secret guidance documentation
- `config/test.yaml` — test environment compatibility audit

**Dependency manifests:**

- `package.json` (root, main app)
- `package-lock.json` (root, main app)
- `serverside/python/manager/package.json`
- `serverside/r/manager/package.json`
- `serverside/java/manager/package.json`
- `serverside/pygame/manager/package.json`
- `serverside/python/shell/requirements.txt` (Python 3 shell dependencies)
- `serverside/pygame/worker/requirements.txt` (Pygame worker dependencies)
- `serverside/r/shell/packages.txt` (R packages)

**Docker files:**

- `Dockerfile` (root, main app) — base image `FROM node:16-bullseye` line 2 (upgrade to `node:20-bullseye`)
- `serverside/python/shell/Dockerfile`, `serverside/python/manager/Dockerfile` (audit base images)
- `serverside/java/shell/Dockerfile`, `serverside/java/manager/Dockerfile` (audit base images)
- `serverside/r/shell/Dockerfile`, `serverside/r/manager/Dockerfile` (audit base images)
- `serverside/pygame/worker/Dockerfile`, `serverside/pygame/manager/Dockerfile` (audit base images)
- `serverside/nginx/Dockerfile` (audit nginx base image)
- `docker-compose.yml` (root, main stack) — main app, MongoDB, Redis hardening
- `serverside/docker-compose.yml` — shell hardening directive activation (`mem_limit`, `pids_limit`, `read_only`, `tmpfs`, `--security-opt=no-new-privileges`, `--cap-drop=ALL`)
- `.dockerignore` (audit no secrets exposure)
- `serverside/nginx/nginx.conf` — security headers, `server_tokens off`

**CI/CD pipelines:**

- Per §6.6.6.1, the repository ships **no CI/CD configuration** — there are no `.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`, or `Jenkinsfile` files committed
- The user prompt specifies CI integration as a deliverable: "Integrate `npm audit --audit-level=high` into CI pipeline", "Integrate `trivy image --exit-code 1 --severity CRITICAL,HIGH`", "Execute ESLint security plugin on pre-commit hook", "Schedule weekly OWASP ZAP baseline scan against staging instance"
- New file required: `.github/workflows/security-scan.yml` (or equivalent operator-deferrable structure documented in the deliverable)

**Documentation:**

- `SECURITY.md` (new, per OWASP best practice — vulnerability disclosure policy)
- `README.md` (security section update)
- `serverside/README.md` (already documents hardening; cross-reference from new defaults in `serverside/docker-compose.yml`)
- `CHANGELOG.md` (security release entry)

**Findings summary:** Vulnerability scope affects approximately **8 dependency manifests**, **7 controllers** in `lib/controllers/`, **17 models** in `lib/models/`, **18 utility modules** in `lib/util/`, **4 configuration YAML files** in `config/`, **2 Hapi-routing files** (`config/routes.js`, `config/api_routes.js`), **2 Docker compose files** plus **9 Dockerfiles**, **1 nginx config**, **all Nunjucks templates** in `lib/views/`, and **vendored frontend assets** in `public/js/embed/` and `public/js/skulpt/` — touching every concentric security layer of the defense-in-depth architecture documented in §6.4.1.2.

### 0.3.2 Root Cause Identification

The vulnerabilities stem from a **defense-in-depth posture with operator-controlled gaps and historically pinned legacy dependencies**. Investigation reveals the following root causes per vulnerability class:

- **Dependency CVE class:** Legacy pinning policy (per §1.3.3 future work and §2.4.1) keeps `config: ~0.4.35`, `mime: ~1.2.11`, `mkdirp: ~0.3.5`, `q: ~1.0.0`, `request: ^2.51.0` (deprecated), and other packages on versions that predate available security patches. The `--legacy-peer-deps` install flag (`Dockerfile` line 31) signals known peer-dependency conflicts that block straightforward upgrades.
- **Cryptographic weakness class:** The MD5 use in `lib/models/courseInvitation.js` line 37 is documented in §6.4.4.1.1 as an identifier hash with security relying on accompanying authorization checks. The user's directive elevates this from informational annotation to active replacement with SHA-256.
- **reCAPTCHA fail-open class:** The `lib/util/recaptcha.js` short-circuit at lines 6–9 returns `{success: true}` when `config.app.recaptcha` or `config.app.recaptcha.secretkey` is absent. This was an explicit design choice for graceful degradation (per §5.4.6 and §6.4.4.4.4) and the compatible Joi rule degrades to optional in `config/routes.js` and `config/api_routes.js`. The user's directive preserves the fail-open posture but adds a configuration warning log.
- **Missing security headers class:** Per §6.4.4.4.1, the `onPreResponse` extension at `app.js` lines 152–198 currently emits only `Cache-Control`, `Pragma`, `Expires`, and conditional `X-Frame-Options: deny` (on `xframeDeny` paths). CSP, X-Content-Type-Options, and Referrer-Policy are absent. The main app does not currently emit a CSP header on its own pages per §6.4.4.4.4.
- **CSRF protection gap class:** Per §6.4.3.4.3, the open-source release does not implement synchronizer-token-pattern CSRF protection. Mitigation relies on `SameSite=Lax` on session cookies, `SameSite=None; Secure` post-processing at `app.js` lines 204–240, `X-Frame-Options: deny` on sensitive paths, and Joi payload validation. The user's directive adds `@hapi/crumb` to highest-risk mutating endpoints.
- **Container hardening default-disabled class:** Per §6.4.4.5.1, server-side shell containers ship "deliberately unhardened" in default `serverside/docker-compose.yml` because hardening is documented as operator responsibility. The user's directive promotes this to default-on with operator opt-out preserved.
- **EOL Node 16 base image class:** `Dockerfile` line 2 `FROM node:16-bullseye` references a Node.js LTS line that reached end-of-life September 2023. OS-layer CVEs in `bullseye` accumulate without security patch backflow.
- **No rate limiting class:** No rate limiter is evident in `config/api_routes.js` for `/login`, `/signup`, `/api/users/reset` per the user's audit guidance. This is a defense-in-depth gap rather than a direct vulnerability.

**Vulnerability propagation traces:**

- **Direct usage locations (cryptographic):** `lib/models/courseInvitation.js` (MD5), `lib/models/trinket.js` (SHA-1 identifiers), `lib/util/file.js` (SHA-1 file hash), `lib/workers/exports.js` (SHA-1 export filename), `lib/controllers/trinket.js` (JWT HS256 email tokens)
- **Indirect dependencies (npm CVE chain):** Transitive dependencies of `request@^2.51.0` (e.g., `tough-cookie`, `form-data`), transitive dependencies of `aws-sdk@^2.1.20` (e.g., `xml2js`), `passport@~0.2.0` transitive chain, `nodemailer@^2.5.0` transitive chain — full enumeration requires `npm ls` output and `npm audit --json` per Phase 1 scanning
- **Configuration enablers:** `config/default.yaml` `xframeDeny` list (insufficient coverage); `serverside/docker-compose.yml` commented hardening directives; `Dockerfile` `FROM node:16-bullseye` declaration; `config/api_routes.js` absence of rate-limit per-route configuration

### 0.3.3 Current State Assessment

The current vulnerable state per primary remediation surface is captured below. Each entry includes the file path, code/config snippet, and the specific vulnerable property.

**Vulnerable package versions (root** `package.json`**):**

- `request@^2.51.0` — deprecated, no security patches available; replacement assessment required
- `passport@~0.2.0` — pinned at minor version 0.2 (current: \~0.7); transitive dependencies on outdated middleware; review for CVEs
- `passport-google-oauth@^0.1.5`, `passport-local@~1.0.0`, `passport-strategy@~1.0.0` — review for CVEs
- `nodemailer@^2.5.0` — major version 2 (current: 6); breaking API changes between v2 and v6; review for CVEs and assess migration cost
- `bull@^0.7.0` — version 0.7 (current: 4.x); breaking API changes; review for CVEs
- `aws-sdk@^2.1.20` — AWS SDK v2 (v3 is the current major); v2 is in maintenance mode per AWS announcement; review for CVEs
- `config@~0.4.35` — legacy pin; main app currently uses 0.4.35 while serverside managers use 3.3.x; cross-runtime version delta
- `mime@~1.2.11`, `mkdirp@~0.3.5`, `q@~1.0.0`, `js-yaml@~3.0.1` — legacy pins; review for CVEs
- `mongoose@^6.0.0` — recent major; review patch updates
- `mongoose-schema-extend@~0.2.2` — flagged deprecated per §3.2.3 and `config/db.js`; ADR-8 tech debt; Node 18+ compatibility risk
- `node-cryptojs-aes@^0.4.0` — review for CVEs in AES implementation
- `jsonwebtoken@^5.0.5` — major version 5 (current: 9); known CVE in v5 (`CVE-2022-23529` and others); review patch path
- `validator@^5.6.0` — major version 5 (current: 13); review for CVEs

**Vulnerable code pattern locations:**

- `lib/models/courseInvitation.js` line 37:

  ```javascript
  token = crypto.createHash("md5").update(email + course.id).digest("hex").substring(0, 8);
  ```
- `lib/util/recaptcha.js` lines 6–9:

  ```javascript
  if (config.isTest || !config.app.recaptcha || !config.app.recaptcha.secretkey) {
    return cb({ success : true });
  }
  ```
- `app.js` lines 152–198: `onPreResponse` extension emits only `Cache-Control`, `Pragma`, `Expires`, conditional `X-Frame-Options: deny` — missing CSP, X-Content-Type-Options, Referrer-Policy

**Vulnerable configuration:**

- `Dockerfile` line 2: `FROM node:16-bullseye` — EOL Node 16 LTS line
- `serverside/docker-compose.yml` (every shell service): hardening directives `mem_limit: 500m`, `pids_limit: 50`, `read_only: true`, `tmpfs: /tmp:size=100m`, `--security-opt=no-new-privileges`, `--cap-drop=ALL` are commented out as `# Production security options (uncomment for hardened deployment):`
- `config/default.yaml` `xframeDeny` list: `['/', '/login', '/signup', '/contact', '/educators']` — `/admin/*` not covered
- `serverside/nginx/nginx.conf`: `server_tokens off` not present (server version disclosure); `X-Content-Type-Options: nosniff` not present on WebSocket proxy responses or generated-file static routes

**Scope of exposure:**

- **Public-facing:** All Hapi routes on port 3000 (browser-reachable via reverse proxy); all [Socket.IO](http://Socket.IO) endpoints via nginx gateway on port 8080 (`/python3/`, `/java/`, `/r/`, `/pygame/`)
- **Internal but adversarial:** Shell containers executing untrusted learner code (Python 3, Java, R, Pygame); manager↔shell internal Docker network
- **Authenticated-only:** `/api/admin/*` routes; resource-mutating endpoints behind `canEdit` pre-handler; impersonation flow (`loginAs`/`logoutAs`) — risk is internal privilege escalation
- **Email-channel:** Course invitation tokens (MD5 → SHA-256 fix changes URL surface entropy without changing length)
- **Out-of-band:** S3 presigned URLs (3-day TTL per §6.4.4.5.1); JWT email share tokens

**Threat-model alignment:** Per §6.4.1.1, the platform's threat model is materially more complex than typical CMS because it executes untrusted learner code on behalf of authenticated minors while hosting educator courseware. The remediation must treat the **shell tier as adversarial** (per §6.4.5 zone definitions: "Code Execution Zone — Adversarial") and the **main application zone as trusted but defended-in-depth** with the seven concentric layers documented in §6.4.1.2.

## 0.4 Version Compatibility Research

### 0.4.1 Secure Version Identification

CRITICAL: Web search activity must identify patched versions for each vulnerable dependency. The matrix below captures the research-required upgrade path framework. Specific version numbers and CVE identifiers will be populated during implementation from the npm advisory database, GitHub Security Advisories, and Snyk Vulnerability DB.

For each vulnerable dependency identified by `npm audit`, the following research matrix applies:

| Dependency Surface | Current Version | Research Required | Constraint |
| --- | --- | --- | --- |
| request | ^2.51.0 (deprecated) | Successor identification: axios, node-fetch, native https | Replacement scope: lib/util/recaptcha.js only (per Minimal Change Clause) |
| passport | ~0.2.0 | First patched version with no Critical/High CVEs; verify passport-local, passport-google-oauth, passport-strategy compatibility | LocalStrategy and conditional GoogleStrategy in lib/auth/passport.js must continue to function unchanged |
| nodemailer | ^2.5.0 | First version with no Critical/High CVEs in v2.x or migration path to v6 | lib/util/mailer.js send() API surface must remain intact |
| bull | ^0.7.0 | First version with no Critical/High CVEs; verify Redis client compatibility | lib/util/queues.js InMemoryQueue/NoOpQueue fallback contract; lib/workers/exports.js consumer interface |
| aws-sdk | ^2.1.20 (v2 maintenance mode) | First v2.x version with no Critical/High CVEs OR migration path to v3 | config/aws.js SDK construction; lib/util/file.js S3 facade for materials/avatars/snapshots/userassets/cdn/exports/useravatars/appassets/vendorassets |
| mongoose | ^6.0.0 | First v6.x patch with no Critical/High CVEs; verify Node 16/18 compatibility | All lib/models/*.js Mongoose schemas; mongoose-schema-extend ~0.2.2 compatibility constraint |
| jsonwebtoken | ^5.0.5 | First v5.x patch OR migration to v9 (known CVE in v5: CVE-2022-23529) | lib/controllers/trinket.js HS256 issuance; lib/util/helpers.js verification |
| node-cryptojs-aes | ^0.4.0 | Verify no AES implementation CVEs; consider native crypto module | lib/util/roles.js AES role payload encryption interface (frozen contract) |
| validator | ^5.6.0 | First v5.x patch OR migration to v13 | Call sites in lib/controllers/users.js, lib/models/user.js |
| config | ~0.4.35 (main app) | Legacy pin; assess migration to v3.3.x to align with serverside managers | Every module via require('config'); YAML layering contract preserved |
| mime | ~1.2.11 | Legacy pin; first v1.x patch | File type resolution call sites |
| mkdirp | ~0.3.5 | Legacy pin; first v0.x patch | Directory creation utility uses |
| q | ~1.0.0 | Legacy pin; first v1.x patch | Q-promise compat polyfill in app.js lines 4–16 |
| js-yaml | ~3.0.1 | Legacy pin; first v3.x patch | config/app.config.js, config/db.js YAML loading |
| socket.io (managers) | ^4.7.4–^4.8.0 | First v4.x patch with no Critical/High CVEs; verify protocol compat with browser embed | serverside/{python,java,r,pygame}/manager/manager.js Socket.IO server; public/js/embed/server.js Socket.IO client |
| socket.io-client (managers) | ^4.7.4–^4.8.0 | Same v4.x patch level | Manager↔shell client connection |
| file-type (managers) | ^18.0.0–^19.0.0 | First v18.x or v19.x patch | File type detection in managers |
| is-svg (managers) | ^4.3.2–^5.0.0 | First v4.x or v5.x patch | SVG detection in python and pygame managers |

**Frontend vendored assets (per Frontend Freeze Directive):**

| Asset | Current Version | Action |
| --- | --- | --- |
| AngularJS | 1.3.20 | DOCUMENT CVEs ONLY (frozen per ADR-5); assess exploitability in iframe-sandboxed context; do not upgrade |
| jQuery | 2.2.4 | Document CVEs; assess exploitability in iframe-sandboxed context; upgrade only where exploitable given Trinket's sandbox attribute configuration |
| Ace Editor | 1.2.6.1rc2 | Document CVEs; assess exploitability; upgrade only where exploitable |
| Skulpt | 0.11.1.34 (Trinket fork) | Audit for security patches in upstream Skulpt; assess applicability |
| Blockly | v20211018 (Trinket fork) | Audit for security patches in upstream Blockly |
| GlowScript | 2.7.5 (Trinket fork) | Audit for security patches in upstream GlowScript |
| Foundation | 5.5.3.1 | Document CVEs |
| jq-console | v2.13.2.1 (Trinket fork) | Document CVEs |

**Per the user directive:** "For vendored frontend assets (jQuery 2.2.4, AngularJS 1.3.20, Ace Editor 1.2.6.1rc2) — document CVEs, assess exploitability in iframe-sandboxed context, and upgrade only where exploitable given Trinket's `sandbox` attribute configuration; do not upgrade AngularJS (ADR-5 freeze)."

**Base image upgrades:**

| Image | Current | Target | Rationale |
| --- | --- | --- | --- |
| Main app Dockerfile | node:16-bullseye | node:20-bullseye LTS | Node 16 reached EOL September 2023; Node 20 is current LTS with longer security horizon (per user directive); validate mongoose-schema-extend ~0.2.2 Node 20 compatibility |
| Python shell | python:3.10-bullseye | Audit OS-layer CVEs; consider patch-level update | Bullseye is current Debian 11 stable; verify numpy, scipy, matplotlib, pandas, pygame compatibility with newer base if needed |
| Java shell | amazoncorretto:8 | Audit for Corretto 8 CVEs | Corretto 8 is LTS through 2030 |
| R shell | r-base:4.4.2 | Audit for OS-layer CVEs | Recent R version |
| Pygame worker | Ubuntu base | Audit for CVEs |  |
| nginx gateway | nginx:alpine | Audit for CVEs in alpine base |  |

**New direct dependency to add (for CSRF protection):**

- `@hapi/crumb@^9.x` (or compatible with Hapi `^20.0.0`) — synchronizer-token CSRF middleware

**New direct dependency to add (for** `request` **replacement, if assessed):**

- One of: `axios@^1.x` (recommended for fetch-style modernization) OR native `https` module (zero new dependency, more code lines) — **decision deferred to implementation per Minimal Change Clause: "When multiple remediation approaches exist, choose the path requiring fewest modified files"**

**New dev dependencies to add (for security testing per R9):**

- `eslint@^8.x` (or compatible) + `eslint-plugin-security@^1.x` — JavaScript SAST linting per user's Phase 1 scanning directive
- Trivy is invoked at the CLI level (no npm dependency) per user's "Trivy (Aqua Security, Apache 2.0): Unified scanner" directive

### 0.4.2 Compatibility Verification

**Node.js runtime constraint analysis:**

- **Main app — Node 16 (current** `Dockerfile`**) → Node 20 (target):**
  - Per §3.1.1 selection rationale: "The Docker image is pinned to Node 16 (`bullseye`) to preserve compatibility with several legacy pinned dependencies (`config: ~0.4.35`, `mime: ~1.2.11`, `mkdirp: ~0.3.5`)"
  - Per Risk Management mitigation: "Node.js base image upgrade (`node:16` → `node:18`+) may surface compatibility issues with `mongoose-schema-extend ~0.2.2` (known legacy, ADR-8 tech debt) → Mitigation: test against Node 18 in isolated branch before merging; if incompatible, document as a blocker requiring ADR-8 resolution first"
  - Per `app.js` lines 29–36: `gleak` leak-detection library has Node 16+ incompatibility worked around with no-op fallback — must remain functional under Node 20
  - Per `app.js` lines 4–16: Q-compatible Promise.spread/Promise.fail polyfill for Mongoose 6 — must remain functional under Node 20
  - **Verification path:** Build new Docker image with `FROM node:20-bullseye`; run `npm ci --legacy-peer-deps`; run `npm test`; if `mongoose-schema-extend` fails, document as ADR-8 blocker
- **Serverside managers — Node 18 (current) → no change required:**
  - Per §3.1.2: Node.js 18 (ESM) for all four managers; `socket.io@^4.7.4`–`^4.8.0` is Node 18+ compatible
  - Manager dependency tree is independent of main app per user directive

**Other dependency compatibility:**

- `bcrypt@^5.1.0` — Node 14+ compatible; verify Node 20 native binding; rebuild prebuilt binaries on base image upgrade
- `mongoose@^6.0.0` — Node 14+ compatible; latest 6.x or 7.x patches likely compatible with Node 20; verify against `mongoose-schema-extend ~0.2.2`
- `@hapi/hapi@^20.0.0` — Node 12+ compatible; current Hapi 21.x is Node 18+ but user directive freezes Hapi 20 route registration DSL ("Hapi 20 route registration DSL...must not change signatures"); remain on Hapi 20
- `redis@^4.0.0` — Node 14+ compatible
- `bull@^0.7.0` upgrade target → likely Bull 4.x requires Node 12+; assess if `lib/workers/exports.js` consumer interface holds across major versions

**Cross-component compatibility verification:**

- **Hapi 20 route DSL frozen** — any package upgrade must not require route signature changes per user's "Must Remain Unchanged" list
- `@hapi/yar` **session architecture frozen** — `catbox-mongoose` custom Catbox engine, sliding 24-hour TTL, 32-char password boot guard must not change
- [**Socket.IO**](http://Socket.IO) **protocol contract frozen** — WebSocket handshake and event names between browser embed and nginx gateway are consumed by deployed embeds in third-party iframes
- **Pre-handler chain API frozen** — `isAdmin`, `canEdit`, `findById`, `validLang`, `trinketTypeEnabled`, `coursesEnabled`, `verifyEmailToken` must resolve identically
- **Bull queue interface frozen** — `InMemoryQueue` and `NoOpQueue` fallback behavior preserved
- **iframe sandbox attribute frozen** — `allow-same-origin` must remain absent
- **AngularJS 1.3.20 frozen** — no framework migration in scope per ADR-5
- `lib/util/roles.js` **AES role-payload encryption interface frozen** — encrypt/decrypt contract consumed by `lib/models/plugins/roles.js`
- **Admin impersonation frozen** — `loginAs`/`logoutAs` mechanism and `_realUserId` tracking preserved

**Documented version conflicts to resolve:**

- **Main app** `config@~0.4.35` **vs serverside manager** `config@^3.3.x` — cross-runtime delta is intentional (different ESM/CommonJS contexts); upgrading main app `config` is **out of scope** unless directly implicated by a CVE (per Minimal Change Clause)
- `mongoose-schema-extend ~0.2.2` — flagged deprecated; if Node 20 surfaces incompatibility, blocker per Risk Management mitigation (defer to ADR-8 resolution)

### 0.4.3 Alternative Packages (where no patch is available)

Per the user's directive: "Replace `[vulnerable dependency]` with `[alternative]` because: No security patch available for `[vulnerable package]`, Package is unmaintained/deprecated, Alternative provides better security posture"

**Replacement candidate analysis (per the Minimal Change Clause "fewest modified files"):**

| Vulnerable Package | Replacement Candidate | Justification | Migration Complexity | Affected Files |
| --- | --- | --- | --- | --- |
| request@^2.51.0 (deprecated) | axios@^1.x | Maintained; promise-based API; broad ecosystem | Low — single use site | lib/util/recaptcha.js (1 file, ~20 lines) |
| request@^2.51.0 (deprecated) | Native https module | Zero new dependency; minimal change to package.json | Low — single use site | lib/util/recaptcha.js (1 file, ~30 lines) |
| request@^2.51.0 (deprecated) | node-fetch@^3.x | Fetch API parity; ESM-native (consideration for CommonJS interop) | Medium — ESM/CJS boundary | lib/util/recaptcha.js (1 file, ~25 lines) |

**Decision criteria:** The user's Minimal Change Clause directive is "When multiple remediation approaches exist, choose the path requiring fewest modified files." All three options touch only `lib/util/recaptcha.js`. Native `https` adds zero new dependency but slightly more code; `axios` adds one well-maintained dependency. Decision deferred to implementation, with `axios` as the default per Hapi/Node ecosystem norms.

**Other replacement candidates:**

| Vulnerable Package | Replacement Candidate | Justification | Migration Complexity |
| --- | --- | --- | --- |
| nodemailer@^2.5.0 | nodemailer@^6.x (in-major-name upgrade) | Same package, current major; v2 EOL | Medium — lib/util/mailer.js API audit; createTransport signature change; OAuth2 vs username/password auth contract preserved |
| bull@^0.7.0 | bull@^4.x OR bullmq@^5.x | Bull 4.x is current major; bullmq is Bull's TypeScript successor | Medium — lib/util/queues.js and lib/workers/exports.js consumer interface; preserve InMemoryQueue/NoOpQueue fallback |
| aws-sdk@^2.1.20 | @aws-sdk/* (v3 modular) | v2 in maintenance mode per AWS announcement; v3 is current | High — every S3 call site in lib/util/file.js; lib/workers/exports.js; config/aws.js SDK construction; assess scope reduction by retaining v2 with patches if available |
| passport@~0.2.0 | passport@^0.7.x | Same package, current minor; v0.2 EOL | Medium — lib/auth/passport.js LocalStrategy and GoogleStrategy registration |
| jsonwebtoken@^5.0.5 | jsonwebtoken@^9.x | Same package, current major; v5 has known CVEs | Low — lib/controllers/trinket.js issuance; lib/util/helpers.js verify |
| validator@^5.6.0 | validator@^13.x | Same package, current major | Low — call sites in users.js, user.js |
| node-cryptojs-aes@^0.4.0 | Native crypto module AES-256-GCM | Native; no third-party dependency | High — frozen interface per user directive; reject replacement; audit for CVEs only |

**Per Minimal Change Clause:** Replacement is the second-choice fix path. The first choice is **upgrade-in-place** to a patched version. Replacement is justified only when no patch exists (`request` deprecated) or when v2/v5 is in EOL with known unmitigated CVEs.

**Migration complexity assessment:**

- **Low (≤2 files):** `request` → `axios`/native `https`; `jsonwebtoken` v5 → v9; `validator` v5 → v13
- **Medium (3–10 files):** `nodemailer` v2 → v6; `bull` v0.7 → v4; `passport` v0.2 → v0.7
- **High (&gt;10 files):** `aws-sdk` v2 → v3 (every S3 call site touched); `node-cryptojs-aes` replacement (frozen interface)

**API differences requiring code changes (illustrative for** `request` **→** `axios`**):**

- `request.post({url, form}, callback)` → `axios.post(url, qs.stringify(form))` returning Promise
- Response handling: `request` callback receives `(err, response, body)`; `axios` resolves to `{data, status, headers}`
- Error semantics: `request` non-200 status not an error by default; `axios` throws for non-2xx by default
- Specific change in `lib/util/recaptcha.js`: \~10 lines modified, callback wrapper adapted

**Performance or feature trade-offs:**

- `axios` adds \~28 KB minified (acceptable for a server-side dep)
- Native `https` zero size impact; \~10 lines additional handshake/parsing code
- `nodemailer` v6 supports modern auth (OAuth2, XOAUTH2) — additive feature, no regression

**Full replacement scope (template for any replacement decision):**

- All `require('<vulnerable_package>')` import statements requiring updates
- All function calls needing modification to match new API surface
- All configuration files requiring changes (e.g., `nodemailer` transport options if signature changed)
- All test files needing updates (e.g., `test/helpers/mail.js` if `mailer.send` signature changed; per current state, `mailer.send` is stubbed via Sinon and signature changes propagate through stub interface)

## 0.5 Security Fix Design

### 0.5.1 Minimal Fix Strategy

PRINCIPLE: Apply the smallest possible change that completely addresses each vulnerability. The fix design below is organized by vulnerability class, with each entry specifying the fix approach and the rationale for selecting the minimal path.

**Fix approach decision matrix:**

| Vulnerability Class | Approach | Rationale |
| --- | --- | --- |
| Dependency vulnerabilities (R1) | Dependency update | Smallest possible change; preserves API surface; aligns with npm audit fix semantics |
| request@^2.51.0 deprecation | Dependency replacement (axios or native https) | No patch available; replacement scoped to single file lib/util/recaptcha.js per Minimal Change Clause |
| MD5 in invitation tokens (R2) | Code patch | Smallest change: substitute 'md5' → 'sha256'; preserve 8-char output format for URL backward compat |
| app.mail.secret entropy (R2) | Code patch | Add boot-time guard paralleling existing app.js lines 50–66 pattern; <20 lines |
| SHA-1 identifier annotations (R2) | Code patch (annotation only) | Per user: "annotate with comments confirming the non-cryptographic intent"; zero functional change |
| reCAPTCHA fail-open (R3) | Code patch | Per user: "add a configuration warning log"; preserve fail-open per graceful-degradation directive |
| Missing security headers (R4) | Configuration change + code patch | Header extension to existing onPreResponse middleware; configuration extension to xframeDeny |
| CSRF protection (R5) | Dependency addition + code patch + configuration | Add @hapi/crumb; register in app.js; apply selectively per route in config/api_routes.js |
| EOL Node 16 base image (R6) | Configuration change | Single-line Dockerfile change node:16-bullseye → node:20-bullseye |
| Default-disabled shell hardening (R6) | Configuration change | Uncomment hardening directives in serverside/docker-compose.yml; preserve operator opt-out via comments |
| nginx security headers (R6) | Configuration change | Add to serverside/nginx/nginx.conf |
| Access control audit (R7) | Code audit + targeted code patches | Verify pre-handler presence on every admin/mutating route; apply minimal additions where missing |
| Injection hardening (R8) | Code audit + targeted code patches | Audit Mongoose query construction and Joi schema rejection of operator-prefixed keys |
| Security testing infrastructure (R9) | New file creation | Create test/security/ suite directory with five test modules |

### 0.5.2 Per-Vulnerability Fix Specifications

**For dependency vulnerabilities (R1):**

For each Critical or High dependency CVE discovered by `npm audit`, the fix is:

- "Upgrade `[package]` from `[current]` to `[patched]` version `[specific version]`"
- Justification: `[security advisory link from npm/GitHub Advisory Database/Snyk]`
- Side effects: Verified by full regression test suite (`npm test`), Supertest API tests, and smoke tests; per Risk Management mitigation: "upgrade one package at a time, run full regression suite per upgrade, maintain rollback tag"

For `request@^2.51.0` (deprecated, no security patches):

- "Replace `request@^2.51.0` with `axios@^1.x` (or native `https` module) in `lib/util/recaptcha.js`"
- Justification: Per `package.json` line 59 `"request": "^2.51.0"` and user directive: "deprecated, no security patches"
- Side effects: `lib/util/recaptcha.js` `verify()` callback signature unchanged; downstream callers in `lib/controllers/users.js` and `lib/controllers/trinket.js` see identical interface
- Modified files: `package.json` (replace `request` with `axios`), `package-lock.json` (regenerate), `lib/util/recaptcha.js` (\~20 lines)

**For code vulnerabilities (R2 — Cryptographic Hardening):**

- **MD5 → SHA-256 in course invitation tokens:** "Apply targeted fix to `lib/models/courseInvitation.js` line 37 by replacing `crypto.createHash('md5')` with `crypto.createHash('sha256')` and preserving the `.substring(0, 8)` truncation for URL backward compatibility"
- `app.mail.secret` **boot guard:** "Implement a configuration boot-time validation in `app.js` after lines 50–66 that warns when `config.app.mail.secret` is shorter than 32 characters or absent (parallel to existing session password guard)"
- **SHA-1 annotation:** "Apply inline `// SECURITY: SHA-1 used as deterministic identifier hash, not for confidentiality` comments at `lib/models/trinket.js` lines 117, 120, 177; `lib/util/file.js` content hash; `lib/workers/exports.js` filename hash"
- Rationale: Per OWASP A02 Cryptographic Failures and §6.4.4.1.1 — MD5 is collision-vulnerable; SHA-256 is the OWASP-recommended baseline for non-AEAD identifier hashing; SHA-1 use as deterministic identifier (not confidentiality primitive) is acceptable with explicit annotation

**For code vulnerabilities (R3 — reCAPTCHA Fail-Closed Posture):**

- "Apply targeted fix to `lib/util/recaptcha.js` lines 6–9 by adding a `log.warn()` call when `!config.app.recaptcha || !config.app.recaptcha.secretkey` is true; preserve `cb({ success: true })` short-circuit for graceful degradation"
- "Update `config/default.yaml` to add an explicit `# SECURITY: reCAPTCHA disabled when secretkey is empty - human verification will fail-open with warning log` comment near the `recaptcha:` block"
- Rationale: Per user directive: "add a configuration warning log and document the security implication clearly in `config/default.yaml`"; preserves graceful-degradation semantics per §5.4.6 and the user's "reCAPTCHA absent → fail-open preserved (with warning)" Phase validation directive

**For code vulnerabilities (R4 — HTTP Security Header Hardening):**

- "Apply targeted fix to `app.js` lines 152–198 `onPreResponse` extension by adding three new headers to all responses: `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Content-Security-Policy: <restrictive-policy>` (CSP applied selectively to main app pages excluding embed/sandbox paths per §6.4.4.4.4)"
- "Apply targeted fix to `config/default.yaml` `xframeDeny` list to add `/admin/*` paths"
- Rationale: Per OWASP A05 Security Misconfiguration; per §6.4.4.4.1: current header set is incomplete; CSP feasibility analysis per §6.4.4.4.4: "the main app is not the execution sandbox"

**For code vulnerabilities (R5 — CSRF Hardening):**

- "Add `@hapi/crumb` to `package.json` dependencies"
- "Apply targeted fix to `app.js` by registering `@hapi/crumb` plugin alongside existing Yar registration"
- "Apply targeted fix to `config/api_routes.js` by adding `crumb: true` (or per-route configuration) on highest-risk mutating endpoints: `/api/exports`, `/api/users` (password/email change subset), `/api/admin/*`"
- Rationale: Per user's directive: "add per-route CSRF tokens via `@hapi/crumb` for the highest-risk mutating endpoints"; per Risk Management: "scope CSRF token addition to non-SPA routes first; coordinate SPA integration as a follow-on"

**For code vulnerabilities (R7 — Access Control):**

- "Audit `config/api_routes.js` to verify every `/api/admin/*` route carries `pre: ['isAdmin(user)']`; apply targeted addition where missing"
- "Audit `config/api_routes.js` to verify every resource-mutating route carries `pre: ['canEdit(<resource>, user)']`; apply targeted addition where missing"
- "Apply targeted fix to `lib/controllers/users.js` `downloadExport` to ensure ownership comparison is `exportRecord._owner.toString() === userId.toString()` (strict `===` after `.toString()`); add inline `// SECURITY: strict ownership comparison prevents IDOR`"
- "Audit `lib/controllers/admin.js` `loginAs`/`logoutAs` to verify non-admin users cannot invoke; verify `_realUserId` is never exposed in API responses or Nunjucks templates (search `lib/views/` for `_realUserId` references)"
- Rationale: Per OWASP A01 Broken Access Control; per §6.4.3.3 ownership check pattern; per user's audit directives

**For code vulnerabilities (R8 — Injection Hardening):**

- "Audit `lib/controllers/*.js` Mongoose query construction. For each `find`, `findOne`, `findById`, `update`, aggregation pipeline, verify user-controlled values pass through Mongoose schema typing (Mongoose ODM provides type-coercion protection); add explicit `String()` or `mongoose.Types.ObjectId()` coercion where Mongoose schema types are ambiguous"
- "Audit `config/api_routes.js` Joi schemas on all mutating routes. Add `.regex(/^[a-zA-Z0-9...]+$/)` or schema-typed Joi rules to reject `$where`, `$regex`, and operator-prefixed keys; add `Joi.object()` with explicit known-keys whitelisting where dynamic key values are not required"
- "Audit `lib/views/*.html` Nunjucks templates. Verify auto-escape is globally enabled in `lib/util/nunjucks.js`; replace any `| safe` filter applied to user-controlled data with explicit `| e` escaping or refactor to use known-safe context"
- Rationale: Per OWASP A03 Injection; per §6.4.6.2 input validation controls

**For configuration vulnerabilities (R6 — Container Hardening):**

- "Update `Dockerfile` line 2 from `FROM node:16-bullseye` to `FROM node:20-bullseye`"

- Security improvement: Eliminates EOL Node 16 OS-layer CVE exposure; aligns with current Node LTS security backflow

- Side effects: Validate `mongoose-schema-extend ~0.2.2` Node 20 compatibility per Risk Management mitigation; rebuild bcrypt native bindings; verify `gleak` no-op fallback still active

- "Update `serverside/docker-compose.yml` shell service definitions to make hardening directives default-enabled rather than commented:

  - `mem_limit: 500m`
  - `mem_reservation: 375m`
  - `cpus: 1.0`
  - `cpu_shares: 512`
  - `pids_limit: 50`
  - `read_only: true`
  - `tmpfs: /tmp:size=100m`
  - `security_opt: [no-new-privileges:true]`
  - `cap_drop: [ALL]`"

- Security improvement: Default-on hardening reduces zero-day exploitation surface for untrusted learner code; operator can opt out by removing directive

- Side effects: Validate compatibility with shell session writes (Python `/tmp/sessions`, Java `/tmp/sessions`, R `/tmp/sessions` mounted volumes); verify `tmpfs` size cap accommodates expected session data

- "Update `serverside/nginx/nginx.conf` to add `server_tokens off;` and `add_header X-Content-Type-Options nosniff;` directives"

- Security improvement: Removes server version disclosure; prevents MIME-type sniffing on generated assets

### 0.5.3 Dependency Replacement Analysis

**Per the user directive when proposing replacement, the following must be exhaustively documented:**

**Replacement:** `request@^2.51.0` **→** `axios@^1.x` **(or native** `https`**)**

- **Why replacement:** No security patch available for `request` (deprecated upstream); package is unmaintained; `axios` is actively maintained with regular security releases
- **Compatibility analysis:** Hapi 20 does not depend on `request` directly; the only project use is `lib/util/recaptcha.js` POST to `https://www.google.com/recaptcha/api/siteverify`; both `axios` and native `https` support form-encoded POST
- **API differences requiring code changes:**
  - `request.post({url, form: {secret, response}}, (err, response, body) => {...})` → `axios.post(url, querystring.stringify({secret, response}), {headers: {'Content-Type': 'application/x-www-form-urlencoded'}}).then(response => {...}).catch(err => {...})`
  - Or with native `https`: explicit `https.request()` with `form-urlencoded` body construction and chunked response collection
- **Performance or feature trade-offs:** None material; both options handle the single Google reCAPTCHA POST adequately
- **Full replacement scope:**
  - **All import statements requiring updates:** 1 file — `lib/util/recaptcha.js` line 1 (`var request = require('request')` → `var axios = require('axios')`)
  - **All function calls needing modification:** 1 — `request.post(...)` callback inside `module.exports.verify`
  - **All configuration files requiring changes:** 1 — `package.json` (remove `request`, add `axios`)
  - **All test files needing updates:** 0 — `lib/util/recaptcha.js` is not directly stubbed in `test/helpers/`; the `recaptcha` validator field is bypassed via Joi config-conditional rule (per §7.9.5) and the `defaults.recaptcha` fixture (per §6.6.2.6) — no test signature change required

**Replacement:** `nodemailer@^2.5.0` **→** `nodemailer@^6.x`

- **Why replacement:** v2 in EOL; v6 receives security patches
- **Compatibility analysis:** Major version upgrade with breaking API changes
- **API differences requiring code changes:**
  - `nodemailer.createTransport(transportName, options)` → `nodemailer.createTransport(options)` (transport pluggable interface changed)
  - `transport.sendMail(mailOptions, callback)` → `transport.sendMail(mailOptions)` returning Promise (or callback still supported)
- **Performance or feature trade-offs:** v6 supports OAuth2, modern TLS, larger attachment streaming
- **Full replacement scope:**
  - **All import statements requiring updates:** 1 file — `lib/util/mailer.js`
  - **All function calls needing modification:** `createTransport()` call signature
  - **All configuration files requiring changes:** Possible `local.example.yaml` `app.mail` block adjustment if transport name changed; verify against existing `app.mail` shape
  - **All test files needing updates:** `test/helpers/mail.js` stubs `mailer.send` returning `Q.resolve()` — preserves abstraction; no signature change required because `mailer.send` is the project-level wrapper, not `transport.sendMail` directly

**Replacement:** `aws-sdk@^2.1.20` **(v2) →** `@aws-sdk/*` **(v3 modular)**

- **Why replacement:** v2 in maintenance mode per AWS announcement; v3 is current
- **Compatibility analysis:** **HIGH migration complexity** — every S3 call site touched
- **API differences requiring code changes:** Significant — v3 uses command pattern (`PutObjectCommand`), per-service modular imports, async/await throughout; v2 method-chain style replaced
- **Per Minimal Change Clause:** **Defer v3 migration unless v2.1.20 has unmitigated CVEs.** First step: identify any v2.x patch level that resolves all v2 Critical/High CVEs and pin to that. v3 migration is out of scope under Minimal Change Clause unless required by CVE absence in v2.

**Replacement:** `bull@^0.7.0` **→** `bull@^4.x`

- **Why replacement:** v0.7 EOL; v4.x receives security patches
- **Compatibility analysis:** Major version upgrade; breaking API changes
- **Full replacement scope:**
  - **All import statements requiring updates:** `lib/util/queues.js`, `lib/workers/exports.js`
  - **All function calls needing modification:** Queue construction, `queue.add()`, `queue.process()`, event listeners
  - **All configuration files requiring changes:** None
  - **All test files needing updates:** `test/helpers/queue.js` stubs `snapshotQueue.add`; preserve abstraction

### 0.5.4 Security Improvement Validation

For each fix, the validation method follows this template:

**MD5 → SHA-256 in invitation tokens:**

- **How fix eliminates the vulnerability:** SHA-256 is collision-resistant; even though invitation token security relies on accompanying authorization checks (per §6.4.4.1.1), eliminating MD5 closes a known cryptographic weakness and aligns with OWASP A02
- **Verification method:** Code review (verify line 37 substitution), unit test (verify token format remains 8 hex chars), security scan (verify `eslint-plugin-security` no longer flags MD5 use)

**reCAPTCHA fail-closed warning:**

- **How fix eliminates the vulnerability:** Operators get explicit visibility that signup/reset/email-verify is unprotected; closes the silent-failure risk
- **Verification method:** Code review (verify warning log added), integration test (boot with `recaptcha: {}` and assert log message)

**HTTP security headers:**

- **How fix eliminates the vulnerability:** CSP mitigates XSS by restricting script sources; X-Content-Type-Options blocks MIME-sniffing; Referrer-Policy reduces information leakage; X-Frame-Options on `/admin/*` blocks clickjacking
- **Verification method:** Code review, integration test asserting headers on response, OWASP ZAP baseline scan re-run showing reduced finding count

**CSRF synchronizer tokens:**

- **How fix eliminates the vulnerability:** Per-request CSRF token in cookie + header/body that attacker cannot forge cross-origin
- **Verification method:** Integration test in `test/security/auth.test.js` verifying state-mutating routes reject requests without valid CSRF token

**EOL Node 16 → Node 20:**

- **How fix eliminates the vulnerability:** Eliminates accumulated OS-layer Bullseye/Node CVEs no longer receiving Node 16 security backports
- **Verification method:** Trivy image scan showing reduced CVE count; `npm test` regression suite passes; smoke test passes

**Shell container hardening defaults:**

- **How fix eliminates the vulnerability:** Memory/PID/CPU limits prevent DoS; read-only root filesystem prevents tamper; `no-new-privileges` blocks setuid escalation; `cap-drop=ALL` removes Linux capability surface
- **Verification method:** Docker container inspection (`docker inspect <shell>` showing security options), runtime test of fork-bomb mitigation, integration test of actual learner code execution under hardened container

**Rollback plan if issues arise (per Risk Management):**

- "Tag codebase before remediation begins: `git tag pre-security-remediation-20260429`"
- "Maintain `package-lock.json` snapshot pre-upgrade: `cp package-lock.json package-lock.baseline.json`"
- "Revert immediately if any regression test suite gate fails; do not stack fixes on a failing baseline"
- Atomic commit pattern: "Commit remediation in atomic units (one CVE or vulnerability class per commit) with message format: `security: [severity] fix [description] in [file]`"

## 0.6 File Transformation Mapping

### 0.6.1 File-by-File Security Fix Plan

CRITICAL: The transformation table below maps EVERY file to be created, updated, or deleted, with target file listed first. The transformation modes are:

- **UPDATE** — Update an existing file to patch vulnerability
- **CREATE** — Create a new file for security improvement
- **DELETE** — Remove a file that introduces vulnerability
- **REFERENCE** — Use as an example for security patterns

| Target File | Transformation | Source File/Reference | Security Changes |
| --- | --- | --- | --- |
| package.json | UPDATE | package.json | Upgrade vulnerable npm dependencies to patched versions per npm audit Phase 1 scan; replace request@^2.51.0 with axios@^1.x (or remove if native https chosen); pin upgraded versions with exact semver; add @hapi/crumb@^9.x for CSRF; add eslint-plugin-security@^1.x and eslint@^8.x to devDependencies |
| package-lock.json | UPDATE | package-lock.json | Regenerate via npm ci --legacy-peer-deps post-upgrade; preserve package-lock.baseline.json snapshot per Risk Management rollback strategy |
| serverside/python/manager/package.json | UPDATE | serverside/python/manager/package.json | Upgrade Critical/High CVE-bearing dependencies (config@^3.3.12, file-type@^18.0.0, is-svg@^4.3.2, socket.io@^4.8.0, socket.io-client@^4.8.0) per npm audit Phase 1 scan against Node 18 manager runtime |
| serverside/r/manager/package.json | UPDATE | serverside/r/manager/package.json | Upgrade Critical/High CVE-bearing dependencies per Node 18 manager npm audit Phase 1 scan |
| serverside/java/manager/package.json | UPDATE | serverside/java/manager/package.json | Upgrade Critical/High CVE-bearing dependencies per Node 18 manager npm audit Phase 1 scan |
| serverside/pygame/manager/package.json | UPDATE | serverside/pygame/manager/package.json | Upgrade Critical/High CVE-bearing dependencies per Node 18 manager npm audit Phase 1 scan |
| serverside/python/shell/requirements.txt | UPDATE | serverside/python/shell/requirements.txt | Apply Trivy-identified Python package patch updates for Critical/High CVEs (e.g., numpy, scipy, matplotlib, pandas, mysql-connector-python) — only if directly implicated per Minimal Change Clause |
| serverside/pygame/worker/requirements.txt | UPDATE | serverside/pygame/worker/requirements.txt | Apply Trivy-identified Python package patch updates for Critical/High CVEs |
| Dockerfile | UPDATE | Dockerfile | Update base image line 2 from FROM node:16-bullseye to FROM node:20-bullseye (LTS); validate mongoose-schema-extend ~0.2.2 Node 20 compatibility per Risk Management |
| serverside/nginx/Dockerfile | UPDATE | serverside/nginx/Dockerfile | Audit and patch base image if Critical/High OS-layer CVEs identified by Trivy |
| serverside/python/shell/Dockerfile | UPDATE | serverside/python/shell/Dockerfile | Audit base image; preserve python:3.10-bullseye unless Critical/High OS CVEs |
| serverside/python/manager/Dockerfile | UPDATE | serverside/python/manager/Dockerfile | Audit base image |
| serverside/java/shell/Dockerfile | UPDATE | serverside/java/shell/Dockerfile | Audit base image (amazoncorretto:8) |
| serverside/java/manager/Dockerfile | UPDATE | serverside/java/manager/Dockerfile | Audit base image |
| serverside/r/shell/Dockerfile | UPDATE | serverside/r/shell/Dockerfile | Audit base image (r-base:4.4.2) |
| serverside/r/manager/Dockerfile | UPDATE | serverside/r/manager/Dockerfile | Audit base image |
| serverside/pygame/worker/Dockerfile | UPDATE | serverside/pygame/worker/Dockerfile | Audit base image |
| serverside/pygame/manager/Dockerfile | UPDATE | serverside/pygame/manager/Dockerfile | Audit base image |
| serverside/docker-compose.yml | UPDATE | serverside/docker-compose.yml | Promote shell hardening directives from comments to defaults: mem_limit: 500m, mem_reservation: 375m, cpus: 1.0, cpu_shares: 512, pids_limit: 50, read_only: true, tmpfs: /tmp:size=100m, security_opt: [no-new-privileges:true], cap_drop: [ALL] on every shell service (python3-shell, java-shell, r-shell, pygame-worker); preserve operator opt-out via comments |
| docker-compose.yml | UPDATE | docker-compose.yml | Audit main app/MongoDB/Redis container hardening; apply read_only where compatible with PM2 logs; verify network isolation |
| serverside/nginx/nginx.conf | UPDATE | serverside/nginx/nginx.conf | Add server_tokens off; directive; add add_header X-Content-Type-Options nosniff always; to WebSocket proxy responses and /{lang}-generated/ static routes |
| app.js | UPDATE | app.js | (1) Add mail.secret boot guard after lines 50–66 paralleling existing 32-char session password guard; (2) Add CSP, X-Content-Type-Options, Referrer-Policy headers in onPreResponse extension lines 152–198; (3) Register @hapi/crumb plugin alongside Yar registration lines 90–111; (4) Verify isSecure flag propagation behind reverse proxy via X-Forwarded-Proto trust at lines 204–240; preserve // SECURITY: [threat addressed] annotations on every changed line |
| lib/util/recaptcha.js | UPDATE | lib/util/recaptcha.js | (1) Replace var request = require('request') with var axios = require('axios') (or native https); (2) Modify lines 6–9 to add log.warn('SECURITY: reCAPTCHA disabled - human verification will fail-open') before the short-circuit cb({success: true}); preserve fail-open behavior per graceful-degradation directive; annotate with // SECURITY: fail-open preserved with operator warning |
| lib/models/courseInvitation.js | UPDATE | lib/models/courseInvitation.js | Replace MD5 with SHA-256 at line 37: crypto.createHash("md5") → crypto.createHash("sha256"); preserve .substring(0, 8) truncation for invitation URL backward compatibility; annotate // SECURITY: SHA-256 replaces MD5 to mitigate cryptographic weakness (OWASP A02) |
| lib/models/trinket.js | UPDATE | lib/models/trinket.js | Annotate SHA-1 use at lines 117, 120, 177 with // SECURITY: SHA-1 used as deterministic identifier hash (shortCode), not for confidentiality - acceptable per §6.4.4.1.1; no functional change |
| lib/util/file.js | UPDATE | lib/util/file.js | Annotate SHA-1 use in file content hashing with // SECURITY: SHA-1 used as content identifier hash, not for confidentiality; no functional change |
| lib/workers/exports.js | UPDATE | lib/workers/exports.js | Annotate SHA-1 use in export filename generation with // SECURITY: SHA-1 used as deterministic export filename identifier, not for confidentiality; no functional change |
| lib/controllers/trinket.js | UPDATE | lib/controllers/trinket.js | Audit JWT HS256 issuance; verify app.mail.secret is read from configured value (boot guard added in app.js); add inline annotation // SECURITY: HS256 secret validated at boot for minimum entropy near JWT issuance |
| lib/util/helpers.js | UPDATE | lib/util/helpers.js | Audit verifyEmailToken JWT verification; verify error path returns Boom.forbidden() rather than leaking JWT error details; add // SECURITY: annotation near jwt.verify call |
| lib/controllers/users.js | UPDATE | lib/controllers/users.js | (1) Audit downloadExport ownership comparison: ensure exportRecord._owner.toString() === userId.toString() strict equality; annotate // SECURITY: strict ownership comparison prevents IDOR per §6.4.3.3; (2) Audit sendPassReset enumeration defense (already returns uniform success per §6.4.4.3); annotate // SECURITY: uniform response prevents email enumeration; (3) Audit signup error response — distinguish duplicate email vs. duplicate username messages may leak account existence (per user's Medium classification); apply targeted fix to merge response into uniform error message; annotate // SECURITY: uniform error prevents account enumeration |
| lib/controllers/admin.js | UPDATE | lib/controllers/admin.js | Audit loginAs/logoutAs impersonation flow; verify pre: ['isAdmin(user)'] on every admin route; verify _realUserId is never returned in API responses (search for _realUserId references); add // SECURITY: annotations near impersonation entry points |
| lib/auth/passport.js | UPDATE | lib/auth/passport.js | Audit Google OAuth callback CSRF state parameter validation; verify the state parameter is generated server-side, stored in session, and validated on callback; add inline // SECURITY: OAuth state parameter prevents CSRF annotation; verify disabled-account two-tier enforcement (Passport deserializeUser + session scheme) is intact per §6.4.2.1.4 |
| lib/util/nunjucks.js | UPDATE | lib/util/nunjucks.js | Audit Nunjucks environment construction; verify autoescape: true is set; if not currently set, enable explicitly with // SECURITY: enable auto-escape on all templates to prevent server-side XSS; preserve existing filter registrations |
| lib/views/*.html (Nunjucks templates - audit) | UPDATE | lib/views/*.html | Audit every template for \| safe filter usage on user-controlled data; replace with explicit \| e escaping or refactor; per Minimal Change Clause, only modify templates that fail the audit; annotate any retained \| safe use with explicit // SECURITY: safe filter applied to known-safe context (e.g., admin-set HTML) |
| config/api_routes.js | UPDATE | config/api_routes.js | (1) Audit Joi schemas on all mutating routes for explicit rejection of $where, $regex, operator-prefixed keys; add Joi.object() known-keys whitelisting where dynamic key values are not required; (2) Add pre: ['isAdmin(user)'] to any /api/admin/* route missing it; (3) Add pre: ['canEdit(<resource>, user)'] to any resource-mutating route missing it; (4) Apply crumb: true (or per-route configuration) on highest-risk mutating endpoints /api/exports, /api/users (password/email change), /api/admin/*; annotate each addition with // SECURITY: [threat addressed] |
| config/routes.js | UPDATE | config/routes.js | Audit page-route Joi schemas; verify /admin/{adminPage*} routes have pre: ['isAdmin(user)']; apply crumb: true selectively to non-SPA mutating routes |
| config/default.yaml | UPDATE | config/default.yaml | (1) Extend app.xframeDeny list to cover /admin, /admin/* paths; (2) Add explicit # SECURITY: reCAPTCHA disabled when secretkey is empty - human verification will fail-open with warning log comment near recaptcha: block; (3) Preserve sandbox permissions (no allow-same-origin); (4) Add # SECURITY: app.mail.secret should be ≥32 characters; boot guard enforces this comment near mail: block |
| config/local.example.yaml | UPDATE | config/local.example.yaml | Add documentation comment for app.mail.secret minimum length; preserve existing structure; annotate with # SECURITY: ≥32 characters required by boot guard |
| lib/util/queues.js | UPDATE | lib/util/queues.js | Audit Bull queue construction; if bull upgraded to v4.x major, modify queue factory to v4 API while preserving InMemoryQueue and NoOpQueue fallback contract per user's frozen-interface directive; annotate with // SECURITY: bull upgrade preserves fallback contract |
| lib/util/mailer.js | UPDATE | lib/util/mailer.js | Audit nodemailer upgrade impact; if nodemailer upgraded to v6, modify createTransport call signature; preserve mailer.send() wrapper API per test/helpers/mail.js stub contract; annotate with // SECURITY: nodemailer upgrade preserves send() wrapper contract |
| config/aws.js | UPDATE | config/aws.js | Audit aws-sdk upgrade impact; if upgraded, adjust SDK construction; per Minimal Change Clause, prefer in-major-version patch over v3 migration |
| lib/auth/passport.js (passport upgrade) | UPDATE | lib/auth/passport.js | If passport upgraded from ~0.2.0 to ^0.7.x, audit LocalStrategy, GoogleStrategy registration; preserve disabled-account deserializeUser check; preserve session-fixation defense pattern |
| lib/workers/exports.js (bull upgrade) | UPDATE | lib/workers/exports.js | If bull upgraded to v4.x, modify queue consumer registration; preserve EXPORT_EXPIRY_DAYS = 3 constant and SHA-1 filename annotation |
| test/security/auth.test.js | CREATE | test/lib/api/login.js, test/lib/api/registration.js, test/lib/api/forgot_pass.js | Authentication bypass attempts (invalid session cookie, expired session, disabled-account enforcement at both Passport and session scheme tiers per §6.4.2.1.4); brute-force scenario validation; Google OAuth callback CSRF state parameter validation; follow existing Mocha + Supertest + Sinon pattern from §6.6.5 |
| test/security/access-control.test.js | CREATE | test/lib/api/admin.js, test/lib/api/course.js, test/lib/api/trinket.js | IDOR attempts on trinket/course/folder/assignment endpoints (User A reading/writing User B's resources); admin route access by non-admin user (302/403/200 matrix per existing admin.js pattern); canEdit bypass attempts; bulk export download ownership enforcement |
| test/security/injection.test.js | CREATE | test/lib/api/trinket.js, test/lib/api/course.js | MongoDB operator injection in search/query parameters ($where, $gt, $regex in request bodies); Mongoose field coercion for user-supplied ObjectId values; Nunjucks template XSS payloads in user-controlled fields (trinket name, description, course title, username) |
| test/security/session.test.js | CREATE | test/lib/api/login.js, test/helpers/flow.js | Session fixation (session ID unchanged after login per §6.4.2.3.4 negative test); concurrent session behavior; yar.reset() verification post-login; sliding TTL enforcement (per §6.4.2.3.3); session cookie flag validation (HttpOnly, SameSite, Secure) |
| test/security/upload.test.js | CREATE | test/lib/api/files.js | File upload with incorrect MIME type (avatar endpoint in lib/util/file.js); oversized payload beyond Hapi route payload.maxBytes; path traversal in filename parameters; preserve existing test/helpers/flow.js uploadFile pattern |
| test/security/index.js | CREATE | test/lib/api/index.js | Sequence aggregator for security test suite following existing test/lib/api/index.js pattern; integrates auth, access-control, injection, session, upload test modules |
| test/helpers/security.js | CREATE | test/helpers/flow.js, test/helpers/store.js, test/helpers/mail.js | Security test helper providing common payload generators (CSRF tokens, malformed ObjectIds, XSS payloads, NoSQL operator injection payloads); follows existing helper stub pattern |
| .github/workflows/security-scan.yml | CREATE | (no existing CI/CD per §6.6.6.1) | Add automated security scanning to CI pipeline: npm audit --audit-level=high against root and each serverside/*/manager/package.json; trivy image --exit-code 1 --severity CRITICAL,HIGH against main app and serverside shell images; ESLint security plugin; weekly OWASP ZAP baseline scan against staging instance |
| .eslintrc.js (or .eslintrc.json) | CREATE | (none currently) | Configure eslint-plugin-security rules; target lib/, config/, serverside/*/manager/ for SAST coverage; exclude public/js/ (frozen AngularJS frontend per ADR-5) |
| .eslintignore | CREATE | (none currently) | Exclude node_modules/, public/components/, public/js/skulpt/, public/js/embed/ (vendored/frozen) from ESLint scan |
| SECURITY.md | CREATE | OWASP best practice; existing CONTRIBUTING.md as structure reference | Document vulnerability disclosure policy; supported version table; reporting channel; expected response time |
| README.md | UPDATE | README.md | Add Security section linking to SECURITY.md and noting the security remediation; document Node 20 base image change |
| CHANGELOG.md | UPDATE | CHANGELOG.md | Add security release entry summarizing changes per version; cross-reference CVEs addressed |
| .dockerignore | UPDATE | .dockerignore | Audit for any secrets exposure paths; ensure *.env, *.local, local.yaml are excluded |

**Wildcard patterns applied carefully:**

- `lib/views/**/*.html` — audit-only pattern; only modify templates that fail Nunjucks `| safe` audit
- `lib/controllers/*.js` — audit-only pattern; only modify controllers with confirmed Mongoose query injection risk
- `lib/models/*.js` — audit-only pattern; only modify models with cryptographic weakness (`courseInvitation.js`, `trinket.js`)
- `serverside/*/manager/package.json` — explicit pattern; all four files updated per Node 18 manager `npm audit`
- `serverside/*/Dockerfile`, `serverside/*/manager/Dockerfile`, `serverside/*/shell/Dockerfile` — audit-only pattern; only modify with Trivy-confirmed Critical/High base image CVEs

**CRITICAL: All affected files comprehensively listed.** Per the Minimal Change Clause and the user's "Note additional security concerns discovered during audit but DO NOT fix unless Critical or High severity" directive, the table above represents the **maximum scope** of remediation. Individual fixes within each transformation are gated on Phase 1 scan findings and severity classification.

### 0.6.2 Code Change Specifications

For each code file update, the per-file change specification follows this template:

**File:** `lib/models/courseInvitation.js`

- Lines affected: line 37 (single substitution)
- Before state: "Currently vulnerable because `crypto.createHash('md5')` produces 128-bit collision-vulnerable digest; user invitation token security relies entirely on accompanying authorization checks"
- After state: "After fix, will use `crypto.createHash('sha256')` producing 256-bit collision-resistant digest, truncated to same 8-character hex output for URL backward compatibility"
- Security improvement: Eliminates MD5 cryptographic weakness (OWASP A02 Cryptographic Failures); aligns with NIST SP 800-131A guidance against MD5 use

**File:** `lib/util/recaptcha.js`

- Lines affected: lines 1, 6–9 (import line + fail-open branch)
- Before state: "Currently vulnerable because `!config.app.recaptcha || !config.app.recaptcha.secretkey` short-circuits silently to `cb({success: true})`, bypassing human verification on signup, password reset, and email verification with no operator visibility"
- After state: "After fix, will log a `WARN`-level message via the global `log` symbol before the short-circuit, preserving fail-open semantics per graceful-degradation directive but giving operators audit visibility"
- Security improvement: Closes silent-failure risk on reCAPTCHA absence (defense-in-depth gap)
- Additional change: Replace `var request = require('request')` with `var axios = require('axios')` and adapt POST call signature per dependency replacement

**File:** `app.js`

- Lines affected: lines 50–66 (existing session password guard — pattern reference); new \~10 lines for `mail.secret` guard; lines 90–111 (Yar registration — add `@hapi/crumb` registration); lines 152–198 (`onPreResponse` — add CSP, X-Content-Type-Options, Referrer-Policy)
- Before state: "Currently vulnerable because (1) `app.mail.secret` has no boot-time validation — empty/weak secret would make JWT email tokens forgeable; (2) `onPreResponse` extension emits only `Cache-Control`, `Pragma`, `Expires`, conditional `X-Frame-Options: deny` — missing CSP, X-Content-Type-Options, Referrer-Policy; (3) no CSRF synchronizer-token middleware registered"
- After state: "After fix, will (1) refuse boot when `app.mail.secret` &lt; 32 chars (paralleling session password guard); (2) emit CSP, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin on all responses (CSP scoped to main app pages excluding embed/sandbox per §6.4.4.4.4); (3) register `@hapi/crumb` plugin"
- Security improvement: Closes JWT token forgery risk (R2); adds defense-in-depth header layer (R4); enables CSRF synchronizer-token protection (R5)

**File:** `serverside/docker-compose.yml`

- Lines affected: every shell service block (`python3-shell`, `java-shell`, `r-shell`, `pygame-worker`)
- Before state: "Currently vulnerable because shell containers executing untrusted learner code ship with all hardening directives commented out as `# Production security options (uncomment for hardened deployment):` — operators must explicitly opt in to defense"
- After state: "After fix, will ship with `mem_limit: 500m`, `mem_reservation: 375m`, `cpus: 1.0`, `cpu_shares: 512`, `pids_limit: 50`, `read_only: true`, `tmpfs: /tmp:size=100m`, `security_opt: [no-new-privileges:true]`, `cap_drop: [ALL]` enabled by default; operators retain opt-out via comment-and-remove"
- Security improvement: Default-on hardening for adversarial-zone shell containers per §6.4.5; eliminates fork-bomb / memory-exhaustion / setuid-escalation surface

**File:** `Dockerfile`

- Lines affected: line 2
- Before state: "Currently vulnerable because `FROM node:16-bullseye` references EOL Node 16 LTS line (end-of-life September 2023); accumulating Bullseye glibc/openssl/OS CVEs no longer receive Node 16 security backports"
- After state: "After fix, will use `FROM node:20-bullseye` (current Node LTS); inherits ongoing security patches"
- Security improvement: Eliminates EOL Node 16 OS-layer CVE accumulation
- Side effects: Requires regression validation per Risk Management mitigation; rebuild bcrypt native bindings; verify `mongoose-schema-extend ~0.2.2` Node 20 compatibility

### 0.6.3 Configuration Change Specifications

For each config file update:

**File:** `config/default.yaml`

- Setting: `app.xframeDeny`

- Current value: `['/', '/login', '/signup', '/contact', '/educators']`

- New value: `['/', '/login', '/signup', '/contact', '/educators', '/admin', '/admin/*']` (or equivalent path-prefix expression supported by the route matcher)

- Security rationale: Per OWASP A05; per user audit directive: "verify `/admin/*` routes are also covered" — admin pages must not be embeddable in attacker-controlled frames

- Setting: `app.recaptcha` (documentation only — no value change)

- Added comment: `# SECURITY: reCAPTCHA disabled when secretkey is empty - human verification will fail-open with warning log per lib/util/recaptcha.js`

- Security rationale: Per user directive: "document the security implication clearly in `config/default.yaml`"

**File:** `serverside/nginx/nginx.conf`

- Setting: `server_tokens`

- Current value: (default `on`)

- New value: `server_tokens off;`

- Security rationale: Removes nginx version disclosure (defense-in-depth; reduces fingerprinting)

- Setting: `add_header X-Content-Type-Options`

- Current value: (not present)

- New value: `add_header X-Content-Type-Options nosniff always;` on WebSocket proxy responses and `/{lang}-generated/` static routes

- Security rationale: Prevents MIME-sniffing on generated assets which may be user-controlled (Python plot images, R-rendered files)

**File:** `serverside/docker-compose.yml`

- Setting: shell service hardening directives (per service: `python3-shell`, `java-shell`, `r-shell`, `pygame-worker`)
- Current value: All commented out under `# Production security options (uncomment for hardened deployment):`
- New value: Active with documented defaults: `mem_limit: 500m`, `mem_reservation: 375m`, `cpus: 1.0`, `cpu_shares: 512`, `pids_limit: 50`, `read_only: true`, `tmpfs: /tmp:size=100m`, `security_opt: [no-new-privileges:true]`, `cap_drop: [ALL]`
- Security rationale: Per user directive: "operators can opt out but hardening must be the default posture for an educational platform executing untrusted learner code"; aligns with §6.4.5 adversarial-zone treatment

## 0.7 Dependency Inventory

### 0.7.1 Security Patches and Updates

The dependency upgrade matrix below captures the **upgrade-path framework** for each package historically pinned at a CVE-bearing version. Specific patched versions, CVE numbers, and severity levels will be populated during Phase 1 scanning by `npm audit`, Trivy, and the Vulnerability Discovery Report (Deliverable #1) using exact names and versions from npm Advisory Database, GitHub Security Advisories, and Snyk Vulnerability DB.

**Root** `package.json` **(Node 16 main app — independent dependency tree per user directive):**

| Registry | Package Name | Current | Patched To | CVE/Advisory | Severity |
| --- | --- | --- | --- | --- | --- |
| npm | request | ^2.51.0 | REPLACE with axios@^1.x (or native https) | Package deprecated; no security patches available; assess Snyk advisories on transitive tough-cookie, form-data | High |
| npm | passport | ~0.2.0 | Latest patched per npm audit (likely ^0.7.x) | TBD per Phase 1 scan | TBD |
| npm | passport-google-oauth | ^0.1.5 | Latest patched | TBD | TBD |
| npm | passport-local | ~1.0.0 | Latest patched | TBD | TBD |
| npm | passport-strategy | ~1.0.0 | Latest patched | TBD | TBD |
| npm | nodemailer | ^2.5.0 | Latest patched (likely ^6.x major upgrade) | TBD per Phase 1 scan | TBD |
| npm | bull | ^0.7.0 | Latest patched (likely ^4.x or bullmq@^5.x migration) | TBD | TBD |
| npm | aws-sdk | ^2.1.20 | Latest patched v2 (v3 migration deferred per Minimal Change Clause) | TBD; per AWS announcement, v2 in maintenance mode | TBD |
| npm | config | ~0.4.35 | Latest v0.4.x patched (or v3.3.x migration if Critical CVE forces) | TBD | TBD |
| npm | mime | ~1.2.11 | Latest v1.x patched | TBD | TBD |
| npm | mkdirp | ~0.3.5 | Latest v0.x patched | TBD | TBD |
| npm | q | ~1.0.0 | Latest v1.x patched | TBD | TBD |
| npm | js-yaml | ~3.0.1 | Latest v3.x patched | CVE-2013-4660 and similar applicable to v3.x; confirm Phase 1 scan | TBD |
| npm | mongoose | ^6.0.0 | Latest v6.x patched | TBD per Phase 1 scan | TBD |
| npm | mongoose-schema-extend | ~0.2.2 | NO PATCH — flagged deprecated per §3.2.3, ADR-8; document residual risk | Package deprecated | Medium (residual) |
| npm | node-cryptojs-aes | ^0.4.0 | Latest patched | TBD per Phase 1 scan | TBD |
| npm | jsonwebtoken | ^5.0.5 | Latest v5.x patched OR ^9.x migration | CVE-2022-23529, CVE-2022-23541 apply to v5.x | High |
| npm | validator | ^5.6.0 | Latest v5.x patched OR ^13.x migration | TBD | TBD |
| npm | lodash | ^4.17.21 | Already at latest patch as of pinned baseline | CVE-2021-23337 resolved at 4.17.21 | Resolved |
| npm | bcrypt | ^5.1.0 | Latest v5.x patched | TBD; bcrypt has good track record | Likely Low |
| npm | redis | ^4.0.0 | Latest v4.x patched | TBD | TBD |
| npm | archiver | ^2.0.0 | Latest v2.x patched OR major upgrade | TBD | TBD |
| npm | marked | git+https://github.com/trinketapp/marked.git | Audit Trinket-maintained fork against upstream marked CVEs | Trinket-maintained fork; assess upstream patches | TBD |
| npm | winston | ^3.8.0 | Latest v3.x patched | TBD | TBD |

**Add to** `package.json` **(new direct dependencies):**

| Registry | Package Name | Version | Purpose |
| --- | --- | --- | --- |
| npm | @hapi/crumb | ^9.x (Hapi 20 compatible) | CSRF synchronizer-token middleware (R5) |
| npm | axios | ^1.x | Replacement for deprecated request (R1) — if axios chosen over native https |
| npm | eslint | ^8.x | JavaScript SAST linting (R9) — devDependency |
| npm | eslint-plugin-security | ^1.x | Security-focused ESLint rules (R9) — devDependency |

**Serverside Node 18 manager** `package.json` **files (independent dependency tree per user directive):**

| File | Registry | Package Name | Current | Patched To | Severity |
| --- | --- | --- | --- | --- | --- |
| serverside/python/manager/package.json | npm | config | ^3.3.12 | Latest v3.x patched | TBD |
| serverside/python/manager/package.json | npm | file-type | ^18.0.0 | Latest patched | TBD |
| serverside/python/manager/package.json | npm | is-svg | ^4.3.2 | Latest patched | TBD |
| serverside/python/manager/package.json | npm | socket.io | ^4.8.0 | Latest v4.x patched | TBD |
| serverside/python/manager/package.json | npm | socket.io-client | ^4.8.0 | Latest v4.x patched | TBD |
| serverside/r/manager/package.json | npm | config | ^3.3.12 | Latest v3.x patched | TBD |
| serverside/r/manager/package.json | npm | file-type | ^18.0.0 | Latest patched | TBD |
| serverside/r/manager/package.json | npm | socket.io | ^4.8.0 | Latest v4.x patched | TBD |
| serverside/r/manager/package.json | npm | socket.io-client | ^4.8.0 | Latest v4.x patched | TBD |
| serverside/java/manager/package.json | npm | config | ^3.3.12 | Latest v3.x patched | TBD |
| serverside/java/manager/package.json | npm | file-type | ^18.0.0 | Latest patched | TBD |
| serverside/java/manager/package.json | npm | socket.io | ^4.8.0 | Latest v4.x patched | TBD |
| serverside/java/manager/package.json | npm | socket.io-client | ^4.8.0 | Latest v4.x patched | TBD |
| serverside/pygame/manager/package.json | npm | config | ^3.3.9 | Latest v3.x patched | TBD |
| serverside/pygame/manager/package.json | npm | file-type | ^19.0.0 | Latest patched | TBD |
| serverside/pygame/manager/package.json | npm | is-svg | ^5.0.0 | Latest patched | TBD |
| serverside/pygame/manager/package.json | npm | socket.io | ^4.7.4 | Latest v4.x patched | TBD |
| serverside/pygame/manager/package.json | npm | socket.io-client | ^4.7.4 | Latest v4.x patched | TBD |

**Vendored frontend assets (CDN/bundled — per Frontend Freeze Directive):**

| Source | Asset | Current Version | Action | Rationale |
| --- | --- | --- | --- | --- |
| CDN (config/default.yaml) | AngularJS | 1.3.20 | DOCUMENT CVEs ONLY | Frozen per ADR-5; "do not upgrade AngularJS" per user directive |
| CDN | jQuery | 2.2.4 | Document CVEs; assess sandbox-context exploitability; upgrade only if exploitable | Per user: "upgrade only where exploitable given Trinket's sandbox attribute configuration" |
| CDN | Ace Editor | v1.2.6.1rc2 | Document CVEs; assess sandbox-context exploitability; upgrade only if exploitable | Per user directive |
| public/components/ | Skulpt | 0.11.1.34 (Trinket fork) | Audit upstream Skulpt for security patches; assess fork applicability | Per user directive on vendored assets |
| public/components/ | Blockly | v20211018 (Trinket fork) | Audit upstream Blockly | Per user directive |
| public/components/ | GlowScript | 2.7.5 (Trinket fork) | Audit upstream GlowScript | Per user directive |
| CDN | Foundation | 5.5.3.1 | Document CVEs | Frontend asset |
| CDN | CryptoJS AES | 3.1.2 | Document CVEs; companion to node-cryptojs-aes server-side | Frontend asset |

**OS-layer base image upgrades (per Trivy scan):**

| Image | Current | Target | Severity Driver |
| --- | --- | --- | --- |
| Main app | node:16-bullseye | node:20-bullseye | EOL Node 16 LTS; OS CVE accumulation; High |
| Python shell | python:3.10-bullseye | TBD per Trivy scan | TBD |
| Java shell | amazoncorretto:8 | TBD per Trivy scan | TBD |
| R shell | r-base:4.4.2 | TBD per Trivy scan | TBD |
| Pygame worker | Ubuntu base | TBD per Trivy scan | TBD |
| nginx gateway | nginx:alpine | TBD per Trivy scan | TBD |

### 0.7.2 Dependency Chain Analysis

**Direct dependencies requiring updates** (to be confirmed by Phase 1 scan):

- Confirmed candidates: `request` (replacement), `passport` (upgrade), `nodemailer` (upgrade), `bull` (upgrade), `aws-sdk` (patch), `jsonwebtoken` (patch or major), `validator` (patch or major)
- New additions: `@hapi/crumb`, `axios` (or native `https`), `eslint`, `eslint-plugin-security`

**Transitive dependencies affected:**

- `request@^2.51.0` transitive chain — `tough-cookie`, `form-data`, `qs`, `combined-stream`, `mime-types`, `caseless`, etc. All carried at versions consistent with the deprecated `request` major; replacement of `request` removes entire transitive chain
- `aws-sdk@^2.1.20` transitive chain — `xml2js`, `jmespath`, `events`, `uuid`, `ieee754`. Patch within v2 reduces transitive CVE exposure
- `passport@~0.2.0` transitive chain — minimal; mostly `pause` and `connect` middleware

**Peer dependencies to verify:**

- `--legacy-peer-deps` flag in `Dockerfile` line 31 indicates known peer-dependency conflicts; post-upgrade re-verify with explicit `npm ls` to identify any new peer-dep failures

**Development dependencies with vulnerabilities:**

- `mocha@^3.4.1` — pinned at major v3 per §6.6.2.1; modernization deferred per §6.6.12.3 (out of scope for this remediation)
- `chai@^3.5.0`, `chai-as-promised@^6.0.0`, `sinon@~1.7.3` — legacy testing toolchain; out of scope unless Critical/High CVE
- `redis-mock@~0.2.0`, `cheerio@~0.22.0` — out of scope unless directly implicated
- `vite@^4.5.14` — already at recent major; verify v4 security patches

### 0.7.3 Import and Reference Updates

**Source files requiring import updates:**

- **For** `request` **→** `axios` **(or native** `https`**) replacement:**

  - `lib/util/recaptcha.js` line 1 — change `var request = require('request')` to `var axios = require('axios')` (or `var https = require('https')`)
  - **Sole consumer in main app** — verified by `grep` for `require('request')` across `lib/` (only `lib/util/recaptcha.js` consumes it)

- **For** `nodemailer` **v2 → v6 (if migration required):**

  - `lib/util/mailer.js` — `require('nodemailer')` retained; `createTransport()` call signature updated (transport name argument removed in v6+)

- **For** `bull` **v0.7 → v4 (if migration required):**

  - `lib/util/queues.js` — Bull queue construction updated to v4 API
  - `lib/workers/exports.js` — Queue consumer registration updated

- **For** `aws-sdk` **v2 → v3 (deferred per Minimal Change Clause):**

  - **No changes** unless Critical CVE forces v3 migration
  - If forced: `config/aws.js`, `lib/util/file.js` (every S3 call), `lib/workers/exports.js` (S3 PUT for export archive)

- **For** `passport` **v0.2 → v0.7 (if migration required):**

  - `lib/auth/passport.js` — Strategy registration verified; `serializeUser`/`deserializeUser` API preserved

- **For** `jsonwebtoken` **v5 → v9 (if migration required):**

  - `lib/controllers/trinket.js` — `jwt.sign()` call signature audited
  - `lib/util/helpers.js` — `jwt.verify()` call signature audited

**Import transformation rules:**

- **Apply to:** All files matching `lib/**/*.js`, `config/**/*.js`, `serverside/*/manager/**/*.js`
- **Exclude:** `public/js/**` (frozen AngularJS frontend per ADR-5); `public/components/**` (vendored); `node_modules/**`

**Configuration reference updates:**

- `config/local.example.yaml` — verify `app.mail`, `app.recaptcha`, `aws`, `db.redis` configuration shapes match upgraded package APIs
- `config/default.yaml` — same audit; add SECURITY annotation comments per R3 and R4
- Documentation: `README.md`, `GETTING_STARTED.md`, `CONTRIBUTING.md`, `serverside/README.md` — audit references to upgraded packages and Node 20

**Environment variables to verify post-upgrade:**

- No new environment variables required by the security remediation
- Existing variables preserved: `NODE_ENV`, `COMMIT_ID`, `NODE_CONFIG_PERSIST_ON_CHANGE`
- AWS, MongoDB, Redis, SMTP credentials remain in `config/local.yaml` (not env vars) per existing layered YAML pattern

**Documentation updates:**

- `README.md` — Update prerequisites (Node 18+ → Node 20+ for local dev to match container)
- `GETTING_STARTED.md` — Update Docker/local setup instructions for Node 20 base
- `serverside/README.md` — Cross-reference new default-on hardening directives in `serverside/docker-compose.yml` (operators no longer need to manually uncomment)
- `SECURITY.md` (new) — Vulnerability disclosure policy per OWASP best practice
- `CHANGELOG.md` — Security release entry per atomic commit pattern

## 0.8 Impact Analysis and Testing Strategy

### 0.8.1 Security Testing Requirements

**Vulnerability regression tests:**

The `test/security/` suite must verify that each remediated vulnerability is no longer exploitable. The Mocha + Supertest + Sinon test pattern documented in §6.6.5 is the foundation; security tests follow the existing `test/lib/api/` integration-test pattern with the per-suite `module.exports = function() { ... }` shape.

**Specific attack scenarios to test:**

| Test Module | Attack Scenario | Verification |
| --- | --- | --- |
| test/security/auth.test.js | Invalid session cookie (tampered payload) | Server returns 401, redirects to /login |
| test/security/auth.test.js | Expired session beyond 24-hour sliding TTL | Server clears userId, returns 401 |
| test/security/auth.test.js | Disabled-account login attempt at Passport tier | Passport deserializeUser rejects with 'Account Disabled' per §6.4.2.1.4 |
| test/security/auth.test.js | Disabled-account session-scheme tier check | app.js lines 262–270 returns Boom.unauthorized('Account disabled') |
| test/security/auth.test.js | Rapid sequential /login POST attempts | Verify rate-limit applied (if hapi-rate-limit adopted in scope) |
| test/security/auth.test.js | Google OAuth callback without valid state parameter | Reject with CSRF error |
| test/security/access-control.test.js | User A authenticated; attempt GET /api/trinkets/:id for User B trinket | Returns owner-only fields per getById ownership audit |
| test/security/access-control.test.js | User A attempt PUT /api/trinkets/:id/code for User B trinket | Returns 403 Forbidden via canEdit pre-handler |
| test/security/access-control.test.js | Non-admin attempt GET /api/admin/users | Returns 403 via isAdmin pre-handler |
| test/security/access-control.test.js | User A attempt GET /api/exports/<UserB-exportId>/download | Returns 403 via strict ownership comparison |
| test/security/access-control.test.js | Non-admin attempt loginAs invocation | Returns 403 |
| test/security/access-control.test.js | Verify _realUserId not present in any API response or rendered template | Search response JSON and HTML for _realUserId substring |
| test/security/injection.test.js | POST /api/courses/search with body {name: {$where: 'sleep(1000)'}} | Joi rejects operator-prefixed key with 400 |
| test/security/injection.test.js | POST /api/users/login with body {email: {$gt: ''}, password: 'x'} | Mongoose schema typing or Joi rejects |
| test/security/injection.test.js | POST /api/trinkets with name: '<script>alert(1)</script>'; verify Nunjucks renders escaped | Cheerio assertion that <script> is escaped |
| test/security/injection.test.js | Trinket description with malicious markdown rendered server-side | Verify lib/shared/trinket-markdown.js sanitizes |
| test/security/session.test.js | Pre-login session ID vs. post-login session ID | Assert different (session fixation defense per §6.4.2.3.4) |
| test/security/session.test.js | Concurrent sessions for same user | Assert independent session lifecycles |
| test/security/session.test.js | Sliding TTL verification — request after 23h → session retained | Per §6.4.2.3.3 sliding expiration |
| test/security/session.test.js | Session cookie flags inspection | HttpOnly, SameSite=Lax, Secure (when isSecure=true) |
| test/security/upload.test.js | Upload non-image file to /file/avatar (e.g., .exe MIME) | Joi ^image/(png\|jpg\|jpeg)$ rejects |
| test/security/upload.test.js | Upload 11 MB file to /api/trinkets (above 10 MB cap) | Hapi route payload.maxBytes rejects |
| test/security/upload.test.js | Filename with ../../../etc/passwd path traversal | Verify path normalization in lib/util/file.js |

**Existing tests to verify:**

- Run full test suite (`npm test` from repo root) — verify zero regressions
- Specific test categories to verify (per §6.6.9.4 security-relevant existing coverage):
  - bcrypt rounds=10 password hashing test (`test/lib/models/user.js`)
  - Case-insensitive email login test (`test/lib/api/login.js`)
  - Admin-only route guard 302/403/200 matrix (`test/lib/api/admin.js`)
  - Password reset token generation in Store (`test/lib/api/forgot_pass.js`)
  - JWT-signed email share tokens (`test/lib/api/trinket.js`)
  - Role-based permission evaluation (`test/lib/models/plugins/roles.js`)

### 0.8.2 Verification Methods

**Automated security scanning (per Phase 1 scan tools):**

| Tool | Target | Expected Result |
| --- | --- | --- |
| npm audit --audit-level=high (root) | package.json + transitive deps | Zero Critical/High CVEs (R1 success criterion) |
| npm audit --audit-level=high (each manager) | serverside/*/manager/package.json | Zero Critical/High CVEs per Node 18 manager runtime |
| trivy image --exit-code 1 --severity CRITICAL,HIGH (main app) | Built Docker image with node:20-bullseye | Zero Critical/High OS-layer or npm CVEs |
| trivy image --exit-code 1 --severity CRITICAL,HIGH (each shell image) | Python/Java/R/Pygame shell images | Zero Critical/High OS-layer CVEs |
| eslint --plugin security | lib/, config/, serverside/*/manager/ | Zero Critical findings (no eval, hardcoded secrets, prototype pollution sinks) |
| Semgrep Node.js ruleset | Same scope as ESLint | Zero Critical findings on Hapi-specific patterns, Mongoose query construction, Socket.IO event handlers |
| OWASP ZAP baseline scan | Running staging instance | Reduced finding count vs. pre-remediation baseline; zero High/Critical |

**Manual verification steps:**

- **CSP header verification:** Open browser DevTools Network tab, navigate to `/login`, `/home`, `/admin`, verify `Content-Security-Policy` response header is present and restrictive (no `'unsafe-eval'` on main app pages)
- **Cookie inspection:** Check `Set-Cookie` for session cookie includes `HttpOnly`, `SameSite=Lax` (or `SameSite=None; Secure` when `isSecure=true`)
- **Container hardening verification:** `docker inspect <python3-shell>` and verify `HostConfig.Memory: 524288000` (500 MB), `HostConfig.PidsLimit: 50`, `HostConfig.ReadonlyRootfs: true`, `HostConfig.SecurityOpt: ["no-new-privileges:true"]`, `HostConfig.CapDrop: ["ALL"]`
- **Boot guard verification:** Set `app.mail.secret: ""` in `local.yaml`, attempt `npm start` or `docker compose up`, verify boot fails with explicit error message
- **reCAPTCHA warning verification:** Set `app.recaptcha: {}` in `local.yaml`, attempt `POST /signup`, verify Winston logs `WARN`-level message about reCAPTCHA disabled

**Penetration testing scenarios:**

- **CSRF on** `/api/exports`**:** Craft attacker-controlled HTML form posting cross-origin to `/api/exports`; verify request rejected without valid `@hapi/crumb` token (when SPA integration follow-up complete)
- **IDOR on bulk export download:** Authenticated as User A, fetch User B's `/api/exports/:exportId/download`; verify 403 response
- **NoSQL injection on** `/api/users/login`**:** POST `{email: {$gt: ''}, password: ''}`; verify schema typing rejects
- **XSS in trinket name field:** Create trinket with name `<img src=x onerror=alert(1)>`; verify Nunjucks-rendered profile page escapes correctly
- **Session fixation test:** Pre-set session cookie, complete login flow, verify session ID rotated post-login

### 0.8.3 Impact Assessment

**Direct security improvements achieved:**

- **CVSS score reduction (R1):** Critical/High dependency CVEs eliminated; npm audit baseline goes to 0 Critical, 0 High
- **MD5 → SHA-256 (R2):** Cryptographic weakness in invitation tokens eliminated (OWASP A02 closed)
- `mail.secret` **boot guard (R2):** Empty/weak JWT signing secret risk eliminated
- **reCAPTCHA warning (R3):** Silent fail-open detection enabled
- **HTTP security headers (R4):** OWASP Secure Headers Project compliance increased; CSP, X-Content-Type-Options, Referrer-Policy added; X-Frame-Options coverage extended to `/admin/*`
- **CSRF synchronizer tokens (R5):** State-mutating endpoints protected against cross-site request forgery on highest-risk routes
- **Node 20 base image (R6):** Node 16 EOL OS-layer CVE exposure eliminated
- **Default-on shell hardening (R6):** Adversarial-zone container surface reduced; fork-bomb/memory-exhaustion/setuid-escalation defense default-applied
- **Access control audit (R7):** Admin route bypass and IDOR risk eliminated; impersonation flow validated
- **Injection hardening (R8):** MongoDB operator injection and Nunjucks XSS surface reduced
- **Security regression tests (R9):** Permanent regression coverage added for auth, access-control, injection, session, upload domains

**Performance impact assessment per user's &lt;10% directive:**

| Critical Path | Baseline Source | Target Tolerance |
| --- | --- | --- |
| Authentication latency (login → session creation) | Pre-remediation git tag pre-security-remediation-20260429 | <10% increase |
| Trinket load (GET /api/trinkets/:id) | Pre-remediation tag | <10% degradation |
| Socket.IO WebSocket handshake to first execution response | Pre-remediation tag | <10% degradation |
| MongoDB query execution (post Mongoose schema typing hardening) | Pre-remediation tag | Profile per Phase Scan |

**Minimal side effects on existing functionality:**

- **No breaking changes to public APIs** per user's API Compatibility Directive — Hapi route signatures, Joi schemas, response shapes preserved
- **Internal changes only** in: cryptographic algorithm substitution (`courseInvitation.js`), header extension (`app.js`), `recaptcha.js` warning log addition, configuration directive activation (`docker-compose.yml`)
- **Mongoose model schemas frozen** per user — no schema changes; only query construction audit
- **Plugin APIs frozen** per user — `roles`, `slug`, `timestamps`, `ownable`, `paginate`, `orderedList`, `isChanged` interfaces preserved
- [**Socket.IO**](http://Socket.IO) **event protocol frozen** per user — no event name or payload structure changes

**Potential impacts to address:**

- **Node 20 base image** may surface `mongoose-schema-extend ~0.2.2` incompatibility per Risk Management mitigation; if encountered, document as ADR-8 blocker before merging Node 20 upgrade
- **CSRF tokens on AngularJS SPA-consumed routes** require coordinated frontend changes per Risk Management; scoped to non-SPA routes first; SPA integration is **explicit follow-on**
- **Default shell hardening** may surface compatibility issues with shell session writes if `tmpfs: /tmp:size=100m` insufficient; `read_only: true` may conflict with PM2 logging in shell containers — validate per shell-by-shell test
- `request` **→** `axios` **replacement** in `lib/util/recaptcha.js` may surface latency change; verify Google reCAPTCHA POST round-trip remains &lt;2 seconds
- `nodemailer` **v2 → v6 upgrade** may require SMTP credential adjustment in operator deployments; document migration path in `CHANGELOG.md`
- `bull` **v0.7 → v4 upgrade** may surface job-format incompatibility for in-flight queue jobs; document drain-and-redeploy migration path
- **Performance regression on Mongoose query hardening** may occur if schema-typed coercion adds overhead; benchmark per Risk Management performance validation directive

**Graceful degradation preservation (per user's validation directive):**

- **Redis absent →** `InMemoryQueue` — preserved by frozen Bull queue interface contract per user
- **SMTP absent →** `{skipped: true}` — preserved by frozen `mailer.send()` API
- **S3 absent → upload error only (no crash)** — preserved by `lib/util/file.js` Boom error pattern
- **reCAPTCHA absent → fail-open preserved (with warning)** — explicitly required by user; warning log added but fail-open behavior intact

## 0.9 Scope Boundaries

### 0.9.1 Exhaustively In Scope (with trailing patterns)

**Vulnerable dependency manifests:**

- `package.json` (root, main app — Node 16 dependency tree)
- `package-lock.json` (root, main app)
- `serverside/python/manager/package.json`
- `serverside/r/manager/package.json`
- `serverside/java/manager/package.json`
- `serverside/pygame/manager/package.json`
- `serverside/python/shell/requirements.txt` (Python 3 shell dependencies — patch updates only)
- `serverside/pygame/worker/requirements.txt` (Pygame worker dependencies — patch updates only)

**Source files with vulnerable code (or audit-and-fix-as-needed):**

- `app.js` (security header extension, boot guards, CSRF registration)
- `lib/util/recaptcha.js` (fail-open warning, `request` → `axios` replacement)
- `lib/util/helpers.js` (JWT verify pre-handler audit)
- `lib/util/mailer.js` (only if `nodemailer` upgraded)
- `lib/util/queues.js` (only if `bull` upgraded)
- `lib/util/file.js` (only if `aws-sdk` upgraded; SHA-1 annotation only)
- `lib/util/roles.js` (annotation; AES interface frozen)
- `lib/util/nunjucks.js` (auto-escape verification)
- `lib/auth/passport.js` (Google OAuth state parameter audit; only if `passport` upgraded)
- `lib/models/courseInvitation.js` (MD5 → SHA-256)
- `lib/models/trinket.js` (SHA-1 annotation only)
- `lib/models/user.js` (audit `publicSpec` allow-list intact)
- `lib/models/plugins/roles.js` (audit `_realUserId` not exposed; interface frozen)
- `lib/controllers/admin.js` (impersonation audit)
- `lib/controllers/users.js` (downloadExport ownership audit; signup error message uniformity)
- `lib/controllers/trinket.js` (JWT issuance audit)
- `lib/controllers/auth.js` (Google OAuth callback audit)
- `lib/controllers/files.js` (Lambda shared-secret audit)
- `lib/workers/exports.js` (only if `bull`/`aws-sdk` upgraded; SHA-1 annotation only)
- `lib/views/**/*.html` (Nunjucks template audit; modify only failures of `| safe` audit)
- `lib/shared/trinket-markdown.js` (only if marked fork has CVE)

**Configuration files requiring security updates:**

- `config/default.yaml` (`xframeDeny` extension, SECURITY annotation comments)
- `config/api_routes.js` (Joi hardening, pre-handler audit, CSRF token application)
- `config/routes.js` (page-route audit)
- `config/local.example.yaml` (security guidance comments)
- `config/aws.js` (only if `aws-sdk` upgraded)
- `config/db.js` (only if `mongoose` upgraded)
- `config/log.js` (only if `winston` upgraded; Winston transport not in scope unless directly implicated)
- `config/redis.js` (only if `redis` client upgraded)

**Infrastructure and deployment:**

- `Dockerfile` (root, main app — `node:16-bullseye` → `node:20-bullseye`)
- `docker-compose.yml` (root, main stack — audit; minimal changes if no Critical/High required)
- `serverside/docker-compose.yml` (shell hardening directive activation)
- `serverside/nginx/nginx.conf` (`server_tokens off`, `X-Content-Type-Options: nosniff`)
- `serverside/nginx/Dockerfile` (only if Trivy identifies CVEs)
- `serverside/python/shell/Dockerfile`, `serverside/python/manager/Dockerfile` (only if Trivy identifies CVEs)
- `serverside/java/shell/Dockerfile`, `serverside/java/manager/Dockerfile` (only if Trivy identifies CVEs)
- `serverside/r/shell/Dockerfile`, `serverside/r/manager/Dockerfile` (only if Trivy identifies CVEs)
- `serverside/pygame/worker/Dockerfile`, `serverside/pygame/manager/Dockerfile` (only if Trivy identifies CVEs)
- `.dockerignore` (audit secrets exclusion)
- `.github/workflows/security-scan.yml` (CREATE — `npm audit`, Trivy, ESLint security plugin in CI)
- `.eslintrc.js` (CREATE — security rule configuration)
- `.eslintignore` (CREATE — exclude vendored/frozen frontend)

**Security test files:**

- `test/security/auth.test.js` (CREATE)
- `test/security/access-control.test.js` (CREATE)
- `test/security/injection.test.js` (CREATE)
- `test/security/session.test.js` (CREATE)
- `test/security/upload.test.js` (CREATE)
- `test/security/index.js` (CREATE — sequence aggregator)
- `test/helpers/security.js` (CREATE — common security test helpers)
- `test/setup.js` (audit; modify only if security suite requires new bootstrap behavior)
- `test/mocha.opts` (audit; preserve `--recursive --check-leaks` semantics)

**Documentation updates:**

- `SECURITY.md` (CREATE — vulnerability disclosure policy)
- `README.md` (security section update; Node version prerequisites update)
- `CHANGELOG.md` (security release entry)
- `serverside/README.md` (cross-reference new default-on hardening)
- `GETTING_STARTED.md` (Node 20 setup instructions update)
- `CONTRIBUTING.md` (security review process documentation)

### 0.9.2 Explicitly Out of Scope

The following items are explicitly excluded from this remediation per the user's "Out of Scope" enumeration and the Minimal Change Clause:

- **Infrastructure TLS termination** — "Trinket does not terminate TLS in-process; outer reverse proxy is operator responsibility per `serverside/README.md`" (per user directive)
- **MongoDB Encrypted Storage Engine or volume-level at-rest encryption** — "operator infrastructure responsibility" (per user directive and §6.4.4.1.1)
- **MFA implementation** — "no TOTP, WebAuthn, or SMS second factor; out of scope per §6.4.2.2" (per user directive); reCAPTCHA v2 remains as the closest approximation
- **CDN dependency pinning** — "for `cdnjs.cloudflare.com` / `ajax.googleapis.com` runtime references (not code-level integrations)" (per user directive)
- `bower.json` — "retained for historical reference only, not used at build per `COMPONENTS.md`" (per user directive)
- **Container hardening directives in** `serverside/docker-compose.yml` **for shell containers — these are documented operator responsibilities; remediation is documentation and default-enable, not code change** — note: this user statement clarifies that the activation of directives is **in scope** (default-enable) but the directives themselves are **operator-controlled** behavior
- **Hapi 20 route registration DSL changes** — "all `config/routes.js` / `config/api_routes.js` contracts — \~60 page routes and \~116 API routes with their Joi validation schemas must not change signatures" (per user "Must Remain Unchanged" list)
- **Mongoose model schema changes** — "database schema and model interfaces are frozen" (per user directive)
- **Mongoose plugin API changes** — "all plugin APIs (`roles`, `slug`, `timestamps`, `ownable`, `paginate`, `orderedList`, `isChanged`) in `lib/models/`" (per user directive)
- `@hapi/yar` **session architecture changes** — "`catbox-mongoose` custom Catbox engine, sliding 24-hour TTL, 32-char password boot guard — session lifecycle behavior must not change" (per user directive)
- [**Socket.IO**](http://Socket.IO) **protocol changes** — "WebSocket handshake and event names are consumed by deployed embeds in third-party iframes" (per user directive)
- **Pre-handler chain API changes** — "all existing route pre-handler strings must resolve identically" (per user directive)
- **Bull queue interface changes** — "`InMemoryQueue` and `NoOpQueue` fallback behavior must be preserved" (per user directive)
- **iframe sandbox attribute changes** — "`allow-same-origin` must remain absent; operator warnings must not be removed" (per user directive)
- **AngularJS 1.3.20 SPA migration** — "frontend framework is acknowledged EOL (ADR-5); no framework migration in scope" (per user directive)
- `lib/util/roles.js` **AES role-payload encryption interface** — "encrypt/decrypt contract consumed by `lib/models/plugins/roles.js`" frozen (per user directive)
- **Admin impersonation mechanism** — "`loginAs`/`logoutAs` mechanism and `_realUserId` tracking" frozen (audit only) (per user directive)
- **Feature additions unrelated to security** — per user's "Special Instructions for Security Fixes" template
- **Performance optimizations not required for security** — per user template
- **Code refactoring beyond security fix requirements** — per user template and Minimal Change Clause
- **Non-vulnerable dependencies** — "DO NOT upgrade dependencies that are not directly implicated in a discovered CVE or security finding" (per user directive)
- **Style or formatting changes** — per user template
- **Test files unrelated to security validation** — per user template; preserve existing `test/lib/api/`, `test/lib/models/`, `test/lib/models/plugins/`, `test/lib/util/` suites unchanged unless new test bootstrap behavior is required
- **AngularJS frontend SPA changes** — "DO NOT alter the AngularJS 1.3.20 frontend (ADR-5 freeze) — note CVEs, assess exploitability in sandboxed context, document findings only" (per user directive)
- **All items explicitly excluded by user instructions** — captured in the "Out of Scope" section of the user's prompt

**Additional out-of-scope deferrals per Minimal Change Clause:**

- `aws-sdk` **v2 → v3 migration** — Deferred unless v2.x has unmitigated Critical CVEs; high migration cost touches every S3 call site
- `mongoose-schema-extend` **replacement** — Deferred to ADR-8 resolution; documented as residual risk if Node 20 incompatibility surfaces
- **Frontend SPA CSRF token integration** — Per Risk Management: "scope CSRF token addition to non-SPA routes first; coordinate SPA integration as a follow-on"
- **Hapi 21 upgrade** — Out of scope; Hapi 20 frozen per user directive
- **Mocha 3 → modern Mocha upgrade** — Out of scope per §6.6.12.3 deferred modernization
- **CI/CD pipeline beyond security scanning** — `.github/workflows/security-scan.yml` is in scope; broader CI pipeline (build, test, deploy) is operator-owned per §6.6.6.1
- **Coverage instrumentation** — `nyc`/`c8` not in scope per §6.6.2.4 operator-owned

**Boundary cross-reference:**

- The user's "Must Remain Unchanged" list (15 items) is the **frozen-interface boundary** that no remediation may cross
- The user's "Out of Scope" list (6 items) is the **deferred-responsibility boundary** that operators own
- The Minimal Change Clause is the **per-fix scope boundary** — when multiple paths exist, choose fewest modified files
- The user's "Note additional security concerns discovered during audit but DO NOT fix unless Critical or High severity" is the **discovery-discipline boundary** — Medium/Low findings are documented but not actively remediated unless they meet the ≥80% Medium criterion explicitly

## 0.10 Execution Parameters

**Environment Setup — Complete before any scanning or implementation begins:**

1. `cp config/local.example.yaml config/local.yaml`
2. Set `app.plugins.session.cookieOptions.password` in `config/local.yaml` to the output of: `openssl rand -base64 32`
3. Start the application: `docker compose up`
4. Confirm the application is running before proceeding to 0.10.1

### 0.10.1 Security Verification Commands

The following commands constitute the verification surface for the remediation. Each is non-interactive, CI-compatible, and produces deterministic exit codes for pipeline integration.

**Dependency vulnerability scan:**

```bash
# Root main app (Node 16 dependency tree)

npm audit --audit-level=high
# Per-manager (Node 18 dependency tree) - run separately

cd serverside/python/manager && npm audit --audit-level=high
cd serverside/r/manager && npm audit --audit-level=high
cd serverside/java/manager && npm audit --audit-level=high
cd serverside/pygame/manager && npm audit --audit-level=high
```

**Container vulnerability scan (Aqua Trivy):**

```bash
# Main app image post-build (after Dockerfile node:20-bullseye change)

trivy image --exit-code 1 --severity CRITICAL,HIGH trinket-main-app:latest
# Per-shell image

trivy image --exit-code 1 --severity CRITICAL,HIGH trinket-python-shell:latest
trivy image --exit-code 1 --severity CRITICAL,HIGH trinket-java-shell:latest
trivy image --exit-code 1 --severity CRITICAL,HIGH trinket-r-shell:latest
trivy image --exit-code 1 --severity CRITICAL,HIGH trinket-pygame-worker:latest
```

**Static analysis (ESLint + security plugin):**

```bash
# Targeted scan; exclude vendored frontend per .eslintignore

npx eslint lib/ config/ serverside/python/manager/ serverside/r/manager/ \
  serverside/java/manager/ serverside/pygame/manager/ \
  --ext .js \
  --no-fix
```

**Semgrep static analysis (supplementary):**

```bash
# Node.js ruleset; targets Hapi-specific patterns and Mongoose query construction

semgrep --config=p/nodejs --error lib/ config/ serverside/*/manager/
```

**OWASP ZAP baseline scan (against running staging):**

```bash
# Requires running instance per Environment Setup

docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://staging.trinket.example.com \
  -r zap-baseline-report.html
```

**Security test suite execution:**

```bash
# Standalone security suite (after test/security/index.js created)

CI=true npx mocha --recursive test/security/ --reporter spec --check-leaks
```

**Full test suite validation (regression):**

```bash
# Complete Mocha suite per §6.6 with --check-leaks

CI=true npm test
```

**Smoke test execution (post-deploy verification):**

```bash
# Per §6.6.4.1 - operates against deployed instance

./test/smoke-test.sh http://localhost:3000
```

**Build verification (post-Node 20 base image change):**

```bash
# Verify Dockerfile builds cleanly with new base

docker build -t trinket-main-app:security-test .
# Verify --legacy-peer-deps install succeeds

docker run --rm trinket-main-app:security-test npm ls --depth=0
```

**Performance benchmark (per &lt;10% directive):**

```bash
# Authentication latency benchmark (illustrative; tool of choice per operator)

ab -n 1000 -c 10 -p login.json -T application/x-www-form-urlencoded \
  http://localhost:3000/login
# Trinket load benchmark

ab -n 1000 -c 10 -H "Cookie: session=$SESSION_COOKIE" \
  http://localhost:3000/api/trinkets/$TRINKET_ID
# Socket.IO handshake benchmark - bespoke per Phase 1 scan tooling

```

**Boot guard verification:**

```bash
# Test mail.secret guard - should refuse boot

echo "app: { mail: { secret: '' } }" > config/local.yaml
node app.js
# Expected: process.exit(1) with mail.secret error message

```

**reCAPTCHA warning verification:**

```bash
# Test reCAPTCHA absent fail-open warning

docker compose up -d
# Trigger signup flow; check Winston logs for WARN message

docker compose logs trinket-main-app | grep "SECURITY: reCAPTCHA"
```

**Container hardening verification:**

```bash
# Inspect shell container runtime config

docker inspect trinket-python3-shell | jq '.[0].HostConfig | {Memory, PidsLimit, ReadonlyRootfs, SecurityOpt, CapDrop}'
# Expected output:

#### {"Memory": 524288000, "PidsLimit": 50, "ReadonlyRootfs": true,

####  "SecurityOpt": ["no-new-privileges:true"], "CapDrop": ["ALL"]}
```

### 0.10.2 Research Documentation

**Links to security advisories consulted (populated during implementation):**

- npm Advisory Database — `https://www.npmjs.com/advisories` (per package: `request`, `passport`, `nodemailer`, `bull`, `aws-sdk`, `jsonwebtoken`, `mongoose`, `validator`, etc.)
- GitHub Security Advisories — `https://github.com/advisories?query=ecosystem%3Anpm` (per package)
- Snyk Vulnerability DB — `https://security.snyk.io/` (per package)
- NVD CVE entries — `https://nvd.nist.gov/vuln/search` (per CVE-YYYY-NNNNN identified by Phase 1 scan)
- Aqua Security Trivy DB — automatic CVE matching during `trivy image` run
- Hapi.dev security policies — `https://hapi.dev/policies/security/`
- Node.js Security WG monthly releases — `https://nodejs.org/en/blog/vulnerability/`

**Reference specific CVE numbers and vulnerability databases:**

- For each upgraded package, populate the table per the Dependency Inventory in §0.7.1 with:
  - CVE number (e.g., `CVE-2022-23529` for `jsonwebtoken@^5.0.5`)
  - CVSS v3.1 score
  - Affected version range
  - Fixed version
  - Advisory URL
- Cross-reference each CVE in commit message: `security: [severity] fix [CVE-YYYY-NNNNN] in [file]`

**Document any security best practices followed:**

- **OWASP Top 10 (2021):** A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A05 Security Misconfiguration, A06 Vulnerable and Outdated Components, A07 Identification and Authentication Failures
- **OWASP Cheat Sheet Series:** CSRF Prevention, Cross-Site Scripting Prevention, Authentication, Session Management, Input Validation, Docker Security
- **OWASP Secure Headers Project:** CSP, X-Content-Type-Options, Referrer-Policy, X-Frame-Options recommended baselines
- **NIST SP 800-131A:** MD5 → SHA-256 migration guidance
- **CWE references:** CWE-79 (XSS), CWE-89 (SQL Injection — analog NoSQL), CWE-352 (CSRF), CWE-284 (Improper Access Control), CWE-327 (Use of Broken/Risky Cryptographic Algorithm), CWE-639 (IDOR), CWE-918 (SSRF), CWE-1104 (Vulnerable Third-Party Component)
- **Hapi security best practices:** `@hapi/crumb` for CSRF, Joi for input validation, Yar for sealed session cookies

**Cite OWASP guidelines or security standards applied:**

- OWASP Top 10 2021 mapping per §0.2.3 vulnerability classification
- OWASP Cheat Sheet — Cross-Site Scripting Prevention applied to Nunjucks template audit
- OWASP Cheat Sheet — Authentication Cheat Sheet applied to session-fixation defense and password policy
- OWASP Docker Security Cheat Sheet applied to shell container hardening

### 0.10.3 Implementation Constraints

**Priority directives:**

- **Security fix first, minimal disruption second** — per Minimal Change Clause; correctness of vulnerability closure takes precedence; ergonomic considerations secondary
- **Atomic commit pattern** — one CVE or vulnerability class per commit per user directive; commit message format `security: [severity] fix [description] in [file]`
- **Rollback readiness** — git tag `pre-security-remediation-20260429` and `package-lock.baseline.json` snapshot before any change

**Backward compatibility:**

- **Must maintain** for all in-scope items per user's API Compatibility Directive
- **Acceptable breakage for security** explicitly applies to:
  - The MD5 → SHA-256 substitution in `courseInvitation.js` is internally backward-compatible (8-char output preserved)
  - The Node 20 base image change is operator-transparent (container internal change)
  - The default-on shell hardening is operator-overridable (opt-out preserved)
  - The reCAPTCHA warning log addition is non-breaking (fail-open preserved per user directive)
- **CSRF token integration** (R5) introduces a temporary breaking surface for AngularJS SPA-consumed routes; per Risk Management, scoped to non-SPA routes first to avoid frontend coordination

**Deployment considerations:**

- **Immediate** for: dependency patch updates within the same major (`npm audit fix` semantics), header additions, configuration directive activation, SHA-1 annotations, MD5 → SHA-256
- **Requires coordination** for: Node 20 base image upgrade (validate `mongoose-schema-extend` compatibility in isolated branch first); CSRF token integration on SPA-consumed routes (frontend coordination required); `nodemailer` v2 → v6 (operator SMTP credential audit); `bull` v0.7 → v4 (queue drain-and-redeploy)
- **Operator opt-out preservation** for shell container hardening — directives default-enabled but documented as overridable
- **Zero-downtime constraint** — atomic per-CVE commits enable rollback at fix granularity; deployment ordering: dependency patches → header additions → MD5/SHA fix → reCAPTCHA warning → CSRF tokens (non-SPA) → Node 20 base image → shell hardening defaults

**Annotation discipline (per user's "Annotation Directive"):**

- Every changed line carries an inline comment of the form `// SECURITY: [threat addressed]`
- Annotation enables retroactive audit and SIEM ingestion
- Examples:
  - `// SECURITY: SHA-256 replaces MD5 (OWASP A02; mitigates CVE-class collision risk)`
  - `// SECURITY: fail-open preserved with warning log per graceful-degradation directive`
  - `// SECURITY: strict ownership comparison prevents IDOR per §6.4.3.3`
  - `// SECURITY: app.mail.secret entropy validated at boot (parallel to session password guard)`
  - `// SECURITY: CSP, X-Content-Type-Options, Referrer-Policy added per OWASP Secure Headers`

## 0.11 Special Instructions for Security Fixes

### 0.11.1 User-Specified Security Directives

The user has explicitly emphasized the following security-specific requirements. Each directive is captured verbatim and translated into actionable implementation constraints.

**Change scope discipline:**

- **User Example:** "Make ONLY the changes necessary to remediate identified security vulnerabilities."

- **Implementation:** Every file modification must trace back to a Phase 1 scan finding (npm audit, Trivy, ESLint security, Semgrep, OWASP ZAP) or a user-enumerated vulnerability class. Audit findings without Critical/High severity are documented in the Vulnerability Discovery Report (Deliverable #1) but not actively remediated.

- **User Example:** "Do not refactor unrelated code"

- **Implementation:** Refactoring is forbidden as a side effect of security fixes. If a security fix touches a function, only the security-relevant lines change; surrounding code is preserved verbatim. Annotation comments are the only additive change.

- **User Example:** "Do not upgrade dependencies that are not directly implicated in a discovered CVE or security finding"

- **Implementation:** Each `package.json` upgrade must cite a specific CVE or advisory link in the commit message. Dependencies passing `npm audit --audit-level=high` cleanly are not upgraded under this remediation, regardless of latest available version.

- **User Example:** "Preserve all existing functionality except where it enables the vulnerability"

- **Implementation:** Functional regression validation is gated by the existing `npm test` suite plus the new `test/security/` suite. Any test failure blocks the commit per Risk Management rollback strategy.

**Principle of least privilege:**

- **User Example:** "Follow principle of least privilege in all changes"
- **Implementation:** Container hardening directives (`cap_drop: [ALL]`, `read_only: true`, `no-new-privileges:true`) embody this principle for the adversarial-zone shell tier. Code changes (e.g., `canEdit` ownership tightening, `isAdmin` audit) reinforce least-privilege at the application tier.

**Audit trail:**

- **User Example:** "Maintain audit trail for all security changes"
- **Implementation:** Every commit follows the format `security: [severity] fix [description] in [file]`. Every changed line carries `// SECURITY: [threat addressed]` annotation. The `CHANGELOG.md` aggregates security changes with CVE cross-references.

**Security review gating:**

- **User Example:** "Require security review before deployment"
- **Implementation:** Per atomic commit pattern, each commit is independently reviewable. The `SECURITY.md` (CREATE) documents the disclosure and review process. CI integration in `.github/workflows/security-scan.yml` (CREATE) gates on `npm audit` and Trivy exit codes.

**Documentation alongside code:**

- **User Example:** "Update security documentation alongside code changes"
- **Implementation:** `SECURITY.md` is created; `README.md`, `CHANGELOG.md`, `serverside/README.md`, `GETTING_STARTED.md`, `CONTRIBUTING.md` are updated as part of this remediation per §0.7.3 Documentation updates.

**Secrets management:**

- **User Example:** "Secrets management: If fix requires secrets/credentials updates, note separately"
- **Implementation:** No new secrets are introduced by this remediation. Existing secrets in `config/local.yaml` (session password ≥32 chars, `app.mail.secret`, AWS keyId/key, Google OAuth, reCAPTCHA, SMTP credentials) are preserved. The new `app.mail.secret` boot guard validates entropy but does not change the secret value or storage mechanism. Operators may need to rotate `app.mail.secret` to satisfy the new ≥32-character minimum if their deployment used a shorter secret — documented in `CHANGELOG.md` and `local.example.yaml`.

**Compliance:**

- **User Example:** "Compliance requirements: Ensure changes meet \[SOC2 | PCI-DSS | HIPAA | etc.\] standards"
- **Implementation:** Per §6.4.4.5.3, the open-source release does not implement explicit controls for specific compliance regimes; the architectural posture is operator-driven. The remediation **strengthens** the operator-driven compliance baseline (CSP, X-Content-Type-Options, Referrer-Policy, default-on shell hardening, MD5 → SHA-256, Node 20 OS-layer patching) without committing to a specific regime. Operators deploying for SOC 2, PCI-DSS, HIPAA, FERPA, COPPA, or GDPR contexts must layer their own DPAs, parental-consent mechanisms, retention runbooks, and SIEM forwarding per §6.4.6.3.

**Breaking changes:**

- **User Example:** "Breaking changes: If fix breaks backward compatibility for security reasons, justify thoroughly"
- **Implementation:** The remediation is designed to be backward compatible. Specific cases requiring justification:
  - `mail.secret` **boot guard:** Operators with `mail.secret` shorter than 32 characters will fail to boot post-upgrade. **Justification:** Eliminates JWT email token forgery risk; aligns with existing 32-char session password guard pattern; documented in `CHANGELOG.md`.
  - **CSRF tokens on** `/api/exports`**,** `/api/users` **(password/email change),** `/api/admin/*`**:** API consumers must include CSRF tokens. **Justification:** Closes OWASP A01/A07; per Risk Management scoped to non-SPA routes first. Operators deploying with custom API consumers (not the AngularJS SPA) must integrate CSRF token handling.
  - **Node 20 base image:** Operators relying on Node 16 specific behavior may surface incompatibility. **Justification:** Node 16 is EOL September 2023; continued use exposes accumulating OS-layer CVEs. `mongoose-schema-extend ~0.2.2` compatibility is the primary technical risk per Risk Management; mitigation: test in isolated branch first.
  - **Default-on shell hardening:** Operators relying on unbounded shell resources may surface `mem_limit: 500m` exhaustion or `read_only: true` write failures. **Justification:** Educational platform executing untrusted learner code requires hardening as the default posture per user directive; opt-out preserved.

**Discovery discipline:**

- **User Example:** "Note additional security concerns discovered during audit but DO NOT fix unless Critical or High severity"
- **Implementation:** The Vulnerability Discovery Report (Deliverable #1) enumerates **all** findings (Critical, High, Medium, Low). Active remediation is gated:
  - Critical (CVSS ≥9.0): 100% remediated
  - High (CVSS 7.0–8.9): 100% remediated
  - Medium (CVSS 4.0–6.9): ≥80% remediated per success criteria
  - Low (CVSS &lt;4.0): Documented; not actively remediated
- Findings deferred to documentation enter the **residual risk register** in the Before/After Security Posture Report (Deliverable #7).

**Selection directive:**

- **User Example:** "When multiple remediation approaches exist, choose the path requiring fewest modified files"
- **Implementation:** Applied throughout §0.5 Security Fix Design. Examples:
  - `request` replacement: 1 file (`lib/util/recaptcha.js`) — chosen over project-wide migration
  - MD5 → SHA-256: 1 file, 1 line — chosen over invitation token contract redesign
  - Header addition: 1 file (`app.js`) — chosen over per-route header configuration
  - CSRF: scoped to highest-risk endpoints first — chosen over project-wide synchronizer-token rollout

### 0.11.2 Risk Management Integration

The user's Risk Management section establishes specific technical risks and mitigations. These are integrated into the remediation execution plan:

**Technical Risks (per user enumeration):**

- **Legacy dependency upgrades** (`request`, `nodemailer`, `passport`, `bull`) may introduce breaking API changes in `lib/util/mailer.js`, `lib/util/recaptcha.js`, `lib/auth/passport.js`, and `lib/workers/exports.js`
  - **Mitigation:** Upgrade one package at a time, run full regression suite per upgrade, maintain rollback tag
  - **Implementation:** Each dependency upgrade is its own commit; `npm test` is run after each commit; rollback to `pre-security-remediation-20260429` git tag if any test fails
- **Node.js base image upgrade** (`node:16` → `node:18`+) may surface compatibility issues with `mongoose-schema-extend ~0.2.2` (known legacy, ADR-8 tech debt)
  - **Mitigation:** Test against Node 18 in isolated branch before merging; if incompatible, document as a blocker requiring ADR-8 resolution first
  - **Implementation:** Branch `security/node20-base` created; `npm test` validates compatibility; if `mongoose-schema-extend` fails, escalate as ADR-8 blocker
- **Adding** `@hapi/crumb` **CSRF tokens** to mutating API routes consumed by the AngularJS SPA requires coordinated frontend changes to inject CSRF tokens in `$http` headers
  - **Mitigation:** Scope CSRF token addition to non-SPA routes first; coordinate SPA integration as a follow-on
  - **Implementation:** First wave: `/api/exports` (non-SPA), `/api/users` password/email change (non-SPA — server-rendered forms), `/api/admin/*` (server-rendered admin pages). Second wave (deferred): SPA-consumed routes after AngularJS `$http` interceptor coordination.

**Rollback Strategy (per user enumeration):**

- **Tag codebase before remediation begins:** `git tag pre-security-remediation-20260429`
- **Atomic commits:** `security: [severity] fix [description] in [file]`
- **Lockfile snapshot:** `cp package-lock.json package-lock.baseline.json`
- **Revert immediately if any regression test suite gate fails; do not stack fixes on a failing baseline**

### 0.11.3 Deliverables

Per user's Deliverables enumeration, the following artifacts must be produced:

1. **Vulnerability Discovery Report** — Complete scan results from `npm audit`, ESLint security plugin, Semgrep, and OWASP ZAP with prioritized remediation backlog sorted by CVSS score. **Format:** Markdown report with severity-sorted finding table, exploitation scenarios specific to the Trinket threat model (untrusted learner code, minor user data, educator courseware).

2. **Dependency Upgrade Report** — CVE-to-package mapping for root and manager dependencies, Node 16/18 compatibility matrix, breaking-change impact summary per upgraded package. **Format:** Markdown report with per-package upgrade rationale, CVE cross-reference, and compatibility verification result.

3. **Remediation Implementation** — All Critical/High vulnerabilities fixed; ≥80% Medium vulnerabilities fixed; inline `// SECURITY:` annotations on all changed lines. **Format:** Atomic git commits per CVE/vulnerability class with the standard commit message format.

4. **Security Test Suite** — `test/security/` directory with auth, access-control, injection, session, and upload test modules integrated into `npm test`. **Format:** Five Mocha test modules following `test/lib/api/` integration pattern; aggregator at `test/security/index.js`.

5. **Performance Validation Report** — Benchmark comparison confirming `<10%` impact on authentication, trinket load, and [Socket.IO](http://Socket.IO) handshake critical paths. **Format:** Markdown report with baseline metrics (from `pre-security-remediation-20260429` tag) vs. post-remediation metrics; explicit pass/fail per critical path.

6. **Container Hardening Diff** — `serverside/docker-compose.yml` with shell hardening directives enabled by default and `Dockerfile` base image upgraded. **Format:** Standard `git diff` output captured in the Remediation Implementation deliverable.

7. **Before/After Security Posture Report** — CVSS score reduction, vulnerability count reduction by severity class, residual risk register for deferred items (AngularJS EOL, MFA absence, no dedicated audit log). **Format:** Markdown report with side-by-side CVSS metrics and a residual risk register documenting:

- **AngularJS 1.3.20 EOL** — Frozen per ADR-5; CVEs documented; sandbox-context exploitability assessed; no upgrade
- **MFA absence** — Out of scope per §6.4.2.2; reCAPTCHA v2 remains as approximation
- **No dedicated audit log** — Per §6.4.3.5; operator-owned SIEM transport recommendation
- `mongoose-schema-extend ~0.2.2` — ADR-8 tech debt; if Node 20 incompatible, blocks migration
- **Operator-owned compliance** — Per §6.4.4.5.3; remediation strengthens baseline but does not commit to specific regime
- `aws-sdk` **v2 maintenance mode** — v3 migration deferred per Minimal Change Clause; ongoing v2 patches only
- **Frontend SPA CSRF coordination** — Deferred to follow-on per Risk Management

### 0.11.4 Success Criteria Verification

Per the user's Core Objectives "Success Criteria" enumeration, the remediation is complete when:

- **100% Critical severity vulnerabilities remediated (CVSS ≥9.0)** — Verified by `npm audit --audit-level=high` exit 0 + Trivy exit 0 + ESLint security exit 0 across all manifests and images
- **100% High severity vulnerabilities remediated (CVSS 7.0–8.9)** — Same verification toolchain
- **≥80% Medium severity vulnerabilities remediated (CVSS 4.0–6.9)** — Computed from Vulnerability Discovery Report finding count by severity class
- **All security tests passing in automated pipeline** — Verified by `CI=true npm test` exit 0 with `test/security/` suite included
- **Performance impact &lt;10% on critical paths** — Verified by Performance Validation Report
- **Zero functional regression across all platform capabilities** — Verified by full `npm test` regression suite + smoke test + manual critical workflow walkthrough (`user signup → email verify → login → create trinket → run Python trinket → submit assignment → bulk export request → logout`)
- **Graceful degradation preserved** — Verified by:
  - Redis absent → `InMemoryQueue` selection
  - SMTP absent → `{skipped: true}` mailer return
  - S3 absent → upload error only (no crash)
  - reCAPTCHA absent → fail-open preserved with new warning log

The remediation is **complete** when all seven success criteria are verifiably met and all seven deliverables are produced.
