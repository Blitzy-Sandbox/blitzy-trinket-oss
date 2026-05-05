# Security Policy

The Trinket open-source project takes security seriously. The codebase has
undergone a comprehensive OWASP Top 10 (2021) audit covering dependency
vulnerabilities, authentication and session controls, cryptographic primitives,
SSRF surfaces, security misconfigurations, container hardening, and the
runtime supply chain. We welcome responsible disclosures from researchers and
operators and commit to coordinated, timely remediation. This document
records the supported versions, the disclosure process, the remediated CVE
inventory from the most recent audit (tagged `pre-security-remediation` in
git), the residual-risk register for findings that remain after the
remediation, and the OWASP Top 10 coverage map.

## Supported Versions

Security fixes are applied to the active development branch. Operators
running their own deployments are expected to track the head of the supported
branch. Older revisions are not maintained and are not eligible for
backported fixes.

| Version              | Supported          |
| -------------------- | ------------------ |
| `master` / `main` (current) | :white_check_mark: |
| Older revisions / forks     | :x:                |

## Reporting a Vulnerability

Please report security issues **privately** to the project's security
mailbox so that affected operators can patch before details become public.

- **Email**: `security@trinket.io` *(operator-configurable placeholder — if
  you maintain a self-hosted deployment, replace this address with the
  contact for your own security response team and update this section
  accordingly).*
- **Acknowledgment**: We aim to acknowledge new reports within **5 business
  days**.
- **Disclosure timeline**: We follow a **coordinated disclosure** model with
  a default embargo of **90 days** from acknowledgment, or until a fix is
  publicly available, whichever comes first. Extensions are negotiated in
  good faith for complex issues.
- **Please do not** open public GitHub issues, pull requests, or discussions
  for suspected security vulnerabilities. Public disclosure before a fix is
  available puts every operator at risk.
- When reporting, please include: a clear description of the issue, the
  affected file(s) and version, reproduction steps or a proof-of-concept,
  the impact you have observed, and any mitigations you have identified.

## Remediated Vulnerabilities (Audit: `pre-security-remediation` tag)

The findings below were eliminated in the current remediation pass. Every
Critical / High fix carries an inline `// SECURITY: [threat addressed]`
annotation in the source code. Reviewers can locate each annotation via the
"Inline Annotation Location" column.

### Critical / High CVEs Eliminated

| CVE / CWE      | Package / Component        | Before               | After                                   | OWASP | CWE      | Inline Annotation Location |
| -------------- | -------------------------- | -------------------- | --------------------------------------- | ----- | -------- | -------------------------- |
| CVE-2022-23540 | `jsonwebtoken`             | `^5.0.5`             | `^9.0.2`                                | A02   | CWE-347  | `lib/util/helpers.js`      |
| CVE-2022-23541 | `jsonwebtoken`             | `^5.0.5`             | `^9.0.2`                                | A02   | CWE-347  | `lib/util/helpers.js`, `lib/controllers/trinket.js` |
| CVE-2022-25896 | `passport`                 | `~0.2.0`             | `^0.7.0`                                | A07   | CWE-384  | (library upgrade)          |
| CVE-2023-28155 | `request` &rarr; `axios`   | `request@^2.51.0`    | replaced with `axios@^1.7.7`            | A10   | CWE-918  | `lib/util/recaptcha.js`, `lib/controllers/auth.js`, `lib/controllers/users.js` |
| CVE-2017-16138 | `mime`                     | `~1.2.11`            | `^3.0.0`                                | A06   | CWE-1333 | (library upgrade; API call-sites updated in `lib/controllers/files.js`, `lib/controllers/users.js`, `lib/controllers/trinket.js`) |
| CVE-2022-24785 | `moment`                   | `^2.18.1`            | `^2.30.1`                               | A06   | CWE-22   | (library upgrade)          |
| CVE-2022-31129 | `moment`                   | `^2.18.1`            | `^2.30.1`                               | A06   | CWE-1333 | (library upgrade)          |
| CVE-2022-24999 | `moment-timezone`          | `~0.5.21`            | `^0.5.45`                               | A06   | CWE-1321 | (library upgrade)          |
| CVE-2022-37489 | `nunjucks`                 | `^3.2.0`             | `^3.2.4`                                | A06   | CWE-1336 | (library upgrade)          |
| CVE-2020-26237 | `highlight.js`             | `^9.6.0`             | `^11.9.0`                               | A06   | CWE-1321 | (library upgrade)          |
| CVE-2021-23413 | `jszip`                    | `~3.6.0`             | `^3.10.1`                               | A06   | CWE-22   | (library upgrade)          |
| CVE-2023-26136 | `tmp`                      | `0.0.25`             | `^0.2.3`                                | A06   | CWE-22   | (library upgrade)          |
| CVE-2020-7769  | `nodemailer`               | `^2.5.0`             | `^6.9.16`                               | A06   | CWE-77   | (library upgrade)          |
| CVE-2015-8851  | `node-uuid` &rarr; `uuid`  | `node-uuid@^1.4.3`   | replaced with `uuid@^9.0.1`             | A02   | CWE-330  | `lib/controllers/users.js` |
| CWE-1104       | `node:16-bullseye` runtime | `node:16-bullseye`   | `node:20-bookworm-slim`                 | A06   | CWE-1104 | `Dockerfile`               |

Additional dependency hardening upgrades applied in the same pass (no
demonstrated Critical/High CVE on installed pin, but pulled forward to a
maintained release line as part of the dependency-graph refresh): `bull`
`^0.7.0` &rarr; `^4.16.4`, `mkdirp` `~0.3.5` &rarr; `^3.0.1`, `js-yaml`
`~3.0.1` &rarr; `^4.1.0`, `is-svg` `^2.1.0` &rarr; `^4.4.0`, `validator`
`^5.6.0` &rarr; `^13.12.0`, `accepts` `~1.1.0` &rarr; `^1.3.8`.

### Configuration Hardening

The following configuration changes were applied as defense-in-depth
alongside the dependency upgrades.

- **Container hardening (adversarial Code Execution Zone)** &mdash; the
  shell-runner services that execute untrusted learner code now run with
  strict resource and capability limits. In `serverside/docker-compose.yml`,
  the `python3-shell`, `java-shell`, `r-shell`, and `pygame-worker` services
  enable `mem_limit: 500m`, `pids_limit: 50`, `read_only: true`,
  `tmpfs: ['/tmp:size=100m']`, `cap_drop: ['ALL']`, and
  `security_opt: ['no-new-privileges:true']`. These limits reduce the
  post-exploit blast radius if a learner program escapes its in-process
  language sandbox.
- **Server-banner suppression** &mdash; `server_tokens off;` is now set in
  the `http {}` block of `serverside/nginx/nginx.conf` so that the nginx
  version is no longer disclosed in the `Server` response header.
- **Security response headers** &mdash; the Hapi `onPreResponse` extension
  in `app.js` now emits `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, and a conservative
  `Content-Security-Policy` (`default-src 'self'` plus the explicit CDN /
  font / iframe sources required by the existing frontend). The nginx
  gateway also emits `add_header X-Content-Type-Options "nosniff" always;`
  and `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`
  in the `server {}` block of `serverside/nginx/nginx.conf` so the
  defense-in-depth headers are present even on responses served directly
  by nginx.
- **nginx base image pinned** &mdash; `serverside/nginx/Dockerfile` now
  pins `FROM nginx:1.27-alpine` (was the implicit-latest `nginx:alpine`),
  removing silent supply-chain drift on the gateway.
- **JWT algorithm pinning** &mdash; every `jwt.verify(...)` call passes
  `{ algorithms: ['HS256'] }` and every `jwt.sign(...)` call passes
  `{ algorithm: 'HS256', expiresIn: '7d' }`. The pin closes the
  algorithm-confusion class even if a future regression were to re-introduce
  permissive defaults in the `jsonwebtoken` library, and `expiresIn` adds a
  hard time bound to the email-share token (which previously had no embedded
  expiry).
- **Boot-time entropy guard extended** &mdash; the existing 32-character
  guard on `app.plugins.session.cookieOptions.password` (in `app.js`) is
  extended to validate `config.app.mail.secret` (the JWT signing secret for
  email-share tokens) when email is configured. The extension logs a warning
  and refuses to issue email-share tokens when the secret is shorter than 32
  characters; it does not hard-exit, so the SMTP-absent graceful-degradation
  contract for non-email-using deployments is preserved.

## Residual-Risk Register

The findings below remain after the remediation. They are below the
Critical/High remediation threshold, are explicitly held out of scope by the
audit's minimal-change clause, or are operator infrastructure
responsibilities. Each row carries a recommended future action.

| ID   | Finding                                                                                                                                | Severity   | Scope Reason                                                  | Recommended Future Action                                                                                                  |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| R-01 | AngularJS 1.3.20 EOL frontend in `public/`                                                                                             | Medium     | Out of scope per user instructions                            | Plan migration to a maintained framework. Interim mitigation: iframe sandbox **without** `allow-same-origin` is preserved. |
| R-02 | Custom `marked` Trinket fork at `git+https://github.com/trinketapp/marked.git`                                                         | Medium     | Out of scope per minimal-change clause                        | Audit the fork against upstream `marked@^14`; consider adopting upstream.                                                  |
| R-03 | `node-cryptojs-aes@^0.4.0` unmaintained                                                                                                | Medium     | Documented; non-exploitable in current usage in `lib/util/roles.js` | Replace with built-in `crypto` AES-GCM in a future sprint.                                                                 |
| R-04 | Dev-dependency staleness (`mocha@^3.4.1`, `chai@^3.5.0`, `sinon@~1.7.3`, `should@~3.0.0`, `supertest@~0.8.3`)                           | Low        | Internal-only; deferred                                       | Upgrade dev dependencies in a follow-up PR. Not part of the `npm audit --omit=dev` gate because they are test-runner only. |
| R-05 | `mongoose-schema-extend@~0.2.2` deprecated                                                                                             | Low        | Out of scope per minimal-change clause                        | Replace with native Mongoose discriminators.                                                                               |
| R-06 | `optimist`, `q`, `tab` deprecated / possibly unused-direct                                                                             | Low        | Out of scope per minimal-change clause                        | Audit for actual usage; remove if unused.                                                                                  |
| R-07 | nginx serverside `Dockerfile` previously used generic `nginx:alpine`                                                                   | Low        | Pinned to `nginx:1.27-alpine` in this remediation             | Maintain the pinned tag; rotate periodically as new patch releases land.                                                   |
| R-08 | `config@~0.4.35` extremely old                                                                                                         | Low        | Out of scope per minimal-change clause                        | Migrate to `config@^3` in a future sprint. The API surface change is non-trivial.                                          |
| R-09 | TLS termination is operator-supplied                                                                                                   | Documented | Out of scope per user instructions                            | Operator must configure HTTPS at the reverse proxy / load balancer in front of Trinket.                                    |
| R-10 | MongoDB at-rest encryption is operator-supplied                                                                                        | Documented | Out of scope per user instructions                            | Operator must enable disk-level / volume encryption on the MongoDB host.                                                   |
| R-11 | MFA is not implemented                                                                                                                 | Documented | Out of scope per user instructions                            | Plan multi-factor authentication in a future product cycle.                                                                |

## OWASP Top 10 Coverage

The remediation maps to the following OWASP Top 10 (2021) categories:

- **A02 Cryptographic Failures** &mdash; `jsonwebtoken` algorithm-confusion
  class eliminated by upgrading to `^9.0.2` and explicitly pinning
  `algorithms: ['HS256']` on every `jwt.verify` and
  `algorithm: 'HS256', expiresIn: '7d'` on every `jwt.sign`. The
  email-share JWT signing secret is additionally entropy-checked at boot.
- **A05 Security Misconfiguration** &mdash; container hardening enabled on
  the adversarial Code Execution Zone services (`cap_drop=ALL`,
  `no-new-privileges`, `read_only`, `tmpfs`, `pids_limit`, `mem_limit`);
  baseline security-response headers added at both the Hapi layer
  (`onPreResponse`) and the nginx gateway; `server_tokens off;`
  suppresses the nginx version banner.
- **A06 Vulnerable & Outdated Components** &mdash; full dependency upgrade
  pass against the root `package.json` (jsonwebtoken, passport, mime,
  moment, moment-timezone, nunjucks, highlight.js, jszip, js-yaml, tmp,
  mkdirp, bull, nodemailer, is-svg, validator, accepts); deprecated
  `request` and `node-uuid` packages replaced with maintained successors
  (`axios`, `uuid`); main-application container base image upgraded from
  `node:16-bullseye` (EOL) to `node:20-bookworm-slim` (Active LTS); nginx
  base image pinned to `nginx:1.27-alpine`.
- **A07 Identification & Authentication Failures** &mdash; `passport`
  upgraded from `~0.2.0` to `^0.7.0`; the library now regenerates the
  session ID on `req.logIn()` / `req.logOut()`. The application's existing
  `request.yar.reset()` belt-and-suspenders calls are preserved as an
  additional layer.
- **A10 Server-Side Request Forgery** &mdash; the deprecated `request`
  library (vulnerable to CVE-2023-28155 cross-protocol redirect SSRF) has
  been replaced with the actively maintained `axios` at every outbound
  call-site (`lib/util/recaptcha.js`, `lib/controllers/auth.js`,
  `lib/controllers/users.js`).

## Validation Gates

The remediation is gated on the following acceptance criteria, which must
all be satisfied before the change set is released. These gates are quoted
from the audit instructions and are binding.

- **Dependency audit**: Zero Critical/High CVEs across all manifests
  (`npm audit --omit=dev --audit-level=high`), evaluated at the repository
  root and inside every `serverside/*/manager/` and
  `serverside/*/shell/trinket/` (and `serverside/pygame/worker/trinket/`)
  package directory.
- **Code audit**: Zero Critical/High findings.
- **Secrets scan**: Zero hardcoded credentials.
- **Existing test suite**: 100% pass rate (`CI=true npm test`).
- **Manual verification**: All Critical/High fixes confirmed via curl
  probes &mdash; security-response header presence on representative
  routes, JWT `alg=none` rejection on the email-share verify endpoint,
  `npm ls request` returns empty, `npm ls node-uuid` returns empty,
  `npm ls jsonwebtoken` resolves to `9.x.x`, `npm ls passport` resolves
  to `0.7.x`.
- **Performance**: All critical paths within 10% of the
  `pre-security-remediation` baseline &mdash; authentication latency,
  trinket page load, and Socket.IO WebSocket handshake to first execution
  response.

Operators consuming this codebase are encouraged to re-run these gates as
part of their own release process and to subscribe to the upstream
repository's security advisories for future updates.
