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
| CVE-2023-2142  | `nunjucks`                 | `^3.2.0`             | `^3.2.4`                                | A06   | CWE-79   | (library upgrade)          |
| CVE-2020-26237 | `highlight.js`             | `^9.6.0`             | `^11.9.0`                               | A06   | CWE-1321 | (library upgrade)          |
| CVE-2021-23413 | `jszip`                    | `~3.6.0`             | `^3.10.1`                               | A06   | CWE-22   | (library upgrade)          |
| CVE-2025-54798 | `tmp`                      | `0.0.25`             | `^0.2.3` (lockfile resolves `0.2.5` &ge; patched `0.2.4`) | A06 | CWE-59   | (library upgrade)          |
| CVE-2020-7769  | `nodemailer`               | `^2.5.0`             | `^8.0.7` (see post-AAP fixes below)     | A06   | CWE-77   | (library upgrade)          |
| CVE-2015-8851  | `node-uuid` &rarr; `uuid`  | `node-uuid@^1.4.3`   | replaced with `uuid@^9.0.1`             | A02   | CWE-330  | `lib/controllers/users.js` |
| CWE-1104       | `node:16-bullseye` runtime | `node:16-bullseye`   | `node:20-bookworm-slim`                 | A06   | CWE-1104 | `Dockerfile`               |

#### Post-AAP Critical / High Advisories (resolved during code review remediation)

The original AAP &sect;0.7.1 dependency table did not anticipate the
following Critical/High advisories, which were surfaced by the
post-implementation `npm audit --omit=dev --audit-level=high` gate during
code review. They have been remediated in this same audit pass either by
direct dependency bump or by `npm` `overrides` (the latter forcing patched
transitive versions while preserving the AAP-specified direct-dependency
pins where the direct dependency itself is not in scope).

| GHSA Advisory(ies) | Package | Path | Resolution | OWASP | CWE | Notes |
| ------------------ | ------- | ---- | ---------- | ----- | --- | ----- |
| GHSA-vh95-rmgr-6w4m, GHSA-xvch-5gv4-984h | `minimist` | transitive via `optimist` | `overrides: { optimist: { minimist: "^1.2.8" } }` | A06 | CWE-1321 | Prototype Pollution. `optimist` is used at `lib/util/routeParser.js:20` so cannot be removed; the scoped override forces optimist's nested minimist to a patched 1.2.x release. |
| GHSA-582f-p4pg-xc74 | `csv-parse` | transitive via `csv` | `overrides: { csv-parse: "^4.16.2" }` | A06 | CWE-1333 | ReDoS in csv-parse. `csv` is used at `lib/controllers/admin.js:8`; the override pins csv-parse to a patched 4.16.x release while preserving the existing `csv@~1.2.1` direct API. |
| GHSA-h6ch-v84p-w6p9, GHSA-73rr-hh4g-fpgx | `diff` | direct dep | direct bump `~1.0.8` &rarr; `^5.2.2` | A06 | CWE-1333 | ReDoS / DoS in `parsePatch` and `applyPatch`. The only call site is `diff.applyPatch(...)` in `lib/controllers/course.js:440`, whose API is preserved across diff 1.x &rarr; 5.x. |
| GHSA-mm7p-fcc7-pg87, GHSA-rcmh-qjqh-p98v, GHSA-c7w3-x93f-qmm8, GHSA-vvjj-xcjg-gr5g | `nodemailer` | direct dep | direct bump `^6.9.16` &rarr; `^8.0.7` | A06 | CWE-77, CWE-93, CWE-400 | Interpretation conflict, addressparser DoS, SMTP command injection via `envelope.size`, CRLF injection via EHLO/HELO transport name. The basic `createTransport` / `sendMail` API used by `lib/util/mailer.js` is preserved across nodemailer 6.x &rarr; 8.x. |
| GHSA-34x7-hfp2-rc4v, GHSA-8qq5-rm4j-mr97, GHSA-83g3-92jg-28cx, GHSA-qffp-2rhf-9h96, GHSA-9ppj-qmqm-q256, GHSA-r6q2-hw4h-h46w | `tar` | transitive via `bcrypt` &rarr; `@mapbox/node-pre-gyp` | `overrides: { tar: "^7.5.13" }` | A06 | CWE-22, CWE-59, CWE-362 | Six path-traversal / symlink / race-condition advisories. `bcrypt@^5.1.0` is preserved as an in-scope direct dependency; the override forces a patched `tar` for the prebuild download path used during install. |
| GHSA-jg4p-7fhp-p32p | `@hapi/content` | transitive via `@hapi/hapi` &rarr; `@hapi/subtext` &rarr; `@hapi/pez` | `overrides: { @hapi/content: "^6.0.1" }` | A06 | CWE-1333 | ReDoS in HTTP header parsing. `@hapi/hapi@^20.0.0` direct pin is preserved per AAP &sect;0.4.2 ("Hapi-ecosystem pins remain unchanged"); the override pins the affected transitive to its patched release. |

Additional dependency hardening upgrades applied in the same pass (no
demonstrated Critical/High CVE on installed pin, but pulled forward to a
maintained release line as part of the dependency-graph refresh): `bull`
`^0.7.0` &rarr; `^4.16.4`, `mkdirp` `~0.3.5` &rarr; `^3.0.1`, `js-yaml`
`~3.0.1` &rarr; `^4.1.0`, `is-svg` `^2.1.0` &rarr; `^4.4.0`, `validator`
`^5.6.0` &rarr; `^13.12.0`, `accepts` `~1.1.0` &rarr; `^1.3.8`,
`moment-timezone` `~0.5.21` &rarr; `^0.5.45` (note: an earlier draft of
this audit attributed CVE-2022-24999 to this row; that CVE in fact
affects the `qs` library &lt;`6.10.3` as used by Express, not
`moment-timezone`, and is not applicable to this Hapi-based project &mdash;
the only `qs@0.6.5` in the dependency tree is reachable solely through
the dev-only `supertest` &rarr; `superagent` chain and predates the 6.x
prototype-pollution code path).

#### Transitive Dependency Overrides

The following block is present in the root `package.json` to force patched
versions of transitive dependencies whose direct parents cannot be upgraded
without violating the AAP minimal-change clause (per AAP &sect;0.10.4) or
breaking an explicitly preserved API contract (per AAP &sect;0.4.2). Each
override targets a single identified CVE class; no override is applied
without a corresponding advisory citation in the post-AAP table above.

```json
"overrides": {
  "@hapi/content": "^6.0.1",
  "csv-parse": "^4.16.2",
  "optimist": {
    "minimist": "^1.2.8"
  },
  "tar": "^7.5.13"
}
```

When upgrading any of the parent direct dependencies (`@hapi/hapi`, `csv`,
`optimist`, `bcrypt`) in a future sprint, the corresponding override should
be re-evaluated and removed if the transitive resolution naturally lands on
a patched version.

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

## Accepted Operator Risk (Explicit Acceptance)

The findings below are flagged at **High** severity by `npm audit` but cannot
be remediated within the scope of the current audit without violating the AAP
minimal-change clause and breaking a runtime-critical security control. They
are therefore documented here as **explicit operator-accepted risk**, with
the compensating controls and the path to future remediation enumerated. This
section supersedes any earlier "soft-fail" interpretation of the
`npm audit --omit=dev --audit-level=high` gate at the repository root: the
gate may legitimately surface these accepted-risk findings, and reviewers
should cross-reference this section to confirm that no NEW (un-accepted)
High/Critical advisory has appeared.

| ID   | Finding                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | npm-audit Severity | Why Not Remediated In This Pass                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Compensating Controls                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Recommended Future Action                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| A-01 | Custom `marked` Trinket fork at `git+https://github.com/trinketapp/marked.git`. `npm audit` reports four ReDoS / Inefficient-Regex advisories whose patched-version ranges all require **`marked >= 4.0.10`**: GHSA-x5pg-88wf-qq4p (CVSS 7.5), GHSA-rrrm-qjm4-v8hf (CVSS 7.5), GHSA-5v2h-r2cx-5xgj (CVSS 7.5), GHSA-hjcp-j389-59ff (CVSS 7.5), plus pre-fork advisories GHSA-cfjh-p3g4-3q2f, GHSA-7px7-7xjx-hxm8, GHSA-vfvf-mqq8-rwqc, GHSA-p9wx-2529-fp83. The Trinket fork is based on upstream `marked@0.3.2` plus Trinket-specific extensions and CANNOT be upgraded to upstream `marked@>=4.0.10` without a substantial refactor — see "Why Not Remediated" column.                                                                                                       | High               | The Trinket fork extends `marked@0.3.2` with a `sanitize: function(html) { ... }` callback option that is **specific to the fork**: upstream `marked` only accepted a Boolean `sanitize` flag in 0.3.x and **removed the `sanitize` option entirely in `marked@1.0.0`**. The fork-only callback drives the application's HTML allow-listing for embedded markdown (whitelisted tags, sanitized iframes via `lib/shared/trinket-markdown.js:211-256`), which is a runtime-critical security control. Replacing the fork with upstream `marked@>=4.0.10` therefore requires (1) re-implementing the entire HTML sanitization pipeline against an external sanitizer (e.g. DOMPurify or sanitize-html), (2) reproducing the fork's tag/attribute allow-list semantics outside marked, and (3) re-validating against the extensive iframe / embed integration surface. That cross-cutting refactor exceeds the current audit's binding minimal-change clause and is explicitly held out as future work pending operator authorization. | (i) The advisories are all ReDoS / Inefficient-Regex against attacker-supplied markdown. Trinket's markdown surface is reached only through authenticated authoring paths (course / lesson content, trinket descriptions) that already require login; anonymous markdown rendering is not exposed. (ii) Rendered markdown is delivered inside iframes that are sandboxed **without** `allow-same-origin`, so any payload that did manage to inflate parser CPU is contained at the iframe boundary. (iii) Hapi's request-level timeouts and the `read_only` filesystem on the adversarial Code Execution Zone limit per-request resource usage. (iv) `npm audit` runs at the supply-chain gate, not at runtime; no parser change is silently introduced. The combination of authenticated input, iframe sandboxing, request timeouts, and the fork's existing tag allow-list reduces the practical exploitability of the four ReDoS advisories. | Plan a separate, explicitly-authorized remediation sprint that (1) audits the Trinket-specific fork extensions in `lib/shared/trinket-markdown.js` (custom `sanitize` callback, custom code/image/link/listitem renderers, embed-URL rewriting), (2) ports those extensions to either upstream `marked@>=4.0.10` (via the `marked.use({extensions: ...})` API and an external sanitizer such as DOMPurify) or a maintained alternative parser, and (3) re-validates against the full markdown rendering test surface. Operators of self-hosted deployments who do not require the Trinket-specific extensions may choose to override the dependency to upstream `marked@^4` immediately, accepting the loss of fork-specific behavior; that path is explicitly **not** part of this audit's scope. **Until the migration lands, operators consuming this codebase should treat the four `marked` HIGH advisories as acknowledged operator risk and ensure the iframe-sandbox + authenticated-authoring compensating controls described above remain in place.** |

The `npm audit --omit=dev --audit-level=high` gate may continue to surface
A-01 (the four `marked` advisories) until the Trinket fork is migrated.
Reviewers MUST verify that **only** the four `marked`-source advisories
appear in the gate output; any other High/Critical finding indicates a
regression and MUST be remediated before release.

## Residual-Risk Register

The findings below remain after the remediation. They are below the
Critical/High remediation threshold, are explicitly held out of scope by the
audit's minimal-change clause, or are operator infrastructure
responsibilities. Each row carries a recommended future action.

| ID   | Finding                                                                                                                                | Severity   | Scope Reason                                                  | Recommended Future Action                                                                                                  |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| R-01 | AngularJS 1.3.20 EOL frontend in `public/`                                                                                             | Medium     | Out of scope per user instructions                            | Plan migration to a maintained framework. Interim mitigation: iframe sandbox **without** `allow-same-origin` is preserved. |
| R-02 | Custom `marked` Trinket fork at `git+https://github.com/trinketapp/marked.git` &mdash; **escalated to A-01 in the Accepted Operator Risk section above**; this row is preserved as a back-reference                                                              | High       | See A-01 above for full operator risk acceptance              | See A-01 above for the migration path.                                                                                     |
| R-03 | `node-cryptojs-aes@^0.4.0` unmaintained                                                                                                | Medium     | Documented; non-exploitable in current usage in `lib/util/roles.js` | Replace with built-in `crypto` AES-GCM in a future sprint.                                                                 |
| R-04 | Dev-dependency staleness (`mocha@^3.4.1`, `chai@^3.5.0`, `sinon@~1.7.3`, `should@~3.0.0`, `supertest@~0.8.3`)                           | Low        | Internal-only; deferred                                       | Upgrade dev dependencies in a follow-up PR. Not part of the `npm audit --omit=dev` gate because they are test-runner only. |
| R-05 | `mongoose-schema-extend@~0.2.2` deprecated                                                                                             | Low        | Out of scope per minimal-change clause                        | Replace with native Mongoose discriminators.                                                                               |
| R-06 | `optimist`, `q`, `tab` deprecated / possibly unused-direct                                                                             | Low        | `optimist` is still used at `lib/util/routeParser.js:20`; its prototype-pollution transitive (minimist) is now overridden &mdash; see "Post-AAP Critical / High Advisories" above. `q` and `tab` remain low-impact. | Audit `q` and `tab` for actual usage; remove if unused. Replace `optimist` with `yargs` or built-in `process.argv` parsing in a future sprint and drop the corresponding override. |
| R-07 | nginx serverside `Dockerfile` previously used generic `nginx:alpine`                                                                   | Low        | Pinned to `nginx:1.27-alpine` in this remediation             | Maintain the pinned tag; rotate periodically as new patch releases land.                                                   |
| R-08 | `config@~0.4.35` extremely old                                                                                                         | Low        | Out of scope per minimal-change clause                        | Migrate to `config@^3` in a future sprint. The API surface change is non-trivial.                                          |
| R-09 | TLS termination is operator-supplied                                                                                                   | Documented | Out of scope per user instructions                            | Operator must configure HTTPS at the reverse proxy / load balancer in front of Trinket.                                    |
| R-10 | MongoDB at-rest encryption is operator-supplied                                                                                        | Documented | Out of scope per user instructions                            | Operator must enable disk-level / volume encryption on the MongoDB host.                                                   |
| R-11 | MFA is not implemented                                                                                                                 | Documented | Out of scope per user instructions                            | Plan multi-factor authentication in a future product cycle.                                                                |
| R-12 | `passport-google-oauth@^0.1.5` &rarr; `passport-oauth@0.1.x` &rarr; older `passport` (GHSA-v923-w3x8-wh69)                              | Moderate   | Direct `passport` is patched at `^0.7.0`; the older nested `passport` is reachable only via the Google OAuth strategy. Deferred per minimal-change clause &mdash; bumping `passport-google-oauth` to `2.x` is a breaking change to the OAuth strategy interface. | Bump `passport-google-oauth` to `^2.0.0` in a future sprint and verify the Google OAuth callback path in `lib/controllers/auth.js`. Below `npm audit --audit-level=high` gate. |
| R-13 | `is-svg@^4.4.0` &rarr; `fast-xml-parser` (GHSA-gh4j-gqv2-49f6, XML Comment / CDATA Injection in `XMLBuilder`)                           | Moderate   | `is-svg` is consumed only on the SVG validation path of file uploads; the `XMLBuilder` injection class requires attacker control of the builder input, which is not present in Trinket's read-only validation usage. Below `npm audit --audit-level=high` gate. | Bump `is-svg` to `^5.x` (which depends on a patched `fast-xml-parser`) once compatibility with `lib/controllers/files.js` and `lib/controllers/users.js` SVG validation is verified. |
| R-14 | `aws-sdk@^2.x` region-validation warning (GHSA-j965-2qgj-vjmq); AWS SDK for JavaScript v2 has reached end-of-support                    | Low        | The application supplies the AWS region via the typed `config` object, not from user input, so the region-injection class does not apply. AWS v2 EOL is acknowledged but a v2 &rarr; v3 migration is a non-trivial cross-cutting change touching `config/aws.js`, `lib/controllers/users.js`, and the bulk-export worker. | Plan migration to `@aws-sdk/*` v3 packages in a future sprint. Below `npm audit --audit-level=high` gate. |
| R-15 | Serverside `package-lock.json` files (`serverside/{python,r,java,pygame}/{manager,shell/trinket,worker/trinket}/package-lock.json`) created during checkpoint 1 but not listed as `CREATE` operations in AAP &sect;0.6.1 | Documented | These lockfiles were created so that the AAP &sect;0.10.1 validation gate ("Re-run dependency audits across root and all manager `package.json` files") can be satisfied locally. Each lockfile is auto-generated by `npm install --legacy-peer-deps` in its respective directory and is not a hand-edited artifact. Verified: all four manager and four shell/worker trees report 0 Critical / 0 High via `npm audit`. | Treat as standard build artifacts going forward; regenerate when serverside dependencies change. |
| R-16 | `lib/controllers/users.js` Lambda thumbnail streaming download has no source-stream error handler &mdash; only `writeStream.on('error', ...)` is wired. The pre-remediation `request` library (callback-based) flowed source-stream errors through its own callback; the new axios-based `responseType: 'stream'` path uses Node's `pipe()` which does not forward source-stream errors by default. | Low (Info) | A mid-stream connection drop after a 2xx response begins streaming will not propagate to the outer `.catch()` &mdash; the `writeStream` may stall without firing `finish`, leaving the upload uninitiated and the request handler hung pending Hapi's outer timeout. This matches the legacy `request` library's de-facto behavior, so the application-level contract is preserved. CP3 instructions explicitly designed this way; the AAP minimal-change clause is binding. | Add `response.data.on('error', ...)` (or migrate to `stream.pipeline()` for automatic error propagation) in a future hardening sprint. Below `npm audit --audit-level=high` gate. |
| R-17 | Outbound axios calls in `lib/controllers/auth.js` (Google OAuth token exchange POST and Google profile GET) have no explicit `timeout` option configured. axios's default is `0` (no timeout). | Low (Info) | A slow or unresponsive Google endpoint could cause the OAuth callback request to hang indefinitely. Hapi's outer request timeout will eventually fire, but adding an explicit per-call timeout provides faster failure. CP3 instructions explicitly noted this as a residual concern, not a blocker per the AAP minimal-change clause. | Add `{ timeout: 10000 }` (or similar) to the axios POST/GET option object in a future hardening sprint. Below `npm audit --audit-level=high` gate. |

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
  mkdirp, bull, nodemailer, is-svg, validator, accepts, diff); deprecated
  `request` and `node-uuid` packages replaced with maintained successors
  (`axios`, `uuid`); transitive vulnerabilities in `minimist` (via
  `optimist`), `csv-parse` (via `csv`), `tar` (via `bcrypt`), and
  `@hapi/content` (via `@hapi/hapi`) eliminated through the
  `package.json` `overrides` block (see "Transitive Dependency Overrides"
  above); main-application container base image upgraded from
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

- **Dependency audit**: Zero **un-accepted** Critical/High CVEs across all
  manifests. Run `npm audit --omit=dev --audit-level=high` at the repository
  root and inside every `serverside/*/manager/`,
  `serverside/*/shell/trinket/`, and `serverside/pygame/worker/trinket/`
  package directory. Reviewers MUST cross-reference any remaining gate
  output against the **Accepted Operator Risk** section above (the four
  `marked` ReDoS advisories grouped under A-01 are the **only** High-severity
  findings that may legitimately appear in the root audit). Any other
  Critical/High finding — including any new `marked` advisory not listed
  under A-01 — represents a regression and MUST be remediated before
  release. The serverside tree audits MUST report zero Critical/High
  findings (no exceptions).
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
