// SECURITY: ESLint security plugin configuration (AAP §0.5.2 Strategy I / R9)
// SECURITY: Targets lib/, config/, serverside/*/manager/ for static analysis (SAST)
// SECURITY: Excludes public/ via .eslintignore (frozen AngularJS frontend per ADR-5)
// SECURITY: Per AAP §0.5.2 Strategy I: "Execute ESLint security plugin on pre-commit hook"
// SECURITY: Per AAP §0.10.1 verification command:
//   npx eslint lib/ config/ serverside/python/manager/ serverside/r/manager/ \
//     serverside/java/manager/ serverside/pygame/manager/ --ext .js --no-fix
// SECURITY: Severity mapping per AAP §0.11.1 Discovery Discipline —
//   'error' = must-fix (Critical/High); 'warn' = document-only (Medium)
// SECURITY: Per AAP §0.11.4 success criterion — zero Critical security findings;
//   warnings on detect-object-injection in routes are acceptable because Mongoose
//   schema typing in mutating routes provides defense-in-depth (per AAP §0.5.2 Strategy H).

'use strict';

module.exports = {
  // SECURITY: root:true prevents ESLint from walking up parent directories looking
  // for additional configurations that could weaken or override this security baseline.
  root: true,

  // SECURITY: Establish runtime environments to give the parser/linter accurate
  // global definitions. Mismatched env declarations are a common source of false
  // positives that hide real findings.
  env: {
    // SECURITY: Trinket main app runs on Node 20 LTS post-Dockerfile upgrade
    // (AAP §0.5.2 Strategy F / R6 — node:16-bullseye → node:20-bullseye).
    node: true,

    // SECURITY: ECMAScript 2022 — supported by Node 20 LTS; enables modern syntax
    // such as Array.prototype.at, Object.hasOwn, top-level await, and class fields,
    // all of which are safer alternatives to legacy patterns.
    es2022: true,

    // SECURITY: Mocha 3.x (frozen per §6.6.12.3) drives test/* — registers
    // describe/it/before/after as readonly globals so the linter does not flag them.
    mocha: true
  },

  // SECURITY: parserOptions establishes the syntax baseline. ecmaVersion mismatches
  // suppress real findings (e.g., async/await flagged as syntax errors) — keep aligned
  // with the runtime environment to ensure security rules can reach all code paths.
  parserOptions: {
    // SECURITY: Match env.es2022 for consistent parsing of modern syntax.
    ecmaVersion: 2022,

    // SECURITY: Main app and serverside shell containers use CommonJS (require/exports);
    // serverside/*/manager files are ESM (per "type": "module" in their package.json)
    // and are handled by an override block below.
    sourceType: 'script'
  },

  // SECURITY: Register the eslint-plugin-security plugin which provides OWASP-aligned
  // security rules. Declared in package.json devDependencies as eslint-plugin-security@^2.1.1
  // per AAP §0.7.1.
  plugins: [
    'security'
  ],

  // SECURITY: Inherit the recommended baseline ruleset from eslint-plugin-security.
  // Per-rule overrides below tune severity per AAP §0.11.1 Discovery Discipline.
  // The 'recommended' preset enables: detect-unsafe-regex, detect-buffer-noassert,
  // detect-child-process, detect-disable-mustache-escape, detect-eval-with-expression,
  // detect-new-buffer, detect-no-csrf-before-method-override, detect-non-literal-fs-filename,
  // detect-non-literal-regexp, detect-non-literal-require, detect-object-injection,
  // detect-possible-timing-attacks, detect-pseudoRandomBytes, detect-bidi-characters.
  extends: [
    'plugin:security/recommended-legacy'
  ],

  // SECURITY: Globals declared in app.js for backwards compatibility with the
  // legacy Mongoose model loader. These mirror gleak.ignore() registrations at
  // app.js lines 341–345 and the global `log` symbol at app.js line 19.
  // Declaring them as 'readonly' lets the linter detect accidental reassignment
  // (a potential auth-bypass vector) while permitting reads across the codebase.
  globals: {
    // SECURITY: Global Winston logger initialized at app.js line 19; consumed by
    // every module via `log.info/warn/error`. Must remain readonly — reassignment
    // would silently disable the audit trail.
    log: 'readonly',

    // SECURITY: Mongoose model globals assigned at app.js lines 290–298.
    // Treating them as readonly catches accidental shadowing that could route
    // queries to the wrong collection (broken access control / OWASP A01).
    User: 'readonly',
    Course: 'readonly',
    Lesson: 'readonly',
    Material: 'readonly',
    File: 'readonly',
    Trinket: 'readonly',
    Interaction: 'readonly',
    Folder: 'readonly',
    CourseInvitation: 'readonly',

    // SECURITY: Promise is a built-in but app.js lines 4–16 polyfills Promise.spread
    // and Promise.fail for Mongoose 6 compatibility. Declared explicitly so that
    // accessing Promise.spread/Promise.fail does not trigger no-undef false positives.
    Promise: 'readonly',

    // SECURITY: NODE_CONFIG is registered by the legacy `config` package.
    // Listed in app.js gleak.ignore so the leak detector does not flag it.
    NODE_CONFIG: 'readonly',

    // SECURITY: DEFAULT_FILE_PATH is a runtime constant used by lib/util/file.js
    // for the default S3 bucket prefix. Listed in app.js gleak.ignore.
    DEFAULT_FILE_PATH: 'readonly',

    // SECURITY: tokenizer / $V / $M / $L / $P are tokenizer/parser globals from
    // legacy code paths exercised under specific feature flags; listed in
    // app.js gleak.ignore so the leak detector does not surface them.
    tokenizer: 'readonly',
    $V: 'readonly',
    $M: 'readonly',
    $L: 'readonly',
    $P: 'readonly'
  },

  rules: {
    // ============================================================
    // SECURITY: OWASP A03 Injection — eval-class and command-injection sinks
    // ============================================================

    // SECURITY: Block eval() invocations on dynamic expressions — direct vector
    // for arbitrary code execution. Critical-severity per AAP threat model
    // (untrusted learner code already executes in sandboxed shell containers,
    // so any eval in main app code is a confused-deputy escalation).
    'security/detect-eval-with-expression': 'error',

    // SECURITY: Block require() with non-literal arguments — dynamic require()
    // can load attacker-controlled modules and bypass the import whitelist.
    // High-severity; covered also by the no-eval-class checks below.
    'security/detect-non-literal-require': 'error',

    // SECURITY: Block child_process.{exec,execSync,spawn,spawnSync,execFile} usage
    // with dynamic input. The main app must never shell out to untrusted strings;
    // shell execution is bounded to the dedicated serverside shell containers.
    'security/detect-child-process': 'error',

    // SECURITY: Flag RegExp constructor with non-literal patterns — ReDoS exposure
    // (CWE-1333) when user input reaches a regex engine. Set to 'warn' because
    // legitimate audit cases exist (e.g., dynamic search filters validated by Joi);
    // each warning must be reviewed for ReDoS-resistant pattern construction.
    'security/detect-non-literal-regexp': 'warn',

    // SECURITY: Flag bracket-notation property access driven by user input — vector
    // for prototype pollution and operator-injection (CWE-915, CWE-1321). Set to
    // 'warn' because Mongoose schema typing in mutating routes plus Joi payload
    // whitelisting (per AAP §0.5.2 Strategy H) provides defense-in-depth; the
    // controllers may legitimately read/write `obj[joiValidatedKey]` patterns.
    'security/detect-object-injection': 'warn',

    // ============================================================
    // SECURITY: OWASP A02 Cryptographic Failures
    // ============================================================

    // SECURITY: Flag pseudoRandomBytes usage — must use crypto.randomBytes (CSPRNG)
    // for any token, ID, or secret generation (CWE-338). High-severity per AAP §0.5.4:
    // crypto.randomBytes is the OWASP-recommended baseline.
    'security/detect-pseudoRandomBytes': 'error',

    // SECURITY: Flag string equality comparisons that may leak timing information
    // (CWE-208). Set to 'warn' because bcrypt.compare and crypto.timingSafeEqual
    // are used for password and HMAC verification respectively (constant-time);
    // application-level == / === comparisons for non-secret identifiers (e.g.,
    // ownership checks per AAP §0.5.2 Strategy G) are intentionally non-timing-safe
    // because the compared values are not secrets, just resource IDs.
    'security/detect-possible-timing-attacks': 'warn',

    // ============================================================
    // SECURITY: OWASP A05 Security Misconfiguration / A01 Broken Access Control
    // ============================================================

    // SECURITY: Flag fs.* methods (readFile, writeFile, createReadStream, etc.)
    // invoked with non-literal path arguments — path traversal exposure (CWE-22).
    // Set to 'warn' because lib/util/file.js and lib/workers/exports.js construct
    // paths from validated database identifiers; each warning must confirm the
    // path component is sanitized (no '..' or null-byte) per AAP §0.5.2 Strategy G.
    'security/detect-non-literal-fs-filename': 'warn',

    // SECURITY: Flag Buffer constructor and noAssert usage — deprecated and
    // exploitable for memory disclosure on older Node versions (CVE-2018-12116
    // and similar). Errors block any new occurrence; existing call sites must
    // be migrated to Buffer.alloc / Buffer.from per Node 20 best practices.
    'security/detect-buffer-noassert': 'error',
    'security/detect-new-buffer': 'error',

    // SECURITY: Flag handlebars/mustache escape disablement — XSS exposure
    // (CWE-79). Trinket uses Nunjucks (autoescape per AAP §0.5.2 Strategy H);
    // any template engine where escape is disabled is an active XSS sink.
    'security/detect-disable-mustache-escape': 'error',

    // ============================================================
    // SECURITY: General code quality rules that enable security defenses
    // ============================================================

    // SECURITY: Strict-mode discipline is mixed (CommonJS files explicit; ESM
    // implicit). Project does not enforce 'use strict' at the linter level;
    // rely on env.es2022 + sourceType to provide modern syntax safety.
    'strict': 'off',

    // SECURITY: Block reads/writes of undefined identifiers — catches typos
    // such as `userid` vs `userId` that have caused real auth-bypass bugs in
    // Hapi route handlers (e.g., misnamed credentials field returning empty).
    'no-undef': 'error',

    // SECURITY: Block eval() entirely (orthogonal to detect-eval-with-expression
    // which flags only dynamic expressions) — eliminates the eval sink class.
    'no-eval': 'error',

    // SECURITY: Block setTimeout/setInterval/Function with string arguments —
    // implied-eval is functionally equivalent to eval() for security purposes.
    'no-implied-eval': 'error',

    // SECURITY: Block new Function(...) — runtime code generation is a code-injection
    // vector indistinguishable from eval(). One legacy use exists at app.js
    // line 323 inside the gleak diagnostic helper (eval(name) inside a try/catch);
    // the override below relaxes this for that one diagnostic file.
    'no-new-func': 'error'
  },

  // SECURITY: Per-path overrides tune the rule set for files whose patterns are
  // intentional and known-safe, preventing review fatigue from noise on
  // legitimate cases. Each override block documents the security rationale.
  overrides: [
    {
      // SECURITY: Serverside managers (Python, R, Java, Pygame) are Node 18 ESM
      // modules per AAP §0.7.1. Their package.json declares "type": "module"
      // and they use import/export syntax; sourceType must be 'module' for the
      // parser to accept their syntax (otherwise security rules cannot reach
      // these files at all and we lose SAST coverage of the manager tier).
      files: ['serverside/*/manager/**/*.js'],
      parserOptions: {
        sourceType: 'module',
        ecmaVersion: 2022
      },
      env: {
        node: true,
        es2022: true
      }
    },
    {
      // SECURITY: Test files (Mocha-driven) deliberately exercise edge cases —
      // including injection payloads, dynamic property access in test fixtures,
      // and dynamic regex patterns — which would otherwise generate false
      // positives that drown out real findings. Production-code rules remain
      // active; only the noisy detection rules are relaxed for tests.
      files: ['test/**/*.js'],
      env: {
        mocha: true,
        node: true
      },
      rules: {
        // SECURITY: Test fixtures legitimately reference path-literal-suffixed
        // files such as test/data/*.json — disable to avoid noise on fixtures.
        'security/detect-non-literal-fs-filename': 'off',

        // SECURITY: Test data uses dynamic property access (e.g., looping over
        // attack payload tables) — disable to keep injection.test.js readable.
        'security/detect-object-injection': 'off',

        // SECURITY: Tests construct regex patterns dynamically to express
        // negative-test scenarios — disable to keep ReDoS-style negative tests
        // from triggering the rule on the exploit payload itself.
        'security/detect-non-literal-regexp': 'off',

        // SECURITY: Test helpers may compare bcrypt hashes or session tokens
        // with string equality for assertion purposes — these are deterministic
        // assertion comparisons, not authentication decisions.
        'security/detect-possible-timing-attacks': 'off'
      }
    },
    {
      // SECURITY: Configuration files (config/*.js, vite.config.mjs, .eslintrc.js)
      // load named modules dynamically by design (e.g., config/aws.js, config/db.js
      // bridging YAML configuration to runtime SDK construction). Object indexing
      // on configuration objects is intentional and operator-controlled, not
      // user-controlled. Relax the noisy rules so that the actual security
      // findings on these files (e.g., hardcoded secrets) remain visible.
      files: ['config/**/*.js', '.eslintrc.js', 'vite.config.*'],
      rules: {
        'security/detect-non-literal-require': 'off',
        'security/detect-object-injection': 'off',
        'security/detect-non-literal-fs-filename': 'off'
      }
    },
    {
      // SECURITY: app.js contains a single eval(name) inside the gleak leak
      // detector at line 323 wrapped in try/catch. The string passed to eval
      // is a global identifier name returned by gleak.detectNew() — an internal
      // diagnostic, never reached by user input. Disable no-new-func and
      // no-eval at this single file to avoid blocking the diagnostic; the
      // detect-eval-with-expression rule remains active and will surface any
      // new eval site that processes a non-literal expression.
      files: ['app.js'],
      rules: {
        'no-eval': 'off',
        'no-new-func': 'off'
      }
    },
    {
      // SECURITY: Vendored frontend bundles (public/components/, public/js/skulpt/,
      // public/js/embed/) are frozen per ADR-5; .eslintignore excludes them
      // from scan entirely. This override is a belt-and-suspenders safety net
      // in case .eslintignore is bypassed (e.g., if a future maintainer runs
      // ESLint with --no-eslintrc): ensure security rules are not enforced on
      // frozen vendored code where remediation is documented as out-of-scope
      // per the AAP Frontend Freeze Directive.
      files: ['public/**/*.js'],
      rules: {
        'security/detect-eval-with-expression': 'off',
        'security/detect-non-literal-require': 'off',
        'security/detect-child-process': 'off',
        'security/detect-non-literal-regexp': 'off',
        'security/detect-object-injection': 'off',
        'security/detect-pseudoRandomBytes': 'off',
        'security/detect-possible-timing-attacks': 'off',
        'security/detect-non-literal-fs-filename': 'off',
        'security/detect-buffer-noassert': 'off',
        'security/detect-new-buffer': 'off',
        'security/detect-disable-mustache-escape': 'off',
        'security/detect-unsafe-regex': 'off',
        'security/detect-bidi-characters': 'off',
        'security/detect-no-csrf-before-method-override': 'off',
        'no-undef': 'off',
        'no-eval': 'off',
        'no-implied-eval': 'off',
        'no-new-func': 'off'
      }
    }
  ]
};
