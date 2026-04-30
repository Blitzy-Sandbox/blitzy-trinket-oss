#!/usr/bin/env node

// Add Q-compatible methods to native Promise for Mongoose 6 compatibility
if (!Promise.prototype.spread) {
  Promise.prototype.spread = function(fn) {
    return this.then(function(result) {
      if (Array.isArray(result)) {
        return fn.apply(null, result);
      }
      return fn(result);
    });
  };
}
if (!Promise.prototype.fail) {
  Promise.prototype.fail = Promise.prototype.catch;
}

// initialize the global logger
log = require('./config/log');

const Hapi           = require('@hapi/hapi');
const Boom           = require('@hapi/boom');
const Inert          = require('@hapi/inert');
const Vision         = require('@hapi/vision');
const Yar            = require('@hapi/yar');
const Crumb          = require('@hapi/crumb'); // SECURITY: CSRF synchronizer-token middleware (AAP §0.5.2 Strategy E / R5 / OWASP A01 / CWE-352)
const config         = require('./config/app.config');
const Helpers        = require('./lib/util/helpers');
const Authentication = require('./lib/auth/passport.js');
// gleak is not compatible with Node 16+ (uses GLOBAL which was removed)
// Use a no-op fallback for now
let gleak;
try {
  gleak = require('gleak')();
} catch (e) {
  gleak = { detectNew: () => [], ignore: () => {} };
}
const mailer         = require('./lib/util/mailer');
const viewEngine     = require('./lib/util/nunjucks');
const CatboxMongoose = require('./lib/util/catbox-mongoose');
const fs             = require('fs');
const path           = require('path');

config.viewEngine = viewEngine;

const cache_control = 'private, s-maxage=0, max-age=0, no-cache, no-store, must-revalidate, proxy-revalidate';

// SECURITY: Content-Security-Policy for main app pages.
//           (AAP §0.5.2 Strategy D / R4; OWASP A05 Security Misconfiguration; CWE-79 XSS).
//
// Threat model: per §6.4.4.4.4 the main app is NOT the execution sandbox - learner code runs
//   in iframe-isolated sandbox URLs (config.sandboxUrl) which are EXEMPTED from this CSP via
//   the isEmbedOrSandbox() path matcher below. This CSP applies to authenticated user UI
//   only (login, signup, profile, course, admin pages) where XSS = account takeover.
//
// Frontend constraints (AAP Frontend Freeze Directive / ADR-5):
//   AngularJS 1.3.20 is FROZEN — it inherently requires 'unsafe-inline' for $compile/ng-bind
//   and 'unsafe-eval' for $parse (Function() constructor). Per the AAP Frontend Freeze Directive
//   "do not upgrade AngularJS"; per AAP §0.5.4 the CSP-vs-AngularJS trade-off is a documented
//   compensating control. We accept the weaker XSS protection on script-src to preserve the
//   frozen frontend, but RETAIN strong defenses elsewhere:
//     - default-src 'self'         → only same-origin resources by default
//     - script-src whitelist       → only the explicit CDN list (blocks rogue script injection)
//     - object-src 'none'          → no <object>/<embed>/<applet> Flash/Java applets
//     - base-uri 'self'            → blocks <base> tag hijacking (CWE-79 vector)
//     - form-action 'self'         → blocks form-jacking to attacker domains
//     - frame-ancestors 'self'     → blocks clickjacking (defense-in-depth with X-Frame-Options)
//     - frame-src 'self' + sandbox → only the execution sandbox iframe is allowed
//
// Protocol policy: lib/views/ templates use protocol-relative URLs (e.g., //cdnjs.cloudflare.com/...)
//   which load over HTTP in dev/HTTP deployments and HTTPS in production. Source expressions
//   without a protocol scheme (per CSP3 §3.2 source-expression grammar) match BOTH http: and
//   https: schemes — required for backward compatibility per AAP API/Backward-Compat directives.
//   Operators deploying behind HTTPS can further tighten by restricting to `https://hostname`
//   if they audit their templates for non-HTTPS references.
const mainAppCSP = [
  "default-src 'self'",
  // Script sources: AngularJS 1.3.20 (frozen per ADR-5) requires 'unsafe-inline' for ng-bind
  // and inline init scripts, plus 'unsafe-eval' for $parse Function() constructor. Documented
  // compensating control per AAP §0.5.4. The whitelist still blocks injection from any other
  // origin (rogue CDN). reCAPTCHA from www.google.com is allowed for human-verification flows.
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' www.google.com www.gstatic.com www.googletagmanager.com cdnjs.cloudflare.com ajax.googleapis.com",
  // Style sources: 'unsafe-inline' REQUIRED for AngularJS 1.3.20's ng-class/ng-style and
  // Foundation 5 inline styles (frozen frontend per ADR-5).
  "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com ajax.googleapis.com fonts.googleapis.com",
  // Image sources: data: for embedded SVG icons; blob: for client-generated images
  // (e.g., trinket snapshot generation); allow any HTTPS+HTTP (CDN images, user uploads).
  "img-src 'self' data: blob: https: http:",
  // Font sources: data: for inline base64 fonts; specific font CDNs.
  "font-src 'self' data: fonts.gstatic.com cdnjs.cloudflare.com",
  // Connect sources: AJAX/fetch/WebSocket origins. Scoped to 'self' + reCAPTCHA verify endpoint
  // + the same CDN whitelist (browsers fetch source maps via fetch and these need to resolve).
  "connect-src 'self' www.google.com cdnjs.cloudflare.com ajax.googleapis.com",
  // Frame sources: 'self' for course/admin embeds; sandboxUrl for the execution iframe.
  "frame-src 'self' " + (config.sandboxUrl || ''),
  // Block <object>/<embed>/<applet> (Flash/Java applets — defense-in-depth per OWASP Top 10).
  "object-src 'none'",
  // Restrict <base> to prevent base-tag hijacking attacks (CWE-79 vector).
  "base-uri 'self'",
  // Restrict form submission targets to same-origin (prevents form-jacking).
  "form-action 'self'",
  // Block embedding in cross-origin frames (defense-in-depth alongside X-Frame-Options).
  "frame-ancestors 'self'"
].join('; ');

// SECURITY: Path matcher for embed/sandbox paths exempt from main-app CSP (per §6.4.4.4.4)
//           Embed paths use inline <script> tags (AngularJS 1.3.20 templates) and need their
//           own security boundary via iframe sandbox attribute (no allow-same-origin per §6.4.5).
//           Matches: /embed, /python_embed, /assignment-embed, /sandbox, /<lang>/run, /<lang>/embed.
//           Implementation note: regexes are anchored at start (^\/) and use bounded character
//           classes ({0,32}) with explicit length limits to prevent ReDoS.
function isEmbedOrSandbox(pathname) {
  if (!pathname) return false;
  return /^\/[a-zA-Z0-9_-]{0,32}embed\b/.test(pathname) ||
         /^\/sandbox\b/.test(pathname) ||
         /^\/(?:python|python3|java|r|glowscript|html|html5|pygame)\/(?:embed|run)\b/.test(pathname);
}

// Main async initialization
const init = async () => {
  // Validate required configuration
  const sessionPassword = config.app.plugins.session.cookieOptions.password;
  if (!sessionPassword || sessionPassword.length < 32) {
    console.error('\n' + '='.repeat(70));
    console.error('ERROR: Session cookie password not configured!');
    console.error('');
    console.error('You must set a secure password (min 32 characters) in config/local.yaml:');
    console.error('');
    console.error('  app:');
    console.error('    plugins:');
    console.error('      session:');
    console.error('        cookieOptions:');
    console.error("          password: 'your-secure-password-at-least-32-characters'");
    console.error('');
    console.error('See config/local.example.yaml for a template.');
    console.error('='.repeat(70) + '\n');
    process.exit(1);
  }

  // SECURITY: Validate app.mail.secret entropy at boot to prevent JWT email-token forgery
  //           (parallel to session password guard above; per AAP §0.5.2 Strategy B / R2 /
  //            OWASP A02 Cryptographic Failures / CWE-798 use of hard-coded credentials).
  // Note: app.mail.secret is used by lib/controllers/trinket.js for JWT HS256 issuance
  //       (email verification and email-share tokens) and by lib/util/helpers.js for verification.
  //       A weak/empty secret allows token forgery, enabling unauthorized email-verify or share.
  // Graceful degradation: only enforce when email IS configured (app.mail.from && app.mail.host)
  //       per lib/util/mailer.js isConfigured() pattern. This preserves the
  //       "SMTP absent → {skipped: true}" directive (AAP §0.8.3) so operators running without
  //       mail features (the default in config/default.yaml which ships empty from/host) are
  //       not blocked at boot. Addresses QA finding 2.1 (mail.secret boot guard absent).
  const mailConfig = config.app && config.app.mail;
  const mailIsConfigured = !!(mailConfig && mailConfig.from && mailConfig.host);
  const mailSecret = mailConfig && mailConfig.secret;
  if (mailIsConfigured && (!mailSecret || mailSecret.length < 32)) {
    console.error('\n' + '='.repeat(70));
    console.error('SECURITY ERROR: app.mail.secret not configured or too short!');
    console.error('');
    console.error('You must set a secure secret (min 32 characters) in config/local.yaml:');
    console.error('');
    console.error('  app:');
    console.error('    mail:');
    console.error("      secret: 'your-mail-jwt-secret-at-least-32-characters'");
    console.error('');
    console.error('This secret signs email verification and email share JWT tokens.');
    console.error('A weak secret allows token forgery (OWASP A02 Cryptographic Failures).');
    console.error('See config/local.example.yaml for a template.');
    console.error('='.repeat(70) + '\n');
    process.exit(1);
  }

  // Create server with Hapi 20+ configuration
  const server = Hapi.server({
    host: config.app.hostname || 'localhost',
    port: config.app.port || 3000,
    routes: {
      cors: config.app.cors || false,
      state: {
        failAction: 'log'
      }
    },
    // Hapi 20+ debug config format
    debug: config.isDev ? { request: ['error'] } : false,
    // Configure MongoDB session cache
    cache: [{
      name: 'sessions',
      provider: {
        constructor: CatboxMongoose.Engine,
        options: {}
      }
    }]
  });

  // Register plugins
  await server.register([
    Inert,  // Static file serving
    Vision, // Template rendering
    {
      plugin: Yar,
      options: {
        storeBlank: false,
        cookieOptions: {
          password: config.app.plugins.session.cookieOptions.password,
          isSecure: config.app.plugins.session.cookieOptions.isSecure !== false,
          isSameSite: 'Lax'
        },
        // Store sessions server-side in MongoDB
        maxCookieSize: 0,
        name: config.app.plugins.session.name || 'session',
        cache: {
          cache: 'sessions',
          expiresIn: 24 * 60 * 60 * 1000 // 24 hours
        }
      }
    },
    {
      // SECURITY: Register @hapi/crumb for synchronizer-token CSRF protection
      //           (AAP §0.5.2 Strategy E / R5 / OWASP A01 Broken Access Control / CWE-352 CSRF).
      //           Per Risk Management: scoped to non-SPA routes first via per-route opt-in
      //           (config/api_routes.js sets `plugins: { crumb: {} }` on /api/exports,
      //           /api/admin/*, /api/users/password, /api/users/email). SPA-consumed (AngularJS)
      //           routes are explicitly deferred per AAP follow-on plan to avoid frontend
      //           coordination breakage. Addresses QA finding 5.1 (CSRF bypass demonstrated).
      // Behavior summary: with restful: true, validation is enforced ONLY on routes that
      //   explicitly opt in via `plugins: { crumb: {} }` (see config/api_routes.js for the
      //   opt-in list). Non-opt-in mutating routes (the AngularJS SPA's POST/PUT/DELETE
      //   endpoints) are NOT validated, preserving SPA backward compatibility. The crumb
      //   cookie is auto-generated on every non-mutating request (GETs, OPTIONs) so the
      //   legitimate user flow can complete the synchronizer-token round trip:
      //     1. User opens server-rendered form via GET → autoGenerate sets crumb cookie
      //     2. User submits POST with crumb in payload (or AJAX with X-CSRF-Token header)
      //     3. @hapi/crumb validates the crumb against the cookie and the route opt-in
      plugin: Crumb,
      options: {
        // SECURITY: Treat POST/PUT/DELETE/PATCH as state-mutating (RFC 7231 §4.2.1).
        //           In `restful` mode, the crumb is delivered via X-CSRF-Token header
        //           (or `_csrf` query/payload) instead of form-encoded body, allowing
        //           AJAX/SPA clients to participate in the synchronizer-token pattern.
        restful: true,
        // SECURITY: Auto-generate token on every response so opt-in routes can validate.
        //           Without autoGenerate, the legitimate POST flow would 403 because the
        //           browser would have no crumb cookie to echo back. This is required for
        //           server-rendered forms (addToViewContext) AND SPA AJAX (X-CSRF-Token).
        autoGenerate: true,
        // SECURITY: Available in Nunjucks templates as 'crumb' context var for server-rendered
        //           forms. Templates can render `<input name="crumb" value="{{crumb}}">` to
        //           submit the token alongside the form payload (synchronizer-token pattern).
        addToViewContext: true,
        cookieOptions: {
          // SECURITY: Mirror session cookie security posture (HTTPS-only when isSecure=true).
          //           When the deployment terminates TLS at a reverse proxy and the app is
          //           behind it (per AAP §0.6.1), isSecure is set in local.yaml accordingly.
          isSecure: config.app.plugins.session.cookieOptions.isSecure !== false,
          // SECURITY: SameSite=Lax matches session cookie; primary CSRF mitigation per AAP §0.6.2.
          //           Synchronizer-token via @hapi/crumb is the secondary, defense-in-depth control.
          isSameSite: 'Lax',
          // Token must be readable by client JS to echo back in X-CSRF-Token header / form body.
          // Note: this is correct per OWASP CSRF Prevention Cheat Sheet — the crumb itself is
          //       not sensitive (it does not authenticate the user; it only proves request origin).
          isHttpOnly: false
        },
        // SECURITY: Skip ALL crumb processing (validation AND generation) for mutating requests
        //           on routes that DO NOT explicitly opt-in via `plugins: { crumb: {} }`.
        //           This is required because @hapi/crumb v9 defaults to opt-OUT (every route
        //           validates by default unless `plugins.crumb === false`). Without this skip,
        //           every existing POST/PUT/DELETE/PATCH endpoint (the entire AngularJS SPA
        //           contract: trinket save, settings update, analytics, etc.) would 403 on
        //           every request, breaking the application. Per AAP Risk Management:
        //           "Scope CSRF token addition to non-SPA routes first; coordinate SPA
        //            integration as a follow-on."
        //
        //           For non-mutating methods (GET/HEAD/OPTIONS), skip returns false so the
        //           crumb cookie is auto-generated on the response — this gives EVERY page
        //           load the crumb cookie that opt-in routes will later validate against.
        //           For mutating methods on opt-in routes, skip returns false so validation
        //           runs (the actual CSRF defense). For mutating methods on non-opt-in routes,
        //           skip returns true so the SPA contract is preserved.
        skip: function(request, h) {
          var mutatingMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
          var isMutating = mutatingMethods.indexOf(request.method.toUpperCase()) !== -1;
          var hasOptIn = !!(request.route.settings.plugins &&
                            request.route.settings.plugins.crumb);
          // Skip when: it's a mutating method AND the route hasn't opted in.
          // Otherwise, let @hapi/crumb run (auto-generate on GETs, validate on opt-ins).
          return isMutating && !hasOptIn;
        }
      }
    }
  ]);

  // Add _logIn method to yar for session-based login
  // Also ensure request.user is set from auth credentials (for inject() calls)
  // Touch session on each request to implement sliding expiration
  server.ext('onPreHandler', (request, h) => {
    if (request.yar) {
      request.yar._logIn = function(user, cb) {
        // Store user id in session
        request.yar.set('userId', user._id ? user._id.toString() : user.id);
        // Also attach user to request for immediate use
        request.user = user;
        if (cb) cb(null);
      };

      // Sliding expiration: touch session to reset TTL on each authenticated request
      if (request.yar.get('userId')) {
        request.yar.touch();
      }
    }
    // Set request.user from auth credentials if not already set
    // This handles inject() calls that pass credentials directly
    if (!request.user && request.auth.credentials && request.auth.credentials._id) {
      request.user = request.auth.credentials;
    }
    return h.continue;
  });

  // Configure view engine (Vision) - use nunjucks compile function
  server.views({
    engines: {
      html: {
        compile: viewEngine.compile
      }
    },
    relativeTo: path.join(__dirname, config.app.templates),
    path: '.',
    isCached: config.isProd
  });

  // SECURITY: Helper to apply security headers to a Hapi response object.
  //           Used for redirects and view responses returned from onPreResponse so that the
  //           security header set is consistent across error pages and HTML responses.
  //           Per AAP §0.5.2 Strategy D / R4 / OWASP A05 / OWASP Secure Headers Project.
  function applySecurityHeadersOnResponse(response, addXFrame, applyCSP) {
    if (!response || typeof response.header !== 'function') return response;
    if (addXFrame) {
      response.header('X-Frame-Options', 'deny');
    }
    response.header('X-Content-Type-Options', 'nosniff');
    response.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (applyCSP) {
      response.header('Content-Security-Policy', mainAppCSP);
    }
    return response;
  }

  // Add onPreResponse extension for cache headers and error pages
  server.ext('onPreResponse', (request, h) => {
    const response = request.response;
    // SECURITY: xframeDeny matcher supports exact paths (e.g., '/login') AND '/<path>/*'
    //   glob entries (e.g., '/admin/*' matches '/admin/users', '/admin/courses') so
    //   X-Frame-Options: deny applies to admin sub-paths served by the
    //   GET /admin/{adminPage*} page route. Per AAP §0.5.2 Strategy D / §0.6.3 / R4 /
    //   OWASP A05 (Security Misconfiguration — clickjacking prevention).
    //   Contract documented in config/default.yaml xframeDeny block.
    const pathname = request.url.pathname;
    const addXFrame = config.app.xframeDeny && config.app.xframeDeny.some((entry) =>
      entry.endsWith('/*') ? pathname.startsWith(entry.slice(0, -1)) : entry === pathname
    );

    // SECURITY: Apply CSP only to non-embed/non-sandbox paths (per §6.4.4.4.4) so the
    //           iframe-based execution sandbox can continue to use inline AngularJS scripts
    //           without being broken by main-app CSP. Computed once per request.
    const applyCSP = !isEmbedOrSandbox(pathname);

    if (response.isBoom) {
      // SECURITY: Apply OWASP-recommended security headers to the Boom response output FIRST,
      //           BEFORE attempting view rendering. This ensures headers are present on the
      //           response even if a subsequent h.view() render fails (which would otherwise
      //           skip the header-setting block at the bottom of this branch).
      //           Addresses QA findings 4.1, 4.2, 4.3 (CSP/X-CTO/Referrer-Policy/X-Frame absent).
      response.output.headers['Cache-Control'] = cache_control;
      response.output.headers['Pragma'] = 'no-cache';
      response.output.headers['Expires'] = '0';
      if (addXFrame) {
        response.output.headers['X-Frame-Options'] = 'deny';
      }
      response.output.headers['X-Content-Type-Options'] = 'nosniff';
      response.output.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
      if (applyCSP) {
        response.output.headers['Content-Security-Policy'] = mainAppCSP;
      }

      const statusCode = response.output.statusCode;

      // Check if this is an HTML request (not API/JSON)
      const acceptHeader = request.headers.accept || '';
      const isApiRequest = request.path.startsWith('/api/') ||
                           acceptHeader.includes('application/json') ||
                           request.path.startsWith('/partials/');

      // Render HTML error pages for browser requests
      const wantsHtml = acceptHeader.includes('text/html') ||
                        (!acceptHeader.includes('application/json') && !isApiRequest);

      if (!isApiRequest && wantsHtml) {
        if (statusCode === 401) {
          // SECURITY: Build the redirect response and apply security headers BEFORE takeover()
          //           per AAP §0.5.2 Strategy D / R4. Without this, takeover() short-circuits
          //           the rest of this extension and the response below is never reached, so
          //           /admin/* unauthenticated requests would return 302 → /login WITHOUT
          //           X-Frame-Options/X-Content-Type-Options/Referrer-Policy/CSP headers.
          //           Addresses QA finding 4.3 (X-Frame-Options missing on /admin redirects).
          const redirectResponse = h.redirect('/login');
          applySecurityHeadersOnResponse(redirectResponse, addXFrame, applyCSP);
          return redirectResponse.takeover();
        } else if (statusCode === 404) {
          // SECURITY: View response wraps the Boom 404 in an HTML error page; if the view render
          //           subsequently fails, Hapi's fallback emits the original Boom output (which
          //           already has our security headers applied above). Headers are applied to
          //           the view response too so successful renders keep the defense-in-depth set.
          return applySecurityHeadersOnResponse(h.view('404.html').code(404), addXFrame, applyCSP);
        } else if (statusCode === 403) {
          return applySecurityHeadersOnResponse(h.view('50x.html').code(403), addXFrame, applyCSP);
        } else if (statusCode >= 500) {
          return applySecurityHeadersOnResponse(h.view('50x.html').code(statusCode), addXFrame, applyCSP);
        }
      }
    }
    else if (response.header) {
      response.header('Cache-Control', cache_control);
      response.header('Pragma', 'no-cache');
      response.header('Expires', '0');

      if (addXFrame) {
        response.header('X-Frame-Options', 'deny');
      }

      // SECURITY: Add OWASP-recommended security headers to all responses
      //           (AAP §0.5.2 Strategy D / R4 / OWASP A05 Security Misconfiguration).
      //           X-Content-Type-Options: blocks MIME sniffing (CWE-430).
      //           Referrer-Policy: limits Referer leakage to cross-origin destinations (privacy).
      //           Addresses QA finding 4.2 (X-CTO and Referrer-Policy headers absent).
      response.header('X-Content-Type-Options', 'nosniff');
      response.header('Referrer-Policy', 'strict-origin-when-cross-origin');

      // SECURITY: Apply CSP to main app pages, excluding embed/sandbox paths (per §6.4.4.4.4).
      //           CSP mitigates server-side XSS surface (CWE-79) by restricting script sources.
      //           Embed/sandbox paths use inline scripts (AngularJS templates) and have their own
      //           security boundary via iframe sandbox attribute (no allow-same-origin per §6.4.5).
      //           Addresses QA finding 4.1 (CSP header absent).
      if (applyCSP) {
        response.header('Content-Security-Policy', mainAppCSP);
      }
    }

    return h.continue;
  });

  // Add onPreResponse extension for cookie expiration
  // SECURITY: cookieIsSecure must be true in production behind HTTPS reverse proxy
  //           (per AAP §0.6.1 audit — X-Forwarded-Proto trust is operator-controlled via
  //            reverse proxy configuration; isSecure is set in local.yaml).
  //           SameSite=None requires Secure flag per RFC 6265bis §5.4.7 / Chrome cookie policy.
  const cookieIsSecure = config.app.plugins.session.cookieOptions.isSecure !== false;
  server.ext('onPreResponse', (request, h) => {
    // if this is a cookie-setting request and we have a _header method
    if (request.cookie && request.response && typeof request.response._header === "function") {
      const header = request.response._header;
      const sessionName = config.app.plugins.session.name || 'session';

      request.response._header = function(key, value) {
        // find the 'set-cookie' header
        if (key.match(/^set\-cookie$/i)) {
          if (!Array.isArray(value)) {
            value = [value];
          }
          const nextYear = new Date();
          nextYear.setFullYear(nextYear.getFullYear() + 1);

          for (let i = 0; i < value.length; i++) {
            // find the session portion of the cookie
            if (value[i].indexOf(sessionName) === 0) {
              // add a custom expires if an expires is not already present
              if (!value[i].match(/;\s*Expires=/i)) {
                value[i] += "; Expires=" + nextYear.toUTCString();
              }
              // Only add Secure flag if isSecure is true in config
              if (cookieIsSecure) {
                value[i] += "; SameSite=None; Secure";
              }
            }
          }
        }
        // call the original _header method
        header.call(request.response, key, value);
      }
    }

    return h.continue;
  });

  // Simple session-based auth scheme for Hapi 20+
  server.auth.scheme('session', (server, options) => {
    return {
      authenticate: async (request, h) => {
        // Get user from session via yar
        const userId = request.yar.get('userId');

        if (!userId) {
          // Not authenticated - continue as guest (for 'try' mode)
          return h.unauthenticated(Boom.unauthorized('Not logged in'), { credentials: {} });
        }

        try {
          const user = await new Promise((resolve, reject) => {
            User.findById(userId, (err, user) => {
              if (err) reject(err);
              else resolve(user);
            });
          });

          if (!user) {
            request.yar.clear('userId');
            return h.unauthenticated(Boom.unauthorized('User not found'), { credentials: {} });
          }

          if (user.hasRole && user.hasRole("disabled")) {
            // SECURITY: Two-tier disabled-account enforcement per §6.4.2.1.4 (defense-in-depth).
            //           First tier:  lib/auth/passport.js deserializeUser (Passport-managed login flow).
            //           Second tier: this session-scheme tier (Hapi auth scheme — runs on every request).
            //           Both tiers must reject disabled accounts to mitigate authentication-bypass
            //           (R7 / OWASP A07 Identification and Authentication Failures / CWE-287).
            request.yar.clear('userId');
            return h.unauthenticated(Boom.unauthorized('Account disabled'), { credentials: {} });
          }

          // Attach user to request
          request.user = user;
          return h.authenticated({ credentials: user });
        } catch (err) {
          log.error('Auth error:', err);
          return h.unauthenticated(Boom.unauthorized('Auth error'), { credentials: {} });
        }
      }
    };
  });

  // Register the session auth strategy
  server.auth.strategy('session', 'session');

  // Make session auth the default but don't require it
  server.auth.default({ strategy: 'session', mode: 'try' });

  // Load models (global for backwards compatibility)
  User     = require('./lib/models/user');
  Course   = require('./lib/models/course');
  Lesson   = require('./lib/models/lesson');
  Material = require('./lib/models/material');
  File     = require('./lib/models/file');
  Trinket  = require('./lib/models/trinket');
  Interaction = require('./lib/models/interaction');
  Folder   = require('./lib/models/folder');
  CourseInvitation = require('./lib/models/courseInvitation');

  // Register helpers
  Helpers.register(server);

  // Register routes
  server.route(config.routes);

  // Start the server
  if (config.app.start) {
    await server.start();
    log.info('Server started on port: ' + server.info.port);

    detectLeaks();
  }

  return server;
};

const detectLeaks = function() {
  let leakData = "";

  gleak.detectNew().forEach(function(name) {
    let value = "unknown", json;
    try {
      value = eval(name);
      if (typeof value === "function") {
        value = value.toString();
      }
      else {
        json  = JSON.stringify(value);
        value = json;
      }
    } catch(e) {}

    leakData += name + "=" + value + "\n";
  });

  if (leakData) {
    console.log('leaked!', leakData);
  }
};

gleak.ignore("User", "Course", "Lesson", "Material", "File", "Trinket");
gleak.ignore("Interaction");
gleak.ignore("Folder", "CourseInvitation");
gleak.ignore("log", "NODE_CONFIG", "tokenizer", "$V", "$M", "$L", "$P");
gleak.ignore("DEFAULT_FILE_PATH", "Promise");

// Poll for new leaks every 60 seconds
setInterval(detectLeaks, 60*1000);

// Initialize and export
const serverPromise = init().catch(err => {
  log.error('Failed to start server:', err);
  process.exit(1);
});

module.exports = serverPromise;
