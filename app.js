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
const Crumb          = require('@hapi/crumb'); // SECURITY: CSRF synchronizer-token middleware (AAP §0.5.2 Strategy E / R5 / OWASP A01)
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

// SECURITY: Restrictive CSP for main app pages (AAP §0.5.2 Strategy D / R4; OWASP A05)
// Per §6.4.4.4.4: main app is NOT the execution sandbox - sandbox iframes are served separately
// Note: 'unsafe-inline' for style-src is required by AngularJS 1.3.20 (frozen per ADR-5)
//       but NOT applied to script-src, blocking inline script injection (XSS mitigation)
// Note: config.sandboxUrl is computed at app.config.js line 20 (config.sandbox.url.* combined)
const mainAppCSP = [
  "default-src 'self'",
  "script-src 'self' https://www.google.com https://www.gstatic.com https://www.googletagmanager.com https://cdnjs.cloudflare.com https://ajax.googleapis.com",
  "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://ajax.googleapis.com https://fonts.googleapis.com",
  "img-src 'self' data: https:",
  "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com",
  "connect-src 'self' https://www.google.com",
  "frame-src 'self' " + (config.sandboxUrl || ''),
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'self'"
].join('; ');

// SECURITY: Path matcher for embed/sandbox paths exempt from main-app CSP (per §6.4.4.4.4)
// Embed paths use inline <script> tags (AngularJS 1.3.20 templates) and need their own
// security boundary via iframe sandbox attribute (no allow-same-origin per §6.4.5)
// Matches: /embed/*, /python_embed/*, /assignment-embed/*, /assignment-embed-feedback/*,
//          /assignment-embed-viewonly/*, /sandbox/*, /python/embed/*, /java/run/*, etc.
// Implementation note: regexes are anchored at start (^\/) and use bounded character classes
// with explicit length limits (no unbounded repetition) to avoid ReDoS — verified clean by
// safe-regex / eslint-plugin-security.
function isEmbedOrSandbox(pathname) {
  if (!pathname) return false;
  // /[<=32 prefix chars>]embed boundary — prefix bounded {0,32} to prevent ReDoS.
  // Matches: /embed, /python_embed, /assignment-embed, /pygame_embed, /python3_embed, etc.
  // Word boundary \b ensures we do not match /embedfoo or /myembedfoo (no false positives).
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

  // SECURITY: Validate app.mail.secret entropy at boot to prevent JWT email token forgery
  // (parallel to session password guard above; per AAP §0.5.2 Strategy B / R2 / OWASP A02)
  // Note: app.mail.secret is used by lib/controllers/trinket.js for JWT HS256 issuance
  //       (email verification and email-share tokens) and lib/util/helpers.js for verification.
  // Graceful degradation: only enforce when email IS configured (app.mail.from && app.mail.host)
  //                       per lib/util/mailer.js isConfigured() pattern. This preserves the
  //                       "SMTP absent → {skipped: true}" directive (AAP §0.8.3) so operators
  //                       running without mail features (the default in config/default.yaml
  //                       which ships empty from/host) are not blocked at boot.
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
      // (AAP §0.5.2 Strategy E / R5 / OWASP A01 Broken Access Control / CWE-352)
      // Per Risk Management: scoped to non-SPA routes first; per-route opt-in via
      // route's options.plugins.crumb. SPA-consumed (AngularJS) routes deferred per
      // AAP follow-on plan to avoid frontend coordination breakage.
      plugin: Crumb,
      options: {
        // SECURITY: Treat POST/PUT/DELETE/PATCH as state-mutating (RFC 7231 §4.2.1)
        restful: true,
        // SECURITY: Auto-generate token on every response so opt-in routes always have one
        autoGenerate: true,
        // SECURITY: Available in Nunjucks templates as 'crumb' context var for server-rendered forms
        addToViewContext: true,
        cookieOptions: {
          // SECURITY: Mirror session cookie security posture (HTTPS-only when isSecure=true)
          isSecure: config.app.plugins.session.cookieOptions.isSecure !== false,
          // SECURITY: SameSite=Lax matches session cookie; primary CSRF mitigation per AAP §0.6.2
          isSameSite: 'Lax',
          // Token must be readable by client to echo back in X-CSRF-Token header / form body
          isHttpOnly: false
        },
        // SECURITY: Default-skip CSRF validation unless route explicitly opts in via
        // options.plugins.crumb. This preserves backward compatibility for the AngularJS
        // SPA-consumed routes (AAP Risk Management) while allowing /api/exports,
        // /api/admin/*, and password/email change routes to opt in via config/api_routes.js.
        skip: function(request, h) {
          return !(request.route.settings.plugins && request.route.settings.plugins.crumb);
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

  // Add onPreResponse extension for cache headers and error pages
  server.ext('onPreResponse', (request, h) => {
    const response = request.response;
    const addXFrame = config.app.xframeDeny && config.app.xframeDeny.indexOf(request.url.pathname) >= 0;

    if (response.isBoom) {
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
          // Redirect to login for unauthorized page requests
          return h.redirect('/login').takeover();
        } else if (statusCode === 404) {
          return h.view('404.html').code(404);
        } else if (statusCode === 403) {
          return h.view('50x.html').code(403);
        } else if (statusCode >= 500) {
          return h.view('50x.html').code(statusCode);
        }
      }

      response.output.headers['Cache-Control'] = cache_control;
      response.output.headers['Pragma'] = 'no-cache';
      response.output.headers['Expires'] = '0';

      if (addXFrame) {
        response.output.headers['X-Frame-Options'] = 'deny';
      }

      // SECURITY: Add OWASP-recommended security headers to all error responses
      // (AAP §0.5.2 Strategy D / R4 / OWASP A05 Security Misconfiguration)
      // X-Content-Type-Options: blocks MIME sniffing (CWE-430)
      // Referrer-Policy: limits Referer leakage to cross-origin destinations (privacy)
      response.output.headers['X-Content-Type-Options'] = 'nosniff';
      response.output.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';

      // SECURITY: Apply CSP to main app pages, excluding embed/sandbox paths (per §6.4.4.4.4).
      // CSP mitigates server-side XSS surface (CWE-79) by restricting script sources.
      // Embed/sandbox paths use inline scripts (AngularJS templates) and have their own
      // security boundary via iframe sandbox attribute (no allow-same-origin per §6.4.5).
      if (request.url && !isEmbedOrSandbox(request.url.pathname)) {
        response.output.headers['Content-Security-Policy'] = mainAppCSP;
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
      // (AAP §0.5.2 Strategy D / R4 / OWASP A05 Security Misconfiguration)
      // X-Content-Type-Options: blocks MIME sniffing (CWE-430)
      // Referrer-Policy: limits Referer leakage to cross-origin destinations (privacy)
      response.header('X-Content-Type-Options', 'nosniff');
      response.header('Referrer-Policy', 'strict-origin-when-cross-origin');

      // SECURITY: Apply CSP to main app pages, excluding embed/sandbox paths (per §6.4.4.4.4).
      // CSP mitigates server-side XSS surface (CWE-79) by restricting script sources.
      // Embed/sandbox paths use inline scripts (AngularJS templates) and have their own
      // security boundary via iframe sandbox attribute (no allow-same-origin per §6.4.5).
      if (request.url && !isEmbedOrSandbox(request.url.pathname)) {
        response.header('Content-Security-Policy', mainAppCSP);
      }
    }

    return h.continue;
  });

  // Add onPreResponse extension for cookie expiration
  // SECURITY: cookieIsSecure must be true in production behind HTTPS reverse proxy
  // (per AAP §0.6.1 audit - X-Forwarded-Proto trust is operator-controlled via reverse proxy
  // configuration; isSecure is operator-configured per local.yaml).
  // SameSite=None requires Secure flag per RFC 6265bis §5.4.7 / Chrome cookie policy.
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
            // SECURITY: Two-tier disabled-account enforcement per §6.4.2.1.4 (defense-in-depth)
            // First tier:  lib/auth/passport.js deserializeUser (Passport-managed)
            // Second tier: this session-scheme tier (Hapi auth scheme)
            // Both tiers must reject disabled accounts to mitigate authentication bypass.
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
