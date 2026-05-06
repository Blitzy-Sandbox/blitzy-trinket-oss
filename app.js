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

  // SECURITY: enforce minimum-entropy on JWT signing secret (CVE-2022-23540 defense-in-depth)
  // When email is enabled (mail.from is set), the email-share token flow signs JWTs with
  // config.app.mail.secret. A short or missing secret weakens the algorithm-pin defense
  // against algorithm-confusion attacks. Per the graceful-degradation contract, we WARN
  // (not exit) so that operators with email intentionally disabled can still boot; the
  // controllers in lib/controllers/trinket.js will fail closed when issuing tokens with
  // a too-short secret.
  if (config.app && config.app.mail && config.app.mail.from) {
    const mailSecret = config.app.mail.secret;
    if (!mailSecret || mailSecret.length < 32) {
      console.warn('\n' + '='.repeat(70));
      console.warn('WARNING: JWT email-share secret (config.app.mail.secret) is missing or shorter than 32 characters.');
      console.warn('Email-share token issuance will fail closed. Set a 32+ character secret in config/local.yaml:');
      console.warn('');
      console.warn('  app:');
      console.warn('    mail:');
      console.warn("      secret: 'your-secure-jwt-secret-at-least-32-characters'");
      console.warn('='.repeat(70) + '\n');
    }
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

    // SECURITY: defense-in-depth Content-Security-Policy.
    //
    // The CSP value below is the AAP §0.5.1 verbatim specification with ONE
    // documented deviation: the `frame-ancestors 'self'` directive is applied
    // route-aware (only for routes already in config.app.xframeDeny: '/',
    // '/login', '/signup', '/contact', '/educators') instead of globally as
    // a strict reading of §0.5.1 would prescribe.
    //
    // Rationale — the AAP itself contains a contractual conflict between
    // §0.5.1 prescriptive guidance (CSP value verbatim, including a global
    // `frame-ancestors 'self'`) and the §0.1.2 binding User Example
    // preservation requirement: "Socket.IO protocol contract between
    // browser embeds and nginx gateway unchanged — consumed by deployed
    // embeds in third-party iframes." A globally-applied `frame-ancestors
    // 'self'` would block ALL third-party iframe framing of Trinket embed
    // routes (/embed/*, /assignment-embed/*, and the trinket player routes
    // /python, /skulpt, /vpython, /webvpython, /r, etc.), destroying the
    // entire deployed-embed product surface that §0.1.2 explicitly
    // protects.
    //
    // Resolution — §0.1.2 User Examples are documented in the AAP as
    // "Preservation requirements (verbatim from user instructions,
    // preserved as User Examples)" and are therefore binding constraints
    // that take precedence over §0.5.1 prescriptive guidance when the two
    // conflict. The route-aware emission preserves the embed contract
    // while still applying `frame-ancestors 'self'` (clickjacking defense)
    // to the same routes that already receive `X-Frame-Options: deny`
    // (i.e., the auth/marketing pages where embed framing is not a
    // product requirement). All other CSP directives (default-src,
    // img-src, style-src, font-src, script-src, frame-src, connect-src)
    // match AAP §0.5.1 verbatim and are emitted globally.
    const cspBase = "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-eval' https://www.google.com https://www.gstatic.com https://cdnjs.cloudflare.com; frame-src 'self' https://www.google.com; connect-src 'self' wss: https:";
    const csp = addXFrame ? (cspBase + "; frame-ancestors 'self'") : cspBase;

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
        // SECURITY: attach defense-in-depth headers to the rendered HTML error view /
        // redirect response. This is part of the same vulnerability class addressed by
        // AAP §0.5.1 (defense-in-depth response header gap closure for
        // X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy).
        // Without this adapter, HTML browser-style 401/403/404/500 responses bypass the
        // security-header injection below, because h.view().code() and
        // h.redirect().takeover() short-circuit the function and the resulting response
        // object does not re-enter this onPreResponse extension — leaving error pages
        // without the AAP-mandated security headers. Adding this adapter completes the
        // §0.5.1 mandate across all response paths, including HTML error renderings.
        // (Pre-existing Cache-Control / Pragma / Expires / X-Frame-Options gaps on
        // these paths are out of scope for this remediation per the Minimal Change
        // Clause and are preserved as-is.)
        const attachSecurity = (resp) => resp
          .header('X-Content-Type-Options', 'nosniff')
          .header('Referrer-Policy', 'strict-origin-when-cross-origin')
          .header('Content-Security-Policy', csp);

        if (statusCode === 401) {
          // Redirect to login for unauthorized page requests
          return attachSecurity(h.redirect('/login')).takeover();
        } else if (statusCode === 404) {
          return attachSecurity(h.view('404.html').code(404));
        } else if (statusCode === 403) {
          return attachSecurity(h.view('50x.html').code(403));
        } else if (statusCode >= 500) {
          return attachSecurity(h.view('50x.html').code(statusCode));
        }
      }

      response.output.headers['Cache-Control'] = cache_control;
      response.output.headers['Pragma'] = 'no-cache';
      response.output.headers['Expires'] = '0';

      if (addXFrame) {
        response.output.headers['X-Frame-Options'] = 'deny';
      }

      // SECURITY: defense-in-depth response headers
      response.output.headers['X-Content-Type-Options'] = 'nosniff';
      response.output.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
      response.output.headers['Content-Security-Policy'] = csp;
    }
    else if (response.header) {
      response.header('Cache-Control', cache_control);
      response.header('Pragma', 'no-cache');
      response.header('Expires', '0');

      if (addXFrame) {
        response.header('X-Frame-Options', 'deny');
      }

      // SECURITY: defense-in-depth response headers
      response.header('X-Content-Type-Options', 'nosniff');
      response.header('Referrer-Policy', 'strict-origin-when-cross-origin');
      response.header('Content-Security-Policy', csp);
    }

    return h.continue;
  });

  // Add onPreResponse extension for cookie expiration
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
