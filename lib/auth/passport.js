var LocalStrategy  = require('passport-local').Strategy
  , GoogleStrategy = require('passport-google-oauth').OAuth2Strategy
  , config         = require('config')
  , userUtil       = require('../util/user');

// SECURITY: Central Passport authentication wiring per AAP §0.5.2 Strategy E (R5) / Strategy G (R7) / Strategy H (R8)
// API surface frozen per AAP "Must Remain Unchanged": serializeUser, deserializeUser, LocalStrategy, GoogleStrategy registration
// If passport upgraded from ~0.2.0 to ^0.7.x per AAP §0.5.3 / §0.7.1, API is backward compatible (session cookie format preserved)
// Session-fixation defense via req.session.reset() (Yar yar.reset()) preserved per AAP "Must Remain Unchanged"
//
// SECURITY (RUNTIME-ACCURATE — CP4 review remediation):
//   This module's configurePassport() function is currently NOT INVOKED at runtime —
//   no caller in app.js or elsewhere imports `Authentication.configure(Passport)`.
//   As a result, none of the Passport.serializeUser / Passport.deserializeUser /
//   Passport.use(...) registrations below execute under the running server. The file
//   is retained because:
//     (1) it documents the intended Passport authentication contract for a future
//         migration that wires Passport into the Hapi server (Authentication.configure
//         + Passport.authenticate('google') route handlers);
//     (2) when wired, it provides defense-in-depth alongside the active runtime paths.
//
//   ACTIVE RUNTIME ENFORCEMENT POINTS (per CP4 review §Findings):
//     - Disabled-account check Tier A — lib/controllers/users.js login handler (line 163,
//       `if (user.hasRole && user.hasRole("disabled"))` short-circuits with "Account
//       Disabled" failure before session cookie is set).
//     - Disabled-account check Tier B — app.js custom session auth scheme (lines 516-524,
//       `if (user.hasRole && user.hasRole("disabled"))` clears userId and returns
//       Boom.unauthorized("Account disabled") on every authenticated request).
//     - Google OAuth state CSRF defense — lib/controllers/auth.js `google` handler
//       generates state via crypto.randomBytes(32) and stores in request.yar; the
//       `googleCallback` handler validates via crypto.timingSafeEqual.
//     - Local password authentication — lib/controllers/users.js login handler, NOT
//       LocalStrategy below.
//
//   The Passport.deserializeUser / LocalStrategy / GoogleStrategy `state: true` config
//   below remain as defense-in-depth only if Authentication.configure(Passport) is later
//   invoked from app.js boot. Until then, they are dead code at the runtime layer.
function configurePassport(Passport) {
  Passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  Passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      // SECURITY: Defense-in-depth disabled-account enforcement IF Passport-driven session
      // deserialization is ever invoked (per AAP §0.5.2 Strategy G / R7 / OWASP A07).
      // CP4 review remediation note: this branch is currently DEAD CODE — see file header
      // for runtime-accurate enforcement points (lib/controllers/users.js login handler
      // line 163 and app.js session auth scheme lines 516-524 are the active tiers).
      // Retained as a safety net for any future code path that wires Passport into the
      // Hapi server — both tiers must remain consistent to avoid bypass on migration.
      if (user && user.hasRole("disabled")) {
        done(null, false, { message: 'Account Disabled' });
      } else {
        done(err, user);
      }
    });
  });

  // SECURITY: LocalStrategy explicit failure-state handling per AAP §0.5.2 Strategy G / R7 / OWASP A07
  // usernameField: 'email' — email serves as login identifier (case-sensitive on email lookup; .toLowerCase() applied to username path in lib/models/user.js findByLogin)
  // Each failure path returns a UNIFORM credential-failure message ('Invalid email or password') to
  // mitigate account enumeration per CWE-203 Observable Discrepancy. The "Unknown user <name>" /
  // "Invalid password" / "A password was not found for this account" messages all collapse to the
  // same response so an attacker cannot distinguish:
  //   - DB lookup error: propagate err
  //   - Unknown user, account without password, password mismatch: uniform 'Invalid email or password'
  //   - Disabled account: 'Account Disabled' (operational signal — represents an existing account in
  //     suspended state; not a credential-failure enumeration vector since it requires admin action)
  Passport.use(new LocalStrategy({ usernameField : 'email' }, function(username, password, done) {
    // SECURITY: User.findByLogin uses Mongoose schema typing for email/username field coercion
    // per AAP §0.5.2 Strategy H / R8 / OWASP A03 (NoSQL operator injection defense)
    // Implementation in lib/models/user.js (FROZEN per user "Mongoose schemas frozen" — annotation only)
    User.findByLogin(username, function(err, user) {
      if (err) {
        return done(err);
      }

      if (!user) {
        // SECURITY: Uniform credential-failure message defends against account enumeration per
        //           AAP §0.5.2 Strategy G / R7 / OWASP A07 / CWE-203 Observable Discrepancy.
        return done(null, false, { message: 'Invalid email or password' });
      }

      if (user.hasRole("disabled")) {
        return done(null, false, { message: 'Account Disabled' });
      }

      if (user.password == null || user.password.length === 0) {
        // SECURITY: Uniform credential-failure message — see comment above. Previously revealed
        //           that a Google-only account exists (without local password). CWE-203.
        return done(null, false, { message: 'Invalid email or password' });
      }

      user.comparePassword(password, function(err, isMatch) {
        if (err) return done(err);
        if(isMatch) {
          return done(null, user);
        } else {
          // SECURITY: Uniform credential-failure message defends against account enumeration per
          //           AAP §0.5.2 Strategy G / R7 / OWASP A07 / CWE-203.
          return done(null, false, { message: 'Invalid email or password' });
        }
      });
    });
  }));

  // SECURITY: Google OAuth conditionally registered when config.app.auth.google.clientID is set.
  // CP4 review remediation note: the actual `/auth/google` and `/auth/google/callback` routes
  // (per config/routes.js lines 565, 573) are wired to lib/controllers/auth.js exports
  // (`auth.google`, `auth.googleCallback`) — NOT to Passport.authenticate('google'). Therefore
  // this GoogleStrategy is NOT invoked at runtime under the current server wiring; the
  // primary R5 / OWASP A07 / CWE-352 (Login CSRF) defense lives in lib/controllers/auth.js
  // (`crypto.randomBytes(32)` state generation in `google` + `crypto.timingSafeEqual`
  // validation in `googleCallback`).
  // The `state: true` option below remains as defense-in-depth ONLY IF a future change wires
  // Passport into app.js (`Authentication.configure(Passport)` + Passport.authenticate route
  // handlers). When honored by passport-google-oauth, `state: true` would auto-generate and
  // validate the OAuth state parameter — providing an additional CSRF guard on the
  // Passport-driven path. Until Passport is wired, this is documentation of intent.
  // passReqToCallback: true is preserved per AAP "Must Remain Unchanged" (allows access to
  // req.session for state validation context and redirect preservation across yar.reset()).
  if (config.app.auth.google && config.app.auth.google.clientID) {
    Passport.use(new GoogleStrategy({
      clientID          : config.app.auth.google.clientID,
      clientSecret      : config.app.auth.google.clientSecret,
      callbackURL       : config.app.auth.google.callbackURL,
      passReqToCallback : true,
      state             : true   // SECURITY: defense-in-depth CSRF state for any future Passport-driven flow per AAP §0.5.2 Strategy E / R5 — primary defense is in lib/controllers/auth.js
    }, function(req, token, refreshToken, profile, done) {
      var email      = profile.emails[0].value,
          emailParts = email.split('@'),
          username   = userUtil.generate_username(email),
          updateUser = false,
          promises   = [];

      // SECURITY: User.findByMultiple uses Mongoose schema typing for email/username/profiles.google.id field coercion
      // per AAP §0.5.2 Strategy H / R8 / OWASP A03 (NoSQL operator injection defense)
      // email/username derived from Google profile (validated by OAuth token exchange);
      // profile.id is Google's stable user identifier — type-coerced to String by Mongoose schema
      // Implementation in lib/models/user.js findByMultiple (FROZEN per user "Mongoose schemas frozen" — annotation only)
      User.findByMultiple({ email : email, username : username, 'profiles.google.id' : profile.id }, function(err, user) {
        if (err) {
          return done(err);
        }

        // SECURITY: Session state mutation post-Google authentication per AAP §0.5.2 Strategy E / R5
        // req.session.reset() rotates session ID to defeat session-fixation per AAP "Must Remain Unchanged" / §6.4.2.3.4
        // 'next' redirect target preserved across reset to maintain post-login navigation
        // 'loggedInWith': 'google' tag enables differential audit per §6.4.2.1.4 (Tier 1 vs Tier 2)
        var next = req.session.get('next');

        req.session.reset();
        if (next) {
          req.session.set('next', next);
        }
        req.session.set('loggedInWith', 'google');

        if (user) {
          req.session.flash('requested', user.username);
          if (!user.avatar) {
            updateUser = true;
            user.avatar = profile._json.picture;
          }
          if (!user.profiles) {
            user.profiles = {};
          }
          if (!user.profiles.google) {
            updateUser = true;
            user.profiles.google = {
              id    : profile.id,
              token : token
            };
          }

          if (updateUser) {
            promises.push(user.save());
          }
          else {
            promises.push(Promise.resolve());
          }

          return Promise.all(promises).then(function() {
            return done(null, user);
          });
        }
        else {
          // SECURITY: New Google OAuth user created with default (non-admin) role per AAP §0.5.2 Strategy G / R7
          // No admin role assigned by default; no privilege escalation surface
          // No disabled flag set by default; gracefully onboards new Google authentications
          // source: 'google' tag enables differential audit per §6.4.2.1.4
          // grantDemoTrinkets: server-controlled feature flag (not user-controlled input — no injection surface)
          // 'next': '/welcome' default redirect preserved across yar.reset() — prevents CSRF on post-login redirect
          user = new User();
          user.email = email;
          user.fullname = profile.displayName || emailParts[0];
          user.username = username;
          req.session.flash('requested', user.username);
          user.source   = 'google';
          user.avatar   = profile._json.picture;
          user.profiles = {
            google : {
              id    : profile.id,
              token : token
            }
          };

          user.save(function(err, newUser) {
              if (!next) {
                req.session.set('next', '/welcome');
              }
              req.session.set('grantDemoTrinkets', true);
              req.session.flash('userAccountCreated', JSON.stringify(opts));

              return done(err, newUser)
            });
        }
      });
    }));
  }
}

module.exports = {
  configure : configurePassport
};
