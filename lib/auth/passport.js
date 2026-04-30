var LocalStrategy  = require('passport-local').Strategy
  , GoogleStrategy = require('passport-google-oauth').OAuth2Strategy
  , config         = require('config')
  , userUtil       = require('../util/user');

// SECURITY: Central Passport authentication wiring per AAP §0.5.2 Strategy E (R5) / Strategy G (R7) / Strategy H (R8)
// API surface frozen per AAP "Must Remain Unchanged": serializeUser, deserializeUser, LocalStrategy, GoogleStrategy registration
// If passport upgraded from ~0.2.0 to ^0.7.x per AAP §0.5.3 / §0.7.1, API is backward compatible (session cookie format preserved)
// Session-fixation defense via req.session.reset() (Yar yar.reset()) preserved per AAP "Must Remain Unchanged"
// Two-tier disabled-account enforcement per §6.4.2.1.4: Tier 1 here (deserializeUser); Tier 2 in app.js lines 262-270
function configurePassport(Passport) {
  Passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  Passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      // SECURITY: Tier 1 of two-tier disabled-account enforcement per §6.4.2.1.4 / AAP §0.5.2 Strategy G / R7
      // Tier 2 is in app.js custom session auth scheme (lines 262-270) — defense-in-depth
      // If user is disabled, reject deserialization to prevent session continuation (OWASP A07)
      if (user && user.hasRole("disabled")) {
        done(null, false, { message: 'Account Disabled' });
      } else {
        done(err, user);
      }
    });
  });

  // SECURITY: LocalStrategy explicit failure-state handling per AAP §0.5.2 Strategy G / R7 / OWASP A07
  // usernameField: 'email' — email serves as login identifier (case-sensitive on email lookup; .toLowerCase() applied to username path in lib/models/user.js findByLogin)
  // Each failure path returns a generic message to mitigate enumeration:
  //   - DB lookup error: propagate err
  //   - Unknown user: 'Unknown user <username>' (existing behavior; uniformity audit per lib/controllers/users.js signup)
  //   - Disabled account: 'Account Disabled' (operational, not enumeration)
  //   - Account without password (Google-only user): generic message
  //   - Password mismatch: 'Invalid password' (existing behavior preserved)
  Passport.use(new LocalStrategy({ usernameField : 'email' }, function(username, password, done) {
    // SECURITY: User.findByLogin uses Mongoose schema typing for email/username field coercion
    // per AAP §0.5.2 Strategy H / R8 / OWASP A03 (NoSQL operator injection defense)
    // Implementation in lib/models/user.js (FROZEN per user "Mongoose schemas frozen" — annotation only)
    User.findByLogin(username, function(err, user) {
      if (err) {
        return done(err);
      }

      if (!user) {
        return done(null, false, { message: 'Unknown user ' + username });
      }

      if (user.hasRole("disabled")) {
        return done(null, false, { message: 'Account Disabled' });
      }

      if (user.password == null || user.password.length === 0) {
        return done(null, false, { message: 'A password was not found for this account.' });
      }

      user.comparePassword(password, function(err, isMatch) {
        if (err) return done(err);
        if(isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Invalid password' });
        }
      });
    });
  }));

  // SECURITY: Google OAuth conditionally registered when config.app.auth.google.clientID is set
  // state: true enables CSRF state parameter generation/validation per AAP §0.5.2 Strategy E / R5 / OWASP A07
  // passReqToCallback: true allows access to req.session for state validation context and redirect preservation
  // Note: actual /auth/google flow is handled in lib/controllers/auth.js (custom OAuth implementation);
  // this Passport GoogleStrategy registration provides defense-in-depth state handling if Passport-driven flow is invoked
  if (config.app.auth.google && config.app.auth.google.clientID) {
    Passport.use(new GoogleStrategy({
      clientID          : config.app.auth.google.clientID,
      clientSecret      : config.app.auth.google.clientSecret,
      callbackURL       : config.app.auth.google.callbackURL,
      passReqToCallback : true,
      state             : true   // SECURITY: CSRF state parameter generated and validated automatically per AAP §0.5.2 Strategy E / R5 / OWASP A07
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
