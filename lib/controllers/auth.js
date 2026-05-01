var _             = require('underscore'),
    config        = require('config'),
    Boom          = require('@hapi/boom'),
    // SECURITY: Replaced deprecated `request` with `axios` (R1 per AAP §0.5.2 Strategy A);
    //           `request` was removed from package.json. The Google OAuth callback flow below
    //           preserves identical resolve(accessToken)/resolve(profile) contracts; only the
    //           HTTP client implementation changed.
    // SECURITY: This module is the ACTIVE Google OAuth code path per config/routes.js lines
    //           565, 573 (handlers `auth.google` / `auth.googleCallback`). The OAuth CSRF
    //           state-parameter generation (in `google`) and validation (in `googleCallback`)
    //           below are the primary R5 / OWASP A07 / CWE-352 (Login CSRF) defense per
    //           AAP §0.5.2 Strategy E. The Passport GoogleStrategy registration in
    //           lib/auth/passport.js is currently NOT wired into the Hapi server
    //           (`Authentication.configure(...)` is never invoked) — its `state: true`
    //           option is defense-in-depth only if Passport is wired in a future change.
    _axios        = require('axios'),
    crypto        = require('crypto'),
    userUtil      = require('../util/user');

// SECURITY: OAuth state parameter byte length (R5 / OWASP A07 / CWE-352 Login CSRF defense).
//           crypto.randomBytes(32) yields 256 bits of entropy; encoded as hex this is 64
//           characters — well above OAuth 2.0 / RFC 6749 §10.12 recommended minimum.
//           Both sides of crypto.timingSafeEqual must be equal-length Buffers, so callers
//           length-check before invoking timingSafeEqual to avoid the TypeError it throws
//           on length mismatch (and to avoid an oracle distinguishing "wrong length" from
//           "wrong bytes" — the rejection path is identical in both cases).
var OAUTH_STATE_BYTES = 32;

module.exports = {
  // Google OAuth - optional, only works if configured
  google : function(request, h) {
    if (!config.app.auth || !config.app.auth.google || !config.app.auth.google.clientID) {
      return request.fail({
        message: 'Google OAuth is not configured. Please set up Google OAuth credentials.'
      });
    }

    request.yar.flash('auth', 'Google', true);
    if (request.query.next) {
      request.yar.set('next', request.query.next);
    }

    // SECURITY: Generate cryptographically random OAuth state per AAP §0.5.2 Strategy E / R5
    //           (OWASP A07 Identification and Authentication Failures / CWE-352 Login CSRF).
    //           crypto.randomBytes is a CSPRNG; 32 bytes (256 bits) of entropy. The state
    //           is bound to the user's Yar session (server-side cookie-sealed storage) so
    //           an attacker cannot forge or replay it across sessions.
    //           On callback, googleCallback retrieves this stored value and compares it via
    //           constant-time crypto.timingSafeEqual against request.query.state.
    //           Without state, an attacker could craft a Google OAuth callback URL with
    //           their own authorization code and trick a victim into visiting it, binding
    //           the victim's Trinket session to the attacker's Google account (login CSRF).
    var state = crypto.randomBytes(OAUTH_STATE_BYTES).toString('hex');
    request.yar.set('oauth_state', state);

    // Build Google OAuth URL
    var googleAuthUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
    var params = new URLSearchParams({
      client_id: config.app.auth.google.clientID,
      redirect_uri: config.app.auth.google.callbackURL,
      response_type: 'code',
      scope: 'profile email',
      access_type: 'online',
      // SECURITY: state echoed back by Google in callback query string per RFC 6749 §10.12;
      //           validated server-side in googleCallback against request.yar.get('oauth_state').
      state: state
    });

    return request.success({ redirectTo: googleAuthUrl + '?' + params.toString() });
  },

  googleCallback : function(request, h) {
    if (!config.app.auth || !config.app.auth.google || !config.app.auth.google.clientID) {
      return request.fail({
        message: 'Google OAuth is not configured.'
      });
    }

    // SECURITY: OAuth state parameter validation per AAP §0.5.2 Strategy E / R5
    //           (OWASP A07 / CWE-352 Login CSRF defense). MUST run before any consumption
    //           of request.query.code (the authorization code) — otherwise an attacker could
    //           bind a victim's session to the attacker's Google account.
    //           Validation steps:
    //             1. Retrieve expected state from server-side Yar session (set in `google`
    //                handler when the OAuth flow was initiated).
    //             2. Read received state from request.query.state (echoed by Google).
    //             3. Reject if either is missing or non-string (prevents type confusion /
    //                NoSQL operator injection where an attacker supplies an object value).
    //             4. Length check (in non-constant time — the attacker controls the input
    //                length so timing reveals nothing they did not already know) to
    //                preempt crypto.timingSafeEqual's TypeError on unequal-length buffers.
    //             5. Constant-time byte comparison via crypto.timingSafeEqual to prevent
    //                timing-oracle attacks against the secret state value.
    //           After validation (success OR failure), clear the stored state to prevent
    //           replay. Failure path uses request.fail (consistent with handler-wide error
    //           pattern; redirects to /signup per config/routes.js fail.redirect) to avoid
    //           leaking whether the failure was state-related vs. token-exchange-related
    //           (oracle-resistance per OWASP A07).
    var expectedState = request.yar.get('oauth_state');
    var receivedState = request.query.state;
    // Always clear the server-side state value after the callback consumes it (success or
    // failure) to prevent replay attacks and stale-state confusion across sessions.
    request.yar.clear('oauth_state');

    if (typeof expectedState !== 'string' || typeof receivedState !== 'string' ||
        expectedState.length === 0 || receivedState.length === 0 ||
        expectedState.length !== receivedState.length) {
      log.warn('SECURITY: Google OAuth state parameter missing or length mismatch — rejecting callback (R5 / CWE-352 Login CSRF defense)');
      return request.fail({ message: 'Authentication failed. Please try again.' });
    }
    var stateMatches;
    try {
      // SECURITY: Constant-time comparison (Buffer.from on equal-length hex strings yields
      //           equal-length Buffers). If timingSafeEqual still throws (e.g. invalid hex),
      //           treat as mismatch — fail closed.
      stateMatches = crypto.timingSafeEqual(Buffer.from(expectedState), Buffer.from(receivedState));
    } catch (err) {
      stateMatches = false;
    }
    if (!stateMatches) {
      log.warn('SECURITY: Google OAuth state parameter mismatch — rejecting callback (R5 / CWE-352 Login CSRF defense)');
      return request.fail({ message: 'Authentication failed. Please try again.' });
    }

    var code = request.query.code;
    if (!code) {
      return request.fail({ message: 'No authorization code received from Google.' });
    }

    // SECURITY: axios.post with URL-encoded form replaces request.post({form, json:true}) per R1.
    //           axios automatically parses JSON responses into response.data when the upstream
    //           responds with application/json; the resolve(accessToken)/reject(err) contract
    //           is preserved identically.
    return new Promise(function(resolve, reject) {
      _axios.post(
        'https://oauth2.googleapis.com/token',
        new URLSearchParams({
          code: code,
          client_id: config.app.auth.google.clientID,
          client_secret: config.app.auth.google.clientSecret,
          redirect_uri: config.app.auth.google.callbackURL,
          grant_type: 'authorization_code'
        }).toString(),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          // SECURITY: 10s timeout prevents indefinite hang on Google OAuth token-exchange
          //           service unreachability (mitigates DoS amplification per OWASP A04
          //           Insecure Design). Matches the precedent established in
          //           lib/util/recaptcha.js (axios.post to Google reCAPTCHA also uses
          //           timeout: 10000) — without this bound, an unresponsive
          //           oauth2.googleapis.com endpoint or DNS-resolution stall would hold
          //           the OAuth callback request open until the OS-level TCP timeout
          //           (typically minutes), holding session state and consuming a Hapi
          //           worker per stalled callback. Aligns all third-party outbound axios
          //           calls in the codebase to the same 10-second resilience envelope.
          timeout: 10000
        }
      ).then(function(response) {
        var body = response.data || {};
        if (!body.access_token) {
          return reject(new Error('Failed to get access token'));
        }
        resolve(body.access_token);
      }).catch(function(err) {
        reject(err);
      });
    })
    .then(function(accessToken) {
      // SECURITY: axios.get replaces request.get({headers, json:true}) per R1; response.data is
      //           the parsed JSON profile object equivalent to the previous `profile` callback param.
      return new Promise(function(resolve, reject) {
        _axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: 'Bearer ' + accessToken },
          // SECURITY: 10s timeout prevents indefinite hang on Google userinfo service
          //           unreachability (mitigates DoS amplification per OWASP A04 Insecure
          //           Design). Matches the timeout on the preceding token-exchange axios.post
          //           call above and the precedent in lib/util/recaptcha.js. Without this
          //           bound, a slow-responding www.googleapis.com endpoint would hold the
          //           OAuth callback request open until the OS-level TCP timeout, holding
          //           session state and consuming a Hapi worker per stalled callback.
          timeout: 10000
        }).then(function(response) {
          var profile = response.data || {};
          if (!profile.email) {
            return reject(new Error('Failed to get user profile'));
          }
          profile.accessToken = accessToken;
          resolve(profile);
        }).catch(function(err) {
          reject(err);
        });
      });
    })
    .then(function(profile) {
      // Find or create user
      return new Promise(function(resolve, reject) {
        User.findByMultiple({
          email: profile.email,
          username: userUtil.generate_username(profile.email),
          'profiles.google.id': profile.id
        }, function(err, user) {
          if (err) reject(err);
          else resolve(user);
        });
      })
      .then(function(user) {
        var next = request.yar.get('next');
        var promises = [];
        var updateUser = false;

        request.yar.reset();
        if (next) {
          request.yar.set('next', next);
        }
        request.yar.set('loggedInWith', 'google');

        if (user) {
          request.yar.flash('requested', user.username);
          if (!user.avatar && profile.picture) {
            updateUser = true;
            user.avatar = profile.picture;
          }
          if (!user.profiles) {
            user.profiles = {};
          }
          if (!user.profiles.google) {
            updateUser = true;
            user.profiles.google = {
              id: profile.id,
              token: profile.accessToken
            };
          }

          if (updateUser) {
            promises.push(user.save());
          }

          return Promise.all(promises).then(function() {
            return user;
          });
        }
        else {
          // Create new user
          user = new User();
          user.email = profile.email;
          user.fullname = profile.name || profile.email.split('@')[0];
          user.username = userUtil.generate_username(profile.email);
          request.yar.flash('requested', user.username);
          user.source = 'google';
          user.avatar = profile.picture;
          user.profiles = {
            google: {
              id: profile.id,
              token: profile.accessToken
            }
          };

          return user.save()
            .then(function(newUser) {
              if (!next) {
                request.yar.set('next', '/welcome');
              }
              request.yar.set('grantDemoTrinkets', true);
              // SECURITY: opts is a server-controlled flash payload (no user-controlled
              // SECURITY: input flows here) — declared as empty object to preserve the
              // SECURITY: backward-compatible flash payload shape while fixing the
              // SECURITY: previously-undefined reference that would crash the live Google
              // SECURITY: OAuth new-user creation path. The 'userAccountCreated' flash key
              // SECURITY: has no consumer in lib/views/* — preserving '{}' avoids
              // SECURITY: information disclosure (CWE-200) by ensuring no profile fields
              // SECURITY: leak into the flash store. Fixes ESLint no-undef error per
              // SECURITY: AAP §0.5.2 Strategy I / R9 audit findings.
              var opts = {};
              request.yar.flash('userAccountCreated', JSON.stringify(opts));

              return newUser;
            });
        }
      });
    })
    .then(function(user) {
      // Log in user - store userId in session
      request.yar.set('userId', user.id);
      request.user = user;

      var redirectTo = request.yar.get('next') || '/home';
      request.yar.clear('next');

      var educatorsFormData = request.yar.get('educatorsFormData');
      var registrationPayload = request.yar.get('registration-payload');

      if (educatorsFormData) {
        request.yar.set('educatorsFormData', educatorsFormData, true);
      }
      if (registrationPayload) {
        request.yar.set('registration-payload', registrationPayload);
      }

      // Grant demo trinkets if needed
      if (request.yar.get('grantDemoTrinkets')) {
        request.yar.clear('grantDemoTrinkets');
        // Demo trinket granting would happen here via server.methods
      }

      return request.success({ redirectTo: redirectTo });
    })
    .catch(function(err) {
      log.error('Google OAuth error:', err);
      return request.fail({ message: 'Authentication failed. Please try again.' });
    });
  }
};
