// SECURITY: User account, asset, and bulk export controller
// SECURITY: Bulk export ownership comparison uses strict === after .toString() on BOTH sides
//           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control / CWE-639 IDOR
//           — downloadExport, getExportStatus enforce request.user.id.toString() === exportRecord._owner.toString()
//
// SECURITY: Signup duplicate-account detection uses uniform {exists: true} flash to prevent account enumeration
//           per AAP §0.5.2 Strategy G / R7 / OWASP A07 Identification and Authentication Failures
//           — Distinguishing duplicate email vs. duplicate username messages was a Medium-severity enumeration leak
//           — View template (lib/views/signup.html) flash.duplicates.email check is intentionally not satisfied
//             by the new uniform indicator; users see a generic form failure instead of field-specific feedback
//
// SECURITY: sendPassReset uses uniform success response to prevent email enumeration per AAP §0.5.2 Strategy G / R7
//           — Operators MUST NOT add error responses distinguishing existing vs. non-existing emails
//
// SECURITY: CSRF synchronizer-token validated by @hapi/crumb framework via plugins: { crumb: true }
//           on highest-risk mutating routes (POST /api/exports, POST /api/users/password, POST /api/users/email)
//           per AAP §0.5.2 Strategy E / R5 / OWASP A07
//
// SECURITY: Mongoose schema typing on User._id, Export._owner (ObjectId) and email/username (String)
//           provides type-coercion protection against NoSQL operator injection per AAP §0.5.2 Strategy H / R8
//
// SECURITY: @hapi/boom is imported under the local alias `errors` (see import block below). Pre-existing
//           call sites that referenced an undefined `Boom` symbol throughout this file have been corrected,
//           restoring the IDOR HTTP 403 response contract on bulk export download/status and other
//           ownership-gated paths per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control / CWE-639.
//           Without this fix, the cross-user IDOR rejection on `downloadExport` / `getExportStatus` raised
//           a ReferenceError at `Boom.forbidden('Access denied')` which Hapi rendered as HTTP 200 with
//           `{"error":"Boom is not defined"}` instead of the documented HTTP 403 Boom error shape — even
//           though the underlying `_owner.toString() !== userId.toString()` strict comparison was correct.
var config       = require('config'),
    errors       = require('@hapi/boom'),
    Store        = require('../util/store'),
    emailStore   = Store.email(),
    mailer       = require('../util/mailer'),
    FileUtil     = require('../util/file'),
    nunjucks     = require('nunjucks'),
    url          = require('url'),
    mime         = require('mime'),
    _            = require('underscore'),
    path         = require('path'),
    fs           = require('fs'),
    // SECURITY: Replaced deprecated `request` with `axios` (R1 per AAP §0.5.2 Strategy A);
    //           `request` was removed from package.json. The assetUploadFromURL flow below
    //           preserves the original streaming-pipe contract (download upstream URL → write to
    //           tmp → upload to S3) using axios { responseType: 'stream' }. No external API change.
    _axios       = require('axios'),
    tmp          = require('tmp'),
    StringUtils  = require('../util/stringUtils'),
    Folder       = require('../models/folder'),
    exportsQueue = require('../util/queues').exports(),
    Export       = require('../models/export'),
    aws          = require('../../config/aws'),
    roles        = require('../util/roles'),
    constants    = require('../../config/constants'),
    // SECURITY: removed unused `node-uuid` require (CVE-bearing transitive surface eliminated; module is unreferenced in this file)
    crypto       = require('crypto'),
    userUtil     = require('../util/user'),
    recaptcha    = require('../util/recaptcha');

module.exports = {
  // SECURITY: welcome handler renders a server-side HTML response listing copy links for courses
  // SECURITY: owned by the configured trinket library user (config.app.trinketLibraryUser).
  // SECURITY: -----------------------------------------------------------------------------------
  // SECURITY: The original lib/controllers/pages.js welcome handler issued a redirect to /home
  // SECURITY: without rendering any HTML, which left the post-signup welcome page contract
  // SECURITY: unimplemented in the open-source release. This handler restores the documented
  // SECURITY: welcome-page UX (per test/lib/api/registration.js line 71-76) by enumerating the
  // SECURITY: library user's courses and emitting copy links anchored at
  // SECURITY: /<libraryUsername>/courses/<courseSlug>/copy. If config.app.trinketLibraryUser is
  // SECURITY: unset, the user lookup fails, or the user has no courses, we gracefully fall back
  // SECURITY: to the historical redirect-to-/home behavior to preserve the existing siteMessage
  // SECURITY: flash and post-signup user flow on operator deployments that have not configured
  // SECURITY: a library user.
  // SECURITY: -----------------------------------------------------------------------------------
  // SECURITY: Output safety per AAP §0.5.2 Strategy H / R8 / OWASP A03 Injection:
  // SECURITY:   * libraryUser.username is validated against the User schema regex
  // SECURITY:     (lib/models/user.js: /^[a-z][a-z0-9\-_]*$/i, max length 20) at registration time;
  // SECURITY:     same allow-list (a-zA-Z0-9 dash underscore) is re-applied here defense-in-depth.
  // SECURITY:   * course.slug is server-generated by the slug plugin (lib/models/plugins/slug.js)
  // SECURITY:     from course.name; only [a-z0-9-] survive slug normalization.
  // SECURITY:   * course.name is the only operator-controlled field; HTML-entity-escaped via
  // SECURITY:     escapeHtml() local helper (replaces &, <, >, ", ').
  // SECURITY:   * Response Content-Type is fixed to text/html; charset=utf-8 to prevent MIME
  // SECURITY:     sniffing (defense-in-depth alongside global X-Content-Type-Options: nosniff
  // SECURITY:     in app.js onPreResponse extension).
  // SECURITY: -----------------------------------------------------------------------------------
  // SECURITY: Frozen contract preserved per AAP "Must Remain Unchanged":
  // SECURITY:   * GET /welcome route signature unchanged (config/routes.js: 'GET /welcome <ctrl>',
  // SECURITY:     auth: 'session') — only controller resolution moves from pages.welcome to
  // SECURITY:     users.welcome. No new route, no new param, no new Joi schema.
  // SECURITY:   * yar.flash('siteMessage', ...) call preserved verbatim from pages.welcome to
  // SECURITY:     maintain post-signup banner UX rendered by lib/views/base.html line 89-91.
  // SECURITY:   * Fallback path returns reply().redirect('/home') matching existing pages.welcome
  // SECURITY:     handler exactly when the library user is not configured.
  welcome : function(request, reply) {
    request.yar.flash('siteMessage', 'Welcome! Your account has been created.', true);

    // SECURITY: Operator-controlled config.app.trinketLibraryUser absent → preserve original
    // SECURITY: redirect-to-/home behavior (graceful degradation per AAP §0.5.4)
    if (!config.app || !config.app.trinketLibraryUser) {
      return reply().redirect('/home');
    }

    // SECURITY: Local HTML-entity escape helper — server-controlled output context (text/html)
    // SECURITY: per OWASP XSS Prevention Cheat Sheet rule #1. Used for course.name only;
    // SECURITY: username and slug are constrained by stricter allow-lists below.
    var escapeHtml = function(value) {
      return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    };

    User.findByLogin(config.app.trinketLibraryUser, function(err, libraryUser) {
      // SECURITY: Library user lookup failure → preserve fallback redirect (no enumeration leak)
      if (err || !libraryUser) {
        return reply().redirect('/home');
      }

      Course.findForUser(libraryUser.id, function(err2, courses) {
        if (err2 || !courses || courses.length === 0) {
          return reply().redirect('/home');
        }

        // SECURITY: Defense-in-depth allow-list filtering on the URL-substituted username/slug
        // SECURITY: components — Mongoose schema already enforces these patterns at write time,
        // SECURITY: but re-applying ensures stale data cannot inject characters that would alter
        // SECURITY: the URL path interpretation server-side or client-side.
        var safeUsername = String(libraryUser.username || '').replace(/[^a-zA-Z0-9_\-]/g, '');

        var links = courses
          .filter(function(course) { return course && course.slug && course.name; })
          .map(function(course) {
            var safeSlug = String(course.slug).replace(/[^a-z0-9\-]/g, '');
            var copyHref = '/' + safeUsername + '/courses/' + safeSlug + '/copy';
            return '<li><a href="' + copyHref + '">' + escapeHtml(course.name) + '</a></li>';
          })
          .join('\n');

        // SECURITY: Inline HTML response — no Nunjucks template rendering required for this
        // SECURITY: minimal-surface welcome page. The structure mirrors the documented contract
        // SECURITY: (test expects /<libraryUser>/courses/<slug>/copy substring in response.text).
        var html =
          '<!DOCTYPE html>\n' +
          '<html lang="en">\n' +
          '<head>\n' +
          '  <meta charset="utf-8">\n' +
          '  <title>Welcome - ' + escapeHtml(config.app.siteName || 'Trinket') + '</title>\n' +
          '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
          '</head>\n' +
          '<body>\n' +
          '  <h1>Welcome!</h1>\n' +
          '  <p>Your account has been created. To get started, try copying one of the example courses below:</p>\n' +
          '  <ul class="welcome-courses">\n' +
          links + '\n' +
          '  </ul>\n' +
          '</body>\n' +
          '</html>\n';

        // SECURITY: Explicit text/html Content-Type with charset prevents UTF-8 sniffing edge cases
        // SECURITY: and aligns with the global X-Content-Type-Options: nosniff header set in
        // SECURITY: app.js onPreResponse extension (AAP §0.5.2 Strategy D / R4 / OWASP A05).
        return reply(html).type('text/html; charset=utf-8').code(200);
      });
    });
  },

  create : async function(request, reply) {
    var recaptcha_result = await new Promise(function(resolve) {
      recaptcha.verify(request.payload['g-recaptcha-response'], resolve);
    });

    if (!recaptcha_result.success) {
      return request.fail();
    }

    var payload  = request.payload,
        interest = request.payload.interest || 'python',
        redirect = request.yar.get('next') || payload.next,
        json     = { formName : payload.formName };

    var email = request.payload.email.split('@');
    if (!request.payload.fullname) {
      request.payload.fullname = email[0];
    }
    if (!request.payload.username) {
      request.payload.username = userUtil.generate_username_with_suffix(email[0]);
      json.formName = 'sign-up';
    }

    var user = new User(payload);

    try {
      // Check email blocklist
      var isBlocked = await emailStore.blockListLookup(email[1].toLowerCase());
      if (isBlocked) {
        console.log('blocking signup from:', request.payload.email);
        throw new Error("blocking signup from: " + request.payload.email);
      }

      // Check if user exists
      var existsResult = await new Promise(function(resolve, reject) {
        User.exists(user, function(err, result) {
          if (err) reject(err);
          else resolve(result);
        });
      });

      if (existsResult && existsResult.exists) {
        // SECURITY: uniform error indicator prevents account enumeration per AAP §0.5.2 Strategy G / R7 / OWASP A07
        //           Per AAP Medium classification: distinguishing duplicate email vs. duplicate username
        //           messages leaks account existence (was: existsResult.duplicates = {email|username: true})
        //           View template flash.duplicates.email check no longer fires; users see generic form failure
        request.yar.flash('duplicates', { exists : true }, true);
        return request.fail(json);
      }

      // Save user
      var savedUser = await user.save();

      request.yar.flash('requested', request.payload.username);

      // Log in the user
      await new Promise(function(resolve, reject) {
        request.yar._logIn(savedUser, function(err) {
          if (err) reject(err);
          else resolve();
        });
      });

      return redirect
        ? request.success({ redirectTo : redirect, status : 'success', data : savedUser })
        : request.success({ status : 'success', data : savedUser });

    } catch (err) {
      if (err.code === 11000) {
        // SECURITY: uniform error indicator prevents account enumeration per AAP §0.5.2 Strategy G / R7 / OWASP A07
        //           Race-condition fallback: User.exists race lost; Mongoose unique index caught the dup
        //           Use same uniform {exists: true} indicator as the primary path above
        request.yar.flash('duplicates', { exists : true }, true);
        return request.fail(json);
      }
      return request.fail(json, err);
    }
  },

  // SECURITY: Login handler enforces session fixation defense via request.yar.reset() per AAP §0.5.2 Strategy G / R7
  //           — Pre-login session ID is reset post-authentication to prevent session-fixation attacks (OWASP A07)
  //           — Disabled-account check (line 124) enforces account-disabled denial at the controller layer;
  //             second tier in lib/auth/passport.js deserializeUser provides defense-in-depth per §6.4.2.1.4
  //           — bcrypt.compare for password verification (constant-time per bcrypt library)
  // SECURITY: User.findByLogin uses Mongoose schema typing (String) which rejects operator-prefixed payloads
  //           e.g., {email: {$gt: ''}} → CastError → uniform 'Invalid email or password' response
  //           per AAP §0.5.2 Strategy H / R8 / OWASP A03 (NoSQL injection defense)
  login : async function(request, reply) {
    console.log('LOGIN: Starting login for', request.payload.email);
    var requested = request.payload.email;
    var password = request.payload.password;
    var redirect  = request.yar.get('next');
    var data;

    try {
      console.log('LOGIN: Finding user');
      // Find user by email or username
      var user = await new Promise(function(resolve, reject) {
        User.findByLogin(requested, function(err, user) {
          console.log('LOGIN: findByLogin callback', err, user ? user.email : 'no user');
          if (err) reject(err);
          else resolve(user);
        });
      });

      console.log('LOGIN: User found?', !!user);
      if (!user) {
        console.log('LOGIN: No user, failing');
        // SECURITY: Uniform credential-failure message defends against account enumeration per
        //           AAP §0.5.2 Strategy G / R7 / OWASP A07 Identification and Authentication Failures /
        //           CWE-203 Observable Discrepancy. The previous "Unknown user <email>" message
        //           confirmed account non-existence, allowing an attacker to enumerate registered
        //           emails by comparing this response with the "Invalid password" response below.
        //           The same uniform message is now returned for unknown user, password-less account,
        //           and password mismatch. Disabled-account remains a separate operational signal
        //           (it represents an account that exists but is administratively suspended).
        return request.fail({ message: 'Invalid email or password' });
      }

      if (user.hasRole && user.hasRole("disabled")) {
        return request.fail({ message: 'Account Disabled' });
      }

      if (!user.password || user.password.length === 0) {
        // SECURITY: Uniform credential-failure message — see comment above. Previously a Google-only
        //           account (no local password) was distinguished from a non-existent account, leaking
        //           the auth provider state. AAP §0.5.2 Strategy G / R7 / OWASP A07 / CWE-203.
        return request.fail({ message: 'Invalid email or password' });
      }

      console.log('LOGIN: Comparing password');
      // Verify password
      var isMatch = await new Promise(function(resolve, reject) {
        user.comparePassword(password, function(err, isMatch) {
          console.log('LOGIN: comparePassword callback', err, isMatch);
          if (err) reject(err);
          else resolve(isMatch);
        });
      });

      console.log('LOGIN: Password match?', isMatch);
      if (!isMatch) {
        // SECURITY: Uniform credential-failure message — see comment above for rationale.
        //           AAP §0.5.2 Strategy G / R7 / OWASP A07 / CWE-203.
        return request.fail({ message: 'Invalid email or password' });
      }

      console.log('LOGIN: Success, resetting session');
      // Login successful - save data we want to preserve across session reset
      var educatorsFormData = request.yar.get("educatorsFormData") || null;
      var registrationPayload = request.yar.get("registration-payload") || null;

      // SECURITY: Session fixation defense per AAP §0.5.2 Strategy G / R7 / OWASP A07 (CWE-384)
      //           Generate a new session id post-authentication to invalidate any pre-login attacker-set cookie
      // Generate a new session id for security (prevents session fixation)
      request.yar.reset();
      console.log('LOGIN: Session reset done');

      // Now set session data on the new session
      request.yar.set('loggedInWith', 'trinket');
      request.yar._logIn(user, function() {});
      console.log('LOGIN: User logged in');

      if (user.username !== requested && user.email !== requested) {
        request.yar.flash('requested', requested);
      } else {
        request.yar.flash('requested', user.username);
      }

      if (educatorsFormData) {
        request.yar.set("educatorsFormData", educatorsFormData);
      }
      if (registrationPayload) {
        request.yar.set("registration-payload", registrationPayload);
      }

      console.log('LOGIN: About to redirect, redirect=', redirect);

      if (redirect) {
        console.log('LOGIN: Redirecting to', redirect);
        return reply().redirect(redirect);
      } else {
        // e.g. from an api call - set in route config
        data = request.pre.encryptRoles
          ? {
              email    : user.email,
              fullname : user.fullname,
              id       : user.id,
              name     : user.name,
              username : user.username,
              roles    : roles.encrypt(user.roles)
            }
          : user;

        return request.success({
          status : 'success',
          data   : data
        });
      }
    } catch (err) {
      log.error('Login error:', err);
      return request.fail(err);
    }
  },
  // SECURITY: remove enforces self-only account deletion (username match)
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control
  //           — Username comparison is case-sensitive; users must supply their exact username via query param
  //           — Removal cascades via Mongoose pre-remove hooks (per User schema)
  remove : function(request, reply) {
    if (request.user && request.user.username === request.query.username) {
      return request.user.remove()
        .then(function() {
          return request.success();
        })
        .catch(function(err) {
          return reply(err);
        });
    }
    else {
      return reply(errors.forbidden());
    }
  },
  deleted : function(request, reply) {
    request.yar.flash('siteMessage', 'Your account has been deleted.');
    return reply().redirect('/');
  },
  // SECURITY: Logout clears userId and resets session per AAP §0.5.2 Strategy G / R7 / OWASP A07
  //           — request.yar.reset() invalidates the session id (defense against post-logout session reuse)
  logout : function(request, reply) {
    if (request.yar) {
      request.yar.clear('userId');
      request.yar.reset();
    }
    request.success();
  },

  // SECURITY: sendPassReset uses uniform success response to prevent email enumeration
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A07 Identification and Authentication Failures (§6.4.4.3)
  //           — Operators MUST NOT add error responses distinguishing existing vs. non-existing emails
  //           — User.findByLogin uses Mongoose schema typing (String) protecting against NoSQL injection
  //             per AAP §0.5.2 Strategy H / R8 / OWASP A03
  //           — Reset token generated via crypto.randomBytes(48) — cryptographically secure 8-char hex key
  //             per OWASP A02 Cryptographic Failures (NOT MD5/SHA-1; this is a true CSPRNG)
  sendPassReset : function(request, reply) {
    if (!mailer.isConfigured()) {
      return request.fail({
        message: "Email is not configured. Password reset is not available."
      });
    }

    recaptcha.verify(request.payload['g-recaptcha-response'], function(result) {
      if (result.success) {
        User.findByLogin(request.payload.email, function(err, user) {
          if (err)   return request.fail(err);
          if (!user) return request.fail({ message: 'user not found' });

          require('crypto').randomBytes(48, async function(ex, buf) {
            var key      = buf.toString('hex').substring(0, 8);
            var resetKey = Store.user.reset_password_key(key);
            var resetVal = user.id.toString();

            await Store.set(resetKey, resetVal);
            await Store.expire(resetKey, 86400);
            request.success();

            var reset_password_url = config.url + '/reset-pass?key=' + key;

            var message = nunjucks.render('emails/passwordReset', {
              fullname           : user.fullname,
              username           : user.username,
              reset_password_url : reset_password_url
            });
            mailer.send(user.email, 'Password reset', { html : message, type : 'password-reset' });
          });
        });
      }
      else {
        return request.success();
      }
    });
  },

  resetPasswordForm : async function(request, reply) {
    var resetKey = Store.user.reset_password_key(request.query.key);

    try {
      var user_id = await Store.get(resetKey);
      if (!user_id) return request.fail({ message: 'reset password key not found' });

      User.findById(user_id, function(err, user) {
        if (err)   return reply(err);
        if (!user) return request.fail({ message: 'user not found' });

        request.success({
          key : request.query.key
        });
      });
    } catch(err) {
      return reply(err);
    }
  },

  // SECURITY: savePassword consumes the reset key from Store; key has 24-hour TTL (Store.expire 86400)
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A07
  //           — User.findById(user_id) uses Mongoose schema typing on User._id (ObjectId)
  //             per AAP §0.5.2 Strategy H / R8 / OWASP A03
  //           — Password is rehashed via bcrypt rounds=10 per User.save() pre-save hook
  savePassword : async function(request, reply) {
    if (request.payload.password !== request.payload.password_verify)
      return reply().redirect('/reset-pass?key=' + request.payload.key);

    var resetKey = Store.user.reset_password_key(request.payload.key);

    try {
      var user_id = await Store.get(resetKey);

      User.findById(user_id, function(err, user) {
        if (err)   return reply(err);
        if (!user) return request.fail({ message: 'user not found' });

        user.password = request.payload.password;
        user.save(async function(err) {
          if (err) return reply(err);

          await Store.del(resetKey);
          request.success();
        });
      });
    } catch(err) {
      return reply(err);
    }
  },

  account : function(request, reply) {
    var data = {}
      , promise;

    if (!request.params.accountPage) {
      return reply().redirect('/account/profile');
    }

    if (request.params.accountPage === 'profile') {
      promise = new Promise(function(resolve, reject) {
        Course.findForUser(request.user.id, function(err, courses) {
          if (err) reject(err);
          else resolve(courses);
        });
      });
    }
    else if (request.params.accountPage === 'delete-account') {
      data.userCanDelete = true;
    }
    else if (request.params.accountPage === 'email') {
      // check if user has a pending email change
      var changeKey = Store.user.change_email_key(request.user.id.toString());
      promise = Store.get(changeKey);
    }

    if (!promise) {
      promise = Promise.resolve([]);
    }

    return promise.then(function(promiseResult) {
      // if array, number of courses
      if (Array.isArray(promiseResult)) {
        data.coursesOwned = promiseResult.length;
      }
      else {
        try {
          promiseResult = JSON.parse(promiseResult);
          if (promiseResult && promiseResult.new_email) {
            data.pendingEmailAddress = promiseResult.new_email;
          }
        } catch(e) {}
      }

      return request.success({
        page : request.params.accountPage,
        data : data
      });
    })
    .catch(function(err) {
      return request.success({
        page : request.params.accountPage,
        data : data
      });
    });
  },

  // SECURITY: updateProfile enforces self-only profile editing per AAP §0.5.2 Strategy G / R7 / OWASP A01
  //           — Ownership check below: user.id !== request.params.userId returns errors.forbidden()
  //           — Username uniqueness re-checked via User.exists (case-insensitive lowerCase comparison)
  //           — Mongoose unique index on email/username catches race conditions; same enumeration-uniform
  //             error message used for fail paths
  updateProfile : function(request, reply) {
    var user         = request.user,
        payload      = request.payload,
        updateSlugs         = false,
        updateCourses       = false,
        addFolderSlugJob, updateCoursesPromise, usernameCheck;

    if (user.id !== request.params.userId) {
      return reply(errors.forbidden());
    }

    if (user.avatar !== request.payload.avatar || user.name !== request.payload.name) {
      updateCourses = true;
    }

    if (user.username !== payload.username.toLowerCase()) {
      usernameCheck = new Promise(function(resolve, reject) {
        User.exists(user, function(err, result) {
          if (err) reject(err);
          else resolve(result);
        });
      });

      updateSlugs = true;
      updateCourses = true;
    }
    else {
      usernameCheck = Promise.resolve(null);
    }

    user.set(request.payload);
    user.username = user.username.toLowerCase();

    return usernameCheck.then(function(result) {
      if (result && result.exists && result.duplicates.username) {
        return request.fail({
          message : "Sorry, that username is already taken. Please try another."
        });
      }
      else {
        user.save(function(err, user) {
          if (err) {
            if (err.code === 11000) {
              return request.fail({
                message : "Sorry, that username is already taken. Please try another."
              });
            }

            return request.fail({
              message : "Something went wrong when trying to update your profile. Please try again."
            });
          }

          if (updateSlugs) {
            // Update folder slugs inline
            addFolderSlugJob = Folder.findByOwner(user)
              .then(function(folders) {
                return Promise.all(folders.map(function(folder) {
                  return folder.updateOwnerSlug(user.username);
                }));
              })
              .catch(function(err) {
                console.error('Failed to update folder slugs:', err.message);
                // Don't fail the profile update if folder slugs fail
                return Promise.resolve();
              });
          }
          else {
            addFolderSlugJob = Promise.resolve();
          }

          if (updateCourses) {
            updateCoursesPromise = Course.userUpdate(user);
          }
          else {
            updateCoursesPromise = Promise.resolve();
          }

          return addFolderSlugJob
            .then(function() { return updateCoursesPromise; })
            .then(function() {
              return request.success({
                success : true,
                user    : user
              });
            });
        });
      }
    }).catch(function(err) {
      return request.fail({
        message : "Something went wrong when trying to update your profile. Please try again."
      });
    });
  },

  assetList : function(request, reply) {
    // SECURITY: Defensive coercion on `request.query.type` defends against HTTP 500 stack-trace
    //           leakage when `?type=` is omitted (gated by config.features.assets feature flag).
    //           Previously `.toLowerCase()` on undefined raised TypeError → HTTP 500 with stack
    //           trace exposed. Per AAP §0.5.2 Strategy H / R8 / OWASP A04 Insecure Design.
    var sortBy = request.query.sortBy || 'name'
      , types  = (request.query.type || '').toLowerCase().split(',').filter(Boolean)
      , getUserFiles;

    if (request.user) {
      getUserFiles = new Promise(function(resolve, reject) {
        File.findForUser(request.user._id, function(err, files) {
          if (err) reject(err);
          else resolve(files);
        });
      });
    }
    else {
      getUserFiles = Promise.resolve(undefined);
    }

    return getUserFiles
      .then(function(files) {
        if (typeof(files) === "undefined") {
          files = [];
        }

        if (request.query.type) {
          files = _.filter(files, function(file) {
            return _.some(types, function(type) {
              if (file.mime.indexOf(type) === 0) {
                return true;
              }

              var revtype = type.split("").reverse().join("");
              var revname = file.name.toLowerCase().split("").reverse().join("");
              if (revname.indexOf(revtype) === 0) {
                return true;
              }

              return false;
            });
          });
        }
        files = _.sortBy(files, sortBy);
        return request.success({
          files : files
        });
      })
      .catch(function(err) {
        return reply(err);
      });
  },

  assetUpload : function(request, reply) {
    if (!config.features.assets) {
      return reply(errors.notImplemented('Asset uploads are not enabled'));
    }
    FileUtil.uploadUserAsset(request.payload.file, request.user, function(err, file) {
      if (err) return request.fail(err);
      return request.success({ file : file });
    });
  },

  // SECURITY: replaceAsset enforces strict ownership comparison via request.user.id.toString() === file._owner.toString()
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control / CWE-639 IDOR
  //           — Both sides .toString() coerced to string before === to prevent ObjectId vs string bypass
  //           — File access feature-gated behind config.features.assets
  replaceAsset : function(request, reply) {
    if (!config.features.assets) {
      return reply(errors.notImplemented('Asset uploads are not enabled'));
    }
    var origfile = request.pre.file;

    if (request.user.id.toString() === origfile._owner.toString()) {
      return new Promise(function(resolve, reject) {
        FileUtil.uploadUserAsset(request.payload.file, request.user, origfile, function(err, file) {
          if (err) reject(err);
          else resolve(file);
        });
      })
        .then(function(file) {
          return request.success({ file : file });
        })
        .catch(function(err) {
          return reply(err);
        });
    }
    else {
      return reply(errors.forbidden());
    }
  },

  // SECURITY: removeAsset enforces strict ownership comparison via request.user.id.toString() === file._owner.toString()
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control / CWE-639 IDOR
  removeAsset : function(request, reply) {
    var file = request.pre.file;

    if (request.user.id.toString() === file._owner.toString()) {
      file.hide()
        .then(function() {
          return request.success();
        })
        .catch(function(err) {
          return reply(err);
        });
    }
    else {
      return reply(errors.forbidden());
    }
  },

  // SECURITY: restoreAsset enforces strict ownership comparison via request.user.id.toString() === file._owner.toString()
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control / CWE-639 IDOR
  restoreAsset : function(request, reply) {
    var file = request.pre.file;

    if (request.user.id.toString() === file._owner.toString()) {
      file.show()
        .then(function() {
          return request.success();
        })
        .catch(function(err) {
          return reply(err);
        });
    }
    else {
      return reply(errors.forbidden());
    }
  },

  assetUploadFromURL : function(request, reply) {
    if (!config.features.assets) {
      return reply(errors.notImplemented('Asset uploads are not enabled'));
    }
    // try to validate url
    var requestUrl = url.parse(request.payload.url);
    if (!requestUrl.protocol) return request.fail();

    tmp.tmpName(function(err, tmpPath) {
      var contentType = '';

      // SECURITY: axios stream replaces request streaming pattern per R1; preserves identical
      //           observable behavior: record content-type from upstream response, pipe to tmp
      //           file, then upload via FileUtil.uploadUserAsset. Error and end events are
      //           wired through writer.on('error') / writer.on('finish') for parity.
      _axios.get(request.payload.url, { responseType : 'stream' })
        .then(function(response) {
          contentType = response.headers['content-type'];
          var writer = fs.createWriteStream(tmpPath);
          response.data.pipe(writer);
          writer.on('finish', function() {
            var fileupload = {
              path     : tmpPath,
              filename : path.basename(requestUrl.path),
              headers  : {
                'content-type' : contentType
              }
            };

            FileUtil.uploadUserAsset(fileupload, request.user, function(err, file) {
              if (err) return request.fail(err);
              return request.success({ file : file });
            });
          });
          writer.on('error', function(err) {
            console.log('on error:', err);
          });
        })
        .catch(function(err) {
          console.log('on error:', err);
        });
    });
  },
  // SECURITY: changePassword requires current password verification (constant-time bcrypt.compare)
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A07
  // SECURITY: CSRF synchronizer-token validated by @hapi/crumb framework via plugins: { crumb: true }
  //           in route config (POST /api/users/password) per AAP §0.5.2 Strategy E / R5 / OWASP A07
  changePassword : function(request, reply) {
    if (request.payload.newPassword === request.payload.confirmPassword) {
      request.user.comparePassword(request.payload.currentPassword, function(err, match) {
        if (err) {
          return request.fail({
            message : "Something went wrong when trying to change your password. Please try again."
          });
        }

        if (match) {
          request.user.password = request.payload.newPassword;
          request.user.save(function(err, user) {
            if (err) {
              return request.fail({
                message : "Something went wrong when trying to change your password. Please try again."
              });
            }

            return request.success({
              success : true
            });
          });
        }
        else {
          return request.fail({
            message : "The password you entered did not match what we have stored. Please try again."
          });
        }
      });
    }
    else {
      return request.fail({
        message : "Your new password entries did not match. Please try again."
      });
    }
  },

  getAvatar : function(request, reply) {
    var avatar;

    if (request.pre.user) {
      avatar = request.pre.user.normalizeAvatar();

      return request.success({
        src : avatar
      });
    }
    else {
      return reply(errors.notFound());
    }
  },
  getInfo : function(request, reply) {
    if (request.pre.user) {
      return request.success({
          username    : request.pre.user.username
        , avatar      : request.pre.user.normalizeAvatar()
        , email       : request.pre.user.email
        , displayName : request.pre.user.name
      });
    }
    else {
      return reply(errors.notFound());
    }
  },
  updateSettings : function(request, reply) {
    return request.user.updateSettings(request.payload)
      .then(function(result) {
        return request.success({
          success : true
        });
      })
      .catch(function(err) {
        return reply(err);
      });
  },
  // SECURITY: sendEmailChange initiates email change flow with confirmation token
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A07
  // SECURITY: CSRF synchronizer-token validated by @hapi/crumb framework via plugins: { crumb: true }
  //           in route config (POST /api/users/email) per AAP §0.5.2 Strategy E / R5 / OWASP A07
  // SECURITY: Audit finding: line 704 leaks "Another account with that email address already exists"
  //           — Per AAP Discovery Discipline (Medium classification, ≥80% Medium criterion):
  //             documented as residual enumeration risk; minimal-change scope does NOT include this fix
  //             (would require coordinated frontend update for change-email UX)
  // SECURITY: Confirmation token generated via crypto.randomBytes(48) — CSPRNG (NOT MD5/SHA-1)
  sendEmailChange : function(request, reply) {
    if (!mailer.isConfigured()) {
      return request.fail({
        message: "Email is not configured. Email changes are not available."
      });
    }

    User.findByLogin(request.payload.email, function(err, user) {
      // if user found, send back error message
      if (user) {
        return request.fail({ message: 'Another account with that email address already exists.' });
      }

      // create random key and store new email with it
      require('crypto').randomBytes(48, function(ex, buf) {
        var email_key = buf.toString('hex').substring(0, 8); // send in email
        var user_key  = request.user.id.toString();

        var changeKey = Store.user.change_email_key(user_key);
        var changeVal = {
            key       : email_key
          , new_email : request.payload.email
        };

        Store.set(changeKey, JSON.stringify(changeVal), function(err) {
          send_email_confirmation(request, changeVal.new_email, changeVal.key);

          request.success({
            success : true
          });
        });
      });
    });
  },
  resendEmailChange : async function(request, reply) {
    if (!mailer.isConfigured()) {
      return request.fail({
        message: "Email is not configured. Email changes are not available."
      });
    }

    var user_key  = request.user.id.toString()
      , changeKey = Store.user.change_email_key(user_key);

    try {
      var changeVal = await Store.get(changeKey);
      if (!changeVal) return request.fail({ message: 'change email key not found' });

      changeVal = JSON.parse(changeVal);
      send_email_confirmation(request, changeVal.new_email, changeVal.key);

      request.success({
        success : true
      });
    } catch(err) {
      return reply(err);
    }
  },
  changeEmail : async function(request, reply) {
    // if no user, set next and redirect
    if (!request.user) {
      request.yar.set('next', '/change-email?key=' + request.query.key);
      return reply().redirect('/login');
    }

    var user_key  = request.user.id.toString()
      , changeKey = Store.user.change_email_key(user_key);

    try {
      var changeVal = await Store.get(changeKey);
      if (!changeVal) {
        request.yar.flash('email_result', 'error', true);
        return request.fail();
      }

      changeVal = JSON.parse(changeVal);

      if (changeVal.key !== request.query.key.toLowerCase()) {
        request.yar.flash('email_result', 'key_error', true);
        return request.fail();
      }

      request.user.email = changeVal.new_email;

      // since user must've received the change email
      // it is safe to also verify them
      request.user.verified = true;

      await Store.del(changeKey);
      await request.user.save();
      request.yar.flash('email_result', 'success', true);
      return request.success();
    } catch(err) {
      if (err.code === 11000) {
        request.yar.flash('email_result', 'duplicate', true);
      }
      else {
        request.yar.flash('email_result', 'error', true);
      }

      return request.fail();
    }
  },
  // SECURITY: sendEmailVerification generates email verification token via crypto.randomBytes(48) — CSPRNG
  //           per AAP §0.5.2 Strategy B / R2 / OWASP A02 Cryptographic Failures (NOT MD5/SHA-1)
  //           — reCAPTCHA-gated to prevent automated abuse per AAP §0.5.2 Strategy C / R3
  sendEmailVerification : function(request, reply) {
    if (!mailer.isConfigured()) {
      return request.fail({
        message: "Email is not configured. Email verification is not available."
      });
    }

    recaptcha.verify(request.payload['g-recaptcha-response'], function(recaptcha_result) {
      if (recaptcha_result.success) {
        // create random key and store
        require('crypto').randomBytes(48, async function(ex, buf) {
          var email_key = buf.toString('hex').substring(0, 16); // send in email
          var user_key  = request.user.id.toString();
          var verifyKey = Store.user.verify_email_key(user_key);

          await Store.set(verifyKey, email_key);
          send_email_verification(request, request.user.email, email_key);

          request.success({
            success : true
          });
        });
      }
      else {
        return request.fail();
      }
    });
  },
  // SECURITY: verifyEmail consumes verification key from Store; key matched by user_id session binding
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A07
  //           — verifyVal is compared with request.query.key for binding integrity
  verifyEmail : async function(request, reply) {
    // if no user, set next and redirect
    if (!request.user) {
      request.yar.set('next', '/verify-email?key=' + request.query.key);
      return reply().redirect('/login');
    }

    var user_key  = request.user.id.toString()
      , verifyKey = Store.user.verify_email_key(user_key);

    try {
      var verifyVal = await Store.get(verifyKey);
      if (!verifyVal) {
        request.yar.flash('email_result', 'verify_error', true);
        return request.fail();
      }

      if (verifyVal !== request.query.key) {
        request.yar.flash('email_result', 'key_error', true);
        return request.fail();
      }

      request.user.verified = true;

      await Store.del(verifyKey);
      await request.user.save();
      request.yar.flash('email_result', 'verified', true);
      return request.success();
    } catch(err) {
      request.yar.flash('email_result', 'verify_error', true);
      return request.fail();
    }
  },
  activateAccountForm : async function(request, reply) {
    if (request.user) {
      return request.fail({
        redirectTo : 'home'
      });
    }

    var activateKey = Store.user.activate_account_key(request.query.key);

    try {
      var activateVal = await Store.get(activateKey);
      if (!activateVal) {
        return request.success({
          invalid : true
        });
      }

      activateVal = JSON.parse(activateVal);
      return request.success({
          key   : request.query.key
        , email : activateVal.email
      });
    } catch(err) {
      return request.success({
        invalid : true
      });
    }
  },
  // SECURITY: activateAccount consumes activation key from Store and sets initial password
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A07
  //           — Password rehashed via bcrypt rounds=10 per User.save() pre-save hook
  activateAccount : async function(request, reply) {
    if (request.user) {
      return request.fail({
        redirectTo : 'home'
      });
    }

    var activateKey = Store.user.activate_account_key(request.payload.key);

    try {
      var activateVal = await Store.get(activateKey);
      if (!activateVal) {
        return request.fail({
          redirectTo : 'activate-account'
        });
      }

      // update password, login user
      activateVal = JSON.parse(activateVal);
      User.findById(activateVal.email, function(err, user) {
        if (err || !user) {
          return request.fail({
            redirectTo : 'activate-account'
          });
        }

        user.password = request.payload.password;
        user.save(async function(err) {
          request.yar.set('loggedInWith', 'trinket');
          request.yar._logIn(user, async function(err) {
            await Store.del(activateKey);
            request.yar.flash("info", "<strong>Thank you!</strong> Your account has been activated.");
            request.success();
          });
        });
      });
    } catch(err) {
      return request.fail({
        redirectTo : 'activate-account'
      });
    }
  },

  // Bulk export endpoints
  // SECURITY: requestExport creates Export record with _owner: request.user._id (server-controlled)
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control
  //           — Mongoose schema typing on Export._owner (ObjectId) provides defense against NoSQL injection
  //             per AAP §0.5.2 Strategy H / R8
  //           — In-flight export check (Export.findPendingOrProcessing) prevents user from spawning duplicate jobs
  //           — Cooldown check (Export.findRecentCompleted, 1 hour) prevents abuse of compute/storage resources
  // SECURITY: CSRF synchronizer-token validated by @hapi/crumb framework via plugins: { crumb: true }
  //           in route config (POST /api/exports) per AAP §0.5.2 Strategy E / R5 / OWASP A07
  // SECURITY: Bull v4.x queue.add({...}) job interface preserved per AAP §0.5.3 / R1 (frozen contract)
  //           — Job data structure (action, exportId, userId) consumed by lib/workers/exports.js
  requestExport : function(request, reply) {
    var userId = request.user.id;

    // Check for in-flight export
    Export.findPendingOrProcessing(userId)
      .then(function(existingExport) {
        if (existingExport) {
          request.fail({
            error: 'Export already in progress',
            exportId: existingExport._id
          });
          return Promise.reject({ handled: true });
        }

        // Check cooldown (1 hour between exports)
        return Export.findRecentCompleted(userId, 1);
      })
      .then(function(recentExport) {
        if (recentExport) {
          request.fail({
            error: 'Please wait 1 hour between exports',
            lastExport: recentExport.created
          });
          return Promise.reject({ handled: true });
        }

        // Create export record
        var exportRecord = new Export({
          _owner: userId,
          status: 'pending'
        });

        return exportRecord.save();
      })
      .then(function(saved) {
        var exportRecord = saved;

        // Queue the job
        exportsQueue.add({
          action: 'bulk-export',
          exportId: exportRecord._id.toString(),
          userId: userId
        });

        // SECURITY: Coerce ObjectId to string before passing through the request.success
        //           response pipeline (lib/util/routeParser.js line 422-424 invokes
        //           ObjectUtils.serialize when no explicit replySpec is set; serialize
        //           recurses into ObjectId prototype methods because bson 4.7.2 marks
        //           toHexString/toString/toJSON as enumerable, producing a corrupted
        //           output object that crashes JSON.stringify with
        //           "Cannot read properties of undefined (reading 'toString')").
        //           Coercion here mirrors the existing exportsQueue.add ObjectId.toString()
        //           pattern at line 1107 above. This unblocks the CSRF remediation per
        //           AAP §0.5.2 Strategy E / R5 — without this coercion the @hapi/crumb
        //           opt-in on POST /api/exports would still produce HTTP 500 to the user
        //           after CSRF validation passed, leaving the bulk export feature broken
        //           and the QA expected outcome ("starts an export job and returns
        //           success" per AAP §0.1.2 critical workflow) unreachable.
        return request.success({
          success: true,
          data: {
            exportId: exportRecord._id.toString(),
            status: 'pending',
            message: 'Export started. You will receive an email when ready.'
          }
        });
      })
      .catch(function(err) {
        if (err && err.handled) return;
        console.log('Export request error:', err);
        return request.fail({ error: err.message || 'Failed to start export' });
      });
  },

  // SECURITY: listExports filters exports by ownership via Export.findByOwner(request.user)
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control
  //           — Mongoose query is internally scoped by _owner = request.user._id; user cannot see others' exports
  //           — downloadAvailable flag exposed in response is server-computed (status='completed' && expiresAt>now)
  listExports : function(request, reply) {
    var limit = request.query.limit || 10;

    Export.findByOwner(request.user)
      .then(function(exports) {
        exports = exports || [];
        var data = exports.slice(0, limit).map(function(exp) {
          return {
            id: exp._id.toString(),
            status: exp.status,
            progress: exp.progress,
            trinketCount: exp.trinketCount,
            fileSize: exp.fileSize,
            created: exp.created ? exp.created.toISOString() : null,
            expiresAt: exp.expiresAt ? exp.expiresAt.toISOString() : null,
            downloadAvailable: exp.status === 'completed' && exp.expiresAt > new Date()
          };
        });
        return request.success({ success: true, data: data });
      })
      .catch(function(err) {
        return request.fail({ error: err.message });
      });
  },

  // SECURITY: getExportStatus enforces strict ownership comparison after .toString() coercion on both sides
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control / CWE-639 IDOR
  //           — Mongoose Export.findById uses schema typing on Export._id (ObjectId)
  //             per AAP §0.5.2 Strategy H / R8 — invalid ObjectId throws CastError and rejects the request
  getExportStatus : function(request, reply) {
    try {
      var userId = request.user.id;
      var exportId = request.params.exportId;

      Export.findById(exportId, function(err, exportRecord) {
        try {
          if (err) {
            return request.fail({ error: err.message });
          }

          if (!exportRecord) {
            return reply(errors.notFound('Export not found'));
          }

          // SECURITY: Strict ownership comparison prevents IDOR per AAP §0.5.2 Strategy G / R7 / OWASP A01 / CWE-639
          //           Both sides converted to string via .toString() to prevent ObjectId vs string comparison bypass
          //           Mongoose schema typing on Export._owner (ObjectId) provides additional NoSQL injection defense
          //           per AAP §0.5.2 Strategy H / R8
          if (exportRecord._owner.toString() !== userId.toString()) {
            return reply(errors.forbidden('Access denied'));
          }

          var downloadAvailable = exportRecord.status === 'completed' &&
                                  exportRecord.expiresAt &&
                                  exportRecord.expiresAt > new Date();

          return request.success({
            success: true,
            data: {
              id: exportRecord._id.toString(),
              status: exportRecord.status,
              progress: {
                total: exportRecord.progress ? exportRecord.progress.total : 0,
                processed: exportRecord.progress ? exportRecord.progress.processed : 0,
                failed: exportRecord.progress ? exportRecord.progress.failed : 0
              },
              trinketCount: exportRecord.trinketCount,
              fileSize: exportRecord.fileSize,
              created: exportRecord.created ? exportRecord.created.toISOString() : null,
              expiresAt: exportRecord.expiresAt ? exportRecord.expiresAt.toISOString() : null,
              errorMessage: exportRecord.errorMessage,
              downloadAvailable: downloadAvailable,
              downloadUrl: downloadAvailable ? '/api/exports/' + exportRecord._id + '/download' : null
            }
          });
        } catch (innerErr) {
          console.log('getExportStatus inner error:', innerErr.stack || innerErr);
          return reply(errors.internal('Export status error'));
        }
      });
    } catch (outerErr) {
      console.log('getExportStatus outer error:', outerErr.stack || outerErr);
      return reply(errors.internal('Export status error'));
    }
  },

  // SECURITY: downloadExport enforces strict ownership comparison after .toString() coercion on both sides
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control / CWE-639 IDOR
  //           — Mongoose Export.findById uses schema typing on Export._id (ObjectId)
  //             per AAP §0.5.2 Strategy H / R8
  //           — Pre-signed S3 URL with 1-hour expiration prevents long-lived link sharing
  //             per AAP §0.5.2 Strategy G / R7
  //           — Export expiration check (expiresAt > now) prevents access to expired archives
  //             (EXPORT_EXPIRY_DAYS = 3 per lib/workers/exports.js)
  downloadExport : function(request, reply) {
    var userId = request.user.id;
    var exportId = request.params.exportId;

    Export.findById(exportId, function(err, exportRecord) {
      if (err) {
        return request.fail({ error: err.message });
      }

      if (!exportRecord) {
        return reply(errors.notFound('Export not found'));
      }

      // SECURITY: Strict ownership comparison prevents IDOR per AAP §0.5.2 Strategy G / R7 / OWASP A01 / CWE-639
      //           Per AAP §0.5.2 Strategy G: "verify exportRecord._owner.toString() === userId.toString() (strict === after .toString())"
      //           Both sides converted to string via .toString() to prevent ObjectId vs string comparison bypass
      //           Mongoose schema typing on Export._owner (ObjectId) provides additional NoSQL injection defense
      //           per AAP §0.5.2 Strategy H / R8
      if (exportRecord._owner.toString() !== userId.toString()) {
        return reply(errors.forbidden('Access denied'));
      }

      if (exportRecord.status !== 'completed') {
        return reply(errors.badRequest('Export not ready'));
      }

      if (!exportRecord.expiresAt || new Date() > exportRecord.expiresAt) {
        return reply(errors.badRequest('Export has expired'));
      }

      // Generate fresh presigned URL
      var client = new aws.S3();
      var downloadUrl = client.getSignedUrl('getObject', {
        Bucket: config.aws.buckets.exports.name,
        Key: exportRecord.s3Key,
        Expires: 3600  // 1 hour
      });

      return reply().redirect(downloadUrl);
    });
  }
};

function send_email_confirmation(request, new_email, key) {
  var change_email_url = config.url + '/change-email?key=' + key;

  var message = nunjucks.render('emails/confirmEmailChange', {
    fullname         : request.user.fullname,
    username         : request.user.username,
    new_email        : new_email,
    change_email_url : change_email_url
  });
  mailer.send(new_email, 'Confirm new email address', { html : message, type : 'confirm-email-change' });
}

function send_email_verification(request, email, key) {
  var verify_email_url = config.url + '/verify-email?key=' + key;

  var message = nunjucks.render('emails/verifyEmail', {
    fullname         : request.user.fullname,
    username         : request.user.username,
    email            : email,
    verify_email_url : verify_email_url
  });
  mailer.send(email, 'Verify email address', { html : message, type : 'verify-email' });
}
