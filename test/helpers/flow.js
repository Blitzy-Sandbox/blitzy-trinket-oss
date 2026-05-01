// SECURITY: app.js MUST be required BEFORE config/app.config to defeat a
// SECURITY: module-load ordering trap that breaks @hapi/inert schema validation under
// SECURITY: mocha. Root cause: config/app.config → config/db → mongoose-schema-extend →
// SECURITY: harmony-reflect, which patches Object.defineProperty / Object.getPrototypeOf
// SECURITY: in ways that prevent @hapi/inert/node_modules/@hapi/validate@2.x from
// SECURITY: registering its Symbol.for('@hapi/joi/schema') marker on freshly-created
// SECURITY: schemas (verified via runtime experiment: loading config/db.js BEFORE
// SECURITY: @hapi/validate causes Validate.isSchema(Validate.string()) to return false;
// SECURITY: reversing the order works correctly). The production app.js avoids this by
// SECURITY: loading @hapi/inert at line 23 BEFORE config/app.config at line 27 — the
// SECURITY: same ordering must be preserved in the test harness. Loading app.js here
// SECURITY: triggers @hapi/inert load FIRST, then config/app.config inside app.js.
// SECURITY: Both `app` and `config` references below remain bound to the same
// SECURITY: module-cache entries — no behavioral change to the test fixture beyond the
// SECURITY: fix. Closes QA Issue #3 (test/security/* suite cannot execute) per FINAL
// SECURITY: SECURITY checkpoint findings; AAP §0.5.2 Strategy I / R9 / §0.6.1 mapping.
var _           = require('underscore'),
    server      = require('supertest'),
    url         = require('url'),
    querystring = require('querystring'),
    defaults    = require('./defaults'),
    app         = require('../../app.js'),
    config      = require('../../config/app.config'),
    appInstance = require('./app-instance');

// public interface
var methods = {
  register : function(body, cb) {
    if (typeof body === 'function') {
      cb   = body;
      body = {};
    }

    var data = defaults.extend(body, 'user');
    if (!data.formName) {
      data.formName = 'signup';
    }

    return this.post('/users')
      .send(defaults.extend(data, 'recaptcha'))
      .end(this.setLastResponse(cb));
  },

  index : function(cb) {
    return this.get('/')
      .end(this.setLastResponse(cb));
  },

  login : function(body, cb) {
    if (typeof body === 'function') {
      cb   = body;
      body = {};
    }

    return this.post('/login')
      .send(defaults.extend(body, 'login'))
      .end(this.setLastResponse(cb));
  },

  viewCourse : function(user, course, cb) {
    return this.get('/u/' + user + '/classes/' + course)
      .end(this.setLastResponse(cb));
  },

  logout : function(cb) {
    // SECURITY: After logout, clear the cached session cookie for the active user so
    // SECURITY: subsequent flow.switchUser(user, done) calls re-login rather than
    // SECURITY: re-using the (now server-side-invalidated) post-logout cookie. Without
    // SECURITY: this cleanup the cookie at flow.cookies[activeUser] gets overwritten
    // SECURITY: by the new yar-reset session cookie returned in the /logout response,
    // SECURITY: but that cookie carries no userId so any authenticated request made
    // SECURITY: with it returns 401 — masquerading as a CSRF or IDOR test failure
    // SECURITY: when the actual cause is stale-session reuse across mocha scenarios.
    // SECURITY: This is a test-helper-only correction that surfaces only after the
    // SECURITY: @hapi/inert / app-instance fixes wired here let the suite execute end
    // SECURITY: to end. Closes QA Issue #3 (test/security/* suite cannot execute) per
    // SECURITY: AAP §0.5.2 Strategy I / R9 mapping; aligns the test infra with the
    // SECURITY: yar.clear('userId') + yar.reset() server contract documented in
    // SECURITY: lib/controllers/users.js logout handler.
    var self = this;
    return this.get('/logout')
      .end(function(err, res) {
        // Inline setLastResponse semantics, then drop the stale cookie before the
        // user-supplied callback runs (so any chained flow.switchUser triggers login).
        if (!err && res && res.headers && res.headers['set-cookie']) {
          self.cookies[self.activeUser] = mergeCookies(
            self.cookies[self.activeUser],
            res.headers['set-cookie']
          );
        }
        self.lastResponse = res;
        self.lastError    = err;
        self.wasOk        = err ? false : true;
        if (res && res.redirect) {
          self.lastRedirect = url.parse(res.headers.location);
        }
        if (res && res.headers) {
          self.lastContentType = res.headers['content-type'];
        }
        // Drop the now-invalid cookie so future switchUser(user, done) re-authenticates.
        delete self.cookies[self.activeUser];
        if (cb) cb(err, res);
      });
  },

  welcome : function(cb) {
    return this.get('/welcome')
      .end(this.setLastResponse(cb));
  },

  home : function(cb) {
    return this.get('/home')
      .end(this.setLastResponse(cb));
  },

  admin : function(cb) {
    return this.get('/admin/users')
      .end(this.setLastResponse(cb));
  },

  sendPassReset : function(body, cb) {
    if (typeof body === 'function') {
      cb   = body;
      body = {};
    }

    return this.post('/send-pass-reset')
      .send(defaults.extend(body, 'recaptcha'))
      .end(this.setLastResponse(cb));
  },

  resetPassForm : function(query, cb) {
    return this.get('/reset-pass?key=' + query)
      .end(this.setLastResponse(cb));
  },

  savePass : function(body, cb) {
    if (typeof body === 'function') {
      cb   = body;
      body = {};
    }

    return this.post('/save-pass')
      .send(body)
      .end(this.setLastResponse(cb));
  },

  updateProfile : function(userId, profile, cb) {
    return this.put('/api/users/' + userId)
      .send(profile)
      .end(this.setLastResponse(cb));
  },

  createCourse : function(body, cb) {
    if (typeof body === 'function') {
      cb   = body;
      body = {};
    }

    return this.post('/api/courses')
      .send(defaults.extend(body, 'course'))
      .end(this.setLastResponse(cb));
  },

  deleteCourse : function(courseId, cb) {
    return this.del('/api/courses/' + courseId)
      .end(this.setLastResponse(cb));
  },

  copyCourse : function(courseId, body, cb) {
    return this.post('/api/courses/' + courseId + '/copy')
      .send(body)
      .end(this.setLastResponse(cb));
  },

  updateCourse : function(courseId, body, cb) {
    return this.put('/api/courses/' + courseId + '/metadata')
      .send(body)
      .end(this.setLastResponse(cb));
  },

  updateLesson : function(courseId, lessonId, body, cb) {
    return this.put('/api/courses/' + courseId + '/lessons/' + lessonId + '/name')
      .send(body)
      .end(this.setLastResponse(cb));
  },

  getCourse : function(id, cb) {
    return this.get('/api/courses/' + id)
      .end(this.setLastResponse(cb));
  },

  getCourseBySlug : function(userSlug, courseSlug, cb) {
    return this.get('/u/' + userSlug + '/classes/' + courseSlug)
      .end(this.setLastResponse(cb));
  },

  getCourseWithOutline : function(id, cb) {
    return this.get('/api/courses/' + id + '?outline=yes')
      .end(this.setLastResponse(cb));
  },

  downloadCourse : function(url, cb) {
    return this.get(url)
      .end(this.setLastResponse(cb));
  },

  addNewLesson : function(courseId, body, cb) {
    if (typeof body === 'function') {
      cb = body;
      body = {};
    }

    return this.post('/api/courses/' + courseId + '/lessons')
      .send(defaults.extend(body, 'lesson'))
      .end(this.setLastResponse(cb));
  },

  getLesson : function(courseId, lessonId, cb) {
    return this.get('/api/courses/' + courseId + '/lessons/' + lessonId)
      .end(this.setLastResponse(cb));
  },

  moveLesson : function(courseId, lessonId, index, cb) {
    return this.put('/api/courses/' + courseId + '/lessons/' + lessonId + '/move')
      .send({ index : index })
      .end(this.setLastResponse(cb));
  },

  deleteLesson : function(courseId, lessonId, cb) {
    return this.del('/api/courses/' + courseId + '/lessons/' + lessonId)
      .end(this.setLastResponse(cb));
  },

  addNewMaterial : function(courseId, lessonId, body, cb) {
    if (typeof body === 'function') {
      cb = body;
      body = {};
    }

    return this.post('/api/courses/' + courseId + '/lessons/' + lessonId + '/materials')
      .send(defaults.extend(body, 'material'))
      .end(this.setLastResponse(cb));
  },

  updateMaterial : function(courseId, lessonId, materialId, body, cb) {
    return this.put('/api/courses/' + courseId + '/lessons/' + lessonId + '/materials/' + materialId + '/name')
      .send(body)
      .end(this.setLastResponse(cb));
  },

  patchMaterialContent : function(courseId, lessonId, materialId, body, cb) {
    return this.put('/api/courses/' + courseId + '/lessons/' + lessonId + '/materials/' + materialId + '/patchContent')
      .send(body)
      .end(this.setLastResponse(cb));
  },

  deleteMaterial : function(courseId, lessonId, materialId, cb) {
    return this.del('/api/courses/' + courseId + '/lessons/' + lessonId + '/materials/' + materialId)
      .end(this.setLastResponse(cb));
  },

  moveMaterial : function(courseId, lessonId, materialId, index, cb) {
    return this.put('/api/courses/' + courseId + '/lessons/' + lessonId + '/materials/' + materialId + '/move')
      .send({ index : index })
      .end(this.setLastResponse(cb));
  },

  getMaterial : function(courseId, lessonId, materialId, cb) {
    return this.get('/api/courses/' + courseId + '/lessons/' + lessonId + '/materials/' + materialId)
      .end(this.setLastResponse(cb));
  },

  markMaterialDraft : function(courseId, lessonId, materialId, cb) {
    return this.put('/api/courses/' + courseId + '/lessons/' + lessonId + '/materials/' + materialId + '/draft')
      .send({ isDraft : true })
      .end(this.setLastResponse(cb));
  },

  uploadFile : function(body, cb) {
    if (typeof body === 'function') {
      cb = body;
      body = {};
    }

    // TODO: create way to override body

    return this.post('/file')
      .field('type', defaults.file.type)
      .attach('upload', defaults.file.upload)
      .end(this.setLastResponse(cb));
  },

  downloadFile : function(fileId, cb) {
    return this.get('/api/files/' + fileId + '/download')
      .end(this.setLastResponse(cb));
  },

  uploadIpynb : function(body, cb) {
    if (typeof body === 'function') {
      cb = body;
      body = {};
    }

    return this.post('/file')
      .field('type', defaults.ipynb.type)
      .attach('upload', defaults.ipynb.upload)
      .end(this.setLastResponse(cb));
  },

  createTrinket : function(body, cb) {
    if (typeof body === 'function') {
      cb = body;
      body = {};
    }

    return this.post('/api/trinkets')
      .send(defaults.trinket)
      .end(this.setLastResponse(cb));
  },

  getTrinket : function(trinketHash, lang, cb) {
    return this.get('/' + lang + '/' + trinketHash)
      .end(this.setLastResponse(cb));
  },

  getEmbeddedTrinket : function(trinketId, lang, query, cb) {
    if (typeof query === 'function') {
      cb = query;
      query = {};
    }

    var url = '/embed/' + lang + '/' + trinketId;
    if (query.length) {
      url += '?' + querystring.stringify(query);
    }

    return this.get(url)
      .end(this.setLastResponse(cb));
  },

  emailTrinket : function(trinketId, body, cb) {
    if (typeof body === 'function') {
      cb = body;
      body = {};
    }

    return this.post('/api/trinkets/' + trinketId + '/email')
      .send(defaults.extend(body, 'recaptcha'))
      .end(this.setLastResponse(cb));
  },

  runTrinket : function(trinketId, cb) {
    return this.put('/api/trinkets/' + trinketId + '/metrics')
      .send({ runs : true })
      .end(this.setLastResponse(cb));
  },

  forkTrinket : function(parentTrinketId, trinketData, cb) {
    return this.post('/api/trinkets/' + parentTrinketId + '/forks')
      .send(trinketData)
      .end(this.setLastResponse(cb));
  },

  snapshotTrinket : function(trinketId, cb) {
    return this.post('/api/trinkets/' + trinketId + '/snapshot')
      .end(this.setLastResponse(cb));
  },

  trinketRunError : function(body, cb) {
    if (typeof body === 'function') {
      cb = body;
      body = {};
    }

    return this.post('/api/trinkets/codeerror')
      .send(defaults.trinketRunError)
      .end(this.setLastResponse(cb));
  },

  subscribe : function(list, email, cb) {
    return this.post('/api/subscriptions/' + list)
      .send({email:email})
      .end(this.setLastResponse(cb));
  },

  unsubscribe : function(list, email, cb) {
    return this.del('/api/subscriptions/' + list + '?email=' + email)
      .end(this.setLastResponse(cb));
  },

  getSubscriptions : function(list, cb) {
    return this.get('/api/subscriptions/' + list)
      .end(this.setLastResponse(cb));
  },

  switchUser : function(user, done) {
    var self = this;

    self.activeUser = user;

    if (done) {
      if (!self.cookies[user]) {
        var credentials = {
          email: defaults[user].email,
          password: defaults[user].password
        };

        function onLoginComplete(err, res) {
          // SECURITY: Each branch MUST `return` before the trailing done() invocation
          // SECURITY: to prevent "done() called multiple times" cascading test failures
          // SECURITY: under Mocha's strict double-callback detector. Pre-existing bug in
          // SECURITY: the original flow.js helper — historically masked because the
          // SECURITY: test/security/* suite could not bootstrap (QA Issue #3); surfaces
          // SECURITY: only after the @hapi/inert / app-instance fixes wired here. The
          // SECURITY: 200 OR 302 success contract reflects the dual-mode response shape
          // SECURITY: of /login per lib/controllers/users.js: 302 redirect when the
          // SECURITY: client supplies a `redirect` query (browser form flow) and 200
          // SECURITY: JSON success response when no redirect is set (API flow used by
          // SECURITY: switchUser fixtures here). Both signal authenticated success and
          // SECURITY: the session cookie is issued in either branch via @hapi/yar.
          if (err) {
            return done(err);
          }
          if (res.statusCode !== 302 && res.statusCode !== 200) {
            return done(new Error('Failed to log in "' + user + '" — got status ' + res.statusCode));
          }

          return done();
        };

        return User.findByLogin(credentials.email, function(err, doc) {
          if (err) {
            return done(err);
          }

          if (!doc) {
            var userModel = new User(defaults[user]);
            return userModel.save(function(err) {
              self.login(credentials, onLoginComplete)
            });
          }

          return self.login(credentials, onLoginComplete);
        });
      }

      return done();
    }
  },

  setLastResponse : function(cb) {
    var self = this;

    return function(err, res) {
      if (!err && res && res.headers && res.headers['set-cookie']) {
        // SECURITY: Merge incoming Set-Cookie headers by cookie NAME rather than
        // SECURITY: replacing the entire cookie jar — Hapi often returns ONLY the
        // SECURITY: cookies that changed in the response (e.g., on a CSRF-403 the
        // SECURITY: response carries only the freshly-rotated `crumb=` cookie and
        // SECURITY: omits the unchanged `session=` cookie). Plain assignment via
        // SECURITY: `self.cookies[self.activeUser] = res.headers['set-cookie']`
        // SECURITY: silently dropped the still-valid session cookie, causing every
        // SECURITY: subsequent request from the same flow to be unauthenticated and
        // SECURITY: producing spurious 401s on access-control / IDOR / admin tests
        // SECURITY: (verified via inject() bisection — see QA Issue #3 fix narrative).
        // SECURITY: Pre-existing helper bug; surfaces only after the @hapi/inert /
        // SECURITY: app-instance / store / catbox-redis fixes wired in this batch let
        // SECURITY: the suite execute end to end. Closes QA Issue #3 (test/security/*
        // SECURITY: suite cannot execute) per AAP §0.5.2 Strategy I / R9 mapping.
        self.cookies[self.activeUser] = mergeCookies(
          self.cookies[self.activeUser],
          res.headers['set-cookie']
        );
      }

      self.lastResponse = res;
      self.lastError    = err;
      self.wasOk        = err ? false : true;
      if (res && res.redirect) {
        self.lastRedirect = url.parse(res.headers.location)
      }

      self.lastContentType = res && res.headers ? res.headers['content-type'] : undefined;

      cb(err, res);
    }
  }
}

// SECURITY: Merge two arrays of Set-Cookie header strings into a single cookie jar
// SECURITY: array, with the second array's cookies overriding any same-named cookies
// SECURITY: in the first. Cookie name is the substring before the first `=`. This
// SECURITY: matches RFC 6265 §5.3 "Storage Model" cookie-replacement semantics —
// SECURITY: a fresh Set-Cookie with the same name replaces the existing entry, and
// SECURITY: cookies with different names coexist. Used by setLastResponse and the
// SECURITY: logout flow to preserve unchanged session cookies across responses that
// SECURITY: only return rotated CSRF / crumb cookies. Closes QA Issue #3 cookie-jar
// SECURITY: defect; AAP §0.5.2 Strategy I / R9 mapping.
function mergeCookies(existing, incoming) {
  var jar = {};
  function ingest(cookies) {
    if (!cookies) return;
    cookies.forEach(function (raw) {
      if (typeof raw !== 'string') return;
      var name = raw.split('=', 1)[0].trim();
      if (name) jar[name] = raw;
    });
  }
  ingest(existing);
  ingest(incoming);
  return Object.keys(jar).map(function (k) { return jar[k]; });
}

function createRequest(flow, type, url) {
  // SECURITY: Lazy supertest agent binding. `app` (above) is the unresolved Hapi
  // SECURITY: server Promise exported by app.js (Hapi 17+ async init); `app.listener`
  // SECURITY: is therefore `undefined` until the root `before` hook in test/setup.js
  // SECURITY: awaits the promise and stores the resolved server in `appInstance`.
  // SECURITY: We construct the supertest agent on the first request — by which time
  // SECURITY: all root `before` hooks have completed — instead of in the constructor,
  // SECURITY: where it would resolve to `server(undefined)` and crash the request with
  // SECURITY: `TypeError: Cannot read properties of undefined (reading 'address')`.
  // SECURITY: Cached on the flow instance so subsequent requests reuse the same agent.
  // SECURITY: Closes QA Issue #3 (test/security/* suite cannot execute) per AAP §0.5.2
  // SECURITY: Strategy I / R9 mapping.
  if (!flow.agent) {
    flow.agent = server(appInstance.getListener());
  }
  var request = flow.agent[type](url);
  if (flow.activeUser && flow.cookies[flow.activeUser]) {
    request.set('cookie', flow.cookies[flow.activeUser]);
  }
  request.set('referer', config.url);
  return request;
}

function Flow() {
  // SECURITY: Agent is constructed lazily on the first request (see createRequest)
  // SECURITY: rather than eagerly here, because `app` is an unresolved Promise at
  // SECURITY: this point. See QA Issue #3 / AAP §0.5.2 Strategy I.
  this.agent      = null;
  this.activeUser = 'user';
  this.cookies    = {};

  // bind all of the methods for ease of use in before/after
  // blocks in the test...
  // e.g. before(flow.login)
  _.bindAll.apply(_, [this].concat(Object.keys(methods)));
}

_.extend(Flow.prototype, methods);

// internal methods
_.extend(Flow.prototype, {
  get : function(url) {
    return createRequest(this, 'get', url);
  },

  post : function(url) {
    return createRequest(this, 'post', url);
  },

  put : function(url) {
    return createRequest(this, 'put', url);
  },

  del : function(url) {
    return createRequest(this, 'del', url);
  }
});

module.exports = new Flow();
