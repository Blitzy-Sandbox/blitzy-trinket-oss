// SECURITY: load `app.js` BEFORE `config/app.config` to ensure @hapi/inert
// is required before mongoose-schema-extend → harmony-reflect monkey-patches
// global Object.* methods (QA-FINAL-2 Issue #6).
//
// The harmony-reflect polyfill (a transitive dep of mongoose-schema-extend@0.2.2)
// rebinds Object.getPrototypeOf and friends; once installed it breaks
// @hapi/inert's Joi schema compilation in node_modules/@hapi/inert/lib/file.js:27,
// which is evaluated at the top of inert's module body. Loading app.js first
// guarantees inert finishes its sync init before any harmony-reflect rebinding.
var app      = require('../../app.js'),
    _        = require('underscore'),
    server   = require('supertest'),
    url      = require('url'),
    querystring = require('querystring'),
    defaults = require('./defaults'),
    config   = require('../../config/app.config');

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
    return this.get('/logout')
      .end(this.setLastResponse(cb));
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
    // SECURITY: Joi 17 (the version pinned per AAP §0.4) no longer auto-coerces
    // the legacy "yes"/"no" string variants accepted by older Joi versions.
    // The `outline` query parameter is validated as `Joi.boolean()` in
    // config/api_routes.js — under Joi 17 only the canonical
    // boolean strings ("true", "false") and 0/1 are accepted. Sending
    // "yes" produces `"outline" must be a boolean` and the controller
    // never sees the request, so getCourseWithOutline returns no `data`
    // and downstream test fixtures crash with `Cannot read properties of
    // undefined (reading 'id')`. Sending "true" preserves the original
    // intent (request the populated outline) while complying with Joi 17.
    return this.get('/api/courses/' + id + '?outline=true')
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
          if (err) {
            done(err);
          }
          if (res.statusCode != 302) {
            done(new Error('Failed to log in "' + user + '"'));
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
      if (!err && res.headers['set-cookie']) {
        self.cookies[self.activeUser] = res.headers['set-cookie'];
      }

      self.lastResponse = res;
      self.lastError    = err;
      self.wasOk        = err ? false : true;
      if (res && res.redirect) {
        self.lastRedirect = url.parse(res.headers.location)
      }

      self.lastContentType = res.headers['content-type'];

      cb(err, res);
    }
  }
}

function createRequest(flow, type, url) {
  var request = flow.agent[type](url);
  if (flow.activeUser && flow.cookies[flow.activeUser]) {
    request.set('cookie', flow.cookies[flow.activeUser]);
  }
  request.set('referer', config.url);
  return request;
}

function Flow() {
  // SECURITY: defer agent creation until the Hapi server promise resolves
  // (QA-FINAL-2 Issue #6). app.js (post-AAP §0.5.1 refactor) exports
  // `serverPromise` rather than the synchronous server, so `app.listener`
  // is undefined at module-load time. The `setServer` method below is
  // invoked from a root `before` hook in test/setup.js once the promise
  // resolves, populating `this.agent` before any test exercises an HTTP
  // route via supertest.
  this.agent      = null;
  this.activeUser = 'user';
  this.cookies    = {};

  // bind all of the methods for ease of use in before/after
  // blocks in the test...
  // e.g. before(flow.login)
  // Use a hand-rolled bind loop instead of underscore's _.bindAll because
  // _.bindAll @ underscore 1.13 wraps each function in a length-0 arrow
  // (so Mocha 3 cannot detect the `done` callback). Native Function.bind
  // preserves the source function's arity.
  Object.keys(methods).forEach(function(name) {
    this[name] = methods[name].bind(this);
  }, this);
}

// SECURITY: bind the resolved Hapi server to the supertest agent.
// Called from test/setup.js's root `before` hook once `app.js`'s
// `serverPromise` resolves. Idempotent — repeated calls overwrite the
// agent, which matters if the server is replaced (e.g., during a hot
// re-init). The supertest agent simply needs `server.listener` (the
// underlying Node http.Server), which is created synchronously inside
// Hapi.server() before init() awaits any plugin registration.
Flow.prototype.setServer = function(hapiServer) {
  this.agent = server(hapiServer.listener);
};

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
