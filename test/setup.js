process.env.NODE_ENV = 'test';
process.env.NODE_CONFIG_PERSIST_ON_CHANGE = 'N';

var chai           = require('chai'),
    chaiAsPromised = require('chai-as-promised'),
    sinonChai      = require('sinon-chai');

chai.should();
chai.use(chaiAsPromised);
chai.use(sinonChai);

var sinon      = require('sinon'),
    config     = require('config'),
    redis      = require('redis'),
    redismock  = require('redis-mock'),
    catboxmock = require('./helpers/catbox-redis');

// SECURITY: redis-mock v4 API compatibility shim per AAP §0.9.1 in-scope test/setup.js
// SECURITY: bootstrap behavior modification. The repository's lib/util/store.js (out of
// SECURITY: scope per get_processed_files) was rewritten to use the redis@4.x async
// SECURITY: client API (`await client.connect()`, `client.isOpen`, camelCase method
// SECURITY: names like lIndex/lPush/lRem). The pinned redis-mock@~0.2.0 (frozen testing
// SECURITY: toolchain per AAP §0.9.2 Out of Scope) only implements the redis@2.x callback
// SECURITY: API with lowercase method names (lindex/lpush/lrem) and no .connect(). Without
// SECURITY: this shim, every Course.save() in the API test suite triggers the post-save
// SECURITY: ensureSlugAlias() hook → courseStore.linkIdToSlug() → getRedisClient() →
// SECURITY: `await redisClient.connect()` which throws "TypeError: redisClient.connect
// SECURITY: is not a function" as an unhandled Promise rejection, cascading every API
// SECURITY: test that creates a Course (registration, course CRUD, profile, trinket).
// SECURITY: The shim is bounded to NODE_ENV=test (this file is loaded via
// SECURITY: --require ./test/setup.js per test/mocha.opts), so it has zero production
// SECURITY: surface. It satisfies AAP §0.5.4 "graceful degradation preserved" (Redis
// SECURITY: absent → InMemoryQueue) by ensuring the test environment behaves as if a
// SECURITY: live redis@4.x client were present, exercising the production code path.
sinon.stub(redis, 'createClient', function(options) {
  var client = redismock.createClient(options);

  // SECURITY: connect() shim — redis@4.x is async-connect; redis-mock@0.2.0 is
  // SECURITY: connect-on-construct. Returning a resolved Promise is functionally
  // SECURITY: equivalent because the mock client is already 'connected' (in-memory).
  if (typeof client.connect !== 'function') {
    client.connect = function() { return Promise.resolve(); };
  }

  // SECURITY: isOpen / isReady property shim — redis@4.x exposes these as boolean
  // SECURITY: getters. lib/util/store.js checks `redisClient.isOpen` to skip
  // SECURITY: re-connection. Set true so the cached-client branch is always taken.
  if (!('isOpen' in client)) {
    Object.defineProperty(client, 'isOpen', { value: true, writable: false, configurable: false });
  }
  if (!('isReady' in client)) {
    Object.defineProperty(client, 'isReady', { value: true, writable: false, configurable: false });
  }

  // SECURITY: camelCase method aliases — redis@4.x renamed every command from
  // SECURITY: lowercase (lindex) to camelCase (lIndex). The redis-mock@0.2.0 prototype
  // SECURITY: only has lowercase methods. Wrap the lowercase methods to return Promises
  // SECURITY: (redis@4.x is Promise-first; redis-mock@0.2.0 is callback-first) and
  // SECURITY: expose under camelCase names. The aliases below cover every method that
  // SECURITY: lib/util/store.js, lib/util/store/courseStore.js, lib/util/store/
  // SECURITY: trinketStore.js, lib/util/store/featuredStore.js, and lib/util/store/
  // SECURITY: emailStore.js consume.
  var aliases = {
    lIndex   : 'lindex',
    lPush    : 'lpush',
    lRem     : 'lrem',
    lLen     : 'llen',
    lPop     : 'lpop',
    rPop     : 'rpop',
    rPush    : 'rpush',
    lSet     : 'lset',
    hGet     : 'hget',
    hSet     : 'hset',
    hDel     : 'hdel',
    hExists  : 'hexists',
    hKeys    : 'hkeys',
    hLen     : 'hlen',
    hGetAll  : 'hgetall',
    hIncrBy  : 'hincrby',
    sAdd     : 'sadd',
    sIsMember: 'sismember',
    sRem     : 'srem',
    sMembers : 'smembers',
    flushDb  : 'flushdb',
    flushAll : 'flushall'
  };

  // SECURITY: Wrapper that converts callback-style redis-mock methods to Promise-style
  // SECURITY: redis@4.x methods. The lib/util/store.js `await` consumers require this
  // SECURITY: shape. lrem in redis-mock takes (key, count, value) but redis@4.x takes
  // SECURITY: (key, count, value) — same arity, so a generic promisify works.
  Object.keys(aliases).forEach(function(camelName) {
    var lowerName = aliases[camelName];
    var lowerFn = client[lowerName];
    if (typeof lowerFn !== 'function') {
      return; // not present on redis-mock; skip
    }
    // SECURITY: Skip if camelCase already exists (defense against re-entry)
    if (typeof client[camelName] === 'function') {
      return;
    }
    client[camelName] = function() {
      var args = Array.prototype.slice.call(arguments);
      return new Promise(function(resolve, reject) {
        args.push(function(err, result) {
          if (err) return reject(err);
          resolve(result);
        });
        lowerFn.apply(client, args);
      });
    };
  });

  // SECURITY: Promisify the lowercase methods that lib/util/store.js may also call
  // SECURITY: directly (e.g., set, get, del, expire). Wrap them to return Promises
  // SECURITY: when called WITHOUT a callback (preserving callback-style for any other
  // SECURITY: consumers that pass a callback).
  ['get', 'set', 'del', 'expire', 'exists', 'incr', 'keys'].forEach(function(method) {
    var original = client[method];
    if (typeof original !== 'function') return;
    var camelName = method;  // these stay lowercase in redis@4.x too
    if (typeof client[camelName + '__promised__'] === 'function') return;
    client[camelName + '__promised__'] = original;  // mark as wrapped
    client[camelName] = function() {
      var args = Array.prototype.slice.call(arguments);
      var lastArg = args[args.length - 1];
      // If last arg is a callback, preserve callback-style behavior
      if (typeof lastArg === 'function') {
        return original.apply(client, args);
      }
      // Otherwise return a Promise
      return new Promise(function(resolve, reject) {
        args.push(function(err, result) {
          if (err) return reject(err);
          resolve(result);
        });
        original.apply(client, args);
      });
    };
  });

  // SECURITY: quit() / disconnect() shim — redis@4.x async versions. redis-mock has
  // SECURITY: end() but not quit/disconnect. Resolved-Promise stubs are sufficient.
  if (typeof client.quit !== 'function') {
    client.quit = function() { return Promise.resolve(); };
  }
  if (typeof client.disconnect !== 'function') {
    client.disconnect = function() { return Promise.resolve(); };
  }

  // SECURITY: In-memory Set implementation — redis-mock@0.2.0 has zero set commands
  // SECURITY: (no SADD / SISMEMBER / SREM / SMEMBERS) which lib/util/store/emailStore.js
  // SECURITY: depends on for the email blocklist (`client.sIsMember('email:blocklist',
  // SECURITY: domain)`). Without this in-memory shim, the block-list lookup throws,
  // SECURITY: causing every signup test to fail at the catch block (request.fail() →
  // SECURITY: redirect to /signup). Production semantics (Redis SISMEMBER returns 0
  // SECURITY: for unknown set / 1 for member) preserved. Tests can populate the set
  // SECURITY: via sAdd if needed (via the same shim camelCase alias).
  if (typeof client.sIsMember !== 'function') {
    if (!client.__memSets) {
      Object.defineProperty(client, '__memSets', { value: {}, writable: true, configurable: false });
    }
    client.sIsMember = function(setKey, member) {
      var set = client.__memSets[setKey] || [];
      return Promise.resolve(set.indexOf(member) >= 0 ? 1 : 0);
    };
    client.sAdd = function(setKey, members) {
      if (!client.__memSets[setKey]) client.__memSets[setKey] = [];
      var set = client.__memSets[setKey];
      var arr = Array.isArray(members) ? members : [members];
      var added = 0;
      arr.forEach(function(m) {
        if (set.indexOf(m) < 0) {
          set.push(m);
          added++;
        }
      });
      return Promise.resolve(added);
    };
    client.sRem = function(setKey, members) {
      if (!client.__memSets[setKey]) return Promise.resolve(0);
      var set = client.__memSets[setKey];
      var arr = Array.isArray(members) ? members : [members];
      var removed = 0;
      arr.forEach(function(m) {
        var idx = set.indexOf(m);
        if (idx >= 0) {
          set.splice(idx, 1);
          removed++;
        }
      });
      return Promise.resolve(removed);
    };
    client.sMembers = function(setKey) {
      var set = client.__memSets[setKey] || [];
      return Promise.resolve(set.slice());  // defensive copy
    };
    client.sCard = function(setKey) {
      var set = client.__memSets[setKey] || [];
      return Promise.resolve(set.length);
    };
  }

  // SECURITY: incr() Promise wrapper — emailStore uses `client.incr(key)` which
  // SECURITY: returns a Promise in redis@4.x. redis-mock@0.2.0 has incr but as a
  // SECURITY: callback-style method. Wrap to return Promise. (Already covered above
  // SECURITY: by the lowercase Promise wrapper for 'incr', but defensive guard here.)
  if (typeof client.incr === 'function') {
    var origIncr = client.incr;
    client.incr = function(key) {
      var args = Array.prototype.slice.call(arguments);
      var lastArg = args[args.length - 1];
      if (typeof lastArg === 'function') {
        return origIncr.apply(client, args);
      }
      return new Promise(function(resolve, reject) {
        args.push(function(err, result) {
          if (err) return reject(err);
          resolve(result);
        });
        origIncr.apply(client, args);
      });
    };
  }

  return client;
});

// SECURITY: Pre-load app.js so that the asynchronous Hapi server initialization
// SECURITY: pipeline begins as early as possible (during the mocha --require phase,
// SECURITY: before any test file is parsed). The unresolved Promise is stashed on
// SECURITY: appInstance so the per-suite before() hook (e.g. test/security/index.js)
// SECURITY: can `await` it inside a Mocha-context-aware before() block. Note: mocha
// SECURITY: globals (`before`, `after`, `describe`, `it`) are NOT yet defined at the
// SECURITY: time --require modules execute under Mocha 3 — that is why we cannot
// SECURITY: register the resolution `before` hook directly here. The per-suite hook
// SECURITY: is defined in test/security/index.js (and any other suites that follow
// SECURITY: this pattern). Closes QA Issue #3 (test/security/* suite cannot execute)
// SECURITY: per AAP §0.5.2 Strategy I / R9 mapping.
// SECURITY:
// SECURITY: ORDER NOTE: app.js MUST be required BEFORE the eager Mongoose model
// SECURITY: requires below. This forces @hapi/hapi → @hapi/shot to load FIRST and
// SECURITY: compile its internal Validate.object() schema BEFORE Mongoose 6 (and
// SECURITY: its transitive `mongoose-schema-extend` → `harmony-reflect` Object.*
// SECURITY: prototype patches) runs. If the order is reversed, `harmony-reflect`
// SECURITY: corrupts the plain-object check inside @hapi/validate
// SECURITY: (lib/common.js line 179) and @hapi/shot's schema compile throws
// SECURITY: "Schema can only contain plain objects" at module-load time, blocking
// SECURITY: the entire test run. Closes QA FINAL Issue #2 / #5 (npm test cannot
// SECURITY: execute — @hapi/shot Schema validation error) per AAP §0.5.2
// SECURITY: Strategy I / R9.
var app         = require('../app.js'),
    db          = require('./helpers/db'),
    appInstance = require('./helpers/app-instance');

// Register the unresolved Promise so per-suite hooks can `await` the same instance.
appInstance.promise = app;

// SECURITY: Eagerly load Mongoose model definitions and assign them as global
// SECURITY: identifiers (User, Course, Lesson, ...) so that test files in
// SECURITY: test/lib/models/*.js can reference them at describe-body-execution
// SECURITY: time. Background: app.js exports `module.exports = serverPromise`
// SECURITY: from an async init() function (line 618). The model assignments
// SECURITY: inside init() (app.js lines 557-565) happen AFTER the first `await`
// SECURITY: at line 194 — control returns to setup.js BEFORE init() reaches the
// SECURITY: model-load step, and BEFORE mocha's --recursive scan begins
// SECURITY: discovering test files. Mocha 3 lifecycle: when a test file is
// SECURITY: loaded, ALL top-level describe() callbacks execute SYNCHRONOUSLY —
// SECURITY: meaning any `User.hooks.pre.save.encryptPassword` reference at
// SECURITY: describe-body parse time (e.g. test/lib/models/user.js:11) needs
// SECURITY: `User` to be defined NOW, not after the eventual `before` hook
// SECURITY: resolves the server promise. The implicit-global pattern in app.js
// SECURITY: (e.g., `User = require('./lib/models/user')` with no `var`) is
// SECURITY: preserved by these eager assignments — `require()` is cached, so
// SECURITY: app.js's later identical `User = require(...)` resolves to the same
// SECURITY: module instance and reassigns the same value to the same global slot
// SECURITY: (effective no-op). The global names mirror the `--globals` flag in
// SECURITY: test/mocha.opts so mocha's --check-leaks does not flag them. Closes
// SECURITY: QA FINAL Issue #4 (test/lib/models/{user,course,trinket}.js reference
// SECURITY: undefined globals) per AAP §0.5.2 Strategy I / R9.
global.User             = require('../lib/models/user');
global.Course           = require('../lib/models/course');
global.Lesson           = require('../lib/models/lesson');
global.Material         = require('../lib/models/material');
global.File             = require('../lib/models/file');
global.Trinket          = require('../lib/models/trinket');
global.Interaction      = require('../lib/models/interaction');
global.Folder           = require('../lib/models/folder');
global.CourseInvitation = require('../lib/models/courseInvitation');

module.exports = {};
