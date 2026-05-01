// SECURITY: catbox-redis test stub updated from the deprecated unscoped 'catbox-redis'
// SECURITY: package (no longer installed) to the maintained '@hapi/catbox-redis' scoped
// SECURITY: package per AAP §0.5.2 Strategy I / R9 audit findings. Closes QA Issue #3
// SECURITY: (test/security/* suite cannot execute — Cannot find module 'catbox-redis').
// SECURITY:
// SECURITY: Runtime context: this stub is loaded by test/setup.js for the legacy api
// SECURITY: integration suite. The project's runtime session cache uses CatboxMongoose
// SECURITY: (lib/util/catbox-mongoose.js), NOT @hapi/catbox-redis — see app.js cache
// SECURITY: provider config — so this stub is defense-in-depth-only against any future
// SECURITY: test path that wires Redis-backed catbox. The stub installs a fake `client`
// SECURITY: with in-memory get/set/del/expire so tests never reach a real Redis instance.
// SECURITY:
// SECURITY: API change: the legacy 'catbox-redis' module exported a constructor function
// SECURITY: with a `.prototype.isReady` method. The maintained '@hapi/catbox-redis'
// SECURITY: exports an `Engine` class (verified: node_modules/@hapi/catbox-redis/lib/
// SECURITY: index.js line 1 `exports.Engine = class CatboxRedis { ... }`). The stub
// SECURITY: target is therefore `catbox.Engine.prototype.isReady`. The existing 3-arg
// SECURITY: sinon.stub(obj, method, fn) form is preserved per Sinon 1.7.x compatibility
// SECURITY: (verified via runtime smoke test); per AAP "Mocha 3 → modern Mocha upgrade"
// SECURITY: out-of-scope, the legacy testing toolchain (sinon ~1.7.3, mocha ^3.4.1, chai
// SECURITY: ^3.5.0) is preserved per AAP §0.7.2 / §0.9.2 Out of Scope.
var catbox = require('@hapi/catbox-redis'),
    sinon  = require('sinon'),
    cache  = {},
    expires = {};

sinon.stub(catbox.Engine.prototype, 'isReady', function() {
  var self = this;
  // SECURITY: In-memory mock replaces a real Redis client so tests run without an
  // SECURITY: external Redis dependency. No user input flows here — all keys/values
  // SECURITY: are test-controlled. expire() uses setTimeout to model Redis TTL
  // SECURITY: semantics; clearTimeout on re-set prevents leaked timers (CWE-401).
  self.client = {
    get : function(key, cb) {
      process.nextTick(function() {
        cb(null, cache[key]);
      });
    },
    set : function(key, value, cb) {
      cache[key] = value;
      process.nextTick(cb);
    },
    del : function(key, cb) {
      delete cache[key];
      process.nextTick(cb);
    },
    expire : function(key, time, cb) {
      if (expires[key]) {
        clearTimeout(expires[key]);
      }

      expires[key] = setTimeout(function() {
        delete cache[key];
        delete expires[key];
      }, time*1000);

      process.nextTick(cb);
    }
  }
  return true;
});
