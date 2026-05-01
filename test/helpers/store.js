// SECURITY: Test-only stub for lib/util/store (Redis backed). Stubs `get`/`set`/`del`/
// SECURITY: `expire` with in-memory implementations so tests can run without a live Redis
// SECURITY: instance. The repository pins sinon @ ~1.7.3 (per package.json
// SECURITY: devDependencies and AAP §0.6.1 frozen testing toolchain — see §6.6.12.3
// SECURITY: deferred modernization), which predates the `.callsFake()` accessor (added
// SECURITY: in sinon 2.x). The compatible 3-argument `sinon.stub(obj, method, fn)` form
// SECURITY: still works in 1.7.3 and is documented in the same Sinon migration notes.
// SECURITY: This is the same legacy-API pattern used in test/helpers/catbox-redis.js
// SECURITY: per the @hapi/catbox-redis fix; both helpers must match the frozen sinon
// SECURITY: API contract. Closes QA Issue #3 (test/security/* suite cannot execute) per
// SECURITY: FINAL SECURITY checkpoint findings; AAP §0.5.2 Strategy I / R9 mapping.
var sinon = require('sinon'),
    Store = require('../../lib/util/store');

module.exports = {
  Store : Store,
  stub  : function() {
    before(function() {
      Store.internals = {};
      sinon.stub(Store, 'get', async function(key) {
        return Store.internals[key];
      });
      sinon.stub(Store, 'set', async function(key, val) {
        Store.internals[key] = val;
        return 'OK';
      });
      sinon.stub(Store, 'del', async function(key) {
        delete Store.internals[key];
        return 1;
      });
      sinon.stub(Store, 'expire', async function(key, s) {
        return 1;
      });
    });

    after(function() {
      Store.internals = {};

      Store.get.restore();
      Store.set.restore();
      Store.del.restore();
      Store.expire.restore();
    });
  }
};
