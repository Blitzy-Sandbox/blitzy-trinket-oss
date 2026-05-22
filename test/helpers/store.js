var sinon = require('sinon'),
    Store = require('../../lib/util/store');

// SECURITY: sinon@1.7.3 (the version pinned in package.json) does NOT expose the
// `.callsFake()` API that was added in sinon@2 — when test/helpers/store.js was
// last updated it used the modern fluent API and threw `TypeError:
// sinon.stub(...).callsFake is not a function` at every test that calls
// `store.stub()` (see QA-FINAL-2 Issue #6 cascade — Forgot Password before/after
// hooks). The 1.7.3-compatible form passes the fake function as the third
// argument to `sinon.stub(obj, method, fn)`. We use the legacy form here to
// remain within the AAP minimal-change clause (no devDependency upgrade).
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
