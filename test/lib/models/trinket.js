var _        = require('underscore'),
    sinon    = require('sinon'),
    should   = require('chai').should(),
    crypto   = require('crypto'),
    Interaction = require('../../../lib/models/interaction');

describe('Trinket model', function(){
  describe('pre save hooks', function() {
    describe('createHash', function() {
      it('should not generate a hash if one is already set', function(done) {
        var trinket = {
          hash            : 'abc123',
          hashify         : sinon.spy(function() {}),
          findModulesUsed : function() {},
          isModified      : function() {}
        }
        Trinket.hooks.pre.save.createHash.call(trinket, function() {
          trinket.hash.should.eql('abc123');
          trinket.hashify.calledOnce.should.be.false;
          done();
        })
      });

      it('should generate a hash and shortcode based on code, lang, owner and parent', function(done) {
        var hash   = 'abcdefghijklmnopqrstuvwxyz';
        var now    = '123456789';
        var update = sinon.spy(function() {
          return {
            digest : function() {
              return hash;
            }
          }
        });
        var cryptoStub = sinon.stub(crypto, 'createHash', function(){
          return {
            update : update
          }
        });
        var dateStub = sinon.stub(Date, 'now', function() {
          return now;
        });
        var trinket = {
          code            : 'abc123',
          lang            : 'python',
          _owner          : 'owner',
          _parent         : 'parent',
          hashify         : Trinket.objectMethods.hashify,
          generateSeed    : Trinket.objectMethods.generateSeed,
          findModulesUsed : Trinket.objectMethods.findModulesUsed,
          isModified      : function() {}
        };

        Trinket.hooks.pre.save.createHash.call(trinket, function() {
          trinket.hash.should.eql(hash);
          // SECURITY: lib/models/trinket.js line 130 hashify() truncates the
          // SECURITY: SHA-1 digest to 12 hex characters for the URL-facing
          // SECURITY: shortCode identifier (`.substring(0, 12)`). Per AAP §0.5.2
          // SECURITY: Strategy B / R2, this 12-char surface is preserved as part
          // SECURITY: of the URL backward-compatibility contract — the shortCode
          // SECURITY: is part of the public trinket URL surface and changing
          // SECURITY: its length would invalidate every existing trinket link.
          // SECURITY: Closes QA FINAL Issue #7 per AAP §0.5.2 Strategy I / R9.
          trinket.shortCode.should.eql(hash.substring(0, 12));
          update.calledWith(trinket.code + trinket.lang + trinket._owner + trinket._parent).should.be.true;
          update.calledWith(trinket.code + trinket.lang + trinket._owner + trinket._parent + now).should.be.true;
          cryptoStub.restore();
          dateStub.restore();
          done();
        });
      });
    });

    describe('findModulesUsed', function() {
      it('should be set modules array', function(done) {
        var trinket = {
          code            : 'import turtle',
          lang            : 'python',
          hashify         : function() {},
          findModulesUsed : sinon.spy(Trinket.objectMethods.findModulesUsed),
          isModified      : function() {}
        }
        Trinket.hooks.pre.save.createHash.call(trinket, function() {
          trinket.findModulesUsed.calledOnce.should.be.true;
          trinket.modules.should.include('turtle');
          done();
        });
      });
    });
  });

  describe('class methods', function() {
    describe('findByHash', function() {
      it('should use the hash as the search criteria', function(done) {
        var doc     = 'foo';
        var findOne = sinon.spy(function(criteria, cb){ cb(null, doc) });
        var scope   = { model : { findOne : findOne } };
        var query   = { hash : 'abc123' };
        var cb      = function(err, result) {
          findOne.calledWithExactly(query, cb).should.be.true;
          done();
        };
        
        Trinket.classMethods.findByHash.call(scope, 'abc123', cb);
      });

      it('should return the results of the findOne call', function(done) {
        var doc     = 'foo';
        var findOne = sinon.spy(function(criteria, cb){ cb(null, doc) });
        var scope   = { model : { findOne : findOne } };
        var query   = { hash : 'abc123' };
        var cb      = function(err, result) {
          result.should.eql('foo');
          done();
        };
        
        Trinket.classMethods.findByHash.call(scope, 'abc123', cb);
      });
    });

    describe('findById', function() {
      it('should include the shortCode as a search criteria', function(done) {
        var doc     = 'foo';
        // SECURITY: Mongoose 6 model.findOne(query) returns a thenable Query;
        // SECURITY: there is no callback parameter. lib/models/model.js
        // SECURITY: classMethods.findById (auto-injected when the host model
        // SECURITY: does not define its own findById) calls findOne with a
        // SECURITY: single argument in the `alternateIds` branch (Trinket has
        // SECURITY: alternateIds: ['shortCode'] per lib/models/trinket.js:601)
        // SECURITY: and chains .then(doc => cb(null, doc)) to invoke the
        // SECURITY: caller-supplied cb. The spy must therefore return a
        // SECURITY: thenable Promise so the internal .then() resolves.
        // SECURITY: Closes QA FINAL Issue #7 per AAP §0.5.2 Strategy I / R9.
        var findOne = sinon.spy(function(criteria) { return Promise.resolve(doc); });
        var scope   = { model : { findOne : findOne } };
        var query   = { shortCode : 'abc123' };
        var cb      = function(err, result) {
          // SECURITY: When alternateIds.length === 1 and the input id does not
          // SECURITY: match ID_REGEXP, lib/models/model.js:132-133 collapses
          // SECURITY: query.$or to its sole condition: {shortCode: 'abc123'}.
          // SECURITY: findOne therefore receives exactly one argument — the
          // SECURITY: literal {shortCode:'abc123'} query — not a (query, cb)
          // SECURITY: pair. Use calledWith(query) to assert just the first arg
          // SECURITY: was the expected query (any/no additional args allowed).
          findOne.calledWith(query).should.be.true;
          done();
        };

        Trinket.classMethods.findById.call(scope, 'abc123', cb);
      });

      it('should return the results of the findOne call', function(done) {
        var doc     = 'foo';
        // SECURITY: Same Mongoose 6 thenable contract — spy returns a resolved
        // SECURITY: Promise so model.js's `promise.then(function(doc) {
        // SECURITY: cb(null, doc); })` callback fires with `doc` and the test
        // SECURITY: receives it via the shared cb closure below.
        var findOne = sinon.spy(function(criteria) { return Promise.resolve(doc); });
        var scope   = { model : { findOne : findOne } };
        var cb      = function(err, result) {
          result.should.eql('foo');
          done();
        };

        Trinket.classMethods.findById.call(scope, 'abc123', cb);
      });
    });

    describe('findByIdAndUpdateMetrics', function() {
      var interactionStub;
      var callScope;

      before(function(done) {
        // SECURITY: lib/models/trinket.js findAndUpdateMetrics (line 219)
        // SECURITY: invokes this.model.findByIdAndUpdate(id, update, options)
        // SECURITY: with three positional arguments and chains .then() on the
        // SECURITY: returned thenable Mongoose 6 Query — there is no callback
        // SECURITY: parameter. The spy must therefore return a resolved Promise
        // SECURITY: that yields the synthetic trinket document, so the internal
        // SECURITY: .then(function(trinket) {...}) handler fires correctly.
        // SECURITY: Closes QA FINAL Issue #7 per AAP §0.5.2 Strategy I / R9.
        var findByIdAndUpdate = sinon.spy(function(id, update, options) {
          return Promise.resolve({
            _id : 'id',
            _owner : 'owner',
            lang : 'lang'
          });
        });

        callScope = { model : { findByIdAndUpdate : findByIdAndUpdate } };

        interactionStub = sinon.stub(global, 'Interaction', function(data) {
          return _.extend({
            // SECURITY: lib/models/trinket.js line 228 invokes
            // SECURITY: `interaction.save();` with no callback (Mongoose 6
            // SECURITY: returns a Promise). Make the save spy tolerant of both
            // SECURITY: the no-arg invocation (returns Promise.resolve(this))
            // SECURITY: and the legacy callback form (cb(this) when cb is a
            // SECURITY: function), so the assertion calledOnce remains
            // SECURITY: meaningful regardless of which contract Mongoose uses.
            save : sinon.spy(function(cb) {
              if (typeof cb === 'function') {
                return cb(this);
              }
              return Promise.resolve(this);
            })
          }, data);
        });

        done();
      });

      beforeEach(function(done) {
        callScope.model.findByIdAndUpdate.reset();
        interactionStub.reset();
        done();
      });

      after(function(done) {
        interactionStub.restore();
        done();
      });

      it('should construct a $inc entry for the metric to be updated', function(done) {
        Trinket.classMethods.findByIdAndUpdateMetrics
          .call(callScope, 'abc123', 'runs')
          .then(function() {
            callScope.model.findByIdAndUpdate.calledWithMatch('abc123', {
              $inc : {
                'metrics.runs'       : 1
              }
            }).should.be.true;
          })
          // SECURITY: Native Promise has no .done() method — that is a Q-library
          // SECURITY: idiom. app.js polyfills .spread and .fail (lines 4-16) but
          // SECURITY: deliberately does NOT polyfill .done because Mongoose 6 +
          // SECURITY: native Promises already throw unhandled rejections to the
          // SECURITY: top level. The native equivalent of `.done(cb)` is
          // SECURITY: `.then(cb, cb)` — invokes cb with no args on success and
          // SECURITY: with the err on failure, exactly matching Mocha's done()
          // SECURITY: contract. Closes QA FINAL Issue #7 per AAP §0.5.2 R9.
          .then(done, done);
      });

      it('should construct an interaction for the metric to be updated', function(done) {
        Trinket.classMethods.findByIdAndUpdateMetrics
          .call(callScope, 'abc123', 'runs')
          .then(function() {
            interactionStub.calledWithMatch({
              action : 'runs',
              _trinket : 'id',
              _owner : 'owner',
              lang : 'lang'
            }).should.be.true;
            interactionStub.returnValues[0].save.calledOnce.should.be.true;
          })
          // SECURITY: Same .done() → .then(done, done) translation as above.
          .then(done, done);
      });
    });
  });
});
