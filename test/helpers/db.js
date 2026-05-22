var _            = require('underscore'),
    db           = require('../../config/db'),
    mongoose     = require('mongoose'),
    initializing = true,
    instance;

function DB() {
  this._isConnected = false;
  // SECURITY: use native Function.prototype.bind instead of _.bindAll
  // (QA-FINAL-2 Issue #6 / Issue #1 cascade). underscore@1.13.x's
  // bindAll wraps the bound function in an arrow function whose
  // `.length` is always 0, which causes Mocha 3.x to treat the
  // bound function as synchronous (no `done` argument is passed).
  // Native bind preserves the source function's `.length`, so Mocha
  // correctly recognises `before(db.reset)` and `beforeEach(db.ensureConnection)`
  // as async hooks that take a `done` callback.
  this.ensureConnection = this.ensureConnection.bind(this);
  this.reset            = this.reset.bind(this);
}

_.extend(DB.prototype, {
  ensureConnection : function(done) {
    var self = this;

    if (self.isConnected()) return done();

    (function wait() {
      if (self.isConnected()) {
        return done();
      }
      setTimeout(wait, 0);
    })();
  },

  reset : function(done) {
    if (!this.isConnected()) return done();

    mongoose.connection.db.dropDatabase(function() {
      done();
    });
  },

  isConnected : function() {
    return this._isConnected;
  }
});

instance = new DB();

function checkState() {
  switch(mongoose.connection.readyState) {
    case 0:
      console.log('mongoose connection died, reconnecting...');
      db.connect();
    case 1:
      // if initializing, clear the db
      if (initializing) {
        initializing = false;
        mongoose.connection.db.dropDatabase(function() {
          instance._isConnected = true;
        });
      }
      else {
        instance._isConnected = true;
      }
      
      break;
    default:
      setTimeout(checkState, 0);
  }
}

checkState();

module.exports = instance;
