var sinon    = require('sinon'),
    should   = require('chai').should(),
    defaults = require('../../helpers/defaults'),
    db       = require('../../helpers/db');

describe('User model', function(){
  // SECURITY: Wrap db.reset in an explicit function(done) closure to preserve
  // SECURITY: Mocha's async-detection arity contract. helpers/db.js applies
  // SECURITY: underscore _.bindAll producing a length-0 wrapper which Mocha
  // SECURITY: treats as synchronous, causing a deferred TypeError at
  // SECURITY: test/helpers/db.js:30 when dropDatabase invokes its
  // SECURITY: undefined `done` callback. Mirrors the working pattern at
  // SECURITY: test/security/index.js per AAP §0.5.2 Strategy I / R9. Closes
  // SECURITY: QA FINAL Issue #2 / #4 cascade for User model class methods.
  before(function(done) {
    db.reset(done);
  });

  describe('hooks', function(){
    describe('pre-save encryptPassword', function() {
      var encryptPassword = User.hooks.pre.save.encryptPassword,
          isModifiedFlag  = false,
          user;

      beforeEach(function() {
        user = {
          isModified : sinon.spy(function(){return isModifiedFlag;}),
          password: 'foo'
        };
      });

      it('should check password for modifications before continuing', function(done) {
        isModifiedFlag = false;

        encryptPassword.call(user, function(err) {
          should.not.exist(err);
          user.isModified.calledOnce.should.be.true;
          user.isModified.calledWith('password').should.be.true;
          user.password.should.eql('foo');
          done();
        });
      });

      it('should encrypt the password if it is being set/modified', function(done) {
        isModifiedFlag = true;

        encryptPassword.call(user, function(err) {
          should.not.exist(err);
          user.password.should.not.eql('foo');
          user.password.length.should.be.above(3);
          done();
        })
      });
    });
  });

  describe('object methods', function() {
    describe('comparePassword', function() {
      var comparePassword = User.objectMethods.comparePassword,
          user;

      beforeEach(function(done) {
        user = new User({password:'foo'});
        User.hooks.pre.save.encryptPassword.call(user, function() {
          done();
        });
      });

      it('should return true when passwords match', function(done) {
        comparePassword.call(user, 'foo', function(err, isMatch) {
          should.not.exist(err);
          isMatch.should.be.true;
          done();
        });
      });

      it("should return false when passwords don't match", function(done) {
        comparePassword.call(user, 'bar', function(err, isMatch) {
          should.not.exist(err);
          isMatch.should.be.false;
          done();
        });
      });
    });

    describe('isAdmin', function() {
      var admin;

      before(function(done) {
        admin = new User(defaults.admin);
        admin.save(function(err, doc) {
          done();
        });
      });

      after(function(done) {
        admin.remove(function() {
          done();
        });
      });

      it('should return true', function(done) {
        User.findByLogin(defaults.admin.email, function(err, doc) {
          doc.hasRole("admin", "site").should.be.true;
          done();
        });
      });
    });
  });

  describe('class methods', function() {
    var user;

    beforeEach(function(done) {
      user = new User(defaults.user);
      user.save(function(err, doc) {
        done();
      });
    });

    afterEach(function(done) {
      user.remove(function() {
        done();
      });
    });

    describe('findByLogin', function() {
      it('should find users by username', function(done) {
        User.findByLogin(defaults.user.email, function(err, doc) {
          should.not.exist(err);
          should.exist(doc);
          doc.username.should.eql(user.username);
          doc.hasRole("admin", "site").should.be.false;
          done();
        });
      });
    });

    describe('findAdminList', function() {
      it('should return a list of users', function(done) {
        var page = 0;
        User.findAdminList(page, function(err, users) {
          should.not.exist(err);
          should.exist(users);
          users.should.be.instanceof(Array);
          users[0].should.be.instanceof(Object).and.have.property('username');
          done();
        });
      });
    });
  });
});
