var sinon    = require('sinon'),
    should   = require('chai').should(),
    defaults = require('../../helpers/defaults'),
    db       = require('../../helpers/db'),
    // SECURITY: explicit User model require (QA-FINAL-2 Issue #7).
    // The User binding is otherwise only set as an implicit global in
    // app.js's async init() at line 374, which runs after Mocha invokes
    // each describe-block callback. Requiring directly here means
    // `User.hooks`, `User.objectMethods`, `User.findByLogin`, and the
    // `new User(...)` constructor all resolve at file-load time without
    // depending on global pollution.
    User     = require('../../../lib/models/user');

describe('User model', function(){
  before(db.reset);

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
