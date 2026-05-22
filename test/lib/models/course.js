var _        = require('underscore'),
    sinon    = require('sinon'),
    should   = require('chai').should(),
    defaults = require('../../helpers/defaults'),
    db       = require('../../helpers/db'),
    ownable     = require('../../../lib/models/plugins/ownable'),
    ObjectId    = require('mongoose').Types.ObjectId,
    // SECURITY: explicit model requires (QA-FINAL-2 Issue #8).
    // Course / Lesson / Material / User are otherwise only set as implicit
    // globals in app.js's async init() at lines 374-381, which runs after
    // Mocha invokes each describe-block callback. Requiring directly here
    // means `Course.plugins`, `new User(...)`, `new Material(...)`, and
    // `new Lesson(...)` all resolve without depending on global pollution.
    Course   = require('../../../lib/models/course'),
    Lesson   = require('../../../lib/models/lesson'),
    Material = require('../../../lib/models/material'),
    User     = require('../../../lib/models/user');

describe('Course model', function(){
  describe('plugins', function() {
    it('should implement the ownable plugin', function() {
      var plugin = _.find(Course.plugins, function(plugin) {
        return Array.isArray(plugin) && plugin[0] === ownable;
      });
      should.exist(plugin);
    });
  });

  describe('object methods', function() {
    describe('copy', function() {
      it('should copy all the things!', function(done) {
        var owner = new User({
          fullname: 'test course owner',
          username: 'testcourseowner',
          email:'testcourseowner@email.com',
          password:'password'
        });
        var user = new User({
          fullname: 'test user',
          username: 'testuser',
          email:'testuser@email.com',
          password:'password'
        });

        var material = new Material({
          name: 'material name',
          content: 'material content',
          _owner: owner
        });

        material.save(function(err) {
          var lesson = new Lesson({
            name: 'lesson name',
            _owner: owner,
            materials: [material.id]
          });

          lesson.save(function(err) {
            var course = new Course({
              name: 'course name',
              description: 'course description',
              _owner: owner,
              ownerSlug: owner.username,
              lessons: [lesson.id]
            });

            course.save(function(err) {
              course.copy(user, function(err, copy) {
                copy.should.have.property('name', course.name);
                copy.should.have.property('description', course.description);
                copy.should.have.property('lessons');


                // TODO: check lesson and material info

                done();
              });
            });
          });
        });
      });
    })
  });
});
