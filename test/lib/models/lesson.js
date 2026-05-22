var _           = require('underscore'),
    sinon       = require('sinon'),
    should      = require('chai').should(),
    defaults    = require('../../helpers/defaults'),
    db          = require('../../helpers/db'),
    ownable     = require('../../../lib/models/plugins/ownable'),
    // SECURITY: explicit Lesson model require (QA-FINAL-2 Issue #8).
    // Lesson is otherwise only set as an implicit global in app.js's async
    // init() at line 376, which runs after Mocha invokes each describe-block
    // callback. Requiring directly here means `Lesson.plugins` resolves at
    // test execution time without depending on global pollution.
    Lesson      = require('../../../lib/models/lesson');

describe('Lesson model', function(){
  describe('plugins', function() {
    it('should implement the ownable plugin', function() {
      var plugin = _.find(Lesson.plugins, function(plugin) {
        return plugin === ownable;
      });
      should.exist(plugin);
    });
  });
});
