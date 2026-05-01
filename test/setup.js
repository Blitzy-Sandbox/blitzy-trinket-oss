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

sinon.stub(redis, 'createClient', redismock.createClient);

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
