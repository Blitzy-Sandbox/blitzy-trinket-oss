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
var app         = require('../app.js'),
    db          = require('./helpers/db'),
    appInstance = require('./helpers/app-instance');

// Register the unresolved Promise so per-suite hooks can `await` the same instance.
appInstance.promise = app;

module.exports = {};
