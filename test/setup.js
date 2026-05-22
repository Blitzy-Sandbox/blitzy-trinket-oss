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

// SECURITY: superagent@0.16.0 (transitive via supertest@~0.8.3, the version
// pinned in devDependencies and held on the residual-risk register R-04 per
// AAP §0.10.5) emits an RFC-7578-noncompliant Content-Disposition for file
// attachments — `attachment; name="..."; filename="..."` — but @hapi/content
// (which powers @hapi/pez's multipart parser inside @hapi/subtext) only
// accepts the canonical `form-data` disposition required by RFC 7578.
//
// Patching the legacy superagent Part class here (before any test loads
// supertest) lets file-upload integration tests exercise POST /file and
// POST /file/avatar with multipart payloads that Hapi 20+ accepts. The
// patch is confined to the test process — the production server never
// loads superagent — and is the minimum-impact fix per the AAP §0.10.4
// minimal-change clause (the alternative would be a devDependency upgrade
// of supertest, which the AAP residual-risk register defers).
var superagentPart = require('superagent/lib/node/part');
superagentPart.prototype.attachment = function(name, filename) {
  this.type(filename);
  // Strip path, retain just basename
  var basename = filename;
  var slashIdx = filename.lastIndexOf('/');
  if (slashIdx !== -1) {
    basename = filename.substring(slashIdx + 1);
  }
  this.set('Content-Disposition', 'form-data; name="' + name + '"; filename="' + basename + '"');
  return this;
};

// SECURITY: Stub the AWS SDK S3 constructor so test runs don't issue real
// network requests to S3 (the example-bucket coordinates in the default
// config have no credentials and would hang/timeout the file-upload and
// file-download integration tests). We provide an in-memory fake that
// records putObject calls and replays the data on getObject — enough to
// exercise the FileUtil contract without leaving the test process. The
// patch is confined to the test process; the production server is never
// affected.
var aws = require('aws-sdk');
var stream = require('stream');
var __testS3Storage = Object.create(null);
function FakeS3() {}
FakeS3.prototype.putObject = function(params, cb) {
  __testS3Storage[params.Bucket + '/' + params.Key] = {
    body: params.Body,
    contentType: params.ContentType
  };
  // For streams, drain to record the bytes (some tests pipe a fs.ReadStream)
  if (params.Body && typeof params.Body.pipe === 'function') {
    var chunks = [];
    params.Body.on('data', function(c) { chunks.push(c); });
    params.Body.on('end', function() {
      __testS3Storage[params.Bucket + '/' + params.Key].body = Buffer.concat(chunks);
      cb && cb(null, { ETag: '"test-etag"' });
    });
    params.Body.on('error', function(e) { cb && cb(e); });
    return;
  }
  setImmediate(function() { cb && cb(null, { ETag: '"test-etag"' }); });
};
FakeS3.prototype.getObject = function(params, cb) {
  var entry = __testS3Storage[params.Bucket + '/' + params.Key];
  if (cb) {
    if (!entry) return setImmediate(function() { cb(new Error('NoSuchKey')); });
    return setImmediate(function() { cb(null, { Body: entry.body }); });
  }
  // Streaming variant used by FileUtil.downloadMaterialFile
  return {
    createReadStream: function() {
      var pass = new stream.PassThrough();
      setImmediate(function() {
        if (entry) {
          pass.end(entry.body);
        } else {
          pass.emit('error', new Error('NoSuchKey'));
        }
      });
      return pass;
    }
  };
};
aws.S3 = FakeS3;

// SECURITY: load app.js synchronously here (before mocha walks
// test/helpers/db.js — which transitively loads mongoose-schema-extend ->
// harmony-reflect and rebinds Object.getPrototypeOf et al.). Loading app.js
// first guarantees @hapi/inert finishes its sync Joi schema compilation
// before any harmony-reflect rebinding (QA-FINAL-2 Issue #6).
//
// app.js exports `serverPromise` (post-AAP §0.5.1 async-init refactor); the
// promise is awaited by the root `before` hook in test/_root_hooks.js,
// which is required separately because Mocha's `--require ./test/setup`
// runs this file BEFORE mocha.ui() initialises the BDD globals
// (`before` / `describe` / `it`). Calling `before(...)` from this file
// therefore throws ReferenceError; the hook lives in a file mocha walks
// via --recursive (after mocha.ui() runs) instead.
var app = require('../app.js'),
    db  = require('./helpers/db');

// Expose the appPromise so test files (and the root-hooks file) can await
// it without re-requiring app.js. Re-requiring is harmless (Node's module
// cache returns the same Promise), but exporting here makes the contract
// explicit.
module.exports = {
  app: app,
  db:  db
};
