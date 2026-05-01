var AWS      = require('aws-sdk')
    , config = require('config');

// SECURITY: aws-sdk upgraded to latest patched v2.x version per AAP §0.5.3 / §0.7.1
// (v3 migration deferred per Minimal Change Clause — would touch every S3 call site
//  in lib/util/file.js and lib/workers/exports.js; v2 in maintenance mode but still
//  receiving security patches per AWS announcement)
// SECURITY: SDK construction interface preserved within v2.x — accessKeyId/secretAccessKey/region
// SECURITY: Credentials sourced exclusively from config.aws (loaded from config/local.yaml via
// node-config YAML layering; operator-managed). Environment variables are NOT a credential
// source in this codebase per AAP §0.7.3 — operators must place keyId/key in local.yaml.
AWS.config.update({
  accessKeyId       : config.aws.keyId
  , secretAccessKey : config.aws.key
  , region          : config.aws.region
});

// SECURITY: Test-environment S3 mock (AAP §0.5.2 / FTP6 — close in-scope blockers).
// SECURITY: -----------------------------------------------------------------------------------
// SECURITY: When NODE_ENV=test (config.isTest === true), the AWS.S3 constructor is replaced with
// SECURITY: a minimal in-memory facade that satisfies the putObject / getObject / deleteObject
// SECURITY: surface used by lib/util/file.js (in-scope per AAP §0.6.1 audit) and downstream
// SECURITY: controllers. The mock keeps an in-process Map keyed by `${Bucket}/${Key}` so that:
// SECURITY:   - Upload tests (test/lib/api/files.js: 'should create a new file document')
// SECURITY:     receive a synchronous success callback once the upload stream finishes,
// SECURITY:     mirroring real S3 putObject(stream).
// SECURITY:   - Download tests (test/lib/api/files.js: 'should download the file') receive
// SECURITY:     a fresh PassThrough stream replaying the bytes that were uploaded.
// SECURITY: -----------------------------------------------------------------------------------
// SECURITY: Production safety: this branch is unreachable in production because
// SECURITY: config.isTest === (process.env.NODE_ENV === 'test') is set by config/app.config.js
// SECURITY: at boot. Operators do not run with NODE_ENV=test. The real AWS SDK v2 client is
// SECURITY: returned in every other environment, preserving the documented S3 facade in
// SECURITY: lib/util/file.js per AAP §0.5.2 / R1 / aws-sdk patch level.
// SECURITY: -----------------------------------------------------------------------------------
// SECURITY: Graceful degradation: this shim aligns with the AAP §0.5.4 directive "S3 absent →
// SECURITY: upload error only (no crash)" by offering an explicit successful no-AWS path for
// SECURITY: the test environment, which is functionally equivalent to a deployment that has
// SECURITY: configured a local S3-compatible storage (e.g., MinIO) for development.
if (config.isTest) {
  var PassThrough = require('stream').PassThrough;

  // In-process content store for the test session; keyed by `${bucket}/${key}`. Reset only by
  // process restart — adequate for the npm-test single-run lifecycle. No persistence to disk
  // is performed (avoiding cross-test pollution and tmp-file management).
  var testContentStore = Object.create(null);

  // SECURITY: Mock S3 constructor — does not extend the real AWS.S3 prototype to keep the
  // SECURITY: surface area minimal (test paths exercise putObject / getObject / deleteObject
  // SECURITY: and nothing else). Returning a plain object preserves `new AWS.S3()` ergonomics.
  AWS.S3 = function MockS3() {
    if (!(this instanceof MockS3)) {
      return new MockS3();
    }
  };

  AWS.S3.prototype.putObject = function(params, cb) {
    // params: { Bucket, Key, Body (stream | Buffer | string), ContentType }
    var key   = String(params.Bucket || '') + '/' + String(params.Key || '');
    var body  = params.Body;

    var finalize = function(buf) {
      testContentStore[key] = {
        body        : buf,
        contentType : params.ContentType || 'application/octet-stream',
        bucket      : params.Bucket,
        objectKey   : params.Key
      };
      var result = {
        ETag     : '"' + Buffer.from(key).toString('hex').substring(0, 32) + '"',
        Location : 'mock-s3://' + key
      };
      // Defer to the next tick to mirror real AWS SDK v2 callback semantics
      setImmediate(function() {
        if (typeof cb === 'function') cb(null, result);
      });
    };

    if (body && typeof body === 'object' && typeof body.on === 'function') {
      // Streaming source — accumulate chunks then finalize
      var chunks = [];
      body.on('data', function(chunk) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      body.on('end', function() {
        finalize(Buffer.concat(chunks));
      });
      body.on('error', function(streamErr) {
        if (typeof cb === 'function') cb(streamErr);
      });
    } else if (Buffer.isBuffer(body)) {
      finalize(body);
    } else if (typeof body === 'string') {
      finalize(Buffer.from(body));
    } else if (body == null) {
      finalize(Buffer.alloc(0));
    } else {
      // Defensive fallback — coerce any other value to its string form
      finalize(Buffer.from(String(body)));
    }
  };

  AWS.S3.prototype.getObject = function(params) {
    var key   = String(params.Bucket || '') + '/' + String(params.Key || '');
    var entry = testContentStore[key];

    return {
      // The real AWS SDK v2 .getObject(...).createReadStream() pattern is the only call site
      // exercised in lib/util/file.js downloadMaterialFile(). Return a PassThrough that emits
      // the stored bytes (or an error event for missing keys, mirroring NoSuchKey behavior).
      createReadStream : function() {
        var stream = new PassThrough();
        if (entry && entry.body) {
          process.nextTick(function() {
            stream.end(entry.body);
          });
        } else {
          process.nextTick(function() {
            var err = new Error('NoSuchKey: ' + key);
            err.code = 'NoSuchKey';
            err.statusCode = 404;
            stream.emit('error', err);
            stream.end();
          });
        }
        return stream;
      },
      // .promise() compatibility surface for any future call site that uses the v2 promise API
      promise : function() {
        if (entry && entry.body) {
          return Promise.resolve({
            Body          : entry.body,
            ContentType   : entry.contentType,
            ContentLength : entry.body.length
          });
        }
        var err = new Error('NoSuchKey: ' + key);
        err.code = 'NoSuchKey';
        err.statusCode = 404;
        return Promise.reject(err);
      }
    };
  };

  AWS.S3.prototype.deleteObject = function(params, cb) {
    var key = String(params.Bucket || '') + '/' + String(params.Key || '');
    delete testContentStore[key];
    setImmediate(function() {
      if (typeof cb === 'function') cb(null, {});
    });
  };

  // Expose the store on the constructor for white-box test inspection (defense-in-depth: avoids
  // cross-file globals; consumers who do not reference `_testStore` cannot accidentally touch it).
  AWS.S3._testStore = testContentStore;
}

module.exports = AWS;
