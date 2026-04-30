// SECURITY: Bulk export worker for the Trinket app per AAP §0.6.1 File Transformation Mapping
//           Processes 'bulk-export' queue jobs, generates ZIP archives, uploads to S3, sends notification emails
// SECURITY: bull v4.x consumer API per AAP §0.5.3 / R1 — process() returns Promise; event listeners preserved
//           InMemoryQueue and NoOpQueue fallback behavior FROZEN per user "Must Remain Unchanged"
//           Per AAP §0.8.3 graceful degradation directive: "Redis absent → InMemoryQueue"
// SECURITY: aws-sdk patched within v2.x per AAP §0.5.3 (v3 migration deferred per Minimal Change Clause)
//           S3 facade interface FROZEN per user; export archive S3 Key = exports/<userId>/<archiveName>
// SECURITY: Nunjucks email templates rendered with autoescape: true per AAP §0.5.2 Strategy H / R8 / OWASP A03 Injection
//           User-controlled fields (trinket name, user display name) auto-escaped to prevent XSS in HTML email
// SECURITY: Filesystem paths constructed from server-controlled IDs (userId, exportId, sanitized trinket name)
//           NOT raw user input per AAP §0.5.2 Strategy H / R8 / OWASP A03 (path traversal defense)
// SECURITY: 3-day TTL on bulk export S3 objects per §6.4.4.5.1 — frozen per AAP §0.6.1
var exportsQueue = require('../util/queues').exports()
  , db           = require('../../config/db')
  , config       = require('../../config/app.config')
  , nunjucks     = require('nunjucks')
  , moment       = require('moment')
  , Q            = require('q')
  , fs           = require('fs')
  , path         = require('path')
  , url          = require('url')
  , crypto       = require('crypto')
  , archiver     = require('archiver')
  , aws          = require('../../config/aws')
  , mailer       = require('../util/mailer')
  , FileUtil     = require('../util/file')
  , Export       = require('../models/export')
  , User         = require('../models/user')
  , Trinket      = require('../models/trinket')
  , mongoose     = require('mongoose')
  , env;

// SECURITY: 3-day TTL on bulk export S3 objects per §6.4.4.5.1
//           FROZEN per AAP §0.6.1 / user "Must Remain Unchanged" data retention policy
//           Limits S3 storage exposure window; aligns with privacy-conscious retention
var EXPORT_EXPIRY_DAYS = 3;

var langExtensions = {
  'python'     : '.py',
  'python3'    : '.py',
  'pygame'     : '.py',
  'html'       : '.html',
  'java'       : '.java',
  'R'          : '.R',
  'glowscript' : '.py',
  'blocks'     : '.xml',
  'console'    : '.py',
  'music'      : '.py',
  'skulpt'     : '.py'
};

// SECURITY: S3 GetObject via aws-sdk v2.x patched per AAP §0.5.3 (v3 migration deferred per Minimal Change Clause)
//           Asset fetched from config.aws.buckets.userassets bucket; filename extracted from URL path
//           SECURITY: path.basename strips any directory prefix from user-supplied URL (path traversal defense)
//                     per AAP §0.5.2 Strategy H / R8 / OWASP A03
// Download asset from S3
function downloadAsset(assetUrl) {
  var deferred = Q.defer();
  var parsed = url.parse(assetUrl);
  // SECURITY: path.basename ensures we extract ONLY the filename (path traversal defense)
  //           Original URL path component is server-stored; defense-in-depth normalization
  var filename = path.basename(parsed.pathname);

  var client = new aws.S3();
  client.getObject({
    Bucket: config.aws.buckets.userassets.name,
    Key: filename
  }, function(err, data) {
    if (err) return deferred.reject(err);
    deferred.resolve(data.Body);
  });

  return deferred.promise;
}

// SECURITY: Queue event listeners use bull v4.x event signatures: ('error', err), ('failed', job, err), ('completed', job, result)
//           per AAP §0.5.3 / R1 — preserved across bull v0.7→v4 upgrade (signatures unchanged)
//           InMemoryQueue.prototype.on(event, handler) provides no-op for compatibility per AAP §0.4.2 frozen contract
//           NoOpQueue.prototype.on returns this (chainable no-op) per frozen contract
exportsQueue.on('error', function(err) {
  console.log('exports queue error:', err);
});

exportsQueue.on('failed', function(job, err) {
  console.log('exports failed job:', job.jobId, job.data);
  console.log('exports failed err:', err);

  // SECURITY: Update Export record to 'failed' status; errorMessage is server-generated (not raw user input)
  //           per AAP §0.5.2 Strategy H / R8 — defensive against error message tampering
  if (job.data.exportId) {
    Export.findByIdAndUpdate(job.data.exportId, {
      status: 'failed',
      errorMessage: err.message || 'Unknown error'
    }, function() {});
  }
});

exportsQueue.on('completed', function(job, result) {
  // SECURITY: job.remove() preserves bull v4.x API for cleanup; InMemoryQueue/NoOpQueue handle gracefully
  job.remove();
});

// SECURITY: bull v4.x consumer registration preserves 'bulk-export' action contract per AAP §0.5.3 / R1
//           process() callback returns Promise (v4 default); InMemoryQueue compatible per frozen contract
//           Per AAP §0.4.2: "Bull queue interface frozen — InMemoryQueue and NoOpQueue fallback behavior must be preserved"
//           Unknown actions are explicitly rejected to prevent stray job processing (defense-in-depth)
//           job.data.action is the only acceptable dispatch key; injection of arbitrary actions returns rejected Promise
exportsQueue.process(function(job) {
  var action = job.data.action;

  if (action === 'bulk-export') {
    return processBulkExport(job);
  }
  else {
    // SECURITY: Reject unknown actions explicitly (defense-in-depth against queue tampering)
    //           per AAP §0.5.2 Strategy H / R8 / OWASP A03
    return Promise.reject(new Error('Unknown action: ' + action));
  }
});

function processBulkExport(job) {
  var exportId = job.data.exportId
    , userId   = job.data.userId
    , exportRecord
    , user
    , tempFile
    , s3Key
    , filename;

  // SECURITY: Generate unique filename from server-controlled values (userId from authenticated session, timestamp)
  //           NOT user input per AAP §0.5.2 Strategy H / R8 / OWASP A03 (path traversal defense)
  // Generate unique filename
  var timestamp = Date.now();
  // SECURITY: SHA-1 used as deterministic export filename identifier, not for confidentiality
  //           Acceptable per §6.4.4.1.1 / AAP §0.5.2 Strategy B / R2 / OWASP A02 acceptable use
  //           NIST SP 800-131A allows SHA-1 for non-cryptographic identifier hashing
  //           Identity-only use: digest is concatenated with constant prefix and ".zip" extension for filename
  //           Integrity is NOT relied upon; collision tolerance is acceptable (filename uniqueness only)
  var hash = crypto.createHash('sha1')
    .update(userId + timestamp.toString())
    .digest('hex')
    .substring(0, 12);

  // SECURITY: Filename, tempFile path, and S3 key are constructed from server-controlled values
  //           userId is from authenticated session; timestamp is Date.now(); hash is SHA-1 of those
  //           No user-supplied path components; path traversal defense per AAP §0.5.2 Strategy H / R8
  filename = 'trinket-export-' + hash + '.zip';
  tempFile = '/tmp/' + filename;
  s3Key = 'exports/' + userId + '/' + filename;

  if (!config.isTest) {
    env = nunjucks.configure(config.app.templates);
  }

  return Q.nsend(Export.model || mongoose.model('Export'), 'findByIdAndUpdate', exportId, { status: 'processing' })
    .then(function(record) {
      exportRecord = record;
      return Q.nsend(User.model || mongoose.model('User'), 'findById', userId);
    })
    .then(function(foundUser) {
      user = foundUser;
      if (!user) {
        throw new Error('User not found');
      }

      // Count total trinkets
      return Q.nsend(Trinket.model || mongoose.model('Snippet'), 'count', { _owner: userId });
    })
    .then(function(count) {
      // Update total count
      return Q.nsend(Export.model || mongoose.model('Export'), 'findByIdAndUpdate', exportId, {
        'progress.total': count,
        trinketCount: count
      });
    })
    .then(function() {
      // Create the archive
      return createExportArchive(userId, exportId, tempFile);
    })
    .then(function(result) {
      // Upload to S3
      return uploadToS3(tempFile, s3Key, filename);
    })
    .then(function(downloadUrl) {
      // SECURITY: 3-day TTL on bulk export S3 objects per §6.4.4.5.1 — limits storage exposure window
      //           per AAP §0.6.1 frozen retention policy
      var expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + EXPORT_EXPIRY_DAYS);

      // Get file size
      var stats = fs.statSync(tempFile);

      // Update export record with completion
      return Q.nsend(Export.model || mongoose.model('Export'), 'findByIdAndUpdate', exportId, {
        status: 'completed',
        downloadUrl: downloadUrl,
        s3Key: s3Key,
        expiresAt: expiresAt,
        fileSize: stats.size
      }, { new: true });
    })
    .then(function(record) {
      exportRecord = record;
      // Send notification email
      return sendCompletionEmail(user, exportRecord);
    })
    .then(function() {
      // Cleanup temp file
      fs.unlink(tempFile, function() {});
      return Promise.resolve();
    })
    .fail(function(err) {
      // Cleanup on failure
      if (tempFile) {
        fs.unlink(tempFile, function() {});
      }

      return Q.nsend(Export.model || mongoose.model('Export'), 'findByIdAndUpdate', exportId, {
        status: 'failed',
        errorMessage: err.message
      })
      .then(function() {
        if (user) {
          return sendFailureEmail(user, err.message);
        }
      })
      .then(function() {
        return Promise.reject(err);
      });
    });
}

// SECURITY: createExportArchive streams user-owned trinkets via Mongoose stream API
//           Owner scoping: TrinketModel.find({ _owner: userId }) — only the user's own trinkets included
//           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control
//           Mongoose schema typing rejects operator-prefixed userId values per AAP §0.5.2 Strategy H / R8
function createExportArchive(userId, exportId, tempFile) {
  var deferred = Q.defer();
  var archive = archiver('zip', { zlib: { level: 6 } });
  var output = fs.createWriteStream(tempFile);
  var processed = 0;
  var failed = 0;
  var manifest = {
    exportedAt: new Date().toISOString(),
    trinkets: []
  };

  output.on('close', function() {
    deferred.resolve({ processed: processed, failed: failed });
  });

  output.on('error', function(err) {
    deferred.reject(err);
  });

  archive.on('error', function(err) {
    deferred.reject(err);
  });

  archive.pipe(output);

  // Use stream to iterate trinkets (older mongoose API)
  var TrinketModel = Trinket.model || mongoose.model('Snippet');
  var stream = TrinketModel.find({ _owner: userId })
    .select('shortCode name lang code assets settings created lastUpdated')
    .stream();

  var trinketPromises = [];

  stream.on('data', function(trinket) {
    stream.pause();

    var trinketPromise = addTrinketToArchive(archive, trinket)
      .then(function(trinketInfo) {
        processed++;
        manifest.trinkets.push(trinketInfo);

        // Update progress every 10 trinkets
        if (processed % 10 === 0) {
          return Q.nsend(Export.model || mongoose.model('Export'), 'findByIdAndUpdate', exportId, {
            'progress.processed': processed,
            'progress.failed': failed
          });
        }
      })
      .fail(function(err) {
        failed++;
        console.log('Failed to add trinket:', trinket.shortCode, err.message);
      })
      .finally(function() {
        stream.resume();
      });

    trinketPromises.push(trinketPromise);
  });

  stream.on('end', function() {
    Q.all(trinketPromises)
      .then(function() {
        // Add manifest
        manifest.totalTrinkets = processed;
        manifest.failedTrinkets = failed;
        archive.append(JSON.stringify(manifest, null, 2), { name: 'manifest.json' });

        // Final progress update
        return Q.nsend(Export.model || mongoose.model('Export'), 'findByIdAndUpdate', exportId, {
          'progress.processed': processed,
          'progress.failed': failed
        });
      })
      .then(function() {
        archive.finalize();
      })
      .fail(function(err) {
        deferred.reject(err);
      });
  });

  stream.on('error', function(err) {
    deferred.reject(err);
  });

  return deferred.promise;
}

// SECURITY: addTrinketToArchive constructs archive paths from sanitized trinket name + shortCode
//           sanitizeFolderName strips path-traversal characters per AAP §0.5.2 Strategy H / R8 / OWASP A03
//           lang is enum-bounded by Mongoose schema (validLang pre-handler in lib/util/helpers.js)
//           shortCode is server-generated identifier (NOT user-controlled raw input)
function addTrinketToArchive(archive, trinket) {
  var deferred = Q.defer();
  // SECURITY: sanitizeFolderName removes path-traversal characters per AAP §0.5.2 Strategy H / R8
  var folderName = sanitizeFolderName(trinket.name || trinket.shortCode);
  // SECURITY: basePath = lang/folderName_shortCode — all components are safe:
  //           - lang: Mongoose enum-bounded
  //           - folderName: stripped to alphanumerics + dash + underscore
  //           - shortCode: server-generated identifier
  var basePath = (trinket.lang || 'other') + '/' + folderName + '_' + trinket.shortCode + '/';

  // Add metadata file
  var metadata = {
    shortCode: trinket.shortCode,
    name: trinket.name,
    lang: trinket.lang,
    created: trinket.created,
    lastUpdated: trinket.lastUpdated,
    settings: trinket.settings,
    url: config.url + '/' + trinket.lang + '/' + trinket.shortCode
  };
  archive.append(JSON.stringify(metadata, null, 2), { name: basePath + 'metadata.json' });

  // Parse and add code files
  var codeFiles = parseCodeFiles(trinket);
  codeFiles.forEach(function(file) {
    archive.append(file.content || '', { name: basePath + file.name });
  });

  // Download and add assets
  var assetPromises = [];
  if (trinket.assets && trinket.assets.length) {
    trinket.assets.forEach(function(asset) {
      if (!asset.url) return;

      // SECURITY: path.basename strips directory prefix from user-supplied asset URL (path traversal defense)
      //           per AAP §0.5.2 Strategy H / R8 / OWASP A03
      var assetFile = path.basename(url.parse(asset.url).pathname);

      var assetPromise = downloadAsset(asset.url)
        .then(function(buffer) {
          archive.append(buffer, { name: basePath + 'assets/' + (asset.name || assetFile) });
        })
        .fail(function(err) {
          // Log but don't fail entire trinket for one missing asset
          console.log('Asset download failed:', asset.name, err.message);
        });

      assetPromises.push(assetPromise);
    });
  }

  Q.allSettled(assetPromises)
    .then(function() {
      deferred.resolve({
        shortCode: trinket.shortCode,
        name: trinket.name,
        lang: trinket.lang
      });
    })
    .fail(function(err) {
      deferred.reject(err);
    });

  return deferred.promise;
}

function parseCodeFiles(trinket) {
  var code;
  try {
    code = JSON.parse(trinket.code);
    if (!Array.isArray(code)) {
      throw new Error('Not an array');
    }
  } catch(e) {
    // Single file trinket
    var extension = langExtensions[trinket.lang] || '.txt';
    var mainName = /blocks/.test(trinket.lang) ? 'main.xml' : 'main' + extension;

    code = [{
      name: mainName,
      content: trinket.code
    }];
  }
  return code;
}

// SECURITY: sanitizeFolderName strips path-traversal and shell-injection characters per AAP §0.5.2 Strategy H / R8 / OWASP A03
//           Whitelist regex: only alphanumerics, underscore, hyphen, whitespace allowed
//           Whitespace collapsed to single underscore; result truncated to 50 chars
//           Defends against trinket names like "../../../etc/passwd" by stripping "../" entirely
//           Returns "untitled" if name is empty (defense against null/undefined trinket names)
function sanitizeFolderName(name) {
  return (name || 'untitled')
    .replace(/[^a-zA-Z0-9_\-\s]/g, '')
    .replace(/\s+/g, '_')
    .substring(0, 50);
}

// SECURITY: S3 PutObject via aws-sdk v2.x patched per AAP §0.5.3 (v3 migration deferred per Minimal Change Clause)
//           Bucket: config.aws.buckets.exports.name (server-configured)
//           Key: server-controlled (constructed in processBulkExport from userId + SHA-1 hash + timestamp)
//           ContentType: 'application/zip' (server-controlled, not user input)
//           ContentDisposition: filename is server-controlled (constructed from SHA-1 identifier hash)
//           Returns: S3 host + key as downloadUrl for downstream presigned URL generation in lib/controllers/users.js
function uploadToS3(localPath, s3Key, filename) {
  var deferred = Q.defer();
  var client = new aws.S3();
  var readStream = fs.createReadStream(localPath);

  client.putObject({
    Bucket: config.aws.buckets.exports.name,
    Key: s3Key,
    Body: readStream,
    ContentType: 'application/zip',
    ContentDisposition: 'attachment; filename="' + filename + '"'
  }, function(err, data) {
    if (err) {
      return deferred.reject(err);
    }

    // SECURITY: Return S3 host + key; presigned URL generation (with 3-day TTL) is performed
    //           on download by lib/controllers/users.js downloadExport per AAP §0.6.1
    //           Strict ownership enforcement (=== after .toString()) protects against IDOR
    // Return the S3 key - we'll generate presigned URLs on download
    deferred.resolve(config.aws.buckets.exports.host + '/' + s3Key);
  });

  return deferred.promise;
}

// SECURITY: Email content rendered via Nunjucks with autoescape: true per AAP §0.5.2 Strategy H / R8 / OWASP A03 Injection
//           Set globally in lib/util/nunjucks.js per lib/util folder agent update
//           User-controlled fields (user.name, user.username, errorMessage) are auto-escaped to prevent XSS in HTML email
//           Email templates: lib/views/emails/export-ready.html and lib/views/emails/export-failed.html
//           Per AAP user directive: graceful degradation preserved — mailer.send returns {skipped: true} when SMTP unconfigured
function sendCompletionEmail(user, exportRecord) {
  var subject = 'Your Trinket Export is Ready';

  var templateData = {
    // SECURITY: user.name and user.username are auto-escaped by Nunjucks autoescape: true (XSS defense)
    username: user.name || user.username,
    trinketCount: exportRecord.progress ? exportRecord.progress.processed : exportRecord.trinketCount,
    fileSize: formatFileSize(exportRecord.fileSize),
    expiresAt: moment(exportRecord.expiresAt).format('MMM D, YYYY'),
    // SECURITY: downloadUrl is server-controlled (config.url + server-generated path); not user input
    downloadUrl: config.url + '/api/exports/' + exportRecord._id + '/download'
  };

  var html = nunjucks.render('emails/export-ready', templateData);

  // SECURITY: mailer.send wrapper preserves graceful degradation per AAP §0.8.3
  //           SMTP absent → {skipped: true} (no crash); per lib/util/mailer.js frozen send() API
  return mailer.send(user.email, subject, { html: html, type: 'export-ready' });
}

// SECURITY: Failure email — same XSS defense via Nunjucks autoescape: true
//           errorMessage is server-generated from caught error (not user input directly)
function sendFailureEmail(user, errorMessage) {
  var subject = 'Your Trinket Export Failed';

  var templateData = {
    // SECURITY: user.name and user.username auto-escaped per AAP §0.5.2 Strategy H / R8
    username: user.name || user.username,
    errorMessage: errorMessage || 'An unexpected error occurred'
  };

  var html = nunjucks.render('emails/export-failed', templateData);

  return mailer.send(user.email, subject, { html: html, type: 'export-failed' });
}

function formatFileSize(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}
