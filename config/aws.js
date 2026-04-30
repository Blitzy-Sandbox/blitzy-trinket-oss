var AWS      = require('aws-sdk')
    , config = require('config');

// SECURITY: aws-sdk upgraded to latest patched v2.x version per AAP §0.5.3 / §0.7.1
// (v3 migration deferred per Minimal Change Clause — would touch every S3 call site
//  in lib/util/file.js and lib/workers/exports.js; v2 in maintenance mode but still
//  receiving security patches per AWS announcement)
// SECURITY: SDK construction interface preserved within v2.x — accessKeyId/secretAccessKey/region
// SECURITY: Credentials sourced from config.aws (loaded from config/local.yaml or environment)
// — never from environment variables in this codebase per AAP §0.7.3
AWS.config.update({
  accessKeyId       : config.aws.keyId
  , secretAccessKey : config.aws.key
  , region          : config.aws.region
});

module.exports = AWS;
