// SECURITY: replaced deprecated `request` package with the actively maintained
// `axios` library to remediate CVE-2023-28155 (cross-protocol redirect SSRF in
// the Request package; the package is no longer supported by the maintainer).
// The (err, response, body) callback contract used by callers in
// lib/controllers/users.js is preserved verbatim; the test-mode short-circuit
// is preserved verbatim. AAP §0.5.1 / §0.6.2 / QA finding #4.
var axios   = require('axios')
  , config  = require('config');

module.exports = {
  verify : function(g_recaptcha_response, cb) {
    // Skip recaptcha verification in test mode or if not configured
    if (config.isTest || !config.app.recaptcha || !config.app.recaptcha.secretkey) {
      return cb({ success : true });
    }

    // Build the form-encoded body manually so we exactly match the wire format
    // emitted by the previous `request.post({form: ...})` call.
    var form = new URLSearchParams({
      secret   : config.app.recaptcha.secretkey,
      response : g_recaptcha_response
    }).toString();

    axios.post(
      "https://www.google.com/recaptcha/api/siteverify",
      form,
      {
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        // Reject any non-2xx so we drop into the .catch branch and emit the
        // existing { status: false } shape; this is the same effective
        // behavior as the previous `if (response.statusCode === 200)` guard.
        validateStatus: function(status) { return status >= 200 && status < 300; }
      }
    )
    .then(function(response) {
      // axios already parses application/json responses into objects, so we
      // forward the body directly to the existing callback contract instead of
      // running JSON.parse a second time.
      cb(response.data);
    })
    .catch(function() {
      cb({ status : false });
    });
  }
};
