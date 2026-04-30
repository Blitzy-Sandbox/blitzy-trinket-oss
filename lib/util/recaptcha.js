// SECURITY: replaced deprecated `request` package with `axios` (R1 per AAP §0.5.2 Strategy A); request
// was removed from package.json because it is unmaintained upstream and ships no security patches.
var axios  = require('axios')
  , config = require('config');

module.exports = {
  verify : function(g_recaptcha_response, cb) {
    // Skip recaptcha verification in test mode or if not configured
    if (config.isTest || !config.app.recaptcha || !config.app.recaptcha.secretkey) {
      return cb({ success : true });
    }

    // SECURITY: axios call replaces request.post() but preserves the original callback contract
    // (cb receives the parsed JSON body on 200, or { status: false } on any other outcome). The
    // log.warn() addition for the fail-open posture (R3) is performed by the recaptcha.js
    // remediation agent in a follow-on commit.
    axios.post(
      "https://www.google.com/recaptcha/api/siteverify",
      new URLSearchParams({
        secret   : config.app.recaptcha.secretkey,
        response : g_recaptcha_response
      }).toString(),
      {
        headers : { 'Content-Type' : 'application/x-www-form-urlencoded' },
        // Treat non-2xx as resolution rather than rejection so the existing branching (status === 200
        // vs. otherwise) preserves the original `request`-style semantics.
        validateStatus : function() { return true; }
      }
    ).then(function(response) {
      if (response.status === 200) {
        // axios already parses application/json responses into response.data
        cb(typeof response.data === 'string' ? JSON.parse(response.data) : response.data);
      }
      else {
        cb({ status : false });
      }
    }).catch(function(err) {
      cb({ status : false });
    });
  }
};
