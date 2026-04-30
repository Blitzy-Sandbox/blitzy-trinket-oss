// SECURITY: Replaced deprecated `request` package with `axios` (R1 per AAP §0.5.2 Strategy A);
//           `request` was removed from package.json because it is unmaintained upstream and
//           ships no security patches (CVE-2023-28155 SSRF residual risk; deprecated 2020).
//           axios@^1.x is actively maintained and provides equivalent HTTP client functionality.
var axios  = require('axios')
  , config = require('config');

module.exports = {
  verify : function(g_recaptcha_response, cb) {
    // SECURITY: reCAPTCHA fail-open warning (R3 per AAP §0.5.2 Strategy C / OWASP A04 Insecure Design).
    //           When config.app.recaptcha is absent or has an empty secretkey, this branch
    //           short-circuits human verification and returns success: true. Per the user's
    //           "reCAPTCHA absent → fail-open preserved (with warning)" graceful-degradation
    //           directive (AAP §0.1.2), the runtime behavior remains permissive but is now
    //           audit-visible via a WARN-level log so operators can detect unconfigured
    //           reCAPTCHA on signup, password-reset, and email-verification flows.
    //           Test mode (config.isTest) intentionally bypasses the warning to keep test
    //           output clean; only production-like environments missing the secret are flagged.
    if (config.isTest || !config.app.recaptcha || !config.app.recaptcha.secretkey) {
      if (!config.isTest) {
        // SECURITY: log.warn surfaces the missing reCAPTCHA configuration to operators
        //           (Winston transport per config/log.js) while preserving fail-open semantics.
        log.warn('SECURITY: reCAPTCHA not configured (missing config.app.recaptcha.secretkey) — '
               + 'human verification will fail-open. Configure config.app.recaptcha.secretkey '
               + 'in local.yaml to enable verification on signup/reset/email-verify flows.');
      }
      return cb({ success : true });
    }

    // SECURITY: axios.post replaces request.post() but preserves the original callback contract:
    //           cb receives the parsed JSON body on HTTP 200, or { status: false } on any other
    //           outcome (network error, non-200 response, parse failure). Downstream callers in
    //           lib/controllers/users.js and lib/controllers/trinket.js see an identical interface.
    //           validateStatus: () => true forces axios to resolve (rather than reject) on non-2xx
    //           so we can branch on response.status === 200 just like the original `request` flow.
    axios.post(
      "https://www.google.com/recaptcha/api/siteverify",
      new URLSearchParams({
        secret   : config.app.recaptcha.secretkey,
        response : g_recaptcha_response
      }).toString(),
      {
        headers : { 'Content-Type' : 'application/x-www-form-urlencoded' },
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
