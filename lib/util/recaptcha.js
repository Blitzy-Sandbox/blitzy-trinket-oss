// SECURITY: axios replaces deprecated `request` package per AAP §0.5.3 / R1 / Minimal Change Clause
//           (request@^2.51.0 deprecated with no security patches; axios@^1.x is maintained successor)
var axios       = require('axios')
  , querystring = require('querystring')
  , config      = require('config');

module.exports = {
  verify : function(g_recaptcha_response, cb) {
    // SECURITY: fail-open preserved with operator warning per AAP §0.5.2 Strategy C / R3 / OWASP A04
    //           graceful degradation per AAP §0.8.3: "reCAPTCHA absent → fail-open preserved (with warning)"
    if (config.isTest || !config.app.recaptcha || !config.app.recaptcha.secretkey) {
      // SECURITY: Log warning when reCAPTCHA is unconfigured (excluding test mode) to give operators audit visibility
      //           per AAP §0.5.2 Strategy C / R3.
      //           Defensive `typeof log` guard protects against module-load ordering: the global `log`
      //           symbol is set at app.js line 19 (`log = require('./config/log')`); this module may be
      //           required before that boot step in some contexts (e.g., test harness, pre-boot validation).
      if (!config.isTest && typeof log !== 'undefined' && log && typeof log.warn === 'function') {
        log.warn('SECURITY: reCAPTCHA disabled (no secretkey configured) - human verification will fail-open. Configure config.app.recaptcha.secretkey in local.yaml for production deployments.');
      }
      return cb({ success : true });
    }

    // SECURITY: POST to Google reCAPTCHA verify endpoint via axios (replaces deprecated `request` package)
    //           per AAP §0.5.3 / R1.
    //           Body is application/x-www-form-urlencoded per Google's siteverify API contract;
    //           querystring.stringify (Node.js built-in, zero new dependency) URL-encodes the form fields.
    //           axios resolves with {data, status, headers}; data is already JSON-parsed by axios when
    //           the response Content-Type is application/json (Google reCAPTCHA always returns JSON).
    axios.post(
        "https://www.google.com/recaptcha/api/siteverify"
      , querystring.stringify({
            secret   : config.app.recaptcha.secretkey
          , response : g_recaptcha_response
        })
      , {
          headers : { 'Content-Type' : 'application/x-www-form-urlencoded' }
          // SECURITY: 10s timeout prevents indefinite hang on Google reCAPTCHA service unreachability
          //           (mitigates DoS amplification per OWASP A04 Insecure Design)
        , timeout : 10000
        }
    ).then(function(response) {
      // axios resolves with {data, status, headers}; data is already JSON-parsed by axios
      // Match existing 200-only success contract: pass response.data to callback
      if (response.status === 200) {
        cb(response.data);
      }
      else {
        cb({ status : false });
      }
    }).catch(function(err) {
      // axios rejects on network errors and on non-2xx status (axios default).
      // Match existing failure contract: callback with {status: false} for HTTP-level failures.
      // For complete network failure (no response received), pass through axios-formatted error
      // so callers can distinguish transport failures from API-level "verification failed" results.
      if (err && err.response && err.response.status) {
        cb({ status : false });
      }
      else {
        cb(err);
      }
    });
  }
};
