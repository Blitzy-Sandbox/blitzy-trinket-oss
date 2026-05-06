// SECURITY: replaced deprecated request with axios (CVE-2023-28155)
var axios  = require('axios')
  , config = require('config');

module.exports = {
  verify : function(g_recaptcha_response, cb) {
    // Skip recaptcha verification in test mode or if not configured
    if (config.isTest || !config.app.recaptcha || !config.app.recaptcha.secretkey) {
      return cb({ success : true });
    }

    // SECURITY: replaced deprecated request with axios (CVE-2023-28155)
    axios.post(
        "https://www.google.com/recaptcha/api/siteverify",
        new URLSearchParams({
            secret   : config.app.recaptcha.secretkey
          , response : g_recaptcha_response
        }).toString(),
        { headers : { 'content-type' : 'application/x-www-form-urlencoded' } }
    )
    .then(function(response) {
      if (response.status === 200) {
        // axios auto-parses JSON responses into response.data; preserve the original cb(parsedBody) contract.
        cb(typeof response.data === 'string' ? JSON.parse(response.data) : response.data);
      }
      else {
        cb({ status : false });
      }
    })
    .catch(function(err) {
      cb({ status : false });
    });
  }
};
