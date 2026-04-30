var request = require('request')
  , config  = require('config');

module.exports = {
  verify : function(g_recaptcha_response, cb) {
    // Skip recaptcha verification in test mode or if not configured
    if (config.isTest || !config.app.recaptcha || !config.app.recaptcha.secretkey) {
      return cb({ success : true });
    }

    request.post({
        url : "https://www.google.com/recaptcha/api/siteverify"
      , form : {
            secret   : config.app.recaptcha.secretkey
          , response : g_recaptcha_response
        }
    }, function(err, response, body) {
      if (response.statusCode === 200) {
        cb(JSON.parse(response.body));
      }
      else {
        cb({ status : false });
      }
    });
  }
};
