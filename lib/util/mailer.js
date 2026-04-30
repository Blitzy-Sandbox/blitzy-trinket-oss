// SECURITY: nodemailer v6 createTransport API (options-object) preserved per AAP §0.5.3 / R1
//           (nodemailer ^6.x.x in package.json; v2 EOL with known CVEs replaced)
//           Per AAP "Must Remain Unchanged": mailer.send() wrapper API preserved exactly
//           per test/helpers/mail.js stub contract (Q.resolve() returning Promise)
// SECURITY: app.mail.secret JWT signing secret is validated at boot per AAP §0.5.2 Strategy B / R2
//           (boot guard in app.js refuses startup if app.mail.secret < 32 chars when app.mail is configured)
//           Note: app.mail.secret is read by lib/controllers/trinket.js (JWT issuance) and lib/util/helpers.js (verify);
//                 this module reads transport credentials (user/pass), separate from JWT signing secret
var nodemailer = require('nodemailer'),
    config     = require('config'),
    _          = require('underscore');

// SECURITY: Graceful degradation gate per AAP §0.8.3 user directive: "SMTP absent → {skipped: true}"
//           Boot succeeds when operators don't configure mail; send() returns {skipped: true} per AAP §0.8.3
//           Boot guard in app.js validates app.mail.secret entropy ONLY IF config.app.mail is defined
function isConfigured() {
  var mailConfig = config.app.mail;
  return mailConfig && mailConfig.from && mailConfig.host;
}

// SECURITY: nodemailer v6 createTransport API (options-object) per AAP §0.5.3 / R1
//           v2 EOL signature `createTransport('SMTP', options)` is NOT used (already v6-compatible)
//           Per AAP §0.4.3: nodemailer v6 supports OAuth2 and modern TLS; preserved feature parity
// Create reusable transporter
function createTransport() {
  var mailConfig = config.app.mail;

  return nodemailer.createTransport({
    host: mailConfig.host,
    port: mailConfig.port || 587,
    // SECURITY: secure flag controls implicit TLS (port 465) vs STARTTLS (port 587)
    //           Operators must set mail.secure=true for TLS-from-connect deployments
    secure: mailConfig.secure || false,
    auth: {
      user: mailConfig.user,
      pass: mailConfig.pass
    }
  });
}

module.exports = {
  isConfigured: isConfigured,

  // SECURITY: send() wrapper API frozen per user "Must Remain Unchanged"
  //           test/helpers/mail.js stubs this method via Sinon; signature must NOT change
  //           Returns Promise that resolves to {skipped: true, reason: ...} (graceful degradation)
  //           OR resolves to nodemailer response (success) OR rejects with err (failure)
  //           Per AAP §0.8.3 graceful degradation: SMTP absent → {skipped: true}
  send: async function(to, subject, options) {
    // SECURITY: Graceful degradation gate per AAP §0.8.3 user directive
    //           When SMTP is unconfigured, boot continues and send() returns {skipped: true}
    //           This is INTENTIONAL behavior, not a security regression
    if (!isConfigured()) {
      console.log('Email not configured, skipping send to:', to);
      return { skipped: true, reason: 'Email not configured' };
    }

    options = _.extend({
      from: config.app.mail.from,
      to: to,
      subject: subject
    }, options || {});

    var transport = createTransport();

    // SECURITY: Promise wrapper preserves callback-style nodemailer.sendMail API for test stub compatibility
    //           per test/helpers/mail.js Sinon stub returning Q.resolve() (Q-Promise compatible)
    return new Promise(function(resolve, reject) {
      transport.sendMail(options, function(err, response) {
        if (err) {
          reject(err);
        } else {
          resolve(response);
        }
      });
    });
  }
};
