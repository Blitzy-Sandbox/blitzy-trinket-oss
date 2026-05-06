var sinon  = require('sinon'),
    Q      = require('q'),
    mailer = require('../../lib/util/mailer');

module.exports = {
  mailer : mailer,
  stub   : function() {
    before(function() {
      // SECURITY: per AAP §0.1.2 graceful-degradation contract, when SMTP is
      // not configured `mailer.isConfigured()` returns false and email-bearing
      // controllers (forgot-pass, trinket email-share, account verification)
      // fail-fast with a friendly "Email is not configured" message instead of
      // sending. Tests that exercise those controllers must run as if email
      // were configured, so we stub BOTH isConfigured() (return true) AND
      // send() (returns a resolved promise) — without the isConfigured stub
      // the tests fail before reaching the stubbed send() and assertions
      // like `mailer.send.calledOnce.should.be.true` always evaluate false.
      sinon.stub(mailer, 'isConfigured').returns(true);
      sinon.stub(mailer, 'send').returns(Q.resolve());
    });

    after(function() {
      mailer.isConfigured.restore();
      mailer.send.restore();
    });
  }
};
