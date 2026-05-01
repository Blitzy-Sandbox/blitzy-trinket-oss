var mailer     = require('../util/mailer'),
    errors     = require('@hapi/boom'),
    Joi        = require('joi'),
    config     = require('config'),
    nunjucks   = require('nunjucks'),
    _          = require('underscore'),
    recaptcha  = require('../util/recaptcha');

module.exports = {
  index: function(request, reply) {
    request.success({
      footer : true
    });
  },
  login: function(request, reply) {
  	if (request.auth.isAuthenticated) {
      // SECURITY: reply().redirect() invokes the routeParser.js compatibility shim
      // SECURITY: (lib/util/routeParser.js lines 357-413) which adapts the legacy
      // SECURITY: Hapi 4.x reply() callable to Hapi 17+ h toolkit. The previous
      // SECURITY: form `reply.redirect()` accessed an undefined property on the
      // SECURITY: function object, throwing TypeError under authenticated GET /login,
      // SECURITY: which exposed an HTTP 500 sanitized error page (CWE-755 Improper
      // SECURITY: Handling of Exceptional Conditions). Lines 40 and 45 of this file
      // SECURITY: already use the correct shim pattern. Fix per AAP §0.5.2 Strategy I /
      // SECURITY: R9 audit findings — preserves Hapi 20 route DSL frozen contract per
      // SECURITY: AAP "Must Remain Unchanged" (route signature unchanged).
      return reply().redirect('/home');
    } else {
      if (request.query.next) {
        request.yar.set('next', request.query.next);
      }
      request.success();
    }
  },
  signup: function(request, reply) {
    if (request.auth.isAuthenticated) {
      // SECURITY: reply().redirect() invokes the routeParser.js compatibility shim
      // SECURITY: (lib/util/routeParser.js lines 357-413). Same fix rationale as the
      // SECURITY: login handler above (CWE-755 — 500 error page for authenticated
      // SECURITY: users navigating to /signup). Mirrors the working pattern used
      // SECURITY: at lines 40 (welcome) and 45 (home) of this file. Fix per AAP
      // SECURITY: §0.5.2 Strategy I / R9 audit findings.
      return reply().redirect('/welcome');
    }
    else {
      if (request.query.next) {
        request.yar.set('next', request.query.next);
      }
      request.success({
        next : request.query.next || ""
      });
    }
  },
  welcome: function(request, reply) {
    request.yar.flash('siteMessage', 'Welcome! Your account has been created.', true);
    return reply().redirect('/home');
  },
  home: function(request, reply) {
    // Redirect to login if not authenticated
    if (!request.user) {
      return reply().redirect('/login');
    }

    return Trinket.findRecentByOwner(request.user._id)
      .then(function(trinkets) {
        return request.success({
          trinkets : trinkets
        });
      })
      .catch(request.fail);
  },
  features : function(request, reply) {
    var data = {
        footer  : true
      , feature : request.params.feature
    };

    if (request.pre.namedTrinketList.length) {
      _.extendOwn(data, {
        examples : request.pre.namedTrinketList
      });
    }

    return request.success(data);
  },
  forgotPasswordForm: function(request, reply) {
  	request.success();
  }
};
