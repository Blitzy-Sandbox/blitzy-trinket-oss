// SECURITY: Nunjucks template environment with autoescape enabled per AAP §0.5.2 Strategy H / R8 / OWASP A03 Injection
//           autoescape: true ensures all {{ var }} references are auto-escaped (HTML entity encoding)
//           Only explicit `| safe` filter produces unescaped output (audited in lib/views per AAP §0.6.1)
// SECURITY: Filter registrations FROZEN per user "Must Remain Unchanged":
//   - cachePrefix : Cache-busting URL prefix (asset versioning)
//   - json        : JSON serialization filter
//   - translate   : i18n string lookup (currently identity stub per lib/util/translate.js)
//   - userAvatar  : Avatar URL generator (handles CDN host vs local path)
//   - encrypt     : AES role-payload encryption via lib/util/roles.js (frozen interface)
//   - escapeJSON  : JSON-safe escape for inline <script> tag injection (XSS defense for window.trinket bootstrap)
var config      = require('config'),
    path        = require('path'),
    _           = require('underscore'),
    lodash      = require('lodash'),
    moment      = require('moment'),
    numeral     = require('numeral'),
    nunjucks    = require('nunjucks'),
    // SECURITY: autoescape: true enabled per AAP §0.5.2 Strategy H / R8 / OWASP A03 Injection
    //           All {{ var }} references are auto-escaped; only explicit `| safe` filter produces raw HTML
    //           watch: true in dev/test; false in production for performance
    env         = nunjucks.configure(config.app.templates, {watch:config.isDev || config.isTest ? true : false, autoescape: true}),
    StringUtils = require('./stringUtils'),
    cachify     = require('./cachify'),
    translate   = require('./translate'),
    roles       = require('./roles'),
    component   = require('./component'),
    constants   = require('../../config/constants');

// SECURITY: Filter registrations frozen per user "Must Remain Unchanged"
//           Each filter is server-controlled and operates on trusted server-side data
//           User-controlled data flows through autoescape: true (default) unless explicit `| safe` is applied
//           DO NOT modify filter implementations; only add new filters if explicitly required by AAP
env.addFilter('cachePrefix', function(src, key) {
  return StringUtils.addPrefix(src, config.app.prefixes, key);
});
env.addFilter('json', function(str, opt) {
  if (opt === 'pretty') {
    return JSON.stringify(str, null, 2);
  } else {
    return JSON.stringify(str);
  }
});
env.addFilter('translate', function(str, locale) {
  return translate(str, locale);
});
env.addFilter('userAvatar', function(str) {
  if (!str) {
    return '/img/avatar-default.svg';
  }
  // Already a full URL
  if (/^http/.test(str)) {
    return str;
  }
  // Already a local path
  if (/^\//.test(str)) {
    return str;
  }
  // Relative path - prepend cloud host if configured
  var cloudHost = config.aws.buckets.useravatars.host || '';
  if (cloudHost.length > 0 && !cloudHost.includes('example.com')) {
    return cloudHost + '/' + str;
  }
  // Default to local img path
  return '/img/' + str;
});
env.addFilter('encrypt', function(obj) {
  return roles.encrypt(obj);
});
// SECURITY: escapeJSON filter recursively HTML-escapes all string values in a data structure
//           per AAP §0.5.2 Strategy H / R8 / OWASP A03 Injection (XSS defense)
//           Used by templates that inject server-side data into <script>window.trinket = {{ data | escapeJSON }}</script>
//           Without this filter, user-controlled strings could break out of JSON context and execute as JS
//           lodash.escape matches client-side escaping convention (per existing comment)
function escapeJSON(data) {
  if (typeof data === 'undefined' || data === null) {
    return null;
  }

  if (data instanceof Array) {
    for (var i = 0; i < data.length; i++) {
      data[i] = escapeJSON(data[i]);
    }
  }
  else if (typeof data === 'object') {
    for (var i in data) {
      if (data.hasOwnProperty(i)) {
        data[i] = escapeJSON(data[i]);
      }
    }
  }
  else if (typeof data === 'string') {
    // SECURITY: lodash.escape converts <, >, &, ', " to HTML entities (XSS defense)
    //           lodash is used on the client-side so we'll use it here too (consistency)
    data = lodash.escape(data);
  }

  return data;
}
env.addFilter('escapeJSON', function(obj) {
  var e = escapeJSON(obj);
  return e;
});

// SECURITY: render() and compile() wrappers preserved per AAP "Must Remain Unchanged"
//           render() returns Promise (used by Vision plugin)
//           compile() injects common server-controlled context vars (config, moment, etc.)
//           Per AAP §0.6.1: context-injection pattern preserved exactly; vars are server-controlled (NOT user input)
module.exports = {
  render: function(template, context) {
    if (config.isDev || config.isTest) {
      env.cache = {};
    }
    return new Promise(function(resolve, reject) {
      nunjucks.render(template, context, function(err, result) {
        if (err) return reject(err);
        resolve(result);
      });
    });
  },
  compile: function(src, info) {
    // Vision passes src (template source string) and info.filename (absolute path)
    // Extract template name relative to templates directory for nunjucks.render()
    // We need to convert absolute path to relative path from templates directory
    var templatesDir = path.resolve(config.app.templates);
    var templateName = info.filename.replace(templatesDir, '');
    // Remove leading slash if present
    if (templateName.charAt(0) === '/' || templateName.charAt(0) === '\\') {
      templateName = templateName.substring(1);
    }

    var subdomain = function(instructor, course) {
      if (config.app.usersubdomains) {
        return '/' + course.slug;
      }
      else {
        return ['', 'u', instructor.slug, 'classes', course.slug].join('/');
      }
    };
    var host = function(instructor) {
      var url = config.app.url.protocol + '://';
      if (config.app.usersubdomains && instructor) {
        url += instructor.slug + '.'
      }
      url += config.app.url.hostname;
      return url;
    };

    return function(context) {
      // kill the nunjucks cache when in dev mode
      if (config.isDev || config.isTest) {
        env.cache = {};
      }

      // SECURITY: Context vars injected here are server-controlled (config, moment, numeral, etc.)
      //           User-controlled data passed in as `context` flows through autoescape: true (default)
      //           Only explicit `| safe` filter applied in templates produces raw HTML
      _.extend(context, {
        config     : config,
        moment     : moment,
        numeral    : numeral,
        subdomain  : subdomain,
        host       : host,
        cachify_js : cachify.js,
        translate  : translate,
        component  : component,
        constants  : constants
      });

      // Use nunjucks.render with template name (like old Hapi 4.x approach)
      // This allows duplicate block names in conditionals to work
      try {
        return nunjucks.render(templateName, context);
      } catch (err) {
        console.error('Nunjucks render error for template:', templateName);
        console.error('Error:', err.message);
        console.error('Stack:', err.stack);
        throw err;
      }
    };
  },
  env : env
}
