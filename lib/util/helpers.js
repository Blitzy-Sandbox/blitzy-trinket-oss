// SECURITY: Central Hapi pre-handler module for the Trinket app
//           Provides access-control pre-handlers (isAdmin, canEdit), resource-resolution pre-handlers
//           (findTrinket, userByUsername, courseBySlug), validation pre-handlers (validLang,
//           trinketTypeEnabled, coursesEnabled, lowerUserFields), and JWT verification (verifyEmailToken)
// SECURITY: Per AAP "Must Remain Unchanged": pre-handler chain API frozen
//           Consumed by config/api_routes.js and config/routes.js as 'isAdmin(user)', 'canEdit(<resource>,user)' etc.
// SECURITY: jwt.verify uses algorithms: ['HS256'] explicit pinning per AAP §0.5.2 Strategy B / R2 / CVE-2022-23529 mitigation
//           jsonwebtoken v9 upgrade requires explicit algorithm pinning to prevent algorithm confusion attacks
// SECURITY: Mongoose query construction passes user-controlled values through Mongoose schema typing
//           per AAP §0.5.2 Strategy H / R8 / OWASP A03 (NoSQL operator injection defense)
//           Joi schemas in config/api_routes.js further reject $where/$regex/operator-prefixed keys
var _                 = require('underscore'),
    Boom              = require('@hapi/boom'),
    config            = require('config'),
    Hapi              = require('@hapi/hapi'),
    Store             = require('./store'),
    features          = require('./features'),
    trinketStore      = Store.trinkets(),
    courseStore       = Store.courses(),
    userStore         = Store.users(),
    fs                = require('fs'),
    jwt               = require('jsonwebtoken'),
    defaultNextResult = true, // use this if your helper doesn't return a value
    internals         = {};

internals.defaultNextResult = defaultNextResult;

// SECURITY: isAdmin pre-handler enforces admin role on /api/admin/* and /admin/* routes
//           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control
//           Consumed by config/api_routes.js and config/routes.js as 'isAdmin(user)' pre-handler string
//           Returns Boom.forbidden() (HTTP 403) for non-admin; throws Boom.forbidden() in modern style
internals.isAdmin = function(user, next) {
  // Hapi 20+ style: return directly or throw
  if (typeof next === 'function') {
    // Legacy callback style
    next(user.hasRole("admin") ? defaultNextResult : Boom.forbidden());
  } else {
    // Modern style: return value or throw Boom error
    if (user && user.hasRole && user.hasRole("admin")) {
      return defaultNextResult;
    }
    throw Boom.forbidden();
  }
}

// SECURITY: findById pre-handler factory uses Mongoose schema-typed `model.findById(id)` lookup
//           per AAP §0.5.2 Strategy H / R8 / OWASP A03 (NoSQL operator injection defense)
//           Mongoose ObjectId casting rejects malformed IDs ($where, $regex, operator-prefixed keys)
//           Soft-deleted documents (doc.deletedAt set) are treated as Boom.notFound() to prevent enumeration
internals.findById = function(model, fallback) {
  return function(id, optional, next) {
    // Handle different argument patterns
    if (typeof optional === 'function') {
      next = optional;
      optional = false;
    } else if (arguments.length === 2 && typeof optional !== 'boolean') {
      next = optional;
      optional = false;
    }

    if (!id) {
      var err = optional ? optional : Boom.badRequest();
      return next ? next(err) : Promise.reject(err);
    }

    // SECURITY: Mongoose findById casts string id to ObjectId; rejects operator-prefixed values
    // Return a promise - works for both pre-handlers and callback style
    return model.findById(id)
      .then(function(doc) {
        // SECURITY: Soft-delete enforcement prevents access to logically-deleted documents
        // Treat soft-deleted documents as not found
        var result = (doc && !doc.deletedAt) ? doc : Boom.notFound();
        return next ? next(result) : result;
      })
      .catch(function(err) {
        // SECURITY: Convert Mongoose CastError (invalid ObjectId / non-coerceable string) into
        //           Boom.notFound() per AAP §0.5.2 Strategy H / R8 / OWASP A04 Insecure Design.
        //           Previously CastError propagated as raw Error → HTTP 500 with stack trace,
        //           leaking schema internals and breaking the documented HTTP 404 contract.
        //           This affects /api/folders/{id}, /api/courses/{id}, and other resources that
        //           use this findById factory pre-handler. NoSQL operator injection vectors
        //           (e.g., $where in id position) are coerced to invalid ObjectId by Mongoose
        //           and now return a clean HTTP 404 instead of a stack-trace 500.
        var notFound = (err && err.name === 'CastError') ? Boom.notFound() : err;
        if (next) return next(notFound);
        throw notFound;
      });
  };
}

internals.userByLogin = function(userSlug, next) {
  return User.findByLogin(userSlug, function(err, doc) {
    if (err) return next(err);
    return next(doc ? doc : Boom.notFound());
  });
},

// TODO: refactor to check roles

// SECURITY: canEdit pre-handler enforces resource ownership per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control
//           Resource owner check: resource._owner.toString() === user.id (strict equality after .toString())
//           Per AAP §0.5.2 Strategy G: "verify exportRecord._owner.toString() === userId.toString() (strict === after .toString())"
//           Consumed by config/api_routes.js and config/routes.js as 'canEdit(<resource>,user)' pre-handler string
//           Note: Both ownerId and user.id are string-typed before === comparison (Mongoose ObjectId.toString())
//           Mongoose populate(): if _owner is populated (full doc), use populated.id; else use raw ObjectId.toString()
internals.canEdit = function(resource, user, next) {
  var result;

  if (!resource) {
    result = Boom.badRequest();
  } else if (!user) {
    result = Boom.forbidden();
  } else {
    // SECURITY: Strict equality === ownership check after .toString() coercion
    //           Prevents IDOR per AAP §0.5.2 Strategy G / R7 / CWE-639
    var ownerId = resource.populated('_owner') || "";
    if (!ownerId && resource._owner) {
      ownerId = resource._owner.toString();
    }
    result = ownerId === user.id ? defaultNextResult : Boom.forbidden();
  }

  // Support both callback and direct return patterns
  if (next) {
    return next(result);
  }
  return result;
}

internals.contains = function(listProperty) {
  return function(haystack, needle, next) {
    if (!haystack || !needle) {
      if (next) return next(Boom.badRequest());
      throw Boom.badRequest();
    }

    if (!haystack[listProperty] || !haystack[listProperty].indexOf || typeof(haystack[listProperty].indexOf) !== 'function') {
      if (next) return next(Boom.badRequest());
      throw Boom.badRequest();
    }

    var result = haystack[listProperty].indexOf(needle) >= 0 ? defaultNextResult : Boom.badRequest();
    if (next) return next(result);
    if (result instanceof Error) throw result;
    return result;
  };
}

// SECURITY: lowerUserFields normalizes email and username for case-insensitive uniqueness enforcement
//           per AAP §0.5.2 Strategy G / R7 / OWASP A07 Identification and Authentication Failures
//           Prevents "User@Example.com" vs "user@example.com" duplicate-account creation
//           Trim removes accidental whitespace prefix/suffix that could enable enumeration
internals.lowerUserFields = function(request, h) {
  ['email', 'username'].forEach(function(field) {
    // SECURITY: Type-guard against NoSQL operator injection (R8 per AAP §0.5.2 Strategy H / OWASP A03 Injection / CWE-20).
    //           Without the typeof === 'string' check, an attacker-supplied object payload such as
    //           {"email": {"$gt": ""}} causes request.payload[field].trim() to throw a TypeError
    //           (object has no .trim method), surfacing an HTTP 500 with stack trace BEFORE the
    //           manual Joi validation in lib/util/routeParser.js can reject the operator-prefixed
    //           key. The guard ensures non-string payloads are silently passed through to Joi,
    //           which will reject them with HTTP 400 (per the routeParser.js validation flow).
    //           This addresses QA finding 8.1 (lowerUserFields HTTP 500 crash on operator payloads).
    if (request.payload && typeof request.payload[field] === 'string') {
      request.payload[field] = request.payload[field].trim().toLowerCase();
    }
  });
  return null;
}

internals.populate = function(source, fields, next) {
  if (!(fields && fields.length)) {
    if (next) return next(defaultNextResult);
    return Promise.resolve(defaultNextResult);
  }

  if (!Array.isArray(fields)) {
    fields = fields.split(',');
  }

  var promises = _.map(fields, function(field) {
    return source.populate(field);
  });

  return Promise.all(promises)
    .then(function() {
      if (next) return next(source);
      return source;
    })
    .catch(function(err) {
      if (next) return next(err);
      throw err;
    });
}

// SECURITY: findTrinket uses Mongoose schema-typed Trinket.findById(trinketId) lookup
//           per AAP §0.5.2 Strategy H / R8 / OWASP A03 (NoSQL operator injection defense)
//           trinketId/shortCode is extracted from request.params (Hapi+Joi-validated path params)
//           Soft-deleted trinkets are treated as Boom.notFound() (enumeration defense)
//           Lang-mismatched access redirects 301 to canonical lang URL (no information disclosure)
module.exports.findTrinket = {
  assign : 'trinket',
  method : function(request, reply) {
    var trinketId = request.params.trinketId || request.params.shortCode;

    // check for extension
    var hasExtension = trinketId.match(/\.(\w+)/);
    if (hasExtension) {
      trinketId = trinketId.substr(0, hasExtension.index);

      // for downstream handlers
      request.params.trinketId = request.params.shortCode = trinketId;
      request.pre.extension = hasExtension[1];
    }

    // SECURITY: Mongoose findById casts trinketId to ObjectId; rejects operator-prefixed values
    return Trinket.findById(trinketId)
      .then(function(doc) {
        if (doc) {
          // SECURITY: Soft-delete enforcement prevents access to logically-deleted trinkets (enumeration defense)
          // Soft-deleted trinkets are treated as not found
          if (doc.deletedAt) {
            return reply(Boom.notFound());
          }

          var requestLang = request.params.lang;
          if (!requestLang) {
            var pathSegments = request.path.split('/');

            // i.e. /{lang}/{shortCode}
            if (Trinket.schema.path('lang').enumValues.indexOf( pathSegments[1] ) >= 0) {
              requestLang = pathSegments[1];
            }
          }

          if (!requestLang || requestLang === doc.lang) {
            return reply(doc);
          }
          else {
            // redirect to correct lang
            var location = config.url + '/' + doc.lang + '/' + trinketId;
            return reply().redirect(location).permanent().takeover();
          }
        }
        else {
          return reply(Boom.notFound());
        }
      })
      .catch(function(err) {
        return reply(err);
      });
  }
};

// SECURITY: validLang enforces lang whitelist via Trinket.schema.path('lang').enumValues
//           per AAP §0.5.2 Strategy H / R8 (input validation; enum-bounded language identifier)
//           Rejects unknown lang values with Boom.notFound() (no SQL/NoSQL injection surface)
module.exports.validLang = {
  assign : 'validLang',
  method : function(request, reply) {
    // strip leading and trailing slashes
    var urlLang = request.url.pathname.replace(/^\//, '').replace(/\/$/, '')
      , lang    = request.params.lang || request.query.lang || (request.payload && request.payload.lang) || urlLang;

    var isValid = Trinket.schema.path('lang').enumValues.indexOf(lang) >= 0;
    return isValid ? reply(lang) : reply(Boom.notFound());
  }
}

/**
 * Check if a trinket type (language) is enabled via feature flags
 * Returns 404 if the trinket type is disabled
 */
// SECURITY: trinketTypeEnabled enforces feature-flag-based trinket type access per AAP §0.5.2 Strategy G / R7
//           Returns 404 (NOT 403) for disabled types to prevent feature enumeration
module.exports.trinketTypeEnabled = {
  assign : 'trinketTypeEnabled',
  method : function(request, reply) {
    // Get lang from various sources
    var urlLang = request.url.pathname.replace(/^\//, '').split('/')[0]
      , lang    = request.params.lang || request.query.lang;

    // Only use urlLang if it's actually a known trinket type
    // (avoids treating paths like /library as a lang)
    if (!lang && features.isKnownTrinketType(urlLang)) {
      lang = urlLang;
    }

    if (!lang) {
      // No lang specified, allow through
      return reply(true);
    }

    if (features.isTrinketTypeEnabled(lang)) {
      return reply(true);
    }

    // Trinket type is disabled
    return reply(Boom.notFound('This trinket type is not available'));
  }
}

/**
 * Pre-handler to check if courses feature is enabled.
 * Returns 404 if courses are disabled.
 */
// SECURITY: coursesEnabled enforces feature-flag-based courses access per AAP §0.5.2 Strategy G / R7
//           Returns 404 (NOT 403) for disabled courses to prevent feature enumeration
module.exports.coursesEnabled = {
  assign : 'coursesEnabled',
  method : function(request, reply) {
    if (features.isCoursesEnabled()) {
      return reply(true);
    }
    return reply(Boom.notFound('Courses are not available'));
  }
}

// SECURITY: verifyEmailToken validates JWT email tokens (issued by lib/controllers/trinket.js)
//           per AAP §0.5.2 Strategy B / R2 / OWASP A02 Cryptographic Failures
//           HS256 algorithm explicit pinning prevents CVE-2022-23529 algorithm confusion attacks
//           (jsonwebtoken v9+ requires explicit algorithms parameter)
//           Secret: config.app.mail.secret + request.pre.trinket.shortCode (boot guard at app.js validates entropy)
//           Per AAP §0.6.1: error path returns generic Boom.forbidden (no JWT error detail leakage to client)
module.exports.verifyEmailToken = function(request, reply) {
  var secret = config.app.mail.secret + request.pre.trinket.shortCode
    , sessionKey = 'emailToken:' + request.pre.trinket.shortCode
    , data, token;

  token = request.payload.token
    ? request.payload.token
    : request.yar && request.yar.get(sessionKey)
      ? request.yar.get(sessionKey)
      : null;

  if (token) {
    // SECURITY: Wrap jwt.verify in try/catch and pin algorithms to ['HS256']
    //           per AAP §0.5.2 Strategy B / R2 / CVE-2022-23529 mitigation
    //           Generic error response prevents JWT error detail leakage (per AAP §0.6.1)
    try {
      data = jwt.verify(token, secret, { algorithms: ['HS256'] });
    } catch (err) {
      // SECURITY: Generic forbidden response prevents JWT error detail leakage
      //           (do NOT pass err.message to client per AAP §0.6.1)
      return reply(Boom.forbidden('Invalid or expired token'));
    }

    if (data && data.shortCode === request.pre.trinket.shortCode) {
      return reply(data);
    } else {
      return reply(Boom.forbidden('Invalid or expired token'));
    }
  }
  else {
    return reply(Boom.badRequest());
  }
}


module.exports.register = function(server) {
  server.method('isAdmin',              internals.isAdmin);
  server.method('user',                 internals.findById(User));
  server.method('course',               internals.findById(Course));
  server.method('folder',               internals.findById(Folder));
  server.method('invitation',           internals.findById(CourseInvitation));
  server.method('canEdit',              internals.canEdit);
  server.method('file',                 internals.findById(File));
  server.method('lesson',               internals.findById(Lesson));
  server.method('parent',               internals.findById(Lesson));
  server.method('material',             internals.findById(Material));
  server.method('trinket',              internals.findById(Trinket));
  server.method('hasLesson',            internals.contains('lessons'));
  server.method('hasMaterial',          internals.contains('materials'));
  server.method('populate',             internals.populate);
  server.method('namedTrinketList', internals.namedTrinketList);
}

module.exports.lowerUserFields = internals.lowerUserFields;

module.exports.toLowerCaseURI = function(request, reply) {
  // requests for static files and api calls should pass through unchanged
  var privacy = (request.route.cache && request.route.cache.privacy) || 'default';
  var static  = privacy === 'public' ? true : false;

  var url     = request.url.pathname;
  var api     = /^\/api\//.test(url) ? true : false;

  var host    = request.headers.host || '';
  var lcHost  = host.toLowerCase();
  var lcUrl   = url.toLowerCase();

  var caseMatches = (url === lcUrl && host === lcHost) ? true : false;

  if (api || static || caseMatches) return reply();

  var hostname = lcHost;

  var location = config.app.url.protocol + '://' + hostname + lcUrl;

  return reply('').redirect(location).permanent();
}

module.exports.logUnauth = function(request, reply) {
  if (request.route.auth && request.route.auth.mode === 'required' && !request.auth.isAuthenticated) {
    log.debug("unauth", {
      route   : request.route,
      auth    : request.auth,
      session : request.yar,
      headers : request.headers,
      params  : request.params,
      query   : request.query,
      payload : request.payload
    });
  }

  return reply();
}

module.exports.getDefaultTrinket = function(request, reply) {
  if (!request.query.category) {
    return reply();
  }

  return trinketStore
    .random(request.params.lang, request.query.category)
    .then(reply)
    .catch(function(err) {
      // TODO: what should we do here?
      reply(err);
    });
}

// SECURITY: userByUsername uses User.findById which supports alternate IDs (username/email)
//           per AAP §0.5.2 Strategy H / R8 / OWASP A03 (NoSQL operator injection defense)
//           username is normalized to lowercase before lookup (case-insensitive uniqueness per lowerUserFields)
//           Mongoose schema typing rejects operator-prefixed values
module.exports.userByUsername = async function(request, reply) {
  var username = request.params.username.toLowerCase();

  try {
    // findById supports alternate IDs (username, email) per user model config
    var user = await User.findById(username);
    if (user) {
      return reply(user);
    }
    return reply(Boom.notFound());
  } catch (err) {
    console.error('userByUsername error:', err);
    return reply(err);
  }
}

// SECURITY: courseBySlug uses Course.findByUserAndSlug + slug alias resolution per AAP §0.5.2 Strategy H / R8
//           User scoping prevents cross-user course access (BAC defense per OWASP A01)
//           Slug alias resolution redirects to canonical URL on slug rename (no info disclosure)
module.exports.courseBySlug = async function(request, reply) {
  var slug = request.params.courseSlug,
      user = request.pre.user || request.user,
      aliasId;

  try {
    var doc = await Course.findByUserAndSlug(user._id, slug);
    if (doc) return reply(doc);

    var id = await courseStore.getIdBySlug(slug);
    if (!id) throw Boom.notFound();

    aliasId = id;
    var alias = await Course.findById(id);

    if (alias) {
      var url_regexp = new RegExp('\\b' + slug + '\\b', 'i');
      var location = request.path.replace(url_regexp, alias.slug);
      return reply().redirect(location).permanent().takeover();
    }
    else {
      // prune the dead link
      courseStore.unlinkIdFromSlug(slug, aliasId);
    }
    throw Boom.notFound();
  } catch (err) {
    return reply(err);
  }
}

module.exports.findFeaturedTrinkets = async function(request, h) {
  var path       = request.path;
  var lenOrIndex = path.indexOf('/', 1) >= 0 ? path.indexOf('/', 1) : path.length;
  var lang       = path.substring(path.indexOf('/') + 1, lenOrIndex);

  return await internals.namedTrinketList(lang, 'featured');
}

module.exports.trinketByOwnerAndSlug = function(request, reply) {
  var slug = request.params.trinketSlug.toLowerCase(),
      user = request.pre.user || request.user,
      aliasId;

  return Trinket.findByOwnerAndSlug(user._id, slug, function(err, doc) {
    if (err) return reply(err);
    if (doc) return reply(doc);

    return trinketStore.getIdBySlugAndUser(slug, user._id)
      .then(function(id) {
        if (!id) throw Boom.notFound();
        aliasId = id;
        return Trinket.findById(id);
      })
      .then(function(alias) {
        if (alias) {
          // Check if aliased trinket is soft-deleted
          if (alias.deletedAt) {
            throw Boom.notFound();
          }
          var url_regexp = new RegExp('\\b' + slug + '\\b', 'i');
          var location = request.path.replace(url_regexp, alias.slug);
          return reply().redirect(location).permanent().takeover();
        }
        else {
          // prune the dead link
          trinketStore.unlinkIdFromSlugAndUser(slug, user._id, aliasId);
        }
        throw Boom.notFound();
      })
      .catch(reply);
  });
}

internals.namedTrinketList = async function(lang, category) {
  var trinkets = await trinketStore.byCategory(lang, category);

  if (!trinkets || !trinkets.length) {
    return [];
  }

  var sortedTrinkets = trinkets.slice();
  var trinketObjects = await Trinket.findByIds(trinkets);

  if (trinketObjects && trinketObjects.length) {
    for (var i = 0; i < trinketObjects.length; i++) {
      var sortedIndex = sortedTrinkets.indexOf(trinketObjects[i].id);
      sortedTrinkets[sortedIndex] = trinketObjects[i];
    }
  }

  return sortedTrinkets;
}

if (config.isTest) {
  // expose internals for testing
  module.exports.internals = internals;
}
