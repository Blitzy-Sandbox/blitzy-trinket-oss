var Joi               = require('joi'),
    yaml              = require('js-yaml'),
    fs                = require('fs'),
    helpers           = require('../lib/util/helpers'),
    config            = require('config'),
    constants         = require('./constants'),  // Ensure constants is loaded
    reservedUsernames = yaml.safeLoad(fs.readFileSync(__dirname + '/reserved.yaml', 'utf8')),
    routes;

// SECURITY: Page route security hardening per AAP §0.5.2 (R4 + R5 + R7) / OWASP A01, A05, A07
// (1) /admin and /admin/{adminPage*} routes audited for pre: ['isAdmin(user)'] enforcement
//     — All admin pages confirmed admin-gated per AAP §0.5.2 Strategy G / R7 / OWASP A01
// (2) /admin/upload (POST) opts in to @hapi/crumb CSRF synchronizer-token via plugins : { crumb : {} }
//     — Per AAP Risk Management: scoped to non-SPA admin routes first; SPA-consumed routes deferred
//     — Per AAP §0.5.2 Strategy E / R5 / OWASP A07
// (3) Auth flow routes (login, signup, password reset) preserved with existing Joi validation
//     — recaptchaValidation degrades to optional when reCAPTCHA unconfigured per AAP §0.5.2 Strategy C / R3
// (4) /admin and /admin/* paths covered by xframeDeny in config/default.yaml per AAP §0.5.2 Strategy D / R4
//     — X-Frame-Options: deny applied via app.js onPreResponse extension
// (5) Joi schema audit: object-literal schemas reject unknown/operator-prefixed keys by default (Joi v6)
//     — Per AAP §0.5.2 Strategy H / R8 / OWASP A03

// Make recaptcha optional when not configured
var recaptchaValidation = (config.app.recaptcha && config.app.recaptcha.secretkey)
  ? Joi.string().required()
  : Joi.string().allow('').optional();

routes = [
  {
    route  : 'GET / pages.index',
    html   : 'index.html',
    enable : true
  },
  {
    route : 'GET /signup pages.signup',
    html  : 'signup.html'
  },
  {
    route : 'GET /login pages.login',
    html  : 'login.html',
    config : {
      validate : {
        query : {
          next : Joi.string().optional()
        }
      }
    }
  },
  {
    // SECURITY: GET /welcome retargeted from pages.welcome to users.welcome to render the
    // SECURITY: documented post-signup library-courses HTML response per AAP §0.5.2 Strategy I /
    // SECURITY: R9 audit findings. The original pages.welcome handler issued reply().redirect('/home')
    // SECURITY: without rendering HTML, leaving the welcome-page UX contract unimplemented in the
    // SECURITY: open-source release. The new users.welcome handler:
    // SECURITY:   (1) preserves the existing yar.flash('siteMessage', ...) post-signup banner;
    // SECURITY:   (2) HTML-entity-escapes course.name (autoescape parity with Nunjucks templates);
    // SECURITY:   (3) re-applies allow-list filtering on libraryUser.username and course.slug
    // SECURITY:       (defense-in-depth alongside Mongoose schema validation);
    // SECURITY:   (4) gracefully falls back to redirect('/home') when config.app.trinketLibraryUser
    // SECURITY:       is unset or the user has no courses (graceful degradation per AAP §0.5.4).
    // SECURITY: Route signature (method, path, auth strategy) unchanged per AAP API Compatibility
    // SECURITY: Directive — only the controller binding moves; no Joi schema, no params, no
    // SECURITY: replySpec change. Per AAP §0.11.1 minimal-change clause this is the smallest
    // SECURITY: in-scope change to satisfy the test/lib/api/registration.js welcome-link contract
    // SECURITY: while keeping lib/controllers/pages.js out-of-scope per AAP §0.6.1.
    route  : 'GET /welcome users.welcome',
    config : { auth: 'session' }
  },
  {
    route  : 'GET /home pages.home',
    html   : 'home.html',
    config : { auth: 'session' }
  },
  {
    route   : 'POST /login users.login',
    cookie  : true,
    success : {
      redirect : '/home'
    },
    fail    : {
      redirect : '/login'
    },
    config  : {
      // SECURITY: helpers.lowerUserFields normalizes email/username for case-insensitive auth (AAP §0.6.1 audit)
      // SECURITY: CSRF deferred to follow-on per AAP Risk Management (SPA-consumed login flow)
      pre : [{ method : helpers.lowerUserFields }],
      // SECURITY: Joi schema rejects NoSQL operator injection per AAP §0.5.2 Strategy H / R8 / OWASP A03
      validate : {
        payload : {
          email    : Joi.string().required(),
          password : Joi.string()
        }
      }
    }
  },
  {
    route    : 'GET /logout users.logout',
    cookie  : true,
    redirect : '/'
  },
  {
    route : 'POST /users users.create',
    cookie  : true,
    success : {
      redirect : '/welcome'
    },
    fail : {
      redirect : '/{formName}'
    },
    config : {
      // SECURITY: helpers.lowerUserFields normalizes email/username for case-insensitive uniqueness (AAP §0.6.1 audit)
      // SECURITY: CSRF deferred to follow-on per AAP Risk Management (SPA-consumed signup flow)
      // SECURITY: reservedUsernames invalidate list prevents impersonation of system identifiers
      pre : [{ method: helpers.lowerUserFields }],
      // SECURITY: Joi schema rejects NoSQL operator injection per AAP §0.5.2 Strategy H / R8 / OWASP A03
      // SECURITY: recaptchaValidation enforces human verification when configured per AAP §0.5.2 Strategy C / R3
      validate  : {
        payload : {
          formName : Joi.string().required(),
          fullname : Joi.string().max(50).optional(),
          username : Joi.string().min(3).max(20).regex(/^[a-z][a-z0-9\-\_]*$/i).optional().invalid(...reservedUsernames),
          email    : Joi.string().email().required(),
          password : Joi.string().min(3).regex(/^[\w`~!@#$%^&*+=:;'"<>,.?{}\-\/\(\)\[\]\|\\\s]*$/).required(),
          interest : Joi.string().allow('').optional(),
          next     : Joi.string().allow('').optional(),
          'g-recaptcha-response' : recaptchaValidation
        },
        language : {
          username : {
            "regular expression" : "Usernames must begin with a letter and must only contain alphanumeric characters and hyphens (-)."
          }
        }
      }
    }
  },
  {
    route : 'GET /account-deleted users.deleted'
  },
  {
    route : 'PUT /api/users/{userId} users.updateProfile',
    config : {
      auth: 'session',
      validate : {
        payload : {
          name     : Joi.string().min(1).max(140),
          avatar   : Joi.string().allow('').optional(),
          username : Joi.string().min(3).max(20).regex(/^[a-z][a-z0-9\-\_]*$/i).required().invalid(...reservedUsernames)
        },
        language : {
          username : {
            "regular expression" : "Usernames must begin with a letter and must only contain alphanumeric characters and hyphens (-)."
          }
        }
      }
    }
  },
  {
    route  : 'GET /courses/new courses.creationForm',
    html   : 'courses/create.html',
    config : {
      auth: 'session',
      pre : [helpers.coursesEnabled]
    }
  },
  {
    route : 'POST /courses courses.create',
    html  : {
      redirect : '/{user.username}/courses/{course.slug}'
    },
    fail  : {
      redirect : '/courses/new'
    },
    config : {
      auth: 'session',
      pre : [helpers.coursesEnabled],
      validate: {
        payload : {
          name: Joi.string().min(1).max(140).required(),
          description: Joi.string().max(500),
          courseType: Joi.string().valid('public', 'private', 'open').optional(),
          contentDefault: Joi.string().valid('publish', 'draft').optional()
        }
      }
    }
  },
  {
    route: 'POST /{userSlug}/courses/{courseSlug}/copy courses.copy',
    success: {
      redirect: '{classPageUrl}'
    },
    fail : {
      redirect : '/welcome'
    },
    config : {
      auth: 'session',
      pre:  [helpers.coursesEnabled, 'user(params.userSlug)', {method:helpers.courseBySlug, assign:'course'}]
    }
  },
  {
    route  : 'GET /{userSlug}/courses/{courseSlug}/download.zip courses.download',
    config : {
      auth: 'session',
      pre  : [helpers.coursesEnabled, 'user(params.userSlug)', {method:helpers.courseBySlug, assign:'course'}],
      validate : {
        query : {
          format : Joi.string().valid('md', 'html').required()
        }
      }
    }
  },
  {
    route  : 'GET /{userSlug}/courses/{courseSlug} courses.coursePage',
    html   : 'courses/view.html',
    config : {
      pre  : [helpers.coursesEnabled, 'user(params.userSlug)', {method:helpers.courseBySlug, assign:'course'}]
    }
  },
  {
    route : 'GET /api/classes/{userSlug}/{courseSlug} classes.getClass',
    config: {
      pre : [helpers.coursesEnabled, 'user(params.userSlug)', {method:helpers.courseBySlug, assign:'course'}]
    }
  },
  {
    route : 'GET /courses/accept/{token} classes.acceptInvitation',
    html  : 'classes/view.html',
    config : {
      pre : [helpers.coursesEnabled]
    }
  },
  {
    route : 'GET /courses/join/{accessCode} classes.joinFromLink',
    html : 'classes/view.html',
    config : {
      pre : [helpers.coursesEnabled]
    }
  },
  {
    route  : 'GET /api/files/{fileId}/{fileName} files.download',
    config : {
      pre : ['file(params.fileId)']
    }
  },
  {
    route  : 'GET /admin admin.index',
    html   : 'admin/index.html',
    fail   : {
      html : 'login.html'
    },
    config : {
      auth: 'session',
      // SECURITY: isAdmin enforcement per AAP §0.5.2 Strategy G / R7 / OWASP A01
      pre  : [
        'isAdmin(user)'
      ]
    }
  },
  {
    route : 'GET /admin/{adminPage*} admin.index',
    html  : 'admin/index.html',
    fail  : {
      html : 'login.html'
    },
    config : {
      auth: 'session',
      // SECURITY: isAdmin enforcement per AAP §0.5.2 Strategy G / R7 / OWASP A01
      pre  : [
        'isAdmin(user)'
      ]
    }
  },
  {
    route : 'POST /admin/upload admin.uploadUsers',
    html : 'admin/index.html',
    config : {
      auth: 'session',
      // SECURITY: CSRF synchronizer-token protection per AAP §0.5.2 Strategy E / R5 (admin server-rendered upload)
      plugins : { crumb : {} },
      // SECURITY: isAdmin enforcement per AAP §0.5.2 Strategy G / R7 / OWASP A01
      pre : ['isAdmin(user)']
    }
  },
  {
    route : 'GET /account users.account',
    html  : 'users/account.html',
    config : {
      auth: 'session'
    }
  },
  {
    route : 'GET /account/{accountPage} users.account',
    html  : 'users/account.html',
    config : {
      auth: 'session'
    }
  },
  {
    route : 'GET /forgot-pass pages.forgotPasswordForm',
    html  : 'users/forgotpass.html'
  },
  {
    route : 'POST /send-pass-reset users.sendPassReset',
    html  : 'users/sendpassreset.html',
    fail  : {
      redirect : '/forgot-pass'
    },
    config : {
      // SECURITY: helpers.lowerUserFields normalizes email for case-insensitive lookup (AAP §0.6.1 audit)
      // SECURITY: Controller emits uniform success response to prevent email enumeration per §6.4.4.3 / AAP §0.6.1
      // SECURITY: CSRF deferred to follow-on per AAP Risk Management (server-rendered form, low-risk)
      pre : [{ method : helpers.lowerUserFields }],
      validate : {
        payload : {
          email : Joi.string().email().required(),
          // SECURITY: recaptchaValidation enforces human verification when configured per AAP §0.5.2 Strategy C / R3
          'g-recaptcha-response' : recaptchaValidation
        }
      }
    }
  },
  {
    route : 'GET /reset-pass users.resetPasswordForm',
    html  : 'users/resetpass.html',
    fail  : {
      redirect : '/forgot-pass'
    },
    config : {
      validate : {
        query : {
          key : Joi.string().required()
        }
      }
    }
  },
  {
    route : 'POST /save-pass users.savePassword',
    html  : 'users/savepass.html',
    fail  : {
      redirect : '/forgot-pass'
    },
    config : {
      // SECURITY: Joi schema rejects NoSQL operator injection per AAP §0.5.2 Strategy H / R8 / OWASP A03
      // SECURITY: key parameter validates against reset-token store; CSRF deferred to follow-on per AAP Risk Management
      validate : {
        payload : {
          key             : Joi.string().required(),
          password        : Joi.string().required(),
          password_verify : Joi.string().required()
        }
      }
    }
  },
  {
    route : 'GET /activate-account users.activateAccountForm',
    html  : 'users/activateaccount.html',
    fail  : {
      redirect : '/{redirectTo}'
    },
    config : {
      validate : {
        query : {
          key : Joi.string().allow('').optional() // optional to allow for meaningful redirects
        }
      }
    }
  },
  {
    route : 'POST /activate-account users.activateAccount',
    success : {
      redirect : '/welcome'
    },
    fail  : {
      redirect : '/{redirectTo}'
    },
    config : {
      // SECURITY: Joi schema rejects NoSQL operator injection per AAP §0.5.2 Strategy H / R8 / OWASP A03
      // SECURITY: key parameter validates against activation-token store; CSRF deferred to follow-on per AAP Risk Management
      validate : {
        payload : {
          key      : Joi.string().required(),
          password : Joi.string().required()
        }
      }
    }
  },
  {
    route  : 'POST /file files.upload',
    config : {
      auth: 'session',
      payload : {
        maxBytes  : 1048576 * 10, // 10MB
        output : 'file',
        // SECURITY: Hapi 20+ requires explicit multipart enablement (defaults to false per
        // SECURITY: @hapi/hapi/lib/config.js multipart schema). Without `multipart: true`,
        // SECURITY: every multipart/form-data POST returns HTTP 415 Unsupported Media Type
        // SECURITY: at @hapi/subtext/lib/index.js line 88. Setting multipart: true preserves
        // SECURITY: pre-existing file upload functionality (per AAP §0.11.1 "Preserve all
        // SECURITY: existing functionality except where it enables the vulnerability") and
        // SECURITY: confines the parts to the same disk-spool output as the parent payload.
        multipart : true,
        // SECURITY: parse: true is the Hapi default but is asserted here for clarity —
        // SECURITY: required so multipart parts are decoded and the Joi validate.payload
        // SECURITY: schema can run (per @hapi/hapi route assertion at lib/route.js).
        parse : true
      },
      validate : {
        payload : {
          type   : Joi.string().valid('embed', 'download').optional(),
          upload : Joi.any().required()
        }
      }
    }
  },
  {
    route : 'POST /file/avatar files.uploadAvatar',
    config : {
      auth: 'session',
      payload : {
        maxBytes  : 1048576 * 5, // 5MB
        output: 'file',
        // SECURITY: Hapi 20+ multipart enablement per /file route comment above; preserves
        // SECURITY: pre-existing avatar upload functionality and confines parts to disk
        // SECURITY: spool consistent with the parent payload's output: 'file'.
        multipart : true,
        parse : true
      },
      validate : {
        payload : {
          upload : Joi.any().required()
        }
      }
    },
    reply : {
      host : true,
      path : true
    }
  },
  {
    route  : 'GET /u/{username}/classes classes.viewCourses',
    html   : 'classes/courses.html',
    config : {
      pre : [helpers.coursesEnabled, { method : helpers.userByUsername, assign : 'user' }]
    }
  },
  {
    route  : 'GET /u/{username}/classes/{courseSlug} classes.viewClass',
    html   : 'classes/view.html',
    config : {
      pre : [helpers.coursesEnabled, { method : helpers.userByUsername, assign : 'user' }, { method : helpers.courseBySlug, assign : 'course' }]
    }
  },
  {
    route : 'GET /embed/beta/{type} trinket.beta',
    html  : 'embed/beta/{type}.html',
    config : {
      pre : [{ method: helpers.findFeaturedTrinkets, assign: 'featuredTrinkets' }]
    }
  },
  {
    route : 'GET /embed/{lang}/{trinketId} trinket.embed',
    html  : 'embed/{lang}.html',
    config : {
      pre : [helpers.trinketTypeEnabled, helpers.validLang, helpers.findTrinket]
    }
  },
  {
    route : 'GET /assignment-embed/{lang}/{trinketId} trinket.assignment', // regular "student" view, auto save
    html : 'embed/{lang}.html',
    config : {
      auth: 'session',
      pre : [helpers.trinketTypeEnabled, helpers.validLang, helpers.findTrinket]
    }
  },
  {
    route : 'GET /assignment-embed-feedback/{lang}/{trinketId} trinket.assignmentFeedback', // "teacher" feedback view, draft
    html : 'embed/{lang}.html',
    config : {
      auth: 'session',
      pre : [helpers.trinketTypeEnabled, helpers.validLang, helpers.findTrinket]
    }
  },
  {
    route : 'GET /assignment-embed-viewonly/{lang}/{trinketId} trinket.viewOnly', // view-only, no auto save or draft
    html : 'embed/{lang}.html',
    config : {
      pre : [helpers.trinketTypeEnabled, helpers.validLang, helpers.findTrinket]
    }
  },
  {
    route : 'GET /embed/blocks-iframe trinket.index',
    html  : 'embed/blocks-iframe.html'
  },
  {
    route : 'GET /embed/glowscript-blocks-iframe trinket.index',
    html  : 'embed/glowscript-blocks-iframe.html'
  },
  {
    route : 'GET /embed/{lang} trinket.embed',
    html: 'embed/{lang}.html',
    config : {
      pre : [helpers.trinketTypeEnabled, helpers.validLang, { method: helpers.getDefaultTrinket, assign: 'trinket' }]
    }
  },
  {
    route : 'GET /tools/{version}/jekyll/embed/{lang} trinket.embed',
    html: 'embed/{lang}.html',
    config : {
      pre : [helpers.trinketTypeEnabled, helpers.validLang]
    }
  },
  {
    route : 'GET /skulpt trinket.index',
    success: {
      redirect: '/python'
    }
  },
  {
    route : 'GET /skulpt/{hash} trinket.index',
    success : {
      redirect: '/python/{hash}'
    }
  },
  {
    route : 'POST /python trinket.create',
    config : {
      validate : {
        payload : {
          code : Joi.string().required(),
        }
      }
    }
  },
  {
    route : 'GET /vpython trinket.index',
    success : {
      redirect : '/glowscript'
    }
  },
  {
    route : 'GET /vpython/{shortCode} trinket.index',
    success : {
      redirect : '/glowscript/{shortCode}'
    }
  },
  {
    route : 'GET /webvpython trinket.index',
    success : {
      redirect : '/glowscript'
    }
  },
  {
    route : 'GET /webvpython/{shortCode} trinket.index',
    success : {
      redirect : '/glowscript/{shortCode}'
    }
  },
  {
    route : 'GET /r trinket.index',
    success : {
      redirect : '/R'
    }
  },
  {
    route : 'GET /r/{shortCode} trinket.index',
    success : {
      redirect : '/R/{shortCode}'
    }
  },
  {
    route : 'GET /library/trinkets/{path*} trinket.library',
    config : {
      pre : [helpers.trinketTypeEnabled],
      validate : {
        query : {
          lang : Joi.string().optional(),
          user : Joi.string().optional(),
          go   : Joi.string().optional(),
          _3d  : Joi.string().optional()
        }
      }
    },
    html  : 'trinket/library.html'
  },
  {
    route : 'GET /library/folder/{slug} folders.listView',
    config : {
      auth: 'session'
    },
    html : 'trinket/library.html'
  },
  {
    route : 'GET /docs/colors pages.index',
    html  : 'docs/colors.html'
  },
  {
    // SECURITY: OAuth state parameter generated to prevent CSRF on callback per AAP §0.5.2
    //          Strategy E / R5 / OWASP A07 / CWE-352 (Login CSRF). The active runtime
    //          generation is in lib/controllers/auth.js `google` handler (crypto.randomBytes(32)
    //          stored in request.yar.set('oauth_state', state) and echoed in the redirect URL).
    //          The Passport GoogleStrategy `state: true` config in lib/auth/passport.js is
    //          defense-in-depth only and currently DEAD CODE — see passport.js header.
    route : 'GET /auth/google auth.google',
    config : {
      auth : false
    }
  },
  {
    // SECURITY: OAuth callback validates state parameter to prevent CSRF per AAP §0.5.2
    //          Strategy E / R5 / OWASP A07 / CWE-352 (Login CSRF). The active runtime
    //          validation is in lib/controllers/auth.js `googleCallback` handler — retrieves
    //          the expected state from request.yar.get('oauth_state'), compares to
    //          request.query.state via crypto.timingSafeEqual after a length pre-check, and
    //          clears the stored state in both success and failure paths to prevent replay.
    route : 'GET /auth/google/callback auth.googleCallback',
    cookie  : true,
    success: {
      redirect:  '{redirectTo}'
    },
    fail: {
      redirect: '/signup'
    },
    config : {
      auth : false
    }
  },
];

// SECURITY: Per-language routes use helpers.trinketTypeEnabled and helpers.validLang
// pre-handlers to enforce language enablement and prevent invalid language access (AAP §0.6.1 audit)
// trinket language specific routes
config.constants.trinketLangs.forEach(function(lang) {
  // language landing page
  routes.push({
      route  : 'GET /' + lang + ' trinket.index'
    , html   : 'trinket/' + lang + '/' + lang + '.html'
    , config : {
        pre  : [
            helpers.trinketTypeEnabled
          , {
                method : helpers.findFeaturedTrinkets
              , assign : 'featuredTrinkets'
            }
        ]
    }
  });

  // trailing slash landing page
  routes.push({
      route   : 'GET /' + lang + '/ pages.index'
    , success : {
        redirect : '/' + lang
      }
    , config  : {
        pre : [helpers.trinketTypeEnabled, helpers.validLang]
      }
  });

  // specific trinket landing page
  routes.push({
      route  : 'GET /' + lang + '/{shortCode} trinket.getByShortCode'
    , html   : 'trinket/' + lang + '/' + lang + '.html'
    , config : {
        pre  : [
            helpers.trinketTypeEnabled
          , helpers.findTrinket
          , {
                method : helpers.findFeaturedTrinkets
              , assign : 'featuredTrinkets'
            }
        ]
      }
  });

  // download the "main" file for a trinket
  routes.push({
      route : 'GET /' + lang + '/{shortCode}/ trinket.downloadMain'
    , config : {
        pre : [helpers.trinketTypeEnabled]
      }
  });

  // download specific file for a trinket
  routes.push({
      route : 'GET /' + lang + '/{shortCode}/{path*} trinket.downloadFile'
    , config : {
        pre : [helpers.trinketTypeEnabled]
      }
  });
});

module.exports = routes;
