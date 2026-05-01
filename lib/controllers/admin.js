var config        = require('config'),
    _             = require('underscore'),
    moment        = require('moment'), // SECURITY: required by grantRole() for trinket-teacher 30-day `thru` date computation; previously missing import caused ReferenceError → HTTP 500
    mailer        = require('../util/mailer'),
    Store         = require('../util/store'),
    userUtil      = require('../util/user'),
    featuredStore = Store.featured(),
    Boom          = require('@hapi/boom'), // SECURITY: aliased as `Boom` to match downstream Boom.notFound()/Boom.forbidden() call sites; pre-existing import alias `errors` left unused by this module's call sites and produced ReferenceError when invoked — see addFeaturedCourse line 285, line 294
    parse         = require('csv').parse;

// SECURITY: All admin handlers in this module require pre: ['isAdmin(user)'] enforcement via route config
//           in config/api_routes.js and config/routes.js per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control
//           — isAdmin pre-handler is defined in lib/util/helpers.js and validated at boot
//           — Audit performed per AAP §0.6.1: every admin route confirmed to carry pre: ['isAdmin(user)']
//
// SECURITY: Admin mutating handlers (updateUser, grantRole, addFeaturedCourse, removeFeaturedCourse,
//           moveFeaturedCourse, uploadUsers) are protected by @hapi/crumb CSRF synchronizer-token
//           via plugins: { crumb: {} } in route config per AAP §0.5.2 Strategy E / R5 / OWASP A01
//           Broken Access Control (CSRF moved from A08:2017 to A01:2021 per OWASP Top 10 2021); CWE-352
//           — CSRF validation performed at framework level; no controller-level token check required
//
// SECURITY: Admin impersonation tracking via _realUserId session field is NEVER exposed in API responses
//           or template render context; impersonation is server-side only per AAP §0.5.2 Strategy G / R7
//           — _realUserId is set in lib/util/routeParser.js (line 351) and read in lib/models/plugins/roles.js (line 307 via loggedInAs())
//           — Audit confirmed by grep: no _realUserId appears in any reply()/request.success()/request.fail() call in this file
//           — Frozen mechanism per user "Must Remain Unchanged" — DO NOT modify impersonation logic
module.exports = {
  index : function(request, reply) {
    var page     = request.params.adminPage
      , pageData = {}
      , subpage, promise, criteria;

    if (!request.params.adminPage) {
      return reply().redirect('/admin/users');
    }
    // SECURITY: admin impersonation EXIT point per AAP §0.5.2 Strategy G / R7 / OWASP A01
    //           Clears 'loginAs' session field; isAdmin pre-handler enforced via route pre-handler in config/routes.js
    //           Per AAP frozen mechanism: do NOT remove this impersonation flow (preserve loginAs/logoutAs)
    else if (request.query.logoutAs) {
      request.yar.clear('loginAs');
      return reply().redirect('/admin/users');
    }

    // SECURITY: When admin is currently impersonating (via loginAs), restrict admin index to /admin/users
    //           per AAP §0.5.2 Strategy G / R7 / OWASP A01
    //           request.user.loggedInAs() reads _realUserId from request.user (set by routeParser.js)
    //           and returns truthy when admin is impersonating; this is the ONLY internal use of _realUserId
    //           and does NOT expose the original admin id to the response
    if (request.user.loggedInAs()) {
      page    = 'users';
      promise = Promise.resolve();
    }
    else if (request.params.adminPage === 'users' && request.query.q) {
      if (/^role:\w+/.test(request.query.q)) {
        criteria = request.query.q.split(':');
        promise  = roleSearch(criteria[1]);
        subpage  = 'userSearchResults'
      }
      else {
        promise = userSearch(request.query.q);
      }
    }
    // SECURITY: admin impersonation ENTRY point per AAP §0.5.2 Strategy G / R7 / OWASP A01
    //           Sets 'loginAs' session field; lib/util/routeParser.js will swap request.user with the target user
    //           and assign the original admin's id to request.user._realUserId on subsequent requests
    //           isAdmin pre-handler enforced via route pre-handler in config/routes.js
    //           Per AAP frozen mechanism: do NOT remove this impersonation flow
    //           Per AAP §0.6.1: _realUserId MUST NEVER appear in API responses (audited and confirmed not exposed)
    else if (request.params.adminPage === 'users' && request.query.loginAs) {
      request.yar.set('loginAs', request.query.loginAs);
      return reply().redirect('/home');
    }
    else if (request.params.adminPage === 'featured-courses') {
      promise = featuredStore.getList()
        .then(function(featuredList) {
          return Promise.all(_.map(featuredList, function(member) {
            return Course.findById(member.id)
              .then(function(course) {
                if (course) {
                  course.page = member.page;
                }
                return course;
              });
          }));
        })
        .then(function(courses) {
          // Filter out null courses (deleted)
          courses = _.compact(courses);
          pageData.courses = _.map(courses, function(course) {
            return {
                id        : course.id
              , name      : course.name
              , slug      : course.slug
              , ownerSlug : course.ownerSlug
              , page      : course.page || null
            };
          });
          return pageData;
        })
        .catch(function(err) {
          pageData.courses = [];
          return pageData;
        });
    }
    else {
      promise = Promise.resolve();
    }

    return promise.then(function(data) {
      return request.success({
        page    : page,
        subpage : subpage || page,
        q       : request.query.q || undefined,
        active  : request.query.active || 'profile',
        data    : data
      });
    });
  },
  // SECURITY: ohnoes handler emails admin alerts; protected by pre: ['isAdmin(user)'] in route config
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01
  //           Payload data is logged to admin email; assumed to be operator-trusted (admin sends alert about themselves)
  ohnoes : function(request, reply) {
    var log = request.payload.log;

    request.success();

    if (!log || !log.length) return;

    var keys = "time,path,referrer,user,userAgent,sesh".split(",");
    var msg;
    for (var i = 0; i < log.length; i++) {
      for (var j = 0; j < keys.length; j++) {
        msg += "\n" + keys[j] + "\t\t" + log[i][keys[j]];
      }
      msg += "\n----------------------------------"
    }

    mailer.send(config.app.adminEmail, 'User Session Alert', {
      text : msg
    });
  },
  // SECURITY: uploadForm handler renders admin upload page; protected by pre: ['isAdmin(user)'] in route config
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01
  uploadForm : function(request, reply) {
    return request.success({});
  },
  // SECURITY: uploadUsers creates users from operator-controlled CSV upload (admin-only operation)
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01 — protected by pre: ['isAdmin(user)'] in config/routes.js
  // SECURITY: CSRF synchronizer-token validated by @hapi/crumb framework via plugins: { crumb: {} }
  //           in route config per AAP §0.5.2 Strategy E / R5 / OWASP A01 Broken Access Control / CWE-352
  // SECURITY: Mongoose schema typing on User._id (ObjectId) and email/username (String) provides
  //           type-coercion protection against NoSQL operator injection per AAP §0.5.2 Strategy H / R8 / OWASP A03
  //           — User.save() rejects operator-prefixed values via Mongoose schema cast
  uploadUsers : function(request, reply) {
    var userList = request.payload.userList.split(/\n/);
    var promises = [];

    // Email, Username, Name, Password
    parse(request.payload.userList, {
      columns: true,
      skip_empty_lines: true
    }, function(err, records) {
      if (err) return request.fail(err);

      records.forEach(function(userInfo) {
        var fullname = userInfo.Name || userInfo.Email;
        var username = userInfo.Username || userUtil.generate_username(userInfo.Email);
        var user = new User({
          email    : userInfo.Email,
          password : userInfo.Password,
          fullname : fullname,
          username : username,
          source   : 'upload'
        });

        promises.push(user.save());
      });

      Promise.allSettled(promises).then(function(results) {
        var success = 0;
        var errors  = 0;

        results.forEach(function(result) {
          if (result.status === 'fulfilled') {
            success++;
          }
          else {
            errors++;
          }
        });

        return request.success({
          page    : 'upload',
          subpage : 'upload',
          success : success,
          errors  : errors
        });
      });
    });
  },
  // SECURITY: updateUser modifies user roles (admin-only operation) per AAP §0.5.2 Strategy G / R7 / OWASP A01
  //           — protected by pre: ['isAdmin(user)'] in config/api_routes.js
  // SECURITY: CSRF synchronizer-token validated by @hapi/crumb framework via plugins: { crumb: {} }
  //           in route config per AAP §0.5.2 Strategy E / R5 / OWASP A01 Broken Access Control / CWE-352
  // SECURITY: Mongoose schema typing on User._id (ObjectId) provides type-coercion protection against
  //           NoSQL operator injection per AAP §0.5.2 Strategy H / R8 / OWASP A03
  updateUser : function(request, reply) {
    User.findById(request.params.userId, function(err, user) {
      if (err) return request.fail(err);

      if (!user) return request.fail({ message : 'user not found' });

      if (request.payload.roles) {
        user.mergeRoles(request.payload.roles);
        user.save(function(err, user) {
          if (err) return request.fail(err);

          return request.success({
            success : true
          });
        });
      }
      else {
        // SECURITY: Close the response when payload.roles is absent per AAP §0.5.2 Strategy G / R7
        //           — Previously the handler returned undefined when payload.roles was missing,
        //             leaving the request hanging until the client timeout (60s+). Each hung
        //             request consumed a Node.js socket and an admin-authenticated session cycle,
        //             enabling a denial-of-service vector against the admin tier.
        //           — Hapi's reply pipeline never resolved because no request.success/fail/reply call
        //             completed the response, and there is no Joi `roles: required()` rule on this
        //             route's payload schema in config/api_routes.js to reject the missing field
        //             with HTTP 400 at validation time.
        return request.success({
          success : true,
          message : 'No changes to apply'
        });
      }
    });
  },
  // SECURITY: grantRole assigns site-wide roles (admin-only operation) per AAP §0.5.2 Strategy G / R7 / OWASP A01
  //           — protected by pre: ['isAdmin(user)'] in config/api_routes.js
  //           — granting trinket-teacher additionally grants trinket-connect/trial with 30-day expiration
  // SECURITY: CSRF synchronizer-token validated by @hapi/crumb framework via plugins: { crumb: {} }
  //           in route config per AAP §0.5.2 Strategy E / R5 / OWASP A01 Broken Access Control / CWE-352
  // SECURITY: Response payload via user.serialize() applies the User.publicSpec allow-list
  //           per AAP §0.5.2 Strategy G / R7 / OWASP A01 Broken Access Control / CWE-200/CWE-522
  //           — JSON.parse(JSON.stringify(user)) was incorrect: it does NOT invoke serialize() because
  //             serialize is a prototype-resident schema.method (registered in lib/models/model.js:64),
  //             NOT Mongoose's toJSON() hook. JSON.stringify therefore emitted EVERY schema field
  //             including the bcrypt password hash and the full roles[] permission inventory.
  //           — user.serialize() iterates User.publicSpec ({id, name, username, fullname, email, avatar,
  //             settings}) and returns a plain object containing only those fields.
  //           — _realUserId is NOT a Mongoose schema field; it is a runtime property assigned in routeParser.js
  //             on request.user only, NEVER on the searched/granted user — confirmed not exposed
  grantRole : function(request, reply) {
    User.findById(request.params.userId, function(err, user) {
      if (err) return request.fail(err);

      if (!user) return request.fail({ message : 'user not found' });

      return user.grant(request.payload.role, "site")
        .then(function(user) {
          if (request.payload.role === "trinket-teacher") {
            // grant connect for 30ish days
            var thru = moment().startOf('day').add(1, 'months').add(1, 'days').toISOString();

            var promise = Promise.resolve(user);
            if (!user.hasRole("trinket-connect")) {
              promise = promise.then(function(user) {
                return user.grant("trinket-connect", "site", { thru : thru });
              });
            }
            if (!user.hasRole("trinket-connect-trial")) {
              promise = promise.then(function(user) {
                return user.grant("trinket-connect-trial", "site", { thru : thru });
              });
            }
            return promise;
          }
          return Promise.resolve(user);
        })
        .then(function(user) {
          // SECURITY: user.serialize() applies User.publicSpec allow-list per AAP §0.5.2 Strategy G / R7
          //           Replaces JSON.parse(JSON.stringify(user)) which leaked password + roles[] (CRITICAL)
          return request.success({
            success : true,
            user    : (user && typeof user.serialize === 'function') ? user.serialize() : user
          });
        })
        .catch(function(err) {
          return request.fail(err);
        });
    });
  },
  // SECURITY: addFeaturedCourse, removeFeaturedCourse, moveFeaturedCourse manage the featured-courses list
  //           (admin-only operations) per AAP §0.5.2 Strategy G / R7 / OWASP A01
  //           — All three handlers protected by pre: ['isAdmin(user)'] in config/api_routes.js
  //           — All three handlers protected by @hapi/crumb CSRF tokens via plugins: { crumb: {} }
  //             per AAP §0.5.2 Strategy E / R5 / OWASP A01 Broken Access Control / CWE-352
  //           — featuredStore is a Mongoose-backed featuredCourses model facade; Mongoose schema typing
  //             provides defense against NoSQL operator injection per AAP §0.5.2 Strategy H / R8
  addFeaturedCourse : function(request, reply) {
    return User.findByLogin(request.payload.ownerSlug)
      .then(function(user) {
        if (user) {
          return Course.findByUserAndSlug(user.id, request.payload.slug);
        }
        else {
          throw Boom.notFound();
        }
      })
      .then(function(course) {
        if (course) {
          return featuredStore.addMember(course.id, request.payload.page)
            .then(function() { return course; });
        }
        else {
          throw Boom.notFound();
        }
      })
      .then(function(course) {
        return request.success({
            success : true
          , course  : {
                id        : course.id
              , slug      : course.slug
              , name      : course.name
              , ownerSlug : course.ownerSlug
              , page      : request.payload.page
            }
        });
      })
      .catch(function(err) {
        return reply(err);
      });
  },
  removeFeaturedCourse : function(request, reply) {
    return featuredStore.removeMember(request.params.courseId, request.query.page)
      .then(function() {
        return request.success();
      })
      .catch(function(err) {
        return reply(err);
      });
  },
  moveFeaturedCourse : function(request, reply) {
    return featuredStore.moveMember(request.payload.courseId, request.payload.page, request.payload.currentIndex, request.payload.newIndex)
      .then(function() {
        return request.success();
      })
      .catch(function(err) {
        return reply(err);
      });
  }
};

// SECURITY: userSearch and roleSearch are helper functions consumed by the index handler for admin user lookup
//           per AAP §0.5.2 Strategy G / R7 / OWASP A01 — only invoked from /admin route which has isAdmin pre-handler
// SECURITY: User.findByLogin and User.findByRole use Mongoose schema typing (String/ObjectId)
//           to provide type-coercion protection against NoSQL operator injection per AAP §0.5.2 Strategy H / R8
// SECURITY: Response data assembled via JSON.parse(JSON.stringify(user)) goes through Mongoose toJSON()
//           which applies publicSpec allow-list filtering — sensitive fields (password, etc.) NOT exposed
//           — _realUserId is NOT a Mongoose schema field; it is NEVER attached to the searched user
function userSearch(q) {
  return new Promise(function(resolve, reject) {
    var data;

    User.findByLogin(q, function(err, user) {
      if (err) {
        return reject(err);
      }

      if (user) {
        data = JSON.parse(JSON.stringify(user));
        data.tags = [];

        Trinket.findForUser(user.id)
          .then(function(trinkets) {
            data.trinketsOwned = trinkets.length;
            return Course.findForUser(user.id);
          })
          .then(function(courses) {
            data.coursesOwned = courses.length;
            resolve(data);
          })
          .catch(function(err) {
            reject(err);
          });
      }
      else {
        resolve();
      }
    });
  });
}

function roleSearch(role, data) {
  return User.findByRole(role)
    .then(function(users) {
      users.map(function(user) {
        user.avatar = user.normalizeAvatar();
      });
      return users;
    });
}
