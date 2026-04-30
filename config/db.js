var mongoose = require('mongoose'),
    // mongoose-schema-extend is deprecated but still used by lib/models/model.js
    // TODO: Migrate to native mongoose discriminators
    extend   = require('mongoose-schema-extend'),
    dbconfig = require('config').db;

// SECURITY: mongoose upgraded to latest v6.x patched version per AAP §0.7.1 / §0.4.2
// (v7+ migration deferred per Mongoose plugin chain frozen — roles, slug, timestamps, ownable,
//  paginate, orderedList, isChanged plugins consumed by lib/models/plugins/* must remain compatible)
// SECURITY: mongoose-schema-extend ~0.2.2 FROZEN per AAP §0.7.1 — flagged deprecated, ADR-8 tech debt
// (documented as residual risk per AAP §0.7.1; if Node 20 surfaces incompatibility, blocks migration
//  per AAP Risk Management mitigation — escalate as ADR-8 blocker before merging)
// SECURITY: Connection string built from config.db.mongo (host/port/database/user/pass)
// — credentials sourced from config/local.yaml per AAP §0.7.3 (never environment variables)
// SECURITY: Mongoose schema typing provides defense-in-depth against NoSQL operator injection
// per AAP §0.5.2 Strategy H / R8 / OWASP A03 — string fields reject objects, ObjectId fields
// reject non-hex inputs, etc. (Joi validation in config/api_routes.js is the first defense)

var mongo_creds = dbconfig.mongo.user && dbconfig.mongo.pass
  ? dbconfig.mongo.user + ':' + dbconfig.mongo.pass + '@' : '';

var read_creds = dbconfig.mongoread.user && dbconfig.mongoread.pass
  ? dbconfig.mongoread.user + ':' + dbconfig.mongoread.pass + '@' : '';

function connect() {
  var connectStr = 'mongodb://'
    + mongo_creds
    + dbconfig.mongo.host + ':'
    + dbconfig.mongo.port + '/'
    + dbconfig.mongo.database;

  if (dbconfig.mongoread.host) {
    connectStr += ','
    + read_creds
    + dbconfig.mongoread.host + ':'
    + dbconfig.mongoread.port + '/'
    + dbconfig.mongoread.database;

    if (dbconfig.mongoread.opts) {
      connectStr += '?' + dbconfig.mongoread.opts;
    }
  }

  mongoose.connect(connectStr);
}

connect();

module.exports = {
  connect : connect
};
