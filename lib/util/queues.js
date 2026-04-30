// SECURITY: Queue factory provides graceful degradation per AAP §0.8.3 user directive:
//   - Redis configured        → bull v4.x backed queue (per AAP §0.5.3 / R1; package.json: bull@^4.x)
//   - Redis absent            → InMemoryQueue (frozen interface per user "Must Remain Unchanged")
//   - Disabled-list match     → NoOpQueue (frozen interface per user "Must Remain Unchanged")
// All three implementations expose: add, process, on('error'/'failed'/'completed'), close
// Per AAP §0.5.3: bull v0.7 EOL → v4.x upgrade preserves InMemoryQueue/NoOpQueue fallback contract
var config = require('config');

// SECURITY: Redis enablement check; graceful degradation falls back to InMemoryQueue when Redis is unconfigured
//           per AAP §0.8.3 user directive: "Redis absent → InMemoryQueue"
// Check if Redis is enabled
var redisEnabled = config.db && config.db.redis && config.db.redis.enabled !== false;

// SECURITY: InMemoryQueue interface FROZEN per user "Must Remain Unchanged"
//           Preserves Bull-compatible API surface: add(data, opts), process(handler), on(event, handler), close()
//           Used when Redis is unavailable per AAP §0.8.3 graceful degradation directive
//           DO NOT modify class methods or constructor signature
// In-memory queue implementation for when Redis is not available
function InMemoryQueue(name) {
  this.name = name;
  this.handlers = [];
  this.processing = false;
  this.jobs = [];
}

InMemoryQueue.prototype.process = function(handler) {
  this.handlers.push(handler);
};

InMemoryQueue.prototype.add = function(data, opts) {
  var self = this;
  var job = {
    id: Date.now() + '-' + Math.random().toString(36).substr(2, 9),
    data: data,
    opts: opts || {},
    attempts: 0
  };

  // Process immediately in next tick (simulates async queue behavior)
  setImmediate(function() {
    self._processJob(job);
  });

  return Promise.resolve(job);
};

InMemoryQueue.prototype._processJob = function(job) {
  var self = this;

  if (this.handlers.length === 0) {
    // No handlers registered, job is essentially dropped
    // This is fine for optional features like analytics/events
    return;
  }

  // Call all handlers
  this.handlers.forEach(function(handler) {
    try {
      var result = handler(job, function done(err) {
        if (err) {
          console.log('InMemoryQueue [' + self.name + '] job failed:', err.message);
        }
      });

      // Handle promise-based handlers
      if (result && typeof result.catch === 'function') {
        result.catch(function(err) {
          console.log('InMemoryQueue [' + self.name + '] job failed:', err.message);
        });
      }
    } catch (err) {
      console.log('InMemoryQueue [' + self.name + '] job error:', err.message);
    }
  });
};

InMemoryQueue.prototype.on = function(event, handler) {
  // No-op for compatibility - in-memory queue doesn't emit events
  return this;
};

InMemoryQueue.prototype.close = function() {
  return Promise.resolve();
};

// SECURITY: NoOpQueue interface FROZEN per user "Must Remain Unchanged"
//           Used for disabled-list queues; provides Bull-compatible no-op API surface
//           DO NOT modify class methods or constructor signature
// No-op queue for features that are disabled
function NoOpQueue(name) {
  this.name = name;
}

NoOpQueue.prototype.process = function() {};
NoOpQueue.prototype.add = function() { return Promise.resolve({ id: 'noop' }); };
NoOpQueue.prototype.on = function() { return this; };
NoOpQueue.prototype.close = function() { return Promise.resolve(); };

// Queue cache
var cache = {};

// SECURITY: disabledQueues list selects NoOpQueue path per AAP "Must Remain Unchanged" frozen contract
//           Operators may extend this list; queues in this list never reach Bull/Redis or InMemoryQueue
// List of queues that should be completely disabled (no-op)
var disabledQueues = ['receipts', 'reports', 'containers', 'notifier', 'events', 'snapshots', 'courses', 'trinkets', 'folders'];

// SECURITY: Queue factory selects Bull/InMemoryQueue/NoOpQueue per AAP §0.8.3 graceful degradation
//           Cache prevents duplicate queue construction (preserves Bull connection pool semantics)
// Create queue factory
function createQueue(name) {
  if (cache[name]) {
    return cache[name];
  }

  // SECURITY: Disabled-list path selects NoOpQueue (frozen contract per AAP)
  // Check if this queue is disabled
  if (disabledQueues.indexOf(name) >= 0) {
    console.log('Queue [' + name + '] is disabled, using no-op queue');
    cache[name] = new NoOpQueue(name);
    return cache[name];
  }

  // Use Bull if Redis is enabled
  if (redisEnabled) {
    // SECURITY: bull v4.x options-object API per AAP §0.5.3 / R1
    //           v0.7 string-URL signature `new Queue(name, redisUrl)` is NOT used (already v4-compatible)
    //           Per AAP §0.4.3: bull v0.7 EOL upgraded to v4.x for security patches
    var Queue = require('bull');
    var queueConfig = config.db.redis[name] || config.db.redis.app;
    var opts = {};

    if (queueConfig.password) {
      opts.redis = {
        host: queueConfig.host,
        port: queueConfig.port,
        password: queueConfig.password
      };
    } else {
      opts.redis = {
        host: queueConfig.host,
        port: queueConfig.port
      };
    }

    cache[name] = new Queue(name, opts);
    console.log('Queue [' + name + '] using Bull with Redis');
  } else {
    // SECURITY: InMemoryQueue fallback per AAP §0.8.3 user directive: "Redis absent → InMemoryQueue"
    // Use in-memory queue
    cache[name] = new InMemoryQueue(name);
    console.log('Queue [' + name + '] using in-memory queue (Redis not configured)');
  }

  return cache[name];
}

// Export queue getters for each queue type
var bullqueues = config.db && config.db.redis && config.db.redis.bullqueues
  ? config.db.redis.bullqueues
  : ['exports'];

bullqueues.forEach(function(queueName) {
  module.exports[queueName] = function() {
    return createQueue(queueName);
  };
});

// Export utilities
module.exports.isRedisEnabled = function() {
  return redisEnabled;
};

module.exports.closeAll = function() {
  var promises = Object.keys(cache).map(function(name) {
    return cache[name].close();
  });
  return Promise.all(promises);
};
