module.exports = {
  // string interpolation:
  // e.g. interpolate('my name is {name}', {name:'ben'})
  interpolate : function(string, values) {
    return string.replace(
      /{([^{}]*)}/g,
      function (a, b) {
        var r    = values;
        var path = b.split('.');
        while(path.length && r !== undefined && r !== null) {
          r = r[path.shift()];
        }

        if (r !== undefined && r !== null && r.toString) {
          r = r.toString();
        }

        return typeof r === 'string' || typeof r === 'number' ? r : a;
      }
    );
  },

  addPrefix : function(string, prefixes, key) {
    // SECURITY: skip cache-prefixing for absolute external URLs.
    //
    // The original regex /^\/\// only matched protocol-relative URLs
    // (`//cdnjs.cloudflare.com/...`). When the security remediation
    // converted those CDN references to explicit `https://` URLs (to
    // satisfy the CSP under both HTTP development and HTTPS production —
    // the CSP whitelist `https://cdnjs.cloudflare.com` does not match the
    // protocol-relative form on an HTTP page), the regex no longer
    // recognized them as external, and the cache-prefix logic below
    // produced corrupted URLs of the form `/cache-prefix-XXX + https://
    // cdnjs.cloudflare.com/...`. Expanding the regex to also match
    // `http://` and `https://` prefixes preserves the original intent
    // (do not cache-prefix absolute external URLs) while supporting the
    // explicit-https form required by the security CSP.
    if (!/^(https?:)?\/\//.test(string)) {
      var path = string.split('/');
      key = key || path[1];
      if (prefixes[ key ]) {
        string = '/' + prefixes[ key ] + string;
      }
      else {
        string = '/cache-prefix-' + Date.now() + string;
      }
    }

    return string;
  }
};
