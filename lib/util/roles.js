// SECURITY: AES role-payload encryption interface FROZEN per AAP §0.9.2 ("Must Remain
//           Unchanged" — `lib/util/roles.js` AES role-payload encryption interface:
//           encrypt/decrypt contract consumed by `lib/models/plugins/roles.js`).
//           This module exposes a single `encrypt(obj)` function used to produce
//           role-context tokens for the Mongoose `roles` plugin (see
//           lib/models/plugins/roles.js). The wire format is `<token-hex>+<aes-base64>`
//           where the per-payload random token is both the AES key (passed to
//           CryptoJS.AES.encrypt) and the public prefix used at decrypt-time.
//
//           Per AAP §0.5.3 / Minimal Change Clause: node-cryptojs-aes@^0.4.0 is
//           retained as the AES implementation despite library age. Replacement was
//           explicitly evaluated and rejected (see AAP §0.5.3 — "node-cryptojs-aes
//           replacement: HIGH migration complexity; frozen interface per user
//           directive; reject replacement; audit for CVEs only"). No CVE in
//           node-cryptojs-aes@^0.4.0 was identified as Critical/High by the
//           Phase 1 npm audit / Snyk Vulnerability DB scan; therefore no upgrade is
//           triggered under the discovery-discipline directive (Critical/High only).
//
//           Annotation-only change per CP4 review remediation (Finding #4 / MINOR):
//           no functional change to the encrypt() implementation. The interface
//           contract — `encrypt(obj) -> '<token-hex>+<aes-base64>'` consumed by the
//           role-context decryption path in lib/models/plugins/roles.js — is preserved.
var crypto   = require('crypto')
  , CryptoJS = require('node-cryptojs-aes').CryptoJS;

module.exports = {
  // SECURITY: encrypt() is the FROZEN export per AAP §0.9.2. Random 16-byte token
  //           (crypto.randomBytes — CSPRNG) doubles as the AES symmetric key; the
  //           returned string format `<token-hex>+<aes-base64>` is contract-stable.
  //           Annotation-only per CP4 review.
  encrypt : function(obj) {
    if (typeof obj === 'object') {
      obj = JSON.stringify(obj);
    }

    var token     = crypto.randomBytes(16).toString('hex');
    var encrypted = CryptoJS.AES.encrypt(obj, token).toString();

    return token + '+' + encrypted;
  }
}
