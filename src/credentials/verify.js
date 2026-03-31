// src/credentials/verify.js
const { canonicalize } = require('../util/canonical-json');
const { verify } = require('../crypto/keys');

function verifyCredential(vc, issuerPublicKey) {
  if (!vc.proof || !vc.proof.jws) {
    return { valid: false, reason: 'Missing proof' };
  }

  const { proof, ...unsignedVc } = vc;
  const payload = Buffer.from(canonicalize(unsignedVc));
  const signature = Buffer.from(proof.jws, 'base64url');

  const ok = verify(payload, signature, issuerPublicKey);
  return { valid: ok, reason: ok ? 'Signature valid' : 'Signature invalid' };
}

module.exports = { verifyCredential };