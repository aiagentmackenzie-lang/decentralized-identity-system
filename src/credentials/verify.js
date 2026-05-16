// src/credentials/verify.js
const { canonicalize } = require('../util/canonical-json');
const { verify } = require('../crypto/keys');

/**
 * Verify a Verifiable Credential's signature and structural validity.
 *
 * @param {Object} vc - The verifiable credential to verify
 * @param {Buffer} issuerPublicKey - The issuer's public key (DER-encoded)
 * @returns {Object} { valid: boolean, reason: string }
 */
function verifyCredential(vc, issuerPublicKey) {
  // FIX B1: Guard against null/undefined/non-object input
  if (!vc || typeof vc !== 'object' || Array.isArray(vc)) {
    return { valid: false, reason: 'Invalid credential: must be a non-null object' };
  }

  // Check proof exists
  if (!vc.proof || !vc.proof.jws) {
    return { valid: false, reason: 'Missing proof' };
  }

  // FIX M3: Structural validation of required W3C VC fields
  if (!vc['@context']) {
    return { valid: false, reason: 'Missing @context field' };
  }
  if (!vc.type || !Array.isArray(vc.type) || !vc.type.includes('VerifiableCredential')) {
    return { valid: false, reason: 'Missing or invalid type: must include VerifiableCredential' };
  }
  if (!vc.issuer || (typeof vc.issuer !== 'string' && (typeof vc.issuer !== 'object' || !vc.issuer.id))) {
    return { valid: false, reason: 'Missing or invalid issuer field' };
  }
  if (!vc.issuanceDate) {
    return { valid: false, reason: 'Missing issuanceDate field' };
  }
  if (!vc.credentialSubject || typeof vc.credentialSubject !== 'object') {
    return { valid: false, reason: 'Missing or invalid credentialSubject field' };
  }

  // FIX M4: Check expiration if present
  if (vc.expirationDate) {
    const expiry = new Date(vc.expirationDate);
    if (!isNaN(expiry.getTime()) && expiry <= new Date()) {
      return { valid: false, reason: `Credential expired on ${vc.expirationDate}` };
    }
  }

  // Verify signature
  const { proof, ...unsignedVc } = vc;
  const payload = Buffer.from(canonicalize(unsignedVc));
  const signature = Buffer.from(proof.jws, 'base64url');

  const ok = verify(payload, signature, issuerPublicKey);
  return { valid: ok, reason: ok ? 'Signature valid' : 'Signature invalid' };
}

module.exports = { verifyCredential };