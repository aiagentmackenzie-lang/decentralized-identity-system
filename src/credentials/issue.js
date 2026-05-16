// src/credentials/issue.js
const { canonicalize } = require('../util/canonical-json');
const { sign } = require('../crypto/keys');
const { validateDid } = require('../identity/did');

/**
 * Issue a Verifiable Credential with an embedded Ed25519 proof.
 *
 * @param {Object} options
 * @param {string} options.issuerDid - Issuer's DID (required, must be valid did:demo format)
 * @param {string} options.subjectDid - Subject's DID (required, must be valid did:demo format)
 * @param {Object} options.subjectClaims - Claims about the subject (required, must be plain object)
 * @param {string} options.issuerPublicKeyId - Verification method ID (required)
 * @param {Buffer} options.issuerPrivateKey - Issuer's private key DER buffer (required)
 * @param {string} [options.expirationDate] - ISO 8601 date when credential expires (optional)
 * @returns {Object} Verifiable Credential with embedded proof
 * @throws {Error} If required parameters are missing or invalid
 */
function issueCredential({
  issuerDid,
  subjectDid,
  subjectClaims,
  issuerPublicKeyId,
  issuerPrivateKey,
  expirationDate
}) {
  // FIX M2: Comprehensive input validation
  if (!issuerDid || typeof issuerDid !== 'string') {
    throw new Error('issueCredential: issuerDid is required and must be a string');
  }
  if (!subjectDid || typeof subjectDid !== 'string') {
    throw new Error('issueCredential: subjectDid is required and must be a string');
  }
  if (!subjectClaims || typeof subjectClaims !== 'object' || Array.isArray(subjectClaims)) {
    throw new Error('issueCredential: subjectClaims is required and must be a plain object');
  }
  if (!issuerPublicKeyId || typeof issuerPublicKeyId !== 'string') {
    throw new Error('issueCredential: issuerPublicKeyId is required and must be a string');
  }
  if (!Buffer.isBuffer(issuerPrivateKey)) {
    throw new Error('issueCredential: issuerPrivateKey is required and must be a Buffer');
  }

  // Validate DID formats (prevents path traversal and malformed DIDs)
  validateDid(issuerDid);
  validateDid(subjectDid);

  // Validate expirationDate if provided
  if (expirationDate !== undefined) {
    if (typeof expirationDate !== 'string') {
      throw new Error('issueCredential: expirationDate must be an ISO 8601 string');
    }
    const parsed = new Date(expirationDate);
    if (isNaN(parsed.getTime())) {
      throw new Error('issueCredential: expirationDate is not a valid ISO 8601 date');
    }
  }

  const now = new Date().toISOString();

  const vc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'CustomCredential'],
    issuer: issuerDid,
    issuanceDate: now,
    credentialSubject: {
      id: subjectDid,
      ...subjectClaims
    }
  };

  // FIX M4: Support optional expirationDate
  if (expirationDate) {
    vc.expirationDate = expirationDate;
  }

  const payload = Buffer.from(canonicalize(vc));
  const signature = sign(payload, issuerPrivateKey);

  vc.proof = {
    type: 'Ed25519Signature2020',
    created: now,
    verificationMethod: issuerPublicKeyId,
    proofPurpose: 'assertionMethod',
    jws: signature.toString('base64url')
  };

  return vc;
}

module.exports = { issueCredential };