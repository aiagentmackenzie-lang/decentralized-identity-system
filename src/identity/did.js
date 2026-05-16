// src/identity/did.js
const crypto = require('crypto');

const DID_METHOD = 'did:demo';

// DID format validation regex — method-specific-id is SHA-256 hex (64 chars)
const DID_REGEX = /^did:demo:[a-f0-9]{64}$/;

/**
 * Validate a DID string format
 * Prevents path traversal by rejecting DIDs containing '/', '..', or other dangerous characters
 * @param {string} did - DID to validate
 * @throws {Error} If DID is invalid or contains dangerous characters
 */
function validateDid(did) {
  if (typeof did !== 'string' || did.length === 0) {
    throw new Error('DID must be a non-empty string');
  }

  if (did.includes('/') || did.includes('..')) {
    throw new Error(`Invalid DID: contains path traversal characters: "${did}"`);
  }

  if (!DID_REGEX.test(did)) {
    throw new Error(
      `Invalid DID format: "${did}". Expected format: did:demo:<64-char-hex-sha256>`
    );
  }
}

/**
 * Sanitize a DID for use in file paths
 * Replaces colons with underscores and validates no path traversal characters exist
 * @param {string} did - DID to sanitize
 * @returns {string} Sanitized directory name
 * @throws {Error} If DID contains dangerous characters
 */
function sanitizeDidForPath(did) {
  validateDid(did);
  return did.replace(/:/g, '_');
}

function publicKeyToDid(publicKeyDer) {
  const hash = crypto.createHash('sha256').update(publicKeyDer).digest('hex');
  return `${DID_METHOD}:${hash}`;
}

function buildDidDocument(did, publicKeyMultibase) {
  validateDid(did);
  return {
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase
      }
    ]
  };
}

module.exports = {
  DID_METHOD,
  DID_REGEX,
  validateDid,
  sanitizeDidForPath,
  publicKeyToDid,
  buildDidDocument
};