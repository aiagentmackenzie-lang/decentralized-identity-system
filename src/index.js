/**
 * Decentralized Identity System (DID) - Library Entry Point
 * 
 * This module exports the core functionality of the DID system for programmatic use.
 * All operations available via CLI are also available via this API.
 * 
 * @module did-system
 * @example
 * const { createDid, issueCredential, verifyCredential, validateDid } = require('./src');
 * 
 * // Create a DID
 * const { did, keyPair } = createDid();
 * 
 * // Issue a credential with optional expiration
 * const vc = issueCredential({
 *   issuerDid: did,
 *   subjectDid: 'did:demo:...',
 *   subjectClaims: { role: 'admin' },
 *   issuerPublicKeyId: `${did}#key-1`,
 *   issuerPrivateKey: keyPair.privateKey,
 *   expirationDate: '2025-12-31T23:59:59Z'
 * });
 * 
 * // Verify the credential
 * const result = verifyCredential(vc, keyPair.publicKey);
 * console.log(result.valid); // true
 */

// Cryptographic primitives
const { generateKeyPair, sign, verify, saveKeyPair, loadKeyPair } = require('./crypto/keys');

// Identity operations
const { publicKeyToDid, buildDidDocument, DID_METHOD, validateDid, sanitizeDidForPath } = require('./identity/did');

// Credential operations
const { issueCredential } = require('./credentials/issue');
const { verifyCredential } = require('./credentials/verify');

// Wallet operations
const {
  createDid,
  getDidKeys,
  listDids,
  storeCredential,
  getCredential,
  getCredentialWithMetadata,
  listCredentials,
  listCredentialsForSubject,
  deleteCredential,
  getWalletStatus
} = require('./wallet/wallet');

// Utility functions
const { canonicalize } = require('./util/canonical-json');

module.exports = {
  // Crypto
  generateKeyPair,
  sign,
  verify,
  saveKeyPair,
  loadKeyPair,

  // Identity
  publicKeyToDid,
  buildDidDocument,
  DID_METHOD,
  validateDid,
  sanitizeDidForPath,

  // Credentials
  issueCredential,
  verifyCredential,

  // Wallet
  createDid,
  getDidKeys,
  listDids,
  storeCredential,
  getCredential,
  getCredentialWithMetadata,
  listCredentials,
  listCredentialsForSubject,
  deleteCredential,
  getWalletStatus,

  // Utilities
  canonicalize
};