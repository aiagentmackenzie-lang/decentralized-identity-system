/**
 * Decentralized Identity System (DID) - Library Entry Point
 * 
 * This module exports the core functionality of the DID system for programmatic use.
 * All operations available via CLI are also available via this API.
 * 
 * @module did-system
 * @example
 * const { createDid, issueCredential, verifyCredential } = require('./src');
 * 
 * // Create a DID
 * const { did, keyPair } = createDid();
 * 
 * // Issue a credential
 * const vc = issueCredential({
 *   issuerDid: did,
 *   subjectDid: 'did:demo:...',
 *   subjectClaims: { role: 'admin' },
 *   issuerPublicKeyId: `${did}#key-1`,
 *   issuerPrivateKey: keyPair.privateKey
 * });
 * 
 * // Verify the credential
 * const result = verifyCredential(vc, keyPair.publicKey);
 * console.log(result.valid); // true
 */

// Cryptographic primitives
const { generateKeyPair, sign, verify, saveKeyPair, loadKeyPair } = require('./crypto/keys');

// Identity operations
const { publicKeyToDid, buildDidDocument, DID_METHOD } = require('./identity/did');

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
  /**
   * Generate an Ed25519 key pair
   * @returns {Object} { publicKey: Buffer, privateKey: Buffer }
   */
  generateKeyPair,
  
  /**
   * Sign a payload with a private key
   * @param {Buffer} payload - Data to sign
   * @param {Buffer} privateKey - DER-encoded private key
   * @returns {Buffer} Signature
   */
  sign,
  
  /**
   * Verify a signature
   * @param {Buffer} payload - Original data
   * @param {Buffer} signature - Signature to verify
   * @param {Buffer} publicKey - DER-encoded public key
   * @returns {boolean} True if valid
   */
  verify,
  
  /**
   * Save a key pair to disk
   * @param {string} baseDir - Base directory for storage
   * @param {string} did - DID to associate with keys
   * @param {Object} keyPair - { publicKey, privateKey } buffers
   */
  saveKeyPair,
  
  /**
   * Load a key pair from disk
   * @param {string} baseDir - Base directory for storage
   * @param {string} did - DID to load keys for
   * @returns {Object} { publicKey: Buffer, privateKey: Buffer }
   */
  loadKeyPair,

  // Identity
  /**
   * Convert a public key to a DID
   * @param {Buffer} publicKey - DER-encoded public key
   * @returns {string} DID (did:demo:...)
   */
  publicKeyToDid,
  
  /**
   * Build a DID document
   * @param {string} did - The DID
   * @param {string} publicKeyMultibase - Multibase-encoded public key
   * @returns {Object} DID Document
   */
  buildDidDocument,
  
  /**
   * The DID method used by this implementation
   * @type {string}
   */
  DID_METHOD,

  // Credentials
  /**
   * Issue a verifiable credential
   * @param {Object} options - Credential options
   * @param {string} options.issuerDid - Issuer's DID
   * @param {string} options.subjectDid - Subject's DID
   * @param {Object} options.subjectClaims - Claims about the subject
   * @param {string} options.issuerPublicKeyId - Verification method ID
   * @param {Buffer} options.issuerPrivateKey - Issuer's private key
   * @returns {Object} Verifiable Credential with embedded proof
   */
  issueCredential,
  
  /**
   * Verify a credential's signature
   * @param {Object} vc - Verifiable Credential
   * @param {Buffer} issuerPublicKey - Issuer's public key
   * @returns {Object} { valid: boolean, reason: string }
   */
  verifyCredential,

  // Wallet
  /**
   * Create a new DID and store it in the wallet
   * @returns {Object} { did: string, publicKey: string, keyPair: { publicKey, privateKey } }
   */
  createDid,
  
  /**
   * Get keys for a DID from the wallet
   * @param {string} did - The DID
   * @returns {Object} { publicKey: Buffer, privateKey: Buffer }
   */
  getDidKeys,
  
  /**
   * List all DIDs in the wallet
   * @returns {Array} Array of DID metadata objects
   */
  listDids,
  
  /**
   * Store a credential in the wallet
   * @param {Object} credential - The credential to store
   * @returns {string} Credential ID (UUID)
   */
  storeCredential,
  
  /**
   * Get a credential by ID
   * @param {string} credentialId - The credential ID
   * @returns {Object|null} The credential or null if not found
   */
  getCredential,
  
  /**
   * Get credential with metadata
   * @param {string} credentialId - The credential ID
   * @returns {Object|null} Full credential object with metadata
   */
  getCredentialWithMetadata,
  
  /**
   * List all credentials in the wallet
   * @returns {Array} Array of stored credentials with metadata
   */
  listCredentials,
  
  /**
   * List credentials for a specific subject
   * @param {string} subjectDid - The subject's DID
   * @returns {Array} Matching credentials
   */
  listCredentialsForSubject,
  
  /**
   * Delete a credential
   * @param {string} credentialId - The credential ID
   * @returns {boolean} True if deleted, false if not found
   */
  deleteCredential,
  
  /**
   * Get wallet status
   * @returns {Object} { walletDir: string, didCount: number, credentialCount: number }
   */
  getWalletStatus,

  // Utilities
  /**
   * Canonicalize an object for deterministic JSON serialization
   * @param {Object} obj - Object to canonicalize
   * @returns {string} Canonical JSON string
   */
  canonicalize
};