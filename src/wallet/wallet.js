// src/wallet/wallet.js
const { generateKeyPair, saveKeyPair, loadKeyPair } = require('../crypto/keys');
const { publicKeyToDid } = require('../identity/did');
const { saveJson, loadJson, WALLET_DIR } = require('./store');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const DIDS_FILE = 'dids.json';
const CREDENTIALS_FILE = 'credentials.json';

/**
 * Create a new DID with associated keypair
 * @returns {Object} { did, publicKey, keyPair }
 */
function createDid() {
  const keyPair = generateKeyPair();
  const did = publicKeyToDid(keyPair.publicKey);
  
  // Save keypair to wallet storage
  saveKeyPair(WALLET_DIR, did, keyPair);
  
  // Track DID in wallet index
  const dids = loadJson(DIDS_FILE) || [];
  dids.push({
    did,
    createdAt: new Date().toISOString()
  });
  saveJson(DIDS_FILE, dids);
  
  return {
    did,
    publicKey: keyPair.publicKey.toString('base64url'),
    keyPair
  };
}

/**
 * Get a DID's keypair from wallet storage
 * @param {string} did - The DID to retrieve keys for
 * @returns {Object} { publicKey, privateKey } buffers
 */
function getDidKeys(did) {
  return loadKeyPair(WALLET_DIR, did);
}

/**
 * List all DIDs in the wallet
 * @returns {Array} List of DIDs with metadata
 */
function listDids() {
  return loadJson(DIDS_FILE) || [];
}

/**
 * Store a credential in the wallet
 * @param {Object} credential - The verifiable credential to store
 * @returns {string} credentialId - Unique ID for the stored credential
 */
function storeCredential(credential) {
  const credentials = loadJson(CREDENTIALS_FILE) || [];
  
  // Generate unique ID for this credential
  const credentialId = crypto.randomUUID();
  
  const storedCredential = {
    id: credentialId,
    credential,
    storedAt: new Date().toISOString()
  };
  
  credentials.push(storedCredential);
  saveJson(CREDENTIALS_FILE, credentials);
  
  return credentialId;
}

/**
 * Get a credential by ID
 * @param {string} credentialId - The credential ID
 * @returns {Object|null} The credential or null if not found
 */
function getCredential(credentialId) {
  const credentials = loadJson(CREDENTIALS_FILE) || [];
  const stored = credentials.find(c => c.id === credentialId);
  return stored ? stored.credential : null;
}

/**
 * Get credential metadata by ID
 * @param {string} credentialId - The credential ID
 * @returns {Object|null} The full stored credential object with metadata
 */
function getCredentialWithMetadata(credentialId) {
  const credentials = loadJson(CREDENTIALS_FILE) || [];
  return credentials.find(c => c.id === credentialId) || null;
}

/**
 * List all credentials in the wallet
 * @returns {Array} List of credentials with metadata
 */
function listCredentials() {
  return loadJson(CREDENTIALS_FILE) || [];
}

/**
 * List credentials for a specific subject DID
 * @param {string} subjectDid - The subject DID to filter by
 * @returns {Array} List of matching credentials
 */
function listCredentialsForSubject(subjectDid) {
  const credentials = loadJson(CREDENTIALS_FILE) || [];
  return credentials.filter(c => c.credential.credentialSubject?.id === subjectDid);
}

/**
 * Delete a credential by ID
 * @param {string} credentialId - The credential ID to delete
 * @returns {boolean} True if deleted, false if not found
 */
function deleteCredential(credentialId) {
  const credentials = loadJson(CREDENTIALS_FILE) || [];
  const index = credentials.findIndex(c => c.id === credentialId);
  
  if (index === -1) return false;
  
  credentials.splice(index, 1);
  saveJson(CREDENTIALS_FILE, credentials);
  return true;
}

/**
 * Get wallet status/info
 * @returns {Object} Wallet statistics
 */
function getWalletStatus() {
  const dids = loadJson(DIDS_FILE) || [];
  const credentials = loadJson(CREDENTIALS_FILE) || [];
  
  return {
    walletDir: WALLET_DIR,
    didCount: dids.length,
    credentialCount: credentials.length
  };
}

module.exports = {
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
};