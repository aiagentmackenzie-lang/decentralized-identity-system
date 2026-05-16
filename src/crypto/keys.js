// src/crypto/keys.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEY_ALGO = 'ed25519'; // Ed25519 for signatures

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync(KEY_ALGO, {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });

  return {
    publicKey,
    privateKey
  };
}

function sign(payloadBuffer, privateKeyDer) {
  return crypto.sign(null, payloadBuffer, {
    key: privateKeyDer,
    format: 'der',
    type: 'pkcs8'
  });
}

function verify(payloadBuffer, signature, publicKeyDer) {
  return crypto.verify(null, payloadBuffer, {
    key: publicKeyDer,
    format: 'der',
    type: 'spki'
  }, signature);
}

function ensureDir(dirPath, mode = 0o700) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { mode, recursive: true });
  } else {
    // Verify/fix permissions on existing directory for defense-in-depth
    try {
      const stats = fs.statSync(dirPath);
      if ((stats.mode & 0o777) !== mode) {
        fs.chmodSync(dirPath, mode);
      }
    } catch {
      // If we can't check/fix permissions, continue — may be read-only FS
    }
  }
}

/**
 * Sanitize a DID for use as a directory name and validate against path traversal.
 * Delegates to identity/did.js for validation, but includes a local safety check
 * to prevent path traversal even if DID validation is bypassed.
 * @param {string} did - DID to sanitize
 * @returns {string} Safe directory name
 * @throws {Error} If DID contains dangerous path characters
 */
function sanitizeDidForPath(did) {
  // Local safety check — always enforced even if upstream validation is missing
  if (typeof did !== 'string' || did.includes('/') || did.includes('..')) {
    throw new Error(`Security: DID contains path traversal characters: "${did}"`);
  }
  const safeName = did.replace(/:/g, '_');
  // Verify the resolved path stays within the base directory after join
  return safeName;
}

function saveKeyPair(baseDir, did, keyPair) {
  const dirName = sanitizeDidForPath(did);
  const dir = path.join(baseDir, dirName);

  // Verify path containment
  const resolvedDir = path.resolve(dir);
  const resolvedBase = path.resolve(baseDir);
  if (!resolvedDir.startsWith(resolvedBase + path.sep) && resolvedDir !== resolvedBase) {
    throw new Error(`Security: resolved path escapes wallet directory: "${resolvedDir}"`);
  }

  ensureDir(dir);

  // FIX L1: Public key now also gets explicit restricted permissions
  fs.writeFileSync(path.join(dir, 'public.key'), keyPair.publicKey, { mode: 0o600 });
  // Private key with strict permissions
  fs.writeFileSync(path.join(dir, 'private.key'), keyPair.privateKey, { mode: 0o600 });
}

function loadKeyPair(baseDir, did) {
  const dirName = sanitizeDidForPath(did);
  const dir = path.join(baseDir, dirName);

  // Verify path containment
  const resolvedDir = path.resolve(dir);
  const resolvedBase = path.resolve(baseDir);
  if (!resolvedDir.startsWith(resolvedBase + path.sep) && resolvedDir !== resolvedBase) {
    throw new Error(`Security: resolved path escapes wallet directory: "${resolvedDir}"`);
  }

  const publicKey = fs.readFileSync(path.join(dir, 'public.key'));
  const privateKey = fs.readFileSync(path.join(dir, 'private.key'));
  return { publicKey, privateKey };
}

module.exports = {
  KEY_ALGO,
  generateKeyPair,
  sign,
  verify,
  saveKeyPair,
  loadKeyPair
};