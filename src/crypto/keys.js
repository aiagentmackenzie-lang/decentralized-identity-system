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

function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { mode: 0o700, recursive: true });
  }
}

function saveKeyPair(baseDir, did, keyPair) {
  const dir = path.join(baseDir, did.replace(/:/g, '_'));
  ensureDir(dir);

  fs.writeFileSync(path.join(dir, 'public.key'), keyPair.publicKey);
  fs.writeFileSync(path.join(dir, 'private.key'), keyPair.privateKey, { mode: 0o600 });
}

function loadKeyPair(baseDir, did) {
  const dir = path.join(baseDir, did.replace(/:/g, '_'));
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