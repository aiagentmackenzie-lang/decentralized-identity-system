// src/wallet/store.js
const fs = require('fs');
const path = require('path');

const WALLET_DIR = process.env.DID_WALLET_DIR || path.join(process.cwd(), '.did-wallet');

function ensureWalletDir() {
  if (!fs.existsSync(WALLET_DIR)) {
    fs.mkdirSync(WALLET_DIR, { mode: 0o700, recursive: true });
  }
}

function walletPath(filename) {
  ensureWalletDir();
  return path.join(WALLET_DIR, filename);
}

function saveJson(filename, data) {
  const p = walletPath(filename);
  fs.writeFileSync(p, JSON.stringify(data, null, 2));
}

function loadJson(filename) {
  const p = walletPath(filename);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

module.exports = {
  WALLET_DIR,
  saveJson,
  loadJson
};