// src/wallet/store.js
const fs = require('fs');
const path = require('path');

const WALLET_DIR = process.env.DID_WALLET_DIR || path.join(process.cwd(), '.did-wallet');

function ensureWalletDir() {
  if (!fs.existsSync(WALLET_DIR)) {
    fs.mkdirSync(WALLET_DIR, { mode: 0o700, recursive: true });
  } else {
    // Defense-in-depth: verify/fix directory permissions
    try {
      const stats = fs.statSync(WALLET_DIR);
      if ((stats.mode & 0o777) !== 0o700) {
        fs.chmodSync(WALLET_DIR, 0o700);
      }
    } catch {
      // If we can't fix permissions, continue
    }
  }
}

function walletPath(filename) {
  ensureWalletDir();
  return path.join(WALLET_DIR, filename);
}

// FIX S2: All wallet files now written with 0o600 to prevent world-readable credential exposure
function saveJson(filename, data) {
  const p = walletPath(filename);
  fs.writeFileSync(p, JSON.stringify(data, null, 2), { mode: 0o600 });
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