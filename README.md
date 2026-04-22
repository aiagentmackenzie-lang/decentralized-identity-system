# 🆔 Decentralized Identity System (DID)

[![Tests](https://img.shields.io/badge/tests-74%20passing-brightgreen)]()

A modern decentralized identity system that gives users cryptographic control over their identifiers and credentials, without depending on a central identity provider.

This repository is designed as a serious, security-conscious reference implementation and teaching tool for decentralized identifiers (DIDs), verifiable credentials (VCs), and zero‑trust authentication flows aligned with W3C standards.

> ⚠️ **Status:** Educational, security‑focused reference. Not audited or hardened for production. Do not use as‑is for high‑risk environments.

---

## 🚀 Features

- **Decentralized Identifiers (DIDs):** URIs that associate a subject with a DID document containing public keys and service endpoints
- **Verifiable Credentials (VCs):** Signed, tamper‑evident credentials expressing claims that an issuer makes about a subject
- **Wallet / Holder:** A local wallet process that manages keys and credentials on behalf of the user
- **Verifier:** A component that validates credentials and cryptographic proofs without ever seeing user passwords
- **CLI Interface:** Full command-line tool for DID and credential management

---

## 📋 Prerequisites

- Node.js >= 18.0.0
- npm

---

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/aiagentmackenzie-lang/decentralized-identity-system.git
cd decentralized-identity-system

# Install dependencies
npm install

# Run tests
npm test
```

---

## 💻 Usage

### Create a new DID

```bash
node src/cli/index.js did:create
```

### List all DIDs

```bash
node src/cli/index.js did:list
```

### Resolve a DID to its document

```bash
node src/cli/index.js did:resolve did:demo:YOUR_DID_HASH
```

### Issue a credential

```bash
node src/cli/index.js vc:issue \
  --issuer did:demo:ISSUER_HASH \
  --subject did:demo:SUBJECT_HASH \
  --claim role=admin \
  --claim department=engineering
```

### List stored credentials

```bash
node src/cli/index.js vc:list
```

### Verify a credential

```bash
node src/cli/index.js vc:verify --id CREDENTIAL_ID
```

### Check wallet status

```bash
node src/cli/index.js wallet:status
```

---

## 🏗️ Architecture

### Actors

- **Issuer:** Entity that issues signed verifiable credentials
- **Holder / Wallet:** Controls a DID, stores private keys locally, and manages credentials
- **Verifier:** Validates proofs and credentials against issuer public keys

### Flow

```
┌──────────────┐
│    User      │
│ (Wallet)     │
└──────┬───────┘
       │ 1. generate keypair + DID
       ▼
┌────────────────────┐
│ DID Generator      │
│ (public key → DID) │
└────────┬───────────┘
         │ 2. register / anchor (optional)
         ▼
┌────────────────────┐
│ Credential Issuer  │
│ (signs VC)         │
└────────┬───────────┘
         │ 3. send VC to wallet
         ▼
┌────────────────────┐
│ Credential Holder  │
│ (local wallet)     │
└────────┬───────────┘
         │ 4. create proof from VC
         ▼
┌────────────────────┐
│ Verifier           │
│ (check signature)  │
└────────────────────┘
```

---

## 📁 Project Structure

```
did-system/
├── src/
│   ├── crypto/
│   │   └── keys.js           # Key generation, sign, verify
│   ├── identity/
│   │   └── did.js            # DID + DID document helpers
│   ├── credentials/
│   │   ├── issue.js          # VC issuance
│   │   └── verify.js         # VC verification
│   ├── wallet/
│   │   ├── store.js          # Secure local storage
│   │   └── wallet.js         # High-level wallet API
│   ├── cli/
│   │   └── index.js          # CLI entrypoint
│   └── util/
│       └── canonical-json.js # Deterministic JSON serialization
├── tests/
│   ├── crypto/
│   ├── identity/
│   ├── credentials/
│   ├── wallet/
│   └── cli/
└── package.json
```

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch
```

All 74 tests covering:
- Key generation, signing, and verification
- DID creation and resolution
- Credential issuance and verification
- Wallet storage and management
- CLI argument parsing

---

## 🔐 Security

### Key Management
- **Ed25519** signatures via Node.js `crypto` module
- Private keys stored with `0o600` permissions
- Wallet directory created with `0o700` permissions
- Keys never logged or exposed

### Data Integrity
- Canonical JSON serialization before signing
- SHA-256 hashing for DID generation
- JWS (JSON Web Signature) format for proofs

---

## 🧭 Roadmap

- [x] DID document resolution (did:resolve)
- [x] Secure local wallet with key management
- [x] Credential issuance and verification
- [ ] Standards-compliant DID method (did:key)
- [ ] Revocation registries and status lists
- [ ] Advanced selective disclosure (BBS+ signatures)
- [ ] Blockchain anchoring
- [ ] Hardware-backed keys (FIDO2/WebAuthn)

---

## 🛠️ Tech Stack

- **Node.js** >= 18 - Runtime
- **Ed25519** - Digital signatures
- **Jest** - Testing framework
- **ESLint** - Code linting
- **bs58** - Base58 encoding for multibase key format

---

## 📄 License

MIT

---

## 📚 References

- [W3C DID Specification](https://www.w3.org/TR/did-1.1/)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model-2.0/)
- [Node.js Crypto Module](https://nodejs.org/api/crypto.html)