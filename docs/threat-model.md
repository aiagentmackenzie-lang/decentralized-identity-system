# Threat Model - Decentralized Identity System (DID)

## Overview

This document outlines the threat model for the Decentralized Identity System (DID) reference implementation. It describes the security assumptions, potential threats, and mitigation strategies employed in the system.

---

## Scope

### In Scope
- DID generation and management
- Verifiable credential issuance and verification
- Key storage and cryptographic operations
- Wallet functionality for credential management
- CLI interactions

### Out of Scope
- Production hardening (HSMs, full audit trails)
- Regulatory compliance
- Blockchain anchoring (future enhancement)
- Network-level attacks (TLS, DDoS)

---

## Threat Model Assumptions

### Assumed Threats

1. **Local File System Access**
   - Attacker can read files if local storage is not protected
   - Attacker can attempt to modify wallet files
   - Mitigation: File permissions (0o700 for directories, 0o600 for private keys)

2. **Arbitrary Input Injection**
   - Attacker can send arbitrary inputs to CLI or verifier
   - Mitigation: Input validation, proper error handling

3. **Network Eavesdropping**
   - Network is untrusted
   - Mitigation: Integrity ensured via signatures, not transport alone

### Not Defended Against

1. **Compromised Host OS**
   - Rootkits, keyloggers, hardware attacks
   - Rationale: Out of scope for educational implementation

2. **Side-Channel Attacks**
   - Timing attacks on key generation or signing
   - Rationale: Requires specialized hardware mitigation

3. **Nation-State Adversaries**
   - Advanced persistent threats
   - Rationale: Requires enterprise-grade security architecture

---

## Asset Inventory

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Private Keys | **Critical** | `.did-wallet/` with 0o600 permissions |
| Credentials | **High** | `.did-wallet/` with 0o700 permissions |
| DID Documents | **Medium** | Generated dynamically |
| Wallet Metadata | **Low** | `.did-wallet/` |

---

## Threat Scenarios

### T1: Private Key Extraction

**Description:** Attacker gains access to wallet files and extracts private keys.

**Risk:** High
**Likelihood:** Medium (depends on file system access)

**Mitigation:**
- Files created with restrictive permissions (0o600)
- Private keys never logged or exposed in output
- Wallet directory permissions (0o700) prevent directory traversal by unprivileged users

### T2: Credential Tampering

**Description:** Attacker modifies a stored credential to change claims.

**Risk:** High
**Likelihood:** Low (requires file access)

**Mitigation:**
- Cryptographic signatures protect credential integrity
- Verification will fail if credential is tampered
- Canonical JSON ensures deterministic signing

### T3: Replay Attack

**Description:** Attacker reuses an old valid credential.

**Risk:** Medium
**Likelihood:** Medium

**Mitigation:**
- Issuance timestamps included in credentials
- Future: Expiration dates and revocation lists

### T4: Impersonation

**Description:** Attacker creates a fake DID claiming to be a legitimate issuer.

**Risk:** High
**Likelihood:** Low

**Mitigation:**
- Trust establishment out of scope (requires DID resolution and trust frameworks)
- Each DID is cryptographically unique
- Future: DID anchoring to blockchain for trust establishment

### T5: CLI Injection

**Description:** Attacker injects malicious arguments through CLI.

**Risk:** Medium
**Likelihood:** Low

**Mitigation:**
- Input validation
- No shell execution of user input
- Proper error handling

---

## Security Controls

### Implemented

| Control | Implementation | Status |
|---------|---------------|--------|
| Key Generation | Ed25519 via Node.js crypto | ✅ |
| Key Storage | 0o600 permissions | ✅ |
| Wallet Directory | 0o700 permissions | ✅ |
| Signature Verification | Ed25519 verify | ✅ |
| Canonical JSON | Deterministic serialization | ✅ |
| No Secret Logging | Sanitized output | ✅ |

### Future Enhancements

| Control | Priority | Notes |
|---------|----------|-------|
| HSM Support | Low | Hardware key storage |
| Revocation Lists | Medium | Credential status checking |
| Audit Logging | Low | Immutable operation logs |
| Encryption at Rest | Medium | Encrypted wallet files |

---

## Privacy Considerations

### Data Minimization
- Credentials contain only necessary claims
- No tracking identifiers beyond DID

### Per-Relying-Party DIDs
- Users can generate separate DIDs for each service
- Reduces correlation of user activity

### PII Handling
- No PII in logs or error messages
- CredentialSubject data controlled by issuer

---

## Testing for Security

### Unit Tests
- Key generation and signing (8 tests)
- DID creation and resolution (7 tests)
- Credential issuance and verification (10 tests)
- Wallet operations (18 tests)
- CLI functionality (7 tests)

### Integration Tests
- Full E2E flow (6 tests)
- Edge cases and robustness (19 tests)

### Security-Specific Tests
- Tamper detection
- Wrong key rejection
- Signature validation
- File permission enforcement

---

## Recommendations for Production

1. **Hardware Security Modules (HSMs)**
   - Store issuer private keys in HSM
   - Prevent key extraction

2. **Revocation Infrastructure**
   - Implement status lists
   - Real-time revocation checking

3. **Secure Enclaves**
   - Use TEE/SE for key operations
   - Protect against memory dumps

4. **Audit Logging**
   - Immutable operation logs
   - Non-repudiation guarantees

5. **Key Rotation**
   - Periodic key updates
   - Forward secrecy

---

## References

- [W3C DID Specification](https://www.w3.org/TR/did-1.1/)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model-2.0/)
- [OWASP Threat Modeling](https://owasp.org/www-community/Application_Threat_Modeling)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57/final)