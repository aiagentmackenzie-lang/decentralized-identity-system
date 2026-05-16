# Bug & Security Audit Log

**Auditor:** Lead Code Quality Engineer / Lead Security Engineer  
**Date:** 2024-04-24  
**Scope:** Full codebase audit — src/, tests/, docs/, CLI  

---

## 🔴 CRITICAL SEVERITY

### S1: Path Traversal in Key Storage Functions
- **File:** `src/crypto/keys.js` (lines 16, 31-36)
- **Category:** Security — Path Traversal (CWE-22)
- **Impact:** Arbitrary file read/write outside wallet directory
- **Description:** `loadKeyPair()` and `saveKeyPair()` replace `:` with `_` in DID strings but do **not** sanitize `/`. A DID like `did:demo:x/../../etc` becomes `did_demo_x/../../etc`, and `path.join(baseDir, ...)` resolves the `..` sequences, escaping the wallet directory.
- **Proof:** `path.join('/wallet', 'did_demo_x/../../etc')` → `/etc`
- **Fix:** Add DID format validation regex `^did:[a-z0-9]+:[a-zA-Z0-9._-]+$` and reject DIDs containing `/` or `..`. Normalize paths with `path.resolve()` + containment check.

### S2: World-Readable Credential Store Files
- **File:** `src/wallet/store.js` (line 19)
- **Category:** Security — Information Exposure (CWE-200)
- **Impact:** PII in stored credentials readable by any local user (permissions 0o644)
- **Description:** `saveJson()` calls `fs.writeFileSync()` without specifying a file mode. Default permissions (0o644) expose credential data including names, emails, and claims to any user on the system.
- **Fix:** Add explicit `mode: 0o600` to all `writeFileSync` calls for wallet files.

### S3: Private Keys Stored in Plaintext
- **File:** `src/crypto/keys.js` (line 33)
- **Category:** Security — Cleartext Storage of Sensitive Information (CWE-312)
- **Impact:** Private keys exposed if file system is compromised; no defense-in-depth
- **Description:** Private keys are stored as raw DER buffers with no encryption at rest. File permissions (0o600) are the only protection, bypassed by root access, backups, or disk imaging.
- **Remediation:** Implement AES-256-GCM encryption for wallet storage (Phase 3 of roadmap). Mark as known limitation for v1.0.

---

## 🟠 HIGH SEVERITY

### B1: verifyCredential Crashes on Null/Undefined Input
- **File:** `src/credentials/verify.js` (line 6)
- **Category:** Robustness — Unhandled Exception
- **Impact:** Denial of service — calling application crashes
- **Description:** `verifyCredential(null, key)` throws `TypeError: Cannot read properties of null (reading 'proof')` instead of returning `{valid: false, reason: '...'}`.
- **Fix:** Add null/type guard at entry point.

### B2: canonicalize Produces Invalid JSON for `undefined` Values
- **File:** `src/util/canonical-json.js` (line 10)
- **Category:** Data Integrity — Silent Corruption (CWE-116)
- **Impact:** Signatures fail or silently validate against different payloads
- **Description:** `canonicalize({a: undefined})` outputs `{"a":undefined}` — this is syntactically invalid JSON. `Buffer.from('{"a":undefined}')` produces valid bytes, but parsing/validation elsewhere will fail.
- **Fix:** Skip `undefined` properties (matching `JSON.stringify` behavior).

### B3: canonicalize Crashes on Circular References
- **File:** `src/util/canonical-json.js`
- **Category:** Robustness — Stack Overflow / DoS (CWE-400)
- **Impact:** Application crash via untrusted input
- **Description:** Circular object references cause unbounded recursion → "Maximum call stack size exceeded". If credential claims contain circular refs, the application crashes.
- **Fix:** Add circular reference detection.

### B4: canonicalize Silently Corrupts Infinity/NaN to null
- **File:** `src/util/canonical-json.js` (line 10)
- **Category:** Data Integrity — Silent Data Loss
- **Impact:** Values that should be invalid are accepted and silently changed
- **Description:** `canonicalize(Infinity)` → `"null"`, `canonicalize(NaN)` → `"null"`. These should throw, as they represent programmer errors in credential data.
- **Fix:** Throw TypeError for Infinity and NaN.

### B5: canonicalize Serializes Date Objects as Empty `{}`
- **File:** `src/util/canonical-json.js`
- **Category:** Data Integrity — Silent Data Loss
- **Impact:** Date objects in credential claims silently lose all information
- **Description:** `canonicalize({a: new Date('2024-01-01')})` → `{"a":{}}` — the date value is entirely lost.
- **Fix:** Convert Date objects to ISO 8601 strings (matching `JSON.stringify` default behavior).

### B6: canonicalize Produces Invalid JSON for Sparse Arrays
- **File:** `src/util/canonical-json.js` (line 5)
- **Category:** Data Integrity — Silent Corruption
- **Impact:** Sparse arrays produce invalid JSON `[1,,3]` instead of `[1,null,3]`
- **Description:** Array `.map()` skips holes in sparse arrays, and `join(',')` preserves the commas but not `null` values.
- **Fix:** Use index-based iteration to handle holes as `null`.

### B7: canonicalize Serializes Buffers as Indexed Objects
- **File:** `src/util/canonical-json.js`
- **Category:** Data Integrity — Wrong Output
- **Impact:** `Buffer.from('test')` serializes as `{"0":116,"1":101,...}` instead of a meaningful representation
- **Description:** Buffers are objects with numeric index keys; `canonicalize` treats them as regular objects.
- **Fix:** Add explicit Buffer handling (convert to base64 string).

---

## 🟡 MEDIUM SEVERITY

### M1: No DID Format Validation
- **File:** `src/identity/did.js`, `src/wallet/wallet.js`, `src/cli/index.js`
- **Category:** Input Validation (CWE-20)
- **Impact:** Invalid/malicious DID strings accepted throughout the system
- **Description:** No function validates that a DID matches the expected format `did:demo:[a-f0-9]{64}`. Combined with S1, this enables path traversal.
- **Fix:** Add `validateDid()` function and enforce at all entry points.

### M2: No Parameter Validation in issueCredential
- **File:** `src/credentials/issue.js`
- **Category:** Input Validation (CWE-20)
- **Impact:** Malformed credentials silently produced from invalid inputs
- **Description:** No checks for missing/null/undefined on required parameters (issuerDid, subjectDid, issuerPublicKeyId, issuerPrivateKey).
- **Fix:** Add parameter validation with descriptive error messages.

### M3: No Structural Validation in verifyCredential
- **File:** `src/credentials/verify.js`
- **Category:** Incomplete Validation (CWE-20)
- **Impact:** Structurally invalid VCs accepted as long as they have a proof.jws field
- **Description:** `verifyCredential` only checks for `proof` and `proof.jws`. No validation of required W3C VC fields (`@context`, `type`, `issuer`, `credentialSubject`).
- **Fix:** Add structural validation before signature check.

### M4: No Expiration Date Support
- **File:** `src/credentials/issue.js`, `src/credentials/verify.js`
- **Category:** Feature Gap / Replay Attack (CWE-294)
- **Impact:** No mechanism to time-limit credentials; replay attacks undetectable
- **Description:** `issueCredential` doesn't accept `expirationDate`. `verifyCredential` doesn't check for expired credentials.
- **Fix:** Add optional `expirationDate` parameter and expiry checking.

### M5: Race Condition in Wallet JSON Operations
- **File:** `src/wallet/wallet.js`, `src/wallet/store.js`
- **Category:** Race Condition (CWE-367)
- **Impact:** Concurrent operations can corrupt credential/DID stores
- **Description:** Read-modify-write on JSON files without locking. Two concurrent `storeCredential` calls could lose data.
- **Fix:** Add advisory file locking (`proper-lockfile` or `fd`-based exclusive lock).

### M6: CLI handleVcVerify Assumes issuer is String
- **File:** `src/cli/index.js` (line 133)
- **Category:** Standards Compliance
- **Impact:** Fails if W3C VC `issuer` is an object `{id: 'did:...'}` instead of string
- **Description:** W3C VC spec allows issuer to be object with `id` property; code only handles string form.
- **Fix:** Handle both string and object issuer forms.

---

## 🟢 LOW / QUALITY

### L1: Public Key Files Have No Explicit Permissions
- **File:** `src/crypto/keys.js` (line 32)
- **Category:** Inconsistent Permissions
- **Impact:** Public key files get default permissions instead of explicit 0o600
- **Fix:** Set explicit mode for consistency.

### L2: no Permission Verification on Existing Wallet Directories
- **File:** `src/wallet/store.js`, `src/crypto/keys.js`
- **Category:** Defense-in-Depth
- **Impact:** If wallet directory was created with loose permissions (e.g. via mkdir -p), it won't be corrected
- **Fix:** Verify and optionally fix directory permissions at wallet init.

### L3: No Credential Deduplication
- **File:** `src/wallet/wallet.js`
- **Category:** Quality
- **Impact:** Same credential stored multiple times with different UUIDs
- **Fix:** Low priority — document as known behavior.

### L4: No Audit Logging
- **Category:** Observability
- **Impact:** No forensic trail for DID creation, credential issuance, or verification events
- **Fix:** Add structured audit logger (future enhancement).

---

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 Critical | 3 | 2 Fixed, 1 Acknowledged (encryption-at-rest) |
| 🟠 High | 7 | All Fixed |
| 🟡 Medium | 6 | 5 Fixed, 1 Deferred (race condition — requires dependency) |
| 🟢 Low | 4 | 2 Fixed, 2 Deferred |

**Total Issues Found:** 20  
**Total Fixed in This Audit:** 14  
**Acknowledged/Deferred:** 6 (encryption-at-rest, race condition locking, credential dedup, audit logging, 2 minor)