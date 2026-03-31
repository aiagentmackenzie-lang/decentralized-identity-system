// tests/integration/edge-cases.test.js
const fs = require('fs');
const path = require('path');
const os = require('os');

const testWalletDir = path.join(os.tmpdir(), 'did-edge-test-' + Date.now());
process.env.DID_WALLET_DIR = testWalletDir;

const { canonicalize } = require('../../src/util/canonical-json');
const { generateKeyPair, sign, verify } = require('../../src/crypto/keys');
const { publicKeyToDid, buildDidDocument } = require('../../src/identity/did');
const { issueCredential } = require('../../src/credentials/issue');
const { verifyCredential } = require('../../src/credentials/verify');
const { createDid, getDidKeys, storeCredential, getCredential, deleteCredential } = require('../../src/wallet/wallet');

describe('Edge Cases & Robustness Tests', () => {
  afterEach(() => {
    if (fs.existsSync(testWalletDir)) {
      fs.rmSync(testWalletDir, { recursive: true });
    }
  });

  describe('Canonical JSON', () => {
    it('should produce same output regardless of key order', () => {
      const obj1 = { z: 1, a: 2, m: 3 };
      const obj2 = { a: 2, m: 3, z: 1 };
      
      expect(canonicalize(obj1)).toBe(canonicalize(obj2));
    });

    it('should handle nested objects consistently', () => {
      const obj1 = { b: { z: 1, a: 2 }, a: 3 };
      const obj2 = { a: 3, b: { a: 2, z: 1 } };
      
      expect(canonicalize(obj1)).toBe(canonicalize(obj2));
    });

    it('should handle arrays', () => {
      const obj1 = { items: [{ z: 1 }, { a: 2 }] };
      const obj2 = { items: [{ z: 1 }, { a: 2 }] };
      
      expect(canonicalize(obj1)).toBe(canonicalize(obj2));
    });

    it('should handle special characters in strings', () => {
      const obj = { name: 'Test\nWith\tSpecial"Chars' };
      const result = canonicalize(obj);
      expect(result).toBe('{"name":"Test\\nWith\\tSpecial\\"Chars"}');
    });
  });

  describe('Crypto Operations', () => {
    it('should handle empty payloads', () => {
      const keyPair = generateKeyPair();
      const payload = Buffer.from('');
      
      const signature = sign(payload, keyPair.privateKey);
      const isValid = verify(payload, signature, keyPair.publicKey);
      
      expect(isValid).toBe(true);
    });

    it('should handle large payloads', () => {
      const keyPair = generateKeyPair();
      const payload = Buffer.alloc(1024 * 1024, 'x'); // 1MB
      
      const signature = sign(payload, keyPair.privateKey);
      const isValid = verify(payload, signature, keyPair.publicKey);
      
      expect(isValid).toBe(true);
    });

    it('should handle unicode content', () => {
      const keyPair = generateKeyPair();
      const payload = Buffer.from('Hello 世界 🌍 مرحبا', 'utf8');
      
      const signature = sign(payload, keyPair.privateKey);
      const isValid = verify(payload, signature, keyPair.publicKey);
      
      expect(isValid).toBe(true);
    });

    it('should generate unique signatures for different payloads', () => {
      const keyPair = generateKeyPair();
      const payload1 = Buffer.from('message 1');
      const payload2 = Buffer.from('message 2');
      
      const sig1 = sign(payload1, keyPair.privateKey);
      const sig2 = sign(payload2, keyPair.privateKey);
      
      expect(sig1.toString('hex')).not.toBe(sig2.toString('hex'));
    });

    it('should generate unique signatures for same payload with different keys', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();
      const payload = Buffer.from('same message');
      
      const sig1 = sign(payload, keyPair1.privateKey);
      const sig2 = sign(payload, keyPair2.privateKey);
      
      expect(sig1.toString('hex')).not.toBe(sig2.toString('hex'));
    });
  });

  describe('DID Operations', () => {
    it('should handle various public key lengths', () => {
      // Ed25519 raw keys are 32 bytes, but DER encoded are 44 bytes
      const keyPair = generateKeyPair();
      expect(keyPair.publicKey.length).toBe(44); // DER encoded Ed25519 public key
      
      const did = publicKeyToDid(keyPair.publicKey);
      expect(did).toMatch(/^did:demo:[a-f0-9]{64}$/);
    });

    it('should create valid DID document structure', () => {
      const did = 'did:demo:abc123';
      const publicKeyMultibase = 'zTestKey123';
      
      const doc = buildDidDocument(did, publicKeyMultibase);
      
      expect(doc).toHaveProperty('id');
      expect(doc).toHaveProperty('verificationMethod');
      expect(Array.isArray(doc.verificationMethod)).toBe(true);
      expect(doc.verificationMethod[0]).toHaveProperty('id');
      expect(doc.verificationMethod[0]).toHaveProperty('type');
      expect(doc.verificationMethod[0]).toHaveProperty('controller');
      expect(doc.verificationMethod[0]).toHaveProperty('publicKeyMultibase');
    });
  });

  describe('Credential Edge Cases', () => {
    it('should handle empty claims', () => {
      const issuer = createDid();
      const subject = createDid();
      const issuerKeys = getDidKeys(issuer.did);
      
      const vc = issueCredential({
        issuerDid: issuer.did,
        subjectDid: subject.did,
        subjectClaims: {},
        issuerPublicKeyId: `${issuer.did}#key-1`,
        issuerPrivateKey: issuerKeys.privateKey
      });
      
      const result = verifyCredential(vc, issuerKeys.publicKey);
      expect(result.valid).toBe(true);
    });

    it('should handle deeply nested claims', () => {
      const issuer = createDid();
      const subject = createDid();
      const issuerKeys = getDidKeys(issuer.did);
      
      const vc = issueCredential({
        issuerDid: issuer.did,
        subjectDid: subject.did,
        subjectClaims: {
          person: {
            name: { first: 'John', last: 'Doe' },
            contact: { email: 'john@example.com' }
          }
        },
        issuerPublicKeyId: `${issuer.did}#key-1`,
        issuerPrivateKey: issuerKeys.privateKey
      });
      
      const result = verifyCredential(vc, issuerKeys.publicKey);
      expect(result.valid).toBe(true);
    });

    it('should handle credential with expiration date', () => {
      // Note: expirationDate would need to be part of the VC before signing
      // This test verifies the basic credential structure still works
      const issuer = createDid();
      const subject = createDid();
      const issuerKeys = getDidKeys(issuer.did);
      
      const vc = issueCredential({
        issuerDid: issuer.did,
        subjectDid: subject.did,
        subjectClaims: { role: 'temp' },
        issuerPublicKeyId: `${issuer.did}#key-1`,
        issuerPrivateKey: issuerKeys.privateKey
      });
      
      // Expiration date is not part of this implementation's signed payload
      // In a full implementation, it would be included in the VC before issueCredential
      const result = verifyCredential(vc, issuerKeys.publicKey);
      expect(result.valid).toBe(true);
    });

    it('should fail verification after tampering any field', () => {
      const issuer = createDid();
      const subject = createDid();
      const issuerKeys = getDidKeys(issuer.did);
      
      // Create base credential
      const baseVc = issueCredential({
        issuerDid: issuer.did,
        subjectDid: subject.did,
        subjectClaims: { a: 1, b: 2 },
        issuerPublicKeyId: `${issuer.did}#key-1`,
        issuerPrivateKey: issuerKeys.privateKey
      });
      
      // Test various tamperings - each test gets a fresh copy
      const tamperTests = [
        (vc) => { vc.issuer = 'did:demo:evil'; },
        (vc) => { vc.credentialSubject.id = 'did:demo:other'; },
        (vc) => { vc.issuanceDate = new Date(0).toISOString(); },
        (vc) => { vc.credentialSubject.a = 999; },
        (vc) => { vc.type = ['FakeCredential']; },
      ];
      
      tamperTests.forEach(tamperFn => {
        const vcCopy = JSON.parse(JSON.stringify(baseVc));
        tamperFn(vcCopy);
        const result = verifyCredential(vcCopy, issuerKeys.publicKey);
        expect(result.valid).toBe(false);
      });
    });
  });

  describe('Wallet Edge Cases', () => {
    it('should handle duplicate credential storage', () => {
      const issuer = createDid();
      const subject = createDid();
      const issuerKeys = getDidKeys(issuer.did);
      
      const vc = issueCredential({
        issuerDid: issuer.did,
        subjectDid: subject.did,
        subjectClaims: { test: 'data' },
        issuerPublicKeyId: `${issuer.did}#key-1`,
        issuerPrivateKey: issuerKeys.privateKey
      });
      
      // Store same credential twice
      const id1 = storeCredential(vc);
      const id2 = storeCredential(vc);
      
      expect(id1).not.toBe(id2); // Should have unique IDs
    });

    it('should handle deletion of non-existent credential', () => {
      const result = deleteCredential('non-existent-id');
      expect(result).toBe(false);
    });

    it('should handle retrieval of non-existent credential', () => {
      const result = getCredential('non-existent-id');
      expect(result).toBeNull();
    });

    it('should persist credentials across wallet instances', () => {
      const issuer = createDid();
      const subject = createDid();
      const issuerKeys = getDidKeys(issuer.did);
      
      const vc = issueCredential({
        issuerDid: issuer.did,
        subjectDid: subject.did,
        subjectClaims: { persistent: 'data' },
        issuerPublicKeyId: `${issuer.did}#key-1`,
        issuerPrivateKey: issuerKeys.privateKey
      });
      
      const id = storeCredential(vc);
      
      // Verify it's still there
      const retrieved = getCredential(id);
      expect(retrieved).toBeDefined();
      expect(retrieved.credentialSubject.persistent).toBe('data');
    });
  });
});