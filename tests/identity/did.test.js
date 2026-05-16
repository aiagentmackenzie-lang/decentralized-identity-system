// tests/identity/did.test.js
const { publicKeyToDid, buildDidDocument, DID_METHOD, validateDid, DID_REGEX } = require('../../src/identity/did');
const { generateKeyPair } = require('../../src/crypto/keys');

describe('Identity Module - DID', () => {
  describe('publicKeyToDid', () => {
    it('should generate a DID from public key', () => {
      const keyPair = generateKeyPair();
      const did = publicKeyToDid(keyPair.publicKey);
      
      expect(did).toMatch(/^did:demo:[a-f0-9]{64}$/);
    });

    it('should generate consistent DIDs for same public key', () => {
      const keyPair = generateKeyPair();
      const did1 = publicKeyToDid(keyPair.publicKey);
      const did2 = publicKeyToDid(keyPair.publicKey);
      
      expect(did1).toBe(did2);
    });

    it('should generate different DIDs for different public keys', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();
      const did1 = publicKeyToDid(keyPair1.publicKey);
      const did2 = publicKeyToDid(keyPair2.publicKey);
      
      expect(did1).not.toBe(did2);
    });

    it('should start with did:demo method', () => {
      const keyPair = generateKeyPair();
      const did = publicKeyToDid(keyPair.publicKey);
      
      expect(did.startsWith(DID_METHOD)).toBe(true);
    });
  });

  describe('buildDidDocument', () => {
    // Use valid 64-char hex DID identifiers to match DID_REGEX
    const validDid1 = 'did:demo:' + 'a'.repeat(64);
    const validDid2 = 'did:demo:' + 'b'.repeat(64);
    const publicKeyMultibase = 'z123456789';

    it('should build a valid DID document', () => {
      const doc = buildDidDocument(validDid1, publicKeyMultibase);
      
      expect(doc).toHaveProperty('id', validDid1);
      expect(doc).toHaveProperty('verificationMethod');
      expect(Array.isArray(doc.verificationMethod)).toBe(true);
      expect(doc.verificationMethod.length).toBe(1);
    });

    it('should include correct verification method structure', () => {
      const doc = buildDidDocument(validDid1, publicKeyMultibase);
      const vm = doc.verificationMethod[0];
      
      expect(vm).toHaveProperty('id', `${validDid1}#key-1`);
      expect(vm).toHaveProperty('type', 'Ed25519VerificationKey2020');
      expect(vm).toHaveProperty('controller', validDid1);
      expect(vm).toHaveProperty('publicKeyMultibase', publicKeyMultibase);
    });

    it('should allow different DIDs with same structure', () => {
      const doc1 = buildDidDocument(validDid1, publicKeyMultibase);
      const doc2 = buildDidDocument(validDid2, publicKeyMultibase);
      
      expect(doc1.id).not.toBe(doc2.id);
      expect(doc1.verificationMethod[0].controller).toBe(validDid1);
      expect(doc2.verificationMethod[0].controller).toBe(validDid2);
    });
  });

  describe('validateDid', () => {
    it('should accept valid did:demo DIDs', () => {
      const keyPair = generateKeyPair();
      const did = publicKeyToDid(keyPair.publicKey);
      expect(() => validateDid(did)).not.toThrow();
    });

    it('should reject DIDs with wrong method', () => {
      expect(() => validateDid('did:web:example.com')).toThrow(/Invalid DID format/);
    });

    it('should reject DIDs with path traversal characters', () => {
      expect(() => validateDid('did:demo:test/../../evil')).toThrow(/path traversal/);
      expect(() => validateDid('did:demo:..evil')).toThrow(/path traversal/);
    });

    it('should reject empty or non-string DIDs', () => {
      expect(() => validateDid('')).toThrow(/non-empty string/);
      expect(() => validateDid(null)).toThrow(/non-empty string/);
      expect(() => validateDid(undefined)).toThrow(/non-empty string/);
      expect(() => validateDid(123)).toThrow(/non-empty string/);
    });

    it('should reject DIDs with incorrect hash length', () => {
      expect(() => validateDid('did:demo:abc123')).toThrow(/Invalid DID format/);
    });
  });
});