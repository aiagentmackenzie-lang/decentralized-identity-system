// tests/identity/did.test.js
const { publicKeyToDid, buildDidDocument, DID_METHOD } = require('../../src/identity/did');
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
    it('should build a valid DID document', () => {
      const did = 'did:demo:abc123';
      const publicKeyMultibase = 'z123456789';
      
      const doc = buildDidDocument(did, publicKeyMultibase);
      
      expect(doc).toHaveProperty('id', did);
      expect(doc).toHaveProperty('verificationMethod');
      expect(Array.isArray(doc.verificationMethod)).toBe(true);
      expect(doc.verificationMethod.length).toBe(1);
    });

    it('should include correct verification method structure', () => {
      const did = 'did:demo:abc123';
      const publicKeyMultibase = 'z123456789';
      
      const doc = buildDidDocument(did, publicKeyMultibase);
      const vm = doc.verificationMethod[0];
      
      expect(vm).toHaveProperty('id', `${did}#key-1`);
      expect(vm).toHaveProperty('type', 'Ed25519VerificationKey2020');
      expect(vm).toHaveProperty('controller', did);
      expect(vm).toHaveProperty('publicKeyMultibase', publicKeyMultibase);
    });

    it('should allow different DIDs with same structure', () => {
      const did1 = 'did:demo:abc';
      const did2 = 'did:demo:def';
      const publicKeyMultibase = 'zTestKey';
      
      const doc1 = buildDidDocument(did1, publicKeyMultibase);
      const doc2 = buildDidDocument(did2, publicKeyMultibase);
      
      expect(doc1.id).not.toBe(doc2.id);
      expect(doc1.verificationMethod[0].controller).toBe(did1);
      expect(doc2.verificationMethod[0].controller).toBe(did2);
    });
  });
});