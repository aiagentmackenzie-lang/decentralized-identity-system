// tests/credentials/credentials.test.js
const { issueCredential } = require('../../src/credentials/issue');
const { verifyCredential } = require('../../src/credentials/verify');
const { publicKeyToDid } = require('../../src/identity/did');
const { generateKeyPair: generateCryptoKeyPair } = require('../../src/crypto/keys');

describe('Credentials Module', () => {
  describe('issueCredential', () => {
    it('should issue a valid verifiable credential', () => {
      const issuerKeyPair = generateCryptoKeyPair();
      const subjectKeyPair = generateCryptoKeyPair();
      
      const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
      const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
      
      const vc = issueCredential({
        issuerDid,
        subjectDid,
        subjectClaims: { role: 'admin' },
        issuerPublicKeyId: `${issuerDid}#key-1`,
        issuerPrivateKey: issuerKeyPair.privateKey
      });
      
      expect(vc).toHaveProperty('@context');
      expect(vc).toHaveProperty('type');
      expect(vc).toHaveProperty('issuer', issuerDid);
      expect(vc).toHaveProperty('issuanceDate');
      expect(vc).toHaveProperty('credentialSubject');
      expect(vc.credentialSubject).toHaveProperty('id', subjectDid);
      expect(vc.credentialSubject).toHaveProperty('role', 'admin');
      expect(vc).toHaveProperty('proof');
    });

    it('should include embedded proof with correct structure', () => {
      const issuerKeyPair = generateCryptoKeyPair();
      const subjectKeyPair = generateCryptoKeyPair();
      
      const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
      const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
      
      const vc = issueCredential({
        issuerDid,
        subjectDid,
        subjectClaims: { role: 'user' },
        issuerPublicKeyId: `${issuerDid}#key-1`,
        issuerPrivateKey: issuerKeyPair.privateKey
      });
      
      expect(vc.proof).toHaveProperty('type', 'Ed25519Signature2020');
      expect(vc.proof).toHaveProperty('created');
      expect(vc.proof).toHaveProperty('verificationMethod', `${issuerDid}#key-1`);
      expect(vc.proof).toHaveProperty('proofPurpose', 'assertionMethod');
      expect(vc.proof).toHaveProperty('jws');
      // JWS should be base64url encoded
      expect(vc.proof.jws).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should include custom claims in credentialSubject', () => {
      const issuerKeyPair = generateCryptoKeyPair();
      const subjectKeyPair = generateCryptoKeyPair();
      
      const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
      const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
      
      const customClaims = {
        name: 'John Doe',
        email: 'john@example.com',
        department: 'Engineering'
      };
      
      const vc = issueCredential({
        issuerDid,
        subjectDid,
        subjectClaims: customClaims,
        issuerPublicKeyId: `${issuerDid}#key-1`,
        issuerPrivateKey: issuerKeyPair.privateKey
      });
      
      expect(vc.credentialSubject).toMatchObject({
        id: subjectDid,
        ...customClaims
      });
    });
  });

  describe('verifyCredential', () => {
    it('should verify a valid credential', () => {
      const issuerKeyPair = generateCryptoKeyPair();
      const subjectKeyPair = generateCryptoKeyPair();
      
      const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
      const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
      
      const vc = issueCredential({
        issuerDid,
        subjectDid,
        subjectClaims: { role: 'admin' },
        issuerPublicKeyId: `${issuerDid}#key-1`,
        issuerPrivateKey: issuerKeyPair.privateKey
      });
      
      const result = verifyCredential(vc, issuerKeyPair.publicKey);
      
      expect(result.valid).toBe(true);
      expect(result.reason).toBe('Signature valid');
    });

    it('should fail verification with tampered credential', () => {
      const issuerKeyPair = generateCryptoKeyPair();
      const subjectKeyPair = generateCryptoKeyPair();
      
      const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
      const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
      
      const vc = issueCredential({
        issuerDid,
        subjectDid,
        subjectClaims: { role: 'admin' },
        issuerPublicKeyId: `${issuerDid}#key-1`,
        issuerPrivateKey: issuerKeyPair.privateKey
      });
      
      // Tamper with the credential
      vc.credentialSubject.role = 'superadmin';
      
      const result = verifyCredential(vc, issuerKeyPair.publicKey);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Signature invalid');
    });

    it('should fail verification with wrong issuer public key', () => {
      const issuerKeyPair = generateCryptoKeyPair();
      const wrongKeyPair = generateCryptoKeyPair();
      const subjectKeyPair = generateCryptoKeyPair();
      
      const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
      const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
      
      const vc = issueCredential({
        issuerDid,
        subjectDid,
        subjectClaims: { role: 'admin' },
        issuerPublicKeyId: `${issuerDid}#key-1`,
        issuerPrivateKey: issuerKeyPair.privateKey
      });
      
      const result = verifyCredential(vc, wrongKeyPair.publicKey);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Signature invalid');
    });

    it('should fail verification with missing proof', () => {
      const issuerKeyPair = generateCryptoKeyPair();
      const subjectKeyPair = generateCryptoKeyPair();
      
      const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
      const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
      
      const vc = issueCredential({
        issuerDid,
        subjectDid,
        subjectClaims: { role: 'admin' },
        issuerPublicKeyId: `${issuerDid}#key-1`,
        issuerPrivateKey: issuerKeyPair.privateKey
      });
      
      // Remove proof
      delete vc.proof;
      
      const result = verifyCredential(vc, issuerKeyPair.publicKey);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Missing proof');
    });

    it('should fail verification with missing jws in proof', () => {
      const issuerKeyPair = generateCryptoKeyPair();
      const subjectKeyPair = generateCryptoKeyPair();
      
      const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
      const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
      
      const vc = issueCredential({
        issuerDid,
        subjectDid,
        subjectClaims: { role: 'admin' },
        issuerPublicKeyId: `${issuerDid}#key-1`,
        issuerPrivateKey: issuerKeyPair.privateKey
      });
      
      // Remove jws
      delete vc.proof.jws;
      
      const result = verifyCredential(vc, issuerKeyPair.publicKey);
      
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Missing proof');
    });

    it('should verify credentials with multiple claims', () => {
      const issuerKeyPair = generateCryptoKeyPair();
      const subjectKeyPair = generateCryptoKeyPair();
      
      const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
      const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
      
      const vc = issueCredential({
        issuerDid,
        subjectDid,
        subjectClaims: { 
          role: 'engineer',
          department: 'Security',
          clearance: 'level-3'
        },
        issuerPublicKeyId: `${issuerDid}#key-1`,
        issuerPrivateKey: issuerKeyPair.privateKey
      });
      
      const result = verifyCredential(vc, issuerKeyPair.publicKey);
      
      expect(result.valid).toBe(true);
    });
  });

  describe('End-to-End Credential Flow', () => {
    it('should complete full issue-verify cycle', () => {
      // Issuer creates their keys
      const issuerKeyPair = generateCryptoKeyPair();
      const issuerDid = publicKeyToDid(issuerKeyPair.publicKey);
      
      // Subject creates their keys (only need DID for this flow)
      const subjectKeyPair = generateCryptoKeyPair();
      const subjectDid = publicKeyToDid(subjectKeyPair.publicKey);
      
      // Issuer issues credential to subject
      const vc = issueCredential({
        issuerDid,
        subjectDid,
        subjectClaims: { 
          name: 'Alice',
          studentId: 'STU-12345',
          enrolled: true
        },
        issuerPublicKeyId: `${issuerDid}#key-1`,
        issuerPrivateKey: issuerKeyPair.privateKey
      });
      
      // Verifier validates the credential
      const verificationResult = verifyCredential(vc, issuerKeyPair.publicKey);
      
      expect(verificationResult.valid).toBe(true);
      expect(vc.issuer).toBe(issuerDid);
      expect(vc.credentialSubject.id).toBe(subjectDid);
    });
  });
});