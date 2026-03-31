// tests/integration/e2e.test.js
const fs = require('fs');
const path = require('path');
const os = require('os');

// Use isolated test directory
const testWalletDir = path.join(os.tmpdir(), 'did-e2e-test-' + Date.now());
process.env.DID_WALLET_DIR = testWalletDir;

const { createDid, getDidKeys, storeCredential, getCredential, listCredentials } = require('../../src/wallet/wallet');
const { issueCredential } = require('../../src/credentials/issue');
const { verifyCredential } = require('../../src/credentials/verify');
const { publicKeyToDid } = require('../../src/identity/did');
const { generateKeyPair } = require('../../src/crypto/keys');

describe('End-to-End Integration Flow', () => {
  beforeEach(() => {
    // Ensure clean state
    if (fs.existsSync(testWalletDir)) {
      fs.rmSync(testWalletDir, { recursive: true });
    }
  });

  afterAll(() => {
    // Final cleanup
    if (fs.existsSync(testWalletDir)) {
      fs.rmSync(testWalletDir, { recursive: true });
    }
  });

  it('should complete full Issuer → Holder → Verifier flow', () => {
    // ==========================================
    // STEP 1: Issuer creates their DID and keys
    // ==========================================
    console.log('  Step 1: Issuer creates DID...');
    const issuerResult = createDid();
    const issuerDid = issuerResult.did;
    const issuerKeys = getDidKeys(issuerDid);
    
    expect(issuerDid).toMatch(/^did:demo:/);
    expect(issuerKeys).toHaveProperty('publicKey');
    expect(issuerKeys).toHaveProperty('privateKey');

    // ==========================================
    // STEP 2: Holder (Subject) creates their DID
    // ==========================================
    console.log('  Step 2: Holder creates DID...');
    const holderResult = createDid();
    const holderDid = holderResult.did;
    
    expect(holderDid).toMatch(/^did:demo:/);
    expect(holderDid).not.toBe(issuerDid);

    // ==========================================
    // STEP 3: Issuer issues credential to Holder
    // ==========================================
    console.log('  Step 3: Issuer issues credential...');
    const credentialSubject = {
      name: 'Alice',
      studentId: 'STU-12345',
      enrolled: true,
      major: 'Computer Science'
    };

    const vc = issueCredential({
      issuerDid: issuerDid,
      subjectDid: holderDid,
      subjectClaims: credentialSubject,
      issuerPublicKeyId: `${issuerDid}#key-1`,
      issuerPrivateKey: issuerKeys.privateKey
    });

    // Verify VC structure
    expect(vc).toHaveProperty('@context');
    expect(vc).toHaveProperty('type');
    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.issuer).toBe(issuerDid);
    expect(vc.credentialSubject.id).toBe(holderDid);
    expect(vc.credentialSubject).toMatchObject(credentialSubject);
    expect(vc).toHaveProperty('proof');
    expect(vc.proof.type).toBe('Ed25519Signature2020');
    expect(vc.proof).toHaveProperty('jws');

    // ==========================================
    // STEP 4: Holder stores credential in wallet
    // ==========================================
    console.log('  Step 4: Holder stores credential...');
    const credentialId = storeCredential(vc);
    
    expect(typeof credentialId).toBe('string');
    expect(credentialId.length).toBeGreaterThan(0);

    // Verify storage
    const storedCredential = getCredential(credentialId);
    expect(storedCredential).toBeDefined();
    expect(storedCredential.issuer).toBe(issuerDid);

    // ==========================================
    // STEP 5: Holder lists their credentials
    // ==========================================
    console.log('  Step 5: Holder lists credentials...');
    const holderCredentials = listCredentials();
    
    expect(holderCredentials.length).toBe(1);
    expect(holderCredentials[0].credential.issuer).toBe(issuerDid);

    // ==========================================
    // STEP 6: Verifier validates the credential
    // ==========================================
    console.log('  Step 6: Verifier validates credential...');
    
    // In a real scenario, verifier would get issuer's public key from DID document
    // For this test, we use the stored issuer keys
    const verificationResult = verifyCredential(vc, issuerKeys.publicKey);
    
    expect(verificationResult.valid).toBe(true);
    expect(verificationResult.reason).toBe('Signature valid');

    console.log('  ✅ Full E2E flow completed successfully!');
  });

  it('should detect tampered credentials during verification', () => {
    // Setup: Create issuer and holder DIDs
    const issuerResult = createDid();
    const issuerDid = issuerResult.did;
    const issuerKeys = getDidKeys(issuerDid);
    
    const holderResult = createDid();
    const holderDid = holderResult.did;

    // Issue credential
    const vc = issueCredential({
      issuerDid: issuerDid,
      subjectDid: holderDid,
      subjectClaims: { role: 'admin' },
      issuerPublicKeyId: `${issuerDid}#key-1`,
      issuerPrivateKey: issuerKeys.privateKey
    });

    // Tamper with the credential
    vc.credentialSubject.role = 'superadmin';

    // Verify should fail
    const verificationResult = verifyCredential(vc, issuerKeys.publicKey);
    
    expect(verificationResult.valid).toBe(false);
    expect(verificationResult.reason).toBe('Signature invalid');
  });

  it('should reject credentials with wrong issuer key', () => {
    // Setup: Create two issuers
    const issuer1Result = createDid();
    const issuer1Did = issuer1Result.did;
    const issuer1Keys = getDidKeys(issuer1Did);
    
    const issuer2Result = createDid();
    const issuer2Keys = getDidKeys(issuer2Result.did);
    
    const holderResult = createDid();
    const holderDid = holderResult.did;

    // Issue credential with issuer 1
    const vc = issueCredential({
      issuerDid: issuer1Did,
      subjectDid: holderDid,
      subjectClaims: { role: 'user' },
      issuerPublicKeyId: `${issuer1Did}#key-1`,
      issuerPrivateKey: issuer1Keys.privateKey
    });

    // Verify with issuer 2's key should fail
    const verificationResult = verifyCredential(vc, issuer2Keys.publicKey);
    
    expect(verificationResult.valid).toBe(false);
    expect(verificationResult.reason).toBe('Signature invalid');
  });

  it('should support multiple credentials from different issuers', () => {
    // Create multiple issuers and one holder
    const issuer1 = createDid();
    const issuer2 = createDid();
    const holder = createDid();

    const issuer1Keys = getDidKeys(issuer1.did);
    const issuer2Keys = getDidKeys(issuer2.did);

    // Issue credentials from both issuers
    const vc1 = issueCredential({
      issuerDid: issuer1.did,
      subjectDid: holder.did,
      subjectClaims: { type: 'university-degree', degree: 'Bachelor of Science' },
      issuerPublicKeyId: `${issuer1.did}#key-1`,
      issuerPrivateKey: issuer1Keys.privateKey
    });

    const vc2 = issueCredential({
      issuerDid: issuer2.did,
      subjectDid: holder.did,
      subjectClaims: { type: 'employment', company: 'Tech Corp' },
      issuerPublicKeyId: `${issuer2.did}#key-1`,
      issuerPrivateKey: issuer2Keys.privateKey
    });

    // Store both credentials
    const id1 = storeCredential(vc1);
    const id2 = storeCredential(vc2);

    // Verify both
    const result1 = verifyCredential(getCredential(id1), issuer1Keys.publicKey);
    const result2 = verifyCredential(getCredential(id2), issuer2Keys.publicKey);

    expect(result1.valid).toBe(true);
    expect(result2.valid).toBe(true);

    // Cross-verification should fail
    const crossResult1 = verifyCredential(getCredential(id1), issuer2Keys.publicKey);
    const crossResult2 = verifyCredential(getCredential(id2), issuer1Keys.publicKey);

    expect(crossResult1.valid).toBe(false);
    expect(crossResult2.valid).toBe(false);
  });

  it('should handle the complete workflow programmatically', () => {
    // This test simulates the exact CLI workflow but programmatically
    
    // 1. wallet:init (implicit via createDid)
    // 2. did:create (for issuer)
    const issuer = createDid();
    // 3. did:create (for subject)
    const subject = createDid();
    
    // Get issuer keys for signing
    const issuerKeys = getDidKeys(issuer.did);
    
    // 4. vc:issue
    const vc = issueCredential({
      issuerDid: issuer.did,
      subjectDid: subject.did,
      subjectClaims: { 
        name: 'Test User',
        clearance: 'level-3'
      },
      issuerPublicKeyId: `${issuer.did}#key-1`,
      issuerPrivateKey: issuerKeys.privateKey
    });
    
    // 5. vc:list (implicit - stored in holder's wallet)
    const credentialId = storeCredential(vc);
    const credentials = listCredentials();
    expect(credentials.length).toBe(1);
    
    // 6. vc:verify
    const retrieved = getCredential(credentialId);
    const verification = verifyCredential(retrieved, issuerKeys.publicKey);
    
    expect(verification.valid).toBe(true);
  });
});