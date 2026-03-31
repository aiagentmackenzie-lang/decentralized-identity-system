// tests/wallet/wallet.test.js
const fs = require('fs');
const path = require('path');
const os = require('os');

// Mock the WALLET_DIR before requiring wallet module
const testWalletDir = path.join(os.tmpdir(), 'did-wallet-test-' + Date.now());
process.env.DID_WALLET_DIR = testWalletDir;

const {
  createDid,
  getDidKeys,
  listDids,
  storeCredential,
  getCredential,
  listCredentials,
  listCredentialsForSubject,
  deleteCredential,
  getWalletStatus
} = require('../../src/wallet/wallet');

describe('Wallet Module', () => {
  afterEach(() => {
    // Cleanup test wallet directory
    if (fs.existsSync(testWalletDir)) {
      fs.rmSync(testWalletDir, { recursive: true });
    }
  });

  describe('createDid', () => {
    it('should create a new DID with keypair', () => {
      const result = createDid();
      
      expect(result).toHaveProperty('did');
      expect(result).toHaveProperty('publicKey');
      expect(result).toHaveProperty('keyPair');
      expect(result.did).toMatch(/^did:demo:/);
    });

    it('should save DID to wallet index', () => {
      createDid();
      const dids = listDids();
      
      expect(dids.length).toBe(1);
      expect(dids[0]).toHaveProperty('did');
      expect(dids[0]).toHaveProperty('createdAt');
    });

    it('should create unique DIDs each time', () => {
      const result1 = createDid();
      const result2 = createDid();
      
      expect(result1.did).not.toBe(result2.did);
    });

    it('should create keypair files in wallet directory', () => {
      const result = createDid();
      const didDir = path.join(testWalletDir, result.did.replace(/:/g, '_'));
      
      expect(fs.existsSync(path.join(didDir, 'public.key'))).toBe(true);
      expect(fs.existsSync(path.join(didDir, 'private.key'))).toBe(true);
    });
  });

  describe('getDidKeys', () => {
    it('should retrieve keys for an existing DID', () => {
      const result = createDid();
      const keys = getDidKeys(result.did);
      
      expect(keys).toHaveProperty('publicKey');
      expect(keys).toHaveProperty('privateKey');
      expect(Buffer.isBuffer(keys.publicKey)).toBe(true);
      expect(Buffer.isBuffer(keys.privateKey)).toBe(true);
    });
  });

  describe('listDids', () => {
    it('should return empty array for new wallet', () => {
      const dids = listDids();
      expect(dids).toEqual([]);
    });

    it('should return all created DIDs', () => {
      createDid();
      createDid();
      createDid();
      
      const dids = listDids();
      expect(dids.length).toBe(3);
    });
  });

  describe('Credential Storage', () => {
    const sampleCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'TestCredential'],
      issuer: 'did:demo:issuer123',
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: 'did:demo:subject456',
        name: 'Test Subject'
      }
    };

    describe('storeCredential', () => {
      it('should store a credential and return an ID', () => {
        const id = storeCredential(sampleCredential);
        
        expect(typeof id).toBe('string');
        expect(id.length).toBeGreaterThan(0);
      });

      it('should store credential with metadata', () => {
        const before = new Date();
        const id = storeCredential(sampleCredential);
        const after = new Date();
        
        const credentials = listCredentials();
        const stored = credentials.find(c => c.id === id);
        
        expect(stored).toBeDefined();
        expect(stored).toHaveProperty('credential');
        expect(stored).toHaveProperty('storedAt');
        
        const storedAt = new Date(stored.storedAt);
        expect(storedAt >= before && storedAt <= after).toBe(true);
      });
    });

    describe('getCredential', () => {
      it('should retrieve stored credential', () => {
        const id = storeCredential(sampleCredential);
        const retrieved = getCredential(id);
        
        expect(retrieved).toMatchObject(sampleCredential);
      });

      it('should return null for non-existent credential', () => {
        const retrieved = getCredential('non-existent-id');
        expect(retrieved).toBeNull();
      });
    });

    describe('listCredentials', () => {
      it('should return empty array for new wallet', () => {
        const credentials = listCredentials();
        expect(credentials).toEqual([]);
      });

      it('should return all stored credentials', () => {
        storeCredential(sampleCredential);
        storeCredential(sampleCredential);
        
        const credentials = listCredentials();
        expect(credentials.length).toBe(2);
      });
    });

    describe('listCredentialsForSubject', () => {
      it('should filter credentials by subject', () => {
        const cred1 = { ...sampleCredential, credentialSubject: { id: 'did:demo:subject1', name: 'Alice' } };
        const cred2 = { ...sampleCredential, credentialSubject: { id: 'did:demo:subject2', name: 'Bob' } };
        const cred3 = { ...sampleCredential, credentialSubject: { id: 'did:demo:subject1', name: 'Alice Again' } };
        
        storeCredential(cred1);
        storeCredential(cred2);
        storeCredential(cred3);
        
        const subject1Creds = listCredentialsForSubject('did:demo:subject1');
        expect(subject1Creds.length).toBe(2);
        
        const subject2Creds = listCredentialsForSubject('did:demo:subject2');
        expect(subject2Creds.length).toBe(1);
      });
    });

    describe('deleteCredential', () => {
      it('should delete an existing credential', () => {
        const id = storeCredential(sampleCredential);
        const deleted = deleteCredential(id);
        
        expect(deleted).toBe(true);
        expect(getCredential(id)).toBeNull();
      });

      it('should return false for non-existent credential', () => {
        const deleted = deleteCredential('non-existent-id');
        expect(deleted).toBe(false);
      });
    });
  });

  describe('getWalletStatus', () => {
    it('should return wallet statistics', () => {
      const status = getWalletStatus();
      
      expect(status).toHaveProperty('walletDir', testWalletDir);
      expect(status).toHaveProperty('didCount', 0);
      expect(status).toHaveProperty('credentialCount', 0);
    });

    it('should reflect current counts', () => {
      createDid();
      createDid();
      storeCredential({
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
        issuer: 'did:demo:test',
        credentialSubject: { id: 'did:demo:test' }
      });
      
      const status = getWalletStatus();
      expect(status.didCount).toBe(2);
      expect(status.credentialCount).toBe(1);
    });
  });
});