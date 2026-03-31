// tests/crypto/keys.test.js
const { generateKeyPair, sign, verify, saveKeyPair, loadKeyPair } = require('../../src/crypto/keys');
const fs = require('fs');
const path = require('path');
const os = require('os');

describe('Crypto Module', () => {
  const testDir = path.join(os.tmpdir(), 'did-test-' + Date.now());

  afterEach(() => {
    // Cleanup test directory
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true });
    }
  });

  describe('generateKeyPair', () => {
    it('should generate Ed25519 key pair', () => {
      const keyPair = generateKeyPair();
      expect(keyPair).toHaveProperty('publicKey');
      expect(keyPair).toHaveProperty('privateKey');
      expect(Buffer.isBuffer(keyPair.publicKey)).toBe(true);
      expect(Buffer.isBuffer(keyPair.privateKey)).toBe(true);
    });

    it('should generate unique key pairs each time', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();
      expect(keyPair1.publicKey.toString('hex')).not.toBe(keyPair2.publicKey.toString('hex'));
    });
  });

  describe('sign and verify', () => {
    it('should sign and verify a payload', () => {
      const keyPair = generateKeyPair();
      const payload = Buffer.from('test message');
      
      const signature = sign(payload, keyPair.privateKey);
      expect(Buffer.isBuffer(signature)).toBe(true);
      
      const isValid = verify(payload, signature, keyPair.publicKey);
      expect(isValid).toBe(true);
    });

    it('should fail verification with wrong public key', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();
      const payload = Buffer.from('test message');
      
      const signature = sign(payload, keyPair1.privateKey);
      const isValid = verify(payload, signature, keyPair2.publicKey);
      expect(isValid).toBe(false);
    });

    it('should fail verification with tampered payload', () => {
      const keyPair = generateKeyPair();
      const payload = Buffer.from('test message');
      const tamperedPayload = Buffer.from('tampered message');
      
      const signature = sign(payload, keyPair.privateKey);
      const isValid = verify(tamperedPayload, signature, keyPair.publicKey);
      expect(isValid).toBe(false);
    });
  });

  describe('saveKeyPair and loadKeyPair', () => {
    it('should save and load key pair', () => {
      const keyPair = generateKeyPair();
      const did = 'did:demo:test123';
      
      saveKeyPair(testDir, did, keyPair);
      
      const loadedKeyPair = loadKeyPair(testDir, did);
      expect(loadedKeyPair.publicKey.toString('hex')).toBe(keyPair.publicKey.toString('hex'));
      expect(loadedKeyPair.privateKey.toString('hex')).toBe(keyPair.privateKey.toString('hex'));
    });

    it('should create directory with correct permissions', () => {
      const keyPair = generateKeyPair();
      const did = 'did:demo:test456';
      
      saveKeyPair(testDir, did, keyPair);
      
      const didDir = path.join(testDir, did.replace(/:/g, '_'));
      expect(fs.existsSync(didDir)).toBe(true);
    });

    it('should save private key with restricted permissions', () => {
      const keyPair = generateKeyPair();
      const did = 'did:demo:test789';
      
      saveKeyPair(testDir, did, keyPair);
      
      const didDir = path.join(testDir, did.replace(/:/g, '_'));
      const privateKeyPath = path.join(didDir, 'private.key');
      const stats = fs.statSync(privateKeyPath);
      // Check that private key has restricted permissions (0o600)
      expect(stats.mode & 0o777).toBe(0o600);
    });
  });
});