// src/identity/did.js
const crypto = require('crypto');

const DID_METHOD = 'did:demo';

function publicKeyToDid(publicKeyDer) {
  const hash = crypto.createHash('sha256').update(publicKeyDer).digest('hex');
  return `${DID_METHOD}:${hash}`;
}

function buildDidDocument(did, publicKeyMultibase) {
  return {
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase
      }
    ]
  };
}

module.exports = {
  DID_METHOD,
  publicKeyToDid,
  buildDidDocument
};