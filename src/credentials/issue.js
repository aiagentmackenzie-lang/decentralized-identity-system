// src/credentials/issue.js
const { canonicalize } = require('../util/canonical-json');
const { sign } = require('../crypto/keys');

function issueCredential({
  issuerDid,
  subjectDid,
  subjectClaims,
  issuerPublicKeyId,
  issuerPrivateKey
}) {
  const now = new Date().toISOString();

  const vc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'CustomCredential'],
    issuer: issuerDid,
    issuanceDate: now,
    credentialSubject: {
      id: subjectDid,
      ...subjectClaims
    }
  };

  const payload = Buffer.from(canonicalize(vc));
  const signature = sign(payload, issuerPrivateKey);

  vc.proof = {
    type: 'Ed25519Signature2020',
    created: now,
    verificationMethod: issuerPublicKeyId,
    proofPurpose: 'assertionMethod',
    jws: signature.toString('base64url')
  };

  return vc;
}

module.exports = { issueCredential };