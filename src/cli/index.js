#!/usr/bin/env node
// src/cli/index.js
const {
  createDid,
  getDidKeys,
  listDids,
  storeCredential,
  getCredential,
  listCredentials,
  deleteCredential,
  getWalletStatus
} = require('../wallet/wallet');
const { issueCredential } = require('../credentials/issue');
const { verifyCredential } = require('../credentials/verify');
const { buildDidDocument, validateDid } = require('../identity/did');
const bs58 = require('bs58').default;

function printUsage() {
  console.log(`
Usage: node src/cli/index.js <command> [options]

Commands:
  did:create                    Create a new DID and keypair
  did:list                      List all DIDs in wallet
  did:resolve <did>            Show DID document for a DID

  vc:issue                      Issue a credential
    --issuer <did>              Issuer DID (required)
    --subject <did>             Subject DID (required)
    --claim <key=value>         Add a claim (can be used multiple times)
    --expires <ISO-date>        Set expiration date (optional)

  vc:list                       List all stored credentials
  vc:show <id>                 Show credential by ID
  vc:verify --id <id>          Verify a stored credential
  vc:delete --id <id>          Delete a credential

  wallet:init                   Initialize wallet directory
  wallet:status                 Show wallet status

Examples:
  node src/cli/index.js did:create
  node src/cli/index.js vc:issue --issuer did:demo:ISSUER_HASH --subject did:demo:SUBJECT_HASH --claim role=admin
  node src/cli/index.js vc:issue --issuer did:demo:ISSUER_HASH --subject did:demo:SUBJECT_HASH --claim role=admin --expires 2025-12-31T23:59:59Z
  node src/cli/index.js vc:list
  node src/cli/index.js vc:verify --id <credential-id>
`);
}

function parseArgs(args) {
  const command = args[0];
  const options = {};
  const positional = [];

  // Keys that should accumulate into arrays when repeated (e.g., --claim a=x --claim b=y)
  const ARRAY_KEYS = new Set(['claim']);

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const value = args[i + 1] && !args[i + 1].startsWith('--') ? args[++i] : true;

      if (ARRAY_KEYS.has(key)) {
        // Accumulate repeated flags into an array
        if (options[key] === undefined) {
          options[key] = value;
        } else if (Array.isArray(options[key])) {
          options[key].push(value);
        } else {
          options[key] = [options[key], value];
        }
      } else {
        options[key] = value;
      }
    } else {
      positional.push(arg);
    }
  }
  
  return { command, options, positional };
}

function parseClaims(options) {
  const claims = {};
  if (options.claim) {
    if (Array.isArray(options.claim)) {
      options.claim.forEach(claim => {
        const [key, value] = claim.split('=');
        if (key && value !== undefined) {
          claims[key] = value;
        }
      });
    } else {
      const [key, value] = options.claim.split('=');
      if (key && value !== undefined) {
        claims[key] = value;
      }
    }
  }
  return claims;
}

/**
 * Extract a DID string from an issuer field that may be a string or object.
 * W3C VC spec allows issuer to be either a string DID or an object { id: 'did:...' }
 */
function extractIssuerDid(issuer) {
  if (typeof issuer === 'string') {
    return issuer;
  }
  if (issuer && typeof issuer === 'object' && issuer.id) {
    return issuer.id;
  }
  throw new Error(`Cannot extract issuer DID from: ${JSON.stringify(issuer)}`);
}

function handleDidCreate() {
  console.log('Creating new DID...');
  const result = createDid();
  console.log('✅ DID created successfully!');
  console.log(`DID: ${result.did}`);
  console.log(`Public Key: ${result.publicKey.substring(0, 32)}...`);
}

function handleDidList() {
  const dids = listDids();
  if (dids.length === 0) {
    console.log('No DIDs found in wallet.');
    return;
  }

  console.log(`\nFound ${dids.length} DID(s):\n`);
  dids.forEach((didInfo, index) => {
    console.log(`${index + 1}. ${didInfo.did}`);
    console.log(`   Created: ${didInfo.createdAt}`);
  });
}

function handleDidResolve(did) {
  if (!did) {
    console.error('Error: DID required');
    process.exit(1);
  }

  // Validate DID format before attempting resolution
  try {
    validateDid(did);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }

  try {
    const keys = getDidKeys(did);
    const publicKeyMultibase = 'z' + bs58.encode(keys.publicKey);
    const doc = buildDidDocument(did, publicKeyMultibase);
    console.log(JSON.stringify(doc, null, 2));
  } catch (error) {
    console.error(`Error: Could not resolve DID ${did}`);
    console.error('Make sure the DID exists in your wallet.');
    process.exit(1);
  }
}

function handleVcIssue(options) {
  if (!options.issuer || !options.subject) {
    console.error('Error: --issuer and --subject are required');
    process.exit(1);
  }

  // Validate DID formats
  try {
    validateDid(options.issuer);
    validateDid(options.subject);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }

  const claims = parseClaims(options);

  try {
    const issuerKeys = getDidKeys(options.issuer);

    console.log('Issuing credential...');
    console.log(`  Issuer: ${options.issuer}`);
    console.log(`  Subject: ${options.subject}`);
    console.log(`  Claims: ${JSON.stringify(claims)}`);
    if (options.expires) {
      console.log(`  Expires: ${options.expires}`);
    }

    const issueOptions = {
      issuerDid: options.issuer,
      subjectDid: options.subject,
      subjectClaims: claims,
      issuerPublicKeyId: `${options.issuer}#key-1`,
      issuerPrivateKey: issuerKeys.privateKey
    };

    // Support optional expiration date
    if (options.expires) {
      issueOptions.expirationDate = options.expires;
    }

    const vc = issueCredential(issueOptions);

    const credentialId = storeCredential(vc);

    console.log('✅ Credential issued successfully!');
    console.log(`Credential ID: ${credentialId}`);
    console.log(`\nTo verify, run: node src/cli/index.js vc:verify --id ${credentialId}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    console.error('Make sure the issuer DID exists in your wallet.');
    process.exit(1);
  }
}

function handleVcList() {
  const credentials = listCredentials();
  if (credentials.length === 0) {
    console.log('No credentials found in wallet.');
    return;
  }

  console.log(`\nFound ${credentials.length} credential(s):\n`);
  credentials.forEach((cred, index) => {
    const vc = cred.credential;
    console.log(`${index + 1}. ${cred.id}`);
    console.log(`   Type: ${vc.type?.join(', ') || 'N/A'}`);
    console.log(`   Issuer: ${typeof vc.issuer === 'string' ? vc.issuer : vc.issuer?.id || 'N/A'}`);
    console.log(`   Subject: ${vc.credentialSubject?.id || 'N/A'}`);
    console.log(`   Issued: ${vc.issuanceDate}`);
    if (vc.expirationDate) {
      console.log(`   Expires: ${vc.expirationDate}`);
    }
    console.log(`   Stored: ${cred.storedAt}`);
  });
}

function handleVcShow(id) {
  if (!id) {
    console.error('Error: Credential ID required');
    process.exit(1);
  }

  const credential = getCredential(id);
  if (!credential) {
    console.error(`Error: Credential ${id} not found`);
    process.exit(1);
  }

  console.log(JSON.stringify(credential, null, 2));
}

function handleVcVerify(options) {
  if (!options.id) {
    console.error('Error: --id required');
    process.exit(1);
  }

  const credential = getCredential(options.id);
  if (!credential) {
    console.error(`Error: Credential ${options.id} not found`);
    process.exit(1);
  }

  try {
    // FIX M6: Handle both string and object issuer forms
    const issuerDid = extractIssuerDid(credential.issuer);
    const issuerKeys = getDidKeys(issuerDid);
    const result = verifyCredential(credential, issuerKeys.publicKey);

    if (result.valid) {
      console.log('✅ Credential is VALID');
      console.log(`   ${result.reason}`);
    } else {
      console.log('❌ Credential is INVALID');
      console.log(`   ${result.reason}`);
      process.exit(1);
    }
  } catch (error) {
    console.error(`Verification error: ${error.message}`);
    process.exit(1);
  }
}

function handleVcDelete(options) {
  if (!options.id) {
    console.error('Error: --id required');
    process.exit(1);
  }

  const deleted = deleteCredential(options.id);
  if (deleted) {
    console.log('✅ Credential deleted successfully');
  } else {
    console.error(`Error: Credential ${options.id} not found`);
    process.exit(1);
  }
}

function handleWalletInit() {
  const status = getWalletStatus();
  console.log('✅ Wallet initialized');
  console.log(`Wallet directory: ${status.walletDir}`);
}

function handleWalletStatus() {
  const status = getWalletStatus();
  console.log('\nWallet Status:\n');
  console.log(`  Directory: ${status.walletDir}`);
  console.log(`  DIDs: ${status.didCount}`);
  console.log(`  Credentials: ${status.credentialCount}`);
}

function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    printUsage();
    process.exit(0);
  }

  const { command, options, positional } = parseArgs(args);

  try {
    switch (command) {
      case 'did:create':
        handleDidCreate();
        break;
      case 'did:list':
        handleDidList();
        break;
      case 'did:resolve':
        handleDidResolve(positional[0]);
        break;
      case 'vc:issue':
        handleVcIssue(options);
        break;
      case 'vc:list':
        handleVcList();
        break;
      case 'vc:show':
        handleVcShow(positional[0]);
        break;
      case 'vc:verify':
        handleVcVerify(options);
        break;
      case 'vc:delete':
        handleVcDelete(options);
        break;
      case 'wallet:init':
        handleWalletInit();
        break;
      case 'wallet:status':
        handleWalletStatus();
        break;
      default:
        console.error(`Unknown command: ${command}`);
        printUsage();
        process.exit(1);
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  parseArgs,
  parseClaims,
  extractIssuerDid
};