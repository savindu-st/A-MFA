/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * WebAuthn / FIDO2 Relying Party Subsystem (@simplewebauthn/server)
 */

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const RP_NAME = 'Accessible Multi-Factor Authentication (A-MFA)';

function getRpId(req) {
  if (process.env.RP_ID) return process.env.RP_ID;
  const host = req ? req.headers.host : 'localhost:3000';
  return host.split(':')[0];
}

function getExpectedOrigin(req) {
  if (process.env.EXPECTED_ORIGIN) return process.env.EXPECTED_ORIGIN;
  const proto = req && req.headers['x-forwarded-proto'] ? req.headers['x-forwarded-proto'] : 'http';
  const host = req ? req.headers.host : 'localhost:3000';
  return `${proto}://${host}`;
}

/**
 * Generate Registration Options for FIDO2/WebAuthn onboarding
 */
async function getRegistrationOptions(user, req) {
  const rpID = getRpId(req);
  return await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID,
    userID: Buffer.from(user.user_id),
    userName: user.email,
    userDisplayName: user.email.split('@')[0],
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred'
    },
    timeout: 120000 // 2-minute generous accessibility window (WCAG 2.2)
  });
}

/**
 * Verify WebAuthn Registration Response
 */
async function verifyRegistration(response, expectedChallenge, req) {
  const rpID = getRpId(req);
  const expectedOrigin = getExpectedOrigin(req);

  return await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID: rpID,
    requireUserVerification: false
  });
}

/**
 * Generate Authentication Options for WebAuthn assertion
 */
async function getAuthenticationOptions(userCredentials, req) {
  const rpID = getRpId(req);
  
  const allowCredentials = (userCredentials || []).map(cred => ({
    id: cred.credential_id,
    type: 'public-key',
    transports: cred.transports ? cred.transports.split(',') : ['usb', 'nfc', 'internal']
  }));

  return await generateAuthenticationOptions({
    rpID,
    timeout: 120000, // 2 minutes generous accessibility window
    allowCredentials,
    userVerification: 'preferred'
  });
}

/**
 * Verify WebAuthn Authentication Assertion with strict monotonic counter validation
 */
async function verifyAuthentication(response, expectedChallenge, credential, req) {
  const rpID = getRpId(req);
  const expectedOrigin = getExpectedOrigin(req);

  // Parse stored public key from Base64 or Buffer
  let publicKeyBytes;
  if (typeof credential.public_key === 'string') {
    publicKeyBytes = Buffer.from(credential.public_key, 'base64');
  } else {
    publicKeyBytes = credential.public_key;
  }

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID: rpID,
    authenticator: {
      credentialID: credential.credential_id,
      credentialPublicKey: publicKeyBytes,
      counter: credential.signature_counter || 0
    },
    requireUserVerification: false
  });

  const { verified, authenticationInfo } = verification;

  // Strict monotonic signature counter check for authenticator cloning detection
  let cloningDetected = false;
  if (verified && authenticationInfo) {
    const prevCounter = credential.signature_counter || 0;
    const currentCounter = authenticationInfo.newCounter;

    // If both counters are > 0 and current is not strictly greater, potential clone!
    if (prevCounter > 0 && currentCounter > 0 && currentCounter <= prevCounter) {
      cloningDetected = true;
    }
  }

  return {
    verified,
    cloningDetected,
    newCounter: authenticationInfo ? authenticationInfo.newCounter : 0
  };
}

module.exports = {
  RP_NAME,
  getRpId,
  getExpectedOrigin,
  getRegistrationOptions,
  verifyRegistration,
  getAuthenticationOptions,
  verifyAuthentication
};
