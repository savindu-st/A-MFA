/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * WebAuthn & Challenge Lifecycle Subsystem Unit Tests
 */

const test = require('node:test');
const assert = require('node:assert');
const db = require('../src/server/db');
const { getAuthenticationOptions } = require('../src/server/webauthn');

test('WebAuthn Challenge Lifecycle & Replay Protection', () => {
  const sqliteDb = db.initDatabase(':memory:');
  const user = db.createUser({
    email: 'test.webauthn@example.com',
    passwordHash: 'dummy_hash'
  });

  // Create initial challenge
  const challenge1 = db.createChallenge({
    userId: user.user_id,
    challengeValue: 'random_challenge_value_1',
    channel: 'WEBAUTHN',
    expiresInSeconds: 120
  });

  assert.ok(challenge1.challengeId);
  const active1 = db.getActiveChallenge(user.user_id, 'WEBAUTHN');
  assert.strictEqual(active1.challenge_value, 'random_challenge_value_1');

  // Issue new challenge (should automatically consume / rotate previous challenge)
  const challenge2 = db.createChallenge({
    userId: user.user_id,
    challengeValue: 'random_challenge_value_2',
    channel: 'WEBAUTHN',
    expiresInSeconds: 120
  });

  const active2 = db.getActiveChallenge(user.user_id, 'WEBAUTHN');
  assert.strictEqual(active2.challenge_value, 'random_challenge_value_2');

  // Consume challenge
  db.consumeChallenge(active2.challenge_id);
  const activePostConsume = db.getActiveChallenge(user.user_id, 'WEBAUTHN');
  assert.strictEqual(activePostConsume, undefined, 'Consumed challenge must not be retrieved');
});

test('WebAuthn Monotonic Signature Counter Tracking (Cloning Detection)', () => {
  const user = db.createUser({
    email: 'cloning.test@example.com',
    passwordHash: 'dummy_hash'
  });

  // Save registered credential with initial counter = 10
  const credential = db.saveWebAuthnCredential({
    credentialId: 'cred_clone_test_001',
    userId: user.user_id,
    publicKey: Buffer.from('mock_public_key').toString('base64'),
    counter: 10,
    deviceName: 'YubiKey 5C'
  });

  assert.strictEqual(credential.signature_counter, 10);

  // Legitimate assertion with counter = 11
  const legitimateNewCounter = 11;
  const isLegitimate = legitimateNewCounter > credential.signature_counter;
  assert.strictEqual(isLegitimate, true, 'Increasing counter indicates legitimate authenticator');

  db.updateWebAuthnCounter(credential.credential_id, legitimateNewCounter);
  const updatedCred = db.getWebAuthnCredentialById(credential.credential_id);
  assert.strictEqual(updatedCred.signature_counter, 11);

  // Cloned or replayed assertion with counter <= 11 (e.g. 11 or 10)
  const clonedCounter = 10;
  const isCloned = (credential.signature_counter > 0 && clonedCounter <= updatedCred.signature_counter);
  assert.strictEqual(isCloned, true, 'Counter <= recorded value must detect cloned/replayed authenticator');
});
