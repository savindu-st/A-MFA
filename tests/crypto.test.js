/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * Cryptographic Subsystem Unit Tests
 */

const test = require('node:test');
const assert = require('node:assert');
const {
  hashPassword,
  verifyPassword,
  generateSecureChallenge,
  generateNumericOTP,
  toPhoneticSpelling,
  timingSafeEqualStrings,
  NATO_DIGIT_MAP
} = require('../src/server/crypto');

test('Argon2id Password Hashing & Verification', async () => {
  const plainPassword = 'CorrectHorseBatteryStaple!123';
  const wrongPassword = 'WrongPassword456';

  const hash = await hashPassword(plainPassword);
  assert.ok(hash, 'Hash should be generated');
  assert.ok(
    hash.startsWith('$argon2id$') || hash.startsWith('pbkdf2_sha512$'),
    'Hash should follow Argon2id or PBKDF2 standard'
  );

  const isValid = await verifyPassword(plainPassword, hash);
  assert.strictEqual(isValid, true, 'Original password must verify successfully');

  const isInvalid = await verifyPassword(wrongPassword, hash);
  assert.strictEqual(isInvalid, false, 'Incorrect password must be rejected');
});

test('Cryptographic Random Challenge Generator', () => {
  const challenge1 = generateSecureChallenge(32);
  const challenge2 = generateSecureChallenge(32);

  assert.strictEqual(typeof challenge1, 'string');
  assert.strictEqual(typeof challenge2, 'string');
  assert.notStrictEqual(challenge1, challenge2, 'Sequential challenges must be statistically unique');
  assert.ok(challenge1.length >= 40, 'Base64URL challenge should have adequate entropy');
});

test('Numeric OTP & NATO Phonetic Alphabet Cadence', () => {
  const otp = generateNumericOTP();
  assert.match(otp, /^[0-9]{6}$/, 'OTP must be exactly 6 numeric digits');

  const phonetic = toPhoneticSpelling(otp);
  assert.ok(phonetic.length > 0, 'Phonetic spelling must be produced');

  const digits = otp.split('');
  digits.forEach(d => {
    assert.ok(phonetic.includes(NATO_DIGIT_MAP[d]), `Phonetic text must include ${NATO_DIGIT_MAP[d]}`);
  });
});

test('Constant-Time String Comparison', () => {
  const secretA = '739102';
  const secretB = '739102';
  const secretC = '739103';
  const secretD = '73910';

  assert.strictEqual(timingSafeEqualStrings(secretA, secretB), true);
  assert.strictEqual(timingSafeEqualStrings(secretA, secretC), false);
  assert.strictEqual(timingSafeEqualStrings(secretA, secretD), false);
});
