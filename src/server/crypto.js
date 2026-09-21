/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * Cryptographic Subsystem (Argon2id, CSPRNG Challenge & Phonetic Audio Generator)
 */

const crypto = require('node:crypto');
let argon2 = null;

try {
  argon2 = require('@node-rs/argon2');
} catch (err) {
  console.warn('Note: @node-rs/argon2 native binding not available, using PBKDF2-SHA512 fallback.');
}

// NATO phonetic alphabet mapping for digits 0-9 per ICAO / ITU-T P.800
const NATO_DIGIT_MAP = {
  '0': 'Zero',
  '1': 'One',
  '2': 'Two',
  '3': 'Three',
  '4': 'Four',
  '5': 'Five',
  '6': 'Six',
  '7': 'Seven',
  '8': 'Eight',
  '9': 'Niner'
};

/**
 * Hash a password using Argon2id (RFC 9106) or timing-hard PBKDF2
 */
async function hashPassword(plainPassword) {
  if (argon2) {
    return await argon2.hash(plainPassword, {
      memoryCost: 19456, // 19 MiB recommended by OWASP
      timeCost: 2,       // 2 iterations
      parallelism: 1,
      algorithm: 2       // Argon2id
    });
  }

  // Fallback PBKDF2-SHA512 (600,000 iterations per OWASP 2023)
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.pbkdf2Sync(plainPassword, salt, 600000, 64, 'sha512').toString('hex');
  return `pbkdf2_sha512$600000$${salt}$${derived}`;
}

/**
 * Verify a plain password against the stored Argon2id or PBKDF2 hash
 */
async function verifyPassword(plainPassword, storedHash) {
  if (!storedHash || !plainPassword) return false;

  if (storedHash.startsWith('$argon2id$') || storedHash.startsWith('$argon2i$')) {
    if (!argon2) throw new Error('Cannot verify Argon2 hash: argon2 binding unavailable');
    return await argon2.verify(storedHash, plainPassword);
  }

  if (storedHash.startsWith('pbkdf2_sha512$')) {
    const parts = storedHash.split('$');
    const iterations = parseInt(parts[1], 10);
    const salt = parts[2];
    const originalHash = parts[3];
    const derived = crypto.pbkdf2Sync(plainPassword, salt, iterations, 64, 'sha512').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(derived, 'hex'), Buffer.from(originalHash, 'hex'));
  }

  return false;
}

/**
 * Generate a cryptographically secure random challenge string (Base64URL)
 */
function generateSecureChallenge(byteLength = 32) {
  return crypto.randomBytes(byteLength).toString('base64url');
}

/**
 * Generate a 6-digit secure numeric OTP
 */
function generateNumericOTP() {
  return String(crypto.randomInt(100000, 1000000));
}

/**
 * Convert a numeric OTP to NATO phonetic representation with human-spaced cadence
 */
function toPhoneticSpelling(otpString) {
  if (!otpString) return '';
  return otpString
    .split('')
    .map(digit => NATO_DIGIT_MAP[digit] || digit)
    .join(', ');
}

/**
 * Timing-safe string comparison
 */
function timingSafeEqualStrings(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateSecureChallenge,
  generateNumericOTP,
  toPhoneticSpelling,
  timingSafeEqualStrings,
  NATO_DIGIT_MAP
};
