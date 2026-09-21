/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * Database Persistence Module (SQLite with Relational Schema Mirroring PostgreSQL)
 */

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

let dbInstance = null;

function initDatabase(dbPath = null) {
  if (dbInstance) return dbInstance;

  const targetPath = dbPath || process.env.DB_PATH || path.join(__dirname, '../../data/amfa.sqlite');
  
  if (targetPath !== ':memory:') {
    const dir = path.dirname(targetPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new DatabaseSync(targetPath);

  // Enable foreign keys
  db.exec('PRAGMA foreign_keys = ON;');

  // Create tables matching PostgreSQL schema specification
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      phone_e164 TEXT,
      mfa_enabled INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS user_accessibility_profiles (
      profile_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      preferred_mfa_channel TEXT DEFAULT 'WEBAUTHN',
      session_timeout_seconds INTEGER DEFAULT 300,
      audio_speech_rate REAL DEFAULT 1.00,
      phonetic_assistance_enabled INTEGER DEFAULT 1,
      haptic_feedback_enabled INTEGER DEFAULT 1,
      high_contrast_theme TEXT DEFAULT 'HIGH_CONTRAST_DARK',
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS webauthn_credentials (
      credential_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      public_key TEXT NOT NULL,
      signature_counter INTEGER NOT NULL DEFAULT 0,
      aaguid TEXT,
      device_friendly_name TEXT,
      transports TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      last_used_at TEXT
    );

    CREATE TABLE IF NOT EXISTS auth_active_challenges (
      challenge_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      challenge_value TEXT NOT NULL,
      channel TEXT NOT NULL,
      otp_code TEXT,
      expires_at TEXT NOT NULL,
      is_consumed INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS auth_audit_log (
      log_id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
      event_type TEXT NOT NULL,
      factor_used TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      metadata TEXT,
      event_timestamp TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_user_credentials ON webauthn_credentials(user_id);
    CREATE INDEX IF NOT EXISTS idx_challenges_lookup ON auth_active_challenges(user_id, is_consumed, expires_at);
    CREATE INDEX IF NOT EXISTS idx_audit_event ON auth_audit_log(event_timestamp DESC);
  `);

  dbInstance = db;
  return dbInstance;
}

// User Operations
function getUserByEmail(email) {
  const db = initDatabase();
  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  return stmt.get(email.toLowerCase().trim());
}

function getUserById(userId) {
  const db = initDatabase();
  const stmt = db.prepare('SELECT * FROM users WHERE user_id = ?');
  return stmt.get(userId);
}

function createUser({ email, passwordHash, phone = '+1234567890' }) {
  const db = initDatabase();
  const userId = crypto.randomUUID();
  const profileId = crypto.randomUUID();

  const insertUser = db.prepare(`
    INSERT INTO users (user_id, email, password_hash, phone_e164)
    VALUES (?, ?, ?, ?)
  `);
  insertUser.run(userId, email.toLowerCase().trim(), passwordHash, phone);

  const insertProfile = db.prepare(`
    INSERT INTO user_accessibility_profiles (profile_id, user_id)
    VALUES (?, ?)
  `);
  insertProfile.run(profileId, userId);

  return getUserById(userId);
}

// Profile Operations
function getProfileByUserId(userId) {
  const db = initDatabase();
  const stmt = db.prepare('SELECT * FROM user_accessibility_profiles WHERE user_id = ?');
  return stmt.get(userId);
}

function updateProfile(userId, profile) {
  const db = initDatabase();
  const stmt = db.prepare(`
    UPDATE user_accessibility_profiles
    SET preferred_mfa_channel = coalesce(?, preferred_mfa_channel),
        session_timeout_seconds = coalesce(?, session_timeout_seconds),
        audio_speech_rate = coalesce(?, audio_speech_rate),
        phonetic_assistance_enabled = coalesce(?, phonetic_assistance_enabled),
        haptic_feedback_enabled = coalesce(?, haptic_feedback_enabled),
        high_contrast_theme = coalesce(?, high_contrast_theme)
    WHERE user_id = ?
  `);
  stmt.run(
    profile.preferred_mfa_channel !== undefined ? profile.preferred_mfa_channel : null,
    profile.session_timeout_seconds !== undefined ? profile.session_timeout_seconds : null,
    profile.audio_speech_rate !== undefined ? profile.audio_speech_rate : null,
    profile.phonetic_assistance_enabled !== undefined ? (profile.phonetic_assistance_enabled ? 1 : 0) : null,
    profile.haptic_feedback_enabled !== undefined ? (profile.haptic_feedback_enabled ? 1 : 0) : null,
    profile.high_contrast_theme !== undefined ? profile.high_contrast_theme : null,
    userId
  );
  return getProfileByUserId(userId);
}

// WebAuthn Credential Operations
function saveWebAuthnCredential({ credentialId, userId, publicKey, counter = 0, aaguid = null, deviceName = 'Security Key', transports = 'usb,nfc,internal' }) {
  const db = initDatabase();
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO webauthn_credentials 
      (credential_id, user_id, public_key, signature_counter, aaguid, device_friendly_name, transports, last_used_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `);
  stmt.run(credentialId, userId, publicKey, counter, aaguid, deviceName, transports);
  return getWebAuthnCredentialById(credentialId);
}

function getWebAuthnCredentialsByUserId(userId) {
  const db = initDatabase();
  const stmt = db.prepare('SELECT * FROM webauthn_credentials WHERE user_id = ?');
  return stmt.all(userId);
}

function getWebAuthnCredentialById(credentialId) {
  const db = initDatabase();
  const stmt = db.prepare('SELECT * FROM webauthn_credentials WHERE credential_id = ?');
  return stmt.get(credentialId);
}

function updateWebAuthnCounter(credentialId, newCounter) {
  const db = initDatabase();
  const stmt = db.prepare(`
    UPDATE webauthn_credentials 
    SET signature_counter = ?, last_used_at = datetime('now')
    WHERE credential_id = ?
  `);
  stmt.run(newCounter, credentialId);
}

// Challenge Operations
function createChallenge({ userId, challengeValue, channel, otpCode = null, expiresInSeconds = 300 }) {
  const db = initDatabase();
  const challengeId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();

  // Invalidate any existing unused challenges for this user/channel to ensure strict challenge rotation
  db.prepare(`
    UPDATE auth_active_challenges 
    SET is_consumed = 1 
    WHERE user_id = ? AND channel = ? AND is_consumed = 0
  `).run(userId, channel);

  const stmt = db.prepare(`
    INSERT INTO auth_active_challenges (challenge_id, user_id, challenge_value, channel, otp_code, expires_at, is_consumed)
    VALUES (?, ?, ?, ?, ?, ?, 0)
  `);
  stmt.run(challengeId, userId, challengeValue, channel, otpCode, expiresAt);

  return { challengeId, challengeValue, expiresAt, channel, otpCode };
}

function getActiveChallenge(userId, channel) {
  const db = initDatabase();
  const now = new Date().toISOString();
  const stmt = db.prepare(`
    SELECT * FROM auth_active_challenges
    WHERE user_id = ? AND channel = ? AND is_consumed = 0 AND expires_at > ?
    ORDER BY created_at DESC LIMIT 1
  `);
  return stmt.get(userId, channel, now);
}

function consumeChallenge(challengeId) {
  const db = initDatabase();
  const stmt = db.prepare('UPDATE auth_active_challenges SET is_consumed = 1 WHERE challenge_id = ?');
  stmt.run(challengeId);
}

// Audit Logging Operations
function logAuditEvent({ userId = null, eventType, factorUsed, ipAddress = '127.0.0.1', userAgent = 'Unknown', metadata = {} }) {
  const db = initDatabase();
  const stmt = db.prepare(`
    INSERT INTO auth_audit_log (user_id, event_type, factor_used, ip_address, user_agent, metadata)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  stmt.run(userId, eventType, factorUsed, ipAddress, userAgent, JSON.stringify(metadata));
}

function getAuditLogs(limit = 50, userId = null) {
  const db = initDatabase();
  if (userId) {
    const stmt = db.prepare('SELECT * FROM auth_audit_log WHERE user_id = ? ORDER BY log_id DESC LIMIT ?');
    return stmt.all(userId, limit);
  }
  const stmt = db.prepare('SELECT * FROM auth_audit_log ORDER BY log_id DESC LIMIT ?');
  return stmt.all(limit);
}

module.exports = {
  initDatabase,
  getUserByEmail,
  getUserById,
  createUser,
  getProfileByUserId,
  updateProfile,
  saveWebAuthnCredential,
  getWebAuthnCredentialsByUserId,
  getWebAuthnCredentialById,
  updateWebAuthnCounter,
  createChallenge,
  getActiveChallenge,
  consumeChallenge,
  logAuditEvent,
  getAuditLogs
};
