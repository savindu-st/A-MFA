-- ============================================================================
-- Accessible Multi-Factor Authentication (A-MFA) System
-- Database Schema Specification (PostgreSQL 14+)
-- Classification: Production Security Architecture
-- ============================================================================

-- 1. Enable Cryptographic Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. Core User Directory Table
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Argon2id hash per RFC 9106
    phone_e164 VARCHAR(32),              -- E.164 phone format for accessible IVR fallback
    mfa_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. User Accessibility & Authentication Factor Preferences
CREATE TABLE user_accessibility_profiles (
    profile_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    preferred_mfa_channel VARCHAR(32) DEFAULT 'WEBAUTHN', -- 'WEBAUTHN', 'IVR', 'AUDIO_OTP', 'PUSH'
    session_timeout_seconds INTEGER DEFAULT 300,          -- Default 5 minutes for screen reader comfort (WCAG 2.2)
    audio_speech_rate NUMERIC(3, 2) DEFAULT 1.00,        -- 0.75x to 2.0x playback rate
    phonetic_assistance_enabled BOOLEAN DEFAULT TRUE,     -- Enables NATO phonetic spelling ("Alpha, Bravo...")
    haptic_feedback_enabled BOOLEAN DEFAULT TRUE,         -- Triggers device vibration where supported
    high_contrast_theme VARCHAR(32) DEFAULT 'HIGH_CONTRAST_DARK', -- 'HIGH_CONTRAST_DARK', 'YELLOW_BLACK', 'LIGHT'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. FIDO2 / WebAuthn Registered Authenticators
CREATE TABLE webauthn_credentials (
    credential_id BYTEA PRIMARY KEY,                      -- Unique WebAuthn Credential ID
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,                           -- COSE public key format
    signature_counter BIGINT NOT NULL DEFAULT 0,         -- Monotonically increasing signature counter (cloning detection)
    aaguid UUID,                                         -- Authenticator Attestation GUID
    device_friendly_name VARCHAR(128),                   -- e.g. "YubiKey 5C NFC", "MacBook Touch ID"
    transports VARCHAR(64),                              -- 'usb,nfc,ble,internal'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE
);

-- 5. Authentication Challenges in Transit
CREATE TABLE auth_active_challenges (
    challenge_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    challenge_value VARCHAR(128) NOT NULL,               -- Cryptographically secure random challenge
    channel VARCHAR(32) NOT NULL,                        -- 'WEBAUTHN', 'IVR', 'AUDIO_OTP', 'PUSH'
    otp_code VARCHAR(16),                                -- Hashed or plain OTP if channel is AUDIO_OTP or IVR
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,        -- Strict expiration timestamp
    is_consumed BOOLEAN DEFAULT FALSE,                   -- Single-use replay protection flag
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Compliance & Security Audit Trail
CREATE TABLE auth_audit_log (
    log_id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    event_type VARCHAR(64) NOT NULL,                     -- 'LOGIN_PRIMARY_SUCCESS', 'MFA_WEBAUTHN_SUCCESS', 'MFA_IVR_SUCCESS', 'MFA_FAILED', 'TIMEOUT_EXTENDED', 'CHALLENGE_EXPIRED', 'CLONING_DETECTED'
    factor_used VARCHAR(32) NOT NULL,                    -- 'PASSWORD', 'WEBAUTHN', 'IVR', 'AUDIO_OTP', 'PUSH'
    ip_address INET,
    user_agent TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. High-Performance Indices
CREATE INDEX idx_user_credentials ON webauthn_credentials(user_id);
CREATE INDEX idx_challenges_lookup ON auth_active_challenges(user_id, is_consumed, expires_at);
CREATE INDEX idx_audit_user ON auth_audit_log(user_id, event_timestamp DESC);
CREATE INDEX idx_audit_event_type ON auth_audit_log(event_type, event_timestamp DESC);
