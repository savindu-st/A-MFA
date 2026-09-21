/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * End-to-End API Integration Test Suite
 */

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const app = require('../src/server/index');

let server;
let baseUrl;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://localhost:${port}`;
      resolve();
    });
  });
});

test.after(async () => {
  await new Promise((resolve) => {
    server.close(resolve);
  });
});

async function apiRequest(path, options = {}) {
  const url = `${baseUrl}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  const data = await response.json();
  return { status: response.status, ok: response.ok, data };
}

test('1. Health Check Endpoint', async () => {
  const { ok, data } = await apiRequest('/health', { method: 'GET' });
  assert.strictEqual(ok, true);
  assert.strictEqual(data.status, 'UP');
});

test('2. Primary Authentication (Email + Password)', async () => {
  // Correct credentials
  const valid = await apiRequest('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'accessible.user@example.com',
      password: 'SecurePassword123!'
    })
  });
  assert.strictEqual(valid.status, 200);
  assert.strictEqual(valid.data.status, 'MFA_REQUIRED');
  assert.ok(valid.data.userId);

  // Invalid credentials
  const invalid = await apiRequest('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'accessible.user@example.com',
      password: 'IncorrectPassword!'
    })
  });
  assert.strictEqual(invalid.status, 401);
});

test('3. Factor 1: WebAuthn Challenge Generation & Assertion Flow', async () => {
  // 1. Authenticate primary credentials
  const loginRes = await apiRequest('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'accessible.user@example.com',
      password: 'SecurePassword123!'
    })
  });
  const userId = loginRes.data.userId;

  // 2. Request WebAuthn authentication options
  const optRes = await apiRequest(`/api/v1/auth/webauthn/generate-options?userId=${userId}`, {
    method: 'GET'
  });
  assert.strictEqual(optRes.status, 200);
  assert.ok(optRes.data.challenge, 'Must return cryptographic challenge');

  // 3. Verify assertion (Virtual Test Mode)
  const verifyRes = await apiRequest('/api/v1/auth/webauthn/verify', {
    method: 'POST',
    body: JSON.stringify({
      userId,
      isSimulation: true
    })
  });
  assert.strictEqual(verifyRes.status, 200);
  assert.strictEqual(verifyRes.data.success, true);
  assert.ok(verifyRes.data.sessionToken, 'Must issue secure session token');
});

test('4. Factor 2: Accessible Telephony IVR Fallback Flow', async () => {
  // 1. Authenticate primary credentials
  const loginRes = await apiRequest('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'accessible.user@example.com',
      password: 'SecurePassword123!'
    })
  });
  const userId = loginRes.data.userId;

  // 2. Dispatch accessible IVR call
  const ivrRes = await apiRequest('/api/v1/auth/fallback/ivr', {
    method: 'POST',
    body: JSON.stringify({ userId })
  });
  assert.strictEqual(ivrRes.status, 200);
  assert.strictEqual(ivrRes.data.status, 'IVR_DISPATCHED');
  assert.strictEqual(ivrRes.data.expectedKey, '1');

  // 3. Confirm with DTMF Keypad "1"
  const confirmRes = await apiRequest('/api/v1/auth/fallback/ivr/confirm', {
    method: 'POST',
    body: JSON.stringify({
      userId,
      dtmfKey: '1'
    })
  });
  assert.strictEqual(confirmRes.status, 200);
  assert.strictEqual(confirmRes.data.success, true);
  assert.ok(confirmRes.data.sessionToken);

  // 4. Rejection test with Keypad "9"
  await apiRequest('/api/v1/auth/fallback/ivr', {
    method: 'POST',
    body: JSON.stringify({ userId })
  });
  const rejectRes = await apiRequest('/api/v1/auth/fallback/ivr/confirm', {
    method: 'POST',
    body: JSON.stringify({
      userId,
      dtmfKey: '9'
    })
  });
  assert.strictEqual(rejectRes.status, 403, 'Keypad 9 must reject login');
});

test('5. Factor 3: Phonetic Audio OTP (Single Consolidated Input)', async () => {
  const loginRes = await apiRequest('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'accessible.user@example.com',
      password: 'SecurePassword123!'
    })
  });
  const userId = loginRes.data.userId;

  // 1. Request Audio OTP
  const otpRes = await apiRequest('/api/v1/auth/fallback/audio-otp', {
    method: 'POST',
    body: JSON.stringify({ userId })
  });
  assert.strictEqual(otpRes.status, 200);
  assert.strictEqual(otpRes.data.status, 'AUDIO_OTP_GENERATED');
  assert.ok(otpRes.data.otpCode);
  assert.ok(otpRes.data.phoneticSpelling);

  const correctCode = otpRes.data.otpCode;

  // 2. Reject incorrect 6-digit code
  const wrongRes = await apiRequest('/api/v1/auth/fallback/audio-otp/verify', {
    method: 'POST',
    body: JSON.stringify({
      userId,
      otp: '000000'
    })
  });
  assert.strictEqual(wrongRes.status, 401);

  // 3. Accept correct 6-digit code in single consolidated input
  const validRes = await apiRequest('/api/v1/auth/fallback/audio-otp/verify', {
    method: 'POST',
    body: JSON.stringify({
      userId,
      otp: correctCode
    })
  });
  assert.strictEqual(validRes.status, 200);
  assert.strictEqual(validRes.data.success, true);
  assert.ok(validRes.data.sessionToken);
});

test('6. WCAG 2.2 Guideline 2.2.1 Dynamic Session Extension (+5 min)', async () => {
  const loginRes = await apiRequest('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'accessible.user@example.com',
      password: 'SecurePassword123!'
    })
  });
  const userId = loginRes.data.userId;

  const extendRes = await apiRequest('/api/v1/auth/session/extend', {
    method: 'POST',
    body: JSON.stringify({
      userId,
      channel: 'WEBAUTHN'
    })
  });
  assert.strictEqual(extendRes.status, 200);
  assert.strictEqual(extendRes.data.success, true);
  assert.strictEqual(extendRes.data.extensionSeconds, 300);
});

test('7. Security Audit Trail Transparency Endpoint', async () => {
  const auditRes = await apiRequest('/api/v1/auth/audit-logs?limit=10', {
    method: 'GET'
  });
  assert.strictEqual(auditRes.status, 200);
  assert.ok(Array.isArray(auditRes.data));
  assert.ok(auditRes.data.length > 0, 'Audit log records must be recorded');
  assert.ok(auditRes.data[0].event_type);
});
