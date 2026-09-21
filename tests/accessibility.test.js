/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * Frontend WAI-ARIA & Accessibility Specification Conformance Tests
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const htmlPath = path.join(__dirname, '../src/public/index.html');
const htmlContent = fs.readFileSync(htmlPath, 'utf8');

test('A11Y-1: Skip Navigation Link is Implemented', () => {
  assert.ok(
    htmlContent.includes('class="skip-link"'),
    'A skip-link class must exist for keyboard and screen reader users'
  );
  assert.ok(
    htmlContent.includes('href="#main-content"'),
    'Skip link must target #main-content anchor'
  );
});

test('A11Y-2: Proper Heading Hierarchy (Single H1)', () => {
  const h1Matches = htmlContent.match(/<h1[\s>]/g) || [];
  assert.strictEqual(
    h1Matches.length,
    1,
    'Page must contain exactly one <h1> element for clean screen reader landmarks'
  );
});

test('A11Y-3: Dual Managed Screen Reader Live Regions (Polite & Assertive)', () => {
  // Polite Live Region for non-disruptive feedback
  assert.ok(
    htmlContent.includes('id="sr-polite-announcer"'),
    'Polite announcer element must exist'
  );
  assert.ok(
    htmlContent.includes('aria-live="polite"'),
    'Polite live region must declare aria-live="polite"'
  );

  // Assertive Live Region for urgent timeout warnings
  assert.ok(
    htmlContent.includes('id="sr-alert-announcer"'),
    'Assertive alert announcer element must exist'
  );
  assert.ok(
    htmlContent.includes('aria-live="assertive"'),
    'Assertive alert region must declare aria-live="assertive"'
  );
  assert.ok(
    htmlContent.includes('role="alert"'),
    'Assertive alert region must declare role="alert"'
  );
});

test('A11Y-4: Single Consolidated OTP Input (Strict Prohibition of 6 Split Boxes)', () => {
  // Check for the single consolidated input
  assert.ok(
    htmlContent.includes('id="otp-input"'),
    'Single OTP input field must exist'
  );
  assert.ok(
    htmlContent.includes('maxlength="6"'),
    'Consolidated OTP field must have maxlength="6"'
  );
  assert.ok(
    htmlContent.includes('autocomplete="one-time-code"'),
    'OTP field must have autocomplete="one-time-code" for native autofill / AT paste'
  );
  assert.ok(
    htmlContent.includes('inputmode="numeric"'),
    'OTP field must specify inputmode="numeric" for mobile/virtual keyboards'
  );

  // Assert that prohibited split box pattern (multiple maxlength="1" inputs) is absent
  const splitInputMatches = htmlContent.match(/maxlength="1"/g) || [];
  assert.strictEqual(
    splitInputMatches.length,
    0,
    'Splitting OTP across individual 1-character input boxes is strictly prohibited'
  );
});

test('A11Y-5: WCAG 2.2 Guideline 2.2.1 Session Extension Controls', () => {
  assert.ok(
    htmlContent.includes('id="timeout-banner"'),
    'Timeout control banner must be present'
  );
  assert.ok(
    htmlContent.includes('id="time-remaining"'),
    'Time remaining span must be present'
  );
  assert.ok(
    htmlContent.includes('aria-live="off"'),
    'Time remaining span must use aria-live="off" to avoid spamming screen readers every second'
  );
  assert.ok(
    htmlContent.includes('id="extend-timer-btn"'),
    'Extend timer button must be present'
  );
});

test('A11Y-6: Semantic Form Label Association', () => {
  const inputIds = ['email-input', 'password-input', 'otp-input'];
  inputIds.forEach(id => {
    assert.ok(
      htmlContent.includes(`for="${id}"`),
      `Every input (${id}) must have a corresponding <label for="${id}">`
    );
  });
});
