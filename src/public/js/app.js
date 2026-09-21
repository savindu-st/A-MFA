/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * Master Application Controller & WAI-ARIA Keyboard Interaction Engine
 */

document.addEventListener('DOMContentLoaded', () => {
  // Application State
  const state = {
    userId: null,
    userEmail: null,
    currentFactor: 'WEBAUTHN',
    currentOtpCode: null,
    activeChallenge: null
  };

  // DOM Elements
  const primaryAuthCard = document.getElementById('primary-auth-card');
  const mfaAuthCard = document.getElementById('mfa-auth-card');
  const dashboardCard = document.getElementById('dashboard-card');
  const loginForm = document.getElementById('login-form');
  const emailInput = document.getElementById('email-input');
  const passwordInput = document.getElementById('password-input');

  const srPolite = document.getElementById('sr-polite-announcer');
  const srAlert = document.getElementById('sr-alert-announcer');
  const statusAlert = document.getElementById('status-alert');
  const statusAlertMsg = document.getElementById('status-alert-message');

  // Factor Tabs & Panels
  const tabs = {
    WEBAUTHN: document.getElementById('tab-webauthn'),
    IVR: document.getElementById('tab-ivr'),
    AUDIO_OTP: document.getElementById('tab-audio-otp'),
    PUSH: document.getElementById('tab-push')
  };

  const panels = {
    WEBAUTHN: document.getElementById('panel-webauthn'),
    IVR: document.getElementById('panel-ivr'),
    AUDIO_OTP: document.getElementById('panel-audio-otp'),
    PUSH: document.getElementById('panel-push')
  };

  // Modals
  const settingsDialog = document.getElementById('settings-dialog');
  const auditDialog = document.getElementById('audit-dialog');

  /**
   * Screen Reader Announcer Helper
   */
  function announce(msg, isAlert = false) {
    if (isAlert) {
      if (srAlert) srAlert.textContent = msg;
    } else {
      if (srPolite) srPolite.textContent = msg;
    }
  }

  function showStatus(msg, type = 'info') {
    if (!statusAlert || !statusAlertMsg) return;
    statusAlert.className = `alert-box alert-${type}`;
    statusAlertMsg.textContent = msg;
    statusAlert.style.display = 'flex';
  }

  /**
   * Switch Active MFA Factor Tab with Strict ARIA Management
   */
  function selectFactor(factorName, focusPanel = true) {
    state.currentFactor = factorName;

    Object.keys(tabs).forEach(key => {
      const tab = tabs[key];
      const panel = panels[key];
      const isSelected = (key === factorName);

      if (tab) {
        tab.setAttribute('aria-selected', isSelected ? 'true' : 'false');
        tab.tabIndex = isSelected ? 0 : -1;
      }

      if (panel) {
        if (isSelected) {
          panel.removeAttribute('hidden');
        } else {
          panel.setAttribute('hidden', '');
        }
      }
    });

    const activeTab = tabs[factorName];
    if (activeTab) {
      announce(`Switched to ${activeTab.textContent.trim()} verification panel.`);
      if (focusPanel) {
        const firstAction = panels[factorName].querySelector('button, input');
        if (firstAction) firstAction.focus();
      }
    }
  }

  // Bind Tab Click and Keyboard Navigation
  Object.keys(tabs).forEach((key, index, keys) => {
    const tab = tabs[key];
    if (!tab) return;

    tab.addEventListener('click', () => {
      selectFactor(key);
    });

    tab.addEventListener('keydown', (e) => {
      let targetKey = null;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        targetKey = keys[(index + 1) % keys.length];
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        targetKey = keys[(index - 1 + keys.length) % keys.length];
      }

      if (targetKey) {
        e.preventDefault();
        tabs[targetKey].focus();
        selectFactor(targetKey, false);
      }
    });
  });

  /**
   * 1. Primary Authentication Submission (Step 1)
   */
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!email || !password) {
      announce("Please provide both email and password.", true);
      showStatus("Please enter your email and password.", "error");
      return;
    }

    try {
      showStatus("Validating primary credentials with server...", "info");
      announce("Validating primary credentials...");

      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (!res.ok) {
        showStatus(data.error || "Authentication failed.", "error");
        announce(data.error || "Primary authentication failed. Please check credentials.", true);
        if (window.audioSynth) window.audioSynth.playFailureEarcon();
        return;
      }

      state.userId = data.userId;
      state.userEmail = data.email;

      if (data.status === 'AUTHENTICATED') {
        // Single factor user
        renderDashboard(data.user, 'Password', data.sessionToken);
        return;
      }

      // MFA Required - Transition to Step 2
      primaryAuthCard.style.display = 'none';
      mfaAuthCard.style.display = 'block';

      // Start WCAG 2.2 Dynamic Session Timer (5 minutes / 300s)
      window.sessionTimer.start(data.profile?.timeoutSeconds || 300, state.userId, 'WEBAUTHN', () => {
        showStatus("Session timed out. Please sign in again.", "error");
        resetToPrimaryLogin();
      });

      // Announce transition to screen reader
      const promptText = "Primary credentials verified. Two-step verification required. Please touch your security key or choose an accessible alternative.";
      announce(promptText);
      if (window.audioSynth) {
        window.audioSynth.playSuccessEarcon();
        window.audioSynth.speakText(promptText);
      }

      // Default to WebAuthn / Passkey
      selectFactor('WEBAUTHN');
      document.getElementById('webauthn-trigger').focus();

    } catch (err) {
      console.error(err);
      showStatus("Network error occurred during sign in.", "error");
      announce("Network error occurred. Please try again.", true);
    }
  });

  /**
   * 2. Factor 1: WebAuthn Touch Activation
   */
  const webauthnTrigger = document.getElementById('webauthn-trigger');
  const simulateKeyCheckbox = document.getElementById('simulate-key-checkbox');

  webauthnTrigger.addEventListener('click', async () => {
    try {
      webauthnTrigger.disabled = true;
      window.webauthnClient.virtualTestMode = simulateKeyCheckbox.checked;

      // Fetch WebAuthn assertion challenge options
      const optionsRes = await fetch(`/api/v1/auth/webauthn/generate-options?userId=${state.userId}`);
      const options = await optionsRes.json();

      const result = await window.webauthnClient.executeAccessibleWebAuthn(
        state.userId,
        options,
        srPolite,
        (status, msg) => {
          document.getElementById('webauthn-prompt-text').textContent = msg;
        }
      );

      // Successfully verified!
      window.sessionTimer.stop();
      renderDashboard(result.user, 'FIDO2 / WebAuthn Touch Security Key', result.sessionToken);

    } catch (err) {
      console.error(err);
      document.getElementById('webauthn-prompt-text').textContent = "Key prompt failed or timed out.";
      showStatus(err.message, "error");
    } finally {
      webauthnTrigger.disabled = false;
    }
  });

  /**
   * 3. Factor 2: Telephone IVR Flow
   */
  const ivrTrigger = document.getElementById('ivr-trigger');
  const ivrCallBox = document.getElementById('ivr-call-box');
  const ivrVoiceStatus = document.getElementById('ivr-voice-status');

  ivrTrigger.addEventListener('click', async () => {
    try {
      ivrTrigger.disabled = true;
      announce("Initiating telephone verification call...");

      const res = await fetch('/api/v1/auth/fallback/ivr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: state.userId })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      ivrCallBox.style.display = 'block';
      ivrVoiceStatus.textContent = `Call in progress: "${data.audioPrompt}"`;
      announce(data.audioPrompt);

      if (window.audioSynth) {
        window.audioSynth.speakText(data.audioPrompt);
      }

      // Focus DTMF keypad
      const key1 = document.querySelector('.dtmf-btn[data-key="1"]');
      if (key1) key1.focus();

    } catch (err) {
      showStatus(err.message, "error");
      announce(err.message, true);
    } finally {
      ivrTrigger.disabled = false;
    }
  });

  // DTMF Keypad Click Handlers
  document.querySelectorAll('.dtmf-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const key = btn.getAttribute('data-key');
      
      // Play authentic DTMF audio frequency
      if (window.audioSynth) {
        window.audioSynth.playDtmfTone(key);
      }

      announce(`Keypad ${key} pressed.`);

      try {
        const res = await fetch('/api/v1/auth/fallback/ivr/confirm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            userId: state.userId,
            dtmfKey: key
          })
        });

        const data = await res.json();

        if (res.ok && data.success) {
          window.sessionTimer.stop();
          if (window.audioSynth) window.audioSynth.playSuccessEarcon();
          announce("Telephone authorization confirmed. Access granted.");
          renderDashboard(data.user, 'Interactive Voice Response (IVR DTMF)', data.sessionToken);
        } else {
          if (window.audioSynth) window.audioSynth.playFailureEarcon();
          showStatus(data.error || "Keypad rejection.", "error");
          announce(data.error || "Invalid keypad response.", true);
        }
      } catch (err) {
        console.error(err);
      }
    });
  });

  /**
   * 4. Factor 3: Phonetic Audio OTP Flow
   */
  const audioOtpTrigger = document.getElementById('audio-otp-trigger');
  const audioOtpPlayerBox = document.getElementById('audio-otp-player-box');
  const replayAudioBtn = document.getElementById('replay-audio-btn');
  const speechRateSlider = document.getElementById('speech-rate-slider');
  const speechRateVal = document.getElementById('speech-rate-val');
  const otpInput = document.getElementById('otp-input');
  const submitOtpBtn = document.getElementById('submit-otp-btn');

  audioOtpTrigger.addEventListener('click', async () => {
    try {
      audioOtpTrigger.disabled = true;
      announce("Generating spoken verification code...");

      const res = await fetch('/api/v1/auth/fallback/audio-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: state.userId })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      state.currentOtpCode = data.otpCode;
      audioOtpPlayerBox.style.display = 'block';

      // Read OTP out loud with deliberate cadence and NATO words
      announce(`Verification code generated. Listen carefully: ${data.phoneticSpelling}`);
      if (window.audioSynth) {
        window.audioSynth.speakOTP(data.otpCode, () => {
          // Focus the consolidated single input field when speech completes
          otpInput.focus();
        });
      } else {
        otpInput.focus();
      }

    } catch (err) {
      showStatus(err.message, "error");
      announce(err.message, true);
    } finally {
      audioOtpTrigger.disabled = false;
    }
  });

  replayAudioBtn.addEventListener('click', () => {
    if (state.currentOtpCode && window.audioSynth) {
      announce("Replaying spoken verification code...");
      window.audioSynth.speakOTP(state.currentOtpCode);
    } else {
      announce("No verification code active. Please generate one first.", true);
    }
  });

  speechRateSlider.addEventListener('input', (e) => {
    const rate = parseFloat(e.target.value);
    speechRateVal.textContent = `${rate.toFixed(2)}x`;
    if (window.audioSynth) window.audioSynth.speechRate = rate;
  });

  submitOtpBtn.addEventListener('click', async () => {
    const code = otpInput.value.trim();
    if (!code || code.length !== 6) {
      announce("Please enter the complete 6-digit code.", true);
      showStatus("Please enter all 6 digits of the verification code.", "error");
      otpInput.focus();
      return;
    }

    try {
      const res = await fetch('/api/v1/auth/fallback/audio-otp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: state.userId,
          otp: code
        })
      });

      const data = await res.json();
      if (res.ok && data.success) {
        window.sessionTimer.stop();
        if (window.audioSynth) window.audioSynth.playSuccessEarcon();
        announce("Verification code accepted. Access granted.");
        renderDashboard(data.user, 'Phonetic Audio OTP', data.sessionToken);
      } else {
        if (window.audioSynth) window.audioSynth.playFailureEarcon();
        showStatus(data.error || "Incorrect verification code.", "error");
        announce(data.error || "Incorrect code. Please try again.", true);
        otpInput.select();
      }
    } catch (err) {
      console.error(err);
    }
  });

  /**
   * 5. Factor 4: Mobile Push Flow
   */
  const pushTrigger = document.getElementById('push-trigger');
  const pushNotificationBox = document.getElementById('push-notification-box');
  const pushApproveBtn = document.getElementById('push-approve-btn');
  const pushDenyBtn = document.getElementById('push-deny-btn');

  pushTrigger.addEventListener('click', async () => {
    try {
      pushTrigger.disabled = true;
      announce("Sending push notification to registered device...");

      const res = await fetch('/api/v1/auth/fallback/push', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: state.userId })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      pushNotificationBox.style.display = 'block';
      announce("Mobile push notification simulated. Choose approve or deny below.");
      pushApproveBtn.focus();

    } catch (err) {
      showStatus(err.message, "error");
    } finally {
      pushTrigger.disabled = false;
    }
  });

  pushApproveBtn.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/v1/auth/fallback/push/respond', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: state.userId, approved: true })
      });

      const data = await res.json();
      if (res.ok && data.success) {
        window.sessionTimer.stop();
        if (window.audioSynth) window.audioSynth.playSuccessEarcon();
        announce("Mobile push authorization confirmed. Access granted.");
        renderDashboard(data.user, 'Mobile One-Tap Push', data.sessionToken);
      }
    } catch (err) {
      console.error(err);
    }
  });

  pushDenyBtn.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/v1/auth/fallback/push/respond', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: state.userId, approved: false })
      });
      const data = await res.json();
      showStatus(data.error || "Authentication denied.", "error");
      announce("Login denied on mobile device.", true);
      if (window.audioSynth) window.audioSynth.playFailureEarcon();
    } catch (err) {
      console.error(err);
    }
  });

  /**
   * 6. WCAG 2.2 Dynamic Session Extension Control (Alt+E)
   */
  const extendTimerBtn = document.getElementById('extend-timer-btn');
  extendTimerBtn.addEventListener('click', () => {
    window.sessionTimer.extendSession();
  });

  /**
   * Global Keyboard Shortcuts
   * Alt+E: Extend verification time (+5 min)
   * Alt+R: Replay Audio OTP
   * Alt+1 to Alt+4: Direct Factor Selection
   */
  window.addEventListener('keydown', (e) => {
    if (e.altKey && (e.key === 'e' || e.key === 'E')) {
      e.preventDefault();
      window.sessionTimer.extendSession();
    } else if (e.altKey && (e.key === 'r' || e.key === 'R')) {
      e.preventDefault();
      replayAudioBtn.click();
    } else if (e.altKey && e.key === '1') {
      e.preventDefault();
      selectFactor('WEBAUTHN');
    } else if (e.altKey && e.key === '2') {
      e.preventDefault();
      selectFactor('IVR');
    } else if (e.altKey && e.key === '3') {
      e.preventDefault();
      selectFactor('AUDIO_OTP');
    } else if (e.altKey && e.key === '4') {
      e.preventDefault();
      selectFactor('PUSH');
    }
  });

  /**
   * Back to Login Button
   */
  document.getElementById('back-to-login-btn').addEventListener('click', () => {
    resetToPrimaryLogin();
  });

  function resetToPrimaryLogin() {
    window.sessionTimer.stop();
    mfaAuthCard.style.display = 'none';
    dashboardCard.style.display = 'none';
    primaryAuthCard.style.display = 'block';
    state.userId = null;
    state.currentOtpCode = null;
    emailInput.focus();
    announce("Returned to primary login form.");
  }

  /**
   * Render Dashboard (Step 3)
   */
  function renderDashboard(user, factorName, token) {
    mfaAuthCard.style.display = 'none';
    dashboardCard.style.display = 'block';

    document.getElementById('dash-email').textContent = user.email;
    document.getElementById('dash-factor').textContent = factorName;
    document.getElementById('dash-token').textContent = token;

    announce(`Welcome back ${user.email}. You are securely authenticated via ${factorName}.`);
    document.getElementById('logout-btn').focus();
  }

  document.getElementById('logout-btn').addEventListener('click', () => {
    resetToPrimaryLogin();
    showStatus("You have safely signed out.", "info");
  });

  /**
   * Register New Key from Dashboard
   */
  document.getElementById('register-new-key-btn').addEventListener('click', async () => {
    try {
      announce("Generating security key registration options...");
      const optionsRes = await fetch(`/api/v1/auth/webauthn/register-options?userId=${state.userId}`);
      const options = await optionsRes.json();

      announce("Security key registration initiated. Please insert your key and touch the sensor.");
      showStatus("Insert your physical security key and touch the sensor.", "info");

      if (window.PublicKeyCredential && !simulateKeyCheckbox.checked) {
        // Real WebAuthn registration
        const credential = await navigator.credentials.create({
          publicKey: {
            ...options,
            challenge: Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
            user: {
              ...options.user,
              id: Uint8Array.from(atob(options.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
            }
          }
        });

        const verifyRes = await fetch('/api/v1/auth/webauthn/register-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            userId: state.userId,
            response: credential,
            deviceFriendlyName: 'Registered Security Key'
          })
        });

        const vData = await verifyRes.json();
        if (verifyRes.ok) {
          showStatus("Security key successfully registered!", "success");
          announce("Security key successfully registered!");
        }
      } else {
        // Virtual demo key registration
        await new Promise(r => setTimeout(r, 1000));
        showStatus("Virtual security key registration simulation completed.", "success");
        announce("Virtual security key registered successfully.");
      }
    } catch (err) {
      console.error(err);
      showStatus("Registration cancelled or failed: " + err.message, "error");
    }
  });

  /**
   * 7. Dialogs: Settings & Audit Logs
   */
  document.getElementById('open-settings-btn').addEventListener('click', () => {
    settingsDialog.showModal();
  });

  document.getElementById('close-settings-btn').addEventListener('click', () => {
    settingsDialog.close();
  });

  document.getElementById('save-settings-btn').addEventListener('click', () => {
    const theme = document.getElementById('theme-select').value;
    const speed = parseFloat(document.getElementById('pref-speech-rate').value);
    const nato = document.getElementById('pref-nato-toggle').checked;
    const earcons = document.getElementById('pref-earcons-toggle').checked;

    document.documentElement.setAttribute('data-theme', theme);
    if (window.audioSynth) {
      window.audioSynth.speechRate = speed;
      window.audioSynth.natoEnabled = nato;
      window.audioSynth.soundEffectsEnabled = earcons;
    }

    settingsDialog.close();
    announce("Accessibility preferences updated successfully.");
    showStatus("Preferences saved.", "success");
  });

  // Audit Logs Dialog
  document.getElementById('open-audit-btn').addEventListener('click', async () => {
    auditDialog.showModal();
    await loadAuditLogs();
  });

  document.getElementById('close-audit-btn').addEventListener('click', () => {
    auditDialog.close();
  });

  document.getElementById('refresh-audit-btn').addEventListener('click', async () => {
    await loadAuditLogs();
  });

  async function loadAuditLogs() {
    const tbody = document.getElementById('audit-table-body');
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">Loading audit trail...</td></tr>';

    try {
      const res = await fetch('/api/v1/auth/audit-logs?limit=25');
      const logs = await res.json();

      if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">No audit records found.</td></tr>';
        return;
      }

      tbody.innerHTML = logs.map(l => `
        <tr>
          <td>${l.event_timestamp || 'Now'}</td>
          <td><strong>${l.event_type}</strong></td>
          <td><span class="badge-a11y">${l.factor_used}</span></td>
          <td>${l.ip_address || '127.0.0.1'}</td>
        </tr>
      `).join('');
    } catch (err) {
      tbody.innerHTML = '<tr><td colspan="4" style="color:var(--accent-red); text-align:center;">Failed to fetch logs.</td></tr>';
    }
  }

});
