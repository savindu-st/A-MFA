/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * WCAG 2.2 Guideline 2.2.1 (Timing Adjustable) Session Timer
 */

class SessionTimer {
  constructor() {
    this.remainingSeconds = 300;
    this.timerInterval = null;
    this.userId = null;
    this.currentChannel = 'WEBAUTHN';
    this.warnedThresholds = new Set();
    this.onExpireCallback = null;
  }

  /**
   * Start the countdown timer for the active challenge
   */
  start(seconds, userId, channel = 'WEBAUTHN', onExpire = null) {
    this.stop();
    this.remainingSeconds = seconds || 300;
    this.userId = userId;
    this.currentChannel = channel;
    this.warnedThresholds.clear();
    this.onExpireCallback = onExpire;

    this.updateDisplay();

    this.timerInterval = setInterval(() => {
      this.tick();
    }, 1000);
  }

  /**
   * Stop / pause the countdown timer
   */
  stop() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
      this.timerInterval = null;
    }
  }

  /**
   * Decrement each second and trigger WCAG 2.2 alerts
   */
  tick() {
    this.remainingSeconds -= 1;
    this.updateDisplay();

    // WCAG 2.2 Warning thresholds (120s, 60s, 30s)
    if ([120, 60, 30].includes(this.remainingSeconds) && !this.warnedThresholds.has(this.remainingSeconds)) {
      this.warnedThresholds.add(this.remainingSeconds);
      this.announceWarning(this.remainingSeconds);
    }

    if (this.remainingSeconds <= 0) {
      this.stop();
      this.handleExpiry();
    }
  }

  /**
   * Update visual UI countdown display
   */
  updateDisplay() {
    const timeDisplay = document.getElementById('time-remaining');
    const banner = document.getElementById('timeout-banner');
    if (!timeDisplay) return;

    const mins = Math.floor(Math.max(0, this.remainingSeconds) / 60);
    const secs = Math.max(0, this.remainingSeconds) % 60;
    const formatted = `${mins} minute${mins === 1 ? '' : 's'} ${secs.toString().padStart(2, '0')} seconds`;

    timeDisplay.textContent = `Time remaining: ${formatted}`;

    if (banner) {
      if (this.remainingSeconds <= 30) {
        banner.className = 'timeout-banner critical';
      } else if (this.remainingSeconds <= 120) {
        banner.className = 'timeout-banner warning';
      } else {
        banner.className = 'timeout-banner';
      }
    }
  }

  /**
   * Announce verbal warning to screen reader assertive live region
   */
  announceWarning(seconds) {
    const alertAnnouncer = document.getElementById('sr-alert-announcer');
    const warningMsg = `Warning: Your verification session will expire in ${seconds} seconds. Press Alt plus E or activate Extend Time to add 5 minutes.`;

    if (alertAnnouncer) {
      alertAnnouncer.textContent = warningMsg;
    }

    if (window.audioSynth) {
      window.audioSynth.playWarningEarcon();
      window.audioSynth.speakText(warningMsg);
    }
  }

  /**
   * Extend verification window by 300 seconds (+5 minutes) per WCAG 2.2
   */
  async extendSession() {
    if (!this.userId) return;

    try {
      const res = await fetch('/api/v1/auth/session/extend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: this.userId,
          channel: this.currentChannel
        })
      });

      const data = await res.json();
      if (res.ok && data.success) {
        this.remainingSeconds += 300;
        this.warnedThresholds.clear();
        this.updateDisplay();

        const successMsg = "Verification window extended by 5 minutes. You now have plenty of time to complete verification.";
        const politeAnnouncer = document.getElementById('sr-polite-announcer');
        if (politeAnnouncer) politeAnnouncer.textContent = successMsg;
        if (window.audioSynth) {
          window.audioSynth.playSuccessEarcon();
          window.audioSynth.speakText(successMsg);
        }
      }
    } catch (err) {
      console.error('Failed to extend session:', err);
    }
  }

  /**
   * Session has expired
   */
  handleExpiry() {
    const alertAnnouncer = document.getElementById('sr-alert-announcer');
    const expiredMsg = "Your authentication session has expired for security. Please restart login.";

    if (alertAnnouncer) alertAnnouncer.textContent = expiredMsg;
    if (window.audioSynth) {
      window.audioSynth.playFailureEarcon();
      window.audioSynth.speakText(expiredMsg);
    }

    if (this.onExpireCallback) {
      this.onExpireCallback();
    }
  }
}

window.sessionTimer = new SessionTimer();
