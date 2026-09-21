/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * Audio Subsystem: Web Audio DTMF Synthesizer, Earcons & Web Speech NATO Phonetics
 */

class AudioSynthesizer {
  constructor() {
    this.audioCtx = null;
    this.speechSynthesis = window.speechSynthesis || null;
    this.speechRate = 1.0;
    this.natoEnabled = true;
    this.soundEffectsEnabled = true;

    // DTMF Frequencies (Row and Column matrices in Hz)
    this.dtmfFreqs = {
      '1': [697, 1209],
      '2': [697, 1336],
      '3': [697, 1477],
      '4': [770, 1209],
      '5': [770, 1336],
      '6': [770, 1477],
      '7': [852, 1209],
      '8': [852, 1336],
      '9': [852, 1477],
      '*': [941, 1209],
      '0': [941, 1336],
      '#': [941, 1477]
    };

    // NATO Phonetic Alphabet Map
    this.natoMap = {
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
  }

  /**
   * Lazily initialize AudioContext upon user gesture (browser autoplay policy)
   */
  getAudioContext() {
    if (!this.audioCtx) {
      const AudioCtxClass = window.AudioContext || window.webkitAudioContext;
      if (AudioCtxClass) {
        this.audioCtx = new AudioCtxClass();
      }
    }
    if (this.audioCtx && this.audioCtx.state === 'suspended') {
      this.audioCtx.resume();
    }
    return this.audioCtx;
  }

  /**
   * Play dual-tone DTMF frequency corresponding to a telephone key
   */
  playDtmfTone(key, durationMs = 180) {
    if (!this.soundEffectsEnabled) return;
    const ctx = this.getAudioContext();
    if (!ctx) return;

    const freqs = this.dtmfFreqs[key];
    if (!freqs) return;

    const [f1, f2] = freqs;
    const now = ctx.currentTime;
    const duration = durationMs / 1000;

    // Master Gain for envelope
    const masterGain = ctx.createGain();
    masterGain.gain.setValueAtTime(0, now);
    masterGain.gain.linearRampToValueAtTime(0.25, now + 0.01);
    masterGain.gain.setValueAtTime(0.25, now + duration - 0.02);
    masterGain.gain.linearRampToValueAtTime(0, now + duration);
    masterGain.connect(ctx.destination);

    // Row Oscillator
    const osc1 = ctx.createOscillator();
    osc1.type = 'sine';
    osc1.frequency.setValueAtTime(f1, now);
    osc1.connect(masterGain);

    // Column Oscillator
    const osc2 = ctx.createOscillator();
    osc2.type = 'sine';
    osc2.frequency.setValueAtTime(f2, now);
    osc2.connect(masterGain);

    osc1.start(now);
    osc2.start(now);
    osc1.stop(now + duration);
    osc2.stop(now + duration);
  }

  /**
   * Earcon: Success Chime (Major Triad: C5 - E5 - G5)
   */
  playSuccessEarcon() {
    if (!this.soundEffectsEnabled) return;
    const ctx = this.getAudioContext();
    if (!ctx) return;

    const now = ctx.currentTime;
    const notes = [523.25, 659.25, 783.99]; // C5, E5, G5

    notes.forEach((freq, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      const startTime = now + idx * 0.08;

      osc.type = 'triangle';
      osc.frequency.setValueAtTime(freq, startTime);

      gain.gain.setValueAtTime(0, startTime);
      gain.gain.linearRampToValueAtTime(0.2, startTime + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.001, startTime + 0.4);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(startTime);
      osc.stop(startTime + 0.4);
    });
  }

  /**
   * Earcon: Failure / Rejection Buzzer (Low Sawtooth)
   */
  playFailureEarcon() {
    if (!this.soundEffectsEnabled) return;
    const ctx = this.getAudioContext();
    if (!ctx) return;

    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(160, now);
    osc.frequency.linearRampToValueAtTime(110, now + 0.35);

    gain.gain.setValueAtTime(0.2, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start(now);
    osc.stop(now + 0.35);
  }

  /**
   * Earcon: Session Warning Tick / Pulse
   */
  playWarningEarcon() {
    if (!this.soundEffectsEnabled) return;
    const ctx = this.getAudioContext();
    if (!ctx) return;

    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = 'sine';
    osc.frequency.setValueAtTime(880, now);
    osc.frequency.setValueAtTime(440, now + 0.1);

    gain.gain.setValueAtTime(0.15, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start(now);
    osc.stop(now + 0.25);
  }

  /**
   * Synthesize spoken speech via Web Speech API
   */
  speakText(text, onComplete = null) {
    if (!this.speechSynthesis) {
      if (onComplete) onComplete();
      return;
    }

    this.speechSynthesis.cancel(); // Stop any pending speech

    const utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = this.speechRate;
    utterance.pitch = 1.0;
    utterance.volume = 1.0;

    if (onComplete) {
      utterance.onend = () => onComplete();
      utterance.onerror = () => onComplete();
    }

    this.speechSynthesis.speak(utterance);
  }

  /**
   * Synthesize a 6-digit OTP with deliberate cadence and NATO phonetic support
   */
  speakOTP(otpCode, onComplete = null) {
    if (!otpCode) return;

    let textToSpeak = 'Your verification code is: ';
    const digits = otpCode.split('');

    if (this.natoEnabled) {
      // Announce each digit along with its NATO word: "One, One. Nine, Niner."
      textToSpeak += digits.map(d => `${d}, as in ${this.natoMap[d] || d}`).join('. ');
    } else {
      // Clear spaced digits: "1 . 2 . 3 . 4 . 5 . 6"
      textToSpeak += digits.join(' . ');
    }

    textToSpeak += '. Repeating code: ' + digits.join(' . ');

    this.speakText(textToSpeak, onComplete);
  }

  /**
   * Stop all ongoing speech and audio
   */
  stopSpeech() {
    if (this.speechSynthesis) {
      this.speechSynthesis.cancel();
    }
  }
}

// Export singleton instance
window.audioSynth = new AudioSynthesizer();
