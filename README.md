# Accessible Multi-Factor Authentication (A-MFA) System

**Course:** Computer Security (Sem 5 Group Project)  
**Student Registration:** 230361L — Lakmal H.M.P.  
**Classification:** Production Engineering & Academic Specification  
**Accessibility Conformance:** WCAG 2.2 Level AAA | WAI-ARIA 1.2  
**Security Assurance:** NIST SP 800-63B AAL3 (Primary) / AAL2 (Fallback)  

---

## 📖 Overview

The **Accessible Multi-Factor Authentication (A-MFA)** system solves the critical accessibility crisis in digital authentication for visually impaired users. Traditional MFA systems depend on reading short-lived 6-digit codes on smartphone screens, solving visual CAPTCHAs, or typing into disorienting split-box input fields under high stress—causing high error rates, cognitive fatigue, and account lockouts.

A-MFA re-engineers the secondary verification paradigm by introducing:
1. **Zero-Transcription Primary Factor (FIDO2 / WebAuthn Level 3)**: Cryptographic, phishing-resistant authentication through physical hardware tokens (e.g. YubiKey capacitive touch via USB/NFC) and platform biometrics (Touch ID, Face ID, Windows Hello).
2. **Accessible Telephony Fallback (IVR)**: Automated phone verification using single-keystroke DTMF confirmation ("Press 1 to authorize login") with zero transcription.
3. **Phonetic Audio OTP with Consolidated Input**: Human-spaced speech generation with NATO phonetic alphabet articulation ("One, Oscar-November-Echo"), speed controls (0.75x–2.0x), and strict enforcement of a single consolidated `<input>` field (strictly prohibiting the 6 split boxes).
4. **WCAG 2.2 Dynamic Session Extension**: Audio timeout warnings at 120s, 60s, and 30s, extendable by 5 minutes with a single keystroke (`Alt+E`).
5. **Real-Time Compliance Audit Trail**: Monotonic signature counter tracking to detect authenticator cloning, replay protection, and tamper-evident audit logging.

---

## 🏛️ System Architecture & Artifacts

Comprehensive design documentation, C4 architecture models, sequence diagrams, ERDs, and STRIDE threat models are detailed in:
👉 [`docs/A_MFA_System_Architecture_and_Design_Document.md`](file:///home/savindust/Documents/aca/sem%205/com.%20sec/group_project/docs/A_MFA_System_Architecture_and_Design_Document.md)  
👉 [`docs/schema.sql`](file:///home/savindust/Documents/aca/sem%205/com.%20sec/group_project/docs/schema.sql) (Production PostgreSQL DDL schema)

---

## 🚀 Quickstart & Setup

### Prerequisites
- Node.js version 20+ (Node v22 installed)
- Modern web browser (Chrome, Edge, Safari, Firefox)

### Running with Docker (One-Command Setup)
Make sure Docker Desktop is open and running, then:
```bash
# Build and start the container
docker compose up -d --build

# View real-time container logs
docker compose logs -f

# Stop the container
docker compose down
```

### Running Locally without Docker
```bash
# 1. Install dependencies
npm install

# 2. Run automated test suites (19 test cases)
npm test

# 3. Start the live server
npm start
```
Open your browser and navigate to:
```
http://localhost:3000
```

---

## 🧪 Step-by-Step Demonstration & Grading Guide

The system includes pre-seeded test credentials for immediate evaluation:
- **Email:** `accessible.user@example.com`
- **Password:** `SecurePassword123!`

### Flow 1: Primary Authentication & WebAuthn Touch Activation
1. Navigate to `http://localhost:3000`. The login form is pre-filled with demo credentials.
2. Press **"Continue to Step 2 Verification"** (or press Enter).
3. The page announces via screen reader live region that primary credentials are valid and transitions to the **Two-Step Verification** panel.
4. The **Security Key (FIDO2/WebAuthn)** panel is active by default.
5. Click **"Activate Security Key / Biometrics"**.
   - *With physical hardware:* Touch your YubiKey or platform biometric sensor.
   - *In virtual/headless testing:* The "Enable Virtual Key Simulation" toggle allows testing the complete cryptographic round-trip without physical USB hardware.
6. A success chime earcon sounds, and access is granted to the protected dashboard!

### Flow 2: Accessible Telephony IVR Fallback ("Press 1")
1. In Step 2, select the **"Phone Call (IVR)"** tab (or press `Alt+2`).
2. Click **"Call My Registered Phone"**.
3. An automated accessible telephone call is initiated. The audio synthesizer speaks the prompt: *"Press 1 on your telephone keypad to authorize login, or press 9 to reject."*
4. Click or navigate to Key **"1"** on the interactive keypad. Authentic DTMF dual-tone audio frequencies ($697\text{ Hz} + 1209\text{ Hz}$) will play through Web Audio API.
5. Access is confirmed and granted immediately. Pressing Key **"9"** cleanly rejects the login.

### Flow 3: Phonetic Audio OTP (Single Consolidated Field)
1. In Step 2, select the **"Audio OTP"** tab (or press `Alt+3`).
2. Click **"Generate & Read Verification Code"**.
3. Web Speech API articulates the 6-digit code with human-spaced cadence and NATO phonetic names (e.g. *"Seven, Sierra... Two, Two..."*).
4. Use the slider to test playback rate adjustment (0.75x to 2.0x), or press **`Alt+R`** to replay the spoken code.
5. Type the 6 digits into the single consolidated input field and press Enter.

### Flow 4: WCAG 2.2 Session Extension Control
1. Notice the countdown timer: *"Time remaining: 5 minutes 00 seconds"*.
2. Press **`Alt+E`** anywhere on the page (or click **"Extend Time"**).
3. The server extends the challenge lifetime by +5 minutes, and the polite live region announces the extension without disrupting focus.

### Flow 5: High-Contrast Themes & Accessibility Settings
1. Click the **"⚙️ Settings"** button in the header.
2. Select **"High-Contrast Yellow on Black"** (custom designed for low vision / cataracts) or **"High-Contrast Light"**.
3. Toggle NATO phonetic assistance or auditory earcons.
4. Save preferences.

### Flow 6: Security & Compliance Audit Log Trail
1. Click the **"📋 Audit Log"** button in the header.
2. Inspect the real-time record of cryptographic challenge issuances, factor verifications, session extensions, and cloning checks.

---

## ⌨️ Accessibility Keyboard Shortcuts

| Key Combination | Action Description |
|---|---|
| `Tab` / `Shift+Tab` | Navigate through focusable elements in logical sequential order |
| `Alt + E` | Dynamically extend verification session window by +5 minutes (WCAG 2.2) |
| `Alt + R` | Replay spoken phonetic verification code |
| `Alt + 1` | Switch directly to FIDO2 / WebAuthn panel |
| `Alt + 2` | Switch directly to Telephone IVR panel |
| `Alt + 3` | Switch directly to Phonetic Audio OTP panel |
| `Alt + 4` | Switch directly to Mobile Push panel |
| `Escape` | Close open modal dialogs (Settings or Audit Trail) |
| `Space` / `Enter` | Activate selected buttons or telephone keypad keys |

---

## 📄 License & Academic Attribution
Developed as part of the Sem 5 Computer Security Group Project by student **230361L (Lakmal H.M.P.)**. Conforms strictly to W3C WebAuthn Level 3, WAI-ARIA 1.2, WCAG 2.2, and NIST SP 800-63B standards.
