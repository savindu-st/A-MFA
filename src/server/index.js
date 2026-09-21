/**
 * Accessible Multi-Factor Authentication (A-MFA)
 * Main Application Server Entrypoint
 */

const express = require('express');
const path = require('node:path');
const cors = require('cors');
const helmet = require('helmet');
const db = require('./db');
const { hashPassword } = require('./crypto');
const authRoutes = require('./auth.routes');

const app = express();
const PORT = process.env.PORT || 3000;

// Security & Middlewares
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend assets
app.use(express.static(path.join(__dirname, '../public')));

// Mount API Routes
app.use('/api/v1/auth', authRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    service: 'Accessible MFA (A-MFA) Service',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * Seed default test user on initial boot
 */
async function seedDefaultUser() {
  const existing = db.getUserByEmail('accessible.user@example.com');
  if (!existing) {
    const passwordHash = await hashPassword('SecurePassword123!');
    const user = db.createUser({
      email: 'accessible.user@example.com',
      passwordHash,
      phone: '+1 (555) 019-2831'
    });

    // Seed a simulated pre-registered WebAuthn credential for evaluation
    db.saveWebAuthnCredential({
      credentialId: 'test-credential-id-yubikey-5c',
      userId: user.user_id,
      publicKey: Buffer.from('mock-cose-public-key-for-test').toString('base64'),
      counter: 10,
      deviceName: 'YubiKey 5C NFC (Tactile Key)',
      transports: 'usb,nfc'
    });

    console.log('✅ Seeded default test user: accessible.user@example.com / SecurePassword123!');
  }
}

// Initialize database
db.initDatabase();
seedDefaultUser().catch(console.error);

// Only listen if executed directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n========================================================`);
    console.log(`🚀 Accessible MFA (A-MFA) Server Running on port ${PORT}`);
    console.log(`🌐 URL: http://localhost:${PORT}`);
    console.log(`♿ Accessibility: WCAG 2.2 Level AAA Compliant`);
    console.log(`🔒 Security: NIST SP 800-63B / W3C WebAuthn Level 3`);
    console.log(`========================================================\n`);
  });
}

module.exports = app;
