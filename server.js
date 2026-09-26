/* ============================================================
   BIERTEX BACKEND — Full Server
   Auth + Email Verification + Password Reset
   ============================================================ */

const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { BrevoClient } = require('@getbrevo/brevo');
const multer = require('multer');
const kycUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const BREVO_API_KEY = process.env.BREVO_API_KEY;

/* ============================================================
   MIDDLEWARE
   ============================================================ */
app.use(cors());
app.use(express.json());

/* ============================================================
   DATABASE
   ============================================================ */
const db = new Database('biertex.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Add email_verified column if it doesn't exist
const hasEmailVerified = db.prepare(
  "SELECT COUNT(*) as c FROM pragma_table_info('users') WHERE name='email_verified'"
).get().c > 0;
if (!hasEmailVerified) {
  db.exec('ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0');
}

// Verification codes table (handles email verify + password reset)
db.exec(`
  CREATE TABLE IF NOT EXISTS verification_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    purpose TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    expires_at TEXT NOT NULL,
    used_at TEXT DEFAULT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Add KYC columns to users (idempotent)
const kycCols = ['kyc_status','kyc_name','kyc_id_type','kyc_id_number','kyc_submitted_at'];
kycCols.forEach(col => {
  const exists = db.prepare("SELECT COUNT(*) as c FROM pragma_table_info('users') WHERE name=?").get(col).c > 0;
  if(!exists) db.exec(`ALTER TABLE users ADD COLUMN ${col} TEXT`);
});
console.log('✅ Database ready (biertex.db)');

/* ============================================================
   BREVO CLIENT
   ============================================================ */
let brevo = null;
if (BREVO_API_KEY) {
  brevo = new BrevoClient({ apiKey: BREVO_API_KEY });
  console.log('✅ Brevo client initialized');
} else {
  console.warn('⚠️ BREVO_API_KEY not set — emails will be skipped');
}

/* ============================================================
   HELPERS
   ============================================================ */
function makeToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function generateCode() {
  return String(crypto.randomInt(100000, 999999));
}

function hashCode(code, userId) {
  return crypto.createHash('sha256').update(code + ':' + userId + ':' + JWT_SECRET).digest('hex');
}

async function sendEmail({ to, toName, subject, html }) {
  if (!brevo) {
    console.log('[EMAIL SKIPPED]', subject, '→', to);
    return;
  }
  await brevo.transactionalEmails.sendTransacEmail({
    subject,
    htmlContent: html,
    sender: { name: 'Biertex', email: 'biertex.org@gmail.com' },
    to: [{ email: to, name: toName }]
  });
}
function kycEmailHTML(user, kycData) {
  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0B0E11;color:#EAECEF;padding:40px;border-radius:14px">
      <div style="text-align:center;margin-bottom:24px">
        <div style="display:inline-block;background:#F0B90B;color:#0B0E11;padding:8px 16px;border-radius:10px;font-weight:800;font-size:18px">◈ BIERTEX</div>
      </div>
      <h1 style="color:#F0B90B;font-size:22px;margin:0 0 20px 0">📋 New KYC Submission</h1>
      <table style="width:100%;color:#EAECEF;font-size:14px;border-collapse:collapse">
        <tr><td style="padding:8px 0;color:#848E9C;width:140px">User</td><td>${user.name}</td></tr>
        <tr><td style="padding:8px 0;color:#848E9C">Email</td><td>${user.email}</td></tr>
        <tr><td style="padding:8px 0;color:#848E9C">User ID</td><td>#${user.id}</td></tr>
        <tr><td style="padding:8px 0;color:#848E9C">Submitted</td><td>${new Date().toUTCString()}</td></tr>
      </table>
      <hr style="border:none;border-top:1px solid #2B3139;margin:20px 0">
      <table style="width:100%;color:#EAECEF;font-size:14px;border-collapse:collapse">
        <tr><td style="padding:8px 0;color:#848E9C;width:140px">Legal Name</td><td>${kycData.name}</td></tr>
        <tr><td style="padding:8px 0;color:#848E9C">ID Type</td><td>${kycData.idType}</td></tr>
        <tr><td style="padding:8px 0;color:#848E9C">ID Number</td><td>${kycData.idNumber}</td></tr>
      </table>
      <hr style="border:none;border-top:1px solid #2B3139;margin:20px 0">
      <p style="color:#848E9C;font-size:13px">See attached ID photos to verify.</p>
      <p style="color:#848E9C;font-size:12px;margin-top:24px">To approve in DB:<br><code style="color:#0ECB81">UPDATE users SET kyc_status='verified' WHERE id=${user.id};</code></p>
      <p style="color:#848E9C;font-size:12px">To reject:<br><code style="color:#F6465D">UPDATE users SET kyc_status='rejected' WHERE id=${user.id};</code></p>
    </div>
  `;
}

async function sendKycEmail(user, kycData, files){
  if(!brevo){
    console.log('[KYC EMAIL SKIPPED]', user.email);
    return;
  }
  const attachments = files.map(f => ({
    name: f.originalname,
    content: f.buffer.toString('base64')
  }));

  await brevo.transactionalEmails.sendTransacEmail({
    subject: `📋 KYC Submission — ${user.name}`,
    htmlContent: kycEmailHTML(user, kycData),
    sender: { name: 'Biertex', email: 'biertex.org@gmail.com' },
    to: [{ email: 'biertex.org@gmail.com', name: 'Biertex Admin' }],
    attachment: attachments
  });
}

function verificationEmailHTML(name, code) {
  return `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#0B0E11;color:#EAECEF;padding:40px;border-radius:14px">
      <div style="text-align:center;margin-bottom:24px">
        <div style="display:inline-block;background:#F0B90B;color:#0B0E11;padding:8px 16px;border-radius:10px;font-weight:800;font-size:18px">◈ BIERTEX</div>
      </div>
      <h1 style="text-align:center;color:#F0B90B;font-size:22px;margin:0 0 8px 0">Your verification code</h1>
      <p style="color:#848E9C;text-align:center;margin-bottom:28px">Hi ${name}, thanks for signing up.</p>
      <div style="background:#12161C;border:1px solid #2B3139;border-radius:12px;padding:32px;text-align:center;margin-bottom:24px">
        <div style="font-size:38px;font-weight:800;letter-spacing:8px;color:#EAECEF">${code}</div>
      </div>
      <p style="color:#848E9C;text-align:center;font-size:14px">Enter this code on the Verify Email page to activate your account.</p>
      <p style="color:#848E9C;text-align:center;font-size:12px;margin-top:24px">This code expires in 15 minutes. If you didn't sign up, ignore this email.</p>
    </div>
  `;
}

function resetEmailHTML(name, code) {
  return `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#0B0E11;color:#EAECEF;padding:40px;border-radius:14px">
      <div style="text-align:center;margin-bottom:24px">
        <div style="display:inline-block;background:#F0B90B;color:#0B0E11;padding:8px 16px;border-radius:10px;font-weight:800;font-size:18px">◈ BIERTEX</div>
      </div>
      <h1 style="text-align:center;color:#F0B90B;font-size:22px;margin:0 0 8px 0">Password reset code</h1>
      <p style="color:#848E9C;text-align:center;margin-bottom:28px">Hi ${name}, you requested a password reset.</p>
      <div style="background:#12161C;border:1px solid #2B3139;border-radius:12px;padding:32px;text-align:center;margin-bottom:24px">
        <div style="font-size:38px;font-weight:800;letter-spacing:8px;color:#EAECEF">${code}</div>
      </div>
      <p style="color:#848E9C;text-align:center;font-size:14px">Enter this code along with your new password on the reset page.</p>
      <p style="color:#848E9C;text-align:center;font-size:12px;margin-top:24px">Expires in 15 minutes. If you didn't request this, ignore this email.</p>
    </div>
  `;
}
/* ============================================================
   ROUTES
   ============================================================ */

app.get('/', (req, res) => {
  res.send('Biertex backend is running! 🚀');
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Biertex API is live', time: new Date() });
});

/* -------- REGISTER -------- */
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || name.length < 2) {
      return res.status(400).json({ error: 'Name must be at least 2 characters' });
    }
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
    if (existing) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const hash = await bcrypt.hash(password, 10);
    const result = db.prepare(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
    ).run(name, email.toLowerCase(), hash);

    const user = { id: result.lastInsertRowid, name, email: email.toLowerCase() };

    // Generate verification code
    const code = generateCode();
    const codeHash = hashCode(code, user.id);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    // Delete any old codes for this user/purpose
    db.prepare("DELETE FROM verification_codes WHERE user_id = ? AND purpose = 'email_verify'").run(user.id);

    db.prepare(
      "INSERT INTO verification_codes (user_id, code_hash, purpose, expires_at) VALUES (?, ?, 'email_verify', ?)"
    ).run(user.id, codeHash, expiresAt);

    // Send email (don't block if it fails)
    sendEmail({
      to: user.email,
      toName: user.name,
      subject: 'Your Biertex verification code',
      html: verificationEmailHTML(user.name, code)
    }).catch(e => console.error('Verification email failed:', e.message));

    const token = makeToken(user);
    res.status(201).json({
      user,
      token,
      needsVerification: true,
      message: 'Account created. Check your email for a verification code.'
    });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

/* -------- LOGIN -------- */
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!row) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    const user = { id: row.id, name: row.name, email: row.email };
    const token = makeToken(user);

    res.json({
      user,
      token,
      emailVerified: row.email_verified === 1
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error during login' });
  }
});

/* -------- GET CURRENT USER -------- */
app.get('/api/me', requireAuth, (req, res) => {
  const row = db.prepare('SELECT id, name, email, email_verified, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'User not found' });
  res.json({ user: row });
});

/* -------- VERIFY EMAIL WITH CODE -------- */
app.post('/api/verify-email-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ error: 'Email and code required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user) return res.status(400).json({ error: 'Invalid code' });

    if (user.email_verified === 1) {
      return res.json({ success: true, message: 'Email already verified' });
    }

    const row = db.prepare(
      "SELECT * FROM verification_codes WHERE user_id = ? AND purpose = 'email_verify' AND used_at IS NULL ORDER BY id DESC LIMIT 1"
    ).get(user.id);

    if (!row) return res.status(400).json({ error: 'No active code. Request a new one.' });
    if (new Date(row.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Code expired. Request a new one.' });
    }
    if (row.attempts >= 5) {
      return res.status(429).json({ error: 'Too many attempts. Request a new code.' });
    }

    const incomingHash = hashCode(code, user.id);
    if (incomingHash !== row.code_hash) {
      db.prepare('UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?').run(row.id);
      return res.status(400).json({ error: 'Invalid code' });
    }

    db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
    db.prepare("UPDATE verification_codes SET used_at = datetime('now') WHERE id = ?").run(row.id);

    res.json({ success: true, message: 'Email verified' });
  } catch (e) {
    console.error('Verify error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* -------- RESEND VERIFICATION CODE -------- */
app.post('/api/resend-code', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user) return res.json({ success: true, message: 'If that email exists, we sent a code.' });

    if (user.email_verified === 1) {
      return res.json({ success: true, message: 'Email already verified' });
    }

    // Rate limit: max 1 code per 45 seconds
    const last = db.prepare(
      "SELECT created_at FROM verification_codes WHERE user_id = ? AND purpose = 'email_verify' ORDER BY id DESC LIMIT 1"
    ).get(user.id);
    if (last) {
      const secs = (Date.now() - new Date(last.created_at + 'Z').getTime()) / 1000;
      if (secs < 45) {
        return res.status(429).json({ error: 'Please wait before requesting another code' });
      }
    }

    const code = generateCode();
    const codeHash = hashCode(code, user.id);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    db.prepare("DELETE FROM verification_codes WHERE user_id = ? AND purpose = 'email_verify'").run(user.id);
    db.prepare(
      "INSERT INTO verification_codes (user_id, code_hash, purpose, expires_at) VALUES (?, ?, 'email_verify', ?)"
    ).run(user.id, codeHash, expiresAt);

    sendEmail({
      to: user.email,
      toName: user.name,
      subject: 'Your Biertex verification code',
      html: verificationEmailHTML(user.name, code)
    }).catch(e => console.error('Resend email failed:', e.message));

    res.json({ success: true, message: 'Code sent' });
  } catch (e) {
    console.error('Resend error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* -------- FORGOT PASSWORD (send reset code) -------- */
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const user = db.prepare('SELECT id, name, email FROM users WHERE email = ?').get(email.toLowerCase());

    // Always return success (prevent email enumeration)
    if (user) {
      const code = generateCode();
      const codeHash = hashCode(code, user.id);
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

      db.prepare("DELETE FROM verification_codes WHERE user_id = ? AND purpose = 'password_reset'").run(user.id);
      db.prepare(
        "INSERT INTO verification_codes (user_id, code_hash, purpose, expires_at) VALUES (?, ?, 'password_reset', ?)"
      ).run(user.id, codeHash, expiresAt);

      sendEmail({
        to: user.email,
        toName: user.name,
        subject: 'Your Biertex password reset code',
        html: resetEmailHTML(user.name, code)
      }).catch(e => console.error('Reset email failed:', e.message));
    }

    res.json({ success: true, message: 'If that email exists, we sent a reset code.' });
  } catch (e) {
    console.error('Forgot password error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* -------- RESET PASSWORD (with code) -------- */
app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) {
      return res.status(400).json({ error: 'Email, code, and new password required' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user) return res.status(400).json({ error: 'Invalid code' });

    const row = db.prepare(
      "SELECT * FROM verification_codes WHERE user_id = ? AND purpose = 'password_reset' AND used_at IS NULL ORDER BY id DESC LIMIT 1"
    ).get(user.id);

    if (!row) return res.status(400).json({ error: 'No active reset code' });
    if (new Date(row.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Code expired. Request a new one.' });
    }
    if (row.attempts >= 5) {
      return res.status(429).json({ error: 'Too many attempts. Request a new code.' });
    }

    const incomingHash = hashCode(code, user.id);
    if (incomingHash !== row.code_hash) {
      db.prepare('UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?').run(row.id);
      return res.status(400).json({ error: 'Invalid code' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
    db.prepare("UPDATE verification_codes SET used_at = datetime('now') WHERE id = ?").run(row.id);

    res.json({ success: true, message: 'Password updated. You can now log in.' });
  } catch (e) {
    console.error('Reset password error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* -------- SUBMIT KYC -------- */
app.post('/api/kyc/submit', requireAuth, kycUpload.fields([
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 }
]), async (req, res) => {
  try {
    const { name, idType, idNumber } = req.body;
    if(!name || name.length < 2) return res.status(400).json({ error: 'Full legal name required' });
    if(!idType) return res.status(400).json({ error: 'ID type required' });
    if(!idNumber || idNumber.length < 4) return res.status(400).json({ error: 'Valid ID number required' });
    if(!req.files || !req.files.idFront || !req.files.idBack){
      return res.status(400).json({ error: 'Both ID photos required' });
    }

    const user = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(req.user.id);
    if(!user) return res.status(404).json({ error: 'User not found' });

    const now = new Date().toISOString();
    db.prepare(`UPDATE users SET kyc_status='pending', kyc_name=?, kyc_id_type=?, kyc_id_number=?, kyc_submitted_at=? WHERE id=?`)
      .run(name, idType, idNumber, now, user.id);

    const files = [req.files.idFront[0], req.files.idBack[0]];
    sendKycEmail(user, { name, idType, idNumber }, files)
      .catch(e => console.error('KYC email failed:', e.message));

    res.json({ success: true, status: 'pending' });
  } catch(e){
    console.error('KYC submit error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* -------- GET KYC STATUS -------- */
app.get('/api/kyc/status', requireAuth, (req, res) => {
  const row = db.prepare('SELECT kyc_status, kyc_submitted_at FROM users WHERE id = ?').get(req.user.id);
  if(!row) return res.status(404).json({ error: 'User not found' });
  res.json({
    status: row.kyc_status || 'none',
    submittedAt: row.kyc_submitted_at || null
  });
});

/* ============================================================
   START SERVER
   ============================================================ */
app.listen(PORT, () => {
  console.log('✅ Biertex backend running at http://localhost:' + PORT);
  console.log(' - POST /api/register');
  console.log(' - POST /api/login');
  console.log(' - GET /api/me');
  console.log(' - POST /api/verify-email-code');
  console.log(' - POST /api/resend-code');
  console.log(' - POST /api/forgot-password');
  console.log(' - POST /api/reset-password');
});
