/* ============================================================
   BIERTEX BACKEND — PostgreSQL Edition
   ============================================================ */

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const multer = require('multer');
const { BrevoClient } = require('@getbrevo/brevo');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;

/* ============================================================
   MIDDLEWARE
   ============================================================ */
app.use(cors());
app.use(express.json({
  verify: (req, res, buf) => {
    if (req.originalUrl === '/api/webhook/shieldz') {
      req.rawBody = buf;
    }
  }
}));

/* ============================================================
   DATABASE (PostgreSQL)
   ============================================================ */
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
/* ============================================================
   WALLET MODULE
   ============================================================ */
const createWallet = require('./wallet');
const wallet = createWallet(pool);

/* ============================================================
   FILE UPLOAD
   ============================================================ */
const kycUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

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
      <div style="margin-top:24px;text-align:center">
  <a href="https://biertex.onrender.com/api/admin/kyc/${user.id}/approve?key=${process.env.ADMIN_KEY}" style="display:inline-block;background:#0ECB81;color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:700;margin:4px">✅ Approve KYC</a>
  <a href="https://biertex.onrender.com/api/admin/kyc/${user.id}/reject?key=${process.env.ADMIN_KEY}" style="display:inline-block;background:#F6465D;color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:700;margin:4px">❌ Reject KYC</a>
</div>
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
function kycApprovedEmailHTML(name){
  return `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#0B0E11;color:#EAECEF;padding:40px;border-radius:14px">
      <div style="text-align:center;margin-bottom:24px">
        <div style="display:inline-block;background:#F0B90B;color:#0B0E11;padding:8px 16px;border-radius:10px;font-weight:800;font-size:18px">◈ BIERTEX</div>
      </div>
      <div style="text-align:center;font-size:56px;margin-bottom:12px">✅</div>
      <h1 style="text-align:center;color:#0ECB81;font-size:24px;margin:0 0 12px 0">KYC Approved</h1>
      <p style="color:#848E9C;text-align:center;margin-bottom:28px">Hi ${name}, great news!</p>
      <p style="color:#EAECEF;text-align:center;font-size:15px">Your identity has been verified. You now have full access to Biertex.</p>
    </div>
  `;
}

function kycRejectedEmailHTML(name){
  return `
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#0B0E11;color:#EAECEF;padding:40px;border-radius:14px">
      <div style="text-align:center;margin-bottom:24px">
        <div style="display:inline-block;background:#F0B90B;color:#0B0E11;padding:8px 16px;border-radius:10px;font-weight:800;font-size:18px">◈ BIERTEX</div>
      </div>
      <div style="text-align:center;font-size:56px;margin-bottom:12px">❌</div>
      <h1 style="text-align:center;color:#F6465D;font-size:24px;margin:0 0 12px 0">KYC Not Approved</h1>
      <p style="color:#848E9C;text-align:center;margin-bottom:28px">Hi ${name},</p>
      <p style="color:#EAECEF;text-align:center;font-size:15px">We couldn't verify your documents. Please contact support for details.</p>
    </div>
  `;
}

async function sendKycStatusEmail(user, status){
  if(!brevo){
    console.log('[KYC STATUS EMAIL SKIPPED]', user.email, status);
    return;
  }
  const isApproved = status === 'verified';
  await brevo.transactionalEmails.sendTransacEmail({
    subject: isApproved ? '✅ KYC Approved — Biertex' : '❌ KYC Update — Biertex',
    htmlContent: isApproved ? kycApprovedEmailHTML(user.name) : kycRejectedEmailHTML(user.name),
    sender: { name: 'Biertex', email: 'biertex.org@gmail.com' },
    to: [{ email: user.email, name: user.name }]
  });
}
function supportEmailHTML(user, subject, message){
  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0B0E11;color:#EAECEF;padding:40px;border-radius:14px">
      <div style="text-align:center;margin-bottom:24px">
        <div style="display:inline-block;background:#F0B90B;color:#0B0E11;padding:8px 16px;border-radius:10px;font-weight:800;font-size:18px">◈ BIERTEX</div>
      </div>
      <h1 style="color:#F0B90B;font-size:22px;margin:0 0 20px 0">📩 Support Request</h1>
      <table style="width:100%;color:#EAECEF;font-size:14px;border-collapse:collapse">
        <tr><td style="padding:8px 0;color:#848E9C;width:120px">From</td><td>${user ? user.name : 'Anonymous'}</td></tr>
        <tr><td style="padding:8px 0;color:#848E9C">Email</td><td>${user ? user.email : 'Not logged in'}</td></tr>
        <tr><td style="padding:8px 0;color:#848E9C">User ID</td><td>${user ? '#' + user.id : '—'}</td></tr>
        <tr><td style="padding:8px 0;color:#848E9C">Time</td><td>${new Date().toUTCString()}</td></tr>
      </table>
      <hr style="border:none;border-top:1px solid #2B3139;margin:20px 0">
      <h3 style="color:#EAECEF;margin:0 0 12px 0">${subject}</h3>
      <div style="background:#12161C;border:1px solid #2B3139;border-radius:12px;padding:20px;color:#EAECEF;font-size:14px;white-space:pre-wrap;line-height:1.6">${message}</div>
      <p style="color:#848E9C;font-size:12px;margin-top:24px">Reply directly to this email to reach the user.</p>
    </div>
  `;
}

async function sendSupportEmail(user, subject, message){
  if(!brevo){
    console.log('[SUPPORT EMAIL SKIPPED]', subject);
    return;
  }
  const emailOpts = {
    subject: `📩 Support: ${subject}`,
    htmlContent: supportEmailHTML(user, subject, message),
    sender: { name: 'Biertex', email: 'biertex.org@gmail.com' },
    to: [{ email: 'biertex.org@gmail.com', name: 'Biertex Support' }]
  };
  if(user) emailOpts.replyTo = { email: user.email, name: user.name };

  await brevo.transactionalEmails.sendTransacEmail(emailOpts);
}
/* ============================================================
   DATABASE INIT
   ============================================================ */
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      email_verified INTEGER DEFAULT 0,
      kyc_status TEXT,
      kyc_name TEXT,
      kyc_id_type TEXT,
      kyc_id_number TEXT,
      kyc_submitted_at TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS verification_codes (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      code_hash TEXT NOT NULL,
      purpose TEXT NOT NULL,
      attempts INTEGER DEFAULT 0,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ DEFAULT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log('✅ Database ready (PostgreSQL)');
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
    if (!name || name.length < 2) return res.status(400).json({ error: 'Name must be at least 2 characters' });
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
    if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id',
      [name, email.toLowerCase(), hash]
    );
    const user = { id: result.rows[0].id, name, email: email.toLowerCase() };
    await wallet.ensureBalances(user.id);

    const code = generateCode();
    const codeHash = hashCode(code, user.id);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    await pool.query("DELETE FROM verification_codes WHERE user_id = $1 AND purpose = 'email_verify'", [user.id]);
    await pool.query(
      "INSERT INTO verification_codes (user_id, code_hash, purpose, expires_at) VALUES ($1, $2, 'email_verify', $3)",
      [user.id, codeHash, expiresAt]
    );

    sendEmail({
      to: user.email,
      toName: user.name,
      subject: 'Your Biertex verification code',
      html: verificationEmailHTML(user.name, code)
    }).catch(e => console.error('Verification email failed:', e.message));

    const token = makeToken(user);
    res.status(201).json({ user, token, needsVerification: true, message: 'Account created. Check your email for a verification code.' });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

/* -------- LOGIN -------- */
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    const user = { id: row.id, name: row.name, email: row.email };
    const token = makeToken(user);

    res.json({ user, token, emailVerified: row.email_verified === 1 });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error during login' });
  }
});

/* -------- GET CURRENT USER -------- */
app.get('/api/me', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT id, name, email, email_verified, created_at FROM users WHERE id = $1', [req.user.id]);
  if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
  res.json({ user: result.rows[0] });
});

/* -------- VERIFY EMAIL WITH CODE -------- */
app.post('/api/verify-email-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: 'Email and code required' });

    const uRes = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = uRes.rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid code' });
    if (user.email_verified === 1) return res.json({ success: true, message: 'Email already verified' });

    const cRes = await pool.query(
      "SELECT * FROM verification_codes WHERE user_id = $1 AND purpose = 'email_verify' AND used_at IS NULL ORDER BY id DESC LIMIT 1",
      [user.id]
    );
    const row = cRes.rows[0];
    if (!row) return res.status(400).json({ error: 'No active code. Request a new one.' });
    if (new Date(row.expires_at) < new Date()) return res.status(400).json({ error: 'Code expired. Request a new one.' });
    if (row.attempts >= 5) return res.status(429).json({ error: 'Too many attempts. Request a new code.' });

    const incomingHash = hashCode(code, user.id);
    if (incomingHash !== row.code_hash) {
      await pool.query('UPDATE verification_codes SET attempts = attempts + 1 WHERE id = $1', [row.id]);
      return res.status(400).json({ error: 'Invalid code' });
    }

    await pool.query('UPDATE users SET email_verified = 1 WHERE id = $1', [user.id]);
    await pool.query('UPDATE verification_codes SET used_at = NOW() WHERE id = $1', [row.id]);

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

    const uRes = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = uRes.rows[0];
    if (!user) return res.json({ success: true, message: 'If that email exists, we sent a code.' });
    if (user.email_verified === 1) return res.json({ success: true, message: 'Email already verified' });

    const lRes = await pool.query(
      "SELECT created_at FROM verification_codes WHERE user_id = $1 AND purpose = 'email_verify' ORDER BY id DESC LIMIT 1",
      [user.id]
    );
    const last = lRes.rows[0];
    if (last) {
      const secs = (Date.now() - new Date(last.created_at).getTime()) / 1000;
      if (secs < 45) return res.status(429).json({ error: 'Please wait before requesting another code' });
    }

    const code = generateCode();
    const codeHash = hashCode(code, user.id);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    await pool.query("DELETE FROM verification_codes WHERE user_id = $1 AND purpose = 'email_verify'", [user.id]);
    await pool.query(
      "INSERT INTO verification_codes (user_id, code_hash, purpose, expires_at) VALUES ($1, $2, 'email_verify', $3)",
      [user.id, codeHash, expiresAt]
    );

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

/* -------- FORGOT PASSWORD -------- */
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const uRes = await pool.query('SELECT id, name, email FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = uRes.rows[0];

    if (user) {
      const code = generateCode();
      const codeHash = hashCode(code, user.id);
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

      await pool.query("DELETE FROM verification_codes WHERE user_id = $1 AND purpose = 'password_reset'", [user.id]);
      await pool.query(
        "INSERT INTO verification_codes (user_id, code_hash, purpose, expires_at) VALUES ($1, $2, 'password_reset', $3)",
        [user.id, codeHash, expiresAt]
      );

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

/* -------- RESET PASSWORD -------- */
app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) return res.status(400).json({ error: 'Email, code, and new password required' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const uRes = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = uRes.rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid code' });

    const cRes = await pool.query(
      "SELECT * FROM verification_codes WHERE user_id = $1 AND purpose = 'password_reset' AND used_at IS NULL ORDER BY id DESC LIMIT 1",
      [user.id]
    );
    const row = cRes.rows[0];
    if (!row) return res.status(400).json({ error: 'No active reset code' });
    if (new Date(row.expires_at) < new Date()) return res.status(400).json({ error: 'Code expired. Request a new one.' });
    if (row.attempts >= 5) return res.status(429).json({ error: 'Too many attempts. Request a new code.' });

    const incomingHash = hashCode(code, user.id);
    if (incomingHash !== row.code_hash) {
      await pool.query('UPDATE verification_codes SET attempts = attempts + 1 WHERE id = $1', [row.id]);
      return res.status(400).json({ error: 'Invalid code' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, user.id]);
    await pool.query('UPDATE verification_codes SET used_at = NOW() WHERE id = $1', [row.id]);

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

    const uRes = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [req.user.id]);
    const user = uRes.rows[0];
    if(!user) return res.status(404).json({ error: 'User not found' });

    const now = new Date().toISOString();
    await pool.query(
      `UPDATE users SET kyc_status='pending', kyc_name=$1, kyc_id_type=$2, kyc_id_number=$3, kyc_submitted_at=$4 WHERE id=$5`,
      [name, idType, idNumber, now, user.id]
    );

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
app.get('/api/kyc/status', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT kyc_status, kyc_submitted_at FROM users WHERE id = $1', [req.user.id]);
  const row = result.rows[0];
  if(!row) return res.status(404).json({ error: 'User not found' });
  res.json({ status: row.kyc_status || 'none', submittedAt: row.kyc_submitted_at || null });
});

/* -------- SUPPORT TICKET -------- */
app.post('/api/support', async (req, res) => {
  try {
    const { subject, message } = req.body;
    if(!subject || subject.length < 2) return res.status(400).json({ error: 'Subject required' });
    if(!message || message.length < 5) return res.status(400).json({ error: 'Message required' });

    let user = null;
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if(token){
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const result = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [decoded.id]);
        user = result.rows[0] || null;
      } catch(e){ /* anonymous */ }
    }

    sendSupportEmail(user, subject, message)
      .catch(e => console.error('Support email failed:', e.message));

    res.json({ success: true, message: 'Ticket received' });
  } catch(e){
    console.error('Support error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});
/* -------- ADMIN: APPROVE KYC -------- */
app.get('/api/admin/kyc/:id/approve', async (req, res) => {
  try {
    const key = req.query.key;
    if(!key || key !== process.env.ADMIN_KEY){
      return res.status(403).send('<h1>❌ Forbidden</h1><p>Invalid admin key.</p>');
    }
    const userId = parseInt(req.params.id);
    if(!userId) return res.status(400).send('Invalid user ID');

    const uRes = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [userId]);
    const user = uRes.rows[0];
    if(!user) return res.status(404).send('<h1>User not found</h1>');

    await pool.query("UPDATE users SET kyc_status='verified' WHERE id = $1", [userId]);
    sendKycStatusEmail(user, 'verified').catch(e => console.error('KYC email failed:', e.message));

    res.send(`
      <html><head><title>KYC Approved</title></head>
      <body style="font-family:Arial;background:#0B0E11;color:#EAECEF;padding:60px;text-align:center">
        <div style="font-size:64px">✅</div>
        <h1 style="color:#0ECB81">KYC Approved</h1>
        <p style="color:#848E9C;font-size:16px"><strong>${user.email}</strong> has been verified.</p>
        <p style="color:#848E9C;font-size:14px;margin-top:24px">An email has been sent to the user.</p>
      </body></html>
    `);
  } catch(e){
    console.error('Admin approve error:', e);
    res.status(500).send('Server error');
  }
});

/* -------- ADMIN: REJECT KYC -------- */
app.get('/api/admin/kyc/:id/reject', async (req, res) => {
  try {
    const key = req.query.key;
    if(!key || key !== process.env.ADMIN_KEY){
      return res.status(403).send('<h1>❌ Forbidden</h1><p>Invalid admin key.</p>');
    }
    const userId = parseInt(req.params.id);
    if(!userId) return res.status(400).send('Invalid user ID');

    const uRes = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [userId]);
    const user = uRes.rows[0];
    if(!user) return res.status(404).send('<h1>User not found</h1>');

    await pool.query("UPDATE users SET kyc_status='rejected' WHERE id = $1", [userId]);
    sendKycStatusEmail(user, 'rejected').catch(e => console.error('KYC email failed:', e.message));

    res.send(`
      <html><head><title>KYC Rejected</title></head>
      <body style="font-family:Arial;background:#0B0E11;color:#EAECEF;padding:60px;text-align:center">
        <div style="font-size:64px">❌</div>
        <h1 style="color:#F6465D">KYC Rejected</h1>
        <p style="color:#848E9C;font-size:16px"><strong>${user.email}</strong> has been rejected.</p>
      </body></html>
    `);
  } catch(e){
    console.error('Admin reject error:', e);
    res.status(500).send('Server error');
  }
});

/* ============================================================
   START SERVER
   ============================================================ */
(async () => {
  try {
    await initDb();
    /* ============================================================
   WALLET ROUTES
   ============================================================ */

app.get('/api/wallet', requireAuth, async (req, res) => {
  try {
    const balances = await wallet.getAllBalances(req.user.id);
    res.json({ balances });
  } catch (err) {
    console.error('GET /api/wallet', err);
    res.status(500).json({ error: 'Failed to load wallet' });
  }
});

app.get('/api/wallet/transactions', requireAuth, async (req, res) => {
  try {
    const asset = req.query.asset || null;
    const limit = parseInt(req.query.limit, 10) || 50;
    const transactions = await wallet.getTransactions(req.user.id, { asset, limit });
    res.json({ transactions });
  } catch (err) {
    console.error('GET /api/wallet/transactions', err);
    res.status(500).json({ error: 'Failed to load transactions' });
  }
});

/* ============================================================
   ADMIN — WALLET BACKFILL + MANUAL CREDIT
   ============================================================ */

app.get('/api/admin/wallet/backfill', async (req, res) => {
  if (req.query.key !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: 'forbidden' });
  }
  try {
    const { rows } = await pool.query('SELECT id FROM users');
    for (const r of rows) await wallet.ensureBalances(r.id);
    res.json({ ok: true, usersProcessed: rows.length });
  } catch (err) {
    console.error('admin backfill', err);
    res.status(500).json({ error: 'backfill failed' });
  }
});

app.post('/api/admin/wallet/credit', async (req, res) => {
  if (req.query.key !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const { userId, asset, amount, reason } = req.body || {};
  if (!userId || !asset || amount == null) {
    return res.status(400).json({ error: 'userId, asset, amount required' });
  }
  try {
    const out = await wallet.applyEntry({
      userId: Number(userId),
      asset,
      amount: Number(amount),
      type: 'adjustment',
      refId: `admin-${Date.now()}-${userId}`,
      metadata: { reason: reason || 'admin credit' },
    });
    res.json(out);
  } catch (err) {
    console.error('admin credit', err);
    res.status(400).json({ error: err.message });
  }
});
    /* ============================================================
   SHIELDZ — DEPOSIT + WEBHOOK
   ============================================================ */

const SHIELDZ_API_BASE = 'https://shieldz.cash/api/v1';

app.post('/api/wallet/deposit', requireAuth, async (req, res) => {
  try {
    if (!process.env.SHIELDZ_API_KEY) {
      return res.status(500).json({ error: 'Deposits not configured' });
    }
    const { amount_usd_cents } = req.body || {};
    const cents = parseInt(amount_usd_cents, 10);
    if (!cents || cents < 100) {
      return res.status(400).json({ error: 'Minimum deposit is $1.00' });
    }
    if (cents > 1000000) {
      return res.status(400).json({ error: 'Maximum deposit is $10,000' });
    }

    const origin = req.headers.origin || 'https://biertex-org.pages.dev';
    const returnUrl = origin + '/?deposit=success';

    const payload = {
      amount_usd_cents: cents,
      customer_email: req.user.email,
      memo: 'Biertex deposit',
      metadata: { user_id: req.user.id },
      return_url: returnUrl,
    };

    const shRes = await fetch(SHIELDZ_API_BASE + '/invoices', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + process.env.SHIELDZ_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const shData = await shRes.json();
    if (!shRes.ok) {
      console.error('Shieldz invoice create failed', shData);
      return res.status(502).json({ error: shData.error || 'Payment provider error' });
    }

    res.json({
      invoice_id: shData.id,
      pay_url: shData.pay_url,
      amount_usd_cents: shData.amount_usd_cents,
      status: shData.status,
    });
  } catch (err) {
    console.error('deposit route error', err);
    res.status(500).json({ error: 'Failed to create deposit' });
  }
});

app.post('/api/webhook/shieldz', async (req, res) => {
  try {
    const secret = process.env.SHIELDZ_WEBHOOK_SECRET;
    if (!secret) {
      console.warn('webhook: SHIELDZ_WEBHOOK_SECRET missing');
      return res.status(200).json({ ok: true, ignored: 'no secret' });
    }

    const sigHeader = req.headers['x-shieldz-signature'] || '';
    const rawBody = req.rawBody ? req.rawBody.toString('utf8') : '';
    if (!rawBody) {
      return res.status(200).json({ ok: true, ignored: 'no body' });
    }

    const parts = sigHeader.split(',');
    const tPart = parts.find(p => p.startsWith('t='));
    if (!tPart) return res.status(200).json({ ok: true, ignored: 'no t' });
    const t = tPart.slice(2);

    if (Math.abs(Math.floor(Date.now() / 1000) - Number(t)) > 300) {
      console.warn('webhook: timestamp too old');
      return res.status(200).json({ ok: true, ignored: 'stale' });
    }

    const expected = crypto.createHmac('sha256', secret)
      .update(t + '.' + rawBody)
      .digest('hex');
    const sigs = parts.filter(p => p.startsWith('v1=')).map(p => p.slice(3));
    const valid = sigs.some(s =>
      s.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected))
    );
    if (!valid) {
      console.warn('webhook: bad signature');
      

      return res.status(200).json({ ok: true, ignored: 'bad sig' });
    }

    const event = JSON.parse(rawBody);
    if (event.type !== 'invoice.paid') {
      return res.status(200).json({ ok: true, ignored: event.type });
    }

    const invoice = event.data && event.data.invoice;
    if (!invoice || !invoice.id) {
      return res.status(200).json({ ok: true, ignored: 'no invoice' });
    }

    const meta = invoice.metadata || {};
    const userId = parseInt(meta.user_id, 10);
    if (!userId) {
      console.warn('webhook: no user_id in metadata', invoice.id);
      return res.status(200).json({ ok: true, ignored: 'no user_id' });
    }

    const cents = parseInt(invoice.amount_usd_cents, 10) || 0;
    if (cents <= 0) {
      return res.status(200).json({ ok: true, ignored: 'zero amount' });
    }
    const usdtAmount = cents / 100;

    try {
      const out = await wallet.applyEntry({
        userId,
        asset: 'USDT',
        amount: usdtAmount,
        type: 'deposit',
        refId: 'shieldz:' + invoice.id,
        metadata: {
          invoice_id: invoice.id,
          amount_usd_cents: cents,
          delivery: req.headers['x-shieldz-delivery'] || null,
        },
      });
      console.log('deposit credited', { userId, invoiceId: invoice.id, amount: usdtAmount });
      return res.status(200).json({ ok: true, credited: usdtAmount, txId: out.txId });
    } catch (err) {
      if (String(err.message || '').includes('duplicate key') ||
          String(err.message || '').includes('unique')) {
        console.log('webhook: already credited', invoice.id);
        return res.status(200).json({ ok: true, ignored: 'already credited' });
      }
      console.error('webhook: credit failed', err);
      return res.status(200).json({ ok: true, error: 'credit failed' });
    }
  } catch (err) {
    console.error('webhook: unexpected', err);
    return res.status(200).json({ ok: true, error: 'handled' });
  }
});
app.listen(PORT, () => {
      console.log('✅ Biertex backend running at http://localhost:' + PORT);
      console.log(' - POST /api/register');
      console.log(' - POST /api/login');
      console.log(' - GET /api/me');
      console.log(' - POST /api/verify-email-code');
      console.log(' - POST /api/resend-code');
      console.log(' - POST /api/forgot-password');
      console.log(' - POST /api/reset-password');
      console.log(' - POST /api/kyc/submit');
      console.log(' - GET /api/kyc/status');
    });
  } catch (e) {
    console.error('❌ Failed to start:', e);
    process.exit(1);
  }
})();
