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


const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

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
   MAILTRAP CLIENT
   ============================================================ */
const MAILTRAP_API_TOKEN = process.env.MAILTRAP_API_TOKEN;
if (MAILTRAP_API_TOKEN) {
  console.log('✅ Mailtrap configured');
} else {
  console.warn('⚠️ MAILTRAP_API_TOKEN not set — emails will be skipped');
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

async function sendEmail({ to, toName, subject, html, attachments }) {
  if (!process.env.MAILTRAP_API_TOKEN) {
    console.log('[EMAIL SKIPPED]', subject, '→', to);
    return;
  }
  const body = {
    from: { name: 'Biertex', email: 'noreply@biertex.com' },
    to: [{ email: to, name: toName || to }],
    subject,
    html
  };
  if (attachments) body.attachments = attachments;

  const r = await fetch('https://send.api.mailtrap.io/api/send', {
    method: 'POST',
    headers: {
      'Api-Token': process.env.MAILTRAP_API_TOKEN,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  const data = await r.json();
  if (!r.ok) {
    console.error('Mailtrap error:', data);
    throw new Error('Mailtrap send failed');
  }
  return data;
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
  if(!process.env.MAILTRAP_API_TOKEN){
    console.log('[KYC EMAIL SKIPPED]', user.email);
    return;
  }
  const attachments = files.map(f => ({
    filename: f.originalname,
    content: f.buffer.toString('base64')
  }));

  await sendEmail({
  to: 'biertex.org@gmail.com',
  toName: 'Biertex Admin',
  subject: `📋 KYC Submission — ${user.name}`,
  html: kycEmailHTML(user, kycData),
  attachments: attachments
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
  const isApproved = status === 'verified';
  await sendEmail({
    to: user.email,
    toName: user.name,
    subject: isApproved ? '✅ KYC Approved — Biertex' : '❌ KYC Update — Biertex',
    html: isApproved ? kycApprovedEmailHTML(user.name) : kycRejectedEmailHTML(user.name)
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
  await sendEmail({
    to: 'biertex.org@gmail.com',
    toName: 'Biertex Support',
    subject: `📩 Support: ${subject}`,
    html: supportEmailHTML(user, subject, message)
  });
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
      }).then(r => console.log('FORGOT EMAIL SENT:', JSON.stringify(r))).catch(e => console.error('Reset email FULL ERROR:', e));
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
/* ============================================================
   WITHDRAWALS — request (user side)
   ============================================================ */

app.post('/api/wallet/withdraw', requireAuth, async (req, res) => {
  try {
    const { amount, address } = req.body || {};
    const amt = Number(amount);
    if (!amt || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });
    if (amt < 10) return res.status(400).json({ error: 'Minimum withdrawal is $10' });
    if (amt > 500) return res.status(400).json({ error: 'Maximum withdrawal is $500' });
    if (typeof address !== 'string' || !/^0x[a-fA-F0-9]{40}$/.test(address)) {
      return res.status(400).json({ error: 'Invalid wallet address' });
    }

    const uRes = await pool.query(
      'SELECT withdrawals_enabled FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!uRes.rows.length) return res.status(404).json({ error: 'User not found' });
    if (!uRes.rows[0].withdrawals_enabled) {
      return res.status(403).json({ error: 'Withdrawals are locked. Complete KYC to unlock.' });
    }

    const wRes = await pool.query(
      `INSERT INTO withdrawals (user_id, asset, amount, address, chain, status)
       VALUES ($1, 'USDC', $2, $3, 'BASE', 'pending_approval')
       RETURNING id, amount, address, chain, created_at`,
      [req.user.id, amt, address]
    );
    const withdrawal = wRes.rows[0];
    const refId = 'withdrawal:' + withdrawal.id;

    try {
      await wallet.applyEntry({
        userId: req.user.id,
        asset: 'USDT',
        amount: -amt,
        type: 'withdrawal_lock',
        refId,
        metadata: { withdrawal_id: withdrawal.id, address, chain: 'BASE' },
      });
    } catch (lockErr) {
      await pool.query('DELETE FROM withdrawals WHERE id = $1', [withdrawal.id]);
      const msg = String(lockErr.message || '');
      if (msg.includes('Insufficient')) {
        return res.status(400).json({ error: 'Insufficient balance' });
      }
      throw lockErr;
    }

    await pool.query('UPDATE withdrawals SET ref_id = $1 WHERE id = $2', [refId, withdrawal.id]);
    notifyAdminNewWithdrawal(withdrawal, req.user).catch(e => console.error('admin email failed', e.message));

    res.json({
      id: withdrawal.id,
      amount: amt,
      address,
      chain: 'BASE',
      status: 'pending_approval',
      created_at: withdrawal.created_at,
    });
  } catch (err) {
    console.error('withdraw route error', err);
    res.status(500).json({ error: 'Failed to submit withdrawal request' });
  }
});
/* ============================================================
   WITHDRAWALS — admin notify + approve/reject + admin page
   ============================================================ */

const ADMIN_EMAIL = 'biertex.org@gmail.com';

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
}

async function notifyAdminNewWithdrawal(withdrawal, user) {
  const adminLink = `https://biertex.onrender.com/admin/withdrawals?key=${process.env.ADMIN_KEY}#w${withdrawal.id}`;
  const html = `
    <div style="font-family:system-ui;max-width:520px">
      <h2>New withdrawal request</h2>
      <p><b>User:</b> ${escapeHtml(user.email)} (id ${user.id})</p>
      <p><b>Amount:</b> ${withdrawal.amount} USDC</p>
      <p><b>Address:</b> <code>${escapeHtml(withdrawal.address)}</code></p>
      <p><b>Chain:</b> ${withdrawal.chain}</p>
      <p><b>Submitted:</b> ${withdrawal.created_at}</p>
      <hr>
      <p>
        <a href="${adminLink}" style="background:#16c784;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;display:inline-block">Open admin page</a>
      </p>
      <p style="color:#888;font-size:13px">
        Send ${withdrawal.amount} USDC to the address above from your Trust Wallet (Base network), then paste the tx hash on the admin page.
      </p>
    </div>
  `;
  return sendEmail({
    to: ADMIN_EMAIL,
    toName: 'Biertex Admin',
    subject: `Withdrawal #${withdrawal.id} — ${withdrawal.amount} USDC`,
    html,
  });
}

app.get('/api/admin/withdrawals/:id/complete', async (req, res) => {
  if (req.query.key !== process.env.ADMIN_KEY) return res.status(403).send('forbidden');
  const id = parseInt(req.params.id, 10);
  const tx = String(req.query.tx || '').trim();
  if (!tx) return res.status(400).send('Missing tx hash');
  try {
    const wRes = await pool.query('SELECT * FROM withdrawals WHERE id = $1', [id]);
    if (!wRes.rows.length) return res.status(404).send('Not found');
    const w = wRes.rows[0];
    if (w.status === 'completed') return res.send('Already completed');
    if (w.status !== 'pending_approval') return res.status(400).send('Cannot complete, status = ' + w.status);

    await pool.query(
      `UPDATE withdrawals SET status = 'completed', tx_hash = $1, completed_at = NOW() WHERE id = $2`,
      [tx, id]
    );

    await pool.query(
  `INSERT INTO wallet_transactions (user_id, asset, amount, type, ref_id, metadata)
   VALUES ($1, 'USDT', 0, 'withdrawal_completed', $2, $3)`,
  [w.user_id, 'withdrawal_completed:' + id, { withdrawal_id: id, tx_hash: tx }]
);

    res.send(`Withdrawal #${id} marked as completed.\nTx: ${tx}`);
  } catch (e) {
    console.error('admin complete error', e);
    res.status(500).send('Error: ' + e.message);
  }
});

app.get('/api/admin/withdrawals/:id/reject', async (req, res) => {
  if (req.query.key !== process.env.ADMIN_KEY) return res.status(403).send('forbidden');
  const id = parseInt(req.params.id, 10);
  const reason = String(req.query.reason || '').trim() || 'Rejected by admin';
  try {
    const wRes = await pool.query('SELECT * FROM withdrawals WHERE id = $1', [id]);
    if (!wRes.rows.length) return res.status(404).send('Not found');
    const w = wRes.rows[0];
    if (w.status === 'rejected') return res.send('Already rejected');
    if (w.status !== 'pending_approval') return res.status(400).send('Cannot reject, status = ' + w.status);

    await wallet.applyEntry({
      userId: w.user_id,
      asset: 'USDT',
      amount: Number(w.amount),
      type: 'withdrawal_refund',
      refId: 'withdrawal_refund:' + id,
      metadata: { withdrawal_id: id, reason },
    });

    await pool.query(
      `UPDATE withdrawals SET status = 'rejected', admin_note = $1, rejected_at = NOW() WHERE id = $2`,
      [reason, id]
    );

    res.send(`Withdrawal #${id} rejected.\nBalance refunded.\nReason: ${reason}`);
  } catch (e) {
    console.error('admin reject error', e);
    res.status(500).send('Error: ' + e.message);
  }
});

app.get('/admin/withdrawals', async (req, res) => {
  if (req.query.key !== process.env.ADMIN_KEY) return res.status(403).send('forbidden');
  try {
    const { rows } = await pool.query(
      `SELECT w.id, w.user_id, w.amount, w.address, w.chain, w.created_at, u.email
       FROM withdrawals w JOIN users u ON u.id = w.user_id
       WHERE w.status = 'pending_approval'
       ORDER BY w.created_at ASC`
    );

    const cards = rows.map(w => `
      <div class="card" id="w${w.id}">
        <div class="row"><span class="muted">Withdrawal #${w.id}</span><span class="muted">${new Date(w.created_at).toLocaleString()}</span></div>
        <div class="amt">${w.amount} USDC</div>
        <div class="row"><span class="muted">User</span><span>${escapeHtml(w.email)} (id ${w.user_id})</span></div>
        <div class="row"><span class="muted">Address</span><span style="font-family:monospace;word-break:break-all;text-align:right">${escapeHtml(w.address)}</span></div>
        <div class="row"><span class="muted">Chain</span><span>${w.chain}</span></div>
        <hr>
        <p class="muted">1. Send <b>${w.amount} USDC</b> to the address above from Trust Wallet (Base network).</p>
        <p class="muted">2. Paste the tx hash here and click Complete.</p>
        <input type="text" id="tx${w.id}" placeholder="0x... tx hash">
        <div style="margin-top:12px">
          <button class="btn-green" onclick="completeW(${w.id})">Complete</button>
          <button class="btn-red" onclick="rejectW(${w.id})">Reject</button>
        </div>
      </div>
    `).join('');

    res.send(`<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Biertex — Pending withdrawals</title>
<style>
  body{font-family:system-ui;background:#0b0e11;color:#eaecef;padding:16px;max-width:640px;margin:0 auto}
  .card{background:#1e2329;border-radius:8px;padding:16px;margin-bottom:12px}
  .row{display:flex;justify-content:space-between;margin:4px 0;gap:12px}
  .amt{color:#f0b90b;font-weight:bold;font-size:22px;margin:8px 0}
  input{width:100%;padding:10px;border-radius:6px;border:1px solid #333;background:#0b0e11;color:#eaecef;font-family:monospace;box-sizing:border-box}
  button{padding:10px 16px;border-radius:6px;border:none;cursor:pointer;font-weight:bold;margin-right:8px}
  .btn-green{background:#16c784;color:white}
  .btn-red{background:#ea3943;color:white}
  .muted{color:#888;font-size:13px}
  hr{border:none;border-top:1px solid #333;margin:12px 0}
</style></head><body>
<h1>Pending withdrawals</h1>
${rows.length ? cards : '<div style="text-align:center;color:#888;padding:40px 20px">No pending withdrawals.</div>'}
<script>
  const KEY = ${JSON.stringify(process.env.ADMIN_KEY)};
  async function completeW(id){
    const tx = document.getElementById('tx'+id).value.trim();
    if(!tx) return alert('Paste the tx hash first');
    const r = await fetch('/api/admin/withdrawals/'+id+'/complete?key='+encodeURIComponent(KEY)+'&tx='+encodeURIComponent(tx));
    alert(await r.text());
    if(r.ok) location.reload();
  }
  async function rejectW(id){
    const reason = prompt('Reason for rejection?','Rejected by admin');
    if(reason === null) return;
    const r = await fetch('/api/admin/withdrawals/'+id+'/reject?key='+encodeURIComponent(KEY)+'&reason='+encodeURIComponent(reason));
    alert(await r.text());
    if(r.ok) location.reload();
  }
</script>
</body></html>`);
  } catch (e) {
    console.error('admin page error', e);
    res.status(500).send('Error: ' + e.message);
  }
});

/* ============================================================
   YIELD POOL — USER ENDPOINTS
   ============================================================ */

app.post('/api/yield/lock', requireAuth, async (req, res) => {
  try {
    const { amount } = req.body || {};
    const amt = Number(amount);
    if (!amt || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });

    const sRes = await pool.query('SELECT * FROM yield_settings WHERE id = 1');
    if (!sRes.rows.length) return res.status(500).json({ error: 'Yield not configured' });
    const settings = sRes.rows[0];

    if (!settings.pool_enabled) {
      return res.status(403).json({ error: 'Yield pool is currently closed' });
    }
    if (amt < Number(settings.min_deposit)) {
      return res.status(400).json({ error: 'Minimum deposit is ' + settings.min_deposit + ' USDT' });
    }
    if (amt > Number(settings.max_per_user)) {
      return res.status(400).json({ error: 'Maximum per deposit is ' + settings.max_per_user + ' USDT' });
    }

    const rate = Number(settings.current_rate_monthly);
    const maturesAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    const yRes = await pool.query(
      `INSERT INTO yield_deposits (user_id, amount, rate_monthly, status, matures_at)
       VALUES ($1, $2, $3, 'active', $4)
       RETURNING id, started_at, matures_at`,
      [req.user.id, amt, rate, maturesAt]
    );
    const deposit = yRes.rows[0];
    const refId = 'yield_lock:' + deposit.id;

    try {
      await wallet.applyEntry({
        userId: req.user.id,
        asset: 'USDT',
        amount: -amt,
        type: 'yield_lock',
        refId,
        metadata: { yield_id: deposit.id, rate_monthly: rate },
      });
    } catch (lockErr) {
      await pool.query('DELETE FROM yield_deposits WHERE id = $1', [deposit.id]);
      const msg = String(lockErr.message || '');
      if (msg.includes('Insufficient')) {
        return res.status(400).json({ error: 'Insufficient balance' });
      }
      throw lockErr;
    }

    res.json({
      id: deposit.id,
      amount: amt,
      rate_monthly: rate,
      status: 'active',
      started_at: deposit.started_at,
      matures_at: deposit.matures_at,
      projected_payout: amt * (1 + rate),
    });
  } catch (err) {
    console.error('yield lock error', err);
    res.status(500).json({ error: 'Failed to lock funds' });
  }
});

/* ============================================================
   YIELD POOL — POSITIONS + MATURITY + ADMIN PAYOUT
   ============================================================ */

app.get('/api/yield/positions', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, amount, rate_monthly, status, started_at, matures_at, matured_at, withdrawn_at, payout_total
       FROM yield_deposits WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({
      positions: rows.map(r => ({
        id: r.id,
        amount: Number(r.amount),
        rate_monthly: Number(r.rate_monthly),
        status: r.status,
        started_at: r.started_at,
        matures_at: r.matures_at,
        matured_at: r.matured_at,
        withdrawn_at: r.withdrawn_at,
        projected_payout: r.payout_total
          ? Number(r.payout_total)
          : Number(r.amount) * (1 + Number(r.rate_monthly)),
      })),
    });
  } catch (err) {
    console.error('yield positions error', err);
    res.status(500).json({ error: 'Failed to load positions' });
  }
});

app.post('/api/admin/yield/mature-check', async (req, res) => {
  if (req.query.key !== process.env.ADMIN_KEY) return res.status(403).json({ error: 'forbidden' });
  try {
    const { rowCount } = await pool.query(
      `UPDATE yield_deposits SET status = 'matured', matured_at = NOW()
       WHERE status = 'active' AND matures_at <= NOW()`
    );
    res.json({ ok: true, marked: rowCount });
  } catch (err) {
    console.error('mature check error', err);
    res.status(500).json({ error: 'Failed' });
  }
});

app.post('/api/admin/yield/:id/payout', async (req, res) => {
  if (req.query.key !== process.env.ADMIN_KEY) return res.status(403).json({ error: 'forbidden' });
  const id = parseInt(req.params.id, 10);
  try {
    const wRes = await pool.query('SELECT * FROM yield_deposits WHERE id = $1', [id]);
    if (!wRes.rows.length) return res.status(404).json({ error: 'Not found' });
    const y = wRes.rows[0];
    if (y.status === 'withdrawn') return res.json({ ok: true, ignored: 'already paid' });
    if (y.status !== 'matured') return res.status(400).json({ error: 'Not matured yet (status=' + y.status + ')' });

    const principal = Number(y.amount);
    const rate = Number(y.rate_monthly);
    const payout = principal * (1 + rate);

    await wallet.applyEntry({
      userId: y.user_id,
      asset: 'USDT',
      amount: payout,
      type: 'yield_payout',
      refId: 'yield_payout:' + id,
      metadata: { yield_id: id, principal, rate, payout },
    });

    await pool.query(
      `UPDATE yield_deposits SET status = 'withdrawn', withdrawn_at = NOW(), payout_total = $1 WHERE id = $2`,
      [payout, id]
    );

    res.json({ ok: true, id, payout, principal, interest: payout - principal });
  } catch (err) {
    const msg = String(err.message || '');
    if (msg.includes('duplicate key') || msg.includes('unique')) {
      return res.json({ ok: true, ignored: 'already paid' });
    }
    console.error('yield payout error', err);
    res.status(500).json({ error: 'Payout failed' });
  }
});

app.get('/admin/yield', async (req, res) => {
  if (req.query.key !== process.env.ADMIN_KEY) return res.status(403).send('forbidden');
  try {
    const sRes = await pool.query('SELECT * FROM yield_settings WHERE id = 1');
    const settings = sRes.rows[0] || {};
    const { rows } = await pool.query(
      `SELECT y.id, y.user_id, y.amount, y.rate_monthly, y.matures_at, u.email
       FROM yield_deposits y JOIN users u ON u.id = y.user_id
       WHERE y.status = 'matured' ORDER BY y.matures_at ASC`
    );

    const cards = rows.map(y => {
      const payout = Number(y.amount) * (1 + Number(y.rate_monthly));
      return `
        <div class="card" id="y${y.id}">
          <div class="row"><span class="muted">Position #${y.id}</span><span class="muted">${new Date(y.matures_at).toLocaleString()}</span></div>
          <div class="amt">${payout.toFixed(2)} USDT payout</div>
          <div class="row"><span class="muted">User</span><span>${escapeHtml(y.email)} (id ${y.user_id})</span></div>
          <div class="row"><span class="muted">Principal</span><span>${Number(y.amount).toFixed(2)} USDT</span></div>
          <div class="row"><span class="muted">Rate</span><span>${(Number(y.rate_monthly)*100).toFixed(2)}%</span></div>
          <div class="row"><span class="muted">Interest</span><span>${(payout - Number(y.amount)).toFixed(2)} USDT</span></div>
          <hr>
          <button class="btn-green" onclick="payout(${y.id})">Approve payout</button>
        </div>`;
    }).join('');

    res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Biertex — Yield Payouts</title>
<style>
  body{font-family:system-ui;background:#0b0e11;color:#eaecef;padding:16px;max-width:640px;margin:0 auto}
  .card{background:#1e2329;border-radius:8px;padding:16px;margin-bottom:12px}
  .row{display:flex;justify-content:space-between;margin:4px 0;gap:12px}
  .amt{color:#f0b90b;font-weight:bold;font-size:22px;margin:8px 0}
  button{padding:10px 16px;border-radius:6px;border:none;cursor:pointer;font-weight:bold;margin-right:8px}
  .btn-green{background:#16c784;color:white}
  .muted{color:#888;font-size:13px}
  hr{border:none;border-top:1px solid #333;margin:12px 0}
  .top{background:#1e2329;padding:14px;border-radius:8px;margin-bottom:16px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
  .top span{font-size:13px;color:#c9ced6}
</style></head><body>
<h1>Yield Payouts</h1>
<div class="top">
  <span>Rate: <b style="color:#f0b90b">${(Number(settings.current_rate_monthly||0)*100).toFixed(2)}%</b> monthly</span>
  <span>Pool: <b>${settings.pool_enabled ? 'OPEN' : 'CLOSED'}</b></span>
</div>
<button class="btn-green" style="margin-bottom:16px" onclick="runMature()">Run maturity check</button>
${rows.length ? cards : '<div style="text-align:center;color:#888;padding:40px 20px">No matured positions awaiting payout.</div>'}
<script>
  const KEY = ${JSON.stringify(process.env.ADMIN_KEY)};
  async function payout(id){
    if(!confirm('Approve payout for position #'+id+'?')) return;
    const r = await fetch('/api/admin/yield/'+id+'/payout?key='+encodeURIComponent(KEY), {method:'POST'});
    alert(JSON.stringify(await r.json()));
    if(r.ok) location.reload();
  }
  async function runMature(){
    const r = await fetch('/api/admin/yield/mature-check?key='+encodeURIComponent(KEY), {method:'POST'});
    alert(JSON.stringify(await r.json()));
    location.reload();
  }
</script>
</body></html>`);
  } catch (e) {
    console.error('admin yield page error', e);
    res.status(500).send('Error: ' + e.message);
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
