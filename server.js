/* ============================================================
   BIERTEX BACKEND — Authentication Server
   ============================================================
   Handles: signup, login, session verification
   Stack: Node + Express + SQLite + bcrypt + JWT
   ============================================================ */

const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'CHANGE_THIS_TO_A_LONG_RANDOM_STRING_LATER';

/* ============================================================
   MIDDLEWARE
   ============================================================ */
app.use(cors()); // allow frontend calls
app.use(express.json()); // parse JSON bodies


/* ============================================================
   DATABASE SETUP
   ============================================================ */
const db = new Database('biertex.db');
db.pragma('journal_mode = WAL');

// Create users table if it doesn't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

console.log('✅ Database ready (biertex.db)');


/* ============================================================
   HELPERS
   ============================================================ */

// Generate JWT token (valid 7 days)
function makeToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// Verify JWT — middleware for protected routes
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}


/* ============================================================
   ROUTES
   ============================================================ */

// Home
app.get('/', (req, res) => {
  res.send('Biertex backend is running! 🚀');
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Biertex API is live', time: new Date() });
});

/* -------- SIGN UP -------- */
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validate
    if (!name || name.length < 2) {
      return res.status(400).json({ error: 'Name must be at least 2 characters' });
    }
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if email already exists
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
    if (existing) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Hash password
    const hash = await bcrypt.hash(password, 10);

    // Insert user
    const result = db.prepare(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
    ).run(name, email.toLowerCase(), hash);

    // Return user + token
    const user = { id: result.lastInsertRowid, name, email: email.toLowerCase() };
    const token = makeToken(user);

    res.status(201).json({ user, token });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

/* -------- LOG IN -------- */
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Find user
    const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!row) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare password
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Success
    const user = { id: row.id, name: row.name, email: row.email };
    const token = makeToken(user);

    res.json({ user, token });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error during login' });
  }
});

/* -------- GET CURRENT USER (protected) -------- */
app.get('/api/me', requireAuth, (req, res) => {
  const row = db.prepare('SELECT id, name, email, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!row) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ user: row });
});


/* ============================================================
   START SERVER
   ============================================================ */
app.listen(PORT, () => {
  console.log('✅ Biertex backend running at http://localhost:' + PORT);
  console.log(' - POST /api/register');
  console.log(' - POST /api/login');
  console.log(' - GET /api/me (requires token)');
});