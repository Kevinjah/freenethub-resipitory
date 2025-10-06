/**
 * FreeNetHub-API with Google OAuth (Passport)
 * - CommonJS (require)
 * - LowDB (JSONFile adapter from 'lowdb/node')
 * - Passport Google OAuth 2.0
 *
 * Usage:
 *  - copy .env.example -> .env and fill values
 *  - npm install
 *  - node server.js
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { join } = require('path');
const fs = require('fs');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const shortid = require('shortid');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_session_secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // set true if using HTTPS and trust proxy
}));
app.use(passport.initialize());
app.use(passport.session());

// Database (lowdb)
const dbFile = join(__dirname, 'db.json');
const adapter = new JSONFile(dbFile);
const db = new Low(adapter);

async function initDB() {
  await db.read();
  db.data = db.data || {
    users: [],
    marketplace: [],
    tasks: [],
    transactions: [],
    leaderboard: [],
    analytics: {},
    sims: [],
    wifi_sources: [],
    subscriptions: []
  };
  if (!db.data.subscriptions || db.data.subscriptions.length === 0) {
    db.data.subscriptions = [
      { id: 'basic', name: 'Basic', price: 0 },
      { id: 'pro', name: 'Pro', price: 299 },
      { id: 'premium', name: 'Premium', price: 499 }
    ];
  }
  await db.write();
}
initDB();

// Helper: create JWT
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret';
function createToken(user) {
  return jwt.sign({ id: user.id, email: user.email, name: user.name, is_admin: !!user.is_admin }, JWT_SECRET, { expiresIn: '30d' });
}

// Passport Google strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || '',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    await db.read();
    // prefer email-provided user match
    const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || null;
    let user = db.data.users.find(u => u.googleId === profile.id || (email && u.email === email));
    if (!user) {
      user = {
        id: shortid.generate(),
        name: profile.displayName || 'GoogleUser',
        email: email || `noemail+${profile.id}@example.com`,
        googleId: profile.id,
        credits: 0,
        is_admin: false,
        referralCode: 'REF' + Math.random().toString(36).slice(2, 8).toUpperCase(),
        data_balance_mb: 0
      };
      db.data.users.push(user);
      await db.write();
    } else {
      if (!user.googleId) {
        user.googleId = profile.id;
        await db.write();
      }
    }
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(async function (id, done) {
  await db.read();
  const user = db.data.users.find(u => u.id === id) || null;
  done(null, user);
});

// AUTH helper middleware
async function auth(req, res, next) {
  try {
    const h = req.headers.authorization;
    if (!h) return res.status(401).json({ error: 'no_auth' });
    const token = h.split(' ')[1];
    const d = jwt.verify(token, JWT_SECRET);
    await db.read();
    const user = db.data.users.find(x => x.id === d.id);
    if (!user) return res.status(401).json({ error: 'unknown_user' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// --- Routes --- //

// Basic status
app.get('/api/status', async (req, res) => {
  await db.read();
  db.data.analytics.visits = (db.data.analytics.visits || 0) + 1;
  await db.write();
  res.json({ ok: true, time: Date.now() });
});

// Register / Login (email/password)
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'missing' });
  await db.read();
  if (db.data.users.find(u => u.email === email)) return res.status(400).json({ error: 'exists' });
  const hashed = await bcrypt.hash(password, 8);
  const user = { id: shortid.generate(), name: name || 'User', email, password: hashed, credits: 0, is_admin: false, referralCode: ('REF' + Math.random().toString(36).slice(2, 8).toUpperCase()), data_balance_mb: 0 };
  db.data.users.push(user);
  await db.write();
  res.json({ user: { id: user.id, name: user.name, email: user.email, credits: user.credits, referralCode: user.referralCode, data_balance_mb: user.data_balance_mb }, token: createToken(user) });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  await db.read();
  const user = db.data.users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: 'invalid' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: 'invalid' });
  res.json({ user: { id: user.id, name: user.name, email: user.email, credits: user.credits, referralCode: user.referralCode, data_balance_mb: user.data_balance_mb }, token: createToken(user) });
});

// --- Google OAuth endpoints ---
// Start Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Callback: issue JWT and redirect to dashboard with token
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/auth/google/failure' }), async (req, res) => {
  // user is at req.user
  const token = createToken(req.user);
  // redirect to /dashboard on same host with token in query (frontend will pick it)
  const redirectPath = '/dashboard';
  // Avoid leaking secret-wide info: it's common to pass token in fragment or body — for simplicity we pass in query param
  res.redirect(`${redirectPath}?token=${encodeURIComponent(token)}`);
});

app.get('/auth/google/failure', (req, res) => {
  res.status(400).send('Google login failed');
});

// Simple dashboard page that picks up token and saves to localStorage
app.get('/dashboard', (req, res) => {
  const html = `<!doctype html>
  <html>
  <head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FreeNetHub Dashboard</title></head>
  <body style="font-family:Arial,Helvetica,sans-serif;background:#071024;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh">
    <div style="max-width:720px;padding:20px;background:#071736;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,0.6);">
      <h2>FreeNetHub Dashboard (Google Login)</h2>
      <p id="status">Processing login...</p>
      <script>
        (function(){
          function qs(name){ const u = new URL(location.href); return u.searchParams.get(name); }
          const token = qs('token');
          if(token){
            try{ localStorage.setItem('freenethub_token', token); document.getElementById('status').innerText = 'Login successful — token saved to localStorage. You may close this page.'; }
            catch(e){ document.getElementById('status').innerText = 'Login received but could not save to localStorage.'; }
          } else {
            document.getElementById('status').innerText = 'No token received. Try logging in again.';
          }
        })();
      </script>
    </div>
  </body>
  </html>`;
  res.send(html);
});

// --- (other endpoints already in your server) ---
// Example marketplace endpoint
app.get('/api/marketplace', async (req, res) => {
  await db.read();
  res.json({ items: db.data.marketplace || [] });
});

// Admin convenience route (promote by email)
app.get('/api/create-admin', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).json({ error: 'missing_email' });
  await db.read();
  const user = db.data.users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'user_not_found' });
  user.is_admin = true;
  await db.write();
  return res.json({ ok: true, message: `User ${email} promoted to admin.` });
});

// Serve static public folder
const publicDir = join(__dirname, 'public');
if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir);
if (!fs.existsSync(join(publicDir, 'index.html'))) fs.writeFileSync(join(publicDir, 'index.html'), '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FreeNetHub</title></head><body><h1>FreeNetHub API</h1><p>Visit /api/status or /auth/google to try Google login.</p></body></html>');

app.get('/api/status', async (req, res) => {
  await db.read();
  res.json({ ok: true, time: Date.now() });
});

app.use('/', express.static(publicDir));

// Start server
app.listen(PORT, () => console.log(`FreeNetHub-API listening on ${PORT}`));
