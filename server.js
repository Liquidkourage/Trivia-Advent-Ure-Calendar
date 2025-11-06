import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import { google } from 'googleapis';
import dotenv from 'dotenv';
// Avoid timezone library; store UTC in DB and compare in UTC

dotenv.config();

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
// Serve static assets (CSS, images)
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, 'public')));

// --- Security: force HTTPS and set security headers ---
app.use((req, res, next) => {
  // HSTS for one year
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  // Upgrade insecure HTTP asset requests to HTTPS
  res.setHeader('Content-Security-Policy', "upgrade-insecure-requests");
  const force = (process.env.FORCE_HTTPS || 'true').toLowerCase() === 'true';
  const proto = req.headers['x-forwarded-proto'];
  if (force && proto && proto !== 'https') {
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    return res.redirect(301, `https://${host}${req.originalUrl}`);
  }
  next();
});

const PORT = process.env.PORT || 8080;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const EVENT_TZ = process.env.EVENT_TZ || 'America/New_York';
const KOFI_CUTOFF_ET = process.env.KOFI_CUTOFF_ET || '2025-11-01 00:00:00 America/New_York';
const WEBHOOK_SHARED_SECRET = process.env.WEBHOOK_SHARED_SECRET || '';

const PgSession = connectPgSimple(session);

// --- DB ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway.app') || process.env.PGSSL === 'require'
    ? { rejectUnauthorized: false }
    : false
});

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new PgSession({ pool, createTableIfMissing: true }),
  cookie: {
    secure: true,
    sameSite: 'lax',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
  }
}));

async function initDb() {
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS citext;
    CREATE TABLE IF NOT EXISTS players (
      id SERIAL PRIMARY KEY,
      email CITEXT UNIQUE NOT NULL,
      access_granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      onboarding_complete BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS magic_tokens (
      token TEXT PRIMARY KEY,
      email CITEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS quizzes (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      unlock_at TIMESTAMPTZ NOT NULL,
      freeze_at TIMESTAMPTZ NOT NULL,
      author TEXT,
      author_blurb TEXT,
      description TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_quizzes_unlock_at ON quizzes(unlock_at);
    CREATE INDEX IF NOT EXISTS idx_quizzes_freeze_at ON quizzes(freeze_at);
    
    CREATE TABLE IF NOT EXISTS questions (
      id SERIAL PRIMARY KEY,
      quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
      number INTEGER NOT NULL,
      text TEXT NOT NULL,
      answer TEXT NOT NULL,
      category TEXT,
      ask TEXT,
      UNIQUE(quiz_id, number)
    );
    CREATE INDEX IF NOT EXISTS idx_questions_quiz_id ON questions(quiz_id);
    
    CREATE TABLE IF NOT EXISTS responses (
      id SERIAL PRIMARY KEY,
      quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
      question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
      user_email CITEXT NOT NULL,
      response_text TEXT NOT NULL,
      points NUMERIC NOT NULL DEFAULT 0,
      locked BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_email, question_id)
    );
    CREATE INDEX IF NOT EXISTS idx_responses_quiz_user ON responses(quiz_id, user_email);
    -- Backfill columns for existing deployments
    DO $$ BEGIN
      ALTER TABLE responses ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT FALSE;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE responses ALTER COLUMN points SET DEFAULT 0;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE quizzes ADD COLUMN IF NOT EXISTS author TEXT;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE quizzes ADD COLUMN IF NOT EXISTS author_blurb TEXT;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE quizzes ADD COLUMN IF NOT EXISTS description TEXT;
    EXCEPTION WHEN others THEN NULL; END $$;
  `);
}

// --- Mailer (Gmail OAuth via nodemailer) ---
function createMailer() {
  // Deprecated path: using Gmail HTTP API instead of SMTP to avoid 530/535 issues
  return null;
}

function parseEmailAddress(from) {
  if (!from) return '';
  const match = from.match(/<([^>]+)>/);
  return match ? match[1] : from;
}

const transporter = (() => {
  try { return createMailer(); } catch (e) { console.warn('Mailer not configured:', e.message); return null; }
})();

async function sendMagicLink(email, token, linkUrl) {
  const fromHeader = process.env.EMAIL_FROM || 'no-reply@example.com';
  const fromEmail = parseEmailAddress(fromHeader) || 'no-reply@example.com';
  const url = linkUrl || `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
  console.log('[info] Magic link:', url);

  // Use Gmail HTTP API with OAuth2
  const oAuth2Client = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET
  );
  oAuth2Client.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });
  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

  const subject = 'Your Trivia Advent-ure magic link';
  const text = `Click to sign in: ${url}\r\nThis link expires in 30 minutes and can be used once.`;

  const rawLines = [
    `From: ${fromHeader}`,
    `To: ${email}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    '',
    text
  ];
  const rawMessage = Buffer.from(rawLines.join('\r\n'))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw: rawMessage }
  });
}

// --- Time helpers ---
function etToUtc(dateTimeStr) {
  // dateTimeStr: 'YYYY-MM-DDTHH:mm' or 'YYYY-MM-DD HH:mm' in Eastern Time (Dec = EST, UTC-5)
  const s = String(dateTimeStr || '').trim().replace(' ', 'T');
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})[T](\d{2}):(\d{2})$/);
  if (!m) return new Date(s);
  const year = Number(m[1]);
  const mon = Number(m[2]) - 1;
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const min = Number(m[5]);
  // December: EST (UTC-5) → UTC = ET + 5 hours
  const utcMillis = Date.UTC(year, mon, day, hour + 5, min, 0);
  return new Date(utcMillis);
}

function utcToEtParts(d){
  // December ET assumed (UTC-5)
  const et = new Date(d.getTime() - 5*60*60*1000);
  return {y: et.getUTCFullYear(), m: et.getUTCMonth()+1, d: et.getUTCDate(), h: et.getUTCHours(), et};
}

// --- Grading helpers ---
function normalizeAnswer(s) {
  return String(s || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // strip diacritics
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ') // strip punctuation
    .replace(/\s+/g, ' ')
    .trim();
}

function isCorrectAnswer(given, correct) {
  const raw = String(correct || '');
  const gNorm = normalizeAnswer(given);
  const variants = raw.split('|').map(v => v.trim()).filter(Boolean);
  for (const v of variants) {
    // regex variant: /pattern/i
    const m = v.match(/^\/(.*)\/(i)?$/);
    if (m) {
      try {
        const re = new RegExp(m[1], m[2] ? 'i' : undefined);
        if (re.test(String(given))) return true;
      } catch (_) {}
      continue;
    }
    if (normalizeAnswer(v) === gNorm) return true;
  }
  return false;
}

async function gradeQuiz(pool, quizId, userEmail) {
  const { rows: qs } = await pool.query('SELECT id, number, answer FROM questions WHERE quiz_id=$1 ORDER BY number ASC', [quizId]);
  const { rows: rs } = await pool.query('SELECT question_id, response_text, locked FROM responses WHERE quiz_id=$1 AND user_email=$2', [quizId, userEmail]);
  const qIdToResp = new Map();
  rs.forEach(r => qIdToResp.set(Number(r.question_id), r));
  let streak = 0;
  let total = 0;
  const graded = [];
  for (const q of qs) {
    const r = qIdToResp.get(q.id);
    const locked = !!(r && r.locked);
    if (locked) {
      const correctLocked = r ? isCorrectAnswer(r.response_text, q.answer) : false;
      const pts = correctLocked ? 5 : 0;
      graded.push({ questionId: q.id, number: q.number, locked: true, correct: correctLocked, points: pts, given: r ? r.response_text : '', answer: q.answer });
      total += pts;
      await pool.query('UPDATE responses SET points = $4 WHERE quiz_id=$1 AND user_email=$2 AND question_id=$3', [quizId, userEmail, q.id, pts]);
      // streak unchanged
      continue;
    }
    const correct = r ? isCorrectAnswer(r.response_text, q.answer) : false;
    if (correct) {
      streak += 1;
      total += streak;
      await pool.query('UPDATE responses SET points = $4 WHERE quiz_id=$1 AND user_email=$2 AND question_id=$3', [quizId, userEmail, q.id, streak]);
    } else {
      streak = 0;
      if (r) await pool.query('UPDATE responses SET points = 0 WHERE quiz_id=$1 AND user_email=$2 AND question_id=$3', [quizId, userEmail, q.id]);
    }
    graded.push({ questionId: q.id, number: q.number, locked: false, correct, points: correct ? streak : 0, given: r ? r.response_text : '', answer: q.answer });
  }
  return { total, graded };
}

function getAdminEmail() {
  const from = process.env.EMAIL_FROM || '';
  const m = from.match(/<([^>]+)>/);
  const fallback = m ? m[1] : from;
  return (process.env.ADMIN_EMAIL || fallback || '').toLowerCase();
}

function requireAuthOrAdmin(req, res, next) {
  if (req.session && (req.session.user || req.session.isAdmin === true)) return next();
  return res.status(401).send('Please sign in.');
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).send('Please sign in.');
  next();
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin === true) return next();
  if (!req.session.user) return res.status(401).send('Please sign in.');
  const adminEmail = getAdminEmail();
  if ((req.session.user.email || '').toLowerCase() !== adminEmail) {
    return res.status(403).send('Admins only');
  }
  next();
}

function parseEtToUtc(dateTimeStr) {
  // Accepts "YYYY-MM-DDTHH:mm" or "YYYY-MM-DD HH:mm" as ET and converts to UTC Date
  const s = String(dateTimeStr || '').replace(' ', 'T');
  return tz.zonedTimeToUtc(s, EVENT_TZ);
}

// --- Auth: request magic link ---
app.post('/auth/request-link', async (req, res) => {
  try {
    const emailRaw = (req.body && req.body.email) || (req.query && req.query.email) || '';
    const email = String(emailRaw).trim();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const { rows } = await pool.query('SELECT 1 FROM players WHERE email = $1', [email]);
    if (rows.length === 0) return res.status(403).json({ error: 'No access. Donate on Ko-fi to join.' });
    const token = crypto.randomBytes(24).toString('base64url');
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
    await pool.query('INSERT INTO magic_tokens(token,email,expires_at,used) VALUES($1,$2,$3,false)', [token, email, expiresAt]);
    const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
    try {
      await sendMagicLink(email, token, linkUrl);
    } catch (mailErr) {
      console.warn('Send mail failed:', mailErr?.message || mailErr);
    }
    const expose = (process.env.EXPOSE_MAGIC_LINKS || '').toLowerCase() === 'true';
    res.json({ ok: true, link: expose ? linkUrl : undefined });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to send link' });
  }
});

// Dev helper: request magic link via GET with ?email= when EXPOSE_MAGIC_LINKS=true
app.get('/auth/dev-link', async (req, res) => {
  if ((process.env.EXPOSE_MAGIC_LINKS || '').toLowerCase() !== 'true') return res.status(404).send('Not found');
  try {
    const email = String(req.query.email || '').trim();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const { rows } = await pool.query('SELECT 1 FROM players WHERE email = $1', [email]);
    if (rows.length === 0) return res.status(403).json({ error: 'No access. Donate on Ko-fi to join.' });
    const token = crypto.randomBytes(24).toString('base64url');
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
    await pool.query('INSERT INTO magic_tokens(token,email,expires_at,used) VALUES($1,$2,$3,false)', [token, email, expiresAt]);
    const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
    console.log('[info] Magic link (dev):', linkUrl);
    return res.json({ ok: true, link: linkUrl });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Failed to create link' });
  }
});

// --- Auth: magic link ---
app.get('/auth/magic', async (req, res) => {
  try {
    const token = req.query.token;
    if (!token) return res.status(400).send('Missing token');
    const { rows } = await pool.query('SELECT * FROM magic_tokens WHERE token = $1', [token]);
    const row = rows[0];
    if (!row) return res.status(400).send('Invalid token');
    if (row.used) return res.status(400).send('Token already used');
    if (new Date(row.expires_at) < new Date()) return res.status(400).send('Token expired');
    await pool.query('UPDATE magic_tokens SET used = true WHERE token = $1', [token]);
    req.session.user = { email: row.email };
    // Check onboarding
    const orow = await pool.query('SELECT onboarding_complete FROM players WHERE email = $1', [row.email]);
    const done = orow.rows[0] && orow.rows[0].onboarding_complete === true;
    res.redirect(done ? '/' : '/onboarding');
  } catch (e) {
    console.error(e);
    res.status(500).send('Auth failed');
  }
});

// --- Ko-fi webhook ---
app.post('/webhooks/kofi', async (req, res) => {
  try {
    if (WEBHOOK_SHARED_SECRET) {
      const provided = req.headers['x-kofi-secret'] || req.query.secret || '';
      if (provided !== WEBHOOK_SHARED_SECRET) return res.status(401).send('Bad secret');
    }
    const body = req.body || {};
    // Support a few possible shapes
    const type = (body.type || body.data?.type || '').toLowerCase();
    const email = (body.email || body.data?.email || '').trim();
    const createdAtStr = body.created_at || body.timestamp || body.data?.created_at || body.data?.timestamp;
    if (!email) return res.status(400).send('No email');
    if (type !== 'donation') return res.status(204).send('Ignored');

  const createdAt = createdAtStr ? new Date(createdAtStr) : new Date();
  // Prefer UTC cutoff env if provided
  const cutoffUtcEnv = process.env.KOFI_CUTOFF_UTC || '';
  const cutoffDate = cutoffUtcEnv ? new Date(cutoffUtcEnv) : new Date('2025-11-01T04:00:00Z');
  if (!(createdAt >= cutoffDate)) {
      return res.status(204).send('Before cutoff');
    }

    await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [email]);

    // Optionally auto-send magic link
    const token = crypto.randomBytes(24).toString('base64url');
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
    await pool.query('INSERT INTO magic_tokens(token,email,expires_at,used) VALUES($1,$2,$3,false)', [token, email, expiresAt]);
    await sendMagicLink(email, token).catch(err => console.warn('Send mail failed:', err.message));

    res.status(200).send('OK');
  } catch (e) {
    console.error('Webhook error:', e);
    res.status(200).send('OK'); // respond OK to avoid retries storms
  }
});

// --- Basic pages ---
app.get('/', (req, res) => {
  const adminEmail = getAdminEmail();
  if (req.session.user) {
    const current = (req.session.user.email || '').toLowerCase();
    if (current === adminEmail) return res.redirect('/admin');
    return res.redirect('/player');
  }
  return res.redirect('/public');
});

// Public landing (logged-out)
app.get('/public', (req, res) => {
  res.type('html').send(`
    <html><head><title>Trivia Advent-ure</title><link rel="stylesheet" href="/style.css"><link rel="icon" href="/favicon.svg" type="image/svg+xml"></head>
    <body class="ta-body">
      <header class="ta-header">
        <div class="ta-header-inner">
          <div class="ta-brand">
            <img class="ta-logo" src="/logo.svg" alt="Trivia Advent-ure"/>
            <span class="ta-title">Trivia Advent‑ure</span>
          </div>
          <nav class="ta-nav"><a href="/login">Login</a> <a href="/calendar">Calendar</a></nav>
        </div>
      </header>
      <main class="ta-main ta-container">
      <h1 class="ta-page-title">Trivia Advent-ure Calendar</h1>
      <p>48 quizzes unlock at midnight and noon ET from Dec 1–24. Play anytime; per-quiz leaderboards finalize after 24 hours. Overall standings keep updating.</p>
      <div class="ta-actions">
        <a class="ta-btn ta-btn-primary" href="/calendar">View Calendar</a>
        <a class="ta-btn ta-btn-outline" href="/login">Login</a>
      </div>
      <h3 class="ta-section-title">How it works</h3>
      <ul class="ta-list">
        <li>10 questions per quiz, immediate recap on submit</li>
        <li>Per‑quiz leaderboard freezes at +24h</li>
        <li>Overall board keeps updating with late plays</li>
      </ul>
      </main>
      <footer class="ta-footer"><div class="ta-container">© Trivia Advent‑ure</div></footer>
    </body></html>
  `);
});

// Player landing (logged-in non-admin)
app.get('/player', requireAuth, (req, res) => {
  const adminEmail = getAdminEmail();
  const email = (req.session.user.email || '').toLowerCase();
  if (email === adminEmail) return res.redirect('/admin');
  res.type('html').send(`
    <html><head><title>Player • Trivia Advent-ure</title><link rel="stylesheet" href="/style.css"><link rel="icon" href="/favicon.svg" type="image/svg+xml"></head>
    <body class="ta-body">
      <header class="ta-header"><div class="ta-header-inner"><div class="ta-brand"><img class="ta-logo" src="/logo.svg"/><span class="ta-title">Trivia Advent‑ure</span></div><nav class="ta-nav"><a href="/calendar">Calendar</a> <a href="/logout">Logout</a></nav></div></header>
      <main class="ta-main ta-container">
        <h1 class="ta-page-title">Welcome, ${req.session.user.email}</h1>
        <p class="ta-lead">Head to the calendar to play unlocked quizzes.</p>
        <div class="ta-actions"><a class="ta-btn ta-btn-primary" href="/calendar">Open Calendar</a></div>
      </main>
      <footer class="ta-footer"><div class="ta-container">© Trivia Advent‑ure</div></footer>
    </body></html>
  `);
});

// Admin dashboard
app.get('/admin', requireAdmin, (req, res) => {
  res.type('html').send(`
    <html><head><title>Admin • Trivia Advent-ure</title><link rel="stylesheet" href="/style.css"><link rel="icon" href="/favicon.svg" type="image/svg+xml"></head>
    <body class="ta-body">
      <header class="ta-header"><div class="ta-header-inner"><div class="ta-brand"><img class="ta-logo" src="/logo.svg"/><span class="ta-title">Trivia Advent‑ure</span></div><nav class="ta-nav"><a href="/calendar">Calendar</a> <a href="/logout">Logout</a></nav></div></header>
      <main class="ta-main ta-container">
        <h1 class="ta-page-title">Admin Dashboard</h1>
        <div class="ta-card-grid">
          <a class="ta-card" href="/admin/upload-quiz"><strong>Upload Quiz</strong><span>Create a quiz with 10 questions</span></a>
          <a class="ta-card" href="/admin/generate-schedule"><strong>Generate Schedule</strong><span>Create Dec 1–24 placeholders</span></a>
          <a class="ta-card" href="/admin/quizzes"><strong>Manage Quizzes</strong><span>View/Edit/Clone/Delete</span></a>
          <a class="ta-card" href="/admin/access"><strong>Access & Links</strong><span>Grant or send magic links</span></a>
          <a class="ta-card" href="/leaderboard"><strong>Overall Leaderboard</strong></a>
        </div>
      </main>
      <footer class="ta-footer"><div class="ta-container">© Trivia Advent‑ure</div></footer>
    </body></html>
  `);
});

// Dedicated login page (magic-link)
app.get('/login', (req, res) => {
  const loggedIn = !!req.session.user;
  res.type('html').send(`
    <html><head><title>Login • Trivia Advent-ure</title><link rel="stylesheet" href="/style.css"></head>
    <body class="ta-body" style="padding: 24px;">
      <h1>Login</h1>
      ${loggedIn ? `<p>You are signed in as ${req.session.user.email}. <a href="/logout">Logout</a></p>` : `
        <form method="post" action="/auth/request-link" onsubmit="event.preventDefault(); const fd=new FormData(this); const v=String(fd.get('email')||'').trim(); if(!v){alert('Enter your email'); return;} fetch('/auth/request-link',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ email: v })}).then(r=>r.json()).then(d=>{ if (d.link) { alert('Magic link (dev):\n'+d.link); } else { alert('If you have access, a magic link was sent.'); } }).catch(()=>alert('Failed.'));">
          <label>Email (Ko-fi): <input id="email" name="email" type="email" required /></label>
          <button type="submit">Send magic link</button>
        </form>
      `}
      <p style="margin-top:16px;"><a href="/">Home</a> · <a href="/admin/pin">Admin PIN</a></p>
    </body></html>
  `);
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Admin PIN login (sets admin session without email check)
app.get('/admin/pin', (req, res) => {
  res.type('html').send(`
    <html><head><title>Admin PIN • Trivia Advent-ure</title><link rel="stylesheet" href="/style.css"></head>
    <body class="ta-body" style="padding: 24px;">
      <h1>Admin PIN</h1>
      <form method="post" action="/admin/pin">
        <label>PIN <input type="password" name="pin" required /></label>
        <button type="submit">Enter</button>
      </form>
      <p style="margin-top:16px;"><a href="/">Home</a></p>
    </body></html>
  `);
});

app.post('/admin/pin', (req, res) => {
  const provided = String((req.body && req.body.pin) || '').trim();
  const expected = String(process.env.ADMIN_PIN || '').trim();
  if (!expected) return res.status(500).send('ADMIN_PIN not set');
  if (provided !== expected) return res.status(403).send('Invalid PIN');
  req.session.isAdmin = true;
  res.redirect('/admin');
});

// --- Calendar ---
app.get('/calendar', async (req, res) => {
  try {
    const { rows: quizzes } = await pool.query('SELECT * FROM quizzes ORDER BY unlock_at ASC, id ASC');
    const nowUtc = new Date();
    const email = req.session.user ? (req.session.user.email || '').toLowerCase() : '';
    let completedSet = new Set();
    if (email) {
      const { rows: c } = await pool.query('SELECT DISTINCT quiz_id FROM responses WHERE user_email = $1', [email]);
      c.forEach(r => completedSet.add(Number(r.quiz_id)));
    }
    // Group quizzes by ET date (YYYY-MM-DD), expect two per day: 00:00 and 12:00
    const byDay = new Map();
    for (const q of quizzes) {
      const unlockUtc = new Date(q.unlock_at);
      const p = utcToEtParts(unlockUtc);
      const key = `${p.y}-${String(p.m).padStart(2,'0')}-${String(p.d).padStart(2,'0')}`;
      const slot = p.h === 0 ? 'am' : 'pm';
      if (!byDay.has(key)) byDay.set(key, { day:key, am:null, pm:null });
      byDay.get(key)[slot] = q;
    }
    // Ensure placeholder doors exist for Dec 1–24 even if DB has none
    const baseYear = quizzes.length > 0
      ? utcToEtParts(new Date(quizzes[0].unlock_at)).y
      : new Date().getUTCFullYear();
    for (let d = 1; d <= 24; d++) {
      const key = `${baseYear}-12-${String(d).padStart(2,'0')}`;
      if (!byDay.has(key)) byDay.set(key, { day: key, am: null, pm: null });
    }
    const doors = Array.from(byDay.values()).sort((a,b)=> a.day.localeCompare(b.day));
    const grid = doors.map(d => {
      const am = d.am, pm = d.pm;
      function qStatus(q){
        if (!q) return { label:'Missing', finalized:false, unlocked:false, completed:false, id:null, title:'' };
        const unlockUtc = new Date(q.unlock_at);
        const freezeUtc = new Date(q.freeze_at);
        const unlocked = nowUtc >= unlockUtc;
        const finalized = nowUtc >= freezeUtc;
        const completed = completedSet.has(q.id);
        const label = finalized ? 'Finalized' : (unlocked ? 'Unlocked' : 'Locked');
        return { label, finalized, unlocked, completed, id:q.id, title:q.title };
      }
      let sAm = qStatus(am), sPm = qStatus(pm);
      const num = Number(d.day.slice(-2));
      // Demo: force Day 1 unlocked when ?demo=1 (temporary preview)
      const demo = String(req.query.demo || '').toLowerCase();
      const isDemoDay1 = (demo === '1' || demo === 'day1') && num === 1;
      if (isDemoDay1) {
        if (!am) { sAm = { label:'Unlocked', finalized:false, unlocked:true, completed:false, id:null, title:'Opens at Midnight ET' }; }
        else { sAm.unlocked = true; sAm.finalized = false; sAm.label = 'Unlocked'; }
        if (!pm) { sPm = { label:'Locked', finalized:false, unlocked:false, completed:false, id:null, title:'Opens at Noon ET' }; }
        else { sPm.unlocked = false; sPm.finalized = false; sPm.label = 'Locked'; }
      }
      const doorUnlocked = (sAm.unlocked || sPm.unlocked) || isDemoDay1;
      const doorFinal = sAm.finalized && sPm.finalized;
      const completedCount = (sAm.completed?1:0) + (sPm.completed?1:0);
      const cls = `ta-door ${doorFinal ? 'is-finalized' : doorUnlocked ? 'is-unlocked' : 'is-locked'}`;
      const badge = completedCount>0 ? `<span class=\"ta-badge\">${completedCount}/2 complete</span>` : '';
      const amBtn = (sAm.unlocked && sAm.id) ? `<a class=\"ta-btn-small\" href=\"/quiz/${sAm.id}\">Open AM</a>` : `<span class=\"ta-door-label\">${sAm.label || 'Locked'}</span>`;
      const pmBtn = (sPm.unlocked && sPm.id) ? `<a class=\"ta-btn-small\" href=\"/quiz/${sPm.id}\">Open PM</a>` : `<span class=\"ta-door-label\">${sPm.label || 'Locked'}</span>`;
      return `
      <div class="ta-door-slot">
        <div class="${cls}" data-day="${d.day}">
          <div class="ta-door-inner">
            <div class="ta-door-front">
              <div class="ta-door-leaf left"></div>
              <div class="ta-door-leaf right"></div>
              <div class="ta-door-number">${num}</div>
              <div class="ta-door-label">${doorFinal ? 'Finalized' : doorUnlocked ? 'Unlocked' : 'Locked'}</div>
              ${badge}
            </div>
            <div class="ta-door-back">
              <div class="slot-grid">
                ${sAm.unlocked && sAm.id ? `<a class=\"slot-btn unlocked\" href=\"/quiz/${sAm.id}\">AM</a>` : `<span class=\"slot-btn ${sAm.unlocked?'unlocked':'locked'}\">AM</span>`}
                ${sPm.unlocked && sPm.id ? `<a class=\"slot-btn unlocked\" href=\"/quiz/${sPm.id}\">PM</a>` : `<span class=\"slot-btn ${sPm.unlocked?'unlocked':'locked'}\">PM</span>`}
              </div>
            </div>
          </div>
        </div>
      </div>
      `;
    }).join('\n');
    res.type('html').send(`
      <html><head><title>Calendar</title><link rel="stylesheet" href="/style.css"><link rel="icon" href="/favicon.svg" type="image/svg+xml"></head>
      <body class="ta-body">
        <header class="ta-header"><div class="ta-header-inner"><div class="ta-brand"><img class="ta-logo" src="/logo.svg"/><span class="ta-title">Trivia Advent‑ure</span></div><nav class="ta-nav"><a href="/player">Player</a> <a href="/logout">Logout</a></nav></div></header>
        <main class="ta-main ta-container ta-calendar">
          <h1 class="ta-page-title">Advent Calendar</h1>
          <div class="ta-calendar-grid">${grid}</div>
        </main>
        <footer class="ta-footer"><div class="ta-container">© Trivia Advent‑ure</div></footer>
        <script>
          (function(){
            function setupDoors(){
              var doors = document.querySelectorAll('.ta-door.is-unlocked');
              doors.forEach(function(d){
                ['click','touchstart'].forEach(function(evt){
                  d.addEventListener(evt, function(e){
                    if (e.target && e.target.closest && e.target.closest('.slot-btn')) return; // let buttons work
                    var wasOpen = d.classList.contains('is-open');
                    document.querySelectorAll('.ta-door.is-open').forEach(function(x){ x.classList.remove('is-open'); });
                    if (!wasOpen) d.classList.add('is-open');
                  }, { passive: true });
                });
              });
            }
            if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', setupDoors); else setupDoors();
          })();
        </script>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load calendar');
  }
});

// --- Admin: upload quiz ---
app.get('/admin/upload-quiz', requireAdmin, (req, res) => {
  res.type('html').send(`
    <html><head><title>Upload Quiz</title><link rel="stylesheet" href="/style.css"></head>
    <body class="ta-body" style="padding: 24px;">
      <h1>Upload Quiz</h1>
      <form method="post" action="/admin/upload-quiz">
        <div><label>Title <input name="title" required /></label></div>
        <div style="margin-top:8px;"><label>Author <input name="author" /></label></div>
        <div style="margin-top:8px;"><label>Author blurb <input name="author_blurb" /></label></div>
        <div style="margin-top:8px;"><label>Description<br/><textarea name="description" rows="3" style="width: 100%;"></textarea></label></div>
        <div style="margin-top:8px;"><label>Unlock (ET) <input name="unlock_at" type="datetime-local" required /></label></div>
        <fieldset style="margin-top:12px;">
          <legend>Questions (10)</legend>
          ${Array.from({length:10}, (_,i)=>{
            const n=i+1;
            return `<div style=\"border:1px solid #ddd;padding:8px;margin:6px 0;border-radius:6px;\">
              <div><strong>Q${n}</strong></div>
              <div><label>Text <input name=\"q${n}_text\" required style=\"width:90%\"/></label></div>
              <div><label>Answer <input name=\"q${n}_answer\" required style=\"width:90%\"/></label></div>
              <div><label>Category <input name=\"q${n}_category\" value=\"General\"/></label>
              <label style=\"margin-left:12px;\">Ask <input name=\"q${n}_ask\"/></label></div>
            </div>`
          }).join('')}
        </fieldset>
        <div style="margin-top:12px;"><button type="submit">Create Quiz</button></div>
      </form>
      <p style="margin-top:16px;"><a href="/">Home</a></p>
    </body></html>
  `);
});

app.post('/admin/upload-quiz', requireAdmin, async (req, res) => {
  try {
    const title = String(req.body.title || '').trim();
    const author = String(req.body.author || '').trim() || null;
    const authorBlurb = String(req.body.author_blurb || '').trim() || null;
    const description = String(req.body.description || '').trim() || null;
    const unlockInput = String(req.body.unlock_at || '').trim();
    if (!title || !unlockInput) return res.status(400).send('Missing title or unlock time');
    const unlockUtc = etToUtc(unlockInput);
    const freezeUtc = new Date(unlockUtc.getTime() + 24*60*60*1000);
    const qInsert = await pool.query('INSERT INTO quizzes(title, unlock_at, freeze_at, author, author_blurb, description) VALUES($1,$2,$3,$4,$5,$6) RETURNING id', [title, unlockUtc, freezeUtc, author, authorBlurb, description]);
    const quizId = qInsert.rows[0].id;
    for (let i=1;i<=10;i++) {
      const qt = String(req.body[`q${i}_text`] || '').trim();
      const qa = String(req.body[`q${i}_answer`] || '').trim();
      const qc = String(req.body[`q${i}_category`] || 'General').trim();
      const qk = String(req.body[`q${i}_ask`] || '').trim() || null;
      if (!qt || !qa) continue;
      await pool.query(
        'INSERT INTO questions(quiz_id, number, text, answer, category, ask) VALUES($1,$2,$3,$4,$5,$6)',
        [quizId, i, qt, qa, qc, qk]
      );
    }
    res.redirect(`/quiz/${quizId}`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to create quiz');
  }
});

// --- Admin: generate schedule ---
app.get('/admin/generate-schedule', requireAdmin, (req, res) => {
  res.type('html').send(`
    <html><head><title>Generate Schedule</title><link rel="stylesheet" href="/style.css"></head>
    <body class="ta-body" style="padding: 24px;">
      <h1>Generate 48-quiz Schedule</h1>
      <p>This will create placeholders for Dec 1–24 at 12:00am and 12:00pm ET. Existing entries are skipped.</p>
      <form method="post" action="/admin/generate-schedule">
        <label>Year <input name="year" type="number" value="${new Date().getUTCFullYear()}" required /></label>
        <button type="submit" style="margin-left:8px;">Generate</button>
      </form>
      <p style="margin-top:16px;"><a href="/admin">Back</a></p>
    </body></html>
  `);
});

app.post('/admin/generate-schedule', requireAdmin, async (req, res) => {
  try {
    const year = Number(req.body.year || new Date().getUTCFullYear());
    const inserts = [];
    let count = 0;
    for (let day = 1; day <= 24; day++) {
      for (const hh of [0, 12]) {
        const mm = '00';
        const month = '12';
        const dd = String(day).padStart(2, '0');
        const hhStr = String(hh).padStart(2, '0');
        const etStr = `${year}-${month}-${dd}T${hhStr}:${mm}`; // ET
        const unlockUtc = etToUtc(etStr);
        const freezeUtc = new Date(unlockUtc.getTime() + 24*60*60*1000);
        const label = `${year}-12-${dd} ${hh === 0 ? 'Midnight' : 'Noon'} ET`;
        // Skip if quiz already exists at same unlock
        const exist = await pool.query('SELECT id FROM quizzes WHERE unlock_at = $1', [unlockUtc]);
        if (exist.rows.length === 0) {
          await pool.query('INSERT INTO quizzes(title, unlock_at, freeze_at) VALUES($1,$2,$3)', [label, unlockUtc, freezeUtc]);
          count++;
        }
      }
    }
    res.type('html').send(`<html><body style="font-family: system-ui; padding:24px;"><h1>Generated ${count} quizzes</h1><p><a href="/calendar">View Calendar</a> · <a href="/admin">Back</a></p></body></html>`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to generate');
  }
});

// --- Play quiz ---
app.get('/quiz/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { rows: qr } = await pool.query('SELECT * FROM quizzes WHERE id = $1', [id]);
    if (qr.length === 0) return res.status(404).send('Quiz not found');
    const quiz = qr[0];
    const nowUtc = new Date();
    const unlockUtc = new Date(quiz.unlock_at);
    const freezeUtc = new Date(quiz.freeze_at);
    const { rows: qs } = await pool.query('SELECT * FROM questions WHERE quiz_id = $1 ORDER BY number ASC', [id]);
    const locked = nowUtc < unlockUtc;
    const status = locked ? 'Locked' : (nowUtc >= freezeUtc ? 'Finalized' : 'Unlocked');
    const loggedIn = !!req.session.user || req.session.isAdmin === true;
    const email = req.session.user ? (req.session.user.email || '') : (req.session.isAdmin === true ? getAdminEmail() : '');
    let existingMap = new Map();
    let existingLockedId = null;
    if (loggedIn) {
      const erows = await pool.query('SELECT question_id, response_text, locked FROM responses WHERE quiz_id=$1 AND user_email=$2', [id, email]);
      erows.rows.forEach(r => {
        existingMap.set(r.question_id, r.response_text);
        if (r.locked === true) existingLockedId = r.question_id;
      });
    }
    const recap = String(req.query.recap || '') === '1';
    if (recap && loggedIn) {
      const { rows: gr } = await pool.query(
        'SELECT q.number, q.text, q.answer, r.response_text, r.points, r.locked FROM questions q LEFT JOIN responses r ON r.question_id=q.id AND r.user_email=$1 WHERE q.quiz_id=$2 ORDER BY q.number ASC',
        [email, id]
      );
      const total = gr.reduce((s, r) => s + Number(r.points || 0), 0);
      const rowsHtml = gr.map(r => `
        <tr>
          <td>${r.number}${r.locked ? ' 🔒' : ''}</td>
          <td>${r.text}</td>
          <td>${r.response_text || ''}</td>
          <td>${r.answer}</td>
          <td>${r.points || 0}</td>
        </tr>`).join('');
      return res.type('html').send(`
        <html><head><title>Quiz ${id} Recap</title></head>
        <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto; padding: 24px;">
          <h1>${quiz.title} (Quiz #${id})</h1>
          <div>Status: ${status}</div>
          <h3>Score: ${total}</h3>
          <table border="1" cellspacing="0" cellpadding="6">
            <tr><th>#</th><th>Question</th><th>Your answer</th><th>Correct answer</th><th>Points</th></tr>
            ${rowsHtml}
          </table>
          <p style="margin-top:16px;"><a href="/calendar">Back to Calendar</a></p>
        </body></html>
      `);
    }

    const form = locked ? '<p>This quiz is locked until unlock time (ET).</p>' : (loggedIn ? `
      ${existingMap.size > 0 ? `<div style="padding:8px 10px;border:1px solid #ddd;border-radius:6px;background:#fafafa;margin-bottom:10px;">You've started this quiz. <a href="/quiz/${id}?recap=1">View recap</a>.</div>` : ''}
      <form method="post" action="/quiz/${id}/submit">
        <p>You may lock exactly one question for scoring. Pick it below; you can change it until grading.</p>
        ${qs.map(q=>{
          const val = existingMap.get(q.id) || '';
          const checked = existingLockedId === q.id ? 'checked' : '';
          const disable = nowUtc >= freezeUtc ? 'disabled' : '';
          const required = (q.number === 1 && !(nowUtc >= freezeUtc)) ? 'required' : '';
          return `
          <div class=\"quiz-card\">\n            <div class=\"quiz-qhead\"><div class=\"quiz-qnum\">Q${q.number}</div> <label class=\"quiz-lock\"><input type=\"radio\" name=\"locked\" value=\"${q.id}\" ${checked} ${disable} ${required}/> Lock this question</label></div>\n            <div class=\"quiz-text\">${q.text}</div>\n            <div class=\"quiz-answer\"><label>Your answer <input name=\"q${q.number}\" value=\"${val.replace(/\"/g,'&quot;')}\" ${disable}/></label></div>\n          </div>`;
        }).join('')}
        <div class=\"quiz-actions\"><button class=\"quiz-submit\" type=\"submit\" ${nowUtc >= freezeUtc ? 'disabled' : ''}>Submit</button></div>
      </form>
    ` : '<p>Please sign in to play.</p>');
    const et = utcToEtParts(unlockUtc);
    const slot = et.h === 0 ? 'AM' : 'PM';
    const dateStr = `${et.y}-${String(et.m).padStart(2,'0')}-${String(et.d).padStart(2,'0')}`;
    res.type('html').send(`
      <html><head><title>Quiz ${id}</title><link rel="stylesheet" href="/style.css"></head>
      <body class="ta-body">
        <header class="ta-header"><div class="ta-header-inner"><div class="ta-brand"><img class="ta-logo" src="/logo.svg"/><span class="ta-title">Trivia Advent‑ure</span></div><nav class="ta-nav"><a href="/calendar">Calendar</a></nav></div></header>
        <main class="ta-container-wide">
          <div class="ta-quiz-header">
            <h1 class="ta-quiz-title">${quiz.title}</h1>
            <div class="ta-quiz-meta">
              <span class="meta-badge">${dateStr} • ${slot}</span>
              ${quiz.author ? `<span class="meta-badge">By ${quiz.author}</span>` : ''}
              <span class="meta-badge">${status}</span>
            </div>
            ${quiz.author_blurb ? `<div class="ta-quiz-desc" style="opacity:.85;">${quiz.author_blurb}</div>` : ''}
            ${quiz.description ? `<div class="ta-quiz-desc">${quiz.description}</div>` : ''}
          </div>
          ${form}
          <p style="margin-top:16px;"><a href="/calendar">Back to Calendar</a></p>
        </main>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load quiz');
  }
});

// --- Per-quiz leaderboard ---
app.get('/quiz/:id/leaderboard', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { rows: qr } = await pool.query('SELECT id, title, freeze_at FROM quizzes WHERE id = $1', [id]);
    if (qr.length === 0) return res.status(404).send('Quiz not found');
    const freezeUtc = new Date(qr[0].freeze_at);
    const { rows } = await pool.query(
      `SELECT user_email, SUM(points) AS points, MIN(created_at) AS first_time
       FROM responses
       WHERE quiz_id = $1 AND created_at <= $2
       GROUP BY user_email
       ORDER BY points DESC, first_time ASC`,
      [id, freezeUtc]
    );
    const items = rows.map(r => `<tr><td>${r.user_email}</td><td>${r.points}</td><td>${new Date(r.first_time).toLocaleString()}</td></tr>`).join('');
    res.type('html').send(`
      <html><head><title>Leaderboard • Quiz ${id}</title><link rel="stylesheet" href="/style.css"></head>
      <body class="ta-body" style="padding:24px;">
        <h1>Leaderboard • ${qr[0].title}</h1>
        <table border="1" cellspacing="0" cellpadding="6">
          <tr><th>Player</th><th>Points</th><th>First Submitted</th></tr>
          ${items || '<tr><td colspan="3">No submissions yet.</td></tr>'}
        </table>
        <p style="margin-top:16px;"><a href="/quiz/${id}">Back to Quiz</a> · <a href="/calendar">Calendar</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load leaderboard');
  }
});

// --- Overall leaderboard ---
app.get('/leaderboard', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT user_email, SUM(points) AS points
       FROM responses
       GROUP BY user_email
       ORDER BY points DESC`
    );
    const items = rows.map(r => `<tr><td>${r.user_email}</td><td>${r.points}</td></tr>`).join('');
    res.type('html').send(`
      <html><head><title>Overall Leaderboard</title><link rel="stylesheet" href="/style.css"></head>
      <body class="ta-body" style="padding:24px;">
        <h1>Overall Leaderboard</h1>
        <table border="1" cellspacing="0" cellpadding="6">
          <tr><th>Player</th><th>Points</th></tr>
          ${items || '<tr><td colspan="2">No submissions yet.</td></tr>'}
        </table>
        <p style="margin-top:16px;"><a href="/calendar">Calendar</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load leaderboard');
  }
});
app.post('/quiz/:id/submit', requireAuthOrAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    // Prevent changes after freeze
    const qinfo = await pool.query('SELECT freeze_at FROM quizzes WHERE id=$1', [id]);
    if (qinfo.rows.length) {
      const freezeUtc = new Date(qinfo.rows[0].freeze_at);
      if (new Date() >= freezeUtc) {
        return res.redirect(`/quiz/${id}?recap=1`);
      }
    }
    const email = (req.session.user && req.session.user.email ? req.session.user.email : getAdminEmail()).toLowerCase();
    const { rows: qs } = await pool.query('SELECT id, number FROM questions WHERE quiz_id = $1 ORDER BY number ASC', [id]);
    const lockedSelected = Number(req.body.locked || 0) || null;
    // Enforce: must have one locked question on submit
    if (!lockedSelected) {
      const existingLock = await pool.query('SELECT 1 FROM responses WHERE quiz_id=$1 AND user_email=$2 AND locked=true LIMIT 1', [id, email]);
      if (existingLock.rows.length === 0) {
        return res.status(400).send('Please choose one question to lock before submitting.');
      }
    }
    for (const q of qs) {
      const key = `q${q.number}`;
      const val = String(req.body[key] || '').trim();
      const isLocked = lockedSelected === q.id;
      if (!val) {
        // still persist lock choice even without new text if row exists
        await pool.query(
          'INSERT INTO responses(quiz_id, question_id, user_email, response_text, locked) VALUES($1,$2,$3,$4,$5) ON CONFLICT (user_email, question_id) DO UPDATE SET locked = EXCLUDED.locked',
          [id, q.id, email, '', isLocked]
        );
        continue;
      }
      await pool.query(
        'INSERT INTO responses(quiz_id, question_id, user_email, response_text, locked) VALUES($1,$2,$3,$4,$5) ON CONFLICT (user_email, question_id) DO UPDATE SET response_text = EXCLUDED.response_text, locked = EXCLUDED.locked',
        [id, q.id, email, val, isLocked]
      );
    }
    if (lockedSelected) {
      await pool.query('UPDATE responses SET locked = FALSE WHERE quiz_id=$1 AND user_email=$2 AND question_id <> $3', [id, email, lockedSelected]);
    }
    // grade and redirect to recap
    await gradeQuiz(pool, id, email);
    res.redirect(`/quiz/${id}?recap=1`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to submit');
  }
});
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Advent staging listening on :${PORT}`);
  });
});

// --- Admin: list quizzes ---
app.get('/admin/quizzes', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, title, unlock_at, freeze_at FROM quizzes ORDER BY unlock_at ASC, id ASC LIMIT 200');
    const items = rows.map(q => `<tr>
      <td>#${q.id}</td>
      <td>${q.title}</td>
      <td>${new Date(q.unlock_at).toLocaleString()}</td>
      <td>${new Date(q.freeze_at).toLocaleString()}</td>
      <td><a href="/admin/quiz/${q.id}">View/Edit</a> · <a href="/quiz/${q.id}">Open</a></td>
    </tr>`).join('');
    res.type('html').send(`
      <html><head><title>Quizzes</title><link rel="stylesheet" href="/style.css"></head>
      <body class="ta-body" style="padding:24px;">
        <h1>Quizzes</h1>
        <table border="1" cellspacing="0" cellpadding="6">
          <tr><th>ID</th><th>Title</th><th>Unlock</th><th>Freeze</th><th>Actions</th></tr>
          ${items || '<tr><td colspan="5">No quizzes</td></tr>'}
        </table>
        <p style="margin-top:16px;"><a href="/admin">Back</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to list quizzes');
  }
});

// --- Admin: view/edit quiz ---
app.get('/admin/quiz/:id', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const qr = await pool.query('SELECT * FROM quizzes WHERE id = $1', [id]);
    if (qr.rows.length === 0) return res.status(404).send('Not found');
    const quiz = qr.rows[0];
    const qs = await pool.query('SELECT * FROM questions WHERE quiz_id = $1 ORDER BY number ASC', [id]);
    const list = qs.rows.map(q => `<li><strong>Q${q.number}</strong> ${q.text} <em>(Ans: ${q.answer})</em></li>`).join('');
  res.type('html').send(`
    <html><head><title>Edit Quiz #${id}</title><link rel="stylesheet" href="/style.css"></head>
    <body class="ta-body" style="padding:24px;">
        <h1>Edit Quiz #${id}</h1>
        <form method="post" action="/admin/quiz/${id}">
          <div><label>Title <input name="title" value="${quiz.title}" required /></label></div>
          <div style="margin-top:8px;"><label>Unlock (ET) <input name="unlock_at" type="datetime-local" /></label> <small>Leave blank to keep</small></div>
          <div style="margin-top:8px;"><button type="submit">Save</button></div>
        </form>
        <h3 style="margin-top:16px;">Questions</h3>
        <ul>${list || '<li>No questions</li>'}</ul>
        <h3>Bulk replace questions</h3>
        <form method="post" action="/admin/quiz/${id}/questions">
          <textarea name="json" rows="12" cols="100" placeholder='[
  {"number":1, "text":"...", "answer":"...", "category":"General", "ask":"..."},
  ... 10 items total ...
]'></textarea>
          <div style="margin-top:8px;"><button type="submit">Replace Questions</button></div>
        </form>
        <form method="post" action="/admin/quiz/${id}/clone" style="margin-top:16px; display:inline-block;"><button type="submit">Clone Quiz</button></form>
        <form method="post" action="/admin/quiz/${id}/delete" style="margin-top:16px; display:inline-block; margin-left:8px;" onsubmit="return confirm('Delete this quiz? This cannot be undone.');"><button type="submit">Delete Quiz</button></form>
        <p style="margin-top:16px;"><a href="/admin/quizzes">Back</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load quiz');
  }
});

app.post('/admin/quiz/:id', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const title = String(req.body.title || '').trim();
    const unlock = String(req.body.unlock_at || '').trim();
    if (!title) return res.status(400).send('Title required');
    if (unlock) {
      const unlockUtc = etToUtc(unlock);
      const freezeUtc = new Date(unlockUtc.getTime() + 24*60*60*1000);
      await pool.query('UPDATE quizzes SET title=$1, unlock_at=$2, freeze_at=$3 WHERE id=$4', [title, unlockUtc, freezeUtc, id]);
    } else {
      await pool.query('UPDATE quizzes SET title=$1 WHERE id=$2', [title, id]);
    }
    res.redirect(`/admin/quiz/${id}`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to save');
  }
});

app.post('/admin/quiz/:id/questions', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const payload = String(req.body.json || '').trim();
    const arr = JSON.parse(payload);
    if (!Array.isArray(arr) || arr.length === 0) return res.status(400).send('Invalid JSON');
    await pool.query('DELETE FROM questions WHERE quiz_id = $1', [id]);
    for (const item of arr) {
      const n = Number(item.number || 0);
      if (!n || !item.text || !item.answer) continue;
      await pool.query('INSERT INTO questions(quiz_id, number, text, answer, category, ask) VALUES($1,$2,$3,$4,$5,$6)', [id, n, String(item.text), String(item.answer), String(item.category || 'General'), item.ask ? String(item.ask) : null]);
    }
    res.redirect(`/admin/quiz/${id}`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to replace questions');
  }
});

app.post('/admin/quiz/:id/clone', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const qr = await pool.query('SELECT * FROM quizzes WHERE id=$1', [id]);
    if (qr.rows.length === 0) return res.status(404).send('Not found');
    const qz = qr.rows[0];
    const ins = await pool.query('INSERT INTO quizzes(title, unlock_at, freeze_at) VALUES($1,$2,$3) RETURNING id', [`${qz.title} (Copy)`, qz.unlock_at, qz.freeze_at]);
    const newId = ins.rows[0].id;
    const qs = await pool.query('SELECT * FROM questions WHERE quiz_id=$1 ORDER BY number ASC', [id]);
    for (const q of qs.rows) {
      await pool.query('INSERT INTO questions(quiz_id, number, text, answer, category, ask) VALUES($1,$2,$3,$4,$5,$6)', [newId, q.number, q.text, q.answer, q.category, q.ask]);
    }
    res.redirect(`/admin/quiz/${newId}`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to clone');
  }
});

app.post('/admin/quiz/:id/delete', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    await pool.query('DELETE FROM quizzes WHERE id=$1', [id]);
    res.redirect('/admin/quizzes');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to delete');
  }
});

// --- Admin: seed demo quiz (unlocks now) ---
app.get('/admin/seed-demo', requireAdmin, async (_req, res) => {
  try {
    const now = new Date();
    const unlockUtc = new Date(now.getTime() - 60 * 1000);
    const freezeUtc = new Date(unlockUtc.getTime() + 24 * 60 * 60 * 1000);
    const title = `Demo Quiz ${now.toISOString().slice(0,10)}`;
    const ins = await pool.query('INSERT INTO quizzes(title, unlock_at, freeze_at) VALUES($1,$2,$3) RETURNING id', [title, unlockUtc, freezeUtc]);
    const quizId = ins.rows[0].id;
    const demoQs = [
      ['Capital of France?', 'paris'],
      ['2 + 2 = ?', '4'],
      ['Primary color that mixes with blue to make green?', 'yellow'],
      ['First name of President Lincoln?', 'abraham|abe'],
      ['The ocean between Africa and South America?', 'atlantic'],
      ['Mammal that can truly fly?', 'bat|bats'],
      ['Opposite of cold?', 'hot'],
      ['Square root of 9?', '3|three'],
      ['Chemical symbol for water?', 'h2o|/\bH\s?2\s?O\b/i'],
      ['Largest planet in our solar system?', 'jupiter']
    ];
    for (let i = 0; i < demoQs.length; i++) {
      const [text, answer] = demoQs[i];
      await pool.query('INSERT INTO questions(quiz_id, number, text, answer, category, ask) VALUES($1,$2,$3,$4,$5,$6)', [quizId, i + 1, text, answer, 'General', null]);
    }
    res.type('html').send(`
      <html><body style="font-family: system-ui; padding:24px;">
        <h1>Seeded Demo Quiz</h1>
        <p>Created <strong>${title}</strong> with 10 questions and unlocked it immediately.</p>
        <p><a href="/quiz/${quizId}">Open Demo Quiz</a> · <a href="/calendar">Back to Calendar</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to seed demo');
  }
});

// --- Admin: access & links ---
app.get('/admin/access', requireAdmin, (req, res) => {
  res.type('html').send(`
    <html><head><title>Access & Links</title><link rel="stylesheet" href="/style.css"></head>
    <body class="ta-body" style="padding:24px;">
      <h1>Access & Links</h1>
      <h3>Grant Access</h3>
      <form method="post" action="/admin/grant">
        <label>Email <input name="email" type="email" required /></label>
        <button type="submit">Grant</button>
      </form>
      <h3 style="margin-top:12px;">Send Magic Link</h3>
      <form method="post" action="/admin/send-link">
        <label>Email <input name="email" type="email" required /></label>
        <button type="submit">Send</button>
      </form>
      <p style="margin-top:16px;"><a href="/admin">Back</a></p>
    </body></html>
  `);
});

app.post('/admin/grant', requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [email]);
    res.redirect('/admin/access');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to grant');
  }
});

app.post('/admin/send-link', requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    const token = crypto.randomBytes(24).toString('base64url');
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
    await pool.query('INSERT INTO magic_tokens(token,email,expires_at,used) VALUES($1,$2,$3,false)', [token, email, expiresAt]);
    const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
    await sendMagicLink(email, token, linkUrl);
    res.redirect('/admin/access');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to send');
  }
});

// --- Onboarding ---
app.get('/onboarding', requireAuth, async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const r = await pool.query('SELECT onboarding_complete FROM players WHERE email = $1', [email]);
    const done = r.rows[0] && r.rows[0].onboarding_complete === true;
    if (done) return res.redirect('/');
    res.type('html').send(`
      <html><head><title>Welcome • Trivia Advent-ure</title><link rel="stylesheet" href="/style.css"></head>
      <body class="ta-body" style="padding:24px; max-width:860px; margin:0 auto;">
        <h1>Welcome!</h1>
        <p>Choose how to apply your donation:</p>

        <section style="border:1px solid #ddd; padding:12px; border-radius:8px; margin-bottom:12px;">
          <h3>1) For me only</h3>
          <p>You keep access under <strong>${req.session.user.email}</strong>.</p>
          <form method="post" action="/onboarding/self">
            <button type="submit">Continue as me</button>
          </form>
        </section>

        <section style="border:1px solid #ddd; padding:12px; border-radius:8px; margin-bottom:12px;">
          <h3>2) As a gift only</h3>
          <p>Give access to someone else. You will <em>not</em> keep access.</p>
          <form method="post" action="/onboarding/gift">
            <label>Recipient email(s) (comma-separated)<br/>
              <input name="recipients" style="width: 100%;" required />
            </label>
            <input type="hidden" name="gift_only" value="1" />
            <div style="margin-top:8px;"><button type="submit">Send gift only</button></div>
          </form>
        </section>

        <section style="border:1px solid #ddd; padding:12px; border-radius:8px;">
          <h3>3) For me <em>and</em> as a gift</h3>
          <p>You keep access, and also gift access to someone else.</p>
          <form method="post" action="/onboarding/gift">
            <label>Recipient email(s) (comma-separated)<br/>
              <input name="recipients" style="width: 100%;" required />
            </label>
            <div style="margin-top:8px;"><button type="submit">Keep mine & send gift</button></div>
          </form>
        </section>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load onboarding');
  }
});

app.post('/onboarding/self', requireAuth, async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    await pool.query('UPDATE players SET onboarding_complete = TRUE WHERE email = $1', [email]);
    res.redirect('/player');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to complete onboarding');
  }
});

function parseRecipientEmails(input) {
  const raw = String(input || '').toLowerCase();
  return raw.split(/[;,\s]+/).map(s => s.trim()).filter(s => /.+@.+\..+/.test(s));
}

app.post('/onboarding/gift', requireAuth, async (req, res) => {
  try {
    const donor = (req.session.user.email || '').toLowerCase();
    const recipients = parseRecipientEmails(req.body.recipients || '');
    const giftOnly = String(req.body.gift_only || '').toLowerCase() === '1';
    if (recipients.length === 0) return res.status(400).send('Enter at least one valid recipient email');
    // Grant recipients and send magic links
    for (const r of recipients) {
      await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [r]);
      const token = crypto.randomBytes(24).toString('base64url');
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
      await pool.query('INSERT INTO magic_tokens(token,email,expires_at,used) VALUES($1,$2,$3,false)', [token, r, expiresAt]);
      const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
      await sendMagicLink(r, token, linkUrl).catch(err => console.warn('Send mail failed:', err?.message || err));
    }
    // Optionally grant donor (default true)
    if (!giftOnly) {
      await pool.query('UPDATE players SET onboarding_complete = TRUE WHERE email = $1', [donor]);
    } else {
      await pool.query('UPDATE players SET onboarding_complete = TRUE WHERE email = $1', [donor]);
    }
    res.type('html').send(`<html><body style="font-family: system-ui; padding:24px;"><h1>Gift sent</h1><p>We emailed ${recipients.length} recipient(s).</p><p><a href="/player">Continue</a></p></body></html>`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to process gift');
  }
});

// --- CSV exports ---
app.get('/admin/quiz/:id/export.csv', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { rows } = await pool.query('SELECT user_email, question_id, response_text, points, created_at FROM responses WHERE quiz_id=$1 ORDER BY user_email, question_id', [id]);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="quiz_${id}_responses.csv"`);
    res.write('user_email,question_id,response_text,points,created_at\n');
    for (const r of rows) {
      const line = `${r.user_email},${r.question_id},"${String(r.response_text).replace(/"/g,'\"')}",${r.points},${new Date(r.created_at).toISOString()}\n`;
      res.write(line);
    }
    res.end();
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to export');
  }
});

app.get('/admin/export-overall.csv', requireAdmin, async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT quiz_id, user_email, question_id, response_text, points, created_at FROM responses ORDER BY quiz_id, user_email, question_id');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="overall_responses.csv"');
    res.write('quiz_id,user_email,question_id,response_text,points,created_at\n');
    for (const r of rows) {
      const line = `${r.quiz_id},${r.user_email},${r.question_id},"${String(r.response_text).replace(/"/g,'\"')}",${r.points},${new Date(r.created_at).toISOString()}\n`;
      res.write(line);
    }
    res.end();
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to export');
  }
});

