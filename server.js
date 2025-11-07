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
      override_correct BOOLEAN,
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
      ALTER TABLE responses ADD COLUMN IF NOT EXISTS override_correct BOOLEAN;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE responses ADD COLUMN IF NOT EXISTS flagged BOOLEAN NOT NULL DEFAULT FALSE;
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
    -- Optimistic locking fields for manual grading
    DO $$ BEGIN
      ALTER TABLE responses ADD COLUMN IF NOT EXISTS override_version INTEGER NOT NULL DEFAULT 0;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE responses ADD COLUMN IF NOT EXISTS override_updated_at TIMESTAMPTZ;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE responses ADD COLUMN IF NOT EXISTS override_updated_by TEXT;
    EXCEPTION WHEN others THEN NULL; END $$;

    -- Admins table for multiple admin accounts
    CREATE TABLE IF NOT EXISTS admins (
      email CITEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    
    -- Writer invites and submissions
    CREATE TABLE IF NOT EXISTS writer_invites (
      token TEXT PRIMARY KEY,
      author TEXT NOT NULL,
      email CITEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ,
      -- scheduling/status fields
      slot_date DATE,
      slot_half TEXT,
      send_at TIMESTAMPTZ,
      sent_at TIMESTAMPTZ,
      clicked_at TIMESTAMPTZ,
      submitted_at TIMESTAMPTZ,
      published_at TIMESTAMPTZ,
      active BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS writer_submissions (
      id SERIAL PRIMARY KEY,
      token TEXT NOT NULL REFERENCES writer_invites(token),
      author TEXT,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      data JSONB NOT NULL
    );
  `);
  // Seed ADMIN_EMAIL into admins table if provided
  const seedAdmin = (process.env.ADMIN_EMAIL || '').toLowerCase();
  if (seedAdmin) {
    try { await pool.query('INSERT INTO admins(email) VALUES($1) ON CONFLICT (email) DO NOTHING', [seedAdmin]); } catch {}
  }
}
// --- Writer invite scheduler: send emails when due ---
const WRITER_INVITE_CHECK_MS = 60 * 1000;
setInterval(async () => {
  try {
    const baseUrl = process.env.PUBLIC_BASE_URL || '';
    const { rows } = await pool.query(
      `SELECT token, author, email, slot_date, slot_half FROM writer_invites
       WHERE active = TRUE AND sent_at IS NULL AND (send_at IS NULL OR send_at <= NOW()) AND email IS NOT NULL`
    );
    for (const row of rows) {
      const link = `${baseUrl}/writer/${row.token}`;
      try {
        await sendWriterInviteEmail(row.email, row.author, link, row.slot_date, row.slot_half);
        await pool.query('UPDATE writer_invites SET sent_at = NOW() WHERE token=$1', [row.token]);
        console.log('[invite] sent to', row.email, 'for', row.author);
      } catch (e) {
        console.error('[invite] failed to send for', row.email, e);
      }
    }
  } catch (e) {
    console.error('writer invite scheduler error:', e);
  }
}, WRITER_INVITE_CHECK_MS);


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

async function sendPlainEmail(email, subject, text) {
  const fromHeader = process.env.EMAIL_FROM || 'no-reply@example.com';
  const oAuth2Client = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET
  );
  oAuth2Client.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });
  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
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
  await gmail.users.messages.send({ userId: 'me', requestBody: { raw: rawMessage } });
}

async function sendWriterInviteEmail(to, author, linkUrl, slotDate, slotHalf) {
  const slot = slotDate ? `\r\nSlot: ${slotDate}${slotHalf ? ' ' + slotHalf : ''}` : '';
  const text = `Hi ${author || ''},\r\n\r\nHere is your private link to compose your quiz:${slot}\r\n${linkUrl}\r\n\r\nThanks!`;
  await sendPlainEmail(to, 'Your Trivia Advent-ure writer link', text);
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
    .replace(/[^a-z0-9]/g, '') // remove punctuation AND whitespace (treat "yel low" == "yellow")
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
  const { rows: rs } = await pool.query('SELECT question_id, response_text, locked, override_correct FROM responses WHERE quiz_id=$1 AND user_email=$2', [quizId, userEmail]);
  const qIdToResp = new Map();
  rs.forEach(r => qIdToResp.set(Number(r.question_id), r));
  let streak = 0;
  let total = 0;
  const graded = [];
  for (const q of qs) {
    const r = qIdToResp.get(q.id);
    const locked = !!(r && r.locked);
    if (locked) {
      const auto = r ? isCorrectAnswer(r.response_text, q.answer) : false;
      const correctLocked = (r && typeof r.override_correct === 'boolean') ? r.override_correct : auto;
      const pts = correctLocked ? 5 : 0;
      graded.push({ questionId: q.id, number: q.number, locked: true, correct: correctLocked, points: pts, given: r ? r.response_text : '', answer: q.answer });
      total += pts;
      await pool.query('UPDATE responses SET points = $4 WHERE quiz_id=$1 AND user_email=$2 AND question_id=$3', [quizId, userEmail, q.id, pts]);
      // streak unchanged
      continue;
    }
    const auto = r ? isCorrectAnswer(r.response_text, q.answer) : false;
    const correct = (r && typeof r.override_correct === 'boolean') ? r.override_correct : auto;
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

async function requireAdmin(req, res, next) {
  try {
    if (req.session && req.session.isAdmin === true) return next(); // PIN bypass
    if (!req.session.user) return res.status(401).send('Please sign in.');
    const email = (req.session.user.email || '').toLowerCase();
    // Allow env ADMIN_EMAIL as implicit admin, and any in admins table
    const envAdmin = (process.env.ADMIN_EMAIL || '').toLowerCase();
    if (envAdmin && email === envAdmin) return next();
    const r = await pool.query('SELECT 1 FROM admins WHERE email=$1', [email]);
    if (r.rows.length === 0) return res.status(403).send('Admins only');
    return next();
  } catch (e) {
    console.error('requireAdmin failed:', e);
    return res.status(500).send('Admin check failed');
  }
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
          <a class="ta-card" href="/admin/writer-invite"><strong>Writer Invite</strong><span>Create token link for guest authors</span></a>
          <a class="ta-card" href="/admin/writer-invites"><strong>Writer Invites (CSV)</strong><span>Prepare CSV and bulk-generate links</span></a>
          <a class="ta-card" href="/admin/access"><strong>Access & Links</strong><span>Grant or send magic links</span></a>
          <a class="ta-card" href="/admin/admins"><strong>Admins</strong><span>Manage admin emails</span></a>
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

// --- Admin: create writer invite (returns unique link) ---
app.post('/admin/writer-invite', requireAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const author = String(req.body.author || '').trim();
    const email = String(req.body.email || '').trim() || null;
    const slotDateRaw = String(req.body.slotDate || '').trim() || null;
    const slotHalf = String(req.body.slotHalf || '').trim().toUpperCase() || null; // 'AM'|'PM'
    const sendAtRaw = String(req.body.sendAt || '').trim() || null; // ET string "YYYY-MM-DD HH:mm"
    if (!author) return res.status(400).send('Missing author');
    const token = crypto.randomBytes(16).toString('hex');
    // Parse sendAt (ET) -> UTC if provided
    let sendAtUtc = null;
    if (sendAtRaw) {
      try { sendAtUtc = etToUtc(sendAtRaw.replace('T',' ')); } catch {}
    }
    // slot_date as date-only if provided
    let slotDate = null;
    if (slotDateRaw) {
      const d = new Date(slotDateRaw + 'T00:00:00Z');
      if (!isNaN(d.getTime())) slotDate = slotDateRaw;
    }
    await pool.query(
      'INSERT INTO writer_invites(token, author, email, slot_date, slot_half, send_at) VALUES($1,$2,$3,$4,$5,$6)',
      [token, author, email, slotDate, (slotHalf==='AM'||slotHalf==='PM')?slotHalf:null, sendAtUtc]
    );
    const base = `${req.protocol}://${req.get('host')}`;
    const link = `${base}/writer/${token}`;
    res.type('text').send(link);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to create invite');
  }
});

// --- Admin: writer invite form (GET) ---
app.get('/admin/writer-invite', requireAdmin, (req, res) => {
  res.type('html').send(`
    <html><head><title>Create Writer Invite</title><link rel="stylesheet" href="/style.css"></head>
    <body class="ta-body" style="padding:24px;">
      <h1>Create Writer Invite</h1>
      <form id="inviteForm" style="margin-top:12px;max-width:520px;">
        <div style="margin:8px 0;"><label>Author <input name="author" required style="width:100%"/></label></div>
        <div style="margin:8px 0;"><label>Email (optional) <input name="email" style="width:100%"/></label></div>
        <button type="submit">Generate Invite Link</button>
      </form>
      <div id="result" style="margin-top:16px;font-family:monospace;"></div>
      <p style="margin-top:16px;"><a href="/admin">Back</a></p>
      <script>
        const form = document.getElementById('inviteForm');
        const result = document.getElementById('result');
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          const fd = new FormData(form);
          const body = new URLSearchParams();
          for (const [k,v] of fd.entries()) body.append(k, v);
          result.textContent = 'Generating...';
          try {
            const res = await fetch('/admin/writer-invite', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
            const text = await res.text();
            if (!res.ok) throw new Error(text || 'Failed');
            result.innerHTML = 'Invite Link: <a href="' + text + '" target="_blank">' + text + '</a>';
          } catch (err) {
            result.textContent = 'Error: ' + (err && err.message ? err.message : 'Failed to create invite');
          }
        });
      </script>
    </body></html>
  `);
});

// --- Admin: CSV builder for writer invites ---
app.get('/admin/writer-invites', requireAdmin, (req, res) => {
  const year = new Date().getFullYear();
  const preRowsArr = [];
  let rowNum = 1;
  for (let d = 1; d <= 24; d++) {
    const dd = String(d).padStart(2,'0');
    const dateStr = `${year}-12-${dd}`;
    preRowsArr.push(
      '<tr>' +
      '<td class="idx" style="padding:6px 4px;">'+ (rowNum++) +'</td>' +
      '<td style="padding:6px 4px;"><input name="author" value="" required style="width:100%"></td>' +
      '<td style="padding:6px 4px;"><input name="email" value="" style="width:100%" type="email"></td>' +
      '<td style="padding:6px 4px;"><span>'+dateStr+'</span><input type="hidden" name="slotDate" value="${dateStr}"></td>' +
      '<td style="padding:6px 4px;"><span>AM</span><input type="hidden" name="slotHalf" value="AM"></td>' +
      '<td style="padding:6px 4px;"><button class="rm">Remove</button></td>' +
      '</tr>'
    );
    preRowsArr.push(
      '<tr>' +
      '<td class="idx" style="padding:6px 4px;">'+ (rowNum++) +'</td>' +
      '<td style="padding:6px 4px;"><input name="author" value="" required style="width:100%"></td>' +
      '<td style="padding:6px 4px;"><input name="email" value="" style="width:100%" type="email"></td>' +
      '<td style="padding:6px 4px;"><span>'+dateStr+'</span><input type="hidden" name="slotDate" value="${dateStr}"></td>' +
      '<td style="padding:6px 4px;"><span>PM</span><input type="hidden" name="slotHalf" value="PM"></td>' +
      '<td style="padding:6px 4px;"><button class="rm">Remove</button></td>' +
      '</tr>'
    );
  }
  const preRows = preRowsArr.join('');
  res.type('html').send(`
    <html><head><title>Writer Invites (CSV)</title><link rel="stylesheet" href="/style.css"></head>
    <body class="ta-body" style="padding:24px;">
      <style>
        /* Soften the visual load of many inputs */
        #tbl { border: 1px solid rgba(212,175,55,0.2); border-radius: 8px; overflow: hidden; }
        #tbl thead th { background: rgba(255,215,0,0.06); }
        #tbl tbody tr:nth-child(odd) { background: rgba(255,255,255,0.02); }
        #tbl tbody tr:nth-child(even) { background: rgba(0,0,0,0.05); }
        #tbl td { vertical-align: middle; }
        #tbl input[type="text"], #tbl input[type="email"] { 
          background: #181818; color: #ffd700; border: 1px solid #444; border-radius: 6px; 
          padding: 6px 8px; height: 30px; box-sizing: border-box; width: 100%;
        }
        #tbl input[name="author"] { background: #000; }
        #tbl input[type="text"]:focus, #tbl input[type="email"]:focus {
          outline: none; border-color: #d4af37; box-shadow: 0 0 0 2px rgba(212,175,55,0.15);
        }
        #tbl .idx { color: #ffd700; width: 28px; }
        #tbl .rm { background: transparent; border: 1px solid #555; color: #ffd700; border-radius: 6px; padding: 4px 10px; cursor: pointer; }
        #tbl .rm:hover { border-color: #d4af37; }
        .toolbar button { background: #d4af37; color: #000; border: none; padding: 6px 10px; border-radius: 6px; font-weight: 700; cursor: pointer; }
        .toolbar button:hover { filter: brightness(1.05); }
        .toolbar a { color: #ffd700; }
      </style>
      <h1>Writer Invites (CSV Builder)</h1>
      <p>Add author names and emails. Slots (date and AM/PM) are pre-filled and fixed. You can download the CSV, or click Generate Links to create invites now.</p>
      <div class="toolbar" style="margin:12px 0; display:flex; gap:8px; align-items:center;">
        <button id="downloadCsv">Download CSV</button>
        <button id="generateLinks">Generate Links</button>
        <a href="/admin" style="margin-left:12px;">Back to Admin</a>
      </div>
      <table id="tbl" style="width:100%;border-collapse:collapse;">
        <thead><tr>
          <th style="text-align:left;border-bottom:1px solid #444;">#</th>
          <th style="text-align:left;border-bottom:1px solid #444;">Author</th>
          <th style="text-align:left;border-bottom:1px solid #444;">Email</th>
          <th style="text-align:left;border-bottom:1px solid #444;">SlotDate</th>
          <th style="text-align:left;border-bottom:1px solid #444;">Half</th>
          <th style="text-align:left;border-bottom:1px solid #444;">Actions</th>
        </tr></thead>
        <tbody>${preRows}</tbody>
      </table>
      <div id="out" style="margin-top:16px;font-family:monospace;"></div>
      <script>
        const tbody = document.querySelector('#tbl tbody');
        const out = document.getElementById('out');
        // rows are pre-rendered server-side
        function renumber(){
          [...tbody.querySelectorAll('tr')].forEach((tr,i)=>tr.querySelector('.idx').textContent = String(i+1));
        }
        function rows(){
          return [...tbody.querySelectorAll('tr')].map(tr=>({
            author: tr.querySelector('input[name="author"]').value.trim(),
            email: tr.querySelector('input[name="email"]').value.trim(),
            slotDate: tr.querySelector('input[name="slotDate"]').value.trim(),
            slotHalf: (tr.querySelector('select[name="slotHalf"]').value || '').toUpperCase(),
            sendAt: tr.querySelector('input[name="sendAt"]').value.trim()
          })).filter(r=>r.author);
        }
        function toCsv(data){
          const esc = v => '"' + String(v||'').replaceAll('"','""') + '"';
          const lines = ['Author,Email,SlotDate,Half'];
          data.forEach(r=>lines.push([r.author,r.email,r.slotDate,r.slotHalf].map(esc).join(',')));
          return lines.join('\n');
        }
        document.getElementById('addRow').addEventListener('click', ()=> addRow());
        // attach remove listeners for pre-rendered rows and renumber
        tbody.querySelectorAll('.rm').forEach(btn => btn.addEventListener('click', function(){ const tr=this.closest('tr'); if(tr){ tr.remove(); renumber(); } }));
        renumber();
        document.getElementById('downloadCsv').addEventListener('click', ()=>{
          const data = rows();
          if (!data.length) { out.textContent = 'Add at least one row.'; return; }
          const csv = toCsv(data);
          const blob = new Blob([csv], { type: 'text/csv' });
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = 'writer_invites.csv';
          a.click();
          URL.revokeObjectURL(a.href);
          out.textContent = 'CSV downloaded.';
        });
        document.getElementById('generateLinks').addEventListener('click', async ()=>{
          const data = rows();
          if (!data.length) { out.textContent = 'Add at least one row.'; return; }
          out.textContent = 'Generating...';
          const results = [];
          for (const r of data){
            try{
              const body = new URLSearchParams();
              body.append('author', r.author);
              if (r.email) body.append('email', r.email);
              if (r.slotDate) body.append('slotDate', r.slotDate);
              if (r.slotHalf) body.append('slotHalf', r.slotHalf);
              const res = await fetch('/admin/writer-invite', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body });
              const text = await res.text();
              if (!res.ok) throw new Error(text||'Failed');
              results.push(r.author + ': ' + text);
            }catch(e){ results.push(r.author + ': ERROR ' + (e && e.message ? e.message : 'Failed')); }
          }
          out.innerHTML = results.map(x=>'<div>'+x+'</div>').join('');
        });
        // seed 48 rows for December: 1 AM through 24 PM of the current year
        (function seedDefaultDecember(){
          const year = new Date().getFullYear();
          for (let d = 1; d <= 24; d++) {
            const dd = String(d).padStart(2,'0');
            const dateStr = year + '-12-' + dd;
            addRow({ slotDate: dateStr, slotHalf: 'AM' });
            addRow({ slotDate: dateStr, slotHalf: 'PM' });
          }
        })();
      </script>
    </body></html>
  `);
});

// --- Writer: tokenized quiz submission (no title/unlock fields for authors) ---
app.get('/writer/:token', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT token, author FROM writer_invites WHERE token=$1 AND active=true AND (expires_at IS NULL OR expires_at > NOW())',
      [req.params.token]
    );
    if (!rows.length) return res.status(404).send('Invalid or expired link');
    const invite = rows[0];
    // mark clicked
    try { await pool.query('UPDATE writer_invites SET clicked_at = COALESCE(clicked_at, NOW()) WHERE token=$1', [invite.token]); } catch {}
    res.type('html').send(`
      <html><head><title>Submit Quiz</title><link rel="stylesheet" href="/style.css"></head>
      <body class="ta-body" style="padding:24px;">
        <h1>Submit Your Quiz</h1>
        <p>Author: <strong>${invite.author}</strong></p>
        <form method="post" action="/writer/${invite.token}">
          <fieldset style="margin-top:12px;">
            <legend>Questions (10)</legend>
            ${Array.from({length:10}, (_,i)=>{
              const n=i+1;
              return `<div style="border:1px solid #ddd;padding:8px;margin:6px 0;border-radius:6px;">
                <div><strong>Q${n}</strong></div>
                <div><label>Text <input name="q${n}_text" required style="width:90%"/></label></div>
                <div><label>Answer <input name="q${n}_answer" required style="width:90%"/></label></div>
                <div><label>Category <input name="q${n}_category" value="General"/></label>
                <label style="margin-left:12px;">Ask <input name="q${n}_ask"/></label></div>
              </div>`
            }).join('')}
          </fieldset>
          <div style="margin-top:12px;"><button type="submit">Submit Quiz</button></div>
        </form>
        <p style="margin-top:16px;"><a href="/">Home</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load page');
  }
});

app.post('/writer/:token', express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT token, author FROM writer_invites WHERE token=$1 AND active=true AND (expires_at IS NULL OR expires_at > NOW())',
      [req.params.token]
    );
    if (!rows.length) return res.status(404).send('Invalid or expired link');
    const invite = rows[0];
    const questions = [];
    for (let i=1;i<=10;i++) {
      const qt = String(req.body['q' + i + '_text'] || '').trim();
      const qa = String(req.body['q' + i + '_answer'] || '').trim();
      const qc = String(req.body['q' + i + '_category'] || 'General').trim();
      const qk = String(req.body['q' + i + '_ask'] || '').trim() || null;
      if (!qt || !qa) continue;
      questions.push({ text: qt, answer: qa, category: qc, ask: qk });
    }
    if (!questions.length) return res.status(400).send('Please provide at least one question');
    await pool.query(
      'INSERT INTO writer_submissions(token, author, data) VALUES($1,$2,$3)',
      [invite.token, invite.author, JSON.stringify({ questions })]
    );
    try { await pool.query('UPDATE writer_invites SET submitted_at = NOW() WHERE token=$1', [invite.token]); } catch {}
    res.type('html').send(`
      <html><head><title>Submitted</title><link rel="stylesheet" href="/style.css"></head>
      <body class="ta-body" style="padding:24px;">
        <h1>Thanks, ${invite.author}!</h1>
        <p>Your quiz was submitted successfully. The team will schedule it.</p>
        <p><a href="/">Return home</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to submit quiz');
  }
});

// --- Admin: list and publish writer submissions ---
app.get('/admin/writer-submissions', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT ws.id, ws.submitted_at, ws.author, ws.data
      FROM writer_submissions ws
      ORDER BY ws.id DESC
      LIMIT 200
    `);
    const list = rows.map(r => {
      let first = '';
      try { first = (r.data?.questions?.[0]?.text) || ''; } catch {}
      return `
        <li style="margin:10px 0;padding:8px;border:1px solid #ddd;border-radius:6px;">
          <div><strong>ID:</strong> ${r.id} · <strong>Author:</strong> ${r.author} · <strong>Submitted:</strong> ${new Date(r.submitted_at).toLocaleString()}</div>
          <div style="margin-top:4px;color:#555;"><em>Preview:</em> ${first ? first.replace(/</g,'&lt;') : '(no preview)'} </div>
          <form method="post" action="/admin/writer-submissions/${r.id}/publish" style="margin-top:8px;">
            <label>Title <input name="title" required style="width:40%"/></label>
            <label style="margin-left:12px;">Unlock (ET) <input name="unlock_at" type="datetime-local" required/></label>
            <button type="submit" style="margin-left:12px;">Publish</button>
          </form>
        </li>
      `;
    }).join('');
    res.type('html').send(`
      <html><head><title>Writer Submissions</title><link rel="stylesheet" href="/style.css"></head>
      <body class="ta-body" style="padding:24px;">
        <h1>Writer Submissions</h1>
        <ul style="list-style:none;padding:0;margin:0;">
          ${list || '<li>No submissions yet.</li>'}
        </ul>
        <p style="margin-top:16px;"><a href="/admin">Back</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load submissions');
  }
});

app.post('/admin/writer-submissions/:id/publish', requireAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const title = String(req.body.title || '').trim();
    const unlockInput = String(req.body.unlock_at || '').trim();
    if (!id || !title || !unlockInput) return res.status(400).send('Missing fields');
    const sres = await pool.query('SELECT data, author FROM writer_submissions WHERE id=$1', [id]);
    if (!sres.rows.length) return res.status(404).send('Submission not found');
    const data = typeof sres.rows[0].data === 'string' ? JSON.parse(sres.rows[0].data) : sres.rows[0].data;
    const questions = Array.isArray(data?.questions) ? data.questions : [];
    if (!questions.length) return res.status(400).send('Submission has no questions');
    const unlockUtc = etToUtc(unlockInput);
    const freezeUtc = new Date(unlockUtc.getTime() + 24*60*60*1000);
    const qInsert = await pool.query(
      'INSERT INTO quizzes(title, unlock_at, freeze_at, author) VALUES($1,$2,$3,$4) RETURNING id',
      [title, unlockUtc, freezeUtc, sres.rows[0].author || null]
    );
    const quizId = qInsert.rows[0].id;
    for (let i=0;i<Math.min(10, questions.length);i++) {
      const q = questions[i];
      const text = String(q.text || '').trim();
      const answer = String(q.answer || '').trim();
      const category = String(q.category || 'General').trim();
      const ask = (q.ask && String(q.ask).trim()) || null;
      if (!text || !answer) continue;
      await pool.query(
        'INSERT INTO questions(quiz_id, number, text, answer, category, ask) VALUES($1,$2,$3,$4,$5,$6)',
        [quizId, i+1, text, answer, category, ask]
      );
    }
    // mark published and deactivate token
    try {
      const tokRes = await pool.query('SELECT token FROM writer_submissions WHERE id=$1', [id]);
      const tok = tokRes.rows[0] && tokRes.rows[0].token;
      if (tok) await pool.query('UPDATE writer_invites SET published_at = NOW(), active = FALSE WHERE token=$1', [tok]);
    } catch {}
    res.redirect(`/quiz/${quizId}`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to publish submission');
  }
});

// --- Writer: public submit quiz (same fields/flow as admin upload) ---
/* app.get('/writer/quiz/new', (req, res) => {
  res.type('html').send(`
    <html><head><title>Submit Quiz</title><link rel="stylesheet" href="/style.css"></head>
    <body class="ta-body" style="padding: 24px;">
      <h1>Submit a New Quiz</h1>
      <form method="post" action="/writer/quiz/new">
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
        <div style="margin-top:12px;"><button type="submit">Submit Quiz</button></div>
      </form>
      <p style="margin-top:16px;"><a href="/">Home</a></p>
    </body></html>
  `);
}); */

/* app.post('/writer/quiz/new', async (req, res) => {
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
    res.status(500).send('Failed to submit quiz');
  }
}); */

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
        'SELECT q.id AS qid, q.number, q.text, q.answer, r.response_text, r.points, r.locked, COALESCE(r.flagged,false) AS flagged FROM questions q LEFT JOIN responses r ON r.question_id=q.id AND r.user_email=$1 WHERE q.quiz_id=$2 ORDER BY q.number ASC',
        [email, id]
      );
      const total = gr.reduce((s, r) => s + Number(r.points || 0), 0);
      const rowsHtml = gr.map(r => `
        <tr${r.flagged ? ' class="is-flagged"' : ''}>
          <td>${r.number}${r.locked ? ' 🔒' : ''}</td>
          <td>${r.text}</td>
          <td>${r.response_text || ''}</td>
          <td>${r.answer}</td>
          <td>${r.points || 0}</td>
          <td>
            ${r.flagged ? '<span class="status-badge status-mixed">🚩 flagged</span>' : `
              <form method="post" action="/quiz/${id}/flag" style="display:inline;">
                <input type="hidden" name="qid" value="${r.qid}"/>
                <button class="btn-chip" type="submit" title="Flag this answer for manual review">🚩 Flag for review</button>
              </form>
            `}
          </td>
        </tr>`).join('');
      return res.type('html').send(`
        <html><head><title>Quiz ${id} Recap</title><link rel="stylesheet" href="/style.css"></head>
        <body class="ta-body" style="padding: 24px;">
          <h1>${quiz.title} (Quiz #${id})</h1>
          <div>Status: ${status}</div>
          <h3>Score: ${total}</h3>
          <table class="recap-table" cellspacing="0" cellpadding="6">
            <tr><th>#</th><th>Question</th><th>Your answer</th><th>Correct answer</th><th>Points</th><th>Actions</th></tr>
            ${rowsHtml}
          </table>
          <p style="margin-top:16px;"><a href="/calendar">Back to Calendar</a></p>
        </body></html>
      `);
    }

    const form = locked ? '<p>This quiz is locked until unlock time (ET).</p>' : (loggedIn ? `
      ${existingMap.size > 0 ? `<div style="padding:8px 10px;border:1px solid #ddd;border-radius:6px;background:#fafafa;margin-bottom:10px;">You've started this quiz. <a href="/quiz/${id}?recap=1">View recap</a>.</div>` : ''}
      <form method="post" action="/quiz/${id}/submit">
        ${qs.map(q=>{
          const val = existingMap.get(q.id) || '';
          const checked = existingLockedId === q.id ? 'checked' : '';
          const disable = nowUtc >= freezeUtc ? 'disabled' : '';
          const required = (q.number === 1 && !(nowUtc >= freezeUtc)) ? 'required' : '';
          return `
          <div class=\"quiz-card\">\n            <div class=\"quiz-qhead\"><div class=\"quiz-left\"><div class=\"quiz-qnum\">Q${q.number}</div><span class=\"quiz-cat\">${q.category || 'General'}</span></div> <label class=\"quiz-lock\"><input type=\"radio\" name=\"locked\" value=\"${q.id}\" ${checked} ${disable} ${required}/> Lock this question</label></div>\n            <div class=\"quiz-text\">${q.text}</div>\n            <div class=\"quiz-answer\"><label>Your answer <input name=\"q${q.number}\" value=\"${val.replace(/\"/g,'&quot;')}\" ${disable}/></label></div>\n          </div>`;
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
          <div class="ta-quiz-hero">
            <div class="ta-quiz-hero-top">
              <h1 class="ta-quiz-title">${quiz.title}</h1>
              ${quiz.author ? `<div class="ta-quiz-subtitle">By ${quiz.author}</div>` : ''}
            </div>
            <div class="ta-quiz-hero-body">
              ${(quiz.author || quiz.author_blurb) ? `<div class=\"meta-panel\"><h4>About the author</h4><span class=\"author-name\">${quiz.author || ''}</span><div style=\"opacity:.9;\">${quiz.author_blurb || ''}</div></div>` : ''}
              ${quiz.description ? `<div class=\"desc-panel\"><h4 style=\"margin:0 0 8px 0;color:var(--gold);\">About this quiz</h4>${quiz.description}</div>` : ''}
            </div>
          </div>
          <section class="rules-panel">
            <h4>How scoring works</h4>
            <ul class="rules-list">
              <li>Lock exactly one question. If your locked answer is correct, you earn <strong>5 points</strong>; if incorrect, it earns <strong>0</strong>. The locked question <em>does not affect</em> your streak.</li>
              <li>For all other questions, correct answers build a streak: <strong>+1, then +2, then +3…</strong>. A wrong/blank answer resets the streak to 0.</li>
              <li>You may change your lock until grading/finalization.</li>
            </ul>
          </section>
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

// Player flags a response for manual review
app.post('/quiz/:id/flag', requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const qid = Number(req.body.qid || 0);
    const email = (req.session.user.email || '').toLowerCase();
    if (!qid) return res.status(400).send('Missing question id');
    const upd = await pool.query(
      'UPDATE responses SET flagged = TRUE WHERE quiz_id=$1 AND question_id=$2 AND user_email=$3',
      [id, qid, email]
    );
    // Even if no row updated (e.g., no response), just redirect back
    return res.redirect(`/quiz/${id}?recap=1`);
  } catch (e) {
    console.error(e);
    return res.status(500).send('Failed to flag');
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
          'INSERT INTO responses(quiz_id, question_id, user_email, response_text, locked, override_correct) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (user_email, question_id) DO UPDATE SET locked = EXCLUDED.locked, response_text = EXCLUDED.response_text, override_correct = COALESCE(responses.override_correct, FALSE)',
          [id, q.id, email, '', isLocked, false]
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
    const ins = await pool.query('INSERT INTO quizzes(title, unlock_at, freeze_at, author, author_blurb, description) VALUES($1,$2,$3,$4,$5,$6) RETURNING id', [title, unlockUtc, freezeUtc, 'Trivia Advent‑ure Team', 'A quick set to demo locking and streak scoring.', 'Ten short questions. Lock one for a fixed 5 if correct; other answers build a streak of 1,2,3…']);
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

// --- Admin: seed demo responses for a quiz (10–15 per question) ---
app.get('/admin/quiz/:id/seed-responses', requireAdmin, async (req, res) => {
  try {
    const quizId = Number(req.params.id);
    const qz = await pool.query('SELECT id, title FROM quizzes WHERE id=$1', [quizId]);
    if (qz.rows.length === 0) return res.status(404).send('Quiz not found');
    const qs = (await pool.query('SELECT id, number, answer FROM questions WHERE quiz_id=$1 ORDER BY number ASC', [quizId])).rows;
    // Prepare demo users
    const emails = Array.from({ length: 12 }, (_, i) => `demo_user_${i + 1}@example.com`);
    for (const e of emails) {
      await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [e]);
    }
    // Answer variants per question number
    const variants = new Map([
      [1, ['Paris', 'paris', 'PARIS', 'Pariis', 'Marseille', 'Lyon', 'paris france', '', 'Pa ris', 'pari', 'Bordeaux', 'Naples']],
      [2, ['4', ' 4 ', 'four', 'IV', '3', 'five', '', '2+2', 'four.', '4.0', 'four  ', 'quatre']],
      [3, ['yellow', 'Yellow', 'yello', 'red', 'blue', 'green', 'yel low', '', 'amber', 'yellows', 'gold', 'lemon']],
      [4, ['Abraham', 'Abe', 'abe lincoln', 'lincoln', 'abram', '', 'abraham lincoln', 'Abe.', 'A.', 'Mr Lincoln', 'abrham', 'abe  ']],
      [5, ['Atlantic', 'atlantic', 'atlantic ocean', 'pacific', 'Atlanic', '', 'indian', 'atlntic', 'atl.', 'gulf of mexico', 'atlantic  ', 'north atlantic']],
      [6, ['bat', 'bats', 'bird', 'flying squirrel', '', 'Bat', 'BAT', 'bta', 'owl', 'fox', 'fruit bat', 'mouse']],
      [7, ['hot', 'Hot', 'warm', 'cold', '', 'heat', 'toasty', 'boiling', 'cool', 'HOT', 'lukewarm', 'scalding']],
      [8, ['3', 'three', 'III', '3.0', '4', '', 'Three', 'iii', '2', '5', 'tres', 'tri']],
      [9, ['H2O', 'h 2 o', 'water', 'H20', 'H 2O', 'h2o', '', 'H-2-O', 'H₂O', 'H2 o', 'hydrogen oxide', 'aqua']],
      [10, ['Jupiter', 'jupiter', 'Saturn', 'Jupitar', 'Mars', '', 'JUPITER', 'Jupi ter', 'Neptune', 'Pluto', 'the gas giant', 'jptr']]
    ]);
    // Insert responses with rotation through variants; lock a different Q per user
    let inserted = 0;
    for (let i = 0; i < emails.length; i++) {
      const email = emails[i];
      const lockNumber = (i % Math.max(1, qs.length)) + 1;
      for (const q of qs) {
        const arr = variants.get(q.number) || [''];
        const answer = arr[i % arr.length];
        const isLocked = q.number === lockNumber;
        // Flag some incorrect answers to demo prioritization (every 4th user per question when auto-incorrect)
        const autoCorrect = isCorrectAnswer(answer, q.answer);
        const flagThis = (!autoCorrect) && (i % 4 === 0);
        await pool.query(
          'INSERT INTO responses(quiz_id, question_id, user_email, response_text, locked, flagged) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (user_email, question_id) DO UPDATE SET response_text=EXCLUDED.response_text, locked=EXCLUDED.locked, flagged=COALESCE(responses.flagged, EXCLUDED.flagged)',
          [quizId, q.id, email, answer, isLocked, flagThis]
        );
        inserted++;
      }
      // Grade this user to compute points
      await gradeQuiz(pool, quizId, email);
    }
    res.type('html').send(`
      <html><body style="font-family: system-ui; padding:24px;">
        <h1>Seeded demo responses</h1>
        <p>Inserted/updated ${inserted} responses for ${emails.length} demo users.</p>
        <p><a href="/admin/quiz/${quizId}/grade">Open Grader</a> · <a href="/calendar">Calendar</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to seed demo responses');
  }
});

// --- Admin: grading UI (per quiz) ---
app.get('/admin/quiz/:id/grade', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const qr = await pool.query('SELECT id, title FROM quizzes WHERE id=$1', [id]);
    if (qr.rows.length === 0) return res.status(404).send('Not found');
    const quiz = qr.rows[0];
    // Per-question show graded toggle: showq=comma-separated question numbers
    const showQStr = String(req.query.showq || '');
    const showSet = new Set(
      showQStr.split(',').map(s => parseInt(s, 10)).filter(n => !isNaN(n))
    );
    // Load responses joined with questions
    const rows = (await pool.query(
      `SELECT q.id AS qid, q.number, q.text, q.answer, r.user_email, r.response_text, r.locked, r.override_correct, COALESCE(r.flagged,false) AS flagged,
              COALESCE(r.override_version,0) AS override_version, r.override_updated_at, r.override_updated_by
       FROM questions q
       LEFT JOIN responses r ON r.question_id = q.id
       WHERE q.quiz_id=$1
       ORDER BY q.number ASC, r.user_email ASC`,
      [id]
    )).rows;
    // Group by question, then by normalized response_text
    const byQ = new Map();
    for (const r of rows) {
      // Skip non-responses created by LEFT JOIN (no user_email)
      if (!r.user_email) continue;
      if (!byQ.has(r.qid)) byQ.set(r.qid, { number: r.number, text: r.text, answer: r.answer, answers: new Map() });
      const key = normalizeAnswer(r.response_text || '');
      if (!byQ.get(r.qid).answers.has(key)) byQ.get(r.qid).answers.set(key, []);
      byQ.get(r.qid).answers.get(key).push(r);
    }
    // Build nav and sections
    const qList = Array.from(byQ.values()).sort((a,b)=>a.number-b.number);
    const nav = qList.map(sec => {
      // count ungraded (override null and auto incorrect)
      let ungraded = 0;
      const all = Array.from(sec.answers.values()).flat();
      let flaggedCount = 0;
      for (const r of all) {
        const txt = r.response_text || '';
        const isBlank = normalizeAnswer(txt) === '';
        if (isBlank) { if (r.flagged === true) flaggedCount++; continue; }
        const auto = isCorrectAnswer(txt, sec.answer);
        if (typeof r.override_correct !== 'boolean' && !auto) ungraded++;
        if (r.flagged === true) flaggedCount++;
      }
      const meta = [];
      if (ungraded > 0) meta.push(`${ungraded} awaiting`);
      if (flaggedCount > 0) meta.push(`${flaggedCount} flagged`);
      const label = meta.length ? `Q${sec.number} (${meta.join(', ')})` : `Q${sec.number}`;
      return `<a class=\"grader-tab\" href=\"#q${sec.number}\">${label}</a>`;
    }).join('');
    const sections = qList.map(sec => {
      // Build rows: awaiting only (default) or all (when show=all)
      let list = Array.from(sec.answers.entries());
      const includeAllForThis = showSet.has(sec.number);
      if (!includeAllForThis) {
        list = list.filter(([ans, arr]) => {
          if (arr.length === 0) return false;
          const firstText = arr[0].response_text || '';
          if (normalizeAnswer(firstText) === '') return false; // blanks auto-rejected, do not show
          const auto = isCorrectAnswer(firstText, sec.answer);
          const hasOverride = arr.some(r => typeof r.override_correct === 'boolean');
          const anyFlagged = arr.some(r => r.flagged === true);
          // Show if flagged OR truly awaiting review
          return anyFlagged || (!auto && !hasOverride);
        });
      }
      // Sort so flagged groups appear first
      list.sort((a, b) => {
        const aFlag = a[1].some(r => r.flagged === true) ? 1 : 0;
        const bFlag = b[1].some(r => r.flagged === true) ? 1 : 0;
        return bFlag - aFlag;
      });
      const items = list.map(([ans, arr]) => {
        const auto = arr.length && isCorrectAnswer(arr[0].response_text || '', sec.answer);
        const groupVersion = Math.max(0, ...arr.map(r => Number(r.override_version || 0)));
        // Determine accepted state using override when set; if mixed, show '-'
        let accepted;
        const overrides = arr.map(r => typeof r.override_correct === 'boolean' ? r.override_correct : null);
        if (overrides.every(v => v === true)) accepted = 'accepted';
        else if (overrides.every(v => v === false)) accepted = 'rejected';
        else if (overrides.some(v => v !== null)) accepted = 'mixed';
        else accepted = auto ? 'accepted' : 'rejected';
        const badgeClass = accepted === 'accepted' ? 'status-accepted' : (accepted === 'mixed' ? 'status-mixed' : 'status-rejected');
        const firstText = (arr[0] && (arr[0].response_text || '').trim()) || '';
        const shownAnswer = firstText ? firstText : '<em>blank</em>';
        const flagged = arr.some(r => r.flagged === true);
        return `<tr${flagged ? ' class="is-flagged"' : ''}>
          <td>${shownAnswer}</td>
          <td><span class="status-badge ${badgeClass}">${accepted}${flagged ? ' • 🚩' : ''} • ${arr.length}</span></td>
          <td>
            <div class="seg">
            <form method="post" action="/admin/quiz/${id}/override" style="display:inline;">
              <input type="hidden" name="question_id" value="${sec.number}"/>
              <input type="hidden" name="norm" value="${ans}"/>
              <input type="hidden" name="expected_version" value="${groupVersion}"/>
              <button name="action" value="accept">Accept</button>
              <button name="action" value="reject">Reject</button>
              <button name="action" value="clear">Clear</button>
            </form>
            </div>
          </td>
        </tr>`;
      }).join('');
      // stats (align with quick-nav: 'ungraded' == awaiting review)
      let right = 0, wrong = 0, ungraded = 0;
      const flat = Array.from(sec.answers.values()).flat();
      for (const r of flat) {
        const txt = r.response_text || '';
        const isBlank = normalizeAnswer(txt) === '';
        if (isBlank) { wrong++; continue; } // blanks are auto-rejected
        const auto = isCorrectAnswer(txt, sec.answer);
        const hasOverride = (typeof r.override_correct === 'boolean');
        const state = hasOverride ? r.override_correct : auto;
        if (!hasOverride && !auto) {
          // truly awaiting review
          ungraded++;
        } else if (state) {
          right++;
        } else {
          wrong++;
        }
      }
      // Build per-question toggle URL
      const nextSet = new Set(showSet);
      if (includeAllForThis) nextSet.delete(sec.number); else nextSet.add(sec.number);
      const param = Array.from(nextSet).sort((a,b)=>a-b).join(',');
      const toggleUrl = `/admin/quiz/${id}/grade${param ? `?showq=${param}` : ''}`;

      return `<div class=\"grader-section\" id=\"q${sec.number}\">
        <div class=\"grader-qtitle\">Q${sec.number}</div>
        <div class=\"grader-qtext\">${sec.text}</div>
        <div class=\"grader-correct\"><strong>Correct Answer:</strong> ${sec.answer}</div>
        <div class=\"grader-stats\">Right: ${right} | Wrong: ${wrong} | Ungraded: ${ungraded} • <a class=\"btn-chip\" href=\"${toggleUrl}\">${includeAllForThis ? 'Hide graded' : 'Show graded'}</a></div>
        <div class="btn-row" style="margin-bottom:8px;">
          <form method="post" action="/admin/quiz/${id}/override-all" style="display:inline;">
            <input type="hidden" name="question_id" value="${sec.number}"/>
            <button name="action" value="accept" class="btn-save" type="submit">Accept all shown</button>
          </form>
          <form method="post" action="/admin/quiz/${id}/override-all" style="display:inline;margin-left:6px;">
            <input type="hidden" name="question_id" value="${sec.number}"/>
            <button name="action" value="reject" class="btn-save" type="submit">Reject all shown</button>
          </form>
          <form method="post" action="/admin/quiz/${id}/override-all" style="display:inline;margin-left:6px;">
            <input type="hidden" name="question_id" value="${sec.number}"/>
            <button name="action" value="clear" class="btn-save" type="submit">Clear all</button>
          </form>
        </div>
        <table class=\"grader-table\">
          <tr><th>Submitted answer</th><th>Result</th><th>Override</th></tr>
          ${items || '<tr><td colspan=\"3\">(no submissions)</td></tr>'}
        </table>
      </div>`;
    }).join('');
    const isStale = String(req.query.stale || '') === '1';
    res.type('html').send(`
      <html><head><title>Grade • ${quiz.title}</title><link rel=\"stylesheet\" href=\"/style.css\"></head>
      <body class=\"ta-body\">
        <main class=\"grader-container\">
          <h1 class=\"grader-title\">Grading: ${quiz.title}</h1>
          ${isStale ? '<div style="background:#ffefef;border:1px solid #cc5555;color:#5a1a1a;padding:10px;border-radius:6px;margin-bottom:10px;">Another grader changed one or more items you were viewing. Please refresh to see the latest state.</div>' : ''}
          <div class=\"grader-date\">Viewing: <strong>Awaiting review</strong> by default (🚩 flagged always shown and prioritized). Use “Show graded / Hide graded” in each question section to include graded rows for that question.</div>
          <form method=\"post\" action=\"/admin/quiz/${id}/regrade\" class=\"btn-row\">
            <button class=\"btn-save\" type=\"submit\">Save All Grading Decisions</button>
            <a class=\"ta-btn ta-btn-outline\" href=\"/admin/quiz/${id}\" style=\"margin-left:8px;\">Back</a>
          </form>
          <div class=\"grader-bar\">${nav}</div>
          ${sections}
        </main>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load grader');
  }
});

// Override all responses matching a specific answer for a question
app.post('/admin/quiz/:id/override', requireAdmin, async (req, res) => {
  try {
    const quizId = Number(req.params.id);
    const qNumber = Number(req.body.question_id);
    const action = String(req.body.action || '').toLowerCase(); // accept|reject|clear
    const norm = String(req.body.norm || '');
    const expectedVersion = Number(req.body.expected_version || '0');
    const q = await pool.query('SELECT id FROM questions WHERE quiz_id=$1 AND number=$2', [quizId, qNumber]);
    if (q.rows.length === 0) return res.status(404).send('Question not found');
    const questionId = q.rows[0].id;
    // Find all response ids for this question whose normalized text matches the provided norm key
    const resp = await pool.query('SELECT id, response_text FROM responses WHERE question_id=$1', [questionId]);
    const ids = resp.rows.filter(r => normalizeAnswer(r.response_text || '') === norm).map(r => r.id);
    if (ids.length === 0) { return res.redirect(`/admin/quiz/${quizId}/grade`); }
    // Optimistic check: ensure no one has updated these since the version we rendered
    const ver = await pool.query('SELECT MAX(override_version) AS v FROM responses WHERE id = ANY($1)', [ids]);
    const currentMax = Number(ver.rows[0].v || 0);
    if (currentMax !== expectedVersion) {
      return res.redirect(`/admin/quiz/${quizId}/grade?stale=1`);
    }
    let val = null;
    if (action === 'accept') val = true;
    else if (action === 'reject') val = false;
    const updatedBy = getAdminEmail() || 'admin';
    if (action === 'accept' || action === 'reject') {
      await pool.query('UPDATE responses SET override_correct = $1, flagged = FALSE, override_version = override_version + 1, override_updated_at = NOW(), override_updated_by = $3 WHERE id = ANY($2)', [val, ids, updatedBy]);
    } else {
      await pool.query('UPDATE responses SET override_correct = $1, override_version = override_version + 1, override_updated_at = NOW(), override_updated_by = $3 WHERE id = ANY($2)', [val, ids, updatedBy]);
    }
    res.redirect(`/admin/quiz/${quizId}/grade`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to override');
  }
});

app.post('/admin/quiz/:id/override-all', requireAdmin, async (req, res) => {
  try {
    const quizId = Number(req.params.id);
    const qNumber = Number(req.body.question_id);
    const action = String(req.body.action || '').toLowerCase();
    const q = await pool.query('SELECT id FROM questions WHERE quiz_id=$1 AND number=$2', [quizId, qNumber]);
    if (q.rows.length === 0) return res.status(404).send('Question not found');
    const questionId = q.rows[0].id;
    let val = null;
    if (action === 'accept') val = true;
    else if (action === 'reject') val = false;
    const updatedBy = getAdminEmail() || 'admin';
    if (action === 'accept' || action === 'reject') {
      await pool.query('UPDATE responses SET override_correct = $1, flagged = FALSE, override_version = override_version + 1, override_updated_at = NOW(), override_updated_by = $3 WHERE question_id=$2', [val, questionId, updatedBy]);
    } else {
      await pool.query('UPDATE responses SET override_correct = $1, override_version = override_version + 1, override_updated_at = NOW(), override_updated_by = $3 WHERE question_id=$2', [val, questionId, updatedBy]);
    }
    res.redirect(`/admin/quiz/${quizId}/grade`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to override all');
  }
});

// Regrade all users for the quiz
app.post('/admin/quiz/:id/regrade', requireAdmin, async (req, res) => {
  try {
    const quizId = Number(req.params.id);
    const users = await pool.query('SELECT DISTINCT user_email FROM responses WHERE quiz_id=$1', [quizId]);
    for (const u of users.rows) {
      await gradeQuiz(pool, quizId, u.user_email);
    }
    res.redirect(`/admin/quiz/${quizId}/grade`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to regrade');
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

// --- Admins management (list/add/remove) ---
app.get('/admin/admins', requireAdmin, async (_req, res) => {
  try {
    const rows = (await pool.query('SELECT email, created_at FROM admins ORDER BY email ASC')).rows;
    const items = rows.map(r => `<tr><td>${r.email}</td><td>${new Date(r.created_at).toLocaleString()}</td><td>
      <form method="post" action="/admin/admins/remove" onsubmit="return confirm('Remove admin ${r.email}?');" style="display:inline;">
        <input type="hidden" name="email" value="${r.email}"/>
        <button type="submit">Remove</button>
      </form>
    </td></tr>`).join('');
    res.type('html').send(`
      <html><head><title>Admins</title><link rel="stylesheet" href="/style.css"></head>
      <body class="ta-body" style="padding:24px;">
        <h1>Admins</h1>
        <form method="post" action="/admin/admins/add" style="margin-bottom:12px;">
          <label>Email <input name="email" type="email" required /></label>
          <button type="submit">Add admin</button>
        </form>
        <form method="post" action="/admin/admins/send-links" style="margin-bottom:16px;">
          <button type="submit">Send magic links to all admins</button>
        </form>
        <table border="1" cellspacing="0" cellpadding="6">
          <tr><th>Email</th><th>Added</th><th>Actions</th></tr>
          ${items || '<tr><td colspan="3">No admins yet</td></tr>'}
        </table>
        <p style="margin-top:16px;"><a href="/admin">Back</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load admins');
  }
});

app.post('/admin/admins/add', requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    await pool.query('INSERT INTO admins(email) VALUES($1) ON CONFLICT (email) DO NOTHING', [email]);
    res.redirect('/admin/admins');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to add admin');
  }
});

app.post('/admin/admins/remove', requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    await pool.query('DELETE FROM admins WHERE email=$1', [email]);
    res.redirect('/admin/admins');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to remove admin');
  }
});

app.post('/admin/admins/send-links', requireAdmin, async (_req, res) => {
  try {
    const rows = (await pool.query('SELECT email FROM admins ORDER BY email ASC')).rows;
    let sent = 0;
    for (const r of rows) {
      const email = (r.email || '').toLowerCase();
      if (!email) continue;
      // Ensure admin can sign in
      await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [email]);
      // Create magic token and send
      const token = crypto.randomBytes(24).toString('base64url');
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
      await pool.query('INSERT INTO magic_tokens(token,email,expires_at,used) VALUES($1,$2,$3,false)', [token, email, expiresAt]);
      const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
      try {
        await sendMagicLink(email, token, linkUrl);
        sent++;
      } catch (mailErr) {
        console.warn('Send mail failed for', email, mailErr?.message || mailErr);
      }
    }
    res.type('html').send(`<html><body style="font-family: system-ui; padding:24px;"><h1>Magic links sent</h1><p>Sent ${sent} link(s) to ${rows.length} admin(s).</p><p><a href="/admin/admins">Back</a></p></body></html>`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to send links');
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

