/*
// Admin: preview a writer submission
app.get('/admin/writer-submissions/:id', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send('Invalid id');
    const sres = await pool.query('SELECT ws.token, ws.author, ws.submitted_at, ws.updated_at, ws.data, wi.slot_date, wi.slot_half, wi.submitted_at as invite_submitted_at FROM writer_submissions ws LEFT JOIN writer_invites wi ON wi.token = ws.token WHERE ws.id=$1', [id]);
    if (!sres.rows.length) return res.status(404).send('Not found');
    const row = sres.rows[0];
    const data = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
    const questions = Array.isArray(data?.questions) ? data.questions : [];
    const warn = [];
    const esc = (v)=>String(v||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
    const qHtml = questions.map((q, i) => {
      const text = String(q.text||'');
      const ask = String(q.ask||'');
      let occ = 0;
      if (ask) {
        const h = text.toLowerCase();
        const n = ask.toLowerCase();
        let idx = 0; while ((idx = h.indexOf(n, idx)) !== -1) { occ++; idx += n.length; }
        if (occ !== 1) warn.push(`Q${i+1}: Ask appears ${occ} times (must be exactly once).`);
      }
      const safeText = esc(text);
      const safeAsk = esc(ask);
      const highlighted = ask && occ === 1 ? safeText.replace(new RegExp(ask.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), 'i'), '<mark>$&</mark>') : safeText;
      return `<div style="border:1px solid #ddd;padding:8px;margin:8px 0;border-radius:6px;">
        <div><strong>Q${i+1}</strong> <em>${esc(q.category||'')}</em></div>
        <div style="margin-top:6px;">${highlighted}</div>
        <div style="margin-top:6px;color:#666;">Answer: <strong>${esc(q.answer||'')}</strong>${ask ? ` · Ask: <code>${safeAsk}</code>` : ''}</div>
      </div>`;
    }).join('');
    const warnHtml = warn.length ? `<div style="background:#fff3cd;color:#664d03;border:1px solid #ffecb5;padding:8px;border-radius:6px;margin:8px 0;">${warn.map(esc).join('<br/>')}</div>` : '';
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead(`Preview Submission #${id}`, false)}
      <body class="ta-body">
      ${header}
        <h1>Submission #${id} Preview</h1>
        <div>Author: <strong>${esc(row.author||'')}</strong></div>
        <div>Slot: ${row.slot_date || ''} ${row.slot_half || ''}</div>
        <div>Submitted: ${fmtEt(row.submitted_at)}${row.updated_at ? ` · Updated: ${fmtEt(row.updated_at)}` : ''}</div>
        ${data.description ? `<h3 style="margin-top:12px;">About this quiz</h3><div>${esc(data.description)}</div>` : ''}
        ${data.author_blurb ? `<h3 style="margin-top:12px;">About the author</h3><div>${esc(data.author_blurb)}</div>` : ''}
        ${warnHtml}
        <h3 style="margin-top:12px;">Questions</h3>
        ${qHtml || '<div>No questions.</div>'}
        <form method="post" action="/admin/writer-submissions/${id}/publish" style="margin-top:12px;">
          <label>Title <input name="title" required style="width:40%"/></label>
          <label style="margin-left:12px;">Unlock (ET) <input name="unlock_at" type="datetime-local" required value="${(req.query && req.query.unlock) ? String(req.query.unlock).replace(' ','T') : ''}"/></label>
          <button type="submit" style="margin-left:12px;">Publish</button>
        </form>
        <p style="margin-top:16px;"><a href="/admin/writer-submissions" class="ta-btn ta-btn-outline">Back</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load preview');
  }
});
*/
import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import fs from 'fs';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import { google } from 'googleapis';
import dotenv from 'dotenv';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
// Avoid timezone library; store UTC in DB and compare in UTC

dotenv.config();

// Cache-busting for static assets
function computeAssetVersion() {
  if (process.env.ASSET_VERSION) return process.env.ASSET_VERSION;
  let pkgVersion = '0.0.0';
  try {
    const pkgJson = fs.readFileSync(new URL('./package.json', import.meta.url), 'utf8');
    pkgVersion = JSON.parse(pkgJson).version || pkgVersion;
  } catch (err) {
    console.warn('[cache] Unable to read package.json version:', err);
  }
  
  // Try to get git commit hash for cache busting
  let commitHash = '';
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    commitHash = execSync('git rev-parse --short HEAD', { encoding: 'utf8', cwd: __dirname }).trim();
  } catch (err) {
    // Fall back to timestamp if git is not available
    commitHash = Date.now().toString(36);
  }
  
  try {
    const hash = crypto.createHash('md5');
    ['./public/style.css', './public/js/common-enhancements.js', './public/js/quiz-enhancements.js']
      .forEach(rel => {
        try {
          const buf = fs.readFileSync(new URL(rel, import.meta.url));
          hash.update(buf);
        } catch (fileErr) {
          // Ignore missing optional asset
        }
      });
    const digest = hash.digest('hex').slice(0, 10);
    return `${pkgVersion}-${digest}-${commitHash}`;
  } catch (err) {
    console.warn('[cache] Unable to compute asset hash:', err);
    return `${pkgVersion}-${commitHash}`;
  }
}
const ASSET_VERSION = computeAssetVersion();

// Feature flags / security toggles
const ADMIN_PIN_ENABLED = (String(process.env.ADMIN_PIN_ENABLE || '').toLowerCase() === 'true') && String(process.env.ADMIN_PIN || '').trim().length > 0;

// Password hashing (scrypt)
import { randomBytes, scrypt as _scrypt, timingSafeEqual } from 'crypto';
import { promisify } from 'util';
const scrypt = promisify(_scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, 64);
  return 's1$' + salt.toString('base64') + '$' + Buffer.from(key).toString('base64');
}
async function verifyPassword(password, stored) {
  try {
    const parts = String(stored||'').split('$');
    if (parts.length !== 3 || parts[0] !== 's1') return false;
    const salt = Buffer.from(parts[1], 'base64');
    const hash = Buffer.from(parts[2], 'base64');
    const key = await scrypt(password, salt, hash.length);
    return timingSafeEqual(hash, Buffer.from(key));
  } catch { return false; }
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
// Serve static assets (CSS, images)
import path from 'path';
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
      onboarding_complete BOOLEAN NOT NULL DEFAULT FALSE,
      username CITEXT UNIQUE
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
    DO $$ BEGIN
      ALTER TABLE quizzes ADD COLUMN IF NOT EXISTS author_email CITEXT;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE quizzes ADD COLUMN IF NOT EXISTS author_points_override NUMERIC;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS password_hash TEXT;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS password_set_at TIMESTAMPTZ;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS username CITEXT;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      CREATE UNIQUE INDEX IF NOT EXISTS ux_players_username ON players((lower(username))) WHERE username IS NOT NULL;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS email_notifications_enabled BOOLEAN NOT NULL DEFAULT TRUE;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS email_quiz_unlocks BOOLEAN NOT NULL DEFAULT TRUE;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS email_results BOOLEAN NOT NULL DEFAULT TRUE;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS email_recaps BOOLEAN NOT NULL DEFAULT TRUE;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS email_summaries BOOLEAN NOT NULL DEFAULT TRUE;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS email_announcements BOOLEAN NOT NULL DEFAULT TRUE;
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
    -- Backfill new columns for existing deployments
    DO $$ BEGIN
      ALTER TABLE writer_invites ADD COLUMN IF NOT EXISTS slot_date DATE;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE writer_invites ADD COLUMN IF NOT EXISTS slot_half TEXT;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE writer_invites ADD COLUMN IF NOT EXISTS send_at TIMESTAMPTZ;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE writer_invites ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE writer_invites ADD COLUMN IF NOT EXISTS clicked_at TIMESTAMPTZ;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE writer_invites ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE writer_invites ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE writer_invites ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE writer_submissions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE writer_submissions ADD CONSTRAINT writer_submissions_token_key UNIQUE(token);
    EXCEPTION WHEN others THEN NULL; END $$;
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
        // Ensure author is in players table before sending email
        if (row.email) {
          await ensureAuthorIsPlayer(row.email);
        }
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
  try {
    const fromHeader = process.env.EMAIL_FROM || 'no-reply@example.com';
    const fromEmail = parseEmailAddress(fromHeader) || 'no-reply@example.com';
    const url = linkUrl || `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
    console.log('[sendMagicLink] Sending magic link to:', email);
    console.log('[sendMagicLink] Magic link URL:', url);

    // Check if Gmail credentials are configured
    if (!process.env.GMAIL_CLIENT_ID || !process.env.GMAIL_CLIENT_SECRET || !process.env.GMAIL_REFRESH_TOKEN) {
      throw new Error('Gmail OAuth credentials not configured. Missing GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, or GMAIL_REFRESH_TOKEN');
    }

    // Use Gmail HTTP API with OAuth2
    const oAuth2Client = new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET
    );
    oAuth2Client.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const subject = 'Welcome to Trivia Advent-ure!';
    const text = `Welcome to Trivia Advent-ure!\r\n\r\nClick the link below to sign in and get started:\r\n${url}\r\n\r\nThis link expires in 30 days and can only be used once.\r\n\r\nIf you didn't request this link, you can safely ignore this email.\r\n\r\nHappy trivia-ing!`;

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

    const result = await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw: rawMessage }
    });
    
    console.log('[sendMagicLink] Email sent successfully. Message ID:', result.data.id);
    return result;
  } catch (error) {
    console.error('[sendMagicLink] Error sending email to', email, ':', error.message);
    console.error('[sendMagicLink] Full error:', error);
    
    // Provide helpful error messages for common OAuth issues
    if (error.response?.data?.error === 'invalid_grant') {
      const helpfulError = new Error('Gmail refresh token has expired or been revoked. Please generate a new refresh token and update GMAIL_REFRESH_TOKEN environment variable.');
      helpfulError.originalError = error;
      throw helpfulError;
    }
    
    throw error;
  }
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

async function sendHTMLEmail(email, subject, html) {
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
    'Content-Type: text/html; charset=UTF-8',
    '',
    html
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

// Helper function to generate HTML head with viewport meta tag
function renderHead(title, includeFavicon = true) {
  const favicon = includeFavicon ? '<link rel="icon" href="/favicon.svg" type="image/svg+xml">' : '';
  return `<html style="background:linear-gradient(180deg,#0f1d5a 0%, #15124a 60%, #0b1338 100%);background-color:#0b1338;min-height:100%;"><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title}</title><style>html,body{margin:0;padding:0;background:linear-gradient(180deg,#0f1d5a 0%, #15124a 60%, #0b1338 100%);background-color:#0b1338;min-height:100vh;}</style><link rel="stylesheet" href="/style.css?v=${ASSET_VERSION}">${favicon}</head>`;
}

// Helper function to generate consistent header HTML across all pages
async function renderHeader(req) {
  const email = (req.session?.user?.email || '').toLowerCase() || null;
  let displayName = '';
  let isAdmin = false;
  
  if (email) {
    try {
      const pr = await pool.query('SELECT username FROM players WHERE email=$1', [email]);
      displayName = (pr.rows.length && pr.rows[0].username) ? pr.rows[0].username : email;
      isAdmin = await isAdminUser(req);
    } catch (e) {
      displayName = email;
    }
  }
  
  const homeHref = email ? '/player' : '/public';
  const navLinks = email 
    ? `<span class="ta-user" style="margin-right:12px;opacity:.9;">${displayName}</span>
       <a href="${homeHref}">Home</a>
       <a href="/calendar">Calendar</a>
       <a href="/leaderboard">Leaderboard</a>
       <a href="/account">Account</a>
       ${isAdmin ? '<a href="/admin">Admin</a>' : ''}
       <a href="https://ko-fi.com/triviaadvent" target="_blank" rel="noopener noreferrer">Donate</a>
       <a href="/logout">Logout</a>`
    : `<a href="/public">Home</a>
       <a href="/leaderboard">Leaderboard</a>
       <a href="https://ko-fi.com/triviaadvent" target="_blank" rel="noopener noreferrer">Donate</a>
       <a href="/login">Login</a>`;
  
  return `<header class="ta-header"><div class="ta-header-inner"><div class="ta-brand"><img class="ta-logo" src="/logo.svg"/><span class="ta-title">Trivia Advent‑ure</span></div><button class="ta-menu-toggle" aria-label="Toggle menu" aria-expanded="false"><span></span><span></span><span></span></button><nav class="ta-nav">${navLinks}</nav></div></header><script src="/js/common-enhancements.js?v=${ASSET_VERSION}"></script>`;
}

function renderFooter(req) {
  const email = (req.session?.user?.email || '').toLowerCase() || null;
  const isAdmin = req.session?.isAdmin === true;
  const homeHref = email ? '/player' : '/public';
  const accountLink = email ? '<a href="/account">Account</a>' : '<a href="/login">Account</a>';
  return `
    <footer class="ta-footer">
      <div class="ta-container">
        <div class="ta-footer-inner">
          <div class="ta-footer-brand">
            <img src="/logo.svg" alt="Trivia Advent-ure logo"/>
            <div>
              <div class="ta-footer-title">Trivia Advent‑ure</div>
              <div class="ta-footer-subtitle">Daily trivia for a good cause</div>
            </div>
          </div>
          <div class="ta-footer-links">
            <div class="ta-footer-section">
              <h4>Explore</h4>
              <a href="${homeHref}">Home</a>
              <a href="/calendar">Calendar</a>
              <a href="/leaderboard">Leaderboard</a>
            </div>
            <div class="ta-footer-section">
              <h4>Account</h4>
              ${accountLink}
              ${email ? '<a href="/logout">Logout</a>' : '<a href="/login">Login</a>'}
              ${isAdmin ? '<a href="/admin">Admin</a>' : ''}
            </div>
            <div class="ta-footer-section">
              <h4>Support</h4>
              <a href="https://ko-fi.com/triviaadvent" target="_blank" rel="noopener noreferrer">Donate on Ko-fi</a>
              <a href="/faq">FAQ</a>
              <a href="/contact">Contact</a>
            </div>
          </div>
          <div class="ta-footer-charities">
            <span>Benefiting</span>
            <a href="https://translifeline.org" target="_blank" rel="noopener noreferrer"><img src="/img/TL-logo_purple_transparent.png" alt="Trans Lifeline"/></a>
            <a href="https://wck.org" target="_blank" rel="noopener noreferrer"><img src="/img/download.png" alt="World Central Kitchen"/></a>
          </div>
        </div>
        <div class="ta-footer-copy">© Trivia Advent‑ure</div>
      </div>
    </footer>
  `;
}

function renderBreadcrumb(trail = []) {
  if (!Array.isArray(trail) || trail.length === 0) return '';
  const items = trail.map((item, idx) => {
    if (idx === trail.length - 1 || !item.href) {
      return `<span>${item.label}</span>`;
    }
    return `<a href="${item.href}">${item.label}</a>`;
  }).join('<span class="ta-breadcrumbs-sep">›</span>');
  return `<nav class="ta-breadcrumbs">${items}</nav>`;
}

const ADMIN_CRUMB = { label: 'Admin', href: '/admin' };

const ADMIN_NAV_LINKS = [
  { id: 'dashboard', label: 'Dashboard', href: '/admin' },
  { id: 'quizzes', label: 'Quizzes', href: '/admin/quizzes' },
  { id: 'calendar', label: 'Calendar', href: '/admin/calendar' },
  { id: 'authors', label: 'Author Assignments', href: '/admin/author-slots' },
  { id: 'writers', label: 'Writer Invites', href: '/admin/writer-invites' },
  { id: 'players', label: 'Players', href: '/admin/players' },
  { id: 'access', label: 'Access & Links', href: '/admin/access' },
  { id: 'announcements', label: 'Announcements', href: '/admin/announcements' }
];

function renderAdminNav(activeId) {
  const items = ADMIN_NAV_LINKS.map(link => `
    <a class="ta-admin-nav__link${link.id === activeId ? ' is-active' : ''}" href="${link.href}">${link.label}</a>
  `).join('');
  return `<nav class="ta-admin-nav">${items}</nav>`;
}

function renderQuizSubnav(quizId, activeId, options = {}) {
  const { allowRecap = false } = options || {};
  const baseLinks = [
    { id: 'quiz', label: 'Quiz', href: `/quiz/${quizId}` },
    { id: 'leaderboard', label: 'Leaderboard', href: `/quiz/${quizId}/leaderboard` }
  ];
  if (allowRecap) {
    baseLinks.push({ id: 'recap', label: 'My Recap', href: `/quiz/${quizId}?recap=1` });
  }
  const items = baseLinks.map(link => `
    <a class="ta-subnav__link${link.id === activeId ? ' is-active' : ''}" href="${link.href}">${link.label}</a>
  `).join('');
  return `<nav class="ta-subnav">${items}</nav>`;
}
// Helper function for user-friendly error pages
async function renderErrorPage(req, statusCode, title, message, suggestions = []) {
  const header = await renderHeader(req);
  const suggestionsHtml = suggestions.length > 0 
    ? `<div style="margin-top:16px;padding:12px;background:rgba(255,167,38,0.1);border-left:3px solid var(--gold);border-radius:4px;">
        <strong style="color:#ffd700;">What you can try:</strong>
        <ul style="margin:8px 0 0 0;padding-left:20px;">
          ${suggestions.map(s => `<li>${s}</li>`).join('')}
        </ul>
      </div>`
    : '';
  
  return `
    ${renderHead(`${title} • Trivia Advent-ure`, true)}
    <body class="ta-body">
      ${header}
      <main class="ta-main ta-container" style="max-width:720px;">
        <h1 class="ta-page-title" style="color:#d32f2f;">${title}</h1>
        <div style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:24px;margin-top:16px;">
          <p style="font-size:18px;line-height:1.6;margin:0;">${message}</p>
          ${suggestionsHtml}
        </div>
        <div style="margin-top:24px;">
          <a href="/" class="ta-btn ta-btn-primary">Go Home</a>
          <a href="javascript:history.back()" class="ta-btn ta-btn-outline" style="margin-left:8px;">Go Back</a>
        </div>
      </main>
      ${renderFooter(req)}
    </body></html>
  `;
}

function fmtEt(dateLike){
  if (!dateLike) return '';
  try {
    return new Date(dateLike).toLocaleString('en-US', { timeZone: 'America/New_York' });
  } catch {
    return String(dateLike);
  }
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

async function computeAuthorAveragePoints(pool, quizId, authorEmailRaw) {
  if (!authorEmailRaw) return { average: 0, count: 0, source: 'none' };
  const authorEmail = String(authorEmailRaw).toLowerCase();
  const { rows: overrideRows } = await pool.query('SELECT author_points_override FROM quizzes WHERE id=$1', [quizId]);
  const overrideVal = overrideRows.length ? overrideRows[0].author_points_override : null;
  if (overrideVal !== null && overrideVal !== undefined) {
    const numeric = Number(overrideVal);
    if (Number.isFinite(numeric)) {
      return { average: numeric, count: 0, source: 'override' };
    }
  }
  const { rows } = await pool.query(
    'SELECT user_email, SUM(points) AS total_points FROM responses WHERE quiz_id=$1 GROUP BY user_email',
    [quizId]
  );
  const others = rows.filter(r => (r.user_email || '').toLowerCase() !== authorEmail);
  if (!others.length) return { average: 0, count: 0, source: 'average' };
  const sum = others.reduce((acc, r) => acc + Number(r.total_points || 0), 0);
  return { average: sum / others.length, count: others.length, source: 'average' };
}

function formatPoints(val) {
  const num = Number(val);
  if (!Number.isFinite(num)) return '0';
  if (Math.abs(num - Math.round(num)) < 1e-6) return String(Math.round(num));
  return num.toFixed(2);
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

async function isAdminUser(req) {
  try {
    if (req.session && req.session.isAdmin === true) return true; // PIN bypass
    if (!req.session.user) return false;
    const email = (req.session.user.email || '').toLowerCase();
    const envAdmin = (process.env.ADMIN_EMAIL || '').toLowerCase();
    if (envAdmin && email === envAdmin) return true;
    const r = await pool.query('SELECT 1 FROM admins WHERE email=$1', [email]);
    return r.rows.length > 0;
  } catch {
    return false;
  }
}

async function requireAdmin(req, res, next) {
  const admin = await isAdminUser(req);
  if (admin) return next();
  if (!req.session.user) return res.status(401).send('Please sign in.');
  return res.status(403).send('Admins only');
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
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
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

// Password login
app.post('/auth/login-password', express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const usernameRaw = (req.body && req.body.username) || '';
    const password = (req.body && req.body.password) || '';
    const username = String(usernameRaw).trim();
    if (!username || !password) return res.status(400).send('Missing username or password');
    const r = await pool.query('SELECT email, password_hash FROM players WHERE lower(username)=lower($1)', [username]);
    if (!r.rows.length) return res.status(403).send('No account. Use magic link first.');
    const ok = await verifyPassword(password, r.rows[0].password_hash);
    if (!ok) return res.status(403).send('Invalid username or password');
    const email = r.rows[0].email.toLowerCase();
    req.session.user = { email };
    res.redirect('/calendar');
  } catch (e) {
    console.error(e);
    res.status(500).send(await renderErrorPage(req, 500, 'Login Failed',
      'We encountered an error while processing your login. Please try again.',
      ['Check your username and password', 'Try using the magic link option if available', 'Clear your browser cache and try again', 'Contact support if the problem persists']
    ));
  }
});

// Account security: set/change password (requires login)
app.get('/account/security', requireAuth, async (req, res) => {
  const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead('Security', false)}
    <body class="ta-body" style="padding:24px;">
    ${header}
      <h1>Account Security</h1>
      <form method="post" action="/account/security">
        <label>New password <input type="password" name="password" required minlength="8" /></label>
        <button type="submit" style="margin-left:8px;">Save</button>
      </form>
      <p style="margin-top:16px;"><a href="/calendar" class="ta-btn ta-btn-outline">Calendar</a></p>
    </body></html>
  `);
});

app.post('/account/security', requireAuth, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const pw = String((req.body && req.body.password) || '').trim();
    if (pw.length < 8 || pw.length > 200) return res.status(400).send('Password length invalid');
    const hash = await hashPassword(pw);
    const email = (req.session.user.email || '').toLowerCase();
    await pool.query('UPDATE players SET password_hash=$1, password_set_at=NOW() WHERE email=$2', [hash, email]);
    res.redirect('/calendar');
  } catch (e) {
    console.error(e);
    res.status(500).send(await renderErrorPage(req, 500, 'Password Setup Failed',
      'We couldn\'t set your password. Please try again.',
      ['Make sure your password is at least 8 characters long', 'Check that both password fields match', 'Try again in a few moments', 'Contact support if the problem continues']
    ));
  }
});
// Main account page - hub for all account settings
app.get('/account', requireAuth, async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const player = (await pool.query('SELECT username, email, access_granted_at, password_set_at, onboarding_complete FROM players WHERE email=$1', [email])).rows[0];
    if (!player) {
      return res.status(404).send(await renderErrorPage(req, 404, 'Account Not Found',
        'We couldn\'t find your account. You may need to sign up first.',
        ['Make sure you\'re logged in', 'Try logging out and back in', 'Contact support if you believe you have an account']
      ));
    }
    
    const isAdmin = await isAdminUser(req);
    const displayName = player.username || email;
    const accountAge = player.access_granted_at ? Math.floor((Date.now() - new Date(player.access_granted_at).getTime()) / (1000 * 60 * 60 * 24)) : 0;
    
    // Get quick stats
    let stats = { totalQuizzes: 0, totalQuestions: 0, avgScore: 0 };
    try {
      const statsResult = await pool.query(`
        SELECT 
          COUNT(DISTINCT r.quiz_id) as total_quizzes,
          COUNT(DISTINCT r.question_id) as total_questions,
          SUM(CASE WHEN r.override_correct = true OR (r.override_correct IS NULL AND LOWER(TRIM(r.response_text)) = LOWER(TRIM(qq.answer))) THEN 1 ELSE 0 END) as correct_answers
        FROM responses r
        JOIN questions qq ON qq.id = r.question_id
        WHERE r.user_email = $1
      `, [email]);
      if (statsResult.rows.length) {
        stats.totalQuizzes = parseInt(statsResult.rows[0].total_quizzes) || 0;
        stats.totalQuestions = parseInt(statsResult.rows[0].total_questions) || 0;
        const correct = parseInt(statsResult.rows[0].correct_answers) || 0;
        stats.avgScore = stats.totalQuestions > 0 ? Math.round((correct / stats.totalQuestions) * 100) : 0;
      }
    } catch (e) {
      console.error('Error fetching account stats:', e);
    }
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Account • Trivia Advent-ure', true)}
      <body class="ta-body">
        ${header}
        <main class="ta-main">
          <div class="account-page">
            <div class="account-header">
          <h1 class="ta-page-title">Account Settings</h1>
              ${req.query.msg ? `<div class="account-alert">${req.query.msg}</div>` : ''}
              </div>
            <div class="account-layout">
              <section class="account-card account-summary">
                <h2>Account Overview</h2>
                <dl>
                  <dt>Username</dt><dd>${player.username || '(not set)'}</dd>
                  <dt>Email</dt><dd>${player.email}</dd>
                  <dt>Member Since</dt><dd>${player.access_granted_at ? new Date(player.access_granted_at).toLocaleDateString() : 'Unknown'}</dd>
                  <dt>Quizzes Played</dt><dd>${stats.totalQuizzes}</dd>
                  <dt>Questions Answered</dt><dd>${stats.totalQuestions}</dd>
                  <dt>Average Score</dt><dd>${stats.avgScore}%</dd>
                </dl>
              </section>
              <div class="account-stack">
                <section class="account-card">
                  <h2>Profile &amp; Security</h2>
                  <div class="account-actions">
                    <a class="account-action" href="/account/credentials">
              <div>
                <strong>Edit Profile</strong>
                        <small>Change username and password</small>
                      </div>
                      <span aria-hidden="true">›</span>
              </a>
            </div>
          </section>
                <section class="account-card">
                  <h2>Activity &amp; Data</h2>
                  <div class="account-actions">
                    <a class="account-action" href="/player">
                      <div>
                <strong>My Dashboard</strong>
                        <small>View your stats and recent quizzes</small>
                      </div>
                      <span aria-hidden="true">›</span>
              </a>
                    <a class="account-action" href="/account/history">
                      <div>
                <strong>Quiz History</strong>
                        <small>View all your quiz attempts</small>
                      </div>
                      <span aria-hidden="true">›</span>
              </a>
                    <a class="account-action" href="/account/export">
                      <div>
                <strong>Export Data</strong>
                        <small>Download your quiz data (CSV/JSON)</small>
                      </div>
                      <span aria-hidden="true">›</span>
              </a>
                    <a class="account-action" href="/calendar">
                      <div>
                <strong>Calendar</strong>
                        <small>Browse and play quizzes</small>
                      </div>
                      <span aria-hidden="true">›</span>
              </a>
            </div>
          </section>
                <section class="account-card">
                  <h2>Communication</h2>
                  <div class="account-actions">
                    <a class="account-action" href="/account/preferences">
                      <div>
                <strong>Email Preferences</strong>
                        <small>Manage notification settings</small>
                      </div>
                      <span aria-hidden="true">›</span>
              </a>
            </div>
          </section>
                <section class="account-card">
                  <h2>Danger Zone</h2>
                  <p>Permanently delete your account and all associated data. This action cannot be undone.</p>
                  <a href="/account/delete" class="account-action account-action--danger">
                    <strong>Delete Account</strong>
                  </a>
          </section>
              </div>
              </div>
              </div>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send(await renderErrorPage(req, 500, 'Account Error',
      'We encountered an error while loading your account page. Please try again.',
      ['Refresh the page', 'Try again in a few moments', 'Contact support if the problem persists']
    ));
  }
});

// Onboarding page - first-time user welcome
app.get('/onboarding', requireAuth, async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const r = await pool.query('SELECT onboarding_complete FROM players WHERE email=$1', [email]);
    if (r.rows.length && r.rows[0].onboarding_complete === true) {
      // Already onboarded, redirect to credentials or home
      const creds = await pool.query('SELECT username, password_set_at FROM players WHERE email=$1', [email]);
      const p = creds.rows[0] || {};
      if (!p.username || !p.password_set_at) return res.redirect('/account/credentials');
      return res.redirect('/');
    }
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Welcome to Trivia Advent-ure', false)}
      <body class="ta-body">
      ${header}
      <main class="ta-main ta-container" style="max-width:720px; margin:0 auto; padding:24px;">
        <h1 class="ta-page-title">Welcome to Trivia Advent-ure!</h1>
        <div style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:24px;margin-bottom:24px;">
          <p style="font-size:18px;line-height:1.6;margin:0 0 16px 0;">
            We're excited to have you join the community! Here's what you need to know:
          </p>
          <ul style="line-height:1.8;margin:0;padding-left:24px;">
            <li><strong>48 quizzes</strong> unlock twice daily (midnight and noon ET) from December 1–24</li>
            <li><strong>10 questions per quiz</strong> with immediate feedback and scoring</li>
            <li><strong>Leaderboards</strong> track your progress and compare with other players</li>
            <li><strong>Play at your own pace</strong> during each 24-hour window</li>
          </ul>
            </div>
        <form method="post" action="/onboarding">
          <button type="submit" class="ta-btn ta-btn-primary" style="font-size:18px;padding:14px 32px;">Get Started</button>
        </form>
        </main>
      ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load onboarding');
  }
});

app.post('/onboarding', requireAuth, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    await pool.query('UPDATE players SET onboarding_complete = true WHERE email = $1', [email]);
    // Check if they need to set credentials
    const creds = await pool.query('SELECT username, password_set_at FROM players WHERE email=$1', [email]);
    const p = creds.rows[0] || {};
    if (!p.username || !p.password_set_at) {
      return res.redirect('/account/credentials');
    }
    res.redirect('/');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to complete onboarding');
  }
});

// Account credentials: set username and password (first-time prompt)
app.get('/account/credentials', requireAuth, async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const r = await pool.query('SELECT username, password_set_at FROM players WHERE email=$1', [email]);
    const havePw = r.rows.length && !!r.rows[0].password_set_at;
    const uname = r.rows.length ? (r.rows[0].username || '') : '';
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Set your account', false)}
      <body class="ta-body">
      ${header}
      <main class="ta-main ta-container" style="max-width:720px; margin:0 auto; padding:24px;">
        <h1 class="ta-page-title">Set your username and password</h1>
        <p style="opacity:0.9;margin-bottom:24px;font-size:16px;">To complete your account setup, please choose a username and password. Your username will appear on leaderboards.</p>
        <form method="post" action="/account/credentials" style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:24px;">
          <div style="margin-bottom:20px;">
            <label style="display:block;margin-bottom:8px;font-weight:600;color:#ffd700;">Username *</label>
            <input name="username" value="${(uname || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;')}" placeholder="letters, numbers, underscore" required style="width:100%;max-width:400px;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:16px;" />
            <div style="opacity:.8;font-size:.9em;margin-top:4px;">3–20 characters, letters/numbers/underscore only. This will appear on leaderboards.</div>
          </div>
          <div style="margin-bottom:24px;">
            <label style="display:block;margin-bottom:8px;font-weight:600;color:#ffd700;">Password *</label>
            <input type="password" name="password" ${havePw ? '' : 'required'} minlength="8" style="width:100%;max-width:400px;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:16px;" />
            <div style="opacity:.8;font-size:.9em;margin-top:4px;">Minimum 8 characters</div>
          </div>
          <button type="submit" class="ta-btn ta-btn-primary" style="font-size:16px;padding:12px 24px;">Complete Setup</button>
        </form>
      </main>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load credentials');
  }
});

function isValidUsername(u){ return /^[A-Za-z0-9_]{3,20}$/.test(String(u||'')); }

app.post('/account/credentials', requireAuth, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const username = String(req.body.username || '').trim();
    const pw = String(req.body.password || '');
    
    // Check if user already has a password
    const existingCheck = await pool.query('SELECT password_set_at FROM players WHERE email=$1', [email]);
    const hasExistingPassword = existingCheck.rows.length && !!existingCheck.rows[0].password_set_at;
    
    if (!isValidUsername(username)) {
      const header = await renderHeader(req);
      return res.status(400).send(`
        ${renderHead('Setup Error', false)}
        <body class="ta-body" style="padding:24px;">
        ${header}
        <main class="ta-main ta-container" style="max-width:720px; margin:0 auto;">
          <h1 class="ta-page-title" style="color:#d32f2f;">Invalid Username</h1>
          <p style="margin-bottom:24px;">Username must be 3-20 characters and contain only letters, numbers, and underscores.</p>
          <a href="/account/credentials" class="ta-btn ta-btn-primary">Try Again</a>
        </main>
        ${renderFooter(req)}
        </body></html>
      `);
    }
    
    const taken = await pool.query('SELECT 1 FROM players WHERE lower(username)=lower($1) AND email<>$2 LIMIT 1', [username, email]);
    if (taken.rows.length) {
      const header = await renderHeader(req);
      return res.status(400).send(`
        ${renderHead('Setup Error', false)}
        <body class="ta-body" style="padding:24px;">
        ${header}
        <main class="ta-main ta-container" style="max-width:720px; margin:0 auto;">
          <h1 class="ta-page-title" style="color:#d32f2f;">Username Already Taken</h1>
          <p style="margin-bottom:24px;">That username is already in use. Please choose a different one.</p>
          <a href="/account/credentials" class="ta-btn ta-btn-primary">Try Again</a>
        </main>
        ${renderFooter(req)}
        </body></html>
      `);
    }
    
    // If they don't have a password yet, require one
    if (!hasExistingPassword && !pw) {
      const header = await renderHeader(req);
      return res.status(400).send(`
        ${renderHead('Setup Error', false)}
        <body class="ta-body" style="padding:24px;">
        ${header}
        <main class="ta-main ta-container" style="max-width:720px; margin:0 auto;">
          <h1 class="ta-page-title" style="color:#d32f2f;">Password Required</h1>
          <p style="margin-bottom:24px;">Please enter a password to complete your account setup.</p>
          <a href="/account/credentials" class="ta-btn ta-btn-primary">Try Again</a>
        </main>
        ${renderFooter(req)}
        </body></html>
      `);
    }
    
    if (pw) {
      if (pw.length < 8 || pw.length > 200) {
        const header = await renderHeader(req);
        return res.status(400).send(`
          ${renderHead('Setup Error', false)}
          <body class="ta-body" style="padding:24px;">
          ${header}
          <main class="ta-main ta-container" style="max-width:720px; margin:0 auto;">
            <h1 class="ta-page-title" style="color:#d32f2f;">Invalid Password</h1>
            <p style="margin-bottom:24px;">Password must be between 8 and 200 characters.</p>
            <a href="/account/credentials" class="ta-btn ta-btn-primary">Try Again</a>
          </main>
          ${renderFooter(req)}
          </body></html>
        `);
      }
      const hash = await hashPassword(pw);
      await pool.query('UPDATE players SET username=$1, password_hash=$2, password_set_at=NOW() WHERE email=$3', [username, hash, email]);
    } else {
      // Only update username if they already have a password (changing username only)
      await pool.query('UPDATE players SET username=$1 WHERE email=$2', [username, email]);
    }
    res.redirect('/calendar');
  } catch (e) {
    console.error('Credentials save error:', e);
    const header = await renderHeader(req);
    res.status(500).send(`
      ${renderHead('Setup Error', false)}
      <body class="ta-body" style="padding:24px;">
      ${header}
      <main class="ta-main ta-container" style="max-width:720px; margin:0 auto;">
        <h1 class="ta-page-title" style="color:#d32f2f;">Setup Failed</h1>
        <p style="margin-bottom:24px;">We encountered an error while saving your credentials. Please try again.</p>
        <a href="/account/credentials" class="ta-btn ta-btn-primary">Try Again</a>
      </main>
      ${renderFooter(req)}
      </body></html>
    `);
  }
});

// Quiz History - view all quiz attempts
app.get('/account/history', requireAuth, async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const quizAttempts = (await pool.query(`
      SELECT 
        q.id,
        q.title,
        q.unlock_at,
        q.freeze_at,
        q.author,
        COUNT(DISTINCT r.question_id) as questions_answered,
        COUNT(DISTINCT qq.id) as total_questions,
        SUM(CASE WHEN r.override_correct = true OR (r.override_correct IS NULL AND LOWER(TRIM(r.response_text)) = LOWER(TRIM(qq.answer))) THEN 1 ELSE 0 END) as correct_count,
        SUM(r.points) as total_points,
        MIN(r.created_at) as first_response,
        MAX(r.created_at) as last_response
      FROM quizzes q
      LEFT JOIN questions qq ON qq.quiz_id = q.id
      LEFT JOIN responses r ON r.quiz_id = q.id AND r.user_email = $1 AND r.question_id = qq.id
      WHERE EXISTS (SELECT 1 FROM responses r2 WHERE r2.quiz_id = q.id AND r2.user_email = $1)
      GROUP BY q.id, q.title, q.unlock_at, q.freeze_at, q.author
      ORDER BY q.unlock_at DESC
    `, [email])).rows;
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Quiz History • Trivia Advent-ure', true)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container" style="max-width:900px;">
          <h1 class="ta-page-title">Quiz History</h1>
          <p style="margin-bottom:24px;"><a href="/account" class="ta-btn ta-btn-outline">← Back to Account</a></p>
          
          ${quizAttempts.length === 0 ? `
            <div style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:32px;text-align:center;">
              <p style="opacity:0.7;">You haven't taken any quizzes yet.</p>
              <p style="margin-top:16px;"><a href="/calendar" class="ta-btn ta-btn-primary">Browse Quizzes</a></p>
            </div>
          ` : `
            <div style="display:flex;flex-direction:column;gap:16px;">
              ${quizAttempts.map(q => {
                const score = q.total_questions > 0 ? Math.round((q.correct_count / q.total_questions) * 100) : 0;
                const unlockDate = q.unlock_at ? new Date(q.unlock_at).toLocaleDateString() : '';
                const isComplete = q.questions_answered === q.total_questions;
                const isFrozen = q.freeze_at ? new Date(q.freeze_at) < new Date() : false;
                return `
                  <div style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:20px;">
                    <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:12px;">
                      <div style="flex:1;">
                        <h3 style="margin:0 0 8px 0;color:#ffd700;">
                          <a href="/quiz/${q.id}" class="ta-btn ta-btn-small" style="color:#111;text-decoration:none;">${q.title || 'Untitled Quiz'}</a>
                        </h3>
                        <div style="font-size:14px;opacity:0.7;margin-bottom:4px;">${unlockDate}${q.author ? ` • ${q.author}` : ''}</div>
                        <div style="font-size:14px;opacity:0.7;">
                          ${q.questions_answered}/${q.total_questions} questions answered
                          ${isComplete ? ' • Complete' : isFrozen ? ' • Quiz closed' : ' • In progress'}
                        </div>
                      </div>
                      <div style="text-align:right;margin-left:16px;">
                        <div style="font-size:28px;font-weight:bold;color:#ffd700;">${score}%</div>
                        <div style="font-size:12px;opacity:0.7;">${q.total_points || 0} pts</div>
                      </div>
                    </div>
                    <div style="margin-top:12px;">
                      <a href="/quiz/${q.id}" class="ta-btn ta-btn-small">View Quiz</a>
                    </div>
                  </div>
                `;
              }).join('')}
            </div>
          `}
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error('Error loading quiz history:', e);
    res.status(500).send('Failed to load quiz history');
  }
});
// Data Export
app.get('/account/export', requireAuth, async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const format = String(req.query.format || '').toLowerCase();
    
    // If no format specified, show selection page
    if (!format || (format !== 'csv' && format !== 'json')) {
      const header = await renderHeader(req);
      res.type('html').send(`
        ${renderHead('Export Data • Trivia Advent-ure', true)}
        <body class="ta-body">
          ${header}
          <main class="ta-main ta-container" style="max-width:720px;">
            <h1 class="ta-page-title">Export Your Data</h1>
            <p style="margin-bottom:24px;"><a href="/account" class="ta-btn ta-btn-outline">← Back to Account</a></p>
            
            <div style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:24px;">
              <p style="margin-bottom:24px;">Download all your quiz data, including responses, scores, and quiz history.</p>
              
              <div style="display:flex;gap:16px;flex-wrap:wrap;">
                <a href="/account/export?format=json" class="ta-btn ta-btn-primary" style="flex:1;min-width:200px;text-align:center;">
                  Download as JSON
                </a>
                <a href="/account/export?format=csv" class="ta-btn ta-btn-primary" style="flex:1;min-width:200px;text-align:center;">
                  Download as CSV
                </a>
              </div>
              
              <div style="margin-top:24px;padding-top:24px;border-top:1px solid #333;">
                <h3 style="margin-top:0;color:#ffd700;">What's included:</h3>
                <ul style="opacity:0.9;">
                  <li>All quiz attempts with scores</li>
                  <li>All question responses</li>
                  <li>Points earned</li>
                  <li>Quiz dates and metadata</li>
                </ul>
              </div>
            </div>
          </main>
          ${renderFooter(req)}
        </body></html>
      `);
      return;
    }
    
    // Get all quiz attempts
    const quizAttempts = (await pool.query(`
      SELECT 
        q.id,
        q.title,
        q.unlock_at,
        q.freeze_at,
        q.author,
        COUNT(DISTINCT r.question_id) as questions_answered,
        COUNT(DISTINCT qq.id) as total_questions,
        SUM(CASE WHEN r.override_correct = true OR (r.override_correct IS NULL AND LOWER(TRIM(r.response_text)) = LOWER(TRIM(qq.answer))) THEN 1 ELSE 0 END) as correct_count,
        SUM(r.points) as total_points
      FROM quizzes q
      LEFT JOIN questions qq ON qq.quiz_id = q.id
      LEFT JOIN responses r ON r.quiz_id = q.id AND r.user_email = $1 AND r.question_id = qq.id
      WHERE EXISTS (SELECT 1 FROM responses r2 WHERE r2.quiz_id = q.id AND r2.user_email = $1)
      GROUP BY q.id, q.title, q.unlock_at, q.freeze_at, q.author
      ORDER BY q.unlock_at DESC
    `, [email])).rows;
    
    // Get all responses
    const responses = (await pool.query(`
      SELECT 
        r.id,
        r.quiz_id,
        r.question_id,
        r.response_text,
        r.points,
        r.locked,
        r.override_correct,
        r.created_at,
        q.title as quiz_title,
        qq.number as question_number,
        qq.text as question_text,
        qq.answer as correct_answer,
        qq.category
      FROM responses r
      JOIN quizzes q ON q.id = r.quiz_id
      JOIN questions qq ON qq.id = r.question_id
      WHERE r.user_email = $1
      ORDER BY q.unlock_at DESC, qq.number ASC
    `, [email])).rows;
    
    if (format === 'csv') {
      // CSV export
      const csvRows = ['Quiz Title,Quiz Date,Question Number,Question Text,Your Answer,Correct Answer,Points,Category,Answered At'];
      for (const r of responses) {
        const row = [
          `"${(r.quiz_title || '').replace(/"/g, '""')}"`,
          r.quiz_id ? new Date(quizAttempts.find(q => q.id === r.quiz_id)?.unlock_at || '').toLocaleDateString() : '',
          r.question_number,
          `"${(r.question_text || '').replace(/"/g, '""')}"`,
          `"${(r.response_text || '').replace(/"/g, '""')}"`,
          `"${(r.correct_answer || '').replace(/"/g, '""')}"`,
          r.points || 0,
          `"${(r.category || '').replace(/"/g, '""')}"`,
          r.created_at ? new Date(r.created_at).toISOString() : ''
        ];
        csvRows.push(row.join(','));
      }
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="trivia-adventure-export-${Date.now()}.csv"`);
      res.send(csvRows.join('\n'));
    } else {
      // JSON export
      const exportData = {
        exported_at: new Date().toISOString(),
        email: email,
        quiz_attempts: quizAttempts.map(q => ({
          quiz_id: q.id,
          title: q.title,
          unlock_at: q.unlock_at,
          author: q.author,
          questions_answered: parseInt(q.questions_answered) || 0,
          total_questions: parseInt(q.total_questions) || 0,
          correct_count: parseInt(q.correct_count) || 0,
          score_percent: q.total_questions > 0 ? Math.round((q.correct_count / q.total_questions) * 100) : 0,
          total_points: parseFloat(q.total_points) || 0
        })),
        responses: responses.map(r => ({
          quiz_id: r.quiz_id,
          quiz_title: r.quiz_title,
          question_number: r.question_number,
          question_text: r.question_text,
          your_answer: r.response_text,
          correct_answer: r.correct_answer,
          points: parseFloat(r.points) || 0,
          category: r.category,
          answered_at: r.created_at
        }))
      };
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="trivia-adventure-export-${Date.now()}.json"`);
      res.send(JSON.stringify(exportData, null, 2));
    }
  } catch (e) {
    console.error('Error exporting data:', e);
    res.status(500).send('Failed to export data');
  }
});
// Email Preferences
app.get('/account/preferences', requireAuth, async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const player = (await pool.query('SELECT email_notifications_enabled, email_announcements FROM players WHERE email=$1', [email])).rows[0];
    const notificationsEnabled = player ? (player.email_notifications_enabled !== false) : true;
    const announcements = player ? (player.email_announcements !== false) : true;
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Email Preferences • Trivia Advent-ure', true)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container" style="max-width:720px;">
          <h1 class="ta-page-title">Email Preferences</h1>
          <p style="margin-bottom:24px;"><a href="/account" class="ta-btn ta-btn-outline">← Back to Account</a></p>
          
          <form method="post" action="/account/preferences" style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:24px;">
            <div style="margin-bottom:24px;">
              <label style="display:flex;align-items:center;gap:12px;cursor:pointer;padding:12px;border-radius:6px;background:rgba(255,255,255,0.02);">
                <input type="checkbox" name="email_notifications_enabled" value="1" ${notificationsEnabled ? 'checked' : ''} style="width:20px;height:20px;cursor:pointer;" />
                <div>
                  <div style="font-weight:bold;margin-bottom:4px;">Enable All Email Notifications</div>
                  <div style="font-size:14px;opacity:0.7;">Master toggle for all email notifications</div>
                </div>
              </label>
            </div>
            
            <div style="margin-top:32px;padding-top:24px;border-top:1px solid #333;">
              <h3 style="margin:0 0 16px 0;color:#ffd700;font-size:18px;">Notification Types</h3>
              <div style="display:flex;flex-direction:column;gap:16px;">
                <label style="display:flex;align-items:center;gap:12px;cursor:pointer;padding:12px;border-radius:6px;background:rgba(255,255,255,0.02);">
                  <input type="checkbox" name="email_announcements" value="1" ${announcements ? 'checked' : ''} style="width:20px;height:20px;cursor:pointer;" />
                  <div>
                    <div style="font-weight:bold;margin-bottom:4px;">Announcements</div>
                    <div style="font-size:14px;opacity:0.7;">Receive important announcements and updates from administrators</div>
                  </div>
                </label>
              </div>
            </div>
            
            <div style="margin-top:24px;">
              <button type="submit" class="ta-btn ta-btn-primary">Save Preferences</button>
              <a href="/account" class="ta-btn ta-btn-outline" style="margin-left:8px;">Cancel</a>
            </div>
          </form>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error('Error loading preferences:', e);
    res.status(500).send('Failed to load preferences');
  }
});
app.post('/account/preferences', requireAuth, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const enabled = req.body.email_notifications_enabled === '1';
    const announcements = req.body.email_announcements === '1';
    await pool.query(
      'UPDATE players SET email_notifications_enabled=$1, email_announcements=$2 WHERE email=$3',
      [enabled, announcements, email]
    );
    res.redirect('/account?msg=Preferences saved');
  } catch (e) {
    console.error('Error saving preferences:', e);
    res.status(500).send('Failed to save preferences');
  }
});

// Account Deletion
app.get('/account/delete', requireAuth, async (req, res) => {
  const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead('Delete Account • Trivia Advent-ure', true)}
    <body class="ta-body">
      ${header}
      <main class="ta-main ta-container" style="max-width:720px;">
        <h1 class="ta-page-title">Delete Account</h1>
        <p style="margin-bottom:24px;"><a href="/account" class="ta-btn ta-btn-outline">← Back to Account</a></p>
        
        <div style="background:#1a1a1a;border:2px solid #d32f2f;border-radius:8px;padding:24px;">
          <h2 style="color:#d32f2f;margin-top:0;">Warning: This action cannot be undone</h2>
          <p style="margin-bottom:16px;">Deleting your account will permanently remove:</p>
          <ul style="margin-bottom:24px;padding-left:24px;">
            <li>All your quiz responses and scores</li>
            <li>Your account information and preferences</li>
            <li>All associated data</li>
          </ul>
          
          <form method="post" action="/account/delete" onsubmit="return confirm('Are you absolutely sure you want to delete your account? This cannot be undone!');">
            <div style="margin-bottom:16px;">
              <label style="display:block;margin-bottom:8px;font-weight:bold;">Type DELETE to confirm:</label>
              <input type="text" name="confirm" required style="width:100%;padding:10px;border:1px solid #555;border-radius:6px;background:#0a0a0a;color:#ffd700;font-size:16px;" placeholder="DELETE" />
            </div>
            <div>
              <button type="submit" class="ta-btn" style="background:#d32f2f;color:#fff;border-color:#d32f2f;">Delete My Account</button>
              <a href="/account" class="ta-btn" style="margin-left:8px;">Cancel</a>
            </div>
          </form>
        </div>
      </main>
      ${renderFooter(req)}
    </body></html>
  `);
});

app.post('/account/delete', requireAuth, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    if (String(req.body.confirm || '').trim() !== 'DELETE') {
      return res.status(400).send('Confirmation text must be exactly "DELETE"');
    }
    
    const email = (req.session.user.email || '').toLowerCase();
    
    // Delete responses first (foreign key constraint)
    await pool.query('DELETE FROM responses WHERE user_email=$1', [email]);
    // Delete player
    await pool.query('DELETE FROM players WHERE email=$1', [email]);
    // Also remove from admins if they were an admin
    await pool.query('DELETE FROM admins WHERE email=$1', [email]);
    
    // Destroy session
    req.session.destroy((err) => {
      if (err) {
        console.error('Error destroying session:', err);
      }
      res.redirect('/?msg=Account deleted');
    });
  } catch (e) {
    console.error('Error deleting account:', e);
    res.status(500).send('Failed to delete account');
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
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
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
    
    // Get all tokens matching this token string (should only be one, but check for duplicates)
    const { rows } = await pool.query('SELECT * FROM magic_tokens WHERE token = $1 ORDER BY created_at DESC', [token]);
    
    if (rows.length === 0) {
      console.log('[auth/magic] Token not found:', token);
      return res.status(400).send('Invalid token');
    }
    
    // If multiple tokens exist, log warning and use the most recent unused one
    if (rows.length > 1) {
      console.warn('[auth/magic] Multiple tokens found for same token string:', token, 'Count:', rows.length);
    }
    
    // Find the first unused, non-expired token
    const now = new Date();
    let row = null;
    for (const r of rows) {
      if (!r.used && new Date(r.expires_at) >= now) {
        row = r;
        break;
      }
    }
    
    if (!row) {
      // Check if all are used or expired
      const allUsed = rows.every(r => r.used);
      const allExpired = rows.every(r => new Date(r.expires_at) < now);
      console.log('[auth/magic] Token issue - All used:', allUsed, 'All expired:', allExpired, 'Email:', rows[0]?.email);
      
      if (allUsed) return res.status(400).send('Token already used');
      if (allExpired) return res.status(400).send('Token expired');
      return res.status(400).send('Invalid token');
    }
    
    // Mark as used using the specific row's ID or token (atomic update)
    const updateResult = await pool.query(
      'UPDATE magic_tokens SET used = true WHERE token = $1 AND used = false AND expires_at > $2 RETURNING email',
      [token, now]
    );
    
    if (updateResult.rows.length === 0) {
      console.log('[auth/magic] Failed to mark token as used - may have been used concurrently:', token);
      return res.status(400).send('Token already used or expired');
    }
    
    const email = updateResult.rows[0].email;
    req.session.user = { email };
    
    // Check onboarding and credentials
    const orow = await pool.query('SELECT onboarding_complete, username, password_set_at FROM players WHERE email = $1', [email]);
    const p = orow.rows[0] || {};
    const onboardingDone = p.onboarding_complete === true;
    if (!onboardingDone) return res.redirect('/onboarding');
    if (!p.username || !p.password_set_at) return res.redirect('/account/credentials');
    res.redirect('/');
  } catch (e) {
    console.error('[auth/magic] Error:', e);
    res.status(500).send('Auth failed');
  }
});

// Shared function to process Ko-fi donation webhook
async function processKofiDonation(body, skipSecretCheck = false) {
  // Ko-fi sends data as a JSON string in body.data, so parse it if needed
  let parsedData = body.data;
  if (typeof parsedData === 'string') {
    try {
      parsedData = JSON.parse(parsedData);
    } catch (e) {
      console.error('[Ko-fi] Failed to parse data JSON:', e);
      return { success: false, error: 'Invalid data format' };
    }
  }
  
  // Support multiple payload shapes
  // Ko-fi format: data.type, data.email, data.timestamp
  // Also support direct body.type, body.email, etc.
  const type = (parsedData?.type || body.type || body.data?.type || '').toLowerCase();
  const emailRaw = (parsedData?.email || body.email || body.data?.email || '').trim();
  const createdAtStr = parsedData?.timestamp || body.created_at || body.timestamp || body.data?.created_at || body.data?.timestamp;
  
  console.log('[Ko-fi] Parsed data - type:', type, 'email:', emailRaw, 'timestamp:', createdAtStr);
  
  if (!emailRaw) {
    return { success: false, error: 'No email' };
  }
  
  // Validate and normalize email
  const email = emailRaw.toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    console.error('[Ko-fi] Invalid email format:', email);
    return { success: false, error: 'Invalid email format' };
  }
  if (type !== 'donation') {
    return { success: false, error: 'Ignored', ignored: true };
  }

  const createdAt = createdAtStr ? new Date(createdAtStr) : new Date();
  // Prefer UTC cutoff env if provided
  const cutoffUtcEnv = process.env.KOFI_CUTOFF_UTC || '';
  const cutoffDate = cutoffUtcEnv ? new Date(cutoffUtcEnv) : new Date('2025-11-01T04:00:00Z');
  if (!(createdAt >= cutoffDate)) {
    return { success: false, error: 'Before cutoff', beforeCutoff: true };
  }

  await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [email]);
  console.log('[Ko-fi] Player record created/updated for:', email);

  // Optionally auto-send magic link
  const token = crypto.randomBytes(24).toString('base64url');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
  await pool.query('INSERT INTO magic_tokens(token,email,expires_at,used) VALUES($1,$2,$3,false)', [token, email, expiresAt]);
  console.log('[Ko-fi] Magic token created for:', email);
  
  const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
  try {
    await sendMagicLink(email, token, linkUrl);
    console.log('[Ko-fi] Magic link email sent successfully to:', email);
  } catch (err) {
    console.error('[Ko-fi] Send mail failed for', email, ':', err.message);
    console.error('[Ko-fi] Full error:', err);
  }

  return { success: true, email, token, linkUrl };
}

// --- Ko-fi webhook ---
// GET handler for testing/verification
app.get('/webhooks/kofi', (req, res) => {
  res.type('html').send(`
    <html>
      <head><title>Ko-fi Webhook Endpoint</title></head>
      <body style="font-family: sans-serif; padding: 24px; max-width: 600px; margin: 0 auto;">
        <h1>Ko-fi Webhook Endpoint</h1>
        <p>This endpoint is configured to receive POST requests from Ko-fi.</p>
        <p><strong>Status:</strong> ✅ Active</p>
        <p><strong>Method:</strong> POST only</p>
        <p><strong>URL:</strong> <code>https://triviaadventure.org/webhooks/kofi</code></p>
        ${WEBHOOK_SHARED_SECRET ? '<p><strong>Secret:</strong> Configured (required)</p>' : '<p><strong>Secret:</strong> Not configured (optional)</p>'}
        <hr>
        <p><small>This endpoint will process donation webhooks from Ko-fi and automatically grant access to players.</small></p>
      </body>
    </html>
  `);
});

// POST handler for actual webhook
app.post('/webhooks/kofi', express.json(), async (req, res) => {
  try {
    console.log('[Ko-fi Webhook] Received request');
    console.log('[Ko-fi Webhook] Headers:', JSON.stringify(req.headers, null, 2));
    console.log('[Ko-fi Webhook] Body:', JSON.stringify(req.body, null, 2));
    
    if (WEBHOOK_SHARED_SECRET) {
      const provided = req.headers['x-kofi-secret'] || req.query.secret || '';
      if (provided !== WEBHOOK_SHARED_SECRET) {
        console.log('[Ko-fi Webhook] Bad secret provided');
        return res.status(401).send('Bad secret');
      }
    }
    const body = req.body || {};
    
    // Ensure we have a body to process
    if (!body || (typeof body === 'object' && Object.keys(body).length === 0)) {
      console.log('[Ko-fi Webhook] Empty body received');
      return res.status(400).send('Empty body');
    }
    
    const result = await processKofiDonation(body);
    
    if (!result.success) {
      console.log('[Ko-fi Webhook] Processing failed:', result.error);
      if (result.ignored) return res.status(204).send('Ignored');
      if (result.beforeCutoff) return res.status(204).send('Before cutoff');
      return res.status(400).send(result.error);
    }
    
    console.log('[Ko-fi Webhook] Successfully processed donation for:', result.email);
    res.status(200).send('OK');
  } catch (e) {
    console.error('[Ko-fi Webhook] Error:', e);
    console.error('[Ko-fi Webhook] Stack:', e.stack);
    // Always respond OK to avoid retry storms from Ko-fi
    // Errors are logged above for debugging
    res.status(200).send('OK');
  }
});

// --- Health check ---
app.get('/health', async (_req, res) => {
  try {
    // Quick DB check
    await pool.query('SELECT 1');
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ status: 'error', error: e.message });
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
app.get('/public', async (req, res) => {
  // Get some stats to make it more enticing
  let stats = { totalQuizzes: 0, totalPlayers: 0 };
  try {
    const quizCount = await pool.query('SELECT COUNT(*) as count FROM quizzes');
    stats.totalQuizzes = parseInt(quizCount.rows[0]?.count || 0);
    const playerCount = await pool.query('SELECT COUNT(*) as count FROM players');
    stats.totalPlayers = parseInt(playerCount.rows[0]?.count || 0);
  } catch (e) {
    console.error('Error fetching stats:', e);
  }
  
  const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead('Trivia Advent-ure', true)}
    <body class="ta-body">
      ${header}
      <main class="ta-main ta-container" style="max-width:900px;">
        <div style="text-align:center;margin:32px 0 48px 0;">
          <h1 class="ta-page-title" style="font-size:48px;margin-bottom:16px;background:linear-gradient(90deg, #FFA726 0%, #FFC46B 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">Trivia Advent-ure Calendar</h1>
          <p style="font-size:20px;line-height:1.6;opacity:0.9;max-width:700px;margin:0 auto 24px auto;">
            Join the ultimate December trivia challenge! 48 quizzes unlock twice daily from December 1–24. 
            Test your knowledge, compete on leaderboards, and have fun with friends.
          </p>
          ${stats.totalPlayers > 0 ? `
          <div style="display:flex;gap:32px;justify-content:center;margin:24px 0;flex-wrap:wrap;">
            <div style="text-align:center;">
              <div style="font-size:32px;font-weight:bold;color:#ffd700;">${stats.totalQuizzes}</div>
              <div style="font-size:14px;opacity:0.7;">Quizzes Available</div>
            </div>
            <div style="text-align:center;">
              <div style="font-size:32px;font-weight:bold;color:#ffd700;">${stats.totalPlayers}</div>
              <div style="font-size:14px;opacity:0.7;">Players</div>
            </div>
          </div>
          ` : ''}
        </div>
        
        <div style="display:flex;gap:16px;justify-content:center;margin:32px 0;flex-wrap:wrap;">
          <a class="ta-btn ta-btn-primary" href="/calendar" style="font-size:18px;padding:14px 28px;">View Calendar</a>
          <a class="ta-btn ta-btn-primary" href="https://ko-fi.com/triviaadvent" target="_blank" rel="noopener noreferrer" style="font-size:18px;padding:14px 28px;">Get Started</a>
          <a class="ta-btn ta-btn-outline" href="/login" style="font-size:18px;padding:14px 28px;">Login to Play</a>
        </div>
        
        <div style="background:linear-gradient(135deg, rgba(255,167,38,0.1) 0%, rgba(255,196,107,0.05) 100%);border:1px solid rgba(255,167,38,0.3);border-radius:12px;padding:32px;margin:48px 0;">
          <h2 style="color:#ffd700;margin:0 0 20px 0;font-size:24px;text-align:center;">Why Join Trivia Advent-ure?</h2>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:24px;margin-top:24px;">
            <div style="text-align:center;">
              <div style="font-size:36px;margin-bottom:8px;">🎯</div>
              <h3 style="color:#ffd700;margin:0 0 8px 0;font-size:18px;">Daily Challenges</h3>
              <p style="margin:0;opacity:0.8;line-height:1.5;">48 unique quizzes unlock at midnight and noon ET. Play at your own pace!</p>
            </div>
            <div style="text-align:center;">
              <div style="font-size:36px;margin-bottom:8px;">🏆</div>
              <h3 style="color:#ffd700;margin:0 0 8px 0;font-size:18px;">Compete & Climb</h3>
              <p style="margin:0;opacity:0.8;line-height:1.5;">Per-quiz leaderboard freezes after 24 hours. Overall standings update continuously.</p>
            </div>
            <div style="text-align:center;">
              <div style="font-size:36px;margin-bottom:8px;">📊</div>
              <h3 style="color:#ffd700;margin:0 0 8px 0;font-size:18px;">Instant Feedback</h3>
              <p style="margin:0;opacity:0.8;line-height:1.5;">Get immediate recaps with answers and points after each quiz.</p>
            </div>
            <div style="text-align:center;">
              <div style="font-size:36px;margin-bottom:8px;">👥</div>
              <h3 style="color:#ffd700;margin:0 0 8px 0;font-size:18px;">Join the Community</h3>
              <p style="margin:0;opacity:0.8;line-height:1.5;">Play alongside friends and trivia enthusiasts. See how you stack up!</p>
            </div>
          </div>
        </div>
        
        <div style="background:#1a1a1a;border:1px solid #333;border-radius:12px;padding:32px;margin:32px 0;">
          <h3 class="ta-section-title" style="margin-top:0;">How It Works</h3>
          <ul class="ta-list" style="font-size:16px;line-height:1.8;">
            <li><strong>10 questions per quiz</strong> covering a variety of topics and difficulty levels</li>
            <li><strong>Immediate recap</strong> on submit with answers and points</li>
            <li><strong>Per-quiz leaderboard</strong> freezes 24 hours after unlock for fair competition</li>
            <li><strong>Overall standings</strong> keep updating as players complete quizzes throughout December</li>
            <li><strong>Play anytime</strong> during the 24-hour window for each quiz slot</li>
          </ul>
        </div>
        
        <div style="text-align:center;margin:48px 0;padding:32px;background:rgba(255,167,38,0.1);border-radius:12px;border:2px solid rgba(255,167,38,0.3);">
          <h3 style="color:#ffd700;margin:0 0 16px 0;font-size:22px;">Play Trivia, Fuel Impact</h3>
          <p style="margin:0 0 16px 0;opacity:0.9;font-size:16px;line-height:1.6;">
            Trivia Advent-ure is a charitable project. 100% of player contributions are donated to mission-driven partners:
          </p>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px;text-align:left;margin:24px 0;">
            <div style="background:rgba(0,0,0,0.35);border:1px solid rgba(255,255,255,0.15);border-radius:12px;padding:18px;display:flex;flex-direction:column;gap:12px;">
              <a href="https://translifeline.org" target="_blank" rel="noopener noreferrer" style="display:inline-flex;">
                <img src="/img/TL-logo_purple_transparent.png" alt="Trans Lifeline logo" style="width:160px;height:auto;">
              </a>
              <h4 style="margin:0;color:#ffd700;">Trans Lifeline</h4>
              <p style="margin:0;opacity:0.9;line-height:1.5;">A peer-support and microgrants organization serving trans people through community-led care.</p>
            </div>
            <div style="background:rgba(0,0,0,0.35);border:1px solid rgba(255,255,255,0.15);border-radius:12px;padding:18px;display:flex;flex-direction:column;gap:12px;">
              <a href="https://wck.org" target="_blank" rel="noopener noreferrer" style="display:inline-flex;">
                <img src="/img/download.png" alt="World Central Kitchen logo" style="width:160px;height:auto;">
              </a>
              <h4 style="margin:0;color:#ffd700;">World Central Kitchen</h4>
              <p style="margin:0;opacity:0.9;line-height:1.5;">Providing nourishing meals to communities impacted by disasters around the globe.</p>
            </div>
          </div>
          <p style="margin:0 0 24px 0;opacity:0.9;font-size:15px;">
            Every Ko-fi donation helps us deliver funds to these partners and keep the experience running smoothly.
          </p>
          <a href="https://ko-fi.com/triviaadvent" target="_blank" rel="noopener noreferrer" 
             class="ta-btn ta-btn-primary" 
             style="font-size:18px;padding:14px 32px;display:inline-flex;align-items:center;gap:8px;text-decoration:none;">
            <span style="font-size:24px;">☕</span>
            <span>Support on Ko-fi</span>
          </a>
        </div>
        
        <div style="text-align:center;margin-top:48px;">
          <a class="ta-btn ta-btn-primary" href="/calendar" style="font-size:18px;padding:14px 32px;margin-right:12px;">Explore the Calendar</a>
          <a class="ta-btn ta-btn-outline" href="/login" style="font-size:18px;padding:14px 32px;">Get Started</a>
        </div>
      </main>
    ${renderFooter(req)}
    </body></html>
  `);
});
// --- Admin: Calendar occupancy view (AM/PM) ---
app.get('/admin/calendar', requireAdmin, async (req, res) => {
  try {
    const { rows: quizzes } = await pool.query('SELECT id, title, unlock_at FROM quizzes ORDER BY unlock_at ASC, id ASC');
    const bySlot = new Map(); // key: YYYY-MM-DD|AM|PM → array of quizzes
    let baseYear = quizzes.length ? utcToEtParts(new Date(quizzes[0].unlock_at)).y : new Date().getUTCFullYear();
    function slotKey(dParts){
      const day = `${dParts.y}-${String(dParts.m).padStart(2,'0')}-${String(dParts.d).padStart(2,'0')}`;
      const half = dParts.h === 0 ? 'AM' : 'PM';
      return `${day}|${half}`;
    }
    for (const q of quizzes) {
      const p = utcToEtParts(new Date(q.unlock_at));
      baseYear = p.y;
      const key = slotKey(p);
      if (!bySlot.has(key)) bySlot.set(key, []);
      bySlot.get(key).push(q);
    }
    const rows = [];
    for (let d=1; d<=24; d++) {
      const day = `${baseYear}-12-${String(d).padStart(2,'0')}`;
      const amKey = `${day}|AM`;
      const pmKey = `${day}|PM`;
      const am = bySlot.get(amKey) || [];
      const pm = bySlot.get(pmKey) || [];
      rows.push({ day, am, pm });
    }
    function cellHtml(list, day, half){
      if (!list.length) {
        const hh = half === 'AM' ? '00:00' : '12:00';
        const unlock = `${day}T${hh}`;
        return `<div style=\"color:#999;\">Empty</div><div><a class=\"ta-btn-small\" href=\"/admin/writer-submissions?unlock=${unlock}\">Publish here</a></div>`;
      }
      if (list.length === 1) {
        const q = list[0];
        return `<div><a href=\"/admin/quiz/${q.id}\" class=\"ta-btn ta-btn-small\">#${q.id} ${q.title.replace(/</g,'&lt;')}</a></div>`;
      }
      // Conflict
      const links = list.map(q=>`<div><a href=\"/admin/quiz/${q.id}\" class=\"ta-btn ta-btn-small\">#${q.id} ${q.title.replace(/</g,'&lt;')}</a></div>`).join('');
      return `<div style=\"color:#c62828;\"><strong>Conflict (${list.length})</strong></div>${links}`;
    }
    const htmlRows = rows.map(r => `
      <tr>
        <td style=\"padding:6px 4px;\">${r.day}</td>
        <td style=\"padding:6px 4px;\">${cellHtml(r.am, r.day, 'AM')}</td>
        <td style=\"padding:6px 4px;\">${cellHtml(r.pm, r.day, 'PM')}</td>
      </tr>`).join('');
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Admin Calendar', true)}
      <body class="ta-body">
      ${header}
        <main class="ta-main ta-container">
          ${renderBreadcrumb([ADMIN_CRUMB, { label: 'Calendar' }])}
          ${renderAdminNav('calendar')}
          <h1 class="ta-page-title">Calendar Overview</h1>
          <p style="margin:0 0 16px 0;opacity:0.85;">Review daily AM/PM slots, identify conflicts, and jump into quiz details.</p>
          <div style="background:#0e0e0e;border:1px solid rgba(255,255,255,0.08);border-radius:12px;overflow:hidden;">
            <table style="width:100%;border-collapse:collapse;">
              <thead style="background:rgba(255,255,255,0.05);">
                <tr>
                  <th style="padding:10px 12px;text-align:left;">Day</th>
                  <th style="padding:10px 12px;text-align:left;">AM Slot</th>
                  <th style="padding:10px 12px;text-align:left;">PM Slot</th>
                </tr>
              </thead>
          <tbody>${htmlRows}</tbody>
        </table>
          </div>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load admin calendar');
  }
});
app.get('/admin/author-slots', requireAdmin, async (req, res) => {
  try {
    const header = await renderHeader(req);
    const msg = String(req.query.msg || '');
    const { rows: quizzes } = await pool.query('SELECT id, title, unlock_at, author, author_email, author_points_override FROM quizzes ORDER BY unlock_at ASC LIMIT 200');
    const esc = (v) => String(v || '').replace(/&/g, '&amp;').replace(/</g, '&lt;');
    const items = quizzes.map(q => {
      const unlock = q.unlock_at ? new Date(q.unlock_at) : null;
      const dateStr = unlock ? unlock.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true }) : '—';
      const overrideStr = (q.author_points_override !== null && q.author_points_override !== undefined)
        ? formatPoints(q.author_points_override)
        : '';
      return `
        <tr>
          <td style="padding:10px 8px;">${q.id}</td>
          <td style="padding:10px 8px;">${esc(q.title || 'Untitled Quiz')}</td>
          <td style="padding:10px 8px;">${dateStr}</td>
          <td style="padding:10px 8px;">${esc(q.author || '')}</td>
          <td style="padding:10px 8px;">
            <form method="post" action="/admin/quizzes/${q.id}/author-email" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
              <input type="email" name="author_email" value="${esc(q.author_email || '')}" placeholder="name@example.com" style="padding:6px 8px;border-radius:6px;border:1px solid #555;background:#0a0a0a;color:#ffd700;min-width:220px;"/>
              <button type="submit" class="ta-btn ta-btn-primary" style="margin:0;">Save</button>
              ${q.author_email ? `<a href="/admin/quizzes/${q.id}/author-email?clear=1" class="ta-btn ta-btn-outline" style="margin:0;">Clear</a>` : ''}
            </form>
          </td>
          <td style="padding:10px 8px;">
            <form method="post" action="/admin/quizzes/${q.id}/author-average" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
              <input type="text" name="author_points_override" value="${overrideStr}" placeholder="e.g. 42" style="padding:6px 8px;border-radius:6px;border:1px solid #555;background:#0a0a0a;color:#ffd700;min-width:120px;"/>
              <button type="submit" class="ta-btn ta-btn-primary" style="margin:0;">Apply</button>
              ${overrideStr ? `<a href="/admin/quizzes/${q.id}/author-average?clear=1" class="ta-btn ta-btn-outline" style="margin:0;">Clear</a>` : ''}
            </form>
          </td>
        </tr>
      `;
    }).join('');
    res.type('html').send(`
      ${renderHead('Author Assignments • Admin', true)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container" style="max-width:1100px;">
          ${renderBreadcrumb([ADMIN_CRUMB, { label: 'Author Assignments' }])}
          ${renderAdminNav('authors')}
          <h1 class="ta-page-title">Author Assignments</h1>
          ${msg ? `<div style="margin-bottom:20px;padding:12px;border:1px solid #2e7d32;border-radius:6px;background:rgba(46,125,50,0.15);color:#81c784;">${esc(msg)}</div>` : ''}
          <div style="background:#1a1a1a;border:1px solid #333;border-radius:10px;overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;min-width:720px;">
              <thead>
                <tr style="background:#111;">
                  <th style="padding:10px 8px;text-align:left;">Quiz ID</th>
                  <th style="padding:10px 8px;text-align:left;">Title</th>
                  <th style="padding:10px 8px;text-align:left;">Unlock</th>
                  <th style="padding:10px 8px;text-align:left;">Author</th>
                  <th style="padding:10px 8px;text-align:left;">Author Email</th>
                  <th style="padding:10px 8px;text-align:left;">Author Points Override</th>
                </tr>
              </thead>
              <tbody>
                ${items || '<tr><td colspan="6" style="padding:16px;text-align:center;opacity:0.8;">No quizzes found.</td></tr>'}
              </tbody>
            </table>
          </div>
          <p style="margin-top:24px;font-size:14px;opacity:0.75;">Overrides replace the automatic average and immediately reflect on leaderboards.</p>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load author assignments');
  }
});

app.get('/admin/quizzes/:id/author-email', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send('Invalid quiz id');
    const clear = String(req.query.clear || '').toLowerCase() === '1';
    const value = clear ? null : String(req.query.author_email || '').trim().toLowerCase();
    await pool.query('UPDATE quizzes SET author_email=$1 WHERE id=$2', [value ? value : null, id]);
    res.redirect('/admin/author-slots?msg=Author%20email%20updated');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to update author email');
  }
});

app.post('/admin/quizzes/:id/author-email', requireAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send('Invalid quiz id');
    const email = String(req.body.author_email || '').trim().toLowerCase();
    const value = email ? email : null;
    await pool.query('UPDATE quizzes SET author_email=$1 WHERE id=$2', [value, id]);
    res.redirect('/admin/author-slots?msg=Author%20email%20updated');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to update author email');
  }
});

app.get('/admin/quizzes/:id/author-average', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send('Invalid quiz id');
    const clear = String(req.query.clear || '').toLowerCase() === '1';
    if (!clear) return res.status(400).send('Specify clear=1 to remove override');
    await pool.query('UPDATE quizzes SET author_points_override=NULL WHERE id=$1', [id]);
    res.redirect('/admin/author-slots?msg=Author%20override%20cleared');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to clear override');
  }
});

app.post('/admin/quizzes/:id/author-average', requireAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send('Invalid quiz id');
    const raw = String(req.body.author_points_override || '').trim();
    let value = null;
    if (raw !== '') {
      const parsed = Number(raw);
      if (!Number.isFinite(parsed)) return res.status(400).send('Invalid points override');
      value = parsed;
    }
    await pool.query('UPDATE quizzes SET author_points_override=$1 WHERE id=$2', [value, id]);
    res.redirect('/admin/author-slots?msg=Author%20override%20saved');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to update override');
  }
});
// Player landing (logged-in non-admin)
app.get('/player', requireAuth, async (req, res) => {
  const adminEmail = getAdminEmail();
  const email = (req.session.user.email || '').toLowerCase();
  if (email === adminEmail) return res.redirect('/admin');
  const isAdmin = await isAdminUser(req);
  
  // Check if user needs to complete setup (unless admin)
  if (!isAdmin) {
    const setupCheck = await pool.query('SELECT onboarding_complete, username, password_set_at FROM players WHERE email=$1', [email]);
    if (setupCheck.rows.length) {
      const p = setupCheck.rows[0];
      if (!p.onboarding_complete) return res.redirect('/onboarding');
      if (!p.username || !p.password_set_at) return res.redirect('/account/credentials');
    }
  }
  
  let needsPassword = false;
  let displayName = '';
  try {
    const pr = await pool.query('SELECT username, password_set_at FROM players WHERE email=$1', [email]);
    needsPassword = pr.rows.length && !pr.rows[0].password_set_at;
    displayName = (pr.rows.length && pr.rows[0].username) ? pr.rows[0].username : email;
  } catch {}
  
  // Get player stats
  let stats = { totalQuizzes: 0, totalQuestions: 0, correctAnswers: 0, totalPoints: 0, recentQuizzes: [] };
  try {
    const statsResult = await pool.query(`
      SELECT 
        COUNT(DISTINCT r.quiz_id) as total_quizzes,
        COUNT(DISTINCT r.question_id) as total_questions,
        SUM(CASE WHEN r.override_correct = true OR (r.override_correct IS NULL AND LOWER(TRIM(r.response_text)) = LOWER(TRIM(qq.answer))) THEN 1 ELSE 0 END) as correct_answers,
        COALESCE(SUM(r.points), 0) as total_points
      FROM responses r
      JOIN questions qq ON qq.id = r.question_id
      WHERE r.user_email = $1
    `, [email]);
    if (statsResult.rows.length) {
      stats.totalQuizzes = parseInt(statsResult.rows[0].total_quizzes) || 0;
      stats.totalQuestions = parseInt(statsResult.rows[0].total_questions) || 0;
      stats.correctAnswers = parseInt(statsResult.rows[0].correct_answers) || 0;
      stats.totalPoints = parseFloat(statsResult.rows[0].total_points) || 0;
    }
    
    // Get recent quiz attempts
    const recentResult = await pool.query(`
      SELECT DISTINCT
        q.id,
        q.title,
        q.unlock_at,
        COUNT(DISTINCT r.question_id) as questions_answered,
        COUNT(DISTINCT qq.id) as total_questions,
        SUM(CASE WHEN r.override_correct = true OR (r.override_correct IS NULL AND LOWER(TRIM(r.response_text)) = LOWER(TRIM(qq.answer))) THEN 1 ELSE 0 END) as correct_count,
        SUM(r.points) as points
      FROM quizzes q
      LEFT JOIN questions qq ON qq.quiz_id = q.id
      LEFT JOIN responses r ON r.quiz_id = q.id AND r.user_email = $1 AND r.question_id = qq.id
      WHERE EXISTS (SELECT 1 FROM responses r2 WHERE r2.quiz_id = q.id AND r2.user_email = $1)
      GROUP BY q.id, q.title, q.unlock_at
      ORDER BY q.unlock_at DESC
      LIMIT 5
    `, [email]);
    stats.recentQuizzes = recentResult.rows;
  } catch (e) {
    console.error('Error fetching player stats:', e);
  }
  
  const header = await renderHeader(req);
  const avgScore = stats.totalQuestions > 0 ? Math.round((stats.correctAnswers / stats.totalQuestions) * 100) : 0;
  res.type('html').send(`
    ${renderHead('Player • Trivia Advent-ure', true)}
    <body class="ta-body">
      ${header}
      <main class="ta-main ta-container">
        ${needsPassword ? `<div style="margin:12px 0;padding:10px;border:1px solid #ffecb5;border-radius:6px;background:#fff8e1;color:#6b4f00;">Welcome! For cross-device login, please <a href="/account/security" class="ta-btn ta-btn-small" style="display:inline-block;margin-left:4px;">set your password</a>.</div>` : ''}
        <h1 class="ta-page-title">Welcome, ${displayName}</h1>
        
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:24px 0;">
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;">
            <div style="font-size:14px;opacity:0.7;margin-bottom:4px;">Quizzes Played</div>
            <div style="font-size:32px;font-weight:bold;color:#ffd700;">${stats.totalQuizzes}</div>
          </div>
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;">
            <div style="font-size:14px;opacity:0.7;margin-bottom:4px;">Questions Answered</div>
            <div style="font-size:32px;font-weight:bold;color:#ffd700;">${stats.totalQuestions}</div>
          </div>
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;">
            <div style="font-size:14px;opacity:0.7;margin-bottom:4px;">Correct Answers</div>
            <div style="font-size:32px;font-weight:bold;color:#ffd700;">${stats.correctAnswers}</div>
          </div>
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;">
            <div style="font-size:14px;opacity:0.7;margin-bottom:4px;">Average Score</div>
            <div style="font-size:32px;font-weight:bold;color:#ffd700;">${avgScore}%</div>
          </div>
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;">
            <div style="font-size:14px;opacity:0.7;margin-bottom:4px;">Total Points</div>
            <div style="font-size:32px;font-weight:bold;color:#ffd700;">${Math.round(stats.totalPoints)}</div>
          </div>
        </div>
        
        ${stats.recentQuizzes.length > 0 ? `
        <div style="margin:24px 0;">
          <h2 style="margin-bottom:16px;">Recent Quizzes</h2>
          <div style="display:flex;flex-direction:column;gap:12px;">
            ${stats.recentQuizzes.map(q => {
              const score = q.total_questions > 0 ? Math.round((q.correct_count / q.total_questions) * 100) : 0;
              const unlockDate = q.unlock_at ? new Date(q.unlock_at).toLocaleDateString() : '';
              return `
                <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;display:flex;justify-content:space-between;align-items:center;">
                  <div>
                    <div style="font-weight:bold;margin-bottom:4px;">${q.title || 'Untitled Quiz'}</div>
                    <div style="font-size:14px;opacity:0.7;">${unlockDate} • ${q.questions_answered}/${q.total_questions} questions</div>
                  </div>
                  <div style="text-align:right;">
                    <div style="font-size:24px;font-weight:bold;color:#ffd700;">${score}%</div>
                    <div style="font-size:12px;opacity:0.7;">${q.points || 0} pts</div>
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>
        ` : ''}
        
        <div class="ta-actions" style="margin-top:32px;display:flex;flex-wrap:wrap;gap:12px;">
          <a class="ta-btn ta-btn-primary" href="/calendar">Open Calendar</a>
          <a class="ta-btn ta-btn-outline" href="/leaderboard">View Leaderboard</a>
          <a class="ta-btn ta-btn-outline" href="/account/credentials">Account Settings</a>
        </div>
      </main>
      ${renderFooter(req)}
    </body></html>
  `);
});

// Admin dashboard
app.get('/admin', requireAdmin, async (req, res) => {
  const header = await renderHeader(req);
  
  // Get analytics
  let stats = {
    totalQuizzes: 0,
    totalPlayers: 0,
    totalSubmissions: 0,
    activeInvites: 0,
    recentQuizzes: []
  };
  
  try {
    const quizCount = await pool.query('SELECT COUNT(*) as count FROM quizzes');
    stats.totalQuizzes = parseInt(quizCount.rows[0]?.count || 0);
    
    const playerCount = await pool.query('SELECT COUNT(*) as count FROM players');
    stats.totalPlayers = parseInt(playerCount.rows[0]?.count || 0);
    
    const submissionCount = await pool.query('SELECT COUNT(*) as count FROM writer_submissions');
    stats.totalSubmissions = parseInt(submissionCount.rows[0]?.count || 0);
    
    const activeInvitesCount = await pool.query('SELECT COUNT(*) as count FROM writer_invites WHERE active=true AND (expires_at IS NULL OR expires_at > NOW())');
    stats.activeInvites = parseInt(activeInvitesCount.rows[0]?.count || 0);
    
    const recentQuizzes = await pool.query(`
      SELECT id, title, unlock_at, author, 
        (SELECT COUNT(*) FROM responses WHERE quiz_id = quizzes.id) as response_count
      FROM quizzes 
      ORDER BY unlock_at DESC 
      LIMIT 5
    `);
    stats.recentQuizzes = recentQuizzes.rows;
  } catch (e) {
    console.error('Error fetching admin stats:', e);
  }
  
  res.type('html').send(`
    ${renderHead('Admin • Trivia Advent-ure', true)}
    <body class="ta-body">
      ${header}
      <main class="ta-main ta-container">
        ${renderBreadcrumb([{ label: 'Admin' }])}
        ${renderAdminNav('dashboard')}
        <h1 class="ta-page-title">Admin Dashboard</h1>
        
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:24px 0;">
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;">
            <div style="font-size:14px;opacity:0.7;margin-bottom:4px;">Total Quizzes</div>
            <div style="font-size:32px;font-weight:bold;color:#ffd700;">${stats.totalQuizzes}</div>
          </div>
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;">
            <div style="font-size:14px;opacity:0.7;margin-bottom:4px;">Total Players</div>
            <div style="font-size:32px;font-weight:bold;color:#ffd700;">${stats.totalPlayers}</div>
          </div>
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;">
            <div style="font-size:14px;opacity:0.7;margin-bottom:4px;">Submissions</div>
            <div style="font-size:32px;font-weight:bold;color:#ffd700;">${stats.totalSubmissions}</div>
          </div>
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;">
            <div style="font-size:14px;opacity:0.7;margin-bottom:4px;">Active Invites</div>
            <div style="font-size:32px;font-weight:bold;color:#ffd700;">${stats.activeInvites}</div>
          </div>
        </div>
        
        ${stats.recentQuizzes.length > 0 ? `
        <div style="margin:24px 0;">
          <h2 style="margin-bottom:16px;color:#ffd700;">Recent Quizzes</h2>
          <div style="display:flex;flex-direction:column;gap:12px;">
            ${stats.recentQuizzes.map(q => {
              const unlockDate = q.unlock_at ? new Date(q.unlock_at).toLocaleDateString() : '';
              return `
                <div style="background:#1a1a1a;padding:16px;border-radius:8px;border:1px solid #333;display:flex;justify-content:space-between;align-items:center;">
                  <div>
                    <div style="font-weight:bold;margin-bottom:4px;"><a href="/admin/quizzes/${q.id}" class="ta-btn ta-btn-small" style="color:#111;text-decoration:none;">${q.title || 'Untitled Quiz'}</a></div>
                    <div style="font-size:14px;opacity:0.7;">${unlockDate} • ${q.author || 'Unknown'} • ${q.response_count || 0} responses</div>
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>
        ` : ''}
        
        <section style="margin-bottom:32px;">
          <h2 style="margin-bottom:12px;color:#ffd700;">Quizzes</h2>
          <div class="ta-card-grid">
            <a class="ta-card" href="/admin/upload-quiz"><strong>Upload Quiz</strong><span>Create a quiz with 10 questions</span></a>
            <a class="ta-card" href="/admin/quizzes"><strong>Manage Quizzes</strong><span>View/Edit/Clone/Delete</span></a>
            <a class="ta-card" href="/admin/calendar"><strong>Admin Calendar</strong><span>AM/PM occupancy and conflicts</span></a>
            <a class="ta-card" href="/admin/author-slots"><strong>Author Assignments</strong><span>Set author emails & slot overrides</span></a>
          </div>
        </section>
        <section style="margin-bottom:32px;">
          <h2 style="margin-bottom:12px;color:#ffd700;">Writers</h2>
          <div class="ta-card-grid">
            <a class="ta-card" href="/admin/writer-invite"><strong>Writer Invite</strong><span>Create token link for guest authors</span></a>
            <a class="ta-card" href="/admin/writer-invites"><strong>Writer Invites (CSV)</strong><span>Prepare CSV and bulk-generate links</span></a>
            <a class="ta-card" href="/admin/writer-invites/list"><strong>Writer Invites (List)</strong><span>Status, resend, deactivate, copy</span></a>
            <a class="ta-card" href="/admin/writer-invites/my"><strong>My Writer Invites</strong><span>View and access your own quiz writing links</span></a>
            <a class="ta-card" href="/admin/writer-submissions"><strong>Writer Submissions</strong><span>Review and publish submitted quizzes</span></a>
          </div>
        </section>
        <section style="margin-bottom:32px;">
          <h2 style="margin-bottom:12px;color:#ffd700;">Communication</h2>
          <div class="ta-card-grid">
            <a class="ta-card" href="/admin/announcements"><strong>Send Announcement</strong><span>Send email announcement to all players</span></a>
          </div>
        </section>
        <section style="margin-bottom:32px;">
          <h2 style="margin-bottom:12px;color:#ffd700;">Access & Users</h2>
          <div class="ta-card-grid">
            <a class="ta-card" href="/admin/players"><strong>Players</strong><span>View and manage all players</span></a>
            <a class="ta-card" href="/admin/access"><strong>Access & Links</strong><span>Grant or send magic links</span></a>
            <a class="ta-card" href="/admin/admins"><strong>Admins</strong><span>Manage admin emails</span></a>
          </div>
        </section>
        <section style="margin-bottom:32px;">
          <h2 style="margin-bottom:12px;color:#ffd700;">Leaderboards</h2>
          <div class="ta-card-grid">
            <a class="ta-card" href="/leaderboard"><strong>Overall Leaderboard</strong></a>
          </div>
        </section>
      </main>
      ${renderFooter(req)}
    </body></html>
  `);
});

// Dedicated login page (magic-link)
app.get('/login', async (req, res) => {
  const loggedIn = !!req.session.user;
  const showMagic = String(process.env.SHOW_MAGIC_LINK_FORM || '').toLowerCase() === 'true' || String(req.query.magic||'') === '1';
  const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead('Login • Trivia Advent-ure', false)}
    <body class="ta-body login-body">
    ${header}
      <main class="ta-main login-main">
        <div class="ta-container login-container">
          <div class="login-shell">
            <section class="login-panel">
              <header class="login-head">
                <span class="login-pill">Trivia Advent-ure</span>
                <h1 class="login-title">${loggedIn ? 'You&rsquo;re signed in' : 'Sign in to play'}</h1>
                <p class="login-lead">${loggedIn ? 'Jump back into the calendar and keep your streak alive.' : 'Sign in to play along with the Trivia Advent‑ure community.'}</p>
              </header>
              ${loggedIn ? `
                <div class="login-card login-card--success">
                  <h2 class="login-card__title">You&rsquo;re already signed in</h2>
                  <p class="login-card__text">Signed in as <strong>${req.session.user.email}</strong>. Jump back into the adventure.</p>
                  <div class="login-actions">
                    <a class="ta-btn ta-btn-primary" href="/calendar">Open calendar</a>
                    <a class="ta-btn ta-btn-outline" href="/logout">Logout</a>
                  </div>
                </div>
              ` : `
                <div class="login-forms">
                  <div class="login-card login-card--primary">
                    <h2 class="login-card__title">Sign in with your password</h2>
                    <p class="login-card__text">Enter your Trivia Advent-ure username and password to continue.</p>
                    <form method="post" action="/auth/login-password" class="login-form">
                      <div class="login-field">
                        <label for="login-username">Username</label>
                        <input id="login-username" name="username" required autocomplete="username" />
                      </div>
                      <div class="login-field">
                        <label for="login-password">Password</label>
                        <input id="login-password" name="password" type="password" required autocomplete="current-password" />
                      </div>
                      <button type="submit" class="ta-btn ta-btn-primary login-submit">Sign in</button>
                      <div class="login-form-footer">
                        <a class="login-link" href="/login?magic=1#magic-link-card">Forgot your password?</a>
                      </div>
          </form>
                  </div>
          ${showMagic ? `
                    <div class="login-card login-card--secondary" id="magic-link-card">
                      <h2 class="login-card__title">Prefer a magic link?</h2>
                      <p class="login-card__text">We&rsquo;ll email you a one-time link you can use on any device.</p>
                      <form method="post" action="/auth/request-link" class="login-form" onsubmit="event.preventDefault(); const fd=new FormData(this); const v=String(fd.get('email')||'').trim(); if(!v){alert('Enter your email'); return;} fetch('/auth/request-link',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ email: v })}).then(r=>r.json()).then(d=>{ if (d.link) { alert('Magic link (dev):\n'+d.link); } else { alert('If you have access, a magic link was sent.'); } }).catch(()=>alert('Failed.'));">
                        <div class="login-field">
                          <label for="login-email">Email</label>
                          <input id="login-email" name="email" type="email" required autocomplete="email" />
        </div>
                        <button type="submit" class="ta-btn ta-btn-outline login-submit">Send magic link</button>
                      </form>
                      <p class="login-hint">Check spam if you don&rsquo;t see the email after a minute.</p>
                    </div>
                  ` : ''}
                </div>
      `}
              <div class="login-links">
                <a href="/" class="ta-btn ta-btn-outline">Return home</a>
                ${ADMIN_PIN_ENABLED ? '<a href="/admin/pin" class="ta-btn ta-btn-outline">Admin PIN access</a>' : ''}
              </div>
              <div class="login-card login-card--donate">
                <h2 class="login-card__title">Support the adventure</h2>
                <p class="login-card__text">Trivia Advent-ure is a charitable project. Every contribution on Ko-fi benefits <strong>Trans Lifeline</strong> and <strong>World Central Kitchen</strong>.</p>
                <div class="login-partner-logos">
                  <a href="https://translifeline.org" target="_blank" rel="noopener noreferrer">
                    <img src="/img/TL-logo_purple_transparent.png" alt="Trans Lifeline logo"/>
                  </a>
                  <a href="https://wck.org" target="_blank" rel="noopener noreferrer">
                    <img src="/img/download.png" alt="World Central Kitchen logo"/>
                  </a>
                </div>
                <a class="ta-btn ta-btn-primary login-donate-btn" href="https://ko-fi.com/triviaadvent" target="_blank" rel="noopener noreferrer">
                  Donate on Ko-fi
                </a>
              </div>
            </section>
          </div>
        </div>
      </main>
      ${renderFooter(req)}
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
app.get('/admin/pin', async (req, res) => {
  if (!ADMIN_PIN_ENABLED) return res.status(404).send('Not found');
  const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead('Admin PIN • Trivia Advent-ure', false)}
    <body class="ta-body" style="padding: 24px;">
    ${header}
      <h1>Admin PIN</h1>
      <form method="post" action="/admin/pin">
        <label>PIN <input type="password" name="pin" required /></label>
        <button type="submit">Enter</button>
      </form>
      <p style="margin-top:16px;"><a href="/" class="ta-btn ta-btn-outline">Home</a></p>
    </body></html>
  `);
});
app.post('/admin/pin', (req, res) => {
  if (!ADMIN_PIN_ENABLED) return res.status(404).send('Not found');
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
    const email = req.session.user ? (req.session.user.email || '').toLowerCase() : '';
    const isAdmin = await isAdminUser(req);
    
    // If logged in but not admin, check if they need to complete setup
    if (email && !isAdmin) {
      const setupCheck = await pool.query('SELECT onboarding_complete, username, password_set_at FROM players WHERE email=$1', [email]);
      if (setupCheck.rows.length) {
        const p = setupCheck.rows[0];
        if (!p.onboarding_complete) return res.redirect('/onboarding');
        if (!p.username || !p.password_set_at) return res.redirect('/account/credentials');
      }
    }
    
    const { rows: quizzes } = await pool.query('SELECT * FROM quizzes ORDER BY unlock_at ASC, id ASC');
    const nowUtc = new Date();
    let completedSet = new Set();
    let needsPassword = false;
    let displayName = '';
    if (email) {
      const { rows: c } = await pool.query('SELECT DISTINCT quiz_id FROM responses WHERE user_email = $1', [email]);
      c.forEach(r => completedSet.add(Number(r.quiz_id)));
      try {
        const pr = await pool.query('SELECT username, password_set_at FROM players WHERE email=$1', [email]);
        needsPassword = pr.rows.length && !pr.rows[0].password_set_at;
        displayName = (pr.rows.length && pr.rows[0].username) ? pr.rows[0].username : email;
      } catch {}
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
    const escapeAttr = (value) => String(value ?? '').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');
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
      const amUnlocked = sAm.unlocked && !!sAm.id;
      const pmUnlocked = sPm.unlocked && !!sPm.id;
      const amUrl = amUnlocked ? `/quiz/${sAm.id}` : '';
      const pmUrl = pmUnlocked ? `/quiz/${sPm.id}` : '';
      const amLabel = sAm.label || 'Locked';
      const pmLabel = sPm.label || 'Locked';
      const amTitle = am ? am.title || '' : '';
      const pmTitle = pm ? pm.title || '' : '';
      const amHref = escapeAttr(amUrl);
      const pmHref = escapeAttr(pmUrl);
      return `
      <div class="ta-door-slot">
        <div class="${cls}" data-day="${d.day}" data-day-number="${num}" data-am-unlocked="${amUnlocked ? 'true' : 'false'}" data-pm-unlocked="${pmUnlocked ? 'true' : 'false'}" data-am-url="${amHref}" data-pm-url="${pmHref}" data-am-status="${escapeAttr(amLabel)}" data-pm-status="${escapeAttr(pmLabel)}" data-am-title="${escapeAttr(amTitle)}" data-pm-title="${escapeAttr(pmTitle)}">
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
                ${amUnlocked ? `<a class=\"slot-btn unlocked\" href=\"${amHref}\" data-door-slot=\"am\">AM</a>` : `<span class=\"slot-btn ${sAm.unlocked?'unlocked':'locked'}\">AM</span>`}
                ${pmUnlocked ? `<a class=\"slot-btn unlocked\" href=\"${pmHref}\" data-door-slot=\"pm\">PM</a>` : `<span class=\"slot-btn ${sPm.unlocked?'unlocked':'locked'}\">PM</span>`}
              </div>
            </div>
          </div>
        </div>
      </div>
      `;
    }).join('\n');
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Calendar', true)}
      <body class="ta-body">
      ${header}
        <main class="ta-main ta-container ta-calendar">
          ${email && needsPassword ? `<div style="margin:12px 0;padding:10px;border:1px solid #ffecb5;border-radius:6px;background:#fff8e1;color:#6b4f00;">Welcome! For cross-device login, please <a href="/account/security">set your password</a>.</div>` : ''}
          <h1 class="ta-page-title">Advent Calendar</h1>
          <div class="ta-calendar-grid">${grid}</div>
        </main>
        ${renderFooter(req)}
        <script>
          (function(){
            var recentlyOpened = new Set();
            var touchStartDoor = null;
            var touchStartTime = 0;
            var isProcessing = false;
            
            function handleDoorClick(e){
              if (isProcessing) {
                e.preventDefault();
                e.stopPropagation();
                return false;
              }
              
              var door = e.currentTarget;
              
              // CRITICAL: If door is NOT open, block ALL clicks from reaching buttons
              var isOpen = door.classList.contains('is-open');
              if (!isOpen) {
                // Door is closed - prevent any clicks from reaching buttons
                if (e.target.closest('.slot-btn')) {
                  e.preventDefault();
                  e.stopPropagation();
                  e.stopImmediatePropagation();
                  return false;
                }
              } else {
                // Door is open - let slot buttons work normally
                if (e.target && e.target.closest && e.target.closest('.slot-btn')) {
                  // If door was just opened, prevent immediate navigation
                  if (recentlyOpened.has(door)) {
                    e.preventDefault();
                    e.stopPropagation();
                    e.stopImmediatePropagation();
                    return false;
                  }
                  return; // Allow normal button navigation
                }
              }
              
              if (!door.classList.contains('is-unlocked')) return;
              
              isProcessing = true;
              
              // Toggle door open/closed (works on both mobile and desktop)
              var wasOpen = door.classList.contains('is-open');
              document.querySelectorAll('.ta-door.is-open').forEach(function(x){ 
                x.classList.remove('is-open');
                recentlyOpened.delete(x);
              });
              if (!wasOpen){
                door.classList.add('is-open');
                // Mark as recently opened to prevent immediate button clicks
                recentlyOpened.add(door);
                // Longer delay for mobile to ensure animation completes
                setTimeout(function(){
                  recentlyOpened.delete(door);
                  isProcessing = false;
                }, 800);
              } else {
                isProcessing = false;
              }
            }
            
            function setupDoors(){
              var doors = document.querySelectorAll('.ta-door');
              doors.forEach(function(d){
                // Block all clicks on slot buttons when door is closed
                var slotButtons = d.querySelectorAll('.slot-btn');
                slotButtons.forEach(function(btn){
                  btn.addEventListener('click', function(e){
                    var door = btn.closest('.ta-door');
                    if (!door || !door.classList.contains('is-open')) {
                      e.preventDefault();
                      e.stopPropagation();
                      e.stopImmediatePropagation();
                      return false;
                    }
                    if (recentlyOpened.has(door)) {
                      e.preventDefault();
                      e.stopPropagation();
                      e.stopImmediatePropagation();
                      return false;
                    }
                  }, true);
                });
                
                // Handle touch events first to prevent double-firing
                if ('ontouchstart' in window) {
                  d.addEventListener('touchstart', function(e){
                    // Block touch on buttons when door is closed
                    if (e.target.closest('.slot-btn')) {
                      var door = e.target.closest('.ta-door');
                      if (!door || !door.classList.contains('is-open')) {
                        return;
                      }
                    }
                    if (!e.target.closest('.slot-btn')) {
                      touchStartDoor = d;
                      touchStartTime = Date.now();
                    }
                  }, { passive: true });
                  
                  d.addEventListener('touchend', function(e){
                    // Block touch on buttons when door is closed
                    if (e.target.closest('.slot-btn')) {
                      var door = e.target.closest('.ta-door');
                      if (!door || !door.classList.contains('is-open')) {
                        e.preventDefault();
                        e.stopPropagation();
                        return false;
                      }
                      if (recentlyOpened.has(door)) {
                        e.preventDefault();
                        e.stopPropagation();
                        return false;
                      }
                      return; // Let button handle its own navigation
                    }
                    
                    var touchDuration = Date.now() - touchStartTime;
                    // Only handle quick taps (not long press or swipe)
                    if (touchStartDoor === d && touchDuration < 300) {
                      e.preventDefault();
                      e.stopPropagation();
                      e.stopImmediatePropagation();
                      handleDoorClick(e);
                      // Block click event for longer
                      setTimeout(function(){
                        touchStartDoor = null;
                      }, 300);
                    } else {
                      touchStartDoor = null;
                    }
                  }, { passive: false });
                  
                  // Also prevent click on touch devices
                  d.addEventListener('click', function(e){
                    if (touchStartDoor === d || recentlyOpened.has(d)) {
                      e.preventDefault();
                      e.stopPropagation();
                      e.stopImmediatePropagation();
                      return false;
                    }
                  }, true);
                } else {
                  // Use click for desktop
                  d.addEventListener('click', function(e){
                    handleDoorClick(e);
                  }, true);
                }
              });
            }
            
            if (document.readyState === 'loading'){
              document.addEventListener('DOMContentLoaded', setupDoors);
            } else {
              setupDoors();
            }
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
app.get('/admin/upload-quiz', requireAdmin, async (req, res) => {
  const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead('Upload Quiz', true)}
    <body class="ta-body">
    ${header}
      <main class="ta-main ta-container" style="max-width:900px;">
        ${renderBreadcrumb([ADMIN_CRUMB, { label: 'Quizzes', href: '/admin/quizzes' }, { label: 'Upload Quiz' }])}
        ${renderAdminNav('quizzes')}
        <h1 class="ta-page-title">Upload Quiz</h1>
        <p style="margin:0 0 16px 0;opacity:0.8;">Provide the core quiz details and we'll create the entry. You can tweak timings, copy, and assignments afterward.</p>
        <form method="post" action="/admin/upload-quiz" class="ta-form-stack">
          <label class="ta-form-field">Title <input name="title" required /></label>
          <label class="ta-form-field">Author <input name="author" /></label>
          <label class="ta-form-field">Author email <input name="author_email" type="email" /></label>
          <label class="ta-form-field">Author blurb <input name="author_blurb" /></label>
          <label class="ta-form-field">Description<textarea name="description" rows="3"></textarea></label>
          <label class="ta-form-field">Unlock (ET) <input name="unlock_at" type="datetime-local" required /></label>
          <fieldset class="ta-fieldset">
          <legend>Questions (10)</legend>
          ${Array.from({length:10}, (_,i)=>{
            const n=i+1;
              return `<div class="ta-question-block">
                <div class="ta-question-header"><strong>Question ${n}</strong></div>
                <label class="ta-form-field">Text <input name="q${n}_text" required /></label>
                <label class="ta-form-field">Answer <input name="q${n}_answer" required /></label>
                <div class="ta-question-row">
                  <label>Category <input name="q${n}_category" value="General"/></label>
                  <label>Ask <input name="q${n}_ask"/></label>
                </div>
              </div>`;
          }).join('')}
        </fieldset>
          <div class="ta-form-actions">
            <button type="submit" class="ta-btn ta-btn-primary">Create Quiz</button>
            <a href="/admin/quizzes" class="ta-btn ta-btn-outline">Cancel</a>
          </div>
      </form>
      </main>
      ${renderFooter(req)}
    </body></html>
  `);
});

app.post('/admin/upload-quiz', requireAdmin, async (req, res) => {
  try {
    const title = String(req.body.title || '').trim();
    const author = String(req.body.author || '').trim() || null;
    const authorEmailRaw = String(req.body.author_email || '').trim().toLowerCase();
    const authorEmail = authorEmailRaw ? authorEmailRaw : null;
    const authorBlurb = String(req.body.author_blurb || '').trim() || null;
    const description = String(req.body.description || '').trim() || null;
    const unlockInput = String(req.body.unlock_at || '').trim();
    if (!title || !unlockInput) return res.status(400).send('Missing title or unlock time');
    const unlockUtc = etToUtc(unlockInput);
    const freezeUtc = new Date(unlockUtc.getTime() + 24*60*60*1000);
    const qInsert = await pool.query('INSERT INTO quizzes(title, unlock_at, freeze_at, author, author_blurb, description, author_email) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id', [title, unlockUtc, freezeUtc, author, authorBlurb, description, authorEmail]);
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

// Helper function to ensure author is in players table
async function ensureAuthorIsPlayer(email) {
  if (!email) return;
  const emailLower = String(email).trim().toLowerCase();
  if (!emailLower) return;
  try {
    // Check if player exists
    const { rows } = await pool.query('SELECT 1 FROM players WHERE email=$1', [emailLower]);
    if (rows.length === 0) {
      // Add to players table
      await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [emailLower]);
      console.log('[writer-invite] Added author to players table:', emailLower);
    }
  } catch (e) {
    console.error('[writer-invite] Error ensuring author is player:', e);
  }
}

// --- Admin: create writer invite (returns unique link) ---
app.post('/admin/writer-invite', requireAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const author = String(req.body.author || '').trim();
    const email = String(req.body.email || '').trim() || null;
    const slotDateRaw = String(req.body.slotDate || '').trim() || null;
    const slotHalf = String(req.body.slotHalf || '').trim().toUpperCase() || null; // 'AM'|'PM'
    const sendAtRaw = String(req.body.sendAt || '').trim() || null; // ET string "YYYY-MM-DD HH:mm"
    if (!author) return res.status(400).send('Missing author');
    
    // Ensure author is in players table if email is provided
    if (email) {
      await ensureAuthorIsPlayer(email);
    }
    
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
app.get('/admin/writer-invite', requireAdmin, async (req, res) => {
  const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead('Create Writer Invite', false)}
    <body class="ta-body" style="padding:24px;">
    ${header}
      <h1>Create Writer Invite</h1>
      <form id="inviteForm" style="margin-top:12px;max-width:520px;">
        <div style="margin:8px 0;"><label>Author <input name="author" required style="width:100%"/></label></div>
        <div style="margin:8px 0;"><label>Email (optional) <input name="email" style="width:100%"/></label></div>
        <button type="submit">Generate Invite Link</button>
      </form>
      <div id="result" style="margin-top:16px;font-family:monospace;"></div>
      <p style="margin-top:16px;"><a href="/admin" class="ta-btn ta-btn-outline">Back</a></p>
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
app.get('/admin/writer-invites', requireAdmin, async (req, res) => {
  const year = new Date().getFullYear();
  const preRowsArr = [];
  let rowNum = 1;
  for (let d = 1; d <= 24; d++) {
    const dd = String(d).padStart(2,'0');
    const dateStr = `${year}-12-${dd}`;
    preRowsArr.push(
      '<tr>' +
      '<td class="idx" style="padding:6px 4px;">'+ (rowNum++) +'</td>' +
      '<td style="padding:6px 4px;"><input type="text" name="author" value="" required style="width:100%"></td>' +
      '<td style="padding:6px 4px;"><input name="email" value="" style="width:100%" type="email"></td>' +
      '<td style="padding:6px 4px;"><span>'+dateStr+'</span><input type="hidden" name="slotDate" value="' + dateStr + '"></td>' +
      '<td style="padding:6px 4px;"><span>AM</span><input type="hidden" name="slotHalf" value="AM"></td>' +
      '<td style="padding:6px 4px;"><button class="rm">Remove</button></td>' +
      '</tr>'
    );
    preRowsArr.push(
      '<tr>' +
      '<td class="idx" style="padding:6px 4px;">'+ (rowNum++) +'</td>' +
      '<td style="padding:6px 4px;"><input type="text" name="author" value="" required style="width:100%"></td>' +
      '<td style="padding:6px 4px;"><input name="email" value="" style="width:100%" type="email"></td>' +
      '<td style="padding:6px 4px;"><span>'+dateStr+'</span><input type="hidden" name="slotDate" value="' + dateStr + '"></td>' +
      '<td style="padding:6px 4px;"><span>PM</span><input type="hidden" name="slotHalf" value="PM"></td>' +
      '<td style="padding:6px 4px;"><button class="rm">Remove</button></td>' +
      '</tr>'
    );
  }
  const preRows = preRowsArr.join('');
  const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead('Writer Invites (CSV)', false)}
    <body class="ta-body" style="padding:24px;">
    ${header}
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
        /* Author inputs match email inputs */
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
        <a href="/admin" class="ta-btn ta-btn-outline" style="margin-left:12px;">Back to Admin</a>
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
      <div id="resultsPanel" style="display:none;margin-top:16px;border:1px solid rgba(212,175,55,0.3);border-radius:8px;padding:12px;background:rgba(0,0,0,0.2);">
        <h3 style="margin:0 0 8px 0;color:#ffd700;">Generated Links</h3>
        <div id="resultsList" style="display:flex;flex-direction:column;gap:6px;"></div>
      </div>
      <script src="/js/writer-invites.js"></script>
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
    // Load existing draft
    let existing = null;
    try {
      const s = await pool.query('SELECT data, submitted_at, updated_at FROM writer_submissions WHERE token=$1 ORDER BY id DESC LIMIT 1', [invite.token]);
      if (s.rows.length) existing = typeof s.rows[0].data === 'string' ? JSON.parse(s.rows[0].data) : s.rows[0].data;
    } catch {}
    const esc = (v)=>String(v||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Submit Quiz', false)}
      <body class="ta-body" style="padding:24px;font-size:18px;line-height:1.5;">
      ${header}
        <div style="max-width: 820px; margin: 0 auto;">
        <h1>Submit Your Quiz</h1>
        <p>Author: <strong>${invite.author}</strong></p>
        <form method="post" action="/writer/${invite.token}">
          <div style="margin-top:12px;">
            <label style="display:block;margin-bottom:6px;font-weight:600;">About the author</label>
            <textarea name="author_blurb" style="width:100%;min-height:80px;border:1px solid #ccc;border-radius:6px;padding:10px;font-size:16px;">${existing && existing.author_blurb ? esc(existing.author_blurb) : ''}</textarea>
          </div>
          <div style="margin-top:12px;">
            <label style="display:block;margin-bottom:6px;font-weight:600;">About this quiz</label>
            <textarea name="description" style="width:100%;min-height:100px;border:1px solid #ccc;border-radius:6px;padding:10px;font-size:16px;">${existing && existing.description ? esc(existing.description) : ''}</textarea>
          </div>
          <fieldset style="margin-top:12px;">
            <legend>Questions (10)</legend>
            ${Array.from({length:10}, (_,i)=>{
              const n=i+1;
              const q = (existing && Array.isArray(existing.questions) && existing.questions[i]) ? existing.questions[i] : null;
              const tVal = q && q.text ? esc(q.text) : '';
              const aVal = q && q.answer ? esc(q.answer) : '';
              const cVal = q && q.category ? esc(q.category) : '';
              const kVal = q && q.ask ? esc(q.ask) : '';
              return `<div style=\"border:1px solid #ddd;padding:12px;margin:8px 0;border-radius:8px;\">\n\
                <div style=\"margin-bottom:8px;\"><strong>Q${n}</strong></div>\n\
                <div style=\"margin-bottom:10px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;\">\n\
                  <label style=\"font-weight:600;\">Category\n\
                    <input name=\"q${n}_category\" value=\"${cVal}\" placeholder=\"General\" style=\"width:260px;border:1px solid #ccc;border-radius:6px;padding:8px;font-size:16px;\"/>\n\
                  </label>\n\
                </div>\n\
                <div style=\"margin-bottom:10px;\">\n\
                  <label style=\"display:block;margin-bottom:6px;font-weight:600;\">Text</label>\n\
                  <textarea name=\"q${n}_text\" required style=\"width:100%;min-height:120px;border:1px solid #ccc;border-radius:6px;padding:10px;font-size:16px;\">${tVal}</textarea>\n\
                </div>\n\
                <div style=\"margin-bottom:10px;\">\n\
                  <label style=\"display:block;margin-bottom:6px;font-weight:600;\">Answer</label>\n\
                  <input name=\"q${n}_answer\" value=\"${aVal}\" required style=\"width:100%;border:1px solid #ccc;border-radius:6px;padding:10px;font-size:16px;\"/>\n\
                </div>\n\
                <div style=\"margin-bottom:6px;\">\n\
                  <label style=\"display:block;margin-bottom:6px;font-weight:600;\">Ask <span style=\"opacity:.8;font-size:.9em;\">(must appear verbatim in the Text; the key part of the question; used as an in-line highlight)</span></label>\n\
                  <input name=\"q${n}_ask\" value=\"${kVal}\" style=\"width:100%;border:1px solid #ccc;border-radius:6px;padding:10px;font-size:16px;\"/>\n\
                </div>\n\
              </div>`
            }).join('')}
          </fieldset>
          <div style="margin-top:12px;"><button type="submit">Submit Quiz</button></div>
        </form>
        <p style="margin-top:16px;"><a href="/" class="ta-btn ta-btn-outline">Home</a></p>
        </div>
        <script src="/js/writer-form.js"></script>
      </body></html>
    `);
  } catch (e) {
    console.error('Error loading writer form:', e);
    res.status(500).send(`
      ${renderHead('Error', false)}
      <body class="ta-body" style="padding:24px;">
        <h1>Unable to Load Form</h1>
        <p>We encountered an error loading the quiz submission form. Please try again later.</p>
        <p><a href="/">Return home</a></p>
      </body></html>
    `);
  }
});

// Autosave endpoint for writer forms
app.post('/writer/:token/autosave', express.json(), async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT token, author FROM writer_invites WHERE token=$1 AND active=true AND (expires_at IS NULL OR expires_at > NOW())',
      [req.params.token]
    );
    if (!rows.length) return res.status(404).json({ error: 'Invalid or expired link' });
    const invite = rows[0];
    const payload = req.body;
    const existing = await pool.query('SELECT id FROM writer_submissions WHERE token=$1 ORDER BY id DESC LIMIT 1', [invite.token]);
    if (existing.rows.length) {
      await pool.query('UPDATE writer_submissions SET data=$2, updated_at=NOW() WHERE id=$1', [existing.rows[0].id, JSON.stringify(payload)]);
    } else {
      await pool.query('INSERT INTO writer_submissions(token, author, data) VALUES($1,$2,$3)', [invite.token, invite.author, JSON.stringify(payload)]);
    }
    res.json({ success: true });
  } catch (e) {
    console.error('Autosave error:', e);
    res.status(500).json({ error: 'Failed to save' });
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
    const description = (String(req.body.description || '').trim() || null);
    const authorBlurb = (String(req.body.author_blurb || '').trim() || null);
    for (let i=1;i<=10;i++) {
      const qt = String(req.body['q' + i + '_text'] || '').trim();
      const qa = String(req.body['q' + i + '_answer'] || '').trim();
      const qc = String(req.body['q' + i + '_category'] || 'General').trim();
      const qk = String(req.body['q' + i + '_ask'] || '').trim() || null;
      if (!qt || !qa) continue;
      questions.push({ text: qt, answer: qa, category: qc, ask: qk });
    }
    if (!questions.length) return res.status(400).send('Please provide at least one question');
    const payload = { description, author_blurb: authorBlurb, questions };
    const existing = await pool.query('SELECT id FROM writer_submissions WHERE token=$1 ORDER BY id DESC LIMIT 1', [invite.token]);
    if (existing.rows.length) {
      await pool.query('UPDATE writer_submissions SET data=$2, updated_at=NOW() WHERE id=$1', [existing.rows[0].id, JSON.stringify(payload)]);
    } else {
      await pool.query('INSERT INTO writer_submissions(token, author, data) VALUES($1,$2,$3)', [invite.token, invite.author, JSON.stringify(payload)]);
    }
    const isNewSubmission = !existing.rows.length;
    try { await pool.query('UPDATE writer_invites SET submitted_at = COALESCE(submitted_at, NOW()) WHERE token=$1', [invite.token]); } catch {}
    
    // Send email notification to all admins when a new submission is made
    if (isNewSubmission) {
      try {
        const adminRows = await pool.query('SELECT email FROM admins ORDER BY email ASC');
        const baseUrl = process.env.PUBLIC_BASE_URL || '';
        const submissionUrl = `${baseUrl}/admin/writer-submissions`;
        const subject = `New Quiz Submission from ${invite.author}`;
        const text = `A new quiz has been submitted by ${invite.author}.\r\n\r\nView and publish it here:\r\n${submissionUrl}\r\n\r\nQuestions submitted: ${questions.length}`;
        
        for (const adminRow of adminRows.rows) {
          const adminEmail = (adminRow.email || '').toLowerCase();
          if (adminEmail) {
            try {
              await sendPlainEmail(adminEmail, subject, text);
              console.log('[writer-submit] Notification sent to admin:', adminEmail);
            } catch (emailErr) {
              console.error('[writer-submit] Failed to notify admin', adminEmail, ':', emailErr?.message || emailErr);
            }
          }
        }
      } catch (notifyErr) {
        console.error('[writer-submit] Error sending admin notifications:', notifyErr);
        // Don't fail the submission if email fails
      }
    }
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Submitted', false)}
      <body class="ta-body" style="padding:24px;">
      ${header}
        <h1>Thanks, ${invite.author}!</h1>
        <p>Your quiz was submitted successfully. The team will schedule it.</p>
        <p><a href="/">Return home</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error('Error submitting quiz:', e);
    const header = await renderHeader(req);
    res.status(500).send(`
      ${renderHead('Submission Error', false)}
      <body class="ta-body" style="padding:24px;">
      ${header}
        <h1>Submission Failed</h1>
        <p>We encountered an error while saving your quiz. Please check your connection and try again.</p>
        <p>If the problem persists, please contact support.</p>
        <p><a href="javascript:history.back()">Go back</a> | <a href="/">Return home</a></p>
      </body></html>
    `);
  }
});

// --- Admin: list and publish writer submissions ---
app.get('/admin/writer-submissions', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT ws.id, ws.submitted_at, ws.updated_at, ws.author, ws.data, wi.submitted_at as invite_submitted_at
      FROM writer_submissions ws
      LEFT JOIN writer_invites wi ON wi.token = ws.token
      ORDER BY ws.id DESC
      LIMIT 200
    `);
    const esc = (v) => String(v || '').replace(/&/g,'&amp;').replace(/</g,'&lt;');
    const list = rows.map(r => {
      let first = '';
      try { first = (r.data?.questions?.[0]?.text) || ''; } catch {}
      // Determine if this is a draft (autosave) or actual submission
      const isDraft = !r.invite_submitted_at;
      const bgColor = isDraft ? '#2a1a0a' : '#0a2a1a';
      const borderColor = isDraft ? '#ff9800' : '#4caf50';
      const accentColor = isDraft ? '#ff9800' : '#4caf50';
      const statusBadge = isDraft 
        ? '<span style="background:#ff9800;color:#000;padding:6px 12px;border-radius:6px;font-size:14px;font-weight:800;text-transform:uppercase;letter-spacing:1px;box-shadow:0 2px 8px rgba(255,152,0,0.4);">⚠️ DRAFT</span>'
        : '<span style="background:#4caf50;color:#fff;padding:6px 12px;border-radius:6px;font-size:14px;font-weight:800;text-transform:uppercase;letter-spacing:1px;box-shadow:0 2px 8px rgba(76,175,80,0.4);">✓ SUBMITTED</span>';
      const statusText = isDraft 
        ? `<span style="color:#ffaa44;font-weight:600;">Draft - Last saved: ${fmtEt(r.updated_at || r.submitted_at)}</span>`
        : `<span style="color:#66ff88;font-weight:600;">Submitted: ${fmtEt(r.invite_submitted_at)}</span>`;
      return `
        <li style="margin:16px 0;padding:16px;background:${bgColor};border:3px solid ${borderColor};border-radius:8px;border-left-width:8px;box-shadow:0 4px 12px rgba(0,0,0,0.3);">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
            ${statusBadge}
            <div style="flex:1;min-width:200px;">
              <div style="font-size:16px;font-weight:700;color:#fff;margin-bottom:4px;"><strong>ID:</strong> ${r.id} · <strong>Author:</strong> ${esc(r.author)}</div>
              <div style="font-size:14px;margin-top:4px;">${statusText}</div>
            </div>
          </div>
          <div style="margin-top:12px;padding:8px;background:rgba(0,0,0,0.3);border-radius:4px;color:#aaa;font-size:13px;"><em>Preview:</em> ${first ? esc(first.substring(0, 150)) + (first.length > 150 ? '...' : '') : '(no preview)'} </div>
          <div style="margin-top:12px;"><a href="/admin/writer-submissions/${r.id}" class="ta-btn ta-btn-primary" style="font-weight:600;padding:10px 20px;">Preview & Publish</a></div>
        </li>
      `;
    }).join('');
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Writer Submissions', false)}
      <body class="ta-body" style="padding:24px;">
      ${header}
        <h1>Writer Submissions</h1>
        <ul style="list-style:none;padding:0;margin:0;">
          ${list || '<li>No submissions yet.</li>'}
        </ul>
        <p style="margin-top:16px;"><a href="/admin" class="ta-btn ta-btn-outline">Back</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load submissions');
  }
});

// Helper function to generate a default title for a quiz submission
// Uses only author name and date/time (the only reliable information)
function generateDefaultTitle(row, data, unlockAtValue) {
  // Use author name and date if both available
  if (unlockAtValue && row.author) {
    try {
      const datePart = unlockAtValue.split('T')[0];
      const [year, month, day] = datePart.split('-');
      const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 
                          'July', 'August', 'September', 'October', 'November', 'December'];
      const monthName = monthNames[parseInt(month) - 1];
      const timePart = unlockAtValue.split('T')[1] || '00:00';
      const hour = parseInt(timePart.split(':')[0]);
      const timeLabel = hour === 0 ? 'AM' : 'PM';
      return `${row.author}'s Quiz - ${monthName} ${parseInt(day)} ${timeLabel}`;
    } catch (e) {
      // If date parsing fails, continue to next fallback
    }
  }
  
  // If we have date but no author
  if (unlockAtValue) {
    try {
      const datePart = unlockAtValue.split('T')[0];
      const [year, month, day] = datePart.split('-');
      const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 
                          'July', 'August', 'September', 'October', 'November', 'December'];
      const monthName = monthNames[parseInt(month) - 1];
      const timePart = unlockAtValue.split('T')[1] || '00:00';
      const hour = parseInt(timePart.split(':')[0]);
      const timeLabel = hour === 0 ? 'AM' : 'PM';
      return `${monthName} ${parseInt(day)} ${timeLabel} Quiz`;
    } catch (e) {
      // If date parsing fails, continue to next fallback
    }
  }
  
  // If we only have author
  if (row.author) {
    return `${row.author}'s Quiz`;
  }
  
  // Final fallback
  return 'Untitled Quiz';
}

// Admin: preview a writer submission
app.get('/admin/writer-submissions/:id', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send('Invalid id');
    const sres = await pool.query('SELECT ws.token, ws.author, ws.submitted_at, ws.updated_at, ws.data, wi.slot_date, wi.slot_half, wi.submitted_at as invite_submitted_at FROM writer_submissions ws LEFT JOIN writer_invites wi ON wi.token = ws.token WHERE ws.id=$1', [id]);
    if (!sres.rows.length) return res.status(404).send('Not found');
    const row = sres.rows[0];
    const data = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
    const questions = Array.isArray(data?.questions) ? data.questions : [];
    const warn = [];
    const esc = (v)=>String(v||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
    const qHtml = questions.map((q, i) => {
      const text = String(q.text||'');
      const ask = String(q.ask||'');
      let occ = 0;
      if (ask) {
        const h = text.toLowerCase();
        const n = ask.toLowerCase();
        let idx = 0; while ((idx = h.indexOf(n, idx)) !== -1) { occ++; idx += n.length; }
        if (occ !== 1) warn.push(`Q${i+1}: Ask appears ${occ} times (must be exactly once).`);
      }
      const safeText = esc(text);
      const safeAsk = esc(ask);
      const highlighted = ask && occ === 1 ? safeText.replace(new RegExp(ask.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), 'i'), '<mark>$&</mark>') : safeText;
      return `<div style="border:1px solid #ddd;padding:8px;margin:8px 0;border-radius:6px;">
        <div><strong>Q${i+1}</strong> <em>${esc(q.category||'')}</em></div>
        <div style="margin-top:6px;">${highlighted}</div>
        <div style="margin-top:6px;color:#666;">Answer: <strong>${esc(q.answer||'')}</strong>${ask ? ` · Ask: <code>${safeAsk}</code>` : ''}</div>
      </div>`;
    }).join('');
    const warnHtml = warn.length ? `<div style="background:#fff3cd;color:#664d03;border:1px solid #ffecb5;padding:8px;border-radius:6px;margin:8px 0;">${warn.map(esc).join('<br/>')}</div>` : '';
    
    // Determine if this is a draft (autosave) or actual submission
    const isDraft = !row.invite_submitted_at;
    const statusBadge = isDraft 
      ? '<span style="background:#ff9800;color:#000;padding:4px 8px;border-radius:4px;font-weight:bold;margin-left:8px;">DRAFT</span>'
      : '<span style="background:#4caf50;color:#fff;padding:4px 8px;border-radius:4px;font-weight:bold;margin-left:8px;">SUBMITTED</span>';
    const statusText = isDraft 
      ? `This is a draft (autosaved). The author has not yet clicked "Submit Quiz". Last saved: ${fmtEt(row.updated_at || row.submitted_at)}`
      : `This quiz was submitted by the author on ${fmtEt(row.invite_submitted_at)}.`;
    
    // Get all existing quizzes to show which slots are taken
    const { rows: existingQuizzes } = await pool.query('SELECT unlock_at, title FROM quizzes ORDER BY unlock_at ASC');
    const takenSlots = new Set();
    const slotInfo = new Map(); // Map of "YYYY-MM-DD-AM" or "YYYY-MM-DD-PM" -> quiz title
    for (const q of existingQuizzes) {
      const unlockUtc = new Date(q.unlock_at);
      const p = utcToEtParts(unlockUtc);
      const dateKey = `${p.y}-${String(p.m).padStart(2,'0')}-${String(p.d).padStart(2,'0')}`;
      const half = p.h === 0 ? 'AM' : 'PM';
      const slotKey = `${dateKey}-${half}`;
      takenSlots.add(slotKey);
      slotInfo.set(slotKey, q.title);
    }
    
    // Calculate unlock_at from slot_date and slot_half if available
    let unlockAtValue = '';
    if (req.query && req.query.unlock) {
      unlockAtValue = String(req.query.unlock).replace(' ','T');
    } else if (row.slot_date && row.slot_half) {
      // slot_date might be a Date object or string (YYYY-MM-DD)
      // Normalize to YYYY-MM-DD string format
      let dateStr = '';
      if (row.slot_date instanceof Date) {
        const year = row.slot_date.getFullYear();
        const month = String(row.slot_date.getMonth() + 1).padStart(2, '0');
        const day = String(row.slot_date.getDate()).padStart(2, '0');
        dateStr = `${year}-${month}-${day}`;
      } else {
        // Already a string, use it directly
        dateStr = String(row.slot_date).trim();
        // If it's in a different format, try to parse it
        if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
          const d = new Date(dateStr);
          if (!isNaN(d.getTime())) {
            const year = d.getFullYear();
            const month = String(d.getMonth() + 1).padStart(2, '0');
            const day = String(d.getDate()).padStart(2, '0');
            dateStr = `${year}-${month}-${day}`;
          }
        }
      }
      
      // Normalize slot_half: trim whitespace and convert to uppercase
      const slotHalf = String(row.slot_half || '').trim().toUpperCase();
      // AM = 00:00, PM = 12:00 in Eastern Time
      const hour = (slotHalf === 'AM') ? '00' : '12';
      unlockAtValue = `${dateStr}T${hour}:00`;
      console.log(`[preview] Auto-filled unlock_at: ${unlockAtValue} from slot_date=${row.slot_date} (formatted: ${dateStr}), slot_half=${row.slot_half} (normalized: ${slotHalf})`);
    } else {
      console.log(`[preview] No slot data to auto-fill. slot_date=${row.slot_date}, slot_half=${row.slot_half}`);
    }
    
    // Build calendar grid for slot selection (Dec 1-24, AM/PM)
    const currentYear = new Date().getFullYear();
    const calendarSlots = [];
    for (let d = 1; d <= 24; d++) {
      const dateStr = `${currentYear}-12-${String(d).padStart(2,'0')}`;
      for (const half of ['AM', 'PM']) {
        const slotKey = `${dateStr}-${half}`;
        const isTaken = takenSlots.has(slotKey);
        const existingTitle = slotInfo.get(slotKey) || '';
        const hour = half === 'AM' ? '00' : '12';
        const datetimeValue = `${dateStr}T${hour}:00`;
        calendarSlots.push({
          date: dateStr,
          day: d,
          half,
          isTaken,
          existingTitle,
          datetimeValue
        });
      }
    }
    
    // Build calendar HTML - only show if no assigned slot (for manual selection)
    const hasAssignedSlot = row.slot_date && row.slot_half;
    let calendarHtml = '';
    
    if (!hasAssignedSlot) {
      // Only show calendar if there's no assigned slot (for manual selection)
      calendarHtml = `
        <div style="margin-top:24px;background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:16px;">
          <h3 style="margin-top:0;color:#ffd700;">Select Timeslot</h3>
          <p style="opacity:0.8;font-size:14px;margin-bottom:16px;">Click an available slot to auto-fill the unlock time. Green = available, Red = taken.</p>
          <style>
            @media (max-width: 768px) {
              .slot-calendar-grid { grid-template-columns: repeat(3, 1fr) !important; gap: 6px !important; }
              .slot-calendar-item { padding: 6px !important; font-size: 11px !important; }
              .slot-calendar-day { font-size: 11px !important; }
              .slot-calendar-half { font-size: 10px !important; }
              .slot-calendar-status { font-size: 8px !important; }
            }
            @media (max-width: 480px) {
              .slot-calendar-grid { grid-template-columns: repeat(2, 1fr) !important; gap: 4px !important; }
              .slot-calendar-item { padding: 4px !important; font-size: 10px !important; }
            }
          </style>
          <div class="slot-calendar-grid" style="display:grid;grid-template-columns:repeat(6,1fr);gap:8px;max-width:900px;">
            ${calendarSlots.map(slot => {
              const slotId = `slot-${slot.date}-${slot.half}`;
              const slotKey = `${slot.date}-${slot.half}`;
              const bgColor = slot.isTaken ? '#4a1a1a' : '#1a4a1a';
              const borderColor = slot.isTaken ? '#ff4444' : '#44ff44';
              const cursor = slot.isTaken ? 'not-allowed' : 'pointer';
              const title = slot.isTaken ? `Taken: ${esc(slot.existingTitle)}` : `Available: Dec ${slot.day} ${slot.half}`;
              return `
                <div 
                  id="${slotId}"
                  class="slot-btn-calendar slot-calendar-item"
                  data-datetime="${slot.datetimeValue}"
                  data-taken="${slot.isTaken}"
                  style="
                    background:${bgColor};
                    border:2px solid ${borderColor};
                    border-radius:6px;
                    padding:8px;
                    text-align:center;
                    cursor:${cursor};
                    opacity:${slot.isTaken ? 0.6 : 1};
                    transition:all 0.2s;
                  "
                  title="${title}"
                  onclick="${slot.isTaken ? '' : `document.getElementById('unlock_at_input').value='${slot.datetimeValue}'; document.querySelectorAll('.slot-btn-calendar').forEach(el=>{if(el.dataset.taken!=='true'){el.style.transform='scale(1)';el.style.boxShadow='none';}}); this.style.transform='scale(1.05)'; this.style.boxShadow='0 0 8px ${borderColor}';`}"
                  onmouseover="${slot.isTaken ? '' : 'this.style.opacity=1;this.style.transform=\'scale(1.02)\';'}"
                  onmouseout="${slot.isTaken ? '' : 'this.style.opacity=1;this.style.transform=\'scale(1)\';'}"
                >
                  <div class="slot-calendar-day" style="font-weight:bold;color:#ffd700;font-size:12px;">Dec ${slot.day}</div>
                  <div class="slot-calendar-half" style="font-size:11px;color:${slot.isTaken ? '#ff8888' : '#88ff88'};margin-top:4px;">${slot.half}</div>
                  ${slot.isTaken 
                    ? '<div class="slot-calendar-status" style="font-size:9px;color:#ff8888;margin-top:2px;">TAKEN</div>' 
                    : '<div class="slot-calendar-status" style="font-size:9px;color:#88ff88;margin-top:2px;">FREE</div>'
                  }
                </div>
              `;
            }).join('')}
          </div>
        </div>
      `;
    }
    
    // Normalize assignedSlotKey for client-side validation (even if calendar is hidden)
    let assignedSlotKey = null;
    if (hasAssignedSlot) {
      let dateStr = '';
      if (row.slot_date instanceof Date) {
        dateStr = `${row.slot_date.getUTCFullYear()}-${String(row.slot_date.getUTCMonth() + 1).padStart(2,'0')}-${String(row.slot_date.getUTCDate()).padStart(2,'0')}`;
      } else {
        dateStr = String(row.slot_date).trim();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
          const d = new Date(dateStr);
          if (!isNaN(d.getTime())) {
            dateStr = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2,'0')}-${String(d.getUTCDate()).padStart(2,'0')}`;
          }
        }
      }
      const half = String(row.slot_half || '').trim().toUpperCase();
      assignedSlotKey = `${dateStr}-${half}`;
    }
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead(`Preview Submission #${id}`, false)}
      <body class="ta-body" style="padding:24px;">
      ${header}
        <h1>Submission #${id} Preview ${statusBadge}</h1>
        <div style="margin:12px 0;padding:8px;background:${isDraft ? 'rgba(255,152,0,0.1)' : 'rgba(76,175,80,0.1)'};border-left:3px solid ${isDraft ? '#ff9800' : '#4caf50'};border-radius:4px;">
          ${statusText}
        </div>
        <div>Author: <strong>${esc(row.author||'')}</strong></div>
        ${row.slot_date && row.slot_half ? `
          <div style="margin:12px 0;padding:12px;background:rgba(76,175,80,0.15);border:2px solid #4caf50;border-radius:6px;">
            <div style="font-weight:bold;color:#4caf50;font-size:16px;margin-bottom:4px;">✓ Assigned Slot</div>
            <div style="color:#ffd700;font-size:18px;"><strong>${row.slot_date} ${row.slot_half}</strong> ET</div>
            <div style="color:#aaa;font-size:13px;margin-top:4px;">This quiz is pre-assigned to this timeslot. The unlock time has been auto-filled below.</div>
          </div>
        ` : `
          <div style="margin:12px 0;padding:12px;background:rgba(255,152,0,0.15);border:2px solid #ff9800;border-radius:6px;">
            <div style="font-weight:bold;color:#ff9800;font-size:16px;margin-bottom:4px;">⚠ No Slot Assigned</div>
            <div style="color:#ccc;font-size:14px;">This writer invite was not assigned a specific slot. Please select a timeslot from the calendar below.</div>
          </div>
        `}
        <div>First saved: ${fmtEt(row.submitted_at)}${row.updated_at ? ` · Last updated: ${fmtEt(row.updated_at)}` : ''}</div>
        ${data.description ? `<h3 style="margin-top:12px;">About this quiz</h3><div>${esc(data.description)}</div>` : ''}
        ${data.author_blurb ? `<h3 style="margin-top:12px;">About the author</h3><div>${esc(data.author_blurb)}</div>` : ''}
        ${warnHtml}
        <h3 style="margin-top:12px;">Questions</h3>
        ${qHtml || '<div>No questions.</div>'}
        ${calendarHtml}
        <form method="post" action="/admin/writer-submissions/${id}/publish" id="publishForm" style="margin-top:24px;">
          <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:flex-end;">
            <div style="flex:1;min-width:300px;">
              <label style="display:block;margin-bottom:6px;font-weight:600;">Title</label>
              <input name="title" required value="${esc(generateDefaultTitle(row, data, unlockAtValue))}" style="width:100%;padding:8px;border-radius:6px;border:1px solid #555;background:#0a0a0a;color:#ffd700;"/>
            </div>
            <div style="flex:1;min-width:250px;">
              <label style="display:block;margin-bottom:6px;font-weight:600;">Unlock (ET)</label>
              <input id="unlock_at_input" name="unlock_at" type="datetime-local" required value="${unlockAtValue}" style="width:100%;padding:8px;border-radius:6px;border:1px solid #555;background:#0a0a0a;color:#ffd700;"/>
            </div>
            <div>
              <button type="submit" class="ta-btn ta-btn-primary" style="margin:0;">Publish Quiz</button>
            </div>
          </div>
          <div id="slotError" style="display:none;margin-top:12px;padding:8px;background:#4a1a1a;border:1px solid #ff4444;border-radius:6px;color:#ff8888;"></div>
        </form>
        <p style="margin-top:16px;"><a href="/admin/writer-submissions" class="ta-btn ta-btn-outline">Back</a></p>
        <script>
          (function() {
            const form = document.getElementById('publishForm');
            const unlockInput = document.getElementById('unlock_at_input');
            const errorDiv = document.getElementById('slotError');
            const takenSlotsData = ${JSON.stringify(Array.from(takenSlots))};
            const takenSlots = new Set(takenSlotsData);
            const assignedSlotKey = ${hasAssignedSlot ? JSON.stringify(assignedSlotKey) : 'null'};
            
            // Check if selected slot is taken
            function checkSlot() {
              const value = unlockInput.value;
              if (!value) {
                errorDiv.style.display = 'none';
                return true;
              }
              // Convert datetime-local to slot key (format: YYYY-MM-DD-AM or YYYY-MM-DD-PM)
              const parts = value.split('T');
              const datePart = parts[0]; // Already in YYYY-MM-DD format
              const timePart = parts[1] || '00:00';
              const hour = parseInt(timePart.split(':')[0]);
              const half = hour === 0 ? 'AM' : 'PM';
              const slotKey = datePart + '-' + half;
              
              // Debug logging
              console.log('[client] Checking slot:', { value, datePart, hour, half, slotKey, assignedSlotKey, match: slotKey === assignedSlotKey, isTaken: takenSlots.has(slotKey) });
              
              // Allow the slot if it's the assigned slot, even if it's taken
              if (assignedSlotKey && slotKey === assignedSlotKey) {
                console.log('[client] Allowing assigned slot even though it may be taken');
                errorDiv.style.display = 'none';
                return true;
              }
              
              if (takenSlots.has(slotKey)) {
                errorDiv.innerHTML = '⚠️ This timeslot is already taken! Please select a different slot from the calendar above.';
                errorDiv.style.display = 'block';
                return false;
              } else {
                errorDiv.style.display = 'none';
                return true;
              }
            }
            
            unlockInput.addEventListener('change', checkSlot);
            unlockInput.addEventListener('input', checkSlot);
            
            form.addEventListener('submit', function(e) {
              if (!checkSlot()) {
                e.preventDefault();
                unlockInput.focus();
                return false;
              }
            });
            
            // Highlight selected slot in calendar
            unlockInput.addEventListener('change', function() {
              const value = unlockInput.value;
              if (!value) return;
              const parts = value.split('T');
              const datePart = parts[0];
              const timePart = parts[1] || '00:00';
              const hour = parseInt(timePart.split(':')[0]);
              const half = hour === 0 ? 'AM' : 'PM';
              const slotId = 'slot-' + datePart + '-' + half;
              
              document.querySelectorAll('.slot-btn-calendar').forEach(function(el) {
                if (el.dataset.taken !== 'true') {
                  el.style.transform = 'scale(1)';
                  el.style.boxShadow = 'none';
                }
              });
              
              const selectedSlot = document.getElementById(slotId);
              if (selectedSlot && selectedSlot.dataset.taken !== 'true') {
                selectedSlot.style.transform = 'scale(1.05)';
                selectedSlot.style.boxShadow = '0 0 8px #44ff44';
              }
            });
          })();
        </script>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load preview');
  }
});
app.post('/admin/writer-submissions/:id/publish', requireAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const title = String(req.body.title || '').trim();
    const unlockInput = String(req.body.unlock_at || '').trim();
    if (!id || !title || !unlockInput) return res.status(400).send('Missing fields');
    const sres = await pool.query('SELECT token, data, author FROM writer_submissions WHERE id=$1', [id]);
    if (!sres.rows.length) return res.status(404).send('Submission not found');
    const data = typeof sres.rows[0].data === 'string' ? JSON.parse(sres.rows[0].data) : sres.rows[0].data;
    const questions = Array.isArray(data?.questions) ? data.questions : [];
    if (!questions.length) return res.status(400).send('Submission has no questions');
    const unlockUtc = etToUtc(unlockInput);
    const tok = sres.rows[0] && sres.rows[0].token;
    let authorEmail = null;
    let assignedSlotDate = null;
    let assignedSlotHalf = null;
    if (tok) {
      try {
        const { rows: inviteRows } = await pool.query('SELECT email, slot_date, slot_half FROM writer_invites WHERE token=$1', [tok]);
        if (inviteRows.length) {
          if (inviteRows[0].email) {
            const email = String(inviteRows[0].email || '').trim().toLowerCase();
            if (email) authorEmail = email;
          }
          assignedSlotDate = inviteRows[0].slot_date;
          assignedSlotHalf = inviteRows[0].slot_half;
        }
      } catch (e) {
        console.error('[publish] Error retrieving writer invite:', e);
      }
    }
    // Check if this unlock time matches the assigned slot
    const unlockEt = utcToEtParts(unlockUtc);
    const unlockDateStr = `${unlockEt.y}-${String(unlockEt.m).padStart(2,'0')}-${String(unlockEt.d).padStart(2,'0')}`;
    const unlockHalf = unlockEt.h === 0 ? 'AM' : 'PM';
    let isAssignedSlot = false;
    if (assignedSlotDate && assignedSlotHalf) {
      // Normalize assignedSlotDate to YYYY-MM-DD string
      // slot_date from PostgreSQL DATE type can come as a Date object or string
      let assignedDateStr = '';
      if (assignedSlotDate instanceof Date) {
        // Date object - use UTC methods to avoid timezone issues
        assignedDateStr = `${assignedSlotDate.getUTCFullYear()}-${String(assignedSlotDate.getUTCMonth() + 1).padStart(2,'0')}-${String(assignedSlotDate.getUTCDate()).padStart(2,'0')}`;
      } else {
        // String - could be YYYY-MM-DD or other format
        assignedDateStr = String(assignedSlotDate).trim();
        // If it's not already YYYY-MM-DD, try to parse it
        if (!/^\d{4}-\d{2}-\d{2}$/.test(assignedDateStr)) {
          // Try parsing as ISO date string or other format
          const d = new Date(assignedDateStr);
          if (!isNaN(d.getTime())) {
            // Use UTC to avoid timezone shifts
            assignedDateStr = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2,'0')}-${String(d.getUTCDate()).padStart(2,'0')}`;
          } else {
            console.error(`[publish] Could not parse assignedSlotDate: ${assignedSlotDate}`);
          }
        }
      }
      const assignedHalf = String(assignedSlotHalf || '').trim().toUpperCase();
      isAssignedSlot = (assignedDateStr === unlockDateStr && assignedHalf === unlockHalf);
      console.log(`[publish] Slot check: assigned=${assignedDateStr} ${assignedHalf}, unlock=${unlockDateStr} ${unlockHalf}, match=${isAssignedSlot}`);
      console.log(`[publish] Raw assignedSlotDate type: ${typeof assignedSlotDate}, value: ${assignedSlotDate}`);
      console.log(`[publish] Raw assignedSlotHalf: ${assignedSlotHalf}`);
    } else {
      console.log(`[publish] No assigned slot data: slot_date=${assignedSlotDate}, slot_half=${assignedSlotHalf}`);
    }
    // Enforce unique slot: prevent duplicate unlock_at
    // BUT: if the existing quiz has the same author_email OR same author name OR this is the writer's assigned slot, allow it
    const dupe = await pool.query('SELECT id, title, author, author_email FROM quizzes WHERE unlock_at=$1 LIMIT 1', [unlockUtc]);
    if (dupe.rows.length) {
      const existingQuiz = dupe.rows[0];
      const existingAuthorEmail = (existingQuiz.author_email || '').toLowerCase();
      const existingAuthorName = (existingQuiz.author || '').trim().toLowerCase();
      const submissionAuthorName = (sres.rows[0].author || '').trim().toLowerCase();
      
      // Check if this is the same writer's quiz by email OR by author name OR if this is their assigned slot
      const emailMatch = authorEmail && existingAuthorEmail && authorEmail === existingAuthorEmail;
      const nameMatch = submissionAuthorName && existingAuthorName && submissionAuthorName === existingAuthorName;
      
      console.log(`[publish] Duplicate slot check: existing quiz ${existingQuiz.id}, author_email match: ${emailMatch}, author name match: ${nameMatch}, is assigned slot: ${isAssignedSlot}`);
      console.log(`[publish] Submission author: "${sres.rows[0].author}", email: ${authorEmail || 'none'}`);
      console.log(`[publish] Existing quiz author: "${existingQuiz.author}", email: ${existingAuthorEmail || 'none'}`);
      
      // If author emails match OR author names match OR this is the writer's assigned slot, allow updating the existing quiz
      if (emailMatch || nameMatch || isAssignedSlot) {
        console.log(`[publish] Found existing quiz ${existingQuiz.id} at same slot with matching author. Updating instead of creating new.`);
        // Update existing quiz instead of creating new one
        const freezeUtc = new Date(unlockUtc.getTime() + 24*60*60*1000);
        const authorBlurb = (data && typeof data.author_blurb !== 'undefined') ? (String(data.author_blurb || '').trim() || null) : null;
        const description = (data && typeof data.description !== 'undefined') ? (String(data.description || '').trim() || null) : null;
        // Update author_email if we have it and the existing quiz doesn't
        const updateAuthorEmail = authorEmail && !existingAuthorEmail ? authorEmail : existingQuiz.author_email;
        await pool.query(
          'UPDATE quizzes SET title=$1, freeze_at=$2, author=$3, author_blurb=$4, description=$5, author_email=$6 WHERE id=$7',
          [title, freezeUtc, sres.rows[0].author || null, authorBlurb, description, updateAuthorEmail, existingQuiz.id]
        );
        // Delete old questions and insert new ones
        await pool.query('DELETE FROM questions WHERE quiz_id=$1', [existingQuiz.id]);
        for (let i=0;i<Math.min(10, questions.length);i++) {
          const q = questions[i];
          const text = String(q.text || '').trim();
          const answer = String(q.answer || '').trim();
          const category = String(q.category || 'General').trim();
          const ask = (q.ask && String(q.ask).trim()) || null;
          if (!text || !answer) continue;
          await pool.query(
            'INSERT INTO questions(quiz_id, number, text, answer, category, ask) VALUES($1,$2,$3,$4,$5,$6)',
            [existingQuiz.id, i+1, text, answer, category, ask]
          );
        }
        // mark published and deactivate token
        try {
          if (tok) await pool.query('UPDATE writer_invites SET published_at = NOW(), active = FALSE WHERE token=$1', [tok]);
        } catch {}
        res.redirect(`/quiz/${existingQuiz.id}`);
        return;
      }
      // Different author or no author match - block duplicate slot
      const unlockEt = utcToEtParts(unlockUtc);
      const dateStr = `${unlockEt.y}-${String(unlockEt.m).padStart(2,'0')}-${String(unlockEt.d).padStart(2,'0')}`;
      const timeStr = unlockEt.h === 0 ? 'Midnight (AM)' : 'Noon (PM)';
      const existingTitle = existingQuiz.title || 'Untitled Quiz';
      const esc = (v) => String(v || '').replace(/&/g,'&amp;').replace(/</g,'&lt;');
      const header = await renderHeader(req);
      return res.status(400).send(`
        ${renderHead('Timeslot Already Taken', false)}
        <body class="ta-body" style="padding:24px;">
        ${header}
          <div style="background:#4a1a1a;border:2px solid #ff4444;border-radius:8px;padding:20px;max-width:600px;margin:40px auto;">
            <h1 style="color:#ff8888;margin-top:0;">⚠️ Timeslot Already Taken</h1>
            <p style="color:#ffd700;font-size:18px;margin:16px 0;"><strong>Date:</strong> ${dateStr} at ${timeStr} ET</p>
            <p style="color:#ccc;margin:16px 0;"><strong>Existing Quiz:</strong> "${esc(existingTitle)}" (ID: ${existingQuiz.id})</p>
            <p style="color:#ff8888;margin-top:24px;">Please select a different timeslot from the calendar.</p>
            <div style="margin-top:24px;">
              <a href="/admin/writer-submissions/${id}" class="ta-btn ta-btn-primary">← Go Back</a>
            </div>
          </div>
        </body></html>
      `);
    }
    const freezeUtc = new Date(unlockUtc.getTime() + 24*60*60*1000);
    const authorBlurb = (data && typeof data.author_blurb !== 'undefined') ? (String(data.author_blurb || '').trim() || null) : null;
    const description = (data && typeof data.description !== 'undefined') ? (String(data.description || '').trim() || null) : null;
    const qInsert = await pool.query(
      'INSERT INTO quizzes(title, unlock_at, freeze_at, author, author_blurb, description, author_email) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [title, unlockUtc, freezeUtc, sres.rows[0].author || null, authorBlurb, description, authorEmail]
    );
    const quizId = qInsert.rows[0].id;
    if (authorEmail) {
      console.log(`[publish] Quiz ${quizId} published with author_email: ${authorEmail}`);
    } else {
      console.log(`[publish] Quiz ${quizId} published WITHOUT author_email (token: ${tok || 'none'})`);
    }
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
      if (tok) await pool.query('UPDATE writer_invites SET published_at = NOW(), active = FALSE WHERE token=$1', [tok]);
    } catch {}
    
    // Send email notification to writer when quiz is published
    if (authorEmail) {
      try {
        const baseUrl = process.env.PUBLIC_BASE_URL || '';
        const quizUrl = `${baseUrl}/quiz/${quizId}`;
        const unlockEt = utcToEtParts(unlockUtc);
        const unlockDateStr = `${unlockEt.y}-${String(unlockEt.m).padStart(2,'0')}-${String(unlockEt.d).padStart(2,'0')} ${String(unlockEt.h).padStart(2,'0')}:${String(unlockEt.et.getUTCMinutes()).padStart(2,'0')} ET`;
        const subject = `Your Quiz Has Been Published: ${title}`;
        const text = `Hi ${sres.rows[0].author || 'there'},\r\n\r\nGreat news! Your quiz "${title}" has been published and is scheduled to unlock on ${unlockDateStr}.\r\n\r\nView your quiz here:\r\n${quizUrl}\r\n\r\nThank you for contributing to Trivia Advent-ure!`;
        await sendPlainEmail(authorEmail, subject, text);
        console.log('[publish] Notification sent to writer:', authorEmail);
      } catch (emailErr) {
        console.error('[publish] Failed to notify writer', authorEmail, ':', emailErr?.message || emailErr);
        // Don't fail the publish if email fails
      }
    }
    
    res.redirect(`/quiz/${quizId}`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to publish submission');
  }
});

// --- Admin: writer invites list with actions ---
app.get('/admin/writer-invites/list', requireAdmin, async (req, res) => {
  try {
    const baseUrl = process.env.PUBLIC_BASE_URL || '';
    const { rows } = await pool.query(
      `SELECT token, author, email, slot_date, slot_half, send_at, sent_at, clicked_at, submitted_at, published_at, active, created_at
       FROM writer_invites
       ORDER BY slot_date NULLS LAST, slot_half NULLS LAST, created_at DESC
       LIMIT 500`
    );
    const fmt = (d) => fmtEt(d);
    const list = rows.map(r => {
      const link = `${baseUrl}/writer/${r.token}`;
      const slotStr = r.slot_date ? (typeof r.slot_date === 'string' ? r.slot_date : new Date(r.slot_date).toISOString().slice(0,10)) : '';
      const status = [
        r.active ? 'active' : 'inactive',
        r.sent_at ? 'sent' : 'not sent',
        r.clicked_at ? 'clicked' : '',
        r.submitted_at ? 'submitted' : '',
        r.published_at ? 'published' : ''
      ].filter(Boolean).join(' · ');
      const esc = (s) => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
      return `
        <tr data-token="${esc(r.token)}">
          <td style="padding:6px 4px;white-space:nowrap;">${slotStr} ${r.slot_half || ''}</td>
          <td style="padding:6px 4px;">${esc(r.author)}</td>
          <td style="padding:6px 4px;">
            <span class="email-display" data-token="${esc(r.token)}">${esc(r.email || '(no email)')}</span>
            <input type="email" class="email-edit" data-token="${esc(r.token)}" value="${esc(r.email || '')}" style="display:none;width:200px;padding:4px;border:1px solid #555;border-radius:4px;background:#2a2a2a;color:#fff;" />
          </td>
          <td style="padding:6px 4px;">${status}</td>
          <td style="padding:6px 4px;"><a href="${link}" target="_blank">${r.token.slice(0,8)}...</a></td>
          <td style="padding:6px 4px;white-space:nowrap;">${fmt(r.sent_at)}</td>
          <td style="padding:6px 4px;white-space:nowrap;">${fmt(r.clicked_at)}</td>
          <td style="padding:6px 4px;white-space:nowrap;">${fmt(r.submitted_at)}</td>
          <td style="padding:6px 4px;white-space:nowrap;">${fmt(r.published_at)}</td>
          <td style="padding:6px 4px;display:flex;gap:6px;flex-wrap:wrap;">
            <button class="edit-email-btn" data-token="${esc(r.token)}" type="button" style="background:#d4af37;color:#000;border:none;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:12px;">Edit Email</button>
            <form method="post" action="/admin/writer-invites/${r.token}/resend" onsubmit="return confirm('Send email now?');" style="display:inline;">
              <button type="submit" style="font-size:12px;">Resend</button>
            </form>
            ${r.active ? `<form method="post" action="/admin/writer-invites/${r.token}/deactivate" onsubmit="return confirm('Deactivate this invite?');" style="display:inline;"><button type="submit" style="font-size:12px;">Deactivate</button></form>` : ''}
            <button class="copy" data-link="${link}" type="button" style="font-size:12px;">Copy</button>
          </td>
        </tr>
      `;
    }).join('');
    const header = await renderHeader(req);
    const adminEmail = getAdminEmail();
    res.type('html').send(`
      ${renderHead('Writer Invites', true)}
      <body class="ta-body" style="padding:24px;">
      ${header}
        <h1>Writer Invites</h1>
        <p>
          <a href="/admin" class="ta-btn ta-btn-outline">Back</a>
          <a href="/admin/writer-invites/my" class="ta-btn ta-btn-primary" style="margin-left:8px;">My Writer Invites</a>
        </p>
        <div style="margin:16px 0;">
          <input type="text" id="searchInput" placeholder="Search by author, email, or token..." style="width:100%;max-width:400px;padding:8px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;" />
        </div>
        <table id="invitesTable" style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="text-align:left;border-bottom:1px solid #444;">
              <th style="padding:6px 4px;">Slot</th>
              <th style="padding:6px 4px;">Author</th>
              <th style="padding:6px 4px;">Email</th>
              <th style="padding:6px 4px;">Status</th>
              <th style="padding:6px 4px;">Token/Link</th>
              <th style="padding:6px 4px;">Sent</th>
              <th style="padding:6px 4px;">Clicked</th>
              <th style="padding:6px 4px;">Submitted</th>
              <th style="padding:6px 4px;">Published</th>
              <th style="padding:6px 4px;">Actions</th>
            </tr>
          </thead>
          <tbody>${list || ''}</tbody>
        </table>
        <script src="/js/writer-invites-list.js"></script>
        <script>
          (function() {
            const searchInput = document.getElementById('searchInput');
            const table = document.getElementById('invitesTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            searchInput.addEventListener('input', function(e) {
              const query = e.target.value.toLowerCase().trim();
              rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = query === '' || text.includes(query) ? '' : 'none';
              });
            });
            
            // Email editing functionality
            document.querySelectorAll('.edit-email-btn').forEach(function(btn) {
              btn.addEventListener('click', function() {
                const token = this.getAttribute('data-token');
                const row = this.closest('tr');
                const display = row.querySelector('.email-display[data-token="' + token + '"]');
                const input = row.querySelector('.email-edit[data-token="' + token + '"]');
                
                if (display.style.display === 'none') {
                  // Currently editing - save
                  const newEmail = input.value.trim();
                  if (newEmail && !newEmail.match(/^[^@]+@[^@]+\.[^@]+$/)) {
                    alert('Please enter a valid email address');
                    return;
                  }
                  
                  btn.disabled = true;
                  btn.textContent = 'Saving...';
                  
                  fetch('/admin/writer-invites/' + token + '/update-email', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'email=' + encodeURIComponent(newEmail || '')
                  })
                  .then(function(r) {
                    if (r.ok) {
                      display.textContent = newEmail || '(no email)';
                      display.style.display = '';
                      input.style.display = 'none';
                      btn.textContent = 'Edit Email';
                    } else {
                      return r.text().then(function(text) {
                        throw new Error(text || 'Failed to update');
                      });
                    }
                  })
                  .catch(function(err) {
                    alert('Failed to update email: ' + (err.message || err));
                    btn.textContent = 'Edit Email';
                  })
                  .finally(function() {
                    btn.disabled = false;
                  });
                } else {
                  // Start editing
                  display.style.display = 'none';
                  input.style.display = 'inline-block';
                  input.focus();
                  input.select();
                  btn.textContent = 'Save';
                }
              });
            });
            
            // Allow Enter key to save, Escape to cancel
            document.querySelectorAll('.email-edit').forEach(function(input) {
              input.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  const token = this.getAttribute('data-token');
                  const btn = this.closest('tr').querySelector('.edit-email-btn[data-token="' + token + '"]');
                  if (btn) btn.click();
                } else if (e.key === 'Escape') {
                  e.preventDefault();
                  const token = this.getAttribute('data-token');
                  const row = this.closest('tr');
                  const display = row.querySelector('.email-display[data-token="' + token + '"]');
                  const btn = row.querySelector('.edit-email-btn[data-token="' + token + '"]');
                  display.style.display = '';
                  this.style.display = 'none';
                  this.value = display.textContent === '(no email)' ? '' : display.textContent;
                  btn.textContent = 'Edit Email';
                }
              });
            });
          })();
        </script>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load invites');
  }
});

app.post('/admin/writer-invites/:token/resend', requireAdmin, async (req, res) => {
  try {
    const token = String(req.params.token || '').trim();
    const { rows } = await pool.query('SELECT token, author, email, slot_date, slot_half FROM writer_invites WHERE token=$1', [token]);
    if (!rows.length) {
      return res.status(404).send('Invite not found');
    }
    if (!rows[0].email) {
      return res.status(400).send('Invite has no email address');
    }
    
    const email = rows[0].email;
    const author = rows[0].author;
    
    // Ensure author is in players table before resending
    try {
      await ensureAuthorIsPlayer(email);
    } catch (e) {
      console.error('[resend] Error ensuring author is player:', e);
      // Continue anyway - not critical
    }
    
    const baseUrl = process.env.PUBLIC_BASE_URL || '';
    const link = `${baseUrl}/writer/${rows[0].token}`;
    
    try {
      await sendWriterInviteEmail(email, author, link, rows[0].slot_date, rows[0].slot_half);
      await pool.query('UPDATE writer_invites SET sent_at = NOW() WHERE token=$1', [token]);
      // Check if this is an AJAX request (from the "Send now" button)
      if (req.headers['x-requested-with'] === 'XMLHttpRequest' || req.headers.accept?.includes('application/json')) {
        return res.json({ success: true, message: 'Email sent successfully' });
      }
      res.redirect('/admin/writer-invites/list?msg=Email sent successfully');
    } catch (emailError) {
      console.error('[resend] Email send error for', email, ':', emailError);
      const errorMsg = emailError?.message || String(emailError);
      let userMessage = `Failed to send email: ${errorMsg}`;
      
      // Check for common Gmail API errors
      if (errorMsg.includes('Gmail OAuth credentials not configured')) {
        userMessage = 'Email not configured. Please check Gmail OAuth credentials.';
      } else if (errorMsg.includes('invalid_grant') || errorMsg.includes('unauthorized')) {
        userMessage = 'Gmail authentication failed. Please refresh the OAuth token.';
      } else if (errorMsg.includes('quota') || errorMsg.includes('rate limit')) {
        userMessage = 'Gmail rate limit exceeded. Please try again later.';
      }
      
      // Check if this is an AJAX request (from the "Send now" button)
      if (req.headers['x-requested-with'] === 'XMLHttpRequest' || req.headers.accept?.includes('application/json')) {
        return res.status(500).json({ success: false, error: userMessage });
      }
      return res.status(500).send(userMessage);
    }
  } catch (e) {
    console.error('[resend] Unexpected error:', e);
    res.status(500).send(`Failed to resend: ${e?.message || String(e)}`);
  }
});

app.post('/admin/writer-invites/:token/deactivate', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE writer_invites SET active = FALSE WHERE token=$1', [req.params.token]);
    res.redirect('/admin/writer-invites/list');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to deactivate');
  }
});

app.post('/admin/writer-invites/:token/update-email', requireAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const token = String(req.params.token || '').trim();
    const newEmail = String(req.body.email || '').trim() || null;
    
    // Validate email format if provided
    if (newEmail && !newEmail.match(/^[^@]+@[^@]+\.[^@]+$/)) {
      return res.status(400).send('Invalid email format');
    }
    
    // Check if invite exists
    const { rows } = await pool.query('SELECT email FROM writer_invites WHERE token=$1', [token]);
    if (!rows.length) {
      return res.status(404).send('Invite not found');
    }
    
    const oldEmail = rows[0].email;
    
    // Update the email
    await pool.query('UPDATE writer_invites SET email=$1 WHERE token=$2', [newEmail, token]);
    
    // If new email is provided and different, ensure they're in players table
    if (newEmail && newEmail.toLowerCase() !== (oldEmail || '').toLowerCase()) {
      try {
        await ensureAuthorIsPlayer(newEmail);
      } catch (e) {
        console.error('[update-email] Error ensuring author is player:', e);
        // Continue anyway - not critical
      }
    }
    
    res.status(200).send('Email updated');
  } catch (e) {
    console.error('[update-email] Error:', e);
    res.status(500).send('Failed to update email: ' + (e?.message || String(e)));
  }
});

// --- Admin: My Writer Invites (shows invites for logged-in admin) ---
app.get('/admin/writer-invites/my', requireAdmin, async (req, res) => {
  try {
    // Get the logged-in user's email from session
    const userEmail = req.session.user ? (req.session.user.email || '').toLowerCase() : '';
    if (!userEmail) {
      return res.status(400).send('Unable to determine your email address');
    }
    const baseUrl = process.env.PUBLIC_BASE_URL || '';
    const { rows } = await pool.query(
      `SELECT token, author, email, slot_date, slot_half, send_at, sent_at, clicked_at, submitted_at, published_at, active, created_at
       FROM writer_invites
       WHERE LOWER(email) = $1
       ORDER BY slot_date NULLS LAST, slot_half NULLS LAST, created_at DESC
       LIMIT 100`,
      [userEmail]
    );
    
    if (rows.length === 0) {
      const header = await renderHeader(req);
      res.type('html').send(`
        ${renderHead('My Writer Invites • Admin', true)}
        <body class="ta-body">
          ${header}
          <main class="ta-main ta-container" style="max-width:900px;">
            <h1 class="ta-page-title">My Writer Invites</h1>
            <p style="margin-bottom:24px;"><a href="/admin" class="ta-btn ta-btn-outline">← Back to Admin</a></p>
            <div style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:24px;text-align:center;">
              <p style="font-size:18px;margin:0;">You don't have any writer invites yet.</p>
              <p style="margin-top:16px;"><a href="/admin/writer-invite" class="ta-btn ta-btn-primary">Create Writer Invite</a></p>
            </div>
          </main>
          ${renderFooter(req)}
        </body></html>
      `);
      return;
    }
    
    const fmt = (d) => d ? fmtEt(d) : '';
    const list = rows.map(r => {
      const link = `${baseUrl}/writer/${r.token}`;
      const slotStr = r.slot_date ? (typeof r.slot_date === 'string' ? r.slot_date : new Date(r.slot_date).toISOString().slice(0,10)) : '';
      const status = [
        r.active ? 'active' : 'inactive',
        r.sent_at ? 'sent' : 'not sent',
        r.clicked_at ? 'clicked' : '',
        r.submitted_at ? 'submitted' : '',
        r.published_at ? 'published' : ''
      ].filter(Boolean).join(' · ');
      return `
        <tr>
          <td style="padding:8px;">${slotStr} ${r.slot_half || ''}</td>
          <td style="padding:8px;">${(r.author || '').replace(/</g,'&lt;')}</td>
          <td style="padding:8px;">${status}</td>
          <td style="padding:8px;"><a href="${link}" target="_blank" class="ta-btn ta-btn-small">Open Quiz Form</a></td>
          <td style="padding:8px;white-space:nowrap;">${fmt(r.submitted_at)}</td>
          <td style="padding:8px;white-space:nowrap;">${fmt(r.published_at)}</td>
        </tr>
      `;
    }).join('');
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('My Writer Invites • Admin', true)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container" style="max-width:900px;">
          <h1 class="ta-page-title">My Writer Invites</h1>
          <p style="margin-bottom:24px;">
            <a href="/admin" class="ta-btn ta-btn-outline">← Back to Admin</a>
            <a href="/admin/writer-invite" class="ta-btn ta-btn-primary" style="margin-left:8px;">Create New Invite</a>
          </p>
          
          <div style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:16px;margin-bottom:24px;">
            <p style="margin:0;opacity:0.9;">These are your writer invites. Click "Open Quiz Form" to access your quiz writing interface.</p>
          </div>
          
          <table style="width:100%;border-collapse:collapse;background:#1a1a1a;border:1px solid #333;border-radius:8px;overflow:hidden;">
            <thead>
              <tr style="text-align:left;border-bottom:1px solid #444;background:#2a2a2a;">
                <th style="padding:12px 8px;">Slot</th>
                <th style="padding:12px 8px;">Author</th>
                <th style="padding:12px 8px;">Status</th>
                <th style="padding:12px 8px;">Link</th>
                <th style="padding:12px 8px;">Submitted</th>
                <th style="padding:12px 8px;">Published</th>
              </tr>
            </thead>
            <tbody>${list || ''}</tbody>
          </table>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error('Error loading my writer invites:', e);
    res.status(500).send('Failed to load invites');
  }
});

// --- Quiz autosave ---
app.post('/quiz/:id/autosave', requireAuth, express.json(), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const email = (req.session.user.email || '').toLowerCase();
    const { rows: qMeta } = await pool.query('SELECT author_email FROM quizzes WHERE id=$1', [id]);
    if (!qMeta.length) return res.status(404).json({ error: 'Quiz not found' });
    const authorEmail = (qMeta[0].author_email || '').toLowerCase();
    if (authorEmail && authorEmail === email) {
      return res.status(403).json({ error: 'Quiz authors cannot submit answers for their own quiz.' });
    }
    const { locked, answers } = req.body;
    
    // Save answers - only save non-empty responses or update existing ones
    for (const [qNum, answerText] of Object.entries(answers || {})) {
      const trimmedText = String(answerText || '').trim();
      const { rows: qRows } = await pool.query('SELECT id FROM questions WHERE quiz_id=$1 AND number=$2', [id, Number(qNum)]);
      if (qRows.length > 0) {
        const questionId = qRows[0].id;
        // Check if a response already exists
        const { rows: existing } = await pool.query(
          'SELECT response_text FROM responses WHERE quiz_id=$1 AND question_id=$2 AND user_email=$3',
          [id, questionId, email]
        );
        
        // Only create/update if there's content OR if a response already exists (to allow clearing)
        if (trimmedText || existing.length > 0) {
        await pool.query(
            'INSERT INTO responses (quiz_id, question_id, user_email, response_text, locked) VALUES ($1, $2, $3, $4, false) ON CONFLICT (user_email, question_id) DO UPDATE SET response_text=$4, created_at=CASE WHEN $4 != \'\' THEN NOW() ELSE responses.created_at END',
            [id, questionId, email, trimmedText]
        );
        }
      }
    }
    
    // Update locked question
    if (locked) {
      const lockedId = Number(locked);
      // Unlock all questions for this user/quiz
      await pool.query('UPDATE responses SET locked=false WHERE quiz_id=$1 AND user_email=$2', [id, email]);
      // Lock the selected question
      await pool.query('UPDATE responses SET locked=true WHERE quiz_id=$1 AND question_id=$2 AND user_email=$3', [id, lockedId, email]);
    }
    
    res.json({ success: true });
  } catch (e) {
    console.error('Autosave error:', e);
    res.status(500).json({ error: 'Failed to save' });
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
    const isAdmin = await isAdminUser(req);
    const previewAsPlayer = req.query.preview === 'player' && isAdmin; // Admin can preview as player
    // In preview mode, simulate the quiz as unlocked so admin can see what players will see
    const locked = previewAsPlayer ? false : (nowUtc < unlockUtc);
    const status = locked ? 'Locked' : (nowUtc >= freezeUtc ? 'Finalized' : 'Unlocked');
    const loggedIn = !!req.session.user || req.session.isAdmin === true;
    const email = String(req.session.user ? (req.session.user.email || '') : (req.session.isAdmin === true ? getAdminEmail() : '')).toLowerCase();
    let existingMap = new Map();
    let existingLockedId = null;
    const quizAuthorEmail = (quiz.author_email || '').toLowerCase();
    const isAuthor = !!quizAuthorEmail && !!email && quizAuthorEmail === email;
    // In preview mode, treat admin as a regular logged-in player (not author)
    const effectiveIsAuthor = previewAsPlayer ? false : isAuthor;
    const effectiveLoggedIn = previewAsPlayer ? true : loggedIn;
    if (effectiveLoggedIn && !effectiveIsAuthor) {
      // In preview mode, don't load actual responses (admin viewing as player)
      if (!previewAsPlayer) {
      const erows = await pool.query('SELECT question_id, response_text, locked FROM responses WHERE quiz_id=$1 AND user_email=$2', [id, email]);
      erows.rows.forEach(r => {
        existingMap.set(r.question_id, r.response_text);
        if (r.locked === true) existingLockedId = r.question_id;
      });
      }
    }
    const recap = String(req.query.recap || '') === '1';
    const allowRecapLink = effectiveLoggedIn && !effectiveIsAuthor;
    if (recap && loggedIn && !isAuthor) {
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
      const header = await renderHeader(req);
      const subnav = renderQuizSubnav(id, 'recap', { allowRecap: true });
      return res.type('html').send(`
        ${renderHead(`Quiz ${id} Recap`, false)}
        <body class="ta-body">
          ${header}
          <main class="ta-main ta-container" style="max-width:900px;">
            ${renderBreadcrumb([{ label: 'Calendar', href: '/calendar' }, { label: quiz.title || `Quiz #${id}` }, { label: 'Recap' }])}
            ${subnav}
            <h1 class="ta-page-title">${quiz.title} (Quiz #${id})</h1>
            <div class="ta-recap-summary">
              <div class="ta-recap-summary__item">
                <span class="ta-recap-summary__label">Status</span>
                <span class="ta-recap-summary__value">${status}</span>
              </div>
              <div class="ta-recap-summary__item">
                <span class="ta-recap-summary__label">Score</span>
                <span class="ta-recap-summary__score">${total}</span>
              </div>
            </div>
            <div class="ta-table-wrapper">
              <table class="ta-table">
                <thead>
            <tr><th>#</th><th>Question</th><th>Your answer</th><th>Correct answer</th><th>Points</th><th>Actions</th></tr>
                </thead>
                <tbody>
            ${rowsHtml}
                </tbody>
          </table>
            </div>
          <p style="margin-top:16px;"><a href="/calendar" class="ta-btn ta-btn-outline">Back to Calendar</a></p>
          </main>
          ${renderFooter(req)}
        </body></html>
      `);
    }

    let authorAverageInfo = null;
    if (effectiveIsAuthor) {
      authorAverageInfo = await computeAuthorAveragePoints(pool, id, quizAuthorEmail);
    }
    const averagePoints = authorAverageInfo ? authorAverageInfo.average : 0;
    const averageCount = authorAverageInfo ? authorAverageInfo.count : 0;
    const averageSource = authorAverageInfo ? authorAverageInfo.source : 'none';
    const averageFooter = averageSource === 'override'
      ? 'An admin set this value manually.'
      : (averageCount ? 'This will update as more players finish.' : 'Once players begin submitting, your score will update automatically.');
    const authorMessage = effectiveIsAuthor ? `
      <div style="margin:16px 0;padding:18px;border-radius:10px;border:1px solid rgba(255,255,255,0.18);background:rgba(0,0,0,0.35);">
        <h3 style="margin:0 0 8px 0;color:#ffd700;">Author participation</h3>
        <p style="margin:0;line-height:1.6;">
          As the author of this quiz, you won't submit answers. We'll automatically award you the current player average:
          <strong>${formatPoints(averagePoints)}</strong> points${averageCount ? ` across ${averageCount} player${averageCount === 1 ? '' : 's'}` : ''}.
          ${averageFooter}
        </p>
      </div>
    ` : '';

    // Check if user is admin (but respect preview mode)
    const showAdminFeatures = isAdmin && !previewAsPlayer;

    let form;
    if (locked) {
      form = '<p>This quiz is locked until unlock time (ET).</p>';
      if (effectiveIsAuthor) form += authorMessage;
      // Show edit button for admins even when locked (unless previewing as player)
      if (showAdminFeatures && !effectiveIsAuthor) {
        form += `<div style="margin-top:16px;"><a href="/quiz/${id}/edit" class="ta-btn ta-btn-primary">Edit Quiz (Admin)</a></div>`;
      }
    } else if (effectiveLoggedIn && !effectiveIsAuthor) {
      form = `
      ${existingMap.size > 0 ? `<div style="padding:8px 10px;border:1px solid #ddd;border-radius:6px;background:#fafafa;margin-bottom:10px;">You've started this quiz. <a href="/quiz/${id}?recap=1">View recap</a>.</div>` : ''}
      <div id="quiz-progress" style="margin-bottom:20px;padding:12px;background:#1a1a1a;border:1px solid #333;border-radius:8px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <span style="font-weight:bold;color:#ffd700;">Progress: <span id="progress-text">0 / ${qs.length}</span></span>
          <span id="autosave-status" style="font-size:14px;opacity:0.7;"></span>
        </div>
        <div style="width:100%;height:8px;background:#333;border-radius:4px;overflow:hidden;">
          <div id="progress-bar" style="height:100%;background:linear-gradient(90deg,var(--gold) 0%,var(--gold-2) 100%);width:0%;transition:width 0.3s ease;"></div>
        </div>
      </div>
      <form id="quiz-form" method="post" action="/quiz/${id}/submit" data-quiz-id="${id}">
        ${qs.map((q, idx)=>{
          const val = existingMap.get(q.id) || '';
          const checked = existingLockedId === q.id ? 'checked' : '';
          const disable = nowUtc >= freezeUtc ? 'disabled' : '';
          const required = (q.number === 1 && !(nowUtc >= freezeUtc)) ? 'required' : '';
          // Highlight the "ask" text within the question text
          let highlightedText = String(q.text || '');
          const ask = String(q.ask || '').trim();
          if (ask) {
            try {
              // Escape special regex characters in ask text
              const escapedAsk = ask.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
              const re = new RegExp(escapedAsk, 'gi');
              highlightedText = highlightedText.replace(re, '<mark>$&</mark>');
            } catch (e) {
              // If regex fails, just use original text
              console.error('Error highlighting ask text:', e);
            }
          }
          return `
          <div class=\"quiz-card\" data-question-num=\"${q.number}\" data-question-id=\"${q.id}\">
            <div class=\"quiz-qhead\">
              <div class=\"quiz-left\">
                <div class=\"quiz-qnum\">Q${q.number} <span style=\"font-size:14px;opacity:0.7;\">(${idx + 1} of ${qs.length})</span></div>
                <span class=\"quiz-cat\">${q.category || 'General'}</span>
              </div>
              <label class=\"quiz-lock\"><input type=\"radio\" name=\"locked\" value=\"${q.id}\" ${checked} ${disable} ${required}/> Lock this question</label>
            </div>
            <div class=\"quiz-text\">${highlightedText}</div>
            <div class=\"quiz-answer\">
              <label>Your answer <input name=\"q${q.number}\" data-question-id=\"${q.id}\" value=\"${val.replace(/\"/g,'&quot;')}\" ${disable} autocomplete=\"off\"/></label>
            </div>
          </div>`;
        }).join('')}
        <div class=\"quiz-actions\">
          <button type=\"button\" id=\"review-btn\" class=\"ta-btn ta-btn-outline\" style=\"margin-right:8px;\" ${nowUtc >= freezeUtc ? 'disabled' : ''}>Review Answers</button>
          <button class=\"quiz-submit ta-btn ta-btn-primary\" type=\"submit\" id=\"submit-btn\" ${nowUtc >= freezeUtc ? 'disabled' : ''}>Submit Quiz</button>
        </div>
        <div id="review-panel" style="display:none;margin-top:24px;padding:20px;background:#1a1a1a;border:2px solid #ffd700;border-radius:8px;">
          <h3 style="margin:0 0 16px 0;color:#ffd700;">Review Your Answers</h3>
          <div id="review-content"></div>
          <div style="margin-top:16px;">
            <button type="button" id="edit-btn" class="ta-btn ta-btn-outline" style="margin-right:8px;">Edit Answers</button>
            <button type="submit" class="ta-btn ta-btn-primary">Confirm & Submit</button>
          </div>
        </div>
      </form>`;
      // Show edit button for admins even when they can play (unless previewing as player)
      if (showAdminFeatures) {
        form += `<div style="margin-top:16px;"><a href="/quiz/${id}/edit" class="ta-btn ta-btn-primary">Edit Quiz (Admin)</a></div>`;
      }
    } else if (effectiveIsAuthor && !previewAsPlayer) {
      const editLink = locked ? `<div style="margin-top:16px;"><a href="/quiz/${id}/edit" class="ta-btn ta-btn-primary">Edit Quiz</a></div>` : '';
      form = authorMessage + editLink;
      // If author is also admin, show admin edit link even after unlock
      if (showAdminFeatures && !locked) {
        form += `<div style="margin-top:16px;"><a href="/quiz/${id}/edit" class="ta-btn ta-btn-primary">Edit Quiz (Admin)</a></div>`;
      }
    } else {
      // Show edit button for admins (unless previewing as player)
      const adminEditLink = showAdminFeatures ? `<div style="margin-top:16px;"><a href="/quiz/${id}/edit" class="ta-btn ta-btn-primary">Edit Quiz (Admin)</a></div>` : '';
      form = '<p>Please sign in to play.</p>' + adminEditLink;
    }
    const et = utcToEtParts(unlockUtc);
    const slot = et.h === 0 ? 'AM' : 'PM';
    const dateStr = `${et.y}-${String(et.m).padStart(2,'0')}-${String(et.d).padStart(2,'0')}`;
    const header = await renderHeader(req);
    const subnav = renderQuizSubnav(id, 'quiz', { allowRecap: allowRecapLink });
    
    // Add preview mode banner for admins
    const previewBanner = previewAsPlayer ? `
      <div style="background:#1a3a4a;border:2px solid #4488ff;border-radius:8px;padding:12px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;">
        <div style="color:#88ccff;font-weight:bold;">👁️ Preview Mode: Viewing as Player</div>
        <a href="/quiz/${id}" class="ta-btn ta-btn-outline" style="padding:6px 12px;font-size:14px;">Exit Preview</a>
      </div>
    ` : (isAdmin ? `
      <div style="background:#1a1a1a;border:1px solid #444;border-radius:6px;padding:8px;margin-bottom:16px;text-align:right;">
        <a href="/quiz/${id}?preview=player" class="ta-btn ta-btn-outline" style="padding:4px 12px;font-size:13px;">👁️ Preview as Player</a>
      </div>
    ` : '');
    
    res.type('html').send(`
      ${renderHead(`Quiz ${id}`, false)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container-wide">
          ${previewBanner}
          ${locked && !previewAsPlayer ? `
            <div class="ta-quiz-hero">
              <div class="ta-quiz-hero-top">
                ${quiz.author ? `<div class="ta-quiz-subtitle" style="font-size:32px;color:#ffd700;">By ${quiz.author}</div>` : ''}
              </div>
            </div>
            ${subnav}
          ` : `
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
            ${subnav}
          <section class="rules-panel">
            <h4>How scoring works</h4>
            <ul class="rules-list">
              <li>Lock exactly one question. If your locked answer is correct, you earn <strong>5 points</strong>; if incorrect, it earns <strong>0</strong>. The locked question <em>does not affect</em> your streak.</li>
              <li>For all other questions, correct answers build a streak: <strong>+1, then +2, then +3…</strong>. A wrong/blank answer resets the streak to 0.</li>
              <li>You may change your lock until grading/finalization.</li>
            </ul>
          </section>
          `}
          ${form}
          <p style="margin-top:16px;"><a href="/calendar" class="ta-btn ta-btn-outline">Back to Calendar</a></p>
        </main>
        ${renderFooter(req)}
        <script src="/js/common-enhancements.js?v=${ASSET_VERSION}"></script>
        <script src="/js/quiz-enhancements.js?v=${ASSET_VERSION}"></script>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load quiz');
  }
});

// --- Author: edit published quiz (until unlock) ---
app.get('/quiz/:id/edit', requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { rows: qr } = await pool.query('SELECT * FROM quizzes WHERE id = $1', [id]);
    if (qr.length === 0) return res.status(404).send('Quiz not found');
    const quiz = qr[0];
    
    // Check if user is admin
    const isAdmin = await isAdminUser(req);
    
    // Check if quiz is locked (not yet unlocked)
    const nowUtc = new Date();
    const unlockUtc = new Date(quiz.unlock_at);
    const locked = nowUtc < unlockUtc;
    
    // Authors can only edit before unlock; admins can edit anytime
    if (!isAdmin && !locked) {
      return res.status(403).send('This quiz has already unlocked. Only admins can edit unlocked quizzes.');
    }
    
    // Check if user is the author (or admin)
    const email = String(req.session.user ? (req.session.user.email || '') : '').toLowerCase();
    const quizAuthorEmail = (quiz.author_email || '').toLowerCase();
    const isAuthor = !!quizAuthorEmail && !!email && quizAuthorEmail === email;
    
    if (!isAdmin && !isAuthor) {
      return res.status(403).send('You are not authorized to edit this quiz. Only the quiz author (before unlock) or admins can edit.');
    }
    
    const { rows: qs } = await pool.query('SELECT * FROM questions WHERE quiz_id = $1 ORDER BY number ASC', [id]);
    const esc = (v) => String(v || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
    const header = await renderHeader(req);
    
    res.type('html').send(`
      ${renderHead(`Edit Quiz #${id}`, false)}
      <body class="ta-body" style="padding:24px;">
      ${header}
        <main class="ta-main ta-container" style="max-width:900px;">
          <h1 class="ta-page-title">${isAdmin ? 'Edit Quiz' : 'Edit Your Quiz'}</h1>
          <p style="margin-bottom:16px;opacity:0.8;">${isAdmin ? 'Admin: You can edit this quiz at any time.' : 'You can edit this quiz until it unlocks. After unlock, only admins can make changes.'}</p>
          <form method="post" action="/quiz/${id}/edit" class="ta-form-stack">
            <div class="ta-form-field">
              <label>Title <input name="title" value="${esc(quiz.title)}" required style="width:100%;" /></label>
            </div>
            <div class="ta-form-field">
              <label>About the Author <textarea name="author_blurb" rows="3" style="width:100%;">${esc(quiz.author_blurb || '')}</textarea></label>
            </div>
            <div class="ta-form-field">
              <label>About this Quiz <textarea name="description" rows="4" style="width:100%;">${esc(quiz.description || '')}</textarea></label>
            </div>
            <h2 style="margin-top:32px;margin-bottom:12px;color:#ffd700;">Questions (${qs.length})</h2>
            ${Array.from({length: 10}, (_, i) => {
              const n = i + 1;
              const q = qs.find(q => q.number === n) || null;
              return `
                <div style="border:1px solid #444;padding:16px;margin:12px 0;border-radius:8px;background:#1a1a1a;">
                  <h3 style="margin:0 0 12px 0;color:#ffd700;">Question ${n}</h3>
                  <div class="ta-form-field">
                    <label>Category <input name="q${n}_category" value="${esc(q?.category || 'General')}" style="width:100%;" /></label>
                  </div>
                  <div class="ta-form-field">
                    <label>Text <textarea name="q${n}_text" rows="3" style="width:100%;">${esc(q?.text || '')}</textarea></label>
                  </div>
                  <div class="ta-form-field">
                    <label>Answer <input name="q${n}_answer" value="${esc(q?.answer || '')}" style="width:100%;" /></label>
                  </div>
                  <div class="ta-form-field">
                    <label>Ask (optional) <input name="q${n}_ask" value="${esc(q?.ask || '')}" style="width:100%;" /></label>
                    <small style="opacity:0.7;">Must appear verbatim in the Text field; used as an in-line highlight</small>
                  </div>
                </div>
              `;
            }).join('')}
            <div class="ta-form-actions">
              <button type="submit" class="ta-btn ta-btn-primary">Save Changes</button>
              <a href="/quiz/${id}" class="ta-btn ta-btn-outline">Cancel</a>
            </div>
          </form>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load edit page');
  }
});

app.post('/quiz/:id/edit', requireAuth, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { rows: qr } = await pool.query('SELECT * FROM quizzes WHERE id = $1', [id]);
    if (qr.length === 0) return res.status(404).send('Quiz not found');
    const quiz = qr[0];
    
    // Check if user is admin
    const isAdmin = await isAdminUser(req);
    
    // Check if quiz is locked (not yet unlocked)
    const nowUtc = new Date();
    const unlockUtc = new Date(quiz.unlock_at);
    const locked = nowUtc < unlockUtc;
    
    // Authors can only edit before unlock; admins can edit anytime
    if (!isAdmin && !locked) {
      return res.status(403).send('This quiz has already unlocked. Only admins can edit unlocked quizzes.');
    }
    
    // Check if user is the author (or admin)
    const email = String(req.session.user ? (req.session.user.email || '') : '').toLowerCase();
    const quizAuthorEmail = (quiz.author_email || '').toLowerCase();
    const isAuthor = !!quizAuthorEmail && !!email && quizAuthorEmail === email;
    
    if (!isAdmin && !isAuthor) {
      return res.status(403).send('You are not authorized to edit this quiz.');
    }
    
    // Update quiz metadata
    const title = String(req.body.title || '').trim();
    const authorBlurb = String(req.body.author_blurb || '').trim() || null;
    const description = String(req.body.description || '').trim() || null;
    
    if (!title) return res.status(400).send('Title required');
    
    await pool.query(
      'UPDATE quizzes SET title=$1, author_blurb=$2, description=$3 WHERE id=$4',
      [title, authorBlurb, description, id]
    );
    
    // Update questions
    const questions = [];
    for (let i = 1; i <= 10; i++) {
      const text = String(req.body[`q${i}_text`] || '').trim();
      const answer = String(req.body[`q${i}_answer`] || '').trim();
      const category = String(req.body[`q${i}_category`] || 'General').trim();
      const ask = String(req.body[`q${i}_ask`] || '').trim() || null;
      
      if (text && answer) {
        questions.push({ number: i, text, answer, category, ask });
      }
    }
    
    if (questions.length === 0) {
      return res.status(400).send('At least one question is required');
    }
    
    // Delete existing questions and insert new ones
    await pool.query('DELETE FROM questions WHERE quiz_id = $1', [id]);
    for (const q of questions) {
      await pool.query(
        'INSERT INTO questions(quiz_id, number, text, answer, category, ask) VALUES($1,$2,$3,$4,$5,$6)',
        [id, q.number, q.text, q.answer, q.category, q.ask]
      );
    }
    
    res.redirect(`/quiz/${id}?msg=Quiz updated successfully`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to save changes');
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
    const { rows: qr } = await pool.query('SELECT id, title, freeze_at, author_email FROM quizzes WHERE id = $1', [id]);
    if (qr.length === 0) return res.status(404).send('Quiz not found');
    const freezeUtc = new Date(qr[0].freeze_at);
    const { rows } = await pool.query(
      `SELECT r.user_email, COALESCE(p.username, r.user_email) AS handle, SUM(r.points) AS points, MIN(r.created_at) AS first_time
       FROM responses r
       LEFT JOIN players p ON p.email = r.user_email
       WHERE r.quiz_id = $1 AND r.created_at <= $2
       GROUP BY r.user_email, handle`,
      [id, freezeUtc]
    );
    const normalized = rows.map(r => ({
      user_email: (r.user_email || '').toLowerCase(),
      handle: r.handle,
      points: Number(r.points || 0),
      first_time: r.first_time ? new Date(r.first_time) : null,
      synthetic: false,
      player_count: null,
      source: 'player',
      email: (r.user_email || '').toLowerCase()
    }));
    const authorEmail = (qr[0].author_email || '').toLowerCase();
    if (authorEmail) {
      const avgInfo = await computeAuthorAveragePoints(pool, id, authorEmail);
      const existingIdx = normalized.findIndex(r => r.user_email === authorEmail);
      const { rows: authorPlayer } = await pool.query('SELECT username FROM players WHERE email=$1', [authorEmail]);
      const handle = authorPlayer.length && authorPlayer[0].username ? authorPlayer[0].username : authorEmail;
      if (existingIdx >= 0) {
        normalized[existingIdx].points = avgInfo.average;
        normalized[existingIdx].first_time = null;
        normalized[existingIdx].synthetic = true;
        normalized[existingIdx].player_count = avgInfo.count;
        normalized[existingIdx].handle = handle;
        normalized[existingIdx].source = avgInfo.source;
        normalized[existingIdx].correctCount = 0;
        normalized[existingIdx].avgPerCorrect = 0;
      } else {
        normalized.push({
          user_email: authorEmail,
          handle,
          points: avgInfo.average,
          first_time: null,
          synthetic: true,
          player_count: avgInfo.count,
          source: avgInfo.source,
          email: authorEmail,
          correctCount: 0,
          avgPerCorrect: 0
        });
      }
    }
    const sorted = normalized.sort((a, b) => {
      if (b.points !== a.points) return b.points - a.points;
      const aTime = a.first_time ? a.first_time.getTime() : Number.POSITIVE_INFINITY;
      const bTime = b.first_time ? b.first_time.getTime() : Number.POSITIVE_INFINITY;
      return aTime - bTime;
    });
    const playerEntries = sorted.filter(r => !r.synthetic);
    const totalParticipants = playerEntries.length;
    const averagePoints = totalParticipants
      ? playerEntries.reduce((acc, r) => acc + Number(r.points || 0), 0) / totalParticipants
      : 0;
    const topCards = sorted.slice(0, 3).map((r, idx) => {
      const medal = ['🥇','🥈','🥉'][idx] || '⭐';
      const detail = r.synthetic
        ? ''
        : `${r.correctCount || 0} correct • ${formatPoints(r.avgPerCorrect || 0)} avg/correct`;
      return `
        <div style="background:#1a1a1a;border:1px solid rgba(255,255,255,0.12);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:8px;box-shadow:0 8px 20px rgba(0,0,0,0.25);">
          <div style="font-size:32px;">${medal}</div>
          <div style="font-weight:800;font-size:18px;color:#ffd700;">${r.synthetic ? `${r.handle} (avg)` : r.handle}</div>
          <div style="font-size:28px;font-weight:700;">${formatPoints(r.points)}</div>
          <div style="font-size:13px;opacity:0.8;">${detail || '—'}</div>
        </div>
      `;
    }).join('');
    const tableRows = sorted.map((r, idx) => {
      const label = r.synthetic ? `${r.handle} (avg)` : r.handle;
      const detail = r.synthetic
        ? '—'
        : `<span class="leaderboard-detail">${r.correctCount || 0} correct</span> <span class="leaderboard-separator">•</span> <span class="leaderboard-detail">${formatPoints(r.avgPerCorrect || 0)} avg/correct</span>`;
      const rank = idx + 1;
      return `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.08);${idx % 2 ? 'background:rgba(255,255,255,0.02);' : ''}">
          <td style="padding:10px 8px;font-weight:700;color:${rank === 1 ? '#ffd700' : '#fff'};">${rank}</td>
          <td style="padding:10px 8px;">${label}</td>
          <td style="padding:10px 8px;font-weight:600;">${formatPoints(r.points)}</td>
          <td style="padding:10px 8px;font-size:13px;opacity:0.75;" class="leaderboard-details-cell">${detail}</td>
        </tr>
      `;
    }).join('');
    const syntheticNote = sorted.some(r => r.synthetic)
      ? '<p style="margin-top:12px;font-size:13px;opacity:0.75;">Entries labelled "avg" represent the quiz author.</p>'
      : '';
    const header = await renderHeader(req);
    const allowRecapLink = !!(req.session?.user);
    const subnav = renderQuizSubnav(id, 'leaderboard', { allowRecap: allowRecapLink });
    res.type('html').send(`
      ${renderHead(`Leaderboard • Quiz ${id}`, false)}
      <body class="ta-body" style="padding:24px;">
      ${header}
        <main class="ta-main ta-container" style="max-width:960px;">
          ${renderBreadcrumb([{ label: 'Calendar', href: '/calendar' }, { label: qr[0].title || `Quiz #${id}` }, { label: 'Leaderboard' }])}
          ${subnav}
          <h1 class="ta-page-title">Leaderboard — ${qr[0].title}</h1>
          <section style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin:20px 0;">
            <div style="background:#1a1a1a;border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:16px;">
              <div style="font-size:14px;opacity:0.75;margin-bottom:6px;">Total participants</div>
              <div style="font-size:28px;font-weight:800;color:#ffd700;">${totalParticipants}</div>
            </div>
            <div style="background:#1a1a1a;border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:16px;">
              <div style="font-size:14px;opacity:0.75;margin-bottom:6px;">Average score</div>
              <div style="font-size:28px;font-weight:800;color:#ffd700;">${formatPoints(averagePoints)}</div>
            </div>
            <div style="background:#1a1a1a;border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:16px;">
              <div style="font-size:14px;opacity:0.75;margin-bottom:6px;">Top score</div>
              <div style="font-size:28px;font-weight:800;color:#ffd700;">${sorted.length ? formatPoints(sorted[0].points) : '0'}</div>
            </div>
          </section>
          ${topCards ? `
          <section style="margin:28px 0;">
            <h2 style="margin:0 0 16px 0;color:#ffd700;">Top finishers</h2>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px;">
              ${topCards}
            </div>
          </section>` : ''}
          <section style="margin:28px 0;">
            <div style="background:#0e0e0e;border:1px solid rgba(255,255,255,0.08);border-radius:12px;overflow:hidden;">
              <table class="leaderboard-table" style="width:100%;border-collapse:collapse;">
                <thead style="background:#111;">
                  <tr>
                    <th style="padding:10px 8px;text-align:left;">Rank</th>
                    <th style="padding:10px 8px;text-align:left;">Player</th>
                    <th style="padding:10px 8px;text-align:left;">Points</th>
                    <th style="padding:10px 8px;text-align:left;">Details</th>
                  </tr>
                </thead>
                <tbody>
                  ${tableRows || '<tr><td colspan="4" style="padding:16px;text-align:center;opacity:0.75;">No submissions yet.</td></tr>'}
                </tbody>
        </table>
            </div>
            ${syntheticNote}
          </section>
        <p style="margin-top:16px;"><a href="/quiz/${id}" class="ta-btn ta-btn-outline">Back to Quiz</a> <a href="/calendar" class="ta-btn ta-btn-outline" style="margin-left:8px;">Calendar</a></p>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load leaderboard');
  }
});

// --- Public: Past quizzes archive ---
app.get('/archive', async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, title, unlock_at FROM quizzes WHERE unlock_at < NOW() ORDER BY unlock_at DESC LIMIT 500');
    const items = rows.map(q => {
      const p = utcToEtParts(new Date(q.unlock_at));
      const day = `${p.y}-${String(p.m).padStart(2,'0')}-${String(p.d).padStart(2,'0')}`;
      const half = (p.h === 0 ? 'AM' : 'PM');
      return `<li style=\"margin:8px 0;\"><a href=\"/archive/${q.id}\">${day} ${half} — ${q.title.replace(/</g,'&lt;')}</a> <span style=\"opacity:.7\">(#${q.id})</span></li>`;
    }).join('');
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Archive', false)}
      <body class=\"ta-body\" style=\"padding:24px;\">
      ${header}
        <h1>Past Quizzes</h1>
        <p><a href=\"/calendar\" class=\"ta-btn ta-btn-outline\">Back to Calendar</a></p>
        <ul style=\"list-style:none;padding:0;\">${items || '<li>No past quizzes.</li>'}</ul>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load archive');
  }
});

app.get('/archive/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).send('Invalid id');
    const qz = await pool.query('SELECT id, title, author, author_blurb, description, unlock_at FROM quizzes WHERE id=$1', [id]);
    if (!qz.rows.length) return res.status(404).send('Not found');
    const qas = await pool.query('SELECT number, text, answer, category, ask FROM questions WHERE quiz_id=$1 ORDER BY number ASC', [id]);
    const quiz = qz.rows[0];
    const esc = (v)=>String(v||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
    const p = utcToEtParts(new Date(quiz.unlock_at));
    const day = `${p.y}-${String(p.m).padStart(2,'0')}-${String(p.d).padStart(2,'0')}`;
    const half = (p.h === 0 ? 'AM' : 'PM');
    const qHtml = qas.rows.map(r => {
      const text = String(r.text||'');
      const ask = String(r.ask||'');
      let highlighted = esc(text);
      if (ask) {
        try {
          const re = new RegExp(ask.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), 'i');
          highlighted = highlighted.replace(re, '<mark>$&</mark>');
        } catch {}
      }
      return `<div style=\"border:1px solid #ddd;padding:8px;margin:8px 0;border-radius:6px;\">\n\
        <div><strong>Q${r.number}</strong> <em>${esc(r.category||'')}</em></div>\n\
        <div style=\"margin-top:6px;\">${highlighted}</div>\n\
        <div style=\"margin-top:6px;color:#666;\">Answer: <strong>${esc(r.answer||'')}</strong>${r.ask ? ' · Ask: <code>'+esc(r.ask)+'</code>' : ''}</div>\n\
      </div>`;
    }).join('');
    res.type('html').send(`
      ${renderHead(`${esc(quiz.title)} • Archive`, false)}
      <body class=\"ta-body\" style=\"padding:24px;\">
        <h1>${esc(quiz.title)}</h1>
        <div>${day} ${half}</div>
        ${(quiz.author || quiz.author_blurb) ? `<div style=\"margin-top:8px;\"><strong>${esc(quiz.author||'')}</strong><div style=\"opacity:.9;\">${esc(quiz.author_blurb||'')}</div></div>` : ''}
        ${quiz.description ? `<div style=\"margin-top:8px;\">${esc(quiz.description)}</div>` : ''}
        <div style=\"margin-top:12px;\">${qHtml}</div>
        <p style=\"margin-top:16px;\"><a href=\"/quiz/${quiz.id}\" class=\"ta-btn ta-btn-outline\">View quiz page</a> <a href=\"/archive\" class=\"ta-btn ta-btn-outline\" style=\"margin-left:8px;\">Back to Archive</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load archived quiz');
  }
});
// --- Overall leaderboard ---
app.get('/leaderboard', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT r.user_email, COALESCE(p.username, r.user_email) AS handle, SUM(r.points) AS points
       FROM responses r
       LEFT JOIN players p ON p.email = r.user_email
       GROUP BY r.user_email, handle`
    );
    const totals = new Map();
    rows.forEach(r => {
      const email = (r.user_email || '').toLowerCase();
      const points = Number(r.points || 0);
      const existing = totals.get(email) || { handle: r.handle || email, points: 0, email: email };
      existing.handle = r.handle || existing.handle;
      existing.points += points;
      totals.set(email, existing);
    });
    // Only add author bonuses if the author has actually submitted responses to quizzes
    const { rows: quizAuthors } = await pool.query('SELECT id, author_email FROM quizzes WHERE author_email IS NOT NULL AND author_email <> \'\'');
    for (const qa of quizAuthors) {
      const authorEmail = (qa.author_email || '').toLowerCase();
      if (!authorEmail) continue;
      
      // Check if author has any actual responses (not just author bonus)
      const { rows: authorResponses } = await pool.query(
        'SELECT COUNT(*) as count FROM responses WHERE user_email = $1',
        [authorEmail]
      );
      
      // Only add author bonus if they have actual responses
      if (authorResponses.length && parseInt(authorResponses[0].count) > 0) {
        const avgInfo = await computeAuthorAveragePoints(pool, qa.id, authorEmail);
        let entry = totals.get(authorEmail);
        if (!entry) {
          const { rows: playerRows } = await pool.query('SELECT username FROM players WHERE email=$1', [authorEmail]);
          entry = { handle: (playerRows.length && playerRows[0].username) ? playerRows[0].username : authorEmail, points: 0, email: authorEmail };
        }
        entry.points += avgInfo.average;
        totals.set(authorEmail, entry);
      }
    }
    
    // Get stats for each player: quizzes submitted, correct answers, avg score per correct
    for (const [email, entry] of totals.entries()) {
      const statsResult = await pool.query(`
        SELECT 
          COUNT(DISTINCT r.quiz_id) as quizzes_submitted,
          COUNT(CASE WHEN r.override_correct = true OR (r.override_correct IS NULL AND LOWER(TRIM(r.response_text)) = LOWER(TRIM(q.answer))) THEN 1 END) as correct_count,
          SUM(r.points) as total_points
        FROM responses r
        JOIN questions q ON q.id = r.question_id
        WHERE r.user_email = $1
      `, [email]);
      
      if (statsResult.rows.length) {
        const stats = statsResult.rows[0];
        entry.quizzesSubmitted = parseInt(stats.quizzes_submitted) || 0;
        entry.correctCount = parseInt(stats.correct_count) || 0;
        entry.totalPoints = parseFloat(stats.total_points) || 0;
        entry.avgPerCorrect = entry.correctCount > 0 ? (entry.totalPoints / entry.correctCount) : 0;
      } else {
        entry.quizzesSubmitted = 0;
        entry.correctCount = 0;
        entry.avgPerCorrect = 0;
      }
    }
    
    const sorted = Array.from(totals.values()).sort((a, b) => b.points - a.points);
    const totalPlayers = sorted.length;
    const averagePoints = totalPlayers
      ? sorted.reduce((acc, r) => acc + Number(r.points || 0), 0) / totalPlayers
      : 0;
    const topCards = sorted.slice(0, 3).map((r, idx) => {
      const medal = ['🥇','🥈','🥉'][idx] || '⭐';
      return `
        <div style="background:#1a1a1a;border:1px solid rgba(255,255,255,0.12);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:8px;box-shadow:0 8px 20px rgba(0,0,0,0.25);">
          <div style="font-size:32px;">${medal}</div>
          <div style="font-weight:800;font-size:18px;color:#ffd700;">${r.handle}</div>
          <div style="font-size:28px;font-weight:700;">${formatPoints(r.points)}</div>
        </div>
      `;
    }).join('');
    const tableRows = sorted.map((r, idx) => {
      const rank = idx + 1;
      const detail = `<span class="leaderboard-detail">${r.quizzesSubmitted} quiz${r.quizzesSubmitted !== 1 ? 'zes' : ''}</span> <span class="leaderboard-separator">•</span> <span class="leaderboard-detail">${r.correctCount} correct</span> <span class="leaderboard-separator">•</span> <span class="leaderboard-detail">${formatPoints(r.avgPerCorrect)} avg/correct</span>`;
      return `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.08);${idx % 2 ? 'background:rgba(255,255,255,0.02);' : ''}">
          <td style="padding:10px 8px;font-weight:700;color:${rank === 1 ? '#ffd700' : '#fff'};">${rank}</td>
          <td style="padding:10px 8px;">${r.handle}</td>
          <td style="padding:10px 8px;font-weight:600;">${formatPoints(r.points)}</td>
          <td style="padding:10px 8px;font-size:13px;opacity:0.75;" class="leaderboard-details-cell">${detail}</td>
        </tr>
      `;
    }).join('');
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Overall Leaderboard', false)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container" style="max-width:960px;padding:24px;">
          ${renderBreadcrumb([{ label: 'Leaderboard' }])}
          <h1 class="ta-page-title">Overall Leaderboard</h1>
          <section style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin:20px 0;">
            <div style="background:#1a1a1a;border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:16px;">
              <div style="font-size:14px;opacity:0.75;margin-bottom:6px;">Total players</div>
              <div style="font-size:28px;font-weight:800;color:#ffd700;">${totalPlayers}</div>
            </div>
            <div style="background:#1a1a1a;border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:16px;">
              <div style="font-size:14px;opacity:0.75;margin-bottom:6px;">Average points</div>
              <div style="font-size:28px;font-weight:800;color:#ffd700;">${formatPoints(averagePoints)}</div>
            </div>
            <div style="background:#1a1a1a;border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:16px;">
              <div style="font-size:14px;opacity:0.75;margin-bottom:6px;">Top score</div>
              <div style="font-size:28px;font-weight:800;color:#ffd700;">${sorted.length ? formatPoints(sorted[0].points) : '0'}</div>
            </div>
          </section>
          ${topCards ? `
          <section style="margin:28px 0;">
            <h2 style="margin:0 0 16px 0;color:#ffd700;">Podium</h2>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px;">
              ${topCards}
            </div>
          </section>` : ''}
          <section style="margin:28px 0;">
            <div style="background:#0e0e0e;border:1px solid rgba(255,255,255,0.08);border-radius:12px;overflow:hidden;">
              <table class="leaderboard-table" style="width:100%;border-collapse:collapse;">
                <thead style="background:#111;">
                  <tr>
                    <th style="padding:10px 8px;text-align:left;">Rank</th>
                    <th style="padding:10px 8px;text-align:left;">Player</th>
                    <th style="padding:10px 8px;text-align:left;">Total Points</th>
                    <th style="padding:10px 8px;text-align:left;">Details</th>
                  </tr>
                </thead>
                <tbody>
                  ${tableRows || '<tr><td colspan="4" style="padding:16px;text-align:center;opacity:0.75;">No submissions yet.</td></tr>'}
                </tbody>
        </table>
            </div>
          </section>
          <p style="margin-top:16px;"><a href="/calendar" class="ta-btn ta-btn-outline">Back to Calendar</a></p>
        </main>
        ${renderFooter(req)}
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
    const qinfo = await pool.query('SELECT freeze_at, author_email FROM quizzes WHERE id=$1', [id]);
    if (!qinfo.rows.length) return res.status(404).send('Quiz not found');
      const freezeUtc = new Date(qinfo.rows[0].freeze_at);
      if (new Date() >= freezeUtc) {
        return res.redirect(`/quiz/${id}?recap=1`);
      }
    const authorEmail = (qinfo.rows[0].author_email || '').toLowerCase();
    const email = (req.session.user && req.session.user.email ? req.session.user.email : getAdminEmail()).toLowerCase();
    if (authorEmail && authorEmail === email) {
      return res.status(403).send('Quiz authors cannot submit this quiz.');
    }
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
    const { rows } = await pool.query(`
      SELECT 
        q.id, 
        q.title, 
        q.unlock_at, 
        q.freeze_at,
        latest_grading.last_graded_at,
        latest_grading.last_graded_by
      FROM quizzes q
      LEFT JOIN LATERAL (
        SELECT 
          r.override_updated_at as last_graded_at,
          r.override_updated_by as last_graded_by
        FROM responses r
        WHERE r.quiz_id = q.id 
          AND r.override_updated_at IS NOT NULL
        ORDER BY r.override_updated_at DESC
        LIMIT 1
      ) latest_grading ON true
      ORDER BY q.unlock_at DESC, q.id DESC
      LIMIT 200
    `);
    
    const fmtTime = (ts) => {
      if (!ts) return 'Never';
      const d = new Date(ts);
      const now = new Date();
      const diffMs = now - d;
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMs / 3600000);
      const diffDays = Math.floor(diffMs / 86400000);
      
      if (diffMins < 1) return 'Just now';
      if (diffMins < 60) return `${diffMins}m ago`;
      if (diffHours < 24) return `${diffHours}h ago`;
      if (diffDays < 7) return `${diffDays}d ago`;
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
    };
    
    const items = rows.map(q => {
      const gradedInfo = q.last_graded_at 
        ? `<div style="font-size:12px;opacity:0.8;">${q.last_graded_by || 'Unknown'} · ${fmtTime(q.last_graded_at)}</div>`
        : '<div style="font-size:12px;opacity:0.5;">Not graded</div>';
      return `<tr>
        <td><input type="checkbox" class="quiz-checkbox" value="${q.id}" /></td>
        <td>#${q.id}</td>
        <td>${q.title || 'Untitled'}</td>
        <td>${fmtEt(q.unlock_at)}</td>
        <td>${fmtEt(q.freeze_at)}</td>
        <td>${gradedInfo}</td>
        <td>
          <a href="/admin/quiz/${q.id}" class="ta-btn ta-btn-small" style="margin-right:4px;">View/Edit</a>
          <a href="/admin/quiz/${q.id}/analytics" class="ta-btn ta-btn-small" style="margin-right:4px;">Analytics</a>
          <a href="/admin/quiz/${q.id}/grade" class="ta-btn ta-btn-small" style="margin-right:4px;">Grade</a>
          <a href="/quiz/${q.id}" class="ta-btn ta-btn-small">Open</a>
        </td>
      </tr>`;
    }).join('');
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Quizzes • Admin', true)}
      <body class="ta-body">
      ${header}
        <main class="ta-main ta-container">
          ${renderBreadcrumb([ADMIN_CRUMB, { label: 'Quizzes' }])}
          ${renderAdminNav('quizzes')}
          <h1 class="ta-page-title">Quizzes</h1>
          <div class="ta-admin-toolbar">
            <p class="ta-admin-toolbar__count">Total: <span id="total-count">${rows.length}</span> quiz${rows.length !== 1 ? 'zes' : ''}</p>
            <div class="ta-admin-toolbar__filters">
              <input type="text" id="quiz-search" class="ta-input" placeholder="Search by title or ID…" />
              <select id="status-filter" class="ta-input">
              <option value="">All Statuses</option>
              <option value="locked">Locked</option>
              <option value="active">Active</option>
              <option value="finalized">Finalized</option>
            </select>
              <button onclick="clearFilters()" class="ta-btn ta-btn-outline">Clear</button>
          </div>
        </div>
          <div id="bulk-quiz-actions" class="ta-admin-bulk" style="display:none;">
            <div class="ta-admin-bulk__header"><strong>Bulk actions (<span id="selected-quiz-count">0</span> selected)</strong></div>
            <div class="ta-admin-bulk__buttons">
              <button onclick="bulkQuizAction('delete')" class="ta-btn ta-btn-danger">Delete Selected</button>
              <button onclick="bulkQuizAction('export')" class="ta-btn ta-btn-success">Export Selected</button>
          </div>
        </div>
          <div class="ta-table-wrapper">
            <table class="ta-table" id="quiz-table">
          <thead>
                <tr>
                  <th><input type="checkbox" id="select-all-quizzes" onchange="toggleAllQuizzes(this)" /></th>
                  <th>ID</th>
                  <th>Title</th>
                  <th>Unlock</th>
                  <th>Freeze</th>
                  <th>Last graded</th>
                  <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${items || '<tr><td colspan="7">No quizzes</td></tr>'}
          </tbody>
        </table>
          </div>
        </main>
        ${renderFooter(req)}
        <script src="/js/common-enhancements.js?v=${ASSET_VERSION}"></script>
        <script>
          function filterQuizzes() {
            const searchTerm = document.getElementById('quiz-search').value.toLowerCase().trim();
            const statusFilter = document.getElementById('status-filter').value;
            const now = new Date();
            const rows = document.querySelectorAll('tbody tr');
            let visibleCount = 0;
            rows.forEach(row => {
              const id = row.cells[0]?.textContent?.toLowerCase() || '';
              const title = row.cells[1]?.textContent?.toLowerCase() || '';
              const unlockText = row.cells[2]?.textContent || '';
              const freezeText = row.cells[3]?.textContent || '';
              const unlockDate = unlockText ? new Date(unlockText) : null;
              const freezeDate = freezeText ? new Date(freezeText) : null;
              
              let status = '';
              if (unlockDate && now < unlockDate) status = 'locked';
              else if (freezeDate && now >= freezeDate) status = 'finalized';
              else if (unlockDate && now >= unlockDate) status = 'active';
              
              const matchesSearch = !searchTerm || id.includes(searchTerm) || title.includes(searchTerm);
              const matchesStatus = !statusFilter || status === statusFilter;
              const matches = matchesSearch && matchesStatus;
              
              row.style.display = matches ? '' : 'none';
              if (matches) visibleCount++;
            });
            document.getElementById('total-count').textContent = visibleCount;
          }
          function clearFilters() {
            document.getElementById('quiz-search').value = '';
            document.getElementById('status-filter').value = '';
            filterQuizzes();
          }
          document.getElementById('quiz-search').addEventListener('input', filterQuizzes);
          document.getElementById('status-filter').addEventListener('change', filterQuizzes);
          
          function toggleAllQuizzes(checkbox) {
            document.querySelectorAll('.quiz-checkbox').forEach(cb => cb.checked = checkbox.checked);
            updateBulkQuizActions();
          }
          
          function updateBulkQuizActions() {
            const selected = document.querySelectorAll('.quiz-checkbox:checked').length;
            const bulkDiv = document.getElementById('bulk-quiz-actions');
            const countSpan = document.getElementById('selected-quiz-count');
            if (selected > 0) {
              bulkDiv.style.display = 'block';
              countSpan.textContent = selected;
            } else {
              bulkDiv.style.display = 'none';
            }
          }
          
          function bulkQuizAction(action) {
            const ids = Array.from(document.querySelectorAll('.quiz-checkbox:checked')).map(cb => cb.value);
            if (ids.length === 0) {
              alert('No quizzes selected');
              return;
            }
            if (action === 'delete') {
              if (!confirm('Delete ' + ids.length + ' quiz(zes)? This cannot be undone.')) return;
              // TODO: Implement bulk delete endpoint
              alert('Bulk delete feature coming soon');
            } else if (action === 'export') {
              // TODO: Implement bulk export
              alert('Bulk export feature coming soon');
            }
          }
          
          document.querySelectorAll('.quiz-checkbox').forEach(cb => {
            cb.addEventListener('change', updateBulkQuizActions);
          });
        </script>
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
    
    // Format unlock_at for datetime-local input (YYYY-MM-DDTHH:mm in ET)
    let unlockAtValue = '';
    if (quiz.unlock_at) {
      const unlockEt = utcToEtParts(new Date(quiz.unlock_at));
      unlockAtValue = `${unlockEt.y}-${String(unlockEt.m).padStart(2,'0')}-${String(unlockEt.d).padStart(2,'0')}T${String(unlockEt.h).padStart(2,'0')}:${String(unlockEt.et.getUTCMinutes()).padStart(2,'0')}`;
    }
    
    const esc = (v) => String(v || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
    const list = qs.rows.map(q => `<li><strong>Q${q.number}</strong> ${esc(q.text)} <em>(Ans: ${esc(q.answer)})</em></li>`).join('');
    
    const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead(`Edit Quiz #${id}`, true)}
    <body class="ta-body">
    ${header}
      <main class="ta-main ta-container" style="max-width:1000px;">
        ${renderBreadcrumb([ADMIN_CRUMB, { label: 'Quizzes', href: '/admin/quizzes' }, { label: `Quiz #${id}` }])}
        ${renderAdminNav('quizzes')}
        <h1 class="ta-page-title">Edit Quiz #${id}</h1>
        <form method="post" action="/admin/quiz/${id}" class="ta-form-stack">
          <div class="ta-form-field">
            <label>Title <input name="title" value="${esc(quiz.title)}" required style="width:100%;" /></label>
          </div>
          <div class="ta-form-field">
            <label>Author <input name="author" value="${esc(quiz.author || '')}" style="width:100%;" /></label>
          </div>
          <div class="ta-form-field">
            <label>Author Email <input name="author_email" type="email" value="${esc(quiz.author_email || '')}" style="width:100%;" /></label>
            <small style="opacity:0.7;">Email address of the quiz author (for author participation logic)</small>
          </div>
          <div class="ta-form-field">
            <label>Unlock (ET) <input name="unlock_at" type="datetime-local" value="${unlockAtValue}" style="width:100%;" /></label>
            <small style="opacity:0.7;">Leave blank to keep existing time. Freeze time will be automatically set to 24 hours after unlock.</small>
          </div>
          <div class="ta-form-field">
            <label>About the Author <textarea name="author_blurb" rows="3" style="width:100%;">${esc(quiz.author_blurb || '')}</textarea></label>
          </div>
          <div class="ta-form-field">
            <label>About this Quiz <textarea name="description" rows="4" style="width:100%;">${esc(quiz.description || '')}</textarea></label>
          </div>
          <div class="ta-form-actions">
            <button type="submit" class="ta-btn ta-btn-primary">Save Changes</button>
            <a href="/admin/quizzes" class="ta-btn ta-btn-outline">Back to list</a>
          </div>
        </form>
        <section style="margin-top:32px;">
          <h2 style="margin-bottom:12px;color:#ffd700;">Questions (${qs.rows.length})</h2>
          <ul style="list-style:none;padding:0;">${list || '<li>No questions</li>'}</ul>
        </section>
        <section style="margin-top:24px;">
          <h2 style="margin-bottom:12px;color:#ffd700;">Edit Individual Questions</h2>
          <form method="post" action="/admin/quiz/${id}/questions" class="ta-form-stack">
            ${Array.from({length: 10}, (_, i) => {
              const n = i + 1;
              const q = qs.rows.find(q => q.number === n) || null;
              return `
                <div style="border:1px solid #444;padding:16px;margin:12px 0;border-radius:8px;background:#1a1a1a;">
                  <h3 style="margin:0 0 12px 0;color:#ffd700;">Question ${n}</h3>
                  <div class="ta-form-field">
                    <label>Category <input name="q${n}_category" value="${esc(q?.category || 'General')}" style="width:100%;" /></label>
                  </div>
                  <div class="ta-form-field">
                    <label>Text <textarea name="q${n}_text" rows="3" style="width:100%;">${esc(q?.text || '')}</textarea></label>
                  </div>
                  <div class="ta-form-field">
                    <label>Answer <input name="q${n}_answer" value="${esc(q?.answer || '')}" style="width:100%;" /></label>
                  </div>
                  <div class="ta-form-field">
                    <label>Ask (optional) <input name="q${n}_ask" value="${esc(q?.ask || '')}" style="width:100%;" /></label>
                    <small style="opacity:0.7;">Must appear verbatim in the Text field; used as an in-line highlight</small>
                  </div>
                </div>
              `;
            }).join('')}
            <div class="ta-form-actions">
              <button type="submit" class="ta-btn ta-btn-primary">Save All Questions</button>
            </div>
          </form>
        </section>
        <section style="margin-top:24px;">
          <h2 style="margin-bottom:12px;color:#ffd700;">Bulk Replace Questions (JSON)</h2>
          <form method="post" action="/admin/quiz/${id}/questions" class="ta-form-stack">
            <textarea name="json" rows="12" placeholder='[
  {"number":1, "text":"...", "answer":"...", "category":"General", "ask":"..."},
  ... 10 items total ...
]' style="width:100%;font-family:monospace;">${JSON.stringify(qs.rows.map(q => ({ number: q.number, text: q.text, answer: q.answer, category: q.category || 'General', ask: q.ask || null })), null, 2)}</textarea>
            <div class="ta-form-actions">
              <button type="submit" class="ta-btn ta-btn-outline">Replace Questions from JSON</button>
        </div>
          </form>
        </section>
        <section style="margin-top:24px;display:flex;flex-wrap:wrap;gap:12px;">
          <a href="/admin/quiz/${id}/analytics" class="ta-btn ta-btn-success">Analytics</a>
          <a href="/admin/quiz/${id}/grade" class="ta-btn" style="background:#2196f3;color:#fff;border-color:#2196f3;">Grade Responses</a>
          <a href="/quiz/${id}" class="ta-btn" target="_blank">View Quiz</a>
          <form method="post" action="/admin/quiz/${id}/clone"><button type="submit" class="ta-btn">Clone Quiz</button></form>
          <form method="post" action="/admin/quiz/${id}/delete" onsubmit="return confirm('Delete this quiz? This cannot be undone.');"><button type="submit" class="ta-btn ta-btn-danger">Delete Quiz</button></form>
        </section>
      </main>
      ${renderFooter(req)}
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
    const author = String(req.body.author || '').trim() || null;
    const authorEmail = String(req.body.author_email || '').trim().toLowerCase() || null;
    const authorBlurb = String(req.body.author_blurb || '').trim() || null;
    const description = String(req.body.description || '').trim() || null;
    const unlock = String(req.body.unlock_at || '').trim();
    
    if (!title) return res.status(400).send('Title required');
    
    // Build update query dynamically
    const updates = ['title=$1'];
    const values = [title];
    let paramIndex = 2;
    
    if (author !== null) {
      updates.push(`author=$${paramIndex++}`);
      values.push(author);
    }
    if (authorEmail !== null) {
      updates.push(`author_email=$${paramIndex++}`);
      values.push(authorEmail);
    }
    if (authorBlurb !== null) {
      updates.push(`author_blurb=$${paramIndex++}`);
      values.push(authorBlurb);
    }
    if (description !== null) {
      updates.push(`description=$${paramIndex++}`);
      values.push(description);
    }
    
    if (unlock) {
      const unlockUtc = etToUtc(unlock);
      const freezeUtc = new Date(unlockUtc.getTime() + 24*60*60*1000);
      updates.push(`unlock_at=$${paramIndex++}`);
      updates.push(`freeze_at=$${paramIndex++}`);
      values.push(unlockUtc, freezeUtc);
    }
    
    values.push(id);
    const query = `UPDATE quizzes SET ${updates.join(', ')} WHERE id=$${paramIndex}`;
    await pool.query(query, values);
    
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
    
    let questions = [];
    
    // Check if JSON payload is provided (bulk replace)
    if (payload) {
      try {
    const arr = JSON.parse(payload);
        if (!Array.isArray(arr)) return res.status(400).send('Invalid JSON: must be an array');
        questions = arr;
      } catch (parseErr) {
        return res.status(400).send('Invalid JSON format: ' + (parseErr?.message || String(parseErr)));
      }
    } else {
      // Parse individual question fields (q1_text, q1_answer, etc.)
      for (let i = 1; i <= 10; i++) {
        const text = String(req.body[`q${i}_text`] || '').trim();
        const answer = String(req.body[`q${i}_answer`] || '').trim();
        const category = String(req.body[`q${i}_category`] || 'General').trim();
        const ask = String(req.body[`q${i}_ask`] || '').trim() || null;
        
        if (text && answer) {
          questions.push({ number: i, text, answer, category, ask });
        }
      }
    }
    
    if (questions.length === 0) {
      return res.status(400).send('No valid questions provided');
    }
    
    // Delete existing questions and insert new ones
    await pool.query('DELETE FROM questions WHERE quiz_id = $1', [id]);
    for (const item of questions) {
      const n = Number(item.number || 0);
      if (!n || !item.text || !item.answer) continue;
      await pool.query('INSERT INTO questions(quiz_id, number, text, answer, category, ask) VALUES($1,$2,$3,$4,$5,$6)', [id, n, String(item.text), String(item.answer), String(item.category || 'General'), item.ask ? String(item.ask) : null]);
    }
    res.redirect(`/admin/quiz/${id}`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to replace questions: ' + (e?.message || String(e)));
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
        <p><a href="/quiz/${quizId}" class="ta-btn ta-btn-primary">Open Demo Quiz</a> <a href="/calendar" class="ta-btn ta-btn-outline" style="margin-left:8px;">Back to Calendar</a></p>
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
        <p><a href="/admin/quiz/${quizId}/grade" class="ta-btn ta-btn-primary">Open Grader</a> <a href="/calendar" class="ta-btn ta-btn-outline" style="margin-left:8px;">Calendar</a></p>
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
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead(`Grade • ${quiz.title}`, false)}
      <body class=\"ta-body\">
      ${header}
        <main class=\"grader-container\">
          <h1 class=\"grader-title\">Grading: ${quiz.title}</h1>
          ${isStale ? '<div style="background:#ffefef;border:1px solid #cc5555;color:#5a1a1a;padding:10px;border-radius:6px;margin-bottom:10px;">Another grader changed one or more items you were viewing. Please refresh to see the latest state.</div>' : ''}
          <div class=\"grader-date\">Viewing: <strong>Awaiting review</strong> by default (🚩 flagged always shown and prioritized). Use "Show graded / Hide graded" in each question section to include graded rows for that question.</div>
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
// --- Quiz Analytics Dashboard ---
app.get('/admin/quiz/:id/analytics', requireAdmin, async (req, res) => {
  try {
    const quizId = Number(req.params.id);
    const quiz = (await pool.query('SELECT * FROM quizzes WHERE id=$1', [quizId])).rows[0];
    if (!quiz) return res.status(404).send('Quiz not found');
    
    // Get all questions for this quiz
    const questions = (await pool.query('SELECT * FROM questions WHERE quiz_id=$1 ORDER BY number ASC', [quizId])).rows;
    
    // Get total number of players who have access
    const totalPlayers = (await pool.query('SELECT COUNT(*) as count FROM players')).rows[0].count;
    
    // Get participation stats
    const participants = (await pool.query(`
      SELECT COUNT(DISTINCT user_email) as count
      FROM responses
      WHERE quiz_id=$1
    `, [quizId])).rows[0].count;
    const participationRate = totalPlayers > 0 ? ((participants / totalPlayers) * 100).toFixed(1) : 0;
    
    // Get question-level statistics
    const questionStats = await Promise.all(questions.map(async (q) => {
      const responses = (await pool.query(`
        SELECT 
          r.response_text,
          r.override_correct,
          r.created_at,
          COUNT(*) as response_count
        FROM responses r
        WHERE r.question_id=$1
        GROUP BY r.response_text, r.override_correct, r.created_at
        ORDER BY response_count DESC
      `, [q.id])).rows;
      
      const totalResponses = responses.reduce((sum, r) => sum + parseInt(r.response_count), 0);
      const correctResponses = responses.filter(r => {
        const isCorrect = r.override_correct === true || 
          (r.override_correct === null && r.response_text && 
           r.response_text.trim().toLowerCase() === q.answer.trim().toLowerCase());
        return isCorrect;
      }).reduce((sum, r) => sum + parseInt(r.response_count), 0);
      
      const correctRate = totalResponses > 0 ? ((correctResponses / totalResponses) * 100).toFixed(1) : 0;
      
      // Get common wrong answers
      const wrongAnswers = responses
        .filter(r => {
          const isCorrect = r.override_correct === true || 
            (r.override_correct === null && r.response_text && 
             r.response_text.trim().toLowerCase() === q.answer.trim().toLowerCase());
          return !isCorrect && r.response_text && r.response_text.trim();
        })
        .slice(0, 5)
        .map(r => ({ text: r.response_text, count: r.response_count }));
      
      return {
        question: q,
        totalResponses,
        correctResponses,
        correctRate,
        wrongAnswers
      };
    }));
    
    // Calculate average score
    const playerScores = (await pool.query(`
      SELECT 
        r.user_email,
        COUNT(DISTINCT r.question_id) as questions_answered,
        SUM(CASE WHEN r.override_correct = true OR (r.override_correct IS NULL AND LOWER(TRIM(r.response_text)) = LOWER(TRIM(q.answer))) THEN 1 ELSE 0 END) as correct_count
      FROM responses r
      JOIN questions q ON q.id = r.question_id
      WHERE r.quiz_id=$1
      GROUP BY r.user_email
    `, [quizId])).rows;
    
    const totalQuestions = questions.length;
    const scores = playerScores.map(p => totalQuestions > 0 ? (p.correct_count / totalQuestions) * 100 : 0);
    const avgScore = scores.length > 0 ? (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1) : 0;
    const medianScore = scores.length > 0 ? scores.sort((a, b) => a - b)[Math.floor(scores.length / 2)].toFixed(1) : 0;
    
    // Build question stats HTML
    const questionStatsHtml = questionStats.map((stat, idx) => {
      const difficulty = parseFloat(stat.correctRate) >= 70 ? 'Easy' : 
                        parseFloat(stat.correctRate) >= 50 ? 'Medium' : 'Hard';
      const difficultyColor = parseFloat(stat.correctRate) >= 70 ? '#4caf50' : 
                             parseFloat(stat.correctRate) >= 50 ? '#ff9800' : '#f44336';
      return `
        <div style="border:1px solid #ddd;padding:16px;margin-bottom:16px;border-radius:6px;">
          <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:12px;">
            <div style="flex:1;">
              <h3 style="margin:0 0 8px 0;">Question ${stat.question.number}: ${stat.question.category || 'General'}</h3>
              <div style="opacity:0.8;margin-bottom:8px;">${stat.question.text.substring(0, 150)}${stat.question.text.length > 150 ? '...' : ''}</div>
              <div style="font-size:12px;opacity:0.7;"><strong>Answer:</strong> ${stat.question.answer}</div>
            </div>
            <div style="text-align:right;margin-left:16px;">
              <div style="font-size:24px;font-weight:bold;color:${difficultyColor};">
                ${stat.correctRate}%
              </div>
              <div style="font-size:12px;opacity:0.7;">${difficulty}</div>
            </div>
          </div>
          <div style="display:flex;gap:24px;font-size:13px;margin-top:12px;padding-top:12px;border-top:1px solid #333;">
            <div><strong>Total Responses:</strong> ${stat.totalResponses}</div>
            <div><strong>Correct:</strong> ${stat.correctResponses}/${stat.totalResponses}</div>
            <div><strong>Response Rate:</strong> ${participants > 0 ? ((stat.totalResponses / participants) * 100).toFixed(1) : 0}%</div>
          </div>
          ${stat.wrongAnswers.length > 0 ? `
            <div style="margin-top:12px;padding-top:12px;border-top:1px solid #333;">
              <div style="font-size:12px;opacity:0.7;margin-bottom:6px;"><strong>Common Wrong Answers:</strong></div>
              <div style="font-size:12px;">
                ${stat.wrongAnswers.map(w => `<span style="display:inline-block;background:#333;padding:4px 8px;margin:2px;border-radius:4px;">${w.text} (${w.count})</span>`).join('')}
              </div>
            </div>
          ` : ''}
        </div>
      `;
    }).join('');
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead(`Analytics: ${quiz.title} • Admin`, true)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container">
          <h1 class="ta-page-title">Quiz Analytics</h1>
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;margin-bottom:24px;">
            <div style="font-size:20px;font-weight:bold;margin-bottom:8px;">${quiz.title || `Quiz #${quizId}`}</div>
            ${quiz.author ? `<div style="opacity:0.8;margin-bottom:4px;">Author: ${quiz.author}</div>` : ''}
            <div style="opacity:0.8;margin-bottom:4px;">Unlocked: ${fmtEt(quiz.unlock_at)}</div>
            <div style="display:flex;gap:24px;margin-top:12px;">
              <div><strong>Total Players:</strong> ${totalPlayers}</div>
              <div><strong>Participants:</strong> ${participants}</div>
              <div><strong>Participation Rate:</strong> ${participationRate}%</div>
              <div><strong>Average Score:</strong> ${avgScore}%</div>
              <div><strong>Median Score:</strong> ${medianScore}%</div>
              <div><strong>Total Questions:</strong> ${totalQuestions}</div>
            </div>
          </div>
          
          <h2 style="margin-top:32px;margin-bottom:16px;">Question Performance</h2>
          ${questionStatsHtml || '<p>No questions found.</p>'}
          
          <p style="margin-top:24px;">
            <a href="/admin/quiz/${quizId}/grade" class="ta-btn ta-btn-outline">← Grade Responses</a>
            <a href="/admin/quizzes" class="ta-btn ta-btn-outline" style="margin-left:8px;">← Back to Quizzes</a>
          </p>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load analytics');
  }
});

// --- Admin: access & links ---
app.get('/admin/access', requireAdmin, async (req, res) => {
  const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead('Access & Links', false)}
    <body class="ta-body" style="padding:24px;">
    ${header}
      <h1>Access & Links</h1>
      ${req.query.msg ? `<p style="padding:8px 12px;background:#2e7d32;color:#fff;border-radius:4px;margin-bottom:16px;">${req.query.msg}</p>` : ''}
      <h3>Grant Access</h3>
      <form method="post" action="/admin/grant">
        <label>Email <input name="email" type="email" required /></label>
        <button type="submit">Grant</button>
      </form>
      <h3 style="margin-top:12px;">Send Magic Link</h3>
      ${req.query.msg ? `<div style="background:#4caf50;color:#fff;padding:12px;border-radius:6px;margin-bottom:16px;">${String(req.query.msg).replace(/&/g,'&amp;').replace(/</g,'&lt;')}</div>` : ''}
      <form method="post" action="/admin/send-link">
        <label>Email <input name="email" type="email" value="${req.query.email ? String(req.query.email).replace(/&/g,'&amp;').replace(/"/g,'&quot;') : ''}" required /></label>
        <button type="submit">Send Magic Link</button>
      </form>
      <h3 style="margin-top:24px;">Test Ko-fi Webhook</h3>
      <form method="post" action="/admin/test-kofi" style="border:1px solid #ddd;padding:16px;border-radius:6px;max-width:500px;">
        <div style="margin-bottom:12px;">
          <label>Test Email <input name="email" type="email" required style="width:100%;" /></label>
          <div style="font-size:12px;opacity:0.7;margin-top:4px;">This will simulate a Ko-fi donation webhook</div>
        </div>
        <div style="margin-bottom:12px;">
          <label>Donation Date (optional) <input name="created_at" type="datetime-local" style="width:100%;" /></label>
          <div style="font-size:12px;opacity:0.7;margin-top:4px;">Leave blank to use current time</div>
        </div>
        <button type="submit" style="background:#ff5e5e;color:#fff;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;">Simulate Ko-fi Donation</button>
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
    
    // Ensure email exists in players table (needed for admins too)
    await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [email]);
    
    const token = crypto.randomBytes(24).toString('base64url');
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await pool.query('INSERT INTO magic_tokens(token,email,expires_at,used) VALUES($1,$2,$3,false)', [token, email, expiresAt]);
    const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
    
    try {
      await sendMagicLink(email, token, linkUrl);
      res.redirect('/admin/access?msg=Magic link sent successfully to ' + encodeURIComponent(email));
    } catch (mailErr) {
      console.error('[admin/send-link] Email send failed:', mailErr);
      const header = await renderHeader(req);
      res.status(500).send(`
        ${renderHead('Send Link Error', false)}
        <body class="ta-body" style="padding:24px;">
        ${header}
        <main class="ta-main ta-container" style="max-width:720px; margin:0 auto;">
          <h1 class="ta-page-title" style="color:#d32f2f;">Failed to Send Magic Link</h1>
          <p style="margin-bottom:16px;"><strong>Email:</strong> ${email.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</p>
          <p style="margin-bottom:16px;"><strong>Error:</strong> ${String(mailErr.message || mailErr).replace(/&/g,'&amp;').replace(/</g,'&lt;')}</p>
          ${mailErr.message && mailErr.message.includes('refresh token') ? `
          <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:16px;margin-bottom:24px;">
            <h3 style="margin-top:0;color:#856404;">Gmail OAuth Token Expired</h3>
            <p style="margin-bottom:12px;">The Gmail refresh token has expired or been revoked. To fix this:</p>
            <ol style="margin-left:20px;margin-bottom:0;">
              <li>Go to <a href="https://console.cloud.google.com/apis/credentials" target="_blank" style="color:#ffd700;">Google Cloud Console → APIs & Services → Credentials</a></li>
              <li>Create or regenerate OAuth 2.0 credentials</li>
              <li>Generate a new refresh token using the OAuth 2.0 Playground or your OAuth flow</li>
              <li>Update the <code>GMAIL_REFRESH_TOKEN</code> environment variable with the new token</li>
            </ol>
          </div>
          ` : ''}
          <p style="margin-bottom:24px;opacity:0.8;">The magic link token was created successfully, but sending the email failed. Check server logs for details.</p>
          <div style="display:flex;gap:12px;">
            <a href="/admin/access" class="ta-btn ta-btn-primary">Back to Access</a>
            <a href="/admin/access?email=${encodeURIComponent(email)}" class="ta-btn ta-btn-outline">Try Again</a>
          </div>
        </main>
        ${renderFooter(req)}
        </body></html>
      `);
    }
  } catch (e) {
    console.error('[admin/send-link] Error:', e);
    const header = await renderHeader(req);
    res.status(500).send(`
      ${renderHead('Send Link Error', false)}
      <body class="ta-body" style="padding:24px;">
      ${header}
      <main class="ta-main ta-container" style="max-width:720px; margin:0 auto;">
        <h1 class="ta-page-title" style="color:#d32f2f;">Failed to Send Magic Link</h1>
        <p style="margin-bottom:16px;"><strong>Error:</strong> ${String(e.message || e).replace(/&/g,'&amp;').replace(/</g,'&lt;')}</p>
        <p style="margin-bottom:24px;opacity:0.8;">Check server logs for details.</p>
        <a href="/admin/access" class="ta-btn ta-btn-primary">Back to Access</a>
      </main>
      ${renderFooter(req)}
      </body></html>
    `);
  }
});

// Test Ko-fi webhook
app.post('/admin/test-kofi', requireAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    
    // Parse donation date if provided
    let createdAt = new Date();
    if (req.body.created_at) {
      const localDate = new Date(req.body.created_at);
      createdAt = localDate;
    }
    
    // Simulate Ko-fi webhook payload (same format as real webhook)
    const webhookBody = {
      type: 'donation',
      email: email,
      created_at: createdAt.toISOString()
    };
    
    // Use the actual webhook processing function
    const result = await processKofiDonation(webhookBody, true);
    
    if (!result.success) {
      if (result.beforeCutoff) {
        return res.redirect('/admin/access?msg=Donation date is before cutoff date');
      }
      return res.status(400).send(result.error || 'Failed to process webhook');
    }
    
    res.redirect(`/admin/access?msg=Ko-fi webhook simulated successfully. Magic link sent to ${result.email}`);
  } catch (e) {
    console.error('Test Ko-fi webhook error:', e);
    res.status(500).send(`Failed to simulate webhook: ${e.message}`);
  }
});

// --- Players management ---
app.get('/admin/players', requireAdmin, async (req, res) => {
  try {
    const rows = (await pool.query(`
      SELECT 
        p.id,
        p.email,
        p.username,
        p.access_granted_at,
        p.onboarding_complete,
        p.password_set_at,
        COUNT(DISTINCT r.quiz_id) as quizzes_played,
        MAX(r.created_at) as last_activity,
        CASE WHEN a.email IS NOT NULL THEN true ELSE false END as is_admin
      FROM players p
      LEFT JOIN responses r ON r.user_email = p.email
      LEFT JOIN admins a ON a.email = p.email
      GROUP BY p.id, p.email, p.username, p.access_granted_at, p.onboarding_complete, p.password_set_at, a.email
      ORDER BY p.access_granted_at DESC
    `)).rows;
    const items = rows.map(r => {
      const status = [];
      if (r.is_admin) status.push('<span style="color:#ffd700;font-weight:bold;">ADMIN</span>');
      if (r.onboarding_complete) status.push('Onboarded');
      if (r.password_set_at) status.push('Password set');
      const statusStr = status.length ? status.join(' • ') : 'Pending setup';
      return `<tr>
        <td><input type="checkbox" class="player-checkbox" value="${r.email}" /></td>
        <td><a href="/admin/players/${encodeURIComponent(r.email)}" class="ta-btn ta-btn-small" style="color:#111;text-decoration:none;">${r.email || ''}</a></td>
        <td><a href="/admin/players/${encodeURIComponent(r.email)}" class="ta-btn ta-btn-small" style="color:#111;text-decoration:none;">${r.username || '<em>Not set</em>'}</a></td>
        <td>${fmtEt(r.access_granted_at)}</td>
        <td>${statusStr}</td>
        <td>${r.quizzes_played || 0}</td>
        <td>${r.last_activity ? fmtEt(r.last_activity) : '<em>Never</em>'}</td>
        <td style="white-space:nowrap;">
          <form method="post" action="/admin/players/send-link" style="display:inline;" onsubmit="return confirm('Send magic link to ${r.email}?');">
            <input type="hidden" name="email" value="${r.email}"/>
            <button type="submit" style="padding:4px 8px;font-size:12px;margin:2px;">Send Link</button>
          </form>
          <form method="post" action="/admin/players/reset-password" style="display:inline;" onsubmit="return confirm('Reset password for ${r.email}? They will need to set a new password.');">
            <input type="hidden" name="email" value="${r.email}"/>
            <button type="submit" style="padding:4px 8px;font-size:12px;margin:2px;">Reset PW</button>
          </form>
          ${r.is_admin ? `
          <form method="post" action="/admin/players/revoke-admin" style="display:inline;" onsubmit="return confirm('Revoke admin status from ${r.email}?');">
            <input type="hidden" name="email" value="${r.email}"/>
            <button type="submit" style="padding:4px 8px;font-size:12px;margin:2px;background:#d32f2f;">Revoke Admin</button>
          </form>
          ` : `
          <form method="post" action="/admin/players/grant-admin" style="display:inline;" onsubmit="return confirm('Grant admin status to ${r.email}?');">
            <input type="hidden" name="email" value="${r.email}"/>
            <button type="submit" style="padding:4px 8px;font-size:12px;margin:2px;background:#2e7d32;">Grant Admin</button>
          </form>
          `}
          <form method="post" action="/admin/players/delete" style="display:inline;" onsubmit="return confirm('DELETE ${r.email} and all their data? This cannot be undone.');">
            <input type="hidden" name="email" value="${r.email}"/>
            <button type="submit" style="padding:4px 8px;font-size:12px;margin:2px;background:#d32f2f;color:#fff;">Delete</button>
          </form>
          <form method="post" action="/admin/players/revoke-access" style="display:inline;" onsubmit="return confirm('REVOKE ACCESS and delete all data for ${r.email}? This cannot be undone.');">
            <input type="hidden" name="email" value="${r.email}"/>
            <button type="submit" style="padding:4px 8px;font-size:12px;margin:2px;background:#d32f2f;">Revoke Access</button>
          </form>
        </td>
      </tr>`;
    }).join('');
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Players • Admin', true)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container">
          <h1 class="ta-page-title">Players</h1>
          ${req.query.msg ? `<p style="padding:8px 12px;background:#2e7d32;color:#fff;border-radius:4px;margin-bottom:16px;">${req.query.msg}</p>` : ''}
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:12px;">
            <p style="margin:0;opacity:0.8;">Total: <span id="total-count">${rows.length}</span> player${rows.length !== 1 ? 's' : ''}</p>
            <div style="display:flex;gap:8px;align-items:center;">
              <input type="text" id="player-search" placeholder="Search by email or username..." style="padding:8px 12px;border-radius:6px;border:1px solid #444;background:#1a1a1a;color:#fff;min-width:250px;" />
              <button onclick="clearSearch()" class="ta-btn ta-btn-outline" style="padding:8px 16px;">Clear</button>
            </div>
          </div>
          
          <div id="bulk-actions" style="display:none;margin-bottom:16px;padding:12px;background:#1a1a1a;border-radius:6px;">
            <div style="margin-bottom:8px;"><strong>Bulk Actions (<span id="selected-count">0</span> selected):</strong></div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <button onclick="bulkAction('send-link')" style="padding:6px 12px;background:#2196f3;color:#fff;border:none;border-radius:4px;cursor:pointer;">Send Magic Links</button>
              <button onclick="bulkAction('export-csv')" style="padding:6px 12px;background:#4caf50;color:#fff;border:none;border-radius:4px;cursor:pointer;">Export CSV</button>
              <button onclick="bulkAction('grant-admin')" style="padding:6px 12px;background:#2e7d32;color:#fff;border:none;border-radius:4px;cursor:pointer;">Grant Admin</button>
              <button onclick="bulkAction('revoke-admin')" style="padding:6px 12px;background:#ff9800;color:#fff;border:none;border-radius:4px;cursor:pointer;">Revoke Admin</button>
              <button onclick="bulkAction('reset-password')" style="padding:6px 12px;background:#9c27b0;color:#fff;border:none;border-radius:4px;cursor:pointer;">Reset Passwords</button>
              <button onclick="bulkAction('delete')" style="padding:6px 12px;background:#d32f2f;color:#fff;border:none;border-radius:4px;cursor:pointer;">Delete Players</button>
            </div>
          </div>
          
          <div style="overflow-x:auto;">
            <table border="1" cellspacing="0" cellpadding="8" style="width:100%;border-collapse:collapse;">
              <thead>
                <tr style="background:#333;">
                  <th style="text-align:left;padding:8px;"><input type="checkbox" id="select-all" onchange="toggleAll(this)" /></th>
                  <th style="text-align:left;padding:8px;">Email</th>
                  <th style="text-align:left;padding:8px;">Username</th>
                  <th style="text-align:left;padding:8px;">Access Granted</th>
                  <th style="text-align:left;padding:8px;">Status</th>
                  <th style="text-align:left;padding:8px;">Quizzes Played</th>
                  <th style="text-align:left;padding:8px;">Last Activity</th>
                  <th style="text-align:left;padding:8px;">Actions</th>
                </tr>
              </thead>
              <tbody>
                ${items || '<tr><td colspan="8">No players yet</td></tr>'}
              </tbody>
            </table>
          </div>
          <script>
            function filterPlayers() {
              const searchTerm = document.getElementById('player-search').value.toLowerCase().trim();
              const rows = document.querySelectorAll('tbody tr');
              let visibleCount = 0;
              rows.forEach(row => {
                const email = row.cells[1]?.textContent?.toLowerCase() || '';
                const username = row.cells[2]?.textContent?.toLowerCase() || '';
                const matches = !searchTerm || email.includes(searchTerm) || username.includes(searchTerm);
                row.style.display = matches ? '' : 'none';
                if (matches) visibleCount++;
              });
              document.getElementById('total-count').textContent = visibleCount;
            }
            function clearSearch() {
              document.getElementById('player-search').value = '';
              filterPlayers();
            }
            document.getElementById('player-search').addEventListener('input', filterPlayers);
            function toggleAll(checkbox) {
              document.querySelectorAll('.player-checkbox').forEach(cb => cb.checked = checkbox.checked);
              updateBulkActions();
            }
            function updateBulkActions() {
              const selected = document.querySelectorAll('.player-checkbox:checked').length;
              const bulkDiv = document.getElementById('bulk-actions');
              const countSpan = document.getElementById('selected-count');
              if (selected > 0) {
                bulkDiv.style.display = 'block';
                countSpan.textContent = selected;
              } else {
                bulkDiv.style.display = 'none';
              }
            }
            function getSelectedEmails() {
              return Array.from(document.querySelectorAll('.player-checkbox:checked')).map(cb => cb.value);
            }
            function bulkAction(action) {
              const emails = getSelectedEmails();
              if (emails.length === 0) {
                alert('No players selected');
                return;
              }
              const actions = {
                'send-link': { msg: 'Send magic links to ' + emails.length + ' player(s)?', endpoint: '/admin/players/bulk/send-link' },
                'export-csv': { msg: null, endpoint: '/admin/players/bulk/export-csv' },
                'grant-admin': { msg: 'Grant admin status to ' + emails.length + ' player(s)?', endpoint: '/admin/players/bulk/grant-admin' },
                'revoke-admin': { msg: 'Revoke admin status from ' + emails.length + ' player(s)?', endpoint: '/admin/players/bulk/revoke-admin' },
                'reset-password': { msg: 'Reset passwords for ' + emails.length + ' player(s)?', endpoint: '/admin/players/bulk/reset-password' },
                'delete': { msg: 'DELETE ' + emails.length + ' player(s) and ALL their data? This cannot be undone!', endpoint: '/admin/players/bulk/delete' }
              };
              const config = actions[action];
              if (!config) return;
              if (config.msg && !confirm(config.msg)) return;
              const form = document.createElement('form');
              form.method = 'POST';
              form.action = config.endpoint;
              emails.forEach(email => {
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'emails[]';
                input.value = email;
                form.appendChild(input);
              });
              document.body.appendChild(form);
              form.submit();
            }
            document.querySelectorAll('.player-checkbox').forEach(cb => {
              cb.addEventListener('change', updateBulkActions);
            });
          </script>
          <p style="margin-top:16px;"><a href="/admin">Back to Admin</a></p>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load players');
  }
});

// Player management actions
app.post('/admin/players/send-link', requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    const token = crypto.randomBytes(24).toString('base64url');
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await pool.query('INSERT INTO magic_tokens(token, email, expires_at, used) VALUES($1, $2, $3, false)', [token, email, expiresAt]);
    const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
    await sendMagicLink(email, token, linkUrl);
    res.redirect('/admin/players?msg=Link sent');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to send link');
  }
});

app.post('/admin/players/reset-password', requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    await pool.query('UPDATE players SET password_hash=NULL, password_set_at=NULL WHERE email=$1', [email]);
    res.redirect('/admin/players?msg=Password reset');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to reset password');
  }
});

app.post('/admin/players/grant-admin', requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    // Ensure they're in players table (should already be, but be safe)
    await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [email]);
    await pool.query('INSERT INTO admins(email) VALUES($1) ON CONFLICT (email) DO NOTHING', [email]);
    res.redirect('/admin/players?msg=Admin granted');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to grant admin');
  }
});

app.post('/admin/players/revoke-admin', requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    await pool.query('DELETE FROM admins WHERE email=$1', [email]);
    res.redirect('/admin/players?msg=Admin revoked');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to revoke admin');
  }
});
app.post('/admin/players/delete', requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    // Delete responses first (foreign key constraint)
    await pool.query('DELETE FROM responses WHERE user_email=$1', [email]);
    // Delete magic tokens
    await pool.query('DELETE FROM magic_tokens WHERE email=$1', [email]);
    // Delete player
    await pool.query('DELETE FROM players WHERE email=$1', [email]);
    // Also remove from admins if they were an admin
    await pool.query('DELETE FROM admins WHERE email=$1', [email]);
    res.redirect('/admin/players?msg=Player deleted');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to delete player');
  }
});

app.post('/admin/players/revoke-access', requireAdmin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).send('Email required');
    // Delete responses first (foreign key constraint)
    await pool.query('DELETE FROM responses WHERE user_email=$1', [email]);
    // Delete player
    await pool.query('DELETE FROM players WHERE email=$1', [email]);
    // Also remove from admins if they were an admin
    await pool.query('DELETE FROM admins WHERE email=$1', [email]);
    res.redirect('/admin/players?msg=Access revoked');
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to revoke access');
  }
});

// Bulk player operations
app.post('/admin/players/bulk/send-link', requireAdmin, async (req, res) => {
  try {
    const emails = Array.isArray(req.body['emails[]']) ? req.body['emails[]'] : [req.body['emails[]']].filter(Boolean);
    if (emails.length === 0) return res.status(400).send('No emails provided');
    let sent = 0;
    let failed = 0;
    for (const email of emails) {
      try {
        const e = String(email || '').trim().toLowerCase();
        if (!e) continue;
        const token = crypto.randomBytes(24).toString('base64url');
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
        await pool.query('INSERT INTO magic_tokens(token, email, expires_at, used) VALUES($1, $2, $3, false)', [token, e, expiresAt]);
        const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
        await sendMagicLink(e, token, linkUrl);
        sent++;
      } catch (err) {
        console.error('Failed to send link to', email, err);
        failed++;
      }
    }
    res.redirect(`/admin/players?msg=${sent} link(s) sent${failed > 0 ? `, ${failed} failed` : ''}`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to send links');
  }
});

app.post('/admin/players/bulk/reset-password', requireAdmin, async (req, res) => {
  try {
    const emails = Array.isArray(req.body['emails[]']) ? req.body['emails[]'] : [req.body['emails[]']].filter(Boolean);
    if (emails.length === 0) return res.status(400).send('No emails provided');
    for (const email of emails) {
      const e = String(email || '').trim().toLowerCase();
      if (!e) continue;
      await pool.query('UPDATE players SET password_hash=NULL, password_set_at=NULL WHERE email=$1', [e]);
    }
    res.redirect(`/admin/players?msg=${emails.length} password(s) reset`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to reset passwords');
  }
});

app.post('/admin/players/bulk/grant-admin', requireAdmin, async (req, res) => {
  try {
    const emails = Array.isArray(req.body['emails[]']) ? req.body['emails[]'] : [req.body['emails[]']].filter(Boolean);
    if (emails.length === 0) return res.status(400).send('No emails provided');
    for (const email of emails) {
      const e = String(email || '').trim().toLowerCase();
      if (!e) continue;
      // Ensure they're in players table (should already be, but be safe)
      await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [e]);
      await pool.query('INSERT INTO admins(email) VALUES($1) ON CONFLICT (email) DO NOTHING', [e]);
    }
    res.redirect(`/admin/players?msg=${emails.length} admin(s) granted`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to grant admin');
  }
});

app.post('/admin/players/bulk/revoke-admin', requireAdmin, async (req, res) => {
  try {
    const emails = Array.isArray(req.body['emails[]']) ? req.body['emails[]'] : [req.body['emails[]']].filter(Boolean);
    if (emails.length === 0) return res.status(400).send('No emails provided');
    for (const email of emails) {
      const e = String(email || '').trim().toLowerCase();
      if (!e) continue;
      await pool.query('DELETE FROM admins WHERE email=$1', [e]);
    }
    res.redirect(`/admin/players?msg=${emails.length} admin(s) revoked`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to revoke admin');
  }
});

app.post('/admin/players/bulk/delete', requireAdmin, async (req, res) => {
  try {
    const emails = Array.isArray(req.body['emails[]']) ? req.body['emails[]'] : [req.body['emails[]']].filter(Boolean);
    if (emails.length === 0) return res.status(400).send('No emails provided');
    let deleted = 0;
    let failed = 0;
    for (const email of emails) {
      try {
        const e = String(email || '').trim().toLowerCase();
        if (!e) continue;
        // Delete responses first (foreign key constraint)
        await pool.query('DELETE FROM responses WHERE user_email=$1', [e]);
        // Delete magic tokens
        await pool.query('DELETE FROM magic_tokens WHERE email=$1', [e]);
        // Delete player
        await pool.query('DELETE FROM players WHERE email=$1', [e]);
        // Also remove from admins if they were an admin
        await pool.query('DELETE FROM admins WHERE email=$1', [e]);
        deleted++;
      } catch (err) {
        console.error('Failed to delete player', email, err);
        failed++;
      }
    }
    res.redirect(`/admin/players?msg=${deleted} player(s) deleted${failed > 0 ? `, ${failed} failed` : ''}`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to delete players');
  }
});

app.post('/admin/players/bulk/export-csv', requireAdmin, async (req, res) => {
  try {
    const emails = Array.isArray(req.body['emails[]']) ? req.body['emails[]'] : [req.body['emails[]']].filter(Boolean);
    if (emails.length === 0) return res.status(400).send('No emails provided');
    const players = (await pool.query(`
      SELECT 
        p.email,
        p.username,
        p.access_granted_at,
        p.onboarding_complete,
        p.password_set_at,
        COUNT(DISTINCT r.quiz_id) as quizzes_played,
        MAX(r.created_at) as last_activity,
        CASE WHEN a.email IS NOT NULL THEN true ELSE false END as is_admin
      FROM players p
      LEFT JOIN responses r ON r.user_email = p.email
      LEFT JOIN admins a ON a.email = p.email
      WHERE p.email = ANY($1)
      GROUP BY p.email, p.username, p.access_granted_at, p.onboarding_complete, p.password_set_at, a.email
    `, [emails])).rows;
    
    const csv = [
      ['Email', 'Username', 'Access Granted', 'Onboarded', 'Password Set', 'Admin', 'Quizzes Played', 'Last Activity'].join(','),
      ...players.map(p => [
        p.email || '',
        p.username || '',
        p.access_granted_at ? fmtEt(p.access_granted_at) : '',
        p.onboarding_complete ? 'Yes' : 'No',
        p.password_set_at ? 'Yes' : 'No',
        p.is_admin ? 'Yes' : 'No',
        p.quizzes_played || 0,
        p.last_activity ? fmtEt(p.last_activity) : ''
      ].map(f => `"${String(f).replace(/"/g, '""')}"`).join(','))
    ].join('\n');
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="players-export-${new Date().toISOString().split('T')[0]}.csv"`);
    res.send(csv);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to export');
  }
});
// --- Individual Player Profile ---
app.get('/admin/players/:email', requireAdmin, async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email).toLowerCase();
    const player = (await pool.query('SELECT * FROM players WHERE email=$1', [email])).rows[0];
    if (!player) return res.status(404).send('Player not found');
    
    // Get all quiz attempts with scores
    const quizAttempts = (await pool.query(`
      SELECT 
        q.id,
        q.title,
        q.unlock_at,
        q.freeze_at,
        q.author,
        COUNT(DISTINCT r.question_id) as questions_answered,
        COUNT(DISTINCT qq.id) as total_questions,
        SUM(CASE WHEN r.override_correct = true OR (r.override_correct IS NULL AND LOWER(TRIM(r.response_text)) = LOWER(TRIM(qq.answer))) THEN 1 ELSE 0 END) as correct_count,
        SUM(r.points) as total_points,
        MIN(r.created_at) as first_response,
        MAX(r.created_at) as last_response
      FROM quizzes q
      LEFT JOIN questions qq ON qq.quiz_id = q.id
      LEFT JOIN responses r ON r.quiz_id = q.id AND r.user_email = $1 AND r.question_id = qq.id
      WHERE EXISTS (SELECT 1 FROM responses r2 WHERE r2.quiz_id = q.id AND r2.user_email = $1)
      GROUP BY q.id, q.title, q.unlock_at, q.freeze_at, q.author
      ORDER BY q.unlock_at DESC
    `, [email])).rows;
    
    // Get detailed responses for all quizzes
    const allResponses = (await pool.query(`
      SELECT 
        r.id,
        r.quiz_id,
        r.question_id,
        r.response_text,
        r.points,
        r.locked,
        r.override_correct,
        r.created_at,
        q.title as quiz_title,
        qq.number as question_number,
        qq.text as question_text,
        qq.answer as correct_answer,
        qq.category
      FROM responses r
      JOIN quizzes q ON q.id = r.quiz_id
      JOIN questions qq ON qq.id = r.question_id
      WHERE r.user_email = $1
      ORDER BY q.unlock_at DESC, qq.number ASC
    `, [email])).rows;
    
    // Calculate overall stats
    const totalQuizzes = quizAttempts.length;
    const totalQuestions = allResponses.length;
    const totalCorrect = allResponses.filter(r => r.override_correct === true || (r.override_correct === null && r.response_text && r.response_text.trim().toLowerCase() === r.correct_answer.trim().toLowerCase())).length;
    const totalPoints = allResponses.reduce((sum, r) => sum + (r.points || 0), 0);
    const avgScore = totalQuizzes > 0 ? (totalCorrect / totalQuestions * 100).toFixed(1) : 0;
    
    // Build quiz attempts HTML
    const attemptsHtml = quizAttempts.map(q => {
      const score = q.total_questions > 0 ? ((q.correct_count / q.total_questions) * 100).toFixed(1) : 0;
      const isComplete = q.questions_answered === q.total_questions;
      return `
        <div style="border:1px solid #ddd;padding:12px;margin-bottom:12px;border-radius:6px;">
          <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px;">
            <div>
              <strong><a href="/admin/quiz/${q.id}/grade" class="ta-btn ta-btn-small" style="color:#111;text-decoration:none;">${q.title || `Quiz #${q.id}`}</a></strong>
              ${q.author ? `<span style="opacity:0.7;margin-left:8px;">by ${q.author}</span>` : ''}
            </div>
            <div style="text-align:right;">
              <div style="font-size:18px;font-weight:bold;color:${score >= 70 ? '#4caf50' : score >= 50 ? '#ff9800' : '#f44336'};">
                ${score}%
              </div>
              <div style="font-size:12px;opacity:0.7;">${q.correct_count}/${q.total_questions} correct</div>
            </div>
          </div>
          <div style="font-size:12px;opacity:0.7;margin-bottom:8px;">
            Unlocked: ${fmtEt(q.unlock_at)} • ${isComplete ? 'Complete' : `Incomplete (${q.questions_answered}/${q.total_questions})`}
          </div>
          <div style="font-size:12px;opacity:0.7;">
            Points: ${q.total_points || 0} • First response: ${q.first_response ? fmtEt(q.first_response) : 'N/A'}
          </div>
        </div>
      `;
    }).join('');
    
    // Build responses HTML grouped by quiz
    const responsesByQuiz = {};
    allResponses.forEach(r => {
      if (!responsesByQuiz[r.quiz_id]) {
        responsesByQuiz[r.quiz_id] = {
          title: r.quiz_title,
          responses: []
        };
      }
      responsesByQuiz[r.quiz_id].responses.push(r);
    });
    
    const responsesHtml = Object.entries(responsesByQuiz).map(([quizId, data]) => {
      const quizResponses = data.responses.map(r => {
        const isCorrect = r.override_correct === true || (r.override_correct === null && r.response_text && r.response_text.trim().toLowerCase() === r.correct_answer.trim().toLowerCase());
        const status = r.override_correct === true ? 'Correct (override)' : 
                      r.override_correct === false ? 'Incorrect (override)' :
                      isCorrect ? 'Correct' : 'Incorrect';
        return `
          <tr>
            <td>Q${r.question_number}</td>
            <td>${r.category || 'General'}</td>
            <td>${r.question_text.substring(0, 80)}${r.question_text.length > 80 ? '...' : ''}</td>
            <td>${r.response_text || '<em>No answer</em>'}</td>
            <td>${r.correct_answer}</td>
            <td style="color:${isCorrect ? '#4caf50' : '#f44336'};">${status}</td>
            <td>${r.points || 0}</td>
            <td><a href="/admin/quiz/${r.quiz_id}/grade?highlight=${r.id}">Review</a></td>
          </tr>
        `;
      }).join('');
      return `
        <div style="margin-bottom:24px;">
          <h3 style="margin-bottom:8px;">${data.title || `Quiz #${quizId}`}</h3>
          <table border="1" cellspacing="0" cellpadding="6" style="width:100%;border-collapse:collapse;font-size:13px;">
            <thead>
              <tr style="background:#333;">
                <th>Q#</th>
                <th>Category</th>
                <th>Question</th>
                <th>Response</th>
                <th>Correct Answer</th>
                <th>Status</th>
                <th>Points</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>${quizResponses}</tbody>
          </table>
        </div>
      `;
    }).join('');
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead(`Player: ${player.username || player.email} • Admin`, true)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container">
          <h1 class="ta-page-title">Player Profile</h1>
          <div style="background:#1a1a1a;padding:16px;border-radius:8px;margin-bottom:24px;">
            <div style="font-size:20px;font-weight:bold;margin-bottom:8px;">${player.username || '<em>No username</em>'}</div>
            <div style="opacity:0.8;margin-bottom:4px;">Email: ${player.email}</div>
            <div style="opacity:0.8;margin-bottom:4px;">Access granted: ${fmtEt(player.access_granted_at)}</div>
            <div style="display:flex;gap:24px;margin-top:12px;">
              <div><strong>Total Quizzes:</strong> ${totalQuizzes}</div>
              <div><strong>Total Questions:</strong> ${totalQuestions}</div>
              <div><strong>Correct:</strong> ${totalCorrect}/${totalQuestions}</div>
              <div><strong>Average Score:</strong> ${avgScore}%</div>
              <div><strong>Total Points:</strong> ${totalPoints}</div>
            </div>
          </div>
          
          <h2 style="margin-top:32px;margin-bottom:16px;">Quiz Attempts</h2>
          ${attemptsHtml || '<p>No quiz attempts yet.</p>'}
          
          <h2 style="margin-top:32px;margin-bottom:16px;">Detailed Responses</h2>
          ${responsesHtml || '<p>No responses yet.</p>'}
          
          <p style="margin-top:24px;"><a href="/admin/players" class="ta-btn ta-btn-outline">← Back to Players</a></p>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load player profile');
  }
});

// --- Admins management (list/add/remove) ---
app.get('/admin/admins', requireAdmin, async (_req, res) => {
  try {
    const rows = (await pool.query('SELECT email, created_at FROM admins ORDER BY email ASC')).rows;
    const items = rows.map(r => `<tr><td>${r.email}</td><td>${fmtEt(r.created_at)}</td><td>
      <form method="post" action="/admin/admins/remove" onsubmit="return confirm('Remove admin ${r.email}?');" style="display:inline;">
        <input type="hidden" name="email" value="${r.email}"/>
        <button type="submit">Remove</button>
      </form>
    </td></tr>`).join('');
    const header = await renderHeader(_req);
    res.type('html').send(`
      ${renderHead('Admins', false)}
      <body class="ta-body" style="padding:24px;">
      ${header}
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
        <p style="margin-top:16px;"><a href="/admin" class="ta-btn ta-btn-outline">Back</a></p>
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
    // Add to players table first (required for authentication and player management)
    await pool.query('INSERT INTO players(email, access_granted_at) VALUES($1, NOW()) ON CONFLICT (email) DO NOTHING', [email]);
    // Then add to admins table
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
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
      await pool.query('INSERT INTO magic_tokens(token,email,expires_at,used) VALUES($1,$2,$3,false)', [token, email, expiresAt]);
      const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
      try {
        await sendMagicLink(email, token, linkUrl);
        sent++;
      } catch (mailErr) {
        console.warn('Send mail failed for', email, mailErr?.message || mailErr);
      }
    }
    res.type('html').send(`<html><body style="font-family: system-ui; padding:24px;"><h1>Magic links sent</h1><p>Sent ${sent} link(s) to ${rows.length} admin(s).</p><p><a href="/admin/admins" class="ta-btn ta-btn-outline">Back</a></p></body></html>`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to send links');
  }
});

// --- Admin: Send Announcements ---
app.get('/admin/announcements', requireAdmin, async (req, res) => {
  try {
    // Get count of players who have announcements enabled
    const countResult = await pool.query(`
      SELECT COUNT(*) as count 
      FROM players 
      WHERE email_notifications_enabled = true 
        AND email_announcements = true
    `);
    const recipientCount = parseInt(countResult.rows[0]?.count || 0);
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Send Announcement • Admin', true)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container" style="max-width:800px;">
          <h1 class="ta-page-title">Send Announcement</h1>
          <p style="margin-bottom:24px;"><a href="/admin" class="ta-btn ta-btn-outline">← Back to Admin</a></p>
          
          <div style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:24px;margin-bottom:24px;">
            <p style="margin:0;opacity:0.9;">This announcement will be sent to <strong>${recipientCount}</strong> player${recipientCount !== 1 ? 's' : ''} who have announcements enabled.</p>
          </div>
          
          <form method="post" action="/admin/announcements" style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:24px;">
            <div style="margin-bottom:20px;">
              <label style="display:block;margin-bottom:8px;font-weight:bold;">Subject</label>
              <input type="text" name="subject" required style="width:100%;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:16px;" placeholder="Announcement subject line" />
            </div>
            
            <div style="margin-bottom:20px;">
              <label style="display:block;margin-bottom:8px;font-weight:bold;">Message</label>
              <textarea name="message" required rows="12" style="width:100%;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:14px;font-family:inherit;resize:vertical;" placeholder="Enter your announcement message here. You can use plain text or basic HTML."></textarea>
              <div style="font-size:12px;opacity:0.7;margin-top:4px;">Basic HTML is supported (e.g., &lt;strong&gt;, &lt;em&gt;, &lt;a&gt;, &lt;br&gt;)</div>
            </div>
            
            <div style="margin-top:24px;">
              <button type="submit" class="ta-btn ta-btn-primary" data-confirm="Send announcement to ${recipientCount} player${recipientCount !== 1 ? 's' : ''}?">Send Announcement</button>
              <a href="/admin" class="ta-btn ta-btn-outline" style="margin-left:8px;">Cancel</a>
            </div>
          </form>
        </main>
        ${renderFooter(req)}
        <script src="/js/common-enhancements.js?v=${ASSET_VERSION}"></script>
      </body></html>
    `);
  } catch (e) {
    console.error('Error loading announcements page:', e);
    res.status(500).send('Failed to load announcements page');
  }
});
app.post('/admin/announcements', requireAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const subject = String(req.body.subject || '').trim();
    const message = String(req.body.message || '').trim();
    
    if (!subject || !message) {
      return res.status(400).send('Subject and message are required');
    }
    
    // Get all players who have announcements enabled
    const players = await pool.query(`
      SELECT email, username 
      FROM players 
      WHERE email_notifications_enabled = true 
        AND email_announcements = true
    `);
    
    let sent = 0;
    let failed = 0;
    const errors = [];
    
    // Create HTML email template
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(90deg, #FFA726 0%, #FFC46B 100%); color: #111; padding: 20px; border-radius: 8px 8px 0 0; text-align: center; }
          .content { background: #f9f9f9; padding: 24px; border: 1px solid #ddd; border-top: none; }
          .footer { text-align: center; padding: 16px; color: #666; font-size: 12px; }
          a { color: #FFA726; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1 style="margin: 0;">Trivia Advent-ure</h1>
        </div>
        <div class="content">
          ${message.replace(/\n/g, '<br>')}
        </div>
        <div class="footer">
          <p>You're receiving this because you have announcements enabled in your email preferences.</p>
          <p><a href="${process.env.PUBLIC_BASE_URL || 'https://triviaadventure.org'}/account/preferences">Manage email preferences</a></p>
        </div>
      </body>
      </html>
    `;
    
    // Send to each player
    for (const player of players.rows) {
      try {
        await sendHTMLEmail(player.email, subject, htmlContent);
        sent++;
        // Small delay to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (e) {
        failed++;
        errors.push({ email: player.email, error: e.message });
        console.error('Failed to send announcement to ' + player.email + ':', e);
      }
    }
    
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Announcement Sent • Admin', true)}
      <body class="ta-body">
        ${header}
        <main class="ta-main ta-container" style="max-width:800px;">
          <h1 class="ta-page-title">Announcement Sent</h1>
          <div style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:24px;margin-bottom:24px;">
            <p style="font-size:18px;margin:0 0 16px 0;"><strong>Successfully sent:</strong> ${sent} email${sent !== 1 ? 's' : ''}</p>
            ${failed > 0 ? '<p style="font-size:18px;margin:0;color:#d32f2f;"><strong>Failed:</strong> ' + failed + ' email' + (failed !== 1 ? 's' : '') + '</p>' : ''}
          </div>
          
          ${errors.length > 0 ? `
          <div style="background:#2a1a1a;border:1px solid #d32f2f;border-radius:8px;padding:16px;margin-bottom:24px;">
            <h3 style="margin:0 0 12px 0;color:#d32f2f;">Errors:</h3>
            <ul style="margin:0;padding-left:20px;">
              ${errors.map(e => '<li>' + e.email + ': ' + e.error + '</li>').join('')}
            </ul>
          </div>
          ` : ''}
          
          <div style="margin-top:24px;">
            <a href="/admin/announcements" class="ta-btn ta-btn-primary">Send Another</a>
            <a href="/admin" class="ta-btn ta-btn-outline" style="margin-left:8px;">Back to Admin</a>
          </div>
        </main>
        ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error('Error sending announcements:', e);
    res.status(500).send('Failed to send announcements');
  }
});

// --- Contact Page ---
app.get('/contact', async (req, res) => {
    const header = await renderHeader(req);
    res.type('html').send(`
    ${renderHead('Contact Us', false)}
    <body class="ta-body" style="padding:24px;">
        ${header}
      <div style="max-width:600px;margin:0 auto;">
        <h1 style="color:#ffd700;margin-bottom:24px;">Contact Us</h1>

        <p style="opacity:0.9;margin-bottom:24px;">Have a question, feedback, or need help? We'd love to hear from you! Fill out the form below and we'll get back to you as soon as possible.</p>

        <form method="post" action="/contact" style="background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:24px;">
          <div style="margin-bottom:20px;">
            <label style="display:block;margin-bottom:8px;font-weight:bold;color:#ffd700;">Name *</label>
            <input type="text" name="name" required style="width:100%;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:16px;" placeholder="Your full name" />
          </div>

          <div style="margin-bottom:20px;">
            <label style="display:block;margin-bottom:8px;font-weight:bold;color:#ffd700;">Email *</label>
            <input type="email" name="email" required style="width:100%;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:16px;" placeholder="your.email@example.com" />
          </div>

          <div style="margin-bottom:20px;">
            <label style="display:block;margin-bottom:8px;font-weight:bold;color:#ffd700;">Subject *</label>
            <input type="text" name="subject" required style="width:100%;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:16px;" placeholder="What's this about?" />
          </div>

          <div style="margin-bottom:24px;">
            <label style="display:block;margin-bottom:8px;font-weight:bold;color:#ffd700;">Message *</label>
            <textarea name="message" required rows="6" style="width:100%;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:16px;font-family:inherit;resize:vertical;" placeholder="Tell us what's on your mind..."></textarea>
          </div>

          <button type="submit" class="ta-btn ta-btn-primary" style="width:100%;padding:12px;font-size:16px;">Send Message</button>
              </form>
          </div>
      ${renderFooter(req)}
    </body>
  `);
});

app.post('/contact', express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
      return res.status(400).send(`
        <html><body style="font-family: system-ui; padding:24px;">
          <h1>Error</h1>
          <p>All fields are required. Please go back and fill out the complete form.</p>
          <a href="/contact" class="ta-btn ta-btn-outline">Try Again</a>
      </body></html>
    `);
    }

    // Send email to the team
    const emailContent = `
      New contact form submission from Trivia Advent-ure Calendar:

      From: ${name} <${email}>
      Subject: ${subject}

      Message:
      ${message}

      ---
      Sent via contact form at ${new Date().toISOString()}
    `;

    await sendHTMLEmail('Trivia.Adventure12124@gmail.com', `Contact Form: ${subject}`, `<pre>${emailContent.replace(/\n/g, '<br>')}</pre>`);

    res.type('html').send(`
      ${renderHead('Message Sent', false)}
      <body class="ta-body" style="padding:24px;">
        ${await renderHeader(req)}
        <div style="max-width:600px;margin:0 auto;text-align:center;">
          <h1 style="color:#ffd700;margin-bottom:24px;">Message Sent!</h1>
          <p style="opacity:0.9;margin-bottom:24px;">Thank you for contacting us! We've received your message and will get back to you as soon as possible.</p>
          <a href="/" class="ta-btn ta-btn-primary">Return Home</a>
        </div>
        ${renderFooter(req)}
      </body>
    `);

  } catch (error) {
    console.error('Contact form error:', error);
    res.status(500).send(`
      <html><body style="font-family: system-ui; padding:24px;">
        <h1>Error</h1>
        <p>Sorry, there was an error sending your message. Please try again later or email us directly at <a href="mailto:Trivia.Adventure12124@gmail.com">Trivia.Adventure12124@gmail.com</a></p>
        <a href="/contact" class="ta-btn ta-btn-outline">Try Again</a>
      </body></html>
    `);
}
});

// --- FAQ Page ---
app.get('/faq', async (req, res) => {
  const header = await renderHeader(req);
  res.type('html').send(`
    ${renderHead('FAQ', false)}
    <body class="ta-body" style="padding:24px;">
      ${header}
      <div style="max-width:800px;margin:0 auto;">
        <h1 style="color:#ffd700;margin-bottom:24px;">Frequently Asked Questions</h1>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">What is Trivia Advent-ure Calendar?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">Trivia Advent-ure Calendar is a daily trivia event that runs throughout December, featuring 48 unique quiz challenges created by different authors. Each day brings new trivia questions to test your knowledge while supporting charitable causes.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">How does the event work?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">From December 1st through December 24th, quizzes will unlock every 12 hours (at midnight and noon Eastern). So that's 48 total quizzes written by 48 different authors in 48 different topics.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">When do quizzes become available?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">Quizzes unlock every 12 hours (at midnight and noon Eastern) from December 1st through December 24th.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">How do I participate?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">This is a fundraising venture, so players receive access by making a donation to the Calendar's Ko-Fi page. Suggested donation is $25 per player, but we operate under a "donate what you can" model so that players can enjoy the experience regardless of economic situation.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">Do I need to create an account?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">After you make a donation, you'll receive an email with a special link to grant you access to the site. From there, you can let us know if you've donated so that you can play, as a gift for someone else to play, or both! You'll be prompted to set a username and password during this process.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">Is participation free?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">This is a fundraising venture, so participation requires a donation to the Calendar's Ko-Fi page. We operate under a "donate what you can" model - suggested donation is $25 per player, but you can contribute any amount that works for your situation. We also have a gifting process where donors can purchase access for others.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">How do I play a quiz?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">Access the Calendar page and you'll see 24 numbered boxes, representing each day from December 1 to December 24. Each door unlocks at the start of each day, giving you access to that day's AM quiz, and at noon that day's PM quiz. Each quiz is 10 questions, presented all at once.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">How are answers scored?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">Answers are compared to the official correct answer and to any other matching responses. The Advent-ure team will regularly check responses, making grading decisions for every response. Answers are marked either correct or incorrect; no partial credit.</p>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">Scoring works like this: Questions are worth points based on consecutive correct answers (1 point for the first correct answer, 2 points for the second consecutive correct, 3 for the third, and so on). Each player *must* choose one question per quiz to "lock" - that question is worth a flat 5 points when answered correctly and doesn't interrupt your streak. Incorrect answers reset your streak to zero.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">Can I change my answers?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">Once a response is submitted, there's no way to amend your answer(s). Read closely, make sure you answer the question being asked, and double-check your answers before submitting.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">Can I participate in multiple quizzes?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">Every quiz is available (after it unlocks) for every registered player.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">Are there prizes?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">As this is a fundraising venture and a massive trivia undertaking without proctors or cheat prevention tools, there is no equitable way to ensure that high-scoring players are competing fairly. For that reason, the only "prize" is pride at how you ended up on the leaderboards.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">Who creates the quizzes?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">Each quiz was written by a trivia professional or enthusiast. 48 quizzes, 48 authors who you'll learn about when their quiz becomes available.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">What types of questions can I expect?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">The sky's the limit on what to expect. Since we have dozens of guest writers, quizzes may vary wildly in topic, difficulty, voice, etc. Each quiz is intended to have a single theme, however, and many quizzes will naturally feature ideas around the holiday season.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">What if I have technical difficulties?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">This site is under active development, so we anticipate there may be technical issues. Any such issues should be brought to the attention of the Trivia Advent-ure Calendar team at <a href="mailto:Trivia.Adventure12124@gmail.com">Trivia.Adventure12124@gmail.com</a>, and we will work to resolve those issues ASAP.</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">Can I play on mobile devices?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">The site is designed to work from any browser on any device, but if you find any issues with accessing the calendar from a mobile device, please let us know!</p>
        </div>

        <div class="faq-section" style="margin-bottom:32px;">
          <h2 style="color:#ffd700;margin-bottom:16px;">What time zone are the quiz times in?</h2>
          <p style="opacity:0.9;line-height:1.6;margin-bottom:16px;">The calendar runs on Eastern Standard Time.</p>
        </div>

      </div>
      ${renderFooter(req)}
    </body>
  `);
});

// ... (rest of the code remains unchanged)