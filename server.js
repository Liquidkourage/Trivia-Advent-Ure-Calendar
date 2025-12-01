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
import multer from 'multer';
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
      used BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    -- Add created_at column to existing tables if it doesn't exist
    DO $$ BEGIN ALTER TABLE magic_tokens ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(); EXCEPTION WHEN others THEN NULL; END $$;
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
      ALTER TABLE quizzes ADD COLUMN IF NOT EXISTS quiz_type TEXT;
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
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS access_choice TEXT;
    EXCEPTION WHEN others THEN NULL; END $$;
    DO $$ BEGIN
      ALTER TABLE players ADD COLUMN IF NOT EXISTS gift_recipient_email CITEXT;
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
    DO $$ BEGIN
      ALTER TABLE responses ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ;
    EXCEPTION WHEN others THEN NULL; END $$;
    -- Backfill submitted_at for existing responses that have been submitted
    -- If a player has a locked question, they've submitted (locking is required for submission)
    -- Use the most recent created_at from their responses as the submitted_at timestamp
    DO $$ 
    BEGIN
      UPDATE responses r
      SET submitted_at = (
        SELECT MAX(created_at) 
        FROM responses r2 
        WHERE r2.quiz_id = r.quiz_id 
          AND r2.user_email = r.user_email
      )
      WHERE r.submitted_at IS NULL
        AND EXISTS (
          SELECT 1 FROM responses r3
          WHERE r3.quiz_id = r.quiz_id
            AND r3.user_email = r.user_email
            AND r3.locked = true
        );
    EXCEPTION WHEN others THEN NULL; 
    END $$;

    -- Donations table to track Ko-fi donations
    CREATE TABLE IF NOT EXISTS donations (
      id SERIAL PRIMARY KEY,
      email CITEXT NOT NULL,
      amount NUMERIC NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      kofi_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_donations_email ON donations(email);
    CREATE INDEX IF NOT EXISTS idx_donations_created_at ON donations(created_at);

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
// --- Quiz unlock notification email (single recipient - kept for backward compatibility) ---
async function sendQuizUnlockEmail(email, quizTitle, quizId, unlockTime) {
  const baseUrl = process.env.PUBLIC_BASE_URL || '';
  const quizUrl = `${baseUrl}/quiz/${quizId}`;
  const preferencesUrl = `${baseUrl}/account/preferences`;
  
  // Escape HTML in quiz title to prevent XSS
  const escapedTitle = String(quizTitle || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  
  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body { font-family: system-ui, -apple-system, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(90deg, #FFA726 0%, #FFC46B 100%); color: #111; padding: 20px; border-radius: 8px 8px 0 0; text-align: center; }
        .content { background: #f9f9f9; padding: 24px; border: 1px solid #ddd; border-top: none; }
        .footer { text-align: center; padding: 16px; color: #666; font-size: 12px; border-top: 1px solid #ddd; }
        .cta-button { display: inline-block; background: #FFA726; color: #111; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0; }
        .opt-out { margin-top: 24px; padding-top: 16px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
        a { color: #FFA726; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1 style="margin: 0;">Trivia Advent-ure</h1>
      </div>
      <div class="content">
        <h2 style="margin-top: 0;">New Quiz Unlocked!</h2>
        <p>A new quiz has just unlocked:</p>
        <p style="font-size: 18px; font-weight: bold; color: #FFA726;">${escapedTitle}</p>
        <p style="opacity: 0.8;">Unlocked at ${unlockTime}</p>
        <div style="text-align: center;">
          <a href="${quizUrl}" class="cta-button">Play Now</a>
        </div>
        <div class="opt-out">
          <p style="margin: 0;"><strong>Don't want these notifications?</strong> You can opt out of quiz unlock emails in your <a href="${preferencesUrl}">account preferences</a>.</p>
        </div>
      </div>
      <div class="footer">
        <p>Trivia Advent-ure Calendar</p>
      </div>
    </body>
    </html>
  `;
  
  const textContent = `New Quiz Unlocked!\r\n\r\nA new quiz has just unlocked: ${quizTitle}\r\nUnlocked at ${unlockTime}\r\n\r\nPlay now: ${quizUrl}\r\n\r\nDon't want these notifications? You can opt out of quiz unlock emails in your account preferences: ${preferencesUrl}`;
  
  await sendHTMLEmail(email, `New Quiz Unlocked: ${quizTitle}`, htmlContent);
}

// --- Quiz unlock notification email (bulk with BCC) ---
async function sendQuizUnlockEmailBulk(recipientEmails, quizTitle, quizId, unlockTime) {
  if (!recipientEmails || recipientEmails.length === 0) return;
  
  const baseUrl = process.env.PUBLIC_BASE_URL || '';
  const quizUrl = `${baseUrl}/quiz/${quizId}`;
  const preferencesUrl = `${baseUrl}/account/preferences`;
  
  // Escape HTML in quiz title to prevent XSS
  const escapedTitle = String(quizTitle || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  
  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
        body { font-family: system-ui, -apple-system, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(90deg, #FFA726 0%, #FFC46B 100%); color: #111; padding: 20px; border-radius: 8px 8px 0 0; text-align: center; }
        .content { background: #f9f9f9; padding: 24px; border: 1px solid #ddd; border-top: none; }
        .footer { text-align: center; padding: 16px; color: #666; font-size: 12px; border-top: 1px solid #ddd; }
        .cta-button { display: inline-block; background: #FFA726; color: #111; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; margin: 16px 0; }
        .opt-out { margin-top: 24px; padding-top: 16px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
        a { color: #FFA726; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1 style="margin: 0;">Trivia Advent-ure</h1>
      </div>
      <div class="content">
        <h2 style="margin-top: 0;">New Quiz Unlocked!</h2>
        <p>A new quiz has just unlocked:</p>
        <p style="font-size: 18px; font-weight: bold; color: #FFA726;">${escapedTitle}</p>
        <p style="opacity: 0.8;">Unlocked at ${unlockTime}</p>
        <div style="text-align: center;">
          <a href="${quizUrl}" class="cta-button">Play Now</a>
        </div>
        <div class="opt-out">
          <p style="margin: 0;"><strong>Don't want these notifications?</strong> You can opt out of quiz unlock emails in your <a href="${preferencesUrl}">account preferences</a>.</p>
        </div>
      </div>
      <div class="footer">
        <p>Trivia Advent-ure Calendar</p>
      </div>
    </body>
    </html>
  `;
  
  // Send single email with all recipients in BCC
  // Use a dummy "To" address (the from address) since all recipients are in BCC
  const fromHeader = process.env.EMAIL_FROM || 'no-reply@example.com';
  await sendHTMLEmail(fromHeader, `New Quiz Unlocked: ${quizTitle}`, htmlContent, { bcc: recipientEmails });
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

// --- Quiz unlock notification scheduler: check for newly unlocked quizzes ---
const QUIZ_UNLOCK_CHECK_MS = 60 * 1000; // Check every minute
setInterval(async () => {
  try {
    // Find quizzes that unlocked in the last 1 minute
    // Quizzes unlock at midnight or noon ET, so checking every minute should catch them
    // Using a 1-minute window (with <= for upper bound to catch exact unlock times)
    const now = new Date();
    const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);
    
    const { rows: unlockedQuizzes } = await pool.query(
      `SELECT id, title, unlock_at, quiz_type
       FROM quizzes
       WHERE unlock_at >= $1 AND unlock_at <= $2
       ORDER BY unlock_at ASC`,
      [oneMinuteAgo, now]
    );
    
    if (unlockedQuizzes.length === 0) return;
    
    // Get all players who want quiz unlock notifications
    const { rows: players } = await pool.query(
      `SELECT email, username FROM players
       WHERE email_notifications_enabled = TRUE
         AND email_quiz_unlocks = TRUE
         AND email IS NOT NULL`
    );
    
    if (players.length === 0) return;
    
    console.log(`[quiz-unlock] Found ${unlockedQuizzes.length} newly unlocked quiz(zes), notifying ${players.length} player(s)`);
    
    // Collect all recipient emails
    const recipientEmails = players.map(p => p.email).filter(Boolean);
    
    if (recipientEmails.length === 0) return;
    
    // Send notification for each unlocked quiz (one email per quiz with all recipients in BCC)
    for (const quiz of unlockedQuizzes) {
      const unlockEt = utcToEtParts(new Date(quiz.unlock_at));
      const unlockTimeStr = `${unlockEt.y}-${String(unlockEt.m).padStart(2,'0')}-${String(unlockEt.d).padStart(2,'0')} ${unlockEt.h === 0 ? '12:00 AM' : '12:00 PM'} ET`;
      
      try {
        await sendQuizUnlockEmailBulk(recipientEmails, quiz.title, quiz.id, unlockTimeStr);
        console.log(`[quiz-unlock] Sent notification for quiz ${quiz.id} to ${recipientEmails.length} recipients via BCC`);
      } catch (e) {
        console.error(`[quiz-unlock] Failed to notify recipients about quiz ${quiz.id}:`, e?.message || e);
      }
    }
    
    console.log(`[quiz-unlock] Notifications sent for ${unlockedQuizzes.length} quiz(zes)`);
  } catch (e) {
    console.error('[quiz-unlock] Scheduler error:', e);
  }
}, QUIZ_UNLOCK_CHECK_MS);


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

// Create a reusable OAuth2 client instance
let cachedOAuth2Client = null;
function getOAuth2Client() {
  if (!process.env.GMAIL_CLIENT_ID || !process.env.GMAIL_CLIENT_SECRET || !process.env.GMAIL_REFRESH_TOKEN) {
    throw new Error('Gmail OAuth credentials not configured. Missing GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, or GMAIL_REFRESH_TOKEN');
  }
  
  // Reuse cached client if available, otherwise create new one
  if (!cachedOAuth2Client) {
    cachedOAuth2Client = new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET
    );
    // Set credentials with refresh token - the library will automatically refresh access tokens
    cachedOAuth2Client.setCredentials({ 
      refresh_token: process.env.GMAIL_REFRESH_TOKEN 
    });
    
    // Handle token refresh events for debugging
    cachedOAuth2Client.on('tokens', (tokens) => {
      if (tokens.refresh_token) {
        console.log('[OAuth2] New refresh token received - update GMAIL_REFRESH_TOKEN if needed');
      }
      if (tokens.access_token) {
        console.log('[OAuth2] Access token refreshed successfully');
      }
    });
  }
  
  return cachedOAuth2Client;
}

async function sendMagicLink(email, token, linkUrl, giftInfo = null) {
  try {
    const fromHeader = process.env.EMAIL_FROM || 'no-reply@example.com';
    const fromEmail = parseEmailAddress(fromHeader) || 'no-reply@example.com';
    const url = linkUrl || `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
    console.log('[sendMagicLink] Sending magic link to:', email);
    console.log('[sendMagicLink] Magic link URL:', url);
    if (giftInfo) {
      console.log('[sendMagicLink] This is a gift from:', giftInfo.donorEmail);
    }

    // Get OAuth2 client (reused or newly created)
    const oAuth2Client = getOAuth2Client();
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    // Encode emoji in subject line using RFC 2047 for proper email header encoding
    const encodeSubject = (text) => {
      // Check if text contains non-ASCII characters (like emojis)
      const hasNonAscii = /[^\x00-\x7F]/.test(text);
      if (!hasNonAscii) return text;
      // Use RFC 2047 Base64 encoding for non-ASCII characters
      return '=?UTF-8?B?' + Buffer.from(text, 'utf-8').toString('base64') + '?=';
    };
    const subject = giftInfo ? encodeSubject('🎁 You\'ve received a gift: Trivia Advent-ure!') : 'Welcome to Trivia Advent-ure!';
    
    let text;
    if (giftInfo) {
      const donorName = giftInfo.donorName || giftInfo.donorEmail;
      const customMessage = giftInfo.customMessage ? `\r\n\r\nMessage from ${donorName}:\r\n"${giftInfo.customMessage}"\r\n` : '';
      text = `🎁 You've received a gift!\r\n\r\n${donorName} has gifted you access to Trivia Advent-ure, a festive daily trivia calendar featuring 60 unique quizzes throughout December and January!${customMessage}\r\nWhat you'll get:\r\n• 48 Advent quizzes (Dec 1-24, AM & PM)\r\n• 12 Days of Quizmas quizzes (Dec 26 - Jan 6)\r\n• Daily challenges with points and leaderboards\r\n• Fun trivia questions from amazing writers\r\n\r\n🎄 Claim your gift:\r\nClick the link below to set up your account and start playing:\r\n${url}\r\n\r\nThis link expires in 30 days and can only be used once.\r\n\r\nThank ${donorName} for this thoughtful gift, and happy trivia-ing! 🎉`;
    } else {
      text = `Welcome to Trivia Advent-ure!\r\n\r\nClick the link below to sign in and get started:\r\n${url}\r\n\r\nThis link expires in 30 days and can only be used once.\r\n\r\nIf you didn't request this link, you can safely ignore this email.\r\n\r\nHappy trivia-ing!`;
    }

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
    console.error('[sendMagicLink] Error code:', error.code);
    console.error('[sendMagicLink] Error response:', error.response?.data);
    
    // Clear cached OAuth2 client on auth errors to force recreation
    if (error.response?.data?.error === 'invalid_grant' || error.code === 'EAUTH') {
      console.warn('[sendMagicLink] Clearing cached OAuth2 client due to auth error');
      cachedOAuth2Client = null;
    }
    
    // Provide helpful error messages for common OAuth issues
    if (error.response?.data?.error === 'invalid_grant') {
      const errorDescription = error.response?.data?.error_description || '';
      let helpfulMessage = 'Gmail refresh token has expired or been revoked. ';
      
      // Add specific guidance based on error description
      if (errorDescription.includes('Token has been expired')) {
        helpfulMessage += 'The token expired. ';
      } else if (errorDescription.includes('Token has been revoked')) {
        helpfulMessage += 'The token was revoked (possibly due to password change or manual revocation). ';
      }
      
      helpfulMessage += 'Common causes: (1) Token not used for 6+ months, (2) Google account password was changed, (3) User manually revoked access in Google account settings, (4) Too many refresh tokens exist for this account, (5) OAuth consent screen is in "Testing" mode (tokens expire after 7 days). ';
      helpfulMessage += 'To prevent frequent expiration: (1) Use a dedicated Google account for sending emails, (2) Avoid changing the password, (3) Don\'t generate multiple refresh tokens, (4) Publish your OAuth consent screen to "Production" mode in Google Cloud Console (APIs & Services → OAuth consent screen). ';
      helpfulMessage += 'Generate a new refresh token using OAuth 2.0 Playground and update GMAIL_REFRESH_TOKEN environment variable.';
      
      const helpfulError = new Error(helpfulMessage);
      helpfulError.originalError = error;
      throw helpfulError;
    }
    
    throw error;
  }
}

async function sendReminderEmail(email, token, linkUrl) {
  try {
    const fromHeader = process.env.EMAIL_FROM || 'no-reply@example.com';
    const fromEmail = parseEmailAddress(fromHeader) || 'no-reply@example.com';
    const url = linkUrl || `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
    console.log('[sendReminderEmail] Sending reminder to:', email);
    console.log('[sendReminderEmail] Magic link URL:', url);

    // Get OAuth2 client (reused or newly created)
    const oAuth2Client = getOAuth2Client();
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const subject = 'Complete Your Trivia Advent-ure Setup';
    const text = `Hi there!\r\n\r\nWe noticed you haven't finished setting up your Trivia Advent-ure account yet. Just a friendly reminder to complete your account setup so you can start playing!\r\n\r\nClick the link below to finish setting up your account:\r\n${url}\r\n\r\nThis link expires in 30 days and can only be used once.\r\n\r\nIf you've already completed setup or have any questions, feel free to reach out.\r\n\r\nHappy trivia-ing!`;

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
    
    console.log('[sendReminderEmail] Reminder sent successfully. Message ID:', result.data.id);
    return result;
  } catch (error) {
    console.error('[sendReminderEmail] Error sending reminder to', email, ':', error.message);
    throw error;
  }
}

async function sendPlainEmail(email, subject, text) {
  const fromHeader = process.env.EMAIL_FROM || 'no-reply@example.com';
  const oAuth2Client = getOAuth2Client();
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

async function sendHTMLEmail(email, subject, html, options = {}) {
  const fromHeader = process.env.EMAIL_FROM || 'no-reply@example.com';
  const oAuth2Client = getOAuth2Client();
  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
  const rawLines = [
    `From: ${fromHeader}`,
    `To: ${email}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=UTF-8',
  ];
  
  // Add BCC if provided (array of email addresses)
  if (options.bcc && Array.isArray(options.bcc) && options.bcc.length > 0) {
    rawLines.push(`Bcc: ${options.bcc.join(', ')}`);
  }
  
  // Add Reply-To if provided
  if (options.replyTo) {
    rawLines.push(`Reply-To: ${options.replyTo}`);
  }
  
  rawLines.push('', html);
  
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
  const baseUrl = process.env.PUBLIC_BASE_URL || '';
  // Use banner logo for social sharing if available, fallback to logo.svg
  const ogImage = `${baseUrl}/img/logo-banner.png`;
  return `<html style="background:linear-gradient(180deg,#0f1d5a 0%, #15124a 60%, #0b1338 100%);background-color:#0b1338;min-height:100%;"><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title}</title><meta property="og:title" content="${title}"><meta property="og:type" content="website"><meta property="og:image" content="${ogImage}"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta property="og:url" content="${baseUrl}"><meta name="twitter:card" content="summary_large_image"><meta name="twitter:image" content="${ogImage}"><style>html,body{margin:0;padding:0;background:linear-gradient(180deg,#0f1d5a 0%, #15124a 60%, #0b1338 100%);background-color:#0b1338;min-height:100vh;}</style><link rel="stylesheet" href="/style.css?v=${ASSET_VERSION}">${favicon}</head>`;
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
       <a href="/quizmas">Quizmas</a>
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
              <a href="/quizmas">Quizmas</a>
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
  { id: 'writers', label: 'Writer Invites', href: '/admin/writer-invites/list' },
  { id: 'submissions', label: 'Writer Submissions', href: '/admin/writer-submissions' },
  { id: 'players', label: 'Players', href: '/admin/players' },
  { id: 'donations', label: 'Donations', href: '/admin/donations' },
  { id: 'admins', label: 'Admins', href: '/admin/admins' },
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
  // Blank responses are NEVER correct
  const givenStr = String(given || '').trim();
  if (!givenStr) return false;
  
  const raw = String(correct || '');
  const gNorm = normalizeAnswer(given);
  if (!gNorm) return false; // Double-check normalized is not blank
  
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

// Check if a normalized answer has been manually accepted for a question
async function isAcceptedAnswer(pool, questionId, responseText) {
  if (!responseText) return false;
  const norm = normalizeAnswer(responseText);
  if (!norm) return false;
  
  // Get all manually accepted responses for this question
  const { rows } = await pool.query(
    `SELECT response_text FROM responses 
     WHERE question_id=$1 AND override_correct=true`,
    [questionId]
  );
  
  // Check if any accepted response normalizes to the same value
  for (const row of rows) {
    if (normalizeAnswer(row.response_text) === norm) {
      return true;
    }
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
    const responseText = r ? (r.response_text || '').trim() : '';
    const isBlank = !responseText;
    const locked = !!(r && r.locked);
    
    if (locked) {
      // Blank locked responses are NEVER correct, even with manual override
      if (isBlank) {
        const pts = 0;
        graded.push({ questionId: q.id, number: q.number, locked: true, correct: false, points: pts, given: '', answer: q.answer });
        await pool.query('UPDATE responses SET points = $4, override_correct = FALSE WHERE quiz_id=$1 AND user_email=$2 AND question_id=$3', [quizId, userEmail, q.id, pts]);
        continue;
      }
      const auto = isCorrectAnswer(responseText, q.answer);
      // Check if this normalized answer has been manually accepted before
      const accepted = await isAcceptedAnswer(pool, q.id, responseText);
      // Only allow manual override if NOT blank
      const correctLocked = (r && typeof r.override_correct === 'boolean' && !isBlank) ? r.override_correct : (auto || accepted);
      const pts = correctLocked ? 5 : 0;
      graded.push({ questionId: q.id, number: q.number, locked: true, correct: correctLocked, points: pts, given: responseText, answer: q.answer });
      total += pts;
      await pool.query('UPDATE responses SET points = $4 WHERE quiz_id=$1 AND user_email=$2 AND question_id=$3', [quizId, userEmail, q.id, pts]);
      // streak unchanged
      continue;
    }
    
    // Blank non-locked responses are NEVER correct
    if (isBlank) {
      streak = 0;
      if (r) await pool.query('UPDATE responses SET points = 0, override_correct = FALSE WHERE quiz_id=$1 AND user_email=$2 AND question_id=$3', [quizId, userEmail, q.id]);
      graded.push({ questionId: q.id, number: q.number, locked: false, correct: false, points: 0, given: '', answer: q.answer });
      continue;
    }
    
    const auto = isCorrectAnswer(responseText, q.answer);
    // Check if this normalized answer has been manually accepted before
    const accepted = await isAcceptedAnswer(pool, q.id, responseText);
    // Only allow manual override if NOT blank (already checked above)
    const correct = (r && typeof r.override_correct === 'boolean') ? r.override_correct : (auto || accepted);
    if (correct) {
      streak += 1;
      total += streak;
      await pool.query('UPDATE responses SET points = $4 WHERE quiz_id=$1 AND user_email=$2 AND question_id=$3', [quizId, userEmail, q.id, streak]);
    } else {
      streak = 0;
      if (r) await pool.query('UPDATE responses SET points = 0 WHERE quiz_id=$1 AND user_email=$2 AND question_id=$3', [quizId, userEmail, q.id]);
    }
    graded.push({ questionId: q.id, number: q.number, locked: false, correct, points: correct ? streak : 0, given: responseText, answer: q.answer });
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
    const email = String(emailRaw).trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email required' });
    const { rows } = await pool.query('SELECT 1 FROM players WHERE email = $1', [email]);
    if (rows.length === 0) return res.status(403).json({ error: 'No access. Donate on Ko-fi to join.' });
    
    // Delete any existing unused tokens for this email to prevent conflicts
    await pool.query('DELETE FROM magic_tokens WHERE email = $1 AND used = false', [email]);
    
    const token = crypto.randomBytes(24).toString('base64url');
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await pool.query('INSERT INTO magic_tokens(token,email,expires_at,used,created_at) VALUES($1,$2,$3,false,NOW())', [token, email, expiresAt]);
    const linkUrl = `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
    try {
      await sendMagicLink(email, token, linkUrl);
    } catch (mailErr) {
      console.warn('[auth/request-link] Send mail failed:', mailErr?.message || mailErr);
    }
    const expose = (process.env.EXPOSE_MAGIC_LINKS || '').toLowerCase() === 'true';
    res.json({ ok: true, link: expose ? linkUrl : undefined });
  } catch (e) {
    console.error('[auth/request-link] Error:', e);
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
          SUM(CASE WHEN (r.override_correct = true AND r.response_text IS NOT NULL AND TRIM(r.response_text) != '') OR (r.override_correct IS NULL AND r.response_text IS NOT NULL AND TRIM(r.response_text) != '' AND LOWER(TRIM(r.response_text)) = LOWER(TRIM(qq.answer))) THEN 1 ELSE 0 END) as correct_answers
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
                  <div class="account-summary-item"><dt>Username</dt><dd>${player.username || '(not set)'}</dd></div>
                  <div class="account-summary-item"><dt>Email</dt><dd>${player.email}</dd></div>
                  <div class="account-summary-item"><dt>Member Since</dt><dd>${player.access_granted_at ? new Date(player.access_granted_at).toLocaleDateString() : 'Unknown'}</dd></div>
                  <div class="account-summary-item"><dt>Quizzes Played</dt><dd>${stats.totalQuizzes}</dd></div>
                  <div class="account-summary-item"><dt>Questions Answered</dt><dd>${stats.totalQuestions}</dd></div>
                  <div class="account-summary-item"><dt>Average Score</dt><dd>${stats.avgScore}%</dd></div>
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

// Access choice page - choose if access is for yourself, gift, or both
app.get('/access-choice', requireAuth, async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const isAdmin = await isAdminUser(req);
    const isPreview = req.query.preview === '1' && isAdmin; // Allow admins to preview
    
    const r = await pool.query('SELECT access_choice FROM players WHERE email=$1', [email]);
    if (r.rows.length && r.rows[0].access_choice && !isPreview) {
      // Already made choice, redirect to next step (unless admin preview)
      const onboardingCheck = await pool.query('SELECT onboarding_complete, username, password_set_at FROM players WHERE email=$1', [email]);
      const onboardingData = onboardingCheck.rows[0] || {};
      if (!onboardingData.onboarding_complete) return res.redirect('/onboarding');
      if (!onboardingData.username || !onboardingData.password_set_at) return res.redirect('/account/credentials');
      return res.redirect('/');
    }
    const header = await renderHeader(req);
    res.type('html').send(`
      ${renderHead('Choose Your Access • Trivia Advent-ure', false)}
      <body class="ta-body">
      ${header}
      <main class="ta-main ta-container" style="max-width:720px; margin:0 auto; padding:24px;">
        ${isPreview ? '<div style="background:#ffd700;color:#000;padding:12px;border-radius:6px;margin-bottom:24px;font-weight:bold;text-align:center;">Admin Preview Mode</div>' : ''}
        <h1 class="ta-page-title">How would you like to use your access?</h1>
        <p style="opacity:0.9;margin-bottom:24px;font-size:16px;">Please let us know how you'd like to use your Trivia Advent-ure access.</p>
        <form method="post" action="/access-choice" style="display:flex;flex-direction:column;gap:16px;">
          <div style="background:#1a1a1a;border:2px solid #333;border-radius:8px;padding:20px;cursor:pointer;" onclick="document.getElementById('choice-self').checked=true;document.getElementById('gift-email').style.display='none';document.querySelector('input[name=\\'gift_recipient_email\\']').removeAttribute('required');">
            <label style="display:flex;align-items:center;gap:12px;cursor:pointer;">
              <input type="radio" name="access_choice" id="choice-self" value="self" required style="width:20px;height:20px;cursor:pointer;" />
              <div style="flex:1;">
                <div style="font-weight:600;font-size:18px;margin-bottom:4px;color:#ffd700;">For myself</div>
                <div style="opacity:0.8;font-size:14px;">I want to play Trivia Advent-ure myself</div>
              </div>
            </label>
              </div>
          <div style="background:#1a1a1a;border:2px solid #333;border-radius:8px;padding:20px;cursor:pointer;" onclick="document.getElementById('choice-gift').checked=true;document.getElementById('gift-email').style.display='block';document.querySelector('input[name=\\'gift_recipient_email\\']').setAttribute('required','required');">
            <label style="display:flex;align-items:center;gap:12px;cursor:pointer;">
              <input type="radio" name="access_choice" id="choice-gift" value="gift" required style="width:20px;height:20px;cursor:pointer;" />
              <div style="flex:1;">
                <div style="font-weight:600;font-size:18px;margin-bottom:4px;color:#ffd700;">As a gift</div>
                <div style="opacity:0.8;font-size:14px;">I want to give this access to someone else</div>
              </div>
            </label>
            </div>
          <div id="gift-email" style="display:none;margin-left:32px;margin-top:-8px;margin-bottom:8px;">
            <label style="display:block;margin-bottom:8px;font-weight:600;color:#ffd700;">Recipient Email</label>
            <input type="email" name="gift_recipient_email" placeholder="their@email.com" style="width:100%;max-width:400px;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:16px;" />
            <div style="opacity:.8;font-size:.9em;margin-top:4px;">We'll send them a magic link to claim their access</div>
            <label style="display:block;margin-top:16px;margin-bottom:8px;font-weight:600;color:#ffd700;">From Name</label>
            <input type="text" name="gift_from_name" placeholder="Your name (or leave blank to use your account name)" maxlength="100" style="width:100%;max-width:400px;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:16px;" />
            <div style="opacity:.8;font-size:.9em;margin-top:4px;">How you'd like to be identified in the gift email</div>
            <label style="display:block;margin-top:16px;margin-bottom:8px;font-weight:600;color:#ffd700;">Personal Message (Optional)</label>
            <textarea name="gift_message" placeholder="Add a personal message to include in the gift email..." rows="3" maxlength="500" style="width:100%;max-width:400px;padding:10px;border-radius:6px;border:1px solid #444;background:#2a2a2a;color:#fff;font-size:16px;font-family:inherit;resize:vertical;"></textarea>
            <div style="opacity:.8;font-size:.9em;margin-top:4px;">This message will be included in the gift email</div>
          </div>
          <div style="background:#1a1a1a;border:2px solid #333;border-radius:8px;padding:20px;cursor:pointer;" onclick="document.getElementById('choice-both').checked=true;document.getElementById('gift-email').style.display='block';document.querySelector('input[name=\\'gift_recipient_email\\']').setAttribute('required','required');">
            <label style="display:flex;align-items:center;gap:12px;cursor:pointer;">
              <input type="radio" name="access_choice" id="choice-both" value="both" required style="width:20px;height:20px;cursor:pointer;" />
              <div style="flex:1;">
                <div style="font-weight:600;font-size:18px;margin-bottom:4px;color:#ffd700;">Both</div>
                <div style="opacity:0.8;font-size:14px;">I want to play myself AND give access to someone else</div>
              </div>
            </label>
          </div>
          <button type="submit" class="ta-btn ta-btn-primary" style="font-size:18px;padding:14px 32px;margin-top:8px;">Continue</button>
        </form>
        <script>
          document.querySelectorAll('input[name="access_choice"]').forEach(radio => {
            radio.addEventListener('change', function() {
              const giftEmailDiv = document.getElementById('gift-email');
              const giftEmailInput = document.querySelector('input[name="gift_recipient_email"]');
              if (this.value === 'gift' || this.value === 'both') {
                giftEmailDiv.style.display = 'block';
                giftEmailInput.setAttribute('required', 'required');
              } else {
                giftEmailDiv.style.display = 'none';
                giftEmailInput.removeAttribute('required');
                giftEmailInput.value = '';
              }
            });
          });
        </script>
        </main>
      ${renderFooter(req)}
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load access choice page');
  }
});

app.post('/access-choice', requireAuth, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const email = (req.session.user.email || '').toLowerCase();
    const isAdmin = await isAdminUser(req);
    const isPreview = req.query.preview === '1' && isAdmin; // Allow admins to preview
    
    const accessChoice = String(req.body.access_choice || '').trim();
    const giftRecipientEmail = accessChoice === 'gift' || accessChoice === 'both' 
      ? String(req.body.gift_recipient_email || '').trim().toLowerCase() 
      : null;
    const giftFromName = accessChoice === 'gift' || accessChoice === 'both'
      ? String(req.body.gift_from_name || '').trim() || null
      : null;
    const giftMessage = accessChoice === 'gift' || accessChoice === 'both'
      ? String(req.body.gift_message || '').trim() || null
      : null;
    
    if (!accessChoice || !['self', 'gift', 'both'].includes(accessChoice)) {
      return res.status(400).send('Invalid access choice');
    }
    
    if ((accessChoice === 'gift' || accessChoice === 'both') && !giftRecipientEmail) {
      return res.status(400).send('Gift recipient email required');
    }
    
    // Update player record
    await pool.query(
      'UPDATE players SET access_choice = $1, gift_recipient_email = $2 WHERE email = $3',
      [accessChoice, giftRecipientEmail, email]
    );
    
    // If gift or both, create access for recipient and send them a magic link
    if (giftRecipientEmail && (accessChoice === 'gift' || accessChoice === 'both')) {
      // Create player record for recipient if it doesn't exist
      await pool.query(
        'INSERT INTO players(email, access_granted_at, access_choice) VALUES($1, NOW(), $2) ON CONFLICT (email) DO UPDATE SET access_choice = $2',
        [giftRecipientEmail, 'gift-received']
      );
      
      // Get donor name - use custom "from name" if provided, otherwise use account name
      let donorName = giftFromName;
      if (!donorName) {
        // Get donor information for gift email
        const donorInfo = await pool.query('SELECT email, username FROM players WHERE email=$1', [email]);
        const donor = donorInfo.rows[0] || {};
        // Use username if available and it's not an email address, otherwise extract a friendly name from email
        donorName = donor.username;
        // Check if username looks like an email address (contains @)
        if (donorName && donorName.includes('@')) {
          donorName = null; // Treat email-like usernames as if no username
        }
        if (!donorName) {
          // Extract a friendly name from email (part before @, capitalize first letter, replace separators with spaces)
          const emailPart = (donor.email || email).split('@')[0];
          donorName = emailPart.charAt(0).toUpperCase() + emailPart.slice(1).replace(/[._-]/g, ' ');
        }
      }
      
      // Create and send magic link to recipient
      await pool.query('DELETE FROM magic_tokens WHERE email = $1 AND used = false', [giftRecipientEmail]);
      const token = crypto.randomBytes(24).toString('base64url');
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
