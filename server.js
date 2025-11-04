import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import * as tz from 'date-fns-tz';

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const PORT = process.env.PORT || 8080;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const EVENT_TZ = process.env.EVENT_TZ || 'America/New_York';
const KOFI_CUTOFF_ET = process.env.KOFI_CUTOFF_ET || '2025-11-01 00:00:00 America/New_York';
const WEBHOOK_SHARED_SECRET = process.env.WEBHOOK_SHARED_SECRET || '';

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, sameSite: 'lax', httpOnly: true }
}));

// --- DB ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway.app') || process.env.PGSSL === 'require'
    ? { rejectUnauthorized: false }
    : false
});

async function initDb() {
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS citext;
    CREATE TABLE IF NOT EXISTS players (
      id SERIAL PRIMARY KEY,
      email CITEXT UNIQUE NOT NULL,
      access_granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS magic_tokens (
      token TEXT PRIMARY KEY,
      email CITEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE
    );
  `);
}

// --- Mailer (Gmail OAuth via nodemailer) ---
function createMailer() {
  const provider = process.env.EMAIL_PROVIDER || 'gmail-oauth';
  if (provider !== 'gmail-oauth') {
    throw new Error('Only gmail-oauth provider is wired in this scaffold');
  }
  const user = parseEmailAddress(process.env.EMAIL_FROM);
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      type: 'OAuth2',
      user,
      clientId: process.env.GMAIL_CLIENT_ID,
      clientSecret: process.env.GMAIL_CLIENT_SECRET,
      refreshToken: process.env.GMAIL_REFRESH_TOKEN
    }
  });
  return transporter;
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
  if (!transporter) {
    console.log('[dev] Magic link:', linkUrl || `https://localhost:${PORT}/auth/magic?token=${token}`);
    return;
  }
  const from = process.env.EMAIL_FROM || parseEmailAddress(process.env.EMAIL_FROM) || 'no-reply@example.com';
  const url = linkUrl || `${process.env.PUBLIC_BASE_URL || ''}/auth/magic?token=${encodeURIComponent(token)}`;
  console.log('[info] Magic link:', url);
  await transporter.sendMail({
    to: email,
    from,
    subject: 'Your Trivia Advent-ure magic link',
    text: `Click to sign in: ${url}\nThis link expires in 30 minutes and can be used once.`,
    html: `<p>Click to sign in:</p><p><a href="${url}">${url}</a></p><p>This link expires in 30 minutes and can be used once.</p>`
  });
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
    res.redirect('/');
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

    const cutoffEt = KOFI_CUTOFF_ET; // e.g., '2025-11-01 00:00:00 America/New_York'
    const createdAt = createdAtStr ? new Date(createdAtStr) : new Date();
    const createdAtET = tz.utcToZonedTime(createdAt, EVENT_TZ);
    const cutoffDate = new Date(tz.utcToZonedTime(new Date(cutoffEt), EVENT_TZ));
    if (!(createdAtET >= cutoffDate)) {
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
  const loggedIn = !!req.session.user;
  res.type('html').send(`
    <html><head><title>Trivia Advent-ure</title></head>
    <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto; padding: 24px;">
      <h1>Trivia Advent-ure (Staging)</h1>
      ${loggedIn ? `<p>Signed in as ${req.session.user.email}.</p>` : `
        <form method="post" action="/auth/request-link" onsubmit="event.preventDefault(); const fd=new FormData(this); const v=String(fd.get('email')||'').trim(); if(!v){alert('Enter your email'); return;} fetch('/auth/request-link',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ email: v })}).then(r=>r.json()).then(d=>{ if (d.link) { alert('Magic link (dev):\n'+d.link); } else { alert('If you have access, a magic link was sent.'); } }).catch(()=>alert('Failed.'));">
          <label>Email (Ko-fi): <input id="email" name="email" type="email" required /></label>
          <button type="submit">Send magic link</button>
        </form>
      `}
    </body></html>
  `);
});

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Advent staging listening on :${PORT}`);
  });
});


