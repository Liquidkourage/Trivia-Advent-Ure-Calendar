import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import { google } from 'googleapis';
import dotenv from 'dotenv';
// Avoid timezone library; store UTC in DB and compare in UTC

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
    CREATE TABLE IF NOT EXISTS quizzes (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      unlock_at TIMESTAMPTZ NOT NULL,
      freeze_at TIMESTAMPTZ NOT NULL,
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
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_email, question_id)
    );
    CREATE INDEX IF NOT EXISTS idx_responses_quiz_user ON responses(quiz_id, user_email);
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

function getAdminEmail() {
  const from = process.env.EMAIL_FROM || '';
  const m = from.match(/<([^>]+)>/);
  const fallback = m ? m[1] : from;
  return (process.env.ADMIN_EMAIL || fallback || '').toLowerCase();
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).send('Please sign in.');
  next();
}

function requireAdmin(req, res, next) {
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
    <html><head><title>Trivia Advent-ure</title></head>
    <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto; padding: 24px; max-width: 860px; margin: 0 auto;">
      <h1>Trivia Advent-ure Calendar</h1>
      <p>48 quizzes unlock at midnight and noon ET from Dec 1–24. Play anytime; per-quiz leaderboards finalize after 24 hours. Overall standings keep updating.</p>
      <div style="margin:16px 0;">
        <a href="/calendar">View Calendar</a> · <a href="/login">Login</a>
      </div>
      <h3>How it works</h3>
      <ul>
        <li>10 questions per quiz, immediate recap on submit</li>
        <li>Per-quiz leaderboard freezes at +24h</li>
        <li>Overall board keeps updating with late plays</li>
      </ul>
    </body></html>
  `);
});

// Player landing (logged-in non-admin)
app.get('/player', requireAuth, (req, res) => {
  const adminEmail = getAdminEmail();
  const email = (req.session.user.email || '').toLowerCase();
  if (email === adminEmail) return res.redirect('/admin');
  res.type('html').send(`
    <html><head><title>Player • Trivia Advent-ure</title></head>
    <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto; padding: 24px;">
      <h1>Welcome, ${req.session.user.email}</h1>
      <p><a href="/calendar">Calendar</a> · <a href="/logout">Logout</a></p>
    </body></html>
  `);
});

// Admin dashboard
app.get('/admin', requireAdmin, (req, res) => {
  res.type('html').send(`
    <html><head><title>Admin • Trivia Advent-ure</title></head>
    <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto; padding: 24px;">
      <h1>Admin Dashboard</h1>
      <ul>
        <li><a href="/admin/upload-quiz">Upload Quiz</a></li>
        <li><a href="/calendar">Calendar</a></li>
        <li><a href="/logout">Logout</a></li>
      </ul>
    </body></html>
  `);
});

// Dedicated login page (magic-link)
app.get('/login', (req, res) => {
  const loggedIn = !!req.session.user;
  res.type('html').send(`
    <html><head><title>Login • Trivia Advent-ure</title></head>
    <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto; padding: 24px;">
      <h1>Login</h1>
      ${loggedIn ? `<p>You are signed in as ${req.session.user.email}. <a href="/logout">Logout</a></p>` : `
        <form method="post" action="/auth/request-link" onsubmit="event.preventDefault(); const fd=new FormData(this); const v=String(fd.get('email')||'').trim(); if(!v){alert('Enter your email'); return;} fetch('/auth/request-link',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ email: v })}).then(r=>r.json()).then(d=>{ if (d.link) { alert('Magic link (dev):\n'+d.link); } else { alert('If you have access, a magic link was sent.'); } }).catch(()=>alert('Failed.'));">
          <label>Email (Ko-fi): <input id="email" name="email" type="email" required /></label>
          <button type="submit">Send magic link</button>
        </form>
      `}
      <p style="margin-top:16px;"><a href="/">Home</a></p>
    </body></html>
  `);
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// --- Calendar ---
app.get('/calendar', async (req, res) => {
  try {
    const { rows: quizzes } = await pool.query('SELECT * FROM quizzes ORDER BY unlock_at ASC, id ASC');
  const nowUtc = new Date();
    const email = req.session.user ? (req.session.user.email || '').toLowerCase() : '';
    let completedMap = {};
    if (email) {
      const { rows: c } = await pool.query('SELECT DISTINCT quiz_id FROM responses WHERE user_email = $1', [email]);
      completedMap = Object.fromEntries(c.map(r => [String(r.quiz_id), true]));
    }
    const tiles = quizzes.map(q => {
      const unlockUtc = new Date(q.unlock_at);
      const freezeUtc = new Date(q.freeze_at);
      let status = 'Locked';
      if (nowUtc >= freezeUtc) status = 'Finalized'; else if (nowUtc >= unlockUtc) status = 'Unlocked';
      const completed = completedMap[String(q.id)] ? 'Completed' : '';
      return { id: q.id, title: q.title, status, completed };
    });
    const grid = tiles.map(t => `<div style="border:1px solid #ccc;padding:10px;border-radius:8px;">
      <div><strong>#${t.id}:</strong> ${t.title}</div>
      <div>Status: ${t.status}${t.completed ? ' • '+t.completed : ''}</div>
      <div style="margin-top:6px;"><a href="/quiz/${t.id}">Open</a></div>
    </div>`).join('\n');
    res.type('html').send(`
      <html><head><title>Calendar</title></head>
      <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto; padding: 24px;">
        <h1>Advent Calendar</h1>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;">${grid}</div>
        <p style="margin-top:16px;"><a href="/">Home</a></p>
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
    <html><head><title>Upload Quiz</title></head>
    <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto; padding: 24px;">
      <h1>Upload Quiz</h1>
      <form method="post" action="/admin/upload-quiz">
        <div><label>Title <input name="title" required /></label></div>
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
    const unlockInput = String(req.body.unlock_at || '').trim();
    if (!title || !unlockInput) return res.status(400).send('Missing title or unlock time');
    const unlockUtc = etToUtc(unlockInput);
    const freezeUtc = new Date(unlockUtc.getTime() + 24*60*60*1000);
    const qInsert = await pool.query('INSERT INTO quizzes(title, unlock_at, freeze_at) VALUES($1,$2,$3) RETURNING id', [title, unlockUtc, freezeUtc]);
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
    const loggedIn = !!req.session.user;
    const email = loggedIn ? (req.session.user.email || '') : '';
    const form = locked ? '<p>This quiz is locked until unlock time (ET).</p>' : (loggedIn ? `
      <form method="post" action="/quiz/${id}/submit">
        ${qs.map(q=>`
          <div style=\"border:1px solid #ddd;padding:8px;margin:6px 0;border-radius:6px;\">
            <div><strong>Q${q.number}:</strong> ${q.text}</div>
            <div><label>Your answer <input name=\"q${q.number}\" style=\"width:90%\"/></label></div>
          </div>
        `).join('')}
        <div><button type="submit">Submit</button></div>
      </form>
    ` : '<p>Please sign in to play.</p>');
    res.type('html').send(`
      <html><head><title>Quiz ${id}</title></head>
      <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto; padding: 24px;">
        <h1>${quiz.title} (Quiz #${id})</h1>
        <div>Status: ${status}</div>
        ${form}
        <p style="margin-top:16px;"><a href="/calendar">Back to Calendar</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to load quiz');
  }
});

app.post('/quiz/:id/submit', requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const email = (req.session.user.email || '').toLowerCase();
    const { rows: qs } = await pool.query('SELECT id, number FROM questions WHERE quiz_id = $1 ORDER BY number ASC', [id]);
    for (const q of qs) {
      const key = `q${q.number}`;
      const val = String(req.body[key] || '').trim();
      if (!val) continue;
      await pool.query(
        'INSERT INTO responses(quiz_id, question_id, user_email, response_text) VALUES($1,$2,$3,$4) ON CONFLICT (user_email, question_id) DO UPDATE SET response_text = EXCLUDED.response_text',
        [id, q.id, email, val]
      );
    }
    res.redirect(`/quiz/${id}?submitted=1`);
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


