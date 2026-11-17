'use strict';
/**
 * Cirpman Homes — backend server
 * Zero npm dependencies. Requires Node.js >= 22.5 (uses the built-in node:sqlite module).
 *
 *   node server.js
 *
 * Environment variables (all optional):
 *   PORT              default 3000
 *   DATA_DIR          default ./data   (SQLite database + uploaded media live here)
 *   ADMIN_PASSWORD    initial admin password (only used the first time the database is created)
 *   TOKEN_SECRET      secret for signing login tokens (generated and stored automatically if absent)
 *   PAYSTACK_SECRET   Paystack secret key (can also be saved from Admin -> Settings)
 *   TRUST_PROXY=1     use X-Forwarded-For for client IPs (set this behind nginx / a PaaS router)
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ============================================================
   DATABASE  (documents in SQLite; one row per record)
============================================================ */
const db = new DatabaseSync(path.join(DATA_DIR, 'cirpman.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  CREATE TABLE IF NOT EXISTS docs (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    collection TEXT NOT NULL,
    id         TEXT NOT NULL,
    data       TEXT NOT NULL,
    UNIQUE (collection, id)
  );
  CREATE INDEX IF NOT EXISTS idx_docs_collection ON docs (collection);
  CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

const q = {
  list: db.prepare('SELECT data FROM docs WHERE collection = ? ORDER BY seq'),
  get: db.prepare('SELECT data FROM docs WHERE collection = ? AND id = ?'),
  put: db.prepare(`INSERT INTO docs (collection, id, data) VALUES (?, ?, ?)
                   ON CONFLICT (collection, id) DO UPDATE SET data = excluded.data`),
  del: db.prepare('DELETE FROM docs WHERE collection = ? AND id = ?'),
  wipe: db.prepare('DELETE FROM docs WHERE collection = ?'),
  kvGet: db.prepare('SELECT value FROM kv WHERE key = ?'),
  kvSet: db.prepare(`INSERT INTO kv (key, value) VALUES (?, ?)
                     ON CONFLICT (key) DO UPDATE SET value = excluded.value`),
  kvDel: db.prepare('DELETE FROM kv WHERE key = ?')
};
const Docs = {
  list: c => q.list.all(c).map(r => JSON.parse(r.data)),
  get: (c, id) => { const r = q.get.get(c, id); return r ? JSON.parse(r.data) : null; },
  put: (c, o) => { q.put.run(c, o.id, JSON.stringify(o)); return o; },
  del: (c, id) => q.del.run(c, id),
  wipe: c => q.wipe.run(c)
};
const KV = {
  get: (k, fb) => { const r = q.kvGet.get(k); return r ? JSON.parse(r.value) : fb; },
  set: (k, v) => q.kvSet.run(k, JSON.stringify(v)),
  del: k => q.kvDel.run(k)
};
let txDepth = 0;
function tx(fn) {
  if (txDepth > 0) return fn(); // already inside a transaction: join it
  db.exec('BEGIN IMMEDIATE');
  txDepth++;
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
  finally { txDepth--; }
}
function nextNumber(key, start) {
  return tx(() => {
    const c = KV.get('counter', {});
    c[key] = (c[key] == null ? (start || 0) : c[key]) + 1;
    KV.set('counter', c);
    return c[key];
  });
}
const uid = p => p + crypto.randomBytes(8).toString('hex');

/* ============================================================
   CRYPTO / AUTH
============================================================ */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + hash.toString('hex');
}
function checkPassword(pw, stored) {
  try {
    const [, saltHex, hashHex] = String(stored).split('$');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(String(pw), Buffer.from(saltHex, 'hex'), expected.length);
    return crypto.timingSafeEqual(actual, expected);
  } catch (e) { return false; }
}
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

let SECRET = process.env.TOKEN_SECRET || KV.get('tokenSecret', null);
if (!SECRET) { SECRET = crypto.randomBytes(32).toString('hex'); KV.set('tokenSecret', SECRET); }

const b64u = b => Buffer.from(b).toString('base64url');
function signToken(payload, ttlSeconds) {
  const body = b64u(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds }));
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function readToken(token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!safeEqual(sig, expect)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() / 1000 ? p : null;
  } catch (e) { return null; }
}

// Admin password: set on first run only; afterwards changed from Admin -> Settings.
if (!KV.get('adminHash', null)) {
  const initial = process.env.ADMIN_PASSWORD || 'Cirpman@2026';
  KV.set('adminHash', hashPassword(initial));
  if (!process.env.ADMIN_PASSWORD) {
    console.warn('\n  !! Admin password initialised to the DEFAULT "Cirpman@2026".');
    console.warn('  !! Log in and change it under Admin -> Settings immediately.\n');
  }
}

/* ---------- tiny in-memory rate limiter ---------- */
const hits = new Map();
function rateLimit(req, bucket, max, windowMs) {
  const key = bucket + '|' + clientIp(req);
  const now = Date.now();
  let h = hits.get(key);
  if (!h || h.reset < now) { h = { n: 0, reset: now + windowMs }; hits.set(key, h); }
  h.n++;
  return h.n <= max;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.reset < n) hits.delete(k); }, 60000).unref();
function clientIp(req) {
  if (process.env.TRUST_PROXY === '1') {
    const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (xf) return xf;
  }
  return req.socket.remoteAddress || 'unknown';
}

/* ============================================================
   SEED (first run only)
============================================================ */
(function seed() {
  if (KV.get('seeded', false)) return;
  const s = JSON.parse(fs.readFileSync(path.join(__dirname, 'seed.json'), 'utf8'));
  tx(() => {
    (s.estates || []).forEach(e => Docs.put('estates', e));
    (s.gallery || []).forEach(g => Docs.put('gallery', g));
    KV.set('content', s.content || {});
    KV.set('counter', { client: 1000, receipt: 5000 });
    KV.set('settings', { paystack: '', paystackSecret: process.env.PAYSTACK_SECRET || '' });
    KV.set('seeded', true);
  });
})();

/* ============================================================
   HELPERS
============================================================ */
class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code; }
}
const bad = (m, code) => new HttpError(400, m, code);
const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max || 500);
const normPhone = s => {
  let d = String(s || '').replace(/\D/g, '');
  if (d.startsWith('234')) d = '0' + d.slice(3);
  return d;
};
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254;
const nowIso = () => new Date().toISOString();
const RATES = { standard: { direct: 10, l1: 2, l2: 1 }, easybuy: { direct: 7, l1: 2, l2: 1 } };

function settings() { return KV.get('settings', { paystack: '', paystackSecret: '' }); }
function paystackSecret() { return settings().paystackSecret || process.env.PAYSTACK_SECRET || ''; }

function safeConsultant(c) { const { passHash, ...rest } = c; return rest; }

function dataUrlInfo(url, allowed, maxBytes, label) {
  const m = /^data:([a-z]+\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=]+)$/i.exec(String(url || ''));
  if (!m) throw bad(label + ' is not a valid file.');
  const mime = m[1].toLowerCase();
  if (!allowed.includes(mime)) throw bad(label + ' must be one of: ' + allowed.join(', ') + '.');
  const bytes = Math.floor(m[2].length * 3 / 4);
  if (bytes > maxBytes) throw bad(label + ' is too large (max ' + Math.round(maxBytes / 1000) + ' KB).');
  return { mime, base64: m[2], bytes };
}

/* ---------- commission engine ---------- */
function findBeneficiary(code) {
  if (!code) return null;
  const key = String(code).trim().toUpperCase();
  const s = Docs.list('staff').find(x => (x.ref || '').toUpperCase() === key);
  if (s) return s;
  const c = Docs.list('consultants').find(x => x.consultantId && x.consultantId.toUpperCase() === key);
  return c ? { name: c.name, ref: c.consultantId, upline: c.upline || '' } : null;
}
function commissionChain(startRef, estateType) {
  const rate = RATES[estateType] || RATES.standard;
  const levels = [
    { level: 'Direct', pct: rate.direct },
    { level: 'Level 1', pct: rate.l1 },
    { level: 'Level 2', pct: rate.l2 }
  ];
  const out = [];
  const seen = new Set();
  let b = findBeneficiary(startRef);
  for (let i = 0; i < levels.length && b; i++) {
    if (seen.has(b.ref)) break; // guard against circular upline references
    seen.add(b.ref);
    out.push({ beneficiary: b, level: levels[i].level, pct: levels[i].pct });
    b = findBeneficiary(b.upline);
  }
  return out;
}
function buildPaymentCommissions(client, payment) {
  if (Docs.list('commissions').some(c => c.paymentId === payment.id)) return 0;
  const estate = Docs.get('estates', client.estateId);
  const type = estate ? estate.type : (client.accountType === 'Easy Buy' ? 'easybuy' : 'standard');
  const chain = commissionChain(client.referredBy, type);
  chain.forEach(l => Docs.put('commissions', {
    id: uid('cm_'), paymentId: payment.id, receiptNo: payment.receiptNo,
    clientName: client.name, estateName: client.estateName, estateType: type,
    staffName: l.beneficiary.name, staffRef: l.beneficiary.ref, level: l.level, rate: l.pct,
    base: payment.amount, amount: Math.round(payment.amount * l.pct / 100), date: nowIso()
  }));
  return chain.length;
}
function buildSaleCommissions(sale) {
  if (Docs.list('commissions').some(c => c.paymentId === sale.id)) return 0;
  const chain = commissionChain(sale.consultantId, sale.estateType);
  chain.forEach(l => Docs.put('commissions', {
    id: uid('cm_'), paymentId: sale.id, receiptNo: sale.ref,
    clientName: sale.clientName, estateName: sale.estateName, estateType: sale.estateType,
    staffName: l.beneficiary.name, staffRef: l.beneficiary.ref, level: l.level, rate: l.pct,
    base: sale.amount, amount: Math.round(sale.amount * l.pct / 100),
    status: 'Active', source: 'Consultant sale', date: nowIso()
  }));
  return chain.length;
}
function markPaid(payment, reference, source) {
  return tx(() => {
    const fresh = Docs.get('payments', payment.id);
    if (!fresh || fresh.status === 'Paid') return fresh;
    fresh.status = 'Paid';
    fresh.reference = reference;
    fresh.paidAt = nowIso();
    fresh.source = source || 'Manual';
    Docs.put('payments', fresh);
    const client = Docs.get('clients', fresh.clientId);
    if (client) {
      client.status = 'Paid';
      Docs.put('clients', client);
      buildPaymentCommissions(client, fresh);
    }
    return fresh;
  });
}

/* ---------- public views (never expose secrets / other people's data) ---------- */
function publicClient(c) { const { passHash, ...rest } = c; return rest; }

/* ============================================================
   ROUTES
============================================================ */
const routes = [];
const route = (method, pattern, auth, handler) => routes.push({ method, re: new RegExp('^' + pattern + '$'), auth, handler });

function requireAdmin(req) {
  const p = readToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!p || p.r !== 'admin') throw new HttpError(401, 'Administrator login required.', 'ADMIN_AUTH');
}
function requireConsultant(req) {
  const p = readToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!p || p.r !== 'consultant') throw new HttpError(401, 'Please log in.', 'CS_AUTH');
  const c = Docs.get('consultants', p.id);
  if (!c || !c.consultantId) throw new HttpError(401, 'Please log in.', 'CS_AUTH');
  // Checked against the database on EVERY request, so deactivation takes effect immediately.
  if (c.status === 'Inactive') throw new HttpError(403, 'Your consultant account has been deactivated. Please contact the Admin.', 'INACTIVE');
  return c;
}

/* ---------- PUBLIC ---------- */
route('GET', '/api/public', null, () => {
  const st = settings();
  return {
    estates: Docs.list('estates').filter(e => e.active !== false),
    gallery: Docs.list('gallery'),
    content: KV.get('content', {}),
    paystackKey: st.paystack || ''
  };
});

route('POST', '/api/subscribe', null, (req, body) => {
  if (!rateLimit(req, 'subscribe', 20, 3600e3)) throw new HttpError(429, 'Too many requests. Please try again later.');
  const name = str(body.name, 120), email = str(body.email, 254).toLowerCase(), phone = str(body.phone, 30);
  const ref = str(body.ref, 40), method = body.method === 'bank' ? 'bank' : 'paystack';
  if (!name) throw bad('Please enter your full name.');
  if (!validEmail(email)) throw bad('Please enter a valid email address.');
  if (normPhone(phone).length < 10) throw bad('Please enter a valid phone number.');

  const estate = Docs.get('estates', str(body.estateId, 64));
  if (!estate || estate.active === false) throw bad('Please select an available estate.');
  const plot = (estate.plots || [])[Number(body.plotIndex)];
  if (!plot) throw bad('Please select a plot size.');
  const plan = ['outright', 'm6', 'm12'].includes(body.plan) ? body.plan : 'outright';
  // The price is always computed on the server from the estate record. The browser cannot set it.
  let amount = plot.outright;
  if (plan === 'm6') amount = plot.m6 > 0 ? plot.m6 : plot.outright;
  if (plan === 'm12') amount = plot.m12 > 0 ? plot.m12 : (plot.m6 > 0 ? plot.m6 : plot.outright);
  if (!(amount > 0)) throw bad('This plot has no price set for the chosen plan.');

  const tempPassword = 'CIRP' + crypto.randomInt(1000, 10000);
  return tx(() => {
    const clientNo = nextNumber('client', 1000);
    const receiptNo = 'RCP-' + nextNumber('receipt', 5000);
    const client = {
      id: uid('c_'), clientId: 'CHL-' + clientNo, passHash: hashPassword(tempPassword),
      name, email, phone,
      accountType: estate.type === 'easybuy' ? 'Easy Buy' : 'Normal Estate',
      estateId: estate.id, estateName: estate.name, plotSize: plot.size, plan, amount,
      referredBy: ref, method, createdAt: nowIso(),
      status: method === 'paystack' ? 'Awaiting payment' : 'Pending transfer'
    };
    Docs.put('clients', client);
    const payment = {
      id: uid('p_'), receiptNo, clientId: client.id, clientNo,
      clientName: name, estateName: client.estateName, plotSize: client.plotSize,
      amount, method, status: method === 'paystack' ? 'Unpaid' : 'Pending', date: nowIso()
    };
    Docs.put('payments', payment);
    return { client: publicClient(client), payment, tempPassword, email };
  });
});

async function verifyPaystack(payment, reference) {
  const secret = paystackSecret();
  if (!secret) throw new HttpError(503, 'Online payment verification is not configured yet. Your subscription is saved and awaits payment.');
  const r = await fetch('https://api.paystack.co/transaction/verify/' + encodeURIComponent(reference), {
    headers: { Authorization: 'Bearer ' + secret }
  });
  const j = await r.json().catch(() => ({}));
  const d = j && j.data;
  const ok = r.ok && j.status && d && d.status === 'success' &&
    d.currency === 'NGN' && Number(d.amount) === Math.round(payment.amount * 100) &&
    d.reference === payment.receiptNo;
  if (!ok) throw new HttpError(402, 'Payment could not be verified.');
  return d.reference;
}

route('POST', '/api/paystack/verify', null, async (req, body) => {
  if (!rateLimit(req, 'verify', 30, 3600e3)) throw new HttpError(429, 'Too many requests.');
  const payment = Docs.get('payments', str(body.paymentId, 64));
  if (!payment || payment.method !== 'paystack') throw new HttpError(404, 'Payment not found.');
  if (payment.status === 'Paid') return { payment };
  const ref = await verifyPaystack(payment, str(body.reference, 100));
  return { payment: markPaid(payment, ref, 'Paystack') };
});

// Paystack calls this itself (set the URL in your Paystack dashboard) — a reliable fallback
// if the customer closes the browser right after paying.
route('POST', '/api/paystack/webhook', 'raw', async (req, body, raw) => {
  const secret = paystackSecret();
  if (!secret) throw new HttpError(503, 'Not configured.');
  const sig = crypto.createHmac('sha512', secret).update(raw).digest('hex');
  if (!safeEqual(sig, req.headers['x-paystack-signature'] || '')) throw new HttpError(401, 'Bad signature.');
  if (body.event === 'charge.success' && body.data) {
    const payment = Docs.list('payments').find(p => p.receiptNo === body.data.reference && p.method === 'paystack');
    if (payment && payment.status !== 'Paid' && body.data.currency === 'NGN' &&
        Number(body.data.amount) === Math.round(payment.amount * 100)) {
      markPaid(payment, body.data.reference, 'Paystack');
    }
  }
  return { received: true };
});

/* ---------- CONSULTANT ---------- */
route('POST', '/api/consultant/register', null, (req, body) => {
  if (!rateLimit(req, 'register', 10, 3600e3)) throw new HttpError(429, 'Too many registrations from this connection. Try again later.');
  const name = str(body.name, 120), email = str(body.email, 254).toLowerCase(), phone = str(body.phone, 30);
  const cause = str(body.cause, 1000), upline = str(body.upline, 40).toUpperCase();
  const pass = String(body.password || '');
  if (!name) throw bad('Please enter your full name.');
  if (!validEmail(email)) throw bad('Please enter a valid email address.');
  if (normPhone(phone).length < 10) throw bad('Enter a valid phone number.');
  if (pass.length < 6 || pass.length > 200) throw bad('Password must be at least 6 characters.');
  if (!cause) throw bad('Please state your cause of registration.');
  dataUrlInfo(body.passport, ['image/jpeg', 'image/png', 'image/webp'], 600000, 'Passport photograph');

  return tx(() => {
    const exists = Docs.list('consultants').some(c =>
      (c.email || '').toLowerCase() === email || normPhone(c.phone) === normPhone(phone));
    if (exists) throw new HttpError(409, 'An account with this email or phone number already exists.');
    Docs.put('consultants', {
      id: uid('cs_'), consultantId: '', status: 'Pending Activation',
      name, email, phone, passHash: hashPassword(pass), passport: body.passport,
      cause, upline, createdAt: nowIso()
    });
    return { ok: true };
  });
});

route('POST', '/api/consultant/login', null, (req, body) => {
  if (!rateLimit(req, 'cslogin', 15, 15 * 60e3)) throw new HttpError(429, 'Too many login attempts. Please wait 15 minutes.');
  const u = str(body.username, 254), pw = String(body.password || '');
  const all = Docs.list('consultants');
  const c = all.find(x => {
    if (!u) return false;
    if (u.includes('@')) return (x.email || '').toLowerCase() === u.toLowerCase();
    const p = normPhone(u);
    return p.length >= 10 && normPhone(x.phone) === p;
  });
  // Always run a hash comparison so response time doesn't reveal whether the account exists.
  const ok = checkPassword(pw, c ? c.passHash : 'scrypt$00$00');
  if (!c || !ok) throw new HttpError(401, 'Incorrect email/phone or password.');
  if (!c.consultantId) throw new HttpError(403, 'Your account is awaiting activation. The Admin must assign your Consultant ID before you can log in.', 'PENDING');
  if (c.status === 'Inactive') throw new HttpError(403, 'Your consultant account has been deactivated. Please contact the Admin.', 'INACTIVE');
  return { token: signToken({ r: 'consultant', id: c.id }, 12 * 3600) };
});

route('POST', '/api/consultant/reset-password', null, (req, body) => {
  if (!rateLimit(req, 'csreset', 5, 3600e3)) throw new HttpError(429, 'Too many attempts. Please try again later.');
  const email = str(body.email, 254).toLowerCase(), phone = normPhone(body.phone);
  const pw = String(body.password || '');
  if (pw.length < 6 || pw.length > 200) throw bad('New password must be at least 6 characters.');
  const c = Docs.list('consultants').find(x => (x.email || '').toLowerCase() === email && normPhone(x.phone) === phone);
  if (!c) throw new HttpError(404, 'We could not match that email and phone number to a consultant account.');
  c.passHash = hashPassword(pw);
  Docs.put('consultants', c);
  return { ok: true };
});

route('GET', '/api/consultant/me', 'consultant', (req, body, raw, c) => {
  return {
    consultant: safeConsultant(c),
    sales: Docs.list('sales').filter(s => s.consultantRef === c.id),
    commissions: Docs.list('commissions').filter(x => (x.staffRef || '').toUpperCase() === c.consultantId.toUpperCase())
  };
});

route('POST', '/api/consultant/sales', 'consultant', (req, body, raw, c) => {
  if (!rateLimit(req, 'sales', 60, 3600e3)) throw new HttpError(429, 'Too many submissions. Try again later.');
  const estate = Docs.get('estates', str(body.estateId, 64));
  if (!estate || estate.active === false) throw bad('Select an estate.');
  const plotSize = str(body.plotSize, 60);
  if (!(estate.plots || []).some(p => p.size === plotSize)) throw bad('Select a valid plot size.');
  const amount = Number(body.amount);
  if (!(amount > 0) || amount > 1e10) throw bad('Enter the amount paid.');
  const clientName = str(body.clientName, 120);
  if (!clientName) throw bad('Enter the client name.');
  const r = body.receipt || {};
  dataUrlInfo(r.data, ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'], 1700000, 'Receipt');
  return tx(() => {
    const sale = {
      id: uid('sl_'), ref: 'SL-' + String(nextNumber('sale', 0)).padStart(4, '0'),
      consultantRef: c.id, consultantId: c.consultantId, consultantName: c.name,
      clientName, clientPhone: str(body.clientPhone, 30),
      estateId: estate.id, estateName: estate.name, estateType: estate.type, plotSize, amount,
      receipt: r.data, receiptType: r.type === 'pdf' ? 'pdf' : 'image',
      status: 'Pending', rejectReason: '', createdAt: nowIso()
    };
    Docs.put('sales', sale);
    return { sale };
  });
});

route('POST', '/api/consultant/sales/([^/]+)/resubmit', 'consultant', (req, body, raw, c, m) => {
  const s = Docs.get('sales', m[1]);
  if (!s || s.consultantRef !== c.id) throw new HttpError(404, 'Sale not found.');
  if (s.status !== 'Rejected') throw bad('Only rejected sales can be re-submitted.');
  const r = body.receipt || {};
  dataUrlInfo(r.data, ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'], 1700000, 'Receipt');
  s.receipt = r.data; s.receiptType = r.type === 'pdf' ? 'pdf' : 'image';
  s.previousRejection = s.rejectReason; s.rejectReason = ''; s.status = 'Pending'; s.createdAt = nowIso();
  Docs.put('sales', s);
  return { sale: s };
});

/* ---------- ADMIN ---------- */
route('POST', '/api/admin/login', null, (req, body) => {
  if (!rateLimit(req, 'adminlogin', 8, 15 * 60e3)) throw new HttpError(429, 'Too many login attempts. Please wait 15 minutes.');
  if (!checkPassword(String(body.password || ''), KV.get('adminHash', ''))) throw new HttpError(401, 'Wrong password. Try again.');
  return { token: signToken({ r: 'admin' }, 8 * 3600) };
});

function adminSnapshot() {
  const st = settings();
  return {
    estates: Docs.list('estates'), gallery: Docs.list('gallery'), content: KV.get('content', {}),
    clients: Docs.list('clients').map(publicClient), payments: Docs.list('payments'),
    commissions: Docs.list('commissions'), staff: Docs.list('staff'),
    consultants: Docs.list('consultants').map(safeConsultant), sales: Docs.list('sales'),
    settings: { paystack: st.paystack || '', hasSecret: !!paystackSecret() },
    counter: KV.get('counter', {})
  };
}
route('GET', '/api/admin/data', 'admin', () => adminSnapshot());

const SYNCABLE = ['estates', 'gallery', 'staff'];
route('POST', '/api/admin/sync', 'admin', (req, body) => {
  const col = body.collection;
  if (!SYNCABLE.includes(col)) throw bad('This collection cannot be edited directly.');
  const ups = Array.isArray(body.upserts) ? body.upserts : [];
  const dels = Array.isArray(body.deletes) ? body.deletes : [];
  if (ups.length > 500 || dels.length > 500) throw bad('Too many changes in one request.');
  tx(() => {
    ups.forEach(o => {
      if (!o || typeof o !== 'object' || typeof o.id !== 'string' || !o.id || o.id.length > 64) throw bad('Invalid record.');
      Docs.put(col, o);
    });
    dels.forEach(id => {
      const old = Docs.get(col, String(id));
      Docs.del(col, String(id));
      if (col === 'gallery' && old && typeof old.url === 'string' && old.url.startsWith('/uploads/')) {
        const f = path.join(UPLOAD_DIR, path.basename(old.url));
        fs.unlink(f, () => {});
      }
    });
  });
  return { ok: true };
});

route('PUT', '/api/admin/content', 'admin', (req, body) => {
  if (!body.content || typeof body.content !== 'object') throw bad('Invalid content.');
  KV.set('content', body.content);
  return { ok: true };
});

route('PUT', '/api/admin/settings', 'admin', (req, body) => {
  const st = settings();
  if (typeof body.paystack === 'string') st.paystack = body.paystack.trim().slice(0, 200);
  if (typeof body.paystackSecret === 'string' && body.paystackSecret.trim()) st.paystackSecret = body.paystackSecret.trim().slice(0, 200);
  KV.set('settings', st);
  if (body.password) {
    if (String(body.password).length < 8) throw bad('Admin password must be at least 8 characters.');
    KV.set('adminHash', hashPassword(String(body.password)));
  }
  return { ok: true, passwordChanged: !!body.password };
});

const UPLOAD_TYPES = {
  'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif', 'image/webp': 'webp', 'image/avif': 'avif',
  'video/mp4': 'mp4', 'video/webm': 'webm', 'video/ogg': 'ogv', 'video/quicktime': 'mov'
};
route('POST', '/api/admin/upload', 'admin', (req, body) => {
  const m = /^data:([a-z]+\/[a-z0-9.+-]+);base64,/i.exec(String(body.data || ''));
  const mime = m && m[1].toLowerCase();
  if (!mime || !UPLOAD_TYPES[mime]) throw bad('Unsupported file type.');
  const buf = Buffer.from(String(body.data).slice(m[0].length), 'base64');
  const isVideo = mime.startsWith('video/');
  if (buf.length > (isVideo ? 30e6 : 8e6)) throw bad('File too large (max ' + (isVideo ? '30' : '8') + ' MB).');
  const file = crypto.randomBytes(12).toString('hex') + '.' + UPLOAD_TYPES[mime];
  fs.writeFileSync(path.join(UPLOAD_DIR, file), buf);
  return { url: '/uploads/' + file, type: isVideo ? 'video' : 'image' };
});

route('POST', '/api/admin/payments/([^/]+)/mark-paid', 'admin', (req, body, raw, _, m) => {
  const p = Docs.get('payments', m[1]);
  if (!p) throw new HttpError(404, 'Payment not found.');
  return { payment: markPaid(p, 'MANUAL-' + Date.now(), 'Manual') };
});

route('POST', '/api/admin/consultants/([^/]+)/activate', 'admin', (req, body, raw, _, m) => {
  return tx(() => {
    const c = Docs.get('consultants', m[1]);
    if (!c) throw new HttpError(404, 'Consultant not found.');
    if (c.consultantId) throw bad('This consultant already has an ID.');
    const yy = String(new Date().getFullYear()).slice(-2);
    c.consultantId = 'CH/IC/' + yy + '/' + String(nextNumber('consultant_' + yy, 0)).padStart(4, '0');
    c.status = 'Active';
    c.activatedAt = nowIso();
    Docs.put('consultants', c);
    return { consultantId: c.consultantId };
  });
});
route('POST', '/api/admin/consultants/([^/]+)/deactivate', 'admin', (req, body, raw, _, m) => {
  const c = Docs.get('consultants', m[1]);
  if (!c || !c.consultantId) throw new HttpError(404, 'Consultant not found.');
  if (c.status === 'Inactive') return { ok: true };
  c.status = 'Inactive'; c.deactivatedAt = nowIso();
  Docs.put('consultants', c);
  return { ok: true };
});
route('POST', '/api/admin/consultants/([^/]+)/reactivate', 'admin', (req, body, raw, _, m) => {
  const c = Docs.get('consultants', m[1]);
  if (!c || c.status !== 'Inactive') throw new HttpError(404, 'Inactive consultant not found.');
  c.status = 'Active'; c.reactivatedAt = nowIso(); delete c.deactivatedAt;
  Docs.put('consultants', c);
  return { ok: true };
});

route('POST', '/api/admin/sales/([^/]+)/approve', 'admin', (req, body, raw, _, m) => {
  return tx(() => {
    const s = Docs.get('sales', m[1]);
    if (!s || s.status !== 'Pending') throw bad('Only pending sales can be approved.');
    s.status = 'Approved'; s.reviewedAt = nowIso();
    Docs.put('sales', s);
    return { entries: buildSaleCommissions(s) };
  });
});
route('POST', '/api/admin/sales/([^/]+)/reject', 'admin', (req, body, raw, _, m) => {
  const reason = str(body.reason, 500);
  if (!reason) throw bad('A rejection reason is required.');
  const s = Docs.get('sales', m[1]);
  if (!s || s.status !== 'Pending') throw bad('Only pending sales can be rejected.');
  s.status = 'Rejected'; s.rejectReason = reason; s.reviewedAt = nowIso();
  Docs.put('sales', s);
  return { ok: true };
});

route('POST', '/api/admin/reset', 'admin', (req, body) => {
  if (body.confirm !== 'RESET') throw bad('Confirmation missing.');
  tx(() => {
    ['clients', 'payments', 'commissions', 'consultants', 'sales'].forEach(Docs.wipe);
    KV.set('counter', { client: 1000, receipt: 5000 });
  });
  return { ok: true };
});

/* ============================================================
   HTTP PLUMBING
============================================================ */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.webp': 'image/webp', '.avif': 'image/avif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.mp4': 'video/mp4', '.webm': 'video/webm', '.ogv': 'video/ogg', '.mov': 'video/quicktime'
};

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (process.env.TRUST_PROXY === '1') res.setHeader('Strict-Transport-Security', 'max-age=31536000');
}
function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new HttpError(413, 'Upload is too large.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function serveFile(req, res, file, cache) {
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end('Not found'); }
    const ext = path.extname(file).toLowerCase();
    const type = MIME[ext];
    if (!type) { res.writeHead(404); return res.end('Not found'); }
    const headers = { 'Content-Type': type, 'Cache-Control': cache || 'no-cache', 'Accept-Ranges': 'bytes' };
    const range = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (range && st.size) { // lets videos seek
      let start = range[1] ? Number(range[1]) : st.size - Number(range[2] || 0);
      let end = range[1] && range[2] ? Number(range[2]) : st.size - 1;
      if (start > end || start >= st.size) { res.writeHead(416, { 'Content-Range': 'bytes */' + st.size }); return res.end(); }
      end = Math.min(end, st.size - 1);
      res.writeHead(206, { ...headers, 'Content-Range': `bytes ${start}-${end}/${st.size}`, 'Content-Length': end - start + 1 });
      return fs.createReadStream(file, { start, end }).pipe(res);
    }
    res.writeHead(200, { ...headers, 'Content-Length': st.size });
    fs.createReadStream(file).pipe(res);
  });
}

const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res);
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, 'http://x').pathname); }
  catch (e) { res.writeHead(400); return res.end('Bad request'); }

  /* ----- API ----- */
  if (pathname.startsWith('/api/')) {
    try {
      const r = routes.find(x => x.method === req.method && x.re.test(pathname));
      if (!r) throw new HttpError(404, 'Not found.');
      const m = r.re.exec(pathname).slice(1);
      m.unshift(null);
      let consultant = null;
      if (r.auth === 'admin') requireAdmin(req);
      if (r.auth === 'consultant') consultant = requireConsultant(req);

      let raw = Buffer.alloc(0), body = {};
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const limit = pathname === '/api/admin/upload' ? 45e6 : 6e6;
        raw = await readBody(req, limit);
        if (raw.length) {
          try { body = JSON.parse(raw.toString('utf8')); }
          catch (e) { throw bad('Invalid JSON body.'); }
        }
      }
      const out = await r.handler(req, body, raw, consultant, m);
      return send(res, 200, out == null ? { ok: true } : out);
    } catch (e) {
      if (e instanceof HttpError) return send(res, e.status, { error: e.message, code: e.code || null });
      console.error('Unhandled error on', req.method, pathname, e);
      return send(res, 500, { error: 'Something went wrong on the server.' });
    }
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end('Method not allowed'); }

  /* ----- uploaded media ----- */
  if (pathname.startsWith('/uploads/')) {
    return serveFile(req, res, path.join(UPLOAD_DIR, path.basename(pathname)), 'public, max-age=31536000, immutable');
  }

  /* ----- static site ----- */
  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const file = path.resolve(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end('Forbidden'); }
  serveFile(req, res, file);
});

server.listen(PORT, () => console.log('Cirpman server running on http://localhost:' + PORT));
