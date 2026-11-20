'use strict';
/* Mill ERP server. One file, no packages. Needs Node 22 or newer.
   Run:  node server.js     (PORT=3000, DB_FILE=data.db) */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data.db');
const SESSION_HOURS = 12;
const MAX_BODY = 12 * 1024 * 1024;

const db = new DatabaseSync(DB_FILE);
db.exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS tenants(code TEXT PRIMARY KEY, name TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(tenant TEXT NOT NULL, emp_id TEXT NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, created TEXT NOT NULL, PRIMARY KEY(tenant,emp_id));
CREATE TABLE IF NOT EXISTS signups(tenant TEXT NOT NULL, emp_id TEXT NOT NULL, name TEXT, dept TEXT, desig TEXT, manager TEXT, salt TEXT, hash TEXT, status TEXT NOT NULL, at TEXT NOT NULL, by TEXT, PRIMARY KEY(tenant,emp_id));
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, tenant TEXT NOT NULL, emp_id TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS store(tenant TEXT NOT NULL, k TEXT NOT NULL, v TEXT NOT NULL, version INTEGER NOT NULL, by TEXT, at TEXT, PRIMARY KEY(tenant,k));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT, at TEXT, emp_id TEXT, action TEXT, detail TEXT);
`);
const q = {
  tenant: db.prepare('SELECT * FROM tenants WHERE code=?'),
  addTenant: db.prepare('INSERT INTO tenants(code,name,created) VALUES(?,?,?)'),
  user: db.prepare('SELECT * FROM users WHERE tenant=? AND emp_id=?'),
  addUser: db.prepare('INSERT OR REPLACE INTO users(tenant,emp_id,salt,hash,created) VALUES(?,?,?,?,?)'),
  addSess: db.prepare('INSERT INTO sessions(token_hash,tenant,emp_id,expires) VALUES(?,?,?,?)'),
  sess: db.prepare('SELECT * FROM sessions WHERE token_hash=?'),
  delSess: db.prepare('DELETE FROM sessions WHERE token_hash=?'),
  purge: db.prepare('DELETE FROM sessions WHERE expires<?'),
  getKey: db.prepare('SELECT v,version FROM store WHERE tenant=? AND k=?'),
  allKeys: db.prepare('SELECT k,v,version FROM store WHERE tenant=?'),
  versions: db.prepare('SELECT k,version FROM store WHERE tenant=?'),
  putKey: db.prepare('INSERT INTO store(tenant,k,v,version,by,at) VALUES(?,?,?,?,?,?) ON CONFLICT(tenant,k) DO UPDATE SET v=excluded.v,version=excluded.version,by=excluded.by,at=excluded.at'),
  addSign: db.prepare('INSERT INTO signups(tenant,emp_id,name,dept,desig,manager,salt,hash,status,at) VALUES(?,?,?,?,?,?,?,?,?,?)'),
  signs: db.prepare("SELECT emp_id,name,dept,desig,manager,status,at FROM signups WHERE tenant=? ORDER BY at"),
  sign: db.prepare('SELECT * FROM signups WHERE tenant=? AND emp_id=?'),
  decide: db.prepare('UPDATE signups SET status=?,by=?,salt=NULL,hash=NULL WHERE tenant=? AND emp_id=?'),
  audit: db.prepare('INSERT INTO audit(tenant,at,emp_id,action,detail) VALUES(?,?,?,?,?)'),
};
const now = () => new Date().toISOString();
const log = (t, who, a, d) => { try { q.audit.run(t, now(), who || '', a, String(d || '').slice(0, 300)); } catch (e) {} };

/* passwords: scrypt with a random salt */
function hashPw(pw, salt) { return crypto.scryptSync(String(pw), salt, 64).toString('hex'); }
function makePw(pw) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: hashPw(pw, salt) }; }
function checkPw(pw, salt, hash) {
  const a = Buffer.from(hashPw(pw, salt), 'hex'), b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function newSession(tenant, emp) {
  const token = crypto.randomBytes(32).toString('hex');
  q.addSess.run(sha(token), tenant, emp, Date.now() + SESSION_HOURS * 3600e3);
  return token;
}

/* login throttle: 5 wrong tries then a 5 minute wait */
const fails = new Map();
function throttled(key) { const f = fails.get(key); return f && f.n >= 5 && Date.now() < f.until; }
function failed(key) { const f = fails.get(key) || { n: 0, until: 0 }; f.n++; if (f.n >= 5) f.until = Date.now() + 5 * 60e3; fails.set(key, f); }

/* data helpers */
function readKey(tenant, k, fallback) { const r = q.getKey.get(tenant, k); if (!r) return fallback; try { return JSON.parse(r.v); } catch (e) { return fallback; } }
function employees(tenant) { return readKey(tenant, 'employee', []); }
function empOf(tenant, id) { return employees(tenant).find(e => e.id === id); }
function isHR(tenant, id) {
  if (id === 'E-1000' && employees(tenant).length === 0) return true; /* first save of a new company */
  const e = empOf(tenant, id); return !!e && e.status === 'Active' && (!!e.isMD || e.dept === 'Admin & HR'); }
function subtree(tenant, id) {
  const emps = employees(tenant), out = new Set([id]), st = [id];
  while (st.length) { const x = st.pop(); emps.forEach(e => { if (e.manager === x && !out.has(e.id)) { out.add(e.id); st.push(e.id); } }); }
  return out;
}
const HR_ONLY_KEYS = new Set(['employee', '_wf', 'signups']);
/* may this person change this row? HR and the MD may change anything. Others only rows about themselves or about people who report to them. */
const STORE_KEYS = new Set(['item-group', 'warehouse', 'supplier', 'item', 'purchase-order', 'goods-receipt', 'material-issue', 'stock-transfer', 'stock-reconciliation', 'material-request', 'uom', 'brand', 'bill-submission', 'quality-inspection', 'gate-pass', 'contract', 'proforma-invoice', 'import-lc', 'shipment-document']);
function rowAllowed(tenant, who, row, tree, me, k) {
  if (!row) return true;
  /* store module: Store and Accounts staff keep stock records; anyone named in a document's approval chain may act on it */
  if (STORE_KEYS.has(k) && me && me.status === 'Active' && (me.dept === 'Store' || me.dept === 'Accounts')) return true;
  if (STORE_KEYS.has(k) && Array.isArray(row.chain) && row.chain.some(s => s && s.who === who)) return true;
  if (row.emp) return tree.has(row.emp);
  if (k === 'job-requisition' && me && row.dept && me.dept === row.dept) return true;
  return false;
}
function writeAllowed(tenant, who, k, oldV, newV) {
  if (isHR(tenant, who)) return true;
  if (HR_ONLY_KEYS.has(k)) return false;
  if (!Array.isArray(newV) || !Array.isArray(oldV)) return false;
  const tree = subtree(tenant, who), me = empOf(tenant, who);
  const om = new Map(oldV.map(r => [r && r.id, r])), nm = new Map(newV.map(r => [r && r.id, r]));
  for (const [id, r] of nm) {
    const o = om.get(id);
    if (!o || JSON.stringify(o) !== JSON.stringify(r)) { if (!rowAllowed(tenant, who, r, tree, me, k) || (o && !rowAllowed(tenant, who, o, tree, me, k))) return false; }
  }
  for (const [id, o] of om) if (!nm.has(id) && !rowAllowed(tenant, who, o, tree, me, k)) return false;
  return true;
}

/* http */
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const parts = [];
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { reject(Object.assign(new Error('too large'), { code: 413 })); req.destroy(); } else parts.push(c); });
    req.on('end', () => { try { resolve(parts.length ? JSON.parse(Buffer.concat(parts).toString('utf8')) : {}); } catch (e) { reject(Object.assign(new Error('bad json'), { code: 400 })); } });
    req.on('error', reject);
  });
}
function auth(req) {
  const h = req.headers.authorization || '';
  const m = /^Bearer ([0-9a-f]{64})$/.exec(h); if (!m) return null;
  q.purge.run(Date.now());
  const s = q.sess.get(sha(m[1])); if (!s || s.expires < Date.now()) return null;
  return { tenant: s.tenant, id: s.emp_id, th: sha(m[1]) };
}
const slug = s => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30);
const strOk = (s, min, max) => typeof s === 'string' && s.trim().length >= min && s.length <= max;
function nextEmpId(tenant) {
  let n = 999;
  employees(tenant).forEach(e => { const m = /^E-(\d+)$/.exec(e.id); if (m) n = Math.max(n, +m[1]); });
  q.signs.all(tenant).forEach(s => { const m = /^E-(\d+)$/.exec(s.emp_id); if (m) n = Math.max(n, +m[1]); });
  return 'E-' + (n + 1);
}

async function api(req, res, url) {
  const route = req.method + ' ' + url.pathname;
  if (route === 'GET /api/ping') return send(res, 200, { ok: true, v: 1 });

  if (route === 'POST /api/tenant') {
    const b = await readBody(req);
    if (!strOk(b.company, 3, 80) || !strOk(b.name, 3, 80)) return send(res, 400, { error: 'Write the company name and your full name.' });
    if (!strOk(b.password, 8, 200)) return send(res, 400, { error: 'The password needs at least 8 characters.' });
    let code = slug(b.company); if (code.length < 3) return send(res, 400, { error: 'Use a longer company name.' });
    if (q.tenant.get(code)) { code = code + '-' + crypto.randomBytes(2).toString('hex'); }
    q.addTenant.run(code, b.company.trim(), now());
    const p = makePw(b.password);
    q.addUser.run(code, 'E-1000', p.salt, p.hash, now());
    log(code, 'E-1000', 'tenant-created', b.company);
    return send(res, 200, { tenant: code, id: 'E-1000', token: newSession(code, 'E-1000') });
  }
  if (route === 'POST /api/login') {
    const b = await readBody(req);
    const tenant = slug(b.tenant), id = String(b.id || '').trim().toUpperCase(), key = tenant + '|' + id + '|' + req.socket.remoteAddress;
    if (throttled(key)) return send(res, 429, { error: 'Too many wrong tries. Wait 5 minutes.' });
    const u = q.user.get(tenant, id);
    if (!u || !checkPw(String(b.password || ''), u.salt, u.hash)) { failed(key); log(tenant, id, 'login-failed', ''); return send(res, 401, { error: 'Company code, employee ID or password is wrong.' }); }
    const emp = empOf(tenant, id);
    if (emp && emp.status !== 'Active') return send(res, 403, { error: 'This employee is no longer active.' });
    fails.delete(key); log(tenant, id, 'login', '');
    return send(res, 200, { tenant, id, token: newSession(tenant, id) });
  }
  if (route === 'POST /api/signup') {
    const b = await readBody(req), tenant = slug(b.tenant);
    if (!q.tenant.get(tenant)) return send(res, 404, { error: 'There is no company with this code.' });
    if (!strOk(b.name, 3, 80)) return send(res, 400, { error: 'Write your full name.' });
    if (!strOk(b.dept, 1, 60) || !strOk(b.desig, 1, 60)) return send(res, 400, { error: 'Choose the department and designation.' });
    if (!strOk(b.password, 8, 200)) return send(res, 400, { error: 'The password needs at least 8 characters.' });
    const mgr = String(b.manager || '').trim().toUpperCase();
    if (!empOf(tenant, mgr)) return send(res, 400, { error: 'The employee ID you report to was not found.' });
    const id = nextEmpId(tenant), p = makePw(b.password);
    q.addSign.run(tenant, id, b.name.trim(), b.dept, b.desig, mgr, p.salt, p.hash, 'Pending', now());
    log(tenant, id, 'signup', b.name);
    return send(res, 200, { id });
  }

  const s = auth(req);
  if (!s) return send(res, 401, { error: 'Please sign in again.' });
  if (route === 'POST /api/logout') { q.delSess.run(s.th); return send(res, 200, { ok: true }); }
  if (route === 'GET /api/me') return send(res, 200, { id: s.id, tenant: s.tenant, name: (q.tenant.get(s.tenant) || {}).name, hr: isHR(s.tenant, s.id) });
  if (route === 'GET /api/state') {
    const data = {}; q.allKeys.all(s.tenant).forEach(r => { data[r.k] = { v: JSON.parse(r.v), version: r.version }; });
    return send(res, 200, { data });
  }
  if (route === 'GET /api/versions') {
    const versions = {}; q.versions.all(s.tenant).forEach(r => { versions[r.k] = r.version; });
    const out = { versions }; if (isHR(s.tenant, s.id)) out.pending = q.signs.all(s.tenant).filter(x => x.status === 'Pending').length;
    return send(res, 200, out);
  }
  let m = /^\/api\/state\/([A-Za-z0-9_.~-]{1,80})$/.exec(url.pathname);
  if (m && req.method === 'GET') {
    const r = q.getKey.get(s.tenant, m[1]); if (!r) return send(res, 404, { error: 'No such data' });
    return send(res, 200, { v: JSON.parse(r.v), version: r.version });
  }
  if (m && req.method === 'PUT') {
    const k = m[1], b = await readBody(req);
    if (!('value' in b) || typeof b.base !== 'number') return send(res, 400, { error: 'Bad request' });
    const cur = q.getKey.get(s.tenant, k), curVer = cur ? cur.version : 0;
    const oldV = cur ? JSON.parse(cur.v) : (Array.isArray(b.value) ? [] : {});
    if (!writeAllowed(s.tenant, s.id, k, oldV, b.value)) { log(s.tenant, s.id, 'write-denied', k); return send(res, 403, { error: 'Your role cannot change this.' }); }
    if (curVer !== b.base) return send(res, 409, { error: 'Someone else changed this data first.', version: curVer });
    q.putKey.run(s.tenant, k, JSON.stringify(b.value), curVer + 1, s.id, now());
    log(s.tenant, s.id, 'write', k + ' v' + (curVer + 1));
    return send(res, 200, { version: curVer + 1 });
  }
  if (route === 'GET /api/signups') {
    if (!isHR(s.tenant, s.id)) return send(res, 403, { error: 'Only HR or the MD can see sign-up requests.' });
    return send(res, 200, { list: q.signs.all(s.tenant) });
  }
  m = /^\/api\/signups\/(E-\d+)\/decide$/.exec(url.pathname);
  if (m && req.method === 'POST') {
    if (!isHR(s.tenant, s.id)) return send(res, 403, { error: 'Only HR or the MD can decide sign-up requests.' });
    const b = await readBody(req), r = q.sign.get(s.tenant, m[1]);
    if (!r || r.status !== 'Pending') return send(res, 409, { error: 'That request was already decided.' });
    if (b.ok) { q.addUser.run(s.tenant, r.emp_id, r.salt, r.hash, now()); }
    q.decide.run(b.ok ? 'Approved' : 'Rejected', s.id, s.tenant, r.emp_id);
    log(s.tenant, s.id, b.ok ? 'signup-approved' : 'signup-rejected', r.emp_id);
    return send(res, 200, { ok: true, emp: { id: r.emp_id, name: r.name, dept: r.dept, desig: r.desig, manager: r.manager } });
  }
  if (route === 'POST /api/password') {
    const b = await readBody(req), u = q.user.get(s.tenant, s.id);
    if (!u || !checkPw(String(b.old || ''), u.salt, u.hash)) return send(res, 401, { error: 'The old password is wrong.' });
    if (!strOk(b.password, 8, 200)) return send(res, 400, { error: 'The new password needs at least 8 characters.' });
    const p = makePw(b.password); q.addUser.run(s.tenant, s.id, p.salt, p.hash, u.created);
    log(s.tenant, s.id, 'password-changed', ''); return send(res, 200, { ok: true });
  }
  return send(res, 404, { error: 'Not found' });
}

const PUB = path.join(__dirname, 'public');
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    const f = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const full = path.join(PUB, f);
    if (!full.startsWith(PUB) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) { res.writeHead(404); return res.end('Not found'); }
    const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
    res.writeHead(200, { 'Content-Type': types[path.extname(full)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
    fs.createReadStream(full).pipe(res);
  } catch (e) {
    if (!res.headersSent) send(res, e.code === 413 || e.code === 400 ? e.code : 500, { error: e.code === 413 ? 'Too much data' : e.code === 400 ? 'Bad request' : 'Server error' });
    if (!e.code) console.error(e);
  }
});
if (require.main === module) server.listen(PORT, () => console.log('Mill ERP running on http://localhost:' + PORT));
module.exports = { server, db };
