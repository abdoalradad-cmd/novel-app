// RadPad API — Cloudflare Worker + D1. بدون أي مكتبات خارجية.
const ITER = 50000;               // عدد لفّات تشفير الباسورد
const TOKEN_DAYS = 30;
const LIM = { title: 120, author: 80, genre: 30, tag: 30, tags: 10, synopsis: 2000, cover: 600,
  subtitle: 100, pass: 40, chTitle: 150, chContent: 120000, chapters: 400, totalChars: 2500000, novelsPerUser: 30, body: 3200000 };
const enc = new TextEncoder();
let jwtKeyCache = null;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization,Content-Type,X-Unlock,X-Device',
  'Access-Control-Max-Age': '86400'
};
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', ...CORS, ...extra } });
}
const fail = (msg, status = 400) => json({ error: msg }, status);

/* ---------- تشفير ---------- */
const b64 = (buf) => { let s = ''; new Uint8Array(buf).forEach((c) => (s += String.fromCharCode(c))); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64u = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));

async function pbkdf2(password, salt, iter) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, key, 256);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `${ITER}$${b64(salt)}$${b64(await pbkdf2(password, salt, ITER))}`;
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function checkPassword(password, stored) {
  const [iter, salt, hash] = String(stored).split('$');
  const got = b64(await pbkdf2(password, unb64(salt), parseInt(iter, 10)));
  return safeEqual(got, hash);
}
async function getKey(env) {
  if (jwtKeyCache) return jwtKeyCache;
  let row = await env.DB.prepare("SELECT v FROM settings WHERE k='jwt'").first();
  if (!row) {
    const secret = b64(crypto.getRandomValues(new Uint8Array(32)));
    await env.DB.prepare("INSERT OR IGNORE INTO settings (k,v) VALUES ('jwt',?)").bind(secret).run();
    row = await env.DB.prepare("SELECT v FROM settings WHERE k='jwt'").first();
  }
  jwtKeyCache = await crypto.subtle.importKey('raw', enc.encode(row.v), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  return jwtKeyCache;
}
async function makeToken(env, uid) {
  const body = b64u(enc.encode(JSON.stringify({ uid, exp: Date.now() + TOKEN_DAYS * 86400000 })));
  const sig = await crypto.subtle.sign('HMAC', await getKey(env), enc.encode(body));
  return `${body}.${b64u(sig)}`;
}
async function readToken(env, token) {
  try {
    const [body, sig] = String(token).split('.');
    const ok = await crypto.subtle.verify('HMAC', await getKey(env), unb64u(sig), enc.encode(body));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(unb64u(body)));
    return p.exp > Date.now() ? p : null;
  } catch (e) { return null; }
}
/* ----- حد الأجهزة: المجاني جهاز واحد، البريميوم 3، الأدمن مفتوح. الجهاز بيبعت X-Device ----- */
const SESS_TTL = 10 * 86400000, MAX_DEV_ACCTS = 2, devMsgs = new WeakMap();
const devOf = (request) => { const d = request.headers.get('X-Device') || ''; return /^[A-Za-z0-9_-]{8,64}$/.test(d) ? d : ''; };
const devBlockMsg = (u) => ((u.role === 'admin' || (u.premium_until || 0) > Date.now()) ? 'لا يمكنك الدخول، الحساب قيد التسجيل على 3 أجهزة' : 'لا يمكنك الدخول، الحساب قيد التسجيل على جهاز آخر');
async function devEnter(env, u, dev) { // true = مسموح
  if (!dev) return true;
  const now = Date.now(), ex = await env.DB.prepare('SELECT seen FROM sessions WHERE uid=? AND dev=?').bind(u.id, dev).first();
  if (ex) { if (now - ex.seen > 600000) await env.DB.prepare('UPDATE sessions SET seen=? WHERE uid=? AND dev=?').bind(now, u.id, dev).run(); return true; }
  if (u.role !== 'admin') {
    const lim = (u.premium_until || 0) > now ? 3 : 1;
    const c = (await env.DB.prepare('SELECT COUNT(*) AS n FROM sessions WHERE uid=? AND seen>?').bind(u.id, now - SESS_TTL).first()).n;
    if (c >= lim) return false;
  }
  await env.DB.prepare('INSERT OR REPLACE INTO sessions (uid,dev,seen,created) VALUES (?,?,?,?)').bind(u.id, dev, now, now).run(); return true;
}
async function authUser(env, request) {
  const h = request.headers.get('Authorization') || '';
  const m = /^Bearer (.+)$/.exec(h); if (!m) return null;
  const p = await readToken(env, m[1]); if (!p) return null;
  const u = await env.DB.prepare('SELECT id,email,name,role,premium_until,avatar,bio,links FROM users WHERE id=?').bind(p.uid).first();
  if (u && !(await devEnter(env, u, devOf(request)))) { devMsgs.set(request, devBlockMsg(u)); return null; }
  return u;
}
const linksOf = (v) => { let o = {}; try { o = typeof v === 'string' ? JSON.parse(v || '{}') : (v || {}); } catch (e) {} const out = {}; for (const k of ['facebook', 'wattpad', 'youtube']) out[k] = (typeof o[k] === 'string') ? cleanUrl(o[k]) : ''; return out; };
const FOREVER = 32503680000000;
const ownerId = async (env) => { const a = await env.DB.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").first(); return a ? a.id : 0; };
const withOwner = async (env, o) => { o.owner = o.role === 'admin' && (await ownerId(env)) === o.id; return o; };
const isPremium = (u) => !!u && (u.role === 'admin' || (u.premium_until || 0) > Date.now());
const userOut = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, premium: isPremium(u), premiumUntil: u.role === 'admin' ? FOREVER : (u.premium_until || 0), avatar: u.avatar || '', bio: u.bio || '', links: linksOf(u.links) });

/* ---------- ترقية القاعدة تلقائيًا (للقواعد القديمة) ---------- */
let migrated = false;
async function ensureSchema(env) {
  if (migrated) return;
  const need = [['novels', 'd_extra'], ['novels', 'l_extra'], ['chapters', 'locked'], ['users', 'premium_until'], ['users', 'avatar'], ['users', 'bio'], ['users', 'links'], ['novels', 'hidden'], ['users', 'payout'], ['users', 'points'], ['users', 'last_ip'], ['users', 'last_seen'], ['users', 'wallet']];
  for (const [t, c] of need) {
    try { await env.DB.prepare(`SELECT ${c} FROM ${t} LIMIT 1`).first(); }
    catch (e) {
      const def = c === 'last_seen' ? 'INTEGER NOT NULL DEFAULT 0' : c === 'last_ip' ? "TEXT NOT NULL DEFAULT ''" : (c === 'points' || c === 'wallet') ? 'REAL NOT NULL DEFAULT 0' : (c === 'locked' || c === 'premium_until' || c === 'hidden') ? 'INTEGER NOT NULL DEFAULT 0' : (c === 'avatar' || c === 'bio' || c === 'payout') ? "TEXT NOT NULL DEFAULT ''" : "TEXT NOT NULL DEFAULT '{}'";
      await env.DB.prepare(`ALTER TABLE ${t} ADD COLUMN ${c} ${def}`).run();
    }
  }
  for (const q of ['CREATE TABLE IF NOT EXISTS follows (follower_id INTEGER NOT NULL, author_id INTEGER NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (follower_id, author_id))',
    'CREATE INDEX IF NOT EXISTS idx_follows_author ON follows(author_id)',
    'CREATE TABLE IF NOT EXISTS reads (k TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)',
    'CREATE TABLE IF NOT EXISTS read_seen (h TEXT NOT NULL, k TEXT NOT NULL, ch INTEGER NOT NULL, ts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (h, k, ch))',
    "CREATE TABLE IF NOT EXISTS cmt_log (id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER NOT NULL, nid TEXT NOT NULL, ch INTEGER NOT NULL, norm TEXT NOT NULL DEFAULT '', day TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL DEFAULT 0, elig INTEGER NOT NULL DEFAULT 0, awarded INTEGER NOT NULL DEFAULT 0)",
    'CREATE INDEX IF NOT EXISTS idx_cmt_uid ON cmt_log(uid, day)',
    'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, author_id INTEGER NOT NULL, kind TEXT NOT NULL, novel_id INTEGER NOT NULL, title TEXT NOT NULL, ts INTEGER NOT NULL)',
    'CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)',
    'CREATE TABLE IF NOT EXISTS sessions (uid INTEGER NOT NULL, dev TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (uid, dev))',
    'CREATE TABLE IF NOT EXISTS presence (dev TEXT PRIMARY KEY, uid INTEGER NOT NULL DEFAULT 0, ip TEXT NOT NULL DEFAULT \'\', seen INTEGER NOT NULL DEFAULT 0)',
    'CREATE INDEX IF NOT EXISTS idx_presence_seen ON presence(seen)',
    'CREATE TABLE IF NOT EXISTS visits (day TEXT NOT NULL, dev TEXT NOT NULL, uid INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, dev))',
    "CREATE TABLE IF NOT EXISTS bcast (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL DEFAULT '', text TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS contact (id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '', text TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS news (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL DEFAULT '', text TEXT NOT NULL DEFAULT '', img TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL DEFAULT 0)",
    'CREATE TABLE IF NOT EXISTS dev_accts (dev TEXT NOT NULL, uid INTEGER NOT NULL, ts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (dev, uid))',
    'CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER NOT NULL, kind TEXT NOT NULL, novel_ref TEXT NOT NULL, who TEXT NOT NULL, title TEXT NOT NULL, text TEXT NOT NULL, ts INTEGER NOT NULL)',
    'CREATE INDEX IF NOT EXISTS idx_notes_uid ON notes(uid, ts)',
    'CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, plan_id TEXT NOT NULL, plan_name TEXT NOT NULL, months INTEGER NOT NULL, amount TEXT NOT NULL, method TEXT NOT NULL, sender TEXT NOT NULL, proof TEXT NOT NULL, note TEXT NOT NULL DEFAULT \'\', status TEXT NOT NULL DEFAULT \'pending\', reason TEXT NOT NULL DEFAULT \'\', created_at INTEGER NOT NULL, decided_at INTEGER NOT NULL DEFAULT 0)',
    'CREATE INDEX IF NOT EXISTS idx_pay_user ON payments(user_id, created_at)',
    'CREATE INDEX IF NOT EXISTS idx_pay_status ON payments(status, created_at)',
    "CREATE TABLE IF NOT EXISTS tts_ch (id INTEGER PRIMARY KEY AUTOINCREMENT, nid TEXT NOT NULL, idx INTEGER NOT NULL, ntitle TEXT NOT NULL DEFAULT '', ctitle TEXT NOT NULL DEFAULT '', ord INTEGER NOT NULL DEFAULT 0, sig TEXT NOT NULL DEFAULT '', text TEXT NOT NULL, parts TEXT NOT NULL DEFAULT '[]', nparts INTEGER NOT NULL DEFAULT 0, done INTEGER NOT NULL DEFAULT 0, secs REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued', owner TEXT NOT NULL DEFAULT '', lock_until INTEGER NOT NULL DEFAULT 0, retry_at INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, err TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL DEFAULT 0, prov TEXT NOT NULL DEFAULT 'gemini')",
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_tts_ch_key ON tts_ch(nid, idx)',
    'CREATE INDEX IF NOT EXISTS idx_tts_ch_q ON tts_ch(status, ord)',
    'CREATE TABLE IF NOT EXISTS tts_use (day TEXT NOT NULL, prov TEXT NOT NULL, reqs INTEGER NOT NULL DEFAULT 0, chars INTEGER NOT NULL DEFAULT 0, secs REAL NOT NULL DEFAULT 0, cost REAL NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, limited INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, prov))',
    "CREATE TABLE IF NOT EXISTS contest_weeks (week TEXT PRIMARY KEY, questions TEXT NOT NULL DEFAULT '[]', prize REAL NOT NULL DEFAULT 0, winner_id INTEGER NOT NULL DEFAULT 0, winner_answer INTEGER NOT NULL DEFAULT 0, picked_at INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS contest_answers (id INTEGER PRIMARY KEY AUTOINCREMENT, week TEXT NOT NULL, user_id INTEGER NOT NULL, answers TEXT NOT NULL DEFAULT '[]', ts INTEGER NOT NULL DEFAULT 0)",
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_contest_ans ON contest_answers(week, user_id)',
    'CREATE TABLE IF NOT EXISTS pts_votes (voter INTEGER NOT NULL, nid TEXT NOT NULL, ch INTEGER NOT NULL, ts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (voter, nid, ch))',
    "CREATE TABLE IF NOT EXISTS wal_log (id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER NOT NULL, day TEXT NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL, amt REAL NOT NULL DEFAULT 0, ts INTEGER NOT NULL DEFAULT 0, UNIQUE(uid,kind,ref))",
    "CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER NOT NULL, points REAL NOT NULL, egp REAL NOT NULL, rate REAL NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', ts INTEGER NOT NULL, decided INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS streaks (uid INTEGER PRIMARY KEY, last TEXT NOT NULL DEFAULT '', cur INTEGER NOT NULL DEFAULT 0, awards INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS ch_alerts (uid INTEGER NOT NULL, nid TEXT NOT NULL, ch INTEGER NOT NULL, rel INTEGER NOT NULL DEFAULT 0, title TEXT NOT NULL DEFAULT '', sent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (uid, nid, ch))",
    'CREATE INDEX IF NOT EXISTS ch_alerts_due ON ch_alerts (sent, rel)',
    "CREATE TABLE IF NOT EXISTS pts_draws (week TEXT PRIMARY KEY, user_id INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL DEFAULT '', avatar TEXT NOT NULL DEFAULT '', points REAL NOT NULL DEFAULT 0, prize REAL NOT NULL DEFAULT 0, ts INTEGER NOT NULL DEFAULT 0)",
    'CREATE TABLE IF NOT EXISTS purchases (user_id INTEGER NOT NULL, nid TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (user_id, nid))',
    "CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, nid TEXT NOT NULL, ntitle TEXT NOT NULL DEFAULT '', author_id INTEGER NOT NULL DEFAULT 0, price REAL NOT NULL DEFAULT 0, share REAL NOT NULL DEFAULT 0, method TEXT NOT NULL DEFAULT '', sender TEXT NOT NULL DEFAULT '', proof TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', reason TEXT NOT NULL DEFAULT '', paid_out INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, decided_at INTEGER NOT NULL DEFAULT 0)",
    'CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at)',
    'CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status, created_at)',
    'CREATE TABLE IF NOT EXISTS tts_usage (day TEXT PRIMARY KEY, reqs INTEGER NOT NULL DEFAULT 0, hits INTEGER NOT NULL DEFAULT 0, chars INTEGER NOT NULL DEFAULT 0, secs REAL NOT NULL DEFAULT 0, cost REAL NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, limited INTEGER NOT NULL DEFAULT 0)']) await env.DB.prepare(q).run();
  try { await env.DB.prepare('SELECT prov FROM tts_ch LIMIT 1').first(); } catch (e) { await env.DB.prepare("ALTER TABLE tts_ch ADD COLUMN prov TEXT NOT NULL DEFAULT 'gemini'").run(); }
  for (const [c, d] of [['author_uid', 'INTEGER NOT NULL DEFAULT 0'], ['status', "TEXT NOT NULL DEFAULT 'ok'"]]) {
    try { await env.DB.prepare('SELECT ' + c + ' FROM news LIMIT 1').first(); } catch (e) { try { await env.DB.prepare('ALTER TABLE news ADD COLUMN ' + c + ' ' + d).run(); } catch (e2) {} }
  }
  migrated = true;
}

/* ---------- تصريح فتح الرواية المقفولة (12 ساعة) ---------- */
async function makeUnlock(env, nid) {
  const body = b64u(enc.encode(JSON.stringify({ n: nid, exp: Date.now() + 12 * 3600000 })));
  const sig = await crypto.subtle.sign('HMAC', await getKey(env), enc.encode(body));
  return `${body}.${b64u(sig)}`;
}
async function hasUnlock(env, request, nid) {
  const t = request.headers.get('X-Unlock');
  if (t) { const p = await readToken(env, t); if (p && p.n === nid) return true; }
  if (request.headers.get('Authorization')) {
    const u = await authUser(env, request);
    if (u) {
      if (u.role === 'admin') return true;
      if (await env.DB.prepare('SELECT 1 AS x FROM novels WHERE id=? AND user_id=?').bind(nid, u.id).first()) return true;
      if (await env.DB.prepare('SELECT 1 AS x FROM purchases WHERE user_id=? AND nid=?').bind(u.id, 'u' + nid).first()) return true;
    }
  }
  return false;
}

/* ---------- حماية من التكرار ---------- */
async function tooMany(env, key, max, windowMs) {
  const now = Date.now();
  await env.DB.prepare('DELETE FROM attempts WHERE ts < ?').bind(now - 86400000).run();
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM attempts WHERE k=? AND ts>?').bind(key, now - windowMs).first();
  return (r && r.n) >= max;
}
const noteAttempt = (env, key) => env.DB.prepare('INSERT INTO attempts (k,ts) VALUES (?,?)').bind(key, Date.now()).run();

/* ---------- تنظيف المدخلات ---------- */
const str = (v, max) => String(v == null ? '' : v).replace(/\r\n/g, '\n').slice(0, max);
const GRADS = ['from-emerald-900 via-slate-950 to-black', 'from-slate-900 via-blue-950 to-slate-950', 'from-amber-950 via-stone-900 to-black', 'from-rose-950 via-slate-950 to-black', 'from-purple-950 via-slate-900 to-black'];
const ICONS = ['fa-book', 'fa-flask-vial', 'fa-feather-pointed', 'fa-anchor', 'fa-hourglass-half', 'fa-key', 'fa-masks-theater'];
function cleanUrl(u) { u = str(u, LIM.cover).trim(); return /^https:\/\/[^\s<>"']+$/i.test(u) ? u : ''; }
// جدولة الفصول: وقت النشر بالمللي ثانية (0 = ينزل علطول)
const relOf = (v) => { v = Math.floor(+v); return Number.isFinite(v) && v > 1e12 && v < Date.now() + 400 * 86400000 ? v : 0; };
function cleanNovel(b) {
  const title = str(b.title, LIM.title).trim();
  if (!title) throw new Error('اكتب عنوان الرواية');
  const tags = (Array.isArray(b.tags) ? b.tags : []).map((t) => str(t, LIM.tag).trim()).filter(Boolean).slice(0, LIM.tags);
  const chapters = Array.isArray(b.chapters) ? b.chapters : [];
  if (chapters.length > LIM.chapters) throw new Error('عدد الفصول أكبر من المسموح');
  let total = 0;
  const chs = chapters.map((c, i) => {
    const content = str(c && c.content, LIM.chContent);
    total += content.length;
    return { title: str(c && c.title, LIM.chTitle).trim() || `الفصل ${i + 1}`, content, locked: c && c.locked ? 1 : 0, release: relOf(c && c.release) };
  });
  if (total > LIM.totalChars) throw new Error('حجم النص كبير جدًا');
  const password = str(b.password, LIM.pass).trim();
  const lockAll = !!b.lockAll, anyLocked = chs.some((c) => c.locked);
  if ((lockAll || anyLocked) && !password) throw new Error('اكتب باسورد القفل أو شيل القفل');
  const extra = { subtitle: str(b.subtitle, LIM.subtitle).trim(), novelStatus: b.novelStatus === 'مكتملة' ? 'مكتملة' : 'مستمرة',
    promoUrl: cleanUrl(b.promoUrl), pdfUrl: cleanUrl(b.pdfUrl), grad: GRADS.includes(b.grad) ? b.grad : GRADS[0],
    icon: ICONS.includes(b.icon) ? b.icon : 'fa-book', allowSharing: b.allowSharing !== false, paper: !!b.paper, password, lockAll, lockPdf: b.lockPdf !== false };
  if (chs.some((c) => c.release)) extra.rel = chs.map((c) => c.release);
  if (b.siteId) extra.siteId = str(b.siteId, 80);
  extra.price = (lockAll || anyLocked || extra.pdfUrl) ? cleanPrice(b.price) : 0; extra.oldPrice = extra.price && cleanPrice(b.oldPrice) > extra.price ? cleanPrice(b.oldPrice) : 0;
  return { title, author: str(b.author, LIM.author).trim(), genre: str(b.genre, LIM.genre).trim() || 'عام',
    tags, synopsis: str(b.synopsis, LIM.synopsis), cover: cleanUrl(b.cover), extra: JSON.stringify(extra), chapters: chs };
}
const parseJson = (s) => { try { const o = JSON.parse(s); return o && typeof o === 'object' ? o : {}; } catch (e) { return {}; } };
const parseTags = (s) => { try { const a = JSON.parse(s); return Array.isArray(a) ? a : []; } catch (e) { return []; } };

async function body(request, max = LIM.body) {
  const len = parseInt(request.headers.get('content-length') || '0', 10);
  if (len > max * 2) throw new Error('الطلب كبير جدًا');
  const text = await request.text();
  if (text.length > max) throw new Error('الطلب كبير جدًا');
  try { return JSON.parse(text || '{}'); } catch (e) { throw new Error('بيانات غير صحيحة'); }
}

/* ---------- حفظ فصول المسودة ---------- */
function chapterStmts(env, id, ver, chs) {
  const del = env.DB.prepare('DELETE FROM chapters WHERE novel_id=? AND ver=?').bind(id, ver);
  const ins = chs.map((c, i) => env.DB.prepare('INSERT INTO chapters (novel_id,ver,idx,title,content,locked) VALUES (?,?,?,?,?,?)').bind(id, ver, i, c.title, c.content, c.locked ? 1 : 0));
  return [del, ...ins];
}

/* مفاتيح المشترين لرواية موقع (نسخة السيرفر) — السيرفر هو المصدر: n = باسورد الرواية كلها، p = الـ PDF، c = فصول مقفولة */
function vaultEntryOf(x, chs) {
  const pw = x.password || '', e = { n: '', p: '', c: {} };
  if (!pw) return null;
  if (x.lockAll) e.n = pw;
  if (x.pdfUrl && x.lockPdf !== false) e.p = pw;
  if (!x.lockAll) (chs || []).forEach((c, i) => { if (c.locked) e.c[i] = pw; });
  return (e.n || e.p || Object.keys(e.c).length) ? e : null;
}
async function serverVault(env) {
  const out = {};
  const { results } = await env.DB.prepare("SELECT id,l_extra FROM novels WHERE is_live=1 AND l_extra LIKE '%\"siteId\"%'").all();
  for (const r of results) {
    const x = extraOf(r.l_extra); if (!x.siteId) continue;
    const { results: cs } = await env.DB.prepare("SELECT locked FROM chapters WHERE novel_id=? AND ver='l' ORDER BY idx").bind(r.id).all();
    const e = vaultEntryOf(x, cs.map((c) => ({ locked: !!c.locked })));
    out[x.siteId] = e || { n: '', p: '', c: {} };
  }
  return out;
}
async function applyServerVault(env) {
  const sv = await serverVault(env); if (!Object.keys(sv).length) return;
  const v = await getSetting(env, 'vault'), keys = { ...(v.keys || {}) };
  Object.keys(sv).forEach((id) => { if (sv[id].n || sv[id].p || Object.keys(sv[id].c).length) keys[id] = sv[id]; else delete keys[id]; });
  await setSetting(env, 'vault', { keys, at: Date.now() });
}
const cleanPrice = (v) => { const n = parseFloat(String(v == null ? '' : v).replace(/[^0-9.]/g, '')); return n > 0 && n <= 100000 ? Math.round(n * 100) / 100 : 0; };
function extraOf(raw) {
  const x = parseJson(raw);
  return { subtitle: x.subtitle || '', novelStatus: x.novelStatus || 'مستمرة', promoUrl: x.promoUrl || '', pdfUrl: x.pdfUrl || '', grad: GRADS.includes(x.grad) ? x.grad : GRADS[0],
    icon: ICONS.includes(x.icon) ? x.icon : 'fa-book', allowSharing: x.allowSharing !== false, paper: !!x.paper, password: x.password || '', lockAll: !!x.lockAll, lockPdf: x.lockPdf !== false, price: cleanPrice(x.price), oldPrice: cleanPrice(x.oldPrice), siteId: x.siteId || '', rel: Array.isArray(x.rel) ? x.rel.slice(0, 2000).map((n) => +n || 0) : [] };
}
function myNovelRow(r) {
  return { id: r.id, status: r.status, isLive: !!r.is_live, hidden: !!r.hidden, rejectReason: r.reject_reason, updatedAt: r.updated_at, publishedAt: r.published_at,
    title: r.d_title, author: r.d_author, genre: r.d_genre, tags: parseTags(r.d_tags), synopsis: r.d_synopsis, cover: r.d_cover, ...extraOf(r.d_extra) };
}
function liveNovelRow(r) {
  return { id: r.id, status: r.status, isLive: !!r.is_live, publishedAt: r.published_at, updatedAt: r.updated_at,
    title: r.l_title, author: r.l_author, genre: r.l_genre, tags: parseTags(r.l_tags), synopsis: r.l_synopsis, cover: r.l_cover, ...extraOf(r.l_extra) };
}

/* ---------- إعدادات Premium (واتساب + الأسعار) ---------- */
async function getSetting(env, k) { const r = await env.DB.prepare('SELECT v FROM settings WHERE k=?').bind(k).first(); return r ? parseJson(r.v) : {}; }
const setSetting = (env, k, v) => env.DB.prepare('INSERT INTO settings (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').bind(k, JSON.stringify(v)).run();
const DEFAULT_PLANS = [{ id: 'm1', name: 'شهر', months: 1, price: '50', old: '', badge: '' }, { id: 'm6', name: '6 شهور', months: 6, price: '250', old: '300', badge: 'وفّر 17%' }, { id: 'y1', name: 'سنة', months: 12, price: '450', old: '600', badge: 'الأوفر' }];
function cleanPlans(p) {
  const arr = Array.isArray(p) && p.length ? p : DEFAULT_PLANS, out = [];
  arr.slice(0, 6).forEach((x, i) => {
    const months = parseInt(x && x.months, 10);
    if (!(months >= 1 && months <= 120)) return;
    out.push({ id: /^[a-z0-9_-]{1,12}$/i.test(String(x.id || '')) ? String(x.id) : 'p' + (i + 1), name: str(x.name, 30).trim() || months + ' شهر', months, price: str(x.price, 20).replace(/[^0-9.]/g, '').slice(0, 10), old: str(x.old, 20).replace(/[^0-9.]/g, '').slice(0, 10), badge: str(x.badge, 24).trim() });
  });
  return out.length ? out : DEFAULT_PLANS;
}
function cleanMethods(m, wa) {
  m = m && typeof m === 'object' ? m : {};
  const ip = m.instapay || {}, wl = m.wallet || {};
  return {
    instapay: { on: ip.on !== false, handle: str(ip.handle, 60).trim(), name: str(ip.name, 60).trim() },
    wallet: { on: wl.on !== false, number: str(wl.number != null ? wl.number : (wa || '01067567795'), 25).replace(/[^0-9+]/g, ''), name: str(wl.name, 60).trim(), kinds: str(wl.kinds != null ? wl.kinds : 'فودافون كاش / اتصالات كاش / أورنج كاش', 80).trim() },
  };
}
async function getPremiumInfo(env) {
  const x = await getSetting(env, 'premium');
  return { whatsapp: x.whatsapp || '01067567795', defaultPrice: x.defaultPrice || '', message: x.message || '', prices: x.prices && typeof x.prices === 'object' ? x.prices : {},
    plans: cleanPlans(x.plans), methods: cleanMethods(x.methods, x.whatsapp), features: cleanFeatures(x.features), novelPrices: cleanNovelPrices((await getSetting(env, 'nprices')).prices) };
}
const DEFAULT_FEATURES = ['تسمع الروايات بصوت مصري وانت بتقرا 🎧', 'شغّال على كل أجهزتك بنفس الحساب', 'بتدعم الكتّاب اللي بتحبهم'];
function cleanFeatures(f) {
  const out = (Array.isArray(f) ? f : []).map((t) => str(t, 120).trim()).filter(Boolean).slice(0, 10);
  return out.length ? out : DEFAULT_FEATURES;
}
function cleanNovelPrices(p) {
  const out = {}; if (!p || typeof p !== 'object') return out;
  Object.keys(p).slice(0, 600).forEach((k) => { const v = p[k] || {}, pr = cleanPrice(v.price); if (pr) { const old = cleanPrice(v.old); out[str(k, 80)] = { price: pr, old: old > pr ? old : 0, title: str(v.title, 120).trim() }; } });
  return out;
}


const COMMISSION = 0.25; // نسبة الموقع من كل رواية بتتباع
const payoutOf = (raw) => { const o = parseJson(raw); return o.value ? { kind: o.kind === 'instapay' ? 'instapay' : 'wallet', value: String(o.value), name: String(o.name || '') } : null; };
async function notifyUser(env, uid, title, text, ref = 'ord') {
  try { await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(uid, 'payment', ref, 'RadPad', title, text, Date.now()).run(); if (env.FCM_SA) await sendPush(env, title, text, '', 'u_' + uid); } catch (e) {}
}
async function notifyAdmins(env, who, title, text, ref = 'ordadm') {
  try {
    const { results } = await env.DB.prepare("SELECT id FROM users WHERE role='admin'").all();
    for (const a of results) {
      await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(a.id, 'payment', ref, who, title, text, Date.now()).run();
      if (env.FCM_SA) { try { await sendPush(env, title, text, '', 'u_' + a.id); } catch (e) {} }
    }
  } catch (e) {}
}

/* ---------- الصوت المصري: Gemini + Azure — طابور لكل مزوّد + أصوات متعددة + تخزين R2 + متابعة التكلفة ---------- */
const ROLES = ['narrator', 'man', 'woman', 'boy', 'girl'];
const G_VOICES = { narrator: 'Charon', man: 'Orus', woman: 'Kore', boy: 'Puck', girl: 'Leda' };
const AZ_VOICES = { narrator: { v: 'ar-SA-HamedNeural', rate: '-4%', pitch: '0%' }, man: { v: 'ar-EG-ShakirNeural', rate: '0%', pitch: '0%' }, woman: { v: 'ar-EG-SalmaNeural', rate: '0%', pitch: '0%' },
  boy: { v: 'ar-EG-ShakirNeural', rate: '+6%', pitch: '+38%' }, girl: { v: 'ar-EG-SalmaNeural', rate: '+6%', pitch: '+30%' } };
const RD_DEF = { mode: 'B', skipNarration: false, humanize: true, pauseMs: 380, batch: 7, autoWait: true, waitSec: 16, narrator: 'kareem', archMap: {}, pers: {}, anaModel: 'gemini-3-flash-preview', partChars: 0 };
function normRd(x) { // كل إعدادات أداة الرداد (كلها بتتغيّر من الأدمن؛ الافتراضي = اللي كان شغال)
  x = x && typeof x === 'object' ? x : {}; const num = (v, d, lo, hi) => (v == null || v === '' || isNaN(+v) ? d : Math.max(lo, Math.min(hi, +v)));
  const ids = RD_P.map((p) => p.id), am = {}, ps = {};
  Object.entries(x.archMap || {}).forEach(([k, v]) => { if (ids.includes(v) && /^[a-z_]{2,40}$/.test(k)) am[k] = v; });
  Object.entries(x.pers || {}).forEach(([k, v]) => { if (ids.includes(k) && v) ps[k] = { v: /^[A-Za-z]{3,24}$/.test(v.v || '') ? v.v : '', p: +v.p ? num(v.p, 0, 0.7, 1.4) : 0 }; });
  return { mode: ['A', 'B', 'C'].includes(x.mode) ? x.mode : 'B', skipNarration: x.skipNarration === true, humanize: x.humanize !== false, pauseMs: num(x.pauseMs, 380, 0, 3000), batch: Math.round(num(x.batch, 7, 1, 10)), autoWait: x.autoWait !== false, waitSec: Math.round(num(x.waitSec, 16, 0, 60)), narrator: ids.includes(x.narrator) ? x.narrator : 'kareem', archMap: am, pers: ps, anaModel: /^[a-z0-9.\-]{4,60}$/i.test(x.anaModel || '') ? x.anaModel : 'gemini-3-flash-preview', partChars: Math.round(num(x.partChars, 0, 0, 3000)) };
}
const TTS_DEFAULT = { model: 'gemini-3.8-flash-tts', legacyModel: 'gemini-2.5-flash-preview-tts', style: 'warm, expressive audiobook narration in natural Egyptian Arabic', concurrency: 2, dailyMin: 20, freeMin: 0, priceIn: 0, priceOut: 0,
  gv: G_VOICES, defProv: 'gemini', novelProv: {}, multi: true, az: { region: '', dailyMin: 30, freeChars: 500000, price: 15, concurrency: 3, voices: AZ_VOICES } };
const PROVS = ['gemini', 'gemini2', 'gemini3', 'gemini4', 'gemini5', 'gemini6', 'rd1', 'rd2', 'rd3', 'rd4', 'rd5', 'rd6', 'azure'];
const isGoogle = (p) => /^(gemini\d*|rd[1-6])$/.test(p);
const normProv = (p) => (PROVS.includes(p) ? p : 'gemini');
const isGem = (p) => p !== 'azure';
// حسابات جوجل (1..6): كل حساب له مفتاحه وإعداداته وطابوره. المفتاح من أسرار Cloudflare (GEMINI_API_KEY, _2.._6) أو متسجّل من لوحة الأدمن
const GN = { gemini: '', gemini2: '_2', gemini3: '_3', gemini4: '_4', gemini5: '_5', gemini6: '_6', rd1: '_RD1', rd2: '_RD2', rd3: '_RD3', rd4: '_RD4', rd5: '_RD5', rd6: '_RD6' };
const gemKey = (env, prov) => env['GEMINI_API_KEY' + (GN[prov] || '')];
const gemEnv = (env, prov) => (prov === 'gemini' ? env : { ...env, GEMINI_API_KEY: gemKey(env, prov) });
const gcf = (conf, prov) => (prov === 'gemini' ? conf : conf[(prov[0] === 'r' ? 'r' + prov.slice(2) : 'g' + prov.slice(6))] || { dailyMin: 0, concurrency: 1, freeMin: 0 });
const provCap = (conf, prov) => (prov === 'azure' ? conf.az.dailyMin : gcf(conf, prov).dailyMin);
// السقف اليومي بيتضرب في عدد مفاتيح الحساب (كل مفتاح ليه حصته)
const provCapE = (env, conf, prov) => provCap(conf, prov) * (prov === 'azure' ? 1 : Math.max(1, gKeyList({ GEMINI_API_KEY: gemKey(env, prov) }).length));
const provPar = (conf, prov) => (prov === 'azure' ? conf.az.concurrency : gcf(conf, prov).concurrency);
let KC = { at: 0, v: null };
async function savedKeys(env) { if (!KC.v || Date.now() - KC.at > 15000) KC = { at: Date.now(), v: (await getSetting(env, 'tts_keys')) || {} }; return KC.v; }
async function withKeys(env) { const k = await savedKeys(env), e = { ...env, __base: env.__base || env }; for (const p of PROVS) if (isGoogle(p) && k[p]) e['GEMINI_API_KEY' + GN[p]] = k[p]; return e; }
async function getTtsConf(env) {
  const x = await getSetting(env, 'tts'), n = (v, d, lo, hi) => { const k = Number(v); return v !== '' && v != null && Number.isFinite(k) && k >= lo && k <= hi ? k : d; };
  const gv = {}; ROLES.forEach((r) => { const v = x.gv && x.gv[r]; gv[r] = /^[A-Za-z0-9_-]{2,40}$/.test(String(v || '')) ? String(v) : G_VOICES[r]; });
  const xa = x.az || {}, voices = {};
  ROLES.forEach((r) => { const v = (xa.voices || {})[r] || {}, d = AZ_VOICES[r]; voices[r] = { v: /^[A-Za-z]{2,3}-[A-Za-z]{2,4}-[A-Za-z0-9]{2,40}$/.test(String(v.v || '')) ? String(v.v) : d.v, rate: /^[+-]?\d{1,3}(\.\d)?%$/.test(String(v.rate || '')) ? String(v.rate) : d.rate, pitch: /^[+-]?\d{1,3}(\.\d)?%$/.test(String(v.pitch || '')) ? String(v.pitch) : d.pitch }; });
  const np = {}; Object.keys(x.novelProv || {}).slice(0, 2000).forEach((k) => { if (PROVS.includes(x.novelProv[k])) np[k] = x.novelProv[k]; });
  return { mm: x.mm !== false, model: x.model || TTS_DEFAULT.model, legacyModel: x.legacyModel || TTS_DEFAULT.legacyModel, style: x.style || TTS_DEFAULT.style, gv,
    concurrency: n(x.concurrency, TTS_DEFAULT.concurrency, 1, 4), dailyMin: n(x.dailyMin, TTS_DEFAULT.dailyMin, 0, 100000), freeMin: n(x.freeMin, 0, 0, 100000), priceIn: n(x.priceIn, 0, 0, 1000), priceOut: n(x.priceOut, 0, 0, 1000),
    defProv: PROVS.includes(x.defProv) ? x.defProv : 'gemini', novelProv: np, multi: x.multi !== false, rd: normRd(x.rd), radad: x.radad !== false, engine: x.engine === 'single' ? 'single' : 'mega', phon: x.phon !== false, smart: x.smart !== false, econ: x.econ !== false, hideListen: x.hideListen === true, listenAll: x.listenAll === true, rebalance: x.rebalance !== false, annModel: /^[A-Za-z0-9._-]{2,60}$/.test(String(x.annModel || '')) ? String(x.annModel) : 'gemini-2.5-flash', dict: String(x.dict || '').slice(0, 3000),
    g2: { dailyMin: n((x.g2 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.g2 || {}).freeMin, 0, 0, 100000), concurrency: n((x.g2 || {}).concurrency, 2, 1, 4) },
    g3: { dailyMin: n((x.g3 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.g3 || {}).freeMin, 0, 0, 100000), concurrency: n((x.g3 || {}).concurrency, 2, 1, 4) },
    g4: { dailyMin: n((x.g4 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.g4 || {}).freeMin, 0, 0, 100000), concurrency: n((x.g4 || {}).concurrency, 2, 1, 4) },
    g5: { dailyMin: n((x.g5 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.g5 || {}).freeMin, 0, 0, 100000), concurrency: n((x.g5 || {}).concurrency, 2, 1, 4) },
    g6: { dailyMin: n((x.g6 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.g6 || {}).freeMin, 0, 0, 100000), concurrency: n((x.g6 || {}).concurrency, 2, 1, 4) },
    r1: { dailyMin: n((x.r1 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.r1 || {}).freeMin, 0, 0, 100000), concurrency: n((x.r1 || {}).concurrency, 2, 1, 4) },
    r2: { dailyMin: n((x.r2 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.r2 || {}).freeMin, 0, 0, 100000), concurrency: n((x.r2 || {}).concurrency, 2, 1, 4) },
    r3: { dailyMin: n((x.r3 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.r3 || {}).freeMin, 0, 0, 100000), concurrency: n((x.r3 || {}).concurrency, 2, 1, 4) },
    r4: { dailyMin: n((x.r4 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.r4 || {}).freeMin, 0, 0, 100000), concurrency: n((x.r4 || {}).concurrency, 2, 1, 4) },
    r5: { dailyMin: n((x.r5 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.r5 || {}).freeMin, 0, 0, 100000), concurrency: n((x.r5 || {}).concurrency, 2, 1, 4) },
    r6: { dailyMin: n((x.r6 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.r6 || {}).freeMin, 0, 0, 100000), concurrency: n((x.r6 || {}).concurrency, 2, 1, 4) },
    az: { region: /^[a-z0-9-]{3,30}$/.test(String(xa.region || '')) ? String(xa.region) : '', dailyMin: n(xa.dailyMin, 30, 0, 100000), freeChars: n(xa.freeChars, 500000, 0, 1e9), price: n(xa.price, 15, 0, 1000), concurrency: n(xa.concurrency, 3, 1, 8), voices } };
}
const azRegion = (env, conf) => conf.az.region || String(env.AZURE_SPEECH_REGION || '').trim().toLowerCase();
const provReady = (env, conf, prov) => !!env.TTS_BUCKET && (prov === 'azure' ? !!(env.AZURE_SPEECH_KEY && azRegion(env, conf)) : !!gemKey(env, prov));
function ttsPrices(conf, now = Date.now()) { const late = now >= Date.UTC(2027, 0, 1); return { inP: conf.priceIn || (late ? 1 : 0.5), outP: conf.priceOut || (late ? 18 : 9) }; }
function ttsCost(chars, secs, conf) { const p = ttsPrices(conf); return (Math.ceil(chars / 2.5) * p.inP + secs * 25 * p.outP) / 1e6; }
const dayKey = (t = Date.now()) => new Date(t + 2 * 3600000).toISOString().slice(0, 10); // بتوقيت مصر تقريبًا
function b64bytes(b64) { const bin = atob(b64); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
function pcmToWav(pcm, rate) {
  const h = new ArrayBuffer(44), v = new DataView(h), w = (o, t) => { for (let i = 0; i < t.length; i++) v.setUint8(o + i, t.charCodeAt(i)); };
  w(0, 'RIFF'); v.setUint32(4, 36 + pcm.length, true); w(8, 'WAVE'); w(12, 'fmt '); v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true);
  v.setUint32(24, rate, true); v.setUint32(28, rate * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true); w(36, 'data'); v.setUint32(40, pcm.length, true);
  const out = new Uint8Array(44 + pcm.length); out.set(new Uint8Array(h), 0); out.set(pcm, 44); return out;
}
function findAudioB64(o, depth = 0) {
  if (!o || depth > 8 || typeof o === 'string') return '';
  if (Array.isArray(o)) { for (const x of o) { const r = findAudioB64(x, depth + 1); if (r) return r; } return ''; }
  for (const k of Object.keys(o)) { const v = o[k]; if (k === 'data' && typeof v === 'string' && v.length > 400 && /^[A-Za-z0-9+/=\s]+$/.test(v.slice(0, 200))) return v; }
  for (const k of Object.keys(o)) { const r = findAudioB64(o[k], depth + 1); if (r) return r; }
  return '';
}
function toWav(b64) { const bytes = b64bytes(b64.replace(/\s+/g, '')); return String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]) === 'RIFF' ? bytes : pcmToWav(bytes, 24000); }

// أكتر من مفتاح للحساب (سطر لكل مفتاح): بيتبدّل تلقائي لو المفتاح خلّص أو اتحظر
const GK = {};
const gKeyList = (env) => String(env.GEMINI_API_KEY || '').split(/[\s,;]+/).filter((k) => k.length > 15);
async function gFetch(env, url, init) {
  const ks = gKeyList(env); if (!ks.length) return fetch(url, init);
  const id = ks.join('|').slice(0, 40) + ks.length; let st = GK[id] || 0, last;
  for (let i = 0; i < ks.length; i++) {
    const k = ks[(st + i) % ks.length];
    last = await fetch(url, { ...init, headers: { ...(init && init.headers), 'x-goog-api-key': k } });
    if (last.status === 429 || last.status === 403 || last.status === 401 || (last.status === 400 && i < ks.length - 1 && /API key|api_key|expired/i.test(await last.clone().text().catch(() => '')))) { GK[id] = (st + i + 1) % ks.length; continue; }
    GK[id] = (st + i) % ks.length; return last;
  }
  return last;
}
async function q429(r) { try { const t = await r.text(); let m = ''; try { const j = JSON.parse(t); m = (j.error && j.error.message) || ''; const d = JSON.stringify((j.error && j.error.details) || ''); const q = /"quotaId":"([^"]+)"/.exec(d); if (q) m += ' [' + q[1] + ']'; } catch (e) { m = t; } return String(m).slice(0, 260); } catch (e) { return ''; } }
const pacificMinsLeft = () => { try { const p = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Los_Angeles', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date()), h = +p.find((x) => x.type === 'hour').value, m = +p.find((x) => x.type === 'minute').value; return 24 * 60 - (h * 60 + m) + 2; } catch (e) { return 120; } };
async function geminiSpeak(env, text, voiceName, conf, style) {
  try { return await geminiSpeak0(env, text, voiceName, conf, style); } catch (e) {
    if (e.code !== 429 || /PerDay|per day/i.test(e.detail || '')) throw e; await new Promise((r) => setTimeout(r, 4000)); return geminiSpeak0(env, text, voiceName, conf, style);
  }
}
async function geminiSpeak0(env, text, voiceName, conf, style) {
  style = style || conf.style;
  const key = env.GEMINI_API_KEY; if (!key) { const e = new Error('not_configured'); e.code = 503; throw e; }
  let lastErr;
  try {
    const r = await gFetch(env, 'https://generativelanguage.googleapis.com/v1beta/interactions', { method: 'POST', signal: AbortSignal.timeout(100000), headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
      body: JSON.stringify({ model: conf.model, input: [{ type: 'user_input', content: [{ type: 'text', text, annotations: [{ type: 'speech_metadata', style }] }] }], response_format: { type: 'audio' }, generation_config: { speech_config: [{ voice: voiceName }] } }) });
    if (r.status === 429) { const d = await q429(r); const e = new Error('busy'); e.code = 429; e.detail = d; throw e; }
    else if (r.ok) { const j = await r.json(); const b = findAudioB64(j); if (b) return toWav(b); lastErr = new Error('no_audio'); } else lastErr = new Error('gemini_' + r.status);
  } catch (e) { if (e.code === 429) throw e; lastErr = e; }
  const r2 = await gFetch(env, 'https://generativelanguage.googleapis.com/v1beta/models/' + conf.legacyModel + ':generateContent', { method: 'POST', signal: AbortSignal.timeout(100000), headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
    body: JSON.stringify({ contents: [{ parts: [{ text: 'Read the following in a ' + style + ': ' + text }] }], generationConfig: { responseModalities: ['AUDIO'], speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName } } } } }) });
  if (r2.status === 429) { const e = new Error('busy'); e.code = 429; e.detail = await q429(r2); throw e; }
  if (!r2.ok) { const e = new Error('gemini_' + r2.status); e.code = 502; e.detail = lastErr && lastErr.message; throw e; }
  const b2 = findAudioB64(await r2.json()); if (!b2) { const e = new Error('no_audio'); e.code = 502; throw e; }
  return toWav(b2);
}
/* ---------- تقسيم النص لأدوار: راوي / راجل / ست / ولد / بنت ---------- */
const AR_NORM = (t) => String(t || '').replace(/[ً-ٟـ]/g, '').replace(/[أإآٱ]/g, 'ا').replace(/ى/g, 'ي');
const SPEECH_STEMS = ['قال', 'رد', 'همس', 'صرخ', 'صاح', 'سال', 'اجاب', 'تمتم', 'هتف', 'اضاف', 'تابع', 'زمجر', 'تنهد', 'ضحك', 'بكي', 'نادي', 'اعترض', 'اكد', 'قاطع', 'هدر', 'تافف', 'تساءل', 'اعترف', 'اردف', 'تحدث', 'توسل', 'استنكر', 'تذمر', 'تلعثم', 'شهق', 'ابتسم', 'لعن', 'امر', 'اقترح', 'عقب', 'علق', 'فسر', 'شرح', 'حذر', 'ردد', 'كرر', 'غمغم', 'تمتمت', 'زعق', 'عاتب', 'رجا', 'قرر', 'سخر', 'همهم', 'اجابه', 'اجابها'];
const SP_M = [...new Set(SPEECH_STEMS)].filter((x) => x !== 'تمتمت'), SP_F = SP_M.map((x) => (/ي$/.test(x) ? x.slice(0, -1) : x) + 'ت');
const reSpM = new RegExp('(?:^|[\\s،,.:؛"«»\\-])[وف]?(?:' + SP_M.join('|') + ')(?:ه|ها|لها|له|لهم)?(?=[\\s،,.:؛"«»!؟?\\-]|$)');
const reSpF = new RegExp('(?:^|[\\s،,.:؛"«»\\-])[وف]?(?:' + SP_F.join('|') + ')(?:ه|ها|لها|له|لهم)?(?=[\\s،,.:؛"«»!؟?\\-]|$)');
const reKidG = /(?:^|[\s،,.:؛])(?:ال)?(?:طفلة|صغيرة|بنت صغيرة|فتاة صغيرة|البنت الصغيرة|الفتاة الصغيرة|طفلتي|طفلتها|بنتها الصغيرة)(?=[\s،,.:؛]|$)/;
const reKidB = /(?:^|[\s،,.:؛])(?:ال)?(?:طفل|صغير|ولد صغير|صبي|غلام|الولد الصغير|طفلي|طفلها)(?=[\s،,.:؛]|$)/;
function guessSpeaker(after, before) {
  const bf = /[:：]\s*$/.test(before || ''); // «قال أحمد: «...»» → المتكلم اللي قبل النقطتين
  for (const ctx of (bf ? [before, after] : [after, before])) {
    if (!ctx) continue;
    const n = AR_NORM(ctx), f = reSpF.test(n), m = reSpM.test(n);
    const kg = reKidG.test(n), kb = reKidB.test(n);
    if (kg || kb) { const g = kg && !kb ? 'girl' : (kb && !kg ? 'boy' : (f && !m ? 'girl' : 'boy')); return g; }
    if (f && !m) return 'woman';
    if (m && !f) return 'man';
    if (f && m) { const fi = n.search(reSpF), mi = n.search(reSpM); return fi <= mi ? 'woman' : 'man'; }
  }
  return null;
}
const OPP = { man: 'woman', woman: 'man', boy: 'man', girl: 'woman' };
// بيرجّع [{role, text}] (النص من غير علامات التنصيص والشرطات). بدون حوار = راوي واحد.
function segmentRoles(text) {
  const items = []; // {dlg:boolean, t, line, ls, a, b}
  const lines = String(text).split('\n');
  const lineMeta = [];
  lines.forEach((line, li) => {
    if (!line.trim()) return;
    const segs = [];
    const dash = /^(\s*)[-–—]+\s*/.exec(line);
    if (dash) {
      const rest = line.slice(dash[0].length); let pos = dash[0].length;
      const pieces = rest.split(/\s[-–—]+\s/); let isD = true;
      for (const pc of pieces) {
        if (isD) {
          const m = /([.!؟?…،])\s*((?:[وف]?(?:قال|رد|همس|صرخ|صاح|سال|اجاب|تمتم|هتف|اضاف|تابع|زمجر|تنهد|ضحك|بكى|نادى|اعترض|أكد|قاطع|هدر|تأفف|تساءل|اعترف|أردف|سأل|أجاب|أضاف)(?:ت)?)(?:\s|$).*)$/.exec(pc);
          if (m && AR_NORM(m[2]).length) { const cut = pc.length - m[2].length; segs.push({ d: true, a: pos, b: pos + cut }); segs.push({ d: false, a: pos + cut, b: pos + pc.length }); }
          else segs.push({ d: true, a: pos, b: pos + pc.length });
        } else segs.push({ d: false, a: pos, b: pos + pc.length });
        pos += pc.length + 0; const sepM = /^\s[-–—]+\s/.exec(rest.slice(pos - dash[0].length)); if (sepM) { segs.push({ d: false, a: pos, b: pos + sepM[0].length, sep: true }); pos += sepM[0].length; }
        isD = !isD;
      }
    } else {
      const re = /«([^»]+)»|"([^"]+)"|“([^”]+)”/g; let m, last = 0;
      while ((m = re.exec(line))) {
        const inner = m[1] || m[2] || m[3] || '';
        if (inner.trim().split(/\s+/).length < 2) continue;
        if (m.index > last) segs.push({ d: false, a: last, b: m.index });
        segs.push({ d: true, a: m.index + 1, b: m.index + m[0].length - 1 }); last = m.index + m[0].length;
      }
      if (last < line.length) segs.push({ d: false, a: last, b: line.length });
    }
    lineMeta.push({ line, segs, onlyD: segs.filter((s) => s.d).length > 0 && segs.every((s) => s.d || !/[؀-ۿA-Za-z0-9]/.test(line.slice(s.a, s.b))) });
  });
  const out = []; let hist = [], prevOnlyD = false;
  const push = (role, t) => { t = t.replace(/[«»"“”]/g, ' ').replace(/^[\s،,:؛]+/, '').replace(/^\s*[-–—]+\s*/, '').replace(/\s+/g, ' ').trim(); if (!/[؀-ۿA-Za-z0-9]/.test(t)) return; const l = out[out.length - 1]; if (l && l.role === role) l.text += ' ' + t; else out.push({ role, text: t }); };
  for (const lm of lineMeta) {
    const { line, segs } = lm;
    segs.forEach((sg, si) => {
      const t = line.slice(sg.a, sg.b);
      if (!sg.d) { if (!sg.sep) push('narrator', t); return; }
      const next = segs.slice(si + 1).find((x) => !x.d && !x.sep), prev = [...segs.slice(0, si)].reverse().find((x) => !x.d && !x.sep);
      let after = next ? line.slice(next.a, Math.min(next.b, next.a + 70)) : '', before = prev ? line.slice(Math.max(prev.a, prev.b - 70), prev.b) : '';
      after = after.replace(/[«»"“”].*$/, ''); before = before.replace(/^.*[«»"“”]/, '');
      let role = guessSpeaker(after.slice(0, 45), before);
      if (!role) {
        const last = hist[hist.length - 1];
        if (!last) role = 'man';
        else if (prevOnlyD || si > 0 && segs[si - 1] && segs[si - 1].d) role = hist.length > 1 && hist[hist.length - 2] !== last ? hist[hist.length - 2] : OPP[last];
        else role = last;
      }
      if (hist[hist.length - 1] !== role) hist.push(role); if (hist.length > 4) hist.shift();
      push(role, t);
    });
    prevOnlyD = lm.onlyD;
  }
  if (!out.length) { const t = String(text).replace(/[«»"“”]/g, ' ').replace(/\s+/g, ' ').trim(); if (t) out.push({ role: 'narrator', text: t }); }
  return out;
}
const stripMarks = (t) => String(t).replace(/[«»"“”]/g, ' ').replace(/^\s*[-–—]+\s*/gm, '').replace(/\s+/g, ' ').trim();
function wavPcm(b) { // يرجّع بيانات الصوت (PCM) من ملف WAV
  for (let i = 12; i + 8 <= b.length;) { const id = String.fromCharCode(b[i], b[i + 1], b[i + 2], b[i + 3]), sz = b[i + 4] | (b[i + 5] << 8) | (b[i + 6] << 16) | (b[i + 7] << 24); if (id === 'data') return b.subarray(i + 8, sz > 0 && i + 8 + sz <= b.length ? i + 8 + sz : b.length); i += 8 + sz + (sz & 1); }
  return b.subarray(44);
}
function joinWavs(list) {
  if (list.length === 1) return list[0];
  const gap = new Uint8Array(Math.round(24000 * 0.22) * 2), pcms = []; list.forEach((w, i) => { if (i) pcms.push(gap); pcms.push(wavPcm(w)); });
  let n = 0; pcms.forEach((p) => (n += p.length)); const all = new Uint8Array(n); let o = 0; pcms.forEach((p) => { all.set(p, o); o += p.length; }); return pcmToWav(all, 24000);
}
const ROLE_EN = { narrator: 'the narrator', man: 'an adult man', woman: 'an adult woman', boy: 'a young boy', girl: 'a young girl' };
const DIA_N = 'narrating in clear Modern Standard Arabic (Fusha) with correct grammar and pronunciation, never colloquial';
const DIA_C = 'speaking in 100% natural Egyptian colloquial Arabic (Cairene, hard "g" for jim), never Fusha';
const roleStyle = (conf, role, emo) => (role === 'narrator' ? 'warm, expressive audiobook voice ' + DIA_N : 'warm, expressive audiobook acting, ' + DIA_C + ', performing the character of ' + ROLE_EN[role] + (role === 'boy' || role === 'girl' ? ' with a childlike voice' : '')) + (emo ? ', acting it out: ' + emo : '');
async function geminiMulti(env, roleA, roleB, items, conf) { // سطرين متكلمين في طلب واحد
  const key = env.GEMINI_API_KEY, nm = { narrator: 'Narrator', man: 'Man', woman: 'Woman', boy: 'Boy', girl: 'Girl' };
  const prompt = 'Perform this audiobook scene like a gifted voice actor. STRICT DIALECT RULE: the Narrator reads in clear Modern Standard Arabic (Fusha); every character speaks 100% natural Egyptian colloquial Arabic (Cairene). Truly living the moment and reacting to what is happening (never robotic). Each line may carry a bracketed emotion/delivery direction after the speaker name: act it with that exact feeling and do NOT read the brackets aloud. ' + [roleA, roleB].filter((r) => r !== 'narrator').map((r) => nm[r] + ' is ' + ROLE_EN[r] + (r === 'boy' || r === 'girl' ? ' (use a childlike voice)' : '') + '.').join(' ') + '\n' + items.map((it) => nm[it.role] + (it.emo ? ' [' + it.emo + ']' : '') + ': ' + it.text).join('\n');
  const r = await gFetch(env, 'https://generativelanguage.googleapis.com/v1beta/models/' + conf.legacyModel + ':generateContent', { method: 'POST', signal: AbortSignal.timeout(100000), headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { responseModalities: ['AUDIO'], speechConfig: { multiSpeakerVoiceConfig: { speakerVoiceConfigs: [roleA, roleB].map((ro) => ({ speaker: nm[ro], voiceConfig: { prebuiltVoiceConfig: { voiceName: conf.gv[ro] } } })) } } } }) });
  if (r.status === 429) { const e = new Error('busy'); e.code = 429; e.detail = await q429(r); throw e; }
  if (!r.ok) { const e = new Error('gemini_' + r.status); e.code = 502; throw e; }
  const b = findAudioB64(await r.json()); if (!b) { const e = new Error('no_audio'); e.code = 502; throw e; }
  return toWav(b);
}
/* ---- تمييز المتكلم بذكاء: نموذج جوجل النصي بيقرا الفقرة (ومعاها اللي قبلها) ويحدد لكل جزء مين بيتكلم: راجل / ست / ولد / بنت ---- */
const ROLE_ENUM = ['narrator', 'man', 'woman', 'boy', 'girl'];
async function smartRoles(env, text, conf, ctx) {
  const base = segmentRoles(text), key = env.GEMINI_API_KEY;
  if (!conf.smart || !key) return base;
  try {
    const list = base.map((r, i) => '[' + i + '] ' + r.text).join('\n');
    const prompt = 'You are preparing an Arabic (Egyptian) novel for an audiobook with different voices. Below is the text before the excerpt (context only), then the excerpt split into numbered segments in order. '
      + 'For EACH numbered segment return who speaks it: "narrator" for narration/description (not spoken by a character), or "man", "woman", "boy", "girl" for a character\'s spoken words. '
      + 'Decide the speaker\'s gender from the clues: names, pronouns, verb forms (قال/قالت, رد/ردت), words like هي/هو/أمه/أبوه/زوجته/زوجها, who is being addressed, and the flow of the conversation (people usually alternate). '
      + 'Keep each character consistent across the excerpt and the context. A speech tag like "قالت سلمى" belongs to narrator but tells you the speaker of the neighbouring spoken segment. Use boy/girl only for clearly young children. '
      + 'ALSO act like a director: for EACH segment give "e", a SHORT English performance direction (max 8 words) describing how the speaker feels and sounds right now, taken from the scene and from descriptions such as "قال بغضب", "قالت وهي تبكي", "همس", "صرخ", "ابتسم" (e.g. "furious, shouting through clenched teeth", "trembling, on the verge of tears", "soft, tender whisper", "tense suspenseful narration"). Use "" only if truly neutral. '
      + 'Return ONLY a JSON array of exactly ' + base.length + ' objects {"r":role,"e":direction}, one per segment, in order.\n\nCONTEXT (before):\n' + String(ctx || '').slice(-600) + '\n\nEXCERPT:\n' + list;
    const r = await gFetch(env, 'https://generativelanguage.googleapis.com/v1beta/models/' + conf.annModel + ':generateContent', { method: 'POST', signal: AbortSignal.timeout(9000), headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0, thinkingConfig: { thinkingBudget: 0 }, responseMimeType: 'application/json', responseSchema: { type: 'ARRAY', items: { type: 'OBJECT', properties: { r: { type: 'STRING', enum: ROLE_ENUM }, e: { type: 'STRING' } }, required: ['r', 'e'] } } } }) });
    if (!r.ok) return base;
    const j = await r.json(), t = (((j.candidates || [])[0] || {}).content || {}).parts; const arr = JSON.parse((t || []).map((x) => x.text || '').join(''));
    if (!Array.isArray(arr) || arr.length !== base.length || !arr.every((x) => x && ROLE_ENUM.includes(x.r))) return base;
    const out = []; base.forEach((b, i) => { const role = base[i].role === 'narrator' ? 'narrator' : (arr[i].r === 'narrator' ? base[i].role : arr[i].r); const emo = String(arr[i].e || '').replace(/[\[\]\n]/g, ' ').trim().slice(0, 80); const l = out[out.length - 1]; if (l && l.role === role) { l.text += ' ' + b.text; if (!l.emo) l.emo = emo; } else out.push({ role, text: b.text, emo }); });
    return out;
  } catch (e) { return base; }
}
function applyDict(runs, conf) { // قاموس النطق: كلمة=كلمة بالتشكيل
  const pairs = String(conf.dict || '').split('\n').map((l) => { const k = l.indexOf('='); return k > 0 ? [l.slice(0, k).trim(), l.slice(k + 1).trim()] : null; }).filter((x) => x && x[0] && x[1]).sort((a, b) => b[0].length - a[0].length);
  if (!pairs.length) return runs;
  // الاستبدال بالكلمة الكاملة (مش جزء من كلمة تانية)، ومسموح حرف سابق (و/ف/ب/ل/ك) للكلمات الطويلة
  const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), L = '\\p{L}\\p{M}';
  const rx = pairs.map(([a, b]) => [new RegExp('(?<![' + L + '])([وفبلك]?)(' + esc(a) + ')(?![' + L + '])', 'gu'), a, b]);
  return runs.map((r) => { let t = r.text; for (const [re, a, b] of rx) t = t.replace(re, (m, p) => (p && a.length < 4 && p !== 'و' && p !== 'ف' ? m : p + b)); return { role: r.role, text: t, emo: r.emo }; });
}
// تقليل عدد الطلبات لجوجل (حدّها في الدقيقة قليل): الأجزاء القصيرة تتدمج في اللي جنبها، وبحد أقصى 4 طلبات للجزء
// لما بندمج أجزاء بانفعالات مختلفة منحافظش على الانفعال بتاع كل جزء جوه النص نفسه: [بغضب] كلام... [بهمس] كلام...
const cueTxt = (r) => (r.emo ? '[' + r.emo + '] ' : '') + r.text;
const joinCue = (a, b) => ((a.emo || a.tg || b.emo || b.tg) ? { text: (a.tg ? a.text : cueTxt(a)) + ' ' + (b.tg ? b.text : cueTxt(b)), emo: '', tg: true } : { text: a.text + ' ' + b.text, emo: '', tg: false });
function mergeRuns(runs, maxCalls, minLen = 45) {
  const out = runs.map((r) => ({ role: r.role, text: r.text, emo: r.emo }));
  const fold = () => { for (let k = out.length - 1; k > 0; k--) if (out[k].role === out[k - 1].role) { const j = joinCue(out[k - 1], out[k]); out[k - 1] = { role: out[k].role, text: j.text, emo: j.emo, tg: j.tg }; out.splice(k, 1); } };
  fold();
  for (;;) {
    let idx = -1, best = 1e9;
    out.forEach((r, i) => { const need = out.length > maxCalls ? 1e9 : minLen; if (r.text.length < best && (out.length > maxCalls || r.text.length < need) && out.length > 1) { best = r.text.length; idx = i; } });
    if (idx < 0) break;
    const r = out[idx], nb = idx === 0 ? 1 : (idx === out.length - 1 ? idx - 1 : (r.role === 'narrator' ? (out[idx - 1].role !== 'narrator' ? idx - 1 : idx + 1) : (out[idx - 1].text.length <= out[idx + 1].text.length ? idx - 1 : idx + 1)));
    // الدور الأطول هو اللي بيفضل
    const keep = out[nb].text.length >= r.text.length ? nb : idx; const other = keep === nb ? idx : nb;
    const first = Math.min(idx, nb), second = Math.max(idx, nb);
    const jc = joinCue(out[first], out[second]), role = out[keep].role;
    out.splice(second, 1); out[first] = { role, text: jc.text, emo: jc.emo, tg: jc.tg }; fold();
    if (out.length <= 1) break;
  }
  return out;
}

/* ---------- تشكيل الحوار بالنطق المصري (منقول من أداة الرداد): بيتطبّق على كلام الشخصيات بس، والسرد فصحى ---------- */
const EGYPTIAN_IDIOMS_BANK = {
  // مصطلحات الشهامة والجدعنة والوعود المصرية
  'رقبتي سدادة': 'رَقَبْتِي سَدَّادَه',
  'رقبتي سدّادة': 'رَقَبْتِي سَدَّادَه',
  'رقبتى سدادة': 'رَقَبْتِي سَدَّادَه',
  'رقبتي سداده': 'رَقَبْتِي سَدَّادَه',
  'على عيني وراسي': 'عَلَى عِينِي وَرَاسِي',
  'على عيني وعلى راسي': 'عَلَى عِينِي وَعَلَى رَاسِي',
  'من عينيا الجوز': 'مِنْ عِينَيَّا الجُوز',
  'من عينيا الاتنين': 'مِنْ عِينَيَّا الإِتْنِين',
  'من عينيا': 'مِنْ عِينَيَّا',
  'عيني ليك': 'عِينِي لِيك',
  'عينيا ليك': 'عِينَيَّا لِيك',
  'تحت أمرك': 'تَحْتَ أَمْرَك',
  'أمرك يا باشا': 'أَمْرَك يَا بَاشَا',
  'حقك عليا': 'حَقَّك عَلَيَّا',
  'حقك عليّ': 'حَقَّك عَلَيَّا',
  'حقي برقبتي': 'حَقِّي بِرَقَبْتِي',
  'على جثتي': 'عَلَى جُثِّتِي',
  'وشي في وشك': 'وِشِّي فِي وِشَّك',
  'إيدك معايا': 'إِيدَك مَعَايَا',
  'ايدك معايا': 'إِيدَك مَعَايَا',
  'إيد على إيد': 'إِيد عَلَى إِيد',
  'جدع وابن بلد': 'جَدَع وِابْنِ بَلَد',
  'ابن حلال': 'إِبْنِ حَلَال',
  'بنت حلال': 'بِنْتِ حَلَال',
  'ابن أصول': 'إِبْنِ أُصُول',
  'كتر خيرك': 'كَتَّر خِيرَك',
  'كثر خيرك': 'كَتَّر خِيرَك',
  'ربنا يخليك': 'رَبِّنَا يِخَلِّيك',
  'الله يخليك': 'اللَّاه يِخَلِّيك',
  'ربنا يكرمك': 'رَبِّنَا يِكْرِمَك',
  'ربنا يستر': 'رَبِّنَا يُسْتُر',
  'فداك الدنيا': 'فِدَاك الدُّنْيَا',
  'ولا يهمك': 'وَلَا يِهِمَّك',
  'حط في بطنك بطيخة صيفي': 'حُطّ فِي بَطْنَك بَطِّيخَه صِيفِي',

  // مصطلحات الغضب والانفعال والضيق المصرية
  'دمي محروق': 'دَمِّي مَحْرُوق',
  'دمي فار': 'دَمِّي فَار',
  'دمي بيغلي': 'دَمِّي بِيِغْلِي',
  'حرقت دمي': 'حَرَقْتِ دَمِّي',
  'مش طايق نفسي': 'مِش طَايِق نَفْسِي',
  'مش طايق كلمة': 'مِش طَايِق كِلْمَه',
  'جبت آخري': 'جِبْت آخْرِي',
  'أنا جبت آخري': 'أَنَا جِبْت آخْرِي',
  'فاض بيا': 'فَاض بِيَّا',
  'طفح الكيل': 'طَفَح الكِيل',
  'طلع عيني': 'طَلَّع عِينِي',
  'طلعت عيني': 'طِلْعِت عِينِي',
  'نشف ريقي': 'نَشَّف رِيقِي',
  'نشفت ريقي': 'نَشِّفْتِ رِيقِي',
  'وجع دماغ': 'وَجَع دِمَاغ',
  'وجع قلب': 'وَجَع قَلْب',
  'مليش نفس': 'مَالِيش نِفْس',
  'ماليش نفس': 'مَالِيش نِفْس',
  'نفسي مسدودة': 'نِفْسِي مَسْدُودَه',
  'نفسي مقفولة': 'نِفْسِي مَقْفُولَه',
  'طلع نفسي': 'طِلِع نَفَسِي',
  'واخد على خاطره': 'وَاخِد عَلَى خَاطْرُه',
  'واخدة على خاطرها': 'وَاخْدَه عَلَى خَاطِرْهَا',
  'شايل في قلبي': 'شَايِل فِي قَلْبِي',
  'صعبان عليا': 'صَعْبَان عَلَيَّا',
  'حاجة تقرف': 'حَاجَه تِقْرِف',
  'حاجة تحزن': 'حَاجَه تِحَزِّن',
  'يا نهار اسود': 'يَا نَهَار إِسْوِد',
  'يا نهار أسود': 'يَا نَهَار إِسْوِد',
  'يا نهار أبيض': 'يَا نَهَار أَبْيَض',
  'يا خبر أبيض': 'يَا خَبَر أَبْيَض',
  'يا خبر اسود': 'يَا خَبَر إِسْوِد',
  'يا ساتر يا رب': 'يَا سَاتِر يَا رَبّ',
  'يا مصيبتي': 'يَا مُصِيبْتِي',
  'يا دهوتي': 'يَا دَهْوِتِي',
  'يا خرابي': 'يَا خَرَابِي',
  'يا حلاوة': 'يَا حَلَاوَه',
  'يا سلام': 'يَا سَلَام',

  // مصطلحات الحياة اليومية والحوارات الروائية المصرية
  'طول بالك': 'طَوِّل بَالَك',
  'طولي بالك': 'طَوِّلِي بَالِك',
  'هدي أعصابك': 'هَدِّي أَعْصَابَك',
  'متشغلش بالك': 'مَتِشْغِلْش بَالَك',
  'خلي بالك من نفسك': 'خَلِّي بَالَك مِن نَفْسَك',
  'خلي بالك': 'خَلِّي بَالَك',
  'خد بالك': 'خُد بَالَك',
  'عشرة عمر': 'عِشْرِة عُمْر',
  'عيش وملح': 'عِيش وَمَلْح',
  'حمالة الأسية': 'حَمَّالِة الأَسِيَّه',
  'اللي فات مات': 'اللِّي فَات مَات',
  'على قد الإيد': 'عَلَى قَدّ الإِيد',
  'على قدي': 'عَلَى قَدِّي',
  'على قدك': 'عَلَى قَدَّك',
  'على قد حاله': 'عَلَى قَدّ حَالُه',
  'ملوش لازمة': 'مَلُوش لَازْمَه',
  'ملهاش لازمة': 'مَلْهَاش لَازْمَه',
  'مفيش فايدة': 'مَفِيش فَايْدَه',
  'كلام في سرك': 'كَلَام فِي سِرَّك',
  'بيني وبينك': 'بِينِي وَبِينَك',
  'من الآخر': 'مِن الآخِر',
  'من غير ما تقول': 'مِن غِير مَا تْقُول',
  'من غير ليه': 'مِن غِير لِيه',
  'زي الفل': 'زَيّ الفُلّ',
  'صباح الفل': 'صَبَاح الفُلّ',
  'مساء الفل': 'مَسَاء الفُلّ',
  'بيضحك عليا': 'بِيِضْحَك عَلَيَّا',
  'بتضحك عليا': 'بِتِضْحَك عَلَيَّا',
  'ما علينا': 'مَا عَلِينَا',
  'ماعلينا': 'مَا عَلِينَا',
  'يا ريت': 'يَا رِيت',
  'ياريت': 'يَا رِيت',
  'والله العظيم': 'وَاللَّاهِي العَظِيم',
  'والله ما كان': 'وَاللَّاهِي مَا كَان',
  'غصب عني': 'غَصْبٍ عَنِّي',
  'أنت إزاي': 'إِنْتَ إِزَّاي',
  'انت ازاي': 'إِنْتَ إِزَّاي',
  'تعمل فيا كدا': 'تِعْمِل فِيَّا كِدَه',
  'تعمل فيا كده': 'تِعْمِل فِيَّا كِدَه',
  'ده أنا': 'دَه أَنَا',
  'دا انا': 'دَه أَنَا',
  'خايف أوي': 'خَايِف أَوِي',
  'خايف قوي': 'خَايِف أَوِي',
  'عايز نمشي': 'عَايِز نِمْشِي',
  'طول ما أنا': 'طُول مَا أَنَا',
  'على فكرة': 'عَلَى فِكْرَه',
  'في إيه': 'فِيه إِيه',
  'عشان كده': 'عَشَان كِدَه',
  'بعد إذنك': 'بَعْد إِذْنَك',
  'يا ترى': 'يَا تَرَى'
};
const EGYPTIAN_PHONETIC_LEXICON = {
  // كلمات على وزن فَعَّال / فَعَّالَه وتفادي خلطها بـ فِعَالة الفصيحة
  'سدادة': 'سَدَّادَه',
  'سدّادة': 'سَدَّادَه',
  'سداده': 'سَدَّادَه',
  'سداد': 'سَدَّاد',
  'شغالة': 'شَغَّالَه',
  'شغاله': 'شَغَّالَه',
  'شغال': 'شَغَّال',
  'شغالين': 'شَغَّالِين',
  'كدابة': 'كَدَّابَه',
  'كذابة': 'كَذَّابَه',
  'كداب': 'كَدَّاب',
  'كذاب': 'كَذَّاب',
  'غلابة': 'غَلَّابَه',
  'غلبان': 'غَلْبَان',
  'غلبانة': 'غَلْبَانَه',
  'رجالة': 'رِجَّالَه',
  'رجاله': 'رِجَّالَه',
  'حمالة': 'حَمَّالَه',
  'حلال': 'حَلَّال',
  'سراق': 'سَرَّاق',
  'سراقة': 'سَرَّاقَه',
  'فهامة': 'فَهَّامَه',
  'علامة': 'عَلَّامَه',
  'بزيادة': 'بِزْيَادَه',
  'زيادة': 'زِيَادَه',

  // الكلمات المضافة إلى ياء المتكلم أو الكاف في المصرية (تسكين الحرف الأوسط بدلاً من فتحه بالفصحى)
  'رقبتي': 'رَقَبْتِي',
  'رقبتك': 'رَقَبْتَك',
  'رقبته': 'رَقَبْتُه',
  'رقبتها': 'رَقَبْتَهَا',
  'رقبتنا': 'رَقَبْتِنَا',
  'كلمتي': 'كِلْمِتِي',
  'كلمتك': 'كِلْمِتَك',
  'كلمته': 'كِلْمِتُه',
  'كلمة': 'كِلْمَه',
  'حركتي': 'حَرَكْتِي',
  'حركتك': 'حَرَكْتَك',
  'حكايتي': 'حِكَايْتِي',
  'حكايتك': 'حِكَايْتَك',
  'حكاية': 'حِكَايَه',
  'مصلحتي': 'مَصْلَحْتِي',
  'مصلحتك': 'مَصْلَحْتَك',
  'مصلحة': 'مَصْلَحَه',
  'صاحبتي': 'صَاحْبِتِي',
  'صاحبي': 'صَاحْبِي',
  'صحاب': 'صْحَاب',
  'صحابي': 'صْحَابِي',
  'مراتي': 'مِرَاتِي',
  'مراتك': 'مِرَاتَك',
  'مراته': 'مِرَاتُه',
  'ولادي': 'وِلَادِي',
  'عيالي': 'عِيَالِي',
  'عيلتي': 'عِيلْتِي',
  'بلدي': 'بَلَدِي',
  'ساعتها': 'سَاعِتْهَا',
  'وقتها': 'وَقْتَهَا',
  'لوحدي': 'لِوَحْدِي',
  'لوحدك': 'لِوَحْدَك',
  'لوحده': 'لِوَحْدُه',
  'لوحدها': 'لِوَحْدَهَا',

  // أعضاء الجسم والمشاعر بالنطق المصري (مع تشديد الميم والشين والقاف)
  'دمي': 'دَمِّي',
  'دمك': 'دَمَّك',
  'دمه': 'دَمُّه',
  'دمها': 'دَمَّهَا',
  'دم': 'دَمّ',
  'همي': 'هَمِّي',
  'همك': 'هَمَّك',
  'هموم': 'هُمُوم',
  'وشي': 'وِشِّي',
  'وشك': 'وِشَّك',
  'وشه': 'وِشُّه',
  'وشها': 'وِشَّهَا',
  'وش': 'وِشّ',
  'حقي': 'حَقِّي',
  'حقك': 'حَقَّك',
  'حقه': 'حَقُّه',
  'حقها': 'حَقَّهَا',
  'حق': 'حَقّ',
  'إيدي': 'إِيدِي',
  'ايدي': 'إِيدِي',
  'إيدك': 'إِيدَك',
  'ايدك': 'إِيدَك',
  'إيده': 'إِيدُه',
  'إيد': 'إِيد',
  'عيني': 'عِينِي',
  'عينيا': 'عِينَيَّا',
  'عينيك': 'عِينِيك',
  'عين': 'عِين',
  'رجلي': 'رِجْلِي',
  'رجلك': 'رِجْلَك',
  'ضهري': 'ضَهْرِي',
  'ظهرك': 'ضَهْرَك',
  'ضهرك': 'ضَهْرَك',
  'قلبي': 'قَلْبِي',
  'قلبك': 'قَلْبَك',
  'قلبه': 'قَلْبُه',
  'روحي': 'رُوحِي',
  'روحك': 'رُوحَك',
  'عقلي': 'عَقْلِي',
  'عقلك': 'عَقْلَك',
  'بالي': 'بَالِي',
  'بالك': 'بَالَك',
  'حالي': 'حَالِي',
  'حالك': 'حَالَك',
  'مخي': 'مُخِّي',
  'مخك': 'مُخَّك',
  'ريقي': 'رِيقِي',
  'حسي': 'حِسِّي',
  'حسك': 'حِسَّك',
  'صوتي': 'صُوتِي',
  'صوتك': 'صُوتَك',
  'صوت': 'صُوت',
  'يوم': 'يُوم',
  'نوم': 'نُوم',
  'خوف': 'خُوف',
  'موت': 'مُوت',
  'بيت': 'بِيت',
  'بيتي': 'بِيتِي',
  'بيتك': 'بِيتَك',
  'ليل': 'لِيل',
  'ليلة': 'لِيلَه',
  'عيب': 'عِيب',
  'غير': 'غِير',
  'غيري': 'غِيرِي',
  'غيرك': 'غِيرَك',
  'خير': 'خِير',
  'خيره': 'خِيرُه',
  'طير': 'طِير',
  'سيف': 'سِيف',
  'ضيف': 'ضِيف',
  'صيف': 'صِيف',
  'زيت': 'زِيت',

  // الضمائر وأسماء الإشارة المصرية
  'أنت': 'إِنْتَ',
  'انت': 'إِنْتَ',
  'أنتي': 'إِنْتِي',
  'انتي': 'إِنْتِي',
  'أنتم': 'إِنْتُو',
  'انتو': 'إِنْتُو',
  'أنتوا': 'إِنْتُو',
  'أنا': 'أَنَا',
  'انا': 'أَنَا',
  'إحنا': 'إِحْنَا',
  'احنا': 'إِحْنَا',
  'هما': 'هُمَّا',
  'هم': 'هُمَّا',
  'هي': 'هِيَّ',
  'هو': 'هُوَّ',
  'ده': 'دَه',
  'دا': 'دَه',
  'دي': 'دِي',
  'دول': 'دُول',
  'كدا': 'كِدَه',
  'كده': 'كِدَه',
  'كدة': 'كِدَه',
  'أهو': 'أَهُو',
  'أهي': 'أَهِي',

  // أدوات الاستفهام والروابط المصرية
  'إزاي': 'إِزَّاي',
  'ازاي': 'إِزَّاي',
  'إيه': 'إِيه',
  'ايه': 'إِيه',
  'ليه': 'لِيه',
  'فين': 'فِين',
  'إمتى': 'إِمْتَى',
  'امتى': 'إِمْتَى',
  'مين': 'مِين',
  'كام': 'كَام',
  'عشان': 'عَشَان',
  'علشان': 'عَلَشَان',
  'دلوقتي': 'دِلْوَقْتِي',
  'لسه': 'لِسَّه',
  'لسة': 'لِسَّه',
  'بقى': 'بَقَى',
  'بقا': 'بَقَى',
  'طيب': 'طَيِّب',
  'طب': 'طَب',
  'خلاص': 'خَلَاص',
  'كفاية': 'كِفَايَه',
  'تاني': 'تَانِي',
  'تانية': 'تَانْيَه',
  'برضو': 'بَرْضُو',
  'برضه': 'بَرْضُو',
  'يعني': 'يَعْنِي',
  'أصل': 'أَصْل',
  'أصلا': 'أَصْلًا',
  'أصلاً': 'أَصْلًا',
  'بس': 'بَسّ',
  'يلا': 'يَلَّا',
  'يا': 'يَا',
  'لما': 'لَمَّا',
  'لو': 'لَو',
  'إنك': 'إِنَّك',
  'انك': 'إِنَّك',
  'إني': 'إِنِّي',
  'اني': 'إِنِّي',
  'إنه': 'إِنُّه',
  'إنها': 'إِنَّهَا',
  'اللي': 'اللِّي',
  'اللى': 'اللِّي',

  // حروف الجر والظروف المدمجة بالضمائر (السبب الأول لخطأ النطق في وسط الجمل)
  'فيا': 'فِيَّا',
  'فيّ': 'فِيَّا',
  'فيك': 'فِيك',
  'فيكي': 'فِيكِي',
  'فيهم': 'فِيهُم',
  'فينا': 'فِينَا',
  'عليا': 'عَلَيَّا',
  'عليّ': 'عَلَيَّا',
  'عليك': 'عَلِيك',
  'عليكي': 'عَلِيكِي',
  'عليهم': 'عَلِيهُم',
  'علينا': 'عَلِينَا',
  'ليا': 'لِيَّا',
  'ليك': 'لِيك',
  'ليكي': 'لِيكِي',
  'ليهم': 'لِيهُم',
  'لينا': 'لِينَا',
  'بيا': 'بِيَّا',
  'بيك': 'بِيك',
  'معايا': 'مَعَايَا',
  'معاك': 'مَعَاك',
  'معاكي': 'مَعَاكِي',
  'معاهم': 'مَعَاهُم',
  'معانا': 'مَعَانَا',
  'مني': 'مِنِّي',
  'منك': 'مِنّك',
  'منه': 'مِنُّه',
  'منها': 'مِنْهَا',
  'منهم': 'مِنْهُم',
  'عني': 'عَنِّي',
  'عنك': 'عَنَّك',
  'عنه': 'عَنُّه',
  'عنها': 'عَنْهَا',
  'فوق': 'فُوق',
  'تحت': 'تَحْت',
  'جوه': 'جُوَّه',
  'جوا': 'جُوَّه',
  'بره': 'بَرَّه',
  'برا': 'بَرَّه',
  'ورا': 'وَرَا',
  'قدام': 'قُدَّام',
  'جمبك': 'جَنْبَك',
  'جنبك': 'جَنْبَك',
  'جمبي': 'جَنْبِي',
  'جنبي': 'جَنْبِي',
  'عشانكم': 'عَشَانْكُم',
  'عشانك': 'عَشَانَك',
  'عشاني': 'عَشَانِي',
  'علشانكم': 'عَلَشَانْكُم',
  'هنا': 'هِنَا',
  'هناك': 'هِنَاك',

  // النفي المصري المركب
  'مش': 'مِش',
  'مفيش': 'مَفِيش',
  'مافيش': 'مَفِيش',
  'مليش': 'مَالِيش',
  'ماليش': 'مَالِيش',
  'ملناش': 'مَالْنَاش',
  'محدش': 'مَحَدِّش',
  'ماحدش': 'مَحَدِّش',
  'مكنش': 'مَكَانْش',
  'ماكانش': 'مَكَانْش',
  'مبقاش': 'مَبَقَاش',
  'مقدرش': 'مَقْدَرْش',
  'ماعرفش': 'مَعْرَفْش',
  'معرفش': 'مَعْرَفْش',
  'مشفش': 'مَشَافْش',
  'مقلش': 'مَقَالْش',
  'متخافش': 'مَتْخَافْش',
  'متخافيش': 'مَتْخَافِيش',
  'متقولش': 'مَتْقُولْش',
  'متزعلش': 'مَتِزْعَلْش',
  'ملوش': 'مَلُوش',
  'ملهاش': 'مَلْهَاش',
  'منفعش': 'مَيْنْفَعْش',
  'مينفعش': 'مَيْنْفَعْش',

  // الأفعال المصرية المتكررة (كسر حرف المضارعة وضبط البنية الداخلية)
  'تعمل': 'تِعْمِل',
  'يعمل': 'يِعْمِل',
  'بعمل': 'بَعْمِل',
  'نعمل': 'نِعْمِل',
  'بتعمل': 'بِتِعْمِل',
  'بيعمل': 'بِيِعْمِل',
  'عملت': 'عَمَلْت',
  'تقول': 'تْقُول',
  'يقول': 'يْقُول',
  'بتقول': 'بِتْقُول',
  'بيقول': 'بِيْقُول',
  'قلت': 'قُلْت',
  'قالت': 'قَالِت',
  'قال': 'قَال',
  'تعرف': 'تِعْرَف',
  'يعرف': 'يِعْرَف',
  'بتعرف': 'بِتِعْرَف',
  'بيعرف': 'بِيِعْرَف',
  'عرفت': 'عِرِفْت',
  'عارف': 'عَارِف',
  'عارفة': 'عَارْفَه',
  'تفتكر': 'تِفْتِكِر',
  'يفتكر': 'يِفْتِكِر',
  'أفتكر': 'أَفْتِكِر',
  'افتكرت': 'اِفْتَكَرْت',
  'فاكر': 'فَاكِر',
  'فاكرة': 'فَاكْرَه',
  'تفضل': 'تِفْضَل',
  'يفضل': 'يِفْضَل',
  'فضلت': 'فِضِلْت',
  'تشوف': 'تْشُوف',
  'يشوف': 'يْشُوف',
  'بتشوف': 'بِتْشُوف',
  'بيشوف': 'بِيْشُوف',
  'شفت': 'شُفْت',
  'شافت': 'شَافِت',
  'نمشي': 'نِمْشِي',
  'أمشي': 'أَمْشِي',
  'تمشي': 'تِمْشِي',
  'يمشي': 'يِمْشِي',
  'مشي': 'مِشِي',
  'تخبي': 'تِخَبِّي',
  'يخبي': 'يِخَبِّي',
  'هيكتشف': 'هَيِكْتِشِف',
  'طلع': 'طِلِع',
  'طلعت': 'طِلْعِت',
  'نزل': 'نِزِل',
  'نزلت': 'نِزْلِت',
  'رجع': 'رِجِع',
  'رجعت': 'رِجْعِت',
  'سكت': 'سِكِت',
  'هسكت': 'هَسْكُت',
  'سمع': 'سِمِع',
  'سمعت': 'سِمِعْت',
  'فهم': 'فِهِم',
  'فهمت': 'فِهِمْت',
  'فاهم': 'فَاهِم',
  'فاهمة': 'فَاهْمَه',
  'تعبت': 'تِعِبْت',
  'زهقت': 'زِهِقْت',
  'خلصت': 'خَلَّصْت',
  'وثقت': 'وَثَقْت',
  'هددوني': 'هَدِّدُونِي',
  'هددني': 'هَدِّدْنِي',
  'هيضيع': 'هَيِضِيع',
  'هيقدر': 'هَيِقْدَر',
  'يقربلك': 'يِقَرَّبْلَك',
  'يلمسك': 'يِلْمِسَك',
  'دفعت': 'دَفَعْت',
  'حصل': 'حَصَل',
  'بيحصل': 'بِيِحْصَل',
  'هيحصل': 'هَيِحْصَل',

  // كلمات درامية وشائعة كانت تُقرأ بالفصحى أحياناً
  'والله': 'وَاللَّاهِي', // منع كسرة الجلالة الفصيحة التي تحول الجملة بعدها لفصحى
  'أوي': 'أَوِي',
  'اوي': 'أَوِي',
  'خالص': 'خَالِص',
  'جدا': 'جِدًّا',
  'جداً': 'جِدًّا',
  'أكتر': 'أَكْتَر',
  'اكتر': 'أَكْتَر',
  'أحسن': 'أَحْسَن',
  'أصعب': 'أَصْعَب',
  'نفسي': 'نَفْسِي',
  'نفسك': 'نَفْسَك',
  'نفسه': 'نَفْسُه',
  'نفسها': 'نَفْسَهَا',
  'ما': 'مَا',
  'كان': 'كَان',
  'كانت': 'كَانِت',
  'قصدي': 'قَصْدِي',
  'قصدك': 'قَصْدَك',
  'غصب': 'غَصْب',
  'خايف': 'خَايِف',
  'خايفة': 'خَايْفَه',
  'مرعوب': 'مَرْعُوب',
  'مرعوبة': 'مَرْعُوبَه',
  'عايز': 'عَايِز',
  'عايزة': 'عَايْزَه',
  'عاوز': 'عَاوِز',
  'عاوزة': 'عَاوْزَه',
  'ماما': 'مَامَا',
  'بابا': 'بَابَا',
  'حبيبي': 'حَبِيبِي',
  'حبيبتي': 'حَبِيبْتِي',
  'طول': 'طُول',
  'عايش': 'عَايِش',
  'عايشة': 'عَايْشَه',
  'ساكت': 'سَاكِت',
  'ساكتة': 'سَاكْتَه',
  'مستني': 'مِسْتَنِّي',
  'مستنية': 'مِسْتَنِّيَه',
  'اللوحة': 'اللُّوحَه',
  'القديمة': 'القَدِيمَه',
  'الحقيقة': 'الحَقِيقَه',
  'بيه': 'بِيه',
  'باشا': 'بَاشَا',
  'العيلة': 'العِيلَه',
  'السر': 'السِّرّ',
  'للنور': 'لِلنُّور',
  'الكل': 'الكُلّ',
  'كذب': 'كِدْب',
  'تمن': 'تَمَن',
  'سكوتكم': 'سُكُوتْكُم',
  'السنين': 'السِّنِين',
  'كلها': 'كُلَّهَا',
  'حاجة': 'حَاجَه',
  'حاجات': 'حَاجَات',
  'واحد': 'وَاحِد',
  'واحدة': 'وَاحْدَه',
  'مخلوق': 'مَخْلُوق',
  'أبدا': 'أَبَدًا',
  'أبداً': 'أَبَدًا',
  'أحمد': 'أَحْمَد',
  'ليلى': 'لَيْلَى',
  'آدم': 'آدَم',
  'مراد': 'مُرَاد',
  'منصور': 'مَنْصُور',
  'سارة': 'سَارَه'
};
function applyEgyptianPhonetics(rawText, customDict = {}) {
  if (!rawText || !rawText.trim()) return '';

  let processed = rawText;

  // 1. تطبيق العبارات والمصطلحات المركبة (أكثر من كلمة) من ذاكرة التدريب الذاتي للمستخدم أولاً!
  if (customDict && typeof customDict === 'object') {
    const multiWordCustomKeys = Object.keys(customDict)
      .filter((k) => k.trim().includes(' '))
      .sort((a, b) => b.length - a.length);

    for (const phrase of multiWordCustomKeys) {
      const cleanPhrase = phrase.trim();
      if (cleanPhrase && processed.includes(cleanPhrase)) {
        processed = processed.split(cleanPhrase).join(customDict[phrase]);
      }
    }
  }

  // 2. تطبيق موسوعة المصطلحات والتعبيرات المصرية الأصيلة (EGYPTIAN_IDIOMS_BANK) مرتبة من الأطول للأقصر
  const idiomKeys = Object.keys(EGYPTIAN_IDIOMS_BANK).sort((a, b) => b.length - a.length);
  for (const idiom of idiomKeys) {
    if (processed.includes(idiom)) {
      processed = processed.split(idiom).join(EGYPTIAN_IDIOMS_BANK[idiom]);
    }
  }

  // 3. الذكاء السياقي لفك التباس الكلمات المتشابهة في المصرية (Contextual Homograph Disambiguation)
  // أ) تفريق "نِفْسِي" (رغبتي/شهيتي - بكسر النون) عن "نَفْسِي" (ذاتي - بفتح النون)
  processed = processed.replace(
    /\bنفسي\s+(أ|ا|ن|ت|ي|م|روح|أكل|آكل|أشرب|أنام|أمشي|أقعد|أشوف|أعرف|أقول|أعمل|أخرج|أسافر)/g,
    'نِفْسِي $1'
  );
  // ب) تفريق "عِشْرَة" (المعاشرة والصحبة - بكسر العين) عن رقم 10
  processed = processed.replace(/\bعشرة\s+(عمر|سنين|طويلة|قديمة|طيبة|أيام)/g, 'عِشْرِة $1');
  // ج) تفريق "هَمّ" (العبء والحزن) عن الضمير "هُمَّا"
  processed = processed.replace(/\b(شايل|تشيل|شال|يا|من)\s+هم\b/g, '$1 هَمّ');

  // 4. تقسيم النص إلى كلمات مع الحفاظ على المسافات وعلامات الترقيم
  const tokens = processed.split(/(\s+|[.,!؟?،؛:"«»\-–—…]+)/);

  return tokens
    .map((token, idx) => {
      if (/[A-Za-z\[\]]/.test(token)) return token;
      if (!token || /^(\s+|[.,!؟?،؛:"«»\-–—…]+)$/.test(token)) {
        return token;
      }

      // إذا كانت الكلمة قد تم تشكيلها بالفعل ضمن مصطلح مركب (تحتوي على حركات كافية) نحافظ عليها كما هي
      const diacriticsCount = (token.match(/[\u064B-\u065F\u0670]/g) || []).length;
      const stripped = token.replace(/[\u064B-\u065F\u0670]/g, '');

      // أولوية قصوى: ذاكرة التدريب الذاتي للمستخدم للكلمات المفردة
      if (customDict && customDict[stripped]) {
        return customDict[stripped];
      }

      if (diacriticsCount >= 2) {
        return token;
      }

      // فحص الكلمة التالية لمعرفة هل نحن في نهاية جملة/وقفة أم في وسط وصل كلامي
      const nextToken = tokens.slice(idx + 1).find((t) => t && !/^\s+$/.test(t));
      const isBeforePause = !nextToken || /^[.,!؟?،؛:"«»\-–—…]+$/.test(nextToken);

      // أولوية 2: القاموس الصوتي المصري الموحد
      if (EGYPTIAN_PHONETIC_LEXICON[stripped]) {
        let lexWord = EGYPTIAN_PHONETIC_LEXICON[stripped];
        if (isBeforePause && !/[اويىهةءأإآًّْ]/.test(lexWord.slice(-1))) {
          lexWord += 'ْ';
        }
        return lexWord;
      }

      let shaped = stripped;

      // 5. معالجة الكلمات المبدوءة بحروف متصلة (و / ف / ب / ل) + كلمة في القاموس أو الذاكرة
      if (shaped.length > 3 && /^[وفبل]/.test(shaped)) {
        const prefix = shaped[0];
        const stem = shaped.slice(1);
        const mappedStem =
          (customDict && customDict[stem]) || EGYPTIAN_PHONETIC_LEXICON[stem];
        if (mappedStem) {
          const prefixVowel = prefix === 'ب' || prefix === 'ل' ? `${prefix}ِ` : `${prefix}َ`;
          return prefixVowel + mappedStem;
        }
      }

      // 6. ضبط الأوزان الصرفية المصرية القياسية (مثل وزن فَعَّالَه: سَدَّادَه، شَغَّالَه، فَهَّامَه)
      if (/^[\u0621-\u064A]{2}ا[\u0621-\u064A]ة$/.test(shaped) && !shaped.startsWith('ال')) {
        shaped = `${shaped[0]}َ${shaped[1]}َّ${shaped.slice(2, -1)}ه`;
      }

      // 7. ضبط البادئات الفعلية المصرية: (بتـ -> بِتْـ ، بيـ -> بِيـ ، هتـ -> هَتِـ ، هيـ -> هَيِـ ، متـ..ش -> مَتْـ..ش)
      if (/^بت[\u0621-\u064A]{2,}/.test(shaped)) {
        shaped = 'بِتْ' + shaped.slice(2);
      } else if (/^بي[\u0621-\u064A]{2,}/.test(shaped)) {
        shaped = 'بِي' + shaped.slice(2);
      } else if (/^هت[\u0621-\u064A]{2,}/.test(shaped)) {
        shaped = 'هَتِ' + shaped.slice(2);
      } else if (/^هي[\u0621-\u064A]{2,}/.test(shaped)) {
        shaped = 'هَيِ' + shaped.slice(2);
      } else if (/^مت[\u0621-\u064A]{2,}ش$/.test(shaped)) {
        shaped = 'مَتْ' + shaped.slice(2);
      } else if (/^[تني][\u0621-\u064A]{3}$/.test(shaped) && !shaped.startsWith('تَا')) {
        shaped = shaped[0] + 'ِ' + shaped.slice(1);
      }

      // 8. معالجة التاء المربوطة (ة) في العامية المصرية لمنع نطقها "ت" فصيحة عند الوقف
      if (shaped.endsWith('ة')) {
        const nextWordStripped = nextToken ? nextToken.replace(/[\u064B-\u065F\u0670]/g, '') : '';
        if (isBeforePause || !nextWordStripped || /^(في|من|على|عن|و|ف|ب|ل|يا|ده|دي|اللي|عشان)$/.test(nextWordStripped)) {
          shaped = shaped.slice(0, -1) + 'ه';
        }
      }

      // 9. تسكين أواخر الجمل والوقفات فقط للحفاظ على انسيابية الكلام البشري المتصل
      const lastChar = shaped.slice(-1);
      if (isBeforePause && !/[اويىةهءأإآًّْ]/.test(lastChar) && shaped.length >= 2) {
        shaped = shaped + 'ْ';
      }

      return shaped;
    })
    .join('');
}
const egyPhon = (t) => { try { return applyEgyptianPhonetics(String(t || '')); } catch (e) { return t; } };
/* ---------- خط أداة الرداد (الوضع B): تحليل ذكي ← تشكيل ← صوت لكل مقطع بشخصيته وانفعاله ← دمج ---------- */
const RD_P = [{"id": "kareem", "v": "Charon", "n": "كريم", "a": "narrator_male", "p": 0.96, "i": "صوت رجالي مصري رخيم وعميق ووقور بنبرة حكواتي سينمائية متزنة"}, {"id": "tarek", "v": "Fenrir", "n": "طارق", "a": "adult_male_dramatic", "p": 1.0, "i": "صوت شاب أو رجل مصري قوي وحاد وحازم يتقن العامية المصرية والانفعالات القوية والغضب بواقعية شديدة"}, {"id": "youssef", "v": "Puck", "n": "يوسف", "a": "young_male", "p": 1.02, "i": "صوت شاب مصري قاهري في العشرينات مفعم بالحيوية وخفة الدم والتلقائية المصرية"}, {"id": "mahmoud", "v": "Orus", "n": "محمود", "a": "elder_male", "p": 0.92, "i": "صوت رجل مصري ناضج أو مسن حكيم يتحدث بتأنٍ وعمق وخبرة"}, {"id": "noor", "v": "Aoede", "n": "نور", "a": "adult_female", "p": 1.0, "i": "صوت امرأة مصرية شابة دافئ ومعبر عاطفياً يتقن العامية المصرية والمشاعر الدرامية والهمس والخوف والحزن"}, {"id": "salma", "v": "Kore", "n": "سلمى", "a": "narrator_female", "p": 0.98, "i": "صوت نسائي ناضج وواضح ورصين بنبرة واثقة وحاسمة"}, {"id": "layla", "v": "Zephyr", "n": "ليلى", "a": "young_female", "p": 1.04, "i": "صوت فتاة مصرية شابة رقيق وعفوي وحساس ينطق العامية المصرية بنعومة وتلقائية"}, {"id": "adam_child", "v": "Leda", "n": "طفل", "a": "child", "p": 1.16, "i": "صوت طفل مصري صغير بريء ذو طبقة صوتية طفولية رفيعة وناعمة يتحدث بالعامية المصرية ببراءة وتلقائية"}];
const RD_I = {"normal": {"l": "عادي", "b": "بأداء تمثيلي طبيعي ومتوازن"}, "strong": {"l": "قوي", "b": "بانفعال قوي وواضح جداً في نبرة الصوت"}, "max": {"l": "أقصى انفعال 🔥", "b": "بأقصى درجات الانفعال التمثيلي الحقيقي من قلب الحدث كأن المشهد حقيقي تماماً"}};
const RD_E = {"angry_shout": {"l": "غاضب ويصرخ بشدة", "m": "انفعال شديد وغضب عارم وصوت مرتفع حاد كأنك تصرخ في مواجهة حقيقية بكل قوة", "e": "انفعال مصري شديد جداً وغضب عارم وصوت عالي وحاد ومنفعل كأنك بتصرخ بجد في خناقة ومواجهة عنيفة"}, "fear_whisper": {"l": "خائفة وتهمس بارتجاف", "m": "خوف شديد وصوت هامس مرتجف وأنفاس متلاحقة متوترة تكاد تُسمع من شدة الرعب", "e": "خوف ورعب حقيقي وصوت مصري واطي مهموس ومرتجف وبيترعش مع نهجان خفيف كأنها مرعوبة بجد"}, "child_fear": {"l": "يبكي بذعر وخوف (طفل)", "m": "صوت طفل صغير بريء يتحدث بطبقة رفيعة وبنبرة خائفة باكية تستنجد بوالدها", "e": "صوت طفل مصري صغير بيعيط ومذعور وخايف أوي وبيستنجد بمامته أو باباه بنبرة طفولية باكية"}, "crying_sad": {"l": "حزين ومنكسر / يبكي", "m": "حزن عميق وصوت مختنق بالدموع والبكاء والرجاء المؤثر", "e": "صوت مصري حزين جداً ومكسور ومخنوق بالدموع والعياط والوجع كأنه بيعيط بجد"}, "sarcastic_cold": {"l": "ساخر ومتهكم ببرود", "m": "برود قاتل وسخرية لاذعة وثقة مستفزة مع نبرة تهديد خفية", "e": "برود أعصاب وسخرية مصرية لاذعة وتهكم واستفزاز وثقة عالية في الكلام مع نبرة تهديد هادية"}, "shock_surprise": {"l": "مصدوم ومذهول", "m": "صدمة مفاجئة وذهول وعدم تصديق مع شهقة خفيفة وتقطع في الأنفاس", "e": "صدمة كبيرة وذهول مصري وعدم تصديق من المفاجأة"}, "happy_warm": {"l": "فرحان، دافئ، أو حنون", "m": "سعادة غامرة وحماس ودفء عاطفي وابتسامة واضحة في نبرة الصوت", "e": "حنان ودفا مصري وطمأنينة أو فرحة كبيرة في الكلام"}, "dramatic_narrator": {"l": "سرد درامي مشوق", "m": "سرد روائي سينمائي عميق ومتزن يبني التشويق الدرامي ويهيئ المستمع للمشهد", "e": "سرد حكواتي مصري سلس وعميق ومشوق بلهجة مصرية رصينة وطبيعية بدون تكلف"}, "natural_dialogue": {"l": "هادئ وحازم / طبيعي", "m": "نبرة حوارية طبيعية وواضحة وحازمة بهدوء", "e": "كلام مصري قاهري طبيعي وتلقائي وحازم زي كلام المصريين في الحقيقة بالظبط"}};
const RD_SYS = "أنت مخرج دراما إذاعية مصري خبير في اللهجة العامية المصرية القاهرية والمصطلحات الشعبية والتمثيل الصوتي البشري.\nمهمتك: تحليل الفصل الروائي وتقسيمه بالترتيب إلى مقاطع (سرد للراوي + حوارات الشخصيات) مع كتابة التشكيل الصوتي المصري المتصل (phoneticText) لكل جملة بحيث ينطقها الممثل كإنسان مصري حقيقي بدون أي أخطاء!\nاجعل الحوار بالعامية المصرية والسرد باللغة العربية الفصحى.\n\nقواعد الذاكرة الذاتية والمصطلحات المصرية المدربة (يجب الالتزام بها حرفياً وعدم الخطأ فيها أبداً):\n[]\n\nقواعد حاسمة جداً للمصطلحات والأوزان الصرفية المصرية:\n1. انتبه للمصطلحات الشعبية المصرية التي تختلف حركاتها عن الفصحى:\n   - «رقبتي سدّادة» تُشكّل صوتياً بالمصري: «رَقَبْتِي سَدَّادَه» (بفتح السين وتشديد الدال على وزن فَعَّالَه، وتسكين الباء في رَقَبْتِي، وإياك أن تكتبها سِدادة بالكسر!).\n   - «دمي محروق» ⬅️ «دَمِّي مَحْرُوق»، «حقك عليا» ⬅️ «حَقَّك عَلَيَّا»، «مليش نفس» ⬅️ «مَالِيش نِفْس» (بكسر النون في نِفْس)، «على عيني وراسي» ⬅️ «عَلَى عِينِي وَرَاسِي».\n2. عندما تقرأ سرداً يمهد للحوار مثل: «انفعل «أحمد» بشدة وصرخ وهو يقول بغضب: - أنت إزاي تعمل فيا كدا!»:\n   - السطر الأول هو سرد للراوي (speaker: \"الراوي\", type: \"narration\", emotionId: \"dramatic_narrator\").\n   - السطر الثاني هو بصوت شخصية «أحمد» (speaker: \"أحمد\", type: \"dialogue\") وانفعاله هو الغضب الشديد والصراخ (emotionId: \"angry_shout\")، ودرجة حدة الانفعال هي القصوى (intensity: \"max\").\n3. اكتب «والله» في العامية المصرية هكذا: «وَاللَّاهِي»، واكتب التاء المربوطة عند الوقف بالهاء الصوتية «ه» (مثل: سَدَّادَه، كِفَايَه، خَايْفَه).\n4. اختر speakerArchetype من القيم التالية فقط:\n   - \"narrator_male\" | \"adult_male_dramatic\" | \"young_male\" | \"elder_male\" | \"adult_female\" | \"narrator_female\" | \"young_female\" | \"child\"\n5. اختر emotionId من القيم التالية فقط:\n   - \"angry_shout\" | \"fear_whisper\" | \"child_fear\" | \"crying_sad\" | \"sarcastic_cold\" | \"shock_surprise\" | \"happy_warm\" | \"dramatic_narrator\" | \"natural_dialogue\"\n6. اختر intensity من القيم التالية فقط:\n   - \"normal\" | \"strong\" | \"max\"";
const rdPartMx = (conf) => ((conf.rd || RD_DEF).partChars > 0 ? conf.rd.partChars : conf.engine === 'single' ? 900 : 1600);
const rdPersB = (id) => RD_P.find((p) => p.id === id) || RD_P[0];
let RD_CF = RD_DEF; // إعدادات الرداد الحالية (بتتظبط أول radadPart)
const rdPers = (id) => { const b = rdPersB(id), o = (RD_CF.pers || {})[id]; return o ? { ...b, v: o.v || b.v, p: o.p || b.p } : b; };
const rdByArch = (a) => RD_P.find((p) => p.a === a);
function rdDsp(pcm16, pitch, warm = true) { // بصمة الشخصية (طبقة) + فلتر الدفء — زي الأداة بالظبط
  let x = pcm16;
  if (pitch && Math.abs(pitch - 1) >= 0.01) {
    const n = Math.floor(pcm16.length / pitch), o = new Int16Array(n);
    for (let i = 0; i < n; i++) { const s = i * pitch, i0 = Math.floor(s), i1 = Math.min(pcm16.length - 1, i0 + 1), f = s - i0; o[i] = Math.round(pcm16[i0] * (1 - f) + pcm16[i1] * f); }
    x = o;
  }
  if (!warm) return x;
  const h = new Int16Array(x.length); let prev = 0;
  for (let i = 0; i < x.length; i++) { const sm = (x[i] / 32768) * 0.88 + prev * 0.12; prev = sm; const w = Math.tanh(sm * 1.12) / Math.tanh(1.12); h[i] = Math.max(-32767, Math.min(32767, Math.round(w * 32767))); }
  return h;
}
async function rdAnalyze(env, text, conf) { // التحليل الذكي: مقاطع (راوي + شخصيات) بالترتيب مع الانفعال والتشكيل
  const MB = 'اجعل الحوار بالعامية المصرية والسرد باللغة العربية الفصحى.', cf = conf.rd || RD_DEF, MT = cf.mode === 'A' ? 'اجعل الحوار بالعامية المصرية المشكّلة صوتياً، والسرد بروح مصرية طبيعية وسلسة غير متكلفة (حكواتي مصري).' : cf.mode === 'C' ? 'حوّل جمل السرد والحوار بالكامل إلى عامية مصرية متدفقة وضعها في حقل text مع الحفاظ على كل المعنى والأحداث.' : MB;
  const body = JSON.stringify({ contents: [{ parts: [{ text }] }], systemInstruction: { parts: [{ text: RD_SYS.replace(MB, MT) }] }, generationConfig: { responseMimeType: 'application/json', responseSchema: { type: 'ARRAY', items: { type: 'OBJECT', properties: { type: { type: 'STRING' }, speaker: { type: 'STRING' }, speakerArchetype: { type: 'STRING' }, dialect: { type: 'STRING' }, emotionId: { type: 'STRING' }, intensity: { type: 'STRING' }, actingDirection: { type: 'STRING' }, text: { type: 'STRING' }, phoneticText: { type: 'STRING' } }, propertyOrdering: ['type', 'speaker', 'speakerArchetype', 'dialect', 'emotionId', 'intensity', 'actingDirection', 'text', 'phoneticText'] } } } });
  for (const model of [cf.anaModel, conf.annModel || 'gemini-2.5-flash']) {
    try {
      const r = await gFetch(env, 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent', { method: 'POST', signal: AbortSignal.timeout(70000), headers: { 'Content-Type': 'application/json' }, body });
      if (r.status === 429) { const e = new Error('busy'); e.code = 429; e.detail = await q429(r); throw e; }
      if (!r.ok) continue;
      const j = await r.json(), t = (((j.candidates || [])[0] || {}).content || {}).parts;
      const arr = JSON.parse((t || []).map((x) => x.text || '').join(''));
      if (Array.isArray(arr) && arr.length) return arr;
    } catch (e) { if (e.code === 429) throw e; }
  }
  return null;
}
async function rdCall(env, conf, body) { // طلب TTS: بيلف على كل المفاتيح، ولو كلها اتزحمت بيستنى 16 ثانية (زي الأداة) ويعيد
  const url = 'https://generativelanguage.googleapis.com/v1beta/models/' + conf.legacyModel + ':generateContent';
  for (let k = 0; k < 3; k++) {
    const r = await gFetch(env, url, { method: 'POST', signal: AbortSignal.timeout(100000), headers: { 'Content-Type': 'application/json' }, body });
    if (r.status !== 429) return r;
    const d = await q429(r);
    const cf = conf.rd || RD_DEF;
    if (/PerDay|per day|daily/i.test(d) || k === 2 || !cf.autoWait) { const e = new Error('busy'); e.code = 429; e.detail = d; throw e; }
    await new Promise((s) => setTimeout(s, cf.waitSec * 1000));
  }
}
const rdPcm = (j) => { const b = findAudioB64(j); if (!b) return null; const raw = wavPcm(toWav(b)); return new Int16Array(raw.slice().buffer, 0, raw.length >> 1); };
const rdDict = (conf) => { const o = {}; String(conf.dict || '').split('\n').forEach((l) => { const k = l.indexOf('='); if (k > 0) o[l.slice(0, k).trim()] = l.slice(k + 1).trim(); }); return o; };
const rdEgy = (seg, conf) => seg.type === 'dialogue' || (conf.rd || RD_DEF).mode !== 'B';
const rdScript = (seg, conf) => {
  let s = rdEgy(seg, conf) ? applyEgyptianPhonetics((seg.phoneticText && seg.phoneticText.trim()) || seg.text, rdDict(conf)) : seg.text;
  if ((conf.rd || RD_DEF).humanize && (seg.emotionId === 'fear_whisper' || seg.emotionId === 'crying_sad' || seg.emotionId === 'child_fear') && !s.includes('..')) s = s.replace(/،\s+/g, '.. ');
  return s;
};
async function rdSpeak(env, seg, persona, conf) { // مقطع واحد بصوت شخصيته (وضع single، وكمان احتياطي لو دفعة طلعت ناقصة)
  const emo = RD_E[seg.emotionId] || RD_E.natural_dialogue, it = RD_I[seg.intensity] || RD_I.strong, dlg = rdEgy(seg, conf), script = rdScript(seg, conf);
  const ins = dlg
    ? 'أنت إنسان مصري حقيقي وممثل دراما محترف تؤدي دور «' + seg.speaker + '» (' + persona.i + ').\nتحدث بلهجة عامية مصرية قاهرية بشرية تلقائية وطبيعية 100% كأنك تتحدث في الواقع وليس كقارئ آلي:\n- وصل الكلام ببعضه بنعومة واخطف الحروف المصرية بشكل طبيعي بدون تقطيع بين الكلمات.\n- انطق الجيم مصرية غير معطشة (G) دائماً، والتزم بالنطق المصري للكلمات المشكّلة أمامك، ولا تفخم الكلمات أو تحولها للفصحى أبداً.\n- جسّد الإحساس البشري الحقيقي الآن (' + it.l + '): ' + emo.e + ' — ' + (seg.actingDirection || '') + ' (' + it.b + ').\nانطق الجملة التالية فقط بتلقائية بشرية كاملة:\n\n' + script
    : 'أنت ممثل صوتي بشري محترف تؤدي دور «' + seg.speaker + '» (' + persona.i + ').\nتحدث باللغة العربية الفصحى السليمة بأداء بشري دافئ وطبيعي بعيد تماماً عن الرتابة الآلية.\nالانفعال والأداء التمثيلي المطلوب الآن (' + it.l + '): ' + emo.m + ' — ' + (seg.actingDirection || '') + '.\nاقرأ النص التالي فقط:\n\n' + script;
  const body = JSON.stringify({ contents: [{ parts: [{ text: ins }] }], generationConfig: { responseModalities: ['AUDIO'], speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName: persona.v } } } } });
  const need = String(seg.text).replace(/\s/g, '').length;
  for (let k = 0; k < 3; k++) {
    const r = await rdCall(env, conf, body);
    if (!r.ok) { if (k < 2 && r.status >= 500) continue; const e = new Error('gemini_' + r.status); e.code = 502; throw e; }
    const pcm16 = rdPcm(await r.json()); if (!pcm16) continue;
    if (need < 25 || pcm16.length / 24000 >= need / 20) return rdDsp(pcm16, persona.p, (conf.rd || RD_DEF).humanize);
  }
  const e = new Error('short_audio'); e.code = 502; e.detail = 'صوت ناقص من جوجل — هيتعاد'; throw e;
}
async function rdMega(env, batch, conf) { // الدمج الفائق: لحد 7 مشاهد (متحدثين اتنين بالكتير) في طلب واحد
  if (batch.length === 1) return rdSpeak(env, batch[0], rdPers(batch[0].pid), conf);
  const sp = []; batch.forEach((s) => { if (!sp.find((u) => u.tag === s.speaker)) sp.push({ tag: s.speaker, p: rdPers(s.pid) }); });
  const A = sp[0], B = sp[1] || { tag: 'المتحدث_الثاني', p: rdPers('youssef') };
  const lines = batch.map((s) => { const emo = RD_E[s.emotionId] || RD_E.natural_dialogue; return s.speaker + ': (' + emo.l + ' - ' + (s.actingDirection || '') + ') ' + rdScript(s, conf); }).join('\n');
  const prompt = 'قم بتمثيل هذا المشهد الدرامي المصري ببراعة وواقعية بشرية 100% باللهجة العامية المصرية القاهرية الصميمة (نطق الجيم المصرية غير المعطشة G، وصل الكلمات بنعومة بشرية، والالتزام التام بالتشكيل الصوتي المصري المكتوب دون تحويل أي كلمة للفصحى).' + (((conf.rd || RD_DEF).mode === 'B') && batch.some((s) => s.type === 'narration') ? '\nاستثناء: المتحدث «الراوي» يقرأ سرده باللغة العربية الفصحى السليمة.' : '') + '\nالتزم بالانفعال المكتوب بين القوسين لكل جملة دون أن تنطق الكلام الموجود داخل القوسين ودون نطق أسماء المتحدثين:\n\n' + lines;
  const body = JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { responseModalities: ['AUDIO'], speechConfig: { multiSpeakerVoiceConfig: { speakerVoiceConfigs: [{ speaker: A.tag, voiceConfig: { prebuiltVoiceConfig: { voiceName: A.p.v } } }, { speaker: B.tag, voiceConfig: { prebuiltVoiceConfig: { voiceName: B.p.v } } }] } } } });
  const need = batch.reduce((a, s) => a + String(s.text).replace(/\s/g, '').length, 0);
  try {
    for (let k = 0; k < 2; k++) {
      const r = await rdCall(env, conf, body);
      if (!r.ok) { if (r.status >= 500) continue; break; }
      const pcm16 = rdPcm(await r.json());
      if (pcm16 && (need < 40 || pcm16.length / 24000 >= need / 20)) return rdDsp(pcm16, 1.0, (conf.rd || RD_DEF).humanize);
    }
  } catch (e) { if (e.code === 429) throw e; }
  // الدفعة طلعت ناقصة/فاشلة: نحوّل مشاهدها واحد واحد عشان ماينقصش كلام
  const parts = []; for (const s of batch) parts.push(await rdSpeak(env, s, rdPers(s.pid), conf));
  const gap = new Int16Array(Math.round(24000 * 0.3)); let n = 0; parts.forEach((p, i) => { n += p.length + (i ? gap.length : 0); });
  const out = new Int16Array(n); let o = 0; parts.forEach((p, i) => { if (i) o += gap.length; out.set(p, o); o += p.length; }); return out;
}
async function radadPart(env, text, conf, ctx, nid) {
  const cf = conf.rd || RD_DEF; RD_CF = cf;
  const segs = await rdAnalyze(env, text, conf);
  if (!segs) return geminiPart(env, text, conf, ctx); // لو التحليل فشل: المسار القديم بدل ما الفصل يقف
  const regKey = 'rdreg_' + (nid || 'x'); let reg = {}; try { reg = (await getSetting(env, regKey)) || {}; } catch (e) {}
  let dirty = false; const items = [];
  for (const s of segs) {
    const clean = String(s.text || '').replace(/^[-–—•]\s*/, '').trim(); if (!clean) continue;
    const sp = String(s.speaker || 'الراوي').trim() || 'الراوي', dlg = s.type !== 'narration' && sp !== 'الراوي';
    let pid = reg[sp];
    if (!pid) { const p = sp === 'الراوي' ? rdPers(cf.narrator) : (cf.archMap[s.speakerArchetype] ? rdPers(cf.archMap[s.speakerArchetype]) : (rdByArch(s.speakerArchetype) || rdPers('tarek'))); pid = p.id; reg[sp] = pid; dirty = true; }
    items.push({ type: dlg ? 'dialogue' : 'narration', speaker: sp, text: clean, phoneticText: String(s.phoneticText || '').replace(/^[-–—•]\s*/, '').trim(), emotionId: RD_E[s.emotionId] ? s.emotionId : 'natural_dialogue', intensity: RD_I[s.intensity] ? s.intensity : 'strong', actingDirection: s.actingDirection || 'أداء تمثيلي مصري صادق ومعبر', pid });
  }
  // حماية من إسقاط الكلام: لو التحليل وقّع أكتر من 15% من النص نرجع للمسار القديم (ما نسيبش فقرات ضايعة)
  const nz = (s) => String(s).replace(/[^ء-ي0-9]/g, '').length, src = nz(text), got = items.reduce((a, x) => a + nz(x.text), 0);
  if (!items.length || (src > 80 && got < src * 0.85)) return geminiPart(env, text, conf, ctx);
  if (dirty) { try { await setSetting(env, regKey, reg); } catch (e) {} }
  if (cf.skipNarration) { const keep = items.filter((x) => x.type !== 'narration'); if (keep.length) { items.length = 0; items.push(...keep); } }
  let jobs;
  if (conf.engine === 'single') jobs = items.map((x) => [x]);
  else { jobs = []; let cur = [], set = new Set(); for (const s of items) { const nx = new Set(set); nx.add(s.speaker); if (cur.length >= cf.batch || nx.size > 2) { jobs.push(cur); cur = [s]; set = new Set([s.speaker]); } else { cur.push(s); set = nx; } } if (cur.length) jobs.push(cur); }
  const pcms = new Array(jobs.length); let nxt = 0;
  await Promise.all(Array.from({ length: Math.min(2, jobs.length) }, async () => { while (nxt < jobs.length) { const i = nxt++; pcms[i] = await rdMega(env, jobs[i], conf); } }));
  const gap = new Int16Array(Math.round(24 * cf.pauseMs)); let n = 0; pcms.forEach((p, i) => { n += p.length + (i ? gap.length : 0); });
  const all = new Int16Array(n); let o = 0; pcms.forEach((p, i) => { if (i) o += gap.length; all.set(p, o); o += p.length; });
  return { wav: pcmToWav(new Uint8Array(all.buffer), 24000), chars: items.reduce((a, x) => a + x.text.length, 0), calls: jobs.length + 1 };
}
async function geminiPart(env, text, conf, ctx) { // جزء واحد: أدوار متعددة (حد أقصى متكلمين اثنين في الطلب)
  const runs = mergeRuns(applyDict(conf.multi ? await smartRoles(env, text, conf, ctx) : [{ role: 'narrator', text: stripMarks(text) }], conf).map((r) => (r.role === 'narrator' || r.tg || conf.phon === false ? r : { ...r, text: egyPhon(r.text) })), conf.econ ? 2 : 4, conf.econ ? 150 : 45), groups = []; let cur = null;
  for (const r of runs) { if (!cur || (!cur.roles.has(r.role) && cur.roles.size >= (conf.mm ? 2 : 1))) { cur = { roles: new Set(), items: [] }; groups.push(cur); } cur.roles.add(r.role); cur.items.push(r); }
  const wavs = new Array(groups.length); let chars = 0, nxt = 0;
  groups.forEach((g) => { chars += g.items.map((x) => x.text).join(' ').length; });
  const one0 = async (i) => { const g = groups[i], roles = [...g.roles], tgs = g.items.some((x) => x.tg), t = g.items.length > 1 ? g.items.map((x) => (x.tg ? x.text : cueTxt(x))).join(' ') : g.items[0].text;
    wavs[i] = roles.length === 1 ? await geminiSpeak(env, t, conf.gv[roles[0]], conf, roleStyle(conf, roles[0], g.items.length === 1 && !tgs ? g.items[0].emo : '') + ((tgs || g.items.length > 1) ? '. The text has square-bracket cues: act each cue out exactly with that feeling for the sentences after it, and never read the cue aloud' : '')) : await geminiMulti(env, roles[0], roles[1], g.items, conf); };
  // حماية من الصوت الناقص: جوجل أحيانًا بترجّع صوت قصير (بيقرا أول سطر/العنوان وبس) — بنقارن المدة بعدد الحروف ونعيد المحاولة
  const one = async (i) => {
    const g = groups[i], clean = g.items.map((x) => String(x.text).replace(/\[[^\]]*\]/g, '')).join(' '), need = clean.replace(/\s/g, '').length;
    for (let k = 0; k < 3; k++) {
      await one0(i);
      const secs = Math.max(0, wavs[i].length - 44) / 48000;
      if (need < 40 || secs >= need / 18) return;
    }
    const e = new Error('short_audio'); e.code = 502; e.detail = 'الصوت اللي رجع من جوجل ناقص (قصير عن النص) — هيتعاد'; throw e;
  };
  // الأجزاء الصغيرة (الأدوار) بتتحوّل بالتوازي (3 مع بعض) علشان الجزء يخلص قبل ما الوقت يخلص
  await Promise.all(Array.from({ length: Math.min(3, groups.length) }, async () => { while (nxt < groups.length) { const i = nxt++; await one(i); } }));
  const wav = joinWavs(wavs); return { wav, chars, calls: groups.length };
}
const xmlEsc = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
function azureSsml(runs, conf) {
  const v = conf.az.voices;
  return '<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" xml:lang="ar-EG">' + runs.map((r) => { const o = v[r.role] || v.narrator; return '<voice name="' + xmlEsc(o.v) + '"><prosody rate="' + o.rate + '" pitch="' + o.pitch + '">' + xmlEsc(r.text) + '</prosody></voice>'; }).join('<break time="180ms"/>') + '</speak>';
}
async function azureSpeakRuns(env, runs, conf) {
  const region = azRegion(env, conf);
  const r = await fetch('https://' + region + '.tts.speech.microsoft.com/cognitiveservices/v1', { method: 'POST', headers: { 'Ocp-Apim-Subscription-Key': env.AZURE_SPEECH_KEY, 'Content-Type': 'application/ssml+xml', 'X-Microsoft-OutputFormat': 'riff-24khz-16bit-mono-pcm', 'User-Agent': 'RadPad' }, body: azureSsml(runs, conf) });
  if (r.status === 429) { const e = new Error('busy'); e.code = 429; e.detail = await q429(r); throw e; }
  if (r.status === 401 || r.status === 403) { const e = new Error('azure_key_or_region_wrong'); e.code = 401; throw e; }
  if (!r.ok) { const e = new Error('azure_' + r.status); e.code = 502; throw e; }
  const b = new Uint8Array(await r.arrayBuffer()); if (b.length < 100) { const e = new Error('no_audio'); e.code = 502; throw e; } return b;
}
async function azurePart(env, text, conf, ctx) {
  const runs = applyDict(conf.multi ? await smartRoles(env, text, conf, ctx) : [{ role: 'narrator', text: stripMarks(text) }], conf);
  const wav = await azureSpeakRuns(env, runs, conf); return { wav, chars: runs.reduce((a, r) => a + r.text.length, 0), calls: 1 };
}
const speakPart = (env, prov, text, conf, ctx, nid) => (prov === 'azure' ? azurePart(env, text, conf, ctx) : conf.radad !== false ? radadPart(gemEnv(env, prov), text, conf, ctx, nid) : geminiPart(gemEnv(env, prov), text, conf, ctx));
const audioResp = (obj, hit) => new Response(obj.body || obj, { status: 200, headers: { ...CORS, 'Content-Type': 'audio/wav', 'Cache-Control': 'private, max-age=86400', 'X-Cache': hit ? 'HIT' : 'MISS' } });
const CPS = 14; // حروف في الثانية تقريبًا (لتقدير المدة والتكلفة قبل التحويل)
const hasMk = (t) => /[«“"]/.test(t) || /(^|\n)\s*[-–—]/.test(t);
const hasLetters = (t) => /[؀-ۿA-Za-z0-9]/.test(t);
// يقسّم نص الفصل لأجزاء (≤700 حرف، أو 2000 في وضع التوفير) على حدود الفقرات/الجمل. بيرجّع [[بداية،نهاية]] بالنسبة للنص الأصلي
function splitParts(text, MX = 700) {
  const out = [], push = (a, b) => { if (b > a && hasLetters(text.slice(a, b))) out.push([a, b]); };
  let a = -1, prevEnd = 0, pos = 0;
  const flush = () => { if (a >= 0) push(a, prevEnd); a = -1; };
  for (const line of text.split('\n')) {
    const ls = pos, le = pos + line.length; pos = le + 1;
    if (!line.trim()) continue;
    if (line.length > MX) {
      flush();
      let cur = -1, curEnd = 0; const re = /[^.!؟?؛;:]+[.!؟?؛;:]*/g; let m;
      while ((m = re.exec(line))) {
        let ms = ls + m.index; const me = ms + m[0].length;
        while (me - ms > MX) { let cut = line.lastIndexOf(' ', ms - ls + MX); cut = cut > ms - ls + Math.min(200, MX / 3) ? ls + cut : ms + MX; if (cur >= 0) { push(cur, curEnd); cur = -1; } push(ms, cut); ms = cut; }
        if (cur >= 0 && me - cur > MX) { push(cur, curEnd); cur = -1; }
        if (cur < 0) cur = ms; curEnd = me;
      }
      if (cur >= 0) push(cur, curEnd);
      continue;
    }
    if (a >= 0 && le - a > MX) flush();
    if (a < 0) a = ls;
    prevEnd = le;
  }
  flush(); return out;
}
async function ttsBump(env, prov, cols) {
  const d = dayKey();
  await env.DB.prepare('INSERT INTO tts_use (day,prov) VALUES (?,?) ON CONFLICT(day,prov) DO NOTHING').bind(d, prov).run();
  const sets = Object.keys(cols).map((k) => k + '=' + k + '+?').join(',');
  await env.DB.prepare('UPDATE tts_use SET ' + sets + ' WHERE day=? AND prov=?').bind(...Object.values(cols), d, prov).run();
}
const stKey = (prov) => (prov === 'azure' ? 'tts_state_az' : prov === 'gemini' ? 'tts_state' : prov[0] === 'r' ? 'tts_state_r' + prov.slice(2) : 'tts_state_g' + prov.slice(6));
const PNAME = { gemini: 'جوجل 1', gemini2: 'جوجل 2', gemini3: 'جوجل 3', gemini4: 'جوجل 4', gemini5: 'جوجل 5', gemini6: 'جوجل 6', rd1: 'الرداد 1', rd2: 'الرداد 2', rd3: 'الرداد 3', rd4: 'الرداد 4', rd5: 'الرداد 5', rd6: 'الرداد 6', azure: 'مايكروسوفت (Azure)' };
async function ttsAlertAdmins(env, title, text, prov = 'gemini') {
  const key = stKey(prov), st = await getSetting(env, key), now = Date.now();
  if (st.alertAt && now - st.alertAt < 6 * 3600000) return;
  await setSetting(env, key, { ...st, alertAt: now });
  try {
    const { results } = await env.DB.prepare("SELECT id FROM users WHERE role='admin'").all();
    for (const a of results) {
      await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(a.id, 'payment', 'pay', 'RadPad', title, text, now).run();
      if (env.FCM_SA) { try { await sendPush(env, title, text, '', 'u_' + a.id); } catch (e) {} }
    }
  } catch (e) {}
}
// الصوت القديم بيفضل زي ما هو (مفيش مسح)؛ الأصوات المتعددة بتشتغل على اللي يتحوّل من دلوقتي
const ECON_MX = 2000; // وضع التوفير: جزء أكبر = طلبات أقل (الحساب المجاني 10 طلبات في اليوم)
const TTS_VER = 3;
async function ttsMigrate(env) {
  const v = await getSetting(env, 'tts_ver'); if (v.v >= TTS_VER) return true;
  await setSetting(env, 'tts_ver', { v: TTS_VER });
  const mk = await getSetting(env, 'tts_mk'); if (!mk.v) { await env.DB.prepare("UPDATE tts_ch SET sig='' WHERE status!='done'").run(); await setSetting(env, 'tts_mk', { v: 1 }); } // الفصول اللي لسه ما اتحوّلتش تتبعت تاني بعلامات الحوار
  return true;
}
async function ttsWipeNovel(env, nid) { // مسح الصوت المتخزّن لرواية
  const { results } = await env.DB.prepare('SELECT id,nparts FROM tts_ch WHERE nid=?').bind(nid).all();
  if (env.TTS_BUCKET) for (const c of results) { const keys = []; for (let i = 0; i < c.nparts; i++) keys.push('c/' + c.id + '/' + i + '.wav'); for (let i = 0; i < keys.length; i += 100) await env.TTS_BUCKET.delete(keys.slice(i, i + 100)); }
}
// خطوة تحويل واحدة لمزوّد واحد: بتاخد أول فصل في طابوره (بالترتيب) وتولّد منه كام جزء، بشرط الحد اليومي. بتتنادى كل دقيقة من Cron.
/* توزيع تلقائي: أي حساب طابوره فضي (وجاهز) بياخد رواية أو اتنين لسه ما اتبدأتش من طوابير الحسابات التانية */
async function ttsRebalance(env, per = 2) {
  const conf = await getTtsConf(env); if (conf.rebalance === false) return [];
  const { results } = await env.DB.prepare("SELECT nid,MAX(prov) AS prov,MIN(ord) AS o,COUNT(*) AS n,SUM(status='done') AS d,SUM(status='running') AS r,SUM(status IN ('queued','running')) AS pend FROM tts_ch GROUP BY nid").all();
  if (!results.length) return [];
  const now = Date.now(), pend = {}, paused = {};
  for (const p of PROVS) { pend[p] = 0; const st = await getSetting(env, stKey(p)); paused[p] = (st.pausedUntil || 0) > now; }
  results.forEach((r) => { pend[r.prov] = (pend[r.prov] || 0) + (r.pend || 0); });
  const idle = PROVS.filter((p) => pend[p] === 0 && !paused[p] && provReady(env, conf, p) && provCap(conf, p) > 0);
  const moved = [];
  for (const to of idle) {
    let got = 0;
    for (let k = 0; k < per; k++) {
      // المتبرّع = الحساب اللي عنده أكتر روايات لسه ما اتبدأتش
      const cand = {};
      results.filter((r) => r.prov !== to && !r.moved && (r.d || 0) === 0 && !(r.r > 0) && r.pend > 0).forEach((r) => { (cand[r.prov] = cand[r.prov] || []).push(r); });
      let best = null;
      for (const pv of Object.keys(cand)) {
        const list = cand[pv].sort((a, b) => a.o - b.o);
        const all = results.filter((r) => r.prov === pv && r.pend > 0 && !r.moved).sort((a, b) => a.o - b.o);
        // متخدش الرواية اللي هتبدأ دلوقتي في طابور الحساب التاني (الأولى) إلا لو الحساب ده واقف/مش جاهز
        const front = all[0], donorOk = provReady(env, conf, pv) && !paused[pv];
        const pool = donorOk ? list.filter((r) => r !== front) : list;
        if (pool.length && (!best || pool.length > best.pool.length)) best = { pv, pool };
      }
      if (!best) break;
      const pick = best.pool[best.pool.length - 1]; // آخر واحدة في طابورهم
      const maxo = (await env.DB.prepare('SELECT COALESCE(MAX(ord),0) AS m FROM tts_ch WHERE prov=?').bind(to).first()).m;
      await env.DB.prepare("UPDATE tts_ch SET prov=?,ord=? WHERE nid=? AND status!='done'").bind(to, maxo + 10, pick.nid).run();
      const raw = await getSetting(env, 'tts'); await setSetting(env, 'tts', { ...raw, novelProv: { ...(raw.novelProv || {}), [pick.nid]: to } });
      pick.moved = true; moved.push({ nid: pick.nid, from: best.pv, to }); got++;
    }
  }
  return moved;
}
async function ttsStep(env, opts = {}) {
  const prov0 = normProv(opts.prov), t00 = Date.now(); let res, ex;
  try { res = await ttsStep0(env, opts); } catch (e) { ex = e; }
  try {
    const r = ex ? { err: String(ex.message || ex).slice(0, 160) } : res.limit ? { err: 'جوجل رفضت (429): ' + res.limit, made: res.made || 0 } : { idle: res.idle || '', made: res.made || 0, ch: res.id || 0, done: res.done, total: res.total, st: res.status || '' };
    await setSetting(env, 'tts_last_' + prov0, { at: Date.now(), ms: Date.now() - t00, ...r });
  } catch (e) {}
  if (ex) throw ex; return res;
}
async function ttsStep0(env, opts = {}) {
  const prov = normProv(opts.prov), conf = await getTtsConf(env);
  if (!provReady(env, conf, prov)) return { ok: false, idle: 'not_configured', prov };
  const now = Date.now(), key = stKey(prov), st = await getSetting(env, key);
  if (st.pausedUntil && st.pausedUntil > now && !opts.force) return { ok: true, idle: 'paused', prov };
  const u = await env.DB.prepare('SELECT secs FROM tts_use WHERE day=? AND prov=?').bind(dayKey(), prov).first();
  let used = u ? u.secs : 0; const cap = provCapE(env, conf, prov) * 60, par = provPar(conf, prov);
  if (used >= cap) return { ok: true, idle: 'daily_limit', prov };
  try { await env.DB.prepare("UPDATE tts_ch SET status='queued',attempts=0,retry_at=0 WHERE status='failed' AND prov=? AND updated<?").bind(prov, now - 1800000).run(); } catch (e) {} // الفصل الفاشل بيتعاد تلقائي بعد نص ساعة (مفيش فصل بيتسقط)
  const tok = crypto.randomUUID();
  const r = await env.DB.prepare("UPDATE tts_ch SET status='running',owner=?2,lock_until=?1+240000,attempts=attempts WHERE id=(SELECT id FROM tts_ch WHERE prov=?3 AND status IN ('queued','running') AND lock_until<=?1 AND retry_at<=?1 ORDER BY ord ASC,nid ASC,idx ASC LIMIT 1)").bind(now, tok, prov).run();
  if (r && r.meta && typeof r.meta.changes === 'number' && !r.meta.changes) return { ok: true, idle: 'empty', prov };
  const ch = await env.DB.prepare("SELECT * FROM tts_ch WHERE owner=? AND status='running'").bind(tok).first();
  if (!ch) return { ok: true, idle: 'empty', prov };
  let parts = JSON.parse(ch.parts || '[]');
  if (conf.radad !== false && ch.done === 0 && parts.length && Math.max(...parts.map((x) => x[1] - x[0])) > rdPartMx(conf) * 1.25) { const np = splitParts(ch.text, rdPartMx(conf)); if (np.length) { parts = np; await env.DB.prepare('UPDATE tts_ch SET parts=?,nparts=? WHERE id=?').bind(JSON.stringify(np), np.length, ch.id).run(); } }
  if (conf.radad === false && conf.econ && ch.done === 0 && parts.length > 1 && Math.max(...parts.map((x) => x[1] - x[0])) <= 800) { // فصل لسه ما بدأش: نكبّر الأجزاء علشان الطلبات تقل
    const np = splitParts(ch.text, ECON_MX); if (np.length && np.length < parts.length) { parts = np; await env.DB.prepare('UPDATE tts_ch SET parts=?,nparts=? WHERE id=?').bind(JSON.stringify(np), np.length, ch.id).run(); }
  }
  let done = ch.done, secsTot = ch.secs, made = 0, err = '', hardFail = false, deadKey = false, limMsg = '';
  const t0 = Date.now();
  const MADE_MX = conf.radad !== false ? 3 : 8;
  while (done < parts.length && Date.now() - t0 < 22000 && made < MADE_MX && used < cap) {
    const idxs = []; for (let k = 0; k < par && done + k < parts.length && made + k < MADE_MX; k++) idxs.push(done + k);
    const res = await Promise.allSettled(idxs.map(async (p) => {
      const txt = ch.text.slice(parts[p][0], parts[p][1]).trim();
      const o = await speakPart(env, prov, txt, conf, ch.text.slice(Math.max(0, parts[p][0] - 600), parts[p][0]), ch.nid);
      await env.TTS_BUCKET.put('c/' + ch.id + '/' + p + '.wav', o.wav, { httpMetadata: { contentType: 'audio/wav' } });
      return { secs: Math.max(0, o.wav.length - 44) / 48000, chars: o.chars, calls: o.calls };
    }));
    let prefix = true, limited = false;
    for (let k = 0; k < res.length; k++) {
      const x = res[k];
      if (x.status === 'fulfilled') {
        used += x.value.secs; secsTot += prefix ? x.value.secs : 0; made++;
        await ttsBump(env, prov, { reqs: x.value.calls || 1, chars: x.value.chars, secs: x.value.secs, cost: prov === 'azure' ? x.value.chars * conf.az.price / 1e6 : ttsCost(x.value.chars, x.value.secs, conf) });
        if (prefix) done++;
      } else {
        prefix = false; const e = x.reason || {};
        if (e.code === 429) { limited = true; limMsg = e.detail || limMsg; }
        else if (e.code === 401 || /^gemini_(401|403)$/.test(String(e.message))) { deadKey = true; err = 'key_dead'; } // مفتاح مرفوض / مشروع جوجل اتوقّف
        else { err = String(e.message || 'error').slice(0, 100); hardFail = true; }
      }
    }
    if (limited) {
      const cs = await getSetting(env, key), strikes = (cs.strikeAt && Date.now() - cs.strikeAt < 3600000 ? (cs.strikes || 0) : 0) + 1, daily = /PerDay|per day|daily/i.test(limMsg), wait = 30; // زي الأول: لو جوجل رفض، نستنى نص ساعة ونبعت الفصل تاني
      await setSetting(env, key, { ...cs, strikes, strikeAt: Date.now(), pausedUntil: Date.now() + wait * 60000, exhaustedAt: Date.now(), limMsg, limDaily: daily });
      await ttsBump(env, prov, { limited: 1 });
      await ttsAlertAdmins(env, '⚠️ تحويل الصوت وقف (' + PNAME[prov] + '): الحصة خلصت أو الطلبات كتيرة', PNAME[prov] + ' رفضت طلبات الصوت (429). التحويل واقف شوية وهيكمّل لوحده. راجع حصتك أو فعّل الفوترة.', prov);
      err = 'limit'; break;
    }
    if (deadKey) { // المفتاح مرفوض: نوقف الحساب ده 6 ساعات (من غير ما نحسبها محاولة فاشلة على الفصل) ورواياته اللي لسه ما بدأتش تتوزع على الحسابات التانية
      const cs = await getSetting(env, key);
      await setSetting(env, key, { ...cs, pausedUntil: Date.now() + 6 * 3600000, exhaustedAt: Date.now(), limMsg: 'المفتاح مرفوض أو مشروع جوجل اتوقّف — غيّر المفتاح من تاب الحساب', limDaily: false, dead: true });
      await ttsBump(env, prov, { fails: 1 });
      await ttsAlertAdmins(env, '🚫 مفتاح ' + PNAME[prov] + ' مرفوض', 'جوجل رفضت المفتاح (403/401) — غالبًا المشروع اتوقّف أو المفتاح اتلغى. وقفنا الحساب ده 6 ساعات وهنوزّع رواياته اللي لسه ما بدأتش على الحسابات التانية. غيّر المفتاح من تاب الحساب في إعدادات الصوت.', prov).catch(() => {});
      break;
    }
    if (hardFail) { await ttsBump(env, prov, { fails: 1 }); break; }
  }
  const complete = done >= parts.length, tries = ch.attempts + (hardFail ? 1 : 0);
  const status = complete ? 'done' : (hardFail && tries >= 5 ? 'failed' : 'queued');
  await env.DB.prepare("UPDATE tts_ch SET status=?,owner='',lock_until=0,done=?,secs=?,attempts=?,err=?,retry_at=?,updated=? WHERE id=?")
    .bind(status, done, secsTot, hardFail ? tries : (made ? 0 : ch.attempts), complete ? '' : err, hardFail ? Date.now() + 60000 : 0, Date.now(), ch.id).run();
  return { ok: true, id: ch.id, prov, done, total: parts.length, status, made, limit: limMsg };
}
async function ttsStats(env) {
  const conf = await getTtsConf(env), d = dayKey(), mo = d.slice(0, 7), pr = ttsPrices(conf);
  const sum = async (prov, where, ...a) => env.DB.prepare('SELECT COALESCE(SUM(reqs),0) AS reqs,COALESCE(SUM(chars),0) AS chars,COALESCE(SUM(secs),0) AS secs,COALESCE(SUM(cost),0) AS cost,COALESCE(SUM(fails),0) AS fails,COALESCE(SUM(limited),0) AS limited FROM tts_use WHERE prov=? AND ' + where).bind(prov, ...a).first();
  const { results: novels } = await env.DB.prepare("SELECT nid,MAX(ntitle) AS title,MIN(ord) AS ord,MAX(prov) AS prov,COUNT(*) AS n,SUM(status='done') AS d,SUM(CASE WHEN status='running' AND lock_until>"+Date.now()+" THEN 1 ELSE 0 END) AS run,SUM(LENGTH(text)) AS chars,SUM(CASE WHEN status='done' THEN 0 ELSE LENGTH(text)*(1.0-done*1.0/(CASE WHEN nparts<1 THEN 1 ELSE nparts END)) END) AS rem FROM tts_ch GROUP BY nid ORDER BY MIN(ord),nid LIMIT 120").all();
  const q = await env.DB.prepare('SELECT prov,status,COUNT(*) AS n FROM tts_ch GROUP BY prov,status').all();
  const out = { conf, hasBucket: !!env.TTS_BUCKET, has: { ...Object.fromEntries(PROVS.filter(isGoogle).map((p) => [p, !!gemKey(env, p)])), azure: !!(env.AZURE_SPEECH_KEY && azRegion(env, conf)), azureKey: !!env.AZURE_SPEECH_KEY, azureRegion: azRegion(env, conf) }, prov: {}, nkeys: Object.fromEntries(PROVS.filter(isGoogle).map((p) => [p, gKeyList({ GEMINI_API_KEY: gemKey(env, p) }).length])), keys: Object.fromEntries(Object.entries(await savedKeys(env)).map(([p, v]) => [p, v ? 'app' : ''])), prices: pr,
    chapters: { queued: 0, running: 0, done: 0, failed: 0 }, novels: novels.map((r) => ({ nid: r.nid, title: r.title, ord: r.ord, prov: r.prov, n: r.n, d: r.d || 0, run: r.run || 0, rem: Math.round(r.rem || 0) })) };
  q.results.forEach((r) => (out.chapters[r.status] = (out.chapters[r.status] || 0) + r.n));
  out.hasKey = out.has.gemini;
  for (const prov of PROVS) {
    const st = await getSetting(env, stKey(prov)), today = await sum(prov, 'day=?', d), month = await sum(prov, 'day LIKE ?', mo + '%');
    const ch = { queued: 0, running: 0, done: 0, failed: 0 }; q.results.filter((r) => r.prov === prov).forEach((r) => (ch[r.status] = r.n));
    const remChars = Math.round(novels.filter((r) => r.prov === prov).reduce((a, r) => a + (r.rem || 0), 0)), remSecs = remChars / CPS;
    const cap = provCapE(env, conf, prov) * 60;
    const o = { last: await getSetting(env, 'tts_last_' + prov), today, month, chapters: ch, pausedUntil: st.pausedUntil || 0, limMsg: st.limMsg || '', limDaily: !!st.limDaily, exhaustedAt: st.exhaustedAt || 0, dailyMin: cap / 60, usedTodayPct: cap ? Math.min(999, Math.round(today.secs / cap * 100)) : 100 };
    if (prov === 'azure') {
      o.freeChars = conf.az.freeChars; o.monthPct = conf.az.freeChars ? Math.min(999, Math.round(month.chars / conf.az.freeChars * 100)) : null; o.extraCostMonth = Math.max(0, month.chars - conf.az.freeChars) * conf.az.price / 1e6;
      o.remain = { chars: remChars, mins: Math.round(remSecs / 60), cost: remChars * conf.az.price / 1e6, days: cap ? Math.ceil(remSecs / cap) : null };
    } else {
      const fm = gcf(conf, prov).freeMin, freeSecs = fm * 60, extraSecs = Math.max(0, today.secs - freeSecs);
      o.freeMin = fm; o.freeUsedPct = freeSecs ? Math.min(999, Math.round(today.secs / freeSecs * 100)) : null; o.extraCostToday = freeSecs ? (extraSecs * 25 * pr.outP) / 1e6 : null;
      o.remain = { chars: remChars, mins: Math.round(remSecs / 60), cost: ttsCost(remChars, remSecs, conf), days: cap ? Math.ceil(remSecs / cap) : null };
    }
    out.prov[prov] = o;
  }
  return out;
}


/* ---------- كبار الداعمين + سلسلة الأيام + تنبيهات نزول الفصول ---------- */
const FAN_TIERS = [[100, 'big', 'من كبار الداعمين', '💎'], [50, 'pro', 'داعم مميز', '🔥'], [20, 'fan', 'داعم', '🌟']];
let FANS_CACHE = { t: 0, v: null };
async function fanScores(env) { // نقاط كل قارئ عند كل كاتب: شراء روايات + تقييم وتعليق على الفصول. محسوبة من الداتا نفسها فتفضل ثابتة على الحساب
  if (FANS_CACHE.v && Date.now() - FANS_CACHE.t < 60000) return FANS_CACHE.v;
  const OWN = await ownerId(env), nidAuthor = {};
  const { results: nv } = await env.DB.prepare('SELECT id,user_id,l_extra,d_extra FROM novels').all();
  for (const r of nv) { nidAuthor['u' + r.id] = r.user_id; const s = extraOf(r.l_extra).siteId || extraOf(r.d_extra).siteId; if (s) nidAuthor[s] = r.user_id; }
  const authorOf = (nid) => (nidAuthor[nid] != null ? nidAuthor[nid] : OWN);
  const { results: vt } = await env.DB.prepare('SELECT voter AS uid, nid, COUNT(*) AS n FROM pts_votes GROUP BY voter, nid').all();
  const { results: both } = await env.DB.prepare('SELECT v.voter AS uid, v.nid AS nid, COUNT(DISTINCT v.ch) AS n FROM pts_votes v JOIN cmt_log c ON c.uid=v.voter AND c.nid=v.nid AND c.ch=v.ch AND c.elig=1 GROUP BY v.voter, v.nid').all();
  const { results: pu } = await env.DB.prepare('SELECT user_id AS uid, nid FROM purchases').all();
  const S = {}, add = (a, u, v) => { if (a === u) return; (S[a] = S[a] || {})[u] = ((S[a] || {})[u] || 0) + v; };
  const bothMap = {}; for (const r of both) bothMap[r.uid + '|' + r.nid] = r.n;
  for (const r of vt) { const b = bothMap[r.uid + '|' + r.nid] || 0; add(authorOf(r.nid), r.uid, b * 2 + (r.n - b) * 0.5); }
  for (const r of pu) add(authorOf(r.nid), r.uid, 40);
  FANS_CACHE = { t: Date.now(), v: S, own: OWN };
  return S;
}
const fanTier = (score, rank) => (rank === 1 && score >= 20 ? { tier: 'top', label: 'الداعم الأول', ic: '👑' } : (() => { for (const [min, tier, label, ic] of FAN_TIERS) if (score >= min) return { tier, label, ic }; return null; })());
async function fansOf(env, author) {
  const S = await fanScores(env), a = author > 0 ? author : (FANS_CACHE.own || 0), row = S[a] || {};
  const top = Object.keys(row).map((u) => ({ uid: +u, score: Math.round(row[u] * 10) / 10 })).filter((x) => x.score >= 20).sort((x, y) => y.score - x.score || x.uid - y.uid).slice(0, 150);
  if (!top.length) return [];
  const { results: us } = await env.DB.prepare('SELECT id,name FROM users WHERE id IN (' + top.map(() => '?').join(',') + ')').bind(...top.map((x) => x.uid)).all();
  const nm = {}; us.forEach((u) => { nm[u.id] = u.name; });
  return top.map((x, i) => ({ uid: x.uid, name: nm[x.uid] || '', score: x.score, rank: i + 1, ...fanTier(x.score, i + 1) })).filter((x) => x.tier && x.name);
}
async function goldConf(env) { const c = await getSetting(env, 'gold'); const n = (v, d, a, z) => { v = Number(v); return Number.isFinite(v) ? Math.max(a, Math.min(z, v)) : d; }; return { rate: n(c.rate, 10, 0.01, 100000), min: n(c.min, 50, 0, 1000000) }; }
const egpOf = (pts, rate) => Math.floor((pts / rate) * 100 + 1e-9) / 100;
async function streakConf(env) { const c = await getSetting(env, 'streak'); const n = (v, d, a, z) => { v = Number(v); return Number.isFinite(v) ? Math.max(a, Math.min(z, v)) : d; }; return { on: c.on !== false, days: Math.round(n(c.days, 7, 2, 60)), pts: 2 }; }
async function streakCheckin(env, uid) {
  const sc = await streakConf(env), today = cairoDay(), yest = new Date(Date.parse(today + 'T00:00:00Z') - DAYMS).toISOString().slice(0, 10);
  const r = await env.DB.prepare('SELECT last,cur,awards FROM streaks WHERE uid=?').bind(uid).first();
  if (!sc.on) return { on: false, cur: r ? r.cur : 0, days: sc.days, pts: sc.pts, awarded: 0 };
  if (r && r.last === today) return { on: true, cur: r.cur || 0, days: sc.days, pts: sc.pts, awarded: 0, today: true, shown: r.cur || sc.days };
  let cur = r && r.last === yest ? r.cur + 1 : 1, awarded = 0, awards = r ? r.awards : 0;
  const shown = cur; if (cur >= sc.days) { awarded = sc.pts * (await walMult(env, uid)); awards++; cur = 0; }
  let ok;
  if (r) { const u = await env.DB.prepare('UPDATE streaks SET last=?,cur=?,awards=? WHERE uid=? AND last<>?').bind(today, cur, awards, uid, today).run(); ok = !!(u && u.meta && u.meta.changes); }
  else { const u = await env.DB.prepare('INSERT OR IGNORE INTO streaks (uid,last,cur,awards) VALUES (?,?,?,?)').bind(uid, today, cur, awards).run(); ok = !!(u && u.meta && u.meta.changes); }
  if (!ok) return { on: true, cur: r ? r.cur : 0, days: sc.days, pts: sc.pts, awarded: 0, today: true };
  if (awarded > 0) await env.DB.prepare('UPDATE users SET wallet=ROUND(wallet+?,1) WHERE id=?').bind(awarded, uid).run();
  return { on: true, cur, shown, days: sc.days, pts: sc.pts, awarded, awards, today: false };
}

async function releasesTick(env) { // من الـ Cron: فصل مجدول حان ميعاده => إشعار «فصل جديد» للمتابعين (الإشعار الأول كان مؤجّل لحد ما ينزل فعلًا)
  const now = Date.now(), last = (await getSetting(env, 'rel_tick')).t || 0;
  await setSetting(env, 'rel_tick', { t: now });
  if (!last) return;
  const { results } = await env.DB.prepare("SELECT n.id,n.user_id,n.l_title,n.l_extra,u.name,u.role FROM novels n JOIN users u ON u.id=n.user_id WHERE n.is_live=1 AND n.l_extra LIKE '%\"rel\"%'").all();
  for (const r of results) {
    const rel = extraOf(r.l_extra).rel; let hit = -1; rel.forEach((v, i) => { if (v > last && v <= now && i > hit) hit = i; });
    if (hit < 0) continue;
    await env.DB.prepare('INSERT INTO events (author_id,kind,novel_id,title,ts) VALUES (?,?,?,?,?)').bind(r.user_id, 'chapter', r.id, r.l_title, now).run();
    if (env.FCM_SA) { const c = await env.DB.prepare("SELECT title FROM chapters WHERE novel_id=? AND ver='l' AND idx=?").bind(r.id, hit).first(); await sendPush(env, 'فصل جديد من ' + r.name, '«' + r.l_title + '»' + (c ? ' — ' + c.title : ''), '', r.role === 'admin' ? 'all' : 'a_' + r.user_id); }
  }
}
async function alertsTick(env) { // من الـ Cron: لما يحين ميعاد فصل مجدول يتبعت إشعار لكل اللي ضغطوا «نبهني»
  const now = Date.now(), { results } = await env.DB.prepare('SELECT uid,nid,ch,title FROM ch_alerts WHERE sent=0 AND rel>0 AND rel<=? LIMIT 300').bind(now).all();
  for (const a of results) {
    const up = await env.DB.prepare('UPDATE ch_alerts SET sent=1 WHERE uid=? AND nid=? AND ch=? AND sent=0').bind(a.uid, a.nid, a.ch).run();
    if (up && up.meta && up.meta.changes) await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(a.uid, 'release', a.nid, '', a.title || 'فصل جديد', 'الفصل اللي كنت مستنيه نزل دلوقتي 🎉 اقرأه الآن', now).run();
  }
  await env.DB.prepare('DELETE FROM ch_alerts WHERE sent=1 AND rel<?').bind(now - 30 * 86400000).run();
}

/* ---------- المسابقة الأسبوعية + نقاط الكتّاب + قرعة نقاط الفوز ---------- */
const DAYMS = 86400000, PT_PER_VOTE = 0.1;
const cairoDay = () => new Date(Date.now() + 2 * 3600000).toISOString().slice(0, 10);
const cairoDayStart = () => Date.parse(cairoDay() + 'T00:00:00Z') - 2 * 3600000;
async function cmtConf(env) { const c = await getSetting(env, 'cmt'); const n = (v, d, a, z) => { v = Number(v); return Number.isFinite(v) ? Math.max(a, Math.min(z, v)) : d; }; return { perCh: n(c.perCh, 2, 0, 50), perDay: n(c.perDay, 5, 0, 500), pts: n(c.pts, 1, 0, 1000), minLen: n(c.minLen, 15, 3, 500), dayPts: n(c.dayPts, 5, 0, 500), newsPerDay: n(c.newsPerDay, 1, 0, 20) }; }
const normTxt = (t) => String(t).toLowerCase().replace(/[\u064B-\u065F\u0670\u0640]/g, '').replace(/[أإآ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه').replace(/[^\p{L}\p{N}\s]/gu, ' ').replace(/\s+/g, ' ').trim();
const jacc = (a, b) => { const x = new Set(a.split(' ')), y = new Set(b.split(' ')); let i = 0; x.forEach((w) => { if (y.has(w)) i++; }); const u = x.size + y.size - i; return u ? i / u : 0; };
const fnv = (t) => { let h = 2166136261; for (let i = 0; i < t.length; i++) { h ^= t.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0).toString(36); };
const WAL_PT = 0.1, WAL_DAY = 3; // كل تقييم/تعليق = 0.1 نقطة، وبحد أقصى 3 مرات في اليوم (تعليق + تصويت مع بعض)
async function walMult(env, uid) { const u = await env.DB.prepare('SELECT role,premium_until FROM users WHERE id=?').bind(uid).first(); return isPremium(u) ? 2 : 1; }
async function walAward(env, uid, kind, ref) { // مصدر النقاط الوحيد للقارئ: vote / comment (+ streak لوحده)
  const day = cairoDay();
  const got = await env.DB.prepare("SELECT COUNT(*) AS n FROM wal_log WHERE uid=? AND day=? AND kind IN ('vote','comment')").bind(uid, day).first();
  if ((got && got.n) >= WAL_DAY) return 0;
  const amt = Math.round(WAL_PT * (await walMult(env, uid)) * 10) / 10;
  const r = await env.DB.prepare('INSERT OR IGNORE INTO wal_log (uid,day,kind,ref,amt,ts) VALUES (?,?,?,?,?,?)').bind(uid, day, kind, String(ref), amt, Date.now()).run();
  if (r && r.meta && r.meta.changes) { await env.DB.prepare('UPDATE users SET wallet=ROUND(wallet+?,1) WHERE id=?').bind(amt, uid).run(); return amt; }
  return 0;
}
async function awardCmt(env, uid, logId) {
  const r = await env.DB.prepare('UPDATE cmt_log SET awarded=1 WHERE id=? AND awarded=0').bind(logId).run();
  if (!(r && r.meta && r.meta.changes)) return 0;
  const p = await walAward(env, uid, 'comment', logId);
  if (!p) await env.DB.prepare('UPDATE cmt_log SET awarded=0 WHERE id=?').bind(logId).run();
  return p;
}
function weekStart(t = Date.now()) { // أول يوم في الأسبوع = السبت (بتوقيت مصر تقريبًا)
  const d = new Date(t + 2 * 3600000), back = (d.getUTCDay() + 1) % 7;
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - back * DAYMS).toISOString().slice(0, 10);
}
const weekEndMs = (w) => Date.parse(w + 'T00:00:00Z') - 2 * 3600000 + 7 * DAYMS;
const cleanQs = (a) => (Array.isArray(a) ? a : []).map((q) => str(q, 400).trim()).filter(Boolean).slice(0, 5);
const winnerOut = (r) => (r ? { id: r.winner_id, name: r.name, avatar: r.avatar || '', prize: r.prize, week: r.week, pickedAt: r.picked_at } : null);
async function contestPublic(env, me) {
  const cur = weekStart(), row = await env.DB.prepare('SELECT * FROM contest_weeks WHERE week=?').bind(cur).first();
  const qs = row ? parseJson(row.questions) : [], questions = Array.isArray(qs) ? qs : [];
  const { results } = await env.DB.prepare('SELECT w.week,w.prize,w.winner_id,w.picked_at,u.name,u.avatar FROM contest_weeks w JOIN users u ON u.id=w.winner_id WHERE w.winner_id>0 ORDER BY w.week DESC LIMIT 8').all();
  let mine = null;
  if (me) { const a = await env.DB.prepare('SELECT answers,ts FROM contest_answers WHERE week=? AND user_id=?').bind(cur, me.id).first(); if (a) mine = { answers: parseJson(a.answers), ts: a.ts }; }
  const latest = results[0] || null;
  return { week: cur, endsAt: weekEndMs(cur), questions, prize: row ? row.prize : 0, closed: !!(row && row.winner_id > 0), answered: !!mine, mine,
    winner: winnerOut(latest), thisWeekWinner: !!(latest && latest.week === cur), history: results.slice(1).map(winnerOut) };
}
async function pointsPublic(env, me) {
  const cur = weekStart(), pts = await getSetting(env, 'pts');
  const { results: top } = await env.DB.prepare("SELECT id,name,avatar,points FROM users WHERE points>0 ORDER BY points DESC,id ASC LIMIT 10").all();
  const { results: draws } = await env.DB.prepare('SELECT week,user_id AS winner_id,name,avatar,points,prize,ts AS picked_at FROM pts_draws WHERE user_id>0 ORDER BY week DESC LIMIT 8').all();
  const d = draws[0] || null;
  return { week: cur, prize: pts.prize || 0, endsAt: weekEndMs(cur), top: top.map((u) => ({ id: u.id, name: u.name, avatar: u.avatar || '', points: u.points })), latest: d, thisWeek: !!(d && d.week === cur), history: draws.slice(1),
    me: me ? { points: (await env.DB.prepare('SELECT points FROM users WHERE id=?').bind(me.id).first() || {}).points || 0 } : null };
}
const randInt = (n) => { const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % n; };
async function ptsDraw(env, force) { // بيختار واحد عشوائي من أعلى 10 حسابات نقاط
  const pts = await getSetting(env, 'pts'), cur = weekStart();
  if (!force && !(pts.prize > 0)) return { ok: false, idle: 'no_prize' };
  const { results } = await env.DB.prepare("SELECT id,name,avatar,points FROM users WHERE points>0 ORDER BY points DESC,id ASC LIMIT 10").all();
  if (!results.length) { if (!force) await env.DB.prepare('INSERT OR IGNORE INTO pts_draws (week,user_id,name,avatar,points,prize,ts) VALUES (?,?,?,?,?,?,?)').bind(cur, 0, '', '', 0, pts.prize || 0, Date.now()).run(); return { ok: false, idle: 'no_candidates' }; }
  const w = results[randInt(results.length)];
  await env.DB.prepare('INSERT OR REPLACE INTO pts_draws (week,user_id,name,avatar,points,prize,ts) VALUES (?,?,?,?,?,?,?)').bind(cur, w.id, w.name, w.avatar || '', w.points, pts.prize || 0, Date.now()).run();
  await notifyUser(env, w.id, '🏆 مبروك! فزت في نقاط الفوز', 'اتختارت الأسبوع ده من أعلى 10 كتّاب بالنقاط وفزت بـ ' + (pts.prize || 0) + ' جنيه. الإدارة هتتواصل معاك.', 'pay');
  return { ok: true, winner: { id: w.id, name: w.name }, week: cur };
}
async function ptsTick(env) { // من الـ Cron: قرعة أول كل أسبوع + تصفير نقاط الكتّاب لبداية منافسة جديدة (نقاط القرّاء "wallet" ما بتتصفّرش)
  const pts = await getSetting(env, 'pts'), cur = weekStart();
  if (!pts.start) { await setSetting(env, 'pts', { ...pts, start: cur, rw: cur }); return; }
  if (!pts.rw) { await setSetting(env, 'pts', { ...pts, rw: cur }); return; }
  if (pts.rw === cur) return;
  if (cur > pts.start && !(await env.DB.prepare('SELECT 1 FROM pts_draws WHERE week=?').bind(cur).first())) await ptsDraw(env, false);
  await env.DB.prepare('UPDATE users SET points=0 WHERE points<>0').run();
  await setSetting(env, 'pts', { ...(await getSetting(env, 'pts')), rw: cur });
}

/* ---------- إشعارات الموبايل (Firebase Cloud Messaging) ---------- */
async function fcmAccessToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claim = b64u(enc.encode(JSON.stringify({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/firebase.messaging', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3300 })));
  const pem = String(sa.private_key).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const key = await crypto.subtle.importKey('pkcs8', unb64(pem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = b64u(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(head + '.' + claim)));
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + head + '.' + claim + '.' + sig });
  const j = await r.json();
  if (!j.access_token) throw new Error('فشل الاتصال بـ Firebase: ' + (j.error_description || j.error || ''));
  return j.access_token;
}
async function sendPush(env, title, text, link, topic) {
  if (!env.FCM_SA) throw new Error('إشعارات الموبايل مش متفعّلة لسه (محتاجة ملف Firebase — راجع الشرح)');
  let sa; try { sa = JSON.parse(env.FCM_SA); } catch (e) { throw new Error('ملف Firebase المحفوظ غير صحيح'); }
  const token = await fcmAccessToken(sa);
  const msg = { message: { topic: topic || 'all', notification: { title: title || 'RadPad', body: text || '' }, data: { url: link || '' }, android: { priority: 'HIGH', notification: { channel_id: 'radpad_alerts', sound: 'default' } } } };
  const r = await fetch('https://fcm.googleapis.com/v1/projects/' + sa.project_id + '/messages:send', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify(msg) });
  if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error('رفض Firebase الإرسال: ' + ((j.error && j.error.message) || r.status)); }
}

/* ---------- الراوتر ---------- */
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    try { await ensureSchema(env); if (new URL(request.url).pathname.startsWith('/api/admin/tts')) env = await withKeys(env); return await route(request, env); }
    catch (e) { return fail(e && e.message ? e.message : 'خطأ غير متوقع', e && e.status ? e.status : 400); }
  },
  // كل دقيقة: يكمّل تحويل الفصول في الطابور (بحد يومي)
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => { try { await ensureSchema(env); env = await withKeys(env); try { await ptsTick(env); } catch (e) {} try { await alertsTick(env); } catch (e) {} try { await releasesTick(env); } catch (e) {} try { await env.DB.prepare('DELETE FROM sessions WHERE seen<?').bind(Date.now() - 40 * 86400000).run(); } catch (e) {} try { await env.DB.prepare('DELETE FROM notes WHERE ts<?').bind(Date.now() - 30 * 86400000).run(); } catch (e) {} try { await env.DB.prepare('DELETE FROM visits WHERE day<?').bind(dayKey(Date.now() - 45 * 86400000)).run(); await env.DB.prepare('DELETE FROM presence WHERE seen<?').bind(Date.now() - 2 * 86400000).run(); } catch (e) {} if (await ttsMigrate(env)) { try { await ttsRebalance(env); } catch (e) {} await Promise.all(PROVS.map((p) => ttsStep(env, { prov: p }).catch(() => {}))); } } catch (e) {} })());
  }
};

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const m = request.method;
  const ip = request.headers.get('CF-Connecting-IP') || 'x';
  let g;

  if (path === '/' || path === '/api') return json({ ok: true, name: 'RadPad API' });

  /* ----- حسابات ----- */
  if (path === '/api/register' && m === 'POST') {
    if (await tooMany(env, 'reg:' + ip, 8, 3600000)) return fail('محاولات كتير، جرّب بعد شوية', 429);
    const b = await body(request);
    const email = str(b.email, 120).trim().toLowerCase(), name = str(b.name, 40).trim(), pass = String(b.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return fail('الإيميل غير صحيح');
    if (name.length < 2) return fail('اكتب اسمك (حرفين على الأقل)');
    if (pass.length < 8 || pass.length > 100) return fail('الباسورد لازم يكون 8 حروف أو أكتر');
    const dev = devOf(request);
    if (dev && (await env.DB.prepare('SELECT COUNT(*) AS n FROM dev_accts WHERE dev=?').bind(dev).first()).n >= MAX_DEV_ACCTS) return fail('أنت تمتلك الآن حسابين، لا يمكنك عمل حساب آخر', 403);
    if (await env.DB.prepare('SELECT 1 FROM users WHERE email=?').bind(email).first()) return fail('الإيميل ده مسجّل قبل كده');
    await noteAttempt(env, 'reg:' + ip);
    const count = (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n;
    const role = count === 0 ? 'admin' : 'user';           // أول حساب = الأدمن
    const r = await env.DB.prepare('INSERT INTO users (email,name,pass_hash,role,created_at) VALUES (?,?,?,?,?)')
      .bind(email, name, await hashPassword(pass), role, Date.now()).run();
    const id = r.meta.last_row_id;
    if (dev) { await env.DB.prepare('INSERT OR IGNORE INTO dev_accts (dev,uid,ts) VALUES (?,?,?)').bind(dev, id, Date.now()).run(); await devEnter(env, { id, role, premium_until: 0 }, dev); }
    return json({ token: await makeToken(env, id), user: await withOwner(env, userOut({ id, email, name, role, premium_until: 0 })) });
  }
  if (path === '/api/login' && m === 'POST') {
    const b = await body(request);
    const email = str(b.email, 120).trim().toLowerCase();
    const key = 'login:' + email + ':' + ip;
    if (await tooMany(env, key, 10, 900000)) return fail('محاولات كتير، استنى ربع ساعة وجرّب تاني', 429);
    const u = await env.DB.prepare('SELECT id,email,name,role,pass_hash,premium_until,avatar,bio,links FROM users WHERE email=?').bind(email).first();
    if (!u || !(await checkPassword(String(b.password || ''), u.pass_hash))) { await noteAttempt(env, key); return fail('الإيميل أو الباسورد غلط', 401); }
    if (!(await devEnter(env, u, devOf(request)))) return fail(devBlockMsg(u), 403);
    return json({ token: await makeToken(env, u.id), user: await withOwner(env, userOut(u)) });
  }

  /* ----- عام: الروايات المعتمدة ----- */
  if (path === '/api/novels' && m === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT n.id,n.user_id,n.l_title,n.l_author,n.l_genre,n.l_tags,n.l_synopsis,n.l_cover,n.l_extra,n.published_at,u.name AS owner
       FROM novels n JOIN users u ON u.id=n.user_id WHERE n.is_live=1 AND n.hidden=0 ORDER BY n.published_at DESC LIMIT 500`).all();
    const chs = (await env.DB.prepare(
      `SELECT c.novel_id,c.idx,c.title,c.locked FROM chapters c JOIN novels n ON n.id=c.novel_id WHERE n.is_live=1 AND n.hidden=0 AND c.ver='l' ORDER BY c.novel_id,c.idx`).all()).results;
    const byNovel = {};
    const chapLocked = {};
    chs.forEach((c) => { (byNovel[c.novel_id] = byNovel[c.novel_id] || []).push({ title: c.title, locked: !!c.locked }); if (c.locked) chapLocked[c.novel_id] = true; });
    return json({ novels: results.map((r) => {
      const x = extraOf(r.l_extra);
      return { id: r.id, title: r.l_title, subtitle: x.subtitle, author: r.l_author || r.owner, genre: r.l_genre, tags: parseTags(r.l_tags),
        synopsis: r.l_synopsis, cover: r.l_cover, novelStatus: x.novelStatus, promoUrl: x.promoUrl, pdfUrl: x.pdfUrl, grad: x.grad, icon: x.icon, allowSharing: x.allowSharing, paper: !!x.paper, price: x.price, oldPrice: x.oldPrice, locked: !!(x.lockAll && x.password), pdfLocked: !!(x.password && x.lockPdf && (x.lockAll || chapLocked[r.id])),
        publishedAt: r.published_at, owner: r.owner, uid: r.user_id, chapters: (byNovel[r.id] || []).map((c, i) => (x.rel[i] ? { ...c, release: x.rel[i] } : c)) };
    }) }, 200, { 'Cache-Control': 'public, max-age=60' });
  }
  if ((g = /^\/api\/novels\/(\d+)\/unlock$/.exec(path)) && m === 'POST') {
    const id = +g[1], key = 'unl:' + ip + ':' + id;
    if (await tooMany(env, key, 10, 900000)) return fail('محاولات كتير، استنى شوية وجرّب تاني', 429);
    const b = await body(request);
    const n = await env.DB.prepare('SELECT l_extra FROM novels WHERE id=? AND is_live=1 AND hidden=0').bind(id).first();
    if (!n) return fail('الرواية غير موجودة', 404);
    const x = extraOf(n.l_extra);
    if (!x.password || !safeEqual(String(b.password || '').trim(), x.password)) { await noteAttempt(env, key); return fail('الباسورد غلط', 401); }
    return json({ token: await makeUnlock(env, id) });
  }
  if ((g = /^\/api\/novels\/(\d+)\/chapters\/(\d+)$/.exec(path)) && m === 'GET') {
    const n = await env.DB.prepare('SELECT l_extra FROM novels WHERE id=? AND is_live=1 AND hidden=0').bind(+g[1]).first();
    if (!n) return fail('الفصل غير موجود', 404);
    const c = await env.DB.prepare(`SELECT title,content,locked FROM chapters WHERE novel_id=? AND ver='l' AND idx=?`).bind(+g[1], +g[2]).first();
    if (!c) return fail('الفصل غير موجود', 404);
    const x = extraOf(n.l_extra);
    if (x.password && (x.lockAll || c.locked) && !(await hasUnlock(env, request, +g[1]))) return fail('الفصل مقفول — اكتب الباسورد', 403);
    const relAt = x.rel[+g[2]] || 0; if (relAt > Date.now()) return json({ error: 'الفصل ده لسه ما نزلش', sched: relAt }, 403);
    const locked = !!(x.password && (x.lockAll || c.locked));
    return json({ title: c.title, content: c.content }, 200, { 'Cache-Control': locked ? 'private, no-store' : 'public, max-age=300' });
  }
  if ((g = /^\/api\/novels\/(\d+)\/full$/.exec(path)) && m === 'GET') {
    const n = await env.DB.prepare('SELECT l_extra FROM novels WHERE id=? AND is_live=1 AND hidden=0').bind(+g[1]).first();
    if (!n) return fail('الرواية غير موجودة', 404);
    const x = extraOf(n.l_extra);
    const open = !x.password || await hasUnlock(env, request, +g[1]);
    const { results } = await env.DB.prepare("SELECT title,content,locked FROM chapters WHERE novel_id=? AND ver='l' ORDER BY idx").bind(+g[1]).all();
    const nowT = Date.now(); const chapters = results.map((c, i) => { const rel = x.rel[i] || 0, sched = rel > nowT; const o = (!sched && (open || !(x.lockAll || c.locked))) ? { title: c.title, content: c.content } : { title: c.title, content: '', locked: true }; if (rel) o.release = rel; return o; });
    return json({ chapters }, 200, { 'Cache-Control': x.password ? 'private, no-store' : 'public, max-age=300' });
  }

  if (path === '/api/reads' && m === 'GET') {
    const { results } = await env.DB.prepare('SELECT k,n FROM reads ORDER BY n DESC LIMIT 1000').all();
    const o = {}; results.forEach((r) => { o[r.k] = r.n; });
    return json({ reads: o, epoch: ((await getSetting(env, 'reads_epoch')) || {}).t || 0 }, 200, { 'Cache-Control': 'public, max-age=20' });
  }
  if (path === '/api/reads' && m === 'POST') {
    const b = await body(request, 2000), k = str(b.k, 60), ch = Number.isInteger(+b.ch) ? Math.max(0, Math.min(9999, +b.ch)) : -1;
    if (!/^[A-Za-z0-9_-]{1,60}$/.test(k) || ch < 0) return fail('مفتاح غير صحيح');
    if (await tooMany(env, 'rdip:' + ip, 80, 3600000)) return json({ ok: true, skipped: true });
    const ins = await env.DB.prepare('INSERT OR IGNORE INTO read_seen (h,k,ch,ts) VALUES (?,?,?,?)').bind(fnv(ip), k, ch, Date.now()).run();
    if (!(ins && ins.meta && ins.meta.changes)) return json({ ok: true, dup: true });
    await noteAttempt(env, 'rdip:' + ip);
    await env.DB.prepare('INSERT INTO reads (k,n) VALUES (?,1) ON CONFLICT(k) DO UPDATE SET n=n+1').bind(k).run();
    return json({ ok: true });
  }
  if (path === '/api/authors' && m === 'GET') {
    const { results: us } = await env.DB.prepare("SELECT id,name,role,avatar,bio,links,created_at,points FROM users WHERE id=(SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1) OR id IN (SELECT user_id FROM novels WHERE is_live=1 AND hidden=0) ORDER BY id").all();
    const OWN = await ownerId(env);
    const total = (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n;
    const { results: fc } = await env.DB.prepare('SELECT author_id, COUNT(*) AS n FROM follows GROUP BY author_id').all();
    const fm = {}; for (const r of fc) fm[r.author_id] = r.n;
    return json({ authors: us.map((u) => ({ id: u.id, name: u.name, avatar: u.avatar, bio: u.bio, links: linksOf(u.links), isAdmin: u.id === OWN, joinedAt: u.created_at, points: u.points || 0, followers: u.id === OWN ? Math.max(0, total - 1) : (fm[u.id] || 0) })) }, 200, { 'Cache-Control': 'public, max-age=30' });
  }
  if ((g = /^\/api\/authors\/(\d+|admin)$/.exec(path)) && m === 'GET') {
    let aid;
    if (g[1] === 'admin') { const a = await env.DB.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").first(); if (!a) return fail('غير موجود', 404); aid = a.id; } else aid = +g[1];
    const a = await env.DB.prepare('SELECT id,name,role,avatar,bio,links,created_at,points FROM users WHERE id=?').bind(aid).first();
    if (!a) return fail('الكاتب غير موجود', 404);
    const isAdm = a.role === 'admin' && (await ownerId(env)) === a.id;
    const followers = isAdm ? Math.max(0, (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n - 1) : (await env.DB.prepare('SELECT COUNT(*) AS n FROM follows WHERE author_id=?').bind(aid).first()).n;
    const { results } = await env.DB.prepare('SELECT n.id,n.l_title,n.l_author,n.l_genre,n.l_cover,n.l_extra,n.published_at FROM novels n WHERE n.user_id=? AND n.is_live=1 AND n.hidden=0 ORDER BY n.published_at DESC').bind(aid).all();
    let me = null, following = false;
    if (request.headers.get('Authorization')) { me = await authUser(env, request); }
    if (me) following = isAdm ? me.id !== aid : !!(await env.DB.prepare('SELECT 1 FROM follows WHERE follower_id=? AND author_id=?').bind(me.id, aid).first());
    return json({ author: { id: a.id, name: a.name, bio: a.bio, links: linksOf(a.links), avatar: a.avatar, isAdmin: isAdm, joinedAt: a.created_at, points: a.points || 0, followers, following, self: !!(me && me.id === aid),
      novels: results.map((r) => { const x = extraOf(r.l_extra); return { id: r.id, title: r.l_title, author: r.l_author || a.name, genre: r.l_genre, cover: r.l_cover, grad: x.grad, icon: x.icon, locked: !!(x.lockAll && x.password), publishedAt: r.published_at }; }) } }, 200, { 'Cache-Control': 'private, no-store' });
  }
  if (path === '/api/premium-info' && m === 'GET') return json({ info: await getPremiumInfo(env) }, 200, { 'Cache-Control': 'public, max-age=30' });

  /* ----- المسابقات (عام) ----- */
  if (path === '/api/contest' && m === 'GET') { const me = request.headers.get('Authorization') ? await authUser(env, request) : null; return json(await contestPublic(env, me), 200, { 'Cache-Control': 'no-store' }); }
  if (path === '/api/fans' && m === 'GET') { const au = Math.max(0, Math.floor(+url.searchParams.get('author') || 0)); return json({ fans: await fansOf(env, au) }, 200, { 'Cache-Control': 'public, max-age=60' }); }
  if (path === '/api/points' && m === 'GET') { const me = request.headers.get('Authorization') ? await authUser(env, request) : null; return json(await pointsPublic(env, me), 200, { 'Cache-Control': 'no-store' }); }

  if (path === '/api/tts/ready' && m === 'GET') {
    const conf = await getTtsConf(env); if (conf.hideListen) return json({ hide: true, novels: {} }, 200, { 'Cache-Control': 'public, max-age=30' });
    const { results } = await env.DB.prepare("SELECT nid,SUM(status='done') AS d,COUNT(*) AS n FROM tts_ch GROUP BY nid").all();
    const novels = {}; results.forEach((r) => { if (r.d > 0) novels[r.nid] = { d: r.d, n: r.n }; });
    return json({ hide: false, open: conf.listenAll === true, novels }, 200, { 'Cache-Control': 'public, max-age=60' });
  }
  if (path === '/api/news' && m === 'GET') {
    const { results } = await env.DB.prepare("SELECT n.id,n.title,n.text,n.img,n.url,n.ts,n.author_uid AS auid,u.name AS author,u.avatar AS aavatar FROM news n LEFT JOIN users u ON u.id=n.author_uid AND n.author_uid>0 WHERE n.status='ok' ORDER BY n.ts DESC LIMIT 50").all();
    return json({ items: results }, 200, { 'Cache-Control': 'public, max-age=30' });
  }
  if (path === '/api/contact' && m === 'POST') {
    const b = await body(request, 6000);
    if (await tooMany(env, 'ct:' + ip, 5, 3600000)) return fail('بعتّ رسايل كتير، جرّب بعد شوية', 429);
    const kinds = { inquiry: 'استفسار', complaint: 'شكوى', suggestion: 'اقتراح', bug: 'مشكلة تقنية', other: 'أخرى' }, kind = kinds[b.kind] ? b.kind : 'other';
    const text = str(b.text, 1500).trim(), name = str(b.name, 60).trim(), email = str(b.email, 120).trim();
    if (text.length < 5) return fail('اكتب رسالتك (5 حروف على الأقل)');
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return fail('الإيميل غير صحيح');
    await noteAttempt(env, 'ct:' + ip);
    let uid = 0; const hm = /^Bearer (.+)$/.exec(request.headers.get('Authorization') || ''); if (hm) { try { const tp = await readToken(env, hm[1]); if (tp && tp.uid) uid = +tp.uid || 0; } catch (e) {} }
    const insC = () => env.DB.prepare('INSERT INTO contact (uid,name,email,kind,text,ts) VALUES (?,?,?,?,?,?)').bind(uid, name, email, kind, text, Date.now()).run();
    try { await insC(); } catch (e) {
      // جدول قديم/ناقص: نكمّل الأعمدة الناقصة ونعيد المحاولة
      for (const col of ["uid INTEGER NOT NULL DEFAULT 0", "name TEXT NOT NULL DEFAULT ''", "email TEXT NOT NULL DEFAULT ''", "kind TEXT NOT NULL DEFAULT ''", "text TEXT NOT NULL DEFAULT ''", "ts INTEGER NOT NULL DEFAULT 0"]) { try { await env.DB.prepare('ALTER TABLE contact ADD COLUMN ' + col).run(); } catch (e2) {} }
      try { await insC(); } catch (e3) { return fail('تعذّر حفظ الرسالة: ' + String(e3 && e3.message || e3).slice(0, 120), 500); }
    }
    try { await env.DB.prepare('DELETE FROM contact WHERE id NOT IN (SELECT id FROM contact ORDER BY ts DESC LIMIT 500)').run(); } catch (e) {}
    await notifyAdmins(env, name || 'زائر', '📨 رسالة جديدة: ' + kinds[kind], text.slice(0, 120), 'msgs');
    return json({ ok: true });
  }
  if (path === '/api/bcast' && m === 'GET') {
    const { results } = await env.DB.prepare('SELECT id,title,text,url,ts FROM bcast ORDER BY ts DESC LIMIT 60').all();
    return json({ items: results.map((r) => ({ id: 'b' + r.id, title: r.title, text: r.text, url: r.url, ts: r.ts })) }, 200, { 'Cache-Control': 'public, max-age=15' });
  }
  /* ----- حضور الزوار (أونلاين / زيارات) ----- */
  if (path === '/api/ping' && m === 'POST') {
    const dev = devOf(request); if (!dev) return json({ ok: true });
    if (await tooMany(env, 'ping:' + dev, 12, 600000) || await tooMany(env, 'pingip:' + ip, 150, 600000)) return json({ ok: true });
    await noteAttempt(env, 'ping:' + dev); await noteAttempt(env, 'pingip:' + ip);
    let uid = 0; const hm = /^Bearer (.+)$/.exec(request.headers.get('Authorization') || ''); if (hm) { try { const tp = await readToken(env, hm[1]); if (tp && tp.uid) uid = +tp.uid || 0; } catch (e) {} }
    const now = Date.now(), ipv = String(ip || '').slice(0, 64);
    try {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO presence (dev,uid,ip,seen) VALUES (?,?,?,?) ON CONFLICT(dev) DO UPDATE SET uid=excluded.uid,ip=excluded.ip,seen=excluded.seen').bind(dev, uid, ipv, now),
        env.DB.prepare('INSERT INTO visits (day,dev,uid) VALUES (?,?,?) ON CONFLICT(day,dev) DO UPDATE SET uid=CASE WHEN excluded.uid>0 THEN excluded.uid ELSE visits.uid END').bind(dayKey(now), dev, uid),
        ...(uid ? [env.DB.prepare('UPDATE users SET last_ip=?,last_seen=? WHERE id=?').bind(ipv, now, uid)] : [])]);
    } catch (e) {}
    return json({ ok: true });
  }

  /* ----- كل ما بعد كده يحتاج تسجيل دخول ----- */
  const user = await authUser(env, request);
  if (!user) return fail(devMsgs.get(request) || 'سجّل الدخول الأول', 401);
  if (path === '/api/logout' && m === 'POST') { const dv = devOf(request); if (dv) await env.DB.prepare('DELETE FROM sessions WHERE uid=? AND dev=?').bind(user.id, dv).run(); return json({ ok: true }); }
  if (path === '/api/devices' && m === 'GET') {
    const { results } = await env.DB.prepare('SELECT dev,seen,created FROM sessions WHERE uid=? AND seen>? ORDER BY seen DESC').bind(user.id, Date.now() - SESS_TTL).all(), cur = devOf(request);
    return json({ limit: user.role === 'admin' ? 0 : (isPremium(user) ? 3 : 1), devices: results.map((d) => ({ id: d.dev, seen: d.seen, created: d.created, current: d.dev === cur })) });
  }
  if (path === '/api/devices/remove' && m === 'POST') { const b = await body(request, 300), id = str(b.id, 64); await env.DB.prepare('DELETE FROM sessions WHERE uid=? AND dev=?').bind(user.id, id).run(); return json({ ok: true }); }

  if (path === '/api/contest/answer' && m === 'POST') {
    const b = await body(request, 6000), cur = weekStart(), row = await env.DB.prepare('SELECT * FROM contest_weeks WHERE week=?').bind(cur).first();
    const qs = row ? parseJson(row.questions) : [];
    if (!Array.isArray(qs) || !qs.length) return fail('أسئلة الأسبوع لسه ما نزلتش');
    if (row.winner_id > 0) return fail('المسابقة دي اتقفلت واتختار الفائز');
    if (!Array.isArray(b.answers)) return fail('اكتب إجاباتك');
    const answers = qs.map((_, i) => str(b.answers[i], 700).trim());
    if (answers.some((a) => a.length < 1)) return fail('جاوب على كل الأسئلة قبل الإرسال');
    if (await env.DB.prepare('SELECT 1 FROM contest_answers WHERE week=? AND user_id=?').bind(cur, user.id).first()) return fail('إنت جاوبت الأسبوع ده قبل كده');
    if (await tooMany(env, 'cans:' + user.id, 20, 3600000)) return fail('كتير أوي، استنى شوية');
    await noteAttempt(env, 'cans:' + user.id);
    await env.DB.prepare('INSERT INTO contest_answers (week,user_id,answers,ts) VALUES (?,?,?,?)').bind(cur, user.id, JSON.stringify(answers), Date.now()).run();
    return json({ ok: true });
  }
  if (path === '/api/me/checkin' && m === 'POST') return json({ ok: true, ...(await streakCheckin(env, user.id)) });
  if (path === '/api/me/alert' && m === 'POST') {
    const b = await body(request, 1000), nid = str(b.novel, 60), ch = Number.isInteger(+b.chapter) ? Math.max(0, Math.min(9999, +b.chapter)) : -1;
    if (!/^[A-Za-z0-9_-]{1,60}$/.test(nid) || ch < 0) return fail('فصل غير صحيح');
    if (b.on === false) { await env.DB.prepare('DELETE FROM ch_alerts WHERE uid=? AND nid=? AND ch=?').bind(user.id, nid, ch).run(); return json({ ok: true, on: false }); }
    let rel = relOf(b.release); const mm = /^u(\d+)$/.exec(nid);
    if (mm) { const nv = await env.DB.prepare('SELECT l_extra FROM novels WHERE id=? AND is_live=1').bind(+mm[1]).first(); rel = nv ? (extraOf(nv.l_extra).rel[ch] || 0) : 0; }
    if (!rel || rel <= Date.now()) return fail('الفصل ده نزل خلاص أو مش مجدول');
    if (await tooMany(env, 'alr:' + user.id, 60, 3600000)) return fail('كتير أوي، استنى شوية', 429);
    await noteAttempt(env, 'alr:' + user.id);
    await env.DB.prepare('INSERT INTO ch_alerts (uid,nid,ch,rel,title,sent) VALUES (?,?,?,?,?,0) ON CONFLICT(uid,nid,ch) DO UPDATE SET rel=excluded.rel,title=excluded.title,sent=0').bind(user.id, nid, ch, rel, str(b.title, 160)).run();
    return json({ ok: true, on: true });
  }
  if (path === '/api/me/alerts' && m === 'GET') { const { results } = await env.DB.prepare('SELECT nid,ch,rel FROM ch_alerts WHERE uid=? AND sent=0 ORDER BY rel LIMIT 200').bind(user.id).all(); return json({ alerts: results.map((a) => ({ novel: a.nid, chapter: a.ch, release: a.rel })) }); }
  if (path === '/api/me/points' && m === 'GET') { const r0 = await env.DB.prepare('SELECT points,wallet FROM users WHERE id=?').bind(user.id).first() || {}; const cf = await cmtConf(env), td = await env.DB.prepare("SELECT COUNT(*) AS n FROM wal_log WHERE uid=? AND day=? AND kind IN ('vote','comment')").bind(user.id, cairoDay()).first(), mu = await walMult(env, user.id); const sk = await env.DB.prepare('SELECT last,cur FROM streaks WHERE uid=?').bind(user.id).first(), sc0 = await streakConf(env); return json({ points: r0.points || 0, wallet: r0.wallet || 0, mult: mu, earn: { per: WAL_PT * mu, max: WAL_DAY, today: (td && td.n) || 0 }, streak: { on: sc0.on, days: sc0.days, pts: sc0.pts * mu, cur: sk ? sk.cur : 0, today: !!(sk && sk.last === cairoDay()) }, cmt: { perCh: cf.perCh, perDay: cf.perDay, today: (td && td.n) || 0, pts: cf.pts } }); }
  if (path === '/api/cmt/gate' && m === 'POST') {
    const b = await body(request, 3000), cf = await cmtConf(env), nid = str(b.novel, 60), ch = Number.isInteger(+b.chapter) ? Math.max(-1, Math.min(9999, +b.chapter)) : -1, text = str(b.text, 1000).trim();
    if (!/^[A-Za-z0-9_-]{1,60}$/.test(nid)) return fail('رواية غير صحيحة');
    if (text.length < 2) return fail('اكتب تعليق');
    const day = cairoDay(), isAdm = user.role === 'admin';
    if (!isAdm) {
      const dn = await env.DB.prepare('SELECT COUNT(*) AS n FROM cmt_log WHERE uid=? AND day=?').bind(user.id, day).first();
      if ((dn && dn.n) >= cf.perDay) return json({ ok: false, reason: 'خلّصت تعليقاتك النهارده (' + cf.perDay + ' تعليقات في اليوم) 💬 ارجع بكرة' });
      const cn = await env.DB.prepare('SELECT COUNT(*) AS n FROM cmt_log WHERE uid=? AND nid=? AND ch=?').bind(user.id, nid, ch).first();
      if ((cn && cn.n) >= cf.perCh) return json({ ok: false, reason: 'ممكن تعلّق مرتين بس على الفصل الواحد (' + cf.perCh + ')' });
    }
    const norm = normTxt(text), words = norm.split(' ').filter(Boolean);
    const { results: mine } = await env.DB.prepare('SELECT norm FROM cmt_log WHERE uid=? ORDER BY id DESC LIMIT 40').bind(user.id).all();
    if (!isAdm && mine.some((r) => r.norm === norm)) return json({ ok: false, reason: 'التعليق ده كتبته قبل كده، اكتب كلام جديد ✍️' });
    let why = '';
    if (norm.length < cf.minLen || words.length < 3) why = 'التعليق قصير — اكتب جملة تشجيع حقيقية (' + cf.minLen + ' حرف على الأقل) علشان تاخد نقطة';
    else if (/(.)\1{4,}/u.test(norm.replace(/\s/g, '')) || new Set(words).size < Math.ceil(words.length / 2)) why = 'التعليق فيه تكرار كلمات — مفيش نقطة';
    else if (mine.some((r) => jacc(r.norm, norm) >= 0.7)) why = 'التعليق شبه تعليق قديم ليك — مفيش نقطة';
    else { const x = await env.DB.prepare('SELECT 1 AS x FROM cmt_log WHERE norm=? LIMIT 1').bind(norm).first(); if (x) why = 'التعليق ده اتكتب قبل كده من حد — مفيش نقطة'; }
    const mm = /^u(\d+)$/.exec(nid); if (!why && mm) { const nv = await env.DB.prepare('SELECT user_id FROM novels WHERE id=?').bind(+mm[1]).first(); if (nv && nv.user_id === user.id) why = 'مفيش نقاط على رواياتك'; }
    const elig = why ? 0 : 1;
    const ins = await env.DB.prepare('INSERT INTO cmt_log (uid,nid,ch,norm,day,ts,elig,awarded) VALUES (?,?,?,?,?,?,?,0)').bind(user.id, nid, ch, norm, day, Date.now(), elig).run();
    let pts = 0, hint = why;
    if (elig) {
      pts = await awardCmt(env, user.id, ins.meta.last_row_id); if (!pts) hint = 'وصلت للحد اليومي للنقاط (3 مرات في اليوم)';
    }
    return json({ ok: true, points: pts, hint });
  }
  if (path === '/api/my/news' && m === 'GET') { const { results } = await env.DB.prepare('SELECT id,title,text,img,status,ts FROM news WHERE author_uid=? ORDER BY ts DESC LIMIT 30').bind(user.id).all(); return json({ items: results }); }
  if (path === '/api/my/news' && m === 'POST') {
    const b = await body(request, 6000), cf = await cmtConf(env), title = str(b.title, 120).trim(), text = str(b.text, 2000).trim();
    if (!title || text.length < 10) return fail('اكتب عنوان وتفاصيل للبوست');
    const isAdm = user.role === 'admin';
    if (!isAdm && !(await env.DB.prepare('SELECT 1 AS x FROM novels WHERE user_id=? LIMIT 1').bind(user.id).first())) return fail('النشر في الأخبار للكتّاب بس', 403);
    if (!isAdm) { const dn = await env.DB.prepare('SELECT COUNT(*) AS n FROM news WHERE author_uid=? AND ts>=?').bind(user.id, cairoDayStart()).first(); if ((dn && dn.n) >= cf.newsPerDay) return fail('ممكن تنشر ' + cf.newsPerDay + ' بوست في اليوم بس، جرّب بكرة'); }
    const st = isAdm ? 'ok' : 'pending';
    const r = await env.DB.prepare('INSERT INTO news (title,text,img,url,ts,author_uid,status) VALUES (?,?,?,?,?,?,?)').bind(title, text, cleanUrl(b.img), '', Date.now(), user.id, st).run();
    if (!isAdm) await notifyAdmins(env, user.name, '📰 بوست جديد من كاتب مستني مراجعتك', title, 'news');
    return json({ ok: true, id: r.meta.last_row_id, status: st });
  }
  if (path === '/api/me' && m === 'GET') return json({ user: await withOwner(env, userOut(user)) });
  if (path === '/api/me' && m === 'PUT') {
    const b = await body(request), name = b.name === undefined ? user.name : str(b.name, 40).trim();
    if (name.length < 2) return fail('اكتب اسمك (حرفين على الأقل)');
    const bio = b.bio === undefined ? user.bio : str(b.bio, 300).trim();
    const avatar = b.avatar === undefined ? user.avatar : cleanUrl(b.avatar);
    const links = b.links === undefined ? user.links : JSON.stringify(linksOf(b.links));
    await env.DB.prepare('UPDATE users SET name=?,bio=?,avatar=?,links=? WHERE id=?').bind(name, bio, avatar, links, user.id).run();
    return json({ user: await withOwner(env, userOut({ ...user, name, bio, avatar, links })) });
  }
  if (path === '/api/password' && m === 'PUT') {
    const b = await body(request);
    const row = await env.DB.prepare('SELECT pass_hash FROM users WHERE id=?').bind(user.id).first();
    if (!(await checkPassword(String(b.oldPassword || ''), row.pass_hash))) return fail('الباسورد الحالي غلط', 401);
    const np = String(b.newPassword || '');
    if (np.length < 8 || np.length > 100) return fail('الباسورد الجديد لازم يكون 8 حروف أو أكتر');
    await env.DB.prepare('UPDATE users SET pass_hash=? WHERE id=?').bind(await hashPassword(np), user.id).run();
    return json({ ok: true });
  }

  if ((g = /^\/api\/follow\/(\d+)$/.exec(path)) && (m === 'POST' || m === 'DELETE')) {
    const aid = +g[1];
    if (aid === user.id) return fail('مينفعش تتابع نفسك');
    const a = await env.DB.prepare('SELECT id,role FROM users WHERE id=?').bind(aid).first();
    if (!a) return fail('الكاتب غير موجود', 404);
    if (a.role === 'admin' && (await ownerId(env)) === a.id) return fail('متابعة صفحة الأدمن تلقائية ومينفعش تتلغي');
    if (m === 'POST') {
      const had = await env.DB.prepare('SELECT 1 FROM follows WHERE follower_id=? AND author_id=?').bind(user.id, aid).first();
      await env.DB.prepare('INSERT OR IGNORE INTO follows (follower_id,author_id,ts) VALUES (?,?,?)').bind(user.id, aid, Date.now()).run();
      if (!had) {
        // إشعار للكاتب إن حد تابعه (مرة واحدة كل 24 ساعة لنفس الشخص)
        const dup = await env.DB.prepare("SELECT 1 FROM notes WHERE uid=? AND kind='follow' AND who=? AND ts>?").bind(aid, user.name, Date.now() - 86400000).first();
        if (!dup) {
          const head = '👤 متابع جديد', text = user.name + ' بدأ يتابعك';
          await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(aid, 'follow', 'p' + user.id, user.name, head, text, Date.now()).run();
          try { await sendPush(env, head, text, '', 'u_' + aid); } catch (e) {}
        }
      }
    }
    else await env.DB.prepare('DELETE FROM follows WHERE follower_id=? AND author_id=?').bind(user.id, aid).run();
    const n = (await env.DB.prepare('SELECT COUNT(*) AS n FROM follows WHERE author_id=?').bind(aid).first()).n;
    return json({ ok: true, followers: n, following: m === 'POST' });
  }
  if (path === '/api/me/follows' && m === 'GET') {
    const { results } = await env.DB.prepare('SELECT author_id FROM follows WHERE follower_id=?').bind(user.id).all();
    const adm = await env.DB.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").first();
    return json({ ids: results.map((r) => r.author_id), adminId: adm ? adm.id : 0 });
  }
  if (path === '/api/me/feed' && m === 'GET') {
    const adm = await env.DB.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").first();
    const { results } = await env.DB.prepare(`SELECT e.id,e.kind,e.author_id,e.novel_id,e.title,e.ts,u.name AS author FROM events e JOIN users u ON u.id=e.author_id
      WHERE (e.author_id IN (SELECT author_id FROM follows WHERE follower_id=?) OR e.author_id=?) AND e.author_id<>? ORDER BY e.ts DESC LIMIT 40`).bind(user.id, adm ? adm.id : 0, user.id).all();
    const { results: nts } = await env.DB.prepare('SELECT id,kind,novel_ref,who,title,text,ts FROM notes WHERE uid=? ORDER BY ts DESC LIMIT 40').bind(user.id).all();
    const items = results.map((e) => ({ id: e.id, kind: e.kind, authorId: e.author_id, author: e.author, novelId: e.novel_id, title: e.title, ts: e.ts }))
      .concat(nts.map((n) => ({ id: 'n' + n.id, kind: n.kind, novelRef: n.novel_ref, author: n.who, title: n.title, text: n.text, ts: n.ts })));
    items.sort((a, b) => b.ts - a.ts);
    return json({ items: items.slice(0, 60) });
  }
  /* ----- إشعار للكاتب لما حد يعلّق أو يقيّم ----- */
  if (path === '/api/notify' && m === 'POST') {
    const b = await body(request);
    const ref = str(b.novel, 60), kind = b.kind === 'rating' ? 'rating' : 'comment';
    if (!/^[A-Za-z0-9_-]{1,60}$/.test(ref)) return fail('رواية غير صحيحة');
    if (await tooMany(env, 'ntf:' + user.id, 30, 3600000)) return fail('كتير أوي، استنى شوية');
    await noteAttempt(env, 'ntf:' + user.id);
    let target = 0;
    const mm = /^u(\d+)$/.exec(ref);
    if (mm) { const r0 = await env.DB.prepare('SELECT user_id FROM novels WHERE id=? AND is_live=1').bind(+mm[1]).first(); if (r0) target = r0.user_id; }
    else {
      const au = +b.authorUid || 0;
      if (au) { const a0 = await env.DB.prepare("SELECT id FROM users WHERE id=? AND (role='admin' OR id IN (SELECT user_id FROM novels WHERE is_live=1))").bind(au).first(); if (a0) target = a0.id; }
      if (!target) { const adm = await env.DB.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").first(); if (adm) target = adm.id; }
    }
    if (!target || target === user.id) return json({ ok: true, skipped: true });
    if (kind === 'rating') { // كل تصويت لفصل = 0.1 نقطة للكاتب (مرة واحدة لكل قارئ لكل فصل)
      const ch = Number.isInteger(+b.chapter) ? Math.max(-1, Math.min(9999, +b.chapter)) : -1;
      const ins = await env.DB.prepare('INSERT OR IGNORE INTO pts_votes (voter,nid,ch,ts) VALUES (?,?,?,?)').bind(user.id, ref, ch, Date.now()).run();
      if (ins && ins.meta && ins.meta.changes) {
        await env.DB.prepare('UPDATE users SET points=ROUND(points+?,1) WHERE id=?').bind(PT_PER_VOTE, target).run();
        try { await walAward(env, user.id, 'vote', ref + '|' + ch); } catch (e) {}
      }
    }
    const title = str(b.title, 120).trim(), stars = Math.max(1, Math.min(5, +b.stars || 5));
    const snip = str(b.snippet, 400).trim().slice(0, 120);
    const head = kind === 'rating' ? '⭐ تقييم جديد على روايتك' : '💬 تعليق جديد على روايتك';
    const text = user.name + (kind === 'rating' ? ' قيّم «' + title + '» ' + stars + '/5' : ' علّق على «' + title + '»' + (b.stars ? ' (⭐ ' + stars + '/5)' : '') + (snip ? ': ' + snip : ''));
    await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(target, kind, ref, user.name, head, text, Date.now()).run();
    await env.DB.prepare('DELETE FROM notes WHERE ts < ?').bind(Date.now() - 60 * 86400000).run();
    try { await sendPush(env, head, text, '', 'u_' + target); } catch (e) {}
    return json({ ok: true });
  }
  if ((g = /^\/api\/my\/novels\/(\d+)\/paper$/.exec(path)) && m === 'PUT') { // تغيير نوع الرواية (ورقية/إلكترونية) فورًا من غير مراجعة
    const b = await body(request, 500);
    const r = await env.DB.prepare('SELECT id,user_id,d_extra,l_extra FROM novels WHERE id=?').bind(+g[1]).first();
    if (!r || (r.user_id !== user.id && user.role !== 'admin')) return fail('الرواية مش موجودة', 404);
    const up = (raw) => JSON.stringify({ ...parseJson(raw), paper: !!b.paper });
    await env.DB.prepare('UPDATE novels SET d_extra=?,l_extra=? WHERE id=?').bind(up(r.d_extra), up(r.l_extra), r.id).run();
    return json({ ok: true, paper: !!b.paper });
  }
  if ((g = /^\/api\/my\/novels\/(\d+)\/visibility$/.exec(path)) && m === 'PUT') {
    const b = await body(request);
    const own = await env.DB.prepare('SELECT id FROM novels WHERE id=? AND user_id=?').bind(+g[1], user.id).first();
    if (!own) return fail('الرواية مش موجودة', 404);
    await env.DB.prepare('UPDATE novels SET hidden=? WHERE id=?').bind(b.hidden ? 1 : 0, +g[1]).run();
    return json({ ok: true, hidden: !!b.hidden });
  }
  if (path === '/api/premium/keys' && m === 'GET') {
    const v = await getSetting(env, 'vault'), all = v.keys || {};
    if (user.role === 'admin') return json({ keys: all }, 200, { 'Cache-Control': 'private, no-store' });
    const { results } = await env.DB.prepare('SELECT nid FROM purchases WHERE user_id=?').bind(user.id).all(), out = {};
    results.forEach((r) => { if (all[r.nid]) out[r.nid] = all[r.nid]; });
    return json({ keys: out }, 200, { 'Cache-Control': 'private, no-store' });
  }

  /* ----- الصوت المصري (للمشتركين) ----- */
  if (path === '/api/tts/chapter' && m === 'GET') {
    if ((await getTtsConf(env)).hideListen) return fail('الاستماع متوقف مؤقتًا', 403);
    if (!isPremium(user) && !(await getTtsConf(env)).listenAll) return fail('الاستماع لمشتركي Premium', 403);
    const nid = str(url.searchParams.get('nid'), 80), ix = parseInt(url.searchParams.get('idx'), 10);
    const c = await env.DB.prepare('SELECT id,status,parts,done,nparts,secs,LENGTH(text) AS total FROM tts_ch WHERE nid=? AND idx=?').bind(nid, ix).first();
    if (!c) return json({ status: 'none' }, 200, { 'Cache-Control': 'no-store' });
    if (c.status === 'done') return json({ status: 'ready', id: c.id, parts: JSON.parse(c.parts), total: c.total, secs: c.secs }, 200, { 'Cache-Control': 'private, max-age=300' });
    return json({ status: 'pending', done: c.done, n: c.nparts }, 200, { 'Cache-Control': 'no-store' });
  }
  if ((g = /^\/api\/tts\/part\/(\d+)\/(\d+)$/.exec(path)) && m === 'GET') {
    if (!isPremium(user) && !(await getTtsConf(env)).listenAll) return fail('الاستماع لمشتركي Premium', 403);
    if (!env.TTS_BUCKET) return fail('التخزين مش متفعّل', 503);
    const o = await env.TTS_BUCKET.get('c/' + g[1] + '/' + g[2] + '.wav'); if (!o) return fail('الجزء مش موجود', 404);
    return audioResp(o, true);
  }

  /* ----- شراء روايات (انستا باي / محفظة) ----- */
  if (path === '/api/me/library' && m === 'GET') {
    const p = await env.DB.prepare('SELECT nid FROM purchases WHERE user_id=?').bind(user.id).all();
    const o = await env.DB.prepare('SELECT id,nid,ntitle,price,method,status,reason,created_at,decided_at FROM orders WHERE user_id=? ORDER BY created_at DESC LIMIT 30').bind(user.id).all();
    return json({ purchases: p.results.map((r) => r.nid), orders: o.results.map((r) => ({ id: r.id, nid: r.nid, title: r.ntitle, price: r.price, method: r.method, status: r.status, reason: r.reason, createdAt: r.created_at, decidedAt: r.decided_at })) }, 200, { 'Cache-Control': 'private, no-store' });
  }
  if (path === '/api/orders' && m === 'POST') {
    const b = await body(request, 6000), nid = str(b.nid, 80).trim(), info = await getPremiumInfo(env);
    if (!nid) return fail('اختار رواية');
    let title = '', price = 0, authorId = 0, g2;
    if ((g2 = /^u(\d+)$/.exec(nid))) {
      const n = await env.DB.prepare('SELECT user_id,l_title,l_extra FROM novels WHERE id=? AND is_live=1 AND hidden=0').bind(+g2[1]).first();
      if (!n) return fail('الرواية مش موجودة', 404);
      const x = extraOf(n.l_extra); if (!x.price || !x.password) return fail('الرواية دي مش معروضة للشراء');
      if (n.user_id === user.id) return fail('دي روايتك 😄');
      title = n.l_title; price = x.price; authorId = n.user_id;
    } else {
      const np = info.novelPrices[nid]; if (!np) return fail('الرواية دي مش معروضة للشراء');
      title = np.title || str(b.title, 120).trim(); price = np.price;
    }
    if (user.role === 'admin') return fail('إنت الأدمن، كل الروايات مفتوحة ليك');
    const method = b.method === 'instapay' ? 'instapay' : 'wallet';
    if (!info.methods[method].on) return fail('طريقة الدفع دي مش متاحة دلوقتي');
    const proof = cleanUrl(b.proof), sender = str(b.sender, 60).trim();
    if (!proof) return fail('ارفع صورة إثبات التحويل');
    if (sender.length < 3) return fail('اكتب رقم أو اسم حساب التحويل');
    if (await env.DB.prepare('SELECT 1 AS x FROM purchases WHERE user_id=? AND nid=?').bind(user.id, nid).first()) return fail('إنت مشتري الرواية دي قبل كده ✅');
    if (await tooMany(env, 'ord:' + user.id, 12, 86400000)) return fail('عملت طلبات كتير النهارده، كلّم الإدارة');
    if (await env.DB.prepare("SELECT 1 AS x FROM orders WHERE user_id=? AND nid=? AND status='pending'").bind(user.id, nid).first()) return fail('عندك طلب لنفس الرواية لسه تحت المراجعة');
    await noteAttempt(env, 'ord:' + user.id);
    const share = authorId ? Math.round(price * (1 - COMMISSION) * 100) / 100 : 0;
    const r = await env.DB.prepare('INSERT INTO orders (user_id,nid,ntitle,author_id,price,share,method,sender,proof,note,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind(user.id, nid, title, authorId, price, share, method, sender, proof, str(b.note, 300).trim(), Date.now()).run();
    await notifyAdmins(env, user.name, '🛒 طلب شراء رواية', user.name + ' عايز يشتري «' + title + '» بـ ' + price + ' جنيه عن طريق ' + (method === 'instapay' ? 'انستا باي' : 'المحفظة'));
    return json({ ok: true, id: r.meta && r.meta.last_row_id });
  }
  if (path === '/api/me/wallet' && m === 'GET') {
    const r0 = await env.DB.prepare('SELECT wallet,payout FROM users WHERE id=?').bind(user.id).first() || {}, g = await goldConf(env), pts = r0.wallet || 0, egp = egpOf(pts, g.rate);
    const { results } = await env.DB.prepare('SELECT id,points,egp,kind,value,status,ts,decided FROM withdrawals WHERE uid=? ORDER BY id DESC LIMIT 20').bind(user.id).all();
    return json({ points: pts, egp, rate: g.rate, min: g.min, can: egp >= g.min && egp > 0, pending: results.some((x) => x.status === 'pending'), payout: payoutOf(r0.payout), history: results }, 200, { 'Cache-Control': 'private, no-store' });
  }
  if (path === '/api/me/withdraw' && m === 'POST') {
    const b = await body(request, 1000), kind = b.kind === 'instapay' ? 'instapay' : 'wallet', value = str(b.value, 60).trim().replace(/[<>"']/g, ''), name = str(b.name, 60).trim().replace(/[<>"']/g, '');
    if (!value) return fail('اكتب رقم المحفظة أو رابط/حساب انستا باي');
    const g = await goldConf(env), r0 = await env.DB.prepare('SELECT wallet FROM users WHERE id=?').bind(user.id).first() || {}, pts = r0.wallet || 0, egp = egpOf(pts, g.rate);
    if (!(egp > 0) || egp < g.min) return fail('معذرةً، لم تصل إلى حد السحب بعد');
    const up = await env.DB.prepare('UPDATE users SET wallet=0 WHERE id=? AND wallet=?').bind(user.id, pts).run();
    if (!(up && up.meta && up.meta.changes)) return fail('حصل تغيير في رصيدك، جرّب تاني');
    const ins = await env.DB.prepare('INSERT INTO withdrawals (uid,points,egp,rate,kind,value,name,status,ts) VALUES (?,?,?,?,?,?,?,?,?)').bind(user.id, pts, egp, g.rate, kind, value, name, 'pending', Date.now()).run();
    await env.DB.prepare('UPDATE users SET payout=? WHERE id=?').bind(JSON.stringify({ kind, value, name }), user.id).run();
    await notifyAdmins(env, user.name, '💸 طلب سحب جديد', user.name + ' طلب سحب ' + egp + ' جنيه (' + pts + ' نقطة ذهبية)', 'wd');
    return json({ ok: true, id: ins.meta.last_row_id, points: pts, egp });
  }
  if (path === '/api/me/payout' && m === 'GET') { const r = await env.DB.prepare('SELECT payout FROM users WHERE id=?').bind(user.id).first(); return json({ payout: payoutOf(r && r.payout) }, 200, { 'Cache-Control': 'private, no-store' }); }
  if (path === '/api/me/payout' && m === 'PUT') {
    const b = await body(request, 1000), kind = b.kind === 'instapay' ? 'instapay' : 'wallet', value = str(b.value, 60).trim().replace(/[<>"']/g, ''), name = str(b.name, 60).trim().replace(/[<>"']/g, '');
    await env.DB.prepare('UPDATE users SET payout=? WHERE id=?').bind(value ? JSON.stringify({ kind, value, name }) : '', user.id).run(); return json({ ok: true, payout: payoutOf(JSON.stringify({ kind, value, name })) });
  }
  if (path === '/api/my/earnings' && m === 'GET') {
    const r = await env.DB.prepare("SELECT COUNT(*) AS n,COALESCE(SUM(share),0) AS total,COALESCE(SUM(CASE WHEN paid_out=0 THEN share ELSE 0 END),0) AS due FROM orders WHERE author_id=? AND status='approved'").bind(user.id).first();
    return json({ sales: r.n, total: r.total, due: r.due, paid: r.total - r.due, commission: COMMISSION * 100 }, 200, { 'Cache-Control': 'private, no-store' });
  }

  /* ----- دفع اشتراك Premium (انستا باي / محفظة) ----- */
  if (path === '/api/premium/pay' && m === 'POST') {
    const b = await body(request, 6000), info = await getPremiumInfo(env);
    const plan = info.plans.filter((p) => p.id === String(b.plan))[0];
    if (!plan) return fail('اختار باقة صحيحة');
    const method = b.method === 'instapay' ? 'instapay' : 'wallet';
    if (!info.methods[method].on) return fail('طريقة الدفع دي مش متاحة دلوقتي');
    const proof = cleanUrl(b.proof), sender = str(b.sender, 60).trim();
    if (!proof) return fail('ارفع صورة إثبات التحويل');
    if (sender.length < 3) return fail('اكتب رقم أو اسم حساب التحويل');
    if (await tooMany(env, 'pay:' + user.id, 8, 86400000)) return fail('عملت طلبات كتير النهارده، كلّم الإدارة');
    const pend = await env.DB.prepare("SELECT COUNT(*) AS n FROM payments WHERE user_id=? AND status='pending'").bind(user.id).first();
    if (pend && pend.n >= 2) return fail('عندك طلبات لسه تحت المراجعة، استنى لحد ما تتراجع');
    await noteAttempt(env, 'pay:' + user.id);
    const amount = plan.price ? plan.price + ' جنيه' : '';
    const r = await env.DB.prepare('INSERT INTO payments (user_id,plan_id,plan_name,months,amount,method,sender,proof,note,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(user.id, plan.id, plan.name, plan.months, amount, method, sender, proof, str(b.note, 300).trim(), Date.now()).run();
    try {
      const { results: adms } = await env.DB.prepare("SELECT id FROM users WHERE role='admin'").all();
      for (const a of adms) {
        const text = user.name + ' طلب اشتراك Premium (' + plan.name + ')' + (amount ? ' — ' + amount : '') + ' عن طريق ' + (method === 'instapay' ? 'انستا باي' : 'المحفظة');
        await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(a.id, 'payment', 'pay', user.name, '👑 طلب اشتراك جديد', text, Date.now()).run();
        if (env.FCM_SA) { try { await sendPush(env, '👑 طلب اشتراك جديد', text, '', 'u_' + a.id); } catch (e) {} }
      }
    } catch (e) {}
    return json({ ok: true, id: r.meta && r.meta.last_row_id });
  }
  if (path === '/api/premium/payments' && m === 'GET') {
    const { results } = await env.DB.prepare('SELECT id,plan_name,months,amount,method,status,reason,created_at,decided_at FROM payments WHERE user_id=? ORDER BY created_at DESC LIMIT 20').bind(user.id).all();
    return json({ payments: results.map((p) => ({ id: p.id, plan: p.plan_name, months: p.months, amount: p.amount, method: p.method, status: p.status, reason: p.reason, createdAt: p.created_at, decidedAt: p.decided_at })) }, 200, { 'Cache-Control': 'private, no-store' });
  }

  /* ----- رواياتي ----- */
  if (path === '/api/my/novels' && m === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM novels WHERE user_id=? ORDER BY updated_at DESC').bind(user.id).all();
    const counts = (await env.DB.prepare("SELECT novel_id,COUNT(*) AS n FROM chapters WHERE ver='d' AND novel_id IN (SELECT id FROM novels WHERE user_id=?) GROUP BY novel_id").bind(user.id).all()).results;
    const cm = {}; counts.forEach((c) => (cm[c.novel_id] = c.n));
    return json({ novels: results.map((r) => ({ ...myNovelRow(r), chaptersCount: cm[r.id] || 0 })) });
  }
  if (path === '/api/my/novels' && m === 'POST') {
    const cnt = (await env.DB.prepare('SELECT COUNT(*) AS n FROM novels WHERE user_id=?').bind(user.id).first()).n;
    if (cnt >= LIM.novelsPerUser) return fail('وصلت للحد الأقصى من الروايات');
    const n = cleanNovel(await body(request)); const now = Date.now();
    const r = await env.DB.prepare('INSERT INTO novels (user_id,status,created_at,updated_at,d_title,d_author,d_genre,d_tags,d_synopsis,d_cover,d_extra) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .bind(user.id, 'draft', now, now, n.title, n.author || user.name, n.genre, JSON.stringify(n.tags), n.synopsis, n.cover, n.extra).run();
    const id = r.meta.last_row_id;
    await env.DB.batch(chapterStmts(env, id, 'd', n.chapters));
    return json({ id });
  }
  if ((g = /^\/api\/my\/novels\/(\d+)$/.exec(path))) {
    const id = +g[1];
    const row = await env.DB.prepare('SELECT * FROM novels WHERE id=? AND user_id=?').bind(id, user.id).first();
    if (!row) return fail('الرواية غير موجودة', 404);
    if (m === 'GET') {
      const { results } = await env.DB.prepare("SELECT title,content,locked FROM chapters WHERE novel_id=? AND ver='d' ORDER BY idx").bind(id).all();
      return json({ novel: { ...myNovelRow(row), chapters: results.map((c, i) => ({ title: c.title, content: c.content, locked: !!c.locked, release: extraOf(row.d_extra).rel[i] || 0 })) } });
    }
    if (m === 'PUT') {
      const n = cleanNovel(await body(request));
      { const sid = parseJson(row.d_extra).siteId; if (sid) { const ex1 = JSON.parse(n.extra); ex1.siteId = sid; n.extra = JSON.stringify(ex1); } }
      await env.DB.batch([
        env.DB.prepare("UPDATE novels SET d_title=?,d_author=?,d_genre=?,d_tags=?,d_synopsis=?,d_cover=?,d_extra=?,updated_at=?,status=CASE WHEN status='pending' THEN 'pending' ELSE 'draft' END WHERE id=?")
          .bind(n.title, n.author || user.name, n.genre, JSON.stringify(n.tags), n.synopsis, n.cover, n.extra, Date.now(), id),
        ...chapterStmts(env, id, 'd', n.chapters)]);
      return json({ ok: true });
    }
    if (m === 'DELETE') {
      await env.DB.batch([env.DB.prepare('DELETE FROM chapters WHERE novel_id=?').bind(id), env.DB.prepare('DELETE FROM novels WHERE id=?').bind(id)]);
      return json({ ok: true });
    }
  }
  if ((g = /^\/api\/my\/novels\/(\d+)\/submit$/.exec(path)) && m === 'POST') {
    const id = +g[1];
    const row = await env.DB.prepare('SELECT d_title FROM novels WHERE id=? AND user_id=?').bind(id, user.id).first();
    if (!row) return fail('الرواية غير موجودة', 404);
    const c = (await env.DB.prepare("SELECT COUNT(*) AS n FROM chapters WHERE novel_id=? AND ver='d'").bind(id).first()).n;
    if (!c) return fail('أضف فصل واحد على الأقل قبل الإرسال');
    if (user.role === 'admin') return await route(new Request(new URL('/api/admin/novels/' + id + '/approve', request.url), { method: 'POST', headers: request.headers, body: '{}' }), env);
    await env.DB.prepare("UPDATE novels SET status='pending',reject_reason='',updated_at=? WHERE id=?").bind(Date.now(), id).run();
    await notifyAdmins(env, user.name, '📚 رواية جديدة مستنية مراجعتك', row.d_title, 'pend');
    return json({ ok: true });
  }

    if (path === '/api/my/import/wattpad' && m === 'POST') {
      if (user.role !== 'admin') { if (await tooMany(env, 'wpimp:' + user.id, 6, 86400000)) return fail('وصلت للحد اليومي للاستيراد، جرّب بكرة'); await noteAttempt(env, 'wpimp:' + user.id); }
      const b = await body(request, 1000), u0 = str(b.url, 300), mm = /wattpad\.com\/(?:story\/)?(\d+)/.exec(u0);
      if (!mm) return fail('لينك واتباد غير صحيح');
      const H = { 'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36', Accept: 'application/json' };
      let sid = mm[1];
      if (!/wattpad\.com\/story\//.test(u0)) { const pr = await fetch('https://www.wattpad.com/api/v3/story_parts/' + sid + '?fields=group(id)', { headers: H }); if (pr.ok) { const pj = await pr.json(); if (pj && pj.group && pj.group.id) sid = String(pj.group.id); } }
      const r = await fetch('https://www.wattpad.com/api/v3/stories/' + sid + '?fields=id,title,description,cover,user(name),parts(id,title)', { headers: H });
      if (!r.ok) return fail('واتباد رفض الطلب (' + r.status + ') — ممكن الرواية خاصة أو واتباد حاجب السيرفر', 502);
      const j = await r.json(); if (!j || !Array.isArray(j.parts) || !j.parts.length) return fail('مفيش فصول في اللينك ده', 404);
      return json({ id: String(j.id), title: str(j.title, 200), author: str((j.user || {}).name, 100), synopsis: str(j.description, 3000), cover: str(j.cover, 500), parts: j.parts.map((x) => ({ id: String(x.id), title: str(x.title, 200) })) });
    }
    if (path === '/api/my/import/wattpad/run' && m === 'POST') {
      const b = await body(request, 20000), nid = +b.novelId, parts = Array.isArray(b.parts) ? b.parts.slice(0, 6) : [];
      if (!nid || !parts.length || !(await env.DB.prepare('SELECT 1 AS x FROM novels WHERE id=? AND user_id=?').bind(nid, user.id).first())) return fail('بيانات غير صحيحة');
      const dec = (t) => t.replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n));
      const texts = await Promise.all(parts.map(async (pt) => {
        if (!/^\d{1,15}$/.test(String(pt.id))) return '';
        try { const r = await fetch('https://www.wattpad.com/apiv2/storytext?id=' + pt.id, { headers: { 'User-Agent': 'Mozilla/5.0 (Linux; Android 13) Chrome/120 Mobile Safari/537.36' } }); if (!r.ok) return ''; const h = await r.text();
          return dec(h.replace(/<\s*br\s*\/?>/gi, '\n').replace(/<\/p>/gi, '\n\n').replace(/<[^>]+>/g, '')).replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim(); } catch (e) { return ''; }
      }));
      const have = (await env.DB.prepare("SELECT COUNT(*) AS n FROM chapters WHERE novel_id=? AND ver='d'").bind(nid).first()).n; if (user.role !== 'admin' && have + parts.length > 400) return fail('الحد الأقصى 400 فصل');
      let idx = ((await env.DB.prepare("SELECT COALESCE(MAX(idx),-1) AS m FROM chapters WHERE novel_id=? AND ver='d'").bind(nid).first()) || {}).m + 1, ok = 0; const failed = [];
      const st = [];
      parts.forEach((pt, i) => { if (!texts[i]) { failed.push(i); return; } st.push(env.DB.prepare("INSERT INTO chapters (novel_id,ver,idx,title,content,locked) VALUES (?,?,?,?,?,0)").bind(nid, 'd', idx++, str(pt.title, 200) || ('الفصل ' + idx), texts[i])); ok++; });
      if (st.length) await env.DB.batch(st);
      return json({ ok, failed });
    }
  /* ----- الأدمن ----- */
  if (path.startsWith('/api/admin/')) {
    if (user.role !== 'admin') return fail('للأدمن فقط', 403);
    if (path === '/api/admin/pending' && m === 'GET') {
      const { results } = await env.DB.prepare("SELECT n.*,u.name AS owner,u.email AS owner_email FROM novels n JOIN users u ON u.id=n.user_id WHERE n.status='pending' ORDER BY n.updated_at ASC").all();
      return json({ novels: results.map((r) => ({ ...myNovelRow(r), owner: r.owner, ownerEmail: r.owner_email })) });
    }
    if ((g = /^\/api\/admin\/novels\/(\d+)$/.exec(path)) && m === 'GET') {
      const r = await env.DB.prepare('SELECT n.*,u.name AS owner,u.email AS owner_email FROM novels n JOIN users u ON u.id=n.user_id WHERE n.id=?').bind(+g[1]).first();
      if (!r) return fail('غير موجودة', 404);
      const { results } = await env.DB.prepare("SELECT title,content,locked FROM chapters WHERE novel_id=? AND ver='d' ORDER BY idx").bind(+g[1]).all();
      return json({ novel: { ...myNovelRow(r), owner: r.owner, ownerEmail: r.owner_email, chapters: results.map((c, i) => ({ title: c.title, content: c.content, locked: !!c.locked, release: extraOf(r.d_extra).rel[i] || 0 })) } });
    }
    if ((g = /^\/api\/admin\/novels\/(\d+)\/approve$/.exec(path)) && m === 'POST') {
      const id = +g[1];
      const r = await env.DB.prepare('SELECT * FROM novels WHERE id=?').bind(id).first();
      if (!r) return fail('غير موجودة', 404);
      const now = Date.now();
      const oldCnt = r.is_live ? (await env.DB.prepare("SELECT COUNT(*) AS n FROM chapters WHERE novel_id=? AND ver='l'").bind(id).first()).n : 0;
      await env.DB.batch([
        env.DB.prepare('UPDATE novels SET l_title=d_title,l_author=d_author,l_genre=d_genre,l_tags=d_tags,l_synopsis=d_synopsis,l_cover=d_cover,l_extra=d_extra,is_live=1,status=?,reject_reason=?,published_at=COALESCE(published_at,?),updated_at=? WHERE id=?').bind('approved', '', now, now, id),
        env.DB.prepare("DELETE FROM chapters WHERE novel_id=? AND ver='l'").bind(id),
        env.DB.prepare("INSERT INTO chapters (novel_id,ver,idx,title,content,locked) SELECT novel_id,'l',idx,title,content,locked FROM chapters WHERE novel_id=? AND ver='d'").bind(id)]);
      try { if (extraOf(r.d_extra).siteId) await applyServerVault(env); } catch (e) {}
      try {
        const newCnt = (await env.DB.prepare("SELECT COUNT(*) AS n FROM chapters WHERE novel_id=? AND ver='l'").bind(id).first()).n;
        const hidden = (ex, cnt) => extraOf(ex).rel.slice(0, cnt).filter((v) => v > now).length; // الفصول المجدولة ما بتتحسبش «فصل جديد» لحد ما ينزل ميعادها
        const kind = !r.is_live ? 'novel' : (newCnt - hidden(r.d_extra, newCnt) > oldCnt - hidden(r.l_extra, oldCnt) ? 'chapter' : '');
        if (kind) {
          const au = await env.DB.prepare('SELECT id,name,role FROM users WHERE id=?').bind(r.user_id).first();
          await env.DB.prepare('INSERT INTO events (author_id,kind,novel_id,title,ts) VALUES (?,?,?,?,?)').bind(r.user_id, kind, id, r.d_title, now).run();
          if (env.FCM_SA && au) {
            const last = kind === 'chapter' ? (await env.DB.prepare("SELECT title FROM chapters WHERE novel_id=? AND ver='l' ORDER BY idx DESC LIMIT 1").bind(id).first()) : null;
            await sendPush(env, kind === 'novel' ? 'رواية جديدة من ' + au.name : 'فصل جديد من ' + au.name, '«' + r.d_title + '»' + (last ? ' — ' + last.title : ''), '', au.role === 'admin' ? 'all' : 'a_' + au.id);
          }
        }
      } catch (e) { /* الإشعار best-effort */ }
      return json({ ok: true });
    }
    if ((g = /^\/api\/admin\/novels\/(\d+)\/reject$/.exec(path)) && m === 'POST') {
      const b = await body(request);
      await env.DB.prepare("UPDATE novels SET status='rejected',reject_reason=?,updated_at=? WHERE id=?").bind(str(b.reason, 500), Date.now(), +g[1]).run();
      return json({ ok: true });
    }
    if ((g = /^\/api\/admin\/novels\/(\d+)\/unpublish$/.exec(path)) && m === 'POST') {
      await env.DB.prepare("UPDATE novels SET is_live=0,status='draft',updated_at=? WHERE id=?").bind(Date.now(), +g[1]).run();
      return json({ ok: true });
    }
    if (path === '/api/admin/backup' && m === 'GET') {
      const all = async (t) => (await env.DB.prepare('SELECT * FROM ' + t).all()).results;
      return json({ app: 'radpad', version: 3, createdAt: Date.now(), users: await all('users'), novels: await all('novels'), chapters: await all('chapters'), follows: await all('follows'), reads: await all('reads') });
    }
    if (path === '/api/admin/restore' && m === 'POST') {
      const b = await body(request, 40000000);
      if (!b || b.app !== 'radpad' || !Array.isArray(b.users) || !Array.isArray(b.novels) || !Array.isArray(b.chapters)) return fail('ملف النسخة الاحتياطية غير صحيح');
      const cols = {
        users: ['id', 'email', 'name', 'pass_hash', 'role', 'created_at', 'premium_until', 'avatar', 'bio', 'links'],
        novels: ['id', 'user_id', 'status', 'is_live', 'hidden', 'reject_reason', 'created_at', 'updated_at', 'published_at', 'd_title', 'd_author', 'd_genre', 'd_tags', 'd_synopsis', 'd_cover', 'd_extra', 'l_title', 'l_author', 'l_genre', 'l_tags', 'l_synopsis', 'l_cover', 'l_extra'],
        chapters: ['novel_id', 'ver', 'idx', 'title', 'content', 'locked'],
        follows: ['follower_id', 'author_id', 'ts'],
        reads: ['k', 'n']
      };
      const dflt = { d_extra: '{}', l_extra: '{}', locked: 0, hidden: 0, premium_until: 0, avatar: '', bio: '', links: '{}', ts: 0, n: 0 };
      const stmts = [];
      for (const t of ['users', 'novels', 'chapters', 'follows', 'reads']) {
        if (!Array.isArray(b[t])) continue;
        const c = cols[t], q = `INSERT OR REPLACE INTO ${t} (${c.join(',')}) VALUES (${c.map(() => '?').join(',')})`;
        for (const row of b[t]) stmts.push(env.DB.prepare(q).bind(...c.map((k) => (row[k] === undefined || row[k] === null ? (k in dflt ? dflt[k] : null) : row[k]))));
      }
      for (let i = 0; i < stmts.length; i += 40) await env.DB.batch(stmts.slice(i, i + 40));
      return json({ ok: true, users: b.users.length, novels: b.novels.length, chapters: b.chapters.length });
    }
    if (path === '/api/admin/tts' && m === 'GET') { await ttsMigrate(env); return json(await ttsStats(env)); }
    if (path === '/api/admin/tts' && m === 'PUT') {
      const b = await body(request, 12000), cur = await getTtsConf(env), nm = (v, d) => (/^[A-Za-z0-9._-]{2,60}$/.test(String(v || '')) ? String(v) : d), nu = (v, d, lo, hi) => { const k = Number(v); return v !== '' && v != null && Number.isFinite(k) && k >= lo && k <= hi ? k : d; };
      const gv = { ...cur.gv }; ROLES.forEach((r) => { const v = (b.gv || {})[r] || (r === 'narrator' ? b.voice : ''); if (v) gv[r] = nm(v, gv[r]); });
      const ba = b.az || {}, az = { region: ba.region != null ? (/^[a-z0-9-]{3,30}$/.test(String(ba.region).trim().toLowerCase()) ? String(ba.region).trim().toLowerCase() : '') : cur.az.region, dailyMin: nu(ba.dailyMin, cur.az.dailyMin, 0, 100000), freeChars: nu(ba.freeChars, cur.az.freeChars, 0, 1e9), price: nu(ba.price, cur.az.price, 0, 1000), concurrency: nu(ba.concurrency, cur.az.concurrency, 1, 8), voices: { ...cur.az.voices } };
      ROLES.forEach((r) => { const v = (ba.voices || {})[r]; if (v && typeof v === 'object') { const o = { ...cur.az.voices[r] }; if (/^[A-Za-z]{2,3}-[A-Za-z]{2,4}-[A-Za-z0-9]{2,40}$/.test(String(v.v || ''))) o.v = String(v.v); if (/^[+-]?\d{1,3}(\.\d)?%$/.test(String(v.rate || ''))) o.rate = String(v.rate); if (/^[+-]?\d{1,3}(\.\d)?%$/.test(String(v.pitch || ''))) o.pitch = String(v.pitch); az.voices[r] = o; } });
      await setSetting(env, 'tts', { model: nm(b.model, cur.model), legacyModel: nm(b.legacyModel, cur.legacyModel), style: str(b.style, 200).trim() || cur.style, gv,
        concurrency: nu(b.concurrency, cur.concurrency, 1, 4), dailyMin: nu(b.dailyMin, cur.dailyMin, 0, 100000), freeMin: nu(b.freeMin, cur.freeMin, 0, 100000), priceIn: nu(b.priceIn, cur.priceIn, 0, 1000), priceOut: nu(b.priceOut, cur.priceOut, 0, 1000),
        defProv: PROVS.includes(b.defProv) ? b.defProv : cur.defProv, novelProv: cur.novelProv, rebalance: b.rebalance == null ? cur.rebalance : !!b.rebalance, rd: b.rd ? normRd({ ...cur.rd, ...b.rd, archMap: b.rd.archMap || cur.rd.archMap, pers: b.rd.pers || cur.rd.pers }) : cur.rd, radad: b.radad == null ? cur.radad : !!b.radad, engine: b.engine == null ? cur.engine : (b.engine === 'single' ? 'single' : 'mega'), multi: b.multi == null ? cur.multi : !!b.multi, mm: b.mm == null ? cur.mm : !!b.mm, econ: b.econ == null ? cur.econ : !!b.econ, hideListen: b.hideListen == null ? cur.hideListen : !!b.hideListen, listenAll: b.listenAll == null ? cur.listenAll : !!b.listenAll, smart: b.smart == null ? cur.smart : !!b.smart, annModel: nm(b.annModel, cur.annModel), dict: b.dict == null ? cur.dict : String(b.dict).slice(0, 3000), az,
        g2: { dailyMin: nu((b.g2 || {}).dailyMin, cur.g2.dailyMin, 0, 100000), freeMin: nu((b.g2 || {}).freeMin, cur.g2.freeMin, 0, 100000), concurrency: nu((b.g2 || {}).concurrency, cur.g2.concurrency, 1, 4) },
        g3: { dailyMin: nu((b.g3 || {}).dailyMin, cur.g3.dailyMin, 0, 100000), freeMin: nu((b.g3 || {}).freeMin, cur.g3.freeMin, 0, 100000), concurrency: nu((b.g3 || {}).concurrency, cur.g3.concurrency, 1, 4) },
        g4: { dailyMin: nu((b.g4 || {}).dailyMin, cur.g4.dailyMin, 0, 100000), freeMin: nu((b.g4 || {}).freeMin, cur.g4.freeMin, 0, 100000), concurrency: nu((b.g4 || {}).concurrency, cur.g4.concurrency, 1, 4) },
        g5: { dailyMin: nu((b.g5 || {}).dailyMin, cur.g5.dailyMin, 0, 100000), freeMin: nu((b.g5 || {}).freeMin, cur.g5.freeMin, 0, 100000), concurrency: nu((b.g5 || {}).concurrency, cur.g5.concurrency, 1, 4) },
        g6: { dailyMin: nu((b.g6 || {}).dailyMin, cur.g6.dailyMin, 0, 100000), freeMin: nu((b.g6 || {}).freeMin, cur.g6.freeMin, 0, 100000), concurrency: nu((b.g6 || {}).concurrency, cur.g6.concurrency, 1, 4) } ,
        r1: { dailyMin: nu((b.r1 || {}).dailyMin, cur.r1.dailyMin, 0, 100000), freeMin: nu((b.r1 || {}).freeMin, cur.r1.freeMin, 0, 100000), concurrency: nu((b.r1 || {}).concurrency, cur.r1.concurrency, 1, 4) },
        r2: { dailyMin: nu((b.r2 || {}).dailyMin, cur.r2.dailyMin, 0, 100000), freeMin: nu((b.r2 || {}).freeMin, cur.r2.freeMin, 0, 100000), concurrency: nu((b.r2 || {}).concurrency, cur.r2.concurrency, 1, 4) },
        r3: { dailyMin: nu((b.r3 || {}).dailyMin, cur.r3.dailyMin, 0, 100000), freeMin: nu((b.r3 || {}).freeMin, cur.r3.freeMin, 0, 100000), concurrency: nu((b.r3 || {}).concurrency, cur.r3.concurrency, 1, 4) },
        r4: { dailyMin: nu((b.r4 || {}).dailyMin, cur.r4.dailyMin, 0, 100000), freeMin: nu((b.r4 || {}).freeMin, cur.r4.freeMin, 0, 100000), concurrency: nu((b.r4 || {}).concurrency, cur.r4.concurrency, 1, 4) },
        r5: { dailyMin: nu((b.r5 || {}).dailyMin, cur.r5.dailyMin, 0, 100000), freeMin: nu((b.r5 || {}).freeMin, cur.r5.freeMin, 0, 100000), concurrency: nu((b.r5 || {}).concurrency, cur.r5.concurrency, 1, 4) },
        r6: { dailyMin: nu((b.r6 || {}).dailyMin, cur.r6.dailyMin, 0, 100000), freeMin: nu((b.r6 || {}).freeMin, cur.r6.freeMin, 0, 100000), concurrency: nu((b.r6 || {}).concurrency, cur.r6.concurrency, 1, 4) } });
      return json({ ok: true, ...(await ttsStats(env)) });
    }
    // فحص: السيرفر شايف كام صوت في فصل متخزّن؟
    if (path === '/api/admin/tts/inspect' && m === 'GET') {
      const nid = str(url.searchParams.get('nid'), 80), ix = url.searchParams.get('idx');
      const c = ix != null && ix !== '' ? await env.DB.prepare('SELECT idx,status,prov,text,parts,updated FROM tts_ch WHERE nid=? AND idx=?').bind(nid, parseInt(ix, 10)).first()
        : await env.DB.prepare("SELECT idx,status,prov,text,parts,updated FROM tts_ch WHERE nid=? ORDER BY (LENGTH(text)-LENGTH(REPLACE(text,'«',''))+LENGTH(text)-LENGTH(REPLACE(text,'-',''))) DESC, idx ASC LIMIT 1").bind(nid).first();
      if (!c) return fail('الفصل مش في الطابور', 404);
      const text = c.text, lines = text.split('\n'), dashLines = lines.filter((l) => /^\s*[-–—]/.test(l)).length, quotes = (text.match(/[«"“]/g) || []).length;
      const runs = segmentRoles(text), roles = {}; runs.forEach((r) => (roles[r.role] = (roles[r.role] || 0) + r.text.length));
      const parts = JSON.parse(c.parts || '[]'); let multi = 0; const sample = [];
      parts.forEach((pr) => { const rr = segmentRoles(text.slice(pr[0], pr[1]).trim()), rs = [...new Set(rr.map((r) => r.role))]; if (rs.length > 1) { multi++; if (sample.length < 2) sample.push({ roles: rs, text: text.slice(pr[0], pr[1]).trim().slice(0, 140) }); } });
      const conf = await getTtsConf(env);
      return json({ idx: c.idx, status: c.status, prov: c.prov, multiOn: conf.multi, chars: text.length, dashLines, quotes, roles, parts: parts.length, multiParts: multi, sample });
    }
    // فحص الفصول المحوّلة وهي أقصر من N ثانية (غالبًا اتحوّل العنوان بس) وحذفها من الطابور علشان الموقع يبعتها تاني بنصها الكامل
    if (path === '/api/admin/tts/fix-short' && m === 'POST') {
      const b = await body(request, 500), max = Math.max(1, Math.min(60, +b.max || 5));
      const ratio = Math.max(0.2, Math.min(0.95, +b.ratio || 0.6)); // الصوت أقصر من 60% من المدة المتوقعة للنص = ناقص (بيفوّت فقرات/جمل)
      const { results } = await env.DB.prepare("SELECT id,nid,idx,ntitle,ctitle,secs,nparts,LENGTH(text) AS len FROM tts_ch WHERE status='done' AND (secs<? OR secs < LENGTH(text)*1.0/" + CPS + "*?)").bind(max, ratio).all();
      if (!b.dry) {
        for (const r of results) {
          if (env.TTS_BUCKET) { const ks = []; for (let i = 0; i < r.nparts; i++) ks.push('c/' + r.id + '/' + i + '.wav'); for (let i = 0; i < ks.length; i += 100) await env.TTS_BUCKET.delete(ks.slice(i, i + 100)); }
          await env.DB.prepare('DELETE FROM tts_ch WHERE id=?').bind(r.id).run();
        }
      }
      return json({ ok: true, dry: !!b.dry, n: results.length, items: results.slice(0, 200).map((r) => ({ nid: r.nid, idx: r.idx, novel: r.ntitle, chapter: r.ctitle, secs: Math.round(r.secs * 10) / 10, expect: Math.round(r.len / CPS) })) });
    }
    if (path === '/api/admin/tts/known' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT nid,idx,sig FROM tts_ch').all(), sigs = {};
      const { results: mkr } = await env.DB.prepare("SELECT nid,idx FROM tts_ch WHERE status='done' OR text LIKE '%«%' OR text LIKE '%' || char(34) || '%' OR text LIKE '%“%' OR text LIKE '-%' OR text LIKE '%' || char(10) || '-%' OR text LIKE '%' || char(10) || '–%' OR text LIKE '%' || char(10) || '—%'").all(), mk = {};
      mkr.forEach((r) => (mk[r.nid + '#' + r.idx] = 1));
      const { results: ln } = await env.DB.prepare('SELECT nid,idx,LENGTH(text) AS n FROM tts_ch').all(), lens = {}; ln.forEach((r) => (lens[r.nid + '#' + r.idx] = r.n));
      results.forEach((r) => (sigs[r.nid + '#' + r.idx] = r.sig)); return json({ sigs, mk, lens });
    }
    if (path === '/api/admin/tts/enqueue' && m === 'POST') {
      if (!(await ttsMigrate(env))) return fail('بنمسح الصوت القديم… جرّب بعد دقيقة', 503);
      const b = await body(request, 700000); if (!Array.isArray(b.items) || b.items.length > 30) return fail('طلب غير صحيح');
      const now = Date.now(), conf = await getTtsConf(env); let added = 0, updated = 0, skipped = 0;
      for (const it of b.items) {
        const nid = str(it.nid, 80), ix = parseInt(it.idx, 10), text = String(it.text || '').slice(0, 150000).trim(), sig = str(it.sig, 40);
        if (!nid || !(ix >= 0 && ix < 5000)) { skipped++; continue; }
        if (!text.includes('\n') && text.length < 120) { skipped++; continue; } // عنوان بس من غير نص الفصل: ما نحوّلوش
        const parts = splitParts(text, conf.radad !== false ? rdPartMx(conf) : conf.econ ? ECON_MX : 700); if (!parts.length) { skipped++; continue; }
        const ntitle = str(it.ntitle, 120), ctitle = str(it.ctitle, 120); let ord = Math.max(-1e9, Math.min(1e9, parseInt(it.ord, 10) || 0));
        const ex = await env.DB.prepare('SELECT id,sig,prov,text,nparts,status FROM tts_ch WHERE nid=? AND idx=?').bind(nid, ix).first();
        const sib = await env.DB.prepare('SELECT prov,MIN(ord) AS o FROM tts_ch WHERE nid=?').bind(nid).first(), prov = conf.novelProv[nid] || (sib && sib.prov) || conf.defProv;
        if (!ex) { if (sib && sib.o != null) ord = sib.o; await env.DB.prepare('INSERT INTO tts_ch (nid,idx,ntitle,ctitle,ord,sig,text,parts,nparts,created,updated,prov) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').bind(nid, ix, ntitle, ctitle, ord, sig, text, JSON.stringify(parts), parts.length, now, now, prov).run(); added++; }
        else if (!it.redo && (ex.status === 'done' || (ex.sig === sig && !(hasMk(text) && !hasMk(ex.text))))) { await env.DB.prepare('UPDATE tts_ch SET ntitle=?,ctitle=? WHERE id=?').bind(ntitle, ctitle, ex.id).run(); skipped++; }
        else {
          if (env.TTS_BUCKET) { const ks = []; for (let i = 0; i < ex.nparts; i++) ks.push('c/' + ex.id + '/' + i + '.wav'); for (let i = 0; i < ks.length; i += 100) await env.TTS_BUCKET.delete(ks.slice(i, i + 100)); } await env.DB.prepare("UPDATE tts_ch SET ntitle=?,ctitle=?,sig=?,text=?,parts=?,nparts=?,done=0,secs=0,status='queued',owner='',lock_until=0,retry_at=0,attempts=0,err='',updated=?,prov=? WHERE id=?").bind(ntitle, ctitle, sig, text, JSON.stringify(parts), parts.length, now, prov, ex.id).run(); updated++; }
      }
      return json({ ok: true, added, updated, skipped });
    }
    if (path === '/api/admin/tts/front' && m === 'POST') {
      const b = await body(request, 500), nid = str(b.nid, 80);
      const mn = await env.DB.prepare('SELECT COALESCE(MIN(ord),0) AS m FROM tts_ch').first();
      await env.DB.prepare('UPDATE tts_ch SET ord=? WHERE nid=?').bind(mn.m - 1, nid).run(); return json({ ok: true, ...(await ttsStats(env)) });
    }
    // ترتيب رواية برقم: pos = ترتيبها بين الروايات اللي لسه بتتحوّل
    if (path === '/api/admin/tts/key' && m === 'POST') {
      const b = await body(request, 6000), prov = b.prov;
      // أكتر من مفتاح: كل مفتاح في سطر (أو مفصولين بمسافة/فاصلة). بنضّف كل واحد لوحده ونشيل المكرر
      const ks = [];
      String(b.key || '').split(/[\n\r,;]+/).forEach((raw) => {
        let k = raw.normalize('NFKC').replace(/[\s\u200B-\u200F\u202A-\u202E\u2060\uFEFF"'`<>]/g, '').replace(/^(bearer|key=|apikey=|api_key=|x-goog-api-key:)/i, '');
        const am = /AIza[A-Za-z0-9_-]{30,60}/.exec(k); if (am) k = am[0];
        if (k) ks.push(k);
      });
      if (!PROVS.includes(prov) || !isGoogle(prov)) return fail('حساب جوجل غير صحيح');
      for (const k of ks) if (!/^[A-Za-z0-9_.-]{20,140}$/.test(k)) return fail('مفتاح شكله غلط (طوله ' + k.length + ') — انسخه كامل من Google AI Studio، كل مفتاح في سطر');
      if (ks.length > 40) return fail('أقصى عدد 40 مفتاح للحساب');
      const key = [...new Set(ks)].join('\n');
      const cur = await getSetting(env, 'tts_keys'); if (key) cur[prov] = key; else delete cur[prov];
      await setSetting(env, 'tts_keys', cur); KC = { at: 0, v: null };
      return json({ ok: true, ...(await ttsStats(await withKeys(env.__base || env))) });
    }
    if (path === '/api/admin/tts/pos' && m === 'POST') {
      const b = await body(request, 400), nid = str(b.nid, 80), pos = Math.max(1, parseInt(b.pos, 10) || 1);
      const { results } = await env.DB.prepare("SELECT nid,MIN(ord) AS o,COUNT(*) AS n,SUM(status='done') AS d,MAX(prov) AS prov FROM tts_ch GROUP BY nid ORDER BY MIN(ord),nid").all();
      const me = results.find((r) => r.nid === nid); if (!me) return fail('الرواية مش موجودة', 404);
      // الترتيب جوه طابور نفس الحساب بس (كل حساب له طابور لوحده)
      const mine = results.filter((r) => r.prov === me.prov);
      const act = mine.filter((r) => (r.d || 0) < r.n).map((r) => r.nid).filter((x) => x !== nid);
      act.splice(Math.min(pos - 1, act.length), 0, nid);
      const base = Math.min(0, ...mine.map((r) => r.o || 0)) - act.length * 10 - 10;
      const st = act.map((x, k) => env.DB.prepare('UPDATE tts_ch SET ord=? WHERE nid=?').bind(base + k * 10, x));
      for (let i = 0; i < st.length; i += 40) await env.DB.batch(st.slice(i, i + 40));
      return json({ ok: true, ...(await ttsStats(env)) });
    }
    if (path === '/api/admin/tts/remove' && m === 'POST') {
      const b = await body(request, 500), nid = str(b.nid, 80);
      await ttsWipeNovel(env, nid);
      await env.DB.prepare('DELETE FROM tts_ch WHERE nid=?').bind(nid).run(); return json({ ok: true, ...(await ttsStats(env)) });
    }
    // تحديد المزوّد (جوجل / Azure) لرواية. redo = مسح الصوت الجاهز وتحويلها من الأول بالمزوّد ده
    if (path === '/api/admin/tts/provider' && m === 'POST') {
      const b = await body(request, 600), nid = str(b.nid, 80), prov = b.prov; if (!nid || !PROVS.includes(prov)) return fail('طلب غير صحيح');
      const conf = await getTtsConf(env), cur = await env.DB.prepare('SELECT prov FROM tts_ch WHERE nid=? LIMIT 1').bind(nid).first();
      const raw = await getSetting(env, 'tts'); await setSetting(env, 'tts', { ...raw, novelProv: { ...conf.novelProv, [nid]: prov } });
      if (cur && (cur.prov !== prov || b.redo)) {
        await ttsWipeNovel(env, nid);
        await env.DB.prepare("UPDATE tts_ch SET prov=?,sig='',done=0,secs=0,status='queued',owner='',lock_until=0,retry_at=0,attempts=0,err='',updated=? WHERE nid=?").bind(prov, Date.now(), nid).run();
      }
      return json({ ok: true, ...(await ttsStats(env)) });
    }
    if (path === '/api/admin/tts/rebalance' && m === 'POST') { const ek = await withKeys(env.__base || env); const moved = await ttsRebalance(ek); return json({ ok: true, moved, ...(await ttsStats(ek)) }); }
    if (path === '/api/admin/tts/retry' && m === 'POST') {
      const b = await body(request, 300).catch(() => ({})), pv = PROVS.includes(b.prov) ? b.prov : null;
      await env.DB.prepare("UPDATE tts_ch SET status='queued',attempts=0,retry_at=0,err='' WHERE status='failed'" + (pv ? ' AND prov=?' : '')).bind(...(pv ? [pv] : [])).run();
      for (const p of (pv ? [pv] : PROVS)) await setSetting(env, stKey(p), { ...(await getSetting(env, stKey(p))), pausedUntil: 0 });
      return json({ ok: true, ...(await ttsStats(env)) });
    }
    if (path === '/api/admin/tts/run' && m === 'POST') { const b = await body(request, 300).catch(() => ({})), r = await ttsStep(env, { force: true, prov: normProv(b.prov) }); return json({ ok: true, step: r, ...(await ttsStats(env)) }); }
    // تجربة الصوت بنص فيه راوي وراجل وست وطفل (بالمزوّد المطلوب)
    if (path === '/api/admin/tts/test' && m === 'POST') {
      const b = await body(request, 3000), conf = await getTtsConf(env), prov = normProv(b.prov);
      if (!provReady({ ...env, TTS_BUCKET: env.TTS_BUCKET || {} }, conf, prov)) return fail(prov === 'azure' ? 'مفتاح Azure أو المنطقة (Region) ناقصين' : ('مفتاح ' + PNAME[prov] + ' مش متسجّل — حطه من تابة الحساب ده'), 503);
      const text = str(b.text, 600).trim() || 'دخل أحمد الغرفة وقال بصوت هادي: «صباح الخير يا سلمى». ابتسمت سلمى وردت: «صباح النور يا أستاذ أحمد». ثم جرى الصغير نحوهما وقال بفرحة: «بابا، بابا، شوف الرسمة!»';
      const o = await speakPart(env, prov, text, conf), secs = Math.max(0, o.wav.length - 44) / 48000;
      await ttsBump(env, prov, { reqs: o.calls || 1, chars: o.chars, secs, cost: prov === 'azure' ? o.chars * conf.az.price / 1e6 : ttsCost(o.chars, secs, conf) });
      return audioResp(o.wav, false);
    }
    if (path === '/api/admin/tts/voices' && m === 'GET') {
      const prov = normProv(url.searchParams.get('prov')), conf = await getTtsConf(env), gkey = gemKey(env, prov);
      if (prov === 'azure') {
        if (!env.AZURE_SPEECH_KEY || !azRegion(env, conf)) return fail('مفتاح Azure أو المنطقة (Region) ناقصين', 503);
        const r = await fetch('https://' + azRegion(env, conf) + '.tts.speech.microsoft.com/cognitiveservices/voices/list', { headers: { 'Ocp-Apim-Subscription-Key': env.AZURE_SPEECH_KEY } });
        const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch (e) {}
        const list = Array.isArray(j) ? j.filter((v) => /^ar-/.test(v.Locale || '')).map((v) => ({ name: v.ShortName, lang: v.Locale, gender: v.Gender })) : [];
        return json({ ok: r.ok, status: r.status, voices: list, raw: list.length ? undefined : t.slice(0, 400) });
      }
      if (!gkey) return fail('مفتاح Gemini مش متحط على السيرفر', 503);
      const r = await gFetch(gemEnv(env, prov), 'https://generativelanguage.googleapis.com/v1beta/voices?pageSize=200', { headers: { 'x-goog-api-key': gkey } });
      const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch (e) {}
      const list = j && Array.isArray(j.voices) ? j.voices.map((v) => ({ name: v.name || v.voiceName || v.id, lang: v.languageCodes || v.language || v.locale || '', gender: v.gender || '' })) : [];
      return json({ ok: r.ok, status: r.status, voices: list, raw: list.length ? undefined : t.slice(0, 600) });
    }
    /* ----- المسابقة (أدمن) ----- */
    if (path === '/api/admin/contest' && m === 'GET') {
      const wk = /^\d{4}-\d{2}-\d{2}$/.test(url.searchParams.get('week') || '') ? url.searchParams.get('week') : weekStart();
      const row = await env.DB.prepare('SELECT * FROM contest_weeks WHERE week=?').bind(wk).first();
      const { results: ans } = await env.DB.prepare('SELECT a.id,a.user_id,a.answers,a.ts,u.name,u.email,u.avatar FROM contest_answers a JOIN users u ON u.id=a.user_id WHERE a.week=? ORDER BY a.ts ASC LIMIT 1000').bind(wk).all();
      const { results: weeks } = await env.DB.prepare('SELECT w.week,w.prize,w.winner_id,u.name AS wname,(SELECT COUNT(*) FROM contest_answers c WHERE c.week=w.week) AS n FROM contest_weeks w LEFT JOIN users u ON u.id=w.winner_id ORDER BY w.week DESC LIMIT 20').all();
      return json({ week: wk, current: weekStart(), questions: row ? parseJson(row.questions) : [], prize: row ? row.prize : 0, winnerId: row ? row.winner_id : 0, winnerAnswer: row ? row.winner_answer : 0,
        count: ans.length, answers: ans.map((a) => ({ id: a.id, userId: a.user_id, name: a.name, email: a.email, avatar: a.avatar || '', answers: parseJson(a.answers), ts: a.ts })), weeks });
    }
    if (path === '/api/admin/contest' && m === 'PUT') {
      const b = await body(request, 6000), wk = /^\d{4}-\d{2}-\d{2}$/.test(b.week || '') ? b.week : weekStart(), qs = cleanQs(b.questions), prize = Math.max(0, Math.min(1e7, Number(b.prize) || 0));
      await env.DB.prepare('INSERT INTO contest_weeks (week,questions,prize,updated) VALUES (?,?,?,?) ON CONFLICT(week) DO UPDATE SET questions=excluded.questions,prize=excluded.prize,updated=excluded.updated').bind(wk, JSON.stringify(qs), prize, Date.now()).run();
      return json({ ok: true, week: wk });
    }
    if (path === '/api/admin/contest/winner' && m === 'POST') {
      const b = await body(request, 600), a = await env.DB.prepare('SELECT id,week,user_id FROM contest_answers WHERE id=?').bind(+b.answerId || 0).first();
      if (!a) return fail('الإجابة مش موجودة', 404);
      const row = await env.DB.prepare('SELECT prize FROM contest_weeks WHERE week=?').bind(a.week).first(); if (!row) return fail('المسابقة مش موجودة', 404);
      await env.DB.prepare('UPDATE contest_weeks SET winner_id=?,winner_answer=?,picked_at=? WHERE week=?').bind(a.user_id, a.id, Date.now(), a.week).run();
      await notifyUser(env, a.user_id, '🏆 مبروك! فزت في مسابقة الأسبوع', 'اتختارت إجابتك الفايزة وجايزتك ' + row.prize + ' جنيه. الإدارة هتتواصل معاك.', 'pay');
      return json({ ok: true });
    }
    if (path === '/api/admin/contest/unwin' && m === 'POST') {
      const b = await body(request, 300); if (!/^\d{4}-\d{2}-\d{2}$/.test(b.week || '')) return fail('طلب غير صحيح');
      await env.DB.prepare('UPDATE contest_weeks SET winner_id=0,winner_answer=0,picked_at=0 WHERE week=?').bind(b.week).run(); return json({ ok: true });
    }
    /* ----- نقاط الفوز (أدمن) ----- */
    if (path === '/api/admin/points' && m === 'GET') {
      const pts = await getSetting(env, 'pts'), { results: top } = await env.DB.prepare("SELECT id,name,email,avatar,points FROM users WHERE points>0 ORDER BY points DESC,id ASC LIMIT 10").all();
      const { results: draws } = await env.DB.prepare('SELECT week,user_id,name,points,prize,ts FROM pts_draws ORDER BY week DESC LIMIT 12').all();
      return json({ prize: pts.prize || 0, start: pts.start || '', week: weekStart(), nextDraw: weekEndMs(weekStart()), top, draws });
    }
    if (path === '/api/admin/gold' && m === 'GET') return json(await goldConf(env));
    if (path === '/api/admin/gold' && m === 'PUT') { const b = await body(request, 300), cur = await goldConf(env); await setSetting(env, 'gold', { rate: b.rate == null ? cur.rate : b.rate, min: b.min == null ? cur.min : b.min }); return json(await goldConf(env)); }
    if (path === '/api/admin/withdrawals' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT w.*,u.name AS uname,u.email AS uemail FROM withdrawals w JOIN users u ON u.id=w.uid ORDER BY (w.status=\'pending\') DESC, w.id DESC LIMIT 100').all();
      return json({ items: results.map((w) => ({ id: w.id, uid: w.uid, user: w.uname, email: w.uemail, points: w.points, egp: w.egp, rate: w.rate, kind: w.kind, value: w.value, name: w.name, status: w.status, ts: w.ts, decided: w.decided })) });
    }
    { const mw = /^\/api\/admin\/withdrawals\/(\d+)\/(approve|reject)$/.exec(path);
      if (mw && m === 'POST') {
        const w = await env.DB.prepare('SELECT * FROM withdrawals WHERE id=?').bind(+mw[1]).first(); if (!w) return fail('الطلب مش موجود', 404);
        const st = mw[2] === 'approve' ? 'approved' : 'rejected';
        const up = await env.DB.prepare("UPDATE withdrawals SET status=?,decided=? WHERE id=? AND status='pending'").bind(st, Date.now(), w.id).run();
        if (!(up && up.meta && up.meta.changes)) return fail('الطلب اتحسم قبل كده');
        if (st === 'approved') await notifyUser(env, w.uid, '✅ تم تأكيد طلب السحب', 'تم تأكيد عملية السحب (' + w.egp + ' جنيه) وسيصلك السحب قريبًا.', 'wd');
        else await notifyUser(env, w.uid, '❌ تم رفض طلب السحب', 'تم رفض طلب السحب (' + w.egp + ' جنيه). لو فيه استفسار تواصل معنا.', 'wd');
        return json({ ok: true, status: st });
      } }
    if (path === '/api/admin/streak' && m === 'GET') return json(await streakConf(env));
    if (path === '/api/admin/streak' && m === 'PUT') { const b = await body(request, 300), cur = await streakConf(env); await setSetting(env, 'streak', { on: b.on == null ? cur.on : !!b.on, days: b.days == null ? cur.days : b.days, pts: b.pts == null ? cur.pts : b.pts }); return json(await streakConf(env)); }
    if (path === '/api/admin/points' && m === 'PUT') { const b = await body(request, 300), pts = await getSetting(env, 'pts'); await setSetting(env, 'pts', { ...pts, prize: Math.max(0, Math.min(1e7, Number(b.prize) || 0)) }); return json({ ok: true }); }
    if (path === '/api/admin/reads/reset' && m === 'POST') {
      const b = await body(request, 500);
      if (b.confirm !== 'RESET') return fail('لازم تأكيد');
      const c1 = await env.DB.prepare('SELECT COALESCE(SUM(n),0) AS s FROM reads').first();
      await env.DB.prepare('DELETE FROM reads').run();
      await env.DB.prepare('DELETE FROM read_seen').run();
      await setSetting(env, 'reads_epoch', { t: Date.now() });
      return json({ ok: true, cleared: (c1 && c1.s) || 0 });
    }
    if (path === '/api/admin/points/draw' && m === 'POST') return json({ ok: true, ...(await ptsDraw(env, true)) });
    if (path === '/api/admin/nprices' && m === 'PUT') {
      const b = await body(request, 300000); await setSetting(env, 'nprices', { prices: cleanNovelPrices(b.prices) });
      return json({ ok: true, info: await getPremiumInfo(env) });
    }
    if (path === '/api/admin/orders' && m === 'GET') {
      const all = url.searchParams.get('status') === 'all';
      const { results } = await env.DB.prepare('SELECT o.*,u.name AS uname,u.email AS uemail,a.name AS aname,a.payout AS apayout FROM orders o JOIN users u ON u.id=o.user_id LEFT JOIN users a ON a.id=o.author_id ' + (all ? '' : "WHERE o.status='pending' ") + 'ORDER BY o.created_at DESC LIMIT 100').all();
      return json({ orders: results.map((o) => ({ id: o.id, user: o.uname, email: o.uemail, userId: o.user_id, nid: o.nid, title: o.ntitle, price: o.price, share: o.share, authorId: o.author_id, author: o.aname || '', payout: o.author_id ? payoutOf(o.apayout) : null, method: o.method, sender: o.sender, proof: o.proof, note: o.note, status: o.status, reason: o.reason, paidOut: !!o.paid_out, createdAt: o.created_at, decidedAt: o.decided_at })) });
    }
    if ((g = /^\/api\/admin\/orders\/(\d+)\/(approve|reject)$/.exec(path)) && m === 'POST') {
      const b = await body(request, 2000), o = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(+g[1]).first();
      if (!o) return fail('الطلب مش موجود', 404);
      if (o.status !== 'pending') return fail('الطلب ده اتراجع قبل كده');
      if (g[2] === 'approve') {
        await env.DB.batch([env.DB.prepare("UPDATE orders SET status='approved',decided_at=? WHERE id=? AND status='pending'").bind(Date.now(), o.id),
          env.DB.prepare('INSERT OR IGNORE INTO purchases (user_id,nid,ts) VALUES (?,?,?)').bind(o.user_id, o.nid, Date.now())]);
        await notifyUser(env, o.user_id, '✅ الرواية اتفتحت ليك', 'تم تأكيد شرائك لرواية «' + o.ntitle + '». تقدر تقراها وتحمّل الـ PDF بتاعها دلوقتي.');
        if (o.author_id) await notifyUser(env, o.author_id, '💰 اتباعت نسخة من روايتك', 'اتباعت نسخة من «' + o.ntitle + '». نصيبك ' + o.share + ' جنيه (بعد نسبة الموقع ' + (COMMISSION * 100) + '%).', 'ord');
        return json({ ok: true });
      }
      const reason = str(b.reason, 300).trim();
      await env.DB.prepare("UPDATE orders SET status='rejected',reason=?,decided_at=? WHERE id=? AND status='pending'").bind(reason, Date.now(), o.id).run();
      await notifyUser(env, o.user_id, 'طلب شراء الرواية اترفض', 'طلب شراء «' + o.ntitle + '» اترفض' + (reason ? ': ' + reason : '') + '. تقدر تبعت طلب جديد أو تكلّمنا.');
      return json({ ok: true });
    }
    if (path === '/api/admin/dues' && m === 'GET') {
      const { results } = await env.DB.prepare("SELECT o.author_id,u.name,u.payout,COUNT(*) AS n,SUM(o.share) AS due FROM orders o JOIN users u ON u.id=o.author_id WHERE o.status='approved' AND o.paid_out=0 AND o.author_id>0 GROUP BY o.author_id ORDER BY due DESC").all();
      const tot = await env.DB.prepare("SELECT COALESCE(SUM(price),0) AS gross,COALESCE(SUM(price-share),0) AS site,COUNT(*) AS n FROM orders WHERE status='approved'").first();
      return json({ dues: results.map((r) => ({ authorId: r.author_id, name: r.name, sales: r.n, due: Math.round(r.due * 100) / 100, payout: payoutOf(r.payout) })), totals: { gross: tot.gross, site: tot.site, sales: tot.n } });
    }
    if ((g = /^\/api\/admin\/dues\/(\d+)\/settle$/.exec(path)) && m === 'POST') {
      const r = await env.DB.prepare("SELECT COALESCE(SUM(share),0) AS due FROM orders WHERE author_id=? AND status='approved' AND paid_out=0").bind(+g[1]).first();
      if (!r.due) return fail('مفيش مستحقات للكاتب ده');
      await env.DB.prepare("UPDATE orders SET paid_out=1 WHERE author_id=? AND status='approved' AND paid_out=0").bind(+g[1]).run();
      await notifyUser(env, +g[1], '💸 اتحوّلك مستحقاتك', 'تم تحويل ' + (Math.round(r.due * 100) / 100) + ' جنيه من مبيعات رواياتك على حساب التحويل بتاعك.');
      return json({ ok: true, amount: r.due });
    }
    if (path === '/api/admin/payments' && m === 'GET') {
      const all = url.searchParams.get('status') === 'all';
      const { results } = await env.DB.prepare('SELECT p.*,u.name AS uname,u.email AS uemail,u.premium_until AS upu FROM payments p JOIN users u ON u.id=p.user_id ' + (all ? '' : "WHERE p.status='pending' ") + 'ORDER BY p.created_at DESC LIMIT 100').all();
      return json({ payments: results.map((p) => ({ id: p.id, user: p.uname, email: p.uemail, userId: p.user_id, plan: p.plan_name, months: p.months, amount: p.amount, method: p.method, sender: p.sender, proof: p.proof, note: p.note, status: p.status, reason: p.reason, createdAt: p.created_at, decidedAt: p.decided_at })) });
    }
    if ((g = /^\/api\/admin\/payments\/(\d+)\/(approve|reject)$/.exec(path)) && m === 'POST') {
      const b = await body(request, 2000);
      const p = await env.DB.prepare('SELECT * FROM payments WHERE id=?').bind(+g[1]).first();
      if (!p) return fail('الطلب مش موجود', 404);
      if (p.status !== 'pending') return fail('الطلب ده اتراجع قبل كده');
      if (g[2] === 'approve') {
        const u = await env.DB.prepare('SELECT id,premium_until FROM users WHERE id=?').bind(p.user_id).first();
        if (!u) return fail('المستخدم مش موجود', 404);
        const until = Math.max(Date.now(), u.premium_until || 0) + p.months * 30 * 86400000;
        await env.DB.batch([
          env.DB.prepare("UPDATE payments SET status='approved',decided_at=? WHERE id=? AND status='pending'").bind(Date.now(), p.id),
          env.DB.prepare('UPDATE users SET premium_until=? WHERE id=?').bind(until, u.id)]);
        const text = 'تم تفعيل اشتراك Premium (' + p.plan_name + ') على حسابك. استمتع بالاستماع للروايات بصوت مصري 👑';
        try { await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(u.id, 'payment', 'pay', 'RadPad', '👑 اشتراكك اتفعّل', text, Date.now()).run(); if (env.FCM_SA) await sendPush(env, '👑 اشتراكك اتفعّل', text, '', 'u_' + u.id); } catch (e) {}
        return json({ ok: true, premiumUntil: until });
      }
      const reason = str(b.reason, 300).trim();
      await env.DB.prepare("UPDATE payments SET status='rejected',reason=?,decided_at=? WHERE id=? AND status='pending'").bind(reason, Date.now(), p.id).run();
      const text = 'طلب اشتراك Premium (' + p.plan_name + ') اترفض' + (reason ? ': ' + reason : '') + '. تقدر تبعت طلب جديد أو تكلّمنا.';
      try { await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(p.user_id, 'payment', 'pay', 'RadPad', 'طلب الاشتراك اترفض', text, Date.now()).run(); if (env.FCM_SA) await sendPush(env, 'طلب الاشتراك اترفض', text, '', 'u_' + p.user_id); } catch (e) {}
      return json({ ok: true });
    }
    if (path === '/api/admin/premium' && m === 'PUT') {
      const b = await body(request, 200000), prices = {};
      Object.keys(b.prices || {}).slice(0, 1000).forEach((k) => { const v = str(b.prices[k], 60).trim(); if (v) prices[str(k, 60)] = v; });
      const old0 = await getSetting(env, 'premium');
      await setSetting(env, 'premium', { whatsapp: str(b.whatsapp, 25).replace(/[^0-9+]/g, ''), defaultPrice: str(b.defaultPrice, 60).trim(), message: str(b.message, 300).trim(), prices,
        plans: b.plans ? cleanPlans(b.plans) : old0.plans, methods: b.methods ? cleanMethods(b.methods, b.whatsapp) : old0.methods, features: Array.isArray(b.features) ? cleanFeatures(b.features) : old0.features });
      return json({ ok: true, info: await getPremiumInfo(env) });
    }
    if (path === '/api/admin/site-novels/import' && m === 'POST') {
      const b = await body(request), n = cleanNovel(b), sid = str(b.siteId, 80).trim();
      if (!sid) return fail('معرّف رواية الموقع ناقص');
      const ex = await env.DB.prepare("SELECT id,user_id FROM novels WHERE d_extra LIKE ?").bind('%"siteId":"' + sid.replace(/[%_"\\]/g, '') + '"%').first();
      const x = JSON.parse(n.extra); x.siteId = sid; const extra = JSON.stringify(x), now = Date.now(), tags = JSON.stringify(n.tags);
      let id;
      if (ex && extraOf((await env.DB.prepare('SELECT d_extra FROM novels WHERE id=?').bind(ex.id).first()).d_extra).siteId === sid) {
        id = ex.id;
        await env.DB.batch([
          env.DB.prepare("UPDATE novels SET d_title=?,d_author=?,d_genre=?,d_tags=?,d_synopsis=?,d_cover=?,d_extra=?,l_title=?,l_author=?,l_genre=?,l_tags=?,l_synopsis=?,l_cover=?,l_extra=?,is_live=1,status='approved',updated_at=? WHERE id=?")
            .bind(n.title, n.author || user.name, n.genre, tags, n.synopsis, n.cover, extra, n.title, n.author || user.name, n.genre, tags, n.synopsis, n.cover, extra, now, id),
          ...chapterStmts(env, id, 'd', n.chapters), ...chapterStmts(env, id, 'l', n.chapters)]);
      } else {
        const r = await env.DB.prepare("INSERT INTO novels (user_id,status,is_live,hidden,created_at,updated_at,published_at,d_title,d_author,d_genre,d_tags,d_synopsis,d_cover,d_extra,l_title,l_author,l_genre,l_tags,l_synopsis,l_cover,l_extra) VALUES (?,?,1,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
          .bind(user.id, 'approved', now, now, now, n.title, n.author || user.name, n.genre, tags, n.synopsis, n.cover, extra, n.title, n.author || user.name, n.genre, tags, n.synopsis, n.cover, extra).run();
        id = r.meta.last_row_id;
        await env.DB.batch([...chapterStmts(env, id, 'd', n.chapters), ...chapterStmts(env, id, 'l', n.chapters)]);
      }
      try { await applyServerVault(env); } catch (e) {}
      return json({ ok: true, id, chapters: n.chapters.length });
    }
    if (path === '/api/admin/vault' && m === 'PUT') {
      const b = await body(request, 2000000), keys = {};
      Object.keys(b.keys || {}).slice(0, 2000).forEach((id) => {
        const k = b.keys[id] || {}, c = {};
        Object.keys(k.c || {}).slice(0, 500).forEach((i) => { c[str(i, 6)] = str(k.c[i], 80); });
        keys[str(id, 60)] = { n: str(k.n, 80), p: str(k.p, 80), c };
      });
      await setSetting(env, 'vault', { keys, at: Date.now() });
      try { await applyServerVault(env); } catch (e) {}
      return json({ ok: true, count: Object.keys(keys).length });
    }
    if (path === '/api/admin/contact' && m === 'GET') { const { results } = await env.DB.prepare('SELECT id,uid,name,email,kind,text,ts FROM contact ORDER BY ts DESC LIMIT 200').all(); return json({ items: results }); }
    if ((g = /^\/api\/admin\/contact\/(\d+)\/delete$/.exec(path)) && m === 'POST') { await env.DB.prepare('DELETE FROM contact WHERE id=?').bind(+g[1]).run(); return json({ ok: true }); }
    if (path === '/api/admin/cmt' && m === 'GET') return json(await cmtConf(env));
    if (path === '/api/admin/cmt' && m === 'PUT') { const b = await body(request, 500), cur = await cmtConf(env); await setSetting(env, 'cmt', { perCh: b.perCh ?? cur.perCh, perDay: b.perDay ?? cur.perDay, pts: b.pts ?? cur.pts, minLen: b.minLen ?? cur.minLen, dayPts: b.dayPts ?? cur.dayPts, newsPerDay: b.newsPerDay ?? cur.newsPerDay }); return json({ ok: true, ...(await cmtConf(env)) }); }
    if (path === '/api/admin/news/pending' && m === 'GET') { const { results } = await env.DB.prepare("SELECT n.id,n.title,n.text,n.img,n.ts,n.author_uid AS auid,u.name AS author,u.avatar AS aavatar FROM news n LEFT JOIN users u ON u.id=n.author_uid WHERE n.status='pending' ORDER BY n.ts DESC LIMIT 50").all(); return json({ items: results }); }
    if ((g = /^\/api\/admin\/news\/(\d+)\/(approve|reject)$/.exec(path)) && m === 'POST') {
      const row = await env.DB.prepare("SELECT author_uid,title FROM news WHERE id=? AND status='pending'").bind(+g[1]).first(); if (!row) return fail('مش موجود', 404);
      if (g[2] === 'approve') { await env.DB.prepare("UPDATE news SET status='ok',ts=? WHERE id=?").bind(Date.now(), +g[1]).run(); await notifyUser(env, row.author_uid, '✅ بوستك اتنشر في الأخبار الأدبية', row.title, 'news'); }
      else { await env.DB.prepare("UPDATE news SET status='no' WHERE id=?").bind(+g[1]).run(); await notifyUser(env, row.author_uid, 'بوستك ما اتنشرش', row.title, 'news'); }
      return json({ ok: true });
    }
    if (path === '/api/admin/news' && m === 'POST') {
      const b = await body(request, 4000), title = str(b.title, 120).trim(), text = str(b.text, 3000).trim();
      if (!title) return fail('اكتب عنوان الخبر');
      const r = await env.DB.prepare('INSERT INTO news (title,text,img,url,ts) VALUES (?,?,?,?,?)').bind(title, text, cleanUrl(b.img), cleanUrl(b.url), Date.now()).run();
      await env.DB.prepare('DELETE FROM news WHERE id NOT IN (SELECT id FROM news ORDER BY ts DESC LIMIT 100)').run();
      if (b.push) { try { await sendPush(env, '📰 ' + title, text.slice(0, 200), cleanUrl(b.url)); } catch (e) {} }
      return json({ ok: true, id: r.meta.last_row_id });
    }
    if ((g = /^\/api\/admin\/news\/(\d+)\/delete$/.exec(path)) && m === 'POST') { await env.DB.prepare('DELETE FROM news WHERE id=?').bind(+g[1]).run(); return json({ ok: true }); }
    if ((g = /^\/api\/admin\/bcast\/(\d+)\/delete$/.exec(path)) && m === 'POST') { await env.DB.prepare('DELETE FROM bcast WHERE id=?').bind(+g[1]).run(); return json({ ok: true }); }
    if (path === '/api/admin/notes/clear' && m === 'POST') {
      const b = await body(request, 500).catch(() => ({})), days = Math.max(0, Math.min(3650, parseInt(b.days, 10) || 0));
      const r = await env.DB.prepare('DELETE FROM notes WHERE ts<?').bind(days ? Date.now() - days * 86400000 : Date.now() + 1000).run();
      return json({ ok: true, removed: (r.meta && r.meta.changes) || 0 });
    }
    if (path === '/api/admin/push' && m === 'POST') {
      const b = await body(request, 20000);
      if (await tooMany(env, 'push:' + user.id, 30, 3600000)) return fail('بعتّ إشعارات كتير، استنى شوية', 429);
      await noteAttempt(env, 'push:' + user.id);
      const bt = str(b.title, 80).trim() || 'RadPad', bx = str(b.text, 600).trim() || bt, bu = cleanUrl(b.url);
      if (!str(b.title, 80).trim() && !str(b.text, 600).trim()) return fail('اكتب عنوان أو نص الإشعار');
      let id = 0;
      if (b.bell !== false) { const r = await env.DB.prepare('INSERT INTO bcast (title,text,url,ts) VALUES (?,?,?,?)').bind(bt, bx, bu, Date.now()).run(); id = r.meta.last_row_id; await env.DB.prepare('DELETE FROM bcast WHERE id NOT IN (SELECT id FROM bcast ORDER BY ts DESC LIMIT 200)').run(); }
      let pushErr = '';
      if (b.push !== false) { try { await sendPush(env, bt, bx.slice(0, 300), bu); } catch (e) { pushErr = e.message || 'فشل إرسال الموبايل'; } }
      if (pushErr && !id) return fail(pushErr, 502);
      return json({ ok: true, id, pushErr });
    }
    if ((g = /^\/api\/admin\/users\/(\d+)\/devices\/reset$/.exec(path)) && m === 'POST') { await env.DB.prepare('DELETE FROM sessions WHERE uid=?').bind(+g[1]).run(); return json({ ok: true }); }
    if ((g = /^\/api\/admin\/users\/(\d+)\/premium$/.exec(path)) && m === 'POST') {
      const b = await body(request, 2000);
      const u = await env.DB.prepare('SELECT id,premium_until FROM users WHERE id=?').bind(+g[1]).first();
      if (!u) return fail('المستخدم غير موجود', 404);
      let until;
      if (b.months === 'forever') until = FOREVER;
      else { const mo = parseInt(b.months, 10); if (!(mo >= 0 && mo <= 1200)) return fail('مدة غير صحيحة'); until = mo === 0 ? 0 : Math.max(Date.now(), u.premium_until || 0) + mo * 30 * 86400000; }
      await env.DB.prepare('UPDATE users SET premium_until=? WHERE id=?').bind(until, u.id).run();
      return json({ ok: true, premiumUntil: until });
    }
    if (path === '/api/admin/online' && m === 'GET') {
      const now = Date.now(), cnt = async (sql, ...b) => (await env.DB.prepare(sql).bind(...b).first()).n || 0;
      const d0 = dayKey(now), d7 = dayKey(now - 6 * 86400000), d30 = dayKey(now - 29 * 86400000), on = now - 3 * 60000;
      const out = {
        online: await cnt('SELECT COUNT(*) AS n FROM presence WHERE seen>?', on), onlineUsers: await cnt('SELECT COUNT(*) AS n FROM presence WHERE seen>? AND uid>0', on),
        day: await cnt('SELECT COUNT(*) AS n FROM visits WHERE day=?', d0), dayUsers: await cnt('SELECT COUNT(*) AS n FROM visits WHERE day=? AND uid>0', d0),
        week: await cnt('SELECT COUNT(DISTINCT dev) AS n FROM visits WHERE day>=?', d7), weekUsers: await cnt('SELECT COUNT(DISTINCT uid) AS n FROM visits WHERE day>=? AND uid>0', d7),
        month: await cnt('SELECT COUNT(DISTINCT dev) AS n FROM visits WHERE day>=?', d30), monthUsers: await cnt('SELECT COUNT(DISTINCT uid) AS n FROM visits WHERE day>=? AND uid>0', d30), since: 0 };
      const f = await env.DB.prepare('SELECT MIN(day) AS d FROM visits').first(); out.since = f && f.d || '';
      return json(out);
    }
    if (path === '/api/admin/users' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT u.id,u.email,u.name,u.role,u.created_at,u.premium_until,u.last_ip,u.last_seen,(SELECT COUNT(*) FROM novels n WHERE n.user_id=u.id) AS novels FROM users u ORDER BY u.id DESC LIMIT 1000').all();
      return json({ users: results.map((u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, createdAt: u.created_at, premiumUntil: u.premium_until || 0, premium: isPremium(u), novels: u.novels, lastIp: u.last_ip || '', lastSeen: u.last_seen || 0 })) });
    }
    if ((g = /^\/api\/admin\/users\/(\d+)\/role$/.exec(path)) && m === 'POST') {
      const b = await body(request, 200), role = b.role === 'admin' ? 'admin' : 'user', tid = +g[1];
      const t = await env.DB.prepare('SELECT id,name,role FROM users WHERE id=?').bind(tid).first();
      if (!t) return fail('المستخدم غير موجود', 404);
      const owner = await env.DB.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").first();
      if (role === 'user') { if (t.id === user.id) return fail('مينفعش تشيل الأدمن من نفسك'); if (owner && t.id === owner.id) return fail('ده الأدمن الأساسي ومينفعش يتشال', 403); }
      await env.DB.prepare('UPDATE users SET role=? WHERE id=?').bind(role, tid).run();
      await notifyUser(env, tid, role === 'admin' ? '🛡️ بقيت أدمن في RadPad' : 'اتشالت صلاحية الأدمن من حسابك', role === 'admin' ? 'سجّل خروج وادخل تاني علشان تظهر لك لوحة التحكم.' : '', 'role');
      return json({ ok: true, role });
    }
    if ((g = /^\/api\/admin\/users\/(\d+)\/reset$/.exec(path)) && m === 'POST') {
      const u = await env.DB.prepare('SELECT id,email FROM users WHERE id=?').bind(+g[1]).first();
      if (!u) return fail('المستخدم غير موجود', 404);
      const alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      const rnd = crypto.getRandomValues(new Uint8Array(10));
      const temp = Array.from(rnd, (x) => alphabet[x % alphabet.length]).join('');
      await env.DB.prepare('UPDATE users SET pass_hash=? WHERE id=?').bind(await hashPassword(temp), u.id).run();
      return json({ email: u.email, tempPassword: temp });
    }
    if ((g = /^\/api\/admin\/novels\/(\d+)\/live$/.exec(path)) && m === 'GET') {
      const r = await env.DB.prepare('SELECT n.*,u.name AS owner FROM novels n JOIN users u ON u.id=n.user_id WHERE n.id=? AND n.is_live=1').bind(+g[1]).first();
      if (!r) return fail('الرواية مش منشورة', 404);
      const { results } = await env.DB.prepare("SELECT title,content,locked FROM chapters WHERE novel_id=? AND ver='l' ORDER BY idx").bind(+g[1]).all();
      return json({ novel: { ...liveNovelRow(r), owner: r.owner, uid: r.user_id, chapters: results.map((c, i) => ({ title: c.title, content: c.content, locked: !!c.locked, release: extraOf(r.l_extra).rel[i] || 0 })) } });
    }
    if ((g = /^\/api\/admin\/novels\/(\d+)$/.exec(path)) && m === 'DELETE') {
      await env.DB.batch([env.DB.prepare('DELETE FROM chapters WHERE novel_id=?').bind(+g[1]), env.DB.prepare('DELETE FROM novels WHERE id=?').bind(+g[1])]);
      return json({ ok: true });
    }
    if (path === '/api/admin/live' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT n.*,u.name AS owner FROM novels n JOIN users u ON u.id=n.user_id WHERE n.is_live=1 ORDER BY n.published_at DESC').all();
      return json({ novels: results.map((r) => ({ ...myNovelRow(r), owner: r.owner, title: r.l_title })) });
    }
  }
  return fail('غير موجود', 404);
}
