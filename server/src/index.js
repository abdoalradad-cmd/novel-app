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
    'CREATE INDEX IF NOT EXISTS idx_cmt_nid ON cmt_log(nid)',
    'CREATE INDEX IF NOT EXISTS idx_cmt_norm ON cmt_log(norm)',
    'CREATE INDEX IF NOT EXISTS idx_votes_nid ON pts_votes(nid)',
    'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, author_id INTEGER NOT NULL, kind TEXT NOT NULL, novel_id INTEGER NOT NULL, title TEXT NOT NULL, ts INTEGER NOT NULL)',
    'CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)',
    'CREATE TABLE IF NOT EXISTS sessions (uid INTEGER NOT NULL, dev TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (uid, dev))',
    'CREATE TABLE IF NOT EXISTS presence (dev TEXT PRIMARY KEY, uid INTEGER NOT NULL DEFAULT 0, ip TEXT NOT NULL DEFAULT \'\', seen INTEGER NOT NULL DEFAULT 0)',
    'CREATE INDEX IF NOT EXISTS idx_presence_seen ON presence(seen)',
    'CREATE TABLE IF NOT EXISTS gone_sent (uid INTEGER PRIMARY KEY, lvl INTEGER NOT NULL DEFAULT 0, seen INTEGER NOT NULL DEFAULT 0, ts INTEGER NOT NULL DEFAULT 0)',
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
    "CREATE TABLE IF NOT EXISTS oauth_ids (provider TEXT NOT NULL, sub TEXT NOT NULL, uid INTEGER NOT NULL, ts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (provider, sub))",
    "CREATE TABLE IF NOT EXISTS streaks (uid INTEGER PRIMARY KEY, last TEXT NOT NULL DEFAULT '', cur INTEGER NOT NULL DEFAULT 0, awards INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS ch_alerts (uid INTEGER NOT NULL, nid TEXT NOT NULL, ch INTEGER NOT NULL, rel INTEGER NOT NULL DEFAULT 0, title TEXT NOT NULL DEFAULT '', sent INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (uid, nid, ch))",
    'CREATE INDEX IF NOT EXISTS ch_alerts_due ON ch_alerts (sent, rel)',
    "CREATE TABLE IF NOT EXISTS tts_notify_q (nid TEXT NOT NULL, idx INTEGER NOT NULL, auid INTEGER NOT NULL, ts INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'new', err TEXT NOT NULL DEFAULT '', done_ts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (nid, idx))",
    "CREATE TABLE IF NOT EXISTS tts_gen_stage (nid TEXT NOT NULL, idx INTEGER NOT NULL, ch_id INTEGER NOT NULL, old_id INTEGER NOT NULL DEFAULT 0, old_updated INTEGER NOT NULL DEFAULT 0, nparts INTEGER NOT NULL, secs REAL NOT NULL DEFAULT 0, parts TEXT NOT NULL DEFAULT '[]', sig TEXT NOT NULL DEFAULT '', voice TEXT NOT NULL DEFAULT '', src_sig TEXT NOT NULL DEFAULT '', staged_at INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'staged', err TEXT NOT NULL DEFAULT '', PRIMARY KEY (nid, idx, ch_id))",
    "CREATE TABLE IF NOT EXISTS tts_notify_gen (nid TEXT NOT NULL, idx INTEGER NOT NULL, ch_id INTEGER NOT NULL, ts INTEGER NOT NULL DEFAULT 0, res TEXT NOT NULL DEFAULT '', PRIMARY KEY (nid, idx, ch_id))",
    "CREATE TABLE IF NOT EXISTS pts_draws (week TEXT PRIMARY KEY, user_id INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL DEFAULT '', avatar TEXT NOT NULL DEFAULT '', points REAL NOT NULL DEFAULT 0, prize REAL NOT NULL DEFAULT 0, ts INTEGER NOT NULL DEFAULT 0)",
    'CREATE TABLE IF NOT EXISTS purchases (user_id INTEGER NOT NULL, nid TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (user_id, nid))',
    "CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, nid TEXT NOT NULL, ntitle TEXT NOT NULL DEFAULT '', author_id INTEGER NOT NULL DEFAULT 0, price REAL NOT NULL DEFAULT 0, share REAL NOT NULL DEFAULT 0, method TEXT NOT NULL DEFAULT '', sender TEXT NOT NULL DEFAULT '', proof TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', reason TEXT NOT NULL DEFAULT '', paid_out INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, decided_at INTEGER NOT NULL DEFAULT 0)",
    'CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at)',
    'CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status, created_at)',
    'CREATE TABLE IF NOT EXISTS tts_usage (day TEXT PRIMARY KEY, reqs INTEGER NOT NULL DEFAULT 0, hits INTEGER NOT NULL DEFAULT 0, chars INTEGER NOT NULL DEFAULT 0, secs REAL NOT NULL DEFAULT 0, cost REAL NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, limited INTEGER NOT NULL DEFAULT 0)']) await env.DB.prepare(q).run();
  try { await env.DB.prepare('SELECT fmt FROM tts_ch LIMIT 1').first(); } catch (e) { try { await env.DB.prepare("ALTER TABLE tts_ch ADD COLUMN fmt TEXT NOT NULL DEFAULT 'wav'").run(); } catch (e2) {} }
  for (const [c, d] of [['fmt', "TEXT NOT NULL DEFAULT 'wav'"], ['mp3_meta', "TEXT NOT NULL DEFAULT ''"]]) { try { await env.DB.prepare('SELECT ' + c + ' FROM tts_gen_stage LIMIT 1').first(); } catch (e) { try { await env.DB.prepare('ALTER TABLE tts_gen_stage ADD COLUMN ' + c + ' ' + d).run(); } catch (e2) {} } } // جيل مجهّز بصيغة MP3: fmt + mp3_meta (kbps + مدد الأجزاء)
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
  try { await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(uid, 'payment', ref, 'RadPad', title, text, Date.now()).run(); if (env.FCM_SA) await sendPush(env, title, text, '', 'u_' + uid, ref); } catch (e) {}
}
async function notifyAdmins(env, who, title, text, ref = 'ordadm') {
  try {
    const { results } = await env.DB.prepare("SELECT id FROM users WHERE role='admin'").all();
    for (const a of results) {
      await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(a.id, 'payment', ref, who, title, text, Date.now()).run();
      if (env.FCM_SA) { try { await sendPush(env, title, text, '', 'u_' + a.id, ref); } catch (e) {} }
    }
  } catch (e) {}
}

/* ---------- الصوت المصري: Gemini + Azure — طابور لكل مزوّد + أصوات متعددة + تخزين R2 + متابعة التكلفة ---------- */
const ROLES = ['narrator', 'man', 'woman', 'boy', 'girl'];
const G_VOICES = { narrator: 'Charon', man: 'Orus', woman: 'Kore', boy: 'Puck', girl: 'Leda' };
const RD_DEF = { mode: 'B', skipNarration: false, humanize: true, pauseMs: 380, batch: 7, autoWait: true, waitSec: 16, narrator: 'kareem', archMap: {}, pers: {}, analysis: 'ai', anaModel: 'gemini-3-flash-preview', partChars: 0, dialect: 2, human: 1, tashkeel: 1 };
function normRd(x) { // كل إعدادات أداة الرداد (كلها بتتغيّر من الأدمن؛ الافتراضي = اللي كان شغال)
  x = x && typeof x === 'object' ? x : {}; const num = (v, d, lo, hi) => (v == null || v === '' || isNaN(+v) ? d : Math.max(lo, Math.min(hi, +v)));
  const ids = RD_P.map((p) => p.id), am = {}, ps = {};
  Object.entries(x.archMap || {}).forEach(([k, v]) => { if (ids.includes(v) && /^[a-z_]{2,40}$/.test(k)) am[k] = v; });
  Object.entries(x.pers || {}).forEach(([k, v]) => { if (ids.includes(k) && v) ps[k] = { v: /^[A-Za-z]{3,24}$/.test(v.v || '') ? v.v : '', p: +v.p ? num(v.p, 0, 0.7, 1.4) : 0 }; });
  return { mode: ['A', 'B', 'C'].includes(x.mode) ? x.mode : 'B', analysis: x.analysis === 'local' ? 'local' : 'ai', skipNarration: x.skipNarration === true, humanize: x.humanize !== false, pauseMs: num(x.pauseMs, 380, 0, 3000), batch: Math.round(num(x.batch, 7, 1, 10)), autoWait: x.autoWait !== false, waitSec: Math.round(num(x.waitSec, 16, 0, 60)), narrator: ids.includes(x.narrator) ? x.narrator : 'kareem', archMap: am, pers: ps, anaModel: /^[a-z0-9.\-]{4,60}$/i.test(x.anaModel || '') ? x.anaModel : 'gemini-3-flash-preview', partChars: Math.round(num(x.partChars, 0, 0, 3000)), learn: x.learn !== false, dialect: Math.round(num(x.dialect, 2, 0, 2)), human: Math.round(num(x.human, 1, 0, 2)), tashkeel: Math.round(num(x.tashkeel, 1, 0, 1)) };
}
const TTS_DEFAULT = { model: 'gemini-3.8-flash-tts', legacyModel: 'gemini-2.5-flash-preview-tts', style: 'warm, expressive audiobook narration in natural Egyptian Arabic', concurrency: 2, dailyMin: 20, freeMin: 0, priceIn: 0, priceOut: 0,
  gv: G_VOICES, defProv: 'gemini', novelProv: {} };
const PROVS = ['gemini', 'gemini2', 'gemini3', 'gemini4', 'gemini5', 'gemini6', 'rd1', 'rd2', 'rd3', 'rd4', 'rd5', 'rd6'];
const isGoogle = (p) => /^(gemini\d*|rd[1-6])$/.test(p);
const normProv = (p) => (PROVS.includes(p) ? p : 'gemini');
// حسابات جوجل (1..6): كل حساب له مفتاحه وإعداداته وطابوره. المفتاح من أسرار Cloudflare (GEMINI_API_KEY, _2.._6) أو متسجّل من لوحة الأدمن
const GN = { gemini: '', gemini2: '_2', gemini3: '_3', gemini4: '_4', gemini5: '_5', gemini6: '_6', rd1: '_RD1', rd2: '_RD2', rd3: '_RD3', rd4: '_RD4', rd5: '_RD5', rd6: '_RD6' };
const gemKey = (env, prov) => env['GEMINI_API_KEY' + (GN[prov] || '')];
const gemEnv = (env, prov) => (prov === 'gemini' ? env : { ...env, GEMINI_API_KEY: gemKey(env, prov) });
const gcf = (conf, prov) => (prov === 'gemini' ? conf : conf[(prov[0] === 'r' ? 'r' + prov.slice(2) : 'g' + prov.slice(6))] || { dailyMin: 0, concurrency: 1, freeMin: 0 });
const provCap = (conf, prov) => gcf(conf, prov).dailyMin;
// السقف اليومي بيتضرب في عدد مفاتيح الحساب (كل مفتاح ليه حصته)
const provCapE = (env, conf, prov) => provCap(conf, prov) * Math.max(1, gKeyList({ GEMINI_API_KEY: gemKey(env, prov) }).length);
const provPar = (conf, prov) => gcf(conf, prov).concurrency;
let KC = { at: 0, v: null };
async function savedKeys(env) { if (!KC.v || Date.now() - KC.at > 15000) KC = { at: Date.now(), v: (await getSetting(env, 'tts_keys')) || {} }; return KC.v; }
async function withKeys(env) { const k = await savedKeys(env), e = { ...env, __base: env.__base || env }; for (const p of PROVS) if (isGoogle(p) && k[p]) e['GEMINI_API_KEY' + GN[p]] = k[p]; return e; }
async function getTtsConf(env) {
  const x = await getSetting(env, 'tts'), n = (v, d, lo, hi) => { const k = Number(v); return v !== '' && v != null && Number.isFinite(k) && k >= lo && k <= hi ? k : d; };
  const gv = {}; ROLES.forEach((r) => { const v = x.gv && x.gv[r]; gv[r] = /^[A-Za-z0-9_-]{2,40}$/.test(String(v || '')) ? String(v) : G_VOICES[r]; });
  const np = {}; Object.keys(x.novelProv || {}).slice(0, 2000).forEach((k) => { if (PROVS.includes(x.novelProv[k])) np[k] = x.novelProv[k]; });
  return { model: x.model || TTS_DEFAULT.model, legacyModel: x.legacyModel || TTS_DEFAULT.legacyModel, style: x.style || TTS_DEFAULT.style, gv,
    concurrency: n(x.concurrency, TTS_DEFAULT.concurrency, 1, 4), dailyMin: n(x.dailyMin, TTS_DEFAULT.dailyMin, 0, 100000), freeMin: n(x.freeMin, 0, 0, 100000), priceIn: n(x.priceIn, 0, 0, 1000), priceOut: n(x.priceOut, 0, 0, 1000),
    defProv: PROVS.includes(x.defProv) ? x.defProv : 'gemini', novelProv: np, rd: normRd(x.rd), engine: x.engine === 'single' ? 'single' : 'mega', phon: x.phon !== false, hideListen: x.hideListen === true, listenAll: x.listenAll === true, rebalance: x.rebalance !== false, annModel: /^[A-Za-z0-9._-]{2,60}$/.test(String(x.annModel || '')) ? String(x.annModel) : 'gemini-2.5-flash', dict: String(x.dict || '').slice(0, 3000),
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
    r6: { dailyMin: n((x.r6 || {}).dailyMin, 20, 0, 100000), freeMin: n((x.r6 || {}).freeMin, 0, 0, 100000), concurrency: n((x.r6 || {}).concurrency, 2, 1, 4) }};
}
const provReady = (env, conf, prov) => !!env.TTS_BUCKET && !!gemKey(env, prov);
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
/* ---------- تقسيم النص لأدوار: راوي / راجل / ست / ولد / بنت ---------- */
const SPEECH_STEMS = ['قال', 'رد', 'همس', 'صرخ', 'صاح', 'سال', 'اجاب', 'تمتم', 'هتف', 'اضاف', 'تابع', 'زمجر', 'تنهد', 'ضحك', 'بكي', 'نادي', 'اعترض', 'اكد', 'قاطع', 'هدر', 'تافف', 'تساءل', 'اعترف', 'اردف', 'تحدث', 'توسل', 'استنكر', 'تذمر', 'تلعثم', 'شهق', 'ابتسم', 'لعن', 'امر', 'اقترح', 'عقب', 'علق', 'فسر', 'شرح', 'حذر', 'ردد', 'كرر', 'غمغم', 'تمتمت', 'زعق', 'عاتب', 'رجا', 'قرر', 'سخر', 'همهم', 'اجابه', 'اجابها'];
const SP_M = [...new Set(SPEECH_STEMS)].filter((x) => x !== 'تمتمت'), SP_F = SP_M.map((x) => (/ي$/.test(x) ? x.slice(0, -1) : x) + 'ت');
const reSpM = new RegExp('(?:^|[\\s،,.:؛"«»\\-])[وف]?(?:' + SP_M.join('|') + ')(?:ه|ها|لها|له|لهم)?(?=[\\s،,.:؛"«»!؟?\\-]|$)');
const reSpF = new RegExp('(?:^|[\\s،,.:؛"«»\\-])[وف]?(?:' + SP_F.join('|') + ')(?:ه|ها|لها|له|لهم)?(?=[\\s،,.:؛"«»!؟?\\-]|$)');
const reKidG = /(?:^|[\s،,.:؛])(?:ال)?(?:طفلة|صغيرة|بنت صغيرة|فتاة صغيرة|البنت الصغيرة|الفتاة الصغيرة|طفلتي|طفلتها|بنتها الصغيرة)(?=[\s،,.:؛]|$)/;
const reKidB = /(?:^|[\s،,.:؛])(?:ال)?(?:طفل|صغير|ولد صغير|صبي|غلام|الولد الصغير|طفلي|طفلها)(?=[\s،,.:؛]|$)/;
const OPP = { man: 'woman', woman: 'man', boy: 'man', girl: 'woman' };
// بيرجّع [{role, text}] (النص من غير علامات التنصيص والشرطات). بدون حوار = راوي واحد.
function wavPcm(b) { // يرجّع بيانات الصوت (PCM) من ملف WAV
  for (let i = 12; i + 8 <= b.length;) { const id = String.fromCharCode(b[i], b[i + 1], b[i + 2], b[i + 3]), sz = b[i + 4] | (b[i + 5] << 8) | (b[i + 6] << 16) | (b[i + 7] << 24); if (id === 'data') return b.subarray(i + 8, sz > 0 && i + 8 + sz <= b.length ? i + 8 + sz : b.length); i += 8 + sz + (sz & 1); }
  return b.subarray(44);
}
const ROLE_EN = { narrator: 'the narrator', man: 'an adult man', woman: 'an adult woman', boy: 'a young boy', girl: 'a young girl' };
const DIA_N = 'narrating in clear Modern Standard Arabic (Fusha) with correct grammar and pronunciation, never colloquial';
const DIA_C = 'speaking in 100% natural Egyptian colloquial Arabic (Cairene, hard "g" for jim), never Fusha';
/* ---- تمييز المتكلم بذكاء: نموذج جوجل النصي بيقرا الفقرة (ومعاها اللي قبلها) ويحدد لكل جزء مين بيتكلم: راجل / ست / ولد / بنت ---- */
const ROLE_ENUM = ['narrator', 'man', 'woman', 'boy', 'girl'];
// تقليل عدد الطلبات لجوجل (حدّها في الدقيقة قليل): الأجزاء القصيرة تتدمج في اللي جنبها، وبحد أقصى 4 طلبات للجزء
// لما بندمج أجزاء بانفعالات مختلفة منحافظش على الانفعال بتاع كل جزء جوه النص نفسه: [بغضب] كلام... [بهمس] كلام...

/* ---------- تشكيل الحوار بالنطق المصري (منقول من أداة الرداد): بيتطبّق على كلام الشخصيات بس، والسرد فصحى ---------- */
function stripDiacritics(str = '') {
  return str.replace(/[\u064B-\u065F\u0670]/g, '').trim();
}

// ============================================================================
// SMART EGYPTIAN PHONETIC ENGINE V11.0 🇪🇬
// (تشكيل مصري ذكي خفيف بالحروف العربية السليمة 100% بدون قلب القاف همزة في الكتابة وبدون التشكيل المفرط الذي يحول الصوت للخليجي)
// ============================================================================

/**
 * موسوعة المصطلحات والتعبيرات المصرية المركبة (Idioms & Collocations Bank):
 * مكتوبة بالحروف العربية الصحيحة 100% مع التشكيل الذكي المستهدف فقط على الحروف الفارقة
 * وتحويل التراكيب الخليجية المشتركة (مثل: "والله ما كان قصدي") إلى التركيب المصري القاهري الأصيل ("والله مَكانش قَصدي")
 */
const EGYPTIAN_IDIOMS_BANK = {
  // منع الانزلاق للهجة الخليجية في جمل الاعتذار والحلفان
  'والله ما كان قصدي': 'والله مَكانش قَصدي',
  'والله ماكان قصدي': 'والله مَكانش قَصدي',
  'ما كان قصدي': 'مَكانش قَصدي',
  'ماكانش قصدي': 'مَكانش قَصدي',
  'مكانش قصدي': 'مَكانش قَصدي',
  'مش قصدي': 'مِش قَصدي',
  'غصب عني': 'غَصب عنّي',
  'غصبن عني': 'غَصب عنّي',
  'حقك عليا': 'حَقّك عليّا',
  'حقك عليّ': 'حَقّك عليّا',

  // مصطلحات الشهامة والجدعنة المصرية بالحروف السليمة والتشكيل الدقيق
  'رقبتي سدادة': 'رَقْبتي سَدّادة',
  'رقبتي سدّادة': 'رَقْبتي سَدّادة',
  'رقبتى سدادة': 'رَقْبتي سَدّادة',
  'رقبتي سداده': 'رَقْبتي سَدّادة',
  'على عيني وراسي': 'على عيني وراسي',
  'على عيني وعلى راسي': 'على عيني وعلى راسي',
  'من عينيا الجوز': 'من عينيّا الجوز',
  'من عينيا الاتنين': 'من عينيّا الاتنين',
  'من عينيا': 'من عينيّا',
  'حقي برقبتي': 'حَقّي برَقْبتي',
  'وشي في وشك': 'وِشّي في وِشّك',
  'إيدك معايا': 'إيدك معايا',
  'كتر خيرك': 'كَتّر خيرك',
  'كثر خيرك': 'كَتّر خيرك',
  'ربنا يخليك': 'ربّنا يخلّيك',
  'ربنا يستر': 'ربّنا يُستر',
  'ولا يهمك': 'ولا يهِمّك',

  // مصطلحات الغضب والانفعال المصرية بالحروف السليمة
  'دمي محروق': 'دَمّي محروق',
  'دمي فار': 'دَمّي فار',
  'دمي بيغلي': 'دَمّي بيِغلي',
  'حرقت دمي': 'حرَقت دَمّي',
  'مش طايق نفسي': 'مِش طايق نَفسي',
  'جبت آخري': 'جِبت آخري',
  'طلع عيني': 'طَلّع عيني',
  'نشف ريقي': 'نَشّف ريقي',
  'وجع دماغ': 'وَجع دماغ',
  'وجع قلب': 'وَجع قَلب',
  'مليش نفس أقعد': 'ماليش نِفْس أقعد',
  'مليش نفس': 'ماليش نِفْس',
  'ماليش نفس': 'ماليش نِفْس',
  'نفسي مسدودة': 'نِفْسي مسدودة',
  'نفسي مقفولة': 'نِفْسي مقفولة',
  'صعبان عليا': 'صَعبان عليّا',
  'يا نهار اسود': 'يا نهار إسوِد',
  'يا نهار أسود': 'يا نهار إسوِد',

  // مصطلحات الحوار اليومي
  'طول بالك': 'طَوّل بالك',
  'طولي بالك': 'طَوّلي بالك',
  'خلي بالك من نفسك': 'خلّي بالك من نَفسك',
  'خلي بالك': 'خلّي بالك',
  'خد بالك': 'خُد بالك',
  'عشرة عمر': 'عِشْرة عُمر',
  'عيش وملح': 'عيش ومَلح',
  'اللي فات مات': 'اللي فات مات',
  'ملوش لازمة': 'مالوش لازمة',
  'مفيش فايدة': 'مفيش فايدة',
  'أنت إزاي تعمل فيا كدا': 'إنت إزّاي تِعمل فيّا كده',
  'انت ازاي تعمل فيا كدا': 'إنت إزّاي تِعمل فيّا كده',
  'أنت إزاي': 'إنت إزّاي',
  'انت ازاي': 'إنت إزّاي',
  'تعمل فيا كدا': 'تِعمل فيّا كده',
  'تعمل فيا كده': 'تِعمل فيّا كده',
  'وثقت فيك': 'وَثَقت فيك',
  'ده أنا': 'ده أنا',
  'خايف أوي': 'خايف أوي',
  'خايف قوي': 'خايف أوي',
  'عايز نمشي': 'عايز نِمشي',
  'طول ما أنا': 'طول ما أنا',
  'مفيش مخلوق هيقدر يقربلك': 'مفيش مخلوق هيِقدر يقَرّبلك'
};

// ---------------------------------------------------------------------------
// V10.1 helpers: input normalisation, safe PCM decoding, click-free joins
// ---------------------------------------------------------------------------
const AR_LETTER = '\\u0621-\\u064A\\u0671';

/** تنظيف المدخل قبل أي معالجة: يزيل التطويل والرموز الخفية ويوحّد المسافات وعلامات الترقيم */
function normalizeArabicInput(str = '') {
  return String(str)
    .replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '') // رموز اتجاه/عرض صفري
    .replace(/\u0640/g, '')                                         // التطويل ـ
    .replace(/[\u0670\u06D6-\u06ED]/g, '')                          // علامات قرآنية غير مفيدة للنطق
    .replace(/([\u064B-\u0652])\1+/g, '$1')                         // تكرار الحركة
    .replace(/([.!؟?،,؛;])\1{3,}/g, '$1$1$1')                      // تكرار الترقيم المفرط
    .replace(/[ \t\u00A0]+/g, ' ')
    .replace(/ *\n */g, '\n')
    .trim();
}

/** Fade قصير في بداية ونهاية المقطع لإزالة فرقعة الدمج (clicks) */
function applyEdgeFades(pcm16, sampleRate = 24000, fadeMs = 12) {
  const n = Math.min(Math.floor((fadeMs / 1000) * sampleRate), Math.floor(pcm16.length / 2));
  if (n < 2) return pcm16;
  const out = new Int16Array(pcm16);
  for (let i = 0; i < n; i++) {
    const g = i / n;
    out[i] = Math.round(out[i] * g);
    out[out.length - 1 - i] = Math.round(out[out.length - 1 - i] * g);
  }
  return out;
}

const QAF_EXEMPT_WORDS = new Set([]);

/**
 * قاموس الضبط الصوتي المصري الذكي بالحروف العربية السليمة 100%:
 * يضع فقط الحركات الضرورية التي تمنع القراءة الخاطئة دون إغراق الكلمة بالسكون والفتحات التي تحول الصوت للخليجي أو الفصحى
 */
const EGYPTIAN_PHONETIC_LEXICON = {
  'سدادة': 'سَدّادة',
  'سدّادة': 'سَدّادة',
  'سداده': 'سَدّادة',
  'شغالة': 'شَغّالة',
  'كدابة': 'كَدّابة',
  'كذابة': 'كَدّابة',
  'كداب': 'كَدّاب',
  'كذاب': 'كَدّاب',
  'غلابة': 'غَلّابة',
  'رجالة': 'رِجّالة',
  'حمالة': 'حَمّالة',
  'رقبتي': 'رَقْبتي',
  'رقبتك': 'رَقْبتك',
  'رقبته': 'رَقْبته',
  'رقبتها': 'رَقْبتها',
  'برقبتي': 'برَقْبتي',
  'قصدي': 'قَصدي',
  'قصدك': 'قَصدك',
  'حقي': 'حَقّي',
  'حقك': 'حَقّك',
  'حقه': 'حَقّه',
  'حقها': 'حَقّها',
  'قلبي': 'قَلبي',
  'قلبك': 'قَلبك',
  'دلوقتي': 'دلوقتي',
  'مخلوق': 'مخلوق',
  'محروق': 'محروق',
  'مخنوق': 'مخنوق',
  'مقفول': 'مقفول',
  'مقفولة': 'مقفولة',
  'معقول': 'معقول',
  'تقول': 'تقول',
  'يقول': 'يقول',
  'بتقول': 'بِتقول',
  'بيقول': 'بِيقول',
  'قلت': 'قُلت',
  'قالت': 'قالت',
  'قال': 'قال',
  'أقعد': 'أقعد',
  'اقعد': 'أقعد',
  'قاعد': 'قاعد',
  'قاعدة': 'قاعدة',
  'تقدر': 'تِقدر',
  'يقدر': 'يِقدر',
  'هيقدر': 'هيِقدر',
  'يقربلك': 'يقَرّبلك',
  'يقرب': 'يقَرّب',
  'قريب': 'قُريّب',
  'قدام': 'قُدّام',
  'قدامي': 'قُدّامي',
  'قدامك': 'قُدّامك',
  'واقف': 'واقف',
  'واقفة': 'واقفة',
  'طايق': 'طايق',
  'متضايق': 'مِتضايق',
  'دمي': 'دَمّي',
  'دمك': 'دَمّك',
  'وشي': 'وِشّي',
  'وشك': 'وِشّك',
  'أنت': 'إنت',
  'انت': 'إنت',
  'أنتي': 'إنتي',
  'انتي': 'إنتي',
  'انتو': 'إنتو',
  'إحنا': 'إحنا',
  'احنا': 'إحنا',
  'هما': 'هُمّا',
  'هم': 'هُمّا',
  'ده': 'ده',
  'دا': 'ده',
  'دي': 'دي',
  'كدا': 'كده',
  'كده': 'كده',
  'كدة': 'كده',
  'إزاي': 'إزّاي',
  'ازاي': 'إزّاي',
  'إيه': 'إيه',
  'ايه': 'إيه',
  'ليه': 'ليه',
  'فين': 'فين',
  'إمتى': 'إمتى',
  'امتى': 'إمتى',
  'عشان': 'عشان',
  'علشان': 'علشان',
  'لسه': 'لِسّه',
  'لسة': 'لِسّه',
  'بقى': 'بقى',
  'خلاص': 'خلاص',
  'كفاية': 'كفاية',
  'تاني': 'تاني',
  'تانية': 'تانية',
  'كتير': 'كتير',
  'كثير': 'كتير',
  'برضو': 'برضو',
  'بس': 'بَس',
  'يلا': 'يلّا',
  'اللي': 'اللي',
  'فيا': 'فيّا',
  'فيّ': 'فيّا',
  'عليا': 'عليّا',
  'عليّ': 'عليّا',
  'ليا': 'ليّا',
  'معايا': 'معايا',
  'مني': 'مِنّي',
  'منك': 'مِنّك',
  'عني': 'عنّي',
  'عنك': 'عنّك',
  'جوه': 'جُوّه',
  'بره': 'بَرّه',
  'جمبك': 'جَنبك',
  'جنبك': 'جَنبك',
  'مش': 'مِش',
  'مفيش': 'مفيش',
  'مليش': 'ماليش',
  'ماليش': 'ماليش',
  'محدش': 'محَدّش',
  'مكنش': 'مَكانش',
  'ماكانش': 'مَكانش',
  'مكانش': 'مَكانش',
  'متخافش': 'متخافش',
  'متخافيش': 'متخافيش',
  'مينفعش': 'مينفعش',
  'تعمل': 'تِعمل',
  'يعمل': 'يِعمل',
  'بتعمل': 'بِتعمل',
  'بيعمل': 'بِيعمِل',
  'تعرف': 'تِعرف',
  'يعرف': 'يِعرف',
  'تفتكر': 'تِفتكر',
  'تفضل': 'تِفضل',
  'تشوف': 'تشوف',
  'شفت': 'شُفت',
  'نمشي': 'نِمشي',
  'تمشي': 'تِمشي',
  'يمشي': 'يِمشي',
  'تخبي': 'تخبّي',
  'هيكتشف': 'هيِكتشف',
  'طلع': 'طِلع',
  'طلعت': 'طِلعت',
  'رجع': 'رِجع',
  'سكت': 'سِكت',
  'هسكت': 'هَسكُت',
  'سمع': 'سِمع',
  'فهم': 'فِهم',
  'تعبت': 'تِعبت',
  'زهقت': 'زِهقت',
  'وثقت': 'وَثَقت',
  'هددوني': 'هدّدوني',
  'هيضيع': 'هيضيع',
  'والله': 'والله',
  'أوي': 'أوي',
  'قوي': 'أوي',
  'أكتر': 'أكتر',
  'أكثر': 'أكتر',
  'غصب': 'غَصب',
  'كذب': 'كِدب',
  'تمن': 'تَمن',
  'ثمن': 'تَمن',
  'العيلة': 'العيلة',

  // === V10.1: توسعة القاموس المصري (كلمات عامية شائعة بنطق قاهري مضبوط) ===
  'دول': 'دُول',
  'برضه': 'بَرْضُه',
  'اوي': 'أَوِي',
  'دلوقت': 'دِلْوَقْت',
  'النهارده': 'النَّهَارْدَه',
  'النهاردة': 'النَّهَارْدَه',
  'بكره': 'بُكْرَه',
  'بكرة': 'بُكْرَه',
  'بكرا': 'بُكْرَه',
  'امبارح': 'إِمْبَارِح',
  'إمبارح': 'إِمْبَارِح',
  'الصبح': 'الصُّبْح',
  'كمان': 'كَمَان',
  'يعني': 'يَعْنِي',
  'طيب': 'طَيِّب',
  'ماشي': 'مَاشِي',
  'حاجة': 'حَاجَة',
  'حاجه': 'حَاجَة',
  'حاجات': 'حَاجَات',
  'ازيك': 'إِزَّيَّك',
  'إزيك': 'إِزَّيَّك',
  'ازيكم': 'إِزَّيِّكُم',
  'أهو': 'أَهُو',
  'اهو': 'أَهُو',
  'أهي': 'أَهِي',
  'اهي': 'أَهِي',
  'بتاع': 'بِتَاع',
  'بتاعي': 'بِتَاعِي',
  'بتاعك': 'بِتَاعَك',
  'بتاعها': 'بِتَاعْهَا',
  'بتاعته': 'بِتَاعْتُه',
  'عايز': 'عَايِز',
  'عايزة': 'عَايْزَة',
  'عايزه': 'عَايْزَة',
  'عاوز': 'عَاوِز',
  'عاوزة': 'عَاوْزَة',
  'عاوزه': 'عَاوْزَة',
  'عايزين': 'عَايْزِين',
  'بتروح': 'بِتْرُوح',
  'بتحب': 'بِتِحِبّ',
  'بتعرف': 'بِتِعْرَف',
  'بتيجي': 'بِتِيجِي',
  'بتشوف': 'بِتْشُوف',
  'بتفكر': 'بِتْفَكَّر',
  'معنديش': 'مَعَنْدِيش',
  'معرفش': 'مَعْرَفْش',
  'مقدرش': 'مَقْدَرْش',
  'مكنتش': 'مَكُنْتِش',
  'ماكنتش': 'مَاكُنْتِش',
  'هيعمل': 'هَيِعْمِل',
  'هتعمل': 'هَتِعْمِل',
  'هقول': 'هَقُول',
  'هروح': 'هَرُوح',
  'هنروح': 'هَنْرُوح',
  'هيجي': 'هَيِجِي',
  'هتيجي': 'هَتِيجِي',
  'هعمل': 'هَعْمِل',
  'هشوف': 'هَشُوف',
  'هنعمل': 'هَنِعْمِل',
  'معلش': 'مَعْلِشّ',
  'معلهش': 'مَعْلِشّ',
  'خالص': 'خَالِص',
  'جامد': 'جَامِد',
  'حلو': 'حِلْو',
  'حلوة': 'حِلْوَة',
  'حلوه': 'حِلْوَة',
  'كويس': 'كُوَيِّس',
  'كويسة': 'كُوَيِّسَة',
  'كويسه': 'كُوَيِّسَة',
  'وحش': 'وِحِش',
  'وحشة': 'وِحْشَة',
  'تعبان': 'تَعْبَان',
  'زهقان': 'زَهْقَان',
  'مبسوط': 'مَبْسُوط',
  'زعلان': 'زَعْلَان',
  'عيان': 'عَيَّان',
  'شغل': 'شُغْل',
  'الشغل': 'الشُّغْل',
  'فلوس': 'فُلُوس',
  'الفلوس': 'الفُلُوس',
  'بيت': 'بِيت',
  'البيت': 'البِيت',
  'ولد': 'وَلَد',
  'بنت': 'بِنْت',
  'البنت': 'البِنْت',
  'راجل': 'رَاجِل',
  'الراجل': 'الرَّاجِل',
  'ست': 'سِتّ',
  'الست': 'السِّتّ',
  'عيال': 'عِيَال',
  'العيال': 'العِيَال',
  'اخويا': 'أَخُويَا',
  'أخويا': 'أَخُويَا',
  'ابويا': 'أَبُويَا',
  'أبويا': 'أَبُويَا',
  'أمي': 'أُمِّي',
  'امي': 'أُمِّي',
  'مراتي': 'مِرَاتِي',
  'جوزي': 'جَوْزِي',
  'صاحبي': 'صَاحْبِي',
  'باشا': 'بَاشَا',
  'حبيبي': 'حَبِيبِي',
  'حبيبتي': 'حَبِيبْتِي',
  'عيني': 'عِينِي',
  'دماغ': 'دِمَاغ',
  'دماغي': 'دِمَاغِي',
  'وشه': 'وِشُّه',
  'وش': 'وِشّ',
  'ايدي': 'إِيدِي',
  'إيدي': 'إِيدِي',
  'ايده': 'إِيدُه',
  'إيده': 'إِيدُه',
  'رجلي': 'رِجْلِي',
  'راسي': 'رَاسِي',
  'راسه': 'رَاسُه',
  'بطني': 'بَطْنِي',
  'ضهري': 'ضَهْرِي',
  'ضهر': 'ضَهْر',
  'هنا': 'هِنَا',
  'ورا': 'وَرَا',
  'جوا': 'جُوَّا',
  'برا': 'بَرَّا',
  'فوق': 'فُوق',
  'تحت': 'تَحْت',
  'جنب': 'جَنْب',
  'عندي': 'عِنْدِي',
  'عندك': 'عِنْدَك',
  'عنده': 'عِنْدُه',
  'عندها': 'عِنْدَهَا',
  'عندنا': 'عِنْدِنَا',
  'رحت': 'رُحْت',
  'جيت': 'جِيت',
  'جه': 'جَه',
  'جت': 'جَت',
  'مشيت': 'مِشِيت',
  'سمعت': 'سِمِعْت',
  'فهمت': 'فِهِمْت',
  'فاهم': 'فَاهِم',
  'فاهمة': 'فَاهْمَة',
  'عرفت': 'عِرِفْت',
  'نسيت': 'نِسِيت',
  'نمت': 'نِمْت',
  'خدت': 'خَدْت',
  'جبت': 'جِبْت',
  'جاب': 'جَاب',
  'هات': 'هَات',
  'سيبني': 'سِيبْنِي',
  'سيبه': 'سِيبُه',
  'سيب': 'سِيب',
  'خليني': 'خَلِّينِي',
  'خليه': 'خَلِّيه',
  'خلي': 'خَلِّي',
  'استنى': 'اِسْتَنَّى',
  'استني': 'اِسْتَنَّى',
  'إستني': 'اِسْتَنَّى',
  'تعالى': 'تَعَالَى',
  'تعال': 'تَعَالَ',
  'تعالي': 'تَعَالَى',
  'قعد': 'قَعَد',
  'بص': 'بُصّ',
  'شوف': 'شُوف',
  'متقولش': 'مَتْقُولْش',
  'ماتقولش': 'مَاتْقُولْش',
  'متزعلش': 'مَتْزَعَّلْش',
  'متعيطش': 'مَتْعَيَّطْش',
  'متروحش': 'مَتْرُوحْش',
  'متقلقش': 'مَتْقَلَقْش',
  'عارف': 'عَارِف',
  'عارفة': 'عَارْفَة',
  'ممكن': 'مُمْكِن',
  'لازم': 'لَازِم',
  'اكيد': 'أَكِيد',
  'أكيد': 'أَكِيد',
  'طبعا': 'طَبْعَن',
  'طبعاً': 'طَبْعَن',
  'بجد': 'بِجَدّ',
  'فعلا': 'فِعْلَن',
  'فعلاً': 'فِعْلَن',
  'تقريبا': 'تَقْرِيبَن',
  'دايما': 'دَايِمَن',
  'دايماً': 'دَايِمَن',
  'مرة': 'مَرَّة',
  'مره': 'مَرَّة',
  'كلهم': 'كُلُّهُم',
  'اللى': 'اللِّي',
  'فاضي': 'فَاضِي',
  'مشغول': 'مَشْغُول',
  'مستني': 'مِسْتَنِّي',
  'مستنيك': 'مِسْتَنِّيك',
  'خايف': 'خَايِف',
  'خايفة': 'خَايْفَة',
  'خايفه': 'خَايْفَة',
  'زي': 'زَيّ',
  'إنتو': 'إِنْتُو',
  'ليك': 'لِيك',
  'عليك': 'عَلَيْك',
  'عليه': 'عَلِيه',
  'معاك': 'مَعَاك',
  'معاه': 'مَعَاه',
  'معاها': 'مَعَاهَا',
  'معانا': 'مَعَانَا',

  // === V10.2: كلمات مصرية بقاف مهموزة (مصدقني = مِصَدِّأْنِي) وما شابهها ===
  'مصدقني': 'مِصَدِّأْنِي',
  'مصدقنيش': 'مِصَدِّأْنِيش',
  'مصدقاني': 'مِصَدِّأَانِي',
  'مصدقانيش': 'مِصَدِّأَانِيش',
  'مصدقاه': 'مِصَدِّأَاه',
  'مصدقه': 'مِصَدِّأُه',
  'مصدقهاش': 'مِصَدِّأْهَاش',
  'مصدق': 'مِصَدِّأ',
  'مصدقة': 'مِصَدِّأَة',
  'مصدقين': 'مِصَدِّأِين',
  'صدقني': 'صَدِّأْنِي',
  'صدقيني': 'صَدِّأِينِي',
  'صدقت': 'صَدَّأْت',
  'بصدق': 'بَصَدَّأ',
  'بتصدق': 'بِتْصَدَّأ',
  'هصدق': 'هَصَدَّأ',
  'مصدقش': 'مِصَدِّأْش',
  'مستغرب': 'مِسْتَغْرِب',
  'مستغربة': 'مِسْتَغْرِبَة',
  'متأكد': 'مِتَأَكِّد',
  'متأكدة': 'مِتَأَكِّدَة',
  'متأكدش': 'مِتَأَكِّدْش',
  'مقتنع': 'مُقْتَنِع',
  'مقتنعش': 'مُقْتَنِعْش',
  'متخيل': 'مِتْخَيِّل',
  'متخيلش': 'مِتْخَيِّلْش',
  'مصدوم': 'مَصْدُوم',
  'مصدومة': 'مَصْدُومَة',
  'متضايقة': 'مِتْضَايْقَة',
  'مستحيل': 'مُسْتَحِيل',
  'معقولة': 'مَعْقُولَة',
  'مصدقناش': 'مِصَدِّأْنَاش',
  'مصدقتش': 'مَصَدَّأْتِش',
  'صدقتك': 'صَدَّأْتَك',
  'صدقتني': 'صَدَّأْتِنِي',

  // === V10.3: توسعة ثالثة للقاموس المصري (يومي، مشاعر، عائلة، مدينة، أكل، مواصلات) ===
  'مين': 'مِين',
  'كام': 'كَام',
  'ايوه': 'أَيْوَه',
  'أيوه': 'أَيْوَه',
  'ايوة': 'أَيْوَه',
  'لأ': 'لَأ',
  'اه': 'آه',
  'أه': 'آه',
  'جدا': 'جِدًّا',
  'شوية': 'شُوَيَّة',
  'شويه': 'شُوَيَّة',
  'شوي': 'شُوَيّ',
  'كتيير': 'كِتِير',
  'قليل': 'قَلِيل',
  'بسرعة': 'بِسُرْعَة',
  'بالراحة': 'بِالرَّاحَة',
  'براحة': 'بِرَاحَة',
  'حالا': 'حَالَا',
  'بعدين': 'بَعْدِين',
  'وقتها': 'وَقْتِهَا',
  'ساعتها': 'سَاعْتِهَا',
  'كله': 'كُلُّه',
  'كلها': 'كُلُّهَا',
  'كلنا': 'كُلِّنَا',
  'بعضنا': 'بَعْضِينَا',
  'بقا': 'بَقَى',
  'ينفع': 'يِنْفَع',
  'ينفعش': 'يِنْفَعْش',
  'يصح': 'يِصِحّ',
  'يصحش': 'يِصِحِّش',
  'مممكنش': 'مُمْكِنْش',
  'يمكن': 'يُمْكِن',
  'احتمال': 'اِحْتِمَال',
  'بيحب': 'بِيِحِبّ',
  'بيكره': 'بِيِكْرَه',
  'بيعرف': 'بِيِعْرَف',
  'بيروح': 'بِيرُوح',
  'بيجي': 'بِيجِي',
  'بياكل': 'بِيَاكُل',
  'بيشرب': 'بِيِشْرَب',
  'بينام': 'بِينَام',
  'بيشتغل': 'بِيِشْتِغِل',
  'بيفكر': 'بِيْفَكَّر',
  'بتحبني': 'بِتِحِبَّنِي',
  'بتكرهني': 'بِتِكْرَهْنِي',
  'بتسمعني': 'بِتِسْمَعْنِي',
  'بتفهمني': 'بِتِفْهَمْنِي',
  'بتعرفني': 'بِتِعْرَفْنِي',
  'بتسيبني': 'بِتِسِيبْنِي',
  'مبقاش': 'مَبْقَاش',
  'مبقتش': 'مَبْقِتْش',
  'مابقتش': 'مَابْقِتْش',
  'ماعدش': 'مَاعَدْش',
  'مبقيتش': 'مَبْقِيتِش',
  'مرضيتش': 'مَرْضِيتِش',
  'مرضاش': 'مَرْضَاش',
  'مسمعتش': 'مَسْمَعْتِش',
  'ماسمعتش': 'مَاسْمَعْتِش',
  'فاكر': 'فَاكِر',
  'فاكرة': 'فَاكْرَة',
  'افتكرت': 'اِفْتَكَرْت',
  'افتكر': 'اِفْتَكَر',
  'حاسس': 'حَاسِس',
  'حاسة': 'حَاسَّة',
  'شايف': 'شَايِف',
  'شايفة': 'شَايْفَة',
  'سامع': 'سَامِع',
  'سامعة': 'سَامْعَة',
  'يخرب': 'يِخْرَب',
  'يخربيتك': 'يِخْرَبِيتَك',
  'يخربيتها': 'يِخْرَبِيتْهَا',
  'ياخي': 'يَاخِي',
  'جدع': 'جَدَع',
  'جدعنة': 'جَدْعَنَة',
  'شهم': 'شَهْم',
  'اصيل': 'أَصِيل',
  'أصيل': 'أَصِيل',
  'محترم': 'مُحْتَرَم',
  'محترمة': 'مُحْتَرَمَة',
  'مزاجي': 'مِزَاجِي',
  'رايق': 'رَايِق',
  'رايقة': 'رَايْقَة',
  'مضايق': 'مِضَايِق',
  'زهق': 'زَهَق',
  'مللت': 'مَلِّيت',
  'قرفان': 'قَرْفَان',
  'قرف': 'قَرَف',
  'غلطان': 'غَلْطَان',
  'غلطانة': 'غَلْطَانَة',
  'حقيقي': 'حَقِيقِي',
  'كدب': 'كِدْب',
  'كدبة': 'كِدْبَة',
  'بتكدب': 'بِتِكْدِب',
  'بتكذب': 'بِتِكْدِب',
  'بكدب': 'بَكْدِب',
  'السر': 'السِّرّ',
  'اسرار': 'أَسْرَار',
  'أسرار': 'أَسْرَار',
  'مصيبة': 'مُصِيبَة',
  'مشكلة': 'مُشْكِلَة',
  'مشاكل': 'مَشَاكِل',
  'ازمة': 'أَزْمَة',
  'أزمة': 'أَزْمَة',
  'الحل': 'الحَلّ',
  'جريمة': 'جَرِيمَة',
  'قاتل': 'قَاتِل',
  'قتلته': 'قَتَلْتُه',
  'قتلتها': 'قَتَلْتْهَا',
  'عايش': 'عَايِش',
  'عايشة': 'عَايْشَة',
  'هرب': 'هَرَب',
  'هربت': 'هِرِبْت',
  'اهرب': 'اِهْرَب',
  'اجري': 'اِجْرِي',
  'اجرى': 'اِجْرِي',
  'امسك': 'اِمْسِك',
  'امسكه': 'اِمْسِكُه',
  'اضربه': 'اِضْرَبُه',
  'بوليس': 'بُولِيس',
  'ظابط': 'ظَابِط',
  'ضابط': 'ظَابِط',
  'نيابة': 'نِيَابَة',
  'محكمة': 'مَحْكَمَة',
  'محامي': 'مُحَامِي',
  'سجن': 'سِجْن',
  'مستشفى': 'مُسْتَشْفَى',
  'المستشفى': 'المُسْتَشْفَى',
  'ممرضة': 'مُمَرِّضَة',
  'دوا': 'دَوَا',
  'الدوا': 'الدَّوَا',
  'مريض': 'مَرِيض',
  'مريضة': 'مَرِيضَة',
  'جامعة': 'جَامْعَة',
  'الجامعة': 'الجَامْعَة',
  'امتحان': 'اِمْتِحَان',
  'الامتحان': 'الاِمْتِحَان',
  'مذاكرة': 'مُذَاكْرَة',
  'عربية': 'عَرَبِيَّة',
  'العربية': 'العَرَبِيَّة',
  'تاكسي': 'تَاكْسِي',
  'ميكروباص': 'مِيكْرُوبَاص',
  'مترو': 'مِتْرُو',
  'شارع': 'شَارِع',
  'الشارع': 'الشَّارِع',
  'حارة': 'حَارَة',
  'الحارة': 'الحَارَة',
  'كباية': 'كُبَّايَة',
  'كوباية': 'كُوبَايَة',
  'ملعقة': 'مِلْعَقَة',
  'شوكة': 'شُوكَة',
  'سكينة': 'سِكِّينَة',
  'عيش': 'عِيش',
  'العيش': 'العِيش',
  'اكل': 'أَكْل',
  'أكل': 'أَكْل',
  'الاكل': 'الأَكْل',
  'شاي': 'شَايْ',
  'قهوة': 'قَهْوَة',
  'قهوه': 'قَهْوَة',
  'فطار': 'فُطَار',
  'غدا': 'غَدَا',
  'عشا': 'عَشَا',
  'عشاء': 'عَشَاء',
  'سندوتش': 'سَنْدْوِتْش',
  'فول': 'فُول',
  'طعمية': 'طَعْمِيَّة',
  'كشري': 'كُشَرِي',
  'ملوخية': 'مُلُوخِيَّة',
  'محشي': 'مَحْشِي',
  'فراخ': 'فِرَاخ',
  'لحمة': 'لَحْمَة',
  'القاهرة': 'القَاهِرَة',
  'اسكندرية': 'إِسْكَنْدَرِيَّة',
  'إسكندرية': 'إِسْكَنْدَرِيَّة',
  'الصعيد': 'الصَّعِيد',
  'صعيدي': 'صَعِيدِي',
  'بلدنا': 'بَلَدْنَا',
  'مبروك': 'مَبْرُوك',
  'عقبال': 'عُقْبَال',
  'عقبالك': 'عُقْبَالَك',
  'عقبالنا': 'عُقْبَالْنَا',
  'تسلم': 'تِسْلَم',
  'تسلمي': 'تِسْلَمِي',
  'شكرا': 'شُكْرًا',
  'متشكر': 'مِتْشَكِّر',
  'متشكرة': 'مِتْشَكِّرَة',
  'العفو': 'العَفْو',
  'عفوا': 'عَفْوًا',
  'اتفضل': 'اِتْفَضَّل',
  'اتفضلي': 'اِتْفَضَّلِي',
  'اتفضلوا': 'اِتْفَضَّلُوا',
  'اسف': 'آسِف',
  'آسف': 'آسِف',
  'آسفة': 'آسْفَة',
  'اسفة': 'آسْفَة',
  'سامحني': 'سَامِحْنِي',
  'سامحيني': 'سَامِحِينِي',
  'اهلا': 'أَهْلًا',
  'أهلا': 'أَهْلًا',
  'مرحبا': 'مَرْحَبًا',
  'تصبح': 'تِصْبَح',
  'تصبحي': 'تِصْبَحِي',
  'وداعا': 'وَدَاعًا',
  'وحشتني': 'وَحَشْتِنِي',
  'وحشتيني': 'وَحَشْتِينِي',
  'اتأخرت': 'اِتْأَخَّرْت',
  'اتأخر': 'اِتْأَخَّر',
  'اتاخرت': 'اِتْأَخَّرْت',
  'لحقت': 'لِحِقْت',
  'لحق': 'لِحِق',
  'فاتني': 'فَاتْنِي',
  'فاتك': 'فَاتَك',
  'تعبتني': 'تَعَّبْتِنِي',
  'ارحمني': 'اِرْحَمْنِي',
  'ارحمي': 'اِرْحَمِي',
  'فضيحة': 'فَضِيحَة',
  'فضحتني': 'فَضَحْتِنِي',
  'روحي': 'رُوحِي',
  'عمري': 'عُمْرِي',
  'حياتي': 'حَيَاتِي',
  'سنين': 'سِنِين',
  'سنتين': 'سَنَتِين',
  'اسبوع': 'أُسْبُوع',
  'أسبوع': 'أُسْبُوع',
  'يومين': 'يُومِين',
  'ساعتين': 'سَاعْتِين',
  'دقيقة': 'دَقِيقَة',
  'دقايق': 'دَقَايِق',
  'لحظة': 'لَحْظَة',
  'اتنين': 'اِتْنِين',
  'تلاتة': 'تَلَاتَة',
  'اربعة': 'أَرْبَعَة',
  'أربعة': 'أَرْبَعَة',
  'خمسة': 'خَمْسَة',
  'ستة': 'سِتَّة',
  'سبعة': 'سَبْعَة',
  'تمانية': 'تَمَانْيَة',
  'تسعة': 'تِسْعَة',
  'ميه': 'مِيَّة',
  'مية': 'مِيَّة',

  // === V10.4: كلمات طلبها المستخدم (نطق قاهري مضبوط + كلمات فيها لبس) ===
  'يحفل': 'يِحَفِّل',
  'بيحفل': 'بِيِحَفِّل',
  'بتحفل': 'بِتِحَفِّل',
  'تحفل': 'تِحَفِّل',
  'ميحفلش': 'مَيِحَفِّلْش',
  'يحفلش': 'يِحَفِّلْش',
  'حفل': 'حَفِّل',
  'يفرفش': 'يِفَرْفِش',
  'بيفرفش': 'بِيِفَرْفِش',
  'بتفرفش': 'بِتِفَرْفِش',
  'فرفش': 'فَرْفِش',
  'فرفشة': 'فَرْفَشَة',
  'المطرة': 'المَطَرَة',
  'مطرة': 'مَطَرَة',
  'المطره': 'المَطَرَة',
  'مطره': 'مَطَرَة',
  'دوشة': 'دَوْشَة',
  'الدوشة': 'الدَّوْشَة',
  'دوشه': 'دَوْشَة',
  'الدوشه': 'الدَّوْشَة',
  'دوشتني': 'دَوَّشْتِنِي',
  'بيدوش': 'بِيدَوِّش',
  'كتفك': 'كِتْفَك',
  'كتفي': 'كِتْفِي',
  'كتفه': 'كِتْفُه',
  'كتفها': 'كِتْفَهَا',
  'كتف': 'كِتْف',
  'الكتف': 'الكِتْف',
  'كتفنا': 'كِتْفِنَا',
  'كتفهم': 'كِتْفُهُم',
  'جاي': 'جَاي',
  'جاية': 'جَايَّة',
  'جايه': 'جَايَّة',
  'جايين': 'جَايِّين',
  'جايلك': 'جَايِلَك',
  'جايلي': 'جَايِلِي',
  'جايبلك': 'جَايِبْلَك',
  'فترة': 'فَطْرَة',
  'فتره': 'فَطْرَة',
  'الفترة': 'الفَطْرَة',
  'الفتره': 'الفَطْرَة',
  'فترات': 'فَطَرَات',
  'الفترات': 'الفَطَرَات',
  'فترتين': 'فَطْرِتِين',
  'موقف': 'مَوْقِف',
  'الموقف': 'المَوْقِف',
  'مواقف': 'مَوَاقِف',
  'المواقف': 'المَوَاقِف',
  'موقفي': 'مَوْقِفِي',
  'موقفك': 'مَوْقِفَك',
  'موقفه': 'مَوْقِفُه',
  'الممل': 'المُمِلّ',
  'ممل': 'مُمِلّ',
  'مملة': 'مُمِلَّة',
  'المملة': 'المُمِلَّة',
  'مملين': 'مُمِلِّين',
  'الممله': 'المُمِلَّة',

  // === V10.5: أسماء وكلمات بتتنطق غلط (ح→خ، كم→كن، لجنة...) ===
  'مت': 'مُتْ',
  'لجنة': 'لَجْنَة',
  'لجنه': 'لَجْنَة',
  'اللجنة': 'اللَّجْنَة',
  'اللجنه': 'اللَّجْنَة',
  'لجنتي': 'لَجْنِتِي',
  'أحمد': 'أَحْمَد',
  'احمد': 'أَحْمَد',
  'محمد': 'مُحَمَّد',
  'محمود': 'مَحْمُود',
  'حمدي': 'حَمْدِي',
  'حسن': 'حَسَن',
  'حسين': 'حُسَيْن',
  'حسام': 'حُسَام',
  'حازم': 'حَازِم',
  'حامد': 'حَامِد',
  'حمزة': 'حَمْزَة',
  'أحمدي': 'أَحْمَدِي',
  'فيكم': 'فِيكُمْ',
  'عجبتكم': 'عَجَبْتُكُمْ',
  'عليكم': 'عَلَيْكُمْ',
  'معاكم': 'مَعَاكُمْ',
  'منكم': 'مِنْكُمْ',
  'ليكم': 'لِيكُمْ',
  'عندكم': 'عِنْدِكُمْ',
  'معكم': 'مَعَكُمْ',
  'بيكم': 'بِيكُمْ',
  'وراكم': 'وَرَاكُمْ',
  'حبيتكم': 'حَبِّيتَكُمْ',
  'شفتكم': 'شُفْتِكُمْ',
  'سمعتكم': 'سِمِعْتِكُمْ',
  'عرفتكم': 'عِرِفْتِكُمْ',
  'وحشتوني': 'وَحَشْتُونِي',
  'كلكم': 'كُلُّكُمْ',
  'انتم': 'إِنْتُمْ',
  'أنتم': 'إِنْتُمْ',
};

/**
 * تطبيق الضبط الصوتي المصري الذكي (Smart Minimal Egyptian Phonetics):
 * - يطبق فقط على جمل الحوار العامي المصري (وليس السرد الفصحى)
 * - لا يحول حرف القاف إلى همزة مكتوبة (حتى لا تتشوه الكلمات مثل دلوقتي أو رقبتي)
 * - يحول التراكيب الخليجية المشتركة مثل "والله ما كان قصدي" إلى التركيب المصري "والله مَكانش قَصدي"
 */
// ---------------------------------------------------------------------------
// V10.3: لفظ الجلالة بالنطق المصري (تفخيم بعد الفتح والضم، ترقيق بعد الكسر)
// ---------------------------------------------------------------------------
// V10.4: كلمات متشابهة الرسم مختلفة المعنى والنطق - تُحسم من السياق
// V10.5: ضمير الجمع "كم" ينطق أحياناً "كن": نثبّته بضمة وسكون
function applyPluralSuffixFix(text) {
  if (!text) return text;
  const AR = '\u0621-\u064A';
  const stems = 'عجبت|حبيت|شفت|سمعت|عرفت|قابلت|كلمت|وحشت|شكرت|سامحت|قلت|جيت|سألت|فهمت|نسيت|ساعدت|في|ل|من|علي|على|مع|معا|عند|عن|ورا|قدام|جنب|بين|لي|بي|ال';
  return text.replace(new RegExp('(?<![' + AR + '])(' + stems + ')كم(?![' + AR + '])', 'g'), '$1كُمْ');
}

function applyHomographRules(text) {
  if (!text) return text;
  const AR = '\u0621-\u064A';
  const B = '(?<![' + AR + '])';
  const A = '(?![' + AR + '])';
  const SUF = '(ي|ك|ه|ها|نا|كم|هم)';
  const SELF = { 'ي': 'نَفْسِي', 'ك': 'نَفْسَك', 'ه': 'نَفْسُه', 'ها': 'نَفْسَها', 'نا': 'نَفْسِنَا', 'كم': 'نَفْسَكُم', 'هم': 'نَفْسُهُم' };
  const WISH = { 'ي': 'نِفْسِي', 'ك': 'نِفْسَك', 'ه': 'نِفْسُه', 'ها': 'نِفْسَها', 'نا': 'نِفْسِنَا', 'كم': 'نِفْسَكُم', 'هم': 'نِفْسُهُم' };
  let t = text;
  // ذات: بعد حرف جر أو فعل يتعدى للنفس (على نفسك، حب نفسك، اهتم بنفسك)
  t = t.replace(new RegExp(B + '(على|عن|من|الى|إلى|حب|احب|أحب|ابقى|خلي|اهتم|اهتمي|دافع|ضحى|لوم|تلوم)\\s+نفس' + SUF + A, 'g'),
    (m, pre, suf) => pre + ' ' + SELF[suf]);
  t = t.replace(new RegExp(B + '(ب|ل|ك)نفس' + SUF + A, 'g'), (m, pre, suf) => pre + SELF[suf]);
  // رغبة: نفسي في / نفسك تـ / نفسه يـ
  t = t.replace(new RegExp(B + 'نفس' + SUF + '\\s+(في|اني|إني|أن|ان|أ|ا|ن|ت|ي)' + A, 'g'),
    (m, suf, nxt) => WISH[suf] + ' ' + nxt);
  // بدون سياق واضح: نفسي = رغبة، والباقي = ذات
  t = t.replace(new RegExp(B + 'نفسي' + A, 'g'), 'نِفْسِي');
  t = t.replace(new RegExp(B + 'نفسك' + A, 'g'), 'نَفْسَك');
  t = t.replace(new RegExp(B + 'نفسه' + A, 'g'), 'نَفْسُه');
  t = t.replace(new RegExp(B + 'نفسها' + A, 'g'), 'نَفْسَها');
  return t;
}


// V12: القاف المصرية (همزة في الكلمات الدارجة) + ظابط — بتتطبّق على الحوار بس
Object.assign(EGYPTIAN_PHONETIC_LEXICON, {
  'بقى': 'بَأَى', 'بقت': 'بَأَت', 'بقيت': 'بَأَيت', 'بقوا': 'بَأَوا', 'يبقى': 'يِبَأَى', 'هيبقى': 'هيِبَأَى', 'هتبقى': 'هتِبَأَى', 'تبقى': 'تِبَأَى', 'ابقى': 'اِبَأَى', 'مبقاش': 'مبَأَاش',
  'قال': 'أَال', 'قالت': 'أَالِت', 'قالوا': 'أَالوا', 'قالها': 'أَالها', 'قاله': 'أَاله', 'قالتلي': 'أَالتلي',
  'قلت': 'أُلت', 'قلتلك': 'أُلتِلَك', 'قلتله': 'أُلتِلُه', 'قلتلها': 'أُلتِلها', 'قلتلي': 'أُلتِلي', 'قولت': 'أُلت',
  'بقول': 'بَأُول', 'بيقول': 'بِيأُول', 'بتقول': 'بِتأُول', 'هقول': 'هَأُول', 'هتقول': 'هتأُول', 'يقول': 'يأُول', 'تقول': 'تأُول', 'نقول': 'نأُول', 'قول': 'أُول', 'قولي': 'أُولي', 'قولوا': 'أُولوا', 'قوليلي': 'أُولِيلي',
  'قدام': 'أُدّام', 'قوي': 'أَوي', 'قوى': 'أَوي', 'قلب': 'أَلب', 'قلبي': 'أَلبي', 'قهوة': 'أَهوَه', 'قريب': 'أُريّب', 'قصاد': 'أُصّاد', 'قمر': 'أَمَر',
  'والله': 'وَاللَّٰهْ', 'بالله': 'بِاللَّٰهْ', 'ظابط': 'ظَابِط', 'ضابط': 'ظَابِط', 'ظباط': 'ظُبَّاط', 'ضباط': 'ظُبَّاط', 'الظابط': 'الظَّابِط', 'الضابط': 'الظَّابِط'
});
function applyAllahPronunciation(text) {
  if (!text) return text;
  text = text.replace(/ا[\u064B-\u0652\u0670]*ل[\u064B-\u0652\u0670]*ل[\u064B-\u0652\u0670]*ه[\u064B-\u0652\u0670]*(?![\u0621-\u064A])/g, 'الله');
  const AR = '\u0621-\u064A';
  const B = '(?<![' + AR + '])';
  const A = '(?![' + AR + '])';
  let t = text;

  const fixed = [
    [/الحمد\s*لله/g, 'الحَمْدُ لِلَّه'],
    [/الحمدلله/g, 'الحَمْدُ لِلَّه'],
    [/إن\s*شاء\s*الله|ان\s*شاء\s*الله|إنشالله|انشالله/g, 'إِنْ شَاءَ اللَّٰه'],
    [/ما\s*شاء\s*الله|ماشاء\s*الله|ماشالله/g, 'مَا شَاءَ اللَّٰه'],
    [/بسم\s*الله/g, 'بِسْمِ اللَّه'],
    [/سبحان\s*الله/g, 'سُبْحَانَ اللَّٰه'],
    [/لا\s*إله\s*إلا\s*الله|لا\s*اله\s*الا\s*الله/g, 'لَا إِلَهَ إِلَّا اللَّٰه'],
    [/استغفر\s*الله|أستغفر\s*الله|استغفرالله/g, 'أَسْتَغْفِرُ اللَّٰه'],
    [/جزاك\s*الله\s*خير(?:ا|اً)?/g, 'جَزَاكَ اللَّٰهُ خَيْرًا'],
    [/يا\s*الله|ياالله/g, 'يَا اللَّٰه'],
    [/في\s*سبيل\s*الله/g, 'فِي سَبِيلِ اللَّه'],
    [/في\s*أمان\s*الله/g, 'فِي أَمَانِ اللَّه'],
    [/عبد\s*الله/g, 'عَبْدِ اللَّه']
  ];
  for (const [re, val] of fixed) t = t.replace(re, val);

  t = t
    .replace(new RegExp(B + 'بالله' + A, 'g'), 'بِاللَّه')
    .replace(new RegExp(B + 'لله' + A, 'g'), 'لِلَّه')
    .replace(new RegExp(B + 'تالله' + A, 'g'), 'تَاللَّه');

  t = t.replace(new RegExp(B + '(و|ف)الله' + A, 'g'), '$1اللَّٰه');
  t = t.replace(new RegExp(B + 'الله' + A, 'g'), 'اللَّٰه');
  // المصريون لا ينطقون حركة إعراب في آخر لفظ الجلالة: نثبّت الهاء بسكون
  t = t.replace(/(اللَّٰ?ا?ه|لِلَّا?ه)(?![\u0621-\u064A\u064B-\u0652])/g, '$1ْ');
  return t;
}

// V11: الوقف المصري — المصريين مابينطقوش حركات الإعراب في آخر الكلمة (اللهِ/كتابُ/مِنَ…). بنشيل آخر حركة قصيرة من أي كلمة (إلا ك/ت علشان المذكر/المؤنث، وإلا الحرف المشدّد)
const RD_PZ = /^(.*[\u0621-\u064A])([\u064B-\u0652]*)$/;
function rdPausalWord(w) {
  const m = RD_PZ.exec(w); if (!m || !m[2]) return w;
  const base = m[1], marks = m[2];
  if (/[\u0651\u0652\u064B]/.test(marks)) return w; // شدّة / سكون / تنوين فتح: سيبه
  if (!/[\u064C\u064D\u064E\u064F\u0650]/.test(marks)) return w;
  const last = base[base.length - 1];
  if (last === 'ك' || last === 'ت') return w;
  if (base.replace(/[\u064B-\u0652]/g, '').length < 2) return w;
  return base;
}
function rdPausal(text) { return String(text || '').replace(/[\u0621-\u064A][\u0621-\u064A\u064B-\u0652\u0670]*/g, rdPausalWord); }
function applyEgyptianPhonetics(rawText, customDict = {}) {
  if (!rawText || !rawText.trim()) return '';
  rawText = normalizeArabicInput(rawText);

  // أولاً: تنظيف أي كلمات مشوهة بهمزة بدلاً من القاف من نسخ سابقة
  let processed = rawText
    .replace(/دِلْوَأْتِي|دلوأتي/g, 'دلوقتي')
    .replace(/رَأَبْتِي/g, 'رَقْبتي')
    .replace(/حَأَّكْ/g, 'حَقّك')
    .replace(/أُأْعُدْ/g, 'أقعد')
    .replace(/مَحْرُوءْ/g, 'محروق')
    .replace(/مَخْلُوءْ/g, 'مخلوق')
    .replace(/يِأَرَّبْلَكْ/g, 'يقَرّبلك')
    .replace(/هَيِإْدَرْ/g, 'هيِقدر')
    .replace(/وَاللَّاهِي/g, 'والله')
    .replace(/أَصْدِي/g, 'قَصدي');

  processed = applyPluralSuffixFix(processed);
  processed = applyHomographRules(processed);
  processed = applyAllahPronunciation(processed);

  // 1. تحويل التراكيب التي تسبب نطقاً خليجياً إلى صيغتها المصرية القاهرية الطبيعية
  processed = processed
    .replace(/والله\s+ما\s*كان\s+قصدي/g, 'والله مَكانش قَصدي')
    .replace(/ما\s*كان\s+قصدي/g, 'مَكانش قَصدي');

  // 2. تطبيق العبارات المركبة من ذاكرة المستخدم (بشرط عدم احتوائها على همزات مشوهة للقاف)
  if (customDict && typeof customDict === 'object') {
    const multiWordCustomKeys = Object.keys(customDict)
      .filter((k) => k.trim().includes(' '))
      .sort((a, b) => b.length - a.length);

    for (const phrase of multiWordCustomKeys) {
      const cleanPhrase = phrase.trim();
      const val = customDict[phrase];
      if (cleanPhrase && val && !/[أإءؤئ]/.test(val.replace(cleanPhrase, '')) && processed.includes(cleanPhrase)) {
        processed = processed.split(cleanPhrase).join(val);
      }
    }
  }

  // 3. تطبيق موسوعة المصطلحات المصرية الأصيلة
  const idiomKeys = Object.keys(EGYPTIAN_IDIOMS_BANK).sort((a, b) => b.length - a.length);
  for (const idiom of idiomKeys) {
    if (processed.includes(idiom)) {
      processed = processed.split(idiom).join(EGYPTIAN_IDIOMS_BANK[idiom]);
    }
  }

  // 4. فك التباس المتشابهات السياقية في المصرية
  processed = processed.replace(
    /(?<![\u0621-\u064A])نفسي\s+(أ|ا|ن|ت|ي|م|روح|أكل|آكل|أشرب|أنام|أمشي|أقعد|أشوف|أعرف|أقول|أعمل|أخرج|أسافر)/g,
    'نِفْسي $1'
  );
  processed = processed.replace(/(?<![\u0621-\u064A])عشرة\s+(عمر|سنين|طويلة|قديمة|طيبة|أيام)/g, 'عِشْرة $1');
  processed = processed.replace(/(?<![\u0621-\u064A])(شايل|تشيل|شال|يا|من)\s+هم(?![\u0621-\u064A])/g, '$1 هَمّ');

  // 5. ضبط الكلمات المفردة من القاموس المصري الخفيف دون إغراق الجملة بالسكون
  const tokens = processed.split(/(\s+|[.,!؟?،؛:"«»\-–—…]+)/);

  return tokens
    .map((token) => {
      if (!token || /^(\s+|[.,!؟?،؛:"«»\-–—…]+)$/.test(token)) {
        return token;
      }

      const stripped = stripDiacritics(token);

      if (EGYPTIAN_PHONETIC_LEXICON[stripped]) {
        return EGYPTIAN_PHONETIC_LEXICON[stripped];
      }

      if (customDict && customDict[stripped]) {
        return customDict[stripped];
      }

      // معالجة حرف العطف (و / ف / ب) المتصل بكلمة في القاموس
      if (stripped.length > 3) {
        for (const prefix of ['وب', 'ول', 'فب', 'فل', 'و', 'ف', 'ب', 'ل']) {
          if (stripped.startsWith(prefix) && stripped.length > prefix.length + 1) {
            const stem = stripped.slice(prefix.length);
            if (EGYPTIAN_PHONETIC_LEXICON[stem]) {
              return prefix + EGYPTIAN_PHONETIC_LEXICON[stem];
            }
          }
        }
      }

      return token;
    })
    .map(rdPausal)
    .join('');
}

/**
 * إرجاع النص الصوتي المصري السليم بدون تشويه حرف القاف إلى همزة مكتوبة
 */
function toDeepEgyptianAcousticScript(rawText, customDict = {}) {
  return applyEgyptianPhonetics(rawText, customDict);
}

/**
 * تشكيل الفصل عند اللصق مع التمييز الذكي بين السرد الروائي (يبقى فصحى سليمة) والحوار (يُضبط بالعامية المصرية)
 */
function shapeFullChapterOnPaste(rawChapterText, customDict = {}) {
  if (!rawChapterText || !rawChapterText.trim()) return '';
  return rawChapterText
    .split('\n')
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) return line;
      // إذا كان السطر حواراً يبدأ بشرطة (-) نطبق عليه الضبط المصري، أما السرد فنحافظ عليه سليماً بدون تشويه
      if (/^[-–—•]/.test(trimmed)) {
        return applyEgyptianPhonetics(line, customDict);
      }
      return line
        .replace(/دِلْوَأْتِي|دلوأتي/g, 'دلوقتي')
        .replace(/يِؤُولْ/g, 'يقول');
    })
    .join('\n');
}
const egyPhon = (t) => { try { return applyEgyptianPhonetics(String(t || '')); } catch (e) { return t; } };
/* ---------- خط أداة الرداد (الوضع B): تحليل ذكي ← تشكيل ← صوت لكل مقطع بشخصيته وانفعاله ← دمج ---------- */
const RD_P = [{"id": "kareem", "v": "Charon", "n": "كريم", "a": "narrator_male", "p": 0.95, "i": "deep, resonant, rich baritone (rakheem) storyteller voice, warm and unhurried"}, {"id": "tarek", "v": "Fenrir", "n": "طارق", "a": "adult_male_dramatic", "p": 1.0, "i": "intense dramatic male voice"}, {"id": "youssef", "v": "Puck", "n": "يوسف", "a": "young_male", "p": 1.02, "i": "lively young male voice"}, {"id": "mahmoud", "v": "Algenib", "n": "محمود", "a": "elder_male", "p": 0.9, "i": "mature calm older male voice"}, {"id": "noor", "v": "Kore", "n": "نور", "a": "adult_female", "p": 1.05, "i": "warm expressive young female voice"}, {"id": "salma", "v": "Sulafat", "n": "سلمى", "a": "narrator_female", "p": 1.02, "i": "confident clear female voice"}, {"id": "layla", "v": "Zephyr", "n": "ليلى", "a": "young_female", "p": 1.08, "i": "soft gentle young female voice"}, {"id": "adam_child", "v": "Leda", "n": "طفل", "a": "child", "p": 1.18, "i": "youthful high-pitched child voice"}];
const RD_I = {"normal": {"l": "عادي", "b": "بأداء تمثيلي طبيعي ومتوازن"}, "strong": {"l": "قوي", "b": "بانفعال قوي وواضح جداً في نبرة الصوت"}, "max": {"l": "أقصى انفعال 🔥", "b": "بأقصى درجات الانفعال التمثيلي الحقيقي من قلب الحدث كأن المشهد حقيقي تماماً"}};
const RD_E = {"angry_shout": {"l": "غاضب ويصرخ بشدة", "m": "انفعال شديد وغضب عارم وصوت مرتفع حاد كأنك تصرخ في مواجهة حقيقية بكل قوة", "e": "انفعال مصري شديد جداً وغضب عارم وصوت عالي وحاد ومنفعل كأنك بتصرخ بجد في خناقة ومواجهة عنيفة"}, "fear_whisper": {"l": "خائفة وتهمس بارتجاف", "m": "خوف شديد وصوت هامس مرتجف وأنفاس متلاحقة متوترة تكاد تُسمع من شدة الرعب", "e": "خوف ورعب حقيقي وصوت مصري واطي مهموس ومرتجف وبيترعش مع نهجان خفيف كأنها مرعوبة بجد"}, "child_fear": {"l": "يبكي بذعر وخوف (طفل)", "m": "صوت طفل صغير بريء يتحدث بطبقة رفيعة وبنبرة خائفة باكية تستنجد بوالدها", "e": "صوت طفل مصري صغير بيعيط ومذعور وخايف أوي وبيستنجد بمامته أو باباه بنبرة طفولية باكية"}, "crying_sad": {"l": "حزين ومنكسر / يبكي", "m": "حزن عميق وصوت مختنق بالدموع والبكاء والرجاء المؤثر", "e": "صوت مصري حزين جداً ومكسور ومخنوق بالدموع والعياط والوجع كأنه بيعيط بجد"}, "sarcastic_cold": {"l": "ساخر ومتهكم ببرود", "m": "برود قاتل وسخرية لاذعة وثقة مستفزة مع نبرة تهديد خفية", "e": "برود أعصاب وسخرية مصرية لاذعة وتهكم واستفزاز وثقة عالية في الكلام مع نبرة تهديد هادية"}, "shock_surprise": {"l": "مصدوم ومذهول", "m": "صدمة مفاجئة وذهول وعدم تصديق مع شهقة خفيفة وتقطع في الأنفاس", "e": "صدمة كبيرة وذهول مصري وعدم تصديق من المفاجأة"}, "happy_warm": {"l": "فرحان، دافئ، أو حنون", "m": "سعادة غامرة وحماس ودفء عاطفي وابتسامة واضحة في نبرة الصوت", "e": "حنان ودفا مصري وطمأنينة أو فرحة كبيرة في الكلام"}, "dramatic_narrator": {"l": "سرد درامي مشوق", "m": "سرد روائي سينمائي عميق ومتزن يبني التشويق الدرامي ويهيئ المستمع للمشهد", "e": "سرد حكواتي مصري سلس وعميق ومشوق بلهجة مصرية رصينة وطبيعية بدون تكلف"}, "natural_dialogue": {"l": "هادئ وحازم / طبيعي", "m": "نبرة حوارية طبيعية وواضحة وحازمة بهدوء", "e": "كلام مصري قاهري طبيعي وتلقائي وحازم زي كلام المصريين في الحقيقة بالظبط"}};
const RD_SYS = "أنت مخرج دراما إذاعية مصري خبير في اللهجة العامية المصرية القاهرية والمصطلحات الشعبية والتمثيل الصوتي البشري.\nمهمتك: تحليل الفصل الروائي وتقسيمه بالترتيب إلى مقاطع (سرد للراوي + حوارات الشخصيات) مع كتابة التشكيل الصوتي المصري المتصل (phoneticText) لكل جملة بحيث ينطقها الممثل كإنسان مصري حقيقي بدون أي أخطاء!\nاجعل الحوار بالعامية المصرية والسرد باللغة العربية الفصحى.\n\nقواعد الذاكرة الذاتية والمصطلحات المصرية المدربة (يجب الالتزام بها حرفياً وعدم الخطأ فيها أبداً):\n[]\n\nقواعد كتابة phoneticText (النطق المصري الأصيل) — تخص أجزاء الحوار (dialogue) فقط. ممنوع تطبيق أي منها على السرد (narration): نص السرد في حقل text يبقى كما هو حرفياً كما كتبه المؤلف تماماً (بنفس الكلمات والحروف والفصحى)، ولا تغيّر فيه حرفاً ولا تحوّله للعامية ولا تضف عليه تشكيلاً، وphoneticText للسرد يكون فارغاً.\nأ) phoneticText = نفس كلام text بالظبط لكن مكتوب «زي ما المصري بينطقه فعلاً». لا تضيف ولا تحذف كلمة ولا تغيّر المعنى.\nب) حوّل أي كلمة مكتوبة بحروف فصحى وبتتنطق مصري بشكل مختلف إلى رسمها المنطوق: ث→ت أو س (ثلاثة=تلاتة، ثقيل=تقيل)، ذ→د أو ز (ذهب=راح أو دَهَب، ذكي=زكي)، ظ→ض أو ز (ظالم=زالِم، ظهر=ضَهر). القاف في الكلمات العامية الدارجة تتكتب همزة لأن المصري بينطقها كده (بقى=بَأَى، قلت=أُلت، قال=أَال، بيقول=بِيأُول، قدام=أُدّام، قهوة=أَهوَه، قلب=أَلب، قوي=أَوي)، أما الكلمات الفصحى أو الرسمية أو الدينية وأسماء العلم فتفضل بالقاف (قرآن، قانون، قاضي، قصر، قاهرة، قدر). حرف ج يفضل كما هو (جيم مصرية صلبة) ولا تحوّله أبداً. كلمة ظابط/ضابط تتكتب «ظَابِط» بالظاء. وتاء التأنيث عند الوقف هاء (مَدرَسَه، كِفايَه).\nج) الضمائر والأدوات بالرسم المصري الأصيل: ده/دي/دول، كده، إزاي، ليه، إيه، فين، إمتى، مين، إنتَ/إنتِ/إنتو، هو/هي/هُمّ، احنا، مش، لسّه، بقى، يعني، أهو/أهي، علشان، بتاع، عايز/عايزة، دلوقتي، النهارده، بكره، برضه، خالص، قوي، حاجه.\nد) الأفعال المصرية: بـ للمضارع (بَاكُل، بِتِقول، بِيروح)، هـ للمستقبل (هَاكُل، هَتِروح)، والنفي بـ «ما…ش» (مَعرَفش، مَقالِش). ولا يوجد مثنى (أنتما=إنتو).\nهـ) التشكيل انتقائي ومحسوب: شكّل فقط الكلمات اللي ممكن تتنطق غلط (الملتبسة أو اللي نطقها المصري يختلف عن الفصحى أو أسماء العلم الغريبة)، واترك الكلمات الشائعة السهلة بدون تشكيل (ده، مش، إيه…) لأن كثرة التشكيل الغلط أسوأ من عدمه. أي كلمة مش متأكد من تشكيلها اتركها بدون تشكيل.\nو) ممنوع حركات الإعراب في آخر أي كلمة (لا ضمة ولا كسرة ولا فتحة ولا تنوين) ما عدا الكاف والتاء اللي بتفرّق المذكر من المؤنث (إنتَ/إنتِ، عليكَ/عليكِ). ولفظ الجلالة دايماً «اللَّٰه» بدون كسرة في آخره.\nز) لو الكلمة موجودة في «قواعد الذاكرة الذاتية» اللي فوق استخدم تشكيلها حرفياً، وهي أولى من تقديرك.\nح) راجع phoneticText كلمة كلمة قبل الإخراج وتأكد إنه ينطق كأنه مصري من القاهرة بدون أي أثر فصحى أو خليجي في الحوار.\n\nقواعد حاسمة جداً للمصطلحات والأوزان الصرفية المصرية:\n1. انتبه للمصطلحات الشعبية المصرية التي تختلف حركاتها عن الفصحى:\n   - «رقبتي سدّادة» تُشكّل صوتياً بالمصري: «رَقَبْتِي سَدَّادَه» (بفتح السين وتشديد الدال على وزن فَعَّالَه، وتسكين الباء في رَقَبْتِي، وإياك أن تكتبها سِدادة بالكسر!).\n   - «دمي محروق» ⬅️ «دَمِّي مَحْرُوق»، «حقك عليا» ⬅️ «حَقَّك عَلَيَّا»، «مليش نفس» ⬅️ «مَالِيش نِفْس» (بكسر النون في نِفْس)، «على عيني وراسي» ⬅️ «عَلَى عِينِي وَرَاسِي».\n2. عندما تقرأ سرداً يمهد للحوار مثل: «انفعل «أحمد» بشدة وصرخ وهو يقول بغضب: - أنت إزاي تعمل فيا كدا!»:\n   - السطر الأول هو سرد للراوي (speaker: \"الراوي\", type: \"narration\", emotionId: \"dramatic_narrator\").\n   - السطر الثاني هو بصوت شخصية «أحمد» (speaker: \"أحمد\", type: \"dialogue\") وانفعاله هو الغضب الشديد والصراخ (emotionId: \"angry_shout\")، ودرجة حدة الانفعال هي القصوى (intensity: \"max\").\n3. اكتب «والله» في العامية المصرية هكذا: «وَاللَّاهِي»، واكتب التاء المربوطة عند الوقف بالهاء الصوتية «ه» (مثل: سَدَّادَه، كِفَايَه، خَايْفَه).\n4. اختر speakerArchetype من القيم التالية فقط:\n   - \"narrator_male\" | \"adult_male_dramatic\" | \"young_male\" | \"elder_male\" | \"adult_female\" | \"narrator_female\" | \"young_female\" | \"child\"\n5. اختر emotionId من القيم التالية فقط:\n   - \"angry_shout\" | \"fear_whisper\" | \"child_fear\" | \"crying_sad\" | \"sarcastic_cold\" | \"shock_surprise\" | \"happy_warm\" | \"dramatic_narrator\" | \"natural_dialogue\"\n6. اختر intensity من القيم التالية فقط:\n   - \"normal\" | \"strong\" | \"max\"\n7. افهم من سياق الحوار مين بيكلم مين (المتكلم والمخاطَب وجنس كل واحد منهم) وراعِ صيغة المذكر والمؤنث في كل كلمة: المخاطَب الرجل = إنتَ / عليك / معاك / ليك / اسمع، والمخاطَبة الست = إنتِ / عليكي / معاكي / ليكي / اسمعي، وكلام المتكلم عن نفسه يتبع جنسه هو. لو في النص المكتوب غلط واضح في الصيغة بالنسبة للسياق صححه، ولو مش متأكد سيب الكلمة زي ما هي. ممنوع تضيف أو تحذف أو تغيّر أي كلمة أو معنى غير كده، وممنوع تكرر أي كلمة.";
function detectLineDialect(line) {
  const cleanLine = stripDiacritics(line);
  const egyMarkers = /(إزاي|ازاي|كدا|كده|أوي|اوي|مكنش|مكانش|مفيش|عشان|علشان|بتاع|اللي|إيه|ايه|عايز|عاوز|يلا|بقى|ليه|احنا|إحنا|ده|دي|دول|دلوقتي|حاجة|فيا|جمبك|معاك|تاني|بس|أكتر|غصب|هما|هددوني|خايف|متخافش|تفتكر|تخبي|ورا|محدش|هيكتشف|كفاية|تمن|رقبتي|سدادة|مليش)/;
  return egyMarkers.test(cleanLine) ? 'egyptian' : 'msa';
}

// ---------------------------------------------------------------------------
// V10.3: استنتاج العمر والجنس من السياق (سرد + اسم + طريقة الكلام) بدل الاعتماد على الاسم فقط
// ---------------------------------------------------------------------------
// أسماء رجال بتنتهي بـ ة/ى وكانت بتتحسب ست غلط
const MALE_NAMES_ENDING_FEM = /^(حمزة|أسامة|اسامة|طلحة|معاوية|عكاشة|قتيبة|مصطفى|موسى|عيسى|يحيى|مرتضى|مجتبى|عكرمة|سلامة|زكريا|عبادة)$/;
const FEMALE_VERBS = /(قالت|ردت|ردّت|همست|صرخت|سألت|أجابت|بكت|ابتسمت|التفتت|نظرت|تنهدت|قاطعت|أضافت|تمتمت|صاحت|هتفت)/;
const MALE_VERBS = /(قال|رد|همس|صرخ|سأل|أجاب|بكى|ابتسم|التفت|نظر|تنهد|قاطع|أضاف|تمتم|صاح|هتف)(?![\u0621-\u064A])/;
const VOICE_GENDER = { kareem: 'm', tarek: 'm', youssef: 'm', mahmoud: 'm', noor: 'f', salma: 'f', layla: 'f', adam_child: 'c' };

/** يتأكد إن صوت الشخصية يطابق جنسها (راجل بصوت ست أو العكس) ولا يستخدم صوت الراوي لشخصية عادية */
function fixVoiceGender(charInfo, narratorVoiceId = 'kareem') {
  if (!charInfo || !charInfo.voiceId) return charInfo ? charInfo.voiceId : undefined;
  if (charInfo.category === 'راوي' || charInfo.name === 'الراوي') return charInfo.voiceId;
  if (charInfo.category === 'طفل') return charInfo.voiceId;
  const vg = VOICE_GENDER[charInfo.voiceId];
  const arch = charInfo.archetype || '';
  const wantF = charInfo.category === 'امرأة' || /امرأة|فتاة|طفلة|بنت/.test(arch);
  const wantM = !wantF && (charInfo.category === 'رجل' || charInfo.category === 'رجل مسن' || /رجل|شاب|بطل/.test(arch));
  const seed = (charInfo.name || '').split('').reduce((a, c) => a + c.charCodeAt(0), 0);
  if (wantF && vg === 'm') return pickVoiceForGenderAge('female', charInfo.ageBand || 'middle', seed);
  if (wantM && vg === 'f') return pickVoiceForGenderAge('male', charInfo.ageBand || 'middle', seed);
  if (charInfo.voiceId === narratorVoiceId) return pickVoiceForGenderAge(wantF ? 'female' : 'male', charInfo.ageBand || 'middle', seed);
  return charInfo.voiceId;
}

const AGE_CUES = {
  child: /(طفل|طفلة|صغير|صغيرة|ولد صغير|بنت صغيرة|رضيع|تلميذ|تلميذة|بابا|ماما|يا بابا|يا ماما|عايز لعبة|في المدرسة|الحضانة)/,
  elder: /(عجوز|شيخ|الشيخ|حاج|الحاج|الحاجة|جد|جده|الجد|الجدة|تيته|جدو|مسن|مسنة|كهل|شايب|ستيني|سبعيني|ثمانيني|شعره الأبيض|شعرها الأبيض|تجاعيد|متكئ على عكاز|عكازه|ظهره المنحني|صوته المتهدج|بصوت مرتعش|بنيي|يا ابني|يا بني|يا بنتي|يا حبيبي يا ابني|زمان كان|أيام زمان|في أيامنا)/,
  middle: /(أب|والد|الأب|أم|الأم|والدة|رجل في الأربعين|امرأة في الأربعين|خمسيني|أربعيني|مدير|الأستاذ|أستاذ|الدكتور|دكتور|المحامي|الضابط|زوجها|زوجته|زوجي|مراتي|جوزي|عيالي|ولادي)/,
  young: /(شاب|شابة|فتى|فتاة|مراهق|مراهقة|طالب|طالبة|جامعة|الجامعة|صديقه|صاحبي|صاحبه|يا صاحبي|يا عم|يا باشا|يا معلم|يا زميل)/
};

/** يرجع الفئة العمرية المرجّحة للمتكلم: child | young | middle | elder */
function inferSpeakerAgeBand(speakerName = '', narrativeContext = '', spokenText = '') {
  const nm = stripDiacritics(speakerName);
  const nar = stripDiacritics(narrativeContext);
  const spk = stripDiacritics(spokenText);

  // السرد المباشر عن المتكلم أقوى دليل
  const scoped = nar.includes(nm) && nm ? nar : nar;
  if (AGE_CUES.child.test(nm) || /(الطفل|الطفلة|ولد صغير|بنت صغيرة|رضيع)/.test(scoped)) return 'child';
  if (AGE_CUES.elder.test(nm) || AGE_CUES.elder.test(scoped)) return 'elder';

  // كلام المتكلم نفسه: "يا ابني / يا بنتي / زمان" => كبير، "يا صاحبي / يا باشا" => شاب
  if (/(يا ابني|يا بني|يا بنتي|زمان كان|أيام زمان|في سني|لما كنت في سنك|ربنا يهديك يا ابني)/.test(spk)) return 'elder';
  if (/(بابا|ماما|يا بابا|يا ماما|عايز لعبة|مش هنام|هقول لماما)/.test(spk)) return 'child';

  if (AGE_CUES.young.test(nm) || AGE_CUES.young.test(scoped) || /(يا صاحبي|يا باشا|يا معلم|يا برو|يا عم)/.test(spk)) return 'young';
  if (AGE_CUES.middle.test(nm) || AGE_CUES.middle.test(scoped)) return 'middle';

  // رقم عمر صريح: "في الستين من عمره"، "عمره 70"
  const ageNum = (scoped.match(/(?:عمره|عمرها|في ال|في)\s*(\d{1,2})\s*(?:سنة|من عمره|من عمرها)?/) || [])[1];
  if (ageNum) {
    const a = parseInt(ageNum, 10);
    if (a < 13) return 'child';
    if (a >= 60) return 'elder';
    if (a >= 38) return 'middle';
    return 'young';
  }
  return 'middle';
}

/** يختار الصوت المناسب لجنس + عمر الشخصية، مع الحفاظ على التنوع بين الشخصيات */
function pickVoiceForGenderAge(gender, ageBand, seed = 0) {
  const MAP = {
    male: { child: ['adam_child'], young: ['youssef'], middle: ['tarek'], elder: ['mahmoud'] },
    female: { child: ['adam_child'], young: ['layla', 'noor'], middle: ['noor'], elder: ['noor'] }
  };
  const list = (MAP[gender] || MAP.male)[ageBand] || (MAP[gender] || MAP.male).middle;
  return list[Math.abs(seed) % list.length];
}

function inferCharacterVoice(speakerName, contextLine = '', existingRegistry = {}) {
  const cleanName = stripDiacritics(speakerName);

  // البحث في بنك الشخصيات بدون تشكيل لضمان التطابق التام دائماً
  for (const regKey of Object.keys(existingRegistry)) {
    if (stripDiacritics(regKey) === cleanName) {
      return existingRegistry[regKey];
    }
  }

  const lowerContext = stripDiacritics(contextLine + ' ' + cleanName).toLowerCase();

  if (/(الطفل|الطفلة|الصغير|الصغيرة|ولد صغير|بنت صغيرة|آدم|ادم|جنى|سليم الصغير)/.test(lowerContext)) {
    return {
      name: cleanName,
      voiceId: 'adam_child',
      archetype: 'طفل صغير',
      category: 'طفل',
      preferredDialect: 'egyptian',
      locked: true
    };
  }

  if (/(الجد|العجوز|الشيخ|الحاج|مسن|كهل|شايب|جدو)/.test(lowerContext) && !/(الجدة|الحاجة|تيته)/.test(lowerContext)) {
    return {
      name: cleanName,
      voiceId: 'mahmoud',
      archetype: 'رجل مسن / حكيم',
      category: 'رجل مسن',
      preferredDialect: 'egyptian',
      locked: true
    };
  }

  const femaleIndicators = /(قالت|همست|صرخت|بكت|تراجعت|ردت|المرأة|الأم|الفتاة|ليلى|ليلي|سارة|نور|سلمى|مريم|فاطمة|هند|رانيا|ملك|حبيبة|ياسمين|آية|دينا|نهى|هدى|عائشة|الجدة|الحاجة|تيته|الست|مسنة)/;
  const hash = cleanName.split('').reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
  const ageBand = inferSpeakerAgeBand(cleanName, contextLine, '');

  const nameLooksFem = (cleanName.endsWith('ة') || cleanName.endsWith('ى')) && !MALE_NAMES_ENDING_FEM.test(cleanName);
  const verbFem = FEMALE_VERBS.test(lowerContext) && lowerContext.includes(cleanName);
  const verbMale = MALE_VERBS.test(lowerContext) && !FEMALE_VERBS.test(lowerContext) && lowerContext.includes(cleanName);
  if ((femaleIndicators.test(lowerContext) || nameLooksFem || verbFem) && !verbMale) {
    const ageLabel = { child: 'طفلة', young: 'فتاة شابة', middle: 'امرأة ناضجة', elder: 'امرأة مسنة' }[ageBand];
    return {
      name: cleanName,
      voiceId: pickVoiceForGenderAge('female', ageBand, hash),
      archetype: ageLabel,
      category: ageBand === 'child' ? 'طفل' : 'امرأة',
      ageBand,
      preferredDialect: 'egyptian',
      locked: true
    };
  }

  const ageLabelM = { child: 'طفل صغير', young: 'شاب', middle: 'رجل ناضج', elder: 'رجل مسن / حكيم' }[ageBand];
  return {
    name: cleanName,
    voiceId: pickVoiceForGenderAge('male', ageBand, hash),
    archetype: ageLabelM,
    category: ageBand === 'child' ? 'طفل' : ageBand === 'elder' ? 'رجل مسن' : 'رجل',
    ageBand,
    preferredDialect: 'egyptian',
    locked: true
  };
}

/**
 * استخراج الانفعال الدرامي + درجة حدة الانفعال (عادي / قوي / أقصى انفعال 🔥) من السرد بعد تجريد التشكيل لضمان عدم فشل المطابقة أبداً
 */
function detectEmotionFromContext(narrativeContext, dialogueText, isChild = false) {
  const combined = stripDiacritics(`${narrativeContext} ${dialogueText}`);

  if (isChild && /(خايف|خائفة|يبكي|تبكي|بذعر|مرعوب|ماما|بابا|الحقوني)/.test(combined)) {
    return {
      emotionId: 'child_fear',
      intensity: 'max',
      actingNote: 'طفل مصري صغير بيبكي بذعر وخوف حقيقي وبيستنجد بمامته بصوت طفولي مرتجف'
    };
  }

  if (/(انفعل|صرخ|بغضب|بشدة|بحدة|هاج|ثائر|صاح|بصوت عال|عنيف|إزاي تعمل|ازاي تعمل|دمرت|كفاية|محروق)/.test(combined)) {
    const isMax = /(بشدة|صرخ|بغضب|انفعل|كفاية|دمرت|!).*/.test(combined);
    return {
      emotionId: 'angry_shout',
      intensity: isMax ? 'max' : 'strong',
      actingNote: 'غاضب جداً وبيصرخ بشدة وانفعال مصري ناري من قلب الخناقة والمواجهة'
    };
  }

  if (/(همس|همست|بخوف|مرتجف|برعب|مذعور|خافت|تراجعت|يرتجف|يكاد يسمع|هددوني)/.test(combined)) {
    return {
      emotionId: 'fear_whisper',
      intensity: /(شديد|مرتجف|رعب|هددوني)/.test(combined) ? 'max' : 'strong',
      actingNote: 'خايفة جداً وبتهمس بصوت مصري واطي ومرتعش وفيه نهجان خوف حقيقي'
    };
  }

  if (/(يبكي|تبكي|بدموع|بحزن|بأسى|بألم|مختنق|متهدج)/.test(combined)) {
    return {
      emotionId: 'crying_sad',
      intensity: 'strong',
      actingNote: 'نبرة مصرية حزينة ومكسورة ومخنوقة بالدموع والعياط'
    };
  }

  if (/(بحنان|بطمأنينة|متخافش|حبيبي|جمبك|جنبك|بحب|بفرح|بسعادة|ابتسم|سدادة)/.test(combined)) {
    return {
      emotionId: 'happy_warm',
      intensity: 'strong',
      actingNote: 'نبرة مصرية حنونة ودافية جداً فيها طمأنينة واحتواء وشهامة'
    };
  }

  if (/(بسخرية|ببرود|بتهكم|استفزاز|ابتسم بخبث|هدوء قاتل)/.test(combined)) {
    return {
      emotionId: 'sarcastic_cold',
      intensity: 'strong',
      actingNote: 'سخرية مصرية لاذعة وبرود أعصاب وثقة مستفزة'
    };
  }

  if (/(بصدمة|بذهول|شهق|شهقت|غير مصدق|مفاجأة)/.test(combined)) {
    return {
      emotionId: 'shock_surprise',
      intensity: 'max',
      actingNote: 'صدمة وذهول وعدم تصديق من المفاجأة'
    };
  }

  if (isChild) {
    return {
      emotionId: 'child_fear',
      intensity: 'normal',
      actingNote: 'صوت طفل مصري صغير بريء وتلقائي'
    };
  }

  return {
    emotionId: 'natural_dialogue',
    intensity: 'normal',
    actingNote: 'أداء تمثيلي مصري طبيعي وحازم يناسب سياق المشهد'
  };
}

/**
 * المحلل الدرامي الذكي للفصول (Smart Chapter & Emotion Parser v11.0):
 * - يجرد التشكيل أولاً عند استخراج اسم الشخصية والانفعال حتى لا تفشل المطابقة أبداً
 * - يفصل تلقائياً بين جمل السرد الروائي (تبقى فصحى سليمة بدون تشويه) وجمل الحوار (تأخذ الضبط المصري القاهري)
 */
// ---------------------------------------------------------------------------
// V10.2: تحديد المخاطَب (بيكلم مين) وضبط صيغة المذكر/المؤنث في الحوار المصري
// ---------------------------------------------------------------------------
const FEM_ADDRESS_CUES = /(لها|إليها|اليها|نحوها|نظر إلى ال?(?:ست|امرأة|فتاة|بنت)|سألها|ناداها|قال لها|قالها لها|التفت إلى ليلى)/;

/** يحدد من هو المخاطَب: يبحث أولاً عن اسم شخصية معروفة في سطر السرد غير المتكلم نفسه، ثم عن ضمير/كلمة تدل على الجنس */
function inferAddressee(speaker, contextLine = '', registry = {}, lastOtherSpeaker = null) {
  const ctx = stripDiacritics(contextLine);
  const cleanSpeaker = stripDiacritics(speaker);

  // 1) اسم صريح بعد "ل/إلى/نحو/مع/على" في السرد
  for (const key of Object.keys(registry)) {
    const k = stripDiacritics(key);
    if (!k || k === 'الراوي' || k === cleanSpeaker) continue;
    const re = new RegExp('(?:^|\\s)(?:ل|إلى|الى|نحو|مع|على|ناد[ىي]|سأل|خاطب|التفت\\s+(?:إلى|الى))\\s*' + k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    if (re.test(ctx)) return registry[key];
  }

  // 2) ضمير مؤنث/مذكر بعد فعل القول
  if (/(قال|قالت|سأل|سألت|همس|همست|صرخ|صرخت|رد|ردت)\s*(?:ل)?(?:ها)\b/.test(ctx) || FEM_ADDRESS_CUES.test(ctx)) {
    return { category: 'امرأة', name: '؟' };
  }
  if (/(قال|قالت|سأل|سألت|همس|همست|صرخ|صرخت|رد|ردت)\s*(?:ل)?(?:ه)\b/.test(ctx)) {
    return { category: 'رجل', name: '؟' };
  }

  // 3) آخر شخصية تكلمت قبل المتكلم الحالي (الحوار بيتبادل غالباً)
  if (lastOtherSpeaker && registry[lastOtherSpeaker] && stripDiacritics(lastOtherSpeaker) !== cleanSpeaker) {
    return registry[lastOtherSpeaker];
  }
  return null;
}

/** ضبط صيغة المخاطَب (مذكر/مؤنث) — بيغيّر بس كلمات المخاطَب الصريحة (إنت/عليك/معاك/ليك/أوامر…) ومبيلمسش كلام المتكلم عن نفسه ولا الغائب */
const RD_DI = '[\\u064B-\\u0652\\u0670]*', RD_AR = '\\u0621-\\u064A';
const rdWord = (w) => new RegExp('(?<![' + RD_AR + '])([وف]?)' + [...w].map((c) => c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join(RD_DI) + RD_DI + '(?![' + RD_AR + '])', 'g');
const RD_F2M = [['إنتي', 'إنتَ'], ['انتي', 'إنتَ'], ['أنتي', 'أنتَ'], ['إنتِ', 'إنتَ'], ['انتِ', 'إنتَ'], ['أنتِ', 'أنتَ'], ['عليكي', 'عليك'], ['معاكي', 'معاك'], ['ليكي', 'ليك'], ['منكي', 'منك'], ['فيكي', 'فيك'], ['عندكي', 'عندك'], ['وراكي', 'وراك'], ['قدامكي', 'قدامك'], ['جنبكي', 'جنبك'], ['حواليكي', 'حواليك'], ['خليكي', 'خليك'], ['اسمعي', 'اسمع'], ['شوفي', 'شوف'], ['ارجعي', 'ارجع'], ['افتحي', 'افتح'], ['اقعدي', 'اقعد'], ['متقوليش', 'متقولش'], ['متخافيش', 'متخافش'], ['متزعليش', 'متزعلش'], ['متعمليش', 'متعملش'], ['متبكيش', 'متبكش'], ['متروحيش', 'متروحش'], ['متسيبيش', 'متسيبش'], ['بتعملي', 'بتعمل'], ['بتقولي', 'بتقول'], ['بتروحي', 'بتروح'], ['بتحبي', 'بتحب'], ['بتفكري', 'بتفكر'], ['بتعرفي', 'بتعرف'], ['بتشوفي', 'بتشوف'], ['بتسمعي', 'بتسمع'], ['بتفهمي', 'بتفهم'], ['هتعملي', 'هتعمل'], ['هتقولي', 'هتقول'], ['هتروحي', 'هتروح']];
const RD_M2F = [['إنت', 'إنتِ'], ['انت', 'إنتِ'], ['أنت', 'أنتِ'], ['عليك', 'عليكي'], ['معاك', 'معاكي'], ['ليك', 'ليكي'], ['فيك', 'فيكي'], ['عندك', 'عندكي'], ['وراك', 'وراكي'], ['قدامك', 'قدامكي'], ['جنبك', 'جنبكي'], ['خليك', 'خليكي'], ['اسمع', 'اسمعي'], ['شوف', 'شوفي'], ['متقولش', 'متقوليش'], ['متخافش', 'متخافيش'], ['متزعلش', 'متزعليش'], ['متعملش', 'متعمليش'], ['متبكش', 'متبكيش']];
const RD_PRED = '(?:عايز|عاوز|فاهم|متأكد|جاهز|مبسوط|زعلان|تعبان|خايف|عارف|مصدق|متخيل|فاكر|موافق|مستعد|جعان|عطشان|مرهق|قلقان|متعصب|مصمم|مش فاهم)';
const RD_RE = { f2m: RD_F2M.map(([a, b]) => [rdWord(a), b]), m2f: RD_M2F.map(([a, b]) => [rdWord(a), b]),
  p2: new RegExp('((?:إنت|انت|أنت|إنتِ|انتي|إنتي|أنتي)' + RD_DI + '\\s+(?:مش\\s+|لسه\\s+|لسة\\s+)?)(' + RD_PRED.slice(3, -1) + ')(ة?)(?![' + RD_AR + '])', 'g'),
  p1: new RegExp('((?:أنا|انا)' + RD_DI + '\\s+(?:مش\\s+|لسه\\s+|لسة\\s+)?)(' + RD_PRED.slice(3, -1) + ')(ة?)(?![' + RD_AR + '])', 'g') };
/** addrG/selfG: 'm' | 'f' | '' — مفيش تعديل لو الجنس مش معروف بثقة */
function rdFixGender(text, addrG, selfG) {
  let out = String(text || ''); if (!out) return out;
  const pred = (re, g) => { out = out.replace(re, (m, pre, w) => pre + w + (g === 'f' ? 'ة' : '')); };
  if (addrG === 'f') { for (const [re, to] of RD_RE.m2f) out = out.replace(re, (m, pf) => pf + to); pred(RD_RE.p2, 'f'); }
  else if (addrG === 'm') { for (const [re, to] of RD_RE.f2m) out = out.replace(re, (m, pf) => pf + to); pred(RD_RE.p2, 'm'); }
  if (selfG === 'f' || selfG === 'm') pred(RD_RE.p1, selfG);
  if (addrG === 'f' || addrG === 'm') out = rdSubj(rdKaf(rdNegImp(out, addrG), addrG), addrG);
  return out;
}
// كاف المخاطَب: قولتلَك (لمذكر) ≠ قولتلِك (لمؤنث) — نشكّل الكاف حسب جنس المخاطَب بدل ما التحويل الصوتي يخمّن فتحة دايماً
const RD_KAF_X = new Set(['ملك', 'مالك', 'سلك', 'شك', 'فك', 'حك', 'ترك', 'تحرك', 'ضحك', 'مسك', 'فلك', 'شباك', 'بنك', 'ديك', 'ذلك', 'كذلك', 'هناك', 'هنالك', 'مبروك', 'مبارك', 'تبارك', 'ملاك', 'بارك', 'اشتبك', 'سبك', 'نك', 'تك', 'كوك', 'ماك', 'بيك', 'تيك', 'يك', 'اك', 'سكك', 'حيك', 'مشترك', 'شريك', 'مدرك', 'مشارك']);
const RD_KAF_RE = /(?<![\u0621-\u064A\u064B-\u0652])([\u0621-\u064A][\u064B-\u0652\u0621-\u064A]*?)ك[\u064E\u064F\u0650]?(?=ش(?![\u0621-\u064A])|(?![\u0621-\u064A\u064B-\u0652]))/g;
function rdKaf(text, g) { // الحركة بتتحط على الحرف اللي قبل الكاف (قولتلِك للمؤنث / قولتلَك للمذكر) والكاف نفسها تفضل ساكنة
  const v = g === 'f' ? '\u0650' : '\u064E';
  return text.replace(RD_KAF_RE, (m, w) => {
    const full = w + 'ك', pl = full.replace(/[\u064B-\u0652]/g, '');
    if (pl.length < 2 || RD_KAF_X.has(pl) || /^(?:ال|وال|بال|لل|فال)/.test(pl) || /^ك/.test(pl) && pl.length < 4) return m;
    if (g === 'f' && /ي$/.test(w.replace(/[\u064B-\u0652]/g, ''))) return m; // ليكي/عليكي بتشتغل لوحدها
    const mm = /^([\s\S]*?)([\u0621-\u064A])([\u064B-\u0652]*)$/.exec(w); if (!mm) return m;
    if (/[اوىي]/.test(mm[2])) return full; // حرف مد قبل الكاف (معاك/عليك): مفيش مكان للحركة
    return mm[1] + mm[2] + (mm[3].includes('\u0651') ? '\u0651' : '') + v + 'ك';
  });
}
// «ذكي»: أي صيغة بتفرّق بين المخاطَب والمخاطَبة بالحركة بس → كسرة للأنثى وفتحة للراجل
// (إنتَ/إنتِ، وفعل الماضي بعد إنت: عملتَ/عملتِ، قلتَ/قلتِ)
const RD_SUBJ_X = new Set(['بنت', 'ست', 'وقت', 'اخت', 'أخت', 'صوت', 'بيت', 'موت', 'زيت', 'كبت', 'مثلت', 'نت', 'ثبت', 'خت', 'امت', 'إمت', 'سكت']);
function rdSubj(text, g) {
  const v = g === 'f' ? '\u0650' : '\u064E', L = '[\\u0621-\\u064A]', D = '[\\u064B-\\u0652]';
  const pron = new RegExp('(?<!' + L + D + '*)([وف]?[إأا][\\u064B-\\u0652]?ن)ت' + D + '*(?![' + '\\u0621-\\u064A\\u064B-\\u0652' + '])', 'g');
  let out = text.replace(pron, (m, a) => a + 'ت' + v);
  const verb = new RegExp('([إأا]نت' + D + '\\s+(?:(?:مش|لسه|لسة|كمان|فعلا|فعلاً|ليه|إزاي|امبارح|دلوقتي)\\s+)*)(' + L + '(?:' + L + D + '*){1,}?)ت' + D + '*(?![\\u0621-\\u064A\\u064B-\\u0652])', 'g');
  out = out.replace(verb, (m, pre, w) => {
    const pl = (w + 'ت').replace(/[\u064B-\u0652]/g, '');
    if (RD_SUBJ_X.has(pl) || pl.length < 3 || /^ال/.test(pl)) return m;
    return pre + w + 'ت' + v;
  });
  return out;
}
// نهي مؤنث/مذكر (متتسرعيش ↔ متتسرعش): قاعدة صرفية عامة بدل قايمة كلمات، مع استثناء الأفعال الناقصة (متنساش/متجيش…)
const RD_NI_X = new Set(['متنس', 'متبك', 'متج', 'متجي', 'متحك', 'ماتنس', 'ماتج', 'ماتجي']);
const RD_NI_AR = '[\\u0621-\\u063A\\u0641-\\u064A]';
const RD_NI_F = new RegExp('(?<!' + RD_NI_AR + '[\\u064B-\\u0652]*)((?:م|ما)[\\u064B-\\u0652]*ت[\\u064B-\\u0652]*(?:' + RD_NI_AR + '[\\u064B-\\u0652]*){1,})ي[\\u064B-\\u0652]*ش(?!' + RD_NI_AR + ')', 'g');
const RD_NI_M = new RegExp('(?<!' + RD_NI_AR + '[\\u064B-\\u0652]*)((?:م|ما)[\\u064B-\\u0652]*ت[\\u064B-\\u0652]*(?:' + RD_NI_AR + '[\\u064B-\\u0652]*){1,})ش(?!' + RD_NI_AR + ')', 'g');
function rdNegImp(text, g) {
  text = g === 'm' ? text.replace(/(?<![\u0621-\u064A])متنسيش(?![\u0621-\u064A])/g, 'متنساش').replace(/(?<![\u0621-\u064A])اتنسيش(?![\u0621-\u064A])/g, 'اتنساش') : text.replace(/(?<![\u0621-\u064A])متنساش(?![\u0621-\u064A])/g, 'متنسيش');
  const plain = (x) => x.replace(/[\u064B-\u0652]/g, '');
  return text.replace(g === 'm' ? RD_NI_F : RD_NI_M, (m, stem) => {
    const ps = plain(stem), last = ps.slice(-1);
    if (RD_NI_X.has(ps) || ps.length < 4) return m;
    if (g === 'f') { if (/[اىيو]/.test(last)) return m; return stem.replace(/[\u064B-\u0652]+$/, '') + 'يش'; }
    return stem.replace(/[\u064B-\u0652]+$/, '') + 'ش';
  });
}
function adaptDialogueToAddressee(text, addresseeCategory) {
  if (!text || !addresseeCategory) return text;
  const isFem = addresseeCategory === 'امرأة', isMasc = addresseeCategory === 'رجل' || addresseeCategory === 'رجل مسن';
  return isFem ? rdFixGender(text, 'f', '') : isMasc ? rdFixGender(text, 'm', '') : text;
}

/** لو الشخصية جديدة (مش مقفولة يدوياً) نحسّن اختيار صوتها من طريقة كلامها نفسه، ولا نغيّر صوت شخصية المستخدم قفلها */
function refineProfileBySpeech(profile, speaker, narrative, spokenText, registry) {
  if (!profile || profile.userLocked) return profile;
  const known = Object.keys(registry).some((k) => stripDiacritics(k) === stripDiacritics(speaker));
  if (known) return profile; // الشخصية متسجلة قبل كده: نحافظ على ثبات صوتها طول الفصل
  const band = inferSpeakerAgeBand(speaker, narrative, spokenText);
  if (band === profile.ageBand) return profile;
  const isFemale = profile.category === 'امرأة' || /امرأة|فتاة|طفلة/.test(profile.archetype || '');
  const hash = stripDiacritics(speaker).split('').reduce((a, c) => a + c.charCodeAt(0), 0);
  return {
    ...profile,
    ageBand: band,
    voiceId: pickVoiceForGenderAge(isFemale ? 'female' : 'male', band, hash),
    category: band === 'child' ? 'طفل' : isFemale ? 'امرأة' : band === 'elder' ? 'رجل مسن' : 'رجل'
  };
}

function parseNovelChapterLocally(
  chapterText,
  currentRegistry,
  novelDialectMode = 'egy_dialogue_msa_narration',
  customDict = {}
) {
  const lines = chapterText
    .split(/\n+/)
    .map((l) => l.trim())
    .filter(Boolean);

  const segments = [];
  const updatedRegistry = { ...currentRegistry };
  let lastNarrativeLine = '';
  let lastHintedSpeaker = null;
  let prevDialogueSpeaker = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const cleanLineNoDiacritics = stripDiacritics(line);

    const colonDialogueMatch = line.match(/^([^:：\-«»]{2,25}?)(?:\s*\(([^)]+)\))?\s*[:：]\s*(.+)$/);
    const dashDialogueMatch = line.match(/^(?:[-–—•]\s*|«)(.+?)(?:»)?$/);

    if (dashDialogueMatch) {
      const spokenText = dashDialogueMatch[1].trim();
      const cleanLastNarrative = stripDiacritics(lastNarrativeLine);
      let speaker = lastHintedSpeaker ? stripDiacritics(lastHintedSpeaker) : ((segments.slice().reverse().find((z) => z.type === 'dialogue') || {}).speaker || 'المتحدث');

      const quotedNameMatch = cleanLastNarrative.match(/[«"']([^«"'»]{2,20})[»"']/);
      const verbNameMatch = cleanLastNarrative.match(
        /(?:انفعل|انفعلت|صرخ|صرخت|همس|همست|قال|قالت|رد|ردت|تراجع|تراجعت|ركض|ركضت|الطفل|الطفلة|المحقق|العجوز|القائد)\s+(?:الطفل\s+|الطفلة\s+|المحقق\s+|العجوز\s+)?[«"']?([^\s«"'»،.:]{2,15})[»"']?/
      );

      if (quotedNameMatch) {
        speaker = stripDiacritics(quotedNameMatch[1]);
      } else if (verbNameMatch) {
        speaker = stripDiacritics(verbNameMatch[1]);
      } else {
        for (const knownName of Object.keys(updatedRegistry)) {
          const cleanKnown = stripDiacritics(knownName);
          if (cleanKnown !== 'الراوي' && cleanLastNarrative.includes(cleanKnown)) {
            speaker = cleanKnown;
            break;
          }
        }
      }

      let charProfile = inferCharacterVoice(speaker, cleanLastNarrative, updatedRegistry);
      charProfile = refineProfileBySpeech(charProfile, speaker, cleanLastNarrative, spokenText, updatedRegistry);
      updatedRegistry[speaker] = charProfile;

      const isChild = charProfile.voiceId === 'adam_child' || /طفل/.test(charProfile.archetype);
      const { emotionId, intensity, actingNote } = detectEmotionFromContext(
        cleanLastNarrative,
        spokenText,
        isChild
      );

      const lineDialect = detectLineDialect(spokenText);

      const addressee = inferAddressee(speaker, cleanLastNarrative, updatedRegistry, prevDialogueSpeaker);
      const adaptedText =
        spokenText;
      const phoneticText =
        lineDialect === 'egyptian' ? applyEgyptianPhonetics(adaptedText, customDict) : spokenText;
      prevDialogueSpeaker = speaker;

      segments.push({
        id: 'seg-' + i,
        type: 'dialogue',
        speaker,
        addressee: addressee?.name || null,
        addresseeCategory: addressee?.category || null,
        text: spokenText,
        phoneticText,
        dialect: lineDialect,
        emotionId,
        intensity: intensity || 'max',
        actingDirection: actingNote,
        contextCue: lastNarrativeLine
      });

      lastHintedSpeaker = null;
    } else if (
      colonDialogueMatch &&
      !/(قال|صرخ|همس|رد|أضاف|تابع|سأل|يقول|تقول)\s/.test(stripDiacritics(colonDialogueMatch[1]))
    ) {
      const speaker = stripDiacritics(colonDialogueMatch[1]);
      const bracketEmotion = colonDialogueMatch[2] || '';
      const spokenText = colonDialogueMatch[3].trim();

      let charProfile = inferCharacterVoice(
        speaker,
        bracketEmotion + ' ' + lastNarrativeLine,
        updatedRegistry
      );
      charProfile = refineProfileBySpeech(
        charProfile,
        speaker,
        bracketEmotion + ' ' + lastNarrativeLine,
        spokenText,
        updatedRegistry
      );
      updatedRegistry[speaker] = charProfile;

      const isChild = charProfile.voiceId === 'adam_child' || /طفل/.test(charProfile.archetype);
      const { emotionId, intensity, actingNote } = detectEmotionFromContext(
        `${lastNarrativeLine} ${bracketEmotion}`,
        spokenText,
        isChild
      );

      const lineDialect = detectLineDialect(spokenText);
      const addressee = inferAddressee(
        speaker,
        bracketEmotion + ' ' + lastNarrativeLine,
        updatedRegistry,
        prevDialogueSpeaker
      );
      const adaptedText =
        spokenText;
      const phoneticText =
        lineDialect === 'egyptian' ? applyEgyptianPhonetics(adaptedText, customDict) : spokenText;
      prevDialogueSpeaker = speaker;

      segments.push({
        id: 'seg-' + i,
        type: 'dialogue',
        speaker,
        addressee: addressee?.name || null,
        addresseeCategory: addressee?.category || null,
        text: spokenText,
        phoneticText,
        dialect: lineDialect,
        emotionId,
        intensity: intensity || 'strong',
        actingDirection: bracketEmotion ? `${actingNote} (${bracketEmotion})` : actingNote,
        contextCue: bracketEmotion || lastNarrativeLine
      });
    } else {
      lastNarrativeLine = line;
      const quotedNameMatch = cleanLineNoDiacritics.match(/[«"']([^«"'»]{2,20})[»"']/);
      if (quotedNameMatch) {
        lastHintedSpeaker = stripDiacritics(quotedNameMatch[1]);
        updatedRegistry[lastHintedSpeaker] = inferCharacterVoice(
          lastHintedSpeaker,
          cleanLineNoDiacritics,
          updatedRegistry
        );
      }

      // السرد الروائي يكون بالفصحى السليمة افتراضياً ما لم يكن مكتوباً بكلمات عامية صريحة
      // السرد فصيح دائماً، إلا لو المستخدم اختار صراحةً تحويل كل النص للمصري
      const narratorDialect = novelDialectMode === 'ai_convert_all_egy' ? 'egyptian' : 'msa';

      const cleanedNarration = line
        .replace(/[:：]\s*$/, '.')
        .replace(/دِلْوَأْتِي|دلوأتي/g, 'دلوقتي')
        .replace(/يِؤُولْ/g, 'يقول');

      segments.push({
        id: 'seg-' + i,
        type: 'narration',
        speaker: 'الراوي',
        text: cleanedNarration,
        phoneticText:
          narratorDialect === 'egyptian'
            ? applyEgyptianPhonetics(cleanedNarration, customDict)
            : cleanedNarration,
        dialect: narratorDialect,
        emotionId: 'dramatic_narrator',
        intensity: 'normal',
        actingDirection:
          narratorDialect === 'egyptian'
            ? 'سرد حكواتي مصري سلس وعميق يمهد لانفعال المشهد القادم بدون تكلف'
            : 'سرد روائي فصيح وعميق يمهد لانفعال المشهد القادم',
        contextCue: 'سرد المشهد'
      });
    }
  }

  return { segments, updatedRegistry };
}
function rdSplitQuotes(text) { // حوار جوه الفقرة «..» أو “..” بيتفصل لسطر حوار لوحده (زي ما الأداة بتقرا الشرطة)
  const out = [];
  for (const raw of String(text).split('\n')) {
    const ln = raw.trim(); if (!ln) continue;
    if (/^[-–—•«]/.test(ln) || /^[^:：\-«»]{2,25}?[:：]\s*\S/.test(ln)) { out.push(ln); continue; }
    let rest = ln, any = false; const re = /[«“"]([^«»“”"\n]{8,}?)[»”"]/;
    for (let m; (m = re.exec(rest)) && (/\s/.test(m[1]) || m[1].length >= 12);) {
      const before = rest.slice(0, m.index).trim(), inner = m[1].trim(); any = true;
      if (before) out.push(before.replace(/[:：،,]\s*$/, '.'));
      out.push('- ' + inner); rest = rest.slice(m.index + m[0].length).trim();
    }
    if (rest) out.push(rest); else if (!any) out.push(ln);
  }
  return out.join('\n');
}
const rdLocal = (text, conf) => {
  const sh = shapeFullChapterOnPaste(rdSplitQuotes(text), rdDict(conf));
  const { segments, updatedRegistry } = parseNovelChapterLocally(sh, {}, (conf.rd || RD_DEF).mode === 'C' ? 'ai_convert_all_egy' : 'egy_dialogue_msa_narration', rdDict(conf));
  const nar = (conf.rd || RD_DEF).narrator;
  return segments.map((s) => ({ ...s, vid: s.type === 'dialogue' ? fixVoiceGender(updatedRegistry[s.speaker], nar) : undefined }));
};
const rdPartMx = (conf) => ((conf.rd || RD_DEF).partChars > 0 ? conf.rd.partChars : conf.engine === 'single' ? 900 : 1600);
const rdPersB = (id) => RD_P.find((p) => p.id === id) || RD_P[0];
let RD_CF = RD_DEF; // إعدادات الرداد الحالية (بتتظبط أول radadPart)
const rdPers = (id) => { const b = rdPersB(id), o = (RD_CF.pers || {})[id]; return o ? { ...b, v: o.v || b.v, p: o.p || b.p } : b; };
const rdByArch = (a) => RD_P.find((p) => p.a === a && !/^narrator/.test(p.a));
function rdDsp(pcm16, pitch, warm = true) { pitch = 0; // V10.5: تغيير الطبقة اتعطّل (بيسبب كسر في الصوت) // بصمة الشخصية (طبقة) + فلتر الدفء — زي الأداة بالظبط
  let x = pcm16;
  if (pitch && Math.abs(pitch - 1) >= 0.02) {
    const n = Math.floor(pcm16.length / pitch), o = new Int16Array(n);
    for (let i = 0; i < n; i++) { const s = i * pitch, i0 = Math.floor(s), i1 = Math.min(pcm16.length - 1, i0 + 1), f = s - i0; o[i] = Math.round(pcm16[i0] * (1 - f) + pcm16[i1] * f); }
    x = o;
  }
  return x; // الأداة الجديدة: نقاء 24kHz بدون أي فلتر كتم — طبقة الصوت بس
  const h = new Int16Array(x.length); let prev = 0;
  for (let i = 0; i < x.length; i++) { const sm = (x[i] / 32768) * 0.88 + prev * 0.12; prev = sm; const w = Math.tanh(sm * 1.12) / Math.tanh(1.12); h[i] = Math.max(-32767, Math.min(32767, Math.round(w * 32767))); }
  return h;
}
function rdHints(text, conf) { // قاموس الكلمات اللي في الجزء ده بس (المتعلّم + المدمج) بتتبعت للنموذج علشان يلتزم بيها
  try {
    const dd = rdDict(conf), seen = new Set(), out = {};
    for (const w of stripDiacritics(String(text)).match(/[\u0621-\u064A]{2,}/g) || []) {
      if (seen.has(w)) continue; seen.add(w);
      const v = dd[w] || EGYPTIAN_PHONETIC_LEXICON[w]; if (v && v !== w) out[w] = v;
      if (Object.keys(out).length >= 160) break;
    }
    return JSON.stringify(out);
  } catch (e) { return '{}'; }
}
async function rdAnalyze(env, text, conf) { // التحليل الذكي: مقاطع (راوي + شخصيات) بالترتيب مع الانفعال والتشكيل
  const MB = 'اجعل الحوار بالعامية المصرية والسرد باللغة العربية الفصحى.', cf = conf.rd || RD_DEF, MT = cf.mode === 'A' ? 'اجعل الحوار بالعامية المصرية المشكّلة صوتياً، والسرد بروح مصرية طبيعية وسلسة غير متكلفة (حكواتي مصري).' : cf.mode === 'C' ? 'حوّل جمل السرد والحوار بالكامل إلى عامية مصرية متدفقة وضعها في حقل text مع الحفاظ على كل المعنى والأحداث.' : MB;
  const body = JSON.stringify({ contents: [{ parts: [{ text }] }], systemInstruction: { parts: [{ text: RD_SYS.replace(MB, MT).replace('[]', () => rdHints(text, conf)) }] }, generationConfig: { responseMimeType: 'application/json', responseSchema: { type: 'ARRAY', items: { type: 'OBJECT', properties: { type: { type: 'STRING' }, speaker: { type: 'STRING' }, speakerArchetype: { type: 'STRING' }, dialect: { type: 'STRING' }, emotionId: { type: 'STRING' }, intensity: { type: 'STRING' }, actingDirection: { type: 'STRING' }, text: { type: 'STRING' }, phoneticText: { type: 'STRING' } }, propertyOrdering: ['type', 'speaker', 'speakerArchetype', 'dialect', 'emotionId', 'intensity', 'actingDirection', 'text', 'phoneticText'] } } } });
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
let RD_LEARN = {};
const rdLrnOk = (k) => !/(ك|كي)$/.test(String(k)); // كلمات المخاطَب (عليك/عليكي…) مبتتحفظش في القاموس: صيغتها بتتحدد من السياق مش من قاموس ثابت
const rdDict = (conf) => { const o = {}; for (const k in RD_LEARN) if (rdLrnOk(k)) o[k] = RD_LEARN[k]; String(conf.dict || '').split('\n').forEach((l) => { const k = l.indexOf('='); if (k > 0) o[l.slice(0, k).trim()] = l.slice(k + 1).trim(); }); return o; };
const rdEgy = (seg, conf) => seg.type === 'dialogue' || (conf.rd || RD_DEF).mode !== 'B';
const rdScript = (seg, conf) => {
  let s = rdEgy(seg, conf) ? applyEgyptianPhonetics((seg.phoneticText && seg.phoneticText.trim()) || seg.text, rdDict(conf)) : applyAllahPronunciation(seg.text);
  if (rdEgy(seg, conf) && (conf.rd || RD_DEF).tashkeel === 0) s = s.replace(/[\u064B-\u0652\u0670]/g, ''); // وضع «من غير تشكيل»: الكلام بالرسم المصري بس
  if (rdEgy(seg, conf) && (seg.addr === 'm' || seg.addr === 'f')) s = rdKaf(s, seg.addr); // كاف المخاطَب تفضل مشكّلة حتى في وضع «من غير تشكيل»
  if ((conf.rd || RD_DEF).humanize && (seg.emotionId === 'fear_whisper' || seg.emotionId === 'crying_sad')) s = s.replace(/\.\./g, '... ');
  return s;
};
// تدريب اللهجة: كل شخصية ليها توجيه لهجة مصرية خاص بيها (عشان صوت الشاب مايضيعش في العامية) — بيتزوّد حسب إعداد dialect (0 عادي/1 قوي/2 أقصى)
const RD_ACC = {
  young_male: 'a young Cairo guy in his twenties speaking street Egyptian slang (ya basha, ya3ni, khalas, eh da) with a confident casual relaxed rhythm, hard Egyptian G for jeem, glottal stop for qaf, never textbook Arabic',
  adult_male_dramatic: 'a grown Cairo man speaking authentic Egyptian colloquial with a firm, deep, intense delivery, glottal qaf, hard G for jeem',
  elder_male: 'an older Cairo man speaking slow, warm, wise baladi Egyptian with a gravelly calm tone, glottal qaf, hard G for jeem',
  adult_female: 'a Cairo woman speaking natural everyday Egyptian colloquial, expressive, warm and confident, glottal qaf, hard G for jeem',
  young_female: 'a young Cairo girl speaking lively natural Egyptian colloquial (ya3ni, khalas, eh da), light and playful but never baby-talk, glottal qaf, hard G for jeem',
  child: 'a little Egyptian child speaking simple cute Egyptian colloquial with childlike rhythm',
  narrator_male: 'a warm Egyptian storyteller', narrator_female: 'a warm Egyptian storyteller'
};
// طبقة "الواقعية البشرية": تنفّس وتردد وتغيّر إيقاع ونزول صوت آخر الجملة… (0 مطفي/1 خفيف/2 أقصى)
const RD_HUM0 = 'Say exactly the written words only, without adding, repeating, skipping or changing any word, and keep every masculine or feminine form exactly as written';
const RD_HUM1 = 'Sound like a real person speaking naturally, not reading: subtle breaths between phrases, uneven natural rhythm, pitch falling at the end of statements and rising on questions. ' + RD_HUM0;
const RD_HUM2 = 'Sound like a real person speaking naturally, not reading: subtle breaths between phrases, uneven natural rhythm, pitch falling at the end of statements and rising on questions, emotion coming through the voice, volume varying with meaning, never a flat announcer cadence. ' + RD_HUM0;
const rdHuman = (conf) => { const lv = ((conf.rd || RD_DEF).human); return ' ' + (lv === 0 ? RD_HUM0 : lv >= 2 ? RD_HUM2 : RD_HUM1) + '.'; };
const rdAccent = (persona, conf) => { const lv = ((conf.rd || RD_DEF).dialect); if (lv === 0) return ''; const a = RD_ACC[persona && persona.a] || ''; if (!a) return ''; return ' Speak as ' + a + (lv >= 2 ? '. Keep authentic Cairo pronunciation (hard G for jeem, glottal stop for qaf) and stay in Egyptian colloquial throughout, never drifting to Gulf, Levantine or Modern Standard Arabic' : '') + '.'; };
const RD_CUE = 'in a natural Cairo Egyptian colloquial accent (Masri, never Gulf/Saudi), like a real human in a real conversation: natural breaths, small hesitations, varied pace and pitch, spontaneous and emotionally alive; a steady natural chest voice like an ordinary adult, no vocal breaks or cracking, no breathy or affected effeminate softness, no sing-song; end words with sukun and never pronounce Arabic grammatical case endings (i3raab); pronounce the Arabic letter ح as a clear breathy pharyngeal ha (never as kh), pronounce ج as a hard Egyptian g (never a soft zh), pronounce the Arabic letter ر as a clear tapped Arabic r (never as غ or ل, no lisp, no slurring of consonants, crisp clear articulation), and pronounce the word الله fully with a heavy emphatic lam as Allaah (never a light allah); never robotic and never like reading text aloud';
const RD_STY = { angry_shout: ['Say angrily and loudly with intense dramatic emotion', 'Say angrily and loudly with intense dramatic emotion in Arabic'], fear_whisper: ['Say in a frightened, trembling, breathless whisper', 'Say in a frightened, trembling whisper in Arabic'], child_fear: ["Say in a scared, crying little child's voice", "Say in a scared, crying little child's voice in Arabic"], crying_sad: ['Say in a sad, heartbroken, tearful voice', 'Say in a sad, tearful voice in Arabic'], sarcastic_cold: ['Say in a cold, sarcastic, mocking tone', 'Say in a cold, sarcastic tone in Arabic'], shock_surprise: ['Say in a shocked, breathless, astonished tone', 'Say in a shocked, astonished tone in Arabic'], happy_warm: ['Say in a warm, affectionate, reassuring Egyptian tone', 'Say in a warm, affectionate, reassuring tone in Arabic'], dramatic_narrator: ['Say as a warm, intimate human storyteller who lives the story, with natural breaths and pauses', 'Say as a deep, resonant, warm human audiobook storyteller in clear Modern Standard Arabic, unhurried measured pace, meaningful pauses, steady chest voice with no vocal breaks, no breathy or affected softness, never robotic'], natural_dialogue: ['Say naturally', 'Say as a natural, expressive human speaker in clear Modern Standard Arabic, steady chest voice, no vocal breaks or affected softness, natural pauses and intonation, never robotic'] };
async function rdSpeak(env, seg, persona, conf) { // مقطع واحد بصوت شخصيته — نفس صيغة الأداة الجديدة (جملة إخراج قصيرة + النص) بـ3 محاولات
  const egy = rdEgy(seg, conf), script = rdScript(seg, conf), st = RD_STY[seg.emotionId] || RD_STY.natural_dialogue;
  const addrH = seg.addr === 'm' ? ' You are speaking to a man, so address him with masculine forms exactly as written.' : seg.addr === 'f' ? ' You are speaking to a woman, so address her with feminine forms exactly as written.' : '', acc = (egy ? rdAccent(persona, conf) : '') + addrH, directive = egy ? st[0] + ' ' + RD_CUE + acc + rdHuman(conf) : st[1] + acc + rdHuman(conf);
  const cands = egy ? [directive + ': ' + script, 'Say ' + RD_CUE + acc + rdHuman(conf) + ': ' + script, script] : [directive + ': ' + script, script, String(seg.text)];
  const need = String(seg.text).replace(/\s/g, '').length;
  for (const pr of cands) {
    for (let k = 0; k < 2; k++) {
      const body = JSON.stringify({ contents: [{ parts: [{ text: pr }] }], generationConfig: { responseModalities: ['AUDIO'], speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName: persona.v } } } } });
      const r = await rdCall(env, conf, body);
      if (!r.ok) { if (r.status >= 500 && k < 1) continue; const e = new Error('gemini_' + r.status); e.code = 502; throw e; }
      const pcm16 = rdPcm(await r.json()); if (!pcm16) break;
      if (need < 25 || pcm16.length / 24000 >= need / 20) return rdDsp(pcm16, persona.p, true);
    }
  }
  const e = new Error('short_audio'); e.code = 502; e.detail = 'صوت ناقص من جوجل — هيتعاد'; throw e;
}
async function rdMega(env, batch, conf) { // الدمج الفائق: لحد 7 مشاهد (متحدثين اتنين بالكتير) في طلب واحد
  if (batch.length === 1) return rdSpeak(env, batch[0], rdPers(batch[0].pid), conf);
  const sp = []; batch.forEach((s) => { if (!sp.find((u) => u.tag === s.speaker)) sp.push({ tag: s.speaker, p: rdPers(s.pid) }); });
  const A = sp[0], B = sp[1] || { tag: 'المتحدث_الثاني', p: rdPers('youssef') };
  const lines = batch.map((s) => { const emo = RD_E[s.emotionId] || RD_E.natural_dialogue; return s.speaker + ': (' + emo.l + ' - ' + (s.actingDirection || '') + ') ' + rdScript(s, conf); }).join('\n');
  const gW = (u) => { const g = rdGen(u.p.id); return g === 'm' ? 'رجل' : g === 'f' ? 'امرأة' : ''; }, adL = (sp.length === 2 && sp[0].tag !== 'الراوي' && sp[1].tag !== 'الراوي' && gW(sp[0]) && gW(sp[1])) ? '\nمين بيكلم مين: ' + sp[0].tag + ' (' + gW(sp[0]) + ') بيكلم ' + sp[1].tag + ' (' + gW(sp[1]) + ') والعكس — اقرأ كل كلمة بصيغتها المكتوبة بالظبط (مذكر/مؤنث) ومتغيّرش إنت/إنتِ ولا عليك/عليكي.' : '', accL = sp.map((u) => { const a = rdAccent(u.p, conf); return a ? u.tag + ':' + a : ''; }).filter(Boolean).join(' | '), prompt = 'قم بتمثيل هذا المشهد الدرامي المصري ببراعة وواقعية بشرية 100% باللهجة العامية المصرية القاهرية الصميمة (نطق الجيم المصرية غير المعطشة G، وصل الكلمات بنعومة بشرية، والالتزام التام بالتشكيل الصوتي المصري المكتوب دون تحويل أي كلمة للفصحى).' + (((conf.rd || RD_DEF).mode === 'B') && batch.some((s) => s.type === 'narration') ? '\nاستثناء: المتحدث «الراوي» يقرأ سرده باللغة العربية الفصحى السليمة.' : '') + ''+(accL?'\nتوجيه لهجة كل متحدث (Egyptian accent coaching) — '+accL:'')+adL+(rdHuman(conf)?'\nتوجيه الأداء البشري (Human performance direction):'+rdHuman(conf):'')+'\nالتزم بالانفعال المكتوب بين القوسين لكل جملة دون أن تنطق الكلام الموجود داخل القوسين ودون نطق أسماء المتحدثين:\n\n' + lines;
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
// تعلّم كلمات الفصل قبل التحويل (من الأداة): الكلمات العامية الجديدة تتشكّل بنطق مصري وتتحفظ في القاموس
async function rdLearn(env, text, conf) {
  try {
    const lines = String(text || '').split('\n').filter((l) => /^\s*[-–—•]/.test(l) || /^[^\s:：]{1,20}\s*[:：]/.test(l) || /[«"“]/.test(l));
    const dd = rdDict(conf), known = new Set([...Object.keys(EGYPTIAN_PHONETIC_LEXICON).map(stripDiacritics), ...Object.keys(dd).map(stripDiacritics)]);
    const freq = {};
    for (const l of lines) for (const w of stripDiacritics(l).match(/[\u0621-\u064A]{3,}/g) || []) if (!known.has(w)) freq[w] = (freq[w] || 0) + 1;
    const words = Object.keys(freq).slice(0, 220); if (!words.length) return 0;
    const prompt = 'أنت خبير نطق في العامية المصرية القاهرية. هذه كلمات من حوار مصري بدون تشكيل:\n' + JSON.stringify(words) + '\nأرجع JSON object فقط: المفتاح الكلمة كما هي، والقيمة نفس الكلمة بنفس الحروف تماماً مع إضافة الحركات بنطقها المصري الصحيح.\nشروط: (1) لا تغيّر أي حرف ولا تستبدل القاف بهمزة. (2) أدرج فقط الكلمات العامية أو التي قد تُنطق خطأً أو بنطق مصري مختلف عن الفصحى. (3) أهمل الكلمات الفصيحة العادية وأسماء الأعلام والكلمات المبهمة المعنى بلا سياق.';
    const r = await gFetch(env, 'https://generativelanguage.googleapis.com/v1beta/models/' + ((conf.rd || RD_DEF).anaModel || 'gemini-3-flash-preview') + ':generateContent', { method: 'POST', signal: AbortSignal.timeout(45000), headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { responseMimeType: 'application/json' } }) });
    if (!r.ok) return 0;
    const j = await r.json(), obj = JSON.parse((((j.candidates || [])[0] || {}).content || {}).parts.map((x) => x.text || '').join('') || '{}'), clean = {};
    for (const [k, v] of Object.entries(obj)) { const key = stripDiacritics(k); if (typeof v === 'string' && freq[key] && stripDiacritics(v) === key && v !== key && v.length <= key.length * 2 + 4) clean[key] = v; }
    const n = Object.keys(clean).length; if (!n) return 0;
    let cur = {}; try { cur = (await getSetting(env, 'rd_learned')) || {}; } catch (e) {}
    const merged = { ...cur, ...clean }, keys = Object.keys(merged); if (keys.length > 20000) keys.slice(0, keys.length - 20000).forEach((k) => delete merged[k]);
    await setSetting(env, 'rd_learned', merged); RD_LEARN = merged; return n;
  } catch (e) { return 0; }
}

// تعليم الأداة من تسجيل صوتي مصري: Gemini يسمع التسجيل ويطلّع تشكيل النطق الصحيح، ويتحفظ في القاموس الدائم
async function rdLearnMerge(env, clean, src) {
  const n = Object.keys(clean).length; if (!n) return 0;
  let cur = {}; try { cur = (await getSetting(env, 'rd_learned')) || {}; } catch (e) {}
  const merged = { ...cur, ...clean }, keys = Object.keys(merged); if (keys.length > 20000) keys.slice(0, keys.length - 20000).forEach((k) => delete merged[k]);
  await setSetting(env, 'rd_learned', merged); RD_LEARN = merged;
  try { const lg = (await getSetting(env, 'rd_learn_log')) || {}; const arr = (lg.items || []).slice(0, 49); arr.unshift({ at: Date.now(), n, src, w: Object.keys(clean).slice(0, 8) }); await setSetting(env, 'rd_learn_log', { items: arr }); } catch (e) {}
  return n;
}
async function rdLearnAudio(env, b64, mime, word, hint) {
  const one = (word || '').trim();
  const prompt = one
    ? 'استمع للتسجيل. المتحدث مصري وبينطق الكلمة «' + one + '». شكّل الكلمة بالحركات بنفس النطق المصري اللي سمعته بالظبط. أرجع JSON object فقط: {"' + one + '": "الكلمة مشكّلة"}. لا تغيّر أي حرف.'
    : 'أنت خبير نطق في العامية المصرية. استمع للتسجيل (كلام مصري' + (hint ? '، والنص المكتوب التقريبي: ' + hint.slice(0, 600) : '') + ') وفرّغه بالعامية المصرية. ثم أرجع JSON object فقط: المفتاح الكلمة بدون تشكيل كما تُكتب، والقيمة نفس الكلمة بنفس الحروف تماماً مع الحركات بحسب نطقها المصري في التسجيل. أدرج فقط الكلمات التي ينطقها المصريون بشكل مختلف عن الفصحى أو التي قد يخطئ فيها قارئ آلي (أسماء، عامية، ضمائر). حد أقصى 150 كلمة، ولا تغيّر أي حرف.';
  const r = await gFetch(env, 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent', { method: 'POST', signal: AbortSignal.timeout(90000), headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts: [{ inlineData: { mimeType: mime, data: b64 } }, { text: prompt }] }], generationConfig: { responseMimeType: 'application/json' } }) });
  if (!r.ok) throw new Error('تعذّر تحليل الصوت (' + r.status + ')');
  const j = await r.json(), txt = (((j.candidates || [])[0] || {}).content || {}).parts; if (!txt) throw new Error('مفيش رد من Gemini');
  let obj = {}; try { obj = JSON.parse(txt.map((x) => x.text || '').join('')); } catch (e) { throw new Error('رد غير مفهوم'); }
  const clean = {};
  for (const [k, v] of Object.entries(obj)) { const key = stripDiacritics(String(k)).trim(); if (typeof v === 'string' && key && !/\s/.test(key) && stripDiacritics(v) === key && v !== key && v.length <= key.length * 2 + 4) clean[key] = v; }
  return clean;
}
// جنس الراوي لكل رواية: m = كريم، f = سلمى (بيتحفظ للرواية كلها)
// جنس الشخصية من اسمها (قوائم أسماء + ألقاب) — بتغلب على تخمين النموذج علشان ما نديش ست صوت راجل
const RD_NM_F = 'سناء سلمي ليلي نور نورا نورهان هدي هدير هبه هاله هناء هند ريم رنا رانيا رحمه رشا رضوي زينب زهره ساره سارا سمر سميه سعاد سلوي سهير ساميه شيماء شهد شروق شاديه صفاء صباح ضحي عايشه عائشه عايده علا عبير ايه ايمان امل اميره اسماء اسراء انتصار الفت الهام بسمه بسنت بدور بثينه تهاني تغريد جميله جيهان جني حنان حبيبه حياه حسناء حليمه خديجه خلود دعاء دينا دنيا دلال رباب رقيه رغده روان روضه ريهام زهراء زكيه سوسن سحر سندس سيلين شريفه شاهنده صابرين عفاف عزه عليا غاده غدير فاطمه فريده فرح فيروز فايزه قمر كريمه كوثر لمياء لبني لينا لمي ماجده مريم مني مها ميار مي ميرنا مروه ملك منال ميسون ناديه ناهد نجلاء نجوي نسرين نهي نيره نشوي نعمه هاجر هايدي هيام وفاء وداد ولاء ياسمين يسري يمني ندي نوال نبيله سميره صفيه تسنيم الاء رولا ريما لارا سالي ماريا مارييه نانسي شيرين شرين فوزيه فتحيه فايقه ورده بهيه نعيمه عزيزه انوار سلمي مديحه ليديا جومانا جوهره رحاب ايناس ابتسام ازهار اماني امنيه ايفا بتول بشري بلقيس تحيه ثريا جنات حور خيريه دارين دعد ذكري رابعه ربا رزان رفيده روفيدا سجي سديل سلاف سما سمحه شذا شفق شمس صفوه طيبه عالياء غزل فجر فدوي كاميليا كوكب لجين لطيفه ليان مارتينا مرفت مفيده منيره موني ناجيه نجاح نرمين نغم هنادي وسام وعد يارا يقين ايلين ايلين ايلاف ايلا ايمي ايات ايسل تالين تالا تيا ديما دانا دانه ريماس رتاج لانا لين ميرا مايا ميرال نيرة نيرمين نادين ناريمان هيا هيفاء يسر جنى جوري سيلا سيرين شهيرة ضحى عائشة عزة فريدة كارما مادلين منار'.split(/\s+/).filter(Boolean);
const RD_NM_M = 'احمد محمد محمود علي عمر عمرو خالد يوسف كريم طارق حسن حسين ابراهيم مصطفي عبدالله عبدالرحمن هشام سامح سيف زياد ياسر ياسين امير انس باسم بلال تامر تميم جمال جاسر حازم حمزه حمدي خليل رامي رضا زكريا سامي سعيد سليم سليمان شريف صلاح عادل عاصم عصام عماد فارس فادي فتحي فريد فهد قاسم كمال ماجد مازن مالك مجدي مراد مروان مسعد معتز منصور مهند ناصر نبيل نادر هاني وائل وليد ياسر يحيي يزيد يونس ادهم اسامه اشرف اكرم ايمن ايهاب بهاء حاتم حسام رمضان سمير صبري عبدالعزيز عزت علاء غسان فؤاد لؤي ممدوح مختار نعمان هيثم وسيم الياس ايلان ايوب ادم اسر يزن يامن جاد جودت دياب ديفيد رائد رامز ريان زين شادي صهيب طه عدنان عز قيس ماهر مؤمن'.split(/\s+/).filter(Boolean);
const rdNmNorm = (t) => String(t || '').replace(/[ً-ْٰـ]/g, '').replace(/[أإآٱ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه').trim();
let RD_NM_FS = null, RD_NM_MS = null;
function rdNameGender(name) {
  if (!RD_NM_FS) { RD_NM_FS = new Set(RD_NM_F.map(rdNmNorm)); RD_NM_MS = new Set(RD_NM_M.map(rdNmNorm)); }
  let w = rdNmNorm(name).replace(/[^ء-ي\s]/g, ' ').split(/\s+/).filter(Boolean); if (!w.length) return '';
  const F = /^(الست|ست|الحاجه|مدام|ماما|طنط|خالتي|عمتي|الاستاذه|الدكتوره|دكتوره|المدرسه|الانسه|انسه|مس|ام|جدتي|تيتا|نينه|الممرضه)$/, M = /^(ابو|عم|الحاج|حاج|الاستاذ|استاذ|الدكتور|دكتور|المدرس|بابا|عمو|خالو|جدي|الباشا|باشا|المعلم|معلم|سيد|السيد|الشيخ|شيخ|الظابط|الضابط|ظابط|ضابط)$/;
  const t0 = w[0]; if (F.test(t0)) return 'f'; if (M.test(t0)) return 'm';
  for (const x of w) { if (RD_NM_FS.has(x)) return 'f'; if (RD_NM_MS.has(x)) return 'm'; }
  return '';
}
const rdGen = (pid) => { try { const a = (rdPers(pid) || {}).a || ''; return /female/.test(a) ? 'f' : /male/.test(a) ? 'm' : ''; } catch (e) { return ''; } };
// مين بيكلم مين: المخاطَب = الشخصية التانية في الحوار (بالدور المتبادل)؛ نغيّر صيغة المخاطَب بس لما نكون متأكدين
function rdGenderPass(items) {
  const spk = new Set(items.filter((x) => x.type === 'dialogue').map((x) => x.speaker)), two = spk.size === 2;
  items.forEach((it, i) => {
    if (it.type !== 'dialogue') return;
    const near = (j) => items[j] && items[j].type === 'dialogue' && items[j].speaker !== it.speaker;
    let aj = -1;
    for (let j = i - 1; j >= Math.max(0, i - (two ? 3 : 1)); j--) { if (near(j)) { aj = j; break; } if (items[j].type === 'dialogue') break; }
    if (aj < 0) for (let j = i + 1; j <= Math.min(items.length - 1, i + (two ? 3 : 1)); j++) { if (near(j)) { aj = j; break; } if (items[j].type === 'dialogue') break; }
    let ag = aj >= 0 ? rdGen(items[aj].pid) : '';
    const sg = rdGen(it.pid);
    { // النداء بيحسم: «يا إلياس» = مخاطَب راجل، «يا سلمى/يا بنتي» = مخاطَبة، حتى لو صوت الشخصية التانية اتحدد غلط
      const vm = /(?:^|[\s،,.!؟?«"“-])يا\s+([\u0621-\u064A]+)(?:\s+([\u0621-\u064A]+))?/.exec(stripDiacritics(it.text || ''));
      if (vm) {
        const w1 = vm[1], VM = /^(ابني|بني|حبيبي|عمي|عم|ولد|رجل|بيه|باشا|اخي|اخويا|صاحبي|معلم|استاذ|دكتور|حاج|حاجي|عمو|خالو|ابويا|بابا|جدي)$/, VF = /^(بنتي|حبيبتي|بنت|ست|هانم|اختي|اختى|اختا|صاحبتي|مدام|ماما|عمتي|خالتي|طنط|ماما|جدتي|ام|حاجه|حاجة|دكتوره|استاذه|مس)$/;
        const vg = VM.test(w1) ? 'm' : VF.test(w1) ? 'f' : rdNameGender(w1 + (vm[2] ? ' ' + vm[2] : '')) || rdNameGender(w1);
        if (vg) ag = vg;
      }
    }
    it.addr = ag;
    if (ag || sg) { it.text = rdFixGender(it.text, ag, sg); if (it.phoneticText) it.phoneticText = rdFixGender(it.phoneticText, ag, sg); }
  });
}
async function rdNarrator(env, nid, cf) {
  let g = ''; try { g = ((await getSetting(env, 'rdnar_' + (nid || 'x'))) || {}).g || ''; } catch (e) {}
  return g === 'f' ? 'salma' : g === 'm' ? 'kareem' : cf.narrator;
}
async function radadPart(env, text, conf, ctx, nid) {
  let cf = conf.rd || RD_DEF; cf = { ...cf, narrator: await rdNarrator(env, nid, cf) }; conf = { ...conf, rd: cf }; RD_CF = cf;
  try { RD_LEARN = (await getSetting(env, 'rd_learned')) || {}; } catch (e) { RD_LEARN = {}; }
  const regKey = 'rdreg_' + (nid || 'x'); let reg = {}; try { reg = (await getSetting(env, regKey)) || {}; } catch (e) {}
  let dirty = false, items = [];
  const build = (segs) => {
  items = [];
  for (const s of segs) {
    const clean = String(s.text || '').replace(/^[-–—•]\s*/, '').trim(); if (!clean) continue;
    const sp = String(s.speaker || 'الراوي').trim() || 'الراوي', dlg = s.type !== 'narration' && sp !== 'الراوي';
    let pid = sp === 'الراوي' ? rdPers(cf.narrator).id : reg[sp];
    if (sp !== 'الراوي') { // اسم معروف الجنس: نصحّح الصوت المحفوظ/المتخمَّن لو جنسه غلط
      const ng = rdNameGender(sp), cg = pid ? rdGen(pid) : '';
      if (ng && cg && ng !== cg) { const a0 = (rdPers(pid) || {}).a || ''; pid = ng === 'f' ? (/young/.test(a0) ? 'layla' : 'noor') : (/young/.test(a0) ? 'youssef' : 'tarek'); reg[sp] = pid; dirty = true; }
      else if (ng && !pid && !s.vid && !cf.archMap[s.speakerArchetype]) { const a1 = String(s.speakerArchetype || ''), ay = /young/.test(a1); pid = ng === 'f' ? (ay ? 'layla' : 'noor') : (ay ? 'youssef' : 'tarek'); reg[sp] = pid; dirty = true; }
      else if (ng && !pid && !s.vid && cf.archMap[s.speakerArchetype] && rdGen(cf.archMap[s.speakerArchetype]) && rdGen(cf.archMap[s.speakerArchetype]) !== ng) { const ay2 = /young/.test(String(s.speakerArchetype || '')); pid = ng === 'f' ? (ay2 ? 'layla' : 'noor') : (ay2 ? 'youssef' : 'tarek'); reg[sp] = pid; dirty = true; }
    }
    if (!pid) { const p = s.vid ? rdPers(s.vid) : sp === 'الراوي' ? rdPers(cf.narrator) : (cf.archMap[s.speakerArchetype] ? rdPers(cf.archMap[s.speakerArchetype]) : (rdByArch(s.speakerArchetype) || rdPers('tarek'))); pid = p.id; reg[sp] = pid; dirty = true; }
    items.push({ type: dlg ? 'dialogue' : 'narration', speaker: sp, text: clean, phoneticText: String(s.phoneticText || '').replace(/^[-–—•]\s*/, '').trim(), emotionId: RD_E[s.emotionId] ? s.emotionId : 'natural_dialogue', intensity: RD_I[s.intensity] ? s.intensity : 'strong', actingDirection: s.actingDirection || 'أداء تمثيلي مصري صادق ومعبر', pid });
  }
  };
  // حماية من إسقاط الكلام: لو التحليل وقّع أكتر من 15% من النص نستخدم المحلل المحلي بتاع الأداة (ما نسيبش فقرات ضايعة)
  const nz = (s) => String(s).replace(/[^ء-ي0-9]/g, '').length, src = nz(text), cover = () => items.reduce((a, x) => a + nz(x.text), 0);
  let segs = cf.analysis === 'local' ? null : await rdAnalyze(env, text, conf);
  if (segs) build(segs);
  // حماية السرد (وضع الفصحى): لو النموذج غيّر في نص السرد (عامية/كلمات تانية) نرجع للمحلل المحلي اللي بيسيب النص زي ما هو
  const nL = (t) => String(t).replace(/[أإآٱ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه').replace(/[^ء-ي0-9]/g, ''), srcL = nL(text);
  const narrAltered = () => { if (cf.mode !== 'B') return false; let bad = 0, tot = 0; for (const x of items) { if (x.type !== 'narration') continue; const l = nz(x.text); if (l < 14) continue; tot++; if (!srcL.includes(nL(x.text))) bad++; } return bad > 0 && bad >= Math.max(1, tot * 0.06); };
  if (!segs || !items.length || (src > 80 && cover() < src * 0.85) || narrAltered()) build(rdLocal(text, conf));
  if (!items.length) build([{ text, speaker: 'الراوي', type: 'narration' }]);
  if (!items.length) { const e = new Error('empty_text'); e.code = 400; throw e; }
  if (dirty) { try { await setSetting(env, regKey, reg); } catch (e) {} }
  try { rdGenderPass(items); } catch (e) {}
  if (cf.skipNarration) { const keep = items.filter((x) => x.type !== 'narration'); if (keep.length) { items.length = 0; items.push(...keep); } }
  let jobs;
  if (conf.engine === 'single') jobs = items.map((x) => [x]);
  else { jobs = []; let cur = [], set = new Set(); for (const s of items) { const nx = new Set(set); nx.add(s.speaker); if (cur.length >= cf.batch || nx.size > 2) { jobs.push(cur); cur = [s]; set = new Set([s.speaker]); } else { cur.push(s); set = nx; } } if (cur.length) jobs.push(cur); }
  const pcms = new Array(jobs.length); let nxt = 0;
  await Promise.all(Array.from({ length: Math.min(2, jobs.length) }, async () => { while (nxt < jobs.length) { const i = nxt++; pcms[i] = await rdMega(env, jobs[i], conf); } }));
  const gap = new Int16Array(Math.round(24 * cf.pauseMs)); let n = 0; pcms.forEach((p, i) => { n += p.length + (i ? gap.length : 0); });
  const all = new Int16Array(n); let o = 0; pcms.forEach((p, i) => { if (i) o += gap.length; all.set(applyEdgeFades(p), o); o += p.length; });
  return { wav: pcmToWav(new Uint8Array(all.buffer), 24000), chars: items.reduce((a, x) => a + x.text.length, 0), calls: jobs.length + 1 };
}
const xmlEsc = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const speakPart = (env, prov, text, conf, ctx, nid) => radadPart(gemEnv(env, prov), text, conf, ctx, nid);
const KEEP_NAMES = ['بنت القلب', 'الترياق الفاسد', 'كن ملاكي', 'عمو الظابط', 'مليونير السنة'];
const keepNorm = (x) => String(x || '').replace(/[\u064B-\u0652\u0640]/g, '').replace(/[أإآ]/g, 'ا').replace(/ة/g, 'ه').replace(/ى/g, 'ي').replace(/ض/g, 'ظ').replace(/\s+/g, ' ').trim();
// الروايات المحمية من المسح: أول مرة بتتعلّم بالاسم من الروايات اللي فيها صوت، وبعد كده بتتحفظ
async function ttsKeep(env, novels) {
  const raw = await getSetting(env, 'ttsKeep'); let set;
  if (raw && Array.isArray(raw.list)) set = new Set(raw.list.map(String));
  else { if (!novels || !novels.length) novels = (await env.DB.prepare("SELECT nid, MAX(ntitle) AS ntitle FROM tts_ch GROUP BY nid").all()).results || []; set = new Set(); const names = KEEP_NAMES.map(keepNorm); for (const n of novels) { const t = keepNorm(n.ntitle); if (names.some((k) => t.includes(k))) set.add(n.nid); } await setSetting(env, 'ttsKeep', { list: [...set] }); }
  set.missing = KEEP_NAMES.filter((k) => !(novels || []).some((n) => set.has(n.nid) && keepNorm(n.ntitle).includes(keepNorm(k))));
  return set;
}
const hex256 = async (buf) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', buf))].map((x) => x.toString(16).padStart(2, '0')).join('');
const MP3_KBPS = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
// فحص ملف MP3 صارم: ID3v2 اختياري في الأول، بعدها إطارات MPEG-2 Layer III بـ24kHz mono بنفس الـbitrate (CBR) متتالية بلا فجوات لحد آخر الملف بالظبط (ولا ID3v1 ولا بايتات زيادة)
function parseMp3(u8) {
  const n = u8.length; let pos = 0;
  if (n >= 10 && u8[0] === 0x49 && u8[1] === 0x44 && u8[2] === 0x33) { if ((u8[6] | u8[7] | u8[8] | u8[9]) & 0x80) return { err: 'ID3 غلط' }; pos = 10 + ((u8[6] << 21) | (u8[7] << 14) | (u8[8] << 7) | u8[9]) + ((u8[5] & 0x10) ? 10 : 0); }
  let kbps = 0, frames = 0, xing = false;
  while (pos < n) {
    if (pos + 4 > n) return { err: 'ذيل غير مكتمل' };
    const b0 = u8[pos], b1 = u8[pos + 1], b2 = u8[pos + 2], b3 = u8[pos + 3];
    if (b0 !== 0xff || (b1 & 0xfe) !== 0xf2) return { err: 'ترويسة إطار غير MPEG-2 Layer III عند ' + pos };
    const bi = b2 >> 4, si = (b2 >> 2) & 3, pad = (b2 >> 1) & 1, mono = (b3 >> 6) === 3;
    if (bi < 1 || bi > 14 || si !== 1 || !mono) return { err: 'إطار غير 24kHz mono عند ' + pos };
    if (!kbps) kbps = MP3_KBPS[bi]; else if (MP3_KBPS[bi] !== kbps) return { err: 'bitrate غير ثابت عند ' + pos };
    const len = 3 * kbps + pad; if (pos + len > n) return { err: 'إطار مقطوع عند ' + pos };
    if (frames === 0 && pos + 17 <= n) { const t = String.fromCharCode(u8[pos + 13], u8[pos + 14], u8[pos + 15], u8[pos + 16]); if (t === 'Xing' || t === 'Info') xing = true; }
    frames++; pos += len;
  }
  const audio = frames - (xing ? 1 : 0);
  if (!(audio > 0)) return { err: 'مفيش إطارات صوت' };
  return { kbps, frames, audio, secs: audio * 576 / 24000 };
}
// تحقق جيل مجهّز MP3 قبل النشر: كل جزء (وجود + حجم + sha في metadata + اتساق الحجم مع المدة المعلنة CBR) + عيّنة أول/وسط/آخر (sha من البايتات + إطارات + مدة) + مجموع المدد مقابل مدة الجيل
async function mp3VerifyStage(env, st) {
  const shas = new Array(st.nparts); let meta; try { meta = JSON.parse(st.mp3_meta || ''); } catch (e) { meta = null; }
  if (!meta || !Number.isInteger(meta.kbps) || meta.kbps < 32 || meta.kbps > 128 || !Array.isArray(meta.durs) || meta.durs.length !== st.nparts || meta.durs.some((d) => !(+d > 0) || !isFinite(+d))) return { shas, err: 'بيانات MP3 للجيل ناقصة أو غير صالحة', bad: -3 };
  const durs = meta.durs.map(Number), sum = durs.reduce((a, z) => a + z, 0);
  if (Math.abs(sum - st.secs) > st.nparts * 0.5 + 1) return { shas, err: 'مدة الجيل المعلنة لا تطابق مدد أجزاء MP3', bad: -2 };
  let bad = -1; const sizes = new Array(st.nparts).fill(0);
  for (let i0 = 0; i0 < st.nparts && bad < 0; i0 += 10) {
    await Promise.all(Array.from({ length: Math.min(10, st.nparts - i0) }, async (_, k) => {
      const i = i0 + k, h = await env.TTS_BUCKET.head('c/' + st.ch_id + '/' + i + '.mp3');
      const m = h && h.customMetadata && /^[0-9a-f]{64}$/.test(h.customMetadata.sha256 || '') ? h.customMetadata.sha256 : '';
      if (!h || !h.size || !m || Math.abs(h.size * 8 / (meta.kbps * 1000) - durs[i]) > 0.25) { if (bad < 0) bad = i; return; }
      shas[i] = m; sizes[i] = h.size;
    }));
  }
  if (bad >= 0) return { shas, err: 'جزء MP3 ناقص أو حجمه لا يطابق مدته: ' + bad, bad };
  for (const i of new Set([0, Math.floor((st.nparts - 1) / 2), st.nparts - 1])) {
    const o = await env.TTS_BUCKET.get('c/' + st.ch_id + '/' + i + '.mp3'); if (!o) return { shas, err: 'جزء MP3 ناقص: ' + i, bad: i };
    const buf = await o.arrayBuffer(); if (buf.byteLength !== sizes[i]) return { shas, err: 'حجم جزء MP3 تغيّر: ' + i, bad: i };
    const p = parseMp3(new Uint8Array(buf));
    if (p.err || p.kbps !== meta.kbps || Math.abs(p.secs - durs[i]) > 0.1) return { shas, err: 'جزء MP3 ' + i + ' غير صالح: ' + (p.err || 'bitrate/مدة لا تطابق'), bad: i };
    if ((await hex256(buf)) !== shas[i]) return { shas, err: 'بصمة جزء MP3 لا تطابق بايتاته: ' + i, bad: i };
  }
  return { shas, err: '', bad: -1 };
}
/* ---------- تسجيل الدخول بجوجل / فيسبوك: بنتحقق من التوكن عند الشركة نفسها ---------- */
const socConf = async (env) => { const c = await getSetting(env, 'social'); return { google: str(c.google, 200).trim(), facebook: str(c.facebook, 40).trim() }; };
async function socVerify(env, provider, token, nonce) { // بيرجّع { sub, email, verified, name } أو null
  const jf = async (u) => { try { const r = await fetch(u, { headers: { Accept: 'application/json' } }); if (!r.ok) return null; return await r.json(); } catch (e) { return null; } };
  const cf = await socConf(env);
  if (provider === 'google') {
    if (!cf.google) return null;
    const t = await jf('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(token));
    if (!t || t.aud !== cf.google || !/^(https:\/\/)?accounts\.google\.com$/.test(String(t.iss || '')) || !(Number(t.exp) * 1000 > Date.now()) || !t.sub) return null;
    if (nonce && t.nonce && t.nonce !== nonce) return null;
    return { sub: String(t.sub), email: String(t.email || '').toLowerCase(), verified: t.email_verified === 'true' || t.email_verified === true, name: String(t.name || '') };
  }
  if (provider === 'facebook') {
    if (!cf.facebook) return null;
    const a = await jf('https://graph.facebook.com/app?access_token=' + encodeURIComponent(token));
    if (!a || String(a.id) !== cf.facebook) return null; // التوكن لازم يكون طالع لتطبيقنا إحنا
    const me = await jf('https://graph.facebook.com/me?fields=id,name,email&access_token=' + encodeURIComponent(token));
    if (!me || !me.id) return null;
    return { sub: String(me.id), email: String(me.email || '').toLowerCase(), verified: false, name: String(me.name || '') };
  }
  return null;
}
const audioResp = (obj, hit) => new Response(obj.body || obj, { status: 200, headers: { ...CORS, 'Content-Type': 'audio/wav', 'Cache-Control': 'private, no-store', 'X-Cache': hit ? 'HIT' : 'MISS' } });
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
const stKey = (prov) => (prov === 'gemini' ? 'tts_state' : prov[0] === 'r' ? 'tts_state_r' + prov.slice(2) : 'tts_state_g' + prov.slice(6));
const PNAME = { gemini: 'جوجل 1', gemini2: 'جوجل 2', gemini3: 'جوجل 3', gemini4: 'جوجل 4', gemini5: 'جوجل 5', gemini6: 'جوجل 6', rd1: 'الرداد 1', rd2: 'الرداد 2', rd3: 'الرداد 3', rd4: 'الرداد 4', rd5: 'الرداد 5', rd6: 'الرداد 6' };
async function ttsAlertAdmins(env, title, text, prov = 'gemini') {
  const key = stKey(prov), st = await getSetting(env, key), now = Date.now();
  if (st.alertAt && now - st.alertAt < 6 * 3600000) return;
  await setSetting(env, key, { ...st, alertAt: now });
  try {
    const { results } = await env.DB.prepare("SELECT id FROM users WHERE role='admin'").all();
    for (const a of results) {
      await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(a.id, 'payment', 'pay', 'RadPad', title, text, now).run();
      if (env.FCM_SA) { try { await sendPush(env, title, text, '', 'u_' + a.id, 'pay'); } catch (e) {} }
    }
  } catch (e) {}
}
// الصوت القديم بيفضل زي ما هو (مفيش مسح)؛ الأصوات المتعددة بتشتغل على اللي يتحوّل من دلوقتي
const TTS_VER = 3;
async function ttsMigrate(env) {
  const v = await getSetting(env, 'tts_ver'); if (v.v >= TTS_VER) return true;
  await setSetting(env, 'tts_ver', { v: TTS_VER });
  const mk = await getSetting(env, 'tts_mk'); if (!mk.v) { await env.DB.prepare("UPDATE tts_ch SET sig='' WHERE status!='done'").run(); await setSetting(env, 'tts_mk', { v: 1 }); } // الفصول اللي لسه ما اتحوّلتش تتبعت تاني بعلامات الحوار
  return true;
}
async function ttsWipeNovel(env, nid) { // مسح الصوت المتخزّن لرواية
  const { results } = await env.DB.prepare('SELECT id,nparts FROM tts_ch WHERE nid=?').bind(nid).all();
  if (env.TTS_BUCKET) for (const c of results) { const keys = []; for (let i = 0; i < c.nparts; i++) keys.push('c/' + c.id + '/' + i + '.wav', 'c/' + c.id + '/' + i + '.mp3'); for (let i = 0; i < keys.length; i += 100) await env.TTS_BUCKET.delete(keys.slice(i, i + 100)); }
}
// خطوة تحويل واحدة لمزوّد واحد: بتاخد أول فصل في طابوره (بالترتيب) وتولّد منه كام جزء، بشرط الحد اليومي. بتتنادى كل دقيقة من Cron.
/* توزيع تلقائي: أي حساب طابوره فضي (وجاهز) بياخد رواية أو اتنين لسه ما اتبدأتش من طوابير الحسابات التانية */
async function ttsRebalance(env, per = 2) {
  const conf = await getTtsConf(env); if (conf.rebalance === false) return [];
  const { results } = await env.DB.prepare("SELECT nid,MAX(prov) AS prov,MIN(ord) AS o,COUNT(*) AS n,SUM(status='done') AS d,SUM(status='running') AS r,SUM(status IN ('queued','running')) AS pend FROM tts_ch GROUP BY nid").all();
  if (!results.length) return [];
  const now = Date.now(), pend = {}, paused = {};
  for (const p of PROVS) { pend[p] = 0; const st = await getSetting(env, stKey(p)); paused[p] = (st.pausedUntil || 0) > now || !!st.manualOff; }
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
  if (st.manualOff) return { ok: true, idle: 'paused', prov };
  if (st.pausedUntil && st.pausedUntil > now && !opts.force) return { ok: true, idle: 'paused', prov };
  const u = await env.DB.prepare('SELECT secs FROM tts_use WHERE day=? AND prov=?').bind(dayKey(), prov).first();
  let used = u ? u.secs : 0; const cap = provCapE(env, conf, prov) * 60, par = provPar(conf, prov);
  if (used >= cap) return { ok: true, idle: 'daily_limit', prov };
  try { await env.DB.prepare("UPDATE tts_ch SET status='queued',attempts=0,retry_at=0 WHERE status='failed' AND prov=? AND updated<?").bind(prov, now - 900000).run(); } catch (e) {} // الفصل الفاشل بيتعاد تلقائي بعد ربع ساعة (مفيش فصل بيتسقط)
  const tok = crypto.randomUUID();
  const r = await env.DB.prepare("UPDATE tts_ch SET status='running',owner=?2,lock_until=?1+240000,attempts=attempts WHERE id=(SELECT id FROM tts_ch WHERE prov=?3 AND status IN ('queued','running') AND lock_until<=?1 AND retry_at<=?1 ORDER BY ord ASC,nid ASC,idx ASC LIMIT 1)").bind(now, tok, prov).run();
  if (r && r.meta && typeof r.meta.changes === 'number' && !r.meta.changes) return { ok: true, idle: 'empty', prov };
  const ch = await env.DB.prepare("SELECT * FROM tts_ch WHERE owner=? AND status='running'").bind(tok).first();
  if (!ch) return { ok: true, idle: 'empty', prov };
  if (ch.fmt === 'mp3') { try { await env.DB.prepare("UPDATE tts_ch SET fmt='wav' WHERE id=?").bind(ch.id).run(); const mk = []; for (let i = 0; i < ch.nparts; i++) mk.push('c/' + ch.id + '/' + i + '.mp3'); for (let i = 0; i < mk.length; i += 100) await env.TTS_BUCKET.delete(mk.slice(i, i + 100)); } catch (e) {} }
  let parts = JSON.parse(ch.parts || '[]');
  if (ch.done === 0 && parts.length && Math.max(...parts.map((x) => x[1] - x[0])) > rdPartMx(conf) * 1.25) { const np = splitParts(ch.text, rdPartMx(conf)); if (np.length) { parts = np; await env.DB.prepare('UPDATE tts_ch SET parts=?,nparts=? WHERE id=?').bind(JSON.stringify(np), np.length, ch.id).run(); } }
  let done = ch.done, secsTot = ch.secs, made = 0, err = '', hardFail = false, deadKey = false, limMsg = '';
  let learnedN = 0;
  if (ch.done === 0 && (conf.rd || RD_DEF).learn !== false) { try { learnedN = await rdLearn(gemEnv(env, prov), ch.text, conf); } catch (e) {} } // تعلّم كلمات الفصل قبل التحويل (مرة واحدة لكل فصل)
  const t0 = Date.now();
  const MADE_MX = 3;
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
        await ttsBump(env, prov, { reqs: x.value.calls || 1, chars: x.value.chars, secs: x.value.secs, cost: ttsCost(x.value.chars, x.value.secs, conf) });
        if (prefix) done++;
        learnedN += x.value.learned || 0;
      } else {
        prefix = false; const e = x.reason || {};
        if (e.code === 429) { limited = true; limMsg = e.detail || limMsg; }
        else if (e.code === 401 || /^gemini_(401|403)$/.test(String(e.message))) { deadKey = true; err = 'key_dead'; } // مفتاح مرفوض / مشروع جوجل اتوقّف
        else { err = String(e.message || 'error').slice(0, 100); hardFail = true; }
      }
    }
    if (limited) {
      const cs = await getSetting(env, key), strikes = (cs.strikeAt && Date.now() - cs.strikeAt < 3600000 ? (cs.strikes || 0) : 0) + 1, daily = /PerDay|per day|daily/i.test(limMsg), wait = 15; // لو جوجل رفض، نستنى ربع ساعة ونبعت الفصل تاني
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
  if (status === 'done') { try { await ttsDoneNotify(env, ch); } catch (e) {} }
  if (learnedN) { try { const ls = await getSetting(env, 'rd_learn_stat'); await setSetting(env, 'rd_learn_stat', { total: (ls.total || 0) + learnedN, last: learnedN, at: Date.now(), ch: ch.nid + '#' + ch.idx }); } catch (e) {} }
  return { ok: true, id: ch.id, prov, done, total: parts.length, status, made, limit: limMsg };
}

/* ---------- نشر الكاتب: إشعارات القبول + تحويل تلقائي للصوت + إشعار الفصل المتحوّل ---------- */
const PUB_DEF = { notify: true, autoq: true, followers: true };
const normPub = (x) => { x = x && typeof x === 'object' ? x : {}; return { notify: x.notify !== false, autoq: x.autoq !== false, followers: x.followers !== false }; };
const chapPlain = (title, content) => {
  const dec = (t) => String(t || '').replace(/<\s*br\s*\/?>|<\/(p|div|h\d|li)>/gi, '\n').replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  const out = []; for (const l of [String(title || ''), ...dec(content).split('\n')]) { const t = l.replace(/[ \t ]+/g, ' ').trim(); if (t && /[؀-ۿa-zA-Z0-9]/.test(t)) out.push(t); }
  return out.join('\n');
};
async function pubPickProv(env, conf, nid) {
  const sib = await env.DB.prepare('SELECT MAX(prov) AS prov FROM tts_ch WHERE nid=?').bind(nid).first();
  if (conf.novelProv[nid] || (sib && sib.prov)) return conf.novelProv[nid] || sib.prov;
  const now = Date.now(); let best = null;
  for (const p of PROVS.filter((x) => /^rd\d$/.test(x))) {
    if (!provReady(env, conf, p) || provCap(conf, p) <= 0) continue;
    const st = await getSetting(env, stKey(p)); if ((st.pausedUntil || 0) > now || st.manualOff) continue;
    const n = (await env.DB.prepare("SELECT COUNT(*) AS n FROM tts_ch WHERE prov=? AND status IN ('queued','running')").bind(p).first()).n;
    if (!best || n < best.n) best = { p, n };
  }
  return best ? best.p : conf.defProv;
}
async function pubAutoQueue(env, r, nid) { // بيحط فصول الرواية المنشورة في طابور الرداد (الحساب الأفضى)
  if (!env.TTS_BUCKET) return 0;
  const conf = await getTtsConf(env), now = Date.now(), ex = extraOf(r.l_extra), rel = ex.rel || [];
  const { results } = await env.DB.prepare("SELECT idx,title,content FROM chapters WHERE novel_id=? AND ver='l' ORDER BY idx").bind(r.id).all();
  const have = new Set((await env.DB.prepare('SELECT idx FROM tts_ch WHERE nid=?').bind(nid).all()).results.map((x) => x.idx));
  const prov = await pubPickProv(env, conf, nid), mx = (await env.DB.prepare('SELECT COALESCE(MAX(ord),0) AS m FROM tts_ch').first()).m;
  const sts = []; let n = 0;
  for (const c of results) {
    if (have.has(c.idx) || (rel[c.idx] && rel[c.idx] > now)) continue;
    const text = chapPlain(c.title, c.content).slice(0, 150000); if (!text.includes('\n') && text.length < 120) continue;
    const parts = splitParts(text, rdPartMx(conf)); if (!parts.length) continue;
    sts.push(env.DB.prepare('INSERT INTO tts_ch (nid,idx,ntitle,ctitle,ord,sig,text,parts,nparts,created,updated,prov) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').bind(nid, c.idx, String(r.l_title || '').slice(0, 120), String(c.title || '').slice(0, 120), mx + 1, 'pub', text, JSON.stringify(parts), parts.length, now, now, prov)); n++;
  }
  for (let i = 0; i < sts.length; i += 40) await env.DB.batch(sts.slice(i, i + 40));
  if (n && !conf.novelProv[nid]) { try { const raw = await getSetting(env, 'tts'); await setSetting(env, 'tts', { ...raw, novelProv: { ...(raw.novelProv || {}), [nid]: prov } }); } catch (e) {} }
  return n;
}
async function pubAfterApprove(env, r, id, kind, newCnt, oldCnt) { // بعد موافقة الأدمن على رواية/فصل كاتب
  const au = await env.DB.prepare('SELECT id,name,role FROM users WHERE id=?').bind(r.user_id).first();
  if (!au || au.role === 'admin') return;
  const cf = normPub(await getSetting(env, 'pubflow')), nid = extraOf(r.l_extra).siteId || extraOf(r.d_extra).siteId || 'u' + id;
  if (cf.notify) {
    const last = kind === 'chapter' ? await env.DB.prepare("SELECT title FROM chapters WHERE novel_id=? AND ver='l' ORDER BY idx DESC LIMIT 1").bind(id).first() : null;
    const ttl = kind === 'novel' ? 'تم قبول روايتك 🎉' : kind === 'chapter' ? 'تم قبول ونشر فصلك الجديد ✅' : 'تم قبول تعديلاتك ✅';
    const txt = kind === 'novel' ? '«' + r.d_title + '» اتنشرت على التطبيق، وسيتم توليد الصوت قريبًا بإذن الله.' : kind === 'chapter' ? '«' + r.d_title + '»' + (last ? ' — ' + last.title : '') + ' اتنشر، وسيتم توليد صوته قريبًا بإذن الله.' : '«' + r.d_title + '» اتحدّثت على التطبيق.';
    await notifyUser(env, au.id, ttl, txt, 'pub' + id);
  }
  if (cf.autoq) await pubAutoQueue(env, r, nid);
}
async function ttsDoneNotify(env, ch, auGiven) { // فصل اتحوّل لصوت: إشعار للكاتب + للمتابعين
  const cf = normPub(await getSetting(env, 'pubflow')); if (!cf.notify) return 'off';
  let au = auGiven || null;
  if (!au && /^u\d+$/.test(ch.nid)) au = await env.DB.prepare('SELECT u.id,u.name,u.role FROM novels n JOIN users u ON u.id=n.user_id WHERE n.id=?').bind(+ch.nid.slice(1)).first();
  if (!au) { const { results } = await env.DB.prepare('SELECT n.l_extra,n.d_extra,u.id,u.name,u.role FROM novels n JOIN users u ON u.id=n.user_id WHERE n.l_extra LIKE ? OR n.d_extra LIKE ?').bind('%' + ch.nid + '%', '%' + ch.nid + '%').all(); au = results.find((x) => extraOf(x.l_extra).siteId === ch.nid || extraOf(x.d_extra).siteId === ch.nid) || null; }
  const cn = ch.ctitle || 'فصل ' + (ch.idx + 1), nt = ch.ntitle || 'روايتك';
  if (!au) { await notifyAdmins(env, '', 'الفصل اتحوّل لصوت 🎧', '«' + nt + '» — ' + cn + ' بقى ينفع تسمعه دلوقتي.', 'tts' + ch.nid + '#' + ch.idx); return 'admins'; }
  const ref = 'tts' + ch.nid + '#' + ch.idx;
  if (await env.DB.prepare('SELECT 1 AS x FROM notes WHERE uid=? AND novel_ref=?').bind(au.id, ref).first()) return 'dup';
  await notifyUser(env, au.id, 'الفصل اتحوّل لصوت 🎧', '«' + nt + '» — ' + cn + ' بقى ينفع تسمعه دلوقتي.', ref);
  if (cf.followers && env.FCM_SA) await sendPush(env, '🎧 فصل جديد بالصوت من ' + au.name, '«' + nt + '» — ' + cn + ' بقى متاح للاستماع.', '', 'a_' + au.id, ch.nid + '#' + ch.idx);
  return 'sent';
}
async function ttsStats(env) {
  const conf = await getTtsConf(env), d = dayKey(), mo = d.slice(0, 7), pr = ttsPrices(conf);
  const sum = async (prov, where, ...a) => env.DB.prepare('SELECT COALESCE(SUM(reqs),0) AS reqs,COALESCE(SUM(chars),0) AS chars,COALESCE(SUM(secs),0) AS secs,COALESCE(SUM(cost),0) AS cost,COALESCE(SUM(fails),0) AS fails,COALESCE(SUM(limited),0) AS limited FROM tts_use WHERE prov=? AND ' + where).bind(prov, ...a).first();
  const { results: novels } = await env.DB.prepare("SELECT nid,MAX(ntitle) AS title,MIN(ord) AS ord,MAX(prov) AS prov,COUNT(*) AS n,SUM(status='done') AS d,SUM(CASE WHEN status='running' AND lock_until>"+Date.now()+" THEN 1 ELSE 0 END) AS run,SUM(LENGTH(text)) AS chars,SUM(CASE WHEN status='done' THEN 0 ELSE LENGTH(text)*(1.0-done*1.0/(CASE WHEN nparts<1 THEN 1 ELSE nparts END)) END) AS rem FROM tts_ch WHERE status!='off' GROUP BY nid ORDER BY MIN(ord),nid LIMIT 120").all();
  const q = await env.DB.prepare('SELECT prov,status,COUNT(*) AS n FROM tts_ch GROUP BY prov,status').all();
  const out = { conf, hasBucket: !!env.TTS_BUCKET, has: { ...Object.fromEntries(PROVS.filter(isGoogle).map((p) => [p, !!gemKey(env, p)])) }, prov: {}, nkeys: Object.fromEntries(PROVS.filter(isGoogle).map((p) => [p, gKeyList({ GEMINI_API_KEY: gemKey(env, p) }).length])), keys: Object.fromEntries(Object.entries(await savedKeys(env)).map(([p, v]) => [p, v ? 'app' : ''])), prices: pr,
    chapters: { queued: 0, running: 0, done: 0, failed: 0 }, novels: novels.map((r) => ({ nid: r.nid, title: r.title, ord: r.ord, prov: r.prov, n: r.n, d: r.d || 0, run: r.run || 0, rem: Math.round(r.rem || 0) })) };
  q.results.forEach((r) => (out.chapters[r.status] = (out.chapters[r.status] || 0) + r.n));
  out.hasKey = out.has.gemini;
  for (const prov of PROVS) {
    const st = await getSetting(env, stKey(prov)), today = await sum(prov, 'day=?', d), month = await sum(prov, 'day LIKE ?', mo + '%');
    const ch = { queued: 0, running: 0, done: 0, failed: 0 }; q.results.filter((r) => r.prov === prov).forEach((r) => (ch[r.status] = r.n));
    const remChars = Math.round(novels.filter((r) => r.prov === prov).reduce((a, r) => a + (r.rem || 0), 0)), remSecs = remChars / CPS;
    const cap = provCapE(env, conf, prov) * 60;
    const o = { last: await getSetting(env, 'tts_last_' + prov), today, month, chapters: ch, manualOff: !!st.manualOff, pausedUntil: st.pausedUntil || 0, limMsg: st.limMsg || '', limDaily: !!st.limDaily, exhaustedAt: st.exhaustedAt || 0, dailyMin: cap / 60, usedTodayPct: cap ? Math.min(999, Math.round(today.secs / cap * 100)) : 100 };
    {
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
async function streakConf(env) { const c = await getSetting(env, 'streak'); const n = (v, d, a, z) => { v = Number(v); return Number.isFinite(v) ? Math.max(a, Math.min(z, v)) : d; }; return { on: c.on !== false, days: Math.round(n(c.days, 7, 2, 60)), pts: n(c.pts, 2, 0, 1000) }; }
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
  if (awarded > 0) await env.DB.prepare('UPDATE users SET wallet=ROUND(wallet+?,2) WHERE id=?').bind(awarded, uid).run();
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
    if (env.FCM_SA) { const c = await env.DB.prepare("SELECT title FROM chapters WHERE novel_id=? AND ver='l' AND idx=?").bind(r.id, hit).first(); await sendPush(env, 'فصل جديد من ' + r.name, '«' + r.l_title + '»' + (c ? ' — ' + c.title : ''), '', r.role === 'admin' ? 'all' : 'a_' + r.user_id, 'u' + r.id + '#' + hit); }
  }
}
async function alertsTick(env) { // من الـ Cron: لما يحين ميعاد فصل مجدول يتبعت إشعار لكل اللي ضغطوا «نبهني»
  const now = Date.now(), { results } = await env.DB.prepare('SELECT uid,nid,ch,title FROM ch_alerts WHERE sent=0 AND rel>0 AND rel<=? LIMIT 300').bind(now).all();
  for (const a of results) {
    const up = await env.DB.prepare('UPDATE ch_alerts SET sent=1 WHERE uid=? AND nid=? AND ch=? AND sent=0').bind(a.uid, a.nid, a.ch).run();
    if (up && up.meta && up.meta.changes) await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(a.uid, 'release', a.nid + '#' + a.ch, '', a.title || 'فصل جديد', 'الفصل اللي كنت مستنيه نزل دلوقتي 🎉 اقرأه الآن', now).run();
    if (up && up.meta && up.meta.changes && env.FCM_SA) { try { await sendPush(env, a.title || 'فصل جديد', 'الفصل اللي كنت مستنيه نزل دلوقتي 🎉 اقرأه الآن', '', 'u_' + a.uid, a.nid + '#' + a.ch); } catch (e) {} }
  }
  await env.DB.prepare('DELETE FROM ch_alerts WHERE sent=1 AND rel<?').bind(now - 30 * 86400000).run();
}
async function ttsNotifyTick(env) { // إشعار «الفصل اتحوّل لصوت» بعد تحقق production: صف new = فصل استُبدل واتأكد تشغيله. بلا رجعية وبلا إعادة تلقائية عند نتيجة غامضة — الفشل يبقى مرئيًا في state/err
  const { results } = await env.DB.prepare("SELECT nid,idx,auid FROM tts_notify_q WHERE state='new' ORDER BY ts LIMIT 20").all();
  for (const q of results) {
    const claim = await env.DB.prepare("UPDATE tts_notify_q SET state='working' WHERE nid=? AND idx=? AND state='new'").bind(q.nid, q.idx).run();
    if (!claim || !claim.meta || !claim.meta.changes) continue;
    const fin = (state, err) => env.DB.prepare('UPDATE tts_notify_q SET state=?, err=?, done_ts=? WHERE nid=? AND idx=?').bind(state, err || '', Date.now(), q.nid, q.idx).run();
    try {
      const ch = await env.DB.prepare('SELECT * FROM tts_ch WHERE nid=? AND idx=?').bind(q.nid, q.idx).first();
      if (!ch) { await fin('error', 'الفصل مش موجود'); continue; }
      if (ch.status !== 'done') { await fin('error', 'الفصل غير مكتمل عند الالتقاط'); continue; }
      const au = await env.DB.prepare('SELECT id,name,role FROM users WHERE id=?').bind(+q.auid || 0).first();
      if (!au) { await fin('error', 'حساب الكاتب غير موجود'); continue; }
      const res = await ttsDoneNotify(env, ch, au);
      await fin(res || 'sent', '');
    } catch (e) {
      await fin('error', String(e && e.message || e).slice(0, 180));
      try { await notifyAdmins(env, '', 'تعذّر إشعار صوت فصل 🎧', 'فشل إشعار صوت فصل ' + (q.idx + 1) + ' — الحالة محفوظة للمراجعة ولن يُعاد الإرسال تلقائيًا.', 'ttsfail' + q.nid + '#' + q.idx); } catch (e2) {}
    }
  }
  const { results: pendN } = await env.DB.prepare("SELECT nid,idx,ch_id FROM tts_notify_gen WHERE res='' AND ts<?").bind(Date.now() - 120000).all(); // استكمال إشعارات لم تُحاول أصلًا (توقف بعد التبديل) — res='' يعني لم يبدأ الإرسال، أما err: فلا يُعاد تلقائيًا
  for (const g2 of pendN) {
    const cl2 = await env.DB.prepare("UPDATE tts_notify_gen SET res='working' WHERE nid=? AND idx=? AND ch_id=? AND res=''").bind(g2.nid, g2.idx, g2.ch_id).run();
    if (!cl2 || !cl2.meta || !cl2.meta.changes) continue;
    const ch2 = await env.DB.prepare('SELECT * FROM tts_ch WHERE nid=? AND idx=?').bind(g2.nid, g2.idx).first();
    if (!ch2 || ch2.id !== g2.ch_id || ch2.status !== 'done') { await env.DB.prepare('UPDATE tts_notify_gen SET res=? WHERE nid=? AND idx=? AND ch_id=?').bind('orphan', g2.nid, g2.idx, g2.ch_id).run(); continue; }
    try { const r3 = (await ttsDoneNotify(env, ch2)) || 'unknown'; await env.DB.prepare('UPDATE tts_notify_gen SET res=? WHERE nid=? AND idx=? AND ch_id=?').bind('recovered:' + r3, g2.nid, g2.idx, g2.ch_id).run(); }
    catch (e) { await env.DB.prepare('UPDATE tts_notify_gen SET res=? WHERE nid=? AND idx=? AND ch_id=?').bind('err:' + String(e && e.message || e).slice(0, 120), g2.nid, g2.idx, g2.ch_id).run(); }
  }
}


/* ---------- إشعارات تلقائية: ميزة اليوم الساعة 1 الضهر + رسالة الغياب (يومين / أسبوع) ---------- */
const ENG_TIPS = [
  ['📖 اقرأ براحتك', 'غيّر لون الخلفية وحجم الخط ومسافة السطور من شريط القراءة، واقرأ بالشكل اللي يريّح عينك.'],
  ['🎧 استمع للفصول', 'اضغط «استمع للفصل» وشغّل الرواية بصوت مصري، وقدّم أو أخّر ١٠ ثواني، وغيّر السرعة ×١.٢٥ و×١.٥ و×٢.'],
  ['🔖 مكتبتك ومفضلتك', 'ضيف رواياتك المفضلة لمكتبتك، وكمّل من آخر فصل وقفت عنده في أي وقت.'],
  ['🔔 نبهني بالفصل الجديد', 'اضغط «نبهني» على أي فصل مجدول، وهيجيلك إشعار أول ما ينزل.'],
  ['💬 شارك رأيك واكسب نقاط', 'علّق وقيّم الفصول، وكل تعليق وتقييم بيزوّد نقاط محفظتك.'],
  ['🏆 المسابقة الأسبوعية', 'جاوب أسئلة المسابقة الأسبوعية، وفرصتك تكسب جوايز كل أسبوع.'],
  ['✍️ تابع كتّابك المفضلين', 'تابع الكاتب اللي بتحبه، وهتعرف فورًا لما ينزّل فصل أو رواية جديدة.'],
  ['📄 حمّل الرواية PDF', 'تقدر تحمّل الروايات الورقية PDF وتقراها في أي وقت.']
];
const ENG_DEF = { tip: true, hour: 13, gone: true, d1: 2, d2: 7, t1: 'أنت غايب بقالك يومين 🌿', x1: 'يارب تكون بخير، افتح التطبيق وطمنا عليك', t2: 'أنت غايب بقالك أسبوع 🌿', x2: 'يارب تكون بخير، افتح التطبيق وطمنا عليك', tips: [] };
function normEng(x) {
  x = x && typeof x === 'object' ? x : {}; const n = (v, d, a, z) => { v = Number(v); return Number.isFinite(v) ? Math.max(a, Math.min(z, Math.round(v))) : d; }, s = (v, d, m) => { v = String(v == null ? '' : v).trim().slice(0, m); return v || d; };
  const tips = Array.isArray(x.tips) ? x.tips.slice(0, 40).map((q) => ({ t: s(q && q.t, '', 60), x: s(q && q.x, '', 220) })).filter((q) => q.t && q.x) : [];
  return { tip: x.tip !== false, hour: n(x.hour, 13, 0, 23), gone: x.gone !== false, d1: n(x.d1, 2, 1, 30), d2: n(x.d2, 7, 2, 60), t1: s(x.t1, ENG_DEF.t1, 60), x1: s(x.x1, ENG_DEF.x1, 220), t2: s(x.t2, ENG_DEF.t2, 60), x2: s(x.x2, ENG_DEF.x2, 220), tips };
}
const cairoHour = () => { try { return +new Intl.DateTimeFormat('en-GB', { timeZone: 'Africa/Cairo', hour: '2-digit', hour12: false }).format(new Date()) % 24; } catch (e) { return (new Date().getUTCHours() + 2) % 24; } };
async function engageTick(env) {
  const now = Date.now(), cf = normEng(await getSetting(env, 'engage')), st = await getSetting(env, 'engage_st');
  if (now - (st.run || 0) < 4 * 60000) return; // مرة كل ~5 دقايق كفاية
  const hr = cairoHour(), day = cairoDay(); let dirty = { ...st, run: now };
  if (cf.tip && hr >= cf.hour && hr < cf.hour + 6 && st.day !== day) {
    dirty.day = day; await setSetting(env, 'engage_st', dirty);
    const pool = cf.tips.length ? cf.tips.map((q) => [q.t, q.x]) : ENG_TIPS, tp = pool[(st.i || 0) % pool.length]; dirty.i = ((st.i || 0) + 1) % pool.length;
    try { await env.DB.prepare('INSERT INTO bcast (title,text,url,ts) VALUES (?,?,?,?)').bind(tp[0], tp[1], '', now).run(); await env.DB.prepare('DELETE FROM bcast WHERE id NOT IN (SELECT id FROM bcast ORDER BY ts DESC LIMIT 60)').run(); } catch (e) {}
    if (env.FCM_SA) { try { await sendPush(env, tp[0], tp[1], '', 'all'); } catch (e) {} }
  }
  if (cf.gone && env.FCM_SA && hr >= 10 && hr < 22) {
    const lim1 = now - cf.d1 * DAYMS, { results } = await env.DB.prepare('SELECT u.id AS id, s.m AS m, g.lvl AS lvl, g.seen AS gs FROM users u JOIN (SELECT uid, MAX(seen) AS m FROM sessions GROUP BY uid) s ON s.uid=u.id LEFT JOIN gone_sent g ON g.uid=u.id WHERE s.m>0 AND s.m<? LIMIT 120').bind(lim1).all();
    for (const r of results) {
      const lvl = now - r.m >= cf.d2 * DAYMS ? 2 : 1;
      if (r.gs === r.m && (r.lvl || 0) >= lvl) continue;
      await env.DB.prepare('INSERT INTO gone_sent (uid,lvl,seen,ts) VALUES (?,?,?,?) ON CONFLICT(uid) DO UPDATE SET lvl=excluded.lvl,seen=excluded.seen,ts=excluded.ts').bind(r.id, lvl, r.m, now).run();
      try { await sendPush(env, lvl === 2 ? cf.t2 : cf.t1, lvl === 2 ? cf.x2 : cf.x1, '', 'u_' + r.id); } catch (e) {}
    }
  }
  await setSetting(env, 'engage_st', dirty);
}

/* ---------- المسابقة الأسبوعية + نقاط الكتّاب + قرعة نقاط الفوز ---------- */
const DAYMS = 86400000, PT_PER_VOTE = 0.1;
const cairoDay = () => new Date(Date.now() + 2 * 3600000).toISOString().slice(0, 10);
const cairoDayStart = () => Date.parse(cairoDay() + 'T00:00:00Z') - 2 * 3600000;
async function cmtConf(env) { const c = await getSetting(env, 'cmt'); const n = (v, d, a, z) => { v = Number(v); return Number.isFinite(v) ? Math.max(a, Math.min(z, v)) : d; }; return { perCh: n(c.perCh, 2, 0, 50), perDay: n(c.perDay, 5, 0, 500), pts: n(c.pts, 1, 0, 1000), minLen: n(c.minLen, 15, 3, 500), dayPts: n(c.dayPts, 5, 0, 500), newsPerDay: n(c.newsPerDay, 1, 0, 20) }; }
const normTxt = (t) => String(t).toLowerCase().replace(/[\u064B-\u065F\u0670\u0640]/g, '').replace(/[أإآ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه').replace(/[^\p{L}\p{N}\s]/gu, ' ').replace(/\s+/g, ' ').trim();
const jacc = (a, b) => { const x = new Set(a.split(' ')), y = new Set(b.split(' ')); let i = 0; x.forEach((w) => { if (y.has(w)) i++; }); const u = x.size + y.size - i; return u ? i / u : 0; };
const fnv = (t) => { let h = 2166136261; for (let i = 0; i < t.length; i++) { h ^= t.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0).toString(36); };
async function walConf(env) { const c = await getSetting(env, 'walcfg'), n = (v, d, a, z) => { v = Number(v); return Number.isFinite(v) && v !== null ? Math.max(a, Math.min(z, v)) : d; }; return { vote: n(c.vote, 0.1, 0, 1000), comment: n(c.comment, 0.1, 0, 1000), perDay: Math.round(n(c.perDay, 3, 0, 500)), premMult: n(c.premMult, 2, 1, 20) }; }
const WAL_PT = 0.1, WAL_DAY = 3; // كل تقييم/تعليق = 0.1 نقطة، وبحد أقصى 3 مرات في اليوم (تعليق + تصويت مع بعض)
async function walMult(env, uid) { const u = await env.DB.prepare('SELECT role,premium_until FROM users WHERE id=?').bind(uid).first(); return isPremium(u) ? (await walConf(env)).premMult : 1; }
async function walAward(env, uid, kind, ref) { // مصدر النقاط الوحيد للقارئ: vote / comment (+ streak لوحده)
  const day = cairoDay();
  const got = await env.DB.prepare("SELECT COUNT(*) AS n FROM wal_log WHERE uid=? AND day=? AND kind IN ('vote','comment')").bind(uid, day).first();
  const wc = await walConf(env);
  if ((got && got.n) >= wc.perDay) return 0;
  const amt = Math.round((kind === 'vote' ? wc.vote : wc.comment) * (await walMult(env, uid)) * 100) / 100;
  if (!(amt > 0)) return 0;
  const r = await env.DB.prepare('INSERT OR IGNORE INTO wal_log (uid,day,kind,ref,amt,ts) VALUES (?,?,?,?,?,?)').bind(uid, day, kind, String(ref), amt, Date.now()).run();
  if (r && r.meta && r.meta.changes) { await env.DB.prepare('UPDATE users SET wallet=ROUND(wallet+?,2) WHERE id=?').bind(amt, uid).run(); return amt; }
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
async function sendPush(env, title, text, link, topic, ref) {
  if (!env.FCM_SA) throw new Error('إشعارات الموبايل مش متفعّلة لسه (محتاجة ملف Firebase — راجع الشرح)');
  let sa; try { sa = JSON.parse(env.FCM_SA); } catch (e) { throw new Error('ملف Firebase المحفوظ غير صحيح'); }
  const token = await fcmAccessToken(sa);
  const msg = { message: { topic: topic || 'all', notification: { title: title || 'RadPad', body: text || '' }, data: { url: link || '', ref: ref || '' }, android: { priority: 'HIGH', notification: { channel_id: 'radpad_alerts', sound: 'default' } } } };
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
    ctx.waitUntil((async () => { try { await ensureSchema(env); env = await withKeys(env); try { await ptsTick(env); } catch (e) {} try { await alertsTick(env); } catch (e) {} try { await ttsNotifyTick(env); } catch (e) {} try { await engageTick(env); } catch (e) {} try { await releasesTick(env); } catch (e) {} try { await env.DB.prepare('DELETE FROM sessions WHERE seen<?').bind(Date.now() - 40 * 86400000).run(); } catch (e) {} try { await env.DB.prepare('DELETE FROM notes WHERE ts<?').bind(Date.now() - 30 * 86400000).run(); } catch (e) {} try { await env.DB.prepare('DELETE FROM visits WHERE day<?').bind(dayKey(Date.now() - 45 * 86400000)).run(); await env.DB.prepare('DELETE FROM presence WHERE seen<?').bind(Date.now() - 2 * 86400000).run(); } catch (e) {} if (await ttsMigrate(env)) { try { await ttsRebalance(env); } catch (e) {} await Promise.all(PROVS.map((p) => ttsStep(env, { prov: p }).catch(() => {}))); } } catch (e) {} })());
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
  if (path === '/api/social/config' && m === 'GET') { const c = await socConf(env); return json({ google: c.google, facebook: c.facebook }, 200, { 'Cache-Control': 'public, max-age=300' }); }
  if (path === '/api/auth/social' && m === 'POST') {
    if (await tooMany(env, 'soc:' + ip, 20, 900000)) return fail('محاولات كتير، جرّب بعد شوية', 429);
    const b = await body(request, 6000), provider = b.provider === 'facebook' ? 'facebook' : (b.provider === 'google' ? 'google' : '');
    const tok = String(b.token || '').trim();
    if (!provider || tok.length < 20 || tok.length > 4000) return fail('بيانات الدخول غير صحيحة');
    await noteAttempt(env, 'soc:' + ip);
    const v = await socVerify(env, provider, tok, str(b.nonce, 80));
    if (!v) return fail('معرفناش نتأكد من حسابك. جرّب تاني', 401);
    const dev = devOf(request);
    let uid = (await env.DB.prepare('SELECT uid FROM oauth_ids WHERE provider=? AND sub=?').bind(provider, v.sub).first() || {}).uid || 0, u = null;
    if (uid) u = await env.DB.prepare('SELECT id,email,name,role,premium_until,avatar,bio,links FROM users WHERE id=?').bind(uid).first();
    if (!u && v.email && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.email)) { // لو الإيميل مسجّل قبل كده
      const ex = await env.DB.prepare('SELECT id,email,name,role,premium_until,avatar,bio,links FROM users WHERE email=?').bind(v.email).first();
      if (ex) {
        if (provider !== 'google' || !v.verified) return fail('الإيميل ده مسجّل عندنا بالباسورد. ادخل بيه عادي', 409);
        u = ex; await env.DB.prepare('INSERT OR IGNORE INTO oauth_ids (provider,sub,uid,ts) VALUES (?,?,?,?)').bind(provider, v.sub, u.id, Date.now()).run();
      }
    }
    if (!u) { // حساب جديد
      if (dev && (await env.DB.prepare('SELECT COUNT(*) AS n FROM dev_accts WHERE dev=?').bind(dev).first()).n >= MAX_DEV_ACCTS) return fail('أنت تمتلك الآن حسابين، لا يمكنك عمل حساب آخر', 403);
      const nm = str(v.name, 40).replace(/[<>"]/g, '').trim(), name = nm.length >= 2 ? nm : 'قارئ',
        email = v.email && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.email) ? v.email : provider + '_' + v.sub + '@social.invalid';
      const count = (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n, role = count === 0 ? 'admin' : 'user';
      const rnd = [...crypto.getRandomValues(new Uint8Array(24))].map((x) => x.toString(16).padStart(2, '0')).join('');
      const r = await env.DB.prepare('INSERT INTO users (email,name,pass_hash,role,created_at) VALUES (?,?,?,?,?)').bind(email, name, await hashPassword(rnd), role, Date.now()).run();
      const id = r.meta.last_row_id;
      await env.DB.prepare('INSERT OR IGNORE INTO oauth_ids (provider,sub,uid,ts) VALUES (?,?,?,?)').bind(provider, v.sub, id, Date.now()).run();
      if (dev) await env.DB.prepare('INSERT OR IGNORE INTO dev_accts (dev,uid,ts) VALUES (?,?,?)').bind(dev, id, Date.now()).run();
      u = { id, email, name, role, premium_until: 0 };
    }
    if (!(await devEnter(env, u, dev))) return fail(devBlockMsg(u), 403);
    return json({ token: await makeToken(env, u.id), user: await withOwner(env, userOut(u)) });
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
  if (path === '/api/site-covers' && m === 'GET') {
    /* أغلفة روايات الموقع المرتبطة بنسخة سيرفر: النسخة دي هي اللي تتعرض بدل الغلاف القديم المرفوع مع الموقع */
    const { results } = await env.DB.prepare("SELECT d_cover,l_cover,d_extra,l_extra FROM novels WHERE l_extra LIKE '%\"siteId\"%' OR d_extra LIKE '%\"siteId\"%'").all();
    const covers = {};
    for (const r of results) {
      const sid = extraOf(r.d_extra).siteId || extraOf(r.l_extra).siteId, cv = r.d_cover || r.l_cover;
      if (sid && cv && /^https:\/\//i.test(cv)) covers[sid] = cv;
    }
    return json({ covers }, 200, { 'Cache-Control': 'public, max-age=30' });
  }
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

  if (path === '/api/trending' && m === 'GET') { // الرائجة: مجموع التصويت + التعليقات لكل رواية (مخزّنة 5 دقايق في الذاكرة لتقليل القراءات)
    const hit = globalThis.__trend;
    if (hit && Date.now() - hit.t < 300000) return json(hit.v, 200, { 'Cache-Control': 'public, max-age=120' });
    const o = {};
    try { const { results: vs } = await env.DB.prepare('SELECT nid, COUNT(*) AS n FROM pts_votes GROUP BY nid').all(); vs.forEach((r) => { (o[r.nid] = o[r.nid] || { v: 0, c: 0 }).v = r.n; }); } catch (e) {}
    try { const { results: cs } = await env.DB.prepare('SELECT nid, COUNT(*) AS n FROM cmt_log GROUP BY nid').all(); cs.forEach((r) => { (o[r.nid] = o[r.nid] || { v: 0, c: 0 }).c = r.n; }); } catch (e) {}
    const top = Object.entries(o).sort((x, y) => (y[1].v + y[1].c) - (x[1].v + x[1].c)).slice(0, 300), out = {}; top.forEach(([k, v]) => { out[k] = v; });
    const val = { scores: out }; globalThis.__trend = { t: Date.now(), v: val };
    return json(val, 200, { 'Cache-Control': 'public, max-age=120' });
  }
  if (path === '/api/reads' && m === 'GET') {
    const hit = globalThis.__reads;
    if (hit && Date.now() - hit.t < 60000) return json(hit.v, 200, { 'Cache-Control': 'public, max-age=60' });
    const { results } = await env.DB.prepare('SELECT k,n FROM reads ORDER BY n DESC LIMIT 1000').all();
    const o = {}; results.forEach((r) => { o[r.k] = r.n; });
    const val = { reads: o, epoch: ((await getSetting(env, 'reads_epoch')) || {}).t || 0 }; globalThis.__reads = { t: Date.now(), v: val };
    return json(val, 200, { 'Cache-Control': 'public, max-age=60' });
  }
  if (path === '/api/reads' && m === 'POST') {
    const b = await body(request, 2000), k = str(b.k, 60), ch = Number.isInteger(+b.ch) ? Math.max(0, Math.min(9999, +b.ch)) : -1;
    if (!/^[A-Za-z0-9_-]{1,60}$/.test(k) || ch < 0) return fail('مفتاح غير صحيح');
    if (await tooMany(env, 'rdip:' + ip, 80, 3600000)) return json({ ok: true, skipped: true });
    const ins = await env.DB.prepare('INSERT OR IGNORE INTO read_seen (h,k,ch,ts) VALUES (?,?,?,?)').bind(fnv(ip), k, ch, Date.now()).run();
    if (!(ins && ins.meta && ins.meta.changes)) return json({ ok: true, dup: true });
    globalThis.__reads = null;
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

  /* ----- بث الصوت بالـRange برابط مؤقت (من غير تحميل الجزء كله قبل التشغيل) ----- */
  if ((g = /^\/api\/tts\/part\/(\d+)\/(\d+)$/.exec(path)) && m === 'GET' && url.searchParams.get('k')) {
    const tk = await readToken(env, str(url.searchParams.get('k'), 400));
    if (!tk || !tk.tp || !env.TTS_BUCKET) return fail('الرابط منتهي', 403);
    const rg = request.headers.get('range'); let ext = url.searchParams.get('f') === 'mp3' ? 'mp3' : 'wav';
    let o = await env.TTS_BUCKET.get('c/' + g[1] + '/' + g[2] + '.' + ext, rg ? { range: request.headers } : undefined);
    if (!o) { ext = ext === 'mp3' ? 'wav' : 'mp3'; o = await env.TTS_BUCKET.get('c/' + g[1] + '/' + g[2] + '.' + ext, rg ? { range: request.headers } : undefined); } // المانيفست ممكن يكون قديم بعد الضغط
    if (!o) return fail('الجزء مش موجود', 404);
    const size = o.size, off = rg && o.range && o.range.offset !== undefined ? o.range.offset : 0, len = rg && o.range && o.range.length !== undefined ? o.range.length : size - off;
    const h = { ...CORS, 'Content-Type': ext === 'mp3' ? 'audio/mpeg' : 'audio/wav', 'Accept-Ranges': 'bytes', 'Cache-Control': 'private, no-store', 'Content-Length': String(len) };
    if (rg) { h['Content-Range'] = 'bytes ' + off + '-' + (off + len - 1) + '/' + size; return new Response(o.body, { status: 206, headers: h }); }
    return new Response(o.body, { status: 200, headers: h });
  }

  /* ----- تنزيل صوت فصل كامل (WAV واحد) برابط مؤقت للأدمن بس: بيتفتح في متصفح الموبايل فينزل مباشرة ----- */
  if (path === '/api/tts/dl' && m === 'GET') {
    const tk = await readToken(env, str(url.searchParams.get('k'), 400));
    if (!tk || !tk.dl || !env.TTS_BUCKET) return fail('الرابط منتهي، اطلبه من التطبيق تاني', 403);
    const c = await env.DB.prepare("SELECT id,nparts,ntitle,ctitle,status,fmt FROM tts_ch WHERE nid=? AND idx=?").bind(tk.dl, tk.ix).first();
    let pubId = c && c.id, pubN = c && c.nparts, stFmt = '';
    if (tk.g) { const sg2 = await env.DB.prepare('SELECT ch_id,nparts,fmt FROM tts_gen_stage WHERE nid=? AND idx=? AND ch_id=?').bind(tk.dl, tk.ix, +tk.g).first(); if (!sg2) return fail('الصوت لسه مش جاهز', 404); pubId = sg2.ch_id; pubN = sg2.nparts; stFmt = sg2.fmt; }
    else if (!c || c.status !== 'done') return fail('الصوت لسه مش جاهز', 404);
    if (!c) return fail('الفصل مش موجود', 404);
    const mp = (tk.g ? stFmt === 'mp3' : c.fmt === 'mp3'), keys = []; for (let i = 0; i < pubN; i++) keys.push('c/' + pubId + '/' + i + (mp ? '.mp3' : '.wav'));
    const heads = await Promise.all(keys.map((k) => env.TTS_BUCKET.head(k)));
    if (heads.some((h) => !h)) return fail('جزء من الصوت ناقص', 404);
    if (mp) { // MP3: الأجزاء بتتلزق ورا بعض زي ما هي
      let i2 = 0, rd2 = null; const bk = env.TTS_BUCKET, tot2 = heads.reduce((a, h) => a + h.size, 0);
      const st2 = new ReadableStream({ async pull(ctl) { for (;;) { if (!rd2) { if (i2 >= keys.length) { ctl.close(); return; } const o = await bk.get(keys[i2++]); if (!o) { ctl.error(new Error('part')); return; } rd2 = o.body.getReader(); } const { done, value } = await rd2.read(); if (done) { rd2 = null; continue; } if (value.length) { ctl.enqueue(value); return; } } } });
      const nm2 = String((c.ntitle || 'novel') + ' - ' + (c.ctitle || ('chapter ' + tk.ix))).replace(/[\\/:*?"<>|\r\n]+/g, ' ').trim().slice(0, 120) + '.mp3';
      return new Response(st2, { status: 200, headers: { ...CORS, 'Content-Type': 'audio/mpeg', 'Content-Length': String(tot2), 'Content-Disposition': "attachment; filename=\"audio.mp3\"; filename*=UTF-8''" + encodeURIComponent(nm2), 'Cache-Control': 'private, no-store' } });
    }
    const total = heads.reduce((a, h) => a + Math.max(0, h.size - 44), 0);
    const hd = pcmToWav(new Uint8Array(0), 24000), hv = new DataView(hd.buffer); hv.setUint32(4, 36 + total, true); hv.setUint32(40, total, true);
    let i = 0, rd = null, skip = 44; const bucket = env.TTS_BUCKET;
    const stream = new ReadableStream({
      start(ctl) { ctl.enqueue(hd); },
      async pull(ctl) {
        for (;;) {
          if (!rd) { if (i >= keys.length) { ctl.close(); return; } const o = await bucket.get(keys[i++]); if (!o) { ctl.error(new Error('part')); return; } rd = o.body.getReader(); skip = 44; }
          const { done, value } = await rd.read();
          if (done) { rd = null; continue; }
          let v = value; if (skip > 0) { const k = Math.min(skip, v.length); v = v.subarray(k); skip -= k; }
          if (v.length) { ctl.enqueue(v); return; }
        }
      }
    });
    const nm = String((c.ntitle || 'novel') + ' - ' + (c.ctitle || ('chapter ' + tk.ix))).replace(/[\\/:*?"<>|\r\n]+/g, ' ').trim().slice(0, 120) + '.wav';
    return new Response(stream, { status: 200, headers: { ...CORS, 'Content-Type': 'audio/wav', 'Content-Length': String(44 + total), 'Content-Disposition': "attachment; filename=\"audio.wav\"; filename*=UTF-8''" + encodeURIComponent(nm), 'Cache-Control': 'private, no-store' } });
  }

  /* ----- ضغط الصوت (GitHub Actions): بمفتاح خاص بيحوّل أجزاء WAV الجاهزة لـ MP3 صغير ----- */
  if ((g = /^\/api\/cx\/(next|get|put|done)(?:\/(\d+)(?:\/(\d+))?)?$/.exec(path)) && env.TTS_BUCKET) {
    const ctk = await readToken(env, str((request.headers.get('authorization') || '').replace(/^Bearer\s+/i, ''), 600));
    if (!ctk || !ctk.cx) return fail('مفتاح الضغط غير صحيح', 403);
    if (g[1] === 'next' && m === 'GET') {
      const kp = await ttsKeep(env, null), args = [Date.now() - 180000];
      let q = "SELECT id,nid,idx,nparts,updated FROM tts_ch WHERE status='done' AND fmt='wav' AND nparts>0 AND updated<? AND id NOT IN (SELECT ch_id FROM tts_gen_stage WHERE status IN ('staged','publishing'))";
      if (kp.size) { q += ' AND nid NOT IN (' + [...kp].map(() => '?').join(',') + ')'; args.push(...kp); }
      const c = await env.DB.prepare(q + ' ORDER BY updated ASC LIMIT 1').bind(...args).first();
      return json({ ch: c || null }, 200, { 'Cache-Control': 'no-store' });
    }
    const cid = +g[2], c = cid ? await env.DB.prepare('SELECT id,nid,nparts,status,fmt,updated FROM tts_ch WHERE id=?').bind(cid).first() : null;
    if (!c || c.status !== 'done' || c.fmt !== 'wav') return fail('الفصل اتغيّر', 409);
    if ((await ttsKeep(env, null)).has(c.nid)) return fail('رواية محميّة', 403);
    if (g[1] === 'get' && m === 'GET') { const o = await env.TTS_BUCKET.get('c/' + c.id + '/' + (+g[3]) + '.wav'); return o ? new Response(o.body, { headers: { ...CORS, 'Content-Type': 'audio/wav', 'Cache-Control': 'no-store' } }) : fail('الجزء مش موجود', 404); }
    if (g[1] === 'put' && m === 'PUT') {
      const pi = +g[3]; if (!(pi >= 0 && pi < c.nparts)) return fail('جزء غلط');
      const buf = await request.arrayBuffer(); if (buf.byteLength < 800 || buf.byteLength > 30000000) return fail('حجم الملف غير منطقي');
      await env.TTS_BUCKET.put('c/' + c.id + '/' + pi + '.mp3', buf, { httpMetadata: { contentType: 'audio/mpeg' } }); return json({ ok: true, size: buf.byteLength });
    }
    if (g[1] === 'done' && m === 'POST') {
      const have = new Set(); let cur = undefined;
      for (let k = 0; k < 5; k++) { const ls = await env.TTS_BUCKET.list({ prefix: 'c/' + c.id + '/', cursor: cur }); ls.objects.forEach((x) => have.add(x.key)); if (!ls.truncated) break; cur = ls.cursor; }
      for (let i = 0; i < c.nparts; i++) if (!have.has('c/' + c.id + '/' + i + '.mp3') || !have.has('c/' + c.id + '/' + i + '.wav')) return fail('جزء ناقص رقم ' + i, 409);
      const r = await env.DB.prepare("UPDATE tts_ch SET fmt='mp3' WHERE id=? AND status='done' AND fmt='wav' AND updated=?").bind(c.id, c.updated).run();
      const mk = [], wk = []; for (let i = 0; i < c.nparts; i++) { mk.push('c/' + c.id + '/' + i + '.mp3'); wk.push('c/' + c.id + '/' + i + '.wav'); }
      if (!(r && r.meta && r.meta.changes)) { for (let i = 0; i < mk.length; i += 100) await env.TTS_BUCKET.delete(mk.slice(i, i + 100)); return fail('الفصل اتغيّر أثناء الضغط', 409); }
      for (let i = 0; i < wk.length; i += 100) await env.TTS_BUCKET.delete(wk.slice(i, i + 100));
      return json({ ok: true });
    }
    return fail('طلب غير صحيح', 400);
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
    const chN = Number.isInteger(+b.chapter) && +b.chapter >= 0 && +b.chapter <= 9999 ? '#' + (+b.chapter) : '', nref = ref + chN;
    await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(target, kind, nref, user.name, head, text, Date.now()).run();
    await env.DB.prepare('DELETE FROM notes WHERE ts < ?').bind(Date.now() - 60 * 86400000).run();
    try { await sendPush(env, head, text, '', 'u_' + target, nref); } catch (e) {}
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
    const c = await env.DB.prepare('SELECT id,status,parts,done,nparts,secs,fmt,LENGTH(text) AS total FROM tts_ch WHERE nid=? AND idx=?').bind(nid, ix).first();
    if (!c) return json({ status: 'none' }, 200, { 'Cache-Control': 'no-store' });
    if (c.status === 'done') return json({ status: 'ready', id: c.id, parts: JSON.parse(c.parts), total: c.total, secs: c.secs, fmt: c.fmt === 'mp3' ? 'mp3' : 'wav' }, 200, { 'Cache-Control': 'private, max-age=300' });
    return json({ status: 'pending', done: c.done, n: c.nparts }, 200, { 'Cache-Control': 'no-store' });
  }
  if (path === '/api/tts/ptoken' && m === 'GET') { // تصريح قصير لتشغيل الأجزاء بالبث (نفس شرط الاستماع)
    if (!isPremium(user) && !(await getTtsConf(env)).listenAll) return fail('الاستماع لمشتركي Premium', 403);
    const bd = b64u(enc.encode(JSON.stringify({ tp: 1, uid: user.id, exp: Date.now() + 3 * 3600000 })));
    const sg = await crypto.subtle.sign('HMAC', await getKey(env), enc.encode(bd));
    return json({ k: bd + '.' + b64u(sg), ttl: 3 * 3600 }, 200, { 'Cache-Control': 'private, no-store' });
  }
  if ((g = /^\/api\/tts\/part\/(\d+)\/(\d+)$/.exec(path)) && m === 'GET') {
    if (!isPremium(user) && !(await getTtsConf(env)).listenAll) return fail('الاستماع لمشتركي Premium', 403);
    if (!env.TTS_BUCKET) return fail('التخزين مش متفعّل', 503);
    const o = await env.TTS_BUCKET.get('c/' + g[1] + '/' + g[2] + '.wav');
    if (!o) { const o2 = await env.TTS_BUCKET.get('c/' + g[1] + '/' + g[2] + '.mp3'); if (o2) return new Response(o2.body, { status: 200, headers: { ...CORS, 'Content-Type': 'audio/mpeg', 'Cache-Control': 'private, no-store' } }); return fail('الجزء مش موجود', 404); }
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
            await sendPush(env, kind === 'novel' ? 'رواية جديدة من ' + au.name : 'فصل جديد من ' + au.name, '«' + r.d_title + '»' + (last ? ' — ' + last.title : ''), '', au.role === 'admin' ? 'all' : 'a_' + au.id, 'u' + id + (kind === 'chapter' ? '#' + (newCnt - 1) : ''));
          }
        }
        try { await pubAfterApprove(env, r, id, kind, newCnt, oldCnt); } catch (e) {}
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
      await setSetting(env, 'tts', { model: nm(b.model, cur.model), legacyModel: nm(b.legacyModel, cur.legacyModel), style: str(b.style, 200).trim() || cur.style, gv,
        concurrency: nu(b.concurrency, cur.concurrency, 1, 4), dailyMin: nu(b.dailyMin, cur.dailyMin, 0, 100000), freeMin: nu(b.freeMin, cur.freeMin, 0, 100000), priceIn: nu(b.priceIn, cur.priceIn, 0, 1000), priceOut: nu(b.priceOut, cur.priceOut, 0, 1000),
        defProv: PROVS.includes(b.defProv) ? b.defProv : cur.defProv, novelProv: cur.novelProv, rebalance: b.rebalance == null ? cur.rebalance : !!b.rebalance, rd: b.rd ? normRd({ ...cur.rd, ...b.rd, archMap: b.rd.archMap || cur.rd.archMap, pers: b.rd.pers || cur.rd.pers }) : cur.rd, engine: b.engine == null ? cur.engine : (b.engine === 'single' ? 'single' : 'mega'), hideListen: b.hideListen == null ? cur.hideListen : !!b.hideListen, listenAll: b.listenAll == null ? cur.listenAll : !!b.listenAll, annModel: nm(b.annModel, cur.annModel), dict: b.dict == null ? cur.dict : String(b.dict).slice(0, 3000),
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
    // فحص الفصول المحوّلة وهي أقصر من N ثانية (غالبًا اتحوّل العنوان بس) وحذفها من الطابور علشان الموقع يبعتها تاني بنصها الكامل
    if (path === '/api/admin/tts/fix-short' && m === 'POST') {
      const b = await body(request, 500), max = Math.max(1, Math.min(60, +b.max || 5));
      const ratio = Math.max(0.2, Math.min(0.95, +b.ratio || 0.6)); // الصوت أقصر من 60% من المدة المتوقعة للنص = ناقص (بيفوّت فقرات/جمل)
      const { results } = await env.DB.prepare("SELECT id,nid,idx,ntitle,ctitle,secs,nparts,LENGTH(text) AS len FROM tts_ch WHERE status='done' AND (secs<? OR secs < LENGTH(text)*1.0/" + CPS + "*?)").bind(max, ratio).all();
      if (!b.dry) {
        for (const r of results) {
          if (env.TTS_BUCKET) { const ks = []; for (let i = 0; i < r.nparts; i++) ks.push('c/' + r.id + '/' + i + '.wav', 'c/' + r.id + '/' + i + '.mp3'); for (let i = 0; i < ks.length; i += 100) await env.TTS_BUCKET.delete(ks.slice(i, i + 100)); }
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
        const parts = splitParts(text, rdPartMx(conf)); if (!parts.length) { skipped++; continue; }
        const ntitle = str(it.ntitle, 120), ctitle = str(it.ctitle, 120); let ord = Math.max(-1e9, Math.min(1e9, parseInt(it.ord, 10) || 0));
        const ex = await env.DB.prepare('SELECT id,sig,prov,text,nparts,status FROM tts_ch WHERE nid=? AND idx=?').bind(nid, ix).first();
        const sib = await env.DB.prepare('SELECT prov,MIN(ord) AS o FROM tts_ch WHERE nid=?').bind(nid).first(), prov = conf.novelProv[nid] || (sib && sib.prov) || conf.defProv;
        if (!ex) { if (sib && sib.o != null) { const old = await env.DB.prepare('SELECT MIN(created) AS c FROM tts_ch WHERE nid=?').bind(nid).first(); if (old && old.c && now - old.c > 600000) { const mx = await env.DB.prepare('SELECT COALESCE(MAX(ord),0) AS m FROM tts_ch').first(); ord = mx.m + 1; } else ord = sib.o; } await env.DB.prepare('INSERT INTO tts_ch (nid,idx,ntitle,ctitle,ord,sig,text,parts,nparts,created,updated,prov) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').bind(nid, ix, ntitle, ctitle, ord, sig, text, JSON.stringify(parts), parts.length, now, now, prov).run(); added++; }
        else if (ex.status === 'off' && !it.redo) { skipped++; } // فصل متشال يدوي من الطابور: السينك ما يرجّعوش لوحده
        else if (!it.redo && (ex.status === 'done' || (ex.sig === sig && !(hasMk(text) && !hasMk(ex.text))))) { await env.DB.prepare('UPDATE tts_ch SET ntitle=?,ctitle=? WHERE id=?').bind(ntitle, ctitle, ex.id).run(); skipped++; }
        else {
          if (env.TTS_BUCKET) { const ks = []; for (let i = 0; i < ex.nparts; i++) ks.push('c/' + ex.id + '/' + i + '.wav', 'c/' + ex.id + '/' + i + '.mp3'); for (let i = 0; i < ks.length; i += 100) await env.TTS_BUCKET.delete(ks.slice(i, i + 100)); } await env.DB.prepare("UPDATE tts_ch SET ntitle=?,ctitle=?,sig=?,text=?,parts=?,nparts=?,done=0,secs=0,status='queued',owner='',lock_until=0,retry_at=0,attempts=0,err='',updated=?,prov=? WHERE id=?").bind(ntitle, ctitle, sig, text, JSON.stringify(parts), parts.length, now, prov, ex.id).run(); updated++; }
      }
      return json({ ok: true, added, updated, skipped });
    }
    // ---- تحكم في كل فصل لوحده ----
    if (path === '/api/admin/tts/chapters' && m === 'GET') {
      const nid = str(url.searchParams.get('nid'), 80);
      const { results } = await env.DB.prepare('SELECT idx,ctitle,status,done,nparts,secs,err,ord,attempts,LENGTH(text) AS n FROM tts_ch WHERE nid=? ORDER BY idx').bind(nid).all();
      const { results: staged } = await env.DB.prepare("SELECT idx,ch_id,nparts,secs,voice,staged_at,status,err FROM tts_gen_stage WHERE nid=? AND status IN ('staged','publishing') ORDER BY staged_at DESC").bind(nid).all();
      const { results: ngen } = await env.DB.prepare('SELECT idx,ch_id,res,ts FROM tts_notify_gen WHERE nid=? ORDER BY ts DESC').bind(nid).all();
      const nby = {}; ngen.forEach((g) => { if (!nby[g.idx]) nby[g.idx] = { ch_id: g.ch_id, res: g.res }; }); // أحدث حالة إشعار لكل فصل: مرئية بعد التحديث
      return json({ chapters: results, staged, notify: nby });
    }
    if (path === '/api/admin/tts/prevch' && m === 'GET') { // معاينة جيل مجهّز قبل النشر للأدمن: نفس شكل /api/tts/chapter لكن للجيل المجهّز — تشغيل native مع مزامنة النص والتقديم عبر /api/tts/part/<ch_id>/<n> بدون تبديل الجيل المنشور
      const nid = str(url.searchParams.get('nid'), 80), ix = parseInt(url.searchParams.get('idx'), 10);
      const genW = Math.max(0, Math.floor(+url.searchParams.get('gen') || 0)); // طلب مثبّت على جيل صريح تعرضه الواجهة
      const pv = genW ? await env.DB.prepare("SELECT ch_id,parts,secs,voice,staged_at FROM tts_gen_stage WHERE nid=? AND idx=? AND ch_id=? AND status='staged'").bind(nid, ix, genW).first() : await env.DB.prepare("SELECT ch_id,parts,secs,voice,staged_at FROM tts_gen_stage WHERE nid=? AND idx=? AND status='staged' ORDER BY staged_at DESC LIMIT 1").bind(nid, ix).first();
      if (!pv) return fail('مفيش جيل جديد جاهز للمعاينة', 404);
      const c0 = await env.DB.prepare('SELECT text, LENGTH(text) AS total FROM tts_ch WHERE nid=? AND idx=?').bind(nid, ix).first();
      return json({ status: 'ready', preview: true, id: pv.ch_id, parts: JSON.parse(pv.parts || '[]'), text: (c0 && c0.text) || '', total: (c0 && c0.total) || 0, secs: pv.secs, voice: pv.voice, stagedAt: pv.staged_at }, 200, { 'Cache-Control': 'private, no-store' });
    }
    if (path === '/api/admin/tts/publish' && m === 'POST') { // اعتماد نشر جيل صوتي مجهّز: فعل النشر نفسه — قبول مربوط بالجيل المعروض، تحقق CAS من الحالة الأساسية، تحقق hash لكل جزء من R2، تبديل ذري، ثم إشعار «الفصل اتحوّل لصوت» في نفس الإتمام (مرة واحدة لكل جيل، بلا إعادة تلقائية)
      const b = await body(request, 400).catch(() => ({}));
      const nid = str(b.nid, 80), ix = parseInt(b.idx, 10), accept = Math.max(0, Math.floor(+b.accept || 0));
      if (!nid || !Number.isInteger(ix)) return fail('حدد الرواية والفصل');
      const now = Date.now();
      let st = await env.DB.prepare("SELECT * FROM tts_gen_stage WHERE nid=? AND idx=? AND status='staged' ORDER BY staged_at DESC LIMIT 1").bind(nid, ix).first();
      if (!st) {
        const pend = await env.DB.prepare("SELECT * FROM tts_gen_stage WHERE nid=? AND idx=? AND status='publishing' ORDER BY claimed_at DESC LIMIT 1").bind(nid, ix).first();
        if (pend) {
          const cur2 = await env.DB.prepare('SELECT id FROM tts_ch WHERE nid=? AND idx=?').bind(nid, ix).first();
          if (cur2 && cur2.id === pend.ch_id) { // التبديل اتم والمعاملة اتكرمت قبل التوقف — يظهر كمنشور والإشعار يكمله الـ sweeper
            await env.DB.prepare("UPDATE tts_gen_stage SET status='published' WHERE nid=? AND idx=? AND ch_id=?").bind(nid, ix, pend.ch_id).run();
            const ng0 = await env.DB.prepare('SELECT res FROM tts_notify_gen WHERE nid=? AND idx=? AND ch_id=?').bind(nid, ix, pend.ch_id).first(); // التبديل الذري ينشئ صف الإشعار معه؛ غيابه = تلف/قديم، يُعلَّم غير معروف ولا يُستنتج «لم يُحاول»
            if (!ng0) await env.DB.prepare("INSERT OR IGNORE INTO tts_notify_gen (nid,idx,ch_id,ts,res) VALUES (?,?,?,?,'unknown')").bind(nid, ix, pend.ch_id, now).run();
            return json({ ok: true, recovered: true, published: pend.ch_id, notify: ng0 ? (ng0.res || 'pending') : 'unknown' });
          }
          if (pend.claimed_at && now - pend.claimed_at > 600000) { // ادعاء ميت قبل التبديل — إرجاعه للتجهيز بشكل مرئي
            await env.DB.prepare("UPDATE tts_gen_stage SET status='staged', err='استُرجع بعد توقف أثناء النشر' WHERE nid=? AND idx=? AND ch_id=? AND status='publishing' AND claimed_at=?").bind(nid, ix, pend.ch_id, pend.claimed_at).run();
            st = await env.DB.prepare("SELECT * FROM tts_gen_stage WHERE nid=? AND idx=? AND status='staged' ORDER BY staged_at DESC LIMIT 1").bind(nid, ix).first();
          }
        }
        if (!st) return fail('مفيش جيل صوتي جديد جاهز للنشر للفصل ده (أو نشر آخر جارٍ)', 404);
      }
      if (accept !== st.ch_id) return fail('الاعتماد لازم يكون للجيل المعروض حاليًا — حدّث الصفحة', 409);
      if (!(st.nparts > 0) || !(st.secs > 0) || !/^[0-9a-f]{64}$/.test(st.sig || '') || !st.voice || !/^[0-9a-f]{64}$/.test(st.src_sig || '')) return fail('بيانات الجيل المجهّز ناقصة (أجزاء/مدة/بصمة/صوت/مصدر)', 409);
      const cur = await env.DB.prepare('SELECT * FROM tts_ch WHERE nid=? AND idx=?').bind(nid, ix).first(); // لقطة واحدة: النص والمعرّف والتوقيت من نفس القراءة، والـ CAS النهائي يضمن عدم تغيّرها
      if (!cur) return fail('الفصل مش موجود', 404);
      if (cur.id === st.ch_id) return json({ ok: true, already: true, notify: 'bound' });
      if (st.old_id !== cur.id || st.old_updated !== cur.updated) return fail('الفصل اتبدل من وقت تجهيز الجيل ده — جهّزه من جديد', 409);
      let pr; try { pr = JSON.parse(st.parts || '[]'); } catch (e) { pr = null; }
      if (!Array.isArray(pr) || pr.length !== st.nparts || pr.some((x) => !Array.isArray(x) || x.length !== 2 || !Number.isInteger(x[0]) || !Number.isInteger(x[1]) || x[0] < 0 || x[1] <= x[0])) return fail('حدود أجزاء الجيل غير سليمة', 409);
      const sep = /^[\s\p{P}]*$/u, gapOk = (a, b) => a <= b && sep.test(cur.text.slice(a, b)); // حدود الأجزاء بفهارس JS UTF16؛ يُسمح بفجوات فواصل/مسافات فقط بين الأجزاء
      if (pr[0][0] !== 0 || pr[pr.length - 1][1] !== cur.text.length || pr.some((x, k) => k > 0 && (x[0] < pr[k - 1][1] || !gapOk(pr[k - 1][1], x[0])))) return fail('أجزاء الجيل لا تغطي نص الفصل من 0 لنهايته (فجوات فواصل فقط بين الأجزاء)', 409); // نهايات حصرية [start,end): آخر جزء ينتهي عند text.length بالضبط
      const srcH = await crypto.subtle.digest('SHA-256', enc.encode(cur.text)); // src_sig = SHA256 UTF8 لنص tts_ch.text الحالي حرفيًا (مش sig/DJB2 ومش المخطوطة)
      if ([...new Uint8Array(srcH)].map((x) => x.toString(16).padStart(2, '0')).join('') !== st.src_sig) return fail('مصدر نص الجيل لا يطابق نص الفصل الحالي — جهّزه من جديد', 409);
      if (!env.TTS_BUCKET) return fail('التخزين مش متفعّل', 503);
      const clash = await env.DB.prepare('SELECT 1 AS x FROM tts_ch WHERE id=?').bind(st.ch_id).first();
      if (clash) return fail('معرّف الجيل الجديد مستخدم — جهّز الجيل بمعرّف مختلف', 409);
      let au = null; // تحقق الكاتب إلزامي قبل أي تبديل
      if (/^u\d+$/.test(nid)) au = await env.DB.prepare('SELECT u.id,u.name,u.role FROM novels n JOIN users u ON u.id=n.user_id WHERE n.id=?').bind(+nid.slice(1)).first();
      if (!au) { const { results: nr } = await env.DB.prepare('SELECT n.l_extra,n.d_extra,u.id,u.name,u.role FROM novels n JOIN users u ON u.id=n.user_id WHERE n.l_extra LIKE ? OR n.d_extra LIKE ?').bind('%' + nid + '%', '%' + nid + '%').all(); au = nr.find((x) => extraOf(x.l_extra).siteId === nid || extraOf(x.d_extra).siteId === nid) || null; }
      if (!au) return fail('تعذّر تحديد كاتب الرواية — النشر متوقف', 409);
      const claim = await env.DB.prepare("UPDATE tts_gen_stage SET status='publishing', claimed_at=? WHERE nid=? AND idx=? AND ch_id=? AND status='staged'").bind(now, nid, ix, st.ch_id).run(); // ادعاء الجيل: قفل متزامن
      if (!(claim && claim.meta && claim.meta.changes)) return fail('نشر آخر جارٍ للجيل ده', 409);
      const release = (m) => env.DB.prepare("UPDATE tts_gen_stage SET status='staged', err=? WHERE nid=? AND idx=? AND ch_id=? AND status='publishing'").bind(m, nid, ix, st.ch_id).run();
      const isMp3 = st.fmt === 'mp3'; // الجيل MP3: مسار تحقق منفصل تحت، مسار WAV تحته زي ما هو
      const shas = new Array(st.nparts), szs = new Array(st.nparts).fill(0); let bad = -1;
      for (let i0 = 0; !isMp3 && i0 < st.nparts && bad < 0; i0 += 10) { // تحقق integrity لكل جزء: وجود + حجم + sha256 من metadata التخزين (مدخلات الرفع)
        await Promise.all(Array.from({ length: Math.min(10, st.nparts - i0) }, async (_, k) => {
          const i = i0 + k, h = await env.TTS_BUCKET.head('c/' + st.ch_id + '/' + i + '.wav');
          const m = h && h.customMetadata && /^[0-9a-f]{64}$/.test(h.customMetadata.sha256 || '') ? h.customMetadata.sha256 : '';
          if (!h || !h.size || !m) { if (bad < 0) bad = i; return; }
          shas[i] = m; szs[i] = h.size;
        }));
      }
      if (!isMp3 && bad < 0) { // مدة PCM الفعلية من أحجام كل الأجزاء ((size-44)/48000) تقارَن بمدة الجيل المعلنة بسماحية تقريب
        const pcmSecs = szs.reduce((a, z) => a + (z - 44) / 48000, 0);
        if (Math.abs(pcmSecs - st.secs) > st.nparts * 0.5 + 1) bad = -2;
      }
      if (bad === -2) { await release('مدة الجيل المعلنة لا تطابق أحجام الأجزاء'); try { await notifyAdmins(env, '', 'تعذّر نشر صوت فصل 🎧', 'نشر صوت فصل ' + (ix + 1) + ' اتوقف: مدة الجيل المعلنة لا تطابق أحجام الأجزاء. لن يُعاد تلقائيًا.', 'ttspub' + nid + '#' + ix + '#' + st.ch_id); } catch (e2) {} return fail('نشر متوقف: مدة الجيل لا تطابق أحجام الأجزاء', 409); }
      let mp3Msg = '';
      if (isMp3) { const mv = await mp3VerifyStage(env, st); mv.shas.forEach((x, i) => { shas[i] = x; }); bad = mv.bad; mp3Msg = mv.err; if (bad === -2) { await release(mp3Msg); try { await notifyAdmins(env, '', 'تعذّر نشر صوت فصل 🎧', 'نشر صوت فصل ' + (ix + 1) + ' اتوقف: ' + mp3Msg + '. لن يُعاد تلقائيًا.', 'ttspub' + nid + '#' + ix + '#' + st.ch_id); } catch (e2) {} return fail('نشر متوقف: ' + mp3Msg, 409); } }
      if (!isMp3 && bad < 0) { // عيّنة محدودة يعاد حساب بصمتها من البايتات الفعلية (أول/وسط/آخر جزء) — البصمات الباقية مدخلات رفع موثّق بها لا إعادة حساب كاملة
        const sample = [...new Set([0, Math.floor((st.nparts - 1) / 2), st.nparts - 1])];
        for (const i of sample) { const o = await env.TTS_BUCKET.get('c/' + st.ch_id + '/' + i + '.wav'); if (!o) { bad = i; break; } const buf = await o.arrayBuffer(), dv = new DataView(buf), td = new TextDecoder('ascii');
          const pcm = buf.byteLength >= 44 && td.decode(new Uint8Array(buf, 0, 4)) === 'RIFF' && td.decode(new Uint8Array(buf, 8, 4)) === 'WAVE' && dv.getUint16(20, true) === 1 && dv.getUint16(22, true) === 1 && dv.getUint32(24, true) === 24000 && dv.getUint16(34, true) === 16 && td.decode(new Uint8Array(buf, 36, 4)) === 'data' && dv.getUint32(40, true) === buf.byteLength - 44;
          if (!pcm) { bad = i; break; } // صيغة PCM 24kHz/16-bit/mono + عدّ البايتات مربوطان بالترويسة الفعلية
          const dh = await crypto.subtle.digest('SHA-256', buf); if ([...new Uint8Array(dh)].map((x) => x.toString(16).padStart(2, '0')).join('') !== shas[i]) { bad = i; break; } }
      }
      if (bad >= 0 || bad === -3) { if (isMp3) { await release(mp3Msg); try { await notifyAdmins(env, '', 'تعذّر نشر صوت فصل 🎧', 'نشر صوت فصل ' + (ix + 1) + ' اتوقف: ' + mp3Msg + '. لن يُعاد تلقائيًا.', 'ttspub' + nid + '#' + ix + '#' + st.ch_id); } catch (e2) {} return fail('نشر متوقف: ' + mp3Msg, 409); } await release('جزء ناقص أو بصمته لا تطابق بايتاته: ' + bad); try { await notifyAdmins(env, '', 'تعذّر نشر صوت فصل 🎧', 'نشر صوت فصل ' + (ix + 1) + ' اتوقف: جزء ' + bad + ' ناقص أو بصمته لا تطابق. لن يُعاد تلقائيًا.', 'ttspub' + nid + '#' + ix + '#' + st.ch_id); } catch (e2) {} return fail('نشر متوقف: جزء ' + bad + ' ناقص أو بصمته لا تطابق', 409); }
      const man = await crypto.subtle.digest('SHA-256', enc.encode(shas.join('')));
      if ([...new Uint8Array(man)].map((x) => x.toString(16).padStart(2, '0')).join('') !== st.sig) { await release('بصمة الجيل لا تطابق التجهيز'); try { await notifyAdmins(env, '', 'تعذّر نشر صوت فصل 🎧', 'نشر صوت فصل ' + (ix + 1) + ' اتوقف: بصمة الأجزاء المخزّنة لا تطابق بصمة التجهيز. لن يُعاد تلقائيًا.', 'ttspub' + nid + '#' + ix + '#' + st.ch_id); } catch (e2) {} return fail('بصمة الأجزاء لا تطابق التجهيز — النشر متوقف', 409); }
      const rb = await env.DB.batch([ // تبديل ذري: التبديل + إغلاق الجيل + سجل الإشعار في معاملة واحدة
        env.DB.prepare("UPDATE tts_ch SET id=?, parts=?, nparts=?, done=?, secs=?, fmt=?, status='done', owner='', lock_until=0, err='', updated=? WHERE id=? AND nid=? AND idx=? AND updated=?").bind(st.ch_id, st.parts, st.nparts, st.nparts, st.secs, isMp3 ? 'mp3' : 'wav', now, st.old_id, nid, ix, st.old_updated),
        env.DB.prepare("UPDATE tts_gen_stage SET status='published' WHERE nid=? AND idx=? AND ch_id=? AND status='publishing' AND EXISTS(SELECT 1 FROM tts_ch WHERE id=? AND nid=? AND idx=? AND status='done')").bind(nid, ix, st.ch_id, st.ch_id, nid, ix),
        env.DB.prepare("INSERT OR IGNORE INTO tts_notify_gen (nid,idx,ch_id,ts,res) SELECT ?,?,?,?,'' WHERE EXISTS(SELECT 1 FROM tts_ch WHERE id=? AND nid=? AND idx=?)").bind(nid, ix, st.ch_id, now, st.ch_id, nid, ix),
      ]);
      if (!(rb[0] && rb[0].meta && rb[0].meta.changes)) { await release('تغيّر متزامن أثناء الاعتماد'); return fail('الفصل اتغيّر أثناء الاعتماد — حدّث الصفحة وحاول تاني', 409); }
      let res = 'dup';
      if (rb[2] && rb[2].meta && rb[2].meta.changes) {
        const cl = await env.DB.prepare("UPDATE tts_notify_gen SET res='working' WHERE nid=? AND idx=? AND ch_id=? AND res=''").bind(nid, ix, st.ch_id).run(); // ادعاء قبل الاستدعاء الخارجي: التوقف بعد قبول المزوّد وقبل الكتابة النهائية يترك 'working' مرئيًا ولا يُعاد تلقائيًا
        if (cl && cl.meta && cl.meta.changes) {
          try { res = (await ttsDoneNotify(env, { ...cur, id: st.ch_id }, au)) || 'unknown'; } catch (e) { res = 'err:' + String(e && e.message || e).slice(0, 120); } // فشل مزوّد/غير معروف: يبقى مرئيًا في res ولا يُعاد تلقائيًا
          await env.DB.prepare("UPDATE tts_notify_gen SET res=? WHERE nid=? AND idx=? AND ch_id=? AND res='working'").bind(String(res), nid, ix, st.ch_id).run();
        } else res = 'unknown'; // الادعاء فشل لأن الصف working بالفعل: النتيجة غير معروفة لا «مُرسل سابقًا»
      } else { // الصف موجود مسبقًا: اعرض حالته الفعلية بدل «مُرسل سابقًا» المعمّمة
        const ng1 = await env.DB.prepare('SELECT res FROM tts_notify_gen WHERE nid=? AND idx=? AND ch_id=?').bind(nid, ix, st.ch_id).first();
        res = !ng1 || ng1.res === 'working' ? 'unknown' : (ng1.res === '' ? 'pending' : (/^err:/.test(String(ng1.res)) ? String(ng1.res) : 'dup'));
      }
      return json({ ok: true, published: st.ch_id, nparts: st.nparts, secs: st.secs, notify: res });
    }
    if (path === '/api/admin/tts/dllink' && m === 'POST') { // رابط تنزيل مؤقت (10 دقايق) لصوت فصل جاهز — أو لجيل جديد بانتظار اعتماد النشر (gen) لمراجعة الجودة قبل النشر
      const b = await body(request, 400), nid = str(b.nid, 80), ix = parseInt(b.idx, 10);
      const gen = Math.max(0, Math.floor(+b.gen || 0));
      if (gen) { const sq = await env.DB.prepare("SELECT 1 AS x FROM tts_gen_stage WHERE nid=? AND idx=? AND ch_id=? AND status='staged'").bind(nid, ix, gen).first(); if (!sq) return fail('الجيل ده مش متاح للمراجعة', 404); }
      else { const c = await env.DB.prepare("SELECT status FROM tts_ch WHERE nid=? AND idx=?").bind(nid, ix).first(); if (!c || c.status !== 'done') return fail('صوت الفصل ده لسه مش جاهز', 404); }
      const bd = b64u(enc.encode(JSON.stringify({ dl: nid, ix, g: gen || undefined, exp: Date.now() + 600000 })));
      const sg = await crypto.subtle.sign('HMAC', await getKey(env), enc.encode(bd));
      return json({ url: new URL(request.url).origin + '/api/tts/dl?k=' + encodeURIComponent(bd + '.' + b64u(sg)) });
    }
    if (path === '/api/admin/tts/ch' && m === 'POST') {
      const b = await body(request, 600), nid = str(b.nid, 80), ix = parseInt(b.idx, 10), op = String(b.op || '');
      const c = await env.DB.prepare('SELECT id,nparts,status FROM tts_ch WHERE nid=? AND idx=?').bind(nid, ix).first(); if (!c) return fail('الفصل مش في الطابور', 404);
      const wipe = async () => { if (env.TTS_BUCKET) { const ks = []; for (let i = 0; i < c.nparts; i++) ks.push('c/' + c.id + '/' + i + '.wav', 'c/' + c.id + '/' + i + '.mp3'); for (let i = 0; i < ks.length; i += 100) await env.TTS_BUCKET.delete(ks.slice(i, i + 100)); } };
      const now = Date.now();
      if (op === 'off') { await wipe(); await env.DB.prepare("UPDATE tts_ch SET status='off',done=0,secs=0,fmt='wav',owner='',lock_until=0,err='',updated=? WHERE id=?").bind(now, c.id).run(); }
      else if (op === 'on') await env.DB.prepare("UPDATE tts_ch SET status=CASE WHEN done>=nparts AND nparts>0 THEN 'done' ELSE 'queued' END,attempts=0,retry_at=0,err='',owner='',lock_until=0,updated=? WHERE id=?").bind(now, c.id).run();
      else if (op === 'redo') { await wipe(); await env.DB.prepare("UPDATE tts_ch SET status='queued',done=0,secs=0,sig='',attempts=0,retry_at=0,err='',owner='',lock_until=0,updated=? WHERE id=?").bind(now, c.id).run(); }
      else if (op === 'front') { const mn = await env.DB.prepare('SELECT COALESCE(MIN(ord),0) AS m FROM tts_ch').first(); await env.DB.prepare('UPDATE tts_ch SET ord=? WHERE id=?').bind(mn.m - 1, c.id).run(); }
      else if (op === 'end') { const mx = await env.DB.prepare('SELECT COALESCE(MAX(ord),0) AS m FROM tts_ch').first(); await env.DB.prepare('UPDATE tts_ch SET ord=? WHERE id=?').bind(mx.m + 1, c.id).run(); }
      else if (op === 'del') { await wipe(); await env.DB.prepare('DELETE FROM tts_ch WHERE id=?').bind(c.id).run(); }
      else return fail('عملية غير معروفة');
      return json({ ok: true, ...(await ttsStats(env)) });
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
    if (path === '/api/admin/tts/acct' && m === 'POST') { // إيقاف/تشغيل أداة (حساب) يدويًا: الموقوفة مبتاخدش فصول ومبتتحسبش في التوزيع
      const b = await body(request, 200), pv = PROVS.includes(b.prov) ? b.prov : null; if (!pv) return fail('حساب غير معروف');
      await setSetting(env, stKey(pv), { ...(await getSetting(env, stKey(pv))), manualOff: !!b.off });
      return json({ ok: true, ...(await ttsStats(env)) });
    }
    if (path === '/api/admin/tts/library' && m === 'GET') { // الروايات اللي فيها صوت جاهز
      const { results } = await env.DB.prepare("SELECT nid, MAX(ntitle) AS ntitle, COUNT(*) AS n, COALESCE(SUM(secs),0) AS secs, SUM(CASE WHEN fmt='mp3' THEN 1 ELSE 0 END) AS mp3 FROM tts_ch WHERE status='done' GROUP BY nid ORDER BY MAX(ntitle)").all();
      const kp = await ttsKeep(env, results);
      return json({ novels: results.map((r) => ({ ...r, keep: kp.has(r.nid) })), keepMissing: kp.missing });
    }
    if (path === '/api/admin/social' && m === 'GET') return json(await socConf(env));
    if (path === '/api/admin/social' && m === 'POST') {
      const b = await body(request, 600), g = str(b.google, 200).trim(), f = str(b.facebook, 40).trim();
      if (g && !/^[\w.-]+\.apps\.googleusercontent\.com$/.test(g)) return fail('Google Client ID شكله غلط (لازم ينتهي بـ apps.googleusercontent.com)');
      if (f && !/^\d{5,25}$/.test(f)) return fail('Facebook App ID لازم يكون أرقام بس');
      await setSetting(env, 'social', { google: g, facebook: f }); return json({ ok: true, google: g, facebook: f });
    }
    if (path === '/api/admin/tts/cxkey' && m === 'POST') { // مفتاح الضغط (للـGitHub Actions): الرابط#المفتاح — صالح سنة
      const bd = b64u(enc.encode(JSON.stringify({ cx: 1, exp: Date.now() + 365 * 86400000 })));
      const sg = await crypto.subtle.sign('HMAC', await getKey(env), enc.encode(bd));
      return json({ key: new URL(request.url).origin + '#' + bd + '.' + b64u(sg) });
    }
    if (path === '/api/admin/tts/keep' && m === 'POST') { // حماية/فكّ حماية رواية من المسح
      const b = await body(request, 300), nid = str(b.nid, 80); if (!nid) return fail('رواية غير محددة');
      const cur = await ttsKeep(env, []), set = new Set([...cur]); if (b.on) set.add(nid); else set.delete(nid);
      await setSetting(env, 'ttsKeep', { list: [...set] }); return json({ ok: true, keep: [...set] });
    }
    if (path === '/api/admin/tts/wipe' && m === 'POST') { // مسح تسجيلات رواية كاملة (أو فصول معيّنة) مع إخراج الفصول من الطابور (status=off) عشان متتحوّلش تاني
      const b = await body(request, 3000), nid = b.all ? '' : str(b.nid, 80), idxs = Array.isArray(b.idx) ? b.idx.map((x) => parseInt(x, 10)).filter((x) => x >= 0).slice(0, 200) : null;
      if (!b.all && !nid) return fail('رواية غير محددة');
      const kp = await ttsKeep(env, null);
      if (nid && kp.has(nid)) return fail('الرواية دي محمية من المسح. فُكّ الحماية الأول لو عايز تمسحها.');
      let q = "SELECT id,nparts FROM tts_ch WHERE status='done'", args = [];
      if (nid) { q += ' AND nid=?'; args.push(nid); }
      if (b.all && kp.size) { q += ' AND nid NOT IN (' + [...kp].map(() => '?').join(',') + ')'; args.push(...kp); }
      if (idxs && idxs.length) q += ' AND idx IN (' + idxs.map(() => '?').join(',') + ')', args.push(...idxs);
      const { results } = await env.DB.prepare(q + ' LIMIT 40').bind(...args).all();
      const keys = []; for (const c of results) for (let i = 0; i < c.nparts; i++) keys.push('c/' + c.id + '/' + i + '.wav', 'c/' + c.id + '/' + i + '.mp3');
      if (env.TTS_BUCKET) for (let i = 0; i < keys.length; i += 100) await env.TTS_BUCKET.delete(keys.slice(i, i + 100));
      const now = Date.now();
      if (results.length) await env.DB.batch(results.map((c) => env.DB.prepare("UPDATE tts_ch SET status='off',done=0,secs=0,fmt='wav',owner='',lock_until=0,err='',updated=? WHERE id=?").bind(now, c.id)));
      const left = (await env.DB.prepare(q.replace('SELECT id,nparts', 'SELECT COUNT(*) AS n')).bind(...args).first()).n;
      return json({ wiped: results.length, left });
    }
    if (path === '/api/admin/tts/remove' && m === 'POST') {
      const b = await body(request, 500), nid = str(b.nid, 80);
      if ((await ttsKeep(env, null)).has(nid)) return fail('الرواية دي محمية من المسح.');
      await ttsWipeNovel(env, nid);
      await env.DB.prepare('DELETE FROM tts_ch WHERE nid=?').bind(nid).run(); return json({ ok: true, ...(await ttsStats(env)) });
    }
    // تحديد المزوّد (جوجل / Azure) لرواية. redo = مسح الصوت الجاهز وتحويلها من الأول بالمزوّد ده
    if (path === '/api/admin/tts/provider' && m === 'POST') {
      const b = await body(request, 600), nid = str(b.nid, 80), prov = b.prov; if (!nid || !PROVS.includes(prov)) return fail('طلب غير صحيح');
      const conf = await getTtsConf(env), cur = await env.DB.prepare('SELECT prov FROM tts_ch WHERE nid=? LIMIT 1').bind(nid).first();
      const raw = await getSetting(env, 'tts'); await setSetting(env, 'tts', { ...raw, novelProv: { ...conf.novelProv, [nid]: prov } });
      if (cur && (cur.prov !== prov || b.redo) && (await ttsKeep(env, null)).has(nid)) return fail('الرواية دي محمية من المسح، فمش هينفع أعيد تحويلها.');
      if (cur && (cur.prov !== prov || b.redo)) {
        await ttsWipeNovel(env, nid);
        await env.DB.prepare("UPDATE tts_ch SET prov=?,sig='',done=0,secs=0,status='queued',owner='',lock_until=0,retry_at=0,attempts=0,err='',updated=? WHERE nid=? AND status!='off'").bind(prov, Date.now(), nid).run();
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
      if (!provReady({ ...env, TTS_BUCKET: env.TTS_BUCKET || {} }, conf, prov)) return fail(('مفتاح ' + PNAME[prov] + ' مش متسجّل — حطه من تابة الحساب ده'), 503);
      const text = str(b.text, 600).trim() || 'دخل أحمد الغرفة وقال بصوت هادي: «صباح الخير يا سلمى». ابتسمت سلمى وردت: «صباح النور يا أستاذ أحمد». ثم جرى الصغير نحوهما وقال بفرحة: «بابا، بابا، شوف الرسمة!»';
      const o = await speakPart(env, prov, text, conf), secs = Math.max(0, o.wav.length - 44) / 48000;
      await ttsBump(env, prov, { reqs: o.calls || 1, chars: o.chars, secs, cost: ttsCost(o.chars, secs, conf) });
      return audioResp(o.wav, false);
    }
    if (path === '/api/admin/tts/voices' && m === 'GET') {
      const prov = normProv(url.searchParams.get('prov')), conf = await getTtsConf(env), gkey = gemKey(env, prov);
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
    if (path === '/api/admin/wallet' && m === 'GET') return json({ ...(await walConf(env)), streak: await streakConf(env) });
    if (path === '/api/admin/wallet' && m === 'PUT') { const b = await body(request, 400), cur = await walConf(env); await setSetting(env, 'walcfg', { vote: b.vote ?? cur.vote, comment: b.comment ?? cur.comment, perDay: b.perDay ?? cur.perDay, premMult: b.premMult ?? cur.premMult }); return json({ ...(await walConf(env)), streak: await streakConf(env) }); }
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
      await setSetting(env, 'reads_epoch', { t: Date.now() }); globalThis.__reads = null;
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
    if (path === '/api/admin/rd/learn-audio' && m === 'POST') { // رفع ملف صوتي أو تسجيل → تعلّم نطق
      const b = await body(request, 6500000); const mime = /^audio\/[\w.+-]+$/.test(String(b.mime || '').split(';')[0]) ? String(b.mime).split(';')[0] : '';
      if (!mime || !b.audio || String(b.audio).length < 500) return fail('الملف الصوتي غير صالح', 400);
      const e2 = gemEnv(env, 'gemini'); let clean;
      try { clean = await rdLearnAudio(e2, String(b.audio), mime, String(b.word || '').slice(0, 40), String(b.text || '')); } catch (e) { return fail(String(e.message || e).slice(0, 160), 502); }
      const n = await rdLearnMerge(env, clean, b.word ? 'record' : 'audio');
      if (env.TTS_BUCKET && n) { try { await env.TTS_BUCKET.put('learn/' + Date.now() + '.' + mime.split('/')[1].replace(/[^a-z0-9]/g, ''), Uint8Array.from(atob(String(b.audio)), (c) => c.charCodeAt(0)), { httpMetadata: { contentType: mime } }); } catch (e) {} }
      return json({ n, words: clean });
    }
    if (path === '/api/admin/rd/learn-word' && m === 'POST') { const b = await body(request, 2000); const key = stripDiacritics(String(b.word || '')).trim(), v = String(b.pron || '').trim(); if (!key || /\s/.test(key) || stripDiacritics(v) !== key) return fail('التشكيل لازم يكون على نفس حروف الكلمة', 400); await rdLearnMerge(env, { [key]: v }, 'manual'); return json({ ok: true }); }
    if (path === '/api/admin/rd/learned' && m === 'GET') { const d = (await getSetting(env, 'rd_learned')) || {}, lg = (await getSetting(env, 'rd_learn_log')) || {}; const k = Object.keys(d); return json({ total: k.length, words: k.slice(-60).reverse().map((w) => [w, d[w]]), log: lg.items || [], stat: await getSetting(env, 'rd_learn_stat') }); }
    if (path === '/api/admin/rd/learned' && m === 'DELETE') { const b = await body(request, 2000); const d = (await getSetting(env, 'rd_learned')) || {}; delete d[String(b.word || '')]; await setSetting(env, 'rd_learned', d); RD_LEARN = d; return json({ ok: true }); }
    if (path === '/api/admin/rd/learned-export' && m === 'GET') { const d = (await getSetting(env, 'rd_learned')) || {}; return json({ total: Object.keys(d).length, words: d }); }
    if (path === '/api/admin/rd/learned-import' && m === 'POST') { const b = await body(request, 2000000), clean = {}; Object.entries((b && b.words) || {}).forEach(([k, v]) => { const key = stripDiacritics(String(k)); if (key && !/\s/.test(key) && typeof v === 'string' && v !== key && stripDiacritics(v) === key && v.length <= key.length * 2 + 4) clean[key] = v; }); const n = await rdLearnMerge(env, clean, 'import'); return json({ n }); }
    if (path === '/api/admin/vc/keys') { // مفاتيح مخصوصة لتابة «تحويل نص» بس (بتتبدّل تلقائي لو واحد اتزحم أو اتحظر)
      const cur = (((await getSetting(env, 'vc_keys')) || {}).list || []).filter((k) => typeof k === 'string');
      const mask = (k) => k.slice(0, 6) + '…' + k.slice(-4);
      if (m === 'GET') return json({ keys: cur.map(mask) });
      const b = await body(request, 4000);
      if (m === 'POST') { const add = String(b.keys || '').split(/[\s,;]+/).filter((k) => k.length > 15 && k.length < 120); const list = [...new Set([...cur, ...add])].slice(0, 30); await setSetting(env, 'vc_keys', { list }); return json({ keys: list.map(mask), added: list.length - cur.length }); }
      if (m === 'DELETE') { const i = parseInt(b.i, 10); if (!(i >= 0 && i < cur.length)) return fail('مفتاح غير موجود', 404); cur.splice(i, 1); await setSetting(env, 'vc_keys', { list: cur }); return json({ keys: cur.map(mask) }); }
    }
    if (path === '/api/admin/vc/voices' && m === 'GET') { const conf = await getTtsConf(env); RD_CF = conf.rd || RD_DEF; return json({ voices: RD_P.map((x) => { const q = rdPers(x.id); return { id: x.id, n: x.n, a: x.a, i: x.i, g: rdGen(x.id) }; }) }); }
    if (path === '/api/admin/vc/convert' && m === 'POST') { // تحويل نص حر بصوت شخصية واحدة — بيرجّع الصوت مباشرة وما بيتخزّنش في أي مكان
      const b = await body(request, 9000), conf = await getTtsConf(env); RD_CF = conf.rd || RD_DEF;
      const text = String(b.text || '').replace(/\r/g, '').trim().slice(0, 3000); if (text.replace(/\s/g, '').length < 2) return fail('اكتب النص الأول');
      const pr = rdPers(String(b.pid || 'kareem')), egy = b.mode !== 'msa';
      const vk = (((await getSetting(env, 'vc_keys')) || {}).list || []).filter((k) => String(k).length > 15);
      const sps = vk.length ? ['vc'] : PROVS.filter((x) => isGoogle(x) && gemKey(env, x)); if (!sps.length) return fail('مفيش مفتاح متسجّل — ضيف مفتاح من التابة نفسها', 503);
      const chunks = []; { let cur = ''; for (const piece of text.split(/(?<=[.!؟?…\n])\s*/)) { if (cur && (cur + piece).length > 450) { chunks.push(cur.trim()); cur = ''; } cur += piece + ' '; } if (cur.trim()) chunks.push(cur.trim()); }
      const ce = { ...conf, rd: { ...RD_CF, mode: egy ? 'A' : 'B' } }, narr = /^narrator/.test(pr.a);
      let lastErr = null;
      for (const sp of sps) { // لو مفتاح حساب بايظ (401/403) بنجرّب الحساب اللي بعده
        try {
          const out = new Array(chunks.length); let nx = 0;
          await Promise.all(Array.from({ length: Math.min(2, chunks.length) }, async () => { while (nx < chunks.length) { const i = nx++; out[i] = await rdSpeak(sp === 'vc' ? { ...env, GEMINI_API_KEY: vk.join(',') } : gemEnv(env, sp), { text: chunks[i], type: egy ? 'dialogue' : 'narration', emotionId: narr ? 'dramatic_narrator' : 'natural_dialogue' }, pr, ce); } }));
          const gap = new Int16Array(Math.round(24000 * 0.25)); let n = 0; out.forEach((q, i) => { n += q.length + (i ? gap.length : 0); });
          const all = new Int16Array(n); let o = 0; out.forEach((q, i) => { if (i) o += gap.length; all.set(q, o); o += q.length; });
          const wav = pcmToWav(new Uint8Array(all.buffer), 24000), secs = (wav.length - 44) / 48000;
          if (sp !== 'vc') { try { await ttsBump(env, sp, { reqs: chunks.length, chars: text.length, secs, cost: ttsCost(text.length, secs, conf) }); } catch (e) {} }
          return new Response(wav, { headers: { ...CORS, 'Content-Type': 'audio/wav', 'Cache-Control': 'no-store', 'X-Secs': String(Math.round(secs)) } });
        } catch (e) { lastErr = e; if (!/gemini_(401|403|429)/.test(String(e.message))) break; }
      }
      const em = String((lastErr && lastErr.message) || '');
      return fail(/gemini_40[13]/.test(em) ? 'مفتاح جوجل مرفوض (' + em + ') — بدّل/ضيف مفاتيح من خانة «مفاتيح التابة دي»' : (lastErr && (lastErr.detail || lastErr.message)) || 'فشل التحويل', (lastErr && lastErr.code) || 502);
    }
    if (path === '/api/admin/rd/sample' && m === 'POST') {
      const b = await body(request, 2000), conf = await getTtsConf(env); RD_CF = conf.rd || RD_DEF; const pr = rdPers(String(b.pid || 'kareem'));
      const SAM = { young_male: 'يا عم هو أنا قلتلك إيه؟ خلاص بقى، ماتقلقش، أنا هجيبه لحد عندك النهارده.', adult_male_dramatic: 'اسمعني كويس، اللي حصل مش هيعدي كده، وأنا مش هسكت.', elder_male: 'يا ابني الدنيا مش زي ما انت فاكر، والصبر ده حلو أوي.', adult_female: 'والله يا حبيبتي أنا مستنياكي من بدري، تعالي نقعد ونتكلم.', young_female: 'إيه ده بجد؟ مش مصدقة! تعالي بسرعة أحكيلك اللي حصل.', child: 'ماما، أنا جعان أوي، هو مفيش أكل؟', narrator_male: 'وفي تلك الليلة، هبّت الريح على المدينة، وكان كل شيء ينذر بما هو آتٍ.', narrator_female: 'وفي تلك الليلة، هبّت الريح على المدينة، وكان كل شيء ينذر بما هو آتٍ.' };
      const text = String(b.text || SAM[pr.a] || SAM.adult_male_dramatic).slice(0, 300), narr = /^narrator/.test(pr.a);
      try { const sp = PROVS.find((x) => isGoogle(x) && gemKey(env, x)) || 'gemini', pcm = await rdSpeak(gemEnv(env, sp), { text, type: narr ? 'narration' : 'dialogue', emotionId: 'natural_dialogue' }, pr, { ...conf, rd: RD_CF }); return new Response(pcmToWav(new Uint8Array(pcm.buffer, pcm.byteOffset, pcm.byteLength), 24000), { headers: { ...CORS, 'Content-Type': 'audio/wav', 'Cache-Control': 'no-store' } }); }
      catch (e) { return fail(e.detail || e.message || 'فشل', e.code || 502); }
    }
    if (path === '/api/admin/pubflow' && m === 'GET') return json({ conf: normPub(await getSetting(env, 'pubflow')), learn: await getSetting(env, 'rd_learn_stat') });
    if (path === '/api/admin/pubflow' && m === 'PUT') { const b = await body(request); const c = normPub(b); await setSetting(env, 'pubflow', c); return json({ conf: c }); }
    if ((g = /^\/api\/admin\/novels\/(\d+)\/narrator$/.exec(path))) { // جنس الراوي للرواية كلها: m = كريم، f = سلمى
      const n = await env.DB.prepare('SELECT user_id,l_extra,d_extra FROM novels WHERE id=?').bind(+g[1]).first(); if (!n) return fail('غير موجودة', 404);
      const nid = extraOf(n.l_extra).siteId || extraOf(n.d_extra).siteId || 'u' + g[1], k = 'rdnar_' + nid;
      if (m === 'GET') { const v = (await getSetting(env, k)).g; return json({ nid, g: v === 'f' || v === 'm' ? v : '' }); }
      if (m === 'PUT') { const b = await body(request); const v = b.g === 'f' ? 'f' : b.g === 'm' ? 'm' : ''; await setSetting(env, k, { g: v }); return json({ nid, g: v }); }
    }
    if (path === '/api/admin/engage' && m === 'GET') return json({ conf: normEng(await getSetting(env, 'engage')), tips: ENG_TIPS });
    if (path === '/api/admin/engage' && m === 'PUT') { const b = await body(request); const c = normEng(b); await setSetting(env, 'engage', c); return json({ conf: c }); }
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
