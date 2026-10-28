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
  'Access-Control-Allow-Headers': 'Authorization,Content-Type,X-Unlock',
  'Access-Control-Max-Age': '86400'
};
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS, ...extra } });
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
async function authUser(env, request) {
  const h = request.headers.get('Authorization') || '';
  const m = /^Bearer (.+)$/.exec(h); if (!m) return null;
  const p = await readToken(env, m[1]); if (!p) return null;
  return env.DB.prepare('SELECT id,email,name,role,premium_until,avatar,bio FROM users WHERE id=?').bind(p.uid).first();
}
const FOREVER = 32503680000000;
const isPremium = (u) => !!u && (u.role === 'admin' || (u.premium_until || 0) > Date.now());
const userOut = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, premium: isPremium(u), premiumUntil: u.role === 'admin' ? FOREVER : (u.premium_until || 0), avatar: u.avatar || '', bio: u.bio || '' });

/* ---------- ترقية القاعدة تلقائيًا (للقواعد القديمة) ---------- */
let migrated = false;
async function ensureSchema(env) {
  if (migrated) return;
  const need = [['novels', 'd_extra'], ['novels', 'l_extra'], ['chapters', 'locked'], ['users', 'premium_until'], ['users', 'avatar'], ['users', 'bio']];
  for (const [t, c] of need) {
    try { await env.DB.prepare(`SELECT ${c} FROM ${t} LIMIT 1`).first(); }
    catch (e) {
      const def = (c === 'locked' || c === 'premium_until') ? 'INTEGER NOT NULL DEFAULT 0' : (c === 'avatar' || c === 'bio') ? "TEXT NOT NULL DEFAULT ''" : "TEXT NOT NULL DEFAULT '{}'";
      await env.DB.prepare(`ALTER TABLE ${t} ADD COLUMN ${c} ${def}`).run();
    }
  }
  for (const q of ['CREATE TABLE IF NOT EXISTS follows (follower_id INTEGER NOT NULL, author_id INTEGER NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (follower_id, author_id))',
    'CREATE INDEX IF NOT EXISTS idx_follows_author ON follows(author_id)',
    'CREATE TABLE IF NOT EXISTS reads (k TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)',
    'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, author_id INTEGER NOT NULL, kind TEXT NOT NULL, novel_id INTEGER NOT NULL, title TEXT NOT NULL, ts INTEGER NOT NULL)',
    'CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)']) await env.DB.prepare(q).run();
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
  if (request.headers.get('Authorization')) { const u = await authUser(env, request); if (isPremium(u)) return true; }
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
    return { title: str(c && c.title, LIM.chTitle).trim() || `الفصل ${i + 1}`, content, locked: c && c.locked ? 1 : 0 };
  });
  if (total > LIM.totalChars) throw new Error('حجم النص كبير جدًا');
  const password = str(b.password, LIM.pass).trim();
  const lockAll = !!b.lockAll, anyLocked = chs.some((c) => c.locked);
  if ((lockAll || anyLocked) && !password) throw new Error('اكتب باسورد القفل أو شيل القفل');
  const extra = { subtitle: str(b.subtitle, LIM.subtitle).trim(), novelStatus: b.novelStatus === 'مكتملة' ? 'مكتملة' : 'مستمرة',
    promoUrl: cleanUrl(b.promoUrl), pdfUrl: cleanUrl(b.pdfUrl), grad: GRADS.includes(b.grad) ? b.grad : GRADS[0],
    icon: ICONS.includes(b.icon) ? b.icon : 'fa-book', allowSharing: b.allowSharing !== false, password, lockAll, lockPdf: b.lockPdf !== false };
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
function extraOf(raw) {
  const x = parseJson(raw);
  return { subtitle: x.subtitle || '', novelStatus: x.novelStatus || 'مستمرة', promoUrl: x.promoUrl || '', pdfUrl: x.pdfUrl || '', grad: GRADS.includes(x.grad) ? x.grad : GRADS[0],
    icon: ICONS.includes(x.icon) ? x.icon : 'fa-book', allowSharing: x.allowSharing !== false, password: x.password || '', lockAll: !!x.lockAll, lockPdf: x.lockPdf !== false };
}
function myNovelRow(r) {
  return { id: r.id, status: r.status, isLive: !!r.is_live, rejectReason: r.reject_reason, updatedAt: r.updated_at, publishedAt: r.published_at,
    title: r.d_title, author: r.d_author, genre: r.d_genre, tags: parseTags(r.d_tags), synopsis: r.d_synopsis, cover: r.d_cover, ...extraOf(r.d_extra) };
}
function liveNovelRow(r) {
  return { id: r.id, status: r.status, isLive: !!r.is_live, publishedAt: r.published_at, updatedAt: r.updated_at,
    title: r.l_title, author: r.l_author, genre: r.l_genre, tags: parseTags(r.l_tags), synopsis: r.l_synopsis, cover: r.l_cover, ...extraOf(r.l_extra) };
}

/* ---------- إعدادات Premium (واتساب + الأسعار) ---------- */
async function getSetting(env, k) { const r = await env.DB.prepare('SELECT v FROM settings WHERE k=?').bind(k).first(); return r ? parseJson(r.v) : {}; }
const setSetting = (env, k, v) => env.DB.prepare('INSERT INTO settings (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').bind(k, JSON.stringify(v)).run();
async function getPremiumInfo(env) {
  const x = await getSetting(env, 'premium');
  return { whatsapp: x.whatsapp || '01067567795', defaultPrice: x.defaultPrice || '', message: x.message || '', prices: x.prices && typeof x.prices === 'object' ? x.prices : {} };
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
    try { await ensureSchema(env); return await route(request, env); }
    catch (e) { return fail(e && e.message ? e.message : 'خطأ غير متوقع', e && e.status ? e.status : 400); }
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
    if (await env.DB.prepare('SELECT 1 FROM users WHERE email=?').bind(email).first()) return fail('الإيميل ده مسجّل قبل كده');
    await noteAttempt(env, 'reg:' + ip);
    const count = (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n;
    const role = count === 0 ? 'admin' : 'user';           // أول حساب = الأدمن
    const r = await env.DB.prepare('INSERT INTO users (email,name,pass_hash,role,created_at) VALUES (?,?,?,?,?)')
      .bind(email, name, await hashPassword(pass), role, Date.now()).run();
    const id = r.meta.last_row_id;
    return json({ token: await makeToken(env, id), user: userOut({ id, email, name, role, premium_until: 0 }) });
  }
  if (path === '/api/login' && m === 'POST') {
    const b = await body(request);
    const email = str(b.email, 120).trim().toLowerCase();
    const key = 'login:' + email + ':' + ip;
    if (await tooMany(env, key, 10, 900000)) return fail('محاولات كتير، استنى ربع ساعة وجرّب تاني', 429);
    const u = await env.DB.prepare('SELECT id,email,name,role,pass_hash,premium_until,avatar,bio FROM users WHERE email=?').bind(email).first();
    if (!u || !(await checkPassword(String(b.password || ''), u.pass_hash))) { await noteAttempt(env, key); return fail('الإيميل أو الباسورد غلط', 401); }
    return json({ token: await makeToken(env, u.id), user: userOut(u) });
  }

  /* ----- عام: الروايات المعتمدة ----- */
  if (path === '/api/novels' && m === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT n.id,n.user_id,n.l_title,n.l_author,n.l_genre,n.l_tags,n.l_synopsis,n.l_cover,n.l_extra,n.published_at,u.name AS owner
       FROM novels n JOIN users u ON u.id=n.user_id WHERE n.is_live=1 ORDER BY n.published_at DESC LIMIT 500`).all();
    const chs = (await env.DB.prepare(
      `SELECT c.novel_id,c.idx,c.title,c.locked FROM chapters c JOIN novels n ON n.id=c.novel_id WHERE n.is_live=1 AND c.ver='l' ORDER BY c.novel_id,c.idx`).all()).results;
    const byNovel = {};
    const chapLocked = {};
    chs.forEach((c) => { (byNovel[c.novel_id] = byNovel[c.novel_id] || []).push({ title: c.title, locked: !!c.locked }); if (c.locked) chapLocked[c.novel_id] = true; });
    return json({ novels: results.map((r) => {
      const x = extraOf(r.l_extra);
      return { id: r.id, title: r.l_title, subtitle: x.subtitle, author: r.l_author || r.owner, genre: r.l_genre, tags: parseTags(r.l_tags),
        synopsis: r.l_synopsis, cover: r.l_cover, novelStatus: x.novelStatus, promoUrl: x.promoUrl, pdfUrl: x.pdfUrl, grad: x.grad, icon: x.icon, allowSharing: x.allowSharing, locked: !!(x.lockAll && x.password), pdfLocked: !!(x.password && x.lockPdf && (x.lockAll || chapLocked[r.id])),
        publishedAt: r.published_at, owner: r.owner, uid: r.user_id, chapters: byNovel[r.id] || [] };
    }) }, 200, { 'Cache-Control': 'public, max-age=60' });
  }
  if ((g = /^\/api\/novels\/(\d+)\/unlock$/.exec(path)) && m === 'POST') {
    const id = +g[1], key = 'unl:' + ip + ':' + id;
    if (await tooMany(env, key, 10, 900000)) return fail('محاولات كتير، استنى شوية وجرّب تاني', 429);
    const b = await body(request);
    const n = await env.DB.prepare('SELECT l_extra FROM novels WHERE id=? AND is_live=1').bind(id).first();
    if (!n) return fail('الرواية غير موجودة', 404);
    const x = extraOf(n.l_extra);
    if (!x.password || !safeEqual(String(b.password || '').trim(), x.password)) { await noteAttempt(env, key); return fail('الباسورد غلط', 401); }
    return json({ token: await makeUnlock(env, id) });
  }
  if ((g = /^\/api\/novels\/(\d+)\/chapters\/(\d+)$/.exec(path)) && m === 'GET') {
    const n = await env.DB.prepare('SELECT l_extra FROM novels WHERE id=? AND is_live=1').bind(+g[1]).first();
    if (!n) return fail('الفصل غير موجود', 404);
    const c = await env.DB.prepare(`SELECT title,content,locked FROM chapters WHERE novel_id=? AND ver='l' AND idx=?`).bind(+g[1], +g[2]).first();
    if (!c) return fail('الفصل غير موجود', 404);
    const x = extraOf(n.l_extra);
    if (x.password && (x.lockAll || c.locked) && !(await hasUnlock(env, request, +g[1]))) return fail('الفصل مقفول — اكتب الباسورد', 403);
    const locked = !!(x.password && (x.lockAll || c.locked));
    return json({ title: c.title, content: c.content }, 200, { 'Cache-Control': locked ? 'private, no-store' : 'public, max-age=300' });
  }
  if ((g = /^\/api\/novels\/(\d+)\/full$/.exec(path)) && m === 'GET') {
    const n = await env.DB.prepare('SELECT l_extra FROM novels WHERE id=? AND is_live=1').bind(+g[1]).first();
    if (!n) return fail('الرواية غير موجودة', 404);
    const x = extraOf(n.l_extra);
    const open = !x.password || await hasUnlock(env, request, +g[1]);
    const { results } = await env.DB.prepare("SELECT title,content,locked FROM chapters WHERE novel_id=? AND ver='l' ORDER BY idx").bind(+g[1]).all();
    const chapters = results.map((c) => (open || !(x.lockAll || c.locked)) ? { title: c.title, content: c.content } : { title: c.title, content: '', locked: true });
    return json({ chapters }, 200, { 'Cache-Control': x.password ? 'private, no-store' : 'public, max-age=300' });
  }

  if (path === '/api/reads' && m === 'GET') {
    const { results } = await env.DB.prepare('SELECT k,n FROM reads ORDER BY n DESC LIMIT 300').all();
    const o = {}; results.forEach((r) => { o[r.k] = r.n; });
    return json({ reads: o }, 200, { 'Cache-Control': 'public, max-age=60' });
  }
  if (path === '/api/reads' && m === 'POST') {
    const b = await body(request, 2000), k = str(b.k, 60);
    if (!/^[A-Za-z0-9_-]{1,60}$/.test(k)) return fail('مفتاح غير صحيح');
    if (await tooMany(env, 'rd:' + ip + ':' + k, 1, 6 * 3600000) || await tooMany(env, 'rdip:' + ip, 40, 3600000)) return json({ ok: true, skipped: true });
    await noteAttempt(env, 'rd:' + ip + ':' + k); await noteAttempt(env, 'rdip:' + ip);
    await env.DB.prepare('INSERT INTO reads (k,n) VALUES (?,1) ON CONFLICT(k) DO UPDATE SET n=n+1').bind(k).run();
    return json({ ok: true });
  }
  if ((g = /^\/api\/authors\/(\d+|admin)$/.exec(path)) && m === 'GET') {
    let aid;
    if (g[1] === 'admin') { const a = await env.DB.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").first(); if (!a) return fail('غير موجود', 404); aid = a.id; } else aid = +g[1];
    const a = await env.DB.prepare('SELECT id,name,role,avatar,bio,created_at FROM users WHERE id=?').bind(aid).first();
    if (!a) return fail('الكاتب غير موجود', 404);
    const isAdm = a.role === 'admin';
    const followers = isAdm ? Math.max(0, (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n - 1) : (await env.DB.prepare('SELECT COUNT(*) AS n FROM follows WHERE author_id=?').bind(aid).first()).n;
    const { results } = await env.DB.prepare('SELECT n.id,n.l_title,n.l_author,n.l_genre,n.l_cover,n.l_extra,n.published_at FROM novels n WHERE n.user_id=? AND n.is_live=1 ORDER BY n.published_at DESC').bind(aid).all();
    let me = null, following = false;
    if (request.headers.get('Authorization')) { me = await authUser(env, request); }
    if (me) following = isAdm ? me.id !== aid : !!(await env.DB.prepare('SELECT 1 FROM follows WHERE follower_id=? AND author_id=?').bind(me.id, aid).first());
    return json({ author: { id: a.id, name: a.name, bio: a.bio, avatar: a.avatar, isAdmin: isAdm, joinedAt: a.created_at, followers, following, self: !!(me && me.id === aid),
      novels: results.map((r) => { const x = extraOf(r.l_extra); return { id: r.id, title: r.l_title, author: r.l_author || a.name, genre: r.l_genre, cover: r.l_cover, grad: x.grad, icon: x.icon, locked: !!(x.lockAll && x.password), publishedAt: r.published_at }; }) } }, 200, { 'Cache-Control': 'private, no-store' });
  }
  if (path === '/api/premium-info' && m === 'GET') return json({ info: await getPremiumInfo(env) }, 200, { 'Cache-Control': 'public, max-age=30' });

  /* ----- كل ما بعد كده يحتاج تسجيل دخول ----- */
  const user = await authUser(env, request);
  if (!user) return fail('سجّل الدخول الأول', 401);

  if (path === '/api/me' && m === 'GET') return json({ user: userOut(user) });
  if (path === '/api/me' && m === 'PUT') {
    const b = await body(request), name = b.name === undefined ? user.name : str(b.name, 40).trim();
    if (name.length < 2) return fail('اكتب اسمك (حرفين على الأقل)');
    const bio = b.bio === undefined ? user.bio : str(b.bio, 300).trim();
    const avatar = b.avatar === undefined ? user.avatar : cleanUrl(b.avatar);
    await env.DB.prepare('UPDATE users SET name=?,bio=?,avatar=? WHERE id=?').bind(name, bio, avatar, user.id).run();
    return json({ user: userOut({ ...user, name, bio, avatar }) });
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
    if (a.role === 'admin') return fail('متابعة صفحة الأدمن تلقائية ومينفعش تتلغي');
    if (m === 'POST') await env.DB.prepare('INSERT OR IGNORE INTO follows (follower_id,author_id,ts) VALUES (?,?,?)').bind(user.id, aid, Date.now()).run();
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
    return json({ items: results.map((e) => ({ id: e.id, kind: e.kind, authorId: e.author_id, author: e.author, novelId: e.novel_id, title: e.title, ts: e.ts })) });
  }
  if (path === '/api/premium/keys' && m === 'GET') {
    if (!isPremium(user)) return fail('للمشتركين فقط', 403);
    const v = await getSetting(env, 'vault');
    return json({ keys: v.keys || {} }, 200, { 'Cache-Control': 'private, no-store' });
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
      return json({ novel: { ...myNovelRow(row), chapters: results.map((c) => ({ title: c.title, content: c.content, locked: !!c.locked })) } });
    }
    if (m === 'PUT') {
      const n = cleanNovel(await body(request));
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
    await env.DB.prepare("UPDATE novels SET status='pending',reject_reason='',updated_at=? WHERE id=?").bind(Date.now(), id).run();
    return json({ ok: true });
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
      return json({ novel: { ...myNovelRow(r), owner: r.owner, ownerEmail: r.owner_email, chapters: results.map((c) => ({ title: c.title, content: c.content, locked: !!c.locked })) } });
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
      try {
        const newCnt = (await env.DB.prepare("SELECT COUNT(*) AS n FROM chapters WHERE novel_id=? AND ver='l'").bind(id).first()).n;
        const kind = !r.is_live ? 'novel' : (newCnt > oldCnt ? 'chapter' : '');
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
        users: ['id', 'email', 'name', 'pass_hash', 'role', 'created_at', 'premium_until', 'avatar', 'bio'],
        novels: ['id', 'user_id', 'status', 'is_live', 'reject_reason', 'created_at', 'updated_at', 'published_at', 'd_title', 'd_author', 'd_genre', 'd_tags', 'd_synopsis', 'd_cover', 'd_extra', 'l_title', 'l_author', 'l_genre', 'l_tags', 'l_synopsis', 'l_cover', 'l_extra'],
        chapters: ['novel_id', 'ver', 'idx', 'title', 'content', 'locked'],
        follows: ['follower_id', 'author_id', 'ts'],
        reads: ['k', 'n']
      };
      const dflt = { d_extra: '{}', l_extra: '{}', locked: 0, premium_until: 0, avatar: '', bio: '', ts: 0, n: 0 };
      const stmts = [];
      for (const t of ['users', 'novels', 'chapters', 'follows', 'reads']) {
        if (!Array.isArray(b[t])) continue;
        const c = cols[t], q = `INSERT OR REPLACE INTO ${t} (${c.join(',')}) VALUES (${c.map(() => '?').join(',')})`;
        for (const row of b[t]) stmts.push(env.DB.prepare(q).bind(...c.map((k) => (row[k] === undefined || row[k] === null ? (k in dflt ? dflt[k] : null) : row[k]))));
      }
      for (let i = 0; i < stmts.length; i += 40) await env.DB.batch(stmts.slice(i, i + 40));
      return json({ ok: true, users: b.users.length, novels: b.novels.length, chapters: b.chapters.length });
    }
    if (path === '/api/admin/premium' && m === 'PUT') {
      const b = await body(request, 200000), prices = {};
      Object.keys(b.prices || {}).slice(0, 1000).forEach((k) => { const v = str(b.prices[k], 60).trim(); if (v) prices[str(k, 60)] = v; });
      await setSetting(env, 'premium', { whatsapp: str(b.whatsapp, 25).replace(/[^0-9+]/g, ''), defaultPrice: str(b.defaultPrice, 60).trim(), message: str(b.message, 300).trim(), prices });
      return json({ ok: true, info: await getPremiumInfo(env) });
    }
    if (path === '/api/admin/vault' && m === 'PUT') {
      const b = await body(request, 2000000), keys = {};
      Object.keys(b.keys || {}).slice(0, 2000).forEach((id) => {
        const k = b.keys[id] || {}, c = {};
        Object.keys(k.c || {}).slice(0, 500).forEach((i) => { c[str(i, 6)] = str(k.c[i], 80); });
        keys[str(id, 60)] = { n: str(k.n, 80), p: str(k.p, 80), c };
      });
      await setSetting(env, 'vault', { keys, at: Date.now() });
      return json({ ok: true, count: Object.keys(keys).length });
    }
    if (path === '/api/admin/push' && m === 'POST') {
      const b = await body(request, 20000);
      await sendPush(env, str(b.title, 80).trim(), str(b.text, 300).trim(), cleanUrl(b.url));
      return json({ ok: true });
    }
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
    if (path === '/api/admin/users' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT u.id,u.email,u.name,u.role,u.created_at,u.premium_until,(SELECT COUNT(*) FROM novels n WHERE n.user_id=u.id) AS novels FROM users u ORDER BY u.id DESC LIMIT 1000').all();
      return json({ users: results.map((u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, createdAt: u.created_at, premiumUntil: u.premium_until || 0, premium: isPremium(u), novels: u.novels })) });
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
      return json({ novel: { ...liveNovelRow(r), owner: r.owner, chapters: results.map((c) => ({ title: c.title, content: c.content, locked: !!c.locked })) } });
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
