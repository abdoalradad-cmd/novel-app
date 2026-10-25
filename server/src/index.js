// RadPad API — Cloudflare Worker + D1. بدون أي مكتبات خارجية.
const ITER = 50000;               // عدد لفّات تشفير الباسورد
const TOKEN_DAYS = 30;
const LIM = { title: 120, author: 80, genre: 30, tag: 30, tags: 10, synopsis: 2000, cover: 600,
  chTitle: 150, chContent: 120000, chapters: 400, totalChars: 2500000, novelsPerUser: 30, body: 3200000 };
const enc = new TextEncoder();
let jwtKeyCache = null;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization,Content-Type',
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
  return env.DB.prepare('SELECT id,email,name,role FROM users WHERE id=?').bind(p.uid).first();
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
    return { title: str(c && c.title, LIM.chTitle).trim() || `الفصل ${i + 1}`, content };
  });
  if (total > LIM.totalChars) throw new Error('حجم النص كبير جدًا');
  return { title, author: str(b.author, LIM.author).trim(), genre: str(b.genre, LIM.genre).trim() || 'عام',
    tags, synopsis: str(b.synopsis, LIM.synopsis), cover: cleanUrl(b.cover), chapters: chs };
}
const parseTags = (s) => { try { const a = JSON.parse(s); return Array.isArray(a) ? a : []; } catch (e) { return []; } };

async function body(request) {
  const len = parseInt(request.headers.get('content-length') || '0', 10);
  if (len > LIM.body) throw new Error('الطلب كبير جدًا');
  const text = await request.text();
  if (text.length > LIM.body) throw new Error('الطلب كبير جدًا');
  try { return JSON.parse(text || '{}'); } catch (e) { throw new Error('بيانات غير صحيحة'); }
}

/* ---------- حفظ فصول المسودة ---------- */
function chapterStmts(env, id, ver, chs) {
  const del = env.DB.prepare('DELETE FROM chapters WHERE novel_id=? AND ver=?').bind(id, ver);
  const ins = chs.map((c, i) => env.DB.prepare('INSERT INTO chapters (novel_id,ver,idx,title,content) VALUES (?,?,?,?,?)').bind(id, ver, i, c.title, c.content));
  return [del, ...ins];
}
function myNovelRow(r) {
  return { id: r.id, status: r.status, isLive: !!r.is_live, rejectReason: r.reject_reason, updatedAt: r.updated_at, publishedAt: r.published_at,
    title: r.d_title, author: r.d_author, genre: r.d_genre, tags: parseTags(r.d_tags), synopsis: r.d_synopsis, cover: r.d_cover };
}

/* ---------- الراوتر ---------- */
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    try { return await route(request, env); }
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
    return json({ token: await makeToken(env, id), user: { id, email, name, role } });
  }
  if (path === '/api/login' && m === 'POST') {
    const b = await body(request);
    const email = str(b.email, 120).trim().toLowerCase();
    const key = 'login:' + email + ':' + ip;
    if (await tooMany(env, key, 10, 900000)) return fail('محاولات كتير، استنى ربع ساعة وجرّب تاني', 429);
    const u = await env.DB.prepare('SELECT id,email,name,role,pass_hash FROM users WHERE email=?').bind(email).first();
    if (!u || !(await checkPassword(String(b.password || ''), u.pass_hash))) { await noteAttempt(env, key); return fail('الإيميل أو الباسورد غلط', 401); }
    return json({ token: await makeToken(env, u.id), user: { id: u.id, email: u.email, name: u.name, role: u.role } });
  }

  /* ----- عام: الروايات المعتمدة ----- */
  if (path === '/api/novels' && m === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT n.id,n.l_title,n.l_author,n.l_genre,n.l_tags,n.l_synopsis,n.l_cover,n.published_at,u.name AS owner
       FROM novels n JOIN users u ON u.id=n.user_id WHERE n.is_live=1 ORDER BY n.published_at DESC LIMIT 500`).all();
    const chs = (await env.DB.prepare(
      `SELECT c.novel_id,c.idx,c.title FROM chapters c JOIN novels n ON n.id=c.novel_id WHERE n.is_live=1 AND c.ver='l' ORDER BY c.novel_id,c.idx`).all()).results;
    const byNovel = {};
    chs.forEach((c) => { (byNovel[c.novel_id] = byNovel[c.novel_id] || []).push({ title: c.title }); });
    return json({ novels: results.map((r) => ({ id: r.id, title: r.l_title, author: r.l_author || r.owner, genre: r.l_genre, tags: parseTags(r.l_tags),
      synopsis: r.l_synopsis, cover: r.l_cover, publishedAt: r.published_at, owner: r.owner, chapters: byNovel[r.id] || [] })) }, 200, { 'Cache-Control': 'public, max-age=60' });
  }
  if ((g = /^\/api\/novels\/(\d+)\/chapters\/(\d+)$/.exec(path)) && m === 'GET') {
    const c = await env.DB.prepare(`SELECT c.title,c.content FROM chapters c JOIN novels n ON n.id=c.novel_id WHERE n.id=? AND n.is_live=1 AND c.ver='l' AND c.idx=?`).bind(+g[1], +g[2]).first();
    return c ? json(c, 200, { 'Cache-Control': 'public, max-age=300' }) : fail('الفصل غير موجود', 404);
  }
  if ((g = /^\/api\/novels\/(\d+)\/full$/.exec(path)) && m === 'GET') {
    const n = await env.DB.prepare('SELECT id FROM novels WHERE id=? AND is_live=1').bind(+g[1]).first();
    if (!n) return fail('الرواية غير موجودة', 404);
    const { results } = await env.DB.prepare("SELECT title,content FROM chapters WHERE novel_id=? AND ver='l' ORDER BY idx").bind(+g[1]).all();
    return json({ chapters: results }, 200, { 'Cache-Control': 'public, max-age=300' });
  }

  /* ----- كل ما بعد كده يحتاج تسجيل دخول ----- */
  const user = await authUser(env, request);
  if (!user) return fail('سجّل الدخول الأول', 401);

  if (path === '/api/me' && m === 'GET') return json({ user });
  if (path === '/api/me' && m === 'PUT') {
    const b = await body(request), name = str(b.name, 40).trim();
    if (name.length < 2) return fail('اكتب اسمك (حرفين على الأقل)');
    await env.DB.prepare('UPDATE users SET name=? WHERE id=?').bind(name, user.id).run();
    return json({ user: { ...user, name } });
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
    const r = await env.DB.prepare('INSERT INTO novels (user_id,status,created_at,updated_at,d_title,d_author,d_genre,d_tags,d_synopsis,d_cover) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .bind(user.id, 'draft', now, now, n.title, n.author || user.name, n.genre, JSON.stringify(n.tags), n.synopsis, n.cover).run();
    const id = r.meta.last_row_id;
    await env.DB.batch(chapterStmts(env, id, 'd', n.chapters));
    return json({ id });
  }
  if ((g = /^\/api\/my\/novels\/(\d+)$/.exec(path))) {
    const id = +g[1];
    const row = await env.DB.prepare('SELECT * FROM novels WHERE id=? AND user_id=?').bind(id, user.id).first();
    if (!row) return fail('الرواية غير موجودة', 404);
    if (m === 'GET') {
      const { results } = await env.DB.prepare("SELECT title,content FROM chapters WHERE novel_id=? AND ver='d' ORDER BY idx").bind(id).all();
      return json({ novel: { ...myNovelRow(row), chapters: results } });
    }
    if (m === 'PUT') {
      const n = cleanNovel(await body(request));
      await env.DB.batch([
        env.DB.prepare("UPDATE novels SET d_title=?,d_author=?,d_genre=?,d_tags=?,d_synopsis=?,d_cover=?,updated_at=?,status=CASE WHEN status='pending' THEN 'pending' ELSE 'draft' END WHERE id=?")
          .bind(n.title, n.author || user.name, n.genre, JSON.stringify(n.tags), n.synopsis, n.cover, Date.now(), id),
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
      const { results } = await env.DB.prepare("SELECT title,content FROM chapters WHERE novel_id=? AND ver='d' ORDER BY idx").bind(+g[1]).all();
      return json({ novel: { ...myNovelRow(r), owner: r.owner, ownerEmail: r.owner_email, chapters: results } });
    }
    if ((g = /^\/api\/admin\/novels\/(\d+)\/approve$/.exec(path)) && m === 'POST') {
      const id = +g[1];
      const r = await env.DB.prepare('SELECT * FROM novels WHERE id=?').bind(id).first();
      if (!r) return fail('غير موجودة', 404);
      const now = Date.now();
      await env.DB.batch([
        env.DB.prepare('UPDATE novels SET l_title=d_title,l_author=d_author,l_genre=d_genre,l_tags=d_tags,l_synopsis=d_synopsis,l_cover=d_cover,is_live=1,status=?,reject_reason=?,published_at=COALESCE(published_at,?),updated_at=? WHERE id=?').bind('approved', '', now, now, id),
        env.DB.prepare("DELETE FROM chapters WHERE novel_id=? AND ver='l'").bind(id),
        env.DB.prepare("INSERT INTO chapters (novel_id,ver,idx,title,content) SELECT novel_id,'l',idx,title,content FROM chapters WHERE novel_id=? AND ver='d'").bind(id)]);
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
    if (path === '/api/admin/live' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT n.*,u.name AS owner FROM novels n JOIN users u ON u.id=n.user_id WHERE n.is_live=1 ORDER BY n.published_at DESC').all();
      return json({ novels: results.map((r) => ({ ...myNovelRow(r), owner: r.owner, title: r.l_title })) });
    }
  }
  return fail('غير موجود', 404);
}
  
