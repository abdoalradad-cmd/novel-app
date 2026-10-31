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
  return env.DB.prepare('SELECT id,email,name,role,premium_until,avatar,bio,links FROM users WHERE id=?').bind(p.uid).first();
}
const linksOf = (v) => { let o = {}; try { o = typeof v === 'string' ? JSON.parse(v || '{}') : (v || {}); } catch (e) {} const out = {}; for (const k of ['facebook', 'wattpad', 'youtube']) out[k] = (typeof o[k] === 'string') ? cleanUrl(o[k]) : ''; return out; };
const FOREVER = 32503680000000;
const isPremium = (u) => !!u && (u.role === 'admin' || (u.premium_until || 0) > Date.now());
const userOut = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role, premium: isPremium(u), premiumUntil: u.role === 'admin' ? FOREVER : (u.premium_until || 0), avatar: u.avatar || '', bio: u.bio || '', links: linksOf(u.links) });

/* ---------- ترقية القاعدة تلقائيًا (للقواعد القديمة) ---------- */
let migrated = false;
async function ensureSchema(env) {
  if (migrated) return;
  const need = [['novels', 'd_extra'], ['novels', 'l_extra'], ['chapters', 'locked'], ['users', 'premium_until'], ['users', 'avatar'], ['users', 'bio'], ['users', 'links'], ['novels', 'hidden']];
  for (const [t, c] of need) {
    try { await env.DB.prepare(`SELECT ${c} FROM ${t} LIMIT 1`).first(); }
    catch (e) {
      const def = (c === 'locked' || c === 'premium_until' || c === 'hidden') ? 'INTEGER NOT NULL DEFAULT 0' : (c === 'avatar' || c === 'bio') ? "TEXT NOT NULL DEFAULT ''" : "TEXT NOT NULL DEFAULT '{}'";
      await env.DB.prepare(`ALTER TABLE ${t} ADD COLUMN ${c} ${def}`).run();
    }
  }
  for (const q of ['CREATE TABLE IF NOT EXISTS follows (follower_id INTEGER NOT NULL, author_id INTEGER NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (follower_id, author_id))',
    'CREATE INDEX IF NOT EXISTS idx_follows_author ON follows(author_id)',
    'CREATE TABLE IF NOT EXISTS reads (k TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)',
    'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, author_id INTEGER NOT NULL, kind TEXT NOT NULL, novel_id INTEGER NOT NULL, title TEXT NOT NULL, ts INTEGER NOT NULL)',
    'CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)',
    'CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER NOT NULL, kind TEXT NOT NULL, novel_ref TEXT NOT NULL, who TEXT NOT NULL, title TEXT NOT NULL, text TEXT NOT NULL, ts INTEGER NOT NULL)',
    'CREATE INDEX IF NOT EXISTS idx_notes_uid ON notes(uid, ts)',
    'CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, plan_id TEXT NOT NULL, plan_name TEXT NOT NULL, months INTEGER NOT NULL, amount TEXT NOT NULL, method TEXT NOT NULL, sender TEXT NOT NULL, proof TEXT NOT NULL, note TEXT NOT NULL DEFAULT \'\', status TEXT NOT NULL DEFAULT \'pending\', reason TEXT NOT NULL DEFAULT \'\', created_at INTEGER NOT NULL, decided_at INTEGER NOT NULL DEFAULT 0)',
    'CREATE INDEX IF NOT EXISTS idx_pay_user ON payments(user_id, created_at)',
    'CREATE INDEX IF NOT EXISTS idx_pay_status ON payments(status, created_at)',
    "CREATE TABLE IF NOT EXISTS tts_ch (id INTEGER PRIMARY KEY AUTOINCREMENT, nid TEXT NOT NULL, idx INTEGER NOT NULL, ntitle TEXT NOT NULL DEFAULT '', ctitle TEXT NOT NULL DEFAULT '', ord INTEGER NOT NULL DEFAULT 0, sig TEXT NOT NULL DEFAULT '', text TEXT NOT NULL, parts TEXT NOT NULL DEFAULT '[]', nparts INTEGER NOT NULL DEFAULT 0, done INTEGER NOT NULL DEFAULT 0, secs REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued', owner TEXT NOT NULL DEFAULT '', lock_until INTEGER NOT NULL DEFAULT 0, retry_at INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, err TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL DEFAULT 0)",
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_tts_ch_key ON tts_ch(nid, idx)',
    'CREATE INDEX IF NOT EXISTS idx_tts_ch_q ON tts_ch(status, ord)',
    'CREATE TABLE IF NOT EXISTS tts_usage (day TEXT PRIMARY KEY, reqs INTEGER NOT NULL DEFAULT 0, hits INTEGER NOT NULL DEFAULT 0, chars INTEGER NOT NULL DEFAULT 0, secs REAL NOT NULL DEFAULT 0, cost REAL NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, limited INTEGER NOT NULL DEFAULT 0)']) await env.DB.prepare(q).run();
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
    plans: cleanPlans(x.plans), methods: cleanMethods(x.methods, x.whatsapp) };
}


/* ---------- الصوت المصري (Gemini TTS): طابور بأولويات + تخزين R2 + متابعة التكلفة ---------- */
const TTS_DEFAULT = { model: 'gemini-3.8-flash-tts', legacyModel: 'gemini-2.5-flash-preview-tts', voice: 'Kore', style: 'warm, expressive audiobook narration in natural Egyptian Arabic', concurrency: 2, dailyMin: 20, freeMin: 0, priceIn: 0, priceOut: 0 };
async function getTtsConf(env) {
  const x = await getSetting(env, 'tts'), n = (v, d, lo, hi) => { const k = Number(v); return v !== '' && v != null && Number.isFinite(k) && k >= lo && k <= hi ? k : d; };
  return { model: x.model || TTS_DEFAULT.model, legacyModel: x.legacyModel || TTS_DEFAULT.legacyModel, voice: x.voice || TTS_DEFAULT.voice, style: x.style || TTS_DEFAULT.style,
    concurrency: n(x.concurrency, TTS_DEFAULT.concurrency, 1, 4), dailyMin: n(x.dailyMin, TTS_DEFAULT.dailyMin, 0, 100000), freeMin: n(x.freeMin, 0, 0, 100000), priceIn: n(x.priceIn, 0, 0, 1000), priceOut: n(x.priceOut, 0, 0, 1000) };
}
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
async function geminiSpeak(env, text, voiceName, conf) {
  const key = env.GEMINI_API_KEY; if (!key) { const e = new Error('not_configured'); e.code = 503; throw e; }
  let lastErr;
  try {
    const r = await fetch('https://generativelanguage.googleapis.com/v1beta/interactions', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
      body: JSON.stringify({ model: conf.model, input: [{ type: 'user_input', content: [{ type: 'text', text, annotations: [{ type: 'speech_metadata', style: conf.style }] }] }], response_format: { type: 'audio' }, generation_config: { speech_config: [{ voice: voiceName }] } }) });
    if (r.status === 429) { const e = new Error('busy'); e.code = 429; throw e; }
    if (r.ok) { const j = await r.json(); const b = findAudioB64(j); if (b) return toWav(b); lastErr = new Error('no_audio'); } else lastErr = new Error('gemini_' + r.status);
  } catch (e) { if (e.code === 429) throw e; lastErr = e; }
  const r2 = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + conf.legacyModel + ':generateContent', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
    body: JSON.stringify({ contents: [{ parts: [{ text: 'Read the following in a ' + conf.style + ': ' + text }] }], generationConfig: { responseModalities: ['AUDIO'], speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName } } } } }) });
  if (r2.status === 429) { const e = new Error('busy'); e.code = 429; throw e; }
  if (!r2.ok) { const e = new Error('gemini_' + r2.status); e.code = 502; e.detail = lastErr && lastErr.message; throw e; }
  const b2 = findAudioB64(await r2.json()); if (!b2) { const e = new Error('no_audio'); e.code = 502; throw e; }
  return toWav(b2);
}
const audioResp = (obj, hit) => new Response(obj.body || obj, { status: 200, headers: { ...CORS, 'Content-Type': 'audio/wav', 'Cache-Control': 'private, max-age=86400', 'X-Cache': hit ? 'HIT' : 'MISS' } });
const CPS = 14; // حروف في الثانية تقريبًا (لتقدير المدة والتكلفة قبل التحويل)
const hasLetters = (t) => /[؀-ۿA-Za-z0-9]/.test(t);
// يقسّم نص الفصل لأجزاء (≤700 حرف) على حدود الفقرات/الجمل. بيرجّع [[بداية،نهاية]] بالنسبة للنص الأصلي
function splitParts(text) {
  const out = [], push = (a, b) => { if (b > a && hasLetters(text.slice(a, b))) out.push([a, b]); };
  let a = -1, prevEnd = 0, pos = 0;
  const flush = () => { if (a >= 0) push(a, prevEnd); a = -1; };
  for (const line of text.split('\n')) {
    const ls = pos, le = pos + line.length; pos = le + 1;
    if (!line.trim()) continue;
    if (line.length > 700) {
      flush();
      let cur = -1, curEnd = 0; const re = /[^.!؟?؛;:]+[.!؟?؛;:]*/g; let m;
      while ((m = re.exec(line))) {
        let ms = ls + m.index; const me = ms + m[0].length;
        while (me - ms > 700) { let cut = line.lastIndexOf(' ', ms - ls + 700); cut = cut > ms - ls + 200 ? ls + cut : ms + 700; if (cur >= 0) { push(cur, curEnd); cur = -1; } push(ms, cut); ms = cut; }
        if (cur >= 0 && me - cur > 700) { push(cur, curEnd); cur = -1; }
        if (cur < 0) cur = ms; curEnd = me;
      }
      if (cur >= 0) push(cur, curEnd);
      continue;
    }
    if (a >= 0 && le - a > 700) flush();
    if (a < 0) a = ls;
    prevEnd = le;
  }
  flush(); return out;
}
async function ttsBump(env, cols) {
  const d = dayKey();
  await env.DB.prepare('INSERT INTO tts_usage (day) VALUES (?) ON CONFLICT(day) DO NOTHING').bind(d).run();
  const sets = Object.keys(cols).map((k) => k + '=' + k + '+?').join(',');
  await env.DB.prepare('UPDATE tts_usage SET ' + sets + ' WHERE day=?').bind(...Object.values(cols), d).run();
}
async function ttsAlertAdmins(env, title, text) {
  const st = await getSetting(env, 'tts_state'), now = Date.now();
  if (st.alertAt && now - st.alertAt < 6 * 3600000) return;
  await setSetting(env, 'tts_state', { ...st, alertAt: now });
  try {
    const { results } = await env.DB.prepare("SELECT id FROM users WHERE role='admin'").all();
    for (const a of results) {
      await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(a.id, 'payment', 'pay', 'RadPad', title, text, now).run();
      if (env.FCM_SA) { try { await sendPush(env, title, text, '', 'u_' + a.id); } catch (e) {} }
    }
  } catch (e) {}
}
// خطوة تحويل واحدة: بتاخد أول فصل في الطابور (بالترتيب) وتولّد منه كام جزء، بشرط الحد اليومي. بتتنادى كل دقيقة من Cron.
async function ttsStep(env, opts = {}) {
  if (!env.GEMINI_API_KEY || !env.TTS_BUCKET) return { ok: false, idle: 'not_configured' };
  const conf = await getTtsConf(env), now = Date.now(), st = await getSetting(env, 'tts_state');
  if (st.pausedUntil && st.pausedUntil > now && !opts.force) return { ok: true, idle: 'paused' };
  const u = await env.DB.prepare('SELECT secs FROM tts_usage WHERE day=?').bind(dayKey()).first();
  let used = u ? u.secs : 0; const cap = conf.dailyMin * 60;
  if (used >= cap) return { ok: true, idle: 'daily_limit' };
  const tok = crypto.randomUUID();
  const r = await env.DB.prepare("UPDATE tts_ch SET status='running',owner=?2,lock_until=?1+60000,attempts=attempts WHERE id=(SELECT id FROM tts_ch WHERE status IN ('queued','running') AND lock_until<=?1 AND retry_at<=?1 ORDER BY ord ASC,nid ASC,idx ASC LIMIT 1)").bind(now, tok).run();
  if (r && r.meta && typeof r.meta.changes === 'number' && !r.meta.changes) return { ok: true, idle: 'empty' };
  const ch = await env.DB.prepare("SELECT * FROM tts_ch WHERE owner=? AND status='running'").bind(tok).first();
  if (!ch) return { ok: true, idle: 'empty' };
  const parts = JSON.parse(ch.parts || '[]'); let done = ch.done, secsTot = ch.secs, made = 0, err = '', hardFail = false;
  const t0 = Date.now();
  while (done < parts.length && Date.now() - t0 < 22000 && made < 8 && used < cap) {
    const idxs = []; for (let k = 0; k < conf.concurrency && done + k < parts.length && made + k < 8; k++) idxs.push(done + k);
    const res = await Promise.allSettled(idxs.map(async (p) => {
      const txt = ch.text.slice(parts[p][0], parts[p][1]).trim();
      const wav = await geminiSpeak(env, txt, conf.voice, conf);
      await env.TTS_BUCKET.put('c/' + ch.id + '/' + p + '.wav', wav, { httpMetadata: { contentType: 'audio/wav' } });
      return { secs: Math.max(0, wav.length - 44) / 48000, chars: txt.length };
    }));
    let prefix = true, limited = false;
    for (let k = 0; k < res.length; k++) {
      const x = res[k];
      if (x.status === 'fulfilled') {
        used += x.value.secs; secsTot += prefix ? x.value.secs : 0; made++;
        await ttsBump(env, { reqs: 1, chars: x.value.chars, secs: x.value.secs, cost: ttsCost(x.value.chars, x.value.secs, conf) });
        if (prefix) done++;
      } else {
        prefix = false; const e = x.reason || {};
        if (e.code === 429) limited = true; else { err = String(e.message || 'error').slice(0, 100); hardFail = true; }
      }
    }
    if (limited) {
      await setSetting(env, 'tts_state', { ...(await getSetting(env, 'tts_state')), pausedUntil: Date.now() + 30 * 60000, exhaustedAt: Date.now() });
      await ttsBump(env, { limited: 1 });
      await ttsAlertAdmins(env, '⚠️ تحويل الصوت وقف: الحصة المجانية خلصت أو الطلبات كتيرة', 'جوجل رفضت طلبات الصوت (429). التحويل واقف نص ساعة وهيكمّل لوحده. راجع حصتك في Google AI Studio أو فعّل الفوترة.');
      err = 'limit'; break;
    }
    if (hardFail) { await ttsBump(env, { fails: 1 }); break; }
  }
  const complete = done >= parts.length, tries = ch.attempts + (hardFail ? 1 : 0);
  const status = complete ? 'done' : (hardFail && tries >= 5 ? 'failed' : 'queued');
  await env.DB.prepare("UPDATE tts_ch SET status=?,owner='',lock_until=0,done=?,secs=?,attempts=?,err=?,retry_at=?,updated=? WHERE id=?")
    .bind(status, done, secsTot, hardFail ? tries : (made ? 0 : ch.attempts), complete ? '' : err, hardFail ? Date.now() + 60000 : 0, Date.now(), ch.id).run();
  return { ok: true, id: ch.id, done, total: parts.length, status, made };
}
async function ttsStats(env) {
  const conf = await getTtsConf(env), d = dayKey(), mo = d.slice(0, 7), st = await getSetting(env, 'tts_state'), pr = ttsPrices(conf);
  const sum = async (where, ...a) => env.DB.prepare('SELECT COALESCE(SUM(reqs),0) AS reqs,COALESCE(SUM(chars),0) AS chars,COALESCE(SUM(secs),0) AS secs,COALESCE(SUM(cost),0) AS cost,COALESCE(SUM(fails),0) AS fails,COALESCE(SUM(limited),0) AS limited FROM tts_usage WHERE ' + where).bind(...a).first();
  const today = await sum('day=?', d), month = await sum('day LIKE ?', mo + '%');
  const q = await env.DB.prepare('SELECT status,COUNT(*) AS n FROM tts_ch GROUP BY status').all();
  const chapters = { queued: 0, running: 0, done: 0, failed: 0 }; q.results.forEach((r) => (chapters[r.status] = r.n));
  const { results: novels } = await env.DB.prepare("SELECT nid,MAX(ntitle) AS title,MIN(ord) AS ord,COUNT(*) AS n,SUM(status='done') AS d,SUM(LENGTH(text)) AS chars,SUM(CASE WHEN status='done' THEN 0 ELSE LENGTH(text)*(1.0-done*1.0/(CASE WHEN nparts<1 THEN 1 ELSE nparts END)) END) AS rem FROM tts_ch GROUP BY nid ORDER BY MIN(ord),nid LIMIT 80").all();
  const remChars = Math.round(novels.reduce((a, r) => a + (r.rem || 0), 0)), remSecs = remChars / CPS;
  const cap = conf.dailyMin * 60, freeSecs = conf.freeMin * 60, extraSecs = Math.max(0, today.secs - freeSecs);
  return { conf, hasKey: !!env.GEMINI_API_KEY, hasBucket: !!env.TTS_BUCKET, chapters, novels: novels.map((r) => ({ nid: r.nid, title: r.title, ord: r.ord, n: r.n, d: r.d || 0, rem: Math.round(r.rem || 0) })),
    today, month, prices: pr, pausedUntil: st.pausedUntil || 0, exhaustedAt: st.exhaustedAt || 0, dailyMin: conf.dailyMin, usedTodayPct: cap ? Math.min(999, Math.round(today.secs / cap * 100)) : 100,
    freeMin: conf.freeMin, freeUsedPct: freeSecs ? Math.min(999, Math.round(today.secs / freeSecs * 100)) : null, extraCostToday: freeSecs ? (extraSecs * 25 * pr.outP) / 1e6 : null,
    remain: { chars: remChars, mins: Math.round(remSecs / 60), cost: ttsCost(remChars, remSecs, conf), days: cap ? Math.ceil(remSecs / cap) : null } };
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
  },
  // كل دقيقة: يكمّل تحويل الفصول في الطابور (بحد يومي)
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => { try { await ensureSchema(env); await ttsStep(env); } catch (e) {} })());
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
    const u = await env.DB.prepare('SELECT id,email,name,role,pass_hash,premium_until,avatar,bio,links FROM users WHERE email=?').bind(email).first();
    if (!u || !(await checkPassword(String(b.password || ''), u.pass_hash))) { await noteAttempt(env, key); return fail('الإيميل أو الباسورد غلط', 401); }
    return json({ token: await makeToken(env, u.id), user: userOut(u) });
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
        synopsis: r.l_synopsis, cover: r.l_cover, novelStatus: x.novelStatus, promoUrl: x.promoUrl, pdfUrl: x.pdfUrl, grad: x.grad, icon: x.icon, allowSharing: x.allowSharing, locked: !!(x.lockAll && x.password), pdfLocked: !!(x.password && x.lockPdf && (x.lockAll || chapLocked[r.id])),
        publishedAt: r.published_at, owner: r.owner, uid: r.user_id, chapters: byNovel[r.id] || [] };
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
    const locked = !!(x.password && (x.lockAll || c.locked));
    return json({ title: c.title, content: c.content }, 200, { 'Cache-Control': locked ? 'private, no-store' : 'public, max-age=300' });
  }
  if ((g = /^\/api\/novels\/(\d+)\/full$/.exec(path)) && m === 'GET') {
    const n = await env.DB.prepare('SELECT l_extra FROM novels WHERE id=? AND is_live=1 AND hidden=0').bind(+g[1]).first();
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
  if (path === '/api/authors' && m === 'GET') {
    const { results: us } = await env.DB.prepare("SELECT id,name,role,avatar,bio,links,created_at FROM users WHERE role='admin' OR id IN (SELECT user_id FROM novels WHERE is_live=1 AND hidden=0) ORDER BY id").all();
    const total = (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n;
    const { results: fc } = await env.DB.prepare('SELECT author_id, COUNT(*) AS n FROM follows GROUP BY author_id').all();
    const fm = {}; for (const r of fc) fm[r.author_id] = r.n;
    return json({ authors: us.map((u) => ({ id: u.id, name: u.name, avatar: u.avatar, bio: u.bio, links: linksOf(u.links), isAdmin: u.role === 'admin', joinedAt: u.created_at, followers: u.role === 'admin' ? Math.max(0, total - 1) : (fm[u.id] || 0) })) }, 200, { 'Cache-Control': 'public, max-age=30' });
  }
  if ((g = /^\/api\/authors\/(\d+|admin)$/.exec(path)) && m === 'GET') {
    let aid;
    if (g[1] === 'admin') { const a = await env.DB.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").first(); if (!a) return fail('غير موجود', 404); aid = a.id; } else aid = +g[1];
    const a = await env.DB.prepare('SELECT id,name,role,avatar,bio,links,created_at FROM users WHERE id=?').bind(aid).first();
    if (!a) return fail('الكاتب غير موجود', 404);
    const isAdm = a.role === 'admin';
    const followers = isAdm ? Math.max(0, (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n - 1) : (await env.DB.prepare('SELECT COUNT(*) AS n FROM follows WHERE author_id=?').bind(aid).first()).n;
    const { results } = await env.DB.prepare('SELECT n.id,n.l_title,n.l_author,n.l_genre,n.l_cover,n.l_extra,n.published_at FROM novels n WHERE n.user_id=? AND n.is_live=1 AND n.hidden=0 ORDER BY n.published_at DESC').bind(aid).all();
    let me = null, following = false;
    if (request.headers.get('Authorization')) { me = await authUser(env, request); }
    if (me) following = isAdm ? me.id !== aid : !!(await env.DB.prepare('SELECT 1 FROM follows WHERE follower_id=? AND author_id=?').bind(me.id, aid).first());
    return json({ author: { id: a.id, name: a.name, bio: a.bio, links: linksOf(a.links), avatar: a.avatar, isAdmin: isAdm, joinedAt: a.created_at, followers, following, self: !!(me && me.id === aid),
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
    const links = b.links === undefined ? user.links : JSON.stringify(linksOf(b.links));
    await env.DB.prepare('UPDATE users SET name=?,bio=?,avatar=?,links=? WHERE id=?').bind(name, bio, avatar, links, user.id).run();
    return json({ user: userOut({ ...user, name, bio, avatar, links }) });
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
    const title = str(b.title, 120).trim(), stars = Math.max(1, Math.min(5, +b.stars || 5));
    const snip = str(b.snippet, 400).trim().slice(0, 120);
    const head = kind === 'rating' ? '⭐ تقييم جديد على روايتك' : '💬 تعليق جديد على روايتك';
    const text = user.name + (kind === 'rating' ? ' قيّم «' + title + '» ' + stars + '/5' : ' علّق على «' + title + '»' + (b.stars ? ' (⭐ ' + stars + '/5)' : '') + (snip ? ': ' + snip : ''));
    await env.DB.prepare('INSERT INTO notes (uid,kind,novel_ref,who,title,text,ts) VALUES (?,?,?,?,?,?,?)').bind(target, kind, ref, user.name, head, text, Date.now()).run();
    await env.DB.prepare('DELETE FROM notes WHERE ts < ?').bind(Date.now() - 60 * 86400000).run();
    try { await sendPush(env, head, text, '', 'u_' + target); } catch (e) {}
    return json({ ok: true });
  }
  if ((g = /^\/api\/my\/novels\/(\d+)\/visibility$/.exec(path)) && m === 'PUT') {
    const b = await body(request);
    const own = await env.DB.prepare('SELECT id FROM novels WHERE id=? AND user_id=?').bind(+g[1], user.id).first();
    if (!own) return fail('الرواية مش موجودة', 404);
    await env.DB.prepare('UPDATE novels SET hidden=? WHERE id=?').bind(b.hidden ? 1 : 0, +g[1]).run();
    return json({ ok: true, hidden: !!b.hidden });
  }
  if (path === '/api/premium/keys' && m === 'GET') {
    if (!isPremium(user)) return fail('للمشتركين فقط', 403);
    const v = await getSetting(env, 'vault');
    return json({ keys: v.keys || {} }, 200, { 'Cache-Control': 'private, no-store' });
  }

  /* ----- الصوت المصري (للمشتركين) ----- */
  if (path === '/api/tts/chapter' && m === 'GET') {
    if (!isPremium(user)) return fail('الاستماع لمشتركي Premium', 403);
    const nid = str(url.searchParams.get('nid'), 80), ix = parseInt(url.searchParams.get('idx'), 10);
    const c = await env.DB.prepare('SELECT id,status,parts,done,nparts,secs,LENGTH(text) AS total FROM tts_ch WHERE nid=? AND idx=?').bind(nid, ix).first();
    if (!c) return json({ status: 'none' }, 200, { 'Cache-Control': 'no-store' });
    if (c.status === 'done') return json({ status: 'ready', id: c.id, parts: JSON.parse(c.parts), total: c.total, secs: c.secs }, 200, { 'Cache-Control': 'private, max-age=300' });
    return json({ status: 'pending', done: c.done, n: c.nparts }, 200, { 'Cache-Control': 'no-store' });
  }
  if ((g = /^\/api\/tts\/part\/(\d+)\/(\d+)$/.exec(path)) && m === 'GET') {
    if (!isPremium(user)) return fail('الاستماع لمشتركي Premium', 403);
    if (!env.TTS_BUCKET) return fail('التخزين مش متفعّل', 503);
    const o = await env.TTS_BUCKET.get('c/' + g[1] + '/' + g[2] + '.wav'); if (!o) return fail('الجزء مش موجود', 404);
    return audioResp(o, true);
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
    if (path === '/api/admin/tts' && m === 'GET') return json(await ttsStats(env));
    if (path === '/api/admin/tts' && m === 'PUT') {
      const b = await body(request, 3000), cur = await getTtsConf(env), nm = (v, d) => (/^[A-Za-z0-9._-]{2,60}$/.test(String(v || '')) ? String(v) : d), nu = (v, d, lo, hi) => { const k = Number(v); return v !== '' && v != null && Number.isFinite(k) && k >= lo && k <= hi ? k : d; };
      await setSetting(env, 'tts', { model: nm(b.model, cur.model), legacyModel: nm(b.legacyModel, cur.legacyModel), voice: nm(b.voice, cur.voice), style: str(b.style, 200).trim() || cur.style,
        concurrency: nu(b.concurrency, cur.concurrency, 1, 4), dailyMin: nu(b.dailyMin, cur.dailyMin, 0, 100000), freeMin: nu(b.freeMin, cur.freeMin, 0, 100000), priceIn: nu(b.priceIn, cur.priceIn, 0, 1000), priceOut: nu(b.priceOut, cur.priceOut, 0, 1000) });
      return json({ ok: true, ...(await ttsStats(env)) });
    }
    if (path === '/api/admin/tts/known' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT nid,idx,sig FROM tts_ch').all(), sigs = {};
      results.forEach((r) => (sigs[r.nid + '#' + r.idx] = r.sig)); return json({ sigs });
    }
    if (path === '/api/admin/tts/enqueue' && m === 'POST') {
      const b = await body(request, 700000); if (!Array.isArray(b.items) || b.items.length > 30) return fail('طلب غير صحيح');
      const now = Date.now(); let added = 0, updated = 0, skipped = 0;
      for (const it of b.items) {
        const nid = str(it.nid, 80), ix = parseInt(it.idx, 10), text = String(it.text || '').slice(0, 150000).trim(), sig = str(it.sig, 40);
        if (!nid || !(ix >= 0 && ix < 5000)) { skipped++; continue; }
        const parts = splitParts(text); if (!parts.length) { skipped++; continue; }
        const ntitle = str(it.ntitle, 120), ctitle = str(it.ctitle, 120), ord = Math.max(-1e9, Math.min(1e9, parseInt(it.ord, 10) || 0));
        const ex = await env.DB.prepare('SELECT id,sig FROM tts_ch WHERE nid=? AND idx=?').bind(nid, ix).first();
        if (!ex) { await env.DB.prepare('INSERT INTO tts_ch (nid,idx,ntitle,ctitle,ord,sig,text,parts,nparts,created,updated) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind(nid, ix, ntitle, ctitle, ord, sig, text, JSON.stringify(parts), parts.length, now, now).run(); added++; }
        else if (ex.sig === sig) { await env.DB.prepare('UPDATE tts_ch SET ntitle=?,ctitle=? WHERE id=?').bind(ntitle, ctitle, ex.id).run(); skipped++; }
        else { await env.DB.prepare("UPDATE tts_ch SET ntitle=?,ctitle=?,sig=?,text=?,parts=?,nparts=?,done=0,secs=0,status='queued',owner='',lock_until=0,retry_at=0,attempts=0,err='',updated=? WHERE id=?").bind(ntitle, ctitle, sig, text, JSON.stringify(parts), parts.length, now, ex.id).run(); updated++; }
      }
      return json({ ok: true, added, updated, skipped });
    }
    if (path === '/api/admin/tts/front' && m === 'POST') {
      const b = await body(request, 500), nid = str(b.nid, 80);
      const mn = await env.DB.prepare('SELECT COALESCE(MIN(ord),0) AS m FROM tts_ch').first();
      await env.DB.prepare('UPDATE tts_ch SET ord=? WHERE nid=?').bind(mn.m - 1, nid).run(); return json({ ok: true, ...(await ttsStats(env)) });
    }
    if (path === '/api/admin/tts/remove' && m === 'POST') {
      const b = await body(request, 500), nid = str(b.nid, 80);
      const { results } = await env.DB.prepare('SELECT id,nparts FROM tts_ch WHERE nid=?').bind(nid).all();
      if (env.TTS_BUCKET) for (const c of results) { const keys = []; for (let i = 0; i < c.nparts; i++) keys.push('c/' + c.id + '/' + i + '.wav'); for (let i = 0; i < keys.length; i += 100) await env.TTS_BUCKET.delete(keys.slice(i, i + 100)); }
      await env.DB.prepare('DELETE FROM tts_ch WHERE nid=?').bind(nid).run(); return json({ ok: true, ...(await ttsStats(env)) });
    }
    if (path === '/api/admin/tts/retry' && m === 'POST') {
      await env.DB.prepare("UPDATE tts_ch SET status='queued',attempts=0,retry_at=0,err='' WHERE status='failed'").run();
      await setSetting(env, 'tts_state', { ...(await getSetting(env, 'tts_state')), pausedUntil: 0 }); return json({ ok: true, ...(await ttsStats(env)) });
    }
    if (path === '/api/admin/tts/run' && m === 'POST') { const r = await ttsStep(env, { force: true }); return json({ ok: true, step: r, ...(await ttsStats(env)) }); }
    if (path === '/api/admin/tts/test' && m === 'POST') {
      if (!env.GEMINI_API_KEY) return fail('مفتاح Gemini مش متحط على السيرفر', 503);
      const b = await body(request, 2000), text = str(b.text, 400).trim(), conf = await getTtsConf(env), vn = /^[A-Za-z0-9_-]{2,40}$/.test(String(b.voiceName || '')) ? String(b.voiceName) : conf.voice;
      if (text.length < 2) return fail('نص فاضي');
      const wav = await geminiSpeak(env, text, vn, conf), secs = Math.max(0, wav.length - 44) / 48000;
      await ttsBump(env, { reqs: 1, chars: text.length, secs, cost: ttsCost(text.length, secs, conf) });
      return audioResp(wav, false);
    }
    if (path === '/api/admin/tts/voices' && m === 'GET') {
      if (!env.GEMINI_API_KEY) return fail('مفتاح Gemini مش متحط على السيرفر', 503);
      const r = await fetch('https://generativelanguage.googleapis.com/v1beta/voices?pageSize=200', { headers: { 'x-goog-api-key': env.GEMINI_API_KEY } });
      const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch (e) {}
      const list = j && Array.isArray(j.voices) ? j.voices.map((v) => ({ name: v.name || v.voiceName || v.id, lang: v.languageCodes || v.language || v.locale || '', gender: v.gender || '' })) : [];
      return json({ ok: r.ok, status: r.status, voices: list, raw: list.length ? undefined : t.slice(0, 600) });
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
        const text = 'تم تفعيل اشتراك Premium (' + p.plan_name + ') على حسابك. استمتع بكل الروايات المقفولة 👑';
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
        plans: b.plans ? cleanPlans(b.plans) : old0.plans, methods: b.methods ? cleanMethods(b.methods, b.whatsapp) : old0.methods });
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
      return json({ novel: { ...liveNovelRow(r), owner: r.owner, uid: r.user_id, chapters: results.map((c) => ({ title: c.title, content: c.content, locked: !!c.locked })) } });
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
