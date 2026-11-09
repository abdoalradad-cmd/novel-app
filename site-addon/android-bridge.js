/* طبقة التطبيق (Capacitor): واجهة التطبيق + تكامل أندرويد — لا تؤثر على الموقع في المتصفح
   ضعها في <head> أول سكريبت:  <script src="android-bridge.js"></script> */
(function () {
  'use strict';

  if (window.__appBridgeInited) return; // يمنع التشغيل مرتين (لو الملف محمّل من التطبيق ومن الصفحة)
  window.__appBridgeInited = true;

  var FORCED = /[?&]appmode=1\b/.test(location.search); // للتجربة في المتصفح: أضف ?appmode=1 للرابط
  function nativeNow() {
    var C = window.Capacitor;
    return !!(C && C.isNativePlatform && C.isNativePlatform());
  }
  var NATIVE = nativeNow() || /; wv\)/.test(navigator.userAgent);
  if (!NATIVE && !FORCED) return;

  // الملف قد يعمل قبل وجود <html> (حقن التطبيق عند بدء الصفحة)، فننتظر العناصر
  function whenRoot(fn) {
    if (document.documentElement) { fn(); return; }
    var mo = new MutationObserver(function () { if (document.documentElement) { mo.disconnect(); fn(); } });
    mo.observe(document, { childList: true });
  }
  whenRoot(function () { document.documentElement.classList.add('is-native-app'); });

  /* ---------- أدوات: الوصول للإضافات الأصلية ---------- */
  var cache = {};
  function plugin(name) {
    if (cache[name]) return cache[name];
    var C = window.Capacitor, p = C && C.Plugins && C.Plugins[name];
    if (!p && C && C.registerPlugin) { try { p = C.registerPlugin(name); } catch (e) {} }
    if (p) cache[name] = p;
    return p;
  }
  function nativeOK(name) {
    var C = window.Capacitor;
    return !!(C && C.isPluginAvailable && C.isPluginAvailable(name));
  }
  function G(name) { try { return (0, eval)('typeof ' + name + ' !== "undefined" ? ' + name + ' : null'); } catch (e) { return null; } }
  function toast(msg) {
    try { if (typeof window.showToast === 'function') return window.showToast(msg); } catch (e) {}
  }

  /* ---------- 1) شريط الحالة ---------- */
  document.addEventListener('DOMContentLoaded', function () {
    try {
      var sb = plugin('StatusBar');
      if (sb) { sb.setStyle({ style: 'DARK' }); sb.setBackgroundColor({ color: '#022c22' }); }
    } catch (e) {}
  });

  /* ---------- 2) الاستماع للفصل: بديل Web Speech يعمل بمحرك أندرويد ---------- */
  if (!('speechSynthesis' in window) || !('SpeechSynthesisUtterance' in window)) {
    var Utt = function (text) {
      this.text = text || ''; this.lang = ''; this.rate = 1; this.pitch = 1; this.volume = 1; this.voice = null;
      this.onstart = this.onend = this.onerror = this.onpause = this.onresume = this.onboundary = null;
    };
    window.SpeechSynthesisUtterance = Utt;
    var voices = [{ name: 'صوت الجهاز العربي', lang: 'ar-SA', voiceURI: 'native-ar', localService: true, default: true }];
    var queue = [], current = null, gen = 0, speaking = false, warned = false;
    var splitText = function (t) {
      var out = [], max = 3000;
      t = String(t);
      while (t.length > max) {
        var i = t.lastIndexOf(' ', max);
        if (i < 500) i = max;
        out.push(t.slice(0, i)); t = t.slice(i);
      }
      if (t.trim()) out.push(t);
      return out;
    };
    var fire = function (u, name, ev) { try { if (typeof u[name] === 'function') u[name](ev || {}); } catch (e) {} };
    var next = function () {
      if (current || !queue.length) return;
      var u = queue.shift(), my = gen, parts = splitText(u.text), i = 0;
      current = u; speaking = true;
      fire(u, 'onstart');
      (function step() {
        if (my !== gen) return;
        if (i >= parts.length) { current = null; speaking = false; fire(u, 'onend'); next(); return; }
        var n = plugin('AppNative');
        if (!n || !nativeOK('AppNative')) { current = null; speaking = false; fire(u, 'onerror', { error: 'canceled' }); toast('الاستماع يحتاج تحديث التطبيق لآخر نسخة'); return; }
        n.speak({ text: parts[i++], lang: u.lang || 'ar-SA', rate: u.rate || 1, pitch: u.pitch || 1 }).then(step, function (err) {
          if (my !== gen) return;
          current = null; speaking = false;
          var msg = String((err && err.message) || err || '');
          if (/canceled/.test(msg)) return;
          if (/lang/.test(msg)) {
            if (!warned) { warned = true; toast('لا يوجد صوت عربي في جهازك. ثبّت بيانات الصوت العربي من إعدادات «تحويل النص إلى كلام»'); }
            fire(u, 'onerror', { error: 'canceled' });
          } else fire(u, 'onerror', { error: 'synthesis-failed' });
          next();
        });
      })();
    };
    window.speechSynthesis = {
      get speaking() { return speaking; },
      get pending() { return queue.length > 0; },
      paused: false,
      onvoiceschanged: null,
      getVoices: function () { return voices; },
      speak: function (u) { queue.push(u); next(); },
      cancel: function () {
        gen++; queue = []; current = null; speaking = false;
        try { var n = plugin('AppNative'); if (n && nativeOK('AppNative')) n.stop(); } catch (e) {}
      },
      pause: function () {}, resume: function () {},
      addEventListener: function () {}, removeEventListener: function () {}
    };
  }

  /* ---------- 3) تحميل الرواية PDF: طباعة أندرويد الأصلية (تدعم العربي والروايات الطويلة) ---------- */
  var origPrint = window.print ? window.print.bind(window) : null;
  window.print = function () {
    if (!nativeOK('AppNative')) {
      toast('تحميل PDF يحتاج النسخة الأحدث من التطبيق. ثبّت آخر APK بعد مسح القديم.');
      return;
    }
    var pa = document.getElementById('print-area');
    var inner = pa ? pa.innerHTML : '';
    if (!inner) { if (origPrint) origPrint(); return; }
    sendToNativePrint(inner, novelTitle());
  };
  function novelTitle() {
    var nid = G('currentNovelId'), list = G('novels') || [], title = 'رواية';
    for (var i = 0; i < list.length; i++) if (list[i].id === nid) title = 'رواية ' + list[i].title;
    return title;
  }
  function printDoc(inner) {
    return '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Amiri:wght@400;700&family=Cairo:wght@400;700;900&display=swap">' +
      '<style>@page{size:A4;margin:14mm}html,body{margin:0;padding:0;background:#fff;direction:rtl}' +
      '#pw>div{width:auto!important;max-width:640px!important;padding:0!important;margin:0 auto!important;box-sizing:border-box!important}' +
      '#pw p,#pw h1,#pw h2,#pw h3{overflow-wrap:anywhere}</style></head><body><div id="pw">' + inner + '</div></body></html>';
  }
  /* شاشة انتظار واضحة أثناء تجهيز الـ PDF (بدل التهنيج الصامت) */
  function busy(on) {
    var el = document.getElementById('rp-busy');
    if (!on) { if (el) el.remove(); return; }
    if (el) return;
    var st = document.getElementById('rp-busy-st');
    if (!st) {
      st = document.createElement('style'); st.id = 'rp-busy-st';
      st.textContent = '@keyframes rpspin{to{transform:rotate(360deg)}}';
      document.head.appendChild(st);
    }
    el = document.createElement('div'); el.id = 'rp-busy';
    el.style.cssText = 'position:fixed;inset:0;z-index:2147483000;background:rgba(2,44,34,.88);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:18px;color:#fff;font-family:Cairo,sans-serif;font-weight:700;font-size:16px;text-align:center;padding:24px';
    el.innerHTML = '<div style="width:54px;height:54px;border:5px solid rgba(255,255,255,.25);border-top-color:#fbbf24;border-radius:50%;animation:rpspin .9s linear infinite"></div>' +
      '<div>جاري تجهيز ملف الـ PDF…<br><span style="font-weight:400;font-size:13px;opacity:.85">اختر «حفظ بتنسيق PDF» من النافذة اللي هتظهر</span></div>';
    document.body.appendChild(el);
  }
  function sendToNativePrint(inner, title) {
    var n = plugin('AppNative');
    busy(true);
    return n.print({ html: printDoc(inner), name: title.replace(/[\\/:*?"<>|]+/g, ' ') })
      .then(function () { setTimeout(function () { busy(false); }, 400); })
      .catch(function (e) {
        busy(false);
        toast('تعذّر تجهيز ملف الـ PDF: ' + String((e && e.message) || e || ''));
      });
  }
  /* نغلّف triggerPrintPdf الأصلية: شاشة انتظار فورية + #print-area مخفي تمامًا (ظهوره كان بيوسّع الصفحة ويهنّج) */
  function installFastPdf() {
    if (!nativeOK('AppNative') || typeof window.triggerPrintPdf !== 'function' || window.triggerPrintPdf.__rp) return;
    var st = document.createElement('style');
    st.textContent = '#print-area{display:none!important}';
    document.head.appendChild(st);
    var orig = window.triggerPrintPdf;
    window.triggerPrintPdf = function () {
      busy(true);
      requestAnimationFrame(function () { setTimeout(function () {
        try { orig(); } catch (e) { busy(false); toast('تعذّر تجهيز ملف الـ PDF'); }
      }, 60); });
    };
    window.triggerPrintPdf.__rp = true;
  }
  window.addEventListener('load', function () {
    // كل أزرار التحميل تمر على الطباعة الأصلية (جودة أفضل من html2canvas)
    installFastPdf();
    if (nativeOK('AppNative') && typeof window.triggerPrintPdf === 'function') {
      window.generateDirectPdfFromChapters = function () { return window.triggerPrintPdf(); };
    }
  });

  /* ---------- 3.5) صور جوجل درايف: محاولات بديلة لو فشل التحميل داخل التطبيق ---------- */
  document.addEventListener('error', function (e) {
    var im = e.target;
    if (!im || im.tagName !== 'IMG') return;
    var m = /(?:googleusercontent\.com\/d\/|drive\.google\.com\/(?:uc\?[^"']*id=|thumbnail\?id=|file\/d\/))([\w-]{20,})/.exec(im.src || '');
    if (!m) return;
    var tries = parseInt(im.getAttribute('data-try') || '0', 10);
    var urls = [
      'https://drive.google.com/thumbnail?id=' + m[1] + '&sz=w1000',
      'https://lh3.googleusercontent.com/d/' + m[1] + '=w1000',
      'https://drive.google.com/uc?export=view&id=' + m[1]
    ];
    if (tries >= urls.length) return;
    im.setAttribute('data-try', String(tries + 1));
    im.referrerPolicy = 'no-referrer';
    im.src = urls[tries];
  }, true);

  /* ---------- شاشة بداية RadPad داخل الصفحة (تظهر حتى يكتمل تحميل الموقع) ---------- */
  (function () {
    var start = Date.now(), hidden = false, el = document.createElement('div');
    el.id = 'rp-splash';
    el.style.cssText = 'position:fixed;left:0;top:0;right:0;bottom:0;z-index:2147483000;display:flex;flex-direction:column;align-items:center;justify-content:center;background:linear-gradient(135deg,#065f46,#022c22);color:#fff;font-family:Poppins,system-ui,-apple-system,Roboto,sans-serif;transition:opacity .45s ease;direction:ltr';
    el.innerHTML = '<div style="width:104px;height:104px;border-radius:28px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.22);display:flex;align-items:center;justify-content:center">' +
      '<svg width="50" viewBox="62 -702 551 702" aria-hidden="true"><path transform="scale(1,-1)" fill="#fff" d="M420 0 274 265H233V0H62V702H349Q432 702 490.5 673.0Q549 644 578.0 593.5Q607 543 607 481Q607 411 567.5 356.0Q528 301 451 278L613 0ZM233 386H339Q386 386 409.5 409.0Q433 432 433 474Q433 514 409.5 537.0Q386 560 339 560H233Z"/></svg></div>' +
      '<div style="font-weight:800;font-size:34px;margin-top:20px;letter-spacing:.3px">RadPad</div>' +
      '<div style="font-size:11px;margin-top:12px;opacity:.65;letter-spacing:.4px">powered by Abdelrahman Alradad</div>';
    whenRoot(function () { document.documentElement.appendChild(el); });
    function hide() {
      if (hidden) return;
      hidden = true;
      setTimeout(function () {
        el.style.opacity = '0';
        setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 500);
      }, Math.max(0, 1100 - (Date.now() - start)));
    }
    if (document.readyState === 'complete') hide(); else window.addEventListener('load', hide);
    setTimeout(hide, 9000);
  })();

  /* ---------- العمل بدون إنترنت: Service Worker (الملف sw.js بجانب index.html) ---------- */
  window.addEventListener('load', function () {
    if (!('serviceWorker' in navigator) || !window.isSecureContext) return;
    var base = location.pathname.replace(/[^\/]*$/, '');
    navigator.serviceWorker.register(base + 'sw.js', { scope: base }).then(function () {
      return navigator.serviceWorker.ready;
    }).then(function (reg) {
      var done = false;
      try { done = localStorage.getItem('__sw_pre_v1') === '1'; } catch (e) {}
      if (done) return;
      // أول مرة: خزّن كل ما حمّلته الصفحة (الروايات والخطوط والصور) ليعمل التطبيق بدون إنترنت
      setTimeout(function () {
        var urls = [location.origin + base];
        try { performance.getEntriesByType('resource').forEach(function (r) { urls.push(r.name); }); } catch (e) {}
        var sw = reg.active || navigator.serviceWorker.controller;
        if (sw) { sw.postMessage({ type: 'precache', urls: urls }); try { localStorage.setItem('__sw_pre_v1', '1'); } catch (e) {} }
      }, 6000);
    }).catch(function (e) { window.__swErr = String((e && e.message) || e || 'خطأ'); });
  });

  /* ---------- تنبيه الإصدار الجديد + تحميل مباشر ---------- */
  function cmpVer(a, b) {
    var x = String(a).split('.'), y = String(b).split('.'), n = Math.max(x.length, y.length);
    for (var i = 0; i < n; i++) {
      var p = parseInt(x[i] || '0', 10) || 0, q = parseInt(y[i] || '0', 10) || 0;
      if (p !== q) return p > q ? 1 : -1;
    }
    return 0;
  }
  function directUrl(u) {
    var m = /drive\.google\.com\/file\/d\/([\w-]+)/.exec(u) || /drive\.google\.com\/(?:open|uc)\?[^#]*\bid=([\w-]+)/.exec(u);
    return m ? 'https://drive.google.com/uc?export=download&id=' + m[1] : u;
  }
  function openDownload(u) {
    u = directUrl(u);
    var br = plugin('Browser');
    if (br && br.open) { br.open({ url: u }); return; }
    window.open(u, '_blank');
  }
  var updShown = false;
  function showUpdate(newV, curV, url) {
    if (updShown || document.getElementById('rp-upd')) return;
    updShown = true;
    var el = document.createElement('div'); el.id = 'rp-upd';
    el.style.cssText = 'position:fixed;inset:0;z-index:2147483200;background:rgba(2,20,16,.78);display:flex;align-items:center;justify-content:center;padding:22px;direction:rtl;font-family:Cairo,system-ui,sans-serif';
    el.innerHTML = '<div style="width:100%;max-width:360px;background:#fff;color:#0f172a;border-radius:26px;padding:26px 22px 18px;text-align:center;box-shadow:0 24px 60px rgba(0,0,0,.45)">' +
      '<div style="width:68px;height:68px;margin:0 auto 14px;border-radius:20px;background:linear-gradient(135deg,#34d399,#065f46);display:flex;align-items:center;justify-content:center;color:#fff;font-size:30px">⬇</div>' +
      '<div style="font-weight:900;font-size:1.2rem;margin-bottom:8px">يوجد إصدار جديد من التطبيق</div>' +
      '<div style="font-size:.9rem;line-height:1.9;color:#475569;margin-bottom:16px">إصدارك الحالي <b dir="ltr">' + curV + '</b> والإصدار الجديد <b dir="ltr">' + newV + '</b>.<br>حمّل التحديث علشان تستمتع بآخر الميزات والإصلاحات.</div>' +
      '<button id="rp-upd-go" style="width:100%;border:0;border-radius:16px;padding:14px;font:900 1rem Cairo,sans-serif;color:#fff;background:linear-gradient(135deg,#065f46,#022c22);box-shadow:0 8px 20px rgba(2,44,34,.35)">تحميل الإصدار الجديد</button>' +
      '<button id="rp-upd-later" style="margin-top:10px;border:0;background:none;color:#94a3b8;font:700 .8rem Cairo,sans-serif;padding:6px 12px">لاحقًا</button></div>';
    document.body.appendChild(el);
    el.querySelector('#rp-upd-go').onclick = function () {
      if (!url) { toast('رابط التحميل غير مُعدّ بعد'); return; }
      openDownload(url);
    };
    el.querySelector('#rp-upd-later').onclick = function () { el.remove(); };
  }
  /* آخر إعدادات محفوظة من الـ Service Worker (أحدث من نسخة الصفحة المعروضة لو الصفحة جت من كاش قديم) */
  function swCfg() {
    return fetch(new URL('__rp_cfg', document.baseURI).href, { cache: 'no-store' }).then(function (r) { return r.json(); }).catch(function () { return {}; });
  }
  function checkUpdate(tries) {
    var c = G('siteConfig');
    if (!c) { if (tries < 10) setTimeout(function () { checkUpdate(tries + 1); }, 1000); return; }
    var app = plugin('App');
    if (!app || !app.getInfo) return;
    Promise.all([app.getInfo(), swCfg()]).then(function (r) {
      var cur = String((r[0] && r[0].version) || '0'), s = r[1] || {};
      var v = String(c.appVersion || '').trim(), url = String(c.appDownloadUrl || '').trim();
      var sv = String(s.appVersion || '').trim();
      if (sv && (!v || cmpVer(sv, v) > 0)) { v = sv; url = String(s.appDownloadUrl || '').trim() || url; }
      if (!v) return;
      if (cmpVer(v, cur) > 0) showUpdate(v, cur, url);
    }).catch(function () {});
  }
  window.addEventListener('load', function () { setTimeout(function () { checkUpdate(0); }, 2800); setTimeout(function () { checkUpdate(5); }, 12000); setInterval(function () { if (!document.hidden && !updShown) checkUpdate(5); }, 90000); });
  document.addEventListener('visibilitychange', function () { if (!document.hidden && !updShown) setTimeout(function () { checkUpdate(5); }, 600); });

  /* ---------- تشخيص: اضغط مطولًا على عنوان الموقع (ثانيتين) ---------- */
  var BRIDGE_VERSION = '2026-10-28.1';
  (function () {
    var t = null;
    function start(e) {
      if (!e.target || !e.target.closest || !e.target.closest('#header-site-title')) return;
      clearTimeout(t);
      t = setTimeout(function () {
        var base = 'نسخة ' + BRIDGE_VERSION + ' | أصلية: ' + (nativeOK('AppNative') ? '✅' : '❌');
        try { var ap = plugin('App'); if (ap && ap.getInfo) ap.getInfo().then(function (i) { window.__appVer = i && i.version; }); if (window.__appVer) base += ' | تطبيق v' + window.__appVer; } catch (e) {}
        if (!('serviceWorker' in navigator)) { toast(base + ' | أوفلاين: غير مدعوم ❌'); return; }
        navigator.serviceWorker.getRegistrations().then(function (regs) {
          return (window.caches ? caches.keys() : Promise.resolve([])).then(function (ks) {
            return Promise.all(ks.map(function (k) { return caches.open(k).then(function (c) { return c.keys(); }); })).then(function (all) {
              var n = all.reduce(function (a, b) { return a + b.length; }, 0);
              toast(base + ' | أوفلاين: تسجيل ' + (regs.length ? '✅' : '❌') + ' / تحكم ' + (navigator.serviceWorker.controller ? '✅' : '❌') + ' / ملفات محفوظة ' + n + (window.__swErr ? ' / خطأ: ' + window.__swErr : ''));
            });
          });
        }).catch(function (e) { toast(base + ' | أوفلاين خطأ: ' + e); });
      }, 1800);
    }
    function stop() { clearTimeout(t); }
    document.addEventListener('touchstart', start, { passive: true });
    document.addEventListener('touchend', stop, { passive: true });
    document.addEventListener('touchmove', stop, { passive: true });
  })();

  /* ---------- 4) الروابط الخارجية ---------- */
  function openExternal(url) {
    try { var b = plugin('Browser'); if (b) return b.open({ url: url }); } catch (e) {}
    window.location.href = url;
  }
  var origOpen = window.open;
  window.open = function (url) {
    if (url && /^(https?:|mailto:|tel:|whatsapp:)/i.test(String(url))) { openExternal(String(url)); return null; }
    return origOpen ? origOpen.apply(window, arguments) : null;
  };
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if (!a) return;
    var href = a.getAttribute('href') || '';
    if (/^https?:/i.test(href) && href.indexOf('://' + location.host) === -1) { e.preventDefault(); openExternal(href); }
  }, true);

  /* ---------- 5) حفظ/مشاركة الملفات (ملفات blob مثل النسخ الاحتياطي) ---------- */
  function blobToBase64(blob) {
    return new Promise(function (res, rej) {
      var r = new FileReader();
      r.onload = function () { res(String(r.result).split(',')[1]); };
      r.onerror = rej;
      r.readAsDataURL(blob);
    });
  }
  function saveBlobUrl(url, name) {
    var safe = (name || 'file').replace(/[\\/:*?"<>|]+/g, '_');
    return fetch(url).then(function (r) { return r.blob(); }).then(blobToBase64).then(function (b64) {
      return plugin('Filesystem').writeFile({ path: safe, data: b64, directory: 'CACHE' });
    }).then(function (f) {
      return plugin('Share').share({ title: safe, dialogTitle: 'حفظ / مشاركة الملف', url: f.uri });
    }).catch(function (err) {
      if (err && /cancel/i.test(String(err.message || err))) return;
      toast('تعذّر حفظ الملف');
    });
  }
  function isBlobDownload(el) {
    return el instanceof HTMLAnchorElement && el.download && /^blob:/.test(el.href);
  }
  var origClick = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function () {
    if (isBlobDownload(this)) { saveBlobUrl(this.href, this.download); return; }
    return origClick.apply(this, arguments);
  };
  var origDispatch = EventTarget.prototype.dispatchEvent;
  EventTarget.prototype.dispatchEvent = function (ev) {
    if (ev && ev.type === 'click' && isBlobDownload(this)) { saveBlobUrl(this.href, this.download); return true; }
    return origDispatch.call(this, ev);
  };

  /* ---------- 6) زر الرجوع في أندرويد ---------- */
  var lastBack = 0;
  function visible(id) {
    var el = document.getElementById(id);
    return el && !el.classList.contains('hidden') && el.style.display !== 'none';
  }
  function handleBack() {
    if (typeof window.__appBack === 'function' && window.__appBack()) return;
    if (typeof window.__rpAcctBack === 'function' && window.__rpAcctBack()) return;
    if (typeof window.__rpNotifIsOpen === 'function' && window.__rpNotifIsOpen()) { window.rpCloseNotifications(); return; }
    var modals = [
      ['secret-pin-modal', 'closeSecretPinModal'],
      ['content-password-modal', 'closeContentPasswordModal'],
      ['control-panel-modal', 'closeControlPanel'],
      ['pdf-modal', 'closePdfModal']
    ];
    for (var i = 0; i < modals.length; i++) {
      if (visible(modals[i][0]) && typeof window[modals[i][1]] === 'function') { window[modals[i][1]](); return; }
    }
    if (visible('view-reader') && typeof window.backToNovelFromReader === 'function') { window.backToNovelFromReader(); return; }
    if (visible('view-novel-details') && typeof window.navigateTo === 'function') { window.navigateTo('home'); return; }
    var now = Date.now();
    if (now - lastBack < 2000) { var a = plugin('App'); if (a) a.exitApp(); }
    else { lastBack = now; toast('اضغط مرة أخرى للخروج'); }
  }
  document.addEventListener('DOMContentLoaded', function () {
    try { var a = plugin('App'); if (a) a.addListener('backButton', handleBack); } catch (e) {}
  });
})();

/* =====================================================================
   واجهة التطبيق (App Mode)
   ===================================================================== */
(function () {
  'use strict';
  var FORCED = /[?&]appmode=1\b/.test(location.search);
  var NATIVE = !!(window.Capacitor && window.Capacitor.isNativePlatform && window.Capacitor.isNativePlatform()) || /; wv\)/.test(navigator.userAgent);
  if (!NATIVE && !FORCED) return;
  if (window.__appModeInited) return;
  window.__appModeInited = true;

  var CSS = [
  /* ---- أساس ---- */
  'html.is-native-app{--sat:0px;-webkit-tap-highlight-color:transparent;overscroll-behavior-y:none;scroll-padding-top:calc(var(--sat) + 12px)}',
  'html.is-native-app body{-webkit-touch-callout:none;padding-top:var(--sat);padding-bottom:calc(72px + env(safe-area-inset-bottom,0px))}',
  'html.is-native-app body *{-webkit-user-select:none;user-select:none}',
  'html.is-native-app #reader-paper,html.is-native-app #reader-paper *,html.is-native-app input,html.is-native-app textarea,html.is-native-app [contenteditable]{-webkit-user-select:text;user-select:text}',
  'html.is-native-app main{padding:14px 14px 24px!important}',
  'html.is-native-app footer{display:none!important}',
  'html.is-native-app #nx-shelves{display:none!important}',
  'html.is-native-app ::-webkit-scrollbar{display:none}',
  'html.is-native-app .dynamic-card-radius{border-radius:22px!important}',
  '#app-sat{display:none}',
  'html.is-native-app #app-sat{display:block;position:fixed;top:0;left:0;right:0;height:var(--sat);background:#022c22;z-index:9500}',
  /* رسائل التنبيه فوق الشريط السفلي */
  'html.is-native-app #toast{bottom:calc(84px + env(safe-area-inset-bottom,0px))!important;left:14px!important;right:14px!important;z-index:9600!important}',
  'html.is-native-app[data-view="reader"] #toast{bottom:calc(20px + env(safe-area-inset-bottom,0px))!important}',

  /* ---- الهيدر: شريط أخضر يتحرك مع الصفحة ---- */
  'html.is-native-app header.sticky{position:relative!important;top:auto!important;background:linear-gradient(135deg,var(--brand-primary),var(--brand-primary-dark))!important;border:0!important;border-radius:0 0 26px 26px;box-shadow:0 6px 24px rgba(2,44,34,.35)!important;backdrop-filter:none!important}',
  'html.is-native-app header.sticky>div:first-child{height:60px!important;padding-left:14px!important;padding-right:14px!important}',
  'html.is-native-app header #header-site-title{font-size:0!important;line-height:1.3;color:#fff!important}',
  'html.is-native-app header #header-site-title::after{content:"RadPad";font-family:Poppins,Cairo,system-ui,sans-serif;font-size:1.45rem;font-weight:800;letter-spacing:.3px;color:#fff}',
  'html.is-native-app header #header-site-subtitle{display:none!important}',
  'html.is-native-app header [onclick*="navigateTo"]>div:first-child{width:2.7rem!important;height:2.7rem!important;background:none!important;border:0!important;box-shadow:none!important}',
  'html.is-native-app header [onclick*="navigateTo"]>div:first-child svg{width:100%;height:100%}',
  'html.is-native-app header button{background:rgba(255,255,255,.14)!important;color:#fcd34d!important;border:0!important}',
  'html.is-native-app header button.admin-only-ui{color:#fff!important}',
  'html.is-native-app header>div:nth-child(2){display:none!important}',
  'html.is-native-app header button:not(#rp-bell){display:none!important}',
  'html.is-native-app header #rp-bell{width:2.6rem!important;height:2.6rem!important;border-radius:.9rem!important;color:#fcd34d!important}',
  'html.is-native-app #rp-bell-badge{border-color:#064e3b}',
  'html.is-native-app header #mobile-search-input{background:rgba(255,255,255,.96)!important;color:#0f172a!important;border:0!important;border-radius:16px!important;height:46px;font-size:.95rem;box-shadow:0 4px 14px rgba(0,0,0,.18)}',
  'html.is-native-app header #mobile-search-input::placeholder{color:#64748b}',
  'html.is-native-app header>div:nth-child(2) i{top:15px!important;color:#64748b!important}',
  'html.is-native-app:not([data-view="home"]) header>div:nth-child(2){display:none!important}',
  'html.is-native-app[data-view="reader"] header.sticky{display:none!important}',
  'html.is-native-app #announcement-bar{display:none!important}',
  'html.is-native-app[data-view="reader"] #announcement-bar{display:none!important}',

  /* ---- البانر الرئيسي ---- */
  'html.is-native-app #hero-banner-wrapper>div{border-radius:26px!important}',
  'html.is-native-app #hero-banner-wrapper>div>div:nth-child(2){display:flex!important;padding:18px!important;gap:16px!important;flex-direction:row!important;align-items:center!important}',
  'html.is-native-app #hero-banner-wrapper .book-cover{width:6.6rem!important;height:9.6rem!important}',
  'html.is-native-app #hero-banner-wrapper .flex-1{text-align:right!important;gap:.5rem}',
  'html.is-native-app #hero-banner-wrapper .flex-1>*{margin-top:0!important}',
  'html.is-native-app #hero-banner-wrapper .flex-1>div:first-child{white-space:nowrap;font-size:.62rem!important;padding:.25rem .6rem!important}',
  'html.is-native-app #hero-banner-wrapper h2{font-size:1.2rem!important;line-height:1.55!important}',
  'html.is-native-app #hero-banner-wrapper p{display:none!important}',
  'html.is-native-app #hero-banner-wrapper .flex-wrap{justify-content:flex-start!important}',
  'html.is-native-app #hero-banner-wrapper button[onclick*="\'pdf\'"]{display:none!important}',
  'html.is-native-app #hero-banner-wrapper .pt-4{padding-top:.4rem!important}',
  'html.is-native-app #hero-banner-wrapper button{white-space:nowrap;padding:.7rem 1.1rem!important;font-size:.85rem!important;border-radius:14px!important}',

  /* ---- عناوين وكروت ---- */
  'html.is-native-app #library-section-title{font-size:1.15rem}',
  'html.is-native-app #library-section-subtitle{display:none!important}',
  'html.is-native-app #category-filters{scroll-snap-type:x proximity;padding-bottom:4px;margin-inline:-14px;padding-inline:14px}',
  'html.is-native-app #category-filters>*{flex-shrink:0;scroll-snap-align:start;border-radius:999px!important}',
  'html.is-native-app #view-home>*+*{margin-top:1.25rem!important}',
  'html.is-native-app #novels-grid{display:grid!important;gap:14px!important;grid-template-columns:1fr!important}',
  'html.is-native-app #novels-grid>div{padding:14px!important;border-radius:22px!important;border:0!important;box-shadow:0 2px 16px rgba(15,23,42,.08)!important;transition:transform .15s ease!important}',
  'html.is-native-app #novels-grid>div:active{transform:scale(.982)}',
  'html.is-native-app #novels-grid .book-cover{width:5.4rem!important;height:7.9rem!important;border-radius:14px!important}',
  'html.is-native-app #novels-grid .flex.gap-5{gap:.9rem!important}',
  'html.is-native-app #novels-grid h3{font-size:1.02rem!important;line-height:1.5}',
  'html.is-native-app #novels-grid p.line-clamp-3{-webkit-line-clamp:2!important;margin-top:.6rem!important;font-size:.8rem!important}',
  'html.is-native-app #novels-grid .border-t{margin-top:.8rem!important;padding-top:.8rem!important}',
  'html.is-native-app #novels-grid .border-t button{border-radius:14px!important;padding:.65rem .5rem!important}',
  'html.is-native-app #author-bio-card{border-radius:22px!important;padding:16px!important;border:0!important;box-shadow:0 2px 16px rgba(15,23,42,.08)!important;margin-bottom:.5rem}',

  /* ---- حركة الانتقال ---- */
  '@keyframes appIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}',
  'html.is-native-app #view-home:not(.hidden),html.is-native-app #view-novel-details:not(.hidden),html.is-native-app #view-reader:not(.hidden){animation:appIn .32s cubic-bezier(.2,.8,.2,1) backwards}',

  /* ---- القارئ: شريط الخط والخلفية فقط هو الثابت ---- */
  'html.is-native-app[data-view="reader"] body{padding-bottom:env(safe-area-inset-bottom,0px)}',
  'html.is-native-app[data-view="reader"] main{padding:0 0 16px!important}',
  'html.is-native-app #view-reader>div:first-child{display:contents!important}',
  'html.is-native-app #view-reader>div:first-child>div:first-child{display:flex!important;flex-wrap:wrap;align-items:center;gap:8px;padding:12px!important;margin:0!important;background:#fff;border-radius:0 0 20px 20px;box-shadow:0 2px 12px rgba(15,23,42,.08)}',
  'html.dark.is-native-app #view-reader>div:first-child>div:first-child{background:#0f1a17}',
  'html.is-native-app #view-reader>div:first-child>div:nth-child(2){position:sticky;top:var(--sat);z-index:30;display:flex!important;flex-wrap:nowrap!important;justify-content:center;align-items:center;gap:10px!important;margin:0!important;padding:8px 12px!important;background:rgba(255,255,255,.96);-webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px);border-radius:0 0 20px 20px;box-shadow:0 6px 18px rgba(15,23,42,.14)}',
  'html.dark.is-native-app #view-reader>div:first-child>div:nth-child(2){background:rgba(15,26,23,.96)}',
  'html.is-native-app #view-reader>article,html.is-native-app #reader-paper{margin-top:14px!important}',
  'html.is-native-app #reader-paper{border-radius:0!important;box-shadow:none!important;padding-left:18px!important;padding-right:18px!important}',
  'html.is-native-app #reading-progress-container{top:var(--sat);z-index:9400}',

  /* ---- الشريط السفلي ---- */
  '#app-tabbar{display:none}',
  'html.is-native-app #app-tabbar{display:flex;position:fixed;left:0;right:0;bottom:0;z-index:9000;direction:rtl;justify-content:space-around;align-items:stretch;background:#fff;border-radius:24px 24px 0 0;box-shadow:0 -6px 28px rgba(15,23,42,.14);padding:6px 6px calc(6px + env(safe-area-inset-bottom,0px));font-family:var(--ui-font,Cairo,sans-serif)}',
  'html.is-native-app.dark #app-tabbar{background:#0f1a17;box-shadow:0 -6px 28px rgba(0,0,0,.5)}',
  'html.is-native-app[data-view="reader"] #app-tabbar,html.is-native-app.search-open #app-tabbar{display:none}',
  '#app-tabbar button{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;background:none;border:0;padding:6px 0 4px;color:#64748b;font:inherit;font-size:.68rem;font-weight:700;position:relative}',
  'html.dark #app-tabbar button{color:#94a3b8}',
  '#app-tabbar button i{font-size:1.15rem;width:3.1rem;height:1.9rem;display:flex;align-items:center;justify-content:center;border-radius:999px;transition:background .2s,color .2s,transform .15s}',
  '#app-tabbar button:active i{transform:scale(.9)}',
  '#app-tabbar button.on{color:var(--brand-primary)}',
  '#app-tabbar button.on i{background:rgba(var(--brand-primary-rgb),.14);color:var(--brand-primary)}',
  'html.dark #app-tabbar button.on{color:var(--brand-accent)}',
  'html.dark #app-tabbar button.on i{background:rgba(245,158,11,.16);color:var(--brand-accent)}',

  /* ---- صفحات كاملة: المكتبة + البحث ---- */
  '#app-lib,#app-search{display:none}',
  'html.is-native-app.lib-open #app-lib,html.is-native-app.search-open #app-search{display:block;position:fixed;left:0;right:0;top:var(--sat);bottom:0;z-index:8500;overflow-y:auto;direction:rtl;font-family:var(--ui-font,Cairo,sans-serif);animation:appIn .28s ease backwards}',
  'html.is-native-app.lib-open #app-lib{padding:18px 14px calc(92px + env(safe-area-inset-bottom,0px))}',
  'html.is-native-app.search-open #app-search{z-index:9200;padding:0 14px calc(24px + env(safe-area-inset-bottom,0px))}',
  '.pg-h{font-size:1.35rem;font-weight:900;margin:2px 4px 2px;display:flex;align-items:center;gap:.5rem}',
  '.pg-h i{color:var(--brand-accent)}',
  '.pg-sub{font-size:.78rem;opacity:.65;margin:0 4px 16px}',
  '.lib-tabs{display:flex;gap:6px;overflow-x:auto;padding:2px 2px 12px;margin:0 -2px;scrollbar-width:none}',
  '.lib-tabs::-webkit-scrollbar{display:none}',
  '.lib-tab{flex:0 0 auto;display:flex;align-items:center;gap:6px;padding:8px 11px;border-radius:999px;border:1px solid rgba(100,116,139,.25);background:rgba(100,116,139,.08);color:inherit;font:inherit;font-size:.76rem;font-weight:800;white-space:nowrap}',
  '.lib-tab.on{background:linear-gradient(135deg,var(--brand-primary),var(--brand-primary-dark));border-color:transparent;color:#fff;box-shadow:0 4px 14px rgba(0,0,0,.18)}',
  '.lib-tab em{font-style:normal;font-size:.68rem;min-width:18px;height:18px;line-height:18px;border-radius:9px;background:rgba(255,255,255,.28);text-align:center;padding:0 5px}',
  '.lib-tab:not(.on) em{background:rgba(100,116,139,.2)}',
  '.pg-h3{font-size:.9rem;font-weight:800;margin:20px 4px 10px;opacity:.75;display:flex;align-items:center;gap:.4rem}',
  '.lib-card{display:flex;gap:12px;align-items:center;background:#fff;border-radius:20px;padding:12px;margin-bottom:12px;box-shadow:0 2px 16px rgba(15,23,42,.08);position:relative;transition:transform .15s}',
  '.lib-card:active{transform:scale(.98)}',
  'html.dark .lib-card{background:#0f1a17;box-shadow:0 2px 16px rgba(0,0,0,.4)}',
  '.lib-cover{width:64px;height:92px;border-radius:12px;flex-shrink:0;background:linear-gradient(135deg,var(--brand-primary),var(--brand-primary-dark));background-size:cover;background-position:center;display:flex;align-items:center;justify-content:center;color:var(--brand-accent);font-size:1.4rem;box-shadow:0 6px 14px rgba(0,0,0,.25)}',
  '.lib-info{flex:1;min-width:0}',
  '.lib-title{font-weight:900;font-size:.98rem;line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}',
  '.lib-meta{font-size:.72rem;opacity:.65;margin:2px 0 8px}',
  '.lib-bar{height:7px;border-radius:99px;background:rgba(100,116,139,.2);overflow:hidden}',
  '.lib-bar>i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--brand-accent),#fbbf24)}',
  '.lib-go{flex-shrink:0;width:40px;height:40px;border-radius:14px;border:0;background:var(--brand-primary);color:#fff;font-size:.95rem;display:flex;align-items:center;justify-content:center}',
  'html.dark .lib-go{background:var(--brand-accent);color:#022c22}',
  '.lib-heart{flex-shrink:0;width:36px;height:36px;border-radius:12px;border:0;background:rgba(225,29,72,.1);color:#e11d48;font-size:.95rem}',
  '.lib-empty{text-align:center;padding:48px 24px;opacity:.85}',
  '.lib-empty i{font-size:3.2rem;color:var(--brand-accent);margin-bottom:14px;display:block}',
  '.lib-empty b{display:block;font-size:1.05rem;margin-bottom:6px}',
  '.lib-empty span{font-size:.82rem;opacity:.7;line-height:1.8}',
  /* البحث */
  '.srch-top{position:sticky;top:0;z-index:2;display:flex;align-items:center;gap:10px;padding:12px 0 10px}',
  '.srch-back{flex-shrink:0;width:44px;height:44px;border-radius:14px;border:0;background:rgba(100,116,139,.14);color:inherit;font-size:1rem}',
  '.srch-box{flex:1;position:relative}',
  '.srch-box input{width:100%;box-sizing:border-box;height:46px;border-radius:16px;border:2px solid rgba(var(--brand-primary-rgb),.35);padding:0 44px 0 40px;font:inherit;font-size:.95rem;background:#fff;color:#0f172a;outline:none}',
  'html.dark .srch-box input{background:#0f1a17;color:#f1f5f9}',
  '.srch-box input:focus{border-color:var(--brand-primary)}',
  '.srch-box>i{position:absolute;right:15px;top:15px;opacity:.5;font-size:.95rem}',
  '.srch-x{position:absolute;left:6px;top:5px;width:36px;height:36px;border:0;background:none;color:inherit;opacity:.5;display:none}',
  '.srch-chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 4px}',
  '.srch-chip{border:0;border-radius:999px;padding:8px 14px;font:inherit;font-size:.8rem;font-weight:700;background:rgba(var(--brand-primary-rgb),.12);color:var(--brand-primary)}',
  'html.dark .srch-chip{background:rgba(245,158,11,.14);color:var(--brand-accent)}'
  ].join('\n');

  var st = document.createElement('style');
  st.id = 'app-mode-css';
  st.textContent = CSS;
  (function addCss() {
    if (document.head) { document.head.appendChild(st); return; }
    var mo = new MutationObserver(function () { if (document.head) { mo.disconnect(); document.head.appendChild(st); } });
    mo.observe(document, { childList: true, subtree: true });
  })();

  var root = document.documentElement;
  var VIEWS = ['home', 'novel-details', 'reader'];
  function G(name) { try { return (0, eval)('typeof ' + name + ' !== "undefined" ? ' + name + ' : null'); } catch (e) { return null; } }
  function allNovels() {
    var arr = G('novels') || [];
    return arr.filter(function (n) { try { return !(typeof window.isNovelHiddenForReader === 'function' && window.isNovelHiddenForReader(n)); } catch (e) { return true; } });
  }
  function novelById(id) { var a = allNovels(); for (var i = 0; i < a.length; i++) if (a[i].id === id) return a[i]; return null; }
  function esc(t) { return String(t == null ? '' : t).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function currentView() {
    for (var i = 0; i < VIEWS.length; i++) {
      var el = document.getElementById('view-' + VIEWS[i]);
      if (el && !el.classList.contains('hidden')) return VIEWS[i];
    }
    return 'home';
  }
  function openNovel(id) {
    if (typeof window.requestNovelAccess === 'function') window.requestNovelAccess(id, 'details');
    else if (typeof window.openNovelDetails === 'function') window.openNovelDetails(id);
  }

  /* ================= الشريط السفلي ================= */
  var TABS = [
    { id: 'home', icon: 'fa-house', label: 'الرئيسية' },
    { id: 'library', icon: 'fa-book-open', label: 'الروايات' },
    { id: 'search', icon: 'fa-magnifying-glass', label: 'بحث' },
    { id: 'mylib', icon: 'fa-bookmark', label: 'المكتبة' },
    { id: 'account', icon: 'fa-user', label: 'حسابي' }
  ];
  var bar = document.createElement('nav');
  bar.id = 'app-tabbar';
  bar.setAttribute('aria-label', 'التنقل');
  TABS.forEach(function (t) {
    var b = document.createElement('button');
    b.type = 'button'; b.dataset.tab = t.id;
    b.innerHTML = '<i class="fa-solid ' + t.icon + '"></i><span>' + t.label + '</span>';
    bar.appendChild(b);
  });
  var activeTab = 'home';
  function setActive(id) {
    activeTab = id;
    [].forEach.call(bar.children, function (b) { b.classList.toggle('on', b.dataset.tab === id); });
  }
  function syncThemeIcon() {
    var ic = bar.querySelector('[data-tab="theme"] i');
    if (ic) ic.className = 'fa-solid ' + (root.classList.contains('dark') ? 'fa-sun' : 'fa-moon');
    if (libOpen()) paintLib();
  }
  function toHome() { if (currentView() !== 'home' && typeof window.navigateTo === 'function') window.navigateTo('home'); }
  function scrollToEl(sel, delay) {
    setTimeout(function () { var el = document.querySelector(sel); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, delay || 60);
  }

  /* ================= صفحة المكتبة (متابعة القراءة + المفضلة) ================= */
  var lib = document.createElement('div');
  lib.id = 'app-lib';
  function libOpen() { return root.classList.contains('lib-open'); }
  function readerData() {
    try { var d = JSON.parse(localStorage.getItem('nx_reader_v1') || '{}') || {}; return { favs: d.favs || [], last: d.last || {} }; }
    catch (e) { return { favs: [], last: {} }; }
  }
  function coverEl(n) {
    return n.coverImg ? '<div class="lib-cover" style="background-image:url(\'' + esc(n.coverImg) + '\')"></div>'
      : '<div class="lib-cover"><i class="fa-solid ' + esc(n.accentIcon || 'fa-book') + '"></i></div>';
  }
  function progCard(n, l, done) {
    var total = n.chapters.length, ch = Math.min(l.ch || 0, total - 1), pct = l.pct || 0;
    var ratio = Math.min(1, (ch + pct / 100) / total);
    var meta = done ? 'أنهيت الرواية' : 'الفصل ' + (ch + 1) + ' من ' + total + ' · ' + Math.round(ratio * 100) + '%';
    return '<div class="lib-card" data-act="cont" data-id="' + esc(n.id) + '">' + coverEl(n) +
      '<div class="lib-info"><div class="lib-title">' + esc(n.title) + '</div><div class="lib-meta">' + meta + '</div>' +
      '<div class="lib-bar"><i style="width:' + (done ? 100 : Math.round(ratio * 100)) + '%"></i></div></div>' +
      '<button class="lib-go" aria-label="متابعة"><i class="fa-solid fa-play" style="margin-right:-2px"></i></button></div>';
  }
  function favCard(n) {
    return '<div class="lib-card" data-act="open" data-id="' + esc(n.id) + '">' + coverEl(n) +
      '<div class="lib-info"><div class="lib-title">' + esc(n.title) + '</div><div class="lib-meta">' + esc(n.author || '') + (n.genre ? ' · ' + esc(n.genre) : '') + ' · ' + n.chapters.length + ' فصول</div></div>' +
      '<button class="lib-heart" data-fav="' + esc(n.id) + '" aria-label="إزالة من المفضلة"><i class="fa-solid fa-heart"></i></button></div>';
  }
  var libTab = null;
  function fmtB(b) { b = +b || 0; return b > 1048576 ? (b / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(b / 1024)) + ' KB'; }
  function dlCard(r) {
    var n = novelById(r.id);
    return '<div class="lib-card" data-act="open" data-id="' + esc(r.id) + '">' + (n ? coverEl(n) : '<div class="lib-cover"><i class="fa-solid fa-book"></i></div>') +
      '<div class="lib-info"><div class="lib-title">' + esc(r.title || (n && n.title) || '') + '</div><div class="lib-meta">' + (r.n ? r.n + ' فصول · ' : '') + fmtB(r.bytes) + (r.partial ? ' · بدون الفصول المقفولة' : '') + '</div>' +
      '<div class="lib-meta" style="color:#059669;font-weight:800"><i class="fa-solid fa-circle-check"></i> متاحة بدون إنترنت</div></div>' +
      '<button class="lib-heart" data-rmdl="' + esc(r.id) + '" aria-label="حذف التحميل" style="background:rgba(100,116,139,.12);color:#64748b"><i class="fa-solid fa-trash-can"></i></button></div>';
  }
  function paintLib() {
    var d = readerData();
    var items = Object.keys(d.last).map(function (id) { return { n: novelById(id), l: d.last[id] }; })
      .filter(function (x) { return x.n && x.n.chapters && x.n.chapters.length; })
      .sort(function (a, b) { return (b.l.t || 0) - (a.l.t || 0); });
    items.forEach(function (x) { x.done = (x.l.ch || 0) >= x.n.chapters.length - 1 && (x.l.pct || 0) >= 93; });
    var cont = items.filter(function (x) { return !x.done; }), done = items.filter(function (x) { return x.done; });
    var favs = d.favs.map(novelById).filter(Boolean);
    var dls = window.rpOffline ? window.rpOffline.list() : [];
    var T = [['dl', 'fa-arrow-down', 'المحمّلة', dls.length], ['cont', 'fa-book-open-reader', 'أكمل القراءة', cont.length], ['fav', 'fa-heart', 'المفضلة', favs.length], ['done', 'fa-circle-check', 'أنهيتها', done.length]];
    if (!libTab || !T.some(function (t) { return t[0] === libTab; })) libTab = (T.filter(function (t) { return t[3]; })[0] || T[1])[0];
    var h = '<h2 class="pg-h"><i class="fa-solid fa-bookmark"></i>مكتبتي</h2><p class="pg-sub">رواياتك المحمّلة، ومتابعة قراءتك، ومفضلتك في مكان واحد</p>' +
      '<div class="lib-tabs">' + T.map(function (t) { return '<button type="button" class="lib-tab' + (libTab === t[0] ? ' on' : '') + '" data-tab="' + t[0] + '"><i class="fa-solid ' + t[1] + '"></i><span>' + t[2] + '</span>' + (t[3] ? '<em>' + t[3] + '</em>' : '') + '</button>'; }).join('') + '</div>';
    var EMPTY = { dl: ['fa-arrow-down', 'مفيش روايات محمّلة', 'افتح أي رواية واضغط الزر الدائري الأخضر لتحميلها وقراءتها بدون إنترنت'], cont: ['fa-book-open-reader', 'مفيش روايات قيد القراءة', 'الروايات التي تبدأ قراءتها ستظهر هنا لتكمل من حيث توقفت'], fav: ['fa-heart', 'مفيش مفضلة لسه', 'اضغط على القلب في أي رواية لتظهر هنا'], done: ['fa-circle-check', 'لسه ما أنهيتش رواية', 'الروايات التي تنهيها ستظهر هنا'] };
    var body = libTab === 'dl' ? dls.map(dlCard).join('') : libTab === 'cont' ? cont.map(function (x) { return progCard(x.n, x.l, false); }).join('') : libTab === 'fav' ? favs.map(favCard).join('') : done.map(function (x) { return progCard(x.n, x.l, true); }).join('');
    h += body || '<div class="lib-empty"><i class="fa-solid ' + EMPTY[libTab][0] + '"></i><b>' + EMPTY[libTab][1] + '</b><span>' + EMPTY[libTab][2] + '</span></div>';
    lib.innerHTML = h;
    paintBg(lib);
  }
  function paintBg(el) {
    var bg = getComputedStyle(document.body).backgroundColor;
    if (!bg || bg === 'transparent' || /rgba\(.*,\s*0\)$/.test(bg)) bg = root.classList.contains('dark') ? '#020617' : '#fcf8f2';
    el.style.background = bg;
  }
  function openLib() { closeSearch(true); libTab = null; paintLib(); root.classList.add('lib-open'); lib.scrollTop = 0; }
  function closeLib() { root.classList.remove('lib-open'); }
  document.addEventListener('rp-offline-changed', function () { if (libOpen()) paintLib(); });
  lib.addEventListener('click', function (e) {
    var tb = e.target.closest('[data-tab]');
    if (tb) { libTab = tb.dataset.tab; paintLib(); lib.scrollTop = 0; return; }
    var rm = e.target.closest('[data-rmdl]');
    if (rm) { if (window.rpOffline && confirm('تمسح النسخة المحمّلة من الموبايل؟')) window.rpOffline.remove(rm.dataset.rmdl); return; }
    var hb = e.target.closest('[data-fav]');
    if (hb) { if (typeof window.nxToggleFav === 'function') window.nxToggleFav(hb.dataset.fav); paintLib(); return; }
    var c = e.target.closest('.lib-card');
    if (!c) return;
    var id = c.dataset.id;
    closeLib();
    if (c.dataset.act === 'cont' && typeof window.nxContinue === 'function') window.nxContinue(id);
    else openNovel(id);
  });

  /* ================= صفحة البحث (نتائج تقريبية) ================= */
  var srch = document.createElement('div');
  srch.id = 'app-search';
  srch.innerHTML = '<div class="srch-top"><button class="srch-back" aria-label="رجوع"><i class="fa-solid fa-arrow-right"></i></button>' +
    '<div class="srch-box"><i class="fa-solid fa-magnifying-glass"></i><input type="search" id="app-search-input" placeholder="ابحث باسم الرواية أو التصنيف أو الكاتب..." autocomplete="off" enterkeyhint="search"><button class="srch-x" aria-label="مسح"><i class="fa-solid fa-xmark"></i></button></div></div>' +
    '<div id="app-search-body"></div>';
  var sInput = srch.querySelector('input'), sBody = srch.querySelector('#app-search-body'), sX = srch.querySelector('.srch-x');
  function searchOpen() { return root.classList.contains('search-open'); }
  function norm(t) {
    return String(t || '').toLowerCase()
      .replace(/[ً-ٰٟـ]/g, '')
      .replace(/[أإآٱ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه').replace(/ؤ/g, 'و').replace(/ئ/g, 'ي')
      .replace(/[^ء-يa-z0-9]+/g, ' ').trim();
  }
  function lev(a, b, max) {
    if (Math.abs(a.length - b.length) > max) return max + 1;
    var prev = [], i, j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      var cur = [i], best = i;
      for (j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        if (cur[j] < best) best = cur[j];
      }
      if (best > max) return max + 1;
      prev = cur;
    }
    return prev[b.length];
  }
  function fuzzyWord(tok, words) {
    var max = tok.length >= 7 ? 2 : (tok.length >= 4 ? 1 : 0);
    if (!max) return false;
    for (var i = 0; i < words.length; i++) if (lev(tok, words[i], max) <= max) return true;
    return false;
  }
  function scoreNovel(n, toks) {
    var title = norm(n.title), tw = title.split(' '), genre = norm(n.genre + ' ' + (n.tags || []).join(' ')), author = norm(n.author), syn = norm(n.synopsis);
    var total = 0, hits = 0;
    toks.forEach(function (t) {
      var s = 0;
      if (title.indexOf(t) !== -1) s = tw.some(function (w) { return w.indexOf(t) === 0; }) ? 12 : 9;
      else if (genre.indexOf(t) !== -1) s = 6;
      else if (author.indexOf(t) !== -1) s = 4;
      else if (syn.indexOf(t) !== -1) s = 2;
      else if (fuzzyWord(t, tw) || fuzzyWord(t, genre.split(' '))) s = 5;
      if (s) hits++;
      total += s;
    });
    return hits === toks.length || (toks.length > 2 && hits >= toks.length - 1) ? total : 0;
  }
  function resCard(n) {
    return '<div class="lib-card" data-id="' + esc(n.id) + '">' + coverEl(n) +
      '<div class="lib-info"><div class="lib-title">' + esc(n.title) + '</div><div class="lib-meta">' + esc(n.author || '') + (n.genre ? ' · ' + esc(n.genre) : '') + ' · ' + n.chapters.length + ' فصول</div></div>' +
      '<button class="lib-go" aria-label="فتح"><i class="fa-solid fa-chevron-left"></i></button></div>';
  }
  function paintSearch() {
    var q = sInput.value, toks = norm(q).split(' ').filter(Boolean);
    sX.style.display = q ? 'block' : 'none';
    if (!toks.length) {
      var genres = {};
      allNovels().forEach(function (n) { if (n.genre) genres[n.genre] = 1; });
      var keys = Object.keys(genres);
      sBody.innerHTML = '<div class="lib-empty" style="padding:36px 16px 20px"><i class="fa-solid fa-magnifying-glass"></i><b>ابحث في الروايات</b><span>اكتب اسم الرواية أو جزءًا منه، أو اسم التصنيف.<br>النتائج تظهر هنا حتى لو أخطأت في حرف.</span></div>' +
        (keys.length ? '<h3 class="pg-h3">التصنيفات</h3><div class="srch-chips">' + keys.map(function (g) { return '<button class="srch-chip" data-q="' + esc(g) + '">' + esc(g) + '</button>'; }).join('') + '</div>' : '');
      return;
    }
    var res = allNovels().map(function (n) { return { n: n, s: scoreNovel(n, toks) }; }).filter(function (x) { return x.s > 0; })
      .sort(function (a, b) { return b.s - a.s; });
    sBody.innerHTML = res.length
      ? '<p class="pg-sub" style="margin-top:4px">' + res.length + ' نتيجة</p>' + res.map(function (x) { return resCard(x.n); }).join('')
      : '<div class="lib-empty"><i class="fa-solid fa-face-sad-tear"></i><b>لا توجد نتائج</b><span>جرّب كلمة أخرى أو جزءًا أقصر من الاسم</span></div>';
  }
  var sTimer = null;
  sInput.addEventListener('input', function () { clearTimeout(sTimer); sTimer = setTimeout(paintSearch, 110); });
  sX.addEventListener('click', function () { sInput.value = ''; paintSearch(); sInput.focus(); });
  srch.querySelector('.srch-back').addEventListener('click', function () { closeSearch(); });
  sBody.addEventListener('click', function (e) {
    var chip = e.target.closest('.srch-chip');
    if (chip) { sInput.value = chip.dataset.q; paintSearch(); return; }
    var c = e.target.closest('.lib-card');
    if (c) { var id = c.dataset.id; closeSearch(true); openNovel(id); }
  });
  function openSearch() {
    closeLib();
    paintBg(srch);
    root.classList.add('search-open');
    sInput.value = '';
    paintSearch();
    srch.scrollTop = 0;
    setTimeout(function () { sInput.focus(); }, 120);
  }
  function closeSearch(silent) {
    if (!searchOpen()) return;
    root.classList.remove('search-open');
    try { sInput.blur(); } catch (e) {}
    if (!silent) setActive(currentView() === 'novel-details' ? 'library' : 'home');
  }
  // الضغط على حقل البحث في الهيدر يفتح صفحة البحث
  document.addEventListener('focusin', function (e) {
    if (e.target && (e.target.id === 'mobile-search-input' || e.target.id === 'search-input')) { e.target.blur(); setActive('search'); openSearch(); }
  });

  window.__appAfterOverlay = function () { if (activeTab === 'account' || activeTab === 'library') setActive(currentView() === 'novel-details' ? 'library' : 'home'); };
  window.__appBack = function () {
    if (searchOpen()) { closeSearch(); return true; }
    if (libOpen()) { closeLib(); setActive('home'); return true; }
    return false;
  };

  /* ================= أحداث الشريط السفلي ================= */
  bar.addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    try { if (navigator.vibrate) navigator.vibrate(8); } catch (x) {}
    var id = b.dataset.tab;
    if (id === 'account') {
      closeLib(); closeSearch(true); setActive('account');
      if (typeof window.rpOpenAccount === 'function') window.rpOpenAccount();
      return;
    }
    if (id === 'search') { setActive('search'); openSearch(); return; }
    if (id === 'mylib') { setActive('mylib'); openLib(); return; }
    var wasHome = currentView() === 'home' && !libOpen();
    closeLib(); closeSearch(true);
    setActive(id);
    toHome();
    var d = wasHome ? 0 : 350;
    if (id === 'home') setTimeout(function () { window.scrollTo({ top: 0, behavior: 'smooth' }); }, d + 30);
    else if (id === 'library') { if (typeof window.rpOpenAll === 'function') window.rpOpenAll(); else scrollToEl('#library-section-title', d + 60); }
  });

  /* ================= متابعة الصفحة الحالية ================= */
  function onView() {
    var v = currentView();
    root.setAttribute('data-view', v);
    if (libOpen()) closeLib();
    if (searchOpen()) closeSearch(true);
    if (v === 'novel-details') setActive('library');
    else if (v === 'home' && (activeTab === 'mylib' || activeTab === 'search')) setActive('home');
  }
  function init() {
    root = document.documentElement;
    var vp = document.querySelector('meta[name="viewport"]');
    if (vp && !/viewport-fit/.test(vp.content)) vp.content += ', viewport-fit=cover';
    var cover = document.createElement('div'); cover.id = 'app-sat';
    document.body.appendChild(cover);
    document.body.appendChild(lib);
    document.body.appendChild(srch);
    // ارتفاع شريط الحالة
    var pr = document.createElement('div');
    pr.style.cssText = 'position:fixed;visibility:hidden;padding-top:max(var(--safe-area-inset-top,0px),env(safe-area-inset-top,0px))';
    document.body.appendChild(pr);
    var sat = parseFloat(getComputedStyle(pr).paddingTop) || 0;
    pr.remove();
    root.style.setProperty('--sat', (sat > 0 ? sat : (/; wv\)/.test(navigator.userAgent) ? 28 : 0)) + 'px');
    document.body.appendChild(bar);
    var mo = new MutationObserver(onView);
    VIEWS.forEach(function (v) {
      var el = document.getElementById('view-' + v);
      if (el) mo.observe(el, { attributes: true, attributeFilter: ['class'] });
    });
    new MutationObserver(syncThemeIcon).observe(root, { attributes: true, attributeFilter: ['class'] });
    setActive('home'); onView(); syncThemeIcon();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();

  /* الضغط على أي مكان في كارت الرواية يفتح صفحتها */
  document.addEventListener('click', function (e) {
    var card = e.target.closest && e.target.closest('#novels-grid>div');
    if (!card || e.target.closest('button,a,[onclick],select,input')) return;
    var btn = card.querySelector('button[onclick*="\'details\'"]');
    if (btn) btn.click();
  });
})();
