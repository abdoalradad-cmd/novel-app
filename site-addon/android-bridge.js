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
    if (!nativeOK('AppNative')) { if (origPrint) origPrint(); return; }
    var pa = document.getElementById('print-area');
    var inner = pa ? pa.innerHTML : '';
    if (!inner) { if (origPrint) origPrint(); return; }
    var nid = G('currentNovelId'), list = G('novels') || [], title = 'رواية';
    for (var i = 0; i < list.length; i++) if (list[i].id === nid) title = 'رواية ' + list[i].title;
    var doc = '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Amiri:wght@400;700&family=Cairo:wght@400;700;900&display=swap">' +
      '<style>@page{size:A4;margin:14mm}html,body{margin:0;padding:0;background:#fff}</style></head><body>' + inner + '</body></html>';
    plugin('AppNative').print({ html: doc, name: title.replace(/[\\/:*?"<>|]+/g, ' ') }).catch(function () { toast('تعذّر تجهيز ملف الـ PDF'); });
  };
  window.addEventListener('load', function () {
    // كل أزرار التحميل تمر على الطباعة الأصلية (جودة أفضل من html2canvas)
    if (nativeOK('AppNative') && typeof window.triggerPrintPdf === 'function') {
      window.generateDirectPdfFromChapters = function () { return window.triggerPrintPdf(); };
    }
  });

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
  'html.is-native-app button,html.is-native-app a,html.is-native-app nav{-webkit-user-select:none;user-select:none}',
  'html.is-native-app .novel-text,html.is-native-app #reader-paper,html.is-native-app input,html.is-native-app textarea{-webkit-user-select:text;user-select:text}',
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
  'html.is-native-app header #header-site-title{color:#fff!important;font-size:1.02rem!important;line-height:1.3}',
  'html.is-native-app header #header-site-subtitle{display:none!important}',
  'html.is-native-app header [onclick*="navigateTo"]>div:first-child{width:2.5rem!important;height:2.5rem!important;border-radius:.9rem!important;background:rgba(255,255,255,.14)!important;border-color:rgba(255,255,255,.25)!important}',
  'html.is-native-app header button{background:rgba(255,255,255,.14)!important;color:#fcd34d!important;border:0!important}',
  'html.is-native-app header button.admin-only-ui{color:#fff!important}',
  'html.is-native-app header>div:nth-child(2){padding:0 14px 14px!important}',
  'html.is-native-app header #mobile-search-input{background:rgba(255,255,255,.96)!important;color:#0f172a!important;border:0!important;border-radius:16px!important;height:46px;font-size:.95rem;box-shadow:0 4px 14px rgba(0,0,0,.18)}',
  'html.is-native-app header #mobile-search-input::placeholder{color:#64748b}',
  'html.is-native-app header>div:nth-child(2) i{top:15px!important;color:#64748b!important}',
  'html.is-native-app:not([data-view="home"]) header>div:nth-child(2){display:none!important}',
  'html.is-native-app[data-view="reader"] header.sticky{display:none!important}',
  'html.is-native-app #announcement-bar{padding:.35rem .9rem!important;font-size:.7rem!important;line-height:1.5;border:0!important}',
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
    { id: 'theme', icon: 'fa-moon', label: 'المظهر' }
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
  function paintLib() {
    var d = readerData();
    var items = Object.keys(d.last).map(function (id) { return { n: novelById(id), l: d.last[id] }; })
      .filter(function (x) { return x.n && x.n.chapters && x.n.chapters.length; })
      .sort(function (a, b) { return (b.l.t || 0) - (a.l.t || 0); });
    items.forEach(function (x) { x.done = (x.l.ch || 0) >= x.n.chapters.length - 1 && (x.l.pct || 0) >= 93; });
    var cont = items.filter(function (x) { return !x.done; }), done = items.filter(function (x) { return x.done; });
    var favs = d.favs.map(novelById).filter(Boolean);
    var h = '<h2 class="pg-h"><i class="fa-solid fa-bookmark"></i>مكتبتي</h2><p class="pg-sub">تابع قراءتك وروائعك المفضلة في مكان واحد</p>';
    if (!cont.length && !favs.length && !done.length) {
      h += '<div class="lib-empty"><i class="fa-solid fa-book-open-reader"></i><b>مكتبتك فارغة</b><span>الروايات التي تبدأ قراءتها وتلك التي تضيفها للمفضلة<br>ستظهر هنا لتصل إليها بسرعة</span></div>';
    } else {
      if (cont.length) h += '<h3 class="pg-h3"><i class="fa-solid fa-book-open-reader"></i>أكمل القراءة</h3>' + cont.map(function (x) { return progCard(x.n, x.l, false); }).join('');
      if (favs.length) h += '<h3 class="pg-h3"><i class="fa-solid fa-heart" style="color:#e11d48"></i>المفضلة</h3>' + favs.map(favCard).join('');
      if (done.length) h += '<h3 class="pg-h3"><i class="fa-solid fa-circle-check"></i>أنهيتها</h3>' + done.map(function (x) { return progCard(x.n, x.l, true); }).join('');
    }
    lib.innerHTML = h;
    paintBg(lib);
  }
  function paintBg(el) {
    var bg = getComputedStyle(document.body).backgroundColor;
    if (!bg || bg === 'transparent' || /rgba\(.*,\s*0\)$/.test(bg)) bg = root.classList.contains('dark') ? '#020617' : '#fcf8f2';
    el.style.background = bg;
  }
  function openLib() { closeSearch(true); paintLib(); root.classList.add('lib-open'); lib.scrollTop = 0; }
  function closeLib() { root.classList.remove('lib-open'); }
  lib.addEventListener('click', function (e) {
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
    if (id === 'theme') {
      if (typeof window.toggleDarkMode === 'function') window.toggleDarkMode();
      setTimeout(function () { syncThemeIcon(); if (libOpen()) paintLib(); }, 60);
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
    else if (id === 'library') scrollToEl('#library-section-title', d + 60);
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
