/* طبقة الربط بين الموقع وتطبيق أندرويد (Capacitor) — لا تؤثر على الموقع الأصلي */
(function () {
  'use strict';

  var Cap = window.Capacitor;
  if (!Cap || !Cap.isNativePlatform || !Cap.isNativePlatform()) return; // يعمل فقط داخل التطبيق
  var P = Cap.Plugins || {};
  document.documentElement.classList.add('is-native-app');

  /* ---------- 1) شريط الحالة ---------- */
  try {
    if (P.StatusBar) {
      P.StatusBar.setStyle({ style: 'DARK' });
      P.StatusBar.setBackgroundColor({ color: '#022c22' });
    }
  } catch (e) {}

  /* ---------- 2) مظهر التطبيق: منع تحديد النصوص خارج القراءة + سحب التحديث ---------- */
  var css = document.createElement('style');
  css.textContent =
    'html.is-native-app{-webkit-tap-highlight-color:transparent;overscroll-behavior-y:none}' +
    'html.is-native-app body{-webkit-touch-callout:none}' +
    'html.is-native-app button,html.is-native-app a,html.is-native-app nav{-webkit-user-select:none;user-select:none}' +
    'html.is-native-app .novel-text,html.is-native-app #reader-paper,html.is-native-app input,html.is-native-app textarea{-webkit-user-select:text;user-select:text}';
  document.head.appendChild(css);

  /* ---------- 3) فتح الروابط الخارجية في المتصفح ---------- */
  function openExternal(url) {
    try {
      if (P.Browser) return P.Browser.open({ url: url });
    } catch (e) {}
    window.location.href = url;
  }
  var origOpen = window.open;
  window.open = function (url) {
    if (url && /^(https?:|mailto:|tel:|whatsapp:)/i.test(String(url))) {
      openExternal(String(url));
      return null;
    }
    return origOpen ? origOpen.apply(window, arguments) : null;
  };
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if (!a) return;
    var href = a.getAttribute('href') || '';
    if (/^https?:/i.test(href) && href.indexOf('://' + location.host) === -1) {
      e.preventDefault();
      openExternal(href);
    }
  }, true);

  /* ---------- 4) حفظ/مشاركة الملفات (PDF والنسخ الاحتياطي) ---------- */
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
      return P.Filesystem.writeFile({ path: safe, data: b64, directory: 'CACHE' });
    }).then(function (f) {
      return P.Share.share({ title: safe, dialogTitle: 'حفظ / مشاركة الملف', url: f.uri });
    }).catch(function (err) {
      if (err && /cancel/i.test(String(err.message || err))) return;
      alert('تعذّر حفظ الملف');
    });
  }
  function isBlobDownload(el) {
    return el instanceof HTMLAnchorElement && el.download && /^blob:/.test(el.href);
  }
  var origClick = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function () {
    if (P.Filesystem && P.Share && isBlobDownload(this)) { saveBlobUrl(this.href, this.download); return; }
    return origClick.apply(this, arguments);
  };
  var origDispatch = EventTarget.prototype.dispatchEvent;
  EventTarget.prototype.dispatchEvent = function (ev) {
    if (ev && ev.type === 'click' && P.Filesystem && P.Share && isBlobDownload(this)) {
      saveBlobUrl(this.href, this.download);
      return true;
    }
    return origDispatch.call(this, ev);
  };

  /* ---------- 6) زر الرجوع في أندرويد ---------- */
  var lastBack = 0;
  function visible(id) {
    var el = document.getElementById(id);
    return el && !el.classList.contains('hidden') && el.style.display !== 'none';
  }
  function toast(msg) {
    try {
      if (typeof window.showSimpleToast === 'function') return window.showSimpleToast(msg);
      if (typeof window.showToast === 'function') return window.showToast(msg);
    } catch (e) {}
  }
  function handleBack() {
    var modals = [
      ['secret-pin-modal', 'closeSecretPinModal'],
      ['content-password-modal', 'closeContentPasswordModal'],
      ['control-panel-modal', 'closeControlPanel'],
      ['pdf-modal', 'closePdfModal']
    ];
    for (var i = 0; i < modals.length; i++) {
      if (visible(modals[i][0]) && typeof window[modals[i][1]] === 'function') {
        window[modals[i][1]]();
        return;
      }
    }
    if (visible('view-reader') && typeof window.backToNovelFromReader === 'function') {
      window.backToNovelFromReader();
      return;
    }
    if (visible('view-novel-details') && typeof window.navigateTo === 'function') {
      window.navigateTo('home');
      return;
    }
    var now = Date.now();
    if (now - lastBack < 2000) {
      P.App.exitApp();
    } else {
      lastBack = now;
      toast('اضغط مرة أخرى للخروج');
    }
  }
  try {
    if (P.App) P.App.addListener('backButton', handleBack);
  } catch (e) {}
})();
