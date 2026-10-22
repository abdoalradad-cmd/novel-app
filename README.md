# تطبيق روائع عبدالرحمن الرداد (أندرويد)

التطبيق يفتح موقعك مباشرة: https://abdoalradad-cmd.github.io/novel_site/
أي تعديل ترفعه على الموقع يظهر في التطبيق تلقائيًا بدون بناء APK جديد.

## خطوة واحدة على الموقع (مرة واحدة)
ارفع `site-addon/android-bridge.js` بجانب `index.html` في مستودع الموقع، وأضف قبل `</body>`:
```html
<script src="android-bridge.js"></script>
```
(يفعّل زر الرجوع وفتح الروابط الخارجية وحفظ الـ PDF داخل التطبيق، ولا يؤثر على المتصفح.)

## بناء الـ APK (مرة واحدة)
1. ارفع هذا المجلد كمستودع GitHub جديد.
2. Actions ← Build Android APK ← Run workflow.
3. نزّل `alradad-novels-apk` (فيه app-debug.apk).
تحتاج بناء جديد فقط لو غيّرت الأيقونة/الاسم/الرابط (`resources/` و `capacitor.config.json`).
