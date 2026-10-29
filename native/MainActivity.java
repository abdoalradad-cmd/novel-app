package com.alradad.novels;

import android.Manifest;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.webkit.WebSettings;
import android.webkit.WebView;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.webkit.WebViewCompat;
import androidx.webkit.WebViewFeature;

import com.getcapacitor.BridgeActivity;

import java.util.HashSet;
import java.util.Set;

public class MainActivity extends BridgeActivity {

    // رابط الموقع (نفس القيمة في capacitor.config.json)
    private static final String SITE_ORIGIN = "https://abdoalradad-cmd.github.io";
    private static final String BRIDGE_URL = SITE_ORIGIN + "/novel_site/android-bridge.js";

    // يُنفَّذ في بداية كل صفحة قبل أي كود في الموقع: يحمّل android-bridge.js من الموقع نفسه.
    // أول مرة يحمّله من الإنترنت ويحفظ نسخة، وبعدها يشغّل النسخة المحفوظة فورًا ويحدّثها في الخلفية.
    private static final String LOADER =
            "(function(){try{"
            + "if(window.__appBridgeLoaded)return;"
            + "var U='" + BRIDGE_URL + "',K='__app_bridge_src_v1',code=null;"
            + "try{code=localStorage.getItem(K);}catch(e){}"
            + "if(!code){try{var x=new XMLHttpRequest();x.open('GET',U+'?t='+Date.now(),false);x.send(null);"
            + "if(x.status===200&&x.responseText.length>1000){code=x.responseText;"
            + "try{localStorage.setItem(K,code);}catch(e){}}}catch(e){}}"
            + "else{try{var f=new XMLHttpRequest();f.open('GET',U+'?t='+Date.now(),true);"
            + "f.onload=function(){if(f.status===200&&f.responseText.length>1000){try{localStorage.setItem(K,f.responseText);}catch(e){}}};"
            + "f.send(null);}catch(e){}}"
            + "if(code){window.__appBridgeLoaded=true;(0,eval)(code);}"
            + "}catch(e){}})();";

    // إشعارات الموبايل: قناة + إذن أندرويد 13 + الاشتراك في موضوع "all" (لو ملف Firebase مش موجود بيتجاهل بهدوء)
    private void initPush() {
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                NotificationChannel ch = new NotificationChannel("radpad_alerts", "إشعارات RadPad", NotificationManager.IMPORTANCE_HIGH);
                getSystemService(NotificationManager.class).createNotificationChannel(ch);
            }
            if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.POST_NOTIFICATIONS}, 77);
            }
        } catch (Throwable t) { }
        try {
            com.google.firebase.messaging.FirebaseMessaging.getInstance().subscribeToTopic("all");
        } catch (Throwable t) { }
    }

    // ===== العمل بدون نت =====
    // لو مفيش نت: نخلّي المتصفح الداخلي يعرض آخر نسخة محفوظة من الموقع (من الكاش) بدل صفحة الخطأ.
    private static final String SITE_URL = SITE_ORIGIN + "/novel_site/";

    private boolean isOnline() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return true;
            if (Build.VERSION.SDK_INT >= 23) {
                Network n = cm.getActiveNetwork();
                if (n == null) return false;
                NetworkCapabilities c = cm.getNetworkCapabilities(n);
                return c != null && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
            }
            return cm.getActiveNetworkInfo() != null && cm.getActiveNetworkInfo().isConnected();
        } catch (Throwable t) { return true; }
    }

    private void applyCacheMode(final boolean reload) {
        try {
            final WebView wv = getBridge().getWebView();
            final boolean online = isOnline();
            runOnUiThread(new Runnable() {
                public void run() {
                    try {
                        wv.getSettings().setCacheMode(online ? WebSettings.LOAD_DEFAULT : WebSettings.LOAD_CACHE_ELSE_NETWORK);
                        String u = wv.getUrl();
                        boolean onErrorPage = u == null || u.startsWith("https://localhost") || u.startsWith("http://localhost") || u.startsWith("about:") || u.startsWith("data:");
                        if (reload && onErrorPage) wv.loadUrl(SITE_URL);
                    } catch (Throwable t) { }
                }
            });
        } catch (Throwable t) { }
    }

    private void watchNetwork() {
        try {
            if (Build.VERSION.SDK_INT < 24) return;
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return;
            cm.registerDefaultNetworkCallback(new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) { applyCacheMode(true); }
                @Override public void onLost(Network network) { applyCacheMode(false); }
            });
        } catch (Throwable t) { }
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(AppNativePlugin.class);
        super.onCreate(savedInstanceState);
        initPush();
        applyCacheMode(true);
        watchNetwork();
        try {
            WebView wv = getBridge().getWebView();
            if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
                Set<String> origins = new HashSet<String>();
                origins.add(SITE_ORIGIN);
                WebViewCompat.addDocumentStartJavaScript(wv, LOADER, origins);
            }
        } catch (Exception e) {
            // لو فشل الحقن يبقى التطبيق شغال عادي (والموقع يقدر يحمّل الملف بنفسه)
        }
    }
}
