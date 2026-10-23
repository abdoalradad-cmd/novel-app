package com.alradad.novels;

import android.os.Bundle;
import android.webkit.WebView;

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

    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(AppNativePlugin.class);
        super.onCreate(savedInstanceState);
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
