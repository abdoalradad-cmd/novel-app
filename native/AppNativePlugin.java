package com.alradad.novels;

import android.app.Application;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.media.AudioManager;
import android.media.AudioPlaybackConfiguration;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.print.PrintAttributes;
import android.print.PrintDocumentAdapter;
import android.print.PrintManager;
import android.speech.tts.TextToSpeech;
import android.speech.tts.UtteranceProgressListener;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.core.content.ContextCompat;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * إضافة أصلية للتطبيق:
 *  - print: طباعة/حفظ PDF عبر نظام الطباعة في أندرويد (تدعم العربي والروايات الطويلة)
 *  - speak/stop: قراءة النص صوتيًا بمحرك أندرويد (TextToSpeech)
 */
@CapacitorPlugin(name = "AppNative")
public class AppNativePlugin extends Plugin {

    private TextToSpeech tts;
    private boolean ttsReady = false;
    private boolean ttsFailed = false;
    private final List<Runnable> waiting = new ArrayList<Runnable>();
    private final Map<String, PluginCall> calls = new ConcurrentHashMap<String, PluginCall>();
    private WebView printView;

    /* ------------------------- PDF / طباعة ------------------------- */

    @PluginMethod
    public void print(final PluginCall call) {
        final String html = call.getString("html", "");
        final String name = call.getString("name", "document");
        getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    final WebView wv = new WebView(getActivity());
                    printView = wv;
                    wv.setWebViewClient(new WebViewClient() {
                        @Override
                        public void onPageFinished(final WebView view, String url) {
                            // ملاحظة: view.postDelayed لا يعمل لأن الـ WebView غير مضاف للشاشة، فنستخدم Handler
                            new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
                                @Override
                                public void run() {
                                    try {
                                        PrintManager pm = (PrintManager) getActivity().getSystemService(Context.PRINT_SERVICE);
                                        PrintDocumentAdapter adapter = view.createPrintDocumentAdapter(name);
                                        PrintAttributes attrs = new PrintAttributes.Builder()
                                                .setMediaSize(PrintAttributes.MediaSize.ISO_A4)
                                                .build();
                                        pm.print(name, adapter, attrs);
                                        call.resolve();
                                    } catch (Exception e) {
                                        call.reject("print-failed: " + e.getMessage());
                                    }
                                }
                            }, 1500);
                        }
                    });
                    wv.loadDataWithBaseURL("https://localhost/", html, "text/html", "UTF-8", null);
                } catch (Exception e) {
                    call.reject("print-failed: " + e.getMessage());
                }
            }
        });
    }

    /* ------------------------- القراءة الصوتية ------------------------- */

    private void finish(String id, String error) {
        PluginCall c = calls.remove(id);
        if (c == null) return;
        if (error == null) c.resolve();
        else c.reject(error);
    }

    private void withTts(final Runnable r, final PluginCall call) {
        if (ttsReady) {
            r.run();
            return;
        }
        if (ttsFailed) {
            call.reject("tts-unavailable");
            return;
        }
        waiting.add(r);
        if (tts != null) return;
        tts = new TextToSpeech(getContext().getApplicationContext(), new TextToSpeech.OnInitListener() {
            @Override
            public void onInit(int status) {
                if (status == TextToSpeech.SUCCESS) {
                    ttsReady = true;
                    tts.setOnUtteranceProgressListener(new UtteranceProgressListener() {
                        @Override
                        public void onStart(String utteranceId) {
                        }

                        @Override
                        public void onDone(String utteranceId) {
                            finish(utteranceId, null);
                        }

                        @Override
                        public void onError(String utteranceId) {
                            finish(utteranceId, "tts-error");
                        }

                        @Override
                        public void onStop(String utteranceId, boolean interrupted) {
                            finish(utteranceId, "canceled");
                        }
                    });
                    List<Runnable> copy = new ArrayList<Runnable>(waiting);
                    waiting.clear();
                    for (Runnable x : copy) x.run();
                } else {
                    ttsFailed = true;
                    tts = null;
                    waiting.clear();
                    for (PluginCall c : calls.values()) c.reject("tts-unavailable");
                    calls.clear();
                }
            }
        });
    }

    private boolean pickLanguage(String lang) {
        String[] tags = new String[]{lang, "ar", "ar-EG", "ar-SA"};
        for (String tag : tags) {
            int r = tts.setLanguage(Locale.forLanguageTag(tag));
            if (r != TextToSpeech.LANG_MISSING_DATA && r != TextToSpeech.LANG_NOT_SUPPORTED) return true;
        }
        return false;
    }

    @PluginMethod
    public void speak(final PluginCall call) {
        final String text = call.getString("text", "");
        final String lang = call.getString("lang", "ar-SA");
        final Float rate = call.getFloat("rate", 1.0f);
        final Float pitch = call.getFloat("pitch", 1.0f);
        getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                withTts(new Runnable() {
                    @Override
                    public void run() {
                        if (!pickLanguage(lang)) {
                            call.reject("lang-unsupported");
                            return;
                        }
                        tts.setSpeechRate(rate);
                        tts.setPitch(pitch);
                        String id = UUID.randomUUID().toString();
                        calls.put(id, call);
                        int res = tts.speak(text, TextToSpeech.QUEUE_FLUSH, new Bundle(), id);
                        if (res != TextToSpeech.SUCCESS) {
                            calls.remove(id);
                            call.reject("tts-error");
                        }
                    }
                }, call);
            }
        });
    }

    @PluginMethod
    public void stop(final PluginCall call) {
        getActivity().runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (tts != null && ttsReady) tts.stop();
                call.resolve();
            }
        });
    }

    @Override
    protected void handleOnDestroy() {
        if (tts != null) {
            tts.stop();
            tts.shutdown();
        }
        super.handleOnDestroy();
    }

    // الاشتراك في موضوع إشعارات (مثلاً متابعة كاتب) — يتجاهل بهدوء لو Firebase غير مفعّل
    @PluginMethod
    public void subscribeTopic(PluginCall call) {
        try {
            String t = call.getString("topic");
            if (t != null && t.matches("[a-zA-Z0-9-_.~%]{1,900}")) com.google.firebase.messaging.FirebaseMessaging.getInstance().subscribeToTopic(t);
        } catch (Throwable e) { }
        call.resolve();
    }

    @PluginMethod
    public void unsubscribeTopic(PluginCall call) {
        try {
            String t = call.getString("topic");
            if (t != null && t.matches("[a-zA-Z0-9-_.~%]{1,900}")) com.google.firebase.messaging.FirebaseMessaging.getInstance().unsubscribeFromTopic(t);
        } catch (Throwable e) { }
        call.resolve();
    }

    /* ------------------------- تشغيل الصوت في الخلفية + إشعار التحكم ------------------------- */

    private boolean lifecycleHooked = false;

    private AudioManager.AudioPlaybackCallback apc;
    private Runnable stopTask;
    private final Handler mainH = new Handler(Looper.getMainLooper());

    @Override
    public void load() {
        PlaybackService.sink = this;
        mainH.post(new Runnable() {
            @Override
            public void run() {
                hookLifecycle();
                watchAudio();
            }
        });
    }

    /** بيراقب صوت التطبيق نفسه: أول ما يبدأ تشغيل صوت بيشغّل الخدمة والإشعار (من غير ما نعتمد على الصفحة)، وبعد ما الصوت يقف 25 ثانية بيقفلهم */
    private void watchAudio() {
        if (Build.VERSION.SDK_INT < 26 || apc != null) return;
        try {
            AudioManager am = (AudioManager) getContext().getSystemService(Context.AUDIO_SERVICE);
            if (am == null) return;
            apc = new AudioManager.AudioPlaybackCallback() {
                @Override
                public void onPlaybackConfigChanged(List<AudioPlaybackConfiguration> configs) {
                    boolean on = configs != null && !configs.isEmpty();
                    if (on) {
                        if (stopTask != null) { mainH.removeCallbacks(stopTask); stopTask = null; }
                        if (!PlaybackService.active) startMedia("RadPad", "جاري تشغيل الصوت", true);
                    } else if (PlaybackService.active && stopTask == null) {
                        stopTask = new Runnable() {
                            @Override
                            public void run() {
                                stopTask = null;
                                try { Context c = getContext(); c.stopService(new Intent(c, PlaybackService.class)); } catch (Throwable e) { }
                            }
                        };
                        mainH.postDelayed(stopTask, 25000);
                    }
                }
            };
            am.registerAudioPlaybackCallback(apc, mainH);
        } catch (Throwable e) { }
    }

    private void startMedia(String title, String sub, boolean playing) {
        startMedia(title, sub, playing, -1L, -1L, 1f);
    }

    private void startMedia(String title, String sub, boolean playing, long pos, long dur, float rate) {
        try {
            Context c = getContext();
            Intent i = new Intent(c, PlaybackService.class);
            i.setAction(PlaybackService.A_SHOW);
            i.putExtra("t", title);
            i.putExtra("s", sub);
            i.putExtra("p", playing);
            i.putExtra("pos", pos);
            i.putExtra("dur", dur);
            i.putExtra("r", rate);
            ContextCompat.startForegroundService(c, i);
        } catch (Throwable e) { }
    }

    private void hookLifecycle() {
        if (lifecycleHooked || getActivity() == null) return;
        lifecycleHooked = true;
        try {
            getActivity().getApplication().registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
                @Override public void onActivityPaused(Activity a) { if (PlaybackService.active) keepWebViewAlive(); }
                @Override public void onActivityStopped(Activity a) { if (PlaybackService.active) keepWebViewAlive(); }
                @Override public void onActivityCreated(Activity a, Bundle b) { }
                @Override public void onActivityStarted(Activity a) { }
                @Override public void onActivityResumed(Activity a) { }
                @Override public void onActivitySaveInstanceState(Activity a, Bundle b) { }
                @Override public void onActivityDestroyed(Activity a) { }
            });
        } catch (Throwable e) { lifecycleHooked = false; }
    }

    /** بتتندهي من الخدمة لما المستخدم يدوس زر في الإشعار */
    public void fireMedia(String action) {
        JSObject o = new JSObject();
        o.put("a", action);
        notifyListeners("mediaAction", o);
    }

    public void fireSeek(long posMs) {
        JSObject o = new JSObject();
        o.put("a", "seek");
        o.put("pos", posMs);
        notifyListeners("mediaAction", o);
    }

    private void keepWebViewAlive() {
        final Handler h = new Handler(Looper.getMainLooper());
        Runnable r = new Runnable() {
            @Override
            public void run() {
                try {
                    if (!PlaybackService.active) return;
                    WebView w = getBridge().getWebView();
                    if (w != null) { w.onResume(); w.resumeTimers(); }
                } catch (Throwable e) { }
            }
        };
        h.postDelayed(r, 200);
        h.postDelayed(r, 1200);
    }

    @PluginMethod
    public void mediaShow(final PluginCall call) {
        Boolean pl = call.getBoolean("playing", true);
        if (stopTask != null) { mainH.removeCallbacks(stopTask); stopTask = null; }
        Integer ps = call.getInt("pos", -1), du = call.getInt("dur", -1);
        Float rt = call.getFloat("rate", 1f);
        startMedia(call.getString("title", "RadPad"), call.getString("sub", ""), pl == null ? true : pl.booleanValue(),
                ps == null ? -1L : ps.longValue(), du == null ? -1L : du.longValue(), rt == null ? 1f : rt.floatValue());
        hookLifecycle();
        call.resolve();
    }

    @PluginMethod
    public void mediaHide(final PluginCall call) {
        try {
            Context c = getContext();
            c.stopService(new Intent(c, PlaybackService.class));
        } catch (Throwable e) { }
        call.resolve();
    }
}
