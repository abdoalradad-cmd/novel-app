package com.alradad.novels;

import android.content.Context;
import android.os.Bundle;
import android.print.PrintAttributes;
import android.print.PrintDocumentAdapter;
import android.print.PrintManager;
import android.speech.tts.TextToSpeech;
import android.speech.tts.UtteranceProgressListener;
import android.webkit.WebView;
import android.webkit.WebViewClient;

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
                            view.postDelayed(new Runnable() {
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
}
