package com.alradad.novels;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ServiceInfo;
import android.graphics.drawable.Icon;
import android.media.session.MediaSession;
import android.media.session.PlaybackState;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

/**
 * خدمة تشغيل الصوت في الخلفية: بتفضل شغالة (Foreground Service) ومعاها إشعار فيه أزرار تحكم،
 * فالصوت يكمّل لو الشاشة قفلت أو المستخدم فتح تطبيق تاني، لحد ما يوقفه بنفسه.
 * الصوت نفسه بيتشغّل في صفحة الموقع؛ الخدمة بس بتحمي التطبيق من الإيقاف وبتعرض الإشعار.
 */
public class PlaybackService extends Service {

    public static final String A_SHOW = "com.alradad.novels.MEDIA_SHOW";
    public static final String A_PLAY = "com.alradad.novels.MEDIA_PLAY";
    public static final String A_PAUSE = "com.alradad.novels.MEDIA_PAUSE";
    public static final String A_PREV = "com.alradad.novels.MEDIA_PREV";
    public static final String A_NEXT = "com.alradad.novels.MEDIA_NEXT";
    public static final String A_STOP = "com.alradad.novels.MEDIA_STOP";
    private static final String CHANNEL = "radpad_playback";
    private static final int NOTIF_ID = 7420;

    /** الإضافة اللي بتوصّل ضغطات الإشعار للصفحة */
    public static volatile AppNativePlugin sink;
    /** true لما الخدمة شغالة (بنستخدمها عشان نمنع إيقاف الـ WebView في الخلفية) */
    public static volatile boolean active = false;

    private MediaSession session;
    private PowerManager.WakeLock wake;
    private String title = "RadPad";
    private String sub = "";
    private boolean playing = true;

    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent == null || intent.getAction() == null) return;
            String a = intent.getAction();
            AppNativePlugin s = sink;
            if (a.equals(A_PLAY)) { if (s != null) s.fireMedia("play"); }
            else if (a.equals(A_PAUSE)) { if (s != null) s.fireMedia("pause"); }
            else if (a.equals(A_PREV)) { if (s != null) s.fireMedia("prev"); }
            else if (a.equals(A_NEXT)) { if (s != null) s.fireMedia("next"); }
            else if (a.equals(A_STOP)) { if (s != null) s.fireMedia("stop"); stopSelf(); }
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        active = true;
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "تشغيل الصوت", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
        IntentFilter f = new IntentFilter();
        f.addAction(A_PLAY);
        f.addAction(A_PAUSE);
        f.addAction(A_PREV);
        f.addAction(A_NEXT);
        f.addAction(A_STOP);
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(receiver, f, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(receiver, f);
        try {
            session = new MediaSession(this, "RadPad");
            session.setCallback(new MediaSession.Callback() {
                @Override
                public void onPlay() { AppNativePlugin s = sink; if (s != null) s.fireMedia("play"); }
                @Override
                public void onPause() { AppNativePlugin s = sink; if (s != null) s.fireMedia("pause"); }
                @Override
                public void onSkipToNext() { AppNativePlugin s = sink; if (s != null) s.fireMedia("next"); }
                @Override
                public void onSkipToPrevious() { AppNativePlugin s = sink; if (s != null) s.fireMedia("prev"); }
                @Override
                public void onStop() { AppNativePlugin s = sink; if (s != null) s.fireMedia("stop"); stopSelf(); }
            });
            session.setActive(true);
        } catch (Throwable e) {
            session = null;
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && A_SHOW.equals(intent.getAction())) {
            String t = intent.getStringExtra("t");
            String s = intent.getStringExtra("s");
            if (t != null && t.length() > 0) title = t;
            sub = s == null ? "" : s;
            playing = intent.getBooleanExtra("p", true);
        }
        try {
            Notification n = build();
            if (Build.VERSION.SDK_INT >= 29) startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK);
            else startForeground(NOTIF_ID, n);
        } catch (Throwable e) {
            // لو النظام رفض الخدمة الأمامية منكسرش التطبيق
        }
        updateSession();
        updateWake();
        if (!playing) {
            try { stopForeground(false); } catch (Throwable e) { }
        }
        return START_NOT_STICKY;
    }

    private void updateWake() {
        try {
            if (playing) {
                if (wake == null) {
                    PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
                    if (pm != null) wake = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "radpad:playback");
                }
                if (wake != null && !wake.isHeld()) wake.acquire(6L * 60L * 60L * 1000L);
            } else if (wake != null && wake.isHeld()) {
                wake.release();
            }
        } catch (Throwable e) { }
    }

    private void updateSession() {
        if (session == null) return;
        try {
            long actions = PlaybackState.ACTION_PLAY | PlaybackState.ACTION_PAUSE | PlaybackState.ACTION_PLAY_PAUSE
                    | PlaybackState.ACTION_SKIP_TO_NEXT | PlaybackState.ACTION_SKIP_TO_PREVIOUS | PlaybackState.ACTION_STOP;
            PlaybackState st = new PlaybackState.Builder()
                    .setActions(actions)
                    .setState(playing ? PlaybackState.STATE_PLAYING : PlaybackState.STATE_PAUSED, 0L, playing ? 1f : 0f)
                    .build();
            session.setPlaybackState(st);
        } catch (Throwable e) { }
    }

    private PendingIntent pi(String action, int code) {
        Intent i = new Intent(action);
        i.setPackage(getPackageName());
        int fl = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) fl |= PendingIntent.FLAG_IMMUTABLE;
        return PendingIntent.getBroadcast(this, code, i, fl);
    }

    private Notification.Action act(int iconRes, String label, String action, int code) {
        Icon ic = Icon.createWithResource(this, iconRes);
        return new Notification.Action.Builder(ic, label, pi(action, code)).build();
    }

    private Notification build() {
        Notification.Builder b = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        b.setSmallIcon(R.drawable.ic_stat_radpad);
        b.setContentTitle(title);
        b.setContentText(sub);
        b.setOnlyAlertOnce(true);
        b.setShowWhen(false);
        b.setOngoing(playing);
        b.setVisibility(Notification.VISIBILITY_PUBLIC);
        try {
            Intent launch = getPackageManager().getLaunchIntentForPackage(getPackageName());
            if (launch != null) {
                int fl = PendingIntent.FLAG_UPDATE_CURRENT;
                if (Build.VERSION.SDK_INT >= 23) fl |= PendingIntent.FLAG_IMMUTABLE;
                b.setContentIntent(PendingIntent.getActivity(this, 0, launch, fl));
            }
        } catch (Throwable e) { }
        b.addAction(act(android.R.drawable.ic_media_previous, "-10", A_PREV, 1));
        if (playing) b.addAction(act(android.R.drawable.ic_media_pause, "إيقاف مؤقت", A_PAUSE, 2));
        else b.addAction(act(android.R.drawable.ic_media_play, "تشغيل", A_PLAY, 3));
        b.addAction(act(android.R.drawable.ic_media_next, "+10", A_NEXT, 4));
        b.addAction(act(android.R.drawable.ic_menu_close_clear_cancel, "إغلاق", A_STOP, 5));
        Notification.MediaStyle style = new Notification.MediaStyle();
        style.setShowActionsInCompactView(0, 1, 2);
        if (session != null) {
            try { style.setMediaSession(session.getSessionToken()); } catch (Throwable e) { }
        }
        b.setStyle(style);
        return b.build();
    }

    @Override
    public void onDestroy() {
        active = false;
        try { unregisterReceiver(receiver); } catch (Throwable e) { }
        try { if (wake != null && wake.isHeld()) wake.release(); } catch (Throwable e) { }
        try { if (session != null) { session.setActive(false); session.release(); } } catch (Throwable e) { }
        try { stopForeground(true); } catch (Throwable e) { }
        super.onDestroy();
    }
}
