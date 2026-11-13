package com.example.carrierdmblocker;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import io.github.libxposed.api.XposedModule;

/**
 * CTAutoRegistBlocker —— 基于 libxposed API 102 的 Xposed 模块
 *
 * 目标: com.oppo.ctautoregist（OPPO 预装 · 中国电信终端自注册，16.1.5）
 *
 * 这个包和联通/移动那两个不一样：它不发 HTTPS 表单，而是
 *   1) 用 SmsManager.sendDataMessage 往电信/卫星发「注册短信」（4 个服务：IMS/Satellite × SIM1/SIM2）
 *   2) 用 HttpURLConnection 打 https://zzhc.vnet.cn/ 与 https://typdm.tydevice.com?jsonstr=
 *   3) 采集 IMEI / IMSI / ICCID（t.t 是设备信息读取器）
 *
 * hook 点（16.1.5 实测）：
 *   L1 网络 : t.j.c(String, byte[]) : JSONObject      -> null
 *            u.a.c(String) : JSONObject               -> null
 *   L2 短信 : ImsSmsSim{1,2}RegisterService.g(SmsManager, byte[], PendingIntent)
 *            SatelliteSmsSim{1,2}RegisterService.h(SmsManager, byte[])   -> 都不执行
 *   L3 采集 : t.t 的全部实例方法（g=IMEI / o=ICCID / p=IMSI ...）        -> 返回默认值
 *   L4 触发 : RegisterReceiver.onReceive(Context, Intent)                -> 不执行
 *            4 个注册服务 onStartCommand(Intent,int,int)                -> START_NOT_STICKY
 *
 * 注意：类名是 16.1.5 的结构，t.t 这类是 R8 重打包后的名字，OTA 后需重新核对。
 */
public class CtaHook extends XposedModule {

    private static final String TAG = "CTBlocker";
    private static final String PKG = "com.oppo.ctautoregist";
    private static final String PREF = "ct_blocker_stats";
    private static final String SHARED_SUBDIR = "SHBlocker";

    private static volatile String hookSummary = "none";
    private static volatile long lastStatusWrite = 0L;

    private static volatile int cL1, cL2, cL3, cL4, cL5;

    private static volatile boolean cfgNet = true;
    private static volatile boolean cfgSms = true;
    private static volatile boolean cfgCollect = true;
    private static volatile boolean cfgTrigger = true;

    private static volatile CtaHook INSTANCE;

    /* ================= 生命周期 ================= */

    @Override
    public void onModuleLoaded(@NonNull ModuleLoadedParam param) {
        INSTANCE = this;
        log("module loaded: process=" + param.getProcessName()
                + " framework=" + getFrameworkName() + " " + getFrameworkVersionCode()
                + " api=" + getApiVersion() + " libApi=" + LIB_API);
    }

    @Override
    @RequiresApi(Build.VERSION_CODES.Q)
    public void onPackageReady(@NonNull PackageReadyParam param) {
        if (!PKG.equals(param.getPackageName())) return;
        final ClassLoader cl = param.getClassLoader();
        log("enter " + param.getPackageName() + " pid=" + android.os.Process.myPid());

        try { cL1 = hookNetwork(cl); }  catch (Throwable t) { log("L1 fail: " + t); }
        try { cL2 = hookSms(cl); }      catch (Throwable t) { log("L2 fail: " + t); }
        try { cL3 = hookCollect(cl); }  catch (Throwable t) { log("L3 fail: " + t); }
        try { cL4 = hookTrigger(cl); }  catch (Throwable t) { log("L4 fail: " + t); }
        try { cL5 = hookAppInfo(cl); }  catch (Throwable t) { log("L5 fail: " + t); }

        hookSummary = "L1=" + cL1 + " L2=" + cL2 + " L3=" + cL3 + " L4=" + cL4;
        log("all hooks installed " + hookSummary);
    }

    /* ================= L1: 两个 HTTP 出口 ================= */

    private int hookNetwork(ClassLoader cl) throws Throwable {
        int n = 0;
        n += hookJsonEgress(cl.loadClass("t.j"), "t.j.c");
        n += hookJsonEgress(cl.loadClass("u.a"), "u.a.c");
        log("L1 hooked " + n + " egress method(s)");
        return n;
    }

    private int hookJsonEgress(Class<?> c, String tag) {
        int n = 0;
        for (Method m : c.getDeclaredMethods()) {
            if (!"c".equals(m.getName())) continue;
            Class<?>[] p = m.getParameterTypes();
            if (m.getReturnType() != org.json.JSONObject.class) continue;
            if (!(p.length == 2 && p[0] == String.class && p[1] == byte[].class)
                    && !(p.length == 1 && p[0] == String.class)) continue;
            try {
                hook(m).setId("ct_l1_" + tag).intercept(chain -> {
                    String url = String.valueOf(chain.getArg(0));
                    long c1 = bump("net_block", 1);
                    maybeWriteStatus();
                    log("L1 network blocked #" + c1 + " -> " + url);
                    return null;   // 调用方拿到 null 会走失败分支，不发包
                });
                n++;
            } catch (Throwable t) {
                log("L1 hook fail " + tag + ": " + t);
            }
        }
        return n;
    }

    /* ================= L2: 注册短信 ================= */

    private int hookSms(ClassLoader cl) {
        int n = 0;
        String[] svcs = {
                "com.oppo.ctautoregist.ImsSmsSim1RegisterService",
                "com.oppo.ctautoregist.ImsSmsSim2RegisterService",
                "com.oppo.ctautoregist.SatelliteSmsSim1RegisterService",
                "com.oppo.ctautoregist.SatelliteSmsSim2RegisterService",
        };
        for (String svc : svcs) {
            try {
                Class<?> c = cl.loadClass(svc);
                for (Method m : c.getDeclaredMethods()) {
                    Class<?>[] p = m.getParameterTypes();
                    if (m.getReturnType() != void.class) continue;
                    boolean isSmsSender = p.length >= 2
                            && p[0] == android.telephony.SmsManager.class
                            && p[1] == byte[].class;
                    if (!isSmsSender) continue;
                    try {
                        hook(m).setId("ct_l2_" + m.getName()).intercept(chain -> {
                            long c2 = bump("sms_block", 1);
                            maybeWriteStatus();
                            log("L2 SMS send blocked #" + c2 + " (" + svc + "#" + m.getName() + ")");
                            return null;   // void：不执行原方法 = 不发短信
                        });
                        n++;
                    } catch (Throwable t) {
                        log("L2 hook fail " + svc + "#" + m.getName() + ": " + t);
                    }
                }
            } catch (Throwable t) {
                log("L2 class fail " + svc + ": " + t);
            }
        }
        log("L2 hooked " + n + " sms-sender method(s)");
        return n;
    }

    /* ================= L3: 设备信息采集 ================= */

    private int hookCollect(ClassLoader cl) throws Throwable {
        Class<?> c = cl.loadClass("t.t");
        int n = 0;
        for (Method m : c.getDeclaredMethods()) {
            if (Modifier.isStatic(m.getModifiers())) continue;
            if (m.getName().equals("<init>")) continue;
            final String name = m.getName();
            try {
                hook(m).setId("ct_l3_" + name).intercept(chain -> {
                    bump("collect_block", 1);
                    maybeWriteStatus();
                    log("L3 device-info blocked: t.t#" + name);
                    return defaultFor(m.getReturnType());
                });
                n++;
            } catch (Throwable t) {
                log("L3 hook fail " + name + ": " + t);
            }
        }
        log("L3 hooked " + n + " method(s) on t.t");
        return n;
    }

    /* ================= L4: 触发入口 ================= */

    private int hookTrigger(ClassLoader cl) {
        int n = 0;

        try {
            Class<?> r = cl.loadClass("com.oppo.ctautoregist.RegisterReceiver");
            for (Method m : r.getDeclaredMethods()) {
                if (!"onReceive".equals(m.getName())) continue;
                hook(m).setId("ct_l4_recv").intercept(chain -> {
                    long c4 = bump("trigger_block", 1);
                    maybeWriteStatus();
                    log("L4 RegisterReceiver.onReceive blocked (" + c4 + ")");
                    return null;
                });
                n++;
            }
        } catch (Throwable t) {
            log("L4 receiver fail: " + t);
        }

        String[] svcs = {
                "com.oppo.ctautoregist.ImsSmsSim1RegisterService",
                "com.oppo.ctautoregist.ImsSmsSim2RegisterService",
                "com.oppo.ctautoregist.SatelliteSmsSim1RegisterService",
                "com.oppo.ctautoregist.SatelliteSmsSim2RegisterService",
        };
        for (String svc : svcs) {
            try {
                Class<?> c = cl.loadClass(svc);
                for (Method m : c.getDeclaredMethods()) {
                    if (!"onStartCommand".equals(m.getName())) continue;
                    try {
                        hook(m).setId("ct_l4_svc").intercept(chain -> {
                            long c5 = bump("trigger_block", 1);
                            maybeWriteStatus();
                            log("L4 service start blocked (" + c5 + "): " + svc);
                            return 2;   // START_NOT_STICKY
                        });
                        n++;
                    } catch (Throwable t) {
                        log("L4 svc hook fail " + svc + ": " + t);
                    }
                }
            } catch (Throwable t) {
                log("L4 svc class fail " + svc + ": " + t);
            }
        }

        log("L4 hooked " + n + " trigger method(s)");
        return n;
    }

    /* ================= 等 Application 就绪 ================= */

    private int hookAppInfo(ClassLoader cl) throws Throwable {
        Method onCreate = Application.class.getDeclaredMethod("onCreate");
        hook(onCreate).setId("ct_app_ready").intercept(chain -> {
            Object result = chain.proceed();
            ensureConfig();
            report();
            writeStatus();
            appendEvent("boot: hooks=" + hookSummary);
            return result;
        });
        return 1;
    }

    /* ================= 与 KernelSU 模块的联动 ================= */

    @Nullable
    private static File sharedDir() {
        try {
            Context c = appContext();
            if (c == null) return null;
            File[] dirs = c.getExternalMediaDirs();
            if (dirs == null || dirs.length == 0 || dirs[0] == null) return null;
            File d = new File(dirs[0], SHARED_SUBDIR);
            if (!d.exists() && !d.mkdirs()) return null;
            return d;
        } catch (Throwable t) {
            return null;
        }
    }

    private static final String DEFAULT_CONFIG =
            "# CTAutoRegistBlocker 开关（1=启用，0=关闭）\n" +
            "# 修改后重启目标进程生效（su -c \"am force-stop " + PKG + "\"）\n" +
            "BLOCK_NET=1\n" +
            "BLOCK_SMS=1\n" +
            "BLOCK_COLLECT=1\n" +
            "BLOCK_TRIGGER=1\n";

    private static class Config {
        boolean net = true, sms = true, collect = true, trigger = true;
    }

    private static Config readConfig() {
        Config c = new Config();
        try {
            File dir = sharedDir();
            if (dir == null) return c;
            File f = new File(dir, "config.conf");
            if (!f.exists()) {
                writeFile(f, DEFAULT_CONFIG);
                return c;
            }
            BufferedReader r = new BufferedReader(new FileReader(f));
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int i = line.indexOf('=');
                if (i <= 0) continue;
                String k = line.substring(0, i).trim();
                boolean on = line.substring(i + 1).trim().equals("1");
                if ("BLOCK_NET".equals(k)) c.net = on;
                else if ("BLOCK_SMS".equals(k)) c.sms = on;
                else if ("BLOCK_COLLECT".equals(k)) c.collect = on;
                else if ("BLOCK_TRIGGER".equals(k)) c.trigger = on;
            }
            r.close();
        } catch (Throwable t) {
            log("readConfig fail " + t);
        }
        return c;
    }

    private static void ensureConfig() {
        try {
            Config c = readConfig();
            cfgNet = c.net;
            cfgSms = c.sms;
            cfgCollect = c.collect;
            cfgTrigger = c.trigger;
            log("config: net=" + cfgNet + " sms=" + cfgSms
                    + " collect=" + cfgCollect + " trigger=" + cfgTrigger);
        } catch (Throwable t) {
            log("ensureConfig fail " + t);
        }
    }

    private static void writeStatus() {
        try {
            File dir = sharedDir();
            if (dir == null) return;
            long now = System.currentTimeMillis();
            lastStatusWrite = now;
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date(now));
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("  \"module\": \"xposed\",\n");
            sb.append("  \"api\": \"libxposed/").append(LIB_API).append("\",\n");
            sb.append("  \"package\": \"").append(PKG).append("\",\n");
            sb.append("  \"pid\": ").append(android.os.Process.myPid()).append(",\n");
            sb.append("  \"updated\": ").append(now).append(",\n");
            sb.append("  \"updated_readable\": \"").append(ts).append("\",\n");
            sb.append("  \"hooks\": \"").append(hookSummary).append("\",\n");
            sb.append("  \"stats\": {\n");
            sb.append("    \"net_block\": ").append(get("net_block")).append(",\n");
            sb.append("    \"sms_block\": ").append(get("sms_block")).append(",\n");
            sb.append("    \"collect_block\": ").append(get("collect_block")).append(",\n");
            sb.append("    \"trigger_block\": ").append(get("trigger_block")).append("\n");
            sb.append("  }\n");
            sb.append("}\n");
            writeFile(new File(dir, "status.json"), sb.toString());
        } catch (Throwable t) {
            log("writeStatus fail " + t);
        }
    }

    private static void maybeWriteStatus() {
        long now = System.currentTimeMillis();
        if (now - lastStatusWrite < 3000) return;
        writeStatus();
    }

    private static void appendEvent(String msg) {
        try {
            File dir = sharedDir();
            if (dir == null) return;
            File f = new File(dir, "events.log");
            String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                    .format(new Date(System.currentTimeMillis()));
            FileOutputStream fos = new FileOutputStream(f, true);
            fos.write((ts + "  " + msg + "\n").getBytes("UTF-8"));
            fos.close();
            if (f.length() > 262144L) writeFile(f, "");
        } catch (Throwable t) {
            // ignore
        }
    }

    private static void writeFile(File f, String content) {
        try {
            FileOutputStream fos = new FileOutputStream(f, false);
            fos.write(content.getBytes("UTF-8"));
            fos.close();
        } catch (Throwable t) {
            log("writeFile fail " + t);
        }
    }

    /* ================= 工具 ================= */

    @Nullable
    private static Context appContext() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Method m = at.getMethod("currentApplication");
            return (Context) m.invoke(null);
        } catch (Throwable t) {
            return null;
        }
    }

    @Nullable
    private static SharedPreferences sp() {
        Context c = appContext();
        return c == null ? null : c.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    private static long bump(String key, long delta) {
        try {
            SharedPreferences p = sp();
            if (p == null) return -1;
            long v = p.getLong(key, 0L) + delta;
            p.edit().putLong(key, v).apply();
            return v;
        } catch (Throwable t) {
            return -1;
        }
    }

    private static long get(String key) {
        try {
            SharedPreferences p = sp();
            return p == null ? 0L : p.getLong(key, 0L);
        } catch (Throwable t) {
            return 0L;
        }
    }

    @Nullable
    private static Object defaultFor(Class<?> t) {
        if (!t.isPrimitive()) return null;
        if (t == boolean.class) return Boolean.FALSE;
        if (t == byte.class) return (byte) 0;
        if (t == char.class) return (char) 0;
        if (t == short.class) return (short) 0;
        if (t == int.class) return 0;
        if (t == long.class) return 0L;
        if (t == float.class) return 0f;
        if (t == double.class) return 0d;
        return null;
    }

    private static void report() {
        log("===== stats =====\n"
                + "net blocked: " + get("net_block") + "\n"
                + "sms blocked: " + get("sms_block") + "\n"
                + "collect blocked: " + get("collect_block") + "\n"
                + "trigger blocked: " + get("trigger_block"));
    }

    private static void log(String msg) {
        CtaHook m = INSTANCE;
        if (m != null) {
            m.log(Log.INFO, TAG, msg);
        } else {
            Log.i(TAG, msg);
        }
    }
}
