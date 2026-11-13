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
 * RegServiceBlocker —— 基于 libxposed API 102 的 Xposed 模块
 *
 * 目标: com.coloros.regservice（OPPO/ColorOS 预装的 神州泰岳 Richinfo DM 组件，16.0.20）
 *
 * 与 SystemHelperBlocker 的差别：这个包没有单一的 HTTP 出口，有三条独立通道，
 * 所以按「出口 → 采集 → 落库 → 触发 → 补丁」五层分别处理：
 *
 *   L1 上报出口 : com.android.volley.RequestQueue.add(Request)          -> 不执行，返回 null
 *                 （全包 20+ 处上报都汇到这个队列，一处掐断全部）
 *   L2 下载出口 : cn.richinfo.dm.i0.b(String):InputStream               -> 返回 null
 *                 cn.richinfo.dm.q.a(File):void                          -> 不执行
 *                 （补丁包走裸 HttpURLConnection，不走 volley，必须单独堵）
 *   L3 采集     : cn.richinfo.dm.DMController 的全部实例方法            -> 全部短路
 *                 （appInfoReport / networkCollect / netSpeedCollect / wifiListCollect /
 *                  reportHeartbeat / reportWifiListMsg / timeTrafficReport / onSimStateChange ...）
 *   L4 落库     : cn.richinfo.dm.db.DbManager 的 insert* / update*      -> 全部短路
 *   L5 三方触发 : cn.richinfo.dm.provider.DMProvider 的 call/query/...  -> 全部短路
 *                 （16.x 新增的无权限 provider，任何应用可调用触发采集）
 *   L6 补丁抑制 : 清空 files/dynamic + DYNAMIC_LOAD_SWITCH=0
 *                 （patch.jar 由 DexClassLoader 加载，源头断掉即无法执行）
 *
 * 注意：类名是本版本(16.0.20 / 20260610)的结构，方法名未混淆；
 *       大版本升级（17.x）后需要重新核对 hook 点。
 */
public class RgsHook extends XposedModule {

    private static final String TAG = "RGSBlocker";
    private static final String PKG = "com.coloros.regservice";
    private static final String PREF = "rgs_blocker_stats";

    /** 与 KernelSU 模块共享的目录（app-specific media，双方都有权限） */
    private static final String SHARED_SUBDIR = "SHBlocker";

    private static volatile String hookSummary = "none";
    private static volatile long lastStatusWrite = 0L;

    private static volatile int cL1, cL2, cL3, cL4, cL5;

    private static volatile boolean cfgEgress = true;
    private static volatile boolean cfgDownload = true;
    private static volatile boolean cfgCollect = true;
    private static volatile boolean cfgDb = true;
    private static volatile boolean cfgProvider = true;
    private static volatile boolean cfgPatch = true;
    private static volatile boolean cfgWipe = true;
    private static volatile boolean cfgUnhide = true;

    /** 被 ColorOS 从包列表里过滤掉的包（实测全机只有它一个真实应用被隐藏） */
    private static final String HIDDEN_PKG = "com.coloros.regservice";
    /** 承载「应用列表」UI 的进程：在这里 hook 才能让用户看见 */
    private static final String UNHIDE_HOST = "com.android.settings";
    private static volatile int cUnhide;

    private static volatile RgsHook INSTANCE;

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
        final String pn = param.getPackageName();
        final boolean isTarget = PKG.equals(pn);
        final boolean isUnhideHost = UNHIDE_HOST.equals(pn);
        if (!isTarget && !isUnhideHost) return;

        final ClassLoader cl = param.getClassLoader();
        log("enter " + pn + " pid=" + android.os.Process.myPid()
                + (isTarget ? " [target]" : " [unhide-host]"));

        if (isTarget) {
            try { cL1 = hookEgress(cl); }    catch (Throwable t) { log("L1 fail: " + t); }
            try { cL2 = hookDownload(cl); }  catch (Throwable t) { log("L2 fail: " + t); }
            try { cL3 = hookCollect(cl); }   catch (Throwable t) { log("L3 fail: " + t); }
            try { cL4 = hookDb(cl); }        catch (Throwable t) { log("L4 fail: " + t); }
            try { cL5 = hookProvider(cl); }  catch (Throwable t) { log("L5 fail: " + t); }
            try { hookAppReady(); }          catch (Throwable t) { log("app-ready fail: " + t); }
        }

        // 隐藏包「现行」：在目标进程和承载 UI 的进程里都要补
        try { cUnhide = hookUnhide(cl); }    catch (Throwable t) { log("UNHIDE fail: " + t); }
        if (isUnhideHost) {
            try { cUnhide += hookColorOSHideFilter(cl); } catch (Throwable t) { log("COS filter fail: " + t); }
        }

        hookSummary = "L1=" + cL1 + " L2=" + cL2 + " L3=" + cL3 + " L4=" + cL4 + " L5=" + cL5
                + " UNHIDE=" + cUnhide;
        log("all hooks installed " + hookSummary);
    }

    /* ================= L1: 掐断 volley 队列 ================= */

    private int hookEgress(ClassLoader cl) throws Throwable {
        Class<?> rq = cl.loadClass("com.android.volley.RequestQueue");
        int n = 0;
        for (Method m : rq.getDeclaredMethods()) {
            if (!"add".equals(m.getName())) continue;
            Class<?>[] p = m.getParameterTypes();
            if (p.length != 1 || !"com.android.volley.Request".equals(p[0].getName())) continue;
            hook(m).setId("rgs_l1").intercept(chain -> {
                String url = urlOf(chain.getArg(0));
                long c = bump("egress_count", 1);
                maybeWriteStatus();
                log("L1 upload blocked #" + c + " -> " + url);
                return null;   // 请求不进队列 = 不发包
            });
            n++;
        }
        log("L1 hooked " + n + " method(s): RequestQueue.add(Request)");
        return n;
    }

    /** 尽力从 Request 里取 URL，只用于日志，失败不影响拦截 */
    private static String urlOf(Object req) {
        if (req == null) return "?";
        try {
            Method g = req.getClass().getMethod("getUrl");
            Object v = g.invoke(req);
            return String.valueOf(v);
        } catch (Throwable t) {
            return "?";
        }
    }

    /* ================= L2: 堵死裸 HttpURLConnection 下载 ================= */

    private int hookDownload(ClassLoader cl) throws Throwable {
        int n = 0;

        // 补丁下载：InputStream b(String url)
        Class<?> i0 = cl.loadClass("cn.richinfo.dm.i0");
        for (Method m : i0.getDeclaredMethods()) {
            if (!"b".equals(m.getName())) continue;
            Class<?>[] p = m.getParameterTypes();
            if (p.length != 1 || p[0] != String.class) continue;
            if (m.getReturnType() != java.io.InputStream.class) continue;
            hook(m).setId("rgs_l2_dl").intercept(chain -> {
                long c = bump("download_block", 1);
                maybeWriteStatus();
                log("L2 download blocked #" + c + " -> " + chain.getArg(0));
                return null;
            });
            n++;
        }

        // 落盘：void a(File)
        Class<?> q = cl.loadClass("cn.richinfo.dm.q");
        for (Method m : q.getDeclaredMethods()) {
            if (!"a".equals(m.getName())) continue;
            Class<?>[] p = m.getParameterTypes();
            if (p.length != 1 || p[0] != File.class) continue;
            hook(m).setId("rgs_l2_file").intercept(chain -> {
                long c = bump("download_block", 1);
                maybeWriteStatus();
                log("L2 file write blocked #" + c);
                return null;
            });
            n++;
        }

        log("L2 hooked " + n + " method(s): i0.b(String) / q.a(File)");
        return n;
    }

    /* ================= L3: 采集层全部短路 ================= */

    private int hookCollect(ClassLoader cl) throws Throwable {
        Class<?> c = cl.loadClass("cn.richinfo.dm.DMController");
        int n = 0;
        for (Method m : c.getDeclaredMethods()) {
            if (Modifier.isStatic(m.getModifiers())) continue;   // 静态的是 R8 桥，交给实例方法兜住
            if (m.getReturnType() == void.class && m.getParameterTypes().length == 0
                    && !isBusinessMethod(m.getName())) continue;
            final String name = m.getName();
            try {
                hook(m).setId("rgs_l3_" + name).intercept(chain -> {
                    bump("collect_block", 1);
                    maybeWriteStatus();
                    log("L3 collect blocked: " + name);
                    return defaultFor(m.getReturnType());
                });
                n++;
            } catch (Throwable t) {
                log("L3 hook fail " + name + ": " + t);
            }
        }
        log("L3 hooked " + n + " method(s) on DMController");
        return n;
    }

    /** 采集/上报相关的方法名（其余实例方法放行，避免误伤 getInstance 之外的工具方法） */
    private static boolean isBusinessMethod(String name) {
        return name.startsWith("report")
                || name.startsWith("on")
                || name.startsWith("collect")
                || name.startsWith("wifiListCollect")
                || name.startsWith("netSpeedCollect")
                || name.startsWith("networkCollect")
                || name.startsWith("appInfoReport")
                || name.startsWith("insertTrafficIno")
                || name.startsWith("timeTrafficReport")
                || name.startsWith("checkUpdate")
                || name.startsWith("checkLogFileReport")
                || name.startsWith("updateBatteryChargeLog")
                || name.startsWith("updateBluetoothLog");
    }

    /* ================= L4: 禁止落库 ================= */

    private int hookDb(ClassLoader cl) throws Throwable {
        Class<?> c = cl.loadClass("cn.richinfo.dm.db.DbManager");
        int n = 0;
        for (Method m : c.getDeclaredMethods()) {
            String nm = m.getName();
            if (!(nm.startsWith("insert") || nm.startsWith("update"))) continue;
            final String name = nm;
            try {
                hook(m).setId("rgs_l4_" + name).intercept(chain -> {
                    long c4 = bump("db_block", 1);
                    maybeWriteStatus();
                    log("L4 write blocked: " + name + " (" + c4 + ")");
                    return defaultFor(m.getReturnType());
                });
                n++;
            } catch (Throwable t) {
                log("L4 hook fail " + name + ": " + t);
            }
        }
        log("L4 hooked " + n + " insert*/update* on DbManager");
        return n;
    }

    /* ================= L5: 三方触发入口 ================= */

    private int hookProvider(ClassLoader cl) throws Throwable {
        Class<?> c = cl.loadClass("cn.richinfo.dm.provider.DMProvider");
        int n = 0;
        for (Method m : c.getDeclaredMethods()) {
            String nm = m.getName();
            if (!("call".equals(nm) || "query".equals(nm) || "insert".equals(nm)
                    || "update".equals(nm) || "delete".equals(nm) || "getType".equals(nm))) continue;
            final String name = nm;
            try {
                hook(m).setId("rgs_l5_" + name).intercept(chain -> {
                    long c5 = bump("provider_block", 1);
                    maybeWriteStatus();
                    log("L5 provider " + name + " blocked (" + c5 + ")");
                    return defaultFor(m.getReturnType());
                });
                n++;
            } catch (Throwable t) {
                log("L5 hook fail " + name + ": " + t);
            }
        }
        log("L5 hooked " + n + " method(s) on DMProvider");
        return n;
    }

    /* ================= UNHIDE: 让被 ColorOS 过滤掉的包在包列表里现行 ================= */

    /**
     * ColorOS 把 com.coloros.regservice 从 PackageManager 的枚举结果里过滤掉了
     * （pm list 查不到，dumpsys 查得到）。这里在「被注入的进程」里 hook
     * ApplicationPackageManager 的枚举方法，把缺失的包补回返回列表。
     *
     * 注意：只影响被 hook 的进程。要让「设置」里能看到，需要把本模块的 scope
     * 再加上 com.android.settings；想让 pm 命令行也看到，必须 scope 到 system（有风险）。
     */
    private int hookUnhide(ClassLoader cl) throws Throwable {
        if (!cfgUnhide) return 0;
        Class<?> apm = Class.forName("android.app.ApplicationPackageManager");
        int n = 0;
        for (Method m : apm.getDeclaredMethods()) {
            String nm = m.getName();
            Class<?>[] p = m.getParameterTypes();
            boolean isPackages;
            if (nm.equals("getInstalledPackages") && p.length == 1 && p[0] == int.class) isPackages = true;
            else if (nm.equals("getInstalledPackagesAsUser") && p.length == 2
                    && p[0] == int.class && p[1] == int.class) isPackages = true;
            else if (nm.equals("getInstalledApplications") && p.length == 1 && p[0] == int.class) isPackages = false;
            else if (nm.equals("getInstalledApplicationsAsUser") && p.length == 2
                    && p[0] == int.class && p[1] == int.class) isPackages = false;
            else continue;

            final boolean wantPkgInfo = isPackages;
            final String id = "rgs_unhide_" + nm;
            try {
                hook(m).setId(id).intercept(chain -> {
                    int flags = 0;
                    try {
                        flags = (Integer) chain.getArg(0);
                    } catch (Throwable ignored) {
                    }
                    Object r = chain.proceed();
                    try {
                        if (r instanceof java.util.List) {
                            @SuppressWarnings("unchecked")
                            java.util.List<Object> src = (java.util.List<Object>) r;
                            java.util.List<Object> copy = new java.util.ArrayList<>(src);
                            if (appendHidden(copy, wantPkgInfo, flags)) {
                                long c = bump("unhide_count", 1);
                                if (c <= 3 || c % 100 == 0) {
                                    log("UNHIDE appended " + HIDDEN_PKG + " into " + id + " (" + c + ")");
                                }
                                return copy;
                            }
                        }
                    } catch (Throwable ignored) {
                        // 补失败就原样返回，绝不影响调用方
                    }
                    return r;
                });
                n++;
            } catch (Throwable t) {
                log("UNHIDE hook fail " + nm + ": " + t);
            }
        }
        log("UNHIDE hooked " + n + " method(s) on ApplicationPackageManager");

        // 设置列表在拿到列表后，还会逐个回查这个包的状态（disabled 就被丢掉），
        // 所以对 getPackageInfo / getApplicationInfo 也做一层「假装启用」。
        for (Method m : apm.getDeclaredMethods()) {
            String nm = m.getName();
            if (!"getPackageInfo".equals(nm) && !"getApplicationInfo".equals(nm)) continue;
            Class<?>[] p = m.getParameterTypes();
            if (p.length < 2 || p[0] != String.class || p[1] != int.class) continue;
            try {
                hook(m).setId("rgs_unhide_info_" + nm + "_" + p.length).intercept(chain -> {
                    Object r = chain.proceed();
                    try {
                        if (r != null && HIDDEN_PKG.equals(chain.getArg(0))) {
                            if (r instanceof android.content.pm.PackageInfo) {
                                android.content.pm.PackageInfo pi = (android.content.pm.PackageInfo) r;
                                if (pi.applicationInfo != null) pi.applicationInfo.enabled = true;
                            } else if (r instanceof android.content.pm.ApplicationInfo) {
                                ((android.content.pm.ApplicationInfo) r).enabled = true;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                    return r;
                });
                n++;
            } catch (Throwable t) {
                log("UNHIDE info hook fail " + nm + ": " + t);
            }
        }
        log("UNHIDE total " + n + " hooks");
        return n;
    }

    /* ================= ColorOS 设置侧的隐藏过滤 ================= */

    /**
     * 设置的应用列表拿到列表后还会过一层过滤：
     *   AppManagerUtils.isHideApp(ApplicationInfo, Map, Map) -> true 就把条目丢掉
     *   AppUtils.isAppInstalled(AppEntry)                    -> false 也会丢
     * 目标不在 ColorOS 的静态隐藏名单里，但停用（enabled=3）时仍会被隐藏，
     * 所以这里把过滤函数直接短路。
     */
    private int hookColorOSHideFilter(ClassLoader cl) {
        int n = 0;
        try {
            Class<?> u = cl.loadClass("com.oplus.settings.feature.appmanager.AppManagerUtils");
            for (Method m : u.getDeclaredMethods()) {
                if (m.getReturnType() != boolean.class) continue;
                String nm = m.getName();
                if ("isHideApp".equals(nm)) {
                    hook(m).setId("rgs_cos_ishide").intercept(chain -> {
                        long c = bump("cos_ishide", 1);
                        if (c <= 3) log("COS isHideApp -> false (" + c + ")");
                        return Boolean.FALSE;
                    });
                    n++;
                } else if ("shouldShowPackage".equals(nm)) {
                    hook(m).setId("rgs_cos_showpkg").intercept(chain -> Boolean.TRUE);
                    n++;
                }
            }
        } catch (Throwable t) {
            log("AppManagerUtils hook fail: " + t);
        }

        try {
            Class<?> au = cl.loadClass("com.oplus.settingslib.applications.AppUtils");
            for (Method m : au.getDeclaredMethods()) {
                if (!"isAppInstalled".equals(m.getName())) continue;
                if (m.getParameterTypes().length != 1) continue;
                hook(m).setId("rgs_cos_installed").intercept(chain -> {
                    try {
                        Object entry = chain.getArg(0);
                        Object info = fieldOf(entry, "info");
                        Object pn = fieldOf(info, "packageName");
                        if (HIDDEN_PKG.equals(pn)) return Boolean.TRUE;
                    } catch (Throwable ignored) {
                    }
                    return chain.proceed();
                });
                n++;
            }
        } catch (Throwable t) {
            log("AppUtils hook fail: " + t);
        }

        log("COS hide-filter hooked " + n + " method(s)");
        return n;
    }

    private static Object fieldOf(Object o, String name) {
        if (o == null) return null;
        Class<?> c = o.getClass();
        while (c != null) {
            try {
                java.lang.reflect.Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(o);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            } catch (Throwable t) {
                return null;
            }
        }
        return null;
    }

    /** 把隐藏包追加进列表；已在列表里则返回 false */
    private static boolean appendHidden(java.util.List<Object> list, boolean wantPackageInfo, int flags) {
        Context ctx = appContext();
        if (ctx == null) return false;
        for (Object o : list) {
            String pn = null;
            if (o instanceof android.content.pm.PackageInfo) pn = ((android.content.pm.PackageInfo) o).packageName;
            else if (o instanceof android.content.pm.ApplicationInfo) pn = ((android.content.pm.ApplicationInfo) o).packageName;
            if (HIDDEN_PKG.equals(pn)) return false;
        }
        try {
            if (wantPackageInfo) {
                // 用调用方原本的 flags 取证，形状才和列表里其他条目一致
                android.content.pm.PackageInfo pi = ctx.getPackageManager()
                        .getPackageInfo(HIDDEN_PKG, flags);
                if (pi == null) return false;
                // 关键：目标当前是「用户停用」(enabled=3)，设置列表会直接过滤掉 disabled 的应用。
                // 这里把它当成 enabled 塞进去，UI 才会显示（系统里的真实状态不变）。
                if (pi.applicationInfo != null) pi.applicationInfo.enabled = true;
                list.add(pi);
                return true;
            } else {
                android.content.pm.ApplicationInfo ai = ctx.getPackageManager()
                        .getApplicationInfo(HIDDEN_PKG, flags);
                if (ai == null) return false;
                android.content.pm.ApplicationInfo copy = new android.content.pm.ApplicationInfo(ai);
                copy.enabled = true;
                list.add(copy);
                return true;
            }
        } catch (Throwable t) {
            return false;
        }
    }

    /* ================= 等 Application 就绪后再清库/关补丁/出报告 ================= */

    private void hookAppReady() throws Throwable {
        Method onCreate = Application.class.getDeclaredMethod("onCreate");
        hook(onCreate).setId("rgs_app_ready").intercept(chain -> {
            Object result = chain.proceed();
            ensureConfig();
            if (cfgWipe) {
                try { wipeDatabases(); } catch (Throwable t) { log("wipe fail " + t); }
            }
            if (cfgPatch) {
                try { suppressPatch(); } catch (Throwable t) { log("patch suppress fail " + t); }
            }
            report();
            writeStatus();
            appendEvent("boot: hooks=" + hookSummary);
            return result;
        });
        log("app-ready hooked: Application.onCreate");
    }

    /* ================= L6 配套: 清库 + 关动态补丁 ================= */

    private void wipeDatabases() {
        Context ctx = appContext();
        if (ctx == null) { log("wipe skipped: no context"); return; }
        String[] dbs = ctx.databaseList();
        if (dbs == null) return;
        for (String db : dbs) {
            String low = db.toLowerCase();
            if (low.contains("cmcc") || low.contains("dm.db") || low.contains("regservice")) {
                boolean ok = ctx.deleteDatabase(db);
                log("wipe: delete " + db + " -> " + ok);
            }
        }
    }

    /** 关掉动态补丁开关 + 清空 files/dynamic，DexClassLoader 就没有东西可加载 */
    private void suppressPatch() {
        Context ctx = appContext();
        if (ctx == null) return;

        try {
            SharedPreferences sp = ctx.getSharedPreferences("config_dm", Context.MODE_PRIVATE);
            sp.edit().putString("DYNAMIC_LOAD_SWITCH", "0").apply();
            log("patch: DYNAMIC_LOAD_SWITCH -> 0");
        } catch (Throwable t) {
            log("patch: set switch fail " + t);
        }

        try {
            File dir = new File(ctx.getFilesDir(), "dynamic");
            if (dir.exists()) {
                File[] fs = dir.listFiles();
                int del = 0;
                if (fs != null) {
                    for (File f : fs) if (f.delete()) del++;
                }
                log("patch: removed " + del + " file(s) in " + dir);
            }
        } catch (Throwable t) {
            log("patch: clean dir fail " + t);
        }
    }

    /* ================= 与 KernelSU 模块的联动 ================= */

    /**
     * 共享目录: /storage/emulated/0/Android/media/com.coloros.regservice/SHBlocker/
     *   config.conf  <- 内核侧/用户写，Xposed 读
     *   status.json  <- Xposed 写，内核侧读
     *   events.log   <- Xposed 追加事件
     */
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
            "# RegServiceBlocker 开关（1=启用，0=关闭）\n" +
            "# 修改后重启目标进程生效（su -c \"am force-stop " + PKG + "\"）\n" +
            "BLOCK_EGRESS=1\n" +
            "BLOCK_DOWNLOAD=1\n" +
            "BLOCK_COLLECT=1\n" +
            "BLOCK_DB=1\n" +
            "BLOCK_PROVIDER=1\n" +
            "BLOCK_PATCH=1\n" +
            "WIPE_DB=1\n" +
            "UNHIDE_PMS=1\n";

    private static class Config {
        boolean egress = true, download = true, collect = true, db = true;
        boolean provider = true, patch = true, wipe = true, unhide = true;
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
                String v = line.substring(i + 1).trim();
                boolean on = v.equals("1") || v.equalsIgnoreCase("true");
                if ("BLOCK_EGRESS".equals(k)) c.egress = on;
                else if ("BLOCK_DOWNLOAD".equals(k)) c.download = on;
                else if ("BLOCK_COLLECT".equals(k)) c.collect = on;
                else if ("BLOCK_DB".equals(k)) c.db = on;
                else if ("BLOCK_PROVIDER".equals(k)) c.provider = on;
                else if ("BLOCK_PATCH".equals(k)) c.patch = on;
                else if ("WIPE_DB".equals(k)) c.wipe = on;
                else if ("UNHIDE_PMS".equals(k)) c.unhide = on;
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
            cfgEgress = c.egress;
            cfgDownload = c.download;
            cfgCollect = c.collect;
            cfgDb = c.db;
            cfgProvider = c.provider;
            cfgPatch = c.patch;
            cfgWipe = c.wipe;
            cfgUnhide = c.unhide;
            log("config: egress=" + cfgEgress + " download=" + cfgDownload + " collect=" + cfgCollect
                    + " db=" + cfgDb + " provider=" + cfgProvider + " patch=" + cfgPatch
                    + " wipe=" + cfgWipe + " unhide=" + cfgUnhide);
        } catch (Throwable t) {
            log("ensureConfig fail " + t);
        }
    }

    private static void writeStatus() {
        try {
            Context ctx = appContext();
            // 只有目标进程才写 status.json；被额外注入的进程（如设置）不要覆盖它
            if (ctx != null && !PKG.equals(ctx.getPackageName())) return;
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
            sb.append("  \"config\": {")
              .append("\"egress\":").append(cfgEgress).append(",")
              .append("\"download\":").append(cfgDownload).append(",")
              .append("\"collect\":").append(cfgCollect).append(",")
              .append("\"db\":").append(cfgDb).append(",")
              .append("\"provider\":").append(cfgProvider).append(",")
              .append("\"patch\":").append(cfgPatch).append(",")
              .append("\"wipe\":").append(cfgWipe).append("},\n");
            sb.append("  \"stats\": {\n");
            sb.append("    \"egress_count\": ").append(get("egress_count")).append(",\n");
            sb.append("    \"download_block\": ").append(get("download_block")).append(",\n");
            sb.append("    \"collect_block\": ").append(get("collect_block")).append(",\n");
            sb.append("    \"db_block\": ").append(get("db_block")).append(",\n");
            sb.append("    \"provider_block\": ").append(get("provider_block")).append(",\n");
            sb.append("    \"unhide_count\": ").append(get("unhide_count")).append("\n");
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
        StringBuilder sb = new StringBuilder();
        sb.append("===== stats =====\n");
        sb.append("upload blocked: ").append(get("egress_count")).append("\n");
        sb.append("download blocked: ").append(get("download_block")).append("\n");
        sb.append("collect blocked: ").append(get("collect_block")).append("\n");
        sb.append("db blocked: ").append(get("db_block")).append("\n");
        sb.append("provider blocked: ").append(get("provider_block"));
        log(sb.toString());
    }

    private static void log(String msg) {
        RgsHook m = INSTANCE;
        if (m != null) {
            m.log(Log.INFO, TAG, msg);
        } else {
            Log.i(TAG, msg);
        }
    }
}
