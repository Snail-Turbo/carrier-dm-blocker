package com.rgs;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import java.io.File;

/**
 * 直接往 LSPosed 的 modules_config.db 里补 scope（三家运营商 DM 合集版）。
 *
 * LSPosed 2.x 的 lspctl 只允许在 ADB root shell 里改 scope，开机脚本会被拒绝，
 * 所以这里绕开 lspctl，用系统 SQLite 直接写库。
 *
 * 注意：在 app_process 里跑，Resources 没有初始化，
 * SQLiteGlobal.getDefaultSyncMode() 会 NPE，所以必须显式指定 sync mode。
 */
public class DbFix {

    private static final String DB = "/data/adb/lspd/config/modules_config.db";
    private static final String MOD = "com.example.carrierdmblocker";
    private static final String[] PKGS = {
            "com.mobiletools.systemhelper",   // 联通
            "com.coloros.regservice",         // 移动（PMS 层被隐藏，界面加不了 scope）
            "com.oppo.ctautoregist",          // 电信
            "com.android.settings"            // UNHIDE 用（让应用列表能看到上面几个）
    };

    public static void main(String[] args) {
        boolean listOnly = args != null && args.length > 0 && "list".equals(args[0]);
        SQLiteDatabase d = null;
        try {
            SQLiteDatabase.OpenParams.Builder b = new SQLiteDatabase.OpenParams.Builder();
            b.setSynchronousMode("FULL");           // 绕开 Resources 未初始化导致的 NPE
            b.addOpenFlags(SQLiteDatabase.NO_LOCALIZED_COLLATORS);
            d = SQLiteDatabase.openDatabase(new File(DB), b.build());

            int added = 0;
            for (String p : PKGS) {
                if (has(d, p)) {
                    System.out.println("exists  " + p);
                    continue;
                }
                if (listOnly) {
                    System.out.println("missing " + p);
                    continue;
                }
                d.execSQL("insert into scope(module_pkg_name,app_pkg_name,user_id) values(?,?,0)",
                        new Object[]{MOD, p});
                added++;
                System.out.println("added   " + p);
            }
            if (listOnly) {
                System.out.println("list done");
                return;
            }
            if (added > 0) {
                try {
                    d.execSQL("pragma wal_checkpoint(TRUNCATE)");
                } catch (Throwable ignored) {
                }
                System.out.println("scope updated (" + added + ")");
            } else {
                System.out.println("scope already complete");
            }
        } catch (Throwable t) {
            System.out.println("ERROR: " + t);
            t.printStackTrace(System.out);
        } finally {
            if (d != null) {
                try {
                    d.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static boolean has(SQLiteDatabase d, String pkg) {
        Cursor c = null;
        try {
            c = d.rawQuery(
                    "select count(*) from scope where module_pkg_name=? and app_pkg_name=? and user_id=0",
                    new String[]{MOD, pkg});
            return c.moveToFirst() && c.getInt(0) > 0;
        } catch (Throwable t) {
            return false;
        } finally {
            if (c != null) {
                try {
                    c.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }
}
