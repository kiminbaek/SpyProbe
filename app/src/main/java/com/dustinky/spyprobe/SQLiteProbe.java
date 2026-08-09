package com.dustinky.spyprobe;

import android.content.ContentValues;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Set;

import io.github.libxposed.api.XposedModule;

/**
 * SQLite 操作记录（v1.4 新增）：
 * hook android.database.sqlite.SQLiteDatabase 的 insert/update/delete/query/rawQuery/execSQL，
 * 记录 app 的数据库增删改查 —— 反编译时直接看它本地存了啥，比抓网络更接近数据真相。
 *
 * 注意：query 高频（启动即大量查询），只记录 SQL 字符串不读 Cursor，性能可控。
 */
public class SQLiteProbe {

    static final String TAG = "SpyProbe.SQL";

    private final XposedModule module;

    public SQLiteProbe(XposedModule module) {
        this.module = module;
    }

    public void install(String phase) {
        // v1.37 P0-1: 惰性安装——开关关闭时完全不装 hook（借鉴 Guise activeHookFeatures，
        //   用户关闭的探测项在目标进程零 hook 存在，减少崩溃面 + 更隐蔽 + 启动更快）
        if (!Config.get().sqliteCapture) {
            DebugLog.get().log("SQLite", "install(" + phase + ") skipped: Config.get().sqliteCapture == false");
            return;
        }
        try {
            Class<?> db = Class.forName("android.database.sqlite.SQLiteDatabase");
            int hooked = 0;

            // execSQL(String) / execSQL(String, Object[])
            hooked += hookByName(db, "execSQL", 1, (chain, name) -> {
                StringBuilder sb = new StringBuilder("[SQL] execSQL: ").append(chain.getArg(0));
                if (chain.getArgs().size() > 1) sb.append("  args=").append(MethodProbe.str(chain.getArg(1), 200));
                LogStore.get().log(TAG, sb.toString());
            });
            hooked += hookByName(db, "execSQL", 2, (chain, name) -> {
                LogStore.get().log(TAG, "[SQL] execSQL: " + chain.getArg(0) + "  args=" + MethodProbe.str(chain.getArg(1), 200));
            });

            // insert(String table, String nullColumnHack, ContentValues values)
            hooked += hookByName(db, "insert", 3, (chain, name) -> {
                LogStore.get().log(TAG, "[SQL] INSERT INTO " + chain.getArg(0) + " " + cv(chain.getArg(2)));
            });

            // update(String table, ContentValues values, String whereClause, String[] whereArgs)
            hooked += hookByName(db, "update", 4, (chain, name) -> {
                LogStore.get().log(TAG, "[SQL] UPDATE " + chain.getArg(0) + " " + cv(chain.getArg(1))
                        + " WHERE " + chain.getArg(2) + " args=" + MethodProbe.str(chain.getArg(3), 200));
            });

            // delete(String table, String whereClause, String[] whereArgs)
            hooked += hookByName(db, "delete", 3, (chain, name) -> {
                LogStore.get().log(TAG, "[SQL] DELETE FROM " + chain.getArg(0)
                        + " WHERE " + chain.getArg(1) + " args=" + MethodProbe.str(chain.getArg(2), 200));
            });

            // rawQuery(String sql, String[] selectionArgs)
            hooked += hookByName(db, "rawQuery", 2, (chain, name) -> {
                LogStore.get().log(TAG, "[SQL] rawQuery: " + chain.getArg(0) + " args=" + MethodProbe.str(chain.getArg(1), 200));
            });

            // v1.15 P2-4: rawQuery(String, String[], CancellationSignal) 3 参重载
            hooked += hookByName(db, "rawQuery", 3, (chain, name) -> {
                LogStore.get().log(TAG, "[SQL] rawQuery: " + chain.getArg(0) + " args=" + MethodProbe.str(chain.getArg(1), 200));
            });

            // query 各重载（4~8 参）→ 拼可读 SELECT
            hooked += hookQuery(db);

            // replace / insertWithOnConflict 等（可选高频）
            // v1.15 P1-4: 官方签名 insertWithOnConflict(String, String, ContentValues, int) = 4 参，
            //   原代码 hookByName(...,5) 找 5 参 → 永远匹配不到 → 静默 hook 0 个
            hooked += hookByName(db, "insertWithOnConflict", 4, (chain, name) -> {
                LogStore.get().log(TAG, "[SQL] INSERT(conflict) INTO " + chain.getArg(0) + " " + cv(chain.getArg(2)));
            });

            // v1.6: replace —— INSERT OR REPLACE 语义
            hooked += hookByName(db, "replace", 3, (chain, name) -> {
                LogStore.get().log(TAG, "[SQL] REPLACE INTO " + chain.getArg(0) + " " + cv(chain.getArg(2)));
            });

            // v1.6: rawQueryWithFactory(CursorFactory, String sql, String[], String)
            hooked += hookByName(db, "rawQueryWithFactory", 4, (chain, name) -> {
                LogStore.get().log(TAG, "[SQL] rawQuery(factory): " + chain.getArg(1)
                        + " args=" + MethodProbe.str(chain.getArg(2), 200));
            });

            // v1.6: queryWithFactory —— 自定义 factory 的 query
            hooked += hookQueryWithFactory(db);

            LogStore.get().log(TAG, "[" + phase + "] hooked SQLiteDatabase x" + hooked);
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] SQLiteDatabase hook fail: " + t);
        }
    }

    /** 按方法名+参数个数精确 hook，回调里记录 */
    private int hookByName(Class<?> db, String name, int argc, SqlCallback cb) {
        int hooked = 0;
        try {
            for (Method m : db.getDeclaredMethods()) {
                if (!m.getName().equals(name)) continue;
                if (m.getParameterTypes().length != argc) continue;
                final String fName = name;
                final SqlCallback fCb = cb;
                module.hook(m).intercept(chain -> {
                    Object r;
                    try {
                        r = chain.proceed();
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "[SQL] !!! " + fName + " FAILED: " + t);
                        throw t;
                    }
                    if (Config.get().sqliteCapture) {
                        try {
                            fCb.onCall(chain, fName);
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                hooked++;
            }
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[SQL] hook " + name + " fail: " + t);
        }
        return hooked;
    }

    /** query 重载拼可读 SELECT */
    private int hookQuery(Class<?> db) {
        int hooked = 0;
        try {
            for (Method m : db.getDeclaredMethods()) {
                if (!m.getName().equals("query")) continue;
                int argc = m.getParameterTypes().length;
                if (argc < 4 || argc > 8) continue;
                // v1.16 P2-5: 删除死代码 fArgc（hook 体用 chain.getArgs().size() 动态判断，此处从未使用）
                module.hook(m).intercept(chain -> {
                    Object r;
                    try {
                        r = chain.proceed();
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "[SQL] !!! query FAILED: " + t);
                        throw t;
                    }
                    if (Config.get().sqliteCapture) {
                        try {
                            StringBuilder sb = new StringBuilder("[SQL] SELECT");
                            // 参数布局（官方重载）：
                            // 4: table, columns, selection, selectionArgs
                            // 5: + groupBy
                            // 6: + having
                            // 7: + orderBy
                            // 8: + limit
                            String table = chain.getArg(0) == null ? "?" : String.valueOf(chain.getArg(0));
                            if (chain.getArgs().size() > 1 && chain.getArg(1) != null) {
                                sb.append(' ').append(joinArr(chain.getArg(1)));
                            } else {
                                sb.append(" *");
                            }
                            sb.append(" FROM ").append(table);
                            if (chain.getArgs().size() > 2 && chain.getArg(2) != null) {
                                sb.append(" WHERE ").append(chain.getArg(2));
                                if (chain.getArgs().size() > 3 && chain.getArg(3) != null) {
                                    sb.append(" args=").append(MethodProbe.str(chain.getArg(3), 200));
                                }
                            }
                            if (chain.getArgs().size() > 4 && chain.getArg(4) != null) sb.append(" GROUP BY ").append(chain.getArg(4));
                            if (chain.getArgs().size() > 5 && chain.getArg(5) != null) sb.append(" HAVING ").append(chain.getArg(5));
                            if (chain.getArgs().size() > 6 && chain.getArg(6) != null) sb.append(" ORDER BY ").append(chain.getArg(6));
                            if (chain.getArgs().size() > 7 && chain.getArg(7) != null) sb.append(" LIMIT ").append(chain.getArg(7));
                            LogStore.get().log(TAG, sb.toString());
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                hooked++;
            }
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[SQL] hook query fail: " + t);
        }
        return hooked;
    }

    /** v1.6: queryWithFactory —— 两种重载：
     *   10 参 (API17+)：queryWithFactory(CursorFactory, boolean distinct, String table, String[] columns,
     *                      String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
     *    9 参 (旧版)   ：queryWithFactory(CursorFactory, String table, String[] columns,
     *                      String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
     */
    private int hookQueryWithFactory(Class<?> db) {
        int hooked = 0;
        try {
            for (Method m : db.getDeclaredMethods()) {
                if (!m.getName().equals("queryWithFactory")) continue;
                int argc = m.getParameterTypes().length;
                if (argc != 9 && argc != 10) continue;
                final int fArgc = argc;
                module.hook(m).intercept(chain -> {
                    Object r;
                    try {
                        r = chain.proceed();
                    } catch (Throwable t) {
                        LogStore.get().log(TAG, "[SQL] !!! queryWithFactory FAILED: " + t);
                        throw t;
                    }
                    if (Config.get().sqliteCapture) {
                        try {
                            // 9 参布局：0=factory 1=table 2=columns 3=selection 4=selectionArgs 5=groupBy 6=having 7=orderBy 8=limit
                            // 10 参布局：0=factory 1=distinct 2=table 3=columns 4=selection 5=selectionArgs 6=groupBy 7=having 8=orderBy 9=limit
                            int base = (fArgc == 9) ? 1 : 2;
                            StringBuilder sb = new StringBuilder("[SQL] SELECT");
                            Object cols = chain.getArg(base + 1);
                            if (cols != null) {
                                sb.append(' ').append(joinArr(cols));
                            } else {
                                sb.append(" *");
                            }
                            sb.append(" FROM ").append(chain.getArg(base));
                            if (chain.getArg(base + 2) != null) {
                                sb.append(" WHERE ").append(chain.getArg(base + 2));
                                if (chain.getArg(base + 3) != null) {
                                    sb.append(" args=").append(MethodProbe.str(chain.getArg(base + 3), 200));
                                }
                            }
                            if (chain.getArg(base + 4) != null) sb.append(" GROUP BY ").append(chain.getArg(base + 4));
                            if (chain.getArg(base + 5) != null) sb.append(" HAVING ").append(chain.getArg(base + 5));
                            if (chain.getArg(base + 6) != null) sb.append(" ORDER BY ").append(chain.getArg(base + 6));
                            if (chain.getArg(base + 7) != null) sb.append(" LIMIT ").append(chain.getArg(base + 7));
                            LogStore.get().log(TAG, sb.toString());
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                hooked++;
            }
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[SQL] hook queryWithFactory fail: " + t);
        }
        return hooked;
    }

    /** ContentValues → 可读 map */
    private static String cv(Object v) {
        if (v == null) return "";
        try {
            if (v instanceof ContentValues) {
                ContentValues c = (ContentValues) v;
                StringBuilder sb = new StringBuilder("{");
                boolean first = true;
                for (Map.Entry<String, Object> e : c.valueSet()) {
                    if (!first) sb.append(", ");
                    first = false;
                    sb.append(e.getKey()).append('=').append(MethodProbe.str(e.getValue(), 120));
                }
                sb.append("}");
                return sb.toString();
            }
            return String.valueOf(v);
        } catch (Throwable t) {
            return "<cv>";
        }
    }

    private static String joinArr(Object o) {
        if (o == null) return "*";
        try {
            if (o instanceof String[]) {
                String[] a = (String[]) o;
                if (a.length == 0) return "*";
                StringBuilder sb = new StringBuilder();
                for (String s : a) {
                    if (sb.length() > 0) sb.append(",");
                    sb.append(s);
                }
                return sb.toString();
            }
            return String.valueOf(o);
        } catch (Throwable t) {
            return "*";
        }
    }

    interface SqlCallback {
        void onCall(io.github.libxposed.api.XposedInterface.Chain chain, String name) throws Throwable;
    }
}
