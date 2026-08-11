package com.dustinky.spyprobe;

import android.content.ContentValues;

import java.lang.reflect.Method;
import java.util.Locale;
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

    // v1.53: 高频 SQL 模板聚合（30s 窗口同模板重复 >=5 次 → 只记首条+汇总，防 cacheObject 之类刷屏）
    // v1.54: 窗口 30s→60s、阈值 5→3——Glide 缓存清理任务约每 10s 一次，30s 窗口仅 3 次达不到
    //   MIN_REPEAT=5 → 永不聚合（v1.53 日志 16+8 行 cacheObject 刷屏）。阈值 3 + 窗口 60s 覆盖
    //   所有"周期性重复"的 SQL（缓存清理/轮询），低频业务 SQL 不受影响。
    private static final java.util.LinkedHashMap<String, SqlAgg> SQL_AGG = new java.util.LinkedHashMap<>();
    private static final long AGG_WINDOW_MS = 60_000L;
    private static final int AGG_MIN_REPEAT = 3;
    static class SqlAgg { int count; long windowStart; }

    private final XposedModule module;

    public SQLiteProbe(XposedModule module) {
        this.module = module;
    }

    /**
     * v1.53: 日志降噪判断——SQLite 驱动内部调用直接过滤，高频模板聚合。
     * 返回 true 表示这条该记（首次出现/低频重复），false 表示跳过（驱动内部调用/窗口内高频）。
     */
    static boolean shouldLog(String sql) {
        if (sql == null) return false;
        String t = sql.trim();
        if (t.isEmpty()) return false;
        // ① SQLiteDatabase 驱动内部实现（每次写操作后自动查，对逆向零价值）→ 直接过滤
        String up = t.toUpperCase(Locale.US);
        if (up.equals("SELECT CHANGES()")
                || up.startsWith("SELECT CHANGES(),")
                || up.equals("SELECT CHANGES(), LAST_INSERT_ROWID()")) {
            return false;
        }
        // ② 高频模板聚合
        String tpl = normalizeSql(t);
        long now = System.currentTimeMillis();
        synchronized (SQL_AGG) {
            SqlAgg a = SQL_AGG.get(tpl);
            if (a == null) {
                a = new SqlAgg();
                a.count = 1;
                a.windowStart = now;
                SQL_AGG.put(tpl, a);
                if (SQL_AGG.size() > 64) {
                    // 防无界增长：淘汰最旧模板（LinkedHashMap 迭代序=插入序）
                    java.util.Iterator<SqlAgg> it = SQL_AGG.values().iterator();
                    if (it.hasNext()) it.next();
                    if (SQL_AGG.size() > 64) SQL_AGG.remove(SQL_AGG.keySet().iterator().next());
                }
                return true;  // 模板首次出现 → 记全量
            }
            a.count++;
            if (now - a.windowStart >= AGG_WINDOW_MS) {
                if (a.count >= AGG_MIN_REPEAT) {
                    LogStore.get().log(TAG, "[SQL] " + tpl + " —— 30s 内重复 " + a.count + " 次，已聚合（防刷屏）");
                }
                SQL_AGG.remove(tpl);
                return false;
            }
            if (a.count >= AGG_MIN_REPEAT) return false;  // 窗口内高频 → 抑制，等窗口结束汇总
            return true;  // 低频重复（<5 次）逐条记
        }
    }

    /**
     * v1.55: 结构化 SQL 事件——日志行嵌入 [EVT#id]，EventStore 写 SpyEvent（UI 卡片化）。
     * 文本行保留（[EVT#id][SQL] ... 前缀，兼容导出/详情原始视图）。
     * @param sql  完整 SQL（含操作前缀）
     * @param args 参数摘要（可空）
     */
    static void logSqlEvent(String sql, String args) {
        try {
            long eid = EventStore.get().nextId();
            String argsPart = (args == null || args.isEmpty()) ? "" : "  " + args;
            String msg = "[EVT#" + eid + "][SQL] " + sql + argsPart;
            LogStore.get().log(TAG, msg);
            // 结构化 payload：op / table / sql / args（详情页渲染）
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("op", extractOp(sql));
            payload.put("table", extractTable(sql));
            payload.put("sql", sql == null ? "" : sql);
            payload.put("args", args == null ? "" : args);
            EventStore.get().add(new SpyEvent("SQL", eid, System.currentTimeMillis(),
                    extractOp(sql) + " " + extractTable(sql), payload, msg, ""));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }

    /** 提取 SQL 操作类型（INSERT/UPDATE/DELETE/SELECT/REPLACE/execSQL...） */
    private static String extractOp(String sql) {
        if (sql == null) return "SQL";
        String t = sql.trim();
        int sp = t.indexOf(' ');
        if (sp < 0) return t.toUpperCase(Locale.US);
        String op = t.substring(0, sp).toUpperCase(Locale.US);
        return op;
    }

    /** 提取操作表名（INSERT INTO xx / UPDATE xx / DELETE FROM xx / SELECT ... FROM xx） */
    private static String extractTable(String sql) {
        if (sql == null) return "";
        String t = sql.trim();
        String up = t.toUpperCase(Locale.US);
        String[] keys = {"INSERT INTO ", "UPDATE ", "DELETE FROM ", "FROM ", "INTO ", "REPLACE INTO "};
        for (String k : keys) {
            int i = up.indexOf(k);
            if (i >= 0) {
                String rest = t.substring(i + k.length()).trim();
                int end = 0;
                while (end < rest.length()) {
                    char c = rest.charAt(end);
                    if (Character.isLetterOrDigit(c) || c == '_' || c == '.') end++;
                    else break;
                }
                if (end > 0) return rest.substring(0, end);
                return rest.isEmpty() ? "?" : rest;
            }
        }
        return "";
    }

    /** 归一化 SQL：去字符串字面量/数字/空白 → 模板 key */
    private static String normalizeSql(String sql) {
        String s = sql;
        StringBuilder sb = new StringBuilder(s.length());
        boolean inStr = false;
        char q = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == q) {
                    if (i + 1 < s.length() && s.charAt(i + 1) == q) { i++; continue; }
                    inStr = false;
                }
                continue;
            }
            if (c == '\'' || c == '"') { inStr = true; q = c; sb.append('?'); continue; }
            if (Character.isDigit(c)) { sb.append('?'); while (i + 1 < s.length() && Character.isDigit(s.charAt(i + 1))) i++; continue; }
            sb.append(c);
        }
        return sb.toString().replaceAll("\\s+", " ").trim();
    }

    public void install(String phase) {
        // v1.37 P0-1: 惰性安装——开关关闭时完全不装 hook（借鉴 Guise activeHookFeatures，
        //   用户关闭的探测项在目标进程零 hook 存在，减少崩溃面 + 更隐蔽 + 启动更快）
        if (!Config.get().sqliteCapture) {
            DebugLog.get().logNoMirror("SQLite", "install(" + phase + ") skipped: Config.get().sqliteCapture == false");
            return;
        }
        try {
            Class<?> db = Class.forName("android.database.sqlite.SQLiteDatabase");
            int hooked = 0;

            // execSQL(String) / execSQL(String, Object[])
            hooked += hookByName(db, "execSQL", 1, (chain, name) -> {
                String sql = String.valueOf(chain.getArg(0));
                if (!shouldLog(sql)) return;
                String args = chain.getArgs().size() > 1 ? MethodProbe.str(chain.getArg(1), 200) : "";
                logSqlEvent(sql, args);
            });
            hooked += hookByName(db, "execSQL", 2, (chain, name) -> {
                String sql = String.valueOf(chain.getArg(0));
                if (!shouldLog(sql)) return;
                logSqlEvent(sql, MethodProbe.str(chain.getArg(1), 200));
            });

            // insert(String table, String nullColumnHack, ContentValues values)
            hooked += hookByName(db, "insert", 3, (chain, name) -> {
                String sql = "INSERT INTO " + chain.getArg(0);
                if (!shouldLog(sql)) return;
                logSqlEvent(sql, cv(chain.getArg(2)));
            });

            // update(String table, ContentValues values, String whereClause, String[] whereArgs)
            hooked += hookByName(db, "update", 4, (chain, name) -> {
                String sql = "UPDATE " + chain.getArg(0);
                if (!shouldLog(sql)) return;
                logSqlEvent(sql, cv(chain.getArg(1))
                        + " WHERE " + chain.getArg(2) + " args=" + MethodProbe.str(chain.getArg(3), 200));
            });

            // delete(String table, String whereClause, String[] whereArgs)
            hooked += hookByName(db, "delete", 3, (chain, name) -> {
                String sql = "DELETE FROM " + chain.getArg(0);
                if (!shouldLog(sql)) return;
                logSqlEvent(sql, " WHERE " + chain.getArg(1) + " args=" + MethodProbe.str(chain.getArg(2), 200));
            });

            // rawQuery(String sql, String[] selectionArgs)
            hooked += hookByName(db, "rawQuery", 2, (chain, name) -> {
                String sql = String.valueOf(chain.getArg(0));
                if (!shouldLog(sql)) return;
                logSqlEvent(sql, MethodProbe.str(chain.getArg(1), 200));
            });

            // v1.15 P2-4: rawQuery(String, String[], CancellationSignal) 3 参重载
            hooked += hookByName(db, "rawQuery", 3, (chain, name) -> {
                String sql = String.valueOf(chain.getArg(0));
                if (!shouldLog(sql)) return;
                logSqlEvent(sql, MethodProbe.str(chain.getArg(1), 200));
            });

            // query 各重载（4~8 参）→ 拼可读 SELECT
            hooked += hookQuery(db);

            // replace / insertWithOnConflict 等（可选高频）
            // v1.15 P1-4: 官方签名 insertWithOnConflict(String, String, ContentValues, int) = 4 参，
            //   原代码 hookByName(...,5) 找 5 参 → 永远匹配不到 → 静默 hook 0 个
            hooked += hookByName(db, "insertWithOnConflict", 4, (chain, name) -> {
                String sql = "INSERT(conflict) INTO " + chain.getArg(0);
                if (!shouldLog(sql)) return;
                logSqlEvent(sql, cv(chain.getArg(2)));
            });

            // v1.6: replace —— INSERT OR REPLACE 语义
            hooked += hookByName(db, "replace", 3, (chain, name) -> {
                String sql = "REPLACE INTO " + chain.getArg(0);
                if (!shouldLog(sql)) return;
                logSqlEvent(sql, cv(chain.getArg(2)));
            });

            // v1.6: rawQueryWithFactory(CursorFactory, String sql, String[], String)
            hooked += hookByName(db, "rawQueryWithFactory", 4, (chain, name) -> {
                String sql = String.valueOf(chain.getArg(1));
                if (!shouldLog(sql)) return;
                logSqlEvent(sql, MethodProbe.str(chain.getArg(2), 200));
            });

            // v1.6: queryWithFactory —— 自定义 factory 的 query
            hooked += hookQueryWithFactory(db);

            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked SQLiteDatabase x" + hooked);
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] SQLiteDatabase hook fail: " + t);
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
            DebugLog.get().logNoMirror(TAG, "[SQL] hook " + name + " fail: " + t);
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
                            String sql = sb.toString();
                            if (shouldLog(sql)) logSqlEvent(sql, "");
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                hooked++;
            }
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[SQL] hook query fail: " + t);
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
                            String sql = sb.toString();
                            if (shouldLog(sql)) logSqlEvent(sql, "");
                        } catch (Throwable t) { }
                    }
                    return r;
                });
                hooked++;
            }
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[SQL] hook queryWithFactory fail: " + t);
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
