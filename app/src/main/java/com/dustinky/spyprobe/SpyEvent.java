package com.dustinky.spyprobe;

import org.json.JSONObject;

/**
 * v1.55: 通用结构化事件——日志页卡片化数据源（替代"纯文本行"展示）。
 *
 * 设计目标：v1.48 只给 HTTP 请求（HttpEntry）做了结构化卡片，SQL/JSON/Crypto/TCP/DNS
 * 仍以文本行刷屏。v1.55 统一为 SpyEvent：所有探测类型捕获时写结构化对象，
 * 日志行嵌入 [EVT#id] 标记 → UI 解析标记 → HomeEventStore.find(id) → 渲染对应卡片，
 * 点开有详情页（结构化字段 + 原始视图）。
 *
 * 类型约定（type）：
 *   SQL     —— 数据库操作（table/op/sql/args）
 *   JSON    —— JSON 序列化（source/content）
 *   CRYPTO  —— 加密操作（algo/mode/key/iv）
 *   NET     —— TCP/DNS 连接（host/ip/port/timeout/ok/fail）
 *   URL     —— URL 构造点（url/stack）
 *   CLIP    —— 剪贴板读取（content/stack）
 *   REQ     —— HTTP 请求（与 HttpEntry 并存，暂不迁移）
 *
 * 字段约定：
 *   id       —— EventStore.nextId 全局唯一，日志行 [EVT#id] 引用
 *   title    —— 卡片标题（如 "execSQL UPDATE cacheObject"）
 *   payload  —— 结构化字段（不同 type 字段不同，详情页渲染）
 *   logLine  —— 原始文本行（详情页"原始"视图 / 导出）
 *   stack    —— 调用栈（详情页折叠展示）
 *   done/durationMs —— 可完成事件用（请求/连接）
 */
public class SpyEvent {

    public final String type;
    public final long id;
    public final long time;
    public final String title;
    public final JSONObject payload;
    public final String logLine;
    public final String stack;

    public volatile boolean done;
    public volatile long durationMs;

    public SpyEvent(String type, long id, long time, String title,
                    JSONObject payload, String logLine, String stack) {
        this.type = type;
        this.id = id;
        this.time = time;
        this.title = title == null ? "" : title;
        this.payload = payload == null ? new JSONObject() : payload;
        this.logLine = logLine == null ? "" : logLine;
        this.stack = stack == null ? "" : stack;
        this.done = false;
        this.durationMs = 0;
    }

    public void complete(long durationMs) {
        this.done = true;
        this.durationMs = durationMs;
    }

    public JSONObject toJson() {
        JSONObject o = new JSONObject();
        try {
            o.put("type", type);
            o.put("id", id);
            o.put("time", time);
            o.put("title", title);
            o.put("payload", payload);
            o.put("logLine", logLine);
            o.put("stack", stack);
            o.put("done", done);
            o.put("durationMs", durationMs);
        } catch (Throwable t) { }
        return o;
    }

    public static SpyEvent fromJson(JSONObject o) {
        try {
            String type = o.optString("type", "?");
            long id = o.optLong("id", 0);
            long time = o.optLong("time", System.currentTimeMillis());
            String title = o.optString("title", "");
            JSONObject payload = o.optJSONObject("payload");
            String logLine = o.optString("logLine", "");
            String stack = o.optString("stack", "");
            SpyEvent e = new SpyEvent(type, id, time, title, payload, logLine, stack);
            e.done = o.optBoolean("done", false);
            e.durationMs = o.optLong("durationMs", 0);
            return e;
        } catch (Throwable t) {
            return null;
        }
    }
}
