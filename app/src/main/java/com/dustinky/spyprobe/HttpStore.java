package com.dustinky.spyprobe;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * v1.48: 结构化 HTTP 条目环形缓冲（目标进程内）
 *
 * NetProbe 捕获 OkHttp/HttpURLConnection 请求时写入；UI 点请求行时按 id 查询。
 * 上限 {@link #MAX} 条环形淘汰（防内存膨胀，与 OkHttpReplay 同思路）。
 * 与日志推送同链路：批量推送主进程落盘（http_entries/），主进程历史页可读。
 *
 * 线程安全：写多读少，lock 保护 + AtomicLong id。
 */
public class HttpStore {

    private static final int MAX = 100;

    private static final HttpStore INSTANCE = new HttpStore();
    public static HttpStore get() { return INSTANCE; }

    private final java.util.List<HttpEntry> entries = new ArrayList<>();
    private final Object lock = new Object();
    private final java.util.concurrent.atomic.AtomicLong nextId = new java.util.concurrent.atomic.AtomicLong(1);

    private boolean pushHome = false;
    private String pushToken = "";
    private java.util.function.Supplier<String> pushTokenProvider = null;

    private HttpStore() { }

    /** 启用推送（与 LogStore 同构：目标进程把结构化条目推回主进程） */
    public void enablePush(String token, java.util.function.Supplier<String> tokenProvider) {
        synchronized (lock) {
            if (pushHome) return;
            this.pushToken = token == null ? "" : token;
            this.pushTokenProvider = tokenProvider;
            pushHome = true;
        }
        Thread t = new Thread(this::pushLoop, "SpyProbe-PushHttp");
        t.setDaemon(true);
        t.start();
    }

    public long nextId() { return nextId.getAndIncrement(); }

    // v1.62 P1-11: 多源重复记录——同一请求 OKHTTP 层 + native TLS 层各建 HttpEntry →
    //   UI 重复卡片。add 时按 (method+url+时间窗≤500ms) 判重，重复条目丢弃但保留 id 别名
    //   （TLS 日志行 [REQ#N] 仍能经别名找到详情，不丢点击链路）。
    //   字段合并：后到的 TLS 条目带四元组/TLS 元数据/证书，merge 进先到的 OKHTTP 条目。
    private static final long DEDUP_WINDOW_MS = 500;
    private final java.util.Map<Long, Long> idAlias = new java.util.HashMap<>();

    /** v1.62 P1-11: 查找最近窗口内同 method+url 的已存条目；返回 null=无重复 */
    private HttpEntry findDup(HttpEntry e) {
        int n = entries.size();
        // 只扫最近 20 条（多源窗口极小；全扫 O(MAX) 每次 add 太贵）
        int start = Math.max(0, n - 20);
        for (int i = start; i < n; i++) {
            HttpEntry old = entries.get(i);
            if (old == null) continue;
            if (!old.method.equals(e.method)) continue;
            if (old.url == null || !old.url.equals(e.url)) continue;
            long dt = Math.abs(old.time - e.time);
            if (dt <= DEDUP_WINDOW_MS) return old;
        }
        return null;
    }

    /** v1.62 P1-11: 后到条目的补充字段 merge 进先到条目（TLS 四元组/元数据/证书/body 补全） */
    private static void mergeInto(HttpEntry dst, HttpEntry src) {
        try {
            if (dst.srcAddr.isEmpty() && !src.srcAddr.isEmpty()) {
                dst.srcAddr = src.srcAddr; dst.srcPort = src.srcPort;
                dst.dstAddr = src.dstAddr; dst.dstPort = src.dstPort;
            }
            if (dst.connId == 0) { dst.connId = src.connId; dst.streamId = src.streamId; }
            if (dst.tlsVersion.isEmpty() && !src.tlsVersion.isEmpty()) {
                dst.tlsVersion = src.tlsVersion; dst.sni = src.sni; dst.alpn = src.alpn;
                dst.cipherSelected = src.cipherSelected; dst.cipherList = src.cipherList;
            }
            if (dst.certSubject.isEmpty() && !src.certSubject.isEmpty()) {
                dst.certSubject = src.certSubject; dst.certIssuer = src.certIssuer;
                dst.certSerial = src.certSerial; dst.certSha256 = src.certSha256;
                dst.certNotBefore = src.certNotBefore; dst.certNotAfter = src.certNotAfter;
                dst.certSubjectCn = src.certSubjectCn; dst.certSubjectC = src.certSubjectC;
                dst.certSubjectSt = src.certSubjectSt; dst.certSubjectL = src.certSubjectL;
                dst.certSubjectO = src.certSubjectO; dst.certSubjectOu = src.certSubjectOu;
                dst.certIssuerCn = src.certIssuerCn; dst.certIssuerC = src.certIssuerC;
                dst.certIssuerO = src.certIssuerO;
            }
            // 响应体补全（先到条目可能因 TLS 层更快而 body 为空）
            if ((dst.respBody == null || dst.respBody.isEmpty()) && src.respBody != null && !src.respBody.isEmpty()) {
                dst.respBody = src.respBody; dst.respBodyType = src.respBodyType; dst.respBodyBytes = src.respBodyBytes;
            }
            if ((dst.reqBody == null || dst.reqBody.isEmpty()) && src.reqBody != null && !src.reqBody.isEmpty()) {
                dst.reqBody = src.reqBody; dst.reqBodyType = src.reqBodyType; dst.reqBodyBytes = src.reqBodyBytes;
            }
            if (dst.durationMs == 0 && src.durationMs > 0) dst.durationMs = src.durationMs;
        } catch (Throwable t) { /* merge 失败不影响主链路 */ }
    }

    /** 新请求入队（返回分配 id）——v1.62 P1-11: 多源重复去重 */
    public long add(HttpEntry e) {
        synchronized (lock) {
            HttpEntry dup = findDup(e);
            if (dup != null) {
                // 重复：丢弃后到条目，merge 补充字段，记录 id 别名（原 id 可经别名查详情）
                mergeInto(dup, e);
                idAlias.put(e.id, dup.id);
                if (idAlias.size() > 256) idAlias.clear(); // 防膨胀（保留最近窗口）
                return dup.id;
            }
            entries.add(e);
            while (entries.size() > MAX) entries.remove(0);
            return e.id;
        }
    }

    /** 按 id 查（未找到返回 null）——v1.62: 支持别名（重复条目 id → 真实条目 id） */
    public HttpEntry find(long id) {
        synchronized (lock) {
            Long real = idAlias.get(id);
            if (real != null) id = real;
            for (HttpEntry e : entries) {
                if (e.id == id) return e;
            }
            return null;
        }
    }

    /** 全部（供推送批量取出） */
    public List<HttpEntry> snapshot() {
        synchronized (lock) {
            return new ArrayList<>(entries);
        }
    }

    public int size() {
        synchronized (lock) { return entries.size(); }
    }

    /** 推送循环：有更新条目 → 批量推主进程（与 LogStore.pushLoop 同构） */
    private void pushLoop() {
        // v1.50 P1-3: count 游标 → id 游标——环形淘汰 remove(0) 后列表前移，
        //   count 游标 subList(lastCount, size) 会漏推中间条目；id 全局唯一单调（LogStore seq），
        //   淘汰不影响 id 游标语义。
        long lastPushedId = 0;
        long backoffMs = 0; // v1.50 P2-12: 失败指数退避（9900 未起时不再每 2s 重推同批刷 DebugLog）
        while (true) {
            try {
                Thread.sleep(2000);
                if (!pushHome) continue;
                List<HttpEntry> snap;
                synchronized (lock) {
                    snap = new ArrayList<>(entries);
                }
                List<HttpEntry> fresh = new ArrayList<>();
                for (HttpEntry e : snap) {
                    if (e.id > lastPushedId) fresh.add(e);
                }
                if (fresh.isEmpty()) {
                    backoffMs = 0;
                    continue;
                }
                // push 成功才推进游标——失败（9900 未起/网络异常）时该批保留待重试
                if (pushBatch(fresh)) {
                    lastPushedId = fresh.get(fresh.size() - 1).id;
                    backoffMs = 0;
                } else {
                    long next = backoffMs == 0 ? 1000 : Math.min(backoffMs * 2, 30000);
                    backoffMs = next;
                    try { Thread.sleep(next); } catch (InterruptedException ie) { return; }
                }
            } catch (InterruptedException ie) {
                return;
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("HttpStore", "pushLoop err: " + t);
            }
        }
    }

    /** 批量推送；返回是否成功（200 才算成功） */
    private boolean pushBatch(List<HttpEntry> batch) {
        try {
            JSONObject payload = new JSONObject();
            JSONArray arr = new JSONArray();
            for (HttpEntry e : batch) arr.put(e.toJson());
            payload.put("entries", arr);
            String body = payload.toString();

            String host = "127.0.0.1:9900";
            StringBuilder head = new StringBuilder();
            head.append("POST /api/push_http HTTP/1.1\r\n");
            head.append("Host: ").append(host).append("\r\n");
            head.append("Content-Type: application/json\r\n");
            head.append("Content-Length: ").append(body.getBytes("UTF-8").length).append("\r\n");
            if (pushTokenProvider != null && (pushToken == null || pushToken.isEmpty())) {
                String t = pushTokenProvider.get();
                if (t != null) pushToken = t;
            }
            if (!pushToken.isEmpty()) head.append("X-Spy-Token: ").append(pushToken).append("\r\n");
            head.append("\r\n");

            java.net.Socket sock = new java.net.Socket();
            sock.connect(new java.net.InetSocketAddress("127.0.0.1", 9900), 3000);
            sock.setSoTimeout(5000);
            java.io.OutputStream os = sock.getOutputStream();
            os.write(head.toString().getBytes("UTF-8"));
            os.write(body.getBytes("UTF-8"));
            os.flush();
            java.io.InputStream is = sock.getInputStream();
            byte[] buf = new byte[4096];
            int n = is.read(buf);
            String statusLine = n > 0 ? new String(buf, 0, Math.min(n, 80), "UTF-8") : "";
            sock.close();
            boolean ok = statusLine.contains("200");
            // v1.53.1: 成功也留痕（低频，2s 一次）——真机验证 REQ# 卡片链路是否打通
            if (ok) {
                DebugLog.get().logNoMirror("HttpStore", "push OK " + batch.size() + " entries");
            } else {
                DebugLog.get().logNoMirror("HttpStore", "push " + batch.size() + " -> " + statusLine.replace("\r\n", " "));
            }
            return ok;
        } catch (Throwable t) {
            DebugLog.get().logNoMirror("HttpStore", "push FAIL: " + t);
            return false;
        }
    }
}
