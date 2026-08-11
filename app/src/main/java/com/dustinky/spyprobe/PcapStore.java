package com.dustinky.spyprobe;

/*
 * v1.39 P0: 主进程 pcap 落盘（SpyProbe 自己家 files/spyprobe_pcap/）
 *
 * - 目标进程 PcapWriter 连接关闭时推 /api/pcap_chunk（pcap 记录字节，无全局头）
 * - 这里 append 到 current.pcap（首次创建写 24B 全局头）
 * - 会话切换（目标进程重启，LogPersister.startSession 同步调 onSessionStart）
 *   → current.pcap 归档为 pcap_<ts>_<n>.pcap，新建 current.pcap
 * - UI「导出 pcap」读目录所有 pcap 文件合并（全局头一次 + 全部记录）分享
 *
 * 由 ModuleMain.onPackageReady 用 ActivityThread.currentApplication().getFilesDir() 初始化。
 */
public class PcapStore {

    private static final PcapStore INSTANCE = new PcapStore();
    public static PcapStore get() { return INSTANCE; }

    // pcap 全局头（24B）：magic 0xa1b2c3d4 / v2.4 / snaplen 65535 / LINKTYPE_IPV4(228)
    private static final byte[] GLOBAL_HEADER = {
            (byte) 0xd4, (byte) 0xc3, (byte) 0xb2, (byte) 0xa1,
            0x02, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            (byte) 0xff, (byte) 0xff, 0x00, 0x00,
            (byte) 0xe4, 0x00, 0x00, 0x00
    };

    private volatile java.io.File dir = null;
    private volatile java.io.File current = null;
    private final Object lock = new Object();

    public synchronized void init(java.io.File appFilesDir) {
        if (dir != null) return;
        dir = new java.io.File(appFilesDir, "spyprobe_pcap");
        if (!dir.exists()) dir.mkdirs();
        current = new java.io.File(dir, "current.pcap");
        DebugLog.get().logNoMirror("Pcap", "init dir=" + dir.getAbsolutePath());
    }

    public boolean isInitialized() { return dir != null; }
    public String dirPath() { return dir != null ? dir.getAbsolutePath() : "(null)"; }

    /** 目标进程推送的 pcap 记录（无全局头）→ append current.pcap */
    public void append(byte[] records) {
        if (records == null || records.length == 0) return;
        synchronized (lock) {
            try {
                if (dir == null || current == null) return;
                boolean first = !current.exists() || current.length() == 0;
                java.io.FileOutputStream fos = new java.io.FileOutputStream(current, true);
                try {
                    if (first) fos.write(GLOBAL_HEADER);
                    fos.write(records);
                } finally {
                    try { fos.close(); } catch (Throwable t2) { }
                }
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("Pcap", "append err: " + t);
            }
        }
    }

    /** 会话切换：current.pcap 归档（避免多会话混一个文件） */
    public void onSessionStart() {
        synchronized (lock) {
            try {
                if (dir == null || current == null) return;
                if (current.exists() && current.length() > 24) { // 有内容才归档
                    java.text.SimpleDateFormat fmt =
                            new java.text.SimpleDateFormat("yyyyMMdd_HHmmss", java.util.Locale.US);
                    String ts = fmt.format(new java.util.Date());
                    java.io.File archived = new java.io.File(dir, "pcap_" + ts + ".pcap");
                    if (archived.exists()) archived.delete();
                    if (!current.renameTo(archived)) {
                        DebugLog.get().logNoMirror("Pcap", "archive rename FAIL -> " + archived.getName());
                    } else {
                        DebugLog.get().logNoMirror("Pcap", "archived -> " + archived.getName()
                                + " (" + archived.length() + "B)");
                    }
                }
                current = new java.io.File(dir, "current.pcap");
                // 清掉历史过大的归档（保留最近 5 个，防占盘）
                cleanOld();
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("Pcap", "onSessionStart err: " + t);
            }
        }
    }

    private void cleanOld() {
        try {
            java.io.File[] fs = dir.listFiles((d, name) -> name.startsWith("pcap_") && name.endsWith(".pcap"));
            if (fs == null || fs.length <= 5) return;
            java.util.Arrays.sort(fs, (a, b) -> Long.compare(b.lastModified(), a.lastModified()));
            for (int i = 5; i < fs.length; i++) {
                try { fs[i].delete(); } catch (Throwable t2) { }
            }
        } catch (Throwable ignored) { }
    }

    /** 合并全部 pcap 文件为一个完整 pcap（全局头一次 + 各文件去掉自带全局头的记录）
     *  v1.42 P1-4: 流式合并——旧实现每文件整读 + 整份复制到 out，pcap 累积几十 MB 时
     *   同时驻留「单文件全量 + 合并全量」两倍内存 → OOM。现在每文件 64KB 分块读、
     *   边读边写 out，且超过 MAX_EXPORT_BYTES 直接放弃（返回 null，UI 提示数据过大）。 */
    private static final long MAX_EXPORT_BYTES = 256L * 1024 * 1024; // 256MB 上限（Wireshark 可开）

    public byte[] exportAllBytes() {
        synchronized (lock) {
            try {
                if (dir == null) return null;
                java.io.File[] fs = dir.listFiles((d, name) -> name.endsWith(".pcap"));
                if (fs == null || fs.length == 0) return null;
                java.util.Arrays.sort(fs, (a, b) -> a.getName().compareTo(b.getName()));
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(1 << 20);
                out.write(GLOBAL_HEADER);
                int files = 0;
                byte[] chunk = new byte[64 * 1024];
                for (java.io.File f : fs) {
                    if (f.length() <= 24) continue;
                    java.io.FileInputStream fis = new java.io.FileInputStream(f);
                    try {
                        // 跳过文件自带 24B 全局头
                        long skip = 0;
                        while (skip < 24) {
                            long k = fis.skip(24 - skip);
                            if (k <= 0) break;
                            skip += k;
                        }
                        int n;
                        while ((n = fis.read(chunk)) > 0) {
                            if (out.size() + n > MAX_EXPORT_BYTES) {
                                DebugLog.get().logNoMirror("Pcap", "export aborted: merged > 256MB");
                                return null;
                            }
                            out.write(chunk, 0, n);
                        }
                    } finally {
                        try { fis.close(); } catch (Throwable t2) { }
                    }
                    files++;
                }
                if (files == 0) return null;
                return out.toByteArray();
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("Pcap", "export err: " + t);
                return null;
            }
        }
    }

    /** 仅导出当前会话（current.pcap，自带 24B 全局头；归档 pcap_*.pcap 不合并）
     *  v1.46.3: 用户反馈不想导出历史——新增「仅当前会话」导出选项 */
    public byte[] exportCurrentBytes() {
        synchronized (lock) {
            try {
                if (current == null || !current.exists()) return null;
                long len = current.length();
                if (len <= 24) return null; // 只有全局头=无记录
                if (len > MAX_EXPORT_BYTES) {
                    DebugLog.get().logNoMirror("Pcap", "exportCurrent aborted: > 256MB");
                    return null;
                }
                byte[] data = new byte[(int) len];
                java.io.FileInputStream fis = new java.io.FileInputStream(current);
                int off = 0;
                try {
                    int n;
                    while (off < data.length && (n = fis.read(data, off, data.length - off)) > 0) {
                        off += n;
                    }
                } finally {
                    try { fis.close(); } catch (Throwable t2) { }
                }
                if (off <= 24) return null;
                return data; // current.pcap 自带 24B 全局头，直接是合法 pcap
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("Pcap", "exportCurrent err: " + t);
                return null;
            }
        }
    }

    /** 清空全部 pcap 数据（current + 历史归档）。删除后下次 append 自动重建全局头。 */
    public int clearAll() {
        synchronized (lock) {
            int n = 0;
            try {
                if (dir == null) return 0;
                java.io.File[] fs = dir.listFiles((d, name) -> name.endsWith(".pcap"));
                if (fs != null) {
                    for (java.io.File f : fs) {
                        try { if (f.delete()) n++; } catch (Throwable t2) { }
                    }
                }
            } catch (Throwable t) {
                DebugLog.get().logNoMirror("Pcap", "clear err: " + t);
            }
            DebugLog.get().logNoMirror("Pcap", "clearAll -> deleted " + n + " pcap files");
            return n;
        }
    }

    /** 当前 pcap 文件大小（UI 状态显示） */
    public long currentSize() {
        try {
            if (current == null) return 0;
            return current.exists() ? current.length() : 0;
        } catch (Throwable t) {
            return 0;
        }
    }
}
