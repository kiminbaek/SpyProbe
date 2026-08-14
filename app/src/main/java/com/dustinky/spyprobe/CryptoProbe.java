package com.dustinky.spyprobe;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import io.github.libxposed.api.XposedModule;

/**
 * 加密算法记录（v1.5 新增，v1.14 重写）：
 * hook javax.crypto.Cipher 的 getInstance/init/update/doFinal，按 Cipher 实例跟踪完整上下文：
 *   - 算法（transformation，如 AES/CBC/PKCS5Padding）
 *   - 加解密方向（ENCRYPT/DECRYPT）
 *   - 密钥（algorithm + base64/hex，完整）
 *   - IV（hex，完整）
 *   - 明文/密文（update 分块拼接 + doFinal 汇总，上限 1MB 防刷屏）
 *   - 调用堆栈
 * v1.14 借鉴 SimpleHook CipherHook：ConcurrentHashMap 实例上下文 + 数据流拼接 + 完整输出。
 * 注意：默认关（cryptoCapture=false）防刷屏；数据加密在 native/pure-Dart 层时这里看不到。
 */
public class CryptoProbe {

    static final String TAG = "SpyProbe.Crypto";

    private final XposedModule module;

    public CryptoProbe(XposedModule module) {
        this.module = module;
    }

    /** 单个 Cipher 实例的跟踪上下文（init 记录，update 拼接，doFinal 汇总后移除） */
    private static class Ctx {
        String algorithm = "unknown";
        String cryptMode = "?";
        String keyAlgo = null;
        String keyHex = null;
        String ivHex = null;
        final ByteArrayOutputStream dataStream = new ByteArrayOutputStream(256);
        boolean hadData = false;
    }

    // v1.15 P1-3: CTXS 强引用泄漏 —— Cipher 未 doFinal 即 GC → Ctx 永久残留。
    //   改 WeakHashMap（Cipher 不复写 equals/hashCode，可安全弱引用）+ synchronizedMap 保证线程安全。
    private static final Map<Cipher, Ctx> CTXS = Collections.synchronizedMap(new WeakHashMap<Cipher, Ctx>());

    // v1.54: Crypto 同签名 5s 限频——视频分片解密同一 AES key 每组 getInstance/init/SecretKeySpec
    //   各打一行，v1.53 日志 102 行纯重复噪音（同一 key 34 组）。按"算法+key 指纹"限频：5s 内
    //   同指纹只记首条，key 变化立即出新条（信息不丢，刷屏根治）。
    private static final java.util.Map<String, Long> CRYPTO_RATE = new java.util.concurrent.ConcurrentHashMap<>();
    private static final long CRYPTO_RATE_MS = 5000;
    private static boolean cryptoRateLimited(String sig) {
        long now = System.currentTimeMillis();
        Long prev = CRYPTO_RATE.get(sig);
        if (prev != null && now - prev < CRYPTO_RATE_MS) return true;
        CRYPTO_RATE.put(sig, now);
        if (CRYPTO_RATE.size() > 128) CRYPTO_RATE.clear(); // 防膨胀
        return false;
    }
    private static final int MAX_CAPTURE = 1024 * 1024; // 1MB 上限防刷屏

    public void install(String phase) {
        // v1.37 P0-1: 惰性安装——开关关闭时完全不装 hook（借鉴 Guise activeHookFeatures，
        //   用户关闭的探测项在目标进程零 hook 存在，减少崩溃面 + 更隐蔽 + 启动更快）
        if (!Config.get().cryptoCapture) {
            DebugLog.get().logNoMirror("Crypto", "install(" + phase + ") skipped: Config.get().cryptoCapture == false");
            return;
        }
        try {
            // getInstance(String) / getInstance(String, String) —— 记算法
            try {
                Method gi = Cipher.class.getMethod("getInstance", String.class);
                module.hook(gi).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture && r instanceof Cipher) {
                        try {
                            Ctx ctx = CTXS.computeIfAbsent((Cipher) r, k -> new Ctx());
                            ctx.algorithm = String.valueOf(chain.getArg(0));
                            // v1.54: 同算法 5s 限频（getInstance 每次 Cipher 构造都打 → 刷屏）
                            if (!cryptoRateLimited("gi:" + ctx.algorithm)) {
                                logCryptoEvent("GETINSTANCE", ctx.algorithm, "", "", "", "",
                                        "[getInstance] " + ctx.algorithm);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            try {
                Method gi2 = Cipher.class.getMethod("getInstance", String.class, String.class);
                module.hook(gi2).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture && r instanceof Cipher) {
                        try {
                            Ctx ctx = CTXS.computeIfAbsent((Cipher) r, k -> new Ctx());
                            ctx.algorithm = String.valueOf(chain.getArg(0));
                            // v1.54: 同算法+provider 5s 限频
                            if (!cryptoRateLimited("gi:" + ctx.algorithm + "@" + chain.getArg(1))) {
                                logCryptoEvent("GETINSTANCE", ctx.algorithm, "", "", "", "",
                                        "[getInstance] " + ctx.algorithm + " provider=" + chain.getArg(1));
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }

            // init(int, Key) —— 记模式+密钥
            try {
                Method init = Cipher.class.getMethod("init", int.class, Key.class);
                module.hook(init).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) initCtx(chain.getThisObject(), chain.getArg(0), chain.getArg(1), null);
                    return r;
                });
            } catch (Throwable t) { }
            // init(int, Key, AlgorithmParameterSpec) —— 记模式+密钥+IV
            try {
                Method init2 = Cipher.class.getMethod("init", int.class, Key.class, AlgorithmParameterSpec.class);
                module.hook(init2).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) initCtx(chain.getThisObject(), chain.getArg(0), chain.getArg(1), chain.getArg(2));
                    return r;
                });
            } catch (Throwable t) { }
            // init(int, Key, SecureRandom)
            try {
                Method init3 = Cipher.class.getMethod("init", int.class, Key.class, java.security.SecureRandom.class);
                module.hook(init3).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) initCtx(chain.getThisObject(), chain.getArg(0), chain.getArg(1), null);
                    return r;
                });
            } catch (Throwable t) { }
            // init(int, Key, AlgorithmParameterSpec, SecureRandom)
            try {
                Method init4 = Cipher.class.getMethod("init", int.class, Key.class, AlgorithmParameterSpec.class, java.security.SecureRandom.class);
                module.hook(init4).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) initCtx(chain.getThisObject(), chain.getArg(0), chain.getArg(1), chain.getArg(2));
                    return r;
                });
            } catch (Throwable t) { }
            // v1.28 P1: init(int, Certificate) / init(int, Certificate, SecureRandom) —— 证书公钥初始化（RSA 验签/加密场景）
            try {
                Method init5 = Cipher.class.getMethod("init", int.class, java.security.cert.Certificate.class);
                module.hook(init5).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        Object cert = chain.getArg(1);
                        Object key = (cert instanceof java.security.cert.Certificate) ? ((java.security.cert.Certificate) cert).getPublicKey() : cert;
                        initCtx(chain.getThisObject(), chain.getArg(0), key, null);
                    }
                    return r;
                });
            } catch (Throwable t) { }
            try {
                Method init6 = Cipher.class.getMethod("init", int.class, java.security.cert.Certificate.class, java.security.SecureRandom.class);
                module.hook(init6).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        Object cert = chain.getArg(1);
                        Object key = (cert instanceof java.security.cert.Certificate) ? ((java.security.cert.Certificate) cert).getPublicKey() : cert;
                        initCtx(chain.getThisObject(), chain.getArg(0), key, null);
                    }
                    return r;
                });
            } catch (Throwable t) { }

            // update(byte[]) —— 流式数据拼接（v1.14 增强：不再是单条日志，拼进 Ctx.dataStream）
            try {
                Method up = Cipher.class.getMethod("update", byte[].class);
                module.hook(up).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            if (in instanceof byte[]) appendStream(chain.getThisObject(), (byte[]) in, 0, ((byte[]) in).length);
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            // v1.14: update(byte[], int, int) —— 分块流式
            try {
                Method up2 = Cipher.class.getMethod("update", byte[].class, int.class, int.class);
                module.hook(up2).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            Object off = chain.getArg(1);
                            Object len = chain.getArg(2);
                            if (in instanceof byte[] && off instanceof Integer && len instanceof Integer) {
                                appendStream(chain.getThisObject(), (byte[]) in, (Integer) off, (Integer) len);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            // v1.14: update(ByteBuffer) —— ByteBuffer 流式
            try {
                Method up3 = Cipher.class.getMethod("update", ByteBuffer.class);
                module.hook(up3).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            if (in instanceof ByteBuffer) {
                                ByteBuffer dup = ((ByteBuffer) in).duplicate();
                                int rem = dup.remaining();
                                byte[] tmp = new byte[Math.min(rem, MAX_CAPTURE)];
                                dup.get(tmp);
                                appendStream(chain.getThisObject(), tmp, 0, tmp.length);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }

            // doFinal() —— 无参收尾
            try {
                Method df = Cipher.class.getMethod("doFinal");
                module.hook(df).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) finalizeCipher(chain.getThisObject(), null, r);
                    return r;
                });
            } catch (Throwable t) { }
            // doFinal(byte[]) —— 一次收尾
            try {
                Method df = Cipher.class.getMethod("doFinal", byte[].class);
                module.hook(df).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            if (in instanceof byte[]) appendStream(chain.getThisObject(), (byte[]) in, 0, ((byte[]) in).length);
                            finalizeCipher(chain.getThisObject(), null, r);
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            // doFinal(byte[], int, int) —— 分块收尾
            try {
                Method df = Cipher.class.getMethod("doFinal", byte[].class, int.class, int.class);
                module.hook(df).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            Object off = chain.getArg(1);
                            Object len = chain.getArg(2);
                            if (in instanceof byte[] && off instanceof Integer && len instanceof Integer) {
                                appendStream(chain.getThisObject(), (byte[]) in, (Integer) off, (Integer) len);
                            }
                            finalizeCipher(chain.getThisObject(), null, r);
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            // v1.15 P2-3: doFinal(ByteBuffer, ByteBuffer) —— 输出写入 output buffer，返回 int(输出长度)
            try {
                Method df = Cipher.class.getMethod("doFinal", ByteBuffer.class, ByteBuffer.class);
                module.hook(df).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            Object out = chain.getArg(1);
                            if (in instanceof ByteBuffer) {
                                ByteBuffer dup = ((ByteBuffer) in).duplicate();
                                int rem = dup.remaining();
                                byte[] tmp = new byte[Math.min(rem, MAX_CAPTURE)];
                                dup.get(tmp);
                                appendStream(chain.getThisObject(), tmp, 0, tmp.length);
                            }
                            if (out instanceof ByteBuffer) {
                                ByteBuffer od = ((ByteBuffer) out).duplicate();
                                od.flip(); // 读 position 前的内容（proceed 后已写入）
                                byte[] ob = new byte[od.remaining()];
                                od.get(ob);
                                finalizeCipher(chain.getThisObject(), null, ob);
                            } else {
                                finalizeCipher(chain.getThisObject(), null, null);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            // v1.15 P2-3: doFinal(byte[], int, int, byte[], int) —— 输出写到 outputOffset 起，返回 int(输出长度)
            try {
                Method df = Cipher.class.getMethod("doFinal", byte[].class, int.class, int.class, byte[].class, int.class);
                module.hook(df).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            Object off = chain.getArg(1);
                            Object len = chain.getArg(2);
                            Object outArr = chain.getArg(3);
                            Object outOff = chain.getArg(4);
                            if (in instanceof byte[] && off instanceof Integer && len instanceof Integer) {
                                appendStream(chain.getThisObject(), (byte[]) in, (Integer) off, (Integer) len);
                            }
                            if (r instanceof Integer && outArr instanceof byte[] && outOff instanceof Integer) {
                                int n = (Integer) r;
                                int oo = (Integer) outOff;
                                byte[] ob = new byte[Math.min(n, MAX_CAPTURE)];
                                System.arraycopy((byte[]) outArr, oo, ob, 0, ob.length);
                                finalizeCipher(chain.getThisObject(), null, ob);
                            } else {
                                finalizeCipher(chain.getThisObject(), null, null);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }

            // v1.38 P1-5: hooker cipher.js/hook_encryption_algo.js 借鉴——补 SecretKeySpec/DESKeySpec/Mac/SecureRandom
            installExt(phase);

            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked Cipher (getInstance/init/update/doFinal, v1.14 实例跟踪 + v1.15 补2重载 + v1.38 扩展)");
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] Cipher hook fail: " + t);
        }
    }

    /**
     * v1.38 P1-5: 加密算法追踪扩展（hooker cipher.js / hook_encryption_algo.js 借鉴）
     *   - SecretKeySpec/DESKeySpec 构造：密钥材料构建点（对称加密密钥源头）
     *   - Mac.getInstance/init/update/doFinal：HMAC/摘要 MAC 计算追踪
     *   - SecureRandom.setSeed：自定义种子（可预测随机数线索）
     */
    private void installExt(String phase) {
        // SecretKeySpec.<init>(byte[], String) / (byte[], int, String) —— 对称密钥材料
        try {
            Class<?> sks = javax.crypto.spec.SecretKeySpec.class;
            java.lang.reflect.Constructor<?> m1 = sks.getConstructor(byte[].class, String.class);
            module.hook(m1).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().cryptoCapture) {
                    try {
                        Object k = chain.getArg(0);
                        if (k instanceof byte[]) {
                            byte[] kb = (byte[]) k;
                            String sig = "sks:" + chain.getArg(1) + ":"
                                    + MethodProbe.hex(kb, Math.min(kb.length, 128));
                            if (!cryptoRateLimited(sig)) {
                                String hexKey = MethodProbe.hex(kb, Math.min(kb.length, 128))
                                        + (kb.length > 128 ? "...(" + kb.length + "B)" : "(" + kb.length + "B)");
                                logCryptoEvent("KEYS", String.valueOf(chain.getArg(1)), "", hexKey, "", "",
                                        "[SecretKeySpec] algo=" + chain.getArg(1) + " key=" + hexKey);
                            }
                        }
                    } catch (Throwable t) { }
                }
                return r;
            });
            java.lang.reflect.Constructor<?> m2 = sks.getConstructor(byte[].class, int.class, String.class);
            module.hook(m2).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().cryptoCapture) {
                    try {
                        Object k = chain.getArg(0);
                        if (k instanceof byte[]) {
                            byte[] kb = (byte[]) k;
                            String sig = "sks:" + chain.getArg(2) + "@" + chain.getArg(1) + ":"
                                    + MethodProbe.hex(kb, Math.min(kb.length, 128));
                            if (!cryptoRateLimited(sig)) {
                                String hexKey = MethodProbe.hex(kb, Math.min(kb.length, 128))
                                        + (kb.length > 128 ? "...(" + kb.length + "B)" : "(" + kb.length + "B)");
                                logCryptoEvent("KEYS", String.valueOf(chain.getArg(2)), "", hexKey, "", "",
                                        "[SecretKeySpec] algo=" + chain.getArg(2) + " off=" + chain.getArg(1)
                                                + " key=" + hexKey);
                            }
                        }
                    } catch (Throwable t) { }
                }
                return r;
            });
        } catch (Throwable t) { }

        // DESKeySpec.<init>(byte[]) / (byte[], int) —— 老 DES 密钥
        try {
            Class<?> dks = javax.crypto.spec.DESKeySpec.class;
            java.lang.reflect.Constructor<?> m1 = dks.getConstructor(byte[].class);
            module.hook(m1).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().cryptoCapture) {
                    try {
                        Object k = chain.getArg(0);
                        if (k instanceof byte[]) {
                            byte[] kb = (byte[]) k;
                            String hexKey = MethodProbe.hex(kb, Math.min(kb.length, 128))
                                    + (kb.length > 128 ? "...(" + kb.length + "B)" : "(" + kb.length + "B)");
                            logCryptoEvent("KEYS", "DES", "", hexKey, "", "",
                                    "[DESKeySpec] key=" + hexKey);
                        }
                    } catch (Throwable t) { }
                }
                return r;
            });
            java.lang.reflect.Constructor<?> m2 = dks.getConstructor(byte[].class, int.class);
            module.hook(m2).intercept(chain -> {
                Object r = chain.proceed();
                if (Config.get().cryptoCapture) {
                    try {
                        Object k = chain.getArg(0);
                        if (k instanceof byte[]) {
                            byte[] kb = (byte[]) k;
                            String hexKey = MethodProbe.hex(kb, Math.min(kb.length, 128))
                                    + (kb.length > 128 ? "...(" + kb.length + "B)" : "(" + kb.length + "B)");
                            logCryptoEvent("KEYS", "DES", "", hexKey, "", "",
                                    "[DESKeySpec] off=" + chain.getArg(1) + " key=" + hexKey);
                        }
                    } catch (Throwable t) { }
                }
                return r;
            });
        } catch (Throwable t) { }

        // Mac —— HMAC 计算（getInstance 记算法；init 记密钥；doFinal 汇总）
        try {
            Class<?> macCls = javax.crypto.Mac.class;
            try {
                Method gi = macCls.getMethod("getInstance", String.class);
                module.hook(gi).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture && r != null) {
                        logCryptoEvent("MAC", String.valueOf(chain.getArg(0)), "", "", "", "",
                                "[Mac.getInstance] " + chain.getArg(0));
                    }
                    return r;
                });
            } catch (Throwable t) { }
            try {
                Method init = macCls.getMethod("init", java.security.Key.class);
                module.hook(init).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object key = chain.getArg(0);
                            if (key instanceof java.security.Key) {
                                java.security.Key k = (java.security.Key) key;
                                String kh = "<" + k.getClass().getName() + ">";
                                try {
                                    byte[] enc = k.getEncoded();
                                    if (enc != null) kh = MethodProbe.hex(enc, Math.min(enc.length, 128))
                                            + (enc.length > 128 ? "...(" + enc.length + "B)" : "(" + enc.length + "B)");
                                } catch (Throwable t2) { }
                                logCryptoEvent("MAC", k.getAlgorithm(), "", kh, "", "",
                                        "[Mac.init] algo=" + k.getAlgorithm() + " key=" + kh);
                            }
                        } catch (Throwable t2) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            try {
                Method up = macCls.getMethod("update", byte[].class);
                module.hook(up).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            if (in instanceof byte[]) {
                                byte[] d = (byte[]) in;
                                logCryptoEvent("MAC", "", "", "", "",
                                        MethodProbe.hex(d, Math.min(d.length, 64))
                                                + (d.length > 64 ? "...(" + d.length + "B)" : "(" + d.length + "B)"),
                                        "[Mac.update] " + MethodProbe.hex(d, Math.min(d.length, 64))
                                                + (d.length > 64 ? "...(" + d.length + "B)" : "(" + d.length + "B)"));
                            }
                        } catch (Throwable t2) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            try {
                Method df = macCls.getMethod("doFinal");
                module.hook(df).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            if (r instanceof byte[]) {
                                byte[] d = (byte[]) r;
                                logCryptoEvent("MAC", "", "", "", "",
                                        MethodProbe.hex(d, Math.min(d.length, 64))
                                                + (d.length > 64 ? "...(" + d.length + "B)" : "(" + d.length + "B)"),
                                        "[Mac.doFinal] mac=" + MethodProbe.hex(d, Math.min(d.length, 64))
                                                + (d.length > 64 ? "...(" + d.length + "B)" : "(" + d.length + "B)"));
                            }
                        } catch (Throwable t2) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked Mac (getInstance/init/update/doFinal)");
        } catch (Throwable t) { }

        // SecureRandom.setSeed —— 自定义种子（可预测 RNG 线索）
        try {
            Class<?> sr = java.security.SecureRandom.class;
            try {
                Method m = sr.getMethod("setSeed", byte[].class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object s = chain.getArg(0);
                            if (s instanceof byte[]) {
                                byte[] d = (byte[]) s;
                                logCryptoEvent("SEED", "", "", "", "",
                                        MethodProbe.hex(d, Math.min(d.length, 64))
                                                + (d.length > 64 ? "...(" + d.length + "B)" : "(" + d.length + "B)"),
                                        "[SecureRandom.setSeed] " + MethodProbe.hex(d, Math.min(d.length, 64))
                                                + (d.length > 64 ? "...(" + d.length + "B)" : "(" + d.length + "B)"));
                            }
                        } catch (Throwable t2) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            try {
                Method m = sr.getMethod("setSeed", long.class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            logCryptoEvent("SEED", "", "", "", "", String.valueOf(chain.getArg(0)),
                                    "[SecureRandom.setSeed] " + chain.getArg(0));
                        } catch (Throwable t2) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked SecureRandom.setSeed");
        } catch (Throwable t) { }

        // v8x P2 (HookNext 借鉴): Base64 编解码记录 —— 敏感数据常 Base64 后传输，
        //   解码能看到明文业务内容（如 91aw 的 token/签名/参数）。
        //   HookNext 的 Base64 记录类型 = android.util.Base64 + java.util.Base64 双 hook。
        installBase64(phase);

        DebugLog.get().logNoMirror(TAG, "[" + phase + "] hooked Base64 (android.util + java.util)");
    }

    /** v8x P2 (HookNext 借鉴): Base64 编解码记录（默认随 cryptoCapture 开关，5s 同签名限频防刷屏） */
    private void installBase64(String phase) {
        final int MAX_B64 = 512; // 单次记录最大字节（超限截断，防大文件刷屏）
        // ---- android.util.Base64（API 8+ 系统级） ----
        try {
            Class<?> b64 = Class.forName("android.util.Base64");
            // decode(String, int) → byte[]：解码最有用（明文内容直接可见）
            try {
                Method m = b64.getMethod("decode", String.class, int.class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            if (in instanceof String) {
                                String s = (String) in;
                                if (s.length() > 4096) return r; // 大块跳过（避免高频刷屏）
                                byte[] out = r instanceof byte[] ? (byte[]) r : null;
                                logBase64Event("DECODE", "android.util.Base64", s, out, MAX_B64);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            // decode(byte[], int) → byte[]
            try {
                Method m = b64.getMethod("decode", byte[].class, int.class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            if (in instanceof byte[] && ((byte[]) in).length <= 4096) {
                                byte[] out = r instanceof byte[] ? (byte[]) r : null;
                                logBase64Event("DECODE", "android.util.Base64", new String((byte[]) in, StandardCharsets.UTF_8), out, MAX_B64);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            // encodeToString(byte[], int) → String：编码方向（同签名限频）
            try {
                Method m = b64.getMethod("encodeToString", byte[].class, int.class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            if (in instanceof byte[] && ((byte[]) in).length <= 4096) {
                                String out = r instanceof String ? (String) r : null;
                                logBase64Event("ENCODE", "android.util.Base64", out, (byte[]) in, MAX_B64);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
        } catch (Throwable t) { }

        // ---- java.util.Base64（API 26+，现代 App 常用） ----
        try {
            // Decoder.decode(String) / decode(byte[])
            try {
                Class<?> dec = Class.forName("java.util.Base64$Decoder");
                Method m = dec.getMethod("decode", String.class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            if (in instanceof String && ((String) in).length() <= 4096) {
                                byte[] out = r instanceof byte[] ? (byte[]) r : null;
                                logBase64Event("DECODE", "java.util.Base64", (String) in, out, MAX_B64);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            try {
                Class<?> dec = Class.forName("java.util.Base64$Decoder");
                Method m = dec.getMethod("decode", byte[].class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            if (in instanceof byte[] && ((byte[]) in).length <= 4096) {
                                byte[] out = r instanceof byte[] ? (byte[]) r : null;
                                logBase64Event("DECODE", "java.util.Base64", new String((byte[]) in, StandardCharsets.UTF_8), out, MAX_B64);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
            // Encoder.encode(byte[]) → byte[]
            try {
                Class<?> enc = Class.forName("java.util.Base64$Encoder");
                Method m = enc.getMethod("encode", byte[].class);
                module.hook(m).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            if (in instanceof byte[] && ((byte[]) in).length <= 4096) {
                                byte[] out = r instanceof byte[] ? (byte[]) r : null;
                                logBase64Event("ENCODE", "java.util.Base64", out == null ? "" : new String(out, StandardCharsets.UTF_8), (byte[]) in, MAX_B64);
                            }
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }
        } catch (Throwable t) { }
    }

    /** v8x P2: Base64 结构化事件（op=DECODE/ENCODE，data 存截断内容 + 可读文本） */
    private static void logBase64Event(String op, String src, String b64In, byte[] rawOut, int maxBytes) {
        try {
            String b64 = b64In == null ? "" : (b64In.length() > 128 ? b64In.substring(0, 128) + "...(" + b64In.length() + ")" : b64In);
            String rawHex = "";
            String rawText = "";
            if (rawOut != null) {
                byte[] view = rawOut.length > maxBytes ? java.util.Arrays.copyOf(rawOut, maxBytes) : rawOut;
                rawHex = MethodProbe.hex(view, Math.min(view.length, 128))
                        + (rawOut.length > maxBytes ? "...(" + rawOut.length + "B)" : "");
                rawText = new String(view, StandardCharsets.UTF_8);
                // 可打印才展示文本（二进制乱码不刷屏）
                boolean printable = true;
                for (byte b : view) {
                    int c = b & 0xFF;
                    if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') { printable = false; break; }
                }
                if (!printable) rawText = "<binary " + rawOut.length + "B>";
                else if (rawText.length() > 200) rawText = rawText.substring(0, 200) + "...";
            }
            String sig = "b64:" + op + ":" + b64 + ":" + rawHex;
            if (cryptoRateLimited(sig)) return;
            String fullMsg = "[Base64 " + op + "] " + src + " in=\"" + b64 + "\" out=" + rawHex
                    + (rawText.isEmpty() ? "" : " text=\"" + rawText + "\"");
            long eid = EventStore.get().nextId();
            String msg = "[EVT#" + eid + "]" + fullMsg;
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("op", op);
            payload.put("algorithm", "Base64");
            payload.put("mode", src);
            payload.put("key", "");
            payload.put("iv", "");
            payload.put("data", rawHex + (rawText.isEmpty() ? "" : " | text: " + rawText));
            EventStore.get().add(new SpyEvent("CRYPTO", eid, System.currentTimeMillis(),
                    "Base64 " + op + " " + src, payload, msg, ""));
        } catch (Throwable t) { }
    }

    /** init 时把算法/模式/密钥/IV 记入实例上下文 */
    private static void initCtx(Object cipher, Object opmode, Object key, Object spec) {
        try {
            if (!(cipher instanceof Cipher)) return;
            Cipher c = (Cipher) cipher;
            Ctx ctx = CTXS.computeIfAbsent(c, k -> new Ctx());
            try { ctx.algorithm = c.getAlgorithm(); } catch (Throwable t) { }
            if (opmode instanceof Integer) {
                int m = (Integer) opmode;
                ctx.cryptMode = m == Cipher.ENCRYPT_MODE ? "ENCRYPT" : m == Cipher.DECRYPT_MODE ? "DECRYPT"
                        : m == Cipher.WRAP_MODE ? "WRAP" : m == Cipher.UNWRAP_MODE ? "UNWRAP" : String.valueOf(m);
            }
            if (key instanceof Key) {
                Key k = (Key) key;
                ctx.keyAlgo = k.getAlgorithm();
                try {
                    byte[] enc = k.getEncoded();
                    if (enc != null) ctx.keyHex = MethodProbe.hex(enc, Math.min(enc.length, 128)) + (enc.length > 128 ? "...(" + enc.length + "B)" : "");
                } catch (Throwable t) { }
            } else if (key != null) {
                ctx.keyHex = "<" + key.getClass().getName() + ">";
            }
            if (spec instanceof IvParameterSpec) {
                byte[] iv = ((IvParameterSpec) spec).getIV();
                ctx.ivHex = MethodProbe.hex(iv, Math.min(iv.length, 128)) + (iv.length > 128 ? "...(" + iv.length + "B)" : "");
            } else if (spec instanceof GCMParameterSpec) {
                byte[] iv = ((GCMParameterSpec) spec).getIV();
                ctx.ivHex = "gcm:" + MethodProbe.hex(iv, Math.min(iv.length, 128));
            } else if (spec instanceof AlgorithmParameterSpec) {
                ctx.ivHex = "<" + spec.getClass().getSimpleName() + ">";
            }
            // v1.54: 同 算法+key+iv 5s 限频（视频分片每片 init 一次 → 34 行重复）
            String initSig = "init:" + ctx.algorithm + "|" + ctx.keyAlgo + ":" + ctx.keyHex + "|" + ctx.ivHex;
            if (cryptoRateLimited(initSig)) return;
            String initMsg = "[init] " + ctx.algorithm + " mode=" + ctx.cryptMode
                    + " key=" + (ctx.keyAlgo != null ? ctx.keyAlgo + ":" : "") + ctx.keyHex
                    + " iv=" + ctx.ivHex;
            // v1.55: 结构化 Crypto 事件（算法/key/iv/mode 详情页直接看，不再从文本里找）
            logCryptoEvent("INIT", ctx.algorithm, ctx.cryptMode,
                    (ctx.keyAlgo != null ? ctx.keyAlgo + ":" : "") + ctx.keyHex, ctx.ivHex, "", initMsg);
        } catch (Throwable t) {
            DebugLog.get().logNoMirror(TAG, "[init] parse fail: " + t);
        }
    }

    /** update 分块数据拼接进实例流（带上限） */
    private static void appendStream(Object cipher, byte[] data, int off, int len) {
        try {
            if (!(cipher instanceof Cipher)) return;
            Cipher c = (Cipher) cipher;
            Ctx ctx = CTXS.computeIfAbsent(c, k -> new Ctx());
            if (ctx.dataStream.size() < MAX_CAPTURE) {
                int room = MAX_CAPTURE - ctx.dataStream.size();
                int take = Math.min(len, room);
                ctx.dataStream.write(data, off, take);
                ctx.hadData = true;
            }
        } catch (Throwable t) { }
    }

    /** doFinal 汇总输出：算法/模式/密钥/IV/明文/密文/堆栈，然后移除实例上下文 */
    private static void finalizeCipher(Object cipher, Object extraInput, Object result) {
        try {
            if (!(cipher instanceof Cipher)) return;
            Cipher c = (Cipher) cipher;
            Ctx ctx = CTXS.remove(c);
            if (ctx == null) ctx = new Ctx();
            byte[] resultBytes = result instanceof byte[] ? (byte[]) result : null;
            StringBuilder sb = new StringBuilder("[doFinal] ").append(ctx.algorithm)
                    .append(" mode=").append(ctx.cryptMode)
                    .append(" key=").append(ctx.keyAlgo != null ? ctx.keyAlgo + ":" : "").append(ctx.keyHex)
                    .append(" iv=").append(ctx.ivHex);
            byte[] inBytes = ctx.hadData ? ctx.dataStream.toByteArray() : null;
            String inHex = "";
            if (inBytes != null) {
                inHex = MethodProbe.hex(inBytes, Math.min(inBytes.length, 128))
                        + (inBytes.length > 128 ? "...(" + inBytes.length + "B)" : "(" + inBytes.length + "B)");
                sb.append(" in=").append(inHex);
            }
            String outHex = resultBytes != null
                    ? MethodProbe.hex(resultBytes, Math.min(resultBytes.length, 128))
                    + (resultBytes.length > 128 ? "...(" + resultBytes.length + "B)" : "(" + resultBytes.length + "B)")
                    : "null";
            sb.append(" out=").append(outHex);
            String stack = MethodProbe.stack(10);
            // v1.55: 结构化 Crypto 事件（doFinal = 一次完整加解密，key/iv/入出数据全在详情页）
            logCryptoEvent("DOFINAL", ctx.algorithm, ctx.cryptMode,
                    (ctx.keyAlgo != null ? ctx.keyAlgo + ":" : "") + ctx.keyHex, ctx.ivHex,
                    inHex + " -> " + outHex, sb.toString() + " [stack]" + stack);
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[doFinal] parse fail: " + t);
        }
    }

    /** v1.55: 结构化 Crypto 事件——日志行嵌入 [EVT#id]，EventStore 写 SpyEvent（UI 卡片化） */
    private static void logCryptoEvent(String op, String algorithm, String mode, String key, String iv,
                                       String data, String fullMsg) {
        try {
            long eid = EventStore.get().nextId();
            String msg = "[EVT#" + eid + "]" + fullMsg;
            LogStore.get().log(TAG, msg);
            org.json.JSONObject payload = new org.json.JSONObject();
            payload.put("op", op == null ? "" : op);
            payload.put("algorithm", algorithm == null ? "" : algorithm);
            payload.put("mode", mode == null ? "" : mode);
            payload.put("key", key == null ? "" : key);
            payload.put("iv", iv == null ? "" : iv);
            payload.put("data", data == null ? "" : data);
            EventStore.get().add(new SpyEvent("CRYPTO", eid, System.currentTimeMillis(),
                    (op == null ? "" : op) + " " + (algorithm == null ? "" : algorithm),
                    payload, msg, ""));
        } catch (Throwable t) { /* 结构化失败不影响文本日志 */ }
    }
}
