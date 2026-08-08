package com.dustinky.spyprobe;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.ConcurrentHashMap;

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

    private static final ConcurrentHashMap<Cipher, Ctx> CTXS = new ConcurrentHashMap<>();
    private static final int MAX_CAPTURE = 1024 * 1024; // 1MB 上限防刷屏

    public void install(String phase) {
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
                            LogStore.get().log(TAG, "[getInstance] " + ctx.algorithm);
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
                            LogStore.get().log(TAG, "[getInstance] " + ctx.algorithm + " provider=" + chain.getArg(1));
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

            LogStore.get().log(TAG, "[" + phase + "] hooked Cipher (getInstance/init/update/doFinal, v1.14 实例跟踪)");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Cipher hook fail: " + t);
        }
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
            LogStore.get().log(TAG, "[init] " + ctx.algorithm + " mode=" + ctx.cryptMode
                    + " key=" + (ctx.keyAlgo != null ? ctx.keyAlgo + ":" : "") + ctx.keyHex
                    + " iv=" + ctx.ivHex);
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[init] parse fail: " + t);
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
            if (inBytes != null) {
                sb.append(" in=").append(MethodProbe.hex(inBytes, Math.min(inBytes.length, 128)))
                        .append(inBytes.length > 128 ? "...(" + inBytes.length + "B)" : "(" + inBytes.length + "B)");
            }
            sb.append(" out=").append(resultBytes != null
                    ? MethodProbe.hex(resultBytes, Math.min(resultBytes.length, 128))
                    + (resultBytes.length > 128 ? "...(" + resultBytes.length + "B)" : "(" + resultBytes.length + "B)")
                    : "null");
            LogStore.get().log(TAG, sb.toString());
            LogStore.get().log(TAG, "[stack]\n" + MethodProbe.stack(10));
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[doFinal] parse fail: " + t);
        }
    }
}
