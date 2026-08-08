package com.dustinky.spyprobe;

import java.lang.reflect.Method;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import io.github.libxposed.api.XposedModule;

/**
 * 加密算法记录（v1.5 新增）：
 * hook javax.crypto.Cipher 的 getInstance/init/doFinal，记录：
 *   - 算法（transformation，如 AES/CBC/PKCS5Padding）
 *   - 密钥（algorithm + hex 前 64B）
 *   - IV（hex 前 64B）
 *   - 明文/密文（doFinal 输入输出前 64B）
 * 用途：反编译时知道 app 用啥加密、密钥放哪（字符串/静态字段/运行时算出）。
 * 注意：默认关（cryptoCapture=false）防刷屏；数据加密在 native/pure-Dart 层时这里看不到。
 */
public class CryptoProbe {

    static final String TAG = "SpyProbe.Crypto";

    private final XposedModule module;

    public CryptoProbe(XposedModule module) {
        this.module = module;
    }

    public void install(String phase) {
        try {
            // getInstance(String) / getInstance(String, String) —— 记算法
            try {
                Method gi = Cipher.class.getMethod("getInstance", String.class);
                module.hook(gi).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture && r instanceof Cipher) {
                        try {
                            LogStore.get().log(TAG, "[getInstance] " + chain.getArg(0));
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }

            // init(int opmode, Key key) / init(int, Key, AlgorithmParameterSpec) —— 记算法+密钥+IV
            try {
                Method init = Cipher.class.getMethod("init", int.class, Key.class);
                module.hook(init).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) logInit(chain.getThisObject(), chain.getArg(0), chain.getArg(1), null);
                    return r;
                });
            } catch (Throwable t) { }
            try {
                Method init2 = Cipher.class.getMethod("init", int.class, Key.class, AlgorithmParameterSpec.class);
                module.hook(init2).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) logInit(chain.getThisObject(), chain.getArg(0), chain.getArg(1), chain.getArg(2));
                    return r;
                });
            } catch (Throwable t) { }
            try {
                Method init3 = Cipher.class.getMethod("init", int.class, Key.class, java.security.SecureRandom.class);
                module.hook(init3).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) logInit(chain.getThisObject(), chain.getArg(0), chain.getArg(1), null);
                    return r;
                });
            } catch (Throwable t) { }
            try {
                Method init4 = Cipher.class.getMethod("init", int.class, Key.class, AlgorithmParameterSpec.class, java.security.SecureRandom.class);
                module.hook(init4).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) logInit(chain.getThisObject(), chain.getArg(0), chain.getArg(1), chain.getArg(2));
                    return r;
                });
            } catch (Throwable t) { }

            // doFinal(byte[]) —— 记输入/输出前 64B
            try {
                Method df = Cipher.class.getMethod("doFinal", byte[].class);
                module.hook(df).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            byte[] out = r instanceof byte[] ? (byte[]) r : null;
                            LogStore.get().log(TAG, "[doFinal] in=" + MethodProbe.str(in, 96)
                                    + " out=" + MethodProbe.str(out, 96));
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }

            // v1.6: doFinal(byte[], int, int) —— 分块加密常用重载
            try {
                Method df = Cipher.class.getMethod("doFinal", byte[].class, int.class, int.class);
                module.hook(df).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            Object off = chain.getArg(1);
                            Object len = chain.getArg(2);
                            byte[] out = r instanceof byte[] ? (byte[]) r : null;
                            LogStore.get().log(TAG, "[doFinal] in=" + MethodProbe.str(in, 96)
                                    + " off=" + off + " len=" + len + " out=" + MethodProbe.str(out, 96));
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }

            // v1.6: update(byte[]) —— 流式加密（Cipher 流式模式数据块经 update 走）
            try {
                Method up = Cipher.class.getMethod("update", byte[].class);
                module.hook(up).intercept(chain -> {
                    Object r = chain.proceed();
                    if (Config.get().cryptoCapture) {
                        try {
                            Object in = chain.getArg(0);
                            byte[] out = r instanceof byte[] ? (byte[]) r : null;
                            LogStore.get().log(TAG, "[update] in=" + MethodProbe.str(in, 96)
                                    + " out=" + MethodProbe.str(out, 96));
                        } catch (Throwable t) { }
                    }
                    return r;
                });
            } catch (Throwable t) { }

            LogStore.get().log(TAG, "[" + phase + "] hooked Cipher (getInstance/init/doFinal/update)");
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[" + phase + "] Cipher hook fail: " + t);
        }
    }

    private static void logInit(Object cipher, Object opmode, Object key, Object spec) {
        try {
            String algo = "";
            try {
                if (cipher instanceof Cipher) algo = ((Cipher) cipher).getAlgorithm();
            } catch (Throwable t) { }
            String mode = "?";
            if (opmode instanceof Integer) {
                int m = (Integer) opmode;
                mode = m == Cipher.ENCRYPT_MODE ? "ENCRYPT" : m == Cipher.DECRYPT_MODE ? "DECRYPT" : String.valueOf(m);
            }
            StringBuilder sb = new StringBuilder();
            sb.append("[init] ").append(algo).append(" mode=").append(mode);
            if (key instanceof Key) {
                Key k = (Key) key;
                sb.append(" key=").append(k.getAlgorithm()).append(":").append(hexOf(k.getEncoded()));
            } else if (key != null) {
                sb.append(" key=").append(key.getClass().getName());
            }
            if (spec instanceof IvParameterSpec) {
                sb.append(" iv=").append(hexOf(((IvParameterSpec) spec).getIV()));
            } else if (spec != null) {
                sb.append(" params=").append(spec.getClass().getSimpleName());
            }
            LogStore.get().log(TAG, sb.toString());
        } catch (Throwable t) {
            LogStore.get().log(TAG, "[init] parse fail: " + t);
        }
    }

    private static String hexOf(byte[] b) {
        if (b == null) return "null";
        return MethodProbe.hex(b, Math.min(b.length, 64)) + (b.length > 64 ? "...(" + b.length + "B)" : "");
    }
}
