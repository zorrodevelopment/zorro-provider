package com.example.zorro.jcajce.provider.keystore;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * PKCS#12 KDF (RFC 7292 §B.2) + расшифровка стандартных PKCS#12 PBE-схем.
 *
 * <p>Поддерживаются три алгоритма, реально встречающиеся в test.p12:
 * <ul>
 *   <li>{@code pbeWithSHAAnd3-KeyTripleDES-CBC} (1.2.840.113549.1.12.1.3)</li>
 *   <li>{@code pbeWithSHAAnd40BitRC2-CBC} (1.2.840.113549.1.12.1.6)</li>
 *   <li>{@code HMAC-SHA1} для проверки MAC-а PFX</li>
 * </ul>
 *
 * <p>Сами шифры берутся из SunJCE — это блочные алгоритмы общего назначения,
 * входят в JDK без дополнительных провайдеров. Криптография PBE
 * (вычисление ключа и IV из пароля) реализована тут.
 */
final class Pkcs12Pbe {

    private Pkcs12Pbe() {}

    /** ID для KDF: 1 — ключ, 2 — IV, 3 — MAC-ключ (RFC 7292 §B.3). */
    static final byte ID_KEY = 1;
    static final byte ID_IV  = 2;
    static final byte ID_MAC = 3;

    /**
     * Производит {@code n} байт секретного материала из пароля и соли по
     * RFC 7292 §B.2 с использованием SHA-1. Это базовый кирпичик всех
     * PKCS#12 PBE-механизмов.
     */
    static byte[] kdf(char[] password, byte[] salt, byte id, int iterations, int n)
            throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        final int u = 20;     // SHA-1 digest size
        final int v = 64;     // SHA-1 block size

        byte[] D = new byte[v];
        for (int i = 0; i < v; i++) D[i] = id;

        byte[] passBmp = passwordToBmp(password);
        byte[] S = expand(salt, v);
        byte[] P = expand(passBmp, v);

        byte[] I = new byte[S.length + P.length];
        System.arraycopy(S, 0, I, 0, S.length);
        System.arraycopy(P, 0, I, S.length, P.length);

        int produced = 0;
        byte[] out = new byte[n];

        while (produced < n) {
            // A_i = H^c(D || I)
            md.reset();
            md.update(D);
            md.update(I);
            byte[] A = md.digest();
            for (int j = 1; j < iterations; j++) {
                md.reset();
                A = md.digest(A);
            }

            int copy = Math.min(u, n - produced);
            System.arraycopy(A, 0, out, produced, copy);
            produced += copy;

            if (produced >= n) break;

            // B = first v bytes of A repeated; then I_j := (I_j + B + 1) mod 2^(8v)
            byte[] B = expand(A, v);
            BigInteger Bplus1 = new BigInteger(1, B).add(BigInteger.ONE);
            int blocks = I.length / v;
            for (int j = 0; j < blocks; j++) {
                byte[] block = new byte[v];
                System.arraycopy(I, j * v, block, 0, v);
                byte[] sum = new BigInteger(1, block).add(Bplus1).toByteArray();
                // Берём последние v байт суммы (модуль 2^(8v))
                if (sum.length >= v) {
                    System.arraycopy(sum, sum.length - v, I, j * v, v);
                } else {
                    java.util.Arrays.fill(I, j * v, j * v + (v - sum.length), (byte) 0);
                    System.arraycopy(sum, 0, I, j * v + (v - sum.length), sum.length);
                }
            }
        }
        return out;
    }

    /** Преобразует пароль в BMP-кодированную форму с замыкающими 0x00 0x00 (UTF-16BE). */
    static byte[] passwordToBmp(char[] password) {
        if (password == null) password = new char[0];
        byte[] out = new byte[password.length * 2 + 2];
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            out[i * 2]     = (byte) (c >>> 8);
            out[i * 2 + 1] = (byte) c;
        }
        return out;
    }

    /** Циклически дополняет {@code data} до длины кратной {@code blockSize}. */
    private static byte[] expand(byte[] data, int blockSize) {
        if (data.length == 0) return new byte[0];
        int n = ((data.length + blockSize - 1) / blockSize) * blockSize;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = data[i % data.length];
        }
        return out;
    }

    // ---- расшифровка ----

    /** Расшифровывает PBE-поток по OID PBE-алгоритма. */
    static byte[] decrypt(String pbeOid, char[] password, byte[] salt,
                          int iterations, byte[] ciphertext) throws GeneralSecurityException {
        switch (pbeOid) {
            case "1.2.840.113549.1.12.1.3":  // pbeWithSHAAnd3-KeyTripleDES-CBC
                return decryptDESede(password, salt, iterations, ciphertext);
            case "1.2.840.113549.1.12.1.6":  // pbeWithSHAAnd40BitRC2-CBC
                return decryptRc2_40(password, salt, iterations, ciphertext);
            default:
                throw new GeneralSecurityException("неподдерживаемый PBE OID: " + pbeOid);
        }
    }

    private static byte[] decryptDESede(char[] password, byte[] salt,
                                        int iterations, byte[] ciphertext)
            throws GeneralSecurityException {
        byte[] keyBytes = kdf(password, salt, ID_KEY, iterations, 24);
        byte[] iv       = kdf(password, salt, ID_IV,  iterations, 8);
        SecretKey k = new SecretKeySpec(keyBytes, "DESede");
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DESede/CBC/PKCS5Padding");
        c.init(javax.crypto.Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
        return c.doFinal(ciphertext);
    }

    private static byte[] decryptRc2_40(char[] password, byte[] salt,
                                        int iterations, byte[] ciphertext)
            throws GeneralSecurityException {
        byte[] keyBytes = kdf(password, salt, ID_KEY, iterations, 5);
        byte[] iv       = kdf(password, salt, ID_IV,  iterations, 8);
        SecretKey k = new SecretKeySpec(keyBytes, "RC2");
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("RC2/CBC/PKCS5Padding");
        c.init(javax.crypto.Cipher.DECRYPT_MODE, k,
                new RC2ParameterSpec(40, iv));
        return c.doFinal(ciphertext);
    }

    // ---- MAC ----

    /** Проверка PKCS#12 MAC = HMAC-SHA1(KDF(password, salt, ID_MAC, iter, 20), data). */
    static boolean verifyMac(char[] password, byte[] salt, int iterations,
                             byte[] data, byte[] expected) throws GeneralSecurityException {
        byte[] macKey = kdf(password, salt, ID_MAC, iterations, 20);
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(macKey, "HmacSHA1"));
        byte[] actual = mac.doFinal(data);
        return java.security.MessageDigest.isEqual(actual, expected);
    }
}
