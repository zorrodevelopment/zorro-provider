package com.example.zorro.jcajce.provider.digest;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.provider.AlgorithmModule;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;

import java.security.MessageDigestSpi;
import java.security.Provider;

/**
 * Хэш-функция ZORRO-HASH-512 — Streebog-512 (ГОСТ Р 34.11-2012, 512 бит).
 *
 * <p>SPI напрямую использует low-level примитив BouncyCastle
 * {@link GOST3411_2012_512Digest} как библиотеку — никаких
 * {@code MessageDigest.getInstance(..., "BC")} тут нет, провайдер ZORRO
 * сам является исполнителем алгоритма.
 *
 * <p>Класс не потокобезопасен; JCE создаёт по одному экземпляру SPI на
 * каждый вызов {@code MessageDigest.getInstance("ZORRO-HASH-512", "ZORRO")}.
 */
public class ZorroHash512 extends MessageDigestSpi {

    private final GOST3411_2012_512Digest digest = new GOST3411_2012_512Digest();

    @Override
    protected void engineUpdate(byte input) {
        digest.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        digest.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    @Override
    protected void engineReset() {
        digest.reset();
    }

    @Override
    protected int engineGetDigestLength() {
        return digest.getDigestSize();
    }

    /** Регистрация алгоритма и его OID-алиасов. */
    public static class Mappings implements AlgorithmModule {
        @Override
        public void register(Provider provider) {
            String spi = ZorroHash512.class.getName();
            provider.put("MessageDigest.ZORRO-HASH-512", spi);
            provider.put("Alg.Alias.MessageDigest.ZORROHASH512", "ZORRO-HASH-512");
            provider.put("Alg.Alias.MessageDigest.ZORRO512", "ZORRO-HASH-512");
            provider.put("Alg.Alias.MessageDigest." + ZorroObjectIdentifiers.ZORRO_HASH_512,
                    "ZORRO-HASH-512");
            provider.put("Alg.Alias.MessageDigest.OID." + ZorroObjectIdentifiers.ZORRO_HASH_512,
                    "ZORRO-HASH-512");
        }
    }
}
