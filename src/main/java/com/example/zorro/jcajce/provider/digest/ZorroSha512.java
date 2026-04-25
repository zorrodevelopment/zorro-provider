package com.example.zorro.jcajce.provider.digest;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.crypto.Sha512;
import com.example.zorro.provider.AlgorithmModule;

import java.security.MessageDigestSpi;
import java.security.Provider;

/**
 * SPI для алгоритма {@code ZORRO-SHA-512} — это <b>собственная</b>
 * реализация SHA-512, не зависящая от внешних библиотек.
 *
 * <p>Это пример полностью самостоятельного алгоритма в нашем провайдере:
 * он есть и работает даже если Kalkan на classpath отсутствует.
 *
 * <p>В отличие от {@link ZorroHash512}, который оборачивает Streebog
 * из Kalkan, здесь и SPI, и сам алгоритм находятся в нашем коде.
 */
public class ZorroSha512 extends MessageDigestSpi {

    private final Sha512 digest = new Sha512();

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
        return digest.digest();
    }

    @Override
    protected void engineReset() {
        digest.reset();
    }

    @Override
    protected int engineGetDigestLength() {
        return Sha512.DIGEST_LENGTH;
    }

    /** Регистрация в провайдере. */
    public static class Mappings implements AlgorithmModule {
        /** OID для ZORRO-SHA-512: {root}.1.2 (SHA-512 как хэш) */
        private static final String OID = ZorroObjectIdentifiers.ROOT + ".1.1.2";

        @Override
        public void register(Provider provider) {
            String spi = ZorroSha512.class.getName();
            provider.put("MessageDigest.ZORRO-SHA-512", spi);
            provider.put("Alg.Alias.MessageDigest.ZORROSHA512", "ZORRO-SHA-512");
            provider.put("Alg.Alias.MessageDigest." + OID, "ZORRO-SHA-512");
            provider.put("Alg.Alias.MessageDigest.OID." + OID, "ZORRO-SHA-512");
        }
    }
}
