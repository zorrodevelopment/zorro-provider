package com.example.zorro.jcajce.provider.digest;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.crypto.Streebog512;
import com.example.zorro.provider.AlgorithmModule;

import java.security.MessageDigestSpi;
import java.security.Provider;

/**
 * SPI для алгоритма {@code ZORRO-HASH-512} — собственная реализация
 * Streebog-512 (ГОСТ Р 34.11-2012, длина хэша 512 бит).
 *
 * <p>Не зависит от внешних криптографических библиотек: используется
 * {@link Streebog512} из пакета {@code com.example.zorro.crypto}. Корректность
 * подтверждается тестами {@code Streebog512Test} (KAT и кросс-проверка
 * против эталонной реализации BouncyCastle).
 *
 * <p>JVM создаёт по одному экземпляру SPI на каждый вызов
 * {@code MessageDigest.getInstance("ZORRO-HASH-512", "ZORRO")}, поэтому
 * глобального состояния класса нет.
 */
public class ZorroHash512 extends MessageDigestSpi {

    private final Streebog512 digest = new Streebog512();

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
        return Streebog512.DIGEST_LENGTH;
    }

    /**
     * Регистрация в провайдере. Кладёт несколько mapping'ов, чтобы
     * к нашему хэшу можно было обратиться по разным именам и по OID.
     */
    public static class Mappings implements AlgorithmModule {
        @Override
        public void register(Provider provider) {
            String spi = ZorroHash512.class.getName();
            provider.put("MessageDigest.ZORRO-HASH-512", spi);
            // Алиасы для удобства
            provider.put("Alg.Alias.MessageDigest.ZORROHASH512", "ZORRO-HASH-512");
            provider.put("Alg.Alias.MessageDigest.ZORRO512", "ZORRO-HASH-512");
            // По OID (как требует X.509/CMS)
            provider.put("Alg.Alias.MessageDigest." + ZorroObjectIdentifiers.ZORRO_HASH_512,
                    "ZORRO-HASH-512");
            provider.put("Alg.Alias.MessageDigest.OID." + ZorroObjectIdentifiers.ZORRO_HASH_512,
                    "ZORRO-HASH-512");
        }
    }
}
