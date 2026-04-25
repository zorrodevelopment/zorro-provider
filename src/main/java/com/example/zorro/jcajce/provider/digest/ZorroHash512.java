package com.example.zorro.jcajce.provider.digest;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.provider.AlgorithmModule;

import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

/**
 * Хэш-функция ZORRO-HASH-512 — обёртка над Streebog-512 из провайдера KALKAN.
 *
 * <p>Этот класс реализует {@link MessageDigestSpi} напрямую (не наследуется
 * от внутренних классов Kalkan/BC), а внутри держит {@link MessageDigest}
 * провайдера KALKAN и делегирует ему. Так провайдер ZORRO остаётся
 * независимым от deeply-internal API KALKAN.
 *
 * <p><b>Внимание:</b> экземпляр KALKAN-MessageDigest создаётся лениво в
 * методах SPI и кешируется. JVM создаёт по одному экземпляру SPI на каждый
 * вызов {@code MessageDigest.getInstance("ZORRO-HASH-512", "ZORRO")}, так
 * что глобального состояния не будет.
 */
public class ZorroHash512 extends MessageDigestSpi {

    /** Имя backend-алгоритма в провайдере KALKAN. */
    private static final String BACKEND_ALG = "GOST3411-2015-512";
    /** Имя backend-провайдера. */
    private static final String BACKEND_PROVIDER = "KALKAN";

    private MessageDigest backend;

    public ZorroHash512() {
        // Не создаём backend в конструкторе — JCE-стандарт требует, чтобы
        // конструктор SPI не бросал checked-исключений.
        this.backend = null;
    }

    private MessageDigest backend() {
        if (backend == null) {
            try {
                backend = MessageDigest.getInstance(BACKEND_ALG, BACKEND_PROVIDER);
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new IllegalStateException(
                        "ZORRO-HASH-512 требует backend " + BACKEND_ALG
                        + " от провайдера " + BACKEND_PROVIDER
                        + ". Зарегистрируйте Kalkan через "
                        + "Security.addProvider(new KalkanProvider()).", e);
            }
        }
        return backend;
    }

    @Override
    protected void engineUpdate(byte input) {
        backend().update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        backend().update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        return backend().digest();
    }

    @Override
    protected void engineReset() {
        backend().reset();
    }

    @Override
    protected int engineGetDigestLength() {
        return 64; // Streebog-512 = 512 бит = 64 байта
    }

    /**
     * Регистрация в провайдере. Кладёт несколько mapping'ов, чтобы
     * к нашему хэшу можно было обратиться по разным именам и по OID.
     */
    public static class Mappings implements AlgorithmModule {
        @Override
        public void register(Provider provider) {
            // Проверяем, что backend (KALKAN) доступен. Если нет — модуль не
            // регистрируется, но провайдер продолжает работать.
            if (java.security.Security.getProvider(BACKEND_PROVIDER) == null) {
                throw new IllegalStateException(
                        "Backend provider " + BACKEND_PROVIDER + " не зарегистрирован, "
                        + "модуль ZorroHash512 пропущен");
            }
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
