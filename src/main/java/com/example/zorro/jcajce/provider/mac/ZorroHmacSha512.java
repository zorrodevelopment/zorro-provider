package com.example.zorro.jcajce.provider.mac;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.crypto.HmacSha512;
import com.example.zorro.provider.AlgorithmModule;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;

/**
 * SPI для алгоритма {@code ZORRO-HMACSHA512}.
 *
 * <p>Полностью самостоятельный MAC: использует {@link HmacSha512} —
 * собственную реализацию HMAC поверх собственного {@code Sha512}.
 * Не требует Kalkan, не требует BouncyCastle.
 *
 * <p>Регистрируется как {@code Mac.ZORRO-HMACSHA512} и принимает
 * любой {@link SecretKey} с {@code algorithm = "ZORRO-HMACSHA512"}
 * или {@code "RAW"} либо {@code "HMAC"} (для совместимости с
 * {@link javax.crypto.spec.SecretKeySpec}).
 */
public class ZorroHmacSha512 extends MacSpi {

    private final HmacSha512 mac = new HmacSha512();

    @Override
    protected int engineGetMacLength() {
        return mac.getMacLength();
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "ZORRO-HMACSHA512 не принимает параметров");
        }
        if (key == null) {
            throw new InvalidKeyException("ключ не может быть null");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException(
                    "ключ не предоставляет encoded форму (формат "
                    + key.getFormat() + ")");
        }
        // Принимаем любой ключ, который может выдать байты — типично
        // SecretKeySpec или результат KeyGenerator
        try {
            mac.init(encoded);
        } finally {
            // обнулим временную копию из соображений гигиены
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        mac.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        mac.update(input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        return mac.doFinal();
    }

    @Override
    protected void engineReset() {
        mac.reset();
    }

    /** Регистрация в провайдере. */
    public static class Mappings implements AlgorithmModule {
        /** OID для HMAC-SHA-512: {root}.1.3.1 */
        private static final String OID = ZorroObjectIdentifiers.ROOT + ".1.3.1";

        @Override
        public void register(Provider provider) {
            String spi = ZorroHmacSha512.class.getName();
            provider.put("Mac.ZORRO-HMACSHA512", spi);
            // Алиасы для удобства
            provider.put("Alg.Alias.Mac.ZORROHMACSHA512", "ZORRO-HMACSHA512");
            provider.put("Alg.Alias.Mac.ZORRO-HMAC-SHA-512", "ZORRO-HMACSHA512");
            // По OID
            provider.put("Alg.Alias.Mac." + OID, "ZORRO-HMACSHA512");
            provider.put("Alg.Alias.Mac.OID." + OID, "ZORRO-HMACSHA512");
            // SupportedKeyClasses — какие ключи мы умеем принимать
            provider.put("Mac.ZORRO-HMACSHA512 SupportedKeyFormats", "RAW");
        }
    }
}
