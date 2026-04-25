package com.example.zorro.jcajce.provider.signature;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.provider.AlgorithmModule;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Подпись ZORRO-SIGN-512.
 *
 * <p>Композитный алгоритм: Streebog-512 + ECGOST3410-2015-512.
 * Внутри делегируется в KALKAN. Поверх KALKAN-подписи добавлен
 * собственный OID {@link ZorroObjectIdentifiers#ZORRO_SIGN_512},
 * чтобы провайдер ZORRO мог распространяться независимо.
 *
 * <h2>Формат подписи</h2>
 * Бинарная подпись имеет ровно тот же формат, что и
 * {@code Signature.getInstance("ECGOST3410-2015-512", "KALKAN")}:
 * 128 байт = конкатенация {@code (s, r)} в little-endian
 * (так задано ГОСТ Р 34.10-2012, §6.1).
 *
 * <h2>Совместимость ключей</h2>
 * Принимает любые ключи, которые понимает backend: чаще всего
 * это {@code EcGost3410_2015PublicKey/PrivateKey} от Kalkan.
 */
public class ZorroSign512 extends SignatureSpi {

    private static final String BACKEND_ALG = "ECGOST3410-2015-512";
    private static final String BACKEND_PROVIDER = "KALKAN";

    private final Signature backend;

    public ZorroSign512() {
        try {
            this.backend = Signature.getInstance(BACKEND_ALG, BACKEND_PROVIDER);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException(
                    "ZORRO-SIGN-512 требует backend " + BACKEND_ALG
                    + " от провайдера " + BACKEND_PROVIDER, e);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        backend.initVerify(publicKey);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        backend.initSign(privateKey);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        backend.initSign(privateKey, random);
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        backend.update(b);
    }

    @Override
    protected void engineUpdate(byte[] data, int off, int len) throws SignatureException {
        backend.update(data, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        return backend.sign();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return backend.verify(sigBytes);
    }

    /** @deprecated параметры устарели — оставлено для совместимости с SPI-контрактом */
    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
        throw new InvalidParameterException("ZORRO-SIGN-512 не имеет параметров");
    }

    /** @deprecated параметры устарели */
    @Override
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("ZORRO-SIGN-512 не имеет параметров");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "ZORRO-SIGN-512 не принимает параметров");
        }
    }

    /**
     * Регистрация подписи в провайдере.
     */
    public static class Mappings implements AlgorithmModule {
        @Override
        public void register(Provider provider) {
            if (java.security.Security.getProvider(BACKEND_PROVIDER) == null) {
                throw new IllegalStateException(
                        "Backend provider " + BACKEND_PROVIDER + " не зарегистрирован, "
                        + "модуль ZorroSign512 пропущен");
            }
            String spi = ZorroSign512.class.getName();
            provider.put("Signature.ZORRO-SIGN-512", spi);
            // Алиасы
            provider.put("Alg.Alias.Signature.ZORROSIGN512", "ZORRO-SIGN-512");
            provider.put("Alg.Alias.Signature.ZORRO-HASH-512withECGOST3410-2015-512",
                    "ZORRO-SIGN-512");
            // По OID
            provider.put("Alg.Alias.Signature." + ZorroObjectIdentifiers.ZORRO_SIGN_512,
                    "ZORRO-SIGN-512");
            provider.put("Alg.Alias.Signature.OID." + ZorroObjectIdentifiers.ZORRO_SIGN_512,
                    "ZORRO-SIGN-512");
            // Подсказка JCA: SupportedKeyClasses — какие ключи мы умеем принимать
            provider.put("Signature.ZORRO-SIGN-512 SupportedKeyClasses",
                    "java.security.interfaces.ECPrivateKey"
                    + "|java.security.interfaces.ECPublicKey");
        }
    }
}
