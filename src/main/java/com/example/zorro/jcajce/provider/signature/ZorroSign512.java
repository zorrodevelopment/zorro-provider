package com.example.zorro.jcajce.provider.signature;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.crypto.Streebog512;
import com.example.zorro.crypto.ec.EcCurveLookup;
import com.example.zorro.crypto.ec.EcCurveParams;
import com.example.zorro.crypto.ec.EcGost2012Signer;
import com.example.zorro.crypto.ec.EcPoint;
import com.example.zorro.provider.AlgorithmModule;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * SPI для подписи {@code ZORRO-SIGN-512} — собственная реализация
 * {@code Streebog-512 + ECGOST3410-2012-512}, не зависящая от внешних
 * криптобиблиотек. Использует {@link Streebog512} и {@link EcGost2012Signer}.
 *
 * <h2>Формат подписи</h2>
 * 128 байт = {@code r_LE(64) || s_LE(64)} — совместимо с
 * {@code Signature.getInstance("ECGOST3410-2015-512", "KALKAN")}. Для обмена
 * с BouncyCastle ({@code ECGOST3410-2012-512}) нужно сделать побайтный реверс
 * всей подписи.
 *
 * <h2>Совместимость ключей</h2>
 * Принимает любой {@link ECPrivateKey} / {@link ECPublicKey} JDK, чьи
 * параметры соответствуют известной ГОСТ-кривой ({@code paramSetA / B / C}).
 * Это включает ключи BouncyCastle ({@code BCECGOST3410_2012PrivateKey}) и
 * наши собственные классы.
 */
public class ZorroSign512 extends SignatureSpi {

    private final Streebog512 digest = new Streebog512();
    private SecureRandom random;

    // Состояние для подписи / проверки. Только одно из двух заполнено.
    private EcCurveParams curve;
    private java.math.BigInteger d;        // приватный ключ для подписи
    private EcPoint Q;                     // публичная точка для проверки

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new InvalidKeyException("ожидается ECPublicKey, получено "
                    + (publicKey == null ? "null" : publicKey.getClass().getName()));
        }
        ECPublicKey ec = (ECPublicKey) publicKey;
        EcCurveParams c = EcCurveLookup.find(ec.getParams());
        if (c == null) {
            throw new InvalidKeyException(
                    "параметры кривой не соответствуют известной ГОСТ-кривой "
                    + "(paramSetA / paramSetB / paramSetC)");
        }
        EcPoint q = EcCurveLookup.toEcPoint(c, ec.getW());
        if (!q.isOnCurve()) {
            throw new InvalidKeyException("публичная точка не лежит на указанной кривой");
        }
        this.curve = c;
        this.Q = q;
        this.d = null;
        digest.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof ECPrivateKey)) {
            throw new InvalidKeyException("ожидается ECPrivateKey, получено "
                    + (privateKey == null ? "null" : privateKey.getClass().getName()));
        }
        ECPrivateKey ec = (ECPrivateKey) privateKey;
        EcCurveParams c = EcCurveLookup.find(ec.getParams());
        if (c == null) {
            throw new InvalidKeyException(
                    "параметры кривой не соответствуют известной ГОСТ-кривой");
        }
        java.math.BigInteger s = ec.getS();
        if (s == null || s.signum() <= 0 || s.compareTo(c.n) >= 0) {
            throw new InvalidKeyException("приватный ключ d вне диапазона [1, n-1]");
        }
        this.curve = c;
        this.d = s;
        this.Q = null;
        if (this.random == null) {
            this.random = new SecureRandom();
        }
        digest.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        this.random = random;
        engineInitSign(privateKey);
    }

    @Override
    protected void engineUpdate(byte b) {
        digest.update(b);
    }

    @Override
    protected void engineUpdate(byte[] data, int off, int len) {
        digest.update(data, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (d == null) throw new SignatureException("signer не инициализирован для подписи");
        byte[] hash = digest.digest();
        return EcGost2012Signer.sign(hash, curve, d, random);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (Q == null) throw new SignatureException("signer не инициализирован для проверки");
        byte[] hash = digest.digest();
        return EcGost2012Signer.verify(hash, curve, Q, sigBytes);
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
        throw new InvalidParameterException("ZORRO-SIGN-512 не имеет параметров");
    }

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

    /** Регистрация подписи в провайдере. */
    public static class Mappings implements AlgorithmModule {
        @Override
        public void register(Provider provider) {
            String spi = ZorroSign512.class.getName();
            provider.put("Signature.ZORRO-SIGN-512", spi);
            // Алиасы
            provider.put("Alg.Alias.Signature.ZORROSIGN512", "ZORRO-SIGN-512");
            provider.put("Alg.Alias.Signature.ZORRO-HASH-512withECGOST3410-2012-512",
                    "ZORRO-SIGN-512");
            // По OID
            provider.put("Alg.Alias.Signature." + ZorroObjectIdentifiers.ZORRO_SIGN_512,
                    "ZORRO-SIGN-512");
            provider.put("Alg.Alias.Signature.OID." + ZorroObjectIdentifiers.ZORRO_SIGN_512,
                    "ZORRO-SIGN-512");
            // Какие ключи мы умеем принимать
            provider.put("Signature.ZORRO-SIGN-512 SupportedKeyClasses",
                    "java.security.interfaces.ECPrivateKey"
                    + "|java.security.interfaces.ECPublicKey");
        }
    }
}
