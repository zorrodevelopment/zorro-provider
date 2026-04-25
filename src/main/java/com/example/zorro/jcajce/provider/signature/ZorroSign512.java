package com.example.zorro.jcajce.provider.signature;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.provider.AlgorithmModule;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECGOST3410_2012Signer;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Подпись ZORRO-SIGN-512 — Streebog-512 + ECGOST Р 34.10-2012-512.
 *
 * <p>SPI собирает алгоритм из low-level примитивов BouncyCastle:
 * {@link GOST3411_2012_512Digest} как хэш и {@link ECGOST3410_2012Signer}
 * как сама ECGOST-подпись. Никакого {@code Signature.getInstance(..., "BC")}:
 * провайдер ZORRO сам выполняет всю работу.
 *
 * <h2>Формат подписи</h2>
 * 128 байт по ГОСТ Р 34.10-2012, §6.1: {@code [s_BE_64 || r_BE_64]} —
 * сначала фиксированное (64 байта) big-endian представление {@code s},
 * затем фиксированное big-endian представление {@code r}. Совпадает с
 * форматом, который выдают BC и Kalkan.
 *
 * <h2>Совместимость ключей</h2>
 * Принимает любые {@link PrivateKey}/{@link PublicKey}, чьё PKCS#8/SPKI
 * представление {@code key.getEncoded()} распознаётся
 * {@link PrivateKeyFactory}/{@link PublicKeyFactory} как
 * ECGOST3410-2012 (типично — {@code BCECGOST3410_2012PrivateKey}
 * либо ключ, загруженный из PKCS#12).
 */
public class ZorroSign512 extends SignatureSpi {

    /** Длина координаты поля в байтах (для curve 512). */
    private static final int FIELD_BYTES = 64;
    /** Полный размер сериализованной подписи. */
    private static final int SIGNATURE_BYTES = FIELD_BYTES * 2;

    private final GOST3411_2012_512Digest digest = new GOST3411_2012_512Digest();
    private final ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        try {
            byte[] encoded = publicKey.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException(
                        "публичный ключ не предоставляет SPKI (формат "
                        + publicKey.getFormat() + ")");
            }
            ECPublicKeyParameters params = (ECPublicKeyParameters)
                    PublicKeyFactory.createKey(encoded);
            signer.init(false, params);
            digest.reset();
        } catch (IOException | ClassCastException e) {
            throw new InvalidKeyException(
                    "не удалось извлечь ECGOST3410-2012-512 публичный ключ", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        try {
            byte[] encoded = privateKey.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException(
                        "приватный ключ не предоставляет PKCS#8 (формат "
                        + privateKey.getFormat() + ")");
            }
            ECPrivateKeyParameters params = (ECPrivateKeyParameters)
                    PrivateKeyFactory.createKey(encoded);
            if (random != null) {
                signer.init(true, new ParametersWithRandom(params, random));
            } else {
                signer.init(true, params);
            }
            digest.reset();
        } catch (IOException | ClassCastException e) {
            throw new InvalidKeyException(
                    "не удалось извлечь ECGOST3410-2012-512 приватный ключ", e);
        }
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
        byte[] hash = finishDigest();
        BigInteger[] rs = signer.generateSignature(hash);
        return encodeSignature(rs[0], rs[1]);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (sigBytes == null || sigBytes.length != SIGNATURE_BYTES) {
            return false;
        }
        byte[] hash = finishDigest();
        BigInteger[] rs = decodeSignature(sigBytes);
        return signer.verifySignature(hash, rs[0], rs[1]);
    }

    private byte[] finishDigest() {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    /**
     * Сериализует {@code (r, s)} в 128-байтный буфер в порядке ГОСТ:
     * первые 64 байта — {@code s} (BE, дополненные слева нулями),
     * следующие 64 байта — {@code r}.
     */
    private static byte[] encodeSignature(BigInteger r, BigInteger s) {
        byte[] out = new byte[SIGNATURE_BYTES];
        copyAsUnsignedBE(s, out, 0,           FIELD_BYTES);
        copyAsUnsignedBE(r, out, FIELD_BYTES, FIELD_BYTES);
        return out;
    }

    private static BigInteger[] decodeSignature(byte[] sig) {
        byte[] sBytes = new byte[FIELD_BYTES];
        byte[] rBytes = new byte[FIELD_BYTES];
        System.arraycopy(sig, 0,           sBytes, 0, FIELD_BYTES);
        System.arraycopy(sig, FIELD_BYTES, rBytes, 0, FIELD_BYTES);
        return new BigInteger[] {
                new BigInteger(1, rBytes),
                new BigInteger(1, sBytes),
        };
    }

    private static void copyAsUnsignedBE(BigInteger v, byte[] dst, int dstOff, int len) {
        byte[] raw = v.toByteArray();
        if (raw.length == len) {
            System.arraycopy(raw, 0, dst, dstOff, len);
        } else if (raw.length < len) {
            System.arraycopy(raw, 0, dst, dstOff + len - raw.length, raw.length);
        } else if (raw.length == len + 1 && raw[0] == 0) {
            System.arraycopy(raw, 1, dst, dstOff, len);
        } else {
            throw new IllegalStateException(
                    "координата подписи длиннее " + len + " байт: bitLen=" + v.bitLength());
        }
    }

    /** @deprecated параметры устарели — оставлено для совместимости с SPI-контрактом. */
    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("ZORRO-SIGN-512 не имеет параметров");
    }

    /** @deprecated параметры устарели. */
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

    /** Регистрация подписи и её OID-алиасов. */
    public static class Mappings implements AlgorithmModule {
        @Override
        public void register(Provider provider) {
            String spi = ZorroSign512.class.getName();
            provider.put("Signature.ZORRO-SIGN-512", spi);
            provider.put("Alg.Alias.Signature.ZORROSIGN512", "ZORRO-SIGN-512");
            provider.put("Alg.Alias.Signature.ZORRO-HASH-512withECGOST3410-2012-512",
                    "ZORRO-SIGN-512");
            provider.put("Alg.Alias.Signature." + ZorroObjectIdentifiers.ZORRO_SIGN_512,
                    "ZORRO-SIGN-512");
            provider.put("Alg.Alias.Signature.OID." + ZorroObjectIdentifiers.ZORRO_SIGN_512,
                    "ZORRO-SIGN-512");
            provider.put("Signature.ZORRO-SIGN-512 SupportedKeyClasses",
                    "java.security.interfaces.ECPrivateKey"
                    + "|java.security.interfaces.ECPublicKey");
        }
    }
}
