package com.example.zorro.jcajce.provider.keys;

import com.example.zorro.crypto.asn1.DerOutput;
import com.example.zorro.crypto.ec.EcCurveParams;
import com.example.zorro.util.ByteUtils;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

/**
 * Приватный ключ ECGOST3410-2012-512 для нашего провайдера. Реализует
 * стандартный JDK-{@link ECPrivateKey}, что даёт совместимость с любыми
 * SPI, ожидающими этот интерфейс — в первую очередь с нашим
 * {@code ZorroSign512}.
 *
 * <p>Формат {@code getEncoded()} — PKCS#8 {@code PrivateKeyInfo} в стиле
 * российской/казахстанской ECGOST-схемы: алгоритм
 * {@code id-tc26-gost3410-2012-512} (1.2.643.7.1.1.1.2), параметры —
 * SEQUENCE из OID кривой и OID хэш-функции, privateKey OCTET STRING
 * содержит 64-байтовое little-endian представление {@code d}.
 */
public final class ZorroGostPrivateKey implements ECPrivateKey {

    /** Российский OID алгоритма. */
    public static final String ALG_OID_RU = "1.2.643.7.1.1.1.2";
    /** Российский OID хэш-функции id-tc26-gost-3411-12-512. */
    public static final String HASH_OID_RU = "1.2.643.7.1.1.2.3";
    /** Казахстанский OID алгоритма (НУЦ РК). */
    public static final String ALG_OID_KZ = "1.2.398.3.10.1.1.2.2";
    /** Казахстанский OID хэш-функции (Streebog-512). */
    public static final String HASH_OID_KZ = "1.2.398.3.10.1.3.3";

    private static final long serialVersionUID = 1L;

    private final BigInteger d;
    private final EcCurveParams curve;
    private final String algOid;
    private final String paramSetOid;
    private final String hashOid;

    public ZorroGostPrivateKey(BigInteger d, EcCurveParams curve, String algOid,
                               String paramSetOid, String hashOid) {
        if (d == null || d.signum() <= 0 || d.compareTo(curve.n) >= 0) {
            throw new IllegalArgumentException("d вне диапазона [1, n-1]");
        }
        this.d = d;
        this.curve = curve;
        this.algOid = algOid;
        this.paramSetOid = paramSetOid;
        this.hashOid = hashOid;
    }

    /** Удобный конструктор: подставляет российские OID-ы алгоритма и хэша. */
    public ZorroGostPrivateKey(BigInteger d, EcCurveParams curve, String paramSetOid) {
        this(d, curve, ALG_OID_RU, paramSetOid, HASH_OID_RU);
    }

    public String getAlgOid()      { return algOid; }
    public String getParamSetOid() { return paramSetOid; }
    public String getHashOid()     { return hashOid; }

    public EcCurveParams getCurveParams() { return curve; }

    @Override public BigInteger getS() { return d; }
    @Override public ECParameterSpec getParams() { return ZorroGostKeySpec.toJdkSpec(curve); }
    @Override public String getAlgorithm() { return "ECGOST3410-2012-512"; }
    @Override public String getFormat() { return "PKCS#8"; }

    @Override
    public byte[] getEncoded() {
        // d записывается little-endian в 64 байта.
        byte[] dLe = ByteUtils.reverse(ByteUtils.toFixedLengthBE(d, 64));

        // Двойная обёртка: внешний privateKey OCTET STRING содержит ВЛОЖЕННУЮ
        // OCTET STRING с LE-байтами d. Это требует Kalkan
        // ({@link kz.gov.pki.kalkan.asn1.pkcs.PrivateKeyInfo} парсит content как
        // ASN1 и ожидает там DEROctetString или DERInteger). BouncyCastle
        // тоже принимает такую форму, поэтому она универсальна.
        byte[] innerOctet = DerOutput.encodeOctetString(dLe);
        byte[] privateKeyOctet = DerOutput.encodeOctetString(innerOctet);

        byte[] paramSet = DerOutput.encodeSequence(
                DerOutput.encodeOid(paramSetOid),
                DerOutput.encodeOid(hashOid));
        byte[] algId = DerOutput.encodeSequence(
                DerOutput.encodeOid(algOid),
                paramSet);
        byte[] version = DerOutput.encodeInteger(BigInteger.ZERO);

        return DerOutput.encodeSequence(version, algId, privateKeyOctet);
    }
}
