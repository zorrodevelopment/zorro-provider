package com.example.zorro.asn1;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Идентификаторы объектов из казахстанского PKI (Kalkan), которые
 * необходимо распознавать при загрузке тестового {@code test.p12}.
 *
 * <p>Казахские OID-ы — это просто другая ветвь иерархии ASN.1:
 * по содержанию криптографических параметров они полностью совпадают
 * со стандартом ГОСТ Р 34.10-2012 / 34.11-2012 (RFC 7836). Поэтому
 * мы умеем переводить их в BouncyCastle-known OID-ы (см.
 * {@link com.example.zorro.jcajce.provider.asymmetric.ZorroKalkanGostKeyFactory}).
 *
 * <pre>
 *   1.2.398.3.10.1.1.2.2     — gostr3410-2015-512 (алгоритм ключа)
 *   1.2.398.3.10.1.1.2.2.1   — paramSet (соответствует Tc26 paramSetA)
 *   1.2.398.3.10.1.3.3       — gostr3411-2012-512 (digest)
 * </pre>
 */
public final class KalkanObjectIdentifiers {

    /** OID алгоритма ключа: ECGOST3410-2015-512 в казахской ветке. */
    public static final ASN1ObjectIdentifier KALKAN_GOST3410_2015_512 =
            new ASN1ObjectIdentifier("1.2.398.3.10.1.1.2.2");

    /** OID параметров кривой (Kalkan). По значению совпадает с Tc26 paramSetA. */
    public static final ASN1ObjectIdentifier KALKAN_PARAMSET =
            new ASN1ObjectIdentifier("1.2.398.3.10.1.1.2.2.1");

    /** OID digest-функции (Kalkan): Streebog-512. */
    public static final ASN1ObjectIdentifier KALKAN_DIGEST_512 =
            new ASN1ObjectIdentifier("1.2.398.3.10.1.3.3");

    // ----- Соответствующие BC (Tc26 / RFC 7836) идентификаторы -----

    public static final ASN1ObjectIdentifier BC_GOST3410_2012_512 =
            new ASN1ObjectIdentifier("1.2.643.7.1.1.1.2");

    public static final ASN1ObjectIdentifier BC_PARAMSET_A =
            new ASN1ObjectIdentifier("1.2.643.7.1.2.1.2.1");

    public static final ASN1ObjectIdentifier BC_GOST3411_2012_512 =
            new ASN1ObjectIdentifier("1.2.643.7.1.1.2.3");

    private KalkanObjectIdentifiers() {}
}
