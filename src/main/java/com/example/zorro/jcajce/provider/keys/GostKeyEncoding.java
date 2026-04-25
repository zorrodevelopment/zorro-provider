package com.example.zorro.jcajce.provider.keys;

import com.example.zorro.crypto.asn1.DerInput;
import com.example.zorro.crypto.asn1.DerValue;
import com.example.zorro.crypto.ec.EcCurveParams;
import com.example.zorro.crypto.ec.EcPoint;
import com.example.zorro.crypto.ec.GostCurves;
import com.example.zorro.util.ByteUtils;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * Парсинг ECGOST3410-2012-512 ключей из PKCS#8 {@code PrivateKeyInfo} и
 * {@code SubjectPublicKeyInfo}. Поддерживаются как российские
 * (id-tc26-gost3410-2012-512), так и казахстанские OID-ы из НУЦ РК.
 *
 * <h2>Формат внутри privateKey OCTET STRING</h2>
 * Стандартное кодирование (RFC 9215, BC-совместимое) — 64 байта в
 * little-endian. Некоторые реализации заворачивают это в ещё один
 * OCTET STRING — это тоже распознаётся.
 *
 * <h2>Формат subjectPublicKey BIT STRING</h2>
 * BIT STRING содержит DER-OCTET STRING, который содержит конкатенацию
 * {@code x_LE(64) || y_LE(64)} — 128 байт.
 */
public final class GostKeyEncoding {

    private GostKeyEncoding() {}

    /** OID-ы алгоритмов, опознаваемых нами как ECGOST3410-2012-512. */
    private static final Map<String, Boolean> SIGN_ALG_512_OIDS = new HashMap<>();
    static {
        SIGN_ALG_512_OIDS.put("1.2.643.7.1.1.1.2",   true); // Россия
        SIGN_ALG_512_OIDS.put("1.2.398.3.10.1.1.2.2", true); // Казахстан
    }

    /** OID-ы кривых, поддерживаемых нами. */
    private static final Map<String, EcCurveParams> CURVES = new HashMap<>();
    static {
        // Россия
        CURVES.put("1.2.643.7.1.2.1.2.1", GostCurves.paramSetA);
        CURVES.put("1.2.643.7.1.2.1.2.2", GostCurves.paramSetB);
        CURVES.put("1.2.643.7.1.2.1.2.3", GostCurves.paramSetC);
        // Казахстан (предполагается тождественность математики; подтверждается тестами)
        CURVES.put("1.2.398.3.10.1.1.2.2.1", GostCurves.paramSetA);
        CURVES.put("1.2.398.3.10.1.1.2.2.2", GostCurves.paramSetB);
        CURVES.put("1.2.398.3.10.1.1.2.2.3", GostCurves.paramSetC);
    }

    /** Декодирует {@code PrivateKeyInfo} (PKCS#8) в {@link ZorroGostPrivateKey}. */
    public static ZorroGostPrivateKey parsePrivateKeyInfo(byte[] pkcs8) {
        DerInput pki = new DerInput(pkcs8).readSequence();
        BigInteger version = pki.readInteger();
        if (!version.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("неожиданная PKCS#8 version: " + version);
        }
        AlgInfo alg = parseAlgorithm(pki.readSequence());
        EcCurveParams curve = requireCurve(alg.paramSetOid);
        byte[] keyOctets = pki.readOctetString();

        // Внутри privateKey OCTET STRING может быть ещё одна обёртка OCTET STRING.
        byte[] dLeBytes;
        if (keyOctets.length == 64) {
            dLeBytes = keyOctets;
        } else if (keyOctets.length == 66 && keyOctets[0] == DerInput.TAG_OCTET_STRING) {
            // {0x04, 0x40, ... 64 bytes ...}
            DerValue inner = new DerInput(keyOctets).readValue();
            dLeBytes = inner.byteCopy();
            if (dLeBytes.length != 64) {
                throw new IllegalArgumentException(
                        "ожидалось 64 байта во внутренней OCTET STRING, получено " + dLeBytes.length);
            }
        } else {
            throw new IllegalArgumentException(
                    "неожиданный размер privateKey OCTET STRING: " + keyOctets.length);
        }

        BigInteger d = new BigInteger(1, ByteUtils.reverse(dLeBytes));
        return new ZorroGostPrivateKey(d, curve, alg.algOid, alg.paramSetOid, alg.hashOid);
    }

    /** Декодирует {@code SubjectPublicKeyInfo} в {@link ZorroGostPublicKey}. */
    public static ZorroGostPublicKey parseSubjectPublicKeyInfo(byte[] spki) {
        DerInput info = new DerInput(spki).readSequence();
        AlgInfo alg = parseAlgorithm(info.readSequence());
        EcCurveParams curve = requireCurve(alg.paramSetOid);
        byte[] subjectPublicKey = info.readBitString();

        // BIT STRING → OCTET STRING { 64 байта x_LE || 64 байта y_LE }
        DerValue v = new DerInput(subjectPublicKey).readValue();
        if (v.tag != DerInput.TAG_OCTET_STRING || v.length != 128) {
            throw new IllegalArgumentException(
                    "ожидался OCTET STRING(128), получен tag=" + v.tagHex() + " len=" + v.length);
        }
        byte[] xy = v.byteCopy();
        byte[] xLe = new byte[64];
        byte[] yLe = new byte[64];
        System.arraycopy(xy, 0,  xLe, 0, 64);
        System.arraycopy(xy, 64, yLe, 0, 64);
        BigInteger x = new BigInteger(1, ByteUtils.reverse(xLe));
        BigInteger y = new BigInteger(1, ByteUtils.reverse(yLe));
        EcPoint Q = EcPoint.affine(curve, x, y);
        return new ZorroGostPublicKey(Q, curve, alg.algOid, alg.paramSetOid, alg.hashOid);
    }

    private static EcCurveParams requireCurve(String oid) {
        EcCurveParams c = CURVES.get(oid);
        if (c == null) throw new IllegalArgumentException("неизвестный OID кривой: " + oid);
        return c;
    }

    private static AlgInfo parseAlgorithm(DerInput algSeq) {
        String algOid = algSeq.readObjectIdentifier();
        if (!SIGN_ALG_512_OIDS.containsKey(algOid)) {
            throw new IllegalArgumentException("неизвестный OID алгоритма ключа: " + algOid);
        }
        DerInput params = algSeq.readSequence();
        String paramSetOid = params.readObjectIdentifier();
        // hashOid опционально — но если есть, сохраняем
        String hashOid = params.hasMore() ? params.readObjectIdentifier() : null;
        return new AlgInfo(algOid, paramSetOid, hashOid);
    }

    private static final class AlgInfo {
        final String algOid;
        final String paramSetOid;
        final String hashOid;
        AlgInfo(String a, String p, String h) { this.algOid = a; this.paramSetOid = p; this.hashOid = h; }
    }
}
