package com.example.zorro.jcajce.provider.keys;

import com.example.zorro.crypto.asn1.DerOutput;
import com.example.zorro.crypto.ec.EcCurveParams;
import com.example.zorro.crypto.ec.EcPoint;
import com.example.zorro.util.ByteUtils;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

/**
 * Публичный ключ ECGOST3410-2012-512.
 *
 * <p>Формат {@code getEncoded()} — стандартный {@code SubjectPublicKeyInfo}:
 * AlgorithmIdentifier, как у приватного ключа, и BIT STRING с
 * {@code OCTET STRING(x_LE || y_LE)} (по 64 байта на координату).
 */
public final class ZorroGostPublicKey implements ECPublicKey {

    private static final long serialVersionUID = 1L;

    private final EcPoint Q;
    private final EcCurveParams curve;
    private final String algOid;
    private final String paramSetOid;
    private final String hashOid;

    public ZorroGostPublicKey(EcPoint Q, EcCurveParams curve, String algOid,
                              String paramSetOid, String hashOid) {
        if (Q.infinity) {
            throw new IllegalArgumentException("Q не может быть точкой в бесконечности");
        }
        if (!Q.isOnCurve()) {
            throw new IllegalArgumentException("Q не лежит на указанной кривой");
        }
        this.Q = Q;
        this.curve = curve;
        this.algOid = algOid;
        this.paramSetOid = paramSetOid;
        this.hashOid = hashOid;
    }

    /** Удобный конструктор с российскими OID-ами по умолчанию. */
    public ZorroGostPublicKey(EcPoint Q, EcCurveParams curve, String paramSetOid) {
        this(Q, curve, ZorroGostPrivateKey.ALG_OID_RU, paramSetOid, ZorroGostPrivateKey.HASH_OID_RU);
    }

    public EcCurveParams getCurveParams() { return curve; }
    public EcPoint getQ() { return Q; }
    public String getAlgOid()      { return algOid; }
    public String getParamSetOid() { return paramSetOid; }
    public String getHashOid()     { return hashOid; }

    @Override public java.security.spec.ECPoint getW() { return ZorroGostKeySpec.toJdkPoint(Q); }
    @Override public ECParameterSpec getParams() { return ZorroGostKeySpec.toJdkSpec(curve); }
    @Override public String getAlgorithm() { return "ECGOST3410-2012-512"; }
    @Override public String getFormat() { return "X.509"; }

    @Override
    public byte[] getEncoded() {
        byte[] xLe = ByteUtils.reverse(ByteUtils.toFixedLengthBE(Q.getX(), 64));
        byte[] yLe = ByteUtils.reverse(ByteUtils.toFixedLengthBE(Q.getY(), 64));
        byte[] xy = new byte[128];
        System.arraycopy(xLe, 0, xy, 0, 64);
        System.arraycopy(yLe, 0, xy, 64, 64);
        byte[] xyOctet = DerOutput.encodeOctetString(xy);

        byte[] paramSet = DerOutput.encodeSequence(
                DerOutput.encodeOid(paramSetOid),
                DerOutput.encodeOid(hashOid));
        byte[] algId = DerOutput.encodeSequence(
                DerOutput.encodeOid(algOid),
                paramSet);

        byte[] subjectPublicKey = DerOutput.encodeBitString(xyOctet);
        return DerOutput.encodeSequence(algId, subjectPublicKey);
    }
}
