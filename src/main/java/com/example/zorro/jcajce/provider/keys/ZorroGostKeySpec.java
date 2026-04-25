package com.example.zorro.jcajce.provider.keys;

import com.example.zorro.crypto.ec.EcCurveParams;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * Утилиты построения JDK-{@link ECParameterSpec} из нашего
 * {@link EcCurveParams}. Нужны нашим классам ключей, чтобы они выглядели
 * как обычные {@code ECPrivateKey}/{@code ECPublicKey} для любого кода,
 * умеющего работать со стандартным JDK-API.
 */
public final class ZorroGostKeySpec {

    private ZorroGostKeySpec() {}

    public static ECParameterSpec toJdkSpec(EcCurveParams curve) {
        ECField field = new ECFieldFp(curve.p);
        EllipticCurve ec = new EllipticCurve(field, curve.a, curve.b);
        ECPoint G = new ECPoint(curve.G.getX(), curve.G.getY());
        return new ECParameterSpec(ec, G, curve.n, 1);
    }

    public static ECPoint toJdkPoint(com.example.zorro.crypto.ec.EcPoint p) {
        if (p.infinity) return ECPoint.POINT_INFINITY;
        return new ECPoint(p.getX(), p.getY());
    }

    /** Хелпер для {@code BigInteger} → знаковый INTEGER bytes (BC-style). */
    public static byte[] integerSignedBytes(BigInteger v) {
        return v.toByteArray();
    }
}
