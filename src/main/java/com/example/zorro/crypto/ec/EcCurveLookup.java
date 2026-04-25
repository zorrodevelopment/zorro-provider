package com.example.zorro.crypto.ec;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * Сопоставление {@link ECParameterSpec} (стандартный класс JDK) с нашими
 * {@link EcCurveParams}. Используется в SPI-классах подписи и {@code KeyFactory}
 * для извлечения известной кривой из любого {@link java.security.interfaces.ECKey},
 * включая ключи, выданные BouncyCastle или загруженные через PKCS#12.
 *
 * <p>Сравниваем по полю и коэффициентам (p, a, b) — это достаточные параметры
 * для уникальной идентификации кривой в нашей небольшой таблице.
 */
public final class EcCurveLookup {

    private EcCurveLookup() {}

    private static final EcCurveParams[] KNOWN = {
            GostCurves.paramSetA,
            GostCurves.paramSetB,
            GostCurves.paramSetC
    };

    /**
     * Возвращает наш {@link EcCurveParams}, соответствующий заданному
     * {@link ECParameterSpec}, либо {@code null} если не нашли.
     */
    public static EcCurveParams find(ECParameterSpec spec) {
        if (spec == null) return null;
        ECField field = spec.getCurve().getField();
        if (!(field instanceof ECFieldFp)) return null;
        BigInteger p = ((ECFieldFp) field).getP();
        BigInteger a = spec.getCurve().getA();
        BigInteger b = spec.getCurve().getB();

        for (EcCurveParams candidate : KNOWN) {
            if (candidate.p.equals(p)
                    && normalize(candidate.a, p).equals(normalize(a, p))
                    && normalize(candidate.b, p).equals(normalize(b, p))) {
                return candidate;
            }
        }
        return null;
    }

    /** Конвертирует {@link ECPoint} (JDK) в нашу точку на указанной кривой. */
    public static com.example.zorro.crypto.ec.EcPoint toEcPoint(EcCurveParams curve, ECPoint w) {
        if (w == null || w.equals(ECPoint.POINT_INFINITY)) {
            return com.example.zorro.crypto.ec.EcPoint.infinity(curve);
        }
        return com.example.zorro.crypto.ec.EcPoint.affine(curve, w.getAffineX(), w.getAffineY());
    }

    private static BigInteger normalize(BigInteger v, BigInteger p) {
        return v.mod(p);
    }
}
