package com.example.zorro.crypto.ec;

import java.math.BigInteger;

/**
 * Параметры кривой над F_p вида {@code y² ≡ x³ + a·x + b (mod p)}.
 *
 * <p>Содержит группу {@code G} и порядок подгруппы {@code n} (для кривых
 * с кофактором 1 — равен порядку кривой). Cofactor для текущих ГОСТ-кривых
 * предполагается равным 1, что соответствует {@code paramSetA/B}.
 */
public final class EcCurveParams {

    public final BigInteger p;
    public final BigInteger a;
    public final BigInteger b;
    public final BigInteger n;     // порядок базовой точки
    public final EcPoint G;        // образующая

    public EcCurveParams(BigInteger p, BigInteger a, BigInteger b,
                         BigInteger n, BigInteger gx, BigInteger gy) {
        this.p = p;
        this.a = a;
        this.b = b;
        this.n = n;
        this.G = EcPoint.affine(this, gx, gy);
    }

    /** Длина координаты в байтах (округлённая вверх). */
    public int coordLength() {
        return (p.bitLength() + 7) / 8;
    }
}
