package com.example.zorro.crypto.ec;

import java.math.BigInteger;

/**
 * Точка эллиптической кривой над F_p в аффинных координатах.
 *
 * <p>Используется простая аффинная арифметика на {@link BigInteger} —
 * это медленнее проективных координат, но даёт максимально читабельный
 * код. Для подписи 512-битного ГОСТа этого хватает с большим запасом
 * по производительности.
 *
 * <p>«Бесконечно удалённая» точка (нейтральный элемент группы) представлена
 * специальным флагом {@code infinity}; её координаты не определены и не
 * должны читаться напрямую.
 *
 * <p>Класс immutable.
 */
public final class EcPoint {

    private static final BigInteger TWO   = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    public final EcCurveParams curve;
    public final boolean infinity;
    private final BigInteger x;
    private final BigInteger y;

    private EcPoint(EcCurveParams curve, BigInteger x, BigInteger y, boolean infinity) {
        this.curve = curve;
        this.x = x;
        this.y = y;
        this.infinity = infinity;
    }

    public static EcPoint affine(EcCurveParams curve, BigInteger x, BigInteger y) {
        return new EcPoint(curve, x.mod(curve.p), y.mod(curve.p), false);
    }

    public static EcPoint infinity(EcCurveParams curve) {
        return new EcPoint(curve, null, null, true);
    }

    public BigInteger getX() {
        if (infinity) throw new IllegalStateException("точка в бесконечности");
        return x;
    }

    public BigInteger getY() {
        if (infinity) throw new IllegalStateException("точка в бесконечности");
        return y;
    }

    /** Принадлежит ли точка кривой? Для проверки публичных ключей. */
    public boolean isOnCurve() {
        if (infinity) return true;
        BigInteger lhs = y.multiply(y).mod(curve.p);
        BigInteger rhs = x.multiply(x).mod(curve.p)
                .add(curve.a).mod(curve.p)
                .multiply(x).mod(curve.p)
                .add(curve.b).mod(curve.p);
        return lhs.equals(rhs);
    }

    public EcPoint negate() {
        if (infinity) return this;
        return new EcPoint(curve, x, curve.p.subtract(y).mod(curve.p), false);
    }

    public EcPoint twice() {
        if (infinity) return this;
        if (y.signum() == 0) return infinity(curve);

        BigInteger p = curve.p;
        // λ = (3x² + a) / (2y)  mod p
        BigInteger lambda = THREE.multiply(x).mod(p).multiply(x).mod(p)
                .add(curve.a).mod(p)
                .multiply(TWO.multiply(y).modInverse(p)).mod(p);

        BigInteger x3 = lambda.multiply(lambda).mod(p)
                .subtract(x).subtract(x).mod(p);
        BigInteger y3 = lambda.multiply(x.subtract(x3)).mod(p)
                .subtract(y).mod(p);
        return new EcPoint(curve, x3, y3, false);
    }

    public EcPoint add(EcPoint other) {
        if (this.curve != other.curve && !this.curve.p.equals(other.curve.p)) {
            throw new IllegalArgumentException("точки на разных кривых");
        }
        if (this.infinity) return other;
        if (other.infinity) return this;

        BigInteger p = curve.p;
        if (x.equals(other.x)) {
            if (y.equals(other.y)) return twice();
            return infinity(curve); // P + (-P) = O
        }
        // λ = (y2 - y1) / (x2 - x1)  mod p
        BigInteger lambda = other.y.subtract(y).mod(p)
                .multiply(other.x.subtract(x).modInverse(p)).mod(p);
        BigInteger x3 = lambda.multiply(lambda).mod(p)
                .subtract(x).subtract(other.x).mod(p);
        BigInteger y3 = lambda.multiply(x.subtract(x3)).mod(p)
                .subtract(y).mod(p);
        return new EcPoint(curve, x3, y3, false);
    }

    /**
     * Скалярное умножение: {@code k·P}. Использует left-to-right
     * double-and-add. Не constant-time — в учебном провайдере мы
     * не претендуем на защиту от side-channel атак.
     */
    public EcPoint multiply(BigInteger k) {
        if (k.signum() < 0) return negate().multiply(k.negate());
        if (k.signum() == 0 || infinity) return infinity(curve);

        EcPoint result = infinity(curve);
        EcPoint addend = this;
        // Простой LSB-first double-and-add.
        for (int i = 0, n = k.bitLength(); i < n; i++) {
            if (k.testBit(i)) {
                result = result.add(addend);
            }
            addend = addend.twice();
        }
        return result;
    }

    /** Линейная комбинация {@code k1·P1 + k2·P2}. Простое сложение двух multiply. */
    public static EcPoint sumOfTwoMultiplies(EcPoint p1, BigInteger k1,
                                             EcPoint p2, BigInteger k2) {
        return p1.multiply(k1).add(p2.multiply(k2));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EcPoint)) return false;
        EcPoint other = (EcPoint) o;
        if (infinity || other.infinity) return infinity == other.infinity;
        return x.equals(other.x) && y.equals(other.y);
    }

    @Override
    public int hashCode() {
        if (infinity) return 0;
        return x.hashCode() ^ y.hashCode();
    }

    @Override
    public String toString() {
        return infinity ? "EcPoint(∞)" : "EcPoint(0x" + x.toString(16) + ", 0x" + y.toString(16) + ")";
    }
}
