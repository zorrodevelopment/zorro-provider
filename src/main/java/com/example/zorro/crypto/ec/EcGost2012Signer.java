package com.example.zorro.crypto.ec;

import com.example.zorro.util.ByteUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Реализация подписи и проверки по ГОСТ Р 34.10-2012 (EC-вариант, 512 бит).
 *
 * <p>Подпись — пара чисел {@code (r, s)}; в бинарной сериализации, совместимой
 * с {@code Signature.getInstance("ECGOST3410-2015-512", "KALKAN")}, это 128
 * байт: {@code r_LE(64) || s_LE(64)} — оба числа в little-endian, по 64 байта.
 * Это казахстанская конвенция (НУЦ РК); BouncyCastle использует другой формат
 * ({@code s_BE || r_BE}), который равен побайтному реверсу нашего — при
 * обмене подписями с BC нужно прогонять массив через {@code reverse()}.
 *
 * <h2>Алгоритм подписи</h2>
 * Дано: {@code H} — Streebog-512 хэш сообщения; {@code d} — приватный ключ;
 * {@code k} — случайное число из {@code [1, n-1]}.
 * <ol>
 *   <li>{@code e ≡ rev(H) mod n} — байты H интерпретируются как little-endian;
 *       если {@code e = 0}, заменяем на 1 (стандартная реализация BC этого
 *       не делает — мы её повторяем, чтобы быть совместимыми).</li>
 *   <li>{@code (x_C, y_C) = k·G}, {@code r = x_C mod n}.</li>
 *   <li>{@code s = (k·e + d·r) mod n}.</li>
 *   <li>Если {@code r = 0} или {@code s = 0} — повторяем с другим {@code k}.</li>
 * </ol>
 *
 * <h2>Алгоритм проверки</h2>
 * <ol>
 *   <li>Проверяем {@code 1 ≤ r ≤ n-1}, {@code 1 ≤ s ≤ n-1}.</li>
 *   <li>{@code v = e^{-1} mod n}, {@code z1 = s·v mod n}, {@code z2 = -r·v mod n}.</li>
 *   <li>{@code (x_C, y_C) = z1·G + z2·Q}.</li>
 *   <li>Если результат — точка в бесконечности, неверно. Иначе {@code R = x_C mod n}
 *       и подпись валидна iff {@code R = r}.</li>
 * </ol>
 */
public final class EcGost2012Signer {

    private EcGost2012Signer() {}

    /** Подписывает 64-байтный хэш приватным ключом {@code d}. */
    public static byte[] sign(byte[] hash, EcCurveParams curve, BigInteger d, SecureRandom random) {
        if (hash.length != 64) {
            throw new IllegalArgumentException("ожидается 64-байтный хэш");
        }
        BigInteger n = curve.n;
        // e = bigint(reverse(hash)) mod n
        BigInteger e = new BigInteger(1, ByteUtils.reverse(hash)).mod(n);
        if (e.signum() == 0) {
            e = BigInteger.ONE;
        }

        while (true) {
            BigInteger k;
            do {
                k = randomMod(n, random);
            } while (k.signum() == 0);

            EcPoint c = curve.G.multiply(k);
            BigInteger r = c.getX().mod(n);
            if (r.signum() == 0) continue;

            BigInteger s = k.multiply(e).add(d.multiply(r)).mod(n);
            if (s.signum() == 0) continue;

            return encode(r, s, curve.coordLength());
        }
    }

    /** Проверяет подпись 64-байтного хэша по публичной точке Q. */
    public static boolean verify(byte[] hash, EcCurveParams curve, EcPoint Q, byte[] signature) {
        if (hash.length != 64) {
            throw new IllegalArgumentException("ожидается 64-байтный хэш");
        }
        int coord = curve.coordLength();
        if (signature.length != coord * 2) {
            return false;
        }
        BigInteger n = curve.n;

        // Декодируем подпись (Kalkan-формат): первая половина — r_LE, вторая — s_LE.
        byte[] rLe = new byte[coord];
        byte[] sLe = new byte[coord];
        System.arraycopy(signature, 0,     rLe, 0, coord);
        System.arraycopy(signature, coord, sLe, 0, coord);
        BigInteger r = new BigInteger(1, ByteUtils.reverse(rLe));
        BigInteger s = new BigInteger(1, ByteUtils.reverse(sLe));

        if (r.signum() <= 0 || r.compareTo(n) >= 0) return false;
        if (s.signum() <= 0 || s.compareTo(n) >= 0) return false;

        BigInteger e = new BigInteger(1, ByteUtils.reverse(hash)).mod(n);
        if (e.signum() == 0) e = BigInteger.ONE;

        BigInteger v = e.modInverse(n);
        BigInteger z1 = s.multiply(v).mod(n);
        BigInteger z2 = n.subtract(r).multiply(v).mod(n);

        EcPoint c = EcPoint.sumOfTwoMultiplies(curve.G, z1, Q, z2);
        if (c.infinity) return false;
        BigInteger R = c.getX().mod(n);
        return R.equals(r);
    }

    /** Кодирует пару {@code (r, s)} в 128-байтный буфер: {@code r_LE || s_LE}. */
    private static byte[] encode(BigInteger r, BigInteger s, int coordLength) {
        byte[] out = new byte[coordLength * 2];
        byte[] rLe = ByteUtils.reverse(ByteUtils.toFixedLengthBE(r, coordLength));
        byte[] sLe = ByteUtils.reverse(ByteUtils.toFixedLengthBE(s, coordLength));
        System.arraycopy(rLe, 0, out, 0,           coordLength);
        System.arraycopy(sLe, 0, out, coordLength, coordLength);
        return out;
    }

    /** Случайное число в диапазоне {@code [0, n-1]} с плотным заполнением. */
    private static BigInteger randomMod(BigInteger n, SecureRandom random) {
        int bits = n.bitLength();
        BigInteger v;
        do {
            v = new BigInteger(bits, random);
        } while (v.compareTo(n) >= 0);
        return v;
    }
}
