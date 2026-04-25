package com.example.zorro.util;

import java.math.BigInteger;

/**
 * Утилиты для работы с байтами.
 *
 * <p>Особое внимание — конвертация между big-endian (как работает
 * {@link BigInteger}) и little-endian (как ГОСТ-стандарты хранят числа
 * в ASN.1).
 */
public final class ByteUtils {

    private ByteUtils() {}

    /**
     * Преобразует {@link BigInteger} в фиксированной длины big-endian массив.
     * <ul>
     *   <li>Отбрасывает знаковый ведущий ноль, если есть.</li>
     *   <li>Дополняет нулями слева до требуемой длины, если число меньше.</li>
     *   <li>Бросает исключение, если число не помещается.</li>
     * </ul>
     */
    public static byte[] toFixedLengthBE(BigInteger value, int length) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("Отрицательные числа не поддерживаются");
        }
        byte[] raw = value.toByteArray();
        if (raw.length == length) return raw;
        if (raw.length == length + 1 && raw[0] == 0) {
            byte[] out = new byte[length];
            System.arraycopy(raw, 1, out, 0, length);
            return out;
        }
        if (raw.length < length) {
            byte[] out = new byte[length];
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
            return out;
        }
        throw new IllegalArgumentException(
                "BigInteger разрядности " + value.bitLength()
                + " не помещается в " + length + " байт");
    }

    /** Возвращает копию массива в обратном порядке (BE↔LE). */
    public static byte[] reverse(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = data[data.length - 1 - i];
        }
        return out;
    }

    /** Конвертирует массив байт в hex-строку (нижний регистр). */
    public static String toHex(byte[] data) {
        if (data == null) return "null";
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** Конвертирует hex-строку в массив байт. */
    public static byte[] fromHex(String hex) {
        int len = hex.length();
        if ((len & 1) != 0) throw new IllegalArgumentException("Нечётная длина hex");
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Нехекс символ");
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** Безопасное сравнение байт (constant-time). */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return a == b;
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
