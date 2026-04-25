package com.example.zorro.crypto.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Минималистичный DER-кодировщик. Хватит для построения PKCS#8
 * {@code PrivateKeyInfo} и {@code SubjectPublicKeyInfo} нашими классами
 * ключей. Не претендует на полноту BER/DER-кодирования — только то, что
 * требуется внутри провайдера.
 */
public final class DerOutput {

    private DerOutput() {}

    public static byte[] encodeSequence(byte[]... children) {
        return wrap(DerInput.TAG_SEQUENCE, concat(children));
    }

    public static byte[] encodeOid(String oid) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String[] parts = oid.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("некорректный OID: " + oid);
        }
        long first = Long.parseLong(parts[0]);
        long second = Long.parseLong(parts[1]);
        out.write((int) (first * 40 + second));
        for (int i = 2; i < parts.length; i++) {
            writeBase128(out, Long.parseLong(parts[i]));
        }
        return wrap(DerInput.TAG_OID, out.toByteArray());
    }

    public static byte[] encodeInteger(BigInteger value) {
        return wrap(DerInput.TAG_INTEGER, value.toByteArray());
    }

    public static byte[] encodeOctetString(byte[] value) {
        return wrap(DerInput.TAG_OCTET_STRING, value);
    }

    public static byte[] encodeBitString(byte[] value) {
        byte[] withZero = new byte[value.length + 1];
        // 0 unused bits prefix
        System.arraycopy(value, 0, withZero, 1, value.length);
        return wrap(DerInput.TAG_BIT_STRING, withZero);
    }

    public static byte[] encodeNull() {
        return new byte[]{0x05, 0x00};
    }

    public static byte[] wrap(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + 6);
        out.write(tag);
        writeLength(out, content.length);
        try { out.write(content); } catch (IOException e) { throw new AssertionError(e); }
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
            return;
        }
        // Сколько байт нужно
        int bytes = 1;
        int x = len >>> 8;
        while (x != 0) { bytes++; x >>>= 8; }
        out.write(0x80 | bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            out.write((len >>> (i * 8)) & 0xFF);
        }
    }

    private static void writeBase128(ByteArrayOutputStream out, long v) {
        if (v < 0) throw new IllegalArgumentException("отрицательный компонент OID");
        // высчитываем количество байт
        long mask = 0x7FL;
        int bits = 7;
        while ((v >>> bits) != 0) { bits += 7; }
        for (int b = bits - 7; b > 0; b -= 7) {
            out.write((int) ((v >>> b) & 0x7F) | 0x80);
        }
        out.write((int) (v & 0x7F));
    }

    private static byte[] concat(byte[][] arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] r = new byte[total];
        int off = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, r, off, a.length);
            off += a.length;
        }
        return r;
    }
}
