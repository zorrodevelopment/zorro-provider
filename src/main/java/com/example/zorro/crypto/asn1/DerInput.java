package com.example.zorro.crypto.asn1;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Минималистичный DER-парсер. Курсор по байтовому массиву + утилиты для
 * извлечения универсальных ASN.1-типов: {@code SEQUENCE}, {@code SET},
 * {@code INTEGER}, {@code OBJECT IDENTIFIER}, {@code OCTET STRING},
 * {@code BIT STRING}, контекстных тегов и т.п.
 *
 * <p>Достаточно для парсинга PKCS#12, PKCS#8 и SubjectPublicKeyInfo —
 * именно того, что нам нужно для загрузки сертификатов и ключей. Никаких
 * BER-индефинитных длин, шифрования по другим стандартам и пр. — только
 * чистая DER-сериализация.
 *
 * <p>Класс не immutable: чтение продвигает курсор вперёд.
 */
public final class DerInput {

    public static final int TAG_BOOLEAN          = 0x01;
    public static final int TAG_INTEGER          = 0x02;
    public static final int TAG_BIT_STRING       = 0x03;
    public static final int TAG_OCTET_STRING     = 0x04;
    public static final int TAG_NULL             = 0x05;
    public static final int TAG_OID              = 0x06;
    public static final int TAG_UTF8_STRING      = 0x0C;
    public static final int TAG_SEQUENCE         = 0x30;
    public static final int TAG_SET              = 0x31;
    public static final int TAG_PRINTABLE_STRING = 0x13;
    public static final int TAG_BMP_STRING       = 0x1E;

    private final byte[] data;
    private final int end;
    private int pos;

    public DerInput(byte[] data) {
        this(data, 0, data.length);
    }

    public DerInput(byte[] data, int offset, int length) {
        this.data = data;
        this.pos = offset;
        this.end = offset + length;
    }

    public boolean hasMore() { return pos < end; }
    public int remaining()   { return end - pos; }

    /** Подглядывает следующий тег, не двигая курсор. */
    public int peekTag() {
        if (pos >= end) throw new IllegalStateException("EOF");
        return data[pos] & 0xFF;
    }

    /**
     * Считывает один TLV: тег и значение. Длина учтена внутри.
     *
     * <p>Поддерживается как DER (строгая длина), так и BER с indefinite-length
     * encoding (длина {@code 0x80} с end-of-contents маркером {@code 0x00 0x00}).
     * Это нужно потому что некоторые PKCS#12-файлы (например, выпускаемые
     * НУЦ РК) используют именно indefinite-length BER.
     */
    public DerValue readValue() {
        int tag = readByte() & 0xFF;
        int len = readLength();
        if (len == -1) {
            // Indefinite-length: ищем end-of-contents, проходя вложенные TLV.
            int start = pos;
            int valueEnd = scanIndefinite();
            DerValue v = new DerValue(tag, data, start, valueEnd - start);
            pos = valueEnd + 2; // пропускаем 00 00
            return v;
        }
        if (pos + len > end) {
            throw new IllegalStateException("длина выходит за пределы буфера: " + len);
        }
        DerValue v = new DerValue(tag, data, pos, len);
        pos += len;
        return v;
    }

    /**
     * При indefinite-length: проходит TLV-ы из текущей позиции, пока не найдёт
     * end-of-contents маркер {@code 0x00 0x00}, и возвращает позицию начала EoC.
     * Курсор остаётся на EoC; вызывающий должен сам пропустить два байта.
     */
    private int scanIndefinite() {
        while (pos < end) {
            int p = pos;
            int t = data[p] & 0xFF;
            int l = data[p + 1] & 0xFF;
            if (t == 0 && l == 0) {
                return p;
            }
            // Прочитаем (рекурсивно) этот TLV целиком, чтобы продвинуть pos.
            readValue();
        }
        throw new IllegalStateException("end-of-contents (0x00 0x00) не найден");
    }

    /** Считывает SEQUENCE или SET и возвращает его содержимое как новый курсор. */
    public DerInput readConstructed(int expectedTag) {
        DerValue v = readValue();
        if (v.tag != expectedTag) {
            throw new IllegalStateException(
                    String.format("ожидался тег 0x%02X, получен 0x%02X", expectedTag, v.tag));
        }
        return new DerInput(v.bytes, v.offset, v.length);
    }

    public DerInput readSequence() { return readConstructed(TAG_SEQUENCE); }
    public DerInput readSet()      { return readConstructed(TAG_SET); }

    /** Контекстный конструктивный тег [n]. */
    public DerInput readContextConstructed(int n) {
        return readConstructed(0xA0 | n);
    }

    /** Контекстный примитивный тег [n]. */
    public DerValue readContextPrimitive(int n) {
        DerValue v = readValue();
        if (v.tag != (0x80 | n)) {
            throw new IllegalStateException(
                    String.format("ожидался [%d], получен 0x%02X", n, v.tag));
        }
        return v;
    }

    /**
     * Читает {@code [n] IMPLICIT OCTET STRING}, поддерживая BER-форму с
     * constructed-обёрткой и сегментацией: {@code [n] CONSTRUCTED} с
     * вложенными {@code OCTET STRING}'ами склеивается в один массив.
     *
     * <p>Это нужно для PKCS#12 файлов с indefinite-length BER, где
     * длинные шифр-тексты часто кодируются именно так.
     */
    public byte[] readContextImplicitOctetString(int n) {
        DerValue v = readValue();
        int primitive   = 0x80 | n;
        int constructed = 0xA0 | n;
        if (v.tag == primitive) {
            return v.byteCopy();
        }
        if (v.tag == constructed) {
            // Внутри — последовательность OCTET STRING-ов, объединяем их.
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(v.length);
            DerInput inner = v.asInput();
            while (inner.hasMore()) {
                DerValue piece = inner.readValue();
                if (piece.tag != TAG_OCTET_STRING) {
                    throw new IllegalStateException(
                            "внутри [" + n + "] CONSTRUCTED ожидался OCTET STRING, получен " + piece.tagHex());
                }
                out.write(piece.bytes, piece.offset, piece.length);
            }
            return out.toByteArray();
        }
        throw new IllegalStateException(
                String.format("ожидался [%d] IMPLICIT OCTET STRING (примитив или constructed), получен 0x%02X", n, v.tag));
    }

    public BigInteger readInteger() {
        DerValue v = readValue();
        if (v.tag != TAG_INTEGER) {
            throw new IllegalStateException("ожидался INTEGER, получен " + v.tagHex());
        }
        return new BigInteger(v.byteCopy());
    }

    public BigInteger readPositiveInteger() {
        return new BigInteger(1, readInteger().toByteArray());
    }

    /**
     * Читает {@code OCTET STRING}. В BER он может быть и в constructed-форме
     * (тег {@code 0x24}) с вложенными сегментами — в этом случае склеиваем
     * содержимое всех вложенных OCTET STRING-ов.
     */
    public byte[] readOctetString() {
        DerValue v = readValue();
        if (v.tag == TAG_OCTET_STRING) {
            return v.byteCopy();
        }
        if (v.tag == 0x24) {  // constructed OCTET STRING (BER)
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(v.length);
            DerInput inner = v.asInput();
            while (inner.hasMore()) {
                byte[] piece = inner.readOctetString();
                out.write(piece, 0, piece.length);
            }
            return out.toByteArray();
        }
        throw new IllegalStateException("ожидался OCTET STRING, получен " + v.tagHex());
    }

    public String readObjectIdentifier() {
        DerValue v = readValue();
        if (v.tag != TAG_OID) {
            throw new IllegalStateException("ожидался OID, получен " + v.tagHex());
        }
        return decodeOid(v.bytes, v.offset, v.length);
    }

    /** BIT STRING без неиспользуемых бит (unused bits == 0) — обычный случай. */
    public byte[] readBitString() {
        DerValue v = readValue();
        if (v.tag != TAG_BIT_STRING) {
            throw new IllegalStateException("ожидался BIT STRING, получен " + v.tagHex());
        }
        if (v.length < 1) throw new IllegalStateException("пустой BIT STRING");
        int unused = v.bytes[v.offset] & 0xFF;
        if (unused != 0) {
            // Поддерживаем только bit-aligned строки — нам этого хватает.
            throw new IllegalStateException("BIT STRING с " + unused + " неиспользуемыми битами не поддерживается");
        }
        byte[] out = new byte[v.length - 1];
        System.arraycopy(v.bytes, v.offset + 1, out, 0, out.length);
        return out;
    }

    public void skip() {
        readValue();
    }

    /** Пропускает текущий TLV если он совпадает с {@code tag}. */
    public boolean skipIfTag(int tag) {
        if (!hasMore() || peekTag() != tag) return false;
        readValue();
        return true;
    }

    /** Читает все оставшиеся TLV в текущей конструкции — удобно для SEQUENCE OF / SET OF. */
    public List<DerValue> readAll() {
        List<DerValue> all = new ArrayList<>();
        while (hasMore()) all.add(readValue());
        return all;
    }

    // ---- low-level helpers ----

    private byte readByte() {
        if (pos >= end) throw new IllegalStateException("EOF");
        return data[pos++];
    }

    /** Возвращает фактическую длину или -1 для indefinite-length BER. */
    private int readLength() {
        int b = readByte() & 0xFF;
        if ((b & 0x80) == 0) return b;
        int n = b & 0x7F;
        if (n == 0) return -1;        // indefinite-length BER (0x80)
        if (n > 4)  throw new IllegalStateException("длина > 4 байт не поддерживается");
        int len = 0;
        for (int i = 0; i < n; i++) {
            len = (len << 8) | (readByte() & 0xFF);
        }
        if (len < 0) throw new IllegalStateException("отрицательная длина");
        return len;
    }

    /** Декодирует BER-кодированный OID в строку точечной записи. */
    static String decodeOid(byte[] data, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        int first = data[offset] & 0xFF;
        sb.append(first / 40).append('.').append(first % 40);
        long acc = 0;
        for (int i = 1; i < length; i++) {
            int b = data[offset + i] & 0xFF;
            acc = (acc << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                sb.append('.').append(acc);
                acc = 0;
            }
        }
        return sb.toString();
    }
}
