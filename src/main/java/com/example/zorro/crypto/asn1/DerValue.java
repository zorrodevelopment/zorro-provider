package com.example.zorro.crypto.asn1;

import java.util.Arrays;

/**
 * Один прочитанный TLV-элемент: тег и срез байт значения. {@link DerInput}
 * возвращает такие объекты при разборе. Сами байты не копируются, но
 * {@link #byteCopy()} даёт изолированный массив, если он нужен наружу.
 */
public final class DerValue {

    public final int tag;
    public final byte[] bytes;
    public final int offset;
    public final int length;

    public DerValue(int tag, byte[] bytes, int offset, int length) {
        this.tag = tag;
        this.bytes = bytes;
        this.offset = offset;
        this.length = length;
    }

    public byte[] byteCopy() {
        return Arrays.copyOfRange(bytes, offset, offset + length);
    }

    public DerInput asInput() {
        return new DerInput(bytes, offset, length);
    }

    public String tagHex() {
        return String.format("0x%02X", tag);
    }
}
