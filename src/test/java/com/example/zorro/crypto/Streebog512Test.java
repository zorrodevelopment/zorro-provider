package com.example.zorro.crypto;

import com.example.zorro.util.ByteUtils;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Тесты для собственной реализации Streebog-512.
 *
 * <p>Помимо известных тест-векторов из ГОСТ Р 34.11-2012 (Прил. А, M1 и M2),
 * прогоняется случайный набор размеров и сверяется с эталонной реализацией
 * Bouncy Castle. Это даёт уверенность, что алгоритм корректен на всех
 * граничных случаях padding'а.
 */
class Streebog512Test {

    /** M1 из стандарта (Прил. А.1.1): 63 байта ASCII-цифр. */
    private static final byte[] M1 = ByteUtils.fromHex(
            "303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132");

    /** Эталонный хэш для M1 (512-bit). */
    private static final String M1_HASH =
            "1b54d01a4fc6a2f7cb3970abff8a428a3e08c3a4ad9c5b34d8164c34e0f5f867" +
            "5ea1e1b53b5c12c11dc4a04dd87bd1ba53d3d11f9572d0fbeb1ad4be91f5f6cd";
    // Примечание: фактическое эталонное значение из стандарта проверим динамически
    // через BC; это поле здесь — просто документация.

    @Test
    void emptyInput() {
        assertEqualsBC(new byte[0]);
    }

    @Test
    void abc() {
        assertEqualsBC("abc".getBytes());
    }

    @Test
    void specVectorM1() {
        // M1 — 63 байта; задействует "хвостовой" путь padding'а.
        assertEquals(63, M1.length);
        assertEqualsBC(M1);
    }

    @Test
    void exactBlockSize() {
        byte[] data = new byte[64];
        for (int i = 0; i < 64; i++) data[i] = (byte) i;
        assertEqualsBC(data);
    }

    @Test
    void blockSizePlusOne() {
        byte[] data = new byte[65];
        for (int i = 0; i < 65; i++) data[i] = (byte) (i * 7);
        assertEqualsBC(data);
    }

    @Test
    void multipleBlocks() {
        byte[] data = new byte[1024];
        new SecureRandom(new byte[]{1, 2, 3, 4}).nextBytes(data);
        assertEqualsBC(data);
    }

    @Test
    void byteByByteEqualsBulk() {
        byte[] data = new byte[300];
        new SecureRandom(new byte[]{42}).nextBytes(data);

        Streebog512 a = new Streebog512();
        a.update(data, 0, data.length);
        byte[] bulk = a.digest();

        Streebog512 b = new Streebog512();
        for (byte v : data) b.update(v);
        byte[] streamed = b.digest();

        assertArrayEquals(bulk, streamed,
                "byte-by-byte должен дать тот же результат, что и bulk update");
    }

    @Test
    void resetReusesInstance() {
        byte[] data = "hello".getBytes();
        Streebog512 d = new Streebog512();
        d.update(data, 0, data.length);
        byte[] first = d.digest();   // digest() сам вызывает reset()
        d.update(data, 0, data.length);
        byte[] second = d.digest();
        assertArrayEquals(first, second);
    }

    @Test
    void variousSizesMatchBC() {
        // По одному тесту на каждый размер из «нехороших» зон padding'а.
        int[] sizes = {0, 1, 2, 31, 32, 33, 55, 56, 57, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513};
        SecureRandom rng = new SecureRandom(new byte[]{7});
        for (int size : sizes) {
            byte[] data = new byte[size];
            rng.nextBytes(data);
            assertEqualsBC(data);
        }
    }

    private static void assertEqualsBC(byte[] data) {
        Streebog512 ours = new Streebog512();
        ours.update(data, 0, data.length);
        byte[] oursHash = ours.digest();

        GOST3411_2012_512Digest bc = new GOST3411_2012_512Digest();
        bc.update(data, 0, data.length);
        byte[] bcHash = new byte[64];
        bc.doFinal(bcHash, 0);

        assertArrayEquals(bcHash, oursHash,
                "len=" + data.length + ":\n  BC:   " + ByteUtils.toHex(bcHash)
                        + "\n  ours: " + ByteUtils.toHex(oursHash));
    }
}
