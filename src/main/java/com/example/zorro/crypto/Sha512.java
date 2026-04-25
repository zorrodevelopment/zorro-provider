package com.example.zorro.crypto;

/**
 * Собственная реализация SHA-512 строго по FIPS 180-4.
 *
 * <p>Используется внутренне SPI-классом {@code ZorroSha512}. Эта реализация
 * не зависит ни от Kalkan, ни от BouncyCastle и позволяет провайдеру ZORRO
 * иметь хотя бы один полностью «собственный» алгоритм.
 *
 * <p>Класс не потокобезопасен и держит всё состояние в полях.
 *
 * <p>Реализация прямо повторяет Python-референс, который проверен против
 * {@code hashlib.sha512()} на нескольких тест-векторах включая пустую
 * строку, "abc" и 4000-байтный input.
 */
public final class Sha512 {

    /** Длина хэша в байтах. */
    public static final int DIGEST_LENGTH = 64;
    /** Длина блока в байтах. */
    public static final int BLOCK_LENGTH  = 128;

    /** Раундовые константы (первые 64 бита дробной части кубических корней первых 80 простых). */
    private static final long[] K = {
        0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
        0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
        0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
        0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
        0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
        0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
        0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
        0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
        0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
        0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
        0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
        0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
        0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
        0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
        0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
        0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
        0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
        0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
        0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
        0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L,
    };

    /** Начальные значения H (первые 64 бита дробной части квадратных корней первых 8 простых). */
    private static final long[] H0 = {
        0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
        0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
    };

    private final long[] H = new long[8];
    private final byte[] buffer = new byte[BLOCK_LENGTH];
    private int  bufferLen;
    private long bytesProcessed;

    public Sha512() {
        reset();
    }

    public void reset() {
        System.arraycopy(H0, 0, H, 0, 8);
        bufferLen = 0;
        bytesProcessed = 0;
    }

    public void update(byte b) {
        buffer[bufferLen++] = b;
        bytesProcessed++;
        if (bufferLen == BLOCK_LENGTH) {
            processBlock(buffer, 0);
            bufferLen = 0;
        }
    }

    public void update(byte[] data, int offset, int length) {
        if (data == null) throw new NullPointerException("data");
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IndexOutOfBoundsException();
        }
        bytesProcessed += length;

        // 1) Если есть незаполненный буфер — добиваем его
        if (bufferLen > 0) {
            int n = Math.min(BLOCK_LENGTH - bufferLen, length);
            System.arraycopy(data, offset, buffer, bufferLen, n);
            bufferLen += n; offset += n; length -= n;
            if (bufferLen == BLOCK_LENGTH) {
                processBlock(buffer, 0);
                bufferLen = 0;
            }
        }
        // 2) Полные блоки прямо из data
        while (length >= BLOCK_LENGTH) {
            processBlock(data, offset);
            offset += BLOCK_LENGTH;
            length -= BLOCK_LENGTH;
        }
        // 3) Хвост — в буфер
        if (length > 0) {
            System.arraycopy(data, offset, buffer, 0, length);
            bufferLen = length;
        }
    }

    public byte[] digest() {
        long bitLength = bytesProcessed * 8L;

        // Padding: 0x80, нули, длина (16 байт BE)
        buffer[bufferLen++] = (byte) 0x80;
        if (bufferLen > BLOCK_LENGTH - 16) {
            // не хватает места для длины — добиваем нулями и обрабатываем блок
            while (bufferLen < BLOCK_LENGTH) buffer[bufferLen++] = 0;
            processBlock(buffer, 0);
            bufferLen = 0;
        }
        while (bufferLen < BLOCK_LENGTH - 16) buffer[bufferLen++] = 0;

        // 16-байтная длина в битах: верхние 8 байт = 0 (мы не поддерживаем
        // сообщения больше 2^64 байт, что в реальности и не нужно)
        for (int i = 0; i < 8; i++) buffer[bufferLen++] = 0;
        for (int i = 7; i >= 0; i--) {
            buffer[bufferLen++] = (byte) (bitLength >>> (i * 8));
        }
        processBlock(buffer, 0);

        // Сохраняем результат
        byte[] out = new byte[DIGEST_LENGTH];
        for (int i = 0; i < 8; i++) {
            long v = H[i];
            out[i*8    ] = (byte) (v >>> 56);
            out[i*8 + 1] = (byte) (v >>> 48);
            out[i*8 + 2] = (byte) (v >>> 40);
            out[i*8 + 3] = (byte) (v >>> 32);
            out[i*8 + 4] = (byte) (v >>> 24);
            out[i*8 + 5] = (byte) (v >>> 16);
            out[i*8 + 6] = (byte) (v >>>  8);
            out[i*8 + 7] = (byte) v;
        }
        reset();
        return out;
    }

    // ----- внутренняя кухня -----

    private final long[] W = new long[80];

    private void processBlock(byte[] block, int offset) {
        // 1) Заполняем W[0..15] из блока (BE)
        for (int t = 0; t < 16; t++) {
            int p = offset + t * 8;
            W[t] = ((long)(block[p    ] & 0xFF) << 56)
                 | ((long)(block[p + 1] & 0xFF) << 48)
                 | ((long)(block[p + 2] & 0xFF) << 40)
                 | ((long)(block[p + 3] & 0xFF) << 32)
                 | ((long)(block[p + 4] & 0xFF) << 24)
                 | ((long)(block[p + 5] & 0xFF) << 16)
                 | ((long)(block[p + 6] & 0xFF) <<  8)
                 | ((long)(block[p + 7] & 0xFF));
        }
        // 2) Расширяем до W[16..79]
        for (int t = 16; t < 80; t++) {
            W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
        }

        long a = H[0], b = H[1], c = H[2], d = H[3];
        long e = H[4], f = H[5], g = H[6], h = H[7];

        for (int t = 0; t < 80; t++) {
            long T1 = h + Sigma1(e) + ch(e, f, g) + K[t] + W[t];
            long T2 = Sigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }

    // Long.rotateRight уже есть в JDK, но зависимость не критична — оставляю явную форму
    private static long rotr(long x, int n) {
        return (x >>> n) | (x << (64 - n));
    }
    private static long ch(long x, long y, long z)   { return (x & y) ^ (~x & z); }
    private static long maj(long x, long y, long z)  { return (x & y) ^ (x & z) ^ (y & z); }
    private static long Sigma0(long x) { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }
    private static long Sigma1(long x) { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }
    private static long sigma0(long x) { return rotr(x,  1) ^ rotr(x,  8) ^ (x >>>  7); }
    private static long sigma1(long x) { return rotr(x, 19) ^ rotr(x, 61) ^ (x >>>  6); }
}
