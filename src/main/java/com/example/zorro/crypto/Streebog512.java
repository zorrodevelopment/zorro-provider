package com.example.zorro.crypto;

/**
 * Собственная реализация Streebog-512 (ГОСТ Р 34.11-2012, длина хэша 512 бит).
 *
 * <p>Не зависит от внешних библиотек. Используется внутри
 * {@code com.example.zorro.jcajce.provider.digest.ZorroHash512}.
 *
 * <p><b>Внутреннее представление состояния.</b> 64-байтные векторы (h, N, Σ, m)
 * хранятся в обратном порядке байт: байт по индексу 0 во внутреннем массиве
 * соответствует байту 63 в нотации стандарта (little-endian whole-block).
 * Это позволяет применять предвычисленную таблицу {@code T} напрямую без
 * дополнительных перестановок и эквивалентно реализации в BouncyCastle.
 *
 * <p><b>Константы.</b> В исходнике зафиксированы только первичные константы из
 * стандарта: подстановка {@code PI} (Прил. А.1), линейная матрица {@code A}
 * (Прил. А.3) и итерационные константы {@code C} (Прил. А.4). Перестановка
 * {@code τ} в явном виде не хранится — её эффект учтён при сборке таблицы
 * {@code T} формулой {@code 8*(7-col)+j}. Таблица {@code T = S∘P∘L} вычисляется
 * один раз при загрузке класса.
 *
 * <p>Класс не потокобезопасен.
 */
public final class Streebog512 {

    public static final int DIGEST_LENGTH = 64;
    public static final int BLOCK_LENGTH  = 64;

    /** S-box π, ГОСТ Р 34.11-2012, Прил. А.1. */
    private static final int[] PI = {
        252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77,
        233, 119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193,
        249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66, 139,   1, 142,  79,
          5, 132,   2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31,
        235,  52,  44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,  58, 206, 204,
        181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156, 183,  93, 135,
         21, 161, 150,  41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
         50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195, 189,  13,  87,
        223, 245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3,
        224,  15, 236, 222, 122, 148, 176, 188, 220, 232,  40,  80,  78,  51,  10,  74,
        167, 151,  96, 115,  30,   0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65,
        173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165, 125, 105, 213, 149,  59,
          7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107, 228, 136, 217, 231, 137,
        225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,  97,
         32, 113, 103, 164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82,
         89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,  75,  99, 182
    };

    /** Линейное преобразование L: 64-битные строки матрицы A, ГОСТ Р 34.11-2012, Прил. А.3. */
    private static final long[] A = {
        0x8e20faa72ba0b470L, 0x47107ddd9b505a38L, 0xad08b0e0c3282d1cL, 0xd8045870ef14980eL,
        0x6c022c38f90a4c07L, 0x3601161cf205268dL, 0x1b8e0b0e798c13c8L, 0x83478b07b2468764L,
        0xa011d380818e8f40L, 0x5086e740ce47c920L, 0x2843fd2067adea10L, 0x14aff010bdd87508L,
        0x0ad97808d06cb404L, 0x05e23c0468365a02L, 0x8c711e02341b2d01L, 0x46b60f011a83988eL,
        0x90dab52a387ae76fL, 0x486dd4151c3dfdb9L, 0x24b86a840e90f0d2L, 0x125c354207487869L,
        0x092e94218d243cbaL, 0x8a174a9ec8121e5dL, 0x4585254f64090fa0L, 0xaccc9ca9328a8950L,
        0x9d4df05d5f661451L, 0xc0a878a0a1330aa6L, 0x60543c50de970553L, 0x302a1e286fc58ca7L,
        0x18150f14b9ec46ddL, 0x0c84890ad27623e0L, 0x0642ca05693b9f70L, 0x0321658cba93c138L,
        0x86275df09ce8aaa8L, 0x439da0784e745554L, 0xafc0503c273aa42aL, 0xd960281e9d1d5215L,
        0xe230140fc0802984L, 0x71180a8960409a42L, 0xb60c05ca30204d21L, 0x5b068c651810a89eL,
        0x456c34887a3805b9L, 0xac361a443d1c8cd2L, 0x561b0d22900e4669L, 0x2b838811480723baL,
        0x9bcf4486248d9f5dL, 0xc3e9224312c8c1a0L, 0xeffa11af0964ee50L, 0xf97d86d98a327728L,
        0xe4fa2054a80b329cL, 0x727d102a548b194eL, 0x39b008152acb8227L, 0x9258048415eb419dL,
        0x492c024284fbaec0L, 0xaa16012142f35760L, 0x550b8e9e21f7a530L, 0xa48b474f9ef5dc18L,
        0x70a6a56e2440598eL, 0x3853dc371220a247L, 0x1ca76e95091051adL, 0x0edd37c48a08a6d8L,
        0x07e095624504536cL, 0x8d70c431ac02a736L, 0xc83862965601dd1bL, 0x641c314b2b8ee083L
    };

    /**
     * Итерационные константы C[1..12], ГОСТ Р 34.11-2012, Прил. А.4.
     * Хранятся в той же байтовой нотации, что и внутреннее состояние
     * (см. {@link #F}): {@code C[i][0]} — старший байт.
     */
    private static final String[] C_HEX = {
        "b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc"
      + "4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507",
        "6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b50131"
      + "9ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7",
        "f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7b"
      + "d3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2",
        "ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353f"
      + "a9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e",
        "4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbd"
      + "bfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57",
        "ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6"
      + "cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e",
        "f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c9"
      + "0992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493",
        "9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49a"
      + "f4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e",
        "378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984"
      + "800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb",
        "abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b336103"
      + "9fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced",
        "7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab07612001802114846679"
      + "8a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b",
        "378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b"
      + "5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720"
    };

    private static final byte[][] C = buildC();

    private static byte[][] buildC() {
        byte[][] out = new byte[12][];
        for (int i = 0; i < 12; i++) {
            out[i] = hexBytes(C_HEX[i]);
        }
        return out;
    }

    private static byte[] hexBytes(String s) {
        if (s.length() != 128) throw new IllegalStateException("C entry must be 64 bytes");
        byte[] r = new byte[64];
        for (int i = 0; i < 64; i++) {
            r[i] = (byte) ((Character.digit(s.charAt(i * 2), 16) << 4)
                    | Character.digit(s.charAt(i * 2 + 1), 16));
        }
        return r;
    }

    /** Предвычисленная таблица S∘P∘L: T[col][b] — вклад байта b в позиции col. */
    private static final long[][] T = computeT();

    private static long[][] computeT() {
        long[] aLE = new long[64];
        for (int i = 0; i < 64; i++) {
            aLE[i] = Long.reverseBytes(A[i]);
        }
        long[][] t = new long[8][256];
        for (int col = 0; col < 8; col++) {
            for (int b = 0; b < 256; b++) {
                int p = PI[b];
                long v = 0;
                for (int j = 0; j < 8; j++) {
                    if ((p & (0x80 >>> j)) != 0) {
                        v ^= aLE[8 * (7 - col) + j];
                    }
                }
                t[col][b] = v;
            }
        }
        return t;
    }

    // ----- Состояние -----

    private final byte[] h     = new byte[BLOCK_LENGTH];   // IV для Streebog-512 — все нули
    private final byte[] N     = new byte[BLOCK_LENGTH];
    private final byte[] sigma = new byte[BLOCK_LENGTH];
    private final byte[] block = new byte[BLOCK_LENGTH];
    private int bOff = BLOCK_LENGTH;

    public Streebog512() {
        // Все массивы уже занулены по умолчанию.
    }

    public void reset() {
        java.util.Arrays.fill(h,     (byte) 0);
        java.util.Arrays.fill(N,     (byte) 0);
        java.util.Arrays.fill(sigma, (byte) 0);
        java.util.Arrays.fill(block, (byte) 0);
        bOff = BLOCK_LENGTH;
    }

    public void update(byte in) {
        block[--bOff] = in;
        if (bOff == 0) {
            gN(h, N, block);
            addMod512(N, 512);
            addMod512(sigma, block);
            bOff = BLOCK_LENGTH;
        }
    }

    public void update(byte[] in, int off, int len) {
        if (in == null) throw new NullPointerException("in");
        if (off < 0 || len < 0 || off + len > in.length) {
            throw new IndexOutOfBoundsException();
        }
        // Добиваем неполный блок
        while (bOff != BLOCK_LENGTH && len > 0) {
            update(in[off++]);
            len--;
        }
        // Полные блоки — копируем сразу с реверсом
        while (len >= BLOCK_LENGTH) {
            for (int i = 0; i < BLOCK_LENGTH; i++) {
                block[BLOCK_LENGTH - 1 - i] = in[off + i];
            }
            gN(h, N, block);
            addMod512(N, 512);
            addMod512(sigma, block);
            off += BLOCK_LENGTH;
            len -= BLOCK_LENGTH;
        }
        // Хвост
        while (len > 0) {
            update(in[off++]);
            len--;
        }
    }

    public byte[] digest() {
        int lenM = BLOCK_LENGTH - bOff;

        // Финальный блок: zeros || 0x01 || tail (всё в "обратном" расположении).
        byte[] m = new byte[BLOCK_LENGTH];
        // m[0 .. 63-lenM-1] = 0  (уже)
        m[BLOCK_LENGTH - 1 - lenM] = 1;
        if (lenM > 0) {
            System.arraycopy(block, bOff, m, BLOCK_LENGTH - lenM, lenM);
        }

        gN(h, N, m);
        addMod512(N, lenM * 8);
        addMod512(sigma, m);

        byte[] zero = new byte[BLOCK_LENGTH];
        gN(h, zero, N);
        gN(h, zero, sigma);

        // Реверс h в выходной массив (отдаём в стандартной BE-нотации)
        byte[] out = new byte[BLOCK_LENGTH];
        for (int i = 0; i < BLOCK_LENGTH; i++) {
            out[i] = h[BLOCK_LENGTH - 1 - i];
        }
        reset();
        return out;
    }

    // ----- Внутренняя криптография -----

    /** F = LPS — линейно-подстановочное преобразование, in-place. */
    private static void F(byte[] V) {
        long r0 = T[0][V[56] & 0xFF] ^ T[1][V[48] & 0xFF] ^ T[2][V[40] & 0xFF] ^ T[3][V[32] & 0xFF]
                ^ T[4][V[24] & 0xFF] ^ T[5][V[16] & 0xFF] ^ T[6][V[ 8] & 0xFF] ^ T[7][V[ 0] & 0xFF];
        long r1 = T[0][V[57] & 0xFF] ^ T[1][V[49] & 0xFF] ^ T[2][V[41] & 0xFF] ^ T[3][V[33] & 0xFF]
                ^ T[4][V[25] & 0xFF] ^ T[5][V[17] & 0xFF] ^ T[6][V[ 9] & 0xFF] ^ T[7][V[ 1] & 0xFF];
        long r2 = T[0][V[58] & 0xFF] ^ T[1][V[50] & 0xFF] ^ T[2][V[42] & 0xFF] ^ T[3][V[34] & 0xFF]
                ^ T[4][V[26] & 0xFF] ^ T[5][V[18] & 0xFF] ^ T[6][V[10] & 0xFF] ^ T[7][V[ 2] & 0xFF];
        long r3 = T[0][V[59] & 0xFF] ^ T[1][V[51] & 0xFF] ^ T[2][V[43] & 0xFF] ^ T[3][V[35] & 0xFF]
                ^ T[4][V[27] & 0xFF] ^ T[5][V[19] & 0xFF] ^ T[6][V[11] & 0xFF] ^ T[7][V[ 3] & 0xFF];
        long r4 = T[0][V[60] & 0xFF] ^ T[1][V[52] & 0xFF] ^ T[2][V[44] & 0xFF] ^ T[3][V[36] & 0xFF]
                ^ T[4][V[28] & 0xFF] ^ T[5][V[20] & 0xFF] ^ T[6][V[12] & 0xFF] ^ T[7][V[ 4] & 0xFF];
        long r5 = T[0][V[61] & 0xFF] ^ T[1][V[53] & 0xFF] ^ T[2][V[45] & 0xFF] ^ T[3][V[37] & 0xFF]
                ^ T[4][V[29] & 0xFF] ^ T[5][V[21] & 0xFF] ^ T[6][V[13] & 0xFF] ^ T[7][V[ 5] & 0xFF];
        long r6 = T[0][V[62] & 0xFF] ^ T[1][V[54] & 0xFF] ^ T[2][V[46] & 0xFF] ^ T[3][V[38] & 0xFF]
                ^ T[4][V[30] & 0xFF] ^ T[5][V[22] & 0xFF] ^ T[6][V[14] & 0xFF] ^ T[7][V[ 6] & 0xFF];
        long r7 = T[0][V[63] & 0xFF] ^ T[1][V[55] & 0xFF] ^ T[2][V[47] & 0xFF] ^ T[3][V[39] & 0xFF]
                ^ T[4][V[31] & 0xFF] ^ T[5][V[23] & 0xFF] ^ T[6][V[15] & 0xFF] ^ T[7][V[ 7] & 0xFF];
        writeLE(V,  0, r0);
        writeLE(V,  8, r1);
        writeLE(V, 16, r2);
        writeLE(V, 24, r3);
        writeLE(V, 32, r4);
        writeLE(V, 40, r5);
        writeLE(V, 48, r6);
        writeLE(V, 56, r7);
    }

    private static void writeLE(byte[] V, int off, long v) {
        V[off    ] = (byte) v;
        V[off + 1] = (byte) (v >>>  8);
        V[off + 2] = (byte) (v >>> 16);
        V[off + 3] = (byte) (v >>> 24);
        V[off + 4] = (byte) (v >>> 32);
        V[off + 5] = (byte) (v >>> 40);
        V[off + 6] = (byte) (v >>> 48);
        V[off + 7] = (byte) (v >>> 56);
    }

    /** E(K, m) = шифр Streebog: 12 раундов сети с раундовыми ключами, выводимыми из K и C. */
    private static void E(byte[] K, byte[] m) {
        byte[] Ki = K.clone();
        xor512(K, m);
        F(K);
        for (int i = 0; i < 11; i++) {
            xor512(Ki, C[i]);
            F(Ki);
            xor512(K, Ki);
            F(K);
        }
        xor512(Ki, C[11]);
        F(Ki);
        xor512(K, Ki);
    }

    /** g_N(h, m): h := E(LPS(h ⊕ N), m) ⊕ h ⊕ m. */
    private static void gN(byte[] h, byte[] N, byte[] m) {
        byte[] hSave = h.clone();
        xor512(h, N);
        F(h);
        E(h, m);
        xor512(h, hSave);
        xor512(h, m);
    }

    private static void xor512(byte[] dst, byte[] src) {
        for (int i = 0; i < 64; i++) dst[i] ^= src[i];
    }

    /** Прибавляет {@code num} к 64-байтному LE-числу {@code arr} по модулю 2^512. */
    private static void addMod512(byte[] arr, int num) {
        int c;
        c = (arr[63] & 0xFF) + (num & 0xFF);
        arr[63] = (byte) c;
        c = (arr[62] & 0xFF) + ((num >>> 8) & 0xFF) + (c >>> 8);
        arr[62] = (byte) c;
        c = (arr[61] & 0xFF) + ((num >>> 16) & 0xFF) + (c >>> 8);
        arr[61] = (byte) c;
        c = (arr[60] & 0xFF) + ((num >>> 24) & 0xFF) + (c >>> 8);
        arr[60] = (byte) c;
        for (int i = 59; i >= 0 && (c >>> 8) != 0; i--) {
            c = (arr[i] & 0xFF) + (c >>> 8);
            arr[i] = (byte) c;
        }
    }

    /** Прибавляет 64-байтное LE-число {@code b} к {@code a} по модулю 2^512. */
    private static void addMod512(byte[] a, byte[] b) {
        int c = 0;
        for (int i = 63; i >= 0; i--) {
            c = (a[i] & 0xFF) + (b[i] & 0xFF) + (c >>> 8);
            a[i] = (byte) c;
        }
    }
}
