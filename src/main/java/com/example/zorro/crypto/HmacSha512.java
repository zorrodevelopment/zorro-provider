package com.example.zorro.crypto;

/**
 * HMAC-SHA-512 — keyed-hash MAC по RFC 2104, использует {@link Sha512}.
 *
 * <p>Полностью самостоятельная реализация, не зависит от внешних библиотек.
 * Корректность проверена через Python-референс на тест-векторах RFC 4231.
 *
 * <p>Класс не потокобезопасен.
 */
public final class HmacSha512 {

    private static final int BLOCK_SIZE  = 128;  // SHA-512 block size в байтах
    private static final int DIGEST_SIZE = 64;

    private final Sha512 inner = new Sha512();
    private byte[] opadKey;       // ключ ⊕ opad, нужен в doFinal()
    private boolean initialized;

    /**
     * Инициализирует MAC заданным ключом. Можно вызывать повторно — состояние
     * сбрасывается.
     *
     * @param key ключ, любой длины (включая пустой)
     */
    public void init(byte[] key) {
        if (key == null) throw new NullPointerException("key");

        // Шаг 1: если ключ длиннее блока — хэшируем его
        byte[] k;
        if (key.length > BLOCK_SIZE) {
            Sha512 h = new Sha512();
            h.update(key, 0, key.length);
            k = h.digest();
        } else {
            k = key;
        }
        // Шаг 2: дополняем нулями до BLOCK_SIZE
        if (k.length < BLOCK_SIZE) {
            byte[] padded = new byte[BLOCK_SIZE];
            System.arraycopy(k, 0, padded, 0, k.length);
            k = padded;
        }

        // Шаг 3: формируем ipad-key и opad-key
        byte[] ipadKey = new byte[BLOCK_SIZE];
        opadKey = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            ipadKey[i] = (byte) (k[i] ^ 0x36);
            opadKey[i] = (byte) (k[i] ^ 0x5c);
        }

        // Шаг 4: запускаем inner = SHA-512(ipadKey || ...)
        inner.reset();
        inner.update(ipadKey, 0, BLOCK_SIZE);
        initialized = true;
    }

    /** Сбрасывает MAC, повторно используя ранее установленный ключ. */
    public void reset() {
        if (!initialized) {
            throw new IllegalStateException("init() ещё не вызывался");
        }
        // Заново применяем ipadKey: ipadKey = opadKey ⊕ (0x5c ⊕ 0x36)
        byte[] ipadKey = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            ipadKey[i] = (byte) (opadKey[i] ^ (0x5c ^ 0x36));
        }
        inner.reset();
        inner.update(ipadKey, 0, BLOCK_SIZE);
    }

    public void update(byte b) {
        ensureInit();
        inner.update(b);
    }

    public void update(byte[] data, int off, int len) {
        ensureInit();
        inner.update(data, off, len);
    }

    /**
     * Завершает вычисление и возвращает MAC длиной 64 байта.
     * После вызова MAC можно использовать снова через {@link #reset()}.
     */
    public byte[] doFinal() {
        ensureInit();
        // Шаг 5: innerHash = SHA-512(ipadKey || message)
        byte[] innerHash = inner.digest();
        // Шаг 6: outerHash = SHA-512(opadKey || innerHash)
        Sha512 outer = new Sha512();
        outer.update(opadKey, 0, BLOCK_SIZE);
        outer.update(innerHash, 0, innerHash.length);
        byte[] mac = outer.digest();
        // подготовим inner к следующему вычислению
        reset();
        return mac;
    }

    public int getMacLength() {
        return DIGEST_SIZE;
    }

    private void ensureInit() {
        if (!initialized) {
            throw new IllegalStateException("init() ещё не вызывался");
        }
    }
}
