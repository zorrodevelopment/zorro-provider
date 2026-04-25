package com.example.zorro.asn1;

/**
 * Идентификаторы объектов (OID) провайдера ZORRO.
 *
 * Используется частный PEN-префикс {@code 1.3.6.1.4.1.99999} (пример).
 * <p>
 * <b>Внимание:</b> для production обязательно зарегистрируйте свой собственный
 * Private Enterprise Number в IANA (https://pen.iana.org/) и замените
 * константу {@link #ROOT}.
 *
 * Дерево:
 * <pre>
 *   1.3.6.1.4.1.99999          — корень ZORRO
 *   1.3.6.1.4.1.99999.1        — алгоритмы
 *   1.3.6.1.4.1.99999.1.1      — хэш-функции
 *   1.3.6.1.4.1.99999.1.1.1    — ZORRO-HASH-512
 *   1.3.6.1.4.1.99999.1.2      — подписи
 *   1.3.6.1.4.1.99999.1.2.1    — ZORRO-SIGN-512 (Streebog-512 + ECGOST-2015-512)
 * </pre>
 *
 * Хранится строкой: ASN.1 объекты создаются on-demand, чтобы не зависеть
 * от конкретной библиотеки ASN.1 (BC, Kalkan, sun.security.util и т.д.).
 */
public final class ZorroObjectIdentifiers {

    /** Корневой OID провайдера. */
    public static final String ROOT = "1.3.6.1.4.1.99999";

    /** Подветка алгоритмов. */
    public static final String ALGORITHMS = ROOT + ".1";

    /** OID хэш-функции ZORRO-HASH-512. */
    public static final String ZORRO_HASH_512 = ALGORITHMS + ".1.1";

    /** OID подписи ZORRO-SIGN-512 (Streebog-512 + ECGOST3410-2015-512). */
    public static final String ZORRO_SIGN_512 = ALGORITHMS + ".2.1";

    private ZorroObjectIdentifiers() {}
}
