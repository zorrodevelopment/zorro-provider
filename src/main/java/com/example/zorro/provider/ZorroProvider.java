package com.example.zorro.provider;

import java.security.Provider;

/**
 * ZORRO Cryptographic Provider — самостоятельный JCE-провайдер с
 * собственными именами алгоритмов и собственными OID-ами.
 *
 * <h2>Архитектура</h2>
 * <ul>
 *   <li>{@code MessageDigest.ZORRO-SHA-512} и {@code Mac.ZORRO-HMACSHA512} —
 *       полностью собственная реализация, не зависит от внешних библиотек.</li>
 *   <li>{@code MessageDigest.ZORRO-HASH-512}, {@code Signature.ZORRO-SIGN-512},
 *       {@code KeyStore.ZORRO-PKCS12} — реализованы внутри ZORRO через
 *       low-level примитивы BouncyCastle (GOST3411-2012, ECGOST3410-2012,
 *       PKCS12KeyStoreSpi). Это не делегат в провайдер «BC» — наш SPI
 *       сам исполняет работу, BC выступает как библиотека примитивов.</li>
 *   <li>Алгоритмы регистрируются через {@link AlgorithmModule} —
 *       каждый модуль кладёт свои mappings.</li>
 * </ul>
 *
 * <h2>Регистрация</h2>
 * <pre>
 * Security.addProvider(new ZorroProvider());           // обычная
 * Security.insertProviderAt(new ZorroProvider(), 1);   // с приоритетом
 * </pre>
 *
 * <h2>Зависимости</h2>
 * Compile/runtime: {@code org.bouncycastle:bcprov-jdk18on}. Регистрировать
 * BC-провайдер в JVM не нужно — мы используем BC как библиотеку.
 */
public final class ZorroProvider extends Provider {

    /** Имя провайдера в JVM. */
    public static final String PROVIDER_NAME = "ZORRO";

    /** Версия — должна совпадать с pom.xml. */
    private static final String VERSION_STR = "0.0.1";

    /** Описание — попадёт в Provider.getInfo(). */
    private static final String INFO =
            "ZORRO Cryptographic Provider v" + VERSION_STR
            + " (own SHA-512/HMAC, BouncyCastle-backed Streebog/ECGOST/PKCS12)";

    /**
     * Список модулей, регистрирующих алгоритмы. Все модули обязательные:
     * BouncyCastle — hard dependency, и без него провайдер не имеет
     * смысла собираться.
     */
    private static final String[] MODULES = {
        "com.example.zorro.jcajce.provider.digest.ZorroSha512$Mappings",
        "com.example.zorro.jcajce.provider.mac.ZorroHmacSha512$Mappings",
        "com.example.zorro.jcajce.provider.digest.ZorroHash512$Mappings",
        "com.example.zorro.jcajce.provider.signature.ZorroSign512$Mappings",
        // KeyFactory-транслятор должен быть зарегистрирован ДО KeyStore,
        // чтобы PKCS12 (через DefaultJcaJceHelper) смог найти его при
        // парсинге ключей с казахскими OID-ами.
        "com.example.zorro.jcajce.provider.asymmetric.ZorroKalkanGostKeyFactory$Mappings",
        "com.example.zorro.jcajce.provider.keystore.ZorroPkcs12$Mappings",
    };

    private static final long serialVersionUID = 1L;

    public ZorroProvider() {
        super(PROVIDER_NAME, VERSION_STR, INFO);

        setup();
    }

    /** Регистрирует все модули. Вызывается из конструктора. */
    private void setup() {
        for (String moduleClassName : MODULES) {
            registerModule(moduleClassName);
        }
    }

    /** Загружает модуль по имени класса и вызывает {@link AlgorithmModule#register}. */
    private void registerModule(String className) {
        try {
            ClassLoader cl = ZorroProvider.class.getClassLoader();
            Class<?> clazz = (cl != null)
                    ? cl.loadClass(className)
                    : Class.forName(className);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            if (!(instance instanceof AlgorithmModule)) {
                throw new IllegalStateException(
                        className + " не реализует AlgorithmModule");
            }
            ((AlgorithmModule) instance).register(this);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(
                    "Модуль не найден: " + className, e);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                    "Не удалось инстанцировать " + className, e);
        }
    }

    @Override
    public String getVersionStr() {
        return VERSION_STR;
    }
}
