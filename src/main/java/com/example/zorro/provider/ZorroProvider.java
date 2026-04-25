package com.example.zorro.provider;

import java.security.Provider;

/**
 * ZORRO Cryptographic Provider — пример собственного JCE-провайдера,
 * расширяющего возможности Kalkan/BouncyCastle собственными именами
 * алгоритмов и собственными OID-ами.
 *
 * <h2>Архитектура</h2>
 * <ul>
 *   <li>Провайдер использует Kalkan как backend — все «настоящие»
 *       криптографические операции (хэш Streebog, подпись ECGOST-2015)
 *       делегируются туда.</li>
 *   <li>Поверх этого добавлены собственные имена и OID'ы:
 *       <ul>
 *         <li>{@code MessageDigest.ZORRO-HASH-512}</li>
 *         <li>{@code Signature.ZORRO-SIGN-512}</li>
 *         <li>{@code KeyStore.ZORRO-PKCS12}</li>
 *       </ul>
 *   </li>
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
 * Требует, чтобы в JVM был зарегистрирован провайдер KALKAN
 * (наш backend для ECGOST/Streebog). Если KALKAN не найден,
 * операции упадут с {@code NoSuchProviderException}.
 */
public final class ZorroProvider extends Provider {

    /** Имя провайдера в JVM. */
    public static final String PROVIDER_NAME = "ZORRO";

    /** Версия — должна совпадать с pom.xml. */
    private static final String VERSION_STR = "0.0.1";

    /** Описание — попадёт в Provider.getInfo(). */
    private static final String INFO =
            "ZORRO Cryptographic Provider v" + VERSION_STR
            + " — backend: KALKAN";

    /**
     * Список модулей, регистрирующих алгоритмы.
     *
     * <p>Модули с префиксом {@code "?"} регистрируются опционально:
     * если их зависимости (например, KALKAN) не на classpath или
     * не зарегистрированы, провайдер ZORRO стартует без них и
     * соответствующие алгоритмы будут просто отсутствовать.
     */
    private static final String[] MODULES = {
        // Собственные алгоритмы — обязательные.
        "com.example.zorro.jcajce.provider.digest.ZorroSha512$Mappings",
        "com.example.zorro.jcajce.provider.mac.ZorroHmacSha512$Mappings",
        // Streebog-512, ECGOST-2012-512 и PKCS#12 — собственные реализации.
        "com.example.zorro.jcajce.provider.digest.ZorroHash512$Mappings",
        "com.example.zorro.jcajce.provider.signature.ZorroSign512$Mappings",
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
            boolean optional = moduleClassName.startsWith("?");
            String name = optional ? moduleClassName.substring(1) : moduleClassName;
            try {
                registerModule(name);
            } catch (RuntimeException e) {
                if (!optional) throw e;
                // Опциональный модуль не загрузился — продолжаем тихо.
                // Можно добавить логирование, если ZORRO будет в production.
            }
        }
    }

    /** Загружает модуль по имени класса и вызывает {@link AlgorithmModule#register}.
     *  Опциональные модули заворачиваются в каждый класс отдельно через try/catch
     *  на ClassNotFoundException также внутри его конструктора. */
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
