# ZORRO — пример собственного JCE-провайдера

Демонстрационный криптопровайдер `ZORRO` поверх Kalkan. Регистрируется в JVM
наряду с любыми другими провайдерами (Sun, BouncyCastle, Kalkan), даёт
собственные имена алгоритмов и собственные OID-ы, но реальную крипто-работу
делегирует Kalkan.

```
java.security.Security
   ├── SunJCE
   ├── BouncyCastle    (org.bouncycastle.jce.provider.BouncyCastleProvider)
   ├── KALKAN          (kz.gov.pki.kalkan.jce.provider.KalkanProvider)
   └── ZORRO           (com.example.zorro.provider.ZorroProvider)
                            ↓ делегирует
                          KALKAN
```

## Зачем такая обёртка нужна

В реальности провайдер-обёртка нужна, чтобы:

1. **Иметь свой brand и OID-пространство.** Если ваша компания строит
   PKI или подписной сервис, у неё должны быть собственные OID для
   расширений сертификатов, политик подписи и т.д.
2. **Развязать бизнес-код от конкретной библиотеки.** Завтра вместо Kalkan
   можно взять BouncyCastle с GOST-аддоном, а имена алгоритмов
   `ZORRO-SIGN-512` останутся теми же.
3. **Аудит и контроль.** Провайдер-обёртка может логировать вызовы,
   проверять политику использования ключей, добавлять hardware-token
   слой, и т.д.
4. **Учить и тестировать.** Понять архитектуру JCE-провайдеров проще
   всего, написав свой.

## Структура

```
zorro-provider/
├── pom.xml
├── src/main/java/com/example/zorro/
│   ├── provider/
│   │   ├── ZorroProvider.java      главный класс, регистрируется в JVM
│   │   └── AlgorithmModule.java    интерфейс плагина
│   ├── jcajce/provider/
│   │   ├── digest/
│   │   │   └── ZorroHash512.java   MessageDigestSpi → KALKAN
│   │   ├── signature/
│   │   │   └── ZorroSign512.java   SignatureSpi → KALKAN
│   │   └── keystore/
│   │       └── ZorroPkcs12.java    KeyStoreSpi → KALKAN
│   ├── asn1/
│   │   └── ZorroObjectIdentifiers.java   OID-ы провайдера
│   ├── util/
│   │   └── ByteUtils.java          BE/LE-утилиты
│   └── demo/
│       └── ZorroDemo.java          демонстрация
└── README.md
```

## Зарегистрированные алгоритмы

| Имя                  | Тип            | Реализация                           | Зависимости |
|----------------------|----------------|--------------------------------------|-------------|
| `ZORRO-SHA-512`      | MessageDigest  | **собственная** (FIPS 180-4)         | нет         |
| `ZORRO-HMACSHA512`   | Mac            | **собственная** (RFC 2104)           | нет         |
| `ZORRO-HASH-512`     | MessageDigest  | обёртка над `GOST3411-2015-512`      | KALKAN      |
| `ZORRO-SIGN-512`     | Signature      | обёртка над `ECGOST3410-2015-512`    | KALKAN      |
| `ZORRO-PKCS12`       | KeyStore       | обёртка над `PKCS12`                 | KALKAN      |

**Опциональность:** если KALKAN не зарегистрирован в JVM, провайдер
ZORRO стартует без обёрток — будет доступен только `ZORRO-SHA-512`.
Это достигается префиксом `?` в массиве `MODULES` главного класса
провайдера и проверкой `Security.getProvider(BACKEND)` в `Mappings.register()`.

И все — с собственными OID-ами в дереве `1.3.6.1.4.1.99999.*` (в production
получите свой PEN).

## Сборка и запуск

Нужны: JDK 11+, Maven, JAR Kalkan.

```cmd
set JAVA_HOME=D:\_PROGRAMS\jdk-17.0.12
set PATH=%JAVA_HOME%\bin;%PATH%

:: 1) Установить Kalkan в локальный Maven-репо
mkdir lib
copy путь\к\kalkan-0_7_5.jar lib\
mvn install:install-file ^
    -Dfile=lib\kalkan-0_7_5.jar ^
    -DgroupId=kz.gov.pki.kalkan ^
    -DartifactId=knca_provider_jce_kalkan ^
    -Dversion=0.7.5 ^
    -Dpackaging=jar

:: 2) Положить тестовый ключ
copy путь\к\GOST512_xxx.p12 test.p12

:: 3) Сборка и запуск
mvn clean package
java -cp "target\zorro-provider-1.0.0.jar;target\lib\*" ^
     com.example.zorro.demo.ZorroTest
```

## Ожидаемый вывод

```
=== ПРОВАЙДЕРЫ ===========================================================
    SUN v...
    SunRsaSign v...
    SunJSSE v...
    SunJCE v...
    ...
  ★ KALKAN v0.7.5
  ★ ZORRO v1.0.0

=== АЛГОРИТМЫ ПРОВАЙДЕРА ZORRO ===========================================
  KeyStore.ZORRO-PKCS12
  Mac.ZORRO-HMACSHA512
  MessageDigest.ZORRO-HASH-512
  MessageDigest.ZORRO-SHA-512
  Signature.ZORRO-SIGN-512

=== СОБСТВЕННЫЙ ALG: ZORRO-SHA-512 =======================================
  алгоритм:    ZORRO-SHA-512
  digest hex:  abcd... (тот же что у SunJCE SHA-512)
  совпадает с SunJCE SHA-512: true

=== СОБСТВЕННЫЙ ALG: ZORRO-HMACSHA512 ====================================
  алгоритм:    ZORRO-HMACSHA512
  mac hex:     def0...
  совпадает с SunJCE HmacSHA512: true

=== ЗАГРУЗКА P12 ЧЕРЕЗ ZORRO-PKCS12 ======================================
  alias:        ...
  key class:    kz.gov.pki.kalkan.jce.provider.asymmetric.ecgost15.EcGost3410_2015PrivateKey
  ...

=== ХЭШ ЧЕРЕЗ ZORRO-HASH-512 =============================================
  алгоритм:    ZORRO-HASH-512
  провайдер:   ZORRO
  digest hex:  abcd...
  совпадает с KALKAN GOST3411-2015-512: true

=== ПОДПИСЬ ЧЕРЕЗ ZORRO-SIGN-512 =========================================
  signature size: 128 bytes
  ...

=== ПРОВЕРКА ПОДПИСИ ЧЕРЕЗ ZORRO =========================================
  валидна (ZORRO):  true

=== КРОСС-ПРОВЕРКА: ZORRO-подпись через KALKAN ===========================
  валидна (KALKAN): true   (доказывает, что мы не «переизобрели» формат)
  KALKAN-подпись валидна через ZORRO: true

=== НЕГАТИВНЫЙ ТЕСТ ======================================================
  изменённое сообщение: false   (должно быть false)

=== ОБРАЩЕНИЕ ПО OID =====================================================
  OID '1.3.6.1.4.1.99999.1.2.1' разрешился в: ZORRO-SIGN-512

=== ИТОГ =================================================================
  ВСЁ ОК — провайдер ZORRO работает корректно,
  совместим с KALKAN на уровне формата.
```

## Как добавить ещё один алгоритм

1. Создайте класс, наследующий `MessageDigestSpi`, `SignatureSpi`,
   `KeyStoreSpi`, `KeyPairGeneratorSpi`, `CipherSpi` и т.д.
2. Внутри сделайте вложенный класс `Mappings implements AlgorithmModule`,
   который кладёт mapping'и в provider.
3. Допишите имя класса `Mappings` в массив `MODULES`
   в `ZorroProvider.java`.

Например, для добавления хэша 256 бит:

```java
public class ZorroHash256 extends MessageDigestSpi {
    // engineUpdate, engineDigest, engineReset, engineGetDigestLength → 32

    public static class Mappings implements AlgorithmModule {
        @Override public void register(Provider p) {
            p.put("MessageDigest.ZORRO-HASH-256", ZorroHash256.class.getName());
            p.put("Alg.Alias.MessageDigest.1.3.6.1.4.1.99999.1.1.2", "ZORRO-HASH-256");
        }
    }
}
```

И в `ZorroProvider.MODULES`:
```java
private static final String[] MODULES = {
    "com.example.zorro.jcajce.provider.digest.ZorroHash512$Mappings",
    "com.example.zorro.jcajce.provider.digest.ZorroHash256$Mappings",   // ← добавили
    "com.example.zorro.jcajce.provider.signature.ZorroSign512$Mappings",
    "com.example.zorro.jcajce.provider.keystore.ZorroPkcs12$Mappings",
};
```

## Что осталось «настоящей» подписью провайдера

Для production-провайдера, который будет работать с *Cipher*-алгоритмами
типа AES, нужна подпись JAR файла специальным сертификатом от Oracle
(JCE Code Signing CA). Без этой подписи Cipher-engine откажется работать.
Для `MessageDigest`, `Signature`, `KeyStore`, `KeyPairGenerator` — **подпись
не требуется**. Этот пример включает только последние, поэтому работает
без специальной подписи.
