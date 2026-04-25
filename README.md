# ZORRO — самостоятельный JCE-провайдер

`ZORRO` — учебный/демонстрационный JCE-провайдер. Регистрируется в JVM
наряду с любыми другими провайдерами (SunJCE, BouncyCastle, Kalkan), даёт
собственные имена алгоритмов и собственные OID-ы. Вся криптография реализована
**внутри ZORRO**, без делегирования в сторонние библиотеки.

```
java.security.Security
   ├── SunJCE
   ├── BouncyCastle    (опционально, нужно только для тестов)
   ├── KALKAN          (опционально, нужно только для тестов)
   └── ZORRO           ← самостоятелен, sign/verify, hash и PKCS#12 — свои
```

## Главная фишка: казахстанский PKCS#12

ZORRO умеет читать PFX-файлы НУЦ РК с алгоритмом ECGOST3410-2015 и казахстанскими OID-ами
(`1.2.398.3.10.1.1.2.2`, `1.2.398.3.10.1.1.2.2.1` и т.д.) — то есть PFX, которые
**ни BouncyCastle, ни openssl самостоятельно загрузить не могут**.

```bash
$ openssl pkcs12 -in test.p12 -info -legacy
... unsupported private key algorithm: TYPE=1.2.398.3.10.1.1.2.2
```

```java
KeyStore ks = KeyStore.getInstance("ZORRO-PKCS12", "ZORRO");
ks.load(new FileInputStream("test.p12"), "Qwerty12".toCharArray());
PrivateKey pk = (PrivateKey) ks.getKey(alias, password);   // OK!
```

## Зачем такая обёртка нужна

1. **Свой brand и OID-пространство** — компания строит PKI, у неё свои OID для
   расширений сертификатов и политик подписи.
2. **Развязка бизнес-кода от конкретной библиотеки** — клиентский код пишет
   `Signature.getInstance("ZORRO-SIGN-512")`, а внутри ZORRO может стоять или
   собственная реализация, или обёртка, или PKCS#11-делегат — без правок в
   приложении.
3. **Аудит и контроль** — провайдер может логировать вызовы, проверять политику
   использования ключей, добавлять hardware-token слой.
4. **Учить и тестировать** — понять архитектуру JCE-провайдеров проще всего
   через свой собственный.

## Зарегистрированные алгоритмы

| Имя                | Тип            | Реализация                                                          |
|--------------------|----------------|---------------------------------------------------------------------|
| `ZORRO-SHA-512`    | MessageDigest  | собственная (FIPS 180-4)                                            |
| `ZORRO-HMACSHA512` | Mac            | собственная (RFC 2104) ¹                                            |
| `ZORRO-HASH-512`   | MessageDigest  | собственный Streebog-512 (ГОСТ Р 34.11-2012)                        |
| `ZORRO-SIGN-512`   | Signature      | собственный ECGOST3410-2012-512 + Streebog-512                      |
| `ZORRO-PKCS12`     | KeyStore       | собственный читатель PFX, поддерживает RU и KZ ECGOST OID-ы         |

¹ Регистрация Mac-алгоритма в JCE формально требует подписанный Oracle JAR
(JCE Code Signing CA). В демо для проверки HMAC используется прямой вызов
`com.example.zorro.crypto.HmacSha512` минуя `Mac.getInstance(...)`. Подпись JAR
ничего не меняет в самой криптографии.

OID-пространство — `1.3.6.1.4.1.99999.*` (примерное; в production регистрируется
свой PEN в IANA).

## Структура

```
zorro-provider/
├── pom.xml
├── src/main/java/com/example/zorro/
│   ├── provider/
│   │   ├── ZorroProvider.java      главный класс, регистрируется в JVM
│   │   └── AlgorithmModule.java    интерфейс модуля
│   ├── crypto/                     "голая" криптография без JCE-обвязки
│   │   ├── Sha512.java             FIPS 180-4
│   │   ├── HmacSha512.java         RFC 2104
│   │   ├── Streebog512.java        ГОСТ Р 34.11-2012, 512 бит
│   │   ├── ec/
│   │   │   ├── EcCurveParams.java  параметры кривой
│   │   │   ├── EcPoint.java        арифметика точек EC
│   │   │   ├── GostCurves.java     paramSetA/B/C из RFC 7836
│   │   │   ├── EcGost2012Signer.java sign/verify
│   │   │   └── EcCurveLookup.java  маппинг JDK ECParameterSpec → EcCurveParams
│   │   └── asn1/
│   │       ├── DerInput.java       минимальный DER+BER парсер
│   │       ├── DerValue.java       TLV-структура
│   │       └── DerOutput.java      DER-кодировщик
│   ├── jcajce/provider/
│   │   ├── digest/                 SPI для MessageDigest
│   │   ├── mac/                    SPI для Mac
│   │   ├── signature/              SPI для Signature
│   │   ├── keystore/               SPI для KeyStore + PKCS#12 PBE
│   │   └── keys/                   ECPrivateKey/ECPublicKey + кодирование PKCS#8/SPKI
│   ├── asn1/
│   │   └── ZorroObjectIdentifiers.java   OID-ы провайдера
│   └── util/
│       └── ByteUtils.java          BE/LE-утилиты
└── src/test/                       37 тестов, см. ниже
```

## Сборка и запуск

Нужны: JDK 17+, Maven. BouncyCastle и Kalkan подтягиваются автоматически из
Maven Central (BC только для тестов; Kalkan уже есть в локальном `~/.m2`).

```cmd
:: Сборка и unit-тесты
mvn clean test

:: Сборка артефакта + копирование зависимостей в target/lib
mvn clean package
```

Все тесты проходят без какого-либо `test.p12` — единственный E2E-тест
({@code ZorroPkcs12IntegrationTest}, {@code KalkanCrossTest}, {@code ZorroTest})
требует файл `src/test/files/test.p12` с паролем `Qwerty12`. В репозитории лежит
тестовый сертификат от НУЦ РК (KZ ГОСТ-2015).

## Использование как библиотека

```java
import com.example.zorro.provider.ZorroProvider;
import java.security.Security;
import java.security.KeyStore;
import java.security.Signature;

// 1. Регистрируем провайдер.
Security.addProvider(new ZorroProvider());

// 2. Загружаем PFX (например, казахстанский).
KeyStore ks = KeyStore.getInstance("ZORRO-PKCS12", "ZORRO");
ks.load(new FileInputStream("user.p12"), password);
String alias = ks.aliases().nextElement();
PrivateKey priv = (PrivateKey) ks.getKey(alias, password);

// 3. Публичный ключ.
//    cert.getPublicKey() вернёт generic X509Key (JDK не знает KZ OID),
//    поэтому парсим SubjectPublicKeyInfo напрямую:
byte[] spki = ks.getCertificate(alias).getPublicKey().getEncoded();
PublicKey pub = com.example.zorro.jcajce.provider.keys.GostKeyEncoding
        .parseSubjectPublicKeyInfo(spki);

// 4. Подписать.
Signature signer = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
signer.initSign(priv);
signer.update(message);
byte[] sig = signer.sign();   // 128 байт, формат r_LE || s_LE

// 5. Проверить.
Signature verifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
verifier.initVerify(pub);
verifier.update(message);
boolean ok = verifier.verify(sig);
```

## Совместимость с другими провайдерами

ZORRO криптографически совместим и с Kalkan, и с BouncyCastle (математика одна
и та же — ГОСТ Р 34.10-2012 paramSetA). Различаются только сериализационные
форматы:

| Провайдер | Имя алгоритма          | Формат подписи          |
|-----------|------------------------|-------------------------|
| ZORRO     | `ZORRO-SIGN-512`       | `r_LE(64) ‖ s_LE(64)`   |
| Kalkan    | `ECGOST3410-2015-512`  | `r_LE(64) ‖ s_LE(64)`   |
| BC        | `ECGOST3410-2012-512`  | `s_BE(64) ‖ r_BE(64)`   |

ZORRO выбрал Kalkan-формат как «родной» (казахстанская конвенция).
**ZORRO ↔ Kalkan** обмениваются подписями без преобразований.
**ZORRO ↔ BC** — нужен побайтный реверс всей подписи:
```java
byte[] sigForBc = reverseBytes(zorroSig);
byte[] sigFromBc = reverseBytes(bcSig);   // прежде чем передать в ZORRO
```

См. `KalkanCrossTest` для всех шести направлений (sign×verify) между тремя
провайдерами.

## Тесты

37 тестов, все зелёные:

| Группа                       | Что проверяет                                                  |
|------------------------------|----------------------------------------------------------------|
| `Streebog512Test` (9)        | KAT-векторы + кросс-проверка с BC                              |
| `EcGost2012SignerTest` (8)   | sign/verify roundtrip, кросс-проверка с BC                     |
| `ZorroHash512SpiTest` (3)    | Streebog через JCE-фасад, доступ по OID                        |
| `ZorroSign512SpiTest` (6)    | подпись через JCE-фасад, ZORRO↔BC через стандартный JDK API    |
| `ZorroPkcs12IntegrationTest` (4) | загрузка реального p12 НУЦ РК, инвариант `d·G == Q`        |
| `KalkanCrossTest` (6)        | все 6 пар sign×verify между ZORRO, BC, KALKAN на ключе из p12  |
| `ZorroTest` (1)              | E2E-демо с печатью прогресса                                   |

```cmd
mvn test                   # все
mvn test -Dtest=ZorroTest  # E2E-демо
```

## Как добавить ещё один алгоритм

1. Создайте класс, наследующий `MessageDigestSpi`, `SignatureSpi`,
   `KeyStoreSpi`, `KeyPairGeneratorSpi` и т.д.
2. Внутри сделайте вложенный класс `Mappings implements AlgorithmModule`,
   который кладёт mapping'и в provider.
3. Допишите имя класса `Mappings` в массив `MODULES` в `ZorroProvider.java`.

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
    "com.example.zorro.jcajce.provider.digest.ZorroSha512$Mappings",
    "com.example.zorro.jcajce.provider.mac.ZorroHmacSha512$Mappings",
    "com.example.zorro.jcajce.provider.digest.ZorroHash512$Mappings",
    "com.example.zorro.jcajce.provider.digest.ZorroHash256$Mappings",   // ← добавили
    "com.example.zorro.jcajce.provider.signature.ZorroSign512$Mappings",
    "com.example.zorro.jcajce.provider.keystore.ZorroPkcs12$Mappings",
};
```

## Что нужно для production

1. **JCE Code Signing.** Mac, Cipher, KeyAgreement, KeyGenerator,
   SecretKeyFactory требуют, чтобы JAR провайдера был подписан Oracle JCE
   Code Signing CA. Этот пример обходится без подписи: `Mac.ZORRO-HMACSHA512`
   зарегистрирован в провайдере, но при `Mac.getInstance(... , "ZORRO")`
   JCE откажется его выдавать. Для прохождения этого шага нужен
   соответствующий сертификат и процедура запроса у Oracle.
2. **Свой PEN.** Замените корень OID-ов в `ZorroObjectIdentifiers.ROOT`
   на собственный, выданный IANA (https://pen.iana.org/).
3. **Производительность.** EC-арифметика реализована через `BigInteger`
   и double-and-add — это удобно читать, но медленно. Для нагруженных
   систем стоит перейти на проективные координаты или wNAF.
4. **Constant-time.** Текущий signer не constant-time (scalar mul зависит
   от битов `k`); для side-channel-резистентности нужна Montgomery ladder
   или constant-time wNAF.
5. **Запись PKCS#12.** Сейчас `ZorroPkcs12` поддерживает только чтение PFX.
   Для подписи запросов на сертификат и генерации ключей нужно реализовать
   `engineStore` и шифрование bag'ов.
