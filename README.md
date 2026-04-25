# ZORRO — пример собственного JCE-провайдера

Демонстрационный криптопровайдер `ZORRO`. Регистрируется в JVM
наряду с любыми другими провайдерами (Sun, BouncyCastle), даёт
собственные имена алгоритмов и собственные OID-ы. Часть алгоритмов
полностью самостоятельная, часть собрана из low-level примитивов
BouncyCastle (digest, signer, ASN.1) — то есть BC выступает как
библиотека, а не как делегируемый JCE-провайдер.

```
java.security.Security
   ├── SunJCE
   ├── BC              (org.bouncycastle.jce.provider.BouncyCastleProvider)
   └── ZORRO           (com.example.zorro.provider.ZorroProvider)
                            ↓ использует как библиотеку
                          BouncyCastle
```

## Зачем такой провайдер нужен

1. **Свой brand и OID-пространство.** Если вы строите PKI или подписной
   сервис, у вашей компании должны быть собственные OID для расширений
   сертификатов, политик подписи и т.д.
2. **Развязка бизнес-кода от backend-библиотеки.** Завтра вместо BC
   можно подложить другой источник примитивов, а имена алгоритмов
   `ZORRO-*` останутся теми же.
3. **Аудит и контроль.** Провайдер может логировать вызовы, проверять
   политику использования ключей, добавлять hardware-token слой и т.д.
4. **Учить и тестировать.** Проще всего понять архитектуру JCE,
   написав свой провайдер.

## Структура

```
zorro-provider/
├── pom.xml
├── src/main/java/com/example/zorro/
│   ├── provider/
│   │   ├── ZorroProvider.java                 главный класс, регистрируется в JVM
│   │   └── AlgorithmModule.java               интерфейс плагина
│   ├── jcajce/provider/
│   │   ├── digest/
│   │   │   ├── ZorroSha512.java               MessageDigestSpi → собственный SHA-512
│   │   │   └── ZorroHash512.java              MessageDigestSpi → BC GOST3411_2012_512Digest
│   │   ├── mac/
│   │   │   └── ZorroHmacSha512.java           MacSpi → собственный HMAC-SHA-512
│   │   ├── signature/
│   │   │   └── ZorroSign512.java              SignatureSpi → BC ECGOST3410_2012Signer
│   │   ├── asymmetric/
│   │   │   └── ZorroKalkanGostKeyFactory.java KeyFactorySpi: казахские OID → BC
│   │   └── keystore/
│   │       └── ZorroPkcs12.java               KeyStoreSpi: собственный PKCS#12 reader
│   ├── asn1/
│   │   ├── ZorroObjectIdentifiers.java        OID-ы провайдера
│   │   └── KalkanObjectIdentifiers.java       OID-ы Kalkan + соответствия Tc26
│   ├── crypto/
│   │   ├── Sha512.java                        FIPS 180-4
│   │   └── HmacSha512.java                    RFC 2104
│   └── util/
│       └── ByteUtils.java                     hex/BE-LE/constant-time
└── src/test/
    ├── files/test.p12                         тестовый GOST-2012 ключ от Kalkan
    └── java/com/example/zorro/demo/
        └── ZorroTest.java                     end-to-end проверка
```

## Зарегистрированные алгоритмы

| Имя                  | Тип            | Источник                          |
|----------------------|----------------|-----------------------------------|
| `ZORRO-SHA-512`      | MessageDigest  | **собственная** (FIPS 180-4)      |
| `ZORRO-HMACSHA512`   | Mac            | **собственная** (RFC 2104)        |
| `ZORRO-HASH-512`     | MessageDigest  | BC `GOST3411_2012_512Digest`      |
| `ZORRO-SIGN-512`     | Signature      | BC `ECGOST3410_2012Signer` + Streebog |
| `ZORRO-PKCS12`       | KeyStore       | **собственный** парсер PFX через BC ASN.1 |
| `GOST3410-2015-512`  | KeyFactory     | транслятор Kalkan OID → BC OID    |

Каждый алгоритм имеет собственный OID в дереве `1.3.6.1.4.1.99999.*`
(в production получите свой PEN на [pen.iana.org](https://pen.iana.org/)).

## Как именно ZORRO «не обёртка»

**Hash и Signature** не делегируют через `MessageDigest.getInstance(..., "BC")`
или `Signature.getInstance(..., "BC")`. SPI-классы создают low-level
объекты BC напрямую и сами вызывают их методы. Между нашим SPI и BC нет
JCE-слоя — всё работает на уровне обычной библиотечной зависимости.

**ZORRO-SIGN-512** сам выполняет хэширование Streebog-512, сам формирует
ECGOST подпись через `ECGOST3410_2012Signer.generateSignature(hash)`,
сам сериализует `(s, r)` в 128 байт по ГОСТ Р 34.10-2012 §6.1.

**ZORRO-PKCS12** — полностью самописный `KeyStoreSpi`. Парсит PFX
через BC ASN.1 helpers (`Pfx`, `AuthenticatedSafe`, `SafeBag`),
проверяет HMAC-SHA1 MAC через PKCS#12 KDF (RFC 7292 §B.2),
дешифрует PBE-оболочки через `Cipher`, конструирует ключи через наш
KeyFactory-транслятор. Стандартный BC `PKCS12KeyStoreSpi` — не используется.

## Особенность: чтение Kalkan-овского P12

Тестовый файл `src/test/files/test.p12` сгенерирован Kalkan и содержит
ECGOST3410-2012-512 ключ с **казахскими** OID-ами (ветка `1.2.398.3.10.*`),
которых нет в стандартной поставке BouncyCastle. ZORRO решает это через
два механизма:

1. **`ZorroKalkanGostKeyFactory`** регистрируется в JVM как `KeyFactory`
   под казахским OID `1.2.398.3.10.1.1.2.2`. На лету переписывает PKCS#8 /
   SPKI с казахских OID на Tc26-known (`1.2.643.7.1.1.1.2`,
   `1.2.643.7.1.2.1.2.1` для `paramSetA`) и делегирует BC.
2. Тот же транслятор регистрируется в **внутреннем** реестре
   `BouncyCastleProvider.addKeyInfoConverter(...)`, чтобы
   `X509Certificate.getPublicKey()` для казахских сертификатов
   возвращал правильный объект (BC использует свой статический
   реестр, минуя JCA-lookup).

D в файле хранится как big-endian внутри OCTET STRING — что соответствует
тому, как BC ожидает byte-input для `BCECGOST3410_2012PrivateKey`.
Параметры кривой Kalkan paramSet'а по значению совпадают с Tc26 paramSetA.

## Сборка и запуск

Нужны: JDK 17+, Maven, доступ в Maven Central.

```bash
mvn clean test
```

Тест `ZorroTest.complexTest()` показывает:
- собственный SHA-512 совпадает с SunJCE SHA-512;
- собственный HMAC-SHA-512 совпадает с SunJCE HmacSHA512;
- `ZORRO-PKCS12` грузит test.p12 (с казахскими OID-ами);
- `ZORRO-HASH-512` совпадает с BC GOST3411-2012-512;
- подпись `ZORRO-SIGN-512` валидна и через ZORRO, и через BC;
- BC-овская подпись валидна через ZORRO;
- негативный тест ловит изменённое сообщение;
- поиск алгоритма по OID работает.

## Как добавить ещё один алгоритм

1. Создайте класс, наследующий `MessageDigestSpi`, `SignatureSpi`,
   `KeyStoreSpi`, `MacSpi`, `KeyPairGeneratorSpi`, `CipherSpi` и т.д.
2. Внутри сделайте вложенный класс `Mappings implements AlgorithmModule`,
   который кладёт mapping'и в provider.
3. Допишите имя класса `Mappings` в массив `MODULES`
   в `ZorroProvider.java`.

## Что осталось «настоящей» подписью провайдера

Для production-провайдера, который будет работать с *Cipher*-алгоритмами
типа AES, нужна подпись JAR-файла специальным сертификатом от Oracle
(JCE Code Signing CA). Без этой подписи Cipher-engine откажется работать.
Для `MessageDigest`, `Signature`, `KeyStore`, `Mac`, `KeyPairGenerator`,
`KeyFactory` — **подпись не требуется**. Этот пример включает только
последние, поэтому работает без специальной подписи.
