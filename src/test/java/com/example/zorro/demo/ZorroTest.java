package com.example.zorro.demo;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.crypto.HmacSha512;
import com.example.zorro.jcajce.provider.keys.GostKeyEncoding;
import com.example.zorro.jcajce.provider.keys.ZorroGostPrivateKey;
import com.example.zorro.jcajce.provider.keys.ZorroGostPublicKey;
import com.example.zorro.provider.ZorroProvider;
import com.example.zorro.util.ByteUtils;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

/**
 * Демонстрационный E2E-тест: загружаем казахстанский PFX, печатаем
 * подробный лог по всем алгоритмам провайдера ZORRO и устраиваем
 * кросс-проверку с KALKAN.
 *
 * <h2>Что проверяет</h2>
 * <ul>
 *   <li>Собственный SHA-512 даёт те же байты, что SunJCE.</li>
 *   <li>Собственный HMAC-SHA-512 совпадает с SunJCE HmacSHA512.</li>
 *   <li>ZORRO-PKCS12 читает реальный PFX от НУЦ РК (которого ни BC,
 *       ни openssl сами не разбирают).</li>
 *   <li>ZORRO-HASH-512 (Streebog-512) даёт тот же результат, что
 *       Kalkan {@code GOST3411-2015-512}.</li>
 *   <li>Подпись через ZORRO-SIGN-512 валидна как через ZORRO, так
 *       и через Kalkan (после конвертации формата).</li>
 *   <li>Подпись через Kalkan валидна через ZORRO.</li>
 *   <li>Изменённое сообщение отвергается.</li>
 *   <li>Поиск алгоритма по OID работает.</li>
 * </ul>
 *
 * <h2>Особенности</h2>
 * <ul>
 *   <li>{@code Mac.getInstance(... , "ZORRO")} тут не используется: JCE
 *       требует, чтобы JAR-провайдеров с Mac/Cipher был подписан Oracle.
 *       Корректность нашего HMAC-SHA-512 проверяется через прямой вызов
 *       {@link HmacSha512} и сравнение с SunJCE.</li>
 *   <li>Публичный ключ из сертификата извлекается через парсер SPKI
 *       ({@link GostKeyEncoding}), потому что JDK не знает казахстанские
 *       OID-ы и {@code cert.getPublicKey()} возвращает generic
 *       {@code X509Key}.</li>
 *   <li>ZORRO использует тот же формат подписи, что и Kalkan
 *       ({@code r_LE || s_LE}), поэтому подписи переходят между ними без
 *       преобразований. Реверс понадобился бы только при обмене с BC.</li>
 * </ul>
 */
class ZorroTest {

    @Test
    void complexTest() throws Exception {
        String p12Path  = "src/test/files/test.p12";
        char[] password = "Qwerty12".toCharArray();
        byte[] message  = "Hello from ZORRO provider".getBytes();

        // --- 1. Регистрируем оба провайдера: KALKAN (для кросс-проверки) и ZORRO
        if (Security.getProvider(KalkanProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new KalkanProvider());
        }
        if (Security.getProvider(ZorroProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new ZorroProvider());
        }
        line("ПРОВАЙДЕРЫ");
        for (Provider p : Security.getProviders()) {
            String mark = (p.getName().equals("ZORRO") || p.getName().equals("KALKAN"))
                    ? "  ★ " : "    ";
            System.out.println(mark + p.getName() + " v" + p.getVersionStr());
        }

        Provider zorro = Security.getProvider("ZORRO");
        line("АЛГОРИТМЫ ПРОВАЙДЕРА ZORRO");
        zorro.entrySet().stream()
                .map(e -> e.getKey().toString())
                .filter(k -> k.startsWith("MessageDigest.")
                        || k.startsWith("Signature.")
                        || k.startsWith("KeyStore.")
                        || k.startsWith("Mac."))
                .filter(k -> !k.contains(" "))
                .sorted()
                .forEach(k -> System.out.println("  " + k));

        // --- 1.5. Собственный SHA-512 (не зависит от Kalkan)
        line("СОБСТВЕННЫЙ ALG: ZORRO-SHA-512");
        MessageDigest sha = MessageDigest.getInstance("ZORRO-SHA-512", "ZORRO");
        sha.update(message);
        byte[] shaHash = sha.digest();
        System.out.println("  алгоритм:    " + sha.getAlgorithm());
        System.out.println("  digest hex:  " + ByteUtils.toHex(shaHash));
        MessageDigest shaRef = MessageDigest.getInstance("SHA-512");
        shaRef.update(message);
        byte[] refHash = shaRef.digest();
        boolean shaMatches = ByteUtils.constantTimeEquals(shaHash, refHash);
        System.out.println("  совпадает с SunJCE SHA-512: " + shaMatches
                + "   (доказывает, что наша реализация корректна)");

        // --- 1.6. Собственный HMAC-SHA-512 — через прямой вызов класса.
        // Через Mac.getInstance JCE отказывается работать, потому что
        // требует, чтобы JAR-провайдер с Mac был подписан Oracle. Корректность
        // алгоритма проверяется тут сравнением с SunJCE HmacSHA512.
        line("СОБСТВЕННЫЙ ALG: HMAC-SHA-512 (прямой вызов класса)");
        byte[] macKey = "secret-key-for-demo".getBytes();
        HmacSha512 ourMac = new HmacSha512();
        ourMac.init(macKey);
        ourMac.update(message, 0, message.length);
        byte[] ourMacBytes = ourMac.doFinal();
        System.out.println("  mac hex:     " + ByteUtils.toHex(ourMacBytes));
        javax.crypto.Mac refMac = javax.crypto.Mac.getInstance("HmacSHA512");
        refMac.init(new javax.crypto.spec.SecretKeySpec(macKey, "HmacSHA512"));
        refMac.update(message);
        byte[] refMacBytes = refMac.doFinal();
        boolean macMatches = ByteUtils.constantTimeEquals(ourMacBytes, refMacBytes);
        System.out.println("  совпадает с SunJCE HmacSHA512: " + macMatches
                + "  (доказывает корректность HMAC по RFC 2104)");

        // --- 2. Загрузка P12 через ZORRO-PKCS12
        line("ЗАГРУЗКА P12 ЧЕРЕЗ ZORRO-PKCS12");
        KeyStore ks = KeyStore.getInstance("ZORRO-PKCS12", "ZORRO");
        try (FileInputStream fis = new FileInputStream(p12Path)) {
            ks.load(fis, password);
        }
        String alias = null;
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) { alias = a; break; }
        }
        ZorroGostPrivateKey privateKey = (ZorroGostPrivateKey) ks.getKey(alias, password);
        X509Certificate x509 = (X509Certificate) ks.getCertificate(alias);

        // Публичный ключ — парсим SPKI напрямую: cert.getPublicKey() даст
        // generic X509Key, потому что JDK не знает казахстанский OID.
        ZorroGostPublicKey publicKey = GostKeyEncoding.parseSubjectPublicKeyInfo(
                x509.getPublicKey().getEncoded());

        System.out.println("  alias:        " + alias);
        System.out.println("  key class:    " + privateKey.getClass().getName());
        System.out.println("  cert subject: " + x509.getSubjectX500Principal());

        // Перевыпускаем ключ как Kalkan-native, чтобы делать им кросс-операции.
        KeyFactory kalkanKf = KeyFactory.getInstance("ECGOST3410-2015-512", "KALKAN");
        PrivateKey kalkanPriv = kalkanKf.generatePrivate(new PKCS8EncodedKeySpec(privateKey.getEncoded()));
        PublicKey  kalkanPub  = kalkanKf.generatePublic(new X509EncodedKeySpec(publicKey.getEncoded()));

        // --- 3. Хэш через ZORRO-HASH-512
        line("ХЭШ ЧЕРЕЗ ZORRO-HASH-512");
        MessageDigest md = MessageDigest.getInstance("ZORRO-HASH-512", "ZORRO");
        md.update(message);
        byte[] hash = md.digest();
        System.out.println("  алгоритм:    " + md.getAlgorithm());
        System.out.println("  провайдер:   " + md.getProvider().getName());
        System.out.println("  digest hex:  " + ByteUtils.toHex(hash));

        // Сверим: хэш через KALKAN-имя должен дать тот же результат
        MessageDigest mdKalkan = MessageDigest.getInstance("GOST3411-2015-512", "KALKAN");
        mdKalkan.update(message);
        byte[] hashKalkan = mdKalkan.digest();
        boolean hashMatches = ByteUtils.constantTimeEquals(hash, hashKalkan);
        System.out.println("  совпадает с KALKAN GOST3411-2015-512: " + hashMatches);

        // --- 4. Подпись через ZORRO-SIGN-512
        line("ПОДПИСЬ ЧЕРЕЗ ZORRO-SIGN-512");
        Signature signer = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        signer.initSign(privateKey);
        signer.update(message);
        byte[] signature = signer.sign();
        System.out.println("  алгоритм:       " + signer.getAlgorithm());
        System.out.println("  провайдер:      " + signer.getProvider().getName());
        System.out.println("  signature size: " + signature.length + " bytes");
        System.out.println("  signature hex:  " + ByteUtils.toHex(signature));

        // --- 5. Проверка через ZORRO
        line("ПРОВЕРКА ПОДПИСИ ЧЕРЕЗ ZORRO");
        Signature verifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        verifier.initVerify(publicKey);
        verifier.update(message);
        boolean validZorro = verifier.verify(signature);
        System.out.println("  валидна (ZORRO):  " + validZorro);

        // --- 6. Кросс-проверка: подпись ZORRO проверяется через KALKAN.
        // ZORRO выдаёт подпись в Kalkan-формате (r_LE || s_LE), поэтому
        // обмен идёт без конвертации.
        line("КРОСС-ПРОВЕРКА: ZORRO-подпись через KALKAN");
        Signature kalkanVerifier = Signature.getInstance("ECGOST3410-2015-512", "KALKAN");
        kalkanVerifier.initVerify(kalkanPub);
        kalkanVerifier.update(message);
        boolean validKalkan = kalkanVerifier.verify(signature);
        System.out.println("  валидна (KALKAN): " + validKalkan
                + "   (тот же формат подписи, что у Kalkan — без реверса)");

        // --- 7. Обратная кросс-проверка: подпись KALKAN проверяется через ZORRO
        line("КРОСС-ПРОВЕРКА: KALKAN-подпись через ZORRO");
        Signature kalkanSigner = Signature.getInstance("ECGOST3410-2015-512", "KALKAN");
        kalkanSigner.initSign(kalkanPriv);
        kalkanSigner.update(message);
        byte[] sigByKalkan = kalkanSigner.sign();
        System.out.println("  алгоритм подписи:  " + kalkanSigner.getAlgorithm());
        System.out.println("  провайдер:         " + kalkanSigner.getProvider().getName());
        System.out.println("  signature size:    " + sigByKalkan.length + " bytes");
        System.out.println("  signature hex:     " + ByteUtils.toHex(sigByKalkan));

        Signature zorroVerifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        zorroVerifier.initVerify(publicKey);
        zorroVerifier.update(message);
        boolean validKalkanSig = zorroVerifier.verify(sigByKalkan);
        System.out.println("  валидна (ZORRO):   " + validKalkanSig
                + "   (подпись KALKAN успешно проверяется ZORRO без преобразований)");

        // --- 8. Негативный тест
        line("НЕГАТИВНЫЙ ТЕСТ");
        byte[] tampered = message.clone();
        tampered[0] ^= 0x01;
        Signature negVerifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        negVerifier.initVerify(publicKey);
        negVerifier.update(tampered);
        boolean validTampered = negVerifier.verify(signature);
        System.out.println("  изменённое сообщение: " + validTampered
                + "   (должно быть false)");

        // --- 9. Поиск по OID
        line("ОБРАЩЕНИЕ ПО OID");
        Signature byOid = Signature.getInstance(
                ZorroObjectIdentifiers.ZORRO_SIGN_512, "ZORRO");
        System.out.println("  OID '" + ZorroObjectIdentifiers.ZORRO_SIGN_512
                + "' разрешился в: " + byOid.getAlgorithm());

        // --- ИТОГ
        line("ИТОГ");
        boolean allOk = shaMatches && macMatches && hashMatches && validZorro
                && validKalkan && validKalkanSig && !validTampered;
        if (allOk) {
            System.out.println("  ВСЁ ОК — провайдер ZORRO работает корректно:");
            System.out.println("   - собственный SHA-512 даёт правильные хэши;");
            System.out.println("   - собственный HMAC-SHA-512 даёт правильные MAC;");
            System.out.println("   - собственный Streebog-512 совпадает с эталоном Kalkan;");
            System.out.println("   - собственный ECGOST sign/verify совместим с Kalkan по криптографии.");
        } else {
            System.out.println("  ОШИБКА — проверьте вывод выше");
            org.junit.jupiter.api.Assertions.fail("E2E test did not pass all checks");
        }
    }

    private static void line(String title) {
        System.out.println();
        System.out.println("=== " + title + " "
                + "=".repeat(Math.max(0, 64 - title.length())));
    }
}
