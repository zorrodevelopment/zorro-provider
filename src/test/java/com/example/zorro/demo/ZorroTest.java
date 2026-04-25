package com.example.zorro.demo;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.provider.ZorroProvider;
import com.example.zorro.util.ByteUtils;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * Демонстрация работы провайдера ZORRO с тем же тестовым P12,
 * что и в {@code KalkanDemo}, но через собственные имена алгоритмов:
 * <pre>
 *   KeyStore.getInstance("ZORRO-PKCS12", "ZORRO")
 *   MessageDigest.getInstance("ZORRO-HASH-512", "ZORRO")
 *   Signature.getInstance("ZORRO-SIGN-512", "ZORRO")
 * </pre>
 *
 * <h2>Дополнительно проверяет</h2>
 * Подпись, сделанная через ZORRO, валидна также при проверке через KALKAN
 * (и наоборот) — потому что внутри это один и тот же алгоритм.
 * Это доказывает, что ZORRO не «переизобретает», а корректно
 * перекладывает работу на backend.
 */
class ZorroTest {

    @Disabled
    @Test
    void complexTest() throws Exception {
        String p12Path  = "src/test/files/test.p12";
        char[] password = "Qwerty12".toCharArray();
        byte[] message  = "Hello from ZORRO provider".getBytes();

        // --- 1. Регистрируем оба провайдера: KALKAN (backend) и ZORRO
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
                        || k.startsWith("KeyStore."))
                .filter(k -> !k.contains(" "))   // без атрибутов вроде "SupportedKeyClasses"
                .sorted()
                .forEach(k -> System.out.println("  " + k));

        // --- 1.5. Собственный SHA-512 (не зависит от Kalkan)
        line("СОБСТВЕННЫЙ ALG: ZORRO-SHA-512");
        MessageDigest sha = MessageDigest.getInstance("ZORRO-SHA-512", "ZORRO");
        sha.update(message);
        byte[] shaHash = sha.digest();
        System.out.println("  алгоритм:    " + sha.getAlgorithm());
        System.out.println("  digest hex:  " + ByteUtils.toHex(shaHash));
        // Сверяем с эталоном из SunJCE
        MessageDigest shaRef = MessageDigest.getInstance("SHA-512");
        shaRef.update(message);
        byte[] refHash = shaRef.digest();
        boolean shaMatches = ByteUtils.constantTimeEquals(shaHash, refHash);
        System.out.println("  совпадает с SunJCE SHA-512: " + shaMatches
                + "   (доказывает, что наша реализация корректна)");

        // --- 1.6. Собственный HMAC-SHA-512
        line("СОБСТВЕННЫЙ ALG: ZORRO-HMACSHA512");
        byte[] macKey = "secret-key-for-demo".getBytes();
        javax.crypto.Mac zorroMac = javax.crypto.Mac.getInstance("ZORRO-HMACSHA512", "ZORRO");
        zorroMac.init(new javax.crypto.spec.SecretKeySpec(macKey, "ZORRO-HMACSHA512"));
        zorroMac.update(message);
        byte[] zorroMacBytes = zorroMac.doFinal();
        System.out.println("  алгоритм:    " + zorroMac.getAlgorithm());
        System.out.println("  mac hex:     " + ByteUtils.toHex(zorroMacBytes));
        // Сверяем с эталоном HmacSHA512 из SunJCE
        javax.crypto.Mac refMac = javax.crypto.Mac.getInstance("HmacSHA512");
        refMac.init(new javax.crypto.spec.SecretKeySpec(macKey, "HmacSHA512"));
        refMac.update(message);
        byte[] refMacBytes = refMac.doFinal();
        boolean macMatches = ByteUtils.constantTimeEquals(zorroMacBytes, refMacBytes);
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
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password);
        Certificate cert = ks.getCertificate(alias);
        if (!(cert instanceof X509Certificate)) {
            throw new IllegalStateException("Ожидался X.509 сертификат");
        }
        X509Certificate x509 = (X509Certificate) cert;
        PublicKey publicKey = x509.getPublicKey();
        System.out.println("  alias:        " + alias);
        System.out.println("  key class:    " + privateKey.getClass().getName());
        System.out.println("  cert subject: " + x509.getSubjectX500Principal());

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

        // --- 6. Кросс-проверка: подпись ZORRO проверяется через KALKAN
        line("КРОСС-ПРОВЕРКА: ZORRO-подпись через KALKAN");
        Signature kalkanVerifier = Signature.getInstance("ECGOST3410-2015-512", "KALKAN");
        kalkanVerifier.initVerify(publicKey);
        kalkanVerifier.update(message);
        boolean validKalkan = kalkanVerifier.verify(signature);
        System.out.println("  валидна (KALKAN): " + validKalkan
                + "   (доказывает, что мы не «переизобрели» формат)");

        // --- 7. Обратная кросс-проверка: подпись KALKAN проверяется через ZORRO
        line("КРОСС-ПРОВЕРКА: KALKAN-подпись через ZORRO");
        Signature kalkanSigner = Signature.getInstance("ECGOST3410-2015-512", "KALKAN");
        kalkanSigner.initSign(privateKey);
        kalkanSigner.update(message);
        byte[] sigByKalkan = kalkanSigner.sign();
        System.out.println("  алгоритм подписи:  " + kalkanSigner.getAlgorithm());
        System.out.println("  провайдер:         " + kalkanSigner.getProvider().getName());
        System.out.println("  signature size:    " + sigByKalkan.length + " bytes");
        System.out.println("  signature hex:     " + ByteUtils.toHex(sigByKalkan));

        Signature zorroVerifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        zorroVerifier.initVerify(publicKey);
        zorroVerifier.update(message);
        boolean validReverse = zorroVerifier.verify(sigByKalkan);
        System.out.println("  валидна (ZORRO):   " + validReverse
                + "   (подпись KALKAN успешно проверяется ZORRO)");

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
                && validKalkan && validReverse && !validTampered;
        if (allOk) {
            System.out.println("  ВСЁ ОК — провайдер ZORRO работает корректно:");
            System.out.println("   - собственный SHA-512 даёт правильные хэши;");
            System.out.println("   - собственный HMAC-SHA-512 даёт правильные MAC;");
            System.out.println("   - обёртки над KALKAN совместимы по формату.");
        } else {
            System.out.println("  ОШИБКА — проверьте вывод выше");
            System.exit(1);
        }
    }

    private static void line(String title) {
        System.out.println();
        System.out.println("=== " + title + " "
                + "=".repeat(Math.max(0, 64 - title.length())));
    }
}
