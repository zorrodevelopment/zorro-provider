package com.example.zorro.demo;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.provider.ZorroProvider;
import com.example.zorro.util.ByteUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end проверка провайдера ZORRO с тестовым файлом
 * {@code src/test/files/test.p12}: загрузка PKCS#12, хэш Streebog,
 * подпись/проверка ECGOST3410-2012-512, кросс-совместимость с BC.
 *
 * <p>Регистрируем BouncyCastleProvider только потому, что он нужен для
 * {@link Signature#getInstance(String, Provider)} и
 * {@link MessageDigest#getInstance(String, Provider)} в кросс-проверках.
 * Сам ZORRO внутри использует BC как библиотеку, без обращения в JVM.
 */
class ZorroTest {

    @Test
    void complexTest() throws Exception {
        String p12Path  = "src/test/files/test.p12";
        char[] password = "Qwerty12".toCharArray();
        byte[] message  = "Hello from ZORRO provider".getBytes();

        // 1. Регистрируем оба провайдера: BC (для кросс-проверок) и ZORRO.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(ZorroProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new ZorroProvider());
        }
        line("ПРОВАЙДЕРЫ");
        for (Provider p : Security.getProviders()) {
            String mark = (p.getName().equals("ZORRO") || p.getName().equals("BC"))
                    ? "  * " : "    ";
            System.out.println(mark + p.getName() + " v" + p.getVersionStr());
        }

        Provider zorro = Security.getProvider("ZORRO");
        line("АЛГОРИТМЫ ПРОВАЙДЕРА ZORRO");
        zorro.entrySet().stream()
                .map(e -> e.getKey().toString())
                .filter(k -> k.startsWith("MessageDigest.")
                        || k.startsWith("Signature.")
                        || k.startsWith("Mac.")
                        || k.startsWith("KeyStore."))
                .filter(k -> !k.contains(" "))
                .sorted()
                .forEach(k -> System.out.println("  " + k));

        // 2. Собственный SHA-512 — сверяем с эталоном SunJCE.
        line("СОБСТВЕННЫЙ ALG: ZORRO-SHA-512");
        MessageDigest sha = MessageDigest.getInstance("ZORRO-SHA-512", "ZORRO");
        byte[] shaHash = sha.digest(message);
        byte[] refSha  = MessageDigest.getInstance("SHA-512").digest(message);
        System.out.println("  digest hex: " + ByteUtils.toHex(shaHash));
        assertTrue(ByteUtils.constantTimeEquals(shaHash, refSha),
                "ZORRO-SHA-512 должен совпадать с SunJCE SHA-512");

        // 3. Собственный HMAC-SHA-512 — сверяем с SunJCE HmacSHA512.
        line("СОБСТВЕННЫЙ ALG: ZORRO-HMACSHA512");
        byte[] macKey = "secret-key-for-demo".getBytes();
        javax.crypto.Mac zorroMac = javax.crypto.Mac.getInstance("ZORRO-HMACSHA512", "ZORRO");
        zorroMac.init(new javax.crypto.spec.SecretKeySpec(macKey, "ZORRO-HMACSHA512"));
        byte[] zorroMacBytes = zorroMac.doFinal(message);
        javax.crypto.Mac refMac = javax.crypto.Mac.getInstance("HmacSHA512");
        refMac.init(new javax.crypto.spec.SecretKeySpec(macKey, "HmacSHA512"));
        byte[] refMacBytes = refMac.doFinal(message);
        System.out.println("  mac hex:    " + ByteUtils.toHex(zorroMacBytes));
        assertTrue(ByteUtils.constantTimeEquals(zorroMacBytes, refMacBytes),
                "ZORRO-HMACSHA512 должен совпадать с SunJCE HmacSHA512");

        // 4. Загрузка P12 через ZORRO-PKCS12 (наш SPI, BC только как библиотека).
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
        assertNotNull(alias, "В test.p12 должен быть key entry");
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password);
        Certificate cert = ks.getCertificate(alias);
        assertTrue(cert instanceof X509Certificate, "ожидается X.509");
        X509Certificate x509 = (X509Certificate) cert;
        PublicKey publicKey = x509.getPublicKey();
        System.out.println("  alias:        " + alias);
        System.out.println("  key class:    " + privateKey.getClass().getName());
        System.out.println("  cert subject: " + x509.getSubjectX500Principal());

        // 5. Хэш через ZORRO-HASH-512 — сверяем с BC GOST3411-2012-512.
        line("ХЭШ ЧЕРЕЗ ZORRO-HASH-512");
        MessageDigest md = MessageDigest.getInstance("ZORRO-HASH-512", "ZORRO");
        byte[] hash = md.digest(message);
        MessageDigest mdBc = MessageDigest.getInstance("GOST3411-2012-512", "BC");
        byte[] hashBc = mdBc.digest(message);
        System.out.println("  digest hex:  " + ByteUtils.toHex(hash));
        assertTrue(ByteUtils.constantTimeEquals(hash, hashBc),
                "ZORRO-HASH-512 должен совпадать с BC GOST3411-2012-512");

        // 6. Подпись через ZORRO-SIGN-512.
        line("ПОДПИСЬ ЧЕРЕЗ ZORRO-SIGN-512");
        Signature signer = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        signer.initSign(privateKey);
        signer.update(message);
        byte[] signature = signer.sign();
        System.out.println("  signature size: " + signature.length + " bytes");
        System.out.println("  signature hex:  " + ByteUtils.toHex(signature));
        assertEquals(128, signature.length, "ECGOST-2012-512 даёт 128 байт");

        // 7. Проверка через ZORRO.
        line("ПРОВЕРКА ПОДПИСИ ЧЕРЕЗ ZORRO");
        Signature verifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        verifier.initVerify(publicKey);
        verifier.update(message);
        boolean validZorro = verifier.verify(signature);
        System.out.println("  валидна (ZORRO): " + validZorro);
        assertTrue(validZorro);

        // 8. Кросс-проверка: подпись ZORRO проверяется через BC.
        line("КРОСС-ПРОВЕРКА: ZORRO -> BC");
        Signature bcVerifier = Signature.getInstance("ECGOST3410-2012-512", "BC");
        bcVerifier.initVerify(publicKey);
        bcVerifier.update(message);
        boolean validBc = bcVerifier.verify(signature);
        System.out.println("  валидна (BC):    " + validBc);
        assertTrue(validBc, "формат подписи должен быть совместим с BC");

        // 9. Обратная кросс-проверка: подпись BC проверяется через ZORRO.
        line("КРОСС-ПРОВЕРКА: BC -> ZORRO");
        Signature bcSigner = Signature.getInstance("ECGOST3410-2012-512", "BC");
        bcSigner.initSign(privateKey);
        bcSigner.update(message);
        byte[] sigByBc = bcSigner.sign();
        Signature zorroVerifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        zorroVerifier.initVerify(publicKey);
        zorroVerifier.update(message);
        boolean validReverse = zorroVerifier.verify(sigByBc);
        System.out.println("  BC-подпись валидна через ZORRO: " + validReverse);
        assertTrue(validReverse);

        // 10. Негативный тест.
        line("НЕГАТИВНЫЙ ТЕСТ");
        byte[] tampered = message.clone();
        tampered[0] ^= 0x01;
        Signature negVerifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        negVerifier.initVerify(publicKey);
        negVerifier.update(tampered);
        boolean validTampered = negVerifier.verify(signature);
        System.out.println("  изменённое сообщение: " + validTampered + " (должно быть false)");
        assertFalse(validTampered);

        // 11. Поиск по OID.
        line("ОБРАЩЕНИЕ ПО OID");
        Signature byOid = Signature.getInstance(
                ZorroObjectIdentifiers.ZORRO_SIGN_512, "ZORRO");
        System.out.println("  OID '" + ZorroObjectIdentifiers.ZORRO_SIGN_512
                + "' разрешился в: " + byOid.getAlgorithm());

        line("ИТОГ");
        System.out.println("  ВСЁ ОК — ZORRO работает на собственном SHA/HMAC и");
        System.out.println("  на BC-примитивах для Streebog/ECGOST/PKCS12.");
    }

    private static void line(String title) {
        System.out.println();
        System.out.println("=== " + title + " "
                + "=".repeat(Math.max(0, 64 - title.length())));
    }
}
