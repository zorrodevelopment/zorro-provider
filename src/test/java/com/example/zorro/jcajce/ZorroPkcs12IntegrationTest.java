package com.example.zorro.jcajce;

import com.example.zorro.crypto.ec.EcCurveParams;
import com.example.zorro.crypto.ec.EcPoint;
import com.example.zorro.jcajce.provider.keys.GostKeyEncoding;
import com.example.zorro.jcajce.provider.keys.ZorroGostPrivateKey;
import com.example.zorro.jcajce.provider.keys.ZorroGostPublicKey;
import com.example.zorro.provider.ZorroProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Интеграционный тест на реальном PFX от НУЦ РК. Проверяет, что
 * ZORRO-PKCS12 может загрузить казахстанский сертификат с OID
 * {@code 1.2.398.3.10.1.1.2.2}, который BC и openssl самостоятельно
 * загрузить не могут.
 */
class ZorroPkcs12IntegrationTest {

    private static final String P12_PATH = "src/test/files/test.p12";
    private static final char[] PASSWORD = "Qwerty12".toCharArray();

    @BeforeAll
    static void setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(ZorroProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new ZorroProvider());
        }
    }

    @Test
    void loadKzCertificate() throws Exception {
        KeyStore ks = KeyStore.getInstance("ZORRO-PKCS12", "ZORRO");
        try (FileInputStream fis = new FileInputStream(P12_PATH)) {
            ks.load(fis, PASSWORD);
        }
        String alias = firstKeyAlias(ks);
        assertNotNull(alias);

        ZorroGostPrivateKey pk = (ZorroGostPrivateKey) ks.getKey(alias, PASSWORD);
        assertNotNull(pk);
        assertEquals("ECGOST3410-2012-512", pk.getAlgorithm());

        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        assertNotNull(cert);

        // Subject содержит казахские атрибуты — главное что объект загрузился.
        String subject = cert.getSubjectX500Principal().toString();
        assertTrue(subject.contains("IIN") || subject.contains("SERIALNUMBER"),
                "subject должен содержать IIN: " + subject);
    }

    /**
     * Ключевой инвариант: {@code d·G = Q}. Если он выполняется, значит
     * {@code d} декодирован с правильным endian-преобразованием, а
     * публичная точка {@code Q} соответствует тому же ключу.
     */
    @Test
    void privateKeyMatchesPublicKeyFromCert() throws Exception {
        KeyStore ks = KeyStore.getInstance("ZORRO-PKCS12", "ZORRO");
        try (FileInputStream fis = new FileInputStream(P12_PATH)) {
            ks.load(fis, PASSWORD);
        }
        String alias = firstKeyAlias(ks);
        ZorroGostPrivateKey pk = (ZorroGostPrivateKey) ks.getKey(alias, PASSWORD);

        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        // cert.getPublicKey() возвращает sun.security.x509.X509Key — generic;
        // его getEncoded() даёт нам сырой SPKI.
        byte[] spki = cert.getPublicKey().getEncoded();
        ZorroGostPublicKey pub = GostKeyEncoding.parseSubjectPublicKeyInfo(spki);

        EcCurveParams curve = pk.getCurveParams();
        assertSame(curve, pub.getCurveParams(),
                "ключи должны быть на одной кривой");

        EcPoint computedQ = curve.G.multiply(pk.getS());
        assertEquals(pub.getQ(), computedQ,
                "d·G должно совпадать с Q из сертификата — иначе перепутан endian");
    }

    @Test
    void wrongPasswordRejected() {
        try (FileInputStream fis = new FileInputStream(P12_PATH)) {
            KeyStore ks = KeyStore.getInstance("ZORRO-PKCS12", "ZORRO");
            ks.load(fis, "wrong".toCharArray());
            org.junit.jupiter.api.Assertions.fail("должно было упасть из-за MAC-проверки");
        } catch (Exception e) {
            // Любая ошибка означает что неверный пароль отвергнут.
            assertNotNull(e);
        }
    }

    @Test
    void signWithLoadedKeyAndVerifyByZorro() throws Exception {
        KeyStore ks = KeyStore.getInstance("ZORRO-PKCS12", "ZORRO");
        try (FileInputStream fis = new FileInputStream(P12_PATH)) {
            ks.load(fis, PASSWORD);
        }
        String alias = firstKeyAlias(ks);
        ZorroGostPrivateKey pk = (ZorroGostPrivateKey) ks.getKey(alias, PASSWORD);

        // Публичный ключ из сертификата — парсим SPKI напрямую,
        // потому что cert.getPublicKey() возвращает generic X509Key.
        byte[] spki = ((X509Certificate) ks.getCertificate(alias))
                .getPublicKey().getEncoded();
        PublicKey pub = GostKeyEncoding.parseSubjectPublicKeyInfo(spki);

        byte[] msg = "End-to-end through ZORRO-PKCS12 + ZORRO-SIGN-512".getBytes();

        Signature signer = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        signer.initSign(pk);
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        verifier.initVerify(pub);
        verifier.update(msg);
        assertTrue(verifier.verify(sig));

        // Подмена сообщения → отказ.
        Signature neg = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        neg.initVerify(pub);
        neg.update("tampered".getBytes());
        assertFalse(neg.verify(sig));
    }

    private static String firstKeyAlias(KeyStore ks) throws Exception {
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) return a;
        }
        return null;
    }
}
