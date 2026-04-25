package com.example.zorro.jcajce;

import com.example.zorro.jcajce.provider.keys.GostKeyEncoding;
import com.example.zorro.jcajce.provider.keys.ZorroGostPrivateKey;
import com.example.zorro.jcajce.provider.keys.ZorroGostPublicKey;
import com.example.zorro.provider.ZorroProvider;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Перекрёстные тесты совместимости трёх провайдеров: ZORRO, BC, KALKAN.
 *
 * <p>Один и тот же ключ из {@code test.p12} (НУЦ РК) подаётся в каждый
 * провайдер: ZORRO загружает p12 напрямую, дальше через {@code KeyFactory}
 * приватный/публичный ключи перевыпускаются в native-форму KALKAN и BC.
 * Затем все шесть пар "подписать в X — проверить в Y" должны срабатывать
 * (математика везде одна и та же; различия — только в OID и обёртках).
 *
 * <p>Если какая-то пара не работает, это указывает на bug в обёртке (типа
 * формата подписи или порядке байт), а не в самой криптографии.
 */
class KalkanCrossTest {

    private static final String P12_PATH = "src/test/files/test.p12";
    private static final char[] PASSWORD = "Qwerty12".toCharArray();

    @BeforeAll
    static void setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(KalkanProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new KalkanProvider());
        }
        if (Security.getProvider(ZorroProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new ZorroProvider());
        }
    }

    /** Bundle всех трёх «образов» одного и того же ключа. */
    private static final class Keys {
        PrivateKey zorroPriv, bcPriv, kalkanPriv;
        PublicKey  zorroPub,  bcPub,  kalkanPub;
    }

    private Keys loadKeys() throws Exception {
        // 1. Загружаем p12 нашим ZORRO — это единственный из трёх, кто умеет
        //    разобрать казахстанскую обёртку без подпиливаний.
        KeyStore zorroKs = KeyStore.getInstance("ZORRO-PKCS12", "ZORRO");
        try (FileInputStream fis = new FileInputStream(P12_PATH)) {
            zorroKs.load(fis, PASSWORD);
        }
        String alias = firstKeyAlias(zorroKs);

        ZorroGostPrivateKey zPriv = (ZorroGostPrivateKey) zorroKs.getKey(alias, PASSWORD);
        X509Certificate cert = (X509Certificate) zorroKs.getCertificate(alias);
        ZorroGostPublicKey zPub = GostKeyEncoding.parseSubjectPublicKeyInfo(
                cert.getPublicKey().getEncoded());

        Keys k = new Keys();
        k.zorroPriv = zPriv;
        k.zorroPub  = zPub;

        // 2. Перевыпускаем как KALKAN-ключ. ZORRO кодирует в "родной" казахской
        //    форме, поэтому Kalkan KeyFactory принимает напрямую.
        KeyFactory kf = KeyFactory.getInstance("ECGOST3410-2015-512", "KALKAN");
        k.kalkanPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(zPriv.getEncoded()));
        k.kalkanPub  = kf.generatePublic(new X509EncodedKeySpec(zPub.getEncoded()));

        // 3. Перевыпускаем как BC-ключ. BC не знает казахских OID-ов, поэтому
        //    клонируем ключи в "русской" обёртке: алгоритм
        //    1.2.643.7.1.1.1.2 + paramSet 1.2.643.7.1.2.1.2.1 (paramSetA, та же
        //    математика).
        ZorroGostPrivateKey ru = new ZorroGostPrivateKey(
                zPriv.getS(), zPriv.getCurveParams(),
                ZorroGostPrivateKey.ALG_OID_RU, "1.2.643.7.1.2.1.2.1",
                ZorroGostPrivateKey.HASH_OID_RU);
        ZorroGostPublicKey  ruPub = new ZorroGostPublicKey(
                zPub.getQ(), zPub.getCurveParams(),
                ZorroGostPrivateKey.ALG_OID_RU, "1.2.643.7.1.2.1.2.1",
                ZorroGostPrivateKey.HASH_OID_RU);
        KeyFactory bckf = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        k.bcPriv = bckf.generatePrivate(new PKCS8EncodedKeySpec(ru.getEncoded()));
        k.bcPub  = bckf.generatePublic(new X509EncodedKeySpec(ruPub.getEncoded()));

        return k;
    }

    // ===== Шесть кросс-проверок =====

    @Test void zorroSignBcVerify()     throws Exception { check("ZORRO-SIGN-512","ZORRO",  "ECGOST3410-2012-512","BC"); }
    @Test void zorroSignKalkanVerify() throws Exception { check("ZORRO-SIGN-512","ZORRO",  "ECGOST3410-2015-512","KALKAN"); }
    @Test void bcSignZorroVerify()     throws Exception { check("ECGOST3410-2012-512","BC", "ZORRO-SIGN-512","ZORRO"); }
    @Test void bcSignKalkanVerify()    throws Exception { check("ECGOST3410-2012-512","BC", "ECGOST3410-2015-512","KALKAN"); }
    @Test void kalkanSignZorroVerify() throws Exception { check("ECGOST3410-2015-512","KALKAN", "ZORRO-SIGN-512","ZORRO"); }
    @Test void kalkanSignBcVerify()    throws Exception { check("ECGOST3410-2015-512","KALKAN", "ECGOST3410-2012-512","BC"); }

    /**
     * Подписывает первым ({@code signAlg/signProv}), проверяет вторым.
     *
     * <p>ZORRO и Kalkan используют один формат подписи:
     * {@code r_LE(64) || s_LE(64)} (казахстанская конвенция).
     * BouncyCastle использует {@code s_BE(64) || r_BE(64)} — это побайтный
     * реверс нашего формата. При пересечении границы BC ↔ {ZORRO, Kalkan}
     * достаточно перевернуть весь массив байт; ZORRO ↔ Kalkan обмениваются
     * подписями без преобразования.
     */
    private void check(String signAlg, String signProv,
                       String verifyAlg, String verifyProv) throws Exception {
        Keys k = loadKeys();
        byte[] msg = ("Cross-test " + signProv + "->" + verifyProv).getBytes();

        Signature signer = Signature.getInstance(signAlg, signProv);
        signer.initSign(pickPriv(k, signProv));
        signer.update(msg);
        byte[] sig = signer.sign();

        sig = convertSigFormat(sig, signProv, verifyProv);

        Signature verifier = Signature.getInstance(verifyAlg, verifyProv);
        verifier.initVerify(pickPub(k, verifyProv));
        verifier.update(msg);
        assertTrue(verifier.verify(sig),
                signProv + " подписал — " + verifyProv + " не смог проверить");
    }

    private static byte[] convertSigFormat(byte[] sig, String fromProv, String toProv) {
        boolean fromBc = "BC".equals(fromProv);
        boolean toBc   = "BC".equals(toProv);
        if (fromBc == toBc) return sig;
        return reverseBytes(sig);
    }

    private static byte[] reverseBytes(byte[] a) {
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++) r[i] = a[a.length - 1 - i];
        return r;
    }

    private static PrivateKey pickPriv(Keys k, String prov) {
        switch (prov) {
            case "ZORRO":  return k.zorroPriv;
            case "BC":     return k.bcPriv;
            case "KALKAN": return k.kalkanPriv;
            default: throw new IllegalArgumentException(prov);
        }
    }

    private static PublicKey pickPub(Keys k, String prov) {
        switch (prov) {
            case "ZORRO":  return k.zorroPub;
            case "BC":     return k.bcPub;
            case "KALKAN": return k.kalkanPub;
            default: throw new IllegalArgumentException(prov);
        }
    }

    private static String firstKeyAlias(KeyStore ks) throws Exception {
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) return a;
        }
        return null;
    }
}
