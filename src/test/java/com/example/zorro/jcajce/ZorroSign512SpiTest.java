package com.example.zorro.jcajce;

import com.example.zorro.provider.ZorroProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Интеграционный тест: ZORRO-SIGN-512 через JCA-фасад.
 *
 * <p>Ключ генерируется BC на кривой Tc26-Gost-3410-12-512-paramSetA. Подпись
 * создаётся и проверяется через {@code Signature.getInstance("ZORRO-SIGN-512", "ZORRO")}.
 * Дополнительно проверяется кросс-совместимость: подпись BC валидна для ZORRO,
 * подпись ZORRO валидна для BC.
 */
class ZorroSign512SpiTest {

    @BeforeAll
    static void setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(ZorroProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new ZorroProvider());
        }
    }

    private KeyPair generateKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(
                "Tc26-Gost-3410-12-512-paramSetA");
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    @Test
    void zorroSignZorroVerify() throws Exception {
        KeyPair kp = generateKey();
        byte[] msg = "Sign me with ZORRO".getBytes();

        Signature signer = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(sig));
    }

    @Test
    void zorroSignVerifiedByBC() throws Exception {
        KeyPair kp = generateKey();
        byte[] msg = "Cross-check ZORRO→BC".getBytes();

        Signature signer = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        // ZORRO формат: r_LE||s_LE (как у Kalkan). BC ждёт s_BE||r_BE,
        // то есть полный реверс байт.
        Signature bcVerifier = Signature.getInstance("ECGOST3410-2012-512", "BC");
        bcVerifier.initVerify(kp.getPublic());
        bcVerifier.update(msg);
        assertTrue(bcVerifier.verify(reverseBytes(sig)),
                "BC должен принимать подпись, созданную ZORRO (после реверса формата)");
    }

    @Test
    void bcSignVerifiedByZorro() throws Exception {
        KeyPair kp = generateKey();
        byte[] msg = "Cross-check BC→ZORRO".getBytes();

        Signature bcSigner = Signature.getInstance("ECGOST3410-2012-512", "BC");
        bcSigner.initSign(kp.getPrivate());
        bcSigner.update(msg);
        byte[] sig = bcSigner.sign();

        Signature verifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(reverseBytes(sig)),
                "ZORRO должен принимать подпись BC после реверса формата");
    }

    private static byte[] reverseBytes(byte[] a) {
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++) r[i] = a[a.length - 1 - i];
        return r;
    }

    @Test
    void tamperedMessageRejected() throws Exception {
        KeyPair kp = generateKey();
        byte[] msg = "Original".getBytes();

        Signature signer = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        verifier.initVerify(kp.getPublic());
        verifier.update("Tampered".getBytes());
        assertFalse(verifier.verify(sig));
    }

    @Test
    void wrongKeyRejected() throws Exception {
        KeyPair kp1 = generateKey();
        KeyPair kp2 = generateKey();
        byte[] msg = "Original".getBytes();

        Signature signer = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        signer.initSign(kp1.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("ZORRO-SIGN-512", "ZORRO");
        verifier.initVerify(kp2.getPublic());
        verifier.update(msg);
        assertFalse(verifier.verify(sig));
    }

    @Test
    void initVerifyByOidAlias() throws Exception {
        KeyPair kp = generateKey();
        byte[] msg = "OID lookup".getBytes();

        Signature signer = Signature.getInstance(
                com.example.zorro.asn1.ZorroObjectIdentifiers.ZORRO_SIGN_512, "ZORRO");
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(
                com.example.zorro.asn1.ZorroObjectIdentifiers.ZORRO_SIGN_512, "ZORRO");
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(sig));
    }
}
