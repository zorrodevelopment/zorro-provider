package com.example.zorro.crypto.ec;

import com.example.zorro.crypto.Streebog512;
import com.example.zorro.util.ByteUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECGOST3410Signer;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Тесты собственной реализации ECGOST3410-2012 (512 бит).
 *
 * <p>Кросс-проверка с BouncyCastle: подпись, сделанная нашим signer, проверяется
 * BC-signer'ом и наоборот. Так мы гарантируем не только криптографическую
 * корректность, но и совместимость по бинарному формату.
 */
class EcGost2012SignerTest {

    /** OID id-tc26-gost-3410-12-512-paramSetA. */
    private static final ASN1ObjectIdentifier PARAM_SET_A =
            new ASN1ObjectIdentifier("1.2.643.7.1.2.1.2.1");

    @Test
    void generatorIsOnCurve() {
        assertTrue(GostCurves.paramSetA.G.isOnCurve(), "G должна лежать на paramSetA");
        assertTrue(GostCurves.paramSetB.G.isOnCurve(), "G должна лежать на paramSetB");
        assertTrue(GostCurves.paramSetC.G.isOnCurve(), "G должна лежать на paramSetC");
    }

    @Test
    void generatorOrderIsN() {
        // n·G = O — фундаментальное свойство порядка подгруппы.
        for (EcCurveParams curve : new EcCurveParams[]{
                GostCurves.paramSetA, GostCurves.paramSetB, GostCurves.paramSetC}) {
            EcPoint nG = curve.G.multiply(curve.n);
            assertTrue(nG.infinity, "n·G должна быть точкой в бесконечности");
        }
    }

    @Test
    void signAndVerifyRoundtripParamSetA() {
        roundtrip(GostCurves.paramSetA);
    }

    @Test
    void signAndVerifyRoundtripParamSetB() {
        roundtrip(GostCurves.paramSetB);
    }

    @Test
    void signAndVerifyRoundtripParamSetC() {
        roundtrip(GostCurves.paramSetC);
    }

    private void roundtrip(EcCurveParams curve) {
        SecureRandom rng = new SecureRandom(new byte[]{1, 2, 3});
        BigInteger d = randInRange(curve.n, rng);
        EcPoint Q = curve.G.multiply(d);

        byte[] hash = streebogOf("test message".getBytes());
        byte[] sig = EcGost2012Signer.sign(hash, curve, d, rng);

        assertEquals(curve.coordLength() * 2, sig.length);
        assertTrue(EcGost2012Signer.verify(hash, curve, Q, sig));

        // Подмена сообщения — проверка должна падать.
        byte[] tampered = streebogOf("tampered message".getBytes());
        assertFalse(EcGost2012Signer.verify(tampered, curve, Q, sig));
    }

    @Test
    void ourSignVerifiedByBC() throws Exception {
        SecureRandom rng = new SecureRandom(new byte[]{42});
        EcCurveParams curve = GostCurves.paramSetA;

        BigInteger d = randInRange(curve.n, rng);
        EcPoint Q = curve.G.multiply(d);

        byte[] msg = "hello cross-validation".getBytes();
        byte[] hash = streebogOf(msg);

        byte[] sig = EcGost2012Signer.sign(hash, curve, d, rng);

        // Распаковываем Kalkan-формат: первая половина r_LE, вторая s_LE.
        int coord = curve.coordLength();
        BigInteger r = new BigInteger(1, ByteUtils.reverse(java.util.Arrays.copyOfRange(sig, 0,     coord)));
        BigInteger s = new BigInteger(1, ByteUtils.reverse(java.util.Arrays.copyOfRange(sig, coord, coord * 2)));

        ECGOST3410Signer bc = new ECGOST3410Signer();
        bc.init(false, new ECPublicKeyParameters(
                bcPoint(Q, curve), bcDomain()));
        assertTrue(bc.verifySignature(hash, r, s),
                "BC должен принимать подпись, созданную нашей реализацией");
    }

    @Test
    void bcSignVerifiedByUs() throws Exception {
        SecureRandom rng = new SecureRandom(new byte[]{99});
        EcCurveParams curve = GostCurves.paramSetA;

        BigInteger d = randInRange(curve.n, rng);
        EcPoint Q = curve.G.multiply(d);

        byte[] hash = streebogOf("BC signs, we verify".getBytes());

        ECGOST3410Signer bc = new ECGOST3410Signer();
        ECDomainParameters domain = bcDomain();
        bc.init(true, new ParametersWithRandom(
                new ECPrivateKeyParameters(d, domain), rng));
        BigInteger[] sig = bc.generateSignature(hash);
        BigInteger r = sig[0];
        BigInteger s = sig[1];

        // Соберём наш Kalkan-формат: r_LE || s_LE
        int coord = curve.coordLength();
        byte[] sigBytes = new byte[coord * 2];
        System.arraycopy(ByteUtils.reverse(ByteUtils.toFixedLengthBE(r, coord)), 0, sigBytes, 0,     coord);
        System.arraycopy(ByteUtils.reverse(ByteUtils.toFixedLengthBE(s, coord)), 0, sigBytes, coord, coord);

        assertTrue(EcGost2012Signer.verify(hash, curve, Q, sigBytes),
                "Наша реализация должна принимать BC-подпись");
    }

    @Test
    void invalidSignatureRejected() {
        SecureRandom rng = new SecureRandom(new byte[]{7});
        EcCurveParams curve = GostCurves.paramSetA;
        BigInteger d = randInRange(curve.n, rng);
        EcPoint Q = curve.G.multiply(d);

        byte[] hash = streebogOf("real".getBytes());
        byte[] fakeSig = new byte[curve.coordLength() * 2]; // всё нули → r=s=0 → отвергнуто

        assertFalse(EcGost2012Signer.verify(hash, curve, Q, fakeSig));
    }

    // ----- хелперы -----

    private static byte[] streebogOf(byte[] msg) {
        Streebog512 d = new Streebog512();
        d.update(msg, 0, msg.length);
        return d.digest();
    }

    private static BigInteger randInRange(BigInteger n, SecureRandom rng) {
        BigInteger v;
        do {
            v = new BigInteger(n.bitLength(), rng);
        } while (v.signum() == 0 || v.compareTo(n) >= 0);
        return v;
    }

    private static ECDomainParameters bcDomain() {
        X9ECParameters p = ECGOST3410NamedCurves.getByOIDX9(PARAM_SET_A);
        return new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
    }

    private static org.bouncycastle.math.ec.ECPoint bcPoint(EcPoint Q, EcCurveParams curve) {
        X9ECParameters p = ECGOST3410NamedCurves.getByOIDX9(PARAM_SET_A);
        return p.getCurve().createPoint(Q.getX(), Q.getY());
    }
}
