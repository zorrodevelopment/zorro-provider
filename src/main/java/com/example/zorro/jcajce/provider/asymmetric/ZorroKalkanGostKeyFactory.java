package com.example.zorro.jcajce.provider.asymmetric;

import com.example.zorro.asn1.KalkanObjectIdentifiers;
import com.example.zorro.provider.AlgorithmModule;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyFactory-транслятор: понимает казахские OID-ы Kalkan
 * (см. {@link KalkanObjectIdentifiers}) и выдаёт стандартный
 * BouncyCastle ECGOST3410-2012-512 ключ.
 *
 * <p>Регистрируется под казахским OID-алиасом, поэтому когда JCA
 * (например, парсер X.509-сертификата или PKCS#12 KeyStore) ищет
 * {@code KeyFactory.getInstance("1.2.398.3.10.1.1.2.2")}, он находит
 * этот класс и тот «на лету» переписывает PKCS#8 / SPKI с
 * {@code 1.2.398.3.10.*} на {@code 1.2.643.7.*}, после чего отдаёт
 * BC-шному KeyFactory, который уже умеет всё.
 *
 * <p>Параметры кривой совпадают по значению (Kalkan paramSet =
 * Tc26 paramSetA), поэтому переводим только идентификаторы.
 *
 * <p>D хранится в OCTET STRING как big-endian — то же самое
 * принимает BC после своего внутреннего реверса.
 */
public class ZorroKalkanGostKeyFactory extends KeyFactorySpi {

    private final KeyFactory delegate;

    public ZorroKalkanGostKeyFactory() throws NoSuchAlgorithmException {
        // Используем BC напрямую, без обращения в JVM-список провайдеров —
        // ZORRO от регистрации BC не зависит.
        // BC регистрирует ECGOST3410-2012 (один KeyFactory на 256 и 512).
        this.delegate = KeyFactory.getInstance("ECGOST3410-2012", new BouncyCastleProvider());
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof X509EncodedKeySpec)) {
            throw new InvalidKeySpecException("ожидается X509EncodedKeySpec");
        }
        byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
        try {
            SubjectPublicKeyInfo translated = translateSpki(SubjectPublicKeyInfo.getInstance(encoded));
            return delegate.generatePublic(new X509EncodedKeySpec(translated.getEncoded()));
        } catch (IOException e) {
            throw new InvalidKeySpecException("не могу переписать SPKI: " + e.getMessage(), e);
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof PKCS8EncodedKeySpec)) {
            throw new InvalidKeySpecException("ожидается PKCS8EncodedKeySpec");
        }
        byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
        try {
            PrivateKeyInfo translated = translatePki(PrivateKeyInfo.getInstance(encoded));
            return delegate.generatePrivate(new PKCS8EncodedKeySpec(translated.getEncoded()));
        } catch (IOException e) {
            throw new InvalidKeySpecException("не могу переписать PKCS#8: " + e.getMessage(), e);
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        return delegate.getKeySpec(key, keySpec);
    }

    @Override
    protected Key engineTranslateKey(Key key) throws java.security.InvalidKeyException {
        return delegate.translateKey(key);
    }

    /**
     * Переводит {@link SubjectPublicKeyInfo} с казахским OID на тот же SPKI,
     * но с BC-known идентификаторами. Содержимое octet string не трогаем.
     */
    static SubjectPublicKeyInfo translateSpki(SubjectPublicKeyInfo spki) {
        AlgorithmIdentifier translated = translateAlg(spki.getAlgorithm());
        return new SubjectPublicKeyInfo(translated, spki.getPublicKeyData().getBytes());
    }

    /**
     * То же для {@link PrivateKeyInfo} — только меняем AlgorithmIdentifier.
     */
    static PrivateKeyInfo translatePki(PrivateKeyInfo pki) throws IOException {
        AlgorithmIdentifier translated = translateAlg(pki.getPrivateKeyAlgorithm());
        return new PrivateKeyInfo(translated, pki.parsePrivateKey(),
                pki.getAttributes(), pki.getPublicKeyData() == null
                        ? null : pki.getPublicKeyData().getBytes());
    }

    private static AlgorithmIdentifier translateAlg(AlgorithmIdentifier in) {
        if (!KalkanObjectIdentifiers.KALKAN_GOST3410_2015_512.equals(in.getAlgorithm())) {
            return in;
        }
        // В параметрах ожидаем SEQUENCE { paramSet OID, digest OID }
        ASN1Sequence params = ASN1Sequence.getInstance(in.getParameters());
        ASN1Encodable[] translated = new ASN1Encodable[params.size()];
        for (int i = 0; i < params.size(); i++) {
            ASN1Encodable a = params.getObjectAt(i);
            if (KalkanObjectIdentifiers.KALKAN_PARAMSET.equals(a)) {
                translated[i] = KalkanObjectIdentifiers.BC_PARAMSET_A;
            } else if (KalkanObjectIdentifiers.KALKAN_DIGEST_512.equals(a)) {
                translated[i] = KalkanObjectIdentifiers.BC_GOST3411_2012_512;
            } else {
                translated[i] = a;
            }
        }
        return new AlgorithmIdentifier(
                KalkanObjectIdentifiers.BC_GOST3410_2012_512,
                new DERSequence(translated));
    }

    /** Регистрация под Kalkan-OID. */
    public static class Mappings implements AlgorithmModule {
        @Override
        public void register(Provider provider) {
            String spi = ZorroKalkanGostKeyFactory.class.getName();
            String oid = KalkanObjectIdentifiers.KALKAN_GOST3410_2015_512.getId();
            // KeyFactory под казахским OID. Имя «GOST3410-2015-512» — для людей.
            provider.put("KeyFactory.GOST3410-2015-512", spi);
            provider.put("Alg.Alias.KeyFactory." + oid, "GOST3410-2015-512");
            provider.put("Alg.Alias.KeyFactory.OID." + oid, "GOST3410-2015-512");

            // BouncyCastle при разборе X.509-сертификата вытаскивает publicKey
            // через свой статический реестр AsymmetricKeyInfoConverter-ов
            // (BouncyCastleProvider.getPublicKey), минуя JCA-lookup. Чтобы
            // cert.getPublicKey() для казахских сертификатов возвращал не null,
            // регистрируем туда наш транслятор.
            BouncyCastleProvider bc = (BouncyCastleProvider) java.security.Security
                    .getProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (bc != null) {
                bc.addKeyInfoConverter(KalkanObjectIdentifiers.KALKAN_GOST3410_2015_512,
                        new KalkanAsymmetricConverter());
            }
        }
    }

    /** Конвертер для статического реестра BC. */
    private static final class KalkanAsymmetricConverter implements AsymmetricKeyInfoConverter {
        private final ZorroKalkanGostKeyFactory delegate;

        KalkanAsymmetricConverter() {
            try {
                this.delegate = new ZorroKalkanGostKeyFactory();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public PrivateKey generatePrivate(PrivateKeyInfo info) throws IOException {
            try {
                return delegate.engineGeneratePrivate(new PKCS8EncodedKeySpec(info.getEncoded()));
            } catch (java.security.spec.InvalidKeySpecException e) {
                throw new IOException(e);
            }
        }

        @Override
        public PublicKey generatePublic(SubjectPublicKeyInfo info) throws IOException {
            try {
                return delegate.engineGeneratePublic(new X509EncodedKeySpec(info.getEncoded()));
            } catch (java.security.spec.InvalidKeySpecException e) {
                throw new IOException(e);
            }
        }
    }
}
