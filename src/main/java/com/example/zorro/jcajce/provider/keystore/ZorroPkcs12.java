package com.example.zorro.jcajce.provider.keystore;

import com.example.zorro.asn1.KalkanObjectIdentifiers;
import com.example.zorro.provider.AlgorithmModule;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * KeyStore ZORRO-PKCS12 — собственный SPI, который читает PKCS#12-файлы
 * (включая Kalkan-овский {@code src/test/files/test.p12}) с помощью
 * low-level примитивов BouncyCastle.
 *
 * <p>SPI делает всё сам, не делегируя через {@code KeyStore.getInstance(..., "BC")}:
 * <ol>
 *   <li>парсит {@link Pfx} → {@link AuthenticatedSafe} → {@link ContentInfo}-ы;</li>
 *   <li>верифицирует MAC PKCS#12 (HMAC-SHA1, KDF — PKCS#12 v1.0);</li>
 *   <li>дешифрует {@code pbeWithSHAAnd*} оболочки через
 *       {@link Cipher} + BC-ный {@link SecretKeyFactory};</li>
 *   <li>распознаёт казахские OID-ы Kalkan и переводит их в Tc26-known
 *       OID-ы через {@link ZorroKalkanGostKeyFactory};</li>
 *   <li>группирует ключи и сертификаты по {@code localKeyId} в один
 *       PrivateKeyEntry.</li>
 * </ol>
 *
 * <p>Запись в файл (engineStore) пока не реализована — этому SPI важно
 * именно <i>читать</i> уже существующие p12, что и нужно для
 * тестового файла в репозитории.
 */
public class ZorroPkcs12 extends KeyStoreSpi {

    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    private final Map<String, Entry> entries = new LinkedHashMap<>();
    private final KeyFactory kalkanKeyFactory;

    public ZorroPkcs12() {
        try {
            this.kalkanKeyFactory = KeyFactory.getInstance(
                    "GOST3410-2015-512",
                    new com.example.zorro.provider.ZorroProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("ZorroKalkanGostKeyFactory не зарегистрирован", e);
        }
    }

    // ============================================================
    // engine* — KeyStoreSpi
    // ============================================================

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        entries.clear();
        if (stream == null) {
            return; // создание нового пустого KeyStore
        }
        byte[] data = stream.readAllBytes();
        try {
            loadPfx(Pfx.getInstance(data), password);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IOException("ошибка разбора PKCS#12: " + e.getMessage(), e);
        }
    }

    @Override
    public Key engineGetKey(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException {
        Entry e = entries.get(alias);
        return e == null ? null : e.key;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        Entry e = entries.get(alias);
        return e == null || e.chain == null ? null : e.chain.clone();
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        Entry e = entries.get(alias);
        if (e == null) return null;
        if (e.chain != null && e.chain.length > 0) return e.chain[0];
        return e.cert;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        Entry e = entries.get(alias);
        return e == null ? null : e.creationDate;
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(new ArrayList<>(entries.keySet()));
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return entries.containsKey(alias);
    }

    @Override
    public int engineSize() {
        return entries.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        Entry e = entries.get(alias);
        return e != null && e.key != null;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        Entry e = entries.get(alias);
        return e != null && e.key == null && (e.cert != null || (e.chain != null && e.chain.length > 0));
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        for (Map.Entry<String, Entry> e : entries.entrySet()) {
            Certificate c = engineGetCertificate(e.getKey());
            if (c != null && c.equals(cert)) return e.getKey();
        }
        return null;
    }

    @Override
    public void engineSetKeyEntry(String a, Key k, char[] p, Certificate[] c) throws KeyStoreException {
        throw new KeyStoreException("ZORRO-PKCS12 read-only в текущей версии");
    }

    @Override
    public void engineSetKeyEntry(String a, byte[] k, Certificate[] c) throws KeyStoreException {
        throw new KeyStoreException("ZORRO-PKCS12 read-only в текущей версии");
    }

    @Override
    public void engineSetCertificateEntry(String a, Certificate c) throws KeyStoreException {
        throw new KeyStoreException("ZORRO-PKCS12 read-only в текущей версии");
    }

    @Override
    public void engineDeleteEntry(String a) throws KeyStoreException {
        throw new KeyStoreException("ZORRO-PKCS12 read-only в текущей версии");
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException {
        throw new IOException("ZORRO-PKCS12 read-only в текущей версии");
    }

    // ============================================================
    // PFX-парсинг
    // ============================================================

    private void loadPfx(Pfx pfx, char[] password) throws IOException, GeneralSecurityException {
        ContentInfo authSafe = pfx.getAuthSafe();
        if (!PKCSObjectIdentifiers.data.equals(authSafe.getContentType())) {
            throw new IOException("ожидается plain data для authSafe, получено "
                    + authSafe.getContentType());
        }
        byte[] authSafeBytes = ASN1OctetString.getInstance(authSafe.getContent()).getOctets();

        // 1. Проверяем MAC (если есть)
        verifyMac(pfx, authSafeBytes, password);

        // 2. Идём по ContentInfo
        AuthenticatedSafe safe = AuthenticatedSafe.getInstance(
                ASN1Sequence.getInstance(authSafeBytes));

        Map<KeyId, PrivateKeyEntry> keysById = new HashMap<>();
        Map<KeyId, List<X509Certificate>> certsById = new LinkedHashMap<>();
        Map<KeyId, String> friendlyNames = new HashMap<>();

        for (ContentInfo ci : safe.getContentInfo()) {
            ASN1Sequence bags;
            if (PKCSObjectIdentifiers.data.equals(ci.getContentType())) {
                bags = ASN1Sequence.getInstance(
                        ASN1OctetString.getInstance(ci.getContent()).getOctets());
            } else if (PKCSObjectIdentifiers.encryptedData.equals(ci.getContentType())) {
                EncryptedData ed = EncryptedData.getInstance(ci.getContent());
                byte[] decrypted = pbeDecrypt(
                        ed.getEncryptionAlgorithm(),
                        ed.getContent().getOctets(),
                        password);
                bags = ASN1Sequence.getInstance(decrypted);
            } else {
                continue;
            }

            for (int i = 0; i < bags.size(); i++) {
                SafeBag sb = SafeBag.getInstance(bags.getObjectAt(i));
                BagAttrs attrs = BagAttrs.from(sb.getBagAttributes());

                if (PKCSObjectIdentifiers.pkcs8ShroudedKeyBag.equals(sb.getBagId())) {
                    EncryptedPrivateKeyInfo epki =
                            EncryptedPrivateKeyInfo.getInstance(sb.getBagValue());
                    byte[] pkcs8 = pbeDecrypt(
                            epki.getEncryptionAlgorithm(),
                            epki.getEncryptedData(),
                            password);
                    java.security.PrivateKey key = decodePrivateKey(pkcs8);
                    KeyId id = attrs.localKeyId != null ? attrs.localKeyId : KeyId.synthetic(i);
                    keysById.put(id, new PrivateKeyEntry(key, attrs.friendlyName));
                    if (attrs.friendlyName != null) friendlyNames.put(id, attrs.friendlyName);

                } else if (PKCSObjectIdentifiers.keyBag.equals(sb.getBagId())) {
                    PrivateKeyInfo pki = PrivateKeyInfo.getInstance(sb.getBagValue());
                    java.security.PrivateKey key = decodePrivateKey(pki.getEncoded());
                    KeyId id = attrs.localKeyId != null ? attrs.localKeyId : KeyId.synthetic(i);
                    keysById.put(id, new PrivateKeyEntry(key, attrs.friendlyName));
                    if (attrs.friendlyName != null) friendlyNames.put(id, attrs.friendlyName);

                } else if (PKCSObjectIdentifiers.certBag.equals(sb.getBagId())) {
                    CertBag cb = CertBag.getInstance(sb.getBagValue());
                    if (!PKCSObjectIdentifiers.x509Certificate.equals(cb.getCertId())) {
                        continue;
                    }
                    byte[] x509Der = ASN1OctetString.getInstance(cb.getCertValue()).getOctets();
                    X509Certificate cert = parseX509(x509Der);
                    KeyId id = attrs.localKeyId != null ? attrs.localKeyId : KeyId.synthetic(i);
                    certsById.computeIfAbsent(id, k -> new ArrayList<>()).add(cert);
                    if (attrs.friendlyName != null) friendlyNames.putIfAbsent(id, attrs.friendlyName);
                }
            }
        }

        // 3. Собираем итоговые entries: ключ + chain под общим localKeyId
        for (Map.Entry<KeyId, PrivateKeyEntry> ke : keysById.entrySet()) {
            KeyId id = ke.getKey();
            PrivateKeyEntry pe = ke.getValue();
            List<X509Certificate> chain = certsById.getOrDefault(id, Collections.emptyList());
            String alias = pe.friendlyName != null ? pe.friendlyName
                    : (friendlyNames.get(id) != null ? friendlyNames.get(id) : id.toString());
            Entry e = new Entry();
            e.key = pe.key;
            e.chain = chain.isEmpty() ? null : chain.toArray(new Certificate[0]);
            e.creationDate = new Date();
            entries.put(alias, e);
        }
        // Cert-only entries (без матчащего ключа)
        for (Map.Entry<KeyId, List<X509Certificate>> ce : certsById.entrySet()) {
            if (keysById.containsKey(ce.getKey())) continue;
            String alias = friendlyNames.getOrDefault(ce.getKey(), ce.getKey().toString());
            Entry e = new Entry();
            e.cert = ce.getValue().get(0);
            e.creationDate = new Date();
            entries.put(alias, e);
        }
    }

    private void verifyMac(Pfx pfx, byte[] authSafeBytes, char[] password)
            throws IOException, GeneralSecurityException {
        MacData macData = pfx.getMacData();
        if (macData == null) {
            return;
        }
        AlgorithmIdentifier macAlg = macData.getMac().getAlgorithmId();
        if (!OIWObjectIdentifiers_idSHA1.equals(macAlg.getAlgorithm())) {
            // упрощение: поддерживаем только SHA-1 MAC (как в test.p12)
            throw new IOException("неподдерживаемый MAC-алгоритм: " + macAlg.getAlgorithm());
        }
        byte[] salt = macData.getSalt();
        int iter = macData.getIterationCount().intValue();

        byte[] macKey = pkcs12Kdf(password, salt, iter, /*purpose=MAC=*/3, 20);
        HMac hmac = new HMac(new SHA1Digest());
        hmac.init(new KeyParameter(macKey));
        hmac.update(authSafeBytes, 0, authSafeBytes.length);
        byte[] computed = new byte[hmac.getMacSize()];
        hmac.doFinal(computed, 0);

        byte[] expected = macData.getMac().getDigest();
        if (!Arrays.equals(computed, expected)) {
            throw new IOException("PKCS#12 MAC не сходится — неверный пароль или повреждённый файл");
        }
    }

    /** PKCS#12 v1.0 KDF (RFC 7292 §B.2) для произвольного назначения (key/IV/MAC). */
    private static byte[] pkcs12Kdf(char[] password, byte[] salt, int iter, int idByte, int outLen) {
        PKCS12ParametersGenerator gen = new PKCS12ParametersGenerator(new SHA1Digest());
        gen.init(PBEParametersGenerator.PKCS12PasswordToBytes(password), salt, iter);
        return ((KeyParameter) gen.generateDerivedMacParameters(outLen * 8)).getKey();
    }

    private static final ASN1ObjectIdentifier OIWObjectIdentifiers_idSHA1 =
            new ASN1ObjectIdentifier("1.3.14.3.2.26");

    // ============================================================
    // PBE-дешифровка
    // ============================================================

    private byte[] pbeDecrypt(AlgorithmIdentifier alg, byte[] encrypted, char[] password)
            throws GeneralSecurityException, IOException {
        String algOid = alg.getAlgorithm().getId();
        SecretKeyFactory skf = SecretKeyFactory.getInstance(algOid, BC);
        SecretKey sk = skf.generateSecret(new PBEKeySpec(password));
        AlgorithmParameters params = AlgorithmParameters.getInstance(algOid, BC);
        params.init(alg.getParameters().toASN1Primitive().getEncoded());
        // PBEParameterSpec из params (поддерживается BC)
        PBEParameterSpec pbeSpec = params.getParameterSpec(PBEParameterSpec.class);
        Cipher cipher = Cipher.getInstance(algOid, BC);
        cipher.init(Cipher.DECRYPT_MODE, sk, pbeSpec);
        return cipher.doFinal(encrypted);
    }

    // ============================================================
    // Декодирование ключей и сертификатов
    // ============================================================

    private java.security.PrivateKey decodePrivateKey(byte[] pkcs8) throws GeneralSecurityException {
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(pkcs8);
        ASN1ObjectIdentifier alg = pki.getPrivateKeyAlgorithm().getAlgorithm();
        if (KalkanObjectIdentifiers.KALKAN_GOST3410_2015_512.equals(alg)) {
            return kalkanKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        }
        // Стандартный путь — пробуем BC по OID
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance(alg.getId(), BC);
        } catch (NoSuchAlgorithmException nsa) {
            throw new GeneralSecurityException("неизвестный алгоритм ключа: " + alg, nsa);
        }
        return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    private X509Certificate parseX509(byte[] x509Der) throws CertificateException {
        // BC's X509CertificateImpl лениво парсит SPKI — getPublicKey() не вызывается
        // на этапе construction. PublicKey будет распарсен при первом обращении и
        // тогда наш ZorroKalkanGostKeyFactory подхватит казахский OID.
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(x509Der));
    }

    // ============================================================
    // Внутренние структуры
    // ============================================================

    private static final class Entry {
        java.security.PrivateKey key;
        Certificate[] chain;
        Certificate cert;
        Date creationDate;
    }

    private record PrivateKeyEntry(java.security.PrivateKey key, String friendlyName) {}

    /** Обёртка над localKeyId для использования в Map. */
    private static final class KeyId {
        private final byte[] bytes;
        private final boolean synthetic;

        private KeyId(byte[] bytes, boolean synthetic) {
            this.bytes = bytes;
            this.synthetic = synthetic;
        }

        static KeyId of(byte[] bytes) {
            return new KeyId(bytes.clone(), false);
        }

        static KeyId synthetic(int idx) {
            return new KeyId(new byte[]{(byte) idx}, true);
        }

        @Override public boolean equals(Object o) {
            return o instanceof KeyId other
                    && synthetic == other.synthetic
                    && Arrays.equals(bytes, other.bytes);
        }
        @Override public int hashCode() {
            return Arrays.hashCode(bytes) * 31 + (synthetic ? 1 : 0);
        }
        @Override public String toString() {
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return synthetic ? ("entry-" + sb) : sb.toString();
        }
    }

    /** Извлечённые из {@link SafeBag} bagAttributes: friendlyName, localKeyId. */
    private static final class BagAttrs {
        String friendlyName;
        KeyId  localKeyId;

        static BagAttrs from(ASN1Set set) {
            BagAttrs out = new BagAttrs();
            if (set == null) return out;
            for (ASN1Encodable a : set.toArray()) {
                ASN1Sequence seq = ASN1Sequence.getInstance(a);
                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
                ASN1Set values = ASN1Set.getInstance(seq.getObjectAt(1));
                if (values.size() == 0) continue;
                ASN1Encodable v = values.getObjectAt(0);
                if (PKCSObjectIdentifiers.pkcs_9_at_friendlyName.equals(oid)) {
                    out.friendlyName = ((DERBMPString) v).getString();
                } else if (PKCSObjectIdentifiers.pkcs_9_at_localKeyId.equals(oid)) {
                    out.localKeyId = KeyId.of(((ASN1OctetString) v).getOctets());
                }
            }
            return out;
        }
    }

    /** Регистрация KeyStore-типа в провайдере. */
    public static class Mappings implements AlgorithmModule {
        @Override
        public void register(Provider provider) {
            provider.put("KeyStore.ZORRO-PKCS12", ZorroPkcs12.class.getName());
            provider.put("Alg.Alias.KeyStore.ZORROPKCS12", "ZORRO-PKCS12");
            provider.put("Alg.Alias.KeyStore.ZORRO", "ZORRO-PKCS12");
        }
    }
}
