package com.example.zorro.jcajce.provider.keystore;

import com.example.zorro.crypto.asn1.DerInput;
import com.example.zorro.crypto.asn1.DerValue;
import com.example.zorro.jcajce.provider.keys.GostKeyEncoding;
import com.example.zorro.provider.AlgorithmModule;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Собственная реализация PKCS#12 KeyStore (только чтение).
 *
 * <p>Не зависит от BouncyCastle/Kalkan: парсит DER самостоятельно, шифры
 * 3DES и RC2-40 берёт из SunJCE, MAC-проверка — HmacSHA1 + наш PKCS#12 KDF.
 *
 * <p>Поддерживает PFX-файлы НУЦ РК (с казахстанскими OID-ами ECGOST), которые
 * BC и openssl самостоятельно загрузить не могут.
 *
 * <h2>Поддержанные алгоритмы</h2>
 * <ul>
 *   <li>MAC: HMAC-SHA1, итерации произвольные.</li>
 *   <li>PBE для KeyBag: pbeWithSHAAnd3-KeyTripleDES-CBC.</li>
 *   <li>PBE для CertBag: pbeWithSHAAnd40BitRC2-CBC.</li>
 *   <li>PrivateKey: ECGOST3410-2012-512 (Россия / Казахстан).</li>
 * </ul>
 *
 * <p>Запись и удаление сейчас не поддерживаются (бросают
 * {@link UnsupportedOperationException}).
 */
public class ZorroPkcs12 extends KeyStoreSpi {

    private static final String OID_PKCS7_DATA            = "1.2.840.113549.1.7.1";
    private static final String OID_PKCS7_ENCRYPTED_DATA  = "1.2.840.113549.1.7.6";
    private static final String OID_KEYBAG                = "1.2.840.113549.1.12.10.1.1";
    private static final String OID_PKCS8_SHROUDED_KEYBAG = "1.2.840.113549.1.12.10.1.2";
    private static final String OID_CERTBAG               = "1.2.840.113549.1.12.10.1.3";
    private static final String OID_X509_CERT             = "1.2.840.113549.1.9.22.1";
    private static final String OID_FRIENDLY_NAME         = "1.2.840.113549.1.9.20";
    private static final String OID_LOCAL_KEY_ID          = "1.2.840.113549.1.9.21";

    private static final class KeyEntry {
        final java.security.PrivateKey key;
        final Certificate[] chain;
        final Date created = new Date();
        KeyEntry(java.security.PrivateKey key, Certificate[] chain) {
            this.key = key; this.chain = chain;
        }
    }

    private final Map<String, KeyEntry>    keyEntries  = new LinkedHashMap<>();
    private final Map<String, Certificate> certEntries = new LinkedHashMap<>();

    @Override
    public Key engineGetKey(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyEntry e = keyEntries.get(alias);
        return e == null ? null : e.key;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        KeyEntry e = keyEntries.get(alias);
        return e == null ? null : e.chain.clone();
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        KeyEntry e = keyEntries.get(alias);
        if (e != null && e.chain.length > 0) return e.chain[0];
        return certEntries.get(alias);
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        KeyEntry e = keyEntries.get(alias);
        if (e != null) return e.created;
        return certEntries.containsKey(alias) ? new Date() : null;
    }

    @Override
    public Enumeration<String> engineAliases() {
        List<String> all = new ArrayList<>(keyEntries.keySet());
        for (String a : certEntries.keySet()) {
            if (!keyEntries.containsKey(a)) all.add(a);
        }
        return Collections.enumeration(all);
    }

    @Override public boolean engineContainsAlias(String alias)      { return keyEntries.containsKey(alias) || certEntries.containsKey(alias); }
    @Override public int     engineSize()                           {
        int n = keyEntries.size();
        for (String a : certEntries.keySet()) {
            if (!keyEntries.containsKey(a)) n++;
        }
        return n;
    }
    @Override public boolean engineIsKeyEntry(String alias)         { return keyEntries.containsKey(alias); }
    @Override public boolean engineIsCertificateEntry(String alias) { return !keyEntries.containsKey(alias) && certEntries.containsKey(alias); }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        for (Map.Entry<String, KeyEntry> e : keyEntries.entrySet()) {
            for (Certificate c : e.getValue().chain) if (c.equals(cert)) return e.getKey();
        }
        for (Map.Entry<String, Certificate> e : certEntries.entrySet()) {
            if (e.getValue().equals(cert)) return e.getKey();
        }
        return null;
    }

    @Override public void engineSetKeyEntry(String a, Key k, char[] p, Certificate[] c) { throw new UnsupportedOperationException("ZORRO-PKCS12 read-only"); }
    @Override public void engineSetKeyEntry(String a, byte[] k, Certificate[] c)        { throw new UnsupportedOperationException("ZORRO-PKCS12 read-only"); }
    @Override public void engineSetCertificateEntry(String a, Certificate c)            { throw new UnsupportedOperationException("ZORRO-PKCS12 read-only"); }
    @Override public void engineDeleteEntry(String a)                                   { throw new UnsupportedOperationException("ZORRO-PKCS12 read-only"); }
    @Override public void engineStore(OutputStream s, char[] p)                         { throw new UnsupportedOperationException("ZORRO-PKCS12 read-only"); }

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        keyEntries.clear();
        certEntries.clear();
        if (stream == null) return;

        byte[] pfx = readAll(stream);
        try {
            parsePfx(pfx, password);
        } catch (GeneralSecurityException e) {
            throw new IOException("ошибка разбора PKCS#12: " + e.getMessage(), e);
        }
    }

    private void parsePfx(byte[] pfx, char[] password)
            throws IOException, GeneralSecurityException, CertificateException {
        DerInput root = new DerInput(pfx).readSequence();
        BigInteger version = root.readInteger();
        if (!version.equals(BigInteger.valueOf(3))) {
            throw new IOException("ожидается PFX v3, получено " + version);
        }

        // authSafe ContentInfo
        DerInput authSafeInfo = root.readSequence();
        String authType = authSafeInfo.readObjectIdentifier();
        if (!OID_PKCS7_DATA.equals(authType)) {
            throw new IOException("ожидается authSafe contentType=data, получено " + authType);
        }
        byte[] authSafeBytes = authSafeInfo.readContextConstructed(0).readOctetString();

        // macData (опциональна, в test.p12 присутствует)
        if (root.hasMore()) {
            DerInput mac = root.readSequence();
            DerInput digestInfo = mac.readSequence();
            digestInfo.readSequence(); // digestAlgorithm — игнорируем, hard-coded SHA-1
            byte[] expectedMac = digestInfo.readOctetString();
            byte[] macSalt = mac.readOctetString();
            int iter = mac.hasMore() ? mac.readInteger().intValue() : 1;

            if (!Pkcs12Pbe.verifyMac(password, macSalt, iter, authSafeBytes, expectedMac)) {
                throw new IOException("PFX MAC не совпал — неверный пароль или повреждённый файл");
            }
        }

        DerInput authSafe = new DerInput(authSafeBytes).readSequence();
        List<SafeBag> bags = new ArrayList<>();
        while (authSafe.hasMore()) {
            DerInput ci = authSafe.readSequence();
            String type = ci.readObjectIdentifier();
            if (OID_PKCS7_DATA.equals(type)) {
                byte[] safeContents = ci.readContextConstructed(0).readOctetString();
                parseSafeContents(safeContents, bags);
            } else if (OID_PKCS7_ENCRYPTED_DATA.equals(type)) {
                byte[] decrypted = decryptEncryptedData(ci.readContextConstructed(0), password);
                parseSafeContents(decrypted, bags);
            } else {
                throw new IOException("неподдерживаемый ContentInfo: " + type);
            }
        }

        materializeEntries(bags, password);
    }

    private byte[] decryptEncryptedData(DerInput contextWrapper, char[] password)
            throws GeneralSecurityException, IOException {
        DerInput encData = contextWrapper.readSequence();
        encData.readInteger(); // version
        DerInput eci = encData.readSequence();
        String contentType = eci.readObjectIdentifier();
        if (!OID_PKCS7_DATA.equals(contentType)) {
            throw new IOException("ожидается encryptedContent.contentType=data, получено " + contentType);
        }
        DerInput algId = eci.readSequence();
        String pbeOid = algId.readObjectIdentifier();
        DerInput params = algId.readSequence();
        byte[] salt = params.readOctetString();
        int iter = params.readInteger().intValue();
        // [0] IMPLICIT OCTET STRING — encrypted bytes; в BER может быть и
        // в виде [0] CONSTRUCTED с вложенными OCTET STRING-сегментами.
        byte[] ct = eci.readContextImplicitOctetString(0);
        return Pkcs12Pbe.decrypt(pbeOid, password, salt, iter, ct);
    }

    private void parseSafeContents(byte[] bytes, List<SafeBag> out) {
        DerInput sc = new DerInput(bytes).readSequence();
        while (sc.hasMore()) {
            out.add(parseSafeBag(sc.readSequence()));
        }
    }

    private SafeBag parseSafeBag(DerInput bag) {
        String bagId = bag.readObjectIdentifier();
        // bagValue [0] EXPLICIT — внутри один TLV (обычно SEQUENCE).
        // Сохраняем полный TLV (тег+длина+значение), чтобы дальше можно было
        // парсить его как самостоятельный DER-документ.
        DerValue innerValue = bag.readContextConstructed(0).readValue();
        byte[] valueBytes = com.example.zorro.crypto.asn1.DerOutput.wrap(
                innerValue.tag, innerValue.byteCopy());
        SafeBag b = new SafeBag(bagId, valueBytes);
        if (bag.hasMore()) {
            DerInput attrSet = bag.readSet();
            while (attrSet.hasMore()) {
                DerInput attr = attrSet.readSequence();
                String oid = attr.readObjectIdentifier();
                DerInput values = attr.readSet();
                DerValue v = values.readValue();
                if (OID_LOCAL_KEY_ID.equals(oid) && v.tag == DerInput.TAG_OCTET_STRING) {
                    b.localKeyId = v.byteCopy();
                } else if (OID_FRIENDLY_NAME.equals(oid) && v.tag == DerInput.TAG_BMP_STRING) {
                    b.friendlyName = decodeBmpString(v.byteCopy());
                }
            }
        }
        return b;
    }

    private void materializeEntries(List<SafeBag> bags, char[] password)
            throws IOException, GeneralSecurityException, CertificateException {
        Map<String, java.security.PrivateKey> keyByLkid = new HashMap<>();
        Map<String, List<Certificate>> certsByLkid = new HashMap<>();
        List<NamedCert> orphanCerts = new ArrayList<>();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        for (SafeBag b : bags) {
            switch (b.bagId) {
                case OID_PKCS8_SHROUDED_KEYBAG: {
                    byte[] pkcs8 = decryptEncryptedPrivateKeyInfo(b.valueBytes, password);
                    java.security.PrivateKey pk = GostKeyEncoding.parsePrivateKeyInfo(pkcs8);
                    keyByLkid.put(toHex(b.localKeyId), pk);
                    break;
                }
                case OID_KEYBAG: {
                    java.security.PrivateKey pk = GostKeyEncoding.parsePrivateKeyInfo(b.valueBytes);
                    keyByLkid.put(toHex(b.localKeyId), pk);
                    break;
                }
                case OID_CERTBAG: {
                    Certificate cert = parseCertBag(cf, b.valueBytes);
                    if (b.localKeyId != null) {
                        certsByLkid.computeIfAbsent(toHex(b.localKeyId), k -> new ArrayList<>()).add(cert);
                    } else if (b.friendlyName != null) {
                        orphanCerts.add(new NamedCert(b.friendlyName, cert));
                    } else {
                        orphanCerts.add(new NamedCert("cert-" + orphanCerts.size(), cert));
                    }
                    break;
                }
                default:
                    // прочие bag-типы игнорируем
                    break;
            }
        }

        for (Map.Entry<String, java.security.PrivateKey> e : keyByLkid.entrySet()) {
            String lkid = e.getKey();
            List<Certificate> chain = certsByLkid.getOrDefault(lkid, Collections.emptyList());
            keyEntries.put(lkid, new KeyEntry(e.getValue(), chain.toArray(new Certificate[0])));
        }
        for (NamedCert nc : orphanCerts) {
            certEntries.put(nc.name, nc.cert);
        }
    }

    private byte[] decryptEncryptedPrivateKeyInfo(byte[] epki, char[] password)
            throws GeneralSecurityException {
        DerInput info = new DerInput(epki).readSequence();
        DerInput algId = info.readSequence();
        String pbeOid = algId.readObjectIdentifier();
        DerInput params = algId.readSequence();
        byte[] salt = params.readOctetString();
        int iter = params.readInteger().intValue();
        byte[] encrypted = info.readOctetString();
        return Pkcs12Pbe.decrypt(pbeOid, password, salt, iter, encrypted);
    }

    private Certificate parseCertBag(CertificateFactory cf, byte[] valueBytes)
            throws IOException, CertificateException {
        DerInput bag = new DerInput(valueBytes).readSequence();
        String certId = bag.readObjectIdentifier();
        if (!OID_X509_CERT.equals(certId)) {
            throw new IOException("неподдерживаемый certId: " + certId);
        }
        byte[] certBytes = bag.readContextConstructed(0).readOctetString();
        return cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    // ---- утилиты ----

    private static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) >= 0) baos.write(buf, 0, n);
        return baos.toByteArray();
    }

    private static String toHex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    private static String decodeBmpString(byte[] bytes) {
        char[] chars = new char[bytes.length / 2];
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (((bytes[i * 2] & 0xFF) << 8) | (bytes[i * 2 + 1] & 0xFF));
        }
        return new String(chars);
    }

    private static final class SafeBag {
        final String bagId;
        final byte[] valueBytes;
        byte[] localKeyId;
        String friendlyName;
        SafeBag(String id, byte[] bytes) { this.bagId = id; this.valueBytes = bytes; }
    }

    private static final class NamedCert {
        final String name;
        final Certificate cert;
        NamedCert(String n, Certificate c) { this.name = n; this.cert = c; }
    }

    public static class Mappings implements AlgorithmModule {
        @Override
        public void register(Provider provider) {
            provider.put("KeyStore.ZORRO-PKCS12", ZorroPkcs12.class.getName());
            provider.put("Alg.Alias.KeyStore.ZORROPKCS12", "ZORRO-PKCS12");
            provider.put("Alg.Alias.KeyStore.ZORRO", "ZORRO-PKCS12");
        }
    }
}
