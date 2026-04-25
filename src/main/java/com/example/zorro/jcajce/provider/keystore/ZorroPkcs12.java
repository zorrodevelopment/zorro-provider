package com.example.zorro.jcajce.provider.keystore;

import com.example.zorro.provider.AlgorithmModule;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

/**
 * KeyStore ZORRO-PKCS12 — обёртка над PKCS#12 KeyStore от Kalkan.
 *
 * <p>Назначение — позволить приложению писать
 * {@code KeyStore.getInstance("ZORRO-PKCS12", "ZORRO")} вместо явного
 * указания имени Kalkan, развязывая бизнес-код от backend-провайдера.
 * Если вы захотите завтра поменять backend (например, на BouncyCastle с
 * включённой поддержкой ГОСТ через bc-gost-modules), достаточно будет
 * поменять {@link #BACKEND_PROVIDER} в одном месте.
 */
public class ZorroPkcs12 extends KeyStoreSpi {

    private static final String BACKEND_TYPE     = "PKCS12";
    private static final String BACKEND_PROVIDER = "KALKAN";

    private final KeyStore backend;

    public ZorroPkcs12() {
        try {
            this.backend = KeyStore.getInstance(BACKEND_TYPE, BACKEND_PROVIDER);
        } catch (KeyStoreException | NoSuchProviderException e) {
            throw new IllegalStateException(
                    "ZORRO-PKCS12 требует KeyStore " + BACKEND_TYPE
                    + " от провайдера " + BACKEND_PROVIDER, e);
        }
    }

    // ---------- engine* методы — простой делегат ----------

    @Override
    public Key engineGetKey(String alias, char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException {
        try {
            return backend.getKey(alias, password);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("backend not loaded", e);
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        try { return backend.getCertificateChain(alias); }
        catch (KeyStoreException e) { throw new IllegalStateException(e); }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        try { return backend.getCertificate(alias); }
        catch (KeyStoreException e) { throw new IllegalStateException(e); }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        try { return backend.getCreationDate(alias); }
        catch (KeyStoreException e) { throw new IllegalStateException(e); }
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password,
                                   Certificate[] chain) throws KeyStoreException {
        backend.setKeyEntry(alias, key, password, chain);
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
            throws KeyStoreException {
        backend.setKeyEntry(alias, key, chain);
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert)
            throws KeyStoreException {
        backend.setCertificateEntry(alias, cert);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        backend.deleteEntry(alias);
    }

    @Override
    public Enumeration<String> engineAliases() {
        try { return backend.aliases(); }
        catch (KeyStoreException e) { throw new IllegalStateException(e); }
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        try { return backend.containsAlias(alias); }
        catch (KeyStoreException e) { throw new IllegalStateException(e); }
    }

    @Override
    public int engineSize() {
        try { return backend.size(); }
        catch (KeyStoreException e) { throw new IllegalStateException(e); }
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        try { return backend.isKeyEntry(alias); }
        catch (KeyStoreException e) { throw new IllegalStateException(e); }
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        try { return backend.isCertificateEntry(alias); }
        catch (KeyStoreException e) { throw new IllegalStateException(e); }
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        try { return backend.getCertificateAlias(cert); }
        catch (KeyStoreException e) { throw new IllegalStateException(e); }
    }

    @Override
    public void engineStore(OutputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        try { backend.store(stream, password); }
        catch (KeyStoreException e) { throw new IOException(e); }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        backend.load(stream, password);
    }

    /** Регистрация в провайдере. */
    public static class Mappings implements AlgorithmModule {
        @Override
        public void register(Provider provider) {
            if (java.security.Security.getProvider(BACKEND_PROVIDER) == null) {
                throw new IllegalStateException(
                        "Backend provider " + BACKEND_PROVIDER + " не зарегистрирован, "
                        + "модуль ZorroPkcs12 пропущен");
            }
            provider.put("KeyStore.ZORRO-PKCS12", ZorroPkcs12.class.getName());
            provider.put("Alg.Alias.KeyStore.ZORROPKCS12", "ZORRO-PKCS12");
            provider.put("Alg.Alias.KeyStore.ZORRO", "ZORRO-PKCS12");
        }
    }
}
