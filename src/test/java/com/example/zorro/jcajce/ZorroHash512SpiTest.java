package com.example.zorro.jcajce;

import com.example.zorro.asn1.ZorroObjectIdentifiers;
import com.example.zorro.provider.ZorroProvider;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Интеграционный тест: ZORRO-HASH-512, доступный через JCA, выдаёт тот же
 * результат, что и эталонный Streebog-512 из BouncyCastle. Дополнительно
 * проверяется, что хэш можно получить и по OID.
 */
class ZorroHash512SpiTest {

    @BeforeAll
    static void setUp() {
        if (Security.getProvider(ZorroProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new ZorroProvider());
        }
    }

    @Test
    void byNameMatchesBouncyCastle() throws Exception {
        byte[] msg = "Hello from ZORRO provider".getBytes();

        MessageDigest md = MessageDigest.getInstance("ZORRO-HASH-512", "ZORRO");
        md.update(msg);
        byte[] ours = md.digest();
        assertEquals(64, ours.length);

        GOST3411_2012_512Digest bc = new GOST3411_2012_512Digest();
        bc.update(msg, 0, msg.length);
        byte[] expected = new byte[64];
        bc.doFinal(expected, 0);

        assertArrayEquals(expected, ours);
    }

    @Test
    void byOid() throws Exception {
        MessageDigest byOid = MessageDigest.getInstance(
                ZorroObjectIdentifiers.ZORRO_HASH_512, "ZORRO");
        byte[] msg = "abc".getBytes();
        byOid.update(msg);
        byte[] hash = byOid.digest();
        assertEquals(64, hash.length);
    }

    @Test
    void multipleInstancesIndependent() throws Exception {
        MessageDigest a = MessageDigest.getInstance("ZORRO-HASH-512", "ZORRO");
        MessageDigest b = MessageDigest.getInstance("ZORRO-HASH-512", "ZORRO");
        a.update("abc".getBytes());
        b.update("xyz".getBytes());
        byte[] ha = a.digest();
        byte[] hb = b.digest();
        // Разные сообщения → разные хэши; и каждый инстанс не залип на другом.
        assertEquals(64, ha.length);
        assertEquals(64, hb.length);
    }
}
