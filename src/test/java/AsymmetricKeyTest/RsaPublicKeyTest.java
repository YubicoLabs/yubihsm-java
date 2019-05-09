package AsymmetricKeyTest;

import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.AsymmetricKeyRsa;
import com.yubico.objects.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;

public class RsaPublicKeyTest {
    Logger log = Logger.getLogger(RsaPublicKeyTest.class.getName());

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init() throws Exception {
        if (session == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
            session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.createAuthenticatedSession();
        }
    }

    @AfterClass
    public static void destroy() throws Exception {
        session.closeSession();
        yubihsm.close();
    }

    @Test
    public void testPublicKey() throws Exception {
        log.info("TEST START: testPublicKey()");
        getRsaPublicKeyTest(Algorithm.RSA_2048, 2048, 128);
        getRsaPublicKeyTest(Algorithm.RSA_3072, 3072, 192);
        getRsaPublicKeyTest(Algorithm.RSA_4096, 4096, 256);
        log.info("TEST END: testPublicKey()");
    }

    private void getRsaPublicKeyTest(Algorithm algorithm, int keysize, int componentLength) throws Exception {
        log.info("Test retrieving the public part of an RSA key with algorithm " + algorithm.getName());
        short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_PSS), algorithm,
                                                                keysize, componentLength);

        try {
            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, algorithm);
            PublicKey returnedPubKey = key.getRsaPublicKey(session);
            assertEquals(pubKey, returnedPubKey);
        } finally {
            YHObject.delete(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }
}
