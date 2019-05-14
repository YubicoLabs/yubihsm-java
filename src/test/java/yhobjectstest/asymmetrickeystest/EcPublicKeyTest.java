package yhobjectstest.asymmetrickeystest;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Type;
import com.yubico.hsm.yhobjects.AsymmetricKeyEc;
import com.yubico.hsm.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;

public class EcPublicKeyTest {
    Logger log = Logger.getLogger(EcPublicKeyTest.class.getName());

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init() throws Exception {
        if (session == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
            session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();
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
        getEcPublicKeyTest(Algorithm.EC_P224, "secp224r1", false);
        getEcPublicKeyTest(Algorithm.EC_P256, "secp256r1", false);
        getEcPublicKeyTest(Algorithm.EC_P384, "secp384r1", false);
        getEcPublicKeyTest(Algorithm.EC_P521, "secp521r1", false);
        getEcPublicKeyTest(Algorithm.EC_K256, "secp256k1", false);
        getEcPublicKeyTest(Algorithm.EC_BP256, "brainpoolP256r1", true);
        getEcPublicKeyTest(Algorithm.EC_BP384, "brainpoolP384r1", true);
        getEcPublicKeyTest(Algorithm.EC_BP512, "brainpoolP512r1", true);
        log.info("TEST END: testPublicKey()");
    }


    private void getEcPublicKeyTest(Algorithm algorithm, String curve, boolean brainpool) throws Exception {
        log.info("Test retrieving the public key of an EC key with algorithm " + algorithm.getName());
        final short id = 0x1234;
        KeyPair keypair = AsymmetricKeyTestHelper
                .importEcKey(session, id, "", Arrays.asList(2, 5, 8), Arrays.asList(Capability.SIGN_ECDSA), algorithm, curve, brainpool);

        try {
            final AsymmetricKeyEc key = new AsymmetricKeyEc(id, algorithm);
            PublicKey returnedPubKey = key.getEcPublicKey(session);
            assertEquals(keypair.getPublic(), returnedPubKey);
        } finally {
            YHObject.delete(session, id, Type.TYPE_ASYMMETRIC_KEY);
        }
    }
}
