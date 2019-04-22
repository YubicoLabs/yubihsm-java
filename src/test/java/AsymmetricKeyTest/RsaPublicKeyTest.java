package AsymmetricKeyTest;

import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.exceptions.*;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.AsymmetricKeyRsa;
import com.yubico.objects.yhobjects.YHObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.MalformedURLException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;

public class RsaPublicKeyTest {
    Logger logger = Logger.getLogger(RsaPublicKeyTest.class.getName());

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init()
            throws MalformedURLException, InvalidKeySpecException, NoSuchAlgorithmException, YHConnectionException, YHDeviceException,
                   YHAuthenticationException, YHInvalidResponseException {
        if (session == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
            session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.createAuthenticatedSession();
        }
    }

    @AfterClass
    public static void destroy()
            throws YHDeviceException, YHAuthenticationException, YHInvalidResponseException, YHConnectionException, InvalidKeyException,
                   NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException,
                   IllegalBlockSizeException {
        session.closeSession();
        yubihsm.close();
    }

    @Test
    public void testPublicKey() throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException,
                                       YHDeviceException, InvalidAlgorithmParameterException, YHAuthenticationException,
                                       YHInvalidResponseException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException,
                                       UnsupportedAlgorithmException {

        logger.info("TEST START: testPublicKey()");

        getRsaPublicKeyTest(Algorithm.RSA_2048, 2048, 128);
        getRsaPublicKeyTest(Algorithm.RSA_3072, 3072, 192);
        getRsaPublicKeyTest(Algorithm.RSA_4096, 4096, 256);

        logger.info("TEST END: testPublicKey()");

    }

    private void getRsaPublicKeyTest(Algorithm algorithm, int keysize, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, UnsupportedAlgorithmException {

        short id = 0x1234;
        PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, id, "", Arrays.asList(2, 5), Arrays.asList(Capability.SIGN_PSS), algorithm,
                                                                keysize, componentLength);

        try {
            AsymmetricKeyRsa key = new AsymmetricKeyRsa(id, algorithm);
            PublicKey returnedPubKey = key.getRsaPublicKey(session);
            assertEquals(pubKey, returnedPubKey);
        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_ASYMMETRIC_KEY);
        }
    }
}
