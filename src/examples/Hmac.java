package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.HmacKey;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class Hmac {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();


            byte[] key = new byte[64];
            new SecureRandom().nextBytes(key);

            short id = HmacKey.importHmacKey(session, (short) 0, "test_hmac_key", Arrays.asList(1, 2, 3), Algorithm.HMAC_SHA256, Arrays.asList(
                    Capability.SIGN_HMAC, Capability.VERIFY_HMAC), key);
            HmacKey hmacKey = new HmacKey(id, Algorithm.HMAC_SHA256);

            byte[] data = "This is example data".getBytes();

            byte[] hmacSig = hmacKey.signHmac(session, data);
            System.out.println("HMAC signature performed by HMAC key on YubiHSM:              " + Base64.getEncoder().encodeToString(hmacSig));

            SecretKeySpec javaHmacKey = new SecretKeySpec(key, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(javaHmacKey);
            byte[] javaHmacSig = mac.doFinal(data);
            System.out.println("HMAC signature performed by HMAC key created by this example: " + Base64.getEncoder().encodeToString(javaHmacSig));

            boolean verified = hmacKey.verifyHmac(session, data, javaHmacSig);
            System.out.println("Verifying the signature using the HMAC key on the YubiHSM returned: " + verified);

            hmacKey.delete(session);
            session.closeSession();
            yubihsm.close();
            backend.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
