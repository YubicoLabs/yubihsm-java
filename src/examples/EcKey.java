package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AsymmetricKeyEc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class EcKey {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();

            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp224r1"));
            KeyPair keypair = generator.generateKeyPair();
            short id = AsymmetricKeyEc.importKey(session, (short) 0, "test_ec_key", Arrays.asList(1, 2, 3), Algorithm.EC_P224, Arrays.asList(
                    Capability.SIGN_ECDSA), (ECPrivateKey) keypair.getPrivate());
            AsymmetricKeyEc ecKey = new AsymmetricKeyEc(id, Algorithm.EC_P224);

            byte[] pubKey = ecKey.getPublicKey(session);
            System.out.println("YubiHSM returned EC public key: " + Base64.getEncoder().encodeToString(pubKey));

            String data = "This is example data";
            System.out.println("Data: " + data);

            // Signing data
            byte[] signature = ecKey.signEcdsa(session, data.getBytes(), Algorithm.EC_ECDSA_SHA256);
            System.out.println("The data signed using ECDSA and the EC key on the YubiHSM: " + (new String(signature)));

            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(keypair.getPublic());
            sig.update(data.getBytes());
            boolean verified = sig.verify(signature);
            System.out.println("Verifying the signature using ECDSA and the EC key generated by this example returned: " + verified);

            ecKey.delete(session);
            session.closeSession();
            yubihsm.close();
            backend.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
