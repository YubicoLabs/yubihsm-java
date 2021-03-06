package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AsymmetricKeyEd;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

public class EdKey {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();


            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
            keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
            Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
            Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();

            short id = AsymmetricKeyEd.importKey(session, (short) 0, "ed_test_key", Arrays.asList(1), Algorithm.EC_ED25519, Arrays.asList(
                    Capability.SIGN_EDDSA), privateKey);
            final AsymmetricKeyEd edKey = new AsymmetricKeyEd(id, Algorithm.EC_ED25519);

            byte[] edPubKey = edKey.getPublicKey(session);
            System.out.println("YubiHSM returned ED public key: " + Base64.getEncoder().encodeToString(edPubKey));

            String data = "This is example data";
            System.out.println("Data: " + data);

            byte[] signature = edKey.signEddsa(session, data.getBytes());
            System.out.println("The data signed using ED key on the YubiHSM: " + Base64.getEncoder().encodeToString(signature));

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            Signer signer = new Ed25519Signer();
            signer.init(false, publicKey);
            signer.update(data.getBytes(), 0, data.getBytes().length);
            boolean verified = signer.verifySignature(signature);
            System.out.println("Verifying the signature using the ED key generated by this example returned: " + verified);

            edKey.delete(session);
            session.closeSession();
            yubihsm.close();
            backend.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
