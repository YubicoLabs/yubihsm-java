package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AsymmetricKeyRsa;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class RsaKey {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();


            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keypair = kpg.generateKeyPair();

            short id = AsymmetricKeyRsa.importKey(session, (short) 0, "test_rsa_key", Arrays.asList(1, 2, 3), Algorithm.RSA_2048, Arrays.asList(
                    Capability.SIGN_PKCS, Capability.SIGN_PSS, Capability.DECRYPT_PKCS, Capability.DECRYPT_OAEP),
                                                  (RSAPrivateKey) keypair.getPrivate());
            AsymmetricKeyRsa rsaKey = new AsymmetricKeyRsa(id, Algorithm.RSA_2048);

            byte[] pubKey = rsaKey.getPublicKey(session);
            System.out.println("YubiHSM returned RSA public key: " + Base64.getEncoder().encodeToString(pubKey));

            String data = "This is example data";
            System.out.println("Data: " + data);

            // Decrypting data using RSA-PKCS#1v1.5
            decryptPkcs1(session, keypair, rsaKey, data.getBytes());

            // Decrypting using RSA-OAEP
            decryptOaep(session, keypair, rsaKey, data.getBytes());

            // Signing data using RSA-PKCS#1v1.5
            signPkcs1(session, keypair, rsaKey, data.getBytes());

            // Signing data using RSA-PSS
            signPss(session, keypair, rsaKey, data.getBytes());

            rsaKey.delete(session);
            session.closeSession();
            yubihsm.close();
            backend.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void decryptPkcs1(YHSession session, KeyPair keypair, AsymmetricKeyRsa rsaKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keypair.getPublic());
        byte[] enc = cipher.doFinal(data);
        System.out.println("The data encrypted using RSA-PKCS#1v1.5 and the RSA key generated by this example: " + (new String(enc)));

        byte[] dec = rsaKey.decryptPkcs1(session, enc);
        System.out.println("The data decrypted using RSA-PKCS#1v1.5 and the RSA key on the YubiHSM: " + (new String(dec)));
    }

    private static void decryptOaep(YHSession session, KeyPair keypair, AsymmetricKeyRsa rsaKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keypair.getPublic());
        byte[] enc = cipher.doFinal(data);
        System.out.println("The data encrypted using RSA-OAEP, the RSA key generated by this example and Java native classes: " + (new String(enc)));

        byte[] dec = rsaKey.decryptOaep(session, enc, "", Algorithm.RSA_MGF1_SHA1, Algorithm.RSA_OAEP_SHA512);
        System.out.println("The data decrypted using RSA-OAEP and the RSA key on the YubiHSM: " + (new String(dec)));

        Security.addProvider(new BouncyCastleProvider());
        cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keypair.getPublic(), new SecureRandom());
        enc = cipher.doFinal(data);
        System.out.println("The data encrypted using RSA-OAEP, the RSA key generated by this example and BouncyCastle library: " + (new String(enc)));

        dec = rsaKey.decryptOaep(session, enc, "", Algorithm.RSA_MGF1_SHA512, Algorithm.RSA_OAEP_SHA512);
        System.out.println("The data decrypted using RSA-OAEP and the RSA key on the YubiHSM: " + (new String(dec)));
    }

    private static void signPkcs1(YHSession session, KeyPair keypair, AsymmetricKeyRsa rsaKey, byte[] data) throws Exception {
        byte[] signature = rsaKey.signPkcs1(session, data, Algorithm.RSA_PKCS1_SHA512);
        System.out.println("The data signed using RSA-PKCS#1v1.5 and the RSA key on the YubiHSM: " + (new String(signature)));

        Signature sig = Signature.getInstance("SHA512withRSA");
        sig.initVerify(keypair.getPublic());
        sig.update(data);
        boolean verified = sig.verify(signature);
        System.out.println("Verifying the signature using RSA-PKCS#1v1.5 and the RSA key generated by this example returned: " + verified);
    }

    private static void signPss(YHSession session, KeyPair keypair, AsymmetricKeyRsa rsaKey, byte[] data) throws Exception {
        byte[] signature = rsaKey.signPss(session, Algorithm.RSA_MGF1_SHA512, (short) 32, data);
        System.out.println("The data signed using RSA-PSS and the RSA key on the YubiHSM: " + (new String(signature)));

        Security.addProvider(new BouncyCastleProvider());
        Signature sig = Signature.getInstance("SHA512withRSA/PSS", "BC");
        MGF1ParameterSpec mgf1Param = new MGF1ParameterSpec("SHA-512");
        PSSParameterSpec pssParam = new PSSParameterSpec("SHA-512", "MGF1", mgf1Param, 32, 1);
        sig.setParameter(pssParam);
        sig.initVerify(keypair.getPublic());
        sig.update(data);
        boolean verified = sig.verify(signature);
        System.out.println("Verifying the signature using RSA-PSS and the RSA key generated by this example returned: " + verified);

    }
}