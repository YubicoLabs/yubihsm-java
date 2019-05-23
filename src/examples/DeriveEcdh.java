package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AsymmetricKeyEc;

import javax.crypto.KeyAgreement;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

public class DeriveEcdh {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();

            KeyPair hsmKeypair = generateEcKeyPair();
            KeyPair remoteKeypair = generateEcKeyPair();

            short id = AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(1), Algorithm.EC_P224, Arrays.asList(Capability.DERIVE_ECDH),
                                                 Utils.getUnsignedByteArrayFromBigInteger(((ECPrivateKey) hsmKeypair.getPrivate()).getS(), 28));
            AsymmetricKeyEc ecKey = new AsymmetricKeyEc(id, Algorithm.EC_P224);
            byte[] secretKey = ecKey.deriveEcdh(session, getUncompressedEcPublicKey(remoteKeypair.getPublic(), 28));
            System.out.println("Secret key generated by YubiHSM: " + Utils.getPrintableBytes(secretKey));

            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(remoteKeypair.getPrivate());
            keyAgreement.doPhase(hsmKeypair.getPublic(), true);
            secretKey = keyAgreement.generateSecret();
            System.out.println("Secret key generated by remote:  " + Utils.getPrintableBytes(secretKey));

            ecKey.delete(session);
            session.closeSession();
            yubihsm.close();
            backend.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp224r1"));
        return generator.generateKeyPair();
    }

    private static byte[] getUncompressedEcPublicKey(PublicKey publicKey, int length) {
        ECPublicKey pubkey = (ECPublicKey) publicKey;
        ECPoint point = pubkey.getW();
        byte[] x = Utils.getUnsignedByteArrayFromBigInteger(point.getAffineX(), length);
        byte[] y = Utils.getUnsignedByteArrayFromBigInteger(point.getAffineY(), length);
        ByteBuffer bb = ByteBuffer.allocate(1 + x.length + y.length);
        bb.put((byte) 0x04).put(x).put(y);
        return bb.array();
    }
}