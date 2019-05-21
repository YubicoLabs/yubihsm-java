/*
 * Copyright 2019 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package yhobjectstest.asymmetrickeystest;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.AsymmetricKeyEc;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.KeyAgreement;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;

@Slf4j
public class EcDeriveEcdhTest {

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
    public void testDeriveEcdh() throws Exception {
        log.info("TEST START: testDeriveEcdh()");
        deriveEcdh(Algorithm.EC_P224, "secp224r1", 28, false);
        deriveEcdh(Algorithm.EC_P256, "secp256r1", 32, false);
        deriveEcdh(Algorithm.EC_P384, "secp384r1", 48, false);
        deriveEcdh(Algorithm.EC_P521, "secp521r1", 66, false);
        deriveEcdh(Algorithm.EC_K256, "secp256k1", 32, false);
        deriveEcdh(Algorithm.EC_BP256, "brainpoolP256r1", 32, true);
        deriveEcdh(Algorithm.EC_BP384, "brainpoolP384r1", 48, true);
        deriveEcdh(Algorithm.EC_BP512, "brainpoolP512r1", 64, true);
        log.info("TEST END: testDeriveEcdh()");
    }

    private void deriveEcdh(Algorithm algorithm, String curve, int componentLength, boolean brainpool) throws Exception {
        KeyPair keypair1 = generateEcKeyPair(curve, brainpool);
        KeyPair keypair2 = generateEcKeyPair(curve, brainpool);

        ECPrivateKey privkey = (ECPrivateKey) keypair1.getPrivate();
        short keyid = AsymmetricKeyEc.importKey(session, (short) 0, "", Arrays.asList(1), algorithm, Arrays.asList(Capability.DERIVE_ECDH),
                                                Utils.getUnsignedByteArrayFromBigInteger(privkey.getS(), componentLength));
        try {
            byte[] secretKey = getVerificationSecretKey(keypair1.getPrivate(), keypair2.getPublic(), brainpool);

            AsymmetricKeyEc key = new AsymmetricKeyEc(keyid, algorithm);
            byte[] ecdh = key.deriveEcdh(session, getUncompressedEcPublicKey(keypair2.getPublic(), componentLength));
            assertArrayEquals(secretKey, ecdh);

            ecdh = key.deriveEcdh(session, (ECPublicKey) keypair2.getPublic());
            assertArrayEquals(secretKey, ecdh);
        } finally {
            YHObject.delete(session, keyid, AsymmetricKey.TYPE);
        }
    }

    private byte[] getVerificationSecretKey(PrivateKey privkey, PublicKey pubkey, boolean brainpool) throws Exception {
        KeyAgreement keyAgreement;
        if (brainpool) {
            keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        } else {
            keyAgreement = KeyAgreement.getInstance("ECDH");
        }
        keyAgreement.init(privkey);
        keyAgreement.doPhase(pubkey, true);
        return keyAgreement.generateSecret();
    }

    private KeyPair generateEcKeyPair(String curve, boolean brainpool) throws Exception {
        KeyPairGenerator generator;
        if (brainpool) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            generator = KeyPairGenerator.getInstance("EC", "BC");
        } else {
            generator = KeyPairGenerator.getInstance("EC");
        }
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private byte[] getUncompressedEcPublicKey(PublicKey publicKey, int length) {
        ECPublicKey pubkey = (ECPublicKey) publicKey;
        ECPoint point = pubkey.getW();
        byte[] x = Utils.getUnsignedByteArrayFromBigInteger(point.getAffineX(), length);
        byte[] y = Utils.getUnsignedByteArrayFromBigInteger(point.getAffineY(), length);
        ByteBuffer bb = ByteBuffer.allocate(1 + x.length + y.length);
        bb.put((byte) 0x04).put(x).put(y);
        return bb.array();
    }
}
