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
import com.yubico.hsm.exceptions.*;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AsymmetricKeyEc;
import com.yubico.hsm.yhobjects.AsymmetricKeyRsa;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class AsymmetricKeyTestHelper {

    private static final String testCertificate = "-----BEGIN CERTIFICATE-----\n" +
                                                  "MIIDMzCCAhugAwIBAgIIV9+4OgOubr4wDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UE\n" +
                                                  "AwwQTmV3TWFuYWdlbWVudEtleTAeFw0xODEyMTMwOTQ1MjVaFw0xODEyMjIxMDEw\n" +
                                                  "MTlaMBcxFTATBgNVBAMMDHl1Ymljb19hZG1pbjCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
                                                  "ggEPADCCAQoCggEBAL2WcfkFWwrBO5ylKVdGMGmGBmiP6neQk8OHhZsTicxry6hw\n" +
                                                  "GJoivGrI6KuBj919+MWcXbgs5lYW1gV+YduUOGPj0JoGMHsZWDzkRo1iF1I0B9Nf\n" +
                                                  "tRhgkd0eSuhzoi1ainZ5MKvR0Tj5J6nnzs/Oy9W9EguUdNjh+LLGuvbJCuDhXYCU\n" +
                                                  "bgGWhNg+bpKtn4bFpOJatJVseXXQdRdJtzdKSFou2xtQPSJqE1+WurxJ1/Qx0ZaA\n" +
                                                  "wPywaAEkUbMRaPFsO2171ZflT01J+S4IO1BpHad6J47LAOWgKODcxdI231WymelB\n" +
                                                  "Qp719v/Bbry5L4/KBj6SWKlKvt7SfOnfxkC4r1ECAwEAAaN/MH0wDAYDVR0TAQH/\n" +
                                                  "BAIwADAfBgNVHSMEGDAWgBRn/G1+IF6vtGM40OvlGxTHnRCUWDAdBgNVHSUEFjAU\n" +
                                                  "BggrBgEFBQcDAgYIKwYBBQUHAwQwHQYDVR0OBBYEFHrLsuB8yPWS4LeMQs0UjYCT\n" +
                                                  "O1v+MA4GA1UdDwEB/wQEAwIF4DANBgkqhkiG9w0BAQsFAAOCAQEAs3c3gPCCC33E\n" +
                                                  "I7lQEp/hrA0bu9K6VCa9NrzSXP8DFXn4hgM487678yhh7PlQ9T60VVnxVpuJgs8M\n" +
                                                  "3PRiVvzY11ABjdnjjDMss5jNC3dOi7MLIT6xxDh5U/1XulEmUoqP7RkXCcmDKg+8\n" +
                                                  "Vd7TnsmlutTmwKRiLOa8zl/o3aJoeCqg+FdNC3hRZuR3w5mG5IlaZ+VLwY7tjdov\n" +
                                                  "12mcMSxsC1JG0aUXv+RdBUtNG1JXFBYA43FBwMNjZPsiYXYgN0T24zGW6OQnTbB3\n" +
                                                  "kw4LNCS2l7cuEDiHwFmxVyCSInUSzcbfryltKCzzqWOCSPuKxwZzhHuRQ1tyy+MB\n" +
                                                  "SKlmUkdizg==\n" +
                                                  "-----END CERTIFICATE-----";

    public static X509Certificate getTestCertificate() throws CertificateException {
        String certStr = testCertificate.replace("-----BEGIN CERTIFICATE-----\n", "");
        certStr = certStr.replace("-----END CERTIFICATE-----", "");
        byte[] encoded = org.bouncycastle.util.encoders.Base64.decode(certStr);
        ByteArrayInputStream in = new ByteArrayInputStream(encoded);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(in);
    }

    public static PublicKey importRsaKey(YHSession session, short id, String label, List<Integer> domains, List<Capability> capabilities,
                                         Algorithm algorithm, int keysize)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, UnsupportedAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keysize);
        KeyPair keypair = kpg.generateKeyPair();

        AsymmetricKeyRsa.importKey(session, id, label, domains, algorithm, capabilities, (RSAPrivateKey) keypair.getPrivate());

        return keypair.getPublic();
    }

    public static KeyPair importEcKey(YHSession session, short id, String label, List<Integer> domains, List<Capability> capabilities,
                                      Algorithm algorithm, String curve, boolean brainpool)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator;
        if (brainpool) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            generator = KeyPairGenerator.getInstance("EC", "BC");
        } else {
            generator = KeyPairGenerator.getInstance("EC");
        }
        generator.initialize(new ECGenParameterSpec(curve));
        KeyPair keypair = generator.generateKeyPair();

        ECPrivateKey privateKey = (ECPrivateKey) keypair.getPrivate();
        AsymmetricKeyEc.importKey(session, id, label, domains, algorithm, capabilities, privateKey);

        return keypair;
    }
}
