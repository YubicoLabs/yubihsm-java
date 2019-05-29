package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.AsymmetricKeyRsa;
import com.yubico.hsm.yhobjects.Opaque;
import com.yubico.hsm.yhobjects.YHObject;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

public class SignAttestationCert {

    private static final String tempCertificate = "-----BEGIN CERTIFICATE-----\n" +
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

    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();

            AsymmetricKeyRsa attestingKey = importRsaKey(session);

            short attestedId = AsymmetricKey.generateAsymmetricKey(session, (short) 0, "", Arrays.asList(1, 2, 3), Algorithm.RSA_2048,
                                                                   Arrays.asList(Capability.SIGN_PKCS));

            Opaque.importCertificate(session, attestingKey.getId(), "", Arrays.asList(1, 2, 3), getTempCertificate());
            X509Certificate attestationCert = attestingKey.signAttestationCertificate(session, attestedId);
            System.out.println("Signed attestation certificate");

            PublicKey attestingPublicKey = attestingKey.getRsaPublicKey(session);
            try {
                attestationCert.verify(attestingPublicKey);
                System.out.println("Verifying the attestation certificate succeeded");
            } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
                System.out.println("Verifying the attestation certificate failed");
            }

            YHObject.delete(session, attestingKey.getId(), Opaque.TYPE);
            YHObject.delete(session, attestedId, AsymmetricKey.TYPE);
            attestingKey.delete(session);
            session.closeSession();
            yubihsm.close();
            backend.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static X509Certificate getTempCertificate() throws CertificateException {
        String certStr = tempCertificate.replace("-----BEGIN CERTIFICATE-----\n", "");
        certStr = certStr.replace("-----END CERTIFICATE-----", "");
        byte[] encoded = org.bouncycastle.util.encoders.Base64.decode(certStr);
        ByteArrayInputStream in = new ByteArrayInputStream(encoded);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(in);
    }

    private static AsymmetricKeyRsa importRsaKey(YHSession session) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keypair = kpg.generateKeyPair();

        short id = AsymmetricKeyRsa.importKey(session, (short) 0, "", Arrays.asList(1, 2, 3), Algorithm.RSA_2048,
                                              Arrays.asList(Capability.SIGN_ATTESTATION_CERTIFICATE),
                                              (RSAPrivateKey) keypair.getPrivate());

        return new AsymmetricKeyRsa(id, Algorithm.RSA_2048);
    }
}
