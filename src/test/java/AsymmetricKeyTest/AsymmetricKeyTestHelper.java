package AsymmetricKeyTest;

import com.yubico.YHSession;
import com.yubico.exceptions.*;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhobjects.AsymmetricKeyEc;
import com.yubico.objects.yhobjects.AsymmetricKeyRsa;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
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
                                         Algorithm algorithm,
                                         int keysize,
                                         int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, InvalidKeySpecException, UnsupportedAlgorithmException {
        byte[] p;
        byte[] q;
        PublicKey publicKey;

        // Sometimes, the prime numbers byte array is not exactly the expected length. When it is longer, it starts with 0 bytes
        // TODO Find out why and how to avoid it (it seems to be a java.security thing)
        do {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keysize);
            KeyPair keypair = kpg.generateKeyPair();
            publicKey = keypair.getPublic();

            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKeySpec ks = kf.getKeySpec(keypair.getPrivate(), RSAPrivateCrtKeySpec.class);

            p = ks.getPrimeP().toByteArray();
            q = ks.getPrimeQ().toByteArray();

        } while (p.length < componentLength);

        if (p.length > componentLength) {
            p = Arrays.copyOfRange(p, p.length - componentLength, p.length);
            q = Arrays.copyOfRange(q, q.length - componentLength, q.length);
        }

        AsymmetricKeyRsa.importKey(session, id, label, domains, algorithm, capabilities, p, q);

        return publicKey;
    }

    public static KeyPair importEcKey(YHSession session, short id, String label, List<Integer> domains, List<Capability> capabilities,
                                      Algorithm algorithm, String curve, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, UnsupportedAlgorithmException {
        byte[] d;
        KeyPair keypair;

        // Sometimes, the prime numbers byte array is not exactly the expected length. When it is longer, it starts with 0 bytes
        // TODO Find out why and how to avoid it (it seems to be a java.security thing)
        do {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            keypair = generator.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) keypair.getPrivate();
            d = privateKey.getS().toByteArray();
        } while (d.length < componentLength);
        if (d.length > componentLength) {
            d = Arrays.copyOfRange(d, d.length - componentLength, d.length);
        }

        AsymmetricKeyEc.importKey(session, id, label, domains, algorithm, capabilities, d);
        return keypair;
    }

    public static KeyPair importEcBrainpoolKey(YHSession session, short id, String label, List<Integer> domains, List<Capability> capabilities,
                                               Algorithm algorithm, String curve, int componentLength)
            throws NoSuchPaddingException, NoSuchAlgorithmException, YHConnectionException, InvalidKeyException, YHDeviceException,
                   InvalidAlgorithmParameterException, YHAuthenticationException, YHInvalidResponseException, BadPaddingException,
                   IllegalBlockSizeException, NoSuchProviderException, UnsupportedAlgorithmException {
        byte[] d;
        KeyPair keypair;

        // Sometimes, the prime numbers byte array is not exactly the expected length. When it is longer, it starts with 0 bytes
        // TODO Find out why and how to avoid it (it seems to be a java.security thing)
        do {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(new ECGenParameterSpec(curve));
            keypair = generator.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) keypair.getPrivate();
            d = privateKey.getS().toByteArray();
        } while (d.length < componentLength);
        if (d.length > componentLength) {
            d = Arrays.copyOfRange(d, d.length - componentLength, d.length);
        }

        AsymmetricKeyEc.importKey(session, id, label, domains, algorithm, capabilities, d);
        return keypair;
    }

}
