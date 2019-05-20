package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhobjects.Opaque;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ImportCert {
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

    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();

            X509Certificate testCert = getTestCertificate();

            System.out.println("Importing test certificate: " + java.util.Base64.getEncoder().encodeToString(testCert.getEncoded()));
            short id = Opaque.importCertificate(session, (short) 0, "test_cert", Arrays.asList(1, 2, 3), testCert);

            Opaque opaque = new Opaque(id, Algorithm.OPAQUE_X509_CERTIFICATE);
            X509Certificate importedCert = opaque.getCertificate(session);
            System.out.println("Certificate retrieved from the YubiHsm: " + java.util.Base64.getEncoder().encodeToString(importedCert.getEncoded()));

            opaque.delete(session);
            session.closeSession();
            yubihsm.close();
            backend.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static X509Certificate getTestCertificate() throws CertificateException {
        String certStr = testCertificate.replace("-----BEGIN CERTIFICATE-----\n", "");
        certStr = certStr.replace("-----END CERTIFICATE-----", "");
        byte[] encoded = Base64.decode(certStr);
        ByteArrayInputStream in = new ByteArrayInputStream(encoded);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(in);
    }
}
