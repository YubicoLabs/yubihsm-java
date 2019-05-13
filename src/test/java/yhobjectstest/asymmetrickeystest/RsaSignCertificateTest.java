package yhobjectstest.asymmetrickeystest;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class RsaSignCertificateTest {
    Logger log = Logger.getLogger(RsaSignCertificateTest.class.getName());

    private static YubiHsm yubihsm;
    private static YHSession session;

    byte[] sshTemplate = {
            // Timestamp key algorithm RSA2048
            (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0x09,
            // Timestamp public key
            (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0xc2, (byte) 0x55, (byte) 0x62, (byte) 0x08, (byte) 0xf5, (byte) 0xd2, (byte) 0xc2,
            (byte) 0x81, (byte) 0xb8, (byte) 0xa5, (byte) 0x16, (byte) 0xfd, (byte) 0x27, (byte) 0x25, (byte) 0xe6, (byte) 0x7e, (byte) 0x88,
            (byte) 0xcd, (byte) 0xc5, (byte) 0xd2, (byte) 0xcf, (byte) 0xdf, (byte) 0xd3, (byte) 0xea, (byte) 0x2d, (byte) 0x35, (byte) 0xdf,
            (byte) 0x35, (byte) 0x27, (byte) 0x93, (byte) 0x44, (byte) 0x45, (byte) 0xa6, (byte) 0x14, (byte) 0x84, (byte) 0xee, (byte) 0xcb,
            (byte) 0x02, (byte) 0xc4, (byte) 0x7b, (byte) 0x67, (byte) 0xc5, (byte) 0x94, (byte) 0x16, (byte) 0xde, (byte) 0xe4, (byte) 0xa6,
            (byte) 0x1f, (byte) 0x25, (byte) 0x52, (byte) 0x4b, (byte) 0x27, (byte) 0x9d, (byte) 0x4d, (byte) 0x09, (byte) 0xb1, (byte) 0x9b,
            (byte) 0x3e, (byte) 0xc5, (byte) 0x89, (byte) 0xde, (byte) 0xe2, (byte) 0x90, (byte) 0xda, (byte) 0xa0, (byte) 0x64, (byte) 0xc7,
            (byte) 0xb3, (byte) 0xaa, (byte) 0xae, (byte) 0xc7, (byte) 0x23, (byte) 0x55, (byte) 0x37, (byte) 0xa0, (byte) 0xea, (byte) 0x63,
            (byte) 0xb4, (byte) 0x1b, (byte) 0x65, (byte) 0x4a, (byte) 0x7f, (byte) 0x71, (byte) 0xc6, (byte) 0x5c, (byte) 0xc2, (byte) 0x34,
            (byte) 0xfe, (byte) 0xa6, (byte) 0x02, (byte) 0xc9, (byte) 0xd6, (byte) 0x65, (byte) 0x13, (byte) 0x5d, (byte) 0xca, (byte) 0x74,
            (byte) 0x32, (byte) 0xf8, (byte) 0x7c, (byte) 0x01, (byte) 0x4b, (byte) 0x67, (byte) 0x61, (byte) 0xdf, (byte) 0x27, (byte) 0xdd,
            (byte) 0x1d, (byte) 0xed, (byte) 0x2f, (byte) 0x71, (byte) 0xcb, (byte) 0x8b, (byte) 0x23, (byte) 0x74, (byte) 0x4c, (byte) 0xfc,
            (byte) 0x99, (byte) 0xe2, (byte) 0x23, (byte) 0xed, (byte) 0xa5, (byte) 0xd8, (byte) 0x41, (byte) 0xe2, (byte) 0x9f, (byte) 0x82,
            (byte) 0x19, (byte) 0xbd, (byte) 0xae, (byte) 0x50, (byte) 0xfb, (byte) 0xb9, (byte) 0xc7, (byte) 0xe6, (byte) 0x83, (byte) 0x01,
            (byte) 0xac, (byte) 0x1c, (byte) 0x63, (byte) 0x89, (byte) 0xb2, (byte) 0xac, (byte) 0xa7, (byte) 0xfd, (byte) 0x01, (byte) 0x2a,
            (byte) 0xa3, (byte) 0xd4, (byte) 0x0d, (byte) 0x88, (byte) 0xf4, (byte) 0xcf, (byte) 0x9f, (byte) 0xed, (byte) 0xc1, (byte) 0x19,
            (byte) 0xc8, (byte) 0x64, (byte) 0x71, (byte) 0xd3, (byte) 0x02, (byte) 0x6b, (byte) 0x9f, (byte) 0x0d, (byte) 0xc2, (byte) 0xdf,
            (byte) 0x81, (byte) 0x5d, (byte) 0x53, (byte) 0x82, (byte) 0x3e, (byte) 0xa0, (byte) 0xab, (byte) 0xf2, (byte) 0x93, (byte) 0xc9,
            (byte) 0xa4, (byte) 0xa8, (byte) 0x3b, (byte) 0x71, (byte) 0xc1, (byte) 0xf4, (byte) 0xe3, (byte) 0x31, (byte) 0xa5, (byte) 0xdc,
            (byte) 0xfe, (byte) 0xc7, (byte) 0x9e, (byte) 0x7f, (byte) 0xd8, (byte) 0x2d, (byte) 0xd9, (byte) 0xfc, (byte) 0x90, (byte) 0xde,
            (byte) 0xa8, (byte) 0xdb, (byte) 0x77, (byte) 0x0b, (byte) 0x2f, (byte) 0xb0, (byte) 0xf4, (byte) 0x49, (byte) 0x21, (byte) 0x95,
            (byte) 0x95, (byte) 0x4b, (byte) 0x7e, (byte) 0xa0, (byte) 0x6f, (byte) 0x15, (byte) 0x8f, (byte) 0x95, (byte) 0xdd, (byte) 0x72,
            (byte) 0x39, (byte) 0x7a, (byte) 0x13, (byte) 0xb6, (byte) 0xcc, (byte) 0xfa, (byte) 0x9a, (byte) 0x07, (byte) 0x2d, (byte) 0x41,
            (byte) 0xcf, (byte) 0x12, (byte) 0xaf, (byte) 0x8e, (byte) 0x87, (byte) 0x9f, (byte) 0x97, (byte) 0xf1, (byte) 0x1e, (byte) 0x00,
            (byte) 0xac, (byte) 0xce, (byte) 0x2d, (byte) 0x12, (byte) 0xd4, (byte) 0x34, (byte) 0x0c, (byte) 0x40, (byte) 0x84, (byte) 0x33,
            (byte) 0x3a, (byte) 0x6c, (byte) 0x9f, (byte) 0x22, (byte) 0x7d, (byte) 0x6f, (byte) 0x89, (byte) 0x87, (byte) 0xfb,
            // CA key whitelist (0x0001, 0x00ab, 0x0014, 0x0005, 0x003a)
            (byte) 0x03, (byte) 0x00, (byte) 0x0a, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0xab, (byte) 0x00, (byte) 0x14, (byte) 0x00,
            (byte) 0x05, (byte) 0x00, (byte) 0x3a,
            // Not before
            (byte) 0x04, (byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            // Not after
            (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            // Principals blacklist (root, toor)
            (byte) 0x06, (byte) 0x00, (byte) 0x0a, (byte) 0x72, (byte) 0x6f, (byte) 0x6f, (byte) 0x74, (byte) 0x00, (byte) 0x74, (byte) 0x6f,
            (byte) 0x6f, (byte) 0x72, (byte) 0x00};

    String sshCertReq =
            "WypxIFBhW0F8BI6TEmfB9wiU0UGodR1OQU/v3Ro3LkcxMWlvj/VaBGaiiYmjz2QpugqKe2jCXgxJ+cCap+oE2Ybz4wS0ztGmhl1wxFoOhW9fKiml5Mxe/zJBMJzVw/LK" +
            "D/2bt7aIWD3kkd5JWkkyR/6ykQUztefPzhAYSw3h0xG5luXC/vXyCvA33sNmaMTDvAbbhJ1rCQP3NJuU10JcqtNTXWDLhOUvGJOh3NiGPko/J4N1/hzUyVeE3/R/mDH9" +
            "xyoEkzJtze5xjbDdQkrEkJi22dl80GW7S+x/+RG8JORGP+3UyOAkB4/8BhgJo4LpWkgqhCtvB9cQ8JoSV2hYvvJFnpcAAAAcc3NoLXJzYS1jZXJ0LXYwMUBvcGVuc3No" +
            "LmNvbQAAACCR54Q0ir0fUixPp1n7l9JLB72tH69TmlA1cbBjZOKIzwAAAAMBAAEAAAEBANgqGFZAW+XH7ZRvHxiHMxDG+gAe3/j1r4naXQU50hVVeEG3iVGcC+C8PGVA" +
            "34TS8a/YDwtAflmEkiSpqoNwC25qvLFgvqGtoU+W6Kf+wyFBp3O8EArbTP1674Wsmef7lH4Jt7aNXQNLnC7GzDucs7KvXUjTUTPCuMIhEECOVCYuuzJuaUtt6UqjC8aj" +
            "ExxyfSNLKek7+yZO4qS8raCc8t20YyE7JbPZILhi2wzT3N+f3w7qdNA/twRnrLfq4skM4kQDPG+cVu57DXz85nasexAm8bmvU2x0u4ok1ZHYyHL7b1JYlOuNwhK80d77" +
            "SfM5UYbUMp82Gze3ik9De9nwJl8AAAAAAAAAAAAAAAEAAAAIaWRlbnRpdHkAAAASAAAABXVzZXIxAAAABXVzZXIyAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBl" +
            "cm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1w" +
            "dHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDTNa0aiuJNCaq0KYsevclBIr4R0w6rJe28Xi+q8kgUWxTu4wOb" +
            "8VKHDWEJUWDJm7s/vv5FRogwBQRu1goXi9i88/FQUMvVjIcXpWw2/CQw0NKZFnIPqUfkP9AVwYZm2fpHPVJ8m7KetP79mW0z82uh11ohMDbc1KYmsiL+XCbm+u68VAns" +
            "kPj62JHyIs6pawZeVS0hcO3T2xCz78cJvOIdR6hY/xNKmEp9zouM21LHqmbKcLbBEXsth3QKbs2rQdD7E/G5oEFZ6p0pQnv/RGq3uyasYZypa7c/3LFzGJhWUWBlIEBR" +
            "WMcxhoJGJZko+zrANNick4ET28WoceNP7uaf";
    String expectedSshCert =
            "AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgkeeENIq9H1IsT6dZ+5fSSwe9rR+vU5pQNXGwY2TiiM8AAAADAQABAAABAQDYKhhWQFvlx+2Ubx8YhzMQ" +
            "xvoAHt/49a+J2l0FOdIVVXhBt4lRnAvgvDxlQN+E0vGv2A8LQH5ZhJIkqaqDcAtuaryxYL6hraFPluin/sMhQadzvBAK20z9eu+FrJnn+5R+Cbe2jV0DS5wuxsw7nLOy" +
            "r11I01EzwrjCIRBAjlQmLrsybmlLbelKowvGoxMccn0jSynpO/smTuKkvK2gnPLdtGMhOyWz2SC4YtsM09zfn98O6nTQP7cEZ6y36uLJDOJEAzxvnFbuew18/OZ2rHsQ" +
            "JvG5r1NsdLuKJNWR2Mhy+29SWJTrjcISvNHe+0nzOVGG1DKfNhs3t4pPQ3vZ8CZfAAAAAAAAAAAAAAABAAAACGlkZW50aXR5AAAAEgAAAAV1c2VyMQAAAAV1c2VyMgAA" +
            "AAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9y" +
            "dC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAABFwAAAAdzc2gtcnNhAAAAAwEAAQAAAQEA0zWtGoriTQmq" +
            "tCmLHr3JQSK+EdMOqyXtvF4vqvJIFFsU7uMDm/FShw1hCVFgyZu7P77+RUaIMAUEbtYKF4vYvPPxUFDL1YyHF6VsNvwkMNDSmRZyD6lH5D/QFcGGZtn6Rz1SfJuynrT+" +
            "/ZltM/NroddaITA23NSmJrIi/lwm5vruvFQJ7JD4+tiR8iLOqWsGXlUtIXDt09sQs+/HCbziHUeoWP8TSphKfc6LjNtSx6pmynC2wRF7LYd0Cm7Nq0HQ+xPxuaBBWeqd" +
            "KUJ7/0Rqt7smrGGcqWu3P9yxcxiYVlFgZSBAUVjHMYaCRiWZKPs6wDTYnJOBE9vFqHHjT+7mnwAAAQ8AAAAHc3NoLXJzYQAAAQAKzJbRw6UF+yAvOnCJc0IBIRRExmG9" +
            "x1/wiwQwqIGBF26K5YgqSvhYghxnGCaaJLX5HMnoEuKT3GPBTTk3RLQGJylTO6FysbB/7HaIaFS6/+QpZ7yuCzPDePiQ4DPaHHZaGM/fIhd6un2EP9FKGG1njKBk6Vfc" +
            "uZmJhdYogjM/ldr7i5I10nMf3UpiCmf73AhtS+TtnyLa4AKOjMsz5giRTSbzx92tCOxj8OgJFHjU88C311ydYgCM3t7NdVyb+4XOPViwSsjDxYblP/SGKVcuetRkKahC" +
            "uvO0kj93w0SqzDC4grLLKZzqhKUPWFk9Q+PE3Rjf5IJFIuqn4ibIQfs3";

    String rsaPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                           "MIIEpQIBAAKCAQEA0zWtGoriTQmqtCmLHr3JQSK+EdMOqyXtvF4vqvJIFFsU7uMD\n" +
                           "m/FShw1hCVFgyZu7P77+RUaIMAUEbtYKF4vYvPPxUFDL1YyHF6VsNvwkMNDSmRZy\n" +
                           "D6lH5D/QFcGGZtn6Rz1SfJuynrT+/ZltM/NroddaITA23NSmJrIi/lwm5vruvFQJ\n" +
                           "7JD4+tiR8iLOqWsGXlUtIXDt09sQs+/HCbziHUeoWP8TSphKfc6LjNtSx6pmynC2\n" +
                           "wRF7LYd0Cm7Nq0HQ+xPxuaBBWeqdKUJ7/0Rqt7smrGGcqWu3P9yxcxiYVlFgZSBA\n" +
                           "UVjHMYaCRiWZKPs6wDTYnJOBE9vFqHHjT+7mnwIDAQABAoIBAQCL375WF6grML22\n" +
                           "NtUFdNa1plaN42KRgbrhxtZ2taF6qZ9BXWJkgfsPqZKb4yLgIZxuaQRnyIAknQ4E\n" +
                           "gQeJ9HmDGWK0t+1l7X0B8fGqsG0fTwxJig3bxVXxGTmrTtC9iJoxV7ErCMnQRTmh\n" +
                           "pVwmzYx4T/BGjnGm6cVnVw3JuimhSVWQnMLUNcwTBQjcwbKI3o/Y4FhoDe0GYof8\n" +
                           "6gJq+cj7jFn+x89e1uuXev562CidbOzfGYEc45X+I+DLEN9+xjRPZM0bfnyBS/bM\n" +
                           "/SCmvcgprITomY+d7H4iJ08BTEEo1z0fWcT8yfM2UgzOrUsjGCOBoZsOnr5zpnlC\n" +
                           "hfmBc+1BAoGBAOvIt1YN8YpOa/6+y2s8+c95S9yPmdTuO3QanybQMrb1W7iWlOb5\n" +
                           "bi3aEuU7cUY+cHbzAYf2WC93pT3cKDPbuvG09EUTXExWw1hOGQ3ot3pgkbshmcBK\n" +
                           "8TeQn3kp4d7YM92hnzDLPoEpkWuPdN+If3x2+CQ0Bs8IZjCRJGn5yMAPAoGBAOVR\n" +
                           "kiLV2qltk5xnOEvlzNXJoaxYeJBiQhXZOrwzYXJXUxz1Kk4QROlSVRboFvHImdGS\n" +
                           "MoLaUJ5WDE77z77v2f8+zaAeoSakbFaIofJ4qTvXrsc7L4djg9prveQvDZY50mbH\n" +
                           "SR5la5aQxJkA+TeE1hEowRhNK69aUJIfyfnga+BxAoGBAJG3946IiYm3k8jZs7Av\n" +
                           "/Be8WCUU3raZEUddGJUNQPqPwsLe1WG2L+DIkLr5NLV761eoMX8MwU18vTPw9yut\n" +
                           "lejBs+Fo6LcJPCs8AQH2nEZWnlovlu0fo9p6WASy3LQznEJSG6c1RQjgXs5B17I6\n" +
                           "kseiYxNE0BxtjXJgkUeppucDAoGAZd5Tlaf8Z9Fmhk8QIh8mXD4i1MXEYRdVFhGW\n" +
                           "1u3YNwv1vuJl9aGiiydo5zEYqDWdpwxT5e8Hax78fsW75qzz4UBL5fpVSi42dkZh\n" +
                           "8q2JOC061gRDu9gIRaohA9GnLnnnLoMOxzL0lUEgJHvbOb+HvL2m8Z2ub0omipMW\n" +
                           "jSsVoPECgYEAodn6s+oG9zpq9Gl4Q8jsPiQAgsjwc4CGzz/oBvWooGf8pei0N2gj\n" +
                           "MIByXmIhpexBlJ4o/MgEMj7g299usGKq06Dg4dMn1DtunkSF/Vd1OcjlZVJpRmrJ\n" +
                           "m2HWLeo2pjD9W9KaMzZWQ5jxpGliC2TtpWuP44/ihZODFrQZc8DytPo=\n" +
                           "-----END RSA PRIVATE KEY-----";

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
    public void testSigningAttestationCertificate() throws Exception {
        log.info("TEST START: testSigningAttestationCertificate()");
        short attestingKeyid = 0x5678;
        short attestedKeyid = 0x0123;
        try {

            PublicKey pubKey = AsymmetricKeyTestHelper.importRsaKey(session, attestingKeyid, "", Arrays.asList(2, 5, 8),
                                                                    Arrays.asList(Capability.SIGN_ATTESTATION_CERTIFICATE),
                                                                    Algorithm.RSA_2048, 2048, 128);
            AsymmetricKey attestingKey = new AsymmetricKey(attestingKeyid, Algorithm.RSA_2048);


            AsymmetricKey.generateAsymmetricKey(session, attestedKeyid, "", Arrays.asList(2, 5, 8), Algorithm.RSA_2048,
                                                Arrays.asList(Capability.SIGN_PKCS));


            boolean exceptionThrown = false;
            try {
                attestingKey.signAttestationCertificate(session, attestedKeyid);
            } catch (UnsupportedOperationException e) {
                exceptionThrown = true;
            }
            assertTrue(exceptionThrown);

            Opaque.importCertificate(session, attestingKeyid, "", Arrays.asList(2, 5, 8), AsymmetricKeyTestHelper.getTestCertificate());
            X509Certificate attestationCert = attestingKey.signAttestationCertificate(session, attestedKeyid);

            try {
                attestationCert.verify(pubKey);
            } catch (Exception e) {
                fail("Attestation certificate was not valid");
            }

        } finally {
            YHObject.delete(session, attestedKeyid, AsymmetricKey.TYPE);
            YHObject.delete(session, attestingKeyid, AsymmetricKey.TYPE);
            YHObject.delete(session, attestingKeyid, Opaque.TYPE);
        }
        log.info("TEST END: testSigningAttestationCertificate()");
    }

    @Test
    public void testSSHCertificateSign() throws Exception {
        log.info("TEST START: testSSHCertificateSign()");

        PrivateKey pk = getRsaPrivateKeyFromPemString(rsaPrivateKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec ks = kf.getKeySpec(pk, RSAPrivateCrtKeySpec.class);

        byte[] prime1 = ks.getPrimeP().toByteArray();
        byte[] prime2 = ks.getPrimeQ().toByteArray();

        prime1 = Arrays.copyOfRange(prime1, prime1.length - 128, prime1.length);
        prime2 = Arrays.copyOfRange(prime2, prime2.length - 128, prime2.length);


        short keyId = 5; // 5 because this is one of the white listed keys in the ssh cert req
        short templateId = 10;

        try {
            AsymmetricKeyRsa.importKey(session, keyId, "", Arrays.asList(5), Algorithm.RSA_2048, Arrays.asList(Capability.SIGN_SSH_CERTIFICATE),
                                       prime1, prime2);

            Template.importTemplate(session, templateId, "", Arrays.asList(5), Arrays.asList(Capability.SIGN_SSH_CERTIFICATE),
                                    Algorithm.TEMPLATE_SSH, sshTemplate);


            byte[] sshReq = Base64.getDecoder().decode(sshCertReq);
            byte[] sig = AsymmetricKey.signSshCertificate(session, keyId, templateId, Algorithm.RSA_PKCS1_SHA1, sshReq);

            byte[] reqReqSigRemoved = Arrays.copyOfRange(sshReq, 256 + 4, sshReq.length);
            ByteBuffer bb = ByteBuffer.allocate(reqReqSigRemoved.length + sig.length);
            bb.put(reqReqSigRemoved).put(sig);
            byte[] resultCert = bb.array();


            byte[] expectedResultCert = Base64.getDecoder().decode(expectedSshCert);

            assertEquals(expectedResultCert.length, resultCert.length);
            assertArrayEquals(expectedResultCert, resultCert);
        } finally {
            YHObject.delete(session, keyId, AsymmetricKey.TYPE);
        }
        log.info("TEST END: testSSHCertificateSign()");
    }

    private PrivateKey getRsaPrivateKeyFromPemString(@Nonnull String pemPrivKey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        PEMParser pemParser = new PEMParser(new StringReader(pemPrivKey));
        PEMKeyPair ukp = (PEMKeyPair) pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair kp = converter.getKeyPair(ukp);
        return kp.getPrivate();
    }

}
