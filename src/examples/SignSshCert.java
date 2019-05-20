package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.AsymmetricKeyRsa;
import com.yubico.hsm.yhobjects.Template;
import com.yubico.hsm.yhobjects.YHObject;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

public class SignSshCert {

    private static byte[] sshTemplate = {
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

    private static String sshCertReq =
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

    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();


            short keyId = 5; // 5 because this is one of the white listed keys in the ssh cert template
            AsymmetricKeyRsa
                    .generateAsymmetricKey(session, keyId, "", Arrays.asList(5), Algorithm.RSA_2048, Arrays.asList(Capability.SIGN_SSH_CERTIFICATE));

            short tempId = Template.importTemplate(session, (short) 0, "", Arrays.asList(5), Arrays.asList(Capability.SIGN_SSH_CERTIFICATE),
                                                   Algorithm.TEMPLATE_SSH, sshTemplate);

            byte[] sshReq = Base64.getDecoder().decode(sshCertReq);
            byte[] sig = AsymmetricKey.signSshCertificate(session, keyId, tempId, Algorithm.RSA_PKCS1_SHA1, sshReq);

            byte[] reqReqSigRemoved = Arrays.copyOfRange(sshReq, 256 + 4, sshReq.length);
            ByteBuffer bb = ByteBuffer.allocate(reqReqSigRemoved.length + sig.length);
            bb.put(reqReqSigRemoved).put(sig);
            byte[] resultSshCert = bb.array();

            System.out.println("Got SSH certificate: " + Base64.getEncoder().encodeToString(resultSshCert));

            YHObject.delete(session, keyId, AsymmetricKey.TYPE);
            YHObject.delete(session, tempId, Template.TYPE);
            session.closeSession();
            yubihsm.close();
            backend.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
