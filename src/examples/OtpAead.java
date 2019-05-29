package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhdata.YubicoOtpData;
import com.yubico.hsm.yhobjects.OtpAeadKey;
import org.bouncycastle.util.encoders.Hex;

import javax.annotation.Nonnull;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class OtpAead {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();

            byte[] otpAeadKey = new byte[16];
            new SecureRandom().nextBytes(otpAeadKey);
            byte[] nonceId = new byte[4];
            new Random().nextBytes(nonceId);
            short id1 = OtpAeadKey.importOtpAeadKey(session, (short) 0, "test_otp_aead_key1", Arrays.asList(2, 5, 8), Algorithm.AES128_YUBICO_OTP,
                                                    Arrays.asList(Capability.CREATE_OTP_AEAD, Capability.DECRYPT_OTP,
                                                                  Capability.REWRAP_FROM_OTP_AEAD_KEY), nonceId, otpAeadKey);
            OtpAeadKey key1 = new OtpAeadKey(id1);

            short id2 = OtpAeadKey.generateOtpAeadKey(session, (short) 0, "test_otp_aead_key2", Arrays.asList(2, 5, 8), Algorithm.AES128_YUBICO_OTP,
                                                      Arrays.asList(Capability.CREATE_OTP_AEAD, Capability.DECRYPT_OTP,
                                                                    Capability.REWRAP_TO_OTP_AEAD_KEY), 1);
            OtpAeadKey key2 = new OtpAeadKey(id2);


            byte[] knownKey = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
            byte[] knownPrivateId = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
            String knownOtp = "dvgtiblfkbgturecfllberrvkinnctnn";
            YubicoOtpData decryptedKnownOtp = new YubicoOtpData((short) 1, (byte) 1, (byte) 1, (short) 1);
            System.out.println("A known OTP decrypted: " + decryptedKnownOtp.toString());

            byte[] aead1 = key1.createOtpAed(session, knownKey, knownPrivateId);
            System.out.println("Created AEAD: " + Utils.getPrintableBytes(aead1));

            byte[] aead2 = OtpAeadKey.rewrapOtpAead(session, key1.getId(), key2.getId(), aead1);
            System.out.println("Re-wrapped previous aead: " + Utils.getPrintableBytes(aead2));

            String otpHex = encodedStringToHex(knownOtp);
            byte[] otpBin = Hex.decode(otpHex);
            YubicoOtpData decryptedOtp = key1.decryptOtp(session, aead1, otpBin);
            System.out.println("A known OTP decrypted using the AEAD on the YubiHSM: " + decryptedOtp.toString());

            key1.delete(session);
            key2.delete(session);
            session.closeSession();
            yubihsm.close();
            backend.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String encodedStringToHex(@Nonnull String string) {
        List from = Arrays.asList('c', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'r', 't', 'u', 'v');
        List to = Arrays.asList('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');

        char[] newString = string.toCharArray();
        for (int i = 0; i < newString.length; i++) {
            newString[i] = (char) to.get(from.indexOf(newString[i]));
        }
        return new String(newString);
    }
}
