package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.ListObjectsFilter;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.HmacKey;
import com.yubico.hsm.yhobjects.WrapKey;
import com.yubico.hsm.yhobjects.YHObject;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class ListObjects {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();

            // Generate 2 Asymmetric keys, 1 HMAC key and 1 Wrapkey
            short asymid1 = AsymmetricKey.generateAsymmetricKey(session, (short) 0, "ec_sign_ssh", Arrays.asList(1), Algorithm.EC_P224,
                                                                Arrays.asList(Capability.SIGN_SSH_CERTIFICATE, Capability.EXPORT_WRAPPED));
            short asymid2 = AsymmetricKey.generateAsymmetricKey(session, (short) 0, "ec_sign_ecdsa", Arrays.asList(2), Algorithm.EC_P224,
                                                                Arrays.asList(Capability.SIGN_ECDSA));
            short hmacid = HmacKey.generateHmacKey(session, (short) 0, "hmac", Arrays.asList(3, 4), Algorithm.HMAC_SHA256,
                                                   Arrays.asList(Capability.VERIFY_HMAC));
            short wrapid = WrapKey.generateWrapKey(session, (short) 0, "wrap", Arrays.asList(2, 4), Algorithm.AES192_CCM_WRAP,
                                                   Arrays.asList(Capability.EXPORT_WRAPPED), null);

            // List object with domains 5 and type HMAC key
            HashMap filters = new HashMap();
            filters.put(ListObjectsFilter.DOMAINS, Utils.getShortFromList(Arrays.asList(5)));
            filters.put(ListObjectsFilter.TYPE, HmacKey.TYPE);
            List<YHObjectInfo> objects = YHObject.getObjectList(session, filters);

            System.out.println("Found items:");
            for (YHObjectInfo info : objects) {
                System.out.println(info.toString());
            }

            YHObject.delete(session, asymid1, AsymmetricKey.TYPE);
            YHObject.delete(session, asymid2, AsymmetricKey.TYPE);
            YHObject.delete(session, hmacid, HmacKey.TYPE);
            YHObject.delete(session, wrapid, WrapKey.TYPE);
            session.closeSession();
            yubihsm.close();
            backend.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
