package examples;

import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhdata.WrapData;
import com.yubico.hsm.yhobjects.AsymmetricKey;
import com.yubico.hsm.yhobjects.AsymmetricKeyEc;
import com.yubico.hsm.yhobjects.WrapKey;
import com.yubico.hsm.yhobjects.YHObject;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

public class Wrap {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();

            byte[] keyBytes = new byte[16];
            new SecureRandom().nextBytes(keyBytes);
            List capabilities = Arrays.asList(Capability.EXPORT_WRAPPED, Capability.IMPORT_WRAPPED, Capability.WRAP_DATA, Capability.UNWRAP_DATA,
                                              Capability.SIGN_ECDSA, Capability.EXPORTABLE_UNDER_WRAP);
            short id = WrapKey.importWrapKey(session, (short) 0, "test_wrap_key", Arrays.asList(2, 5, 8), Algorithm.AES128_CCM_WRAP, capabilities,
                                             capabilities, keyBytes);
            WrapKey key = new WrapKey(id);

            String data = "This is example data";
            System.out.println("Data: " + data);

            WrapData wrappedData = key.wrapData(session, data.getBytes());
            System.out.println("The data wrapped using Wrap key on the YubiHSM: " + wrappedData.toString());

            byte[] unwrappedData = key.unwrapData(session, wrappedData);
            System.out.println("Data unwrapped using Wrap key on the YubiHSM: " + (new String(unwrappedData)));


            short asymKeyId = AsymmetricKeyEc.generateAsymmetricKey(session, (short) 0, "asymkey", Arrays.asList(2, 5, 8), Algorithm.EC_P224,
                                                                    Arrays.asList(Capability.SIGN_ECDSA, Capability.EXPORTABLE_UNDER_WRAP));
            WrapData wrappedAsym = key.exportWrapped(session, asymKeyId, AsymmetricKey.TYPE);
            YHObject.delete(session, asymKeyId, AsymmetricKey.TYPE);

            key.importWrapped(session, wrappedAsym);


            key.delete(session);
            YHObject.delete(session, asymKeyId, AsymmetricKey.TYPE);
            session.closeSession();
            yubihsm.close();
            backend.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
