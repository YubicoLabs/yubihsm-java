package examples;

import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhobjects.AuthenticationKey;
import com.yubico.hsm.yhobjects.YHObject;

import java.util.Arrays;

public class HandleAuthenticationKey {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();

            short id = AuthenticationKey.importAuthenticationKey(session, (short) 0, "test_auth_key", Arrays.asList(1, 2, 3),
                                                                 Algorithm.AES128_YUBICO_AUTHENTICATION,
                                                                 Arrays.asList(Capability.CHANGE_AUTHENTICATION_KEY), null, "foo123".toCharArray());

            YHSession session2 = new YHSession(yubihsm, id, "foo123".toCharArray());
            YHCore.secureEcho(session2, "example".getBytes());

            AuthenticationKey.changeAuthenticationKey(session2, id, "bar123".toCharArray());
            session2.closeSession();

            session2 = new YHSession(yubihsm, id, "bar123".toCharArray());
            YHCore.secureEcho(session2, "example".getBytes());
            session2.closeSession();


            YHObject.delete(session, id, AuthenticationKey.TYPE);
            session.closeSession();
            yubihsm.close();
            backend.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
