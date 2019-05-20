package examples;

import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.internal.util.Utils;

public class OpenSession {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);

            System.out.println("Connecting to YubiHSM device:");
            System.out.println(yubihsm.getDeviceInfo().toString());

            byte[] data = {1, 2, 3, 4, 5};
            System.out.println("Sending echo command with data: " + Utils.getPrintableBytes(data));
            byte[] retData = yubihsm.echo(data);
            System.out.println("Received response: " + Utils.getPrintableBytes(retData));

            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();

            byte[] data2 = {6, 7, 8, 9, 10};
            System.out.println("Sending echo command over encrypted session with data: " + Utils.getPrintableBytes(data2));
            retData = YHCore.secureEcho(session, data2);
            System.out.println("Received response: " + Utils.getPrintableBytes(retData));

            session.closeSession();
            yubihsm.close();
            backend.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
