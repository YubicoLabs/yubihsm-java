package examples;

import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhdata.LogData;

public class Logs {
    public static void main(String[] args) {
        try {
            Backend backend = new HttpBackend();
            YubiHsm yubihsm = new YubiHsm(backend);
            YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.authenticateSession();

            LogData logData = YHCore.getAuditLogData(session);
            System.out.println(logData.toString());

            short lastLogEntry = logData.getLastLogEntry().getItemNumber();
            YHCore.setAuditLogIndex(session, lastLogEntry);

            logData = YHCore.getAuditLogData(session);
            System.out.println(logData.toString());

            session.closeSession();
            yubihsm.close();
            backend.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
