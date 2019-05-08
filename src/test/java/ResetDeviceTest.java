import com.yubico.YHCore;
import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhobjects.Opaque;
import com.yubico.objects.yhobjects.YHObject;
import com.yubico.objects.yhobjects.YHObjectInfo;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class ResetDeviceTest {
    Logger log = Logger.getLogger(ResetDeviceTest.class.getName());

    private static YubiHsm yubihsm;

    @BeforeClass
    public static void init() throws MalformedURLException {
        if (yubihsm == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
        }
    }

    @AfterClass
    public static void destroy() throws Exception {
        yubihsm.close();
    }

    @Test
    public void testResetDevice() throws Exception {
        log.info("TEST START: testResetDevice()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        assertNotNull("Failed to create an authenticated session", session);

        byte[] data = new byte[16];
        new Random().nextBytes(data);
        Opaque.importOpaque(session, (short) 0, "", Arrays.asList(1, 2), new ArrayList<Capability>(), Algorithm.OPAQUE_DATA, data);
        List<YHObjectInfo> objects = YHObject.getObjectList(session, null);
        assertTrue(objects.size() > 1);

        YHCore.resetDevice(session);
        destroy();

        Thread.sleep(1000);
        init();

        session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        assertNotNull("Failed to create an authenticated session", session);
        objects = YHObject .getObjectList(session, null);
        assertEquals(1, objects.size());

        log.info("TEST END: testResetDevice()");
    }

}