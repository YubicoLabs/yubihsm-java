import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhdata.DeviceInfo;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@Slf4j
public class YubiHsmTest {

    private static YubiHsm yubihsm;

    @BeforeClass
    public static void init() throws MalformedURLException {
        if (yubihsm == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
        }
    }

    @AfterClass
    public static void destroy() {
        yubihsm.close();
    }


    @Test
    public void testPlainEcho() throws Exception {
        log.info("TEST START: testPlainEcho()");
        for (int i = 0; i < 5; i++) {
            byte[] data = new byte[32];
            new Random().nextBytes(data);

            byte[] response = yubihsm.echo(data);
            assertTrue(Arrays.equals(response, data));
        }
        log.info("TEST END: testPlainEcho()");
    }

    @Test
    public void testGetDeviceInfo() throws Exception {
        log.info("TEST START: testGetDeviceInfo()");
        DeviceInfo info = yubihsm.getDeviceInfo();
        assertNotNull(info);
        assertNotNull(info.getVersion());
        //assertNotEquals(0, info.getSerialnumber());
        assertNotNull(info.getSupportedAlgorithms());
        log.info("TEST END: testGetDeviceInfo()");
    }

}
