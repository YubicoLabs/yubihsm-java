/*
 * Copyright 2019 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.Opaque;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.*;

@Slf4j
public class ResetDeviceTest {

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
        if(yubihsm != null) {
            yubihsm.close();
        }
    }

    @Test
    public void testResetDevice() throws Exception {
        log.info("TEST START: testResetDevice()");
        YHSession session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        session.authenticateSession();
        assertNotNull("Failed to create an authenticated session", session);

        List<YHObjectInfo> objects = YHObject.getObjectList(session, null);
        if(objects.size() == 1) {
            byte[] data = new byte[16];
            new Random().nextBytes(data);
            Opaque.importOpaque(session, (short) 0, "", Arrays.asList(1, 2), null, Algorithm.OPAQUE_DATA, data);
            objects = YHObject.getObjectList(session, null);
        }
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
