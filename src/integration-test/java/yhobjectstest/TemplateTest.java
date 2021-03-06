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
package yhobjectstest;

import com.yubico.hsm.YHCore;
import com.yubico.hsm.YHSession;
import com.yubico.hsm.YubiHsm;
import com.yubico.hsm.backend.Backend;
import com.yubico.hsm.backend.HttpBackend;
import com.yubico.hsm.yhconcepts.Algorithm;
import com.yubico.hsm.yhconcepts.Capability;
import com.yubico.hsm.yhconcepts.Origin;
import com.yubico.hsm.yhconcepts.Type;
import com.yubico.hsm.yhdata.YHObjectInfo;
import com.yubico.hsm.yhobjects.Template;
import com.yubico.hsm.yhobjects.YHObject;
import lombok.extern.slf4j.Slf4j;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.*;

@Slf4j
public class TemplateTest {

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init() throws Exception {
        if (session == null) {
            openSession(new HttpBackend());
        }
        YHCore.resetDevice(session);
        yubihsm.close();

        Thread.sleep(1000);
        openSession(new HttpBackend());
    }

    private static void openSession(Backend backend) throws Exception {
        yubihsm = new YubiHsm(backend);
        session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
        session.authenticateSession();
    }

    @AfterClass
    public static void destroy() throws Exception {
        if(session != null) {
            session.closeSession();
            yubihsm.close();
        }
    }

    @Test
    public void testTemplateObject() throws Exception {
        log.info("TEST START: testTemplateObject()");

        final List domains = Arrays.asList(2, 5, 8);
        final List capabilities = Arrays.asList(Capability.GET_TEMPLATE);
        final String label = "template";

        byte[] templateData = new byte[1024];
        new Random().nextBytes(templateData);
        final short id = Template.importTemplate(session, (short) 0, label, domains, capabilities, Algorithm.TEMPLATE_SSH, templateData);

        try {
            // Verify object properties
            final YHObjectInfo tempObj = YHObject.getObjectInfo(session, id, Type.TYPE_TEMPLATE);
            assertNotEquals(0, tempObj.getId());
            assertEquals(id, tempObj.getId());
            assertEquals(Type.TYPE_TEMPLATE, tempObj.getType());
            assertEquals(domains, tempObj.getDomains());
            assertEquals(Algorithm.TEMPLATE_SSH, tempObj.getAlgorithm());
            assertEquals(Origin.YH_ORIGIN_IMPORTED, tempObj.getOrigin());
            assertEquals(label, tempObj.getLabel());
            assertEquals(capabilities.size(), tempObj.getCapabilities().size());
            assertTrue(tempObj.getCapabilities().containsAll(capabilities));
            assertEquals(0, tempObj.getDelegatedCapabilities().size());

            Template template = new Template(id);
            byte[] returnedTemplateData = template.getTemplate(session);
            assertArrayEquals(templateData, returnedTemplateData);
        } finally {
            YHObject.delete(session, id, Type.TYPE_TEMPLATE);
        }

        log.info("TEST END: testTemplateObject()");
    }

}
