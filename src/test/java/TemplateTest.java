import com.yubico.YHSession;
import com.yubico.YubiHsm;
import com.yubico.backend.Backend;
import com.yubico.backend.HttpBackend;
import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.ObjectOrigin;
import com.yubico.objects.yhconcepts.ObjectType;
import com.yubico.objects.yhobjects.Template;
import com.yubico.objects.yhobjects.YHObject;
import com.yubico.objects.yhobjects.YHObjectInfo;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class TemplateTest {
    Logger log = Logger.getLogger(TemplateTest.class.getName());

    private static YubiHsm yubihsm;
    private static YHSession session;

    @BeforeClass
    public static void init() throws Exception {
        if (session == null) {
            Backend backend = new HttpBackend();
            yubihsm = new YubiHsm(backend);
            session = new YHSession(yubihsm, (short) 1, "password".toCharArray());
            session.createAuthenticatedSession();
        }
    }

    @AfterClass
    public static void destroy() throws Exception {
        session.closeSession();
        yubihsm.close();
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
            final YHObjectInfo tempObj = YHObject.getObjectInfo(session, id, ObjectType.TYPE_TEMPLATE);
            assertNotEquals(0, tempObj.getId());
            assertEquals(id, tempObj.getId());
            assertEquals(ObjectType.TYPE_TEMPLATE, tempObj.getType());
            assertEquals(domains, tempObj.getDomains());
            assertEquals(Algorithm.TEMPLATE_SSH, tempObj.getAlgorithm());
            assertEquals(ObjectOrigin.YH_ORIGIN_IMPORTED, tempObj.getOrigin());
            assertEquals(label, tempObj.getLabel());
            assertEquals(capabilities.size(), tempObj.getCapabilities().size());
            assertTrue(tempObj.getCapabilities().containsAll(capabilities));
            assertEquals(0, tempObj.getDelegatedCapabilities().size());

            Template template = new Template(id, Algorithm.TEMPLATE_SSH);
            byte[] returnedTemplateData = template.getTemplate(session);
            assertArrayEquals(templateData, returnedTemplateData);
        } finally {
            YHObject.deleteObject(session, id, ObjectType.TYPE_TEMPLATE);
        }

        log.info("TEST END: testTemplateObject()");
    }

}
