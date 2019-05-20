import com.yubico.hsm.internal.util.Utils;
import com.yubico.hsm.yhconcepts.Capability;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.*;

@Slf4j
public class UtilsTest {

    @Test
    public void testPadding() {
        log.info("TEST START: testAddPadding()");
        byte[] pad = new byte[16];
        pad[0] = (byte) 0x80;

        for (int i = 0; i < 20; i++) {
            testPadding(i, pad);
        }
        log.info("TEST END: testAddPadding()");
    }

    private void testPadding(final int dataLength, final byte[] pad) {
        byte[] data = new byte[dataLength];
        new Random().nextBytes(data);
        byte[] padded = Utils.addPadding(data, 16);
        assertTrue("Padded data is not a multiple of 16", padded.length % 16 == 0);

        ByteBuffer bb = ByteBuffer.allocate(padded.length);
        bb.put(data);
        bb.put(pad, 0, padded.length - dataLength);
        assertTrue("Adding padding failed", Arrays.equals(bb.array(), padded));
        assertTrue("Removing padding failed", Arrays.equals(data, Utils.removePadding(padded, 16)));
    }

    @Test
    public void testGetShortFromList() {
        log.info("TEST START: testGetShortFromList()");

        List<Integer> values = new ArrayList(Arrays.asList(2, 5, 8));
        short expectedResult = 0x0092;
        assertEquals(expectedResult, Utils.getShortFromList(values));

        values = new ArrayList(Arrays.asList(1, 11));
        expectedResult = 0x0401;
        assertEquals(expectedResult, Utils.getShortFromList(values));

        values = new ArrayList(Arrays.asList(1, 8, 10, 11, 16));
        expectedResult = (short) 0x8681;
        assertEquals(expectedResult, Utils.getShortFromList(values));

        assertEquals(0, Utils.getShortFromList(new ArrayList<>()));

        assertEquals(0, Utils.getShortFromList(null));

        log.info("TEST END: testGetShortFromList()");
    }

    @Test
    public void testGetListFromShort() {
        log.info("TEST START: testGetListFromShort()");

        short s = (short) 0x0092;
        List<Integer> expectedResult = new ArrayList(Arrays.asList(2, 5, 8));
        List<Integer> actualResult = Utils.getListFromShort(s);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));

        s = (short) 0x0401;
        expectedResult = new ArrayList(Arrays.asList(1, 11));
        actualResult = Utils.getListFromShort(s);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));

        s = (short) 0x8681;
        expectedResult = new ArrayList(Arrays.asList(1, 8, 10, 11, 16));
        actualResult = Utils.getListFromShort(s);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));

        s = 0;
        actualResult = Utils.getListFromShort(s);
        assertNotNull(actualResult);
        assertEquals(0, actualResult.size());

        log.info("TEST END: testGetListFromShort()");
    }

    @Test
    public void testGetCapabilitiesFromList() {
        log.info("TEST START: testGetCapabilitiesFromList()");

        List<Capability> capabilities = new ArrayList(Arrays.asList(Capability.SIGN_ECDSA, Capability.WRAP_DATA, Capability.DELETE_TEMPLATE,
                                                                    Capability.GET_OPAQUE));
        long expectedResult = 0x0000102000000081L;
        assertEquals(expectedResult, Utils.getLongFromCapabilities(capabilities));

        capabilities = new ArrayList(Arrays.asList(Capability.GENERATE_ASYMMETRIC_KEY, Capability.DECRYPT_OAEP));
        expectedResult = 0x0000000000000410L;
        assertEquals(expectedResult, Utils.getLongFromCapabilities(capabilities));

        capabilities = new ArrayList(Arrays.asList(Capability.REWRAP_FROM_OTP_AEAD_KEY, Capability.UNWRAP_DATA,
                                                   Capability.DELETE_AUTHENTICATION_KEY, Capability.CHANGE_AUTHENTICATION_KEY));
        expectedResult = 0x0000414100000000L;
        assertEquals(expectedResult, Utils.getLongFromCapabilities((capabilities)));

        assertEquals(0, Utils.getLongFromCapabilities((new ArrayList<>())));

        assertEquals(0, Utils.getLongFromCapabilities((null)));

        log.info("TEST END: testGetCapabilitiesFromList()");
    }

    @Test
    public void testGetCapabilitiesFromLong() {
        log.info("TEST START: testGetCapabilitiesFromList()");

        long capabilities = 0x0000102000000081L;
        List<Capability> expectedResult = new ArrayList(Arrays.asList(Capability.SIGN_ECDSA, Capability.WRAP_DATA, Capability.DELETE_TEMPLATE,
                                                                      Capability.GET_OPAQUE));
        List<Capability> actualResult = Utils.getCapabilitiesFromLong(capabilities);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));

        capabilities = 0x0000000000000410L;
        expectedResult = new ArrayList(Arrays.asList(Capability.GENERATE_ASYMMETRIC_KEY, Capability.DECRYPT_OAEP));
        actualResult = Utils.getCapabilitiesFromLong(capabilities);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));

        capabilities = 0x0000414100000000L;
        expectedResult = new ArrayList(Arrays.asList(Capability.REWRAP_FROM_OTP_AEAD_KEY, Capability.UNWRAP_DATA,
                                                     Capability.DELETE_AUTHENTICATION_KEY, Capability.CHANGE_AUTHENTICATION_KEY));
        actualResult = Utils.getCapabilitiesFromLong(capabilities);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));

        capabilities = 0x0000000002000000L;
        expectedResult = new ArrayList(Arrays.asList(Capability.SIGN_SSH_CERTIFICATE));
        actualResult = Utils.getCapabilitiesFromLong(capabilities);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));


        capabilities = 0;
        actualResult = Utils.getCapabilitiesFromLong(capabilities);
        assertNotNull(actualResult);
        assertEquals(0, actualResult.size());

        log.info("TEST END: testGetCapabilitiesFromList()");
    }

}
