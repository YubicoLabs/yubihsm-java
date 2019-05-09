import com.yubico.hsm.internal.util.Utils;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;

public class UtilsTest {
    Logger log = Logger.getLogger(YHSessionTest.class.getName());

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

}
