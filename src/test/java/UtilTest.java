import com.yubico.util.Utils;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Random;
import java.util.logging.Logger;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UtilTest {

    Logger logger = Logger.getLogger(YHSessionTest.class.getName());

    @Test
    public void testIsByteArrayEqual() {
        logger.info("TEST START: testIsByteArrayEqual()");

        for (int i = 0; i < 5; i++) {
            byte[] data = new byte[32];
            new Random().nextBytes(data);
            assertTrue("Fail to detect when two byte arrays are equal", Utils.isByteArrayEqual(data, data));
        }

        byte[] data1 = new byte[32];
        new Random().nextBytes(data1);
        byte[] data2 = new byte[32];
        new Random().nextBytes(data2);
        assertFalse("Fail to detect when two byte arrays are not equal", Utils.isByteArrayEqual(data1, data2));

        logger.info("TEST END: testIsByteArrayEqual()");
    }

    @Test
    public void testGetSubArray() {
        logger.info("TEST START: testGetSubArray()");

        byte[] data = new byte[32];
        new Random().nextBytes(data);

        ByteBuffer exp = ByteBuffer.allocate(8);
        exp.put(data, 0, 8);
        assertTrue("Failed to get a sub byte array", Utils.isByteArrayEqual(exp.array(), Utils.getSubArray(data, 0, 8)));

        exp = ByteBuffer.allocate(8);
        exp.put(data, data.length - 8, 8);
        assertTrue("Failed to get a sub byte array", Utils.isByteArrayEqual(exp.array(), Utils.getSubArray(data, data.length - 8, 8)));

        exp = ByteBuffer.allocate(8);
        exp.put(data, 10, 8);
        assertTrue("Failed to get a sub byte array", Utils.isByteArrayEqual(exp.array(), Utils.getSubArray(data, 10, 8)));

        logger.info("TEST END: testGetSubArray()");
    }


    @Test
    public void testPadding() {
        logger.info("TEST START: testAddPadding()");
        byte[] pad = new byte[16];
        pad[0] = (byte) 0x80;

        for (int i = 0; i < 20; i++) {
            testPadding(i, pad);
        }
        logger.info("TEST END: testAddPadding()");
    }

    private void testPadding(final int dataLength, final byte[] pad) {
        byte[] data = new byte[dataLength];
        new Random().nextBytes(data);
        byte[] padded = Utils.addPadding(data, 16);
        assertTrue("Padded data is not a multiple of 16", padded.length % 16 == 0);

        ByteBuffer bb = ByteBuffer.allocate(padded.length);
        bb.put(data);
        bb.put(pad, 0, padded.length - dataLength);
        assertTrue("Adding padding failed", Utils.isByteArrayEqual(bb.array(), padded));
        assertTrue("Removing padding failed", Utils.isByteArrayEqual(data, Utils.removePadding(padded)));
    }


}
