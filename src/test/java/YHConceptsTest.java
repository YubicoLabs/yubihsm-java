import com.yubico.objects.yhconcepts.Algorithm;
import com.yubico.objects.yhconcepts.Capability;
import com.yubico.objects.yhconcepts.Command;
import com.yubico.objects.yhconcepts.YHConcept;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.Assert.*;

public class YHConceptsTest {
    Logger log = Logger.getLogger(YHConceptsTest.class.getName());

    @Test
    public void testConceptsEquality() {
        log.info("TEST START: testConceptsEquality()");
        assertTrue(YHConcept.equals(Algorithm.EC_ECDSA_SHA1, Algorithm.EC_ECDSA_SHA1));
        assertTrue(YHConcept.equals(Capability.DELETE_AUTHENTICATION_KEY, Capability.DELETE_AUTHENTICATION_KEY));
        assertFalse(YHConcept.equals(Algorithm.EC_ECDSA_SHA1, Capability.DELETE_AUTHENTICATION_KEY));
        assertFalse(YHConcept.equals(Algorithm.RSA_PKCS1_SHA512, Command.AUTHENTICATE_SESSION)); // Both concepts have ID 0x04
        log.info("TEST END: testConceptsEquality()");
    }


    @Test
    public void testGetCapabilitiesFromList() {
        log.info("TEST START: testGetCapabilitiesFromList()");

        List<Capability> capabilities = new ArrayList(Arrays.asList(Capability.SIGN_ECDSA, Capability.WRAP_DATA, Capability.DELETE_TEMPLATE,
                                                                    Capability.GET_OPAQUE));
        long expectedResult = 0x0000102000000081L;
        assertEquals(expectedResult, Capability.getCapabilities(capabilities));

        capabilities = new ArrayList(Arrays.asList(Capability.GENERATE_ASYMMETRIC_KEY, Capability.DECRYPT_OAEP));
        expectedResult = 0x0000000000000410L;
        assertEquals(expectedResult, Capability.getCapabilities(capabilities));

        capabilities = new ArrayList(Arrays.asList(Capability.REWRAP_FROM_OTP_AEAD_KEY, Capability.UNWRAP_DATA,
                                                   Capability.DELETE_AUTHENTICATION_KEY, Capability.CHANGE_AUTHENTICATION_KEY));
        expectedResult = 0x0000414100000000L;
        assertEquals(expectedResult, Capability.getCapabilities(capabilities));

        assertEquals(0, Capability.getCapabilities(new ArrayList<>()));

        assertEquals(0, Capability.getCapabilities(null));

        log.info("TEST END: testGetCapabilitiesFromList()");
    }

    @Test
    public void testGetCapabilitiesFromLong() {
        log.info("TEST START: testGetCapabilitiesFromList()");

        long capabilities = 0x0000102000000081L;
        List<Capability> expectedResult = new ArrayList(Arrays.asList(Capability.SIGN_ECDSA, Capability.WRAP_DATA, Capability.DELETE_TEMPLATE,
                                                                      Capability.GET_OPAQUE));
        List<Capability> actualResult = Capability.getCapabilities(capabilities);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));

        capabilities = 0x0000000000000410L;
        expectedResult = new ArrayList(Arrays.asList(Capability.GENERATE_ASYMMETRIC_KEY, Capability.DECRYPT_OAEP));
        actualResult = Capability.getCapabilities(capabilities);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));

        capabilities = 0x0000414100000000L;
        expectedResult = new ArrayList(Arrays.asList(Capability.REWRAP_FROM_OTP_AEAD_KEY, Capability.UNWRAP_DATA,
                                                     Capability.DELETE_AUTHENTICATION_KEY, Capability.CHANGE_AUTHENTICATION_KEY));
        actualResult = Capability.getCapabilities(capabilities);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));

        capabilities = 0x0000000002000000L;
        expectedResult = new ArrayList(Arrays.asList(Capability.SIGN_SSH_CERTIFICATE));
        actualResult = Capability.getCapabilities(capabilities);
        assertEquals(expectedResult.size(), actualResult.size());
        assertTrue(actualResult.containsAll(expectedResult));


        capabilities = 0;
        actualResult = Capability.getCapabilities(capabilities);
        assertNotNull(actualResult);
        assertEquals(0, actualResult.size());

        log.info("TEST END: testGetCapabilitiesFromList()");
    }

}
