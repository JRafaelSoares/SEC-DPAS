package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.primitives.Bytes;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;

import static org.junit.Assert.*;

public class FreshnessHandlerTest {

    private static FreshnessHandler clientHandler;
    private static FreshnessHandler serverHandler;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setUp() {
        clientHandler = new FreshnessHandler(System.currentTimeMillis());
        serverHandler = new FreshnessHandler(System.currentTimeMillis());

    }

    @Test
    public void success(){
        byte[] freshness1 = clientHandler.getFreshness();
        byte[] freshness2 = serverHandler.getFreshness();

        assertTrue(serverHandler.verifyFreshness(freshness1));
        assertTrue(clientHandler.verifyFreshness(freshness2));
    }

    @Test
    public void failNull(){
        assertFalse(serverHandler.verifyFreshness(null));
    }

    @Test
    public void failEmpty(){
        assertFalse(serverHandler.verifyFreshness(new byte[0]));
    }

    @Test
    public void failTooSmall(){
        byte[] freshness = clientHandler.getFreshness();
        freshness = Arrays.copyOf(freshness, freshness.length-1);

        assertFalse(serverHandler.verifyFreshness(freshness));
    }

    @Test
    public void failTooLong(){
        byte[] freshness = clientHandler.getFreshness();

        assertFalse(serverHandler.verifyFreshness(Bytes.concat(freshness, new byte[1])));
    }

    @Test
    public void failAlreadyUsed(){
        byte[] freshness = clientHandler.getFreshness();

        assertFalse(clientHandler.verifyFreshness(freshness));

        assertTrue(serverHandler.verifyFreshness(freshness));
        assertFalse(serverHandler.verifyFreshness(freshness));
    }

    @Test
    public void nonceCleaningSuccess(){
        FreshnessHandler testHandler = new FreshnessHandler(System.currentTimeMillis());

        testHandler.setNonceRefresh(1000);
        byte[] obtainedFreshness = testHandler.getFreshness();
        HashMap<ByteBuffer, Long> freshness = testHandler.getUsedNonces();
        assertEquals(freshness.size(), 1);
        try{
            Thread.sleep(2*1000);
        } catch (InterruptedException e){

        }
        testHandler.verifyFreshness(obtainedFreshness);
        freshness = testHandler.getUsedNonces();

        assertEquals(0, freshness.size());

    }

}
