package pt.ulisboa.tecnico.SECDPAS;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.*;

public class FreshnessHandlerTest {

    private static FreshnessHandler clientHandler;
    private static FreshnessHandler serverHandler;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void successFreshness(){
        clientHandler = new FreshnessHandler();
        serverHandler = new FreshnessHandler();
        int num = 10;
        int seq = 0;

        while(num-- != 0){
            long freshnessClient = clientHandler.getNextFreshness();
            assertEquals(seq++, freshnessClient);
            assertTrue(serverHandler.verifyFreshness(freshnessClient));
            long freshnessServer = serverHandler.getNextFreshness();
            assertEquals(seq++, freshnessServer);
            assertTrue(clientHandler.verifyFreshness(freshnessServer));

        }
    }

    @Test
    public void successExceptionFreshness(){
        clientHandler = new FreshnessHandler();
        serverHandler = new FreshnessHandler();
        int num = 10;
        int seq = 0;

        while(num-- != 0){
            long freshnessClient = clientHandler.getNextFreshness();
            assertEquals(seq, freshnessClient);
            assertTrue(serverHandler.verifyFreshness(freshnessClient));

            assertEquals(seq++, freshnessClient);
            assertTrue(clientHandler.verifyExceptionFreshness(freshnessClient));
        }
    }

    @Test
    public void successOver(){
        clientHandler = new FreshnessHandler();
        serverHandler = new FreshnessHandler();
        int num = 10;
        int seq = 0;

        while(num-- != 0){
            long freshnessClient = clientHandler.getNextFreshness();
            assertEquals(seq++, freshnessClient);
            freshnessClient = clientHandler.getNextFreshness();
            assertEquals(seq++, freshnessClient);
            freshnessClient = clientHandler.getNextFreshness();
            assertEquals(seq++, freshnessClient);

            assertTrue(serverHandler.verifyFreshness(freshnessClient));
            long freshnessServer = serverHandler.getNextFreshness();
            assertEquals(seq++, freshnessServer);
            assertTrue(clientHandler.verifyFreshness(freshnessServer));

        }
    }

    @Test
    public void failUnder(){
        clientHandler = new FreshnessHandler();
        serverHandler = new FreshnessHandler();

        long freshnessClient = clientHandler.getNextFreshness()-1;
        assertFalse(serverHandler.verifyFreshness(freshnessClient));

        long freshnessServer = serverHandler.getNextFreshness()-1;
        assertFalse(clientHandler.verifyFreshness(freshnessServer));
    }

}
