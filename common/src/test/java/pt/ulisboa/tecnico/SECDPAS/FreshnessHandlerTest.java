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
            long freshnessClient = clientHandler.getFreshness();
            assertEquals(seq, freshnessClient);
            assertTrue(serverHandler.verifyFreshness(freshnessClient));
            clientHandler.incrementFreshness();
            assertEquals(++seq, clientHandler.getFreshness());
            serverHandler.incrementFreshness();
            long freshnessServer = serverHandler.getFreshness();
            assertEquals(seq, freshnessServer);
            assertTrue(clientHandler.verifyFreshness(freshnessServer));

        }
    }
    /*
    @Test
    public void successExceptionFreshness(){
        clientHandler = new FreshnessHandler();
        serverHandler = new FreshnessHandler();
        int num = 10;
        int seq = 0;

        while(num-- != 0){
            clientHandler.incrementFreshness();
            long freshnessClient = clientHandler.getFreshness();
            assertEquals(seq, freshnessClient);
            assertTrue(serverHandler.verifyFreshness(freshnessClient));

            assertEquals(seq++, freshnessClient);
            assertTrue(clientHandler.verifyExceptionFreshness(freshnessClient));
        }
    }
    */
    @Test
    public void failOver(){
        clientHandler = new FreshnessHandler();
        serverHandler = new FreshnessHandler();
        int num = 10;
        int seq = 0;

        while(num-- != 0){
            clientHandler.incrementFreshness();
            long freshnessClient = clientHandler.getFreshness();
            assertEquals(++seq, freshnessClient);

            clientHandler.incrementFreshness();
            freshnessClient = clientHandler.getFreshness();
            assertEquals(++seq, freshnessClient);

            clientHandler.incrementFreshness();
            freshnessClient = clientHandler.getFreshness();
            assertEquals(++seq, freshnessClient);

            assertFalse(serverHandler.verifyFreshness(freshnessClient));

            serverHandler.incrementFreshness();
            long freshnessServer = serverHandler.getFreshness();
            assertFalse(clientHandler.verifyFreshness(freshnessServer));
        }
    }

    @Test
    public void failUnder(){
        clientHandler = new FreshnessHandler();
        serverHandler = new FreshnessHandler();

        long freshnessClient = clientHandler.getFreshness()-1;
        assertFalse(serverHandler.verifyFreshness(freshnessClient));

        long freshnessServer = serverHandler.getFreshness()-1;
        assertFalse(clientHandler.verifyFreshness(freshnessServer));
    }

}
