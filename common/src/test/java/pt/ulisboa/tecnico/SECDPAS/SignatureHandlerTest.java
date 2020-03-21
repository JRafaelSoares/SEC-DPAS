package pt.ulisboa.tecnico.SECDPAS;

import com.google.common.primitives.Bytes;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Arrays;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SignatureHandlerTest {

    private static SignatureHandler clientHandler;
    private static FreshnessHandler serverHandler;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setUp() {
        //clientHandler = new SignatureHandler();
        //serverHandler = new FreshnessHandler();

    }

    @Test
    public void success(){

    }
}
