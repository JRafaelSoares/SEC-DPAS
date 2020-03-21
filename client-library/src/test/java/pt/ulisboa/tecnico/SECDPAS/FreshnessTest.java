package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

public class FreshnessTest {

    private static ClientLibrary lib;
    private static String s = "message";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @BeforeClass
    public static void setUp() {

        try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            PublicKey pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            lib = new ClientLibrary("localhost", 8080, pub, priv);
            lib.register();

            lib.setupConnection();

        }catch(Exception e){
            System.out.println("Unable to set up test");
        }
    }

    @AfterClass
    public static void cleanUp(){
        lib.cleanPosts();
    }

    @Test
    public void successPost() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

        lib.postRequest(request);
    }

    @Test
    public void successPostGeneral() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

        lib.postGeneralRequest(request);
    }

    @Test
    public void failPostFreshness() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

        lib.postRequest(request);
        thrown.expect(ClientNotRegisteredException.class);
        lib.postRequest(request);

    }

    @Test
    public void failGeneralPostFreshness() throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException{
        Contract.PostRequest request = lib.getPostRequest(s.toCharArray(), new Announcement[0]);

        lib.postGeneralRequest(request);
        thrown.expect(ClientNotRegisteredException.class);
        lib.postGeneralRequest(request);

    }

}
