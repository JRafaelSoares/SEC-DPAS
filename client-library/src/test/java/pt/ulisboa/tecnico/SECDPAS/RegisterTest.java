package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.*;

public class RegisterTest {

	private static ClientLibrary lib1;
	private static ClientLibrary lib2;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@BeforeClass
	public static void setUp(){

		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			PublicKey pub = kp.getPublic();
			PrivateKey priv = kp.getPrivate();

			lib1 = new ClientLibrary("localhost", 8080, pub, priv);

			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			kp = kpg.genKeyPair();
			pub = kp.getPublic();
			priv = kp.getPrivate();

			lib2 = new ClientLibrary("localhost", 8080, pub, priv);
			
		}catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@AfterClass
	public static void cleanUp(){
		lib1.cleanPosts();
		lib2.cleanPosts();
		lib1.shutDown();
		lib2.shutDown();
	}

	@Test
	public void registerCorrectTest() throws ClientAlreadyRegisteredException, ComunicationException {
		lib1.register();
		assertTrue(lib1.clientRegisteredState());
	}

	@Test
	public void registerClientAlreadyRegisteredTest() throws ClientAlreadyRegisteredException, ComunicationException {
		lib2.register();
		thrown.expect(ClientAlreadyRegisteredException.class);
		lib2.register();
	}

}

