package pt.ulisboa.tecnico.SECDPAS;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.*;

public class RegisterTest {

	private static ClientLibrary lib;
	private static PublicKey pub1;
	private static PrivateKey priv1;
	private static PublicKey pub2;
	private static PrivateKey priv2;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@BeforeClass
	public static void setUp(){
		lib = new ClientLibrary("localhost", 8080);

		try{

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			pub1 = kp.getPublic();
			priv1 = kp.getPrivate();

			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp2 = kpg.genKeyPair();
			pub2 = kp2.getPublic();
			priv2 = kp2.getPrivate();

		}catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@Test
	public void registerCorrectTest() throws ClientAlreadyRegisteredException, pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException{
		lib.register(pub1, priv1);
		assertTrue(lib.clientRegisteredState(pub1));
	}

	@Test
	public void registerClientAlreadyRegisteredTest() throws ClientAlreadyRegisteredException, pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException{
		lib.register(pub2, priv2);
		thrown.expect(ClientAlreadyRegisteredException.class);
		lib.register(pub2, priv2);
	}

	@Test
	public void registerNullTest() throws ClientAlreadyRegisteredException, pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException{
		thrown.expect(pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException.class);
		lib.register(null, null);
	}
}

