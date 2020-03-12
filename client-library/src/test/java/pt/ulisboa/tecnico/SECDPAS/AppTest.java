package pt.ulisboa.tecnico.SECDPAS;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.*;

public class AppTest {

	private static ClientLibrary lib;
	private static PublicKey pub1;
	private static PublicKey pub2;

	@Rule
	public ExpectedException thrown= ExpectedException.none();

	@BeforeClass
	public static void setUp(){
		lib = new ClientLibrary("localhost", 8080);

		try{

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			pub1 = kp.getPublic();

			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp2 = kpg.genKeyPair();
			pub2 = kp2.getPublic();
			//PrivateKey privateKey = kp.getPrivate();

		}catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@Test
	public void registerCorrectTest(){
		try{
			lib.Register(pub1);
		}catch(pt.ulisboa.tecnico.SECDPAS.ClientAlreadyRegistredException e){
			fail(e.getMessage());
		}
	}

	@Test()
	public void registerClientAlreadyRegisteredTest() throws pt.ulisboa.tecnico.SECDPAS.ClientAlreadyRegistredException{
		lib.Register(pub2);
		thrown.expect(pt.ulisboa.tecnico.SECDPAS.ClientAlreadyRegistredException.class);
		lib.Register(pub2);
	}
}

