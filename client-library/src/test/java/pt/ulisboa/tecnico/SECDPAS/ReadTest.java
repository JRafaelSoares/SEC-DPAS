package pt.ulisboa.tecnico.SECDPAS;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.*;

public class ReadTest {

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

			lib.register(pub1);

		}catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}
	@Test
	public void readTest(){
		try{
			String s = "ReadTest";
			lib.post(pub1, s.toCharArray());

			Announcement[] announcement = lib.read(pub1, 1);
			System.out.println("Size: " + announcement.length);
			String readPost = new String(announcement[0].getPost());
			assertEquals(readPost,s);
		}catch(Exception e){
			fail(e.getCause().getMessage());
		}
	}
}

