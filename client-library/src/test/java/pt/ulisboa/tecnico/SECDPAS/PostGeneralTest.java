package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.*;

public class PostGeneralTest {

	private static ClientLibrary lib1;
	private static ClientLibrary lib2;
	private static PublicKey pub1;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@BeforeClass
	public static void setUp(){

		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			pub1 = kp.getPublic();
			PrivateKey priv = kp.getPrivate();

			lib1 = new ClientLibrary("localhost", 8080, pub1, priv);

			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp2 = kpg.genKeyPair();
			PublicKey pub = kp2.getPublic();
			priv = kp2.getPrivate();

			lib2 = new ClientLibrary("localhost", 8080, pub, priv);

			lib1.register();

		}catch (Exception e){
			System.out.println("// Exception message: " + e.getMessage());
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@AfterClass
	public static void cleanUp(){
		lib1.cleanGeneralPosts();
		lib2.cleanGeneralPosts();
		lib1.shutDown();
		lib2.shutDown();

	}
	@Test
	public void postGeneralCorrectNoAnnouncementsTest() throws ClientNotRegisteredException, InvalidArgumentException {
		String s = "NoAnnouncement";
		lib1.postGeneral(s.toCharArray());

		assertTrue(lib1.postGeneralState(s.toCharArray()));
	}

	@Test
	public void postGeneralCorrectWithAnnouncementsTest() throws ClientNotRegisteredException, InvalidArgumentException, ClientSignatureException {
		String s1 = "NoAnnouncement";
		//Announcement a = new Announcement(s1.toCharArray(), pub1, 0);
		lib1.postGeneral(s1.toCharArray());

		String[] announcements = {Integer.toString(lib1.readGeneral(1)[0].getAnnouncementID())};


		String s2 = "WithAnnouncement";

		lib1.postGeneral(s2.toCharArray(), announcements);

		assertTrue(lib1.postGeneralState(s1.toCharArray()));
		assertTrue(lib1.postGeneralState(s2.toCharArray(), announcements));
	}

	@Test
	public void postGeneralMessageLimitTest() throws ClientNotRegisteredException, InvalidArgumentException {
		char[] messageLimit = new char[255];
		for (int i = 0; i<255; i++){
			messageLimit[i] = 'a';
		}

		lib1.postGeneral(messageLimit);
		assertTrue(lib1.postGeneralState(messageLimit));
	}

	@Test
	public void postGeneralMessageEmptyTest() throws ClientNotRegisteredException, pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException{
		char[] emptyMessage = new char[0];
		lib1.postGeneral(emptyMessage);

		assertTrue(lib1.postGeneralState(emptyMessage));
	}

	@Test
	public void postGeneralClientNotRegisteredTest() throws InvalidArgumentException {
		try{
			lib2.postGeneral("Client Not Registered".toCharArray());
			fail("Exception ClientNotRegisteredException should have been thrown");

		}catch (ClientNotRegisteredException e){
			assertFalse(lib2.postGeneralState("Client Not Registered".toCharArray()));
		}
	}

	@Test
	public void postGeneralMessageTooLongTest() throws ClientNotRegisteredException {
		char[] messageTooLong = new char[256];
		for (int i = 0; i<256; i++){
			messageTooLong[i] = 'a';
		}

		try{
			lib1.postGeneral(messageTooLong);
			fail("Exception InvalidArgumentException should have been thrown");

		}catch (InvalidArgumentException e){
			assertFalse(lib1.postGeneralState(messageTooLong));
		}
	}

	@Test
	public void postGeneralMessageNullTest() throws ClientNotRegisteredException {

		try {
			lib1.postGeneral(null);
			fail("Exception InvalidArgumentException should have been thrown");

		} catch (InvalidArgumentException e) {
			assertFalse(lib1.postGeneralState(null));
		}
	}
}

