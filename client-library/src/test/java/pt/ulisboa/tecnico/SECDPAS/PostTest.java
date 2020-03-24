package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.*;

public class PostTest {

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
	public void postCorrectNoAnnouncementsTest() throws ClientNotRegisteredException, InvalidArgumentException {
		String s = "NoAnnouncement";
		lib1.post(s.toCharArray());

		assertTrue(lib1.postState(s.toCharArray()));
	}

	@Test
	public void postCorrectWithAnnouncementsTest() throws ClientNotRegisteredException, InvalidArgumentException {
		String s1 = "NoAnnouncement";
		Announcement a = new Announcement(s1.toCharArray(), pub1);
		Announcement[] announcements = {a};

		lib1.post(s1.toCharArray());

		String s2 = "WithAnnouncement";
		lib1.post(s2.toCharArray(), announcements);

		assertTrue(lib1.postState(s1.toCharArray()));
		assertTrue(lib1.postState(s2.toCharArray(), announcements));
	}

	@Test
	public void postMessageLimitTest() throws ClientNotRegisteredException, InvalidArgumentException {
		char[] messageLimit = new char[255];
		for (int i = 0; i<255; i++){
			messageLimit[i] = 'a';
		}

		lib1.post(messageLimit);
		assertTrue(lib1.postState(messageLimit));
	}

	@Test
	public void postMessageEmptyTest() throws ClientNotRegisteredException, pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException{
		char[] emptyMessage = new char[0];
		lib1.post(emptyMessage);

		assertTrue(lib1.postState(emptyMessage));
	}

	@Test
	public void postClientNotRegisteredTest() throws InvalidArgumentException {
		try{
			lib2.post("Client Not Registered".toCharArray());
			fail("Exception ClientNotRegisteredException should have been thrown");

		}catch (ClientNotRegisteredException e){
			assertFalse(lib2.postState("Client Not Registered".toCharArray()));
		}
	}

	@Test
	public void postMessageTooLongTest() throws ClientNotRegisteredException {
		char[] messageTooLong = new char[256];
		for (int i = 0; i< 256; i++){
			messageTooLong[i] = 'a';
		}

		try{
			lib1.post(messageTooLong);
			fail("Exception InvalidArgumentException should have been thrown");

		}catch (InvalidArgumentException e){
			assertFalse(lib1.postState(messageTooLong));
		}
	}

	@Test
	public void postMessageNullTest() throws ClientNotRegisteredException {

		try {
			lib1.post(null);
			fail("Exception InvalidArgumentException should have been thrown");

		} catch (InvalidArgumentException e) {
			assertFalse(lib1.postState(null));
		}
	}

}

