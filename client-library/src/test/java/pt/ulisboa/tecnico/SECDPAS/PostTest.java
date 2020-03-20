package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.*;

public class PostTest {

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

			lib.register(pub1, priv1);

		}catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@AfterClass
	public static void cleanUp(){
		lib.cleanPosts();
	}


	@Test
	public void postCorrectNoAnnouncementsTest() throws ClientNotRegisteredException, InvalidArgumentException {
		String s = "NoAnnouncement";
		lib.post(pub1, s.toCharArray());

		assertTrue(lib.postState(pub1, s.toCharArray()));
	}

	@Test
	public void postCorrectWithAnnouncementsTest() throws ClientNotRegisteredException, InvalidArgumentException {
		String s1 = "NoAnnouncement";
		Announcement a = new Announcement(s1.toCharArray(), pub1);
		Announcement[] announcements = {a};

		lib.post(pub1, s1.toCharArray());

		String s2 = "WithAnnouncement";
		lib.post(pub1, s2.toCharArray(), announcements);

		assertTrue(lib.postState(pub1, s1.toCharArray()));
		assertTrue(lib.postState(pub1, s2.toCharArray(), announcements));
	}

	@Test
	public void postMessageLimitTest() throws ClientNotRegisteredException, InvalidArgumentException {
		char[] messageLimit = new char[255];
		for (int i = 0; i<255; i++){
			messageLimit[i] = 'a';
		}

		lib.post(pub1, messageLimit);
		assertTrue(lib.postState(pub1, messageLimit));
	}

	@Test
	public void postMessageEmptyTest() throws ClientNotRegisteredException, pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException{
		char[] emptyMessage = new char[0];
		lib.post(pub1, emptyMessage);

		assertTrue(lib.postState(pub1, emptyMessage));
	}

	@Test
	public void postClientNotRegisteredTest() throws InvalidArgumentException {
		try{
			lib.post(pub2, "Client Not Registered".toCharArray());
			fail("Exception ClientNotRegisteredException should have been thrown");

		}catch (ClientNotRegisteredException e){
			assertFalse(lib.postState(pub1, "Client Not Registered".toCharArray()));
		}
	}

	@Test
	public void postMessageTooLongTest() throws ClientNotRegisteredException {
		char[] messageTooLong = new char[256];
		for (int i = 0; i< 256; i++){
			messageTooLong[i] = 'a';
		}

		try{
			lib.post(pub1, messageTooLong);
			fail("Exception InvalidArgumentException should have been thrown");

		}catch (InvalidArgumentException e){
			assertFalse(lib.postState(pub1, messageTooLong));
		}
	}

	@Test
	public void postMessageNullTest() throws ClientNotRegisteredException {

		try {
			lib.post(pub1, null);
			fail("Exception InvalidArgumentException should have been thrown");

		} catch (InvalidArgumentException e) {
			assertFalse(lib.postState(pub1, null));
		}
	}

	@Test
	public void postPublicKeyNullTest() throws ClientNotRegisteredException {
		char[] message = new char[256];
		message[0] = 'a';
		try{
			lib.post(null, message);
			fail("Exception InvalidArgumentException should have been thrown");

		}catch (InvalidArgumentException e){
			assertFalse(lib.postState(pub1, null));
		}
	}

	@Test
	public void postPublicKeyMessageNullTest() throws ClientNotRegisteredException {

		try{
			lib.post(null, null);
			fail("Exception InvalidArgumentException should have been thrown");

		}catch (InvalidArgumentException e){
			assertFalse(lib.postState(pub1, null));
		}
	}

}

