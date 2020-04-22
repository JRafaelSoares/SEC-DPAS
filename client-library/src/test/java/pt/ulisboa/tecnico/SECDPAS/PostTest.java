package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;
import java.util.Arrays;

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
	public void postCorrectNoAnnouncementsTest() throws InvalidArgumentException, ComunicationException {
		String s = "NoAnnouncement";
		lib1.post(s.toCharArray());

		assertTrue(lib1.postState(s.toCharArray()));
	}

	//TODO when read quorum is completed

	@Test
	public void postCorrectWithAnnouncementsTest() throws InvalidArgumentException, ComunicationException {
		String s1 = "NoAnnouncement";

		lib1.post(s1.toCharArray());

		Announcement announcement = lib1.read(pub1, 1)[0];
		String[] announcements = {  announcement.getAnnouncementID() };

		String s2 = "WithAnnouncement";
		lib1.post(s2.toCharArray(), announcements);

		assertTrue(lib1.postState(s1.toCharArray()));
		assertTrue(lib1.postState(s2.toCharArray(), announcements));
	}

	@Test
	public void postMessageLimitTest() throws InvalidArgumentException, ComunicationException {
		char[] messageLimit = new char[255];
		for (int i = 0; i<255; i++){
			messageLimit[i] = 'a';
		}

		lib1.post(messageLimit);
		assertTrue(lib1.postState(messageLimit));
	}

	@Test
	public void postMessageEmptyTest() throws InvalidArgumentException, ComunicationException {
		char[] emptyMessage = new char[0];
		lib1.post(emptyMessage);

		assertTrue(lib1.postState(emptyMessage));
	}

	@Test
	public void postMessageTooLongTest() throws ComunicationException {
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
	public void postMessageNullTest() throws ComunicationException {

		try {
			lib1.post(null);
			fail("Exception InvalidArgumentException should have been thrown");

		} catch (InvalidArgumentException e) {
			assertFalse(lib1.postState(null));
		}
	}

}

