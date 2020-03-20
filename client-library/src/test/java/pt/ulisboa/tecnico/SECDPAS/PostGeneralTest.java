package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.*;

public class PostGeneralTest {

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
			System.out.println("// Exception message: " + e.getMessage());
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@AfterClass
	public static void cleanUp(){
		lib.cleanGeneralPosts();
	}
	@Test
	public void postGeneralCorrectNoAnnouncementsTest() throws ClientNotRegisteredException, InvalidArgumentException {
		String s = "NoAnnouncement";
		lib.postGeneral(pub1, s.toCharArray());

		assertTrue(lib.postGeneralState(pub1, s.toCharArray()));
	}

	@Test
	public void postGeneralCorrectWithAnnouncementsTest() throws ClientNotRegisteredException, InvalidArgumentException {
		String s1 = "NoAnnouncement";
		Announcement a = new Announcement(s1.toCharArray(), pub1);
		Announcement[] announcements = {a};

		lib.postGeneral(pub1, s1.toCharArray());

		String s2 = "WithAnnouncement";
		lib.postGeneral(pub1, s2.toCharArray(), announcements);

		assertTrue(lib.postGeneralState(pub1, s1.toCharArray()));
		assertTrue(lib.postGeneralState(pub1, s2.toCharArray(), announcements));
	}

	@Test
	public void postGeneralMessageLimitTest() throws ClientNotRegisteredException, InvalidArgumentException {
		char[] messageLimit = new char[255];
		for (int i = 0; i<255; i++){
			messageLimit[i] = 'a';
		}

		lib.postGeneral(pub1, messageLimit);
		assertTrue(lib.postGeneralState(pub1, messageLimit));
	}

	@Test
	public void postGeneralMessageEmptyTest() throws ClientNotRegisteredException, pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException{
		char[] emptyMessage = new char[0];
		lib.postGeneral(pub1, emptyMessage);

		assertTrue(lib.postGeneralState(pub1, emptyMessage));
	}

	@Test
	public void postGeneralClientNotRegisteredTest() throws InvalidArgumentException {
		try{
			lib.postGeneral(pub2, "Client Not Registered".toCharArray());
			fail("Exception ClientNotRegisteredException should have been thrown");

		}catch (ClientNotRegisteredException e){
			assertFalse(lib.postGeneralState(pub1, "Client Not Registered".toCharArray()));
		}
	}

	@Test
	public void postGeneralMessageTooLongTest() throws ClientNotRegisteredException {
		char[] messageTooLong = new char[256];
		for (int i = 0; i<256; i++){
			messageTooLong[i] = 'a';
		}

		try{
			lib.postGeneral(pub1, messageTooLong);
			fail("Exception InvalidArgumentException should have been thrown");

		}catch (InvalidArgumentException e){
			assertFalse(lib.postGeneralState(pub1, messageTooLong));
		}
	}

	@Test
	public void postGeneralMessageNullTest() throws ClientNotRegisteredException {

		try {
			lib.postGeneral(pub1, null);
			fail("Exception InvalidArgumentException should have been thrown");

		} catch (InvalidArgumentException e) {
			assertFalse(lib.postGeneralState(pub1, null));
		}
	}

	@Test
	public void postGeneralPublicKeyNullTest() throws ClientNotRegisteredException {
		char[] message = new char[256];
		message[0] = 'a';
		try{
			lib.postGeneral(null, message);
			fail("Exception InvalidArgumentException should have been thrown");

		}catch (InvalidArgumentException e){
			assertFalse(lib.postGeneralState(pub1, null));
		}
	}

	@Test
	public void postGeneralPublicKeyMessageNullTest() throws ClientNotRegisteredException {

		try{
			lib.postGeneral(null, null);
			fail("Exception InvalidArgumentException should have been thrown");

		}catch (InvalidArgumentException e){
			assertFalse(lib.postGeneralState(pub1, null));
		}
	}
}

