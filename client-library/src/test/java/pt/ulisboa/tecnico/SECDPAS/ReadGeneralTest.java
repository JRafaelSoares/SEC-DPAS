package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;

import static org.junit.Assert.*;

public class ReadGeneralTest {

	private static ClientLibrary lib;
	private static PublicKey pub1;
	private static PrivateKey priv1;
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
			priv1 = kp.getPrivate();
		} catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@AfterClass
	public static void cleanUp(){
		lib.cleanGeneralPosts();
	}

	@Test
	public void readTest() throws pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException, ClientNotRegisteredException {
		PublicKey key1 = registerClient();
		PublicKey key2 = registerClient();

		String s1 = "post1";
		String s2 = "post2";

		lib.post(key1, s1.toCharArray());
		lib.postGeneral(key1, s1.toCharArray());
		lib.postGeneral(key2, s2.toCharArray());

		Announcement[] announcement = lib.readGeneral(key1, 1);

		String readPost = new String(announcement[0].getPost());
		assertEquals(announcement.length, 1);
		assertEquals(readPost, s2);
	}

	@Test
	public void readAllAnnouncementsTest() throws pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException, ClientNotRegisteredException {
		PublicKey key1 = registerClient();
		PublicKey key2 = registerClient();

		String s1 = "post1";
		String s2 = "post2";

		lib.postGeneral(key1, s1.toCharArray());
		lib.postGeneral(key2, s2.toCharArray());

		Announcement[] announcement = lib.readGeneral(key1, 0);

		assertEquals(announcement.length, 2);

		String readPost1 = new String(announcement[0].getPost());
		String readPost2 = new String(announcement[1].getPost());

		assertEquals(readPost1, s1);
		assertEquals(readPost2, s2);
	}

	@Test
	public void readNumberBiggerThanPostsTest() throws pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException, ClientNotRegisteredException {
		lib.cleanGeneralPosts();
		PublicKey key1 = registerClient();
		PublicKey key2 = registerClient();

		String s1 = "post1";
		String s2 = "post2";

		lib.postGeneral(key1, s1.toCharArray());
		lib.postGeneral(key2, s2.toCharArray());

		Announcement[] announcement = lib.readGeneral(key2, 3);
		assertEquals(announcement.length, 2);

		String readPost1 = new String(announcement[0].getPost());
		String readPost2 = new String(announcement[1].getPost());

		assertEquals(readPost1, s1);
		assertEquals(readPost2, s2);
	}

	@Test
	public void readInvalidNumberTest() throws ClientNotRegisteredException {
		Announcement[] announcements = null;
		try{
			PublicKey key = registerClient();

			announcements = lib.readGeneral(key, -1);
			fail("Exception InvalidArguments should have been thrown");

		}catch(pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException e){
			assertNull(announcements);
		}
	}

	@Test
	public void readClientNotExistsTest() throws InvalidArgumentException{
		Announcement[] announcements = null;
		try{
			announcements = lib.readGeneral(pub1, 1);
			fail("Exception ClientNotRegisteredException should have been thrown");

		}catch(ClientNotRegisteredException e){
			assertNull(announcements);
		}
	}

	@Test
	public void readAllClientNotExistsTest() throws InvalidArgumentException{
		Announcement[] announcements = null;
		try{
			announcements = lib.readGeneral(pub1, 0);
			fail("Exception ClientNotRegisteredException should have been thrown");

		}catch(ClientNotRegisteredException e){
			assertNull(announcements);
		}
	}

	@Test
	public void readNullPublicKeyTest() throws ClientNotRegisteredException {
		Announcement[] announcements = null;
		try{
			announcements = lib.readGeneral(null, 1);
			fail("Exception InvalidArgumentException should have been thrown");

		}catch(pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException e){
			assertNull(announcements);
		}
	}

	//Aux function
	public PublicKey registerClient(){
		try{

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			PublicKey pk = kp.getPublic();
			PrivateKey privateKey = kp.getPrivate();

			lib.register(pk, privateKey);
			return pk;
		}catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
			return null;
		}
	}
}

