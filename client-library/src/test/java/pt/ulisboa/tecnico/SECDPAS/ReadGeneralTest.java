package pt.ulisboa.tecnico.SECDPAS;

import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runners.MethodSorters;

import java.security.*;

import static org.junit.Assert.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ReadGeneralTest {

	private static ClientLibrary lib1;
	private static ClientLibrary lib2;
	private static ClientLibrary lib3;
	private static PublicKey pub;

	@Rule
	public ExpectedException thrown= ExpectedException.none();

	@BeforeClass
	public static void setUp(){

		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			pub = kp.getPublic();
			PrivateKey priv = kp.getPrivate();

			lib1 = new ClientLibrary("localhost", 8080, pub, priv);

			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			kp = kpg.genKeyPair();
			PublicKey pub = kp.getPublic();
			priv = kp.getPrivate();

			lib2 = new ClientLibrary("localhost", 8080, pub, priv);

			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			kp = kpg.genKeyPair();
			pub = kp.getPublic();
			priv = kp.getPrivate();

			lib3 = new ClientLibrary("localhost", 8080, pub, priv);

			lib1.register();
			lib2.register();

		} catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@AfterClass
	public static void cleanUp(){
		lib1.cleanGeneralPosts();
		lib1.cleanPosts();
		lib1.shutDown();
		lib2.shutDown();
	}

	@Test
	public void readTest() throws pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException, ClientNotRegisteredException {
		String s1 = "post1";
		String s2 = "post2";

		lib1.post(s1.toCharArray());
		lib1.postGeneral(s1.toCharArray());
		lib2.postGeneral(s2.toCharArray());

		Announcement[] announcement = lib1.readGeneral(1);

		String readPost = new String(announcement[0].getPost());

		assertEquals(announcement.length, 1);
		assertEquals(s2, readPost);
	}

	@Test
	public void readAllAnnouncementsTest() throws pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException, ClientNotRegisteredException {
		String s1 = "post1";
		String s2 = "post2";

		lib1.postGeneral(s1.toCharArray());
		lib2.postGeneral(s2.toCharArray());

		Announcement[] announcement = lib1.readGeneral( 0);

		assertEquals(2, announcement.length);

		assertEquals(s1, new String(announcement[0].getPost()));
		assertEquals(s2, new String(announcement[1].getPost()));

	}

	@Test
	public void readAzNumberBiggerThanPostsTest() throws pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException, ClientNotRegisteredException {
		String s1 = "post1";
		String s2 = "post2";

		//both already posted by readAllAnnouncementsTest, tests run by name order
		//lib1.postGeneral(s1.toCharArray());
		//lib1.postGeneral(s2.toCharArray());

		Announcement[] announcement = lib1.readGeneral(3);

		assertEquals(2, announcement.length);

		assertEquals(s1, new String(announcement[0].getPost()));
		assertEquals(s2, new String(announcement[1].getPost()));
	}

	@Test
	public void readInvalidNumberTest() throws ClientNotRegisteredException {
		Announcement[] announcements = null;
		try{
			announcements = lib1.readGeneral(-1);
			fail("Exception InvalidArguments should have been thrown");

		}catch(pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException e){
			assertNull(announcements);
		}
	}

	@Test
	public void readClientNotExistsTest() throws InvalidArgumentException{
		Announcement[] announcements = null;
		try{
			announcements = lib3.readGeneral(1);
			fail("Exception ClientNotRegisteredException should have been thrown");

		}catch(ClientNotRegisteredException e){
			assertNull(announcements);
		}
	}

	@Test
	public void readAllClientNotExistsTest() throws InvalidArgumentException{
		Announcement[] announcements = null;
		try{
			announcements = lib3.readGeneral(0);
			fail("Exception ClientNotRegisteredException should have been thrown");

		}catch(ClientNotRegisteredException e){
			assertNull(announcements);
		}
	}
}

