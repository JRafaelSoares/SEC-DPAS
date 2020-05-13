package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.*;

public class MultiPostsTest {

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
		lib1.cleanGeneralPosts();
		lib2.cleanGeneralPosts();
		lib1.shutDown();
		lib2.shutDown();
	}

	@Test
	public void post_Read_PostGeneral_ReadGeneralTest() throws InvalidArgumentException {
		String s = "NoAnnouncement";
		lib1.post(s.toCharArray());
		Announcement[] read = lib1.read(pub1, 1);
		lib1.postGeneral(s.toCharArray());
		Announcement[] readGeneral = lib1.readGeneral(1);

		assertEquals(read.length, 1);
		assertEquals(new String(read[0].getPost()), s);
		assertEquals(readGeneral.length, 1);
		assertEquals(new String(readGeneral[0].getPost()), s);
	}

	@Test
	public void postGeneral_ReadGeneral_Post_ReadGeneralTest() throws InvalidArgumentException {
		String s = "NoAnnouncement";
		lib1.postGeneral(s.toCharArray());
		Announcement[] readGeneral = lib1.readGeneral(1);
		lib1.post(s.toCharArray());
		Announcement[] readGeneral2 = lib1.readGeneral(1);

		assertEquals(readGeneral.length, 1);
		assertEquals(readGeneral2.length, 1);
		assertEquals(new String(readGeneral[0].getPost()), s);
		assertEquals(new String(readGeneral2[0].getPost()), s);
	}

	@Test
	public void postGeneral_ReadGeneral_Post_ReadGeneral_ReadTest() throws InvalidArgumentException {
		String s = "NoAnnouncement";
		lib1.postGeneral(s.toCharArray());
		Announcement[] readGeneral = lib1.readGeneral(1);
		lib1.post(s.toCharArray());
		Announcement[] readGeneral2 = lib1.readGeneral(1);
		Announcement[] read = lib1.read(pub1, 1);

		assertEquals(readGeneral.length, 1);
		assertEquals(readGeneral2.length, 1);
		assertEquals(read.length, 1);
		assertEquals(new String(read[0].getPost()), s);
		assertEquals(new String(readGeneral[0].getPost()), s);
		assertEquals(new String(readGeneral2[0].getPost()), s);
	}

	@Test
	public void ReadGeneral_Read_PostGeneral_PostTest() throws InvalidArgumentException {
		String s = "NoAnnouncement";

		lib1.readGeneral(1);
		lib1.read(pub1, 1);
		lib1.post(s.toCharArray());
		lib1.postGeneral(s.toCharArray());
		Announcement[] readGeneral2 = lib1.readGeneral(1);
		Announcement[] read2 = lib1.read(pub1, 1);

		assertEquals(read2.length, 1);
		assertEquals(readGeneral2.length, 1);
		assertEquals(new String(read2[0].getPost()), s);
		assertEquals(new String(readGeneral2[0].getPost()), s);
	}

}

