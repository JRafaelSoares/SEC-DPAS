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
		} catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@AfterClass
	public static void cleanUp(){
		lib.cleanGeneralPosts();
	}

	@Test
	public void readTest(){
		try{
			PublicKey key = registerClient();

			String s = "ReadTest";

			lib.postGeneral(key, s.toCharArray());

			Announcement[] announcement = lib.readGeneral(key, 1);

			String readPost = new String(announcement[0].getPost());
			assertEquals(readPost,s);
		}catch(Exception e){
			fail(e.getCause().getMessage());
		}
	}

	@Test
	public void readAllAnnouncementsTest(){
		try{
			PublicKey key = registerClient();

			String s = "ReadTest";
			lib.postGeneral(key, s.toCharArray());

			String s1 = s+"1";
			lib.postGeneral(key, s1.toCharArray());

			Announcement[] announcement = lib.readGeneral(key, 0);

			String readPost = new String(announcement[0].getPost());
			String readPost1 = new String(announcement[1].getPost());

			assertEquals(announcement.length, 2);
			assertEquals(readPost,s);
			assertEquals(readPost1, s1);
		}catch(Exception e){
			fail(e.getCause().getMessage());
		}
	}

	@Test
	public void readNumberBiggerThanPostsTest(){
		try{
			lib.cleanGeneralPosts();
			PublicKey key = registerClient();

			String s = "ReadTest";
			lib.postGeneral(key, s.toCharArray());

			String s1 = s+"1";
			lib.postGeneral(key, s1.toCharArray());

			Announcement[] announcement = lib.readGeneral(key, 3);
			assertEquals(announcement.length, 2);
		}catch(Exception e){
			fail(e.getCause().getMessage());
		}
	}

	@Test
	public void readInvalidNumberTest() throws ClientNotRegistredException{
		try{
			PublicKey key = registerClient();

			lib.readGeneral(key, -1);
			fail("Exception InvalidArguments should have been thrown");

		}catch(pt.ulisboa.tecnico.SECDPAS.InvalidArgumentException e){
		}
	}

	@Test
	public void readClientNotExistsTest() throws InvalidArgumentException{
		try{
			lib.readGeneral(pub1, 1);
			fail("Exception ClientNotRegisteredException should have been thrown");

		}catch(pt.ulisboa.tecnico.SECDPAS.ClientNotRegistredException e){

		}
	}

	@Test
	public void readAllClientNotExistsTest() throws InvalidArgumentException{
		try{
			lib.readGeneral(pub1, 0);
			fail("Exception ClientNotRegisteredException should have been thrown");

		}catch(pt.ulisboa.tecnico.SECDPAS.ClientNotRegistredException e){

		}
	}
	//Aux function
	public PublicKey registerClient(){
		try{

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			PublicKey pk = kp.getPublic();

			lib.register(pk);
			return pk;
		}catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
			return null;
		}
	}
}

