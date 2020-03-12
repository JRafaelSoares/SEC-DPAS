package pt.ulisboa.tecnico.SECDPAS;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.*;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class PostGeneralTest {

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
			lib.register(pub2);

		}catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}
	@Test
	public void postGeneralCorrectNoAnnouncementsTest(){
		try{
			String s = "NoAnnouncement";
			lib.postGeneral(pub1, s.toCharArray());
			//TO-DO add read to verify
			assertTrue(lib.postGeneralState(pub1, s.toCharArray()));
		}catch(Exception e){
			fail(e.getCause().getMessage());
		}
	}

	@Test
	public void postGeneralCorrectWithAnnouncementsTest(){
		try{
			//TO-DO add read to verify

			String s = "WithAnnouncement";
			Announcement a = new Announcement(s.toCharArray(), pub1);
			Announcement[] announcements = {a};

			lib.post(pub1, s.toCharArray());
			s += "2";
			lib.postGeneral(pub1, s.toCharArray(), announcements);
			assertTrue(lib.postGeneralState(pub1, s.toCharArray(), announcements));
		}catch(Exception e){
			fail(e.getMessage());
		}
	}
}

