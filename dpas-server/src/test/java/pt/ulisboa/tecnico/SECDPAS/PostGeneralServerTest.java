package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.protobuf.ByteString;
import com.sun.source.tree.AssertTree;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.*;

public class PostGeneralServerTest {

	private static DPASServiceImpl server;
	private static PublicKey clientPublicKey;
	private static PrivateKey clientPrivateKey;

	private static PublicKey clientPublicKey2;
	private static PrivateKey clientPrivateKey2;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@BeforeClass
	public static void setUp(){

		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();

			clientPublicKey = kp.getPublic();
			clientPrivateKey = kp.getPrivate();

			kp = kpg.genKeyPair();
			clientPublicKey2 = kp.getPublic();
			clientPrivateKey2 = kp.getPrivate();
		}catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@Before
	public void init() {
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			PrivateKey priv = kp.getPrivate();

			server = new DPASServiceImpl(priv, 0);
			server.register(getRegisterRequest(clientPublicKey, clientPrivateKey), new StreamObserver<Contract.ACK>() {
				@Override
				public void onNext(Contract.ACK ack) {

				}

				@Override
				public void onError(Throwable throwable) {

				}

				@Override
				public void onCompleted() {

				}
			});
			server.register(getRegisterRequest(clientPublicKey2, clientPrivateKey2), new StreamObserver<Contract.ACK>() {
				@Override
				public void onNext(Contract.ACK ack) {

				}

				@Override
				public void onError(Throwable throwable) {

				}

				@Override
				public void onCompleted() {

				}
			});
		} catch (Exception e){
			System.out.println("Failed to restart server");
		}

	}

	@Test
	public void postGeneralCorrectTest() {
		final boolean[] testCorrect = new boolean[1];

		StreamObserver<Contract.ACK> observer = new StreamObserver<Contract.ACK>() {
			@Override
			public void onNext(Contract.ACK ack) {
				testCorrect[0] =true;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[0]=false;
			}

			@Override
			public void onCompleted() {

			}
		};

		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		assertTrue(testCorrect[0]);
	}

	@Test
	public void postTwoCorrectTest() {
		final boolean[] testCorrect = new boolean[2];

		StreamObserver<Contract.ACK> observer = new StreamObserver<Contract.ACK>() {
			int i = 0;

			@Override
			public void onNext(Contract.ACK ack) {
				testCorrect[i] =true;
				i++;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[i]=false;
				i++;
			}

			@Override
			public void onCompleted() {

			}
		};

		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 1), observer);
		assertTrue(testCorrect[0]);
		assertTrue(testCorrect[1]);
	}

	@Test
	public void postCorrectWithReferencesTest() {
		final boolean[] testCorrect = new boolean[3];
		final String[] reference = new String[1];
		StreamObserver<Contract.ACK> observer = new StreamObserver<Contract.ACK>() {
			int i = 0;

			@Override
			public void onNext(Contract.ACK ack) {
				testCorrect[i] =true;
				i+=2;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[i]=false;
				i+=2;
			}

			@Override
			public void onCompleted() {

			}
		};


		StreamObserver<Contract.ReadResponse> readObserver = new StreamObserver<Contract.ReadResponse>() {
			@Override
			public void onNext(Contract.ReadResponse response) {
				Announcement[] announcements = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
				reference[0] = announcements[0].getAnnouncementID();
				testCorrect[1] = true;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[1] = false;

			}

			@Override
			public void onCompleted() {

			}
		};


		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		assertTrue(testCorrect[0]);

		server.readGeneral(getReadGeneralRequest(clientPublicKey, clientPrivateKey, 1, 0), readObserver);
		assertTrue(testCorrect[1]);

		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), reference, 1), observer);
		assertTrue(testCorrect[2]);
	}

	@Test
	public void postWrongReferenceTest() {
		final boolean[] testCorrect = new boolean[1];

		StreamObserver<Contract.ACK> observer = new StreamObserver<Contract.ACK>() {
			@Override
			public void onNext(Contract.ACK ack) {
				testCorrect[0] =true;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[0]=false;
			}

			@Override
			public void onCompleted() {

			}
		};

		String[] references = {"WrongReference"};
		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), references, 0), observer);
		assertFalse(testCorrect[0]);
	}

	/*********************/
	/** Freshness Tests **/
	/*********************/

	@Test
	public void postConcurrentWriteTest() {
		final boolean[] testCorrect = new boolean[3];
		final Announcement[][] announcements = new Announcement[1][];
		StreamObserver<Contract.ACK> observer = new StreamObserver<Contract.ACK>() {
			int i = 0;
			@Override
			public void onNext(Contract.ACK ack) {
				testCorrect[i] =true;
				i++;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[i]=false;
				i++;
			}

			@Override
			public void onCompleted() {

			}
		};
		StreamObserver<Contract.ReadResponse> readObserver = new StreamObserver<Contract.ReadResponse>() {
			@Override
			public void onNext(Contract.ReadResponse response) {
				announcements[0] = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
				testCorrect[2] = true;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[2] = false;

			}

			@Override
			public void onCompleted() {

			}
		};
		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test1".toCharArray(), new String[0], 0), observer);
		server.postGeneral(getPostRequest(clientPublicKey2, clientPrivateKey2, "test2".toCharArray(), new String[0], 0), observer);
		server.readGeneral(getReadGeneralRequest(clientPublicKey, clientPrivateKey, 0, 0), readObserver);

		assertTrue(testCorrect[0]);
		assertTrue(testCorrect[1]);
		assertTrue(testCorrect[2]);
		assertEquals(2, announcements[0].length);
		assertNotEquals(new String(announcements[0][0].getPost()), new String(announcements[0][1].getPost()));
	}

	@Test
	public void postConcurrentFurtherWriteTest() {
		final boolean[] testCorrect = new boolean[4];

		final Announcement[][] announcements = new Announcement[1][];

		StreamObserver<Contract.ACK> observer = new StreamObserver<Contract.ACK>() {
			int i = 0;
			@Override
			public void onNext(Contract.ACK ack) {
				testCorrect[i] =true;
				i++;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[i]=false;
				i++;
			}

			@Override
			public void onCompleted() {

			}
		};

		StreamObserver<Contract.ReadResponse> readObserver = new StreamObserver<Contract.ReadResponse>() {
			@Override
			public void onNext(Contract.ReadResponse response) {
				announcements[0] = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
				testCorrect[3] = true;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[3] = false;

			}

			@Override
			public void onCompleted() {

			}
		};

		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test1".toCharArray(), new String[0], 0), observer);
		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test2".toCharArray(), new String[0], 1), observer);
		server.postGeneral(getPostRequest(clientPublicKey2, clientPrivateKey2, "test3".toCharArray(), new String[0], 0), observer);
		server.readGeneral(getReadGeneralRequest(clientPublicKey, clientPrivateKey, 0, 0), readObserver);

		assertTrue(testCorrect[0]);
		assertTrue(testCorrect[1]);
		assertTrue(testCorrect[2]);
		assertTrue(testCorrect[3]);

		assertEquals(3, announcements[0].length);
		assertNotEquals(new String(announcements[0][0].getPost()), new String(announcements[0][1].getPost()));
		assertNotEquals(new String(announcements[0][1].getPost()), new String(announcements[0][2].getPost()));
		assertNotEquals(new String(announcements[0][0].getPost()), new String(announcements[0][2].getPost()));


	}

	@Test
	public void postReplyAttackTest() {
		final boolean[] testCorrect = new boolean[2];

		StreamObserver<Contract.ACK> observer = new StreamObserver<Contract.ACK>() {
			int i = 0;
			@Override
			public void onNext(Contract.ACK ack) {
				testCorrect[i] =true;
				i++;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[i]=false;
				i++;
			}

			@Override
			public void onCompleted() {

			}
		};

		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		assertTrue(testCorrect[0]);
		assertTrue(testCorrect[1]);
	}

	@Test
	public void postWrongFreshnessTest() {
		final boolean[] testCorrect = new boolean[2];

		StreamObserver<Contract.ACK> observer = new StreamObserver<Contract.ACK>() {
			int i = 0;
			@Override
			public void onNext(Contract.ACK ack) {
				testCorrect[i] =true;
				i++;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[i]=false;
				i++;
			}

			@Override
			public void onCompleted() {

			}
		};

		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		server.postGeneral(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 2), observer);
		assertTrue(testCorrect[0]);
		assertFalse(testCorrect[1]);
	}

	@Test
	public void postWrongSignatureTest() {
		final boolean[] testCorrect = new boolean[2];

		StreamObserver<Contract.ACK> observer = new StreamObserver<Contract.ACK>() {
			int i = 0;
			@Override
			public void onNext(Contract.ACK ack) {
				testCorrect[i] =true;
				i++;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[i]=false;
				i++;
			}

			@Override
			public void onCompleted() {

			}
		};

		server.postGeneral(getPostRequestWrongSignature(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		assertFalse(testCorrect[0]);
	}

	/*****************************/
	/***** Request Builders	******/
	/*****************************/

	private Contract.ReadRequest getReadGeneralRequest(PublicKey clientPublicKey, PrivateKey clientPrivateKey, int number, long freshness){
		byte[] publicKey = SerializationUtils.serialize(clientPublicKey);
		byte[] numberBytes = Ints.toByteArray(number);

		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, numberBytes, Longs.toByteArray(freshness)), clientPrivateKey);

		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();

	}

	private Contract.PostRequest getPostRequest(PublicKey clientPublicKey, PrivateKey clientPrivateKey, char[] message, String[] references, long freshness) {
		String generalBoardId = "1";

		byte[] publicKey = SerializationUtils.serialize(clientPublicKey);
		String post = new String(message);
		byte[] announcements = SerializationUtils.serialize(references);

		byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(publicKey, post.getBytes(), announcements, Longs.toByteArray(freshness), generalBoardId.getBytes()), clientPrivateKey);

		return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setMessageSignature(ByteString.copyFrom(messageSignature)).setAnnouncements(ByteString.copyFrom(announcements)).setBoard(generalBoardId).setFreshness(freshness).build();
	}

	private static Contract.RegisterRequest getRegisterRequest(PublicKey clientPublicKeyKey, PrivateKey clientPrivateKey){
		/* Serializes key and changes to ByteString */
		byte[] publicKey = SerializationUtils.serialize(clientPublicKeyKey);
		byte[] signature = SignatureHandler.publicSign(publicKey, clientPrivateKey);

		/* Prepare request */
		return Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setSignature(ByteString.copyFrom(signature)).build();
	}

	/*************************************/
	/******* Fake Request Builders	******/
	/*************************************/

	private Contract.PostRequest getPostRequestWrongSignature(PublicKey clientPublicKey, PrivateKey clientPrivateKey, char[] message, String[] references, long freshness) {
		String generalBoardId = "1";

		byte[] publicKey = SerializationUtils.serialize(clientPublicKey);
		String post = new String(message);
		byte[] announcements = SerializationUtils.serialize(references);

		byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(publicKey, post.getBytes(), announcements, Longs.toByteArray(freshness)), clientPrivateKey);

		return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setMessageSignature(ByteString.copyFrom(messageSignature)).setAnnouncements(ByteString.copyFrom(announcements)).setBoard(generalBoardId).setFreshness(freshness).build();
	}
}

