package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.protobuf.ByteString;
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

public class ReadServerTest {

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
			if(server != null){
				server.shutDown();
			}
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
	public void readCorrectOneAnnouncementTest() {
		final boolean[] testCorrect = new boolean[2];
		final Announcement[][] announcements = new Announcement[1][1];
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

		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		server.read(getReadRequest(clientPublicKey, clientPrivateKey, clientPublicKey, 1, 0), readObserver);
		assertTrue(testCorrect[0]);
		assertTrue(testCorrect[1]);
		assertEquals("test", new String(announcements[0][0].getPost()));
	}

	@Test
	public void readCorrectAllAnnouncementsTest() {
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

		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test1".toCharArray(), new String[0], 0), observer);
		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test2".toCharArray(), new String[0], 1), observer);
		server.read(getReadRequest(clientPublicKey, clientPrivateKey, clientPublicKey, 0, 0), readObserver);

		assertTrue(testCorrect[0]);
		assertTrue(testCorrect[1]);
		assertTrue(testCorrect[2]);

		assertEquals(2, announcements[0].length);
		assertEquals("test1", new String(announcements[0][0].getPost()));
		assertEquals("test2", new String(announcements[0][1].getPost()));
	}

	@Test
	public void readCorrectOneAnnouncementOtherClientTest() {
		final boolean[] testCorrect = new boolean[2];
		final Announcement[][] announcements = new Announcement[1][1];
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

		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		server.read(getReadRequest(clientPublicKey2, clientPrivateKey2, clientPublicKey, 1, 0), readObserver);
		assertTrue(testCorrect[0]);
		assertTrue(testCorrect[1]);
		assertEquals("test", new String(announcements[0][0].getPost()));
	}

	@Test
	public void readCorrectAllAnnouncementsOtherClientTest() {
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

		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test1".toCharArray(), new String[0], 0), observer);
		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test2".toCharArray(), new String[0], 1), observer);
		server.read(getReadRequest(clientPublicKey2, clientPrivateKey2, clientPublicKey, 0, 0), readObserver);

		assertTrue(testCorrect[0]);
		assertTrue(testCorrect[1]);
		assertTrue(testCorrect[2]);

		assertEquals(2, announcements[0].length);
		assertEquals("test1", new String(announcements[0][0].getPost()));
		assertEquals("test2", new String(announcements[0][1].getPost()));
	}

	@Test
	public void readCorrectNoAnnouncementTest() {
		final boolean[] testCorrect = new boolean[2];
		final Announcement[][] announcements = new Announcement[1][1];

		StreamObserver<Contract.ReadResponse> readObserver = new StreamObserver<Contract.ReadResponse>() {
			@Override
			public void onNext(Contract.ReadResponse response) {
				announcements[0] = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
				testCorrect[0] = true;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[0] = false;

			}

			@Override
			public void onCompleted() {

			}
		};

		server.read(getReadRequest(clientPublicKey, clientPrivateKey, clientPublicKey, 1, 0), readObserver);
		assertTrue(testCorrect[0]);
		assertEquals(0, announcements[0].length);
	}

	@Test
	public void readAllCorrectNoAnnouncementTest() {
		final boolean[] testCorrect = new boolean[2];
		final Announcement[][] announcements = new Announcement[1][1];

		StreamObserver<Contract.ReadResponse> readObserver = new StreamObserver<Contract.ReadResponse>() {
			@Override
			public void onNext(Contract.ReadResponse response) {
				announcements[0] = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
				testCorrect[0] = true;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[0] = false;

			}

			@Override
			public void onCompleted() {

			}
		};

		server.read(getReadRequest(clientPublicKey, clientPrivateKey, clientPublicKey, 0, 0), readObserver);
		assertTrue(testCorrect[0]);
		assertEquals(0, announcements[0].length);
	}
	/*****************************/
	/** Freshness Related Tests **/
	/*****************************/

	@Test
	public void readReplyAttackTest() {
		final boolean[] testCorrect = new boolean[3];

		StreamObserver<Contract.ReadResponse> readObserver = new StreamObserver<Contract.ReadResponse>() {
			int i = 0;
			@Override
			public void onNext(Contract.ReadResponse response) {
				testCorrect[i] = true;
				i++;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[i] = false;
				i++;

			}

			@Override
			public void onCompleted() {

			}
		};

		server.read(getReadRequest(clientPublicKey, clientPrivateKey, clientPublicKey, 1, 0), readObserver);
		server.read(getReadRequest(clientPublicKey, clientPrivateKey, clientPublicKey, 1, 0), readObserver);
		assertTrue(testCorrect[0]);
		assertFalse(testCorrect[1]);

	}

	@Test
	public void readWrongFreshnessTest() {
		final boolean[] testCorrect = new boolean[2];

		StreamObserver<Contract.ReadResponse> readObserver = new StreamObserver<Contract.ReadResponse>() {
			int i = 0;
			@Override
			public void onNext(Contract.ReadResponse response) {
				testCorrect[i] = true;
				i++;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[i] = false;
				i++;

			}

			@Override
			public void onCompleted() {

			}
		};

		server.read(getReadRequest(clientPublicKey, clientPrivateKey, clientPublicKey, 1, 0), readObserver);
		server.read(getReadRequest(clientPublicKey, clientPrivateKey, clientPublicKey, 1, 2), readObserver);
		assertTrue(testCorrect[0]);
		assertFalse(testCorrect[1]);

	}

	@Test
	public void readWrongSignatureTest() {
		final boolean[] testCorrect = new boolean[2];

		StreamObserver<Contract.ReadResponse> readObserver = new StreamObserver<Contract.ReadResponse>() {
			int i = 0;
			@Override
			public void onNext(Contract.ReadResponse response) {
				testCorrect[i] = true;
				i++;
			}

			@Override
			public void onError(Throwable throwable) {
				testCorrect[i] = false;
				i++;

			}

			@Override
			public void onCompleted() {

			}
		};

		server.read(getReadRequestWrongSignature(clientPublicKey, clientPrivateKey, clientPublicKey, 1, 0), readObserver);
		assertFalse(testCorrect[0]);

	}

	/*****************************/
	/***** Request Builders	******/
	/*****************************/
	private Contract.ReadRequest getReadRequest(PublicKey clientPublicKey, PrivateKey clientPrivateKey, PublicKey clientTargetKey, int number, long freshness){
		byte[] targetPublicKey = SerializationUtils.serialize(clientTargetKey);
		byte[] userPublicKey = SerializationUtils.serialize(clientPublicKey);

		byte[] keys = Bytes.concat(targetPublicKey, userPublicKey);
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(keys, Ints.toByteArray(number), Longs.toByteArray(freshness)), clientPrivateKey);

		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(userPublicKey)).setTargetPublicKey(ByteString.copyFrom(targetPublicKey)).setNumber(number).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();
	}

	private Contract.PostRequest getPostRequest(PublicKey clientPublicKey, PrivateKey clientPrivateKey, char[] message, String[] references, long freshness) {
		String privateBoardId = "0";

		byte[] publicKey = SerializationUtils.serialize(clientPublicKey);
		String post = new String(message);
		byte[] announcements = SerializationUtils.serialize(references);

		byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(publicKey, post.getBytes(), announcements, Longs.toByteArray(freshness), privateBoardId.getBytes()), clientPrivateKey);

		return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setMessageSignature(ByteString.copyFrom(messageSignature)).setAnnouncements(ByteString.copyFrom(announcements)).setBoard(privateBoardId).setFreshness(freshness).build();
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

	private Contract.ReadRequest getReadRequestWrongSignature(PublicKey clientPublicKey, PrivateKey clientPrivateKey, PublicKey clientTargetKey, int number, long freshness){
		byte[] targetPublicKey = SerializationUtils.serialize(clientTargetKey);
		byte[] userPublicKey = SerializationUtils.serialize(clientPublicKey);

		byte[] keys = Bytes.concat(targetPublicKey, userPublicKey);
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(keys, Ints.toByteArray(number)), clientPrivateKey);

		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(userPublicKey)).setTargetPublicKey(ByteString.copyFrom(targetPublicKey)).setNumber(number).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();
	}
}

