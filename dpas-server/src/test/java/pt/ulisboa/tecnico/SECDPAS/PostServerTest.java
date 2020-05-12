package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import com.google.common.primitives.Bytes;
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PostServerTest {

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
	public void postCorrectTest() {
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

		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
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

		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 1), observer);
		assertTrue(testCorrect[0]);
		assertTrue(testCorrect[1]);
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

		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
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

		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 0), observer);
		server.post(getPostRequest(clientPublicKey, clientPrivateKey, "test".toCharArray(), new String[0], 2), observer);
		assertTrue(testCorrect[0]);
		assertFalse(testCorrect[1]);

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
}

