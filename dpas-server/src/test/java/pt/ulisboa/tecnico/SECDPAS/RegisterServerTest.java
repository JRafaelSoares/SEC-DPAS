package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.assertTrue;

public class RegisterServerTest {

	private static DPASServiceImpl server;
	private static PublicKey clientPublicKey;
	private static PrivateKey clientPrivateKey;

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@BeforeClass
	public static void setUp(){

		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			PublicKey pub = kp.getPublic();
			PrivateKey priv = kp.getPrivate();

			server = new DPASServiceImpl(priv, 0);

			kp = kpg.genKeyPair();
			clientPublicKey = kp.getPublic();
			clientPrivateKey = kp.getPrivate();

		}catch (Exception e){
			System.out.println("Unable to obtain public key for testing");
		}
	}

	@Test
	public void registerCorrectTest() {
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

		server.register(getRegisterRequest(clientPublicKey, clientPrivateKey), observer);
		assertTrue(testCorrect[0]);
	}

	/*
	@Test
	public void registerTwiceCorrectTest() {
		lib2.register();
		lib2.register();
		assertTrue(lib2.clientRegisteredState());
	}
	*/

	public Contract.RegisterRequest getRegisterRequest(PublicKey clientPublicKeyKey, PrivateKey clientPrivateKey){
		/* Serializes key and changes to ByteString */
		byte[] publicKey = SerializationUtils.serialize(clientPublicKeyKey);
		byte[] signature = SignatureHandler.publicSign(publicKey, clientPrivateKey);

		/* Prepare request */
		return Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setSignature(ByteString.copyFrom(signature)).build();
	}
}

