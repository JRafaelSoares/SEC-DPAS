package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.Empty;

import com.google.protobuf.ByteString;
import io.grpc.*;
import org.apache.commons.lang3.SerializationUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;

public class ClientLibrary {

	private String host = "localhost";
	private int port = 8080;

	private ManagedChannel[] channel;
	private DPASServiceGrpc.DPASServiceFutureStub[] futureStub;
	private DPASServiceGrpc.DPASServiceBlockingStub stub;

	private FreshnessHandler[] freshnessHandlers;

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private PublicKey[] serverPublicKey;

	/* for debugging change to 1 */
	private int debug = 0;

	public ClientLibrary(String host, int port, PublicKey publicKey, PrivateKey privateKey, int faults) throws InvalidArgumentException, CertificateInvalidException{
		checkConstructor(host, port, publicKey, privateKey, faults);

		//Client variables
		this.publicKey = publicKey;
		this.privateKey = privateKey;

		//Byzantine Quorum number
		int numServers = faults*3+1;
		this.serverPublicKey = new PublicKey[numServers];
		this.channel = new ManagedChannel[numServers];
		this.futureStub = new DPASServiceGrpc.DPASServiceFutureStub[numServers];
		this.freshnessHandlers = new FreshnessHandler[numServers];

		Path currentRelativePath = Paths.get("");


		//Stub and certificate for each server
		for(int server = 0; server < numServers; server++){
			String target = host + ":" + (port+server);
			this.channel[server] = ManagedChannelBuilder.forTarget(target).usePlaintext().build();
			this.futureStub[server] = DPASServiceGrpc.newFutureStub(this.channel[server]);
			this.freshnessHandlers[server] = new FreshnessHandler();

			//Get certificate
			try{
				CertificateFactory fact = CertificateFactory.getInstance("X.509");
				FileInputStream is = new FileInputStream (String.format("%s/src/main/security/certificates/server/certServer%d.der", currentRelativePath.toAbsolutePath().toString(), server));
				X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
				this.serverPublicKey[server] = cer.getPublicKey();
			} catch (CertificateException | FileNotFoundException e){
				throw new CertificateInvalidException(e.getMessage());
			}
		}

		//Test server
		this.stub = DPASServiceGrpc.newBlockingStub(this.channel[0]);
	}

	//Testing single client purposes
	public ClientLibrary(String host, int port, PublicKey publicKey, PrivateKey privateKey) throws InvalidArgumentException, CertificateInvalidException{
		this(host, port, publicKey, privateKey, 0);
	}

	/* constructor only for tests */
	public ClientLibrary(DPASServiceGrpc.DPASServiceFutureStub futureStub, PublicKey publicKeyClient, PrivateKey privateKeyClient, PublicKey publicKeyServer) {
		this.futureStub = new DPASServiceGrpc.DPASServiceFutureStub[]{futureStub};

		this.publicKey = publicKeyClient;
		this.privateKey = privateKeyClient;
		this.serverPublicKey = new PublicKey[]{publicKeyServer};

		this.freshnessHandlers = new FreshnessHandler[1];
		this.freshnessHandlers[0] = new FreshnessHandler();
	}

	public void register() throws ComunicationException, ClientAlreadyRegisteredException {
		if(debug != 0) System.out.println("[REGISTER] Request from client.\n");

		/* Serializes key and changes to ByteString */
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey), privateKey);

		/* Prepare request */
		Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setSignature(ByteString.copyFrom(signature)).build();

		try{
			ListenableFuture<Contract.ACK> listenable = futureStub[0].register(request);
			Contract.ACK response = listenable.get();

			/* Verify response signature */
			if(!SignatureHandler.verifyPublicSignature(response.getFreshness().toByteArray(), response.getSignature().toByteArray(), this.serverPublicKey[0])){
				if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - ServerSignatureInvalid \n");
				throw new ComunicationException("Server signature was invalid");
			}

		} catch (StatusRuntimeException e){
			verifyExceptionNoFreshnessCheck(e.getStatus(), e.getTrailers());
			handleRegistrationError(e.getStatus());
			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");

		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				verifyExceptionNoFreshnessCheck(exception.getStatus(), exception.getTrailers());
				handleRegistrationError(exception.getStatus());
			}

			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");
		}
	}

	public void post(char[] message) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		checkMessage(message);

		/* A post without announcements */
		post(message, new String[0]);
	}

	public void post(char[] message, String[] references) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[POST] Request from client.\n");
		checkMessage(message);

		try{
			ListenableFuture<Contract.ACK> listenableFuture = futureStub[0].post(getPostRequest(message, references));
			Contract.ACK response = listenableFuture.get();

			if(!SignatureHandler.verifyPublicSignature(response.getFreshness().toByteArray(), response.getSignature().toByteArray(), this.serverPublicKey[0])){
				throw new ComunicationException("The integrity of the server response was violated");
			}

			if(!freshnessHandlers[0].verifyFreshness(Longs.fromByteArray(response.getFreshness().toByteArray()))){
				throw new ComunicationException("Server response was not fresh");
			}

		} catch (StatusRuntimeException e){
			verifyException(e.getStatus(), e.getTrailers());
			handlePostError(e.getStatus());
			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");

		}  catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				verifyException(exception.getStatus(), exception.getTrailers());
				handlePostError(exception.getStatus());
			}

			throw new ComunicationException("Received invalid exception, please try again.");
		}
	}

	public void postGeneral(char[] message) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		checkMessage(message);

		/* A post without announcements */
		postGeneral(message, new String[0]);
	}

	public void postGeneral(char[] message, String[] references) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[POST GENERAL] Request from client.\n");
		checkMessage(message);

		try{
			ListenableFuture<Contract.ACK> listenableFuture = futureStub[0].postGeneral(getPostRequest(message, references));
			Contract.ACK response = listenableFuture.get();

			if(!SignatureHandler.verifyPublicSignature(response.getFreshness().toByteArray(), response.getSignature().toByteArray(), this.serverPublicKey[0])){
				throw new ComunicationException("The integrity of the server response was violated");
			}

			if(!freshnessHandlers[0].verifyFreshness(Longs.fromByteArray(response.getFreshness().toByteArray()))){
				throw new ComunicationException("Server response was not fresh");
			}

		} catch (StatusRuntimeException e){
			verifyException(e.getStatus(), e.getTrailers());
			handlePostError(e.getStatus());
			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");

		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				verifyException(exception.getStatus(), exception.getTrailers());
				handlePostError(exception.getStatus());
			}

			throw new ComunicationException("Received invalid exception, please try again.");
		}
	}

	public Announcement[] read(PublicKey client, int number) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[READ] Request from client.\n");
		checkNumber(number);

		try {
			ListenableFuture<Contract.ReadResponse> listenableFuture = futureStub[0].read(getReadRequest(client, number));
			Contract.ReadResponse response = listenableFuture.get();

			if(!SignatureHandler.verifyPublicSignature(Bytes.concat(response.getAnnouncements().toByteArray(), response.getFreshness().toByteArray()), response.getSignature().toByteArray(), this.serverPublicKey[0])){
				throw new ComunicationException("The integrity of the server response was violated");
			}

			if(!freshnessHandlers[0].verifyFreshness(Longs.fromByteArray(response.getFreshness().toByteArray()))){
				throw new ComunicationException("Server response was not fresh");
			}
			//messageHandler[0].verifyMessage(response.getAnnouncements().toByteArray(), Longs.fromByteArray(response.getFreshness().toByteArray()), response.getSignature().toByteArray());

			Announcement[] announcements = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());

			for(Announcement announcement : announcements){
				byte[] serializedAnnouncements = SerializationUtils.serialize(announcement.getAnnouncements());
				byte[] serializedPublicKey = SerializationUtils.serialize(announcement.getPublicKey());
				byte[] messageBytes = new String(announcement.getPost()).getBytes();

				if(!SignatureHandler.verifyPublicSignature(Bytes.concat(serializedPublicKey, messageBytes, serializedAnnouncements), announcement.getSignature(), announcement.getPublicKey())){
					throw new ComunicationException("An announcement was not properly signed");
				}
			}

			return announcements;
		} catch (StatusRuntimeException e){
			verifyException(e.getStatus(), e.getTrailers());
			handleReadError(e.getStatus());
			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");

		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				verifyException(exception.getStatus(), exception.getTrailers());
				handleReadError(exception.getStatus());
			}

			throw new ComunicationException("Received invalid exception, please try again.");
		}
	}

	public Announcement[] readGeneral(int number) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[READ GENERAL] Request from client.\n");
		checkNumber(number);

		try {
			ListenableFuture<Contract.ReadResponse> listenableFuture = futureStub[0].readGeneral(getReadGeneralRequest(number));
			Contract.ReadResponse response = listenableFuture.get();

			if(!SignatureHandler.verifyPublicSignature(Bytes.concat(response.getAnnouncements().toByteArray(), response.getFreshness().toByteArray()), response.getSignature().toByteArray(), this.serverPublicKey[0])){
				throw new ComunicationException("The integrity of the server response was violated");
			}

			if(!freshnessHandlers[0].verifyFreshness(Longs.fromByteArray(response.getFreshness().toByteArray()))){
				throw new ComunicationException("Server response was not fresh");
			}

			//messageHandler[0].verifyMessage(response.getAnnouncements().toByteArray(), Longs.fromByteArray(response.getFreshness().toByteArray()), response.getSignature().toByteArray());

			Announcement[] announcements = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
			for(Announcement announcement : announcements){
				byte[] serializedAnnouncements = SerializationUtils.serialize(announcement.getAnnouncements());
				byte[] serializedPublicKey = SerializationUtils.serialize(announcement.getPublicKey());
				byte[] messageBytes = new String(announcement.getPost()).getBytes();

				if(!SignatureHandler.verifyPublicSignature(Bytes.concat(serializedPublicKey, messageBytes, serializedAnnouncements), announcement.getSignature(), announcement.getPublicKey())){
					throw new ComunicationException("An announcement was not properly signed");
				}
			}

			return announcements;
		} catch (StatusRuntimeException e){
			verifyException(e.getStatus(), e.getTrailers());
			handleReadError(e.getStatus());
			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");

		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				verifyException(exception.getStatus(), exception.getTrailers());
				handleReadError(exception.getStatus());
			}

			throw new ComunicationException("Received invalid exception, please try again.");
		}

	}

	/*************************/
	/**** AUX FUNCTIONS ******/
	/*************************/

	public Contract.PostRequest getPostRequest(char[] message, String[] references) {
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		String post = new String(message);
		byte[] announcements = SerializationUtils.serialize(references);

		byte[] postBytes = post.getBytes();

		byte[] encryptedMessage = null;
		try {
			Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			encrypt.init(Cipher.ENCRYPT_MODE, this.serverPublicKey[0]);
			encryptedMessage = encrypt.doFinal(post.getBytes(StandardCharsets.UTF_8));
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
			System.out.println("Unexpected error while encrypting message");
			e.printStackTrace();
		}

		byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(publicKey, postBytes, announcements), privateKey);
		byte[] freshness = Longs.toByteArray(freshnessHandlers[0].getNextFreshness());
		byte[] integrity = SignatureHandler.publicSign(Bytes.concat(publicKey, encryptedMessage, messageSignature, announcements, freshness), privateKey);

		return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(encryptedMessage)).setMessageSignature(ByteString.copyFrom(messageSignature)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(integrity)).build();
	}

	public Contract.PostRequest getTestPostRequest(char[] message, String[] references) {
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		String post = new String(message);
		byte[] announcements = SerializationUtils.serialize(references);

		return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(post.getBytes())).setAnnouncements(ByteString.copyFrom(announcements)).build();
	}

	public Contract.ReadRequest getReadRequest(PublicKey clientKey, int number){
		byte[] targetPublicKey = SerializationUtils.serialize(clientKey);
		byte[] userPublicKey = SerializationUtils.serialize(this.publicKey);
		byte[] numberBytes = Ints.toByteArray(number);
		byte[] freshness = Longs.toByteArray(freshnessHandlers[0].getNextFreshness());

		byte[] keys = Bytes.concat(targetPublicKey, userPublicKey);
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(keys, numberBytes, freshness), this.privateKey);
		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(userPublicKey)).setTargetPublicKey(ByteString.copyFrom(targetPublicKey)).setNumber(number).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

	}

	public Contract.ReadRequest getReadGeneralRequest(int number){
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] numberBytes = Ints.toByteArray(number);

		byte[] freshness = Longs.toByteArray(freshnessHandlers[0].getNextFreshness());
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, numberBytes, freshness), this.privateKey);

		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

	}

	public Contract.RegisterRequest getRegisterRequest(){
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] freshness = new byte[0];
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, freshness), privateKey);

		return Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();
	}

	/********************/
	/** TEST FUNCTIONS **/
	/********************/

	public boolean clientRegisteredState() {
		ByteString publicKey = ByteString.copyFrom(SerializationUtils.serialize(this.publicKey));
		Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(publicKey).build();

		Contract.TestsResponse response = stub.clientRegisteredState(request);

		return response.getTestResult();
	}

	public boolean postState(char[] message, String[] references) {
		try{
			checkMessage(message);

			Contract.TestsResponse response = stub.postState(getTestPostRequest(message, references));
			return response.getTestResult();
		} catch (InvalidArgumentException e){
			return false;
		}
	}

	public boolean postState(char[] message) {
		try{
			checkMessage(message);

			return postState(message, new String[0]);
		}catch (InvalidArgumentException e){
			return false;
		}
	}

	public boolean postGeneralState(char[] message, String[] references) {
		try{
			checkMessage(message);

			Contract.TestsResponse response = stub.postGeneralState(getTestPostRequest(message, references));
			return response.getTestResult();
		} catch (InvalidArgumentException e){
			return false;
		}
	}

	public boolean postGeneralState(char[] message) {
		try{
			checkMessage(message);

			return postGeneralState(message, new String[0]);
		}catch (InvalidArgumentException e){
			return false;
		}
	}

	public void postRequest(Contract.PostRequest request) throws ComunicationException, ClientNotRegisteredException {

		try{
			Contract.ACK response = stub.post(request);

			if(!SignatureHandler.verifyPublicSignature(response.getFreshness().toByteArray(), response.getSignature().toByteArray(), this.serverPublicKey[0])){
				throw new ComunicationException("The integrity of the server response was violated");
			}

			if(!freshnessHandlers[0].verifyFreshness(Longs.fromByteArray(response.getFreshness().toByteArray()))){
				throw new ComunicationException("Server response was not fresh");
			}

			//messageHandler[0].verifyMessage(new byte[0], Longs.fromByteArray(response.getFreshness().toByteArray()), response.getSignature().toByteArray());
		} catch (StatusRuntimeException e){
			verifyException(e.getStatus(), e.getTrailers());
			handlePostError(e.getStatus());
			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");

		}
	}

	public void postGeneralRequest(Contract.PostRequest request) throws ComunicationException, ClientNotRegisteredException {
		try{
			Contract.ACK response = stub.postGeneral(request);

            if(!SignatureHandler.verifyPublicSignature(response.getFreshness().toByteArray(), response.getSignature().toByteArray(), this.serverPublicKey[0])){
                throw new ComunicationException("The integrity of the server response was violated");
            }

            if(!freshnessHandlers[0].verifyFreshness(Longs.fromByteArray(response.getFreshness().toByteArray()))){
                throw new ComunicationException("Server response was not fresh");
            }
		} catch (StatusRuntimeException e){
			verifyException(e.getStatus(), e.getTrailers());
			handlePostError(e.getStatus());
			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");

		}
	}

	public Announcement[] readRequest(Contract.ReadRequest request) throws ComunicationException, ClientNotRegisteredException {
		try {
			Contract.ReadResponse response = stub.read(request);

            if(!SignatureHandler.verifyPublicSignature(Bytes.concat(response.getAnnouncements().toByteArray(), response.getFreshness().toByteArray()), response.getSignature().toByteArray(), this.serverPublicKey[0])){
                throw new ComunicationException("The integrity of the server response was violated");
            }

            if(!freshnessHandlers[0].verifyFreshness(Longs.fromByteArray(response.getFreshness().toByteArray()))){
                throw new ComunicationException("Server response was not fresh");
            }
			//messageHandler[0].verifyMessage(response.getAnnouncements().toByteArray(), Longs.fromByteArray(response.getFreshness().toByteArray()), response.getSignature().toByteArray());
			return SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
		} catch (StatusRuntimeException e){
			verifyException(e.getStatus(), e.getTrailers());
			handleReadError(e.getStatus());
			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");

		}
    }

	public Announcement[] readGeneralRequest(Contract.ReadRequest request) throws ComunicationException, ClientNotRegisteredException {
		try {
			Contract.ReadResponse response = stub.readGeneral(request);

			if(!SignatureHandler.verifyPublicSignature(Bytes.concat(response.getAnnouncements().toByteArray(), response.getFreshness().toByteArray()), response.getSignature().toByteArray(), this.serverPublicKey[0])){
				throw new ComunicationException("The integrity of the server response was violated");
			}

			if(!freshnessHandlers[0].verifyFreshness(Longs.fromByteArray(response.getFreshness().toByteArray()))){
				throw new ComunicationException("Server response was not fresh");
			}
			//messageHandler[0].verifyMessage(response.getAnnouncements().toByteArray(), Longs.fromByteArray(response.getFreshness().toByteArray()), response.getSignature().toByteArray());
			return SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
		} catch (StatusRuntimeException e){
			verifyException(e.getStatus(), e.getTrailers());
			handleReadError(e.getStatus());
			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");

		}

	}

	public void registerRequest(Contract.RegisterRequest request) throws ClientAlreadyRegisteredException, ComunicationException {
		try{
			Contract.ACK response = stub.register(request);

			if(!SignatureHandler.verifyPublicSignature(response.getFreshness().toByteArray(), response.getSignature().toByteArray(), this.serverPublicKey[0])){
				throw new ComunicationException("Server signature was invalid");
			}
		} catch (StatusRuntimeException e){
			verifyExceptionNoFreshnessCheck(e.getStatus(), e.getTrailers());
			handleRegistrationError(e.getStatus());
			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException("Received invalid exception, please try again.");

		}
	}

	public void cleanPosts(){
		stub.cleanPosts(Empty.newBuilder().build());
	}

	public void cleanGeneralPosts(){
		stub.cleanGeneralPosts(Empty.newBuilder().build());
	}

	/*********************/
	/** CHECK ARGUMENTS **/
	/*********************/

	private void checkConstructor(String host, int port, PublicKey publicKey, PrivateKey privateKey, int faults) throws InvalidArgumentException {
		if(host == null || host.isEmpty() || port < 0 || publicKey == null || privateKey == null || faults < 0){
			if(debug != 0) System.out.println("\t ERROR: INVALID_ARGUMENT - Invalid constructor arguments \n");
			throw new InvalidArgumentException("Invalid constructor arguments");
		}
	}

	private void checkMessage(char[] message) throws InvalidArgumentException {
		if(message == null){
			if(debug != 0) System.out.println("\t ERROR: INVALID_ARGUMENT - Public key can not be null \n");
			throw new InvalidArgumentException("Public key can not be null");
		}
		if(message.length > 255) {
			if(debug != 0) System.out.println("\t ERROR: INVALID_ARGUMENT - Post too long, must be smaller than 256 chars \n");
			throw new InvalidArgumentException("Post too long, must be smaller than 256 chars");
		}
	}

	private void checkNumber(int n) throws InvalidArgumentException {
		if(n < 0){
			if(debug != 0) System.out.println("\t ERROR: INVALID_ARGUMENT - Number can not be negative \n");
			throw new InvalidArgumentException("Number can not be negative");
		}
	}

	/******************************/
	/** ERROR HANDLING FUNCTIONS **/
	/******************************/

	private void handleRegistrationError(Status status) throws ClientAlreadyRegisteredException, ComunicationException {
		switch(status.getCode()){
			case INVALID_ARGUMENT:
				switch(status.getDescription()){
					case "PublicKey":
						if(debug != 0) System.out.println("\t ERROR: INVALID_ARGUMENT - The public key could not be deserialised on the server \n");
						throw new ComunicationException("The public key could not be deserialised on the server");
					case "ClientAlreadyRegistered":
						if(debug != 0) System.out.println("\t ERROR: INVALID_ARGUMENT - This client was already registered \n");
						throw new ClientAlreadyRegisteredException("This client was already registered");
				}
			case PERMISSION_DENIED:
				switch(status.getDescription()){
					case "ClientSignatureInvalid":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The signature of the request wasn't valid \n");
						throw new ComunicationException("The signature of the request wasn't valid");
				}
		}
	}

	private void handlePostError(Status status) throws ComunicationException, ClientNotRegisteredException {
		switch(status.getCode()){
			case INVALID_ARGUMENT:
				switch (status.getDescription()){
					case "PublicKey":
						if(debug != 0) System.out.println("\t ERROR: INVALID_ARGUMENT - The public key could not be deserialised on the server \n");
						throw new ComunicationException("The public key could not be deserialised on the server");
					case "NonExistentAnnouncementReference":
						if(debug != 0) System.out.println("\t ERROR: INVALID_ARGUMENT - There is a non-existent announcement referenced in this post \n");
						throw new ComunicationException("There is a non-existent announcement referenced in this post");
				}
			case PERMISSION_DENIED:
				switch(status.getDescription()){
					case "ClientNotRegistered":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The client wasn't registered yet \n");
						throw new ClientNotRegisteredException("The client wasn't registered yet");
					case "ClientRequestNotFresh":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The request received from the client wasn't fresh \n");
						throw new ComunicationException("The request received from the client wasn't fresh");
					case "ClientIntegrityViolation":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The integrity of the request was violated \n");
						throw new ComunicationException("The integrity of the request was violated");
					case "AnnouncementSignatureInvalid":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - An announcement was not properly signed \n");
						throw new ComunicationException("An announcement was not properly signed");
				}
		}
	}

	private void handleReadError(Status status) throws ComunicationException, ClientNotRegisteredException{
		switch(status.getCode()){
			case INVALID_ARGUMENT:
				if ("PublicKey".equals(status.getDescription())) {
					throw new ComunicationException("The public key could not be deserialised on the server");
				}
			case PERMISSION_DENIED:
				switch(status.getDescription()){
					case "ClientNotRegistered":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The client wasn't registered yet \n");
						throw new ClientNotRegisteredException("The client wasn't registered yet");
					case "TargetClientNotRegistered":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The target wasn't registered yet \n");
						throw new ComunicationException("The read target client wasn't registered yet");
					case "ClientRequestNotFresh":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The request received from the client wasn't fresh \n");
						throw new ComunicationException("The request received from the client wasn't fresh");
					case "ClientIntegrityViolation":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The integrity of the request was violated \n");
						throw new ComunicationException("The integrity of the request was violated");
				}
		}
	}

	private void verifyException(Status status, Metadata metadata) throws ComunicationException {
		Metadata.Key<byte[]> clientKey = Metadata.Key.of("clientKey-bin", Metadata.BINARY_BYTE_MARSHALLER);
		Metadata.Key<byte[]> clientFreshnessKey = Metadata.Key.of("clientFreshness-bin", Metadata.BINARY_BYTE_MARSHALLER);
		Metadata.Key<byte[]> signatureKey = Metadata.Key.of("signature-bin", Metadata.BINARY_BYTE_MARSHALLER);

		byte[] serializedClientKey = metadata.get(clientKey);
		byte[] clientFreshness = metadata.get(clientFreshnessKey);
		byte[] signature = metadata.get(signatureKey);


		if(!SignatureHandler.verifyPublicSignature(Bytes.concat(Ints.toByteArray(status.getCode().value()), status.getDescription().getBytes(), serializedClientKey, clientFreshness), signature, this.serverPublicKey[0])){
			throw new ComunicationException("Server exception signature invalid");
		}

		if(clientFreshness != null){
			if(!this.freshnessHandlers[0].verifyExceptionFreshness(Longs.fromByteArray(clientFreshness))){
				throw new ComunicationException("Server exception not fresh");
			}
		}
	}

	private void verifyExceptionNoFreshnessCheck(Status status, Metadata metadata) throws ComunicationException {
		Metadata.Key<byte[]> clientKey = Metadata.Key.of("clientKey-bin", Metadata.BINARY_BYTE_MARSHALLER);
		Metadata.Key<byte[]> clientFreshnessKey = Metadata.Key.of("clientFreshness-bin", Metadata.BINARY_BYTE_MARSHALLER);
		Metadata.Key<byte[]> signatureKey = Metadata.Key.of("signature-bin", Metadata.BINARY_BYTE_MARSHALLER);

		byte[] serializedClientKey = metadata.get(clientKey);
		byte[] clientFreshness = metadata.get(clientFreshnessKey);
		byte[] signature = metadata.get(signatureKey);

		if(!SignatureHandler.verifyPublicSignature(Bytes.concat(Ints.toByteArray(status.getCode().value()), status.getDescription().getBytes(), serializedClientKey, clientFreshness), signature, this.serverPublicKey[0])){
			throw new ComunicationException("Server exception signature invalid");
		}

	}

	/***********************/
	/** Channel Shut Down **/
	/***********************/

	public void shutDown(){
		for(ManagedChannel channel: this.channel){
			channel.shutdown();
		}
	}

}
