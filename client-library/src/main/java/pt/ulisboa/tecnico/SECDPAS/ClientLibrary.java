package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.Empty;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
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
import java.util.concurrent.ExecutionException;

public class ClientLibrary {

	private String host = "localhost";
	private int port = 8080;
	private String target = host + ":" + port;

	private ManagedChannel channel;
	private DPASServiceGrpc.DPASServiceFutureStub futureStub;
	private DPASServiceGrpc.DPASServiceBlockingStub stub;

	private MessageHandler messageHandler;

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private PublicKey serverPublicKey;

	private long timeout = 10000;

	/* for debugging change to 1 */
	private int debug = 0;

	public ClientLibrary(String host, int port, PublicKey publicKey, PrivateKey privateKey) throws InvalidArgumentException, CertificateInvalidException{
		checkConstructor(host, port, publicKey, privateKey);

		this.target = host + ":" + port;
		this.channel = ManagedChannelBuilder.forTarget(target).usePlaintext().build();
		this.futureStub = DPASServiceGrpc.newFutureStub(channel);//.withDeadlineAfter(timeout, TimeUnit.MILLISECONDS);
		this.stub = DPASServiceGrpc.newBlockingStub(channel);//.withDeadlineAfter(timeout, TimeUnit.MILLISECONDS);

		this.messageHandler = new MessageHandler(null);
		this.publicKey = publicKey;
		this.privateKey = privateKey;

		try{
			Path currentRelativePath = Paths.get("");

			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			FileInputStream is = new FileInputStream (currentRelativePath.toAbsolutePath().toString() + "/src/main/security/certificates/server/certServer.der");
			X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
			this.serverPublicKey = cer.getPublicKey();
		} catch (CertificateException | FileNotFoundException e){
			throw new CertificateInvalidException(e.getMessage());
		}
	}

	/* constructor only for tests */
	public ClientLibrary(DPASServiceGrpc.DPASServiceFutureStub futureStub, PublicKey publicKeyClient, PrivateKey privateKeyClient, PublicKey publicKeyServer) {
		this.futureStub = futureStub;//.withDeadlineAfter(timeout, TimeUnit.MILLISECONDS);

		this.messageHandler = new MessageHandler(null);
		this.publicKey = publicKeyClient;
		this.privateKey = privateKeyClient;
		this.serverPublicKey = publicKeyServer;
	}

	public void register() throws ComunicationException, ClientAlreadyRegisteredException {
		if(debug != 0) System.out.println("[REGISTER] Request from client.\n");

		/* Serializes key and changes to ByteString */
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] freshness = messageHandler.getFreshness();
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, freshness), privateKey);

		/* Prepare request */
		Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

		try{
			ListenableFuture<Contract.ACK> listenable = futureStub.register(request);
			Contract.ACK response = listenable.get();

			/* Verify response freshness */
			messageHandler.verifyFreshness(response.getFreshness().toByteArray());

			/* Verify response signature */
			if(!SignatureHandler.verifyPublicSignature(response.getFreshness().toByteArray(), response.getSignature().toByteArray(), this.serverPublicKey)){
				if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - ServerSignatureInvalid \n");
				throw new ComunicationException("Server signature was invalid");
			}

		} catch (StatusRuntimeException e){
			handleRegistrationError(e.getStatus());
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handleRegistrationError(exception.getStatus());
			}

			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException(e.getMessage());
		} catch (MessageNotFreshException e) {
			if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - ServerRequestNotFresh.\n");
			throw new ComunicationException("Server response was not fresh");
		}
	}

	protected void setupConnection() throws ClientNotRegisteredException, ComunicationException {
		if(debug != 0) System.out.println("[SETUP CONNECTION] Request from client.\n");

		/* Create Diffie-Hellman agreement */
		DiffieHellmanClient diffieHellmanClient = new DiffieHellmanClient();

		byte[] clientAgreement = null;

		try {
			clientAgreement = diffieHellmanClient.prepareAgreement();
		} catch (SignatureException e) {
			//TODO- Proper exceptions for client side
			e.printStackTrace();
		}

		/* Prepare request for server */
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);

		byte[] freshness = messageHandler.getFreshness();
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, clientAgreement, freshness), privateKey);

		Contract.DHRequest request = Contract.DHRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setClientAgreement(ByteString.copyFrom(clientAgreement)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

		Contract.DHResponse response = null;
		try{
			ListenableFuture<Contract.DHResponse> listenable = futureStub.setupConnection(request);
			response = listenable.get();
		} catch (StatusRuntimeException e){
			handleSetupConnectionError(e.getStatus());
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handleSetupConnectionError(exception.getStatus());
			}

			if(debug != 0) System.out.println("\t ERROR: UNKNOWN - " + e.getMessage() + "\n");
			throw new ComunicationException(e.getMessage());
		}

		byte[] serverAgreement = response.getServerAgreement().toByteArray();

		/* Verify if message is fresh */
		byte[] serverFreshness = response.getFreshness().toByteArray();

		try {
			messageHandler.verifyFreshness(serverFreshness);
		} catch (MessageNotFreshException e) {
			if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - Server response was not fresh \n");
			throw new ComunicationException("Server response was not fresh");
		}

		/* Verify if the signature is valid */
		byte[] serverSignature = response.getSignature().toByteArray();

		if(!SignatureHandler.verifyPublicSignature(serverFreshness, serverSignature, this.serverPublicKey)){
			if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - Server signature was not valid \n");
			throw new ComunicationException("Server signature was not valid");
		}

		/* Obtain shared key */
		diffieHellmanClient.execute(serverAgreement);

		/* Set shared key */
		messageHandler.resetSignature(diffieHellmanClient.getSharedHMACKey());
	}

	public void post(char[] message) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		checkMessage(message);

		/* A post without announcements */
		post(message, new String[0]);
	}

	public void post(char[] message, String[] references) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[POST] Request from client.\n");
		checkMessage(message);

		/* Check if client is in session */
		if(!messageHandler.isInSession()){
			setupConnection();
		}

		try{
			ListenableFuture<Contract.ACK> listenableFuture = futureStub.post(getPostRequest(message, references));
			Contract.ACK response = listenableFuture.get();
			messageHandler.verifyMessage(new byte[0], response.getFreshness().toByteArray(), response.getSignature().toByteArray());
		} catch (StatusRuntimeException e){
			handlePostError(e.getStatus());
		} catch (SignatureNotValidException e) {
			throw new ComunicationException("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ComunicationException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handlePostError(exception.getStatus());
			}

			throw new ComunicationException(e.getMessage());
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

		/* Check if client is in session */
		if(!messageHandler.isInSession()){
			setupConnection();
		}

		try{
			ListenableFuture<Contract.ACK> listenableFuture = futureStub.postGeneral(getPostRequest(message, references));
			Contract.ACK response = listenableFuture.get();
			messageHandler.verifyMessage(new byte[0], response.getFreshness().toByteArray(), response.getSignature().toByteArray());
		} catch (StatusRuntimeException e){
			handlePostError(e.getStatus());
		} catch (SignatureNotValidException e) {
			throw new ComunicationException("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ComunicationException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handlePostError(exception.getStatus());
			}

			throw new ComunicationException(e.getMessage());
		}
	}

	public Announcement[] read(PublicKey client, int number) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[READ] Request from client.\n");
		checkNumber(number);

		/* Check if client is in session */
		if(!messageHandler.isInSession()){
			setupConnection();
		}

		try {
			ListenableFuture<Contract.ReadResponse> listenableFuture = futureStub.read(getReadRequest(client, number));
			Contract.ReadResponse response = listenableFuture.get();
			messageHandler.verifyMessage(response.getAnnouncements().toByteArray(), response.getFreshness().toByteArray(), response.getSignature().toByteArray());

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
			handleReadError(e.getStatus());
		} catch (SignatureNotValidException e) {
			throw new ComunicationException("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ComunicationException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handleReadError(exception.getStatus());
			}

			throw new ComunicationException(e.getMessage());
		}

		throw new RuntimeException("Unknown error");
	}

	public Announcement[] readGeneral(int number) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[READ GENERAL] Request from client.\n");
		checkNumber(number);

		/* Check if client is in session */
		if(!messageHandler.isInSession()){
			setupConnection();
		}

		try {
			ListenableFuture<Contract.ReadResponse> listenableFuture = futureStub.readGeneral(getReadGeneralRequest(number));
			Contract.ReadResponse response = listenableFuture.get();
			messageHandler.verifyMessage(response.getAnnouncements().toByteArray(), response.getFreshness().toByteArray(), response.getSignature().toByteArray());

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
			handleReadError(e.getStatus());
		} catch (SignatureNotValidException e) {
			throw new ComunicationException("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ComunicationException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handleReadError(exception.getStatus());
			}

			throw new ComunicationException(e.getMessage());
		}

		throw new RuntimeException("Unknown error");
	}

	public void closeConnection() throws ComunicationException, ClientNotRegisteredException, InvalidArgumentException {
		if(debug != 0) System.out.println("[CLOSE CONNECTION] Request from client.\n");

		/* Check if client is in session */
		if(!messageHandler.isInSession()){
			throw new InvalidArgumentException("Session already closed");
		}

		try{
			ListenableFuture<Contract.ACK> listenableFuture = futureStub.closeSession(getCloseSessionRequest());
			Contract.ACK response = listenableFuture.get();

			messageHandler.verifyMessage(new byte[0], response.getFreshness().toByteArray(), response.getSignature().toByteArray());
			messageHandler.resetSignature(null);
		} catch (StatusRuntimeException e){
			handleCloseConnectionError(e.getStatus());
		} catch (SignatureNotValidException e) {
			throw new ComunicationException("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ComunicationException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handleCloseConnectionError(exception.getStatus());
			}

			throw new ComunicationException(e.getMessage());
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
			encrypt.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			encryptedMessage = encrypt.doFinal(post.getBytes(StandardCharsets.UTF_8));
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
			System.out.println("Unexpected error while encrypting message");
			e.printStackTrace();
		}

		byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(publicKey, postBytes, announcements), privateKey);
		byte[] freshness = messageHandler.getFreshness();
		byte[] integrity = messageHandler.sign(Bytes.concat(publicKey, encryptedMessage, messageSignature, announcements), freshness);

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
		byte[] freshness = messageHandler.getFreshness();

		byte[] keys = Bytes.concat(targetPublicKey, userPublicKey);
		byte[] signature = messageHandler.sign(Bytes.concat(keys, numberBytes), freshness);
		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(userPublicKey)).setTargetPublicKey(ByteString.copyFrom(targetPublicKey)).setNumber(number).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

	}

	public Contract.ReadRequest getReadGeneralRequest(int number){
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] numberBytes = Ints.toByteArray(number);
		byte[] freshness = messageHandler.getFreshness();
		byte[] signature = messageHandler.sign(Bytes.concat(publicKey, numberBytes), freshness);

		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

	}

	public Contract.RegisterRequest getRegisterRequest(){
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] freshness = messageHandler.getFreshness();
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, freshness), privateKey);

		return Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();
	}

	public Contract.CloseSessionRequest getCloseSessionRequest(){
		byte[] serializedPublicKey = SerializationUtils.serialize(publicKey);
		byte[] freshness = messageHandler.getFreshness();
		byte[] signature = messageHandler.sign(serializedPublicKey, freshness);

		return Contract.CloseSessionRequest.newBuilder().setPublicKey(ByteString.copyFrom(serializedPublicKey)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();
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

	public void postRequest(Contract.PostRequest request) throws ClientNotRegisteredException, ComunicationException {
		try{
			Contract.ACK response = stub.post(request);
			messageHandler.verifyMessage(new byte[0], response.getFreshness().toByteArray(), response.getSignature().toByteArray());
		} catch (StatusRuntimeException e){
			handlePostError(e.getStatus());
		} catch (MessageNotFreshException e){
			throw new ComunicationException("Server response was not fresh");
		} catch (SignatureNotValidException e){
			throw new ComunicationException("The integrity of the server response was violated");
		}

	}

	public void postGeneralRequest(Contract.PostRequest request) throws ClientNotRegisteredException, ComunicationException {
		try{
			Contract.ACK response = stub.postGeneral(request);
			messageHandler.verifyMessage(new byte[0], response.getFreshness().toByteArray(), response.getSignature().toByteArray());
		} catch (StatusRuntimeException e){
			handlePostError(e.getStatus());
		} catch (MessageNotFreshException e){
			throw new ComunicationException("Server response was not fresh");
		} catch (SignatureNotValidException e){
			throw new ComunicationException("The integrity of the server response was violated");
		}
	}

	public Announcement[] readRequest(Contract.ReadRequest request) throws ClientNotRegisteredException, ComunicationException {
		try {
			Contract.ReadResponse response = stub.read(request);
			messageHandler.verifyMessage(response.getAnnouncements().toByteArray(), response.getFreshness().toByteArray(), response.getSignature().toByteArray());
			return SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
		} catch (StatusRuntimeException e){
			handleReadError(e.getStatus());
		} catch (MessageNotFreshException e){
			throw new ComunicationException("Server response was not fresh");
		} catch (SignatureNotValidException e){
			throw new ComunicationException("The integrity of the server response was violated");
		}

		throw new RuntimeException("Unexpected Error");
	}

	public Announcement[] readGeneralRequest(Contract.ReadRequest request) throws ClientNotRegisteredException, ComunicationException {
		try {
			Contract.ReadResponse response = stub.readGeneral(request);
			messageHandler.verifyMessage(response.getAnnouncements().toByteArray(), response.getFreshness().toByteArray(), response.getSignature().toByteArray());
			return SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
		} catch (StatusRuntimeException e){
			handleReadError(e.getStatus());
		} catch (MessageNotFreshException e){
			throw new ComunicationException("Server response was not fresh");
		} catch (SignatureNotValidException e){
			throw new ComunicationException("The integrity of the server response was violated");
		}

		throw new RuntimeException("Unexpected error");
	}

	public void registerRequest(Contract.RegisterRequest request) throws ClientAlreadyRegisteredException, ComunicationException {
		try{
			Contract.ACK response = stub.register(request);
			messageHandler.verifyFreshness(response.getFreshness().toByteArray());

			if(!SignatureHandler.verifyPublicSignature(response.getFreshness().toByteArray(), response.getSignature().toByteArray(), this.serverPublicKey)){
				throw new ComunicationException("Server signature was invalid");
			}
		} catch (StatusRuntimeException e){
			handleRegistrationError(e.getStatus());
		} catch (MessageNotFreshException e) {
			throw new ComunicationException("Server response was not fresh");
		}
	}

	public void closeConnectionRequest(Contract.CloseSessionRequest request) throws ComunicationException, ClientNotRegisteredException, InvalidArgumentException {
		if(debug != 0) System.out.println("[CLOSE CONNECTION] Request from client.\n");

		/* Check if client is in session */
		if(!messageHandler.isInSession()){
			throw new InvalidArgumentException("Session already closed");
		}

		try{
			ListenableFuture<Contract.ACK> listenableFuture = futureStub.closeSession(request);
			Contract.ACK response = listenableFuture.get();

			messageHandler.verifyMessage(new byte[0], response.getFreshness().toByteArray(), response.getSignature().toByteArray());
			messageHandler.resetSignature(null);
		} catch (StatusRuntimeException e){
			handleCloseConnectionError(e.getStatus());
		} catch (SignatureNotValidException e) {
			throw new ComunicationException("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ComunicationException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handleCloseConnectionError(exception.getStatus());
			}

			throw new ComunicationException(e.getMessage());
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

	private void checkConstructor(String host, int port, PublicKey publicKey, PrivateKey privateKey) throws InvalidArgumentException {
		if(host == null || host.isEmpty() || port < 0 || publicKey == null || privateKey == null){
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
					case "ClientRequestNotFresh":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The request received from the client wasn't fresh \n");
						throw new ComunicationException("The request received from the client wasn't fresh");
					case "ClientSignatureInvalid":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The signature of the request wasn't valid \n");
						throw new ComunicationException("The signature of the request wasn't valid");
				}
		}
	}

	private void handleSetupConnectionError(Status status) throws ComunicationException, ClientNotRegisteredException {
		switch(status.getCode()){
			case INVALID_ARGUMENT:
				if ("PublicKey".equals(status.getDescription())) {
					if(debug != 0) System.out.println("\t ERROR: INVALID_ARGUMENT - The public key could not be deserialised on the server \n");
					throw new ComunicationException("The public key could not be deserialised on the server");
				}
			case PERMISSION_DENIED:
				switch(status.getDescription()){
					case "ClientNotRegistered":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The client wasn't registered yet \n");
						throw new ClientNotRegisteredException("The client wasn't registered yet");
					case "ClientRequestNotFresh":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The request received from the client wasn't fresh \n");
						throw new ComunicationException("The request received from the client wasn't fresh");
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
			case UNAUTHENTICATED:
				if ("SessionNotInitiated".equals(status.getDescription())) {
					if(debug != 0) System.out.println("\t ERROR: UNAUTHENTICATED - The client hasn't initiated a session with the server yet (or it is invalid \n");
					throw new ComunicationException("The client hasn't initiated a session with the server yet (or it is invalid");
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
			case UNAUTHENTICATED:
				if ("SessionNotInitiated".equals(status.getDescription())) {
					if(debug != 0) System.out.println("\t ERROR: UNAUTHENTICATED - The client hasn't initiated a session with the server yet (or it is invalid \n");
					throw new ComunicationException("The client hasn't initiated a session with the server yet (or it is invalid");
				}
		}
	}

	private void handleCloseConnectionError(Status status) throws ComunicationException, ClientNotRegisteredException {
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
					case "ClientRequestNotFresh":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The request received from the client wasn't fresh \n");
						throw new ComunicationException("The request received from the client wasn't fresh");
					case "ClientIntegrityViolation":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The integrity of the request was violated \n");
						throw new ComunicationException("The integrity of the request was violated");
				}
			case UNAUTHENTICATED:
				if ("SessionNotInitiated".equals(status.getDescription())) {
					if(debug != 0) System.out.println("\t ERROR: UNAUTHENTICATED - The client hasn't initiated a session with the server yet (or it is invalid \n");
					throw new ComunicationException("The client hasn't initiated a session with the server yet (or it is invalid");
				}
		}	}

	/***********************/
	/** Channel Shut Down **/
	/***********************/

	public void shutDown(){
		this.channel.shutdown();
	}

}
