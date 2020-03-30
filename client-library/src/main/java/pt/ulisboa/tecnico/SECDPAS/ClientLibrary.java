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

	public void register() throws InvalidArgumentException, ServerResponseNotFreshException, ServerConnectionException, ClientSignatureInvalidException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientAlreadyRegisteredException {
		//Serializes key and changes to ByteString
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] freshness = messageHandler.getFreshness();
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, freshness), privateKey);

		Contract.RegisterRequest request = Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();
		try{
			ListenableFuture<Contract.ACK> listenable = futureStub.register(request);
			Contract.ACK response = listenable.get();
			messageHandler.verifyFreshness(response.getFreshness().toByteArray());

			if(!SignatureHandler.verifyPublicSignature(response.getFreshness().toByteArray(), response.getSignature().toByteArray(), this.serverPublicKey)){
				throw new ServerSignatureInvalidException("Server signature was invalid");
			}
		} catch (StatusRuntimeException e){
			handleRegistrationError(e.getStatus());
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handleRegistrationError(exception.getStatus());
			}

			throw new ServerConnectionException(e.getMessage());
		} catch (MessageNotFreshException e) {
			throw new ServerResponseNotFreshException("Server response was not fresh");
		}
	}

	protected void setupConnection() throws InvalidArgumentException, ServerResponseNotFreshException, ServerConnectionException, ClientSignatureInvalidException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientNotRegisteredException {
		// Create Diffie-Hellman agreement
		DiffieHellmanClient diffieHellmanClient = new DiffieHellmanClient();

		byte[] clientAgreement = null;

		try {
			clientAgreement = diffieHellmanClient.prepareAgreement();
		} catch (SignatureException e) {
			//TODO- Proper exceptions for client side
			e.printStackTrace();
		}

		// Serializes key and changes to ByteString
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

			throw new ServerConnectionException(e.getMessage());
		}

		byte[] serverAgreement = response.getServerAgreement().toByteArray();

		// First check if message is fresh and if it's signature is valid
		byte[] serverFreshness = response.getFreshness().toByteArray();

		try {
			messageHandler.verifyFreshness(serverFreshness);
		} catch (MessageNotFreshException e) {
			throw new ServerResponseNotFreshException("Server response was not fresh");
		}

		byte[] serverSignature = response.getSignature().toByteArray();

		if(!SignatureHandler.verifyPublicSignature(serverFreshness, serverSignature, this.serverPublicKey)){
			throw new ServerSignatureInvalidException("Server signature was not valid");
		}


		diffieHellmanClient.execute(serverAgreement);

		messageHandler.resetSignature(diffieHellmanClient.getSharedHMACKey());
	}

	public void post(char[] message) throws InvalidArgumentException, ServerResponseNotFreshException, ServerConnectionException, ClientSignatureInvalidException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientNotRegisteredException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ClientIntegrityViolationException, ClientSessionNotInitiatedException, NonExistentAnnouncementReferenceException {
		checkMessage(message);

		post(message, new String[0]);
	}

	public void post(char[] message, String[] references) throws InvalidArgumentException, ServerResponseNotFreshException, ServerConnectionException, ClientSignatureInvalidException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientNotRegisteredException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ClientIntegrityViolationException, ClientSessionNotInitiatedException, NonExistentAnnouncementReferenceException {
		checkMessage(message);

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
			throw new ServerIntegrityViolation("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ServerResponseNotFreshException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handlePostError(exception.getStatus());
			}

			throw new ServerConnectionException(e.getMessage());
		}
	}

	public void postGeneral(char[] message) throws InvalidArgumentException, ServerResponseNotFreshException, ServerConnectionException, ClientSignatureInvalidException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientNotRegisteredException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ClientIntegrityViolationException, ClientSessionNotInitiatedException, NonExistentAnnouncementReferenceException {
		checkMessage(message);

		postGeneral(message, new String[0]);
	}

	public void postGeneral(char[] message, String[] references) throws InvalidArgumentException, ServerResponseNotFreshException, ServerConnectionException, ClientSignatureInvalidException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientNotRegisteredException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ClientIntegrityViolationException, ClientSessionNotInitiatedException, NonExistentAnnouncementReferenceException {
		checkMessage(message);

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
			throw new ServerIntegrityViolation("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ServerResponseNotFreshException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handlePostError(exception.getStatus());
			}

			throw new ServerConnectionException(e.getMessage());
		}
	}

	public Announcement[] read(PublicKey client, int number) throws InvalidArgumentException, ServerResponseNotFreshException, ServerConnectionException, ClientSignatureInvalidException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientNotRegisteredException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ClientIntegrityViolationException, ClientSessionNotInitiatedException, TargetClientNotRegisteredException {
		checkNumber(number);

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
					throw new AnnouncementSignatureInvalidException("An announcement was not properly signed");
				}
			}

			return announcements;
		} catch (StatusRuntimeException e){
			handleReadError(e.getStatus());
		} catch (SignatureNotValidException e) {
			throw new ServerIntegrityViolation("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ServerResponseNotFreshException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handleReadError(exception.getStatus());
			}

			throw new ServerConnectionException(e.getMessage());
		}

		throw new RuntimeException("Unknown error");
	}

	public Announcement[] readGeneral(int number) throws InvalidArgumentException, ServerResponseNotFreshException, ServerConnectionException, ClientSignatureInvalidException, ServerSignatureInvalidException, ClientRequestNotFreshException, ClientNotRegisteredException, AnnouncementSignatureInvalidException, ServerIntegrityViolation, ClientIntegrityViolationException, ClientSessionNotInitiatedException, TargetClientNotRegisteredException {
		checkNumber(number);

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
					throw new AnnouncementSignatureInvalidException("An announcement was not properly signed");
				}
			}

			return announcements;
		} catch (StatusRuntimeException e){
			handleReadError(e.getStatus());
		} catch (SignatureNotValidException e) {
			throw new ServerIntegrityViolation("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ServerResponseNotFreshException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handleReadError(exception.getStatus());
			}

			throw new ServerConnectionException(e.getMessage());
		}

		throw new RuntimeException("Unknown error");
	}

	public void closeConnection() throws InvalidArgumentException, ServerResponseNotFreshException, ServerConnectionException, ClientRequestNotFreshException, ClientNotRegisteredException, ServerIntegrityViolation, ClientIntegrityViolationException, ClientSessionNotInitiatedException {
		if(!messageHandler.isInSession()){
			return;
		}

		try{
			byte[] serializedPublicKey = SerializationUtils.serialize(publicKey);
			byte[] freshness = messageHandler.getFreshness();
			byte[] signature = messageHandler.sign(serializedPublicKey, freshness);

			Contract.CloseSessionRequest closeSessionRequest = Contract.CloseSessionRequest.newBuilder().setPublicKey(ByteString.copyFrom(serializedPublicKey)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();
			ListenableFuture<Contract.ACK> listenableFuture = futureStub.closeSession(closeSessionRequest);
			Contract.ACK response = listenableFuture.get();

			messageHandler.verifyMessage(new byte[0], response.getFreshness().toByteArray(), response.getSignature().toByteArray());
			messageHandler.resetSignature(null);
		} catch (StatusRuntimeException e){
			handleCloseConnectionError(e.getStatus());
		} catch (SignatureNotValidException e) {
			throw new ServerIntegrityViolation("The integrity of the server response was violated");
		} catch (MessageNotFreshException e) {
			throw new ServerResponseNotFreshException("Server response was not fresh");
		} catch (InterruptedException | ExecutionException e){
			if(e.getCause() instanceof StatusRuntimeException){
				StatusRuntimeException exception = (StatusRuntimeException) e.getCause();
				handleCloseConnectionError(exception.getStatus());
			}

			throw new ServerConnectionException(e.getMessage());
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

	public void postRequest(Contract.PostRequest request) throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException, InvalidArgumentException, ClientIntegrityViolationException, ClientSessionNotInitiatedException, ClientRequestNotFreshException, AnnouncementSignatureInvalidException, NonExistentAnnouncementReferenceException {
		try{
			Contract.ACK response = stub.post(request);
			messageHandler.verifyMessage(new byte[0], response.getFreshness().toByteArray(), response.getSignature().toByteArray());
		} catch (StatusRuntimeException e){
			handlePostError(e.getStatus());
		}
	}

	public void postGeneralRequest(Contract.PostRequest request) throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException, InvalidArgumentException, ClientIntegrityViolationException, ClientSessionNotInitiatedException, ClientRequestNotFreshException, AnnouncementSignatureInvalidException, NonExistentAnnouncementReferenceException {
		try{
			Contract.ACK response = stub.postGeneral(request);
			messageHandler.verifyMessage(new byte[0], response.getFreshness().toByteArray(), response.getSignature().toByteArray());
		} catch (StatusRuntimeException e){
			handlePostError(e.getStatus());
		}
	}

	public Announcement[] readRequest(Contract.ReadRequest request) throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException, InvalidArgumentException, ClientIntegrityViolationException, ClientSessionNotInitiatedException, ClientRequestNotFreshException, TargetClientNotRegisteredException {
		try {
			Contract.ReadResponse response = stub.read(request);
			messageHandler.verifyMessage(response.getAnnouncements().toByteArray(), response.getFreshness().toByteArray(), response.getSignature().toByteArray());
			return SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
		} catch (StatusRuntimeException e){
			handleReadError(e.getStatus());
		}

		throw new RuntimeException("Unexpected Error");
	}

	public Announcement[] readGeneralRequest(Contract.ReadRequest request) throws ClientNotRegisteredException, SignatureNotValidException, MessageNotFreshException, InvalidArgumentException, ClientIntegrityViolationException, ClientSessionNotInitiatedException, ClientRequestNotFreshException, TargetClientNotRegisteredException {
		try {
			Contract.ReadResponse response = stub.readGeneral(request);
			messageHandler.verifyMessage(response.getAnnouncements().toByteArray(), response.getFreshness().toByteArray(), response.getSignature().toByteArray());
			return SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
		} catch (StatusRuntimeException e){
			handleReadError(e.getStatus());
		}

		throw new RuntimeException("Unexpected error");
	}

	public void registerRequest(Contract.RegisterRequest request) throws ClientAlreadyRegisteredException, MessageNotFreshException, ClientSignatureInvalidException, ClientRequestNotFreshException, InvalidArgumentException, ServerSignatureInvalidException {
		try{
			Contract.ACK response = stub.register(request);
			messageHandler.verifyFreshness(response.getFreshness().toByteArray());

			if(!SignatureHandler.verifyPublicSignature(response.getFreshness().toByteArray(), response.getSignature().toByteArray(), this.serverPublicKey)){
				throw new ServerSignatureInvalidException("Server signature was invalid");
			}
		} catch (StatusRuntimeException e){
			handleRegistrationError(e.getStatus());
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
			throw new InvalidArgumentException("Invalid constructor arguments");
		}
	}

	private void checkMessage(char[] message) throws InvalidArgumentException {
		if(message == null){
			throw new InvalidArgumentException("Public key can not be null");
		}
		if(message.length > 255) {
			throw new InvalidArgumentException("Post too long, must be smaller than 256 chars");
		}
	}

	private void checkNumber(int n) throws InvalidArgumentException {
		if(n < 0){
			throw new InvalidArgumentException("Number can not be negative");
		}
	}

	/******************************/
	/** ERROR HANDLING FUNCTIONS **/
	/******************************/

	private void handleRegistrationError(Status status) throws InvalidArgumentException, ClientAlreadyRegisteredException, ClientSignatureInvalidException, ClientRequestNotFreshException {
		switch(status.getCode()){
			case INVALID_ARGUMENT:
				switch(status.getDescription()){
					case "PublicKey":
						throw new InvalidArgumentException("The public key could not be deserialised on the server");
					case "ClientAlreadyRegistered":
						throw new ClientAlreadyRegisteredException("This client was already registered");
				}
			case PERMISSION_DENIED:
				switch(status.getDescription()){
					case "ClientRequestNotFresh":
						throw new ClientRequestNotFreshException("The request received from the client wasn't fresh");
					case "ClientSignatureInvalid":
						throw new ClientSignatureInvalidException("The signature of the request wasn't valid");
				}
		}
	}

	private void handleSetupConnectionError(Status status) throws InvalidArgumentException, ClientSignatureInvalidException, ClientRequestNotFreshException, ClientNotRegisteredException {
		switch(status.getCode()){
			case INVALID_ARGUMENT:
				if ("PublicKey".equals(status.getDescription())) {
					throw new InvalidArgumentException("The public key could not be deserialised on the server");
				}
			case PERMISSION_DENIED:
				switch(status.getDescription()){
					case "ClientNotRegistered":
						throw new ClientNotRegisteredException("The client wasn't registered yet");
					case "ClientRequestNotFresh":
						throw new ClientRequestNotFreshException("The request received from the client wasn't fresh");
					case "ClientSignatureInvalid":
						throw new ClientSignatureInvalidException("The signature of the request wasn't valid");
				}
		}
	}

	private void handlePostError(Status status) throws InvalidArgumentException, ClientRequestNotFreshException, ClientNotRegisteredException, ClientSessionNotInitiatedException, ClientIntegrityViolationException, AnnouncementSignatureInvalidException, NonExistentAnnouncementReferenceException {
		switch(status.getCode()){
			case INVALID_ARGUMENT:
				switch (status.getDescription()){
					case "PublicKey":
						throw new InvalidArgumentException("The public key could not be deserialised on the server");
					case "NonExistentAnnouncementReference":
						throw new NonExistentAnnouncementReferenceException("There is a non-existent announcement referenced in this post");
				}
			case PERMISSION_DENIED:
				switch(status.getDescription()){
					case "ClientNotRegistered":
						throw new ClientNotRegisteredException("The client wasn't registered yet");
					case "ClientRequestNotFresh":
						throw new ClientRequestNotFreshException("The request received from the client wasn't fresh");
					case "ClientIntegrityViolation":
						throw new ClientIntegrityViolationException("The integrity of the request was violated");
					case "AnnouncementSignatureInvalid":
						throw new AnnouncementSignatureInvalidException("The signature of the request wasn't valid");
				}
			case UNAUTHENTICATED:
				if ("SessionNotInitiated".equals(status.getDescription())) {
					throw new ClientSessionNotInitiatedException("The client hasn't initiated a session with the server yet (or it is invalid");
				}
		}
	}

	private void handleReadError(Status status) throws InvalidArgumentException, ClientRequestNotFreshException, ClientNotRegisteredException, ClientSessionNotInitiatedException, ClientIntegrityViolationException, TargetClientNotRegisteredException {
		switch(status.getCode()){
			case INVALID_ARGUMENT:
				if ("PublicKey".equals(status.getDescription())) {
					throw new InvalidArgumentException("The public key could not be deserialised on the server");
				}
			case PERMISSION_DENIED:
				switch(status.getDescription()){
					case "ClientNotRegistered":
						throw new ClientNotRegisteredException("The client wasn't registered yet");
					case "TargetClientNotRegistered":
						throw new TargetClientNotRegisteredException("The read target client wasn't registered yet");
					case "ClientRequestNotFresh":
						throw new ClientRequestNotFreshException("The request received from the client wasn't fresh");
					case "ClientIntegrityViolation":
						throw new ClientIntegrityViolationException("The integrity of the request was violated");
				}
			case UNAUTHENTICATED:
				if ("SessionNotInitiated".equals(status.getDescription())) {
					throw new ClientSessionNotInitiatedException("The client hasn't initiated a session with the server yet (or it is invalid");
				}
		}
	}

	private void handleCloseConnectionError(Status status) throws InvalidArgumentException, ClientNotRegisteredException, ClientRequestNotFreshException, ClientIntegrityViolationException, ClientSessionNotInitiatedException {
		switch(status.getCode()){
			case INVALID_ARGUMENT:
				if ("PublicKey".equals(status.getDescription())) {
					throw new InvalidArgumentException("The public key could not be deserialised on the server");
				}
			case PERMISSION_DENIED:
				switch(status.getDescription()){
					case "ClientNotRegistered":
						throw new ClientNotRegisteredException("The client wasn't registered yet");
					case "ClientRequestNotFresh":
						throw new ClientRequestNotFreshException("The request received from the client wasn't fresh");
					case "ClientIntegrityViolation":
						throw new ClientIntegrityViolationException("The integrity of the request was violated");
				}
			case UNAUTHENTICATED:
				if ("SessionNotInitiated".equals(status.getDescription())) {
					throw new ClientSessionNotInitiatedException("The client hasn't initiated a session with the server yet (or it is invalid");
				}
		}	}

	/***********************/
	/** Channel Shut Down **/
	/***********************/

	public void shutDown(){
		this.channel.shutdown();
	}

}
