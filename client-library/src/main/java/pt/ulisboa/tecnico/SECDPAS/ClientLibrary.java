package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.protobuf.Empty;

import com.google.protobuf.ByteString;
import io.grpc.*;
import org.apache.commons.lang3.SerializationUtils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class ClientLibrary {

	private ManagedChannel[] channel;
	private Map<PublicKey, AuthenticatedPerfectLink> calls;
	private DPASServiceGrpc.DPASServiceBlockingStub stub;
	private FreshnessHandler[] freshnessHandlers;
	private DPASServiceGrpc.DPASServiceFutureStub[] futureStubs;

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private PublicKey[] serverPublicKey;

	private int numServers;
	private int minQuorumResponses;

	/* for debugging change to 1 */
	private int debug = 0;

	public ClientLibrary(String host, int port, PublicKey publicKey, PrivateKey privateKey, int faults) throws InvalidArgumentException, CertificateInvalidException{
		checkConstructor(host, port, publicKey, privateKey, faults);

		//Client variables
		this.publicKey = publicKey;
		this.privateKey = privateKey;

		//Byzantine Quorum number
		this.numServers = faults*3+1;
		this.minQuorumResponses = numServers;//2*faults+1;
		this.serverPublicKey = new PublicKey[numServers];
		this.channel = new ManagedChannel[numServers];
		this.calls = new HashMap<>();
		this.freshnessHandlers = new FreshnessHandler[numServers];
		this.futureStubs = new DPASServiceGrpc.DPASServiceFutureStub[numServers];

		Path currentRelativePath = Paths.get("");

		//Stub and certificate for each server
		for(int server = 0; server < numServers; server++){
			String target = host + ":" + (port+server);
			this.channel[server] = ManagedChannelBuilder.forTarget(target).usePlaintext().build();
			this.futureStubs[server] = DPASServiceGrpc.newFutureStub(this.channel[server]);
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
			this.calls.put(serverPublicKey[server], new AuthenticatedPerfectLink(futureStubs[server], freshnessHandlers[server], serverPublicKey[server]));
		}

		//Test server
		this.stub = DPASServiceGrpc.newBlockingStub(this.channel[0]);
	}

	//Testing single client purposes
	public ClientLibrary(String host, int port, PublicKey publicKey, PrivateKey privateKey) throws InvalidArgumentException, CertificateInvalidException{
		this(host, port, publicKey, privateKey, 0);
	}

	public void register() throws ComunicationException, ClientAlreadyRegisteredException {
		if(debug != 0) System.out.println("[REGISTER] RequestType from client.\n");

		/* Create quorum */
		Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new RegisterRequest(getRegisterRequest()), minQuorumResponses);

		try{
			int result = qr.waitForQuorum();

			if(result == 1){
				StatusRuntimeException e = (StatusRuntimeException) qr.getException();
				handleRegistrationError(e.getStatus());
			}

			if(result == -1){
				throw new ComunicationException("No consensus in quorum");
			}

		}catch (InterruptedException e){
			System.out.println(e.getMessage());
		}

	}

	public void post(char[] message) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		checkMessage(message);

		/* A post without announcements */
		post(message, new String[0]);
	}

	public void post(char[] message, String[] references) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[POST] RequestType from client.\n");
		checkMessage(message);

		/* Create quorum */
		Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new PostRequest(getPostRequest(message, references), "PostRequest"), minQuorumResponses);

		try{
			int result = qr.waitForQuorum();

			if(result == 1){
				StatusRuntimeException e = (StatusRuntimeException) qr.getException();
				handlePostError(e.getStatus());
			}

			if(result == -1){
				throw new ComunicationException("No consensus in quorum");
			}

		}catch (InterruptedException e){
			System.out.println(e.getMessage());
		}

	}

	public void postGeneral(char[] message) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		checkMessage(message);

		/* A post without announcements */
		postGeneral(message, new String[0]);
	}

	public void postGeneral(char[] message, String[] references) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[POST GENERAL] RequestType from client.\n");
		checkMessage(message);

		/* Create quorum */
		Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, new PostRequest(getPostRequest(message, references), "PostGeneralRequest"), minQuorumResponses);

		try{
			int result = qr.waitForQuorum();

			if(result == 1){
				StatusRuntimeException e = (StatusRuntimeException) qr.getException();
				handlePostError(e.getStatus());
			}

			if(result == -1){
				throw new ComunicationException("No consensus in quorum");
			}

		}catch (InterruptedException e){
			System.out.println(e.getMessage());
		}

	}

	public Announcement[] read(PublicKey client, int number) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[READ] RequestType from client.\n");
		checkNumber(number);

		/* Create quorum */
		Quorum<PublicKey, Contract.ReadResponse> qr = Quorum.create(calls, new ReadRequest(getReadRequest(client, number), "ReadRequest"), minQuorumResponses);

		try{
			int result = qr.waitForQuorum();

			if(result == 0){
				Contract.ReadResponse response = qr.getResult();
				return SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
			}

			if(result == 1){
				StatusRuntimeException e = (StatusRuntimeException) qr.getException();
				handleReadError(e.getStatus());
			}

		}catch (InterruptedException e){
			System.out.println(e.getMessage());
		}

		throw new ComunicationException("No consensus in quorum");
	}

	public Announcement[] readGeneral(int number) throws InvalidArgumentException, ComunicationException, ClientNotRegisteredException {
		if(debug != 0) System.out.println("[READ GENERAL] RequestType from client.\n");
		checkNumber(number);

		/* Create quorum */
		Quorum<PublicKey, Contract.ReadResponse> qr = Quorum.create(calls, new ReadRequest(getReadGeneralRequest(number), "ReadGeneralRequest"), minQuorumResponses);

		try{
			int result = qr.waitForQuorum();

			if(result == 0){
				Contract.ReadResponse response = qr.getResult();
				return SerializationUtils.deserialize(response.getAnnouncements().toByteArray());
			}

			if(result == 1){
				StatusRuntimeException e = (StatusRuntimeException) qr.getException();
				handleReadError(e.getStatus());
			}

		}catch (InterruptedException e){
			System.out.println(e.getMessage());
		}

		throw new ComunicationException("No consensus in quorum");
	}

	/*************************/
	/**** AUX FUNCTIONS ******/
	/*************************/

	public Contract.PostRequest getPostRequest(char[] message, String[] references) {
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		String post = new String(message);
		byte[] announcements = SerializationUtils.serialize(references);

		byte[] postBytes = post.getBytes();

		byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(publicKey, postBytes, announcements), privateKey);

		byte[] freshness = null;

		for(FreshnessHandler handler : freshnessHandlers){
			freshness = Longs.toByteArray(handler.getNextFreshness());
		}

		byte[] integrity = SignatureHandler.publicSign(Bytes.concat(publicKey, postBytes, messageSignature, announcements, freshness), privateKey);

		return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(ByteString.copyFrom(postBytes)).setMessageSignature(ByteString.copyFrom(messageSignature)).setAnnouncements(ByteString.copyFrom(announcements)).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(integrity)).build();
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
		byte[] freshness = null;

		for(FreshnessHandler handler : freshnessHandlers){
			freshness = Longs.toByteArray(handler.getNextFreshness());
		}

		byte[] keys = Bytes.concat(targetPublicKey, userPublicKey);
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(keys, numberBytes, freshness), this.privateKey);
		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(userPublicKey)).setTargetPublicKey(ByteString.copyFrom(targetPublicKey)).setNumber(number).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

	}

	public Contract.ReadRequest getReadGeneralRequest(int number){
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] numberBytes = Ints.toByteArray(number);

		byte[] freshness = null;

		for(FreshnessHandler handler : freshnessHandlers){
			freshness = Longs.toByteArray(handler.getNextFreshness());
		}
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, numberBytes, freshness), this.privateKey);

		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(ByteString.copyFrom(freshness)).setSignature(ByteString.copyFrom(signature)).build();

	}

	public Contract.RegisterRequest getRegisterRequest(){
		/* Serializes key and changes to ByteString */
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey), privateKey);

		/* Prepare request */
		return Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setSignature(ByteString.copyFrom(signature)).build();
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

	public void cleanPosts(){
		for(DPASServiceGrpc.DPASServiceFutureStub stub : futureStubs){
			stub.cleanPosts(Empty.newBuilder().build());
		}
	}

	public void cleanGeneralPosts(){
		for(DPASServiceGrpc.DPASServiceFutureStub stub : futureStubs){
			stub.cleanGeneralPosts(Empty.newBuilder().build());
		}
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
					case "ServerSignatureException":
						if(debug != 0) System.out.println("\t ERROR: PERMISSION_DENIED - The integrity of the server response was violated \n");
						throw new ComunicationException("The integrity of the server response was violated");
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

	/***********************/
	/** Channel Shut Down **/
	/***********************/

	public void shutDown(){
		for(ManagedChannel channel: this.channel){
			channel.shutdown();
		}
	}

}
