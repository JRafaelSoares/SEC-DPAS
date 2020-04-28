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
	private DPASServiceGrpc.DPASServiceBlockingStub stub;
	private FreshnessHandler writeFreshnessHandler;
	private FreshnessHandler readFreshnessHandler;

	private DPASServiceGrpc.DPASServiceFutureStub[] futureStubs;

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private PublicKey[] serverPublicKey;

	private int numServers;
	private int minQuorumResponses;

	private String privateBoardId = "0";
	private String generalBoardId = "1";

	/* for debugging change to 1 */
	private int debug = 0;

	public ClientLibrary(String host, int port, PublicKey publicKey, PrivateKey privateKey, int faults) throws InvalidArgumentException, CertificateInvalidException{
		checkConstructor(host, port, publicKey, privateKey, faults);

		//Client variables
		this.publicKey = publicKey;
		this.privateKey = privateKey;

		//Byzantine Quorum number
		this.numServers = faults*3+1;
		this.minQuorumResponses = 2*faults+1;
		this.serverPublicKey = new PublicKey[numServers];
		this.channel = new ManagedChannel[numServers];
		this.writeFreshnessHandler = new FreshnessHandler();
		this.readFreshnessHandler = new FreshnessHandler();
		this.futureStubs = new DPASServiceGrpc.DPASServiceFutureStub[numServers];

		Path currentRelativePath = Paths.get("");

		//Stub and certificate for each server
		for(int server = 0; server < numServers; server++){
			String target = host + ":" + (port+server);
			this.channel[server] = ManagedChannelBuilder.forTarget(target).usePlaintext().build();
			this.futureStubs[server] = DPASServiceGrpc.newFutureStub(this.channel[server]);

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
		this(host, port, publicKey, privateKey, 1);
	}

	public void register() {
		if(debug != 0) System.out.println("[REGISTER] RequestType from client.\n");

		/* Create quorum */
		Quorum<PublicKey, Contract.ACK> qr = Quorum.create(getLinks(-1, null), new RegisterRequest(getRegisterRequest()), minQuorumResponses);

		try{
			qr.waitForQuorum();

		}catch (InterruptedException e){
			System.out.println(e.getMessage());
		}

	}

	public void post(char[] message) throws InvalidArgumentException {
		checkMessage(message);

		/* A post without announcements */
		post(message, new String[0]);
	}

	public void post(char[] message, String[] references) throws InvalidArgumentException {
		if(debug != 0) System.out.println("[POST] RequestType from client.\n");
		checkMessage(message);
		ByzantineRegularRegister.write(getLinks(writeFreshnessHandler.getFreshness(), this.publicKey), new PostRequest(getPostRequest(message, references, privateBoardId), "PostRequest"), minQuorumResponses);
		writeFreshnessHandler.incrementFreshness();

	}

	public void postGeneral(char[] message) throws InvalidArgumentException {
		checkMessage(message);

		/* A post without announcements */
		postGeneral(message, new String[0]);
	}

	public void postGeneral(char[] message, String[] references) throws InvalidArgumentException {
		if(debug != 0) System.out.println("[POST GENERAL] RequestType from client.\n");
		checkMessage(message);

		ByzantineRegularRegister.write(getLinks(writeFreshnessHandler.getFreshness(), this.publicKey), new PostRequest(getPostRequest(message, references, generalBoardId), "PostGeneralRequest"), minQuorumResponses);
		writeFreshnessHandler.incrementFreshness();
	}

	public Announcement[] read(PublicKey client, int number) throws InvalidArgumentException {
		if(debug != 0) System.out.println("[READ] RequestType from client.\n");
		checkNumber(number);

		Announcement[] announcements = ByzantineRegularRegister.read(getLinks(readFreshnessHandler.getFreshness(), client), new ReadRequest(getReadRequest(client, number), "ReadRequest"), minQuorumResponses, number);
		readFreshnessHandler.incrementFreshness();
		return announcements;
	}

	public Announcement[] readGeneral(int number) throws InvalidArgumentException {
		if(debug != 0) System.out.println("[READ GENERAL] RequestType from client.\n");
		checkNumber(number);

		Announcement[] announcements = ByzantineRegularRegister.read(getLinks(readFreshnessHandler.getFreshness(), this.publicKey), new ReadRequest(getReadGeneralRequest(number), "ReadGeneralRequest"), minQuorumResponses, number);
		readFreshnessHandler.incrementFreshness();
		return announcements;
	}

	/*********************************/
	/***** QUORUM AUX FUNCTIONS ******/
	/*********************************/
	public Map<PublicKey, AuthenticatedPerfectLink> getLinks(long freshness, PublicKey targetClientKey){
		Map<PublicKey, AuthenticatedPerfectLink> links = new HashMap<>();

		for(int server = 0; server < numServers; server++){
			links.put(serverPublicKey[server], new AuthenticatedPerfectLink(futureStubs[server], freshness, serverPublicKey[server], targetClientKey));
		}

		return links;
	}

	/**********************************/
	/***** REQUESTS AUX FUNCTIONS *****/
	/**********************************/
	public Contract.PostRequest getPostRequest(char[] message, String[] references, String board) {
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		String post = new String(message);
		byte[] announcements = SerializationUtils.serialize(references);
        long freshness = writeFreshnessHandler.getFreshness();

        byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(publicKey, post.getBytes(), announcements, Longs.toByteArray(freshness), board.getBytes()), privateKey);

		return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setMessageSignature(ByteString.copyFrom(messageSignature)).setAnnouncements(ByteString.copyFrom(announcements)).setBoard(board).setFreshness(freshness).build();
	}

	public Contract.PostRequest getTestPostRequest(char[] message, String[] references, String board) {
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		String post = new String(message);
		byte[] announcements = SerializationUtils.serialize(references);

		return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setAnnouncements(ByteString.copyFrom(announcements)).setBoard(board).build();
	}

	public Contract.ReadRequest getReadRequest(PublicKey clientKey, int number){
		byte[] targetPublicKey = SerializationUtils.serialize(clientKey);
		byte[] userPublicKey = SerializationUtils.serialize(this.publicKey);
		long freshness = readFreshnessHandler.getFreshness();

		byte[] keys = Bytes.concat(targetPublicKey, userPublicKey);
		byte[] signature = SignatureHandler.publicSign(Bytes.concat(keys, Ints.toByteArray(number), Longs.toByteArray(freshness)), this.privateKey);

		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(userPublicKey)).setTargetPublicKey(ByteString.copyFrom(targetPublicKey)).setNumber(number).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();

	}

	public Contract.ReadRequest getReadGeneralRequest(int number){
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] numberBytes = Ints.toByteArray(number);

		long freshness = readFreshnessHandler.getFreshness();

		byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, numberBytes, Longs.toByteArray(freshness)), this.privateKey);

		return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();

	}

	public Contract.RegisterRequest getRegisterRequest(){
		/* Serializes key and changes to ByteString */
		byte[] publicKey = SerializationUtils.serialize(this.publicKey);
		byte[] signature = SignatureHandler.publicSign(publicKey, privateKey);

		/* Prepare request */
		return Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setSignature(ByteString.copyFrom(signature)).build();
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

			Contract.TestsResponse response = stub.postState(getTestPostRequest(message, references, privateBoardId));
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

			Contract.TestsResponse response = stub.postGeneralState(getTestPostRequest(message, references, generalBoardId));
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


	/***********************/
	/** Channel Shut Down **/
	/***********************/

	public void shutDown(){
		for(ManagedChannel channel: this.channel){
			channel.shutdown();
		}
	}

}
