package pt.ulisboa.tecnico.SECDPAS;

import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.ServerBuilder;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;



public class DPASServer {

	/*
	//private String[] arguments;
	private Socket clientSocket;
	private ServerSocket serverSocket;
	private INCSClient incsClient;
	private Server server;
	private int toggle;
	private static String mode;
	private static NonConfidentialMessageHandler nonConfidentialMessageHandler;
	private String baseDir;
	*/
	public DPASServer() {
		/*
		clientSocket = clientSoc;
		serverSocket = serverSoc;
		this.incsClient = incsClient;
		server = manServer;
		toggle = tog;
		this.baseDir = baseDir;
		*/
	}

	public static void main(String[] args) throws Exception {

		System.out.println("------------------------------------------------------------");
		System.out.println("                       DPAS Server                          ");
		System.out.println("------------------------------------------------------------");
		System.out.println();

		// receive and print arguments


		// check arguments
		if (args.length < 1) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s port%n", Server.class.getName());
			return;
		}

		int portClient = Integer.parseInt(args[0]);
		final BindableService impl = new DPASServiceImpl();

		Server server = ServerBuilder.forPort(portClient).addService(impl).build();
		server.start();

		System.out.println("Server started");

		// Do not exit the main thread. Wait until server is terminated.
		server.awaitTermination();

		/*
		Server manufacturerServer = serverBuilder.addService(impl).build();
		manufacturerServer.start();
		//server for client requests. Change port
		Server clientServer = ServerBuilder.forPort(portGrpcClient).addService(impl).build();
		clientServer.start();



	    ServerSocket serverSocket = new ServerSocket(portClient);
    	System.out.println("Server started");

    	//Thread for manufacturer
		Runnable implThread = new INCSServer(null, null, null, manufacturerServer, 0, null);
		new Thread(implThread).start();

    	while(true) {

		   	Socket clientSocket = null;
		        try 
		        {
		            clientSocket = serverSocket.accept();
		        } catch (IOException e) {
		            throw new RuntimeException(
		                "Error accepting client connection", e);
		        }

		        //Thread for each of the clients
		        
				Runnable cliThread = new INCSServer(clientSocket, serverSocket, new INCSClient("localhost", portGrpcClient), clientServer, 1, args[6]);
				new Thread(cliThread).start();
    	}
	}
		/*

	@Override
	public void run() {
		if(toggle == 0) {
			try {
				System.out.println(server.getPort());
				server.awaitTermination();
			} catch (InterruptedException e) {
				System.out.println("The server was interrupted.");
			}
		}

		else if(toggle == 1) {
	        try {
				DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
				DataInputStream in = new DataInputStream(clientSocket.getInputStream());

				AtomicInteger clientNumber = new AtomicInteger();

				// Perform diffie-hellman key exchange with INCS server
				DiffieHellmanServer dhServer = new DiffieHellmanServer((m) -> {
					try {
						byte[] preparedMessage;

						switch(mode){
							case "No Data Integrity":
								preparedMessage = nonConfidentialMessageHandler.prepareMessage(m, clientNumber.get());
								preparedMessage[m.length / 2] += 42;
								break;
							case "No Freshness":
								preparedMessage = nonConfidentialMessageHandler.prepareMessage(m, clientNumber.get(), new byte[FreshnessHandler.NONCE_SIZE]);
								break;
							default:
								preparedMessage = nonConfidentialMessageHandler.prepareMessage(m, clientNumber.get());
								break;
						}

						out.write(preparedMessage, 0, preparedMessage.length);

					} catch (IOException e) {
						System.out.println(e.getMessage());
					}
				}, () -> {
					while(!clientSocket.isClosed()){
						try {
							byte[] lengthBytes = new byte[Integer.BYTES];
							for(int i = 0; i < Integer.BYTES;){
								i += in.read(lengthBytes, i, Integer.BYTES - i);
							}

							int length = Ints.fromByteArray(lengthBytes);

							byte[] message = new byte[length];

							for(int i = 0; i < length;){
								i += in.read(message, i, length - i);
							}

							clientNumber.set(Ints.fromByteArray(message));
							Mac mac = SignatureHandler.read("" + this.baseDir + "/clients/" + clientNumber);

							nonConfidentialMessageHandler.setMac(mac);

							return nonConfidentialMessageHandler.decodeMessage(message);
						} catch (IOException | NoSuchAlgorithmException | InvalidKeyException e){
							System.out.println(e.getMessage());
							throw new SignatureException();
						}
					}
					return new byte[0];
				});

				dhServer.execute();

				SecretKey sharedKey = dhServer.getSharedKey();
				SecretKey sharedHMACKey = dhServer.getSharedHMACKey();

				StringBuilder builder = new StringBuilder();
				for(byte b : sharedKey.getEncoded()) {
					builder.append(String.format("%02x", b));
				}

				System.out.println("Shared key: " + builder.toString());

				builder = new StringBuilder();
				for(byte b : sharedHMACKey.getEncoded()) {
					builder.append(String.format("%02x", b));
				}

				System.out.println("Shared HMAC key: " + builder.toString());

				Mac sessionMac = Mac.getInstance(SignatureHandler.HMAC_ALGO);
				sessionMac.init(sharedHMACKey);

				ConfidentialMessageHandler confidentialMessageHandler = new ConfidentialMessageHandler(sessionMac, sharedKey);

				while (!clientSocket.isClosed()) {
					// Read message

					byte[] lengthBytes = new byte[Integer.BYTES];
					for(int i = 0; i < Integer.BYTES;){
						i += in.read(lengthBytes, i, Integer.BYTES - i);
					}

					int length = Ints.fromByteArray(lengthBytes);

					byte[] message = new byte[length];

					for(int i = 0; i < length;){
						i += in.read(message, i, length - i);
					}

					String request = new String(confidentialMessageHandler.decodeMessage(message), "UTF-8");
					String toSend;

					switch(request){

						case "Open car doors":
							toSend = "Open door: " + this.incsClient.openDoor().getAck().getAck();
							break;

						case "Close car doors":
							toSend = "Close door: " + this.incsClient.closeDoor().getAck().getAck();
							break;

						case "Turn on AC":
							toSend = "AC turned on: " + this.incsClient.turnOnAc().getAck();
							break;

						case "Turn off AC":
							toSend = "Ac turned off: " + this.incsClient.turnOffAc().getAck();
							break;

						case "Get gas level":
							toSend = "Gas level is: " + this.incsClient.nonCriticalStatus().getGasStatus();
							break;

						case "Get oil level":
							toSend = "Oil level is: " + this.incsClient.nonCriticalStatus().getOilStatus();
							break;

						case "Get tire pressure":
							toSend = "Tire pressure is: " + this.incsClient.nonCriticalStatus().getTirePressureStatus();
							break;
						case "Get general information":
							toSend = "General Information is: " + this.incsClient.generalInformation().getCritical().getBrake();
							break;
						default:
							toSend = "Invalid Request";
							break;
					}

					byte[] preparedMessage = confidentialMessageHandler.prepareMessage(toSend.getBytes(), clientNumber.get());
					out.write(preparedMessage, 0, preparedMessage.length);
				}

				incsClient.ShutDown();

	        } catch (IOException | INCSClientException | SignatureException | MessageNotFreshException | NoSuchAlgorithmException | InvalidKeyException e) {
	        	System.out.print("An error occured: ");
	        	System.out.println(e.getMessage());
	        	try{
		        	clientSocket.close();
	        	} catch (IOException exc) {
	        		System.out.println("An error occured while closing connection with client.");
	        		return;
	        	}
		        System.out.println("Closed connection with client");
	        }
		}
	}
}
*/
	}
}

