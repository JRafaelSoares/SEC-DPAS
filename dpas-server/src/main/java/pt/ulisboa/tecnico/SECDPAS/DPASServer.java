package pt.ulisboa.tecnico.SECDPAS;

import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.ServerBuilder;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;


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
		try{
			KeyStore keyStore = KeyStore.getInstance("JKS");
			Path currentRelativePath = Paths.get("");
			InputStream keyStoreData = new FileInputStream(currentRelativePath.toAbsolutePath().toString() + "/src/main/security/keys/serverKeyStore.jks");

			keyStore.load(keyStoreData, args[1].toCharArray());
			KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(args[1].toCharArray());
			KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(args[2], entryPassword);
			final BindableService impl = new DPASServiceImpl(privateKeyEntry.getPrivateKey());


			Server server = ServerBuilder.forPort(portClient).addService(impl).build();
			server.start();

			System.out.println("[SERVER] Server started");

			// Do not exit the main thread. Wait until server is terminated.
			server.awaitTermination();

		} catch (KeyStoreException e){

		}



	}
}

