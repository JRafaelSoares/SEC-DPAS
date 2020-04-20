package pt.ulisboa.tecnico.SECDPAS;

import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.ServerBuilder;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;


public class DPASServer {

	public static void main(String[] args) throws Exception {

		System.out.println("------------------------------------------------------------");
		System.out.println("                       DPAS Server                          ");
		System.out.println("------------------------------------------------------------");
		System.out.println();

		// receive and print arguments


		// check arguments
		if (args.length != 5) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s port%n", Server.class.getName());
			return;
		}
		int serverID = Integer.parseInt(args[3]);
		int portClient = Integer.parseInt(args[0])+serverID;
		String alias = String.format("%s%d", args[2], serverID);
		try{
			KeyStore keyStore = KeyStore.getInstance("JKS");
			Path currentRelativePath = Paths.get("");
			InputStream keyStoreData = new FileInputStream(currentRelativePath.toAbsolutePath().toString() + "/src/main/security/keys/serverKeyStore.jks");

			keyStore.load(keyStoreData, args[1].toCharArray());

			KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(args[1].toCharArray());
			KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, entryPassword);
			final BindableService impl = new DPASServiceImpl(privateKeyEntry.getPrivateKey(), serverID, Integer.parseInt(args[4]));


			Server server = ServerBuilder.forPort(portClient).addService(impl).build();
			server.start();

			System.out.println(String.format("[SERVER] Server %d started in location localhost:%d \n", serverID, portClient));

			// Do not exit the main thread. Wait until server is terminated.
			server.awaitTermination();

		} catch (KeyStoreException e){

		}



	}
}

