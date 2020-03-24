package pt.ulisboa.tecnico.SECDPAS;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;


public class DPASClient {

	public static void main(String[] args) throws Exception {

		final String host = args[0];
		final int port = Integer.parseInt(args[1]);
		System.out.println("HOST: " + host + " PORT: " + port);

		KeyStore keyStore = KeyStore.getInstance("JKS");
		Path currentRelativePath = Paths.get("");
		InputStream keyStoreData = new FileInputStream(currentRelativePath.toAbsolutePath().toString() + "/src/main/security/keys/clientKeyStore.jks");

		keyStore.load(keyStoreData, args[1].toCharArray());
		KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(args[1].toCharArray());
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(args[2], entryPassword);

		ClientLibrary api = new ClientLibrary(host, port, privateKeyEntry.getCertificate().getPublicKey(), privateKeyEntry.getPrivateKey());

		System.out.println("------------------------------------------------------------");
		System.out.println("                        Manufacturer                        ");
		System.out.println("------------------------------------------------------------");
		System.out.println();


		MenuInterface menu = new MenuInterface();

		menu.addOption("Register");
		menu.addOption("Post on personal board");
		menu.addOption("Post on general board");
		menu.addOption("Read from a personal board");
		menu.addOption("Read from the general board");
		menu.addOption("Exit");

		menu.showMenu();

		String selectedOption;

		do {
			selectedOption = menu.selectOption();

			switch(selectedOption){
				case "Register":
					try{
						api.register();
						System.out.println("Registred successfuly!");
					} catch (ClientAlreadyRegisteredException e){
						System.out.println("You are already registered!");
					}
					break;
				case "Read from a personal board":

					break;
				case "Update System No Data Integrity":
					break;
				default:
					break;
			}
		} while(!selectedOption.equals("Exit"));
		api.shutDown();
	}


}