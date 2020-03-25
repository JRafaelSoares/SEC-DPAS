package pt.ulisboa.tecnico.SECDPAS;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Scanner;


public class DPASClient {

	public static void main(String[] args) throws Exception {

		final String host = args[0];
		final int port = Integer.parseInt(args[1]);
		System.out.println("HOST: " + host + " PORT: " + port);

		KeyStore keyStore = KeyStore.getInstance("JKS");
		Path currentRelativePath = Paths.get("");
		InputStream keyStoreData = new FileInputStream(currentRelativePath.toAbsolutePath().toString() + "/src/main/security/keys/clientKeyStore.jks");

		keyStore.load(keyStoreData, args[2].toCharArray());
		KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(args[2].toCharArray());
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(args[3], entryPassword);

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
		Scanner s = new Scanner(System.in);

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
				case "Post on personal board":
					System.out.println("Write the post right here:");
					char[] message = s.nextLine().toCharArray();
					System.out.println("Do you want to reference announcements? (Y/N)");
					String ref = s.nextLine();

					if(ref.equals("Y")){
						System.out.println("You may enter the announcements seperated by a comma (,):");
						ref = s.nextLine();
						String[] announcements = ref.split(",");

						api.post(message, announcements);

						System.out.println("Posted successfully");
						break;
					}
					if(ref.equals("N")){
						api.post(message);
						System.out.println("Posted successfully");
						break;
					}

					System.out.println("Unexpected input");
					break;
				case "Post on general board":
					System.out.println("Write the post right here:");
					message = s.nextLine().toCharArray();
					System.out.println("Do you want to reference announcements? (Y/N)");
					ref = s.nextLine();

					if(ref.equals("Y")){
						System.out.println("You may enter the announcements seperated by a comma (,):");
						ref = s.nextLine();
						String[] announcements = ref.split(",");

						api.postGeneral(message, announcements);
						System.out.println("Posted successfully");
						break;
					}
					if(ref.equals("N")){
						api.postGeneral(message);
						System.out.println("Posted successfully");
						break;
					}

					System.out.println("Unexpected input");
					break;
				case "Read from a personal board":
					System.out.println("Indicate the public key of the client you wish to read from: ");
					String client = s.nextLine();
					System.out.println("Please indicate the number of last posts you wish to see (0 for all):");
					int number = s.nextInt();
					Announcement[] announcements = api.read(privateKeyEntry.getCertificate().getPublicKey(), number);
					printRead(announcements);
					break;
				case "Read from the general board":
					System.out.println("Please indicate the number of last posts you wish to see (0 for all):");
					number = s.nextInt();
					announcements = api.readGeneral(number);
					printRead(announcements);
					break;
				case "Update System No Data Integrity":
					break;
				default:
					break;
			}
		} while(!selectedOption.equals("Exit"));
		api.shutDown();
	}

	private static void printRead(Announcement[] announcements){
		System.out.println("Posts: ");
		for(Announcement a : announcements){
			System.out.println("Id: " + a.getAnnouncementID());
			System.out.println("Public key: " + a.getPublicKey());
			System.out.println("Post: " + new String(a.getPost()));
			if(a.getAnnouncements().length != 0){
				System.out.println("References: ");
				for(String reference : a.getAnnouncements()){
					System.out.println("\t" + reference);
				}
			}else{
				System.out.println("No references.");
			}
		}
	}


}