package pt.ulisboa.tecnico.SECDPAS;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Scanner;


public class DPASClient {

	public static void main(String[] args) throws Exception {

		if(args.length != 5){
			System.out.println("Invalid number of arguments");
			return;
		}

		final String host = args[0];
		final int port = Integer.parseInt(args[1]);
		System.out.println("HOST: " + host + " PORT: " + port);

		// Get java key store
		KeyStore keyStore = KeyStore.getInstance("JKS");
		Path currentRelativePath = Paths.get("");
		InputStream keyStoreData = new FileInputStream(currentRelativePath.toAbsolutePath().toString() + "/src/main/security/keys/clientKeyStore.jks");

		// Obtain private key
		keyStore.load(keyStoreData, args[2].toCharArray());
		KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(args[2].toCharArray());
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(args[3], entryPassword);

		//Obtain my public keys
		PublicKey myPublicKey = privateKeyEntry.getCertificate().getPublicKey();

		//Obtain client public keys
		ArrayList<PublicKey> clientKeys = new ArrayList<>();

		File dir = new File(currentRelativePath.toAbsolutePath().toString() + "/src/main/security/certificates/clients");
		File[] directoryListing = dir.listFiles();

		if (directoryListing != null) {
			for (File child : directoryListing) {
				CertificateFactory fact = CertificateFactory.getInstance("X.509");
				FileInputStream is = new FileInputStream (child);
				X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
				PublicKey client = cer.getPublicKey();
				if(!client.equals(myPublicKey)){
					clientKeys.add(cer.getPublicKey());
				}
			}
		}


		ClientLibrary api = new ClientLibrary(host, port, myPublicKey, privateKeyEntry.getPrivateKey(), Integer.parseInt(args[4]));

		System.out.println("------------------------------------------------------------");
		System.out.println("                         DPAS-Client                        ");
		System.out.println("------------------------------------------------------------");
		System.out.println();


		MenuInterface menu = new MenuInterface();

		menu.addOption("Register");
		menu.addOption("See registered clients");
		menu.addOption("Post on personal board");
		menu.addOption("Post on general board");
		menu.addOption("Read from a personal board");
		menu.addOption("Read from the general board");
		menu.addOption("Exit");


		String selectedOption;
		Scanner s = new Scanner(System.in);

		do {
			menu.showMenu();

			selectedOption = menu.selectOption();

			switch(selectedOption){
				case "Register":
					try{
						api.register();
						System.out.println("Registered successfully!");
					} catch (ClientAlreadyRegisteredException e){
						System.out.println("You are already registered!");
					} catch(ComunicationException e){
						System.out.println("Error in the communication - " + e.getMessage());
					}
					break;
				case "See registered clients":
					System.out.println("My Key 0:");
					System.out.println(myPublicKey);
					int currentKey = 1;
					for(PublicKey clientKey: clientKeys){
						System.out.println(String.format("%d: %s", currentKey, clientKey));
						currentKey++;
					}
					break;
				case "Post on personal board":
					System.out.println("Write the post right here:");
					char[] message = s.nextLine().toCharArray();
					System.out.println("Do you want to reference announcements? (Y/N)");
					String ref = s.nextLine();

					try{
						if(ref.equals("Y")){
							System.out.println("You may enter the announcements separated by a comma (,):");
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
					} catch(InvalidArgumentException e){
						System.out.println(e.getMessage());
						break;
					} catch(ClientNotRegisteredException e){
						System.out.println("Client not registered");
						break;
					} catch(ComunicationException e){
						System.out.println("Error in the communication - " + e.getMessage());
						break;
					}
					System.out.println("Unexpected input");
					break;
				case "Post on general board":
					System.out.println("Write the post right here:");
					message = s.nextLine().toCharArray();
					System.out.println("Do you want to reference announcements? (Y/N)");
					ref = s.nextLine();

					try{
						if(ref.equals("Y")){
							System.out.println("You may enter the announcements separated by a comma (,):");
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
					} catch(InvalidArgumentException e){
						System.out.println(e.getMessage());
						break;
					} catch(ClientNotRegisteredException e){
						System.out.println("Client not registered");
						break;
					} catch(ComunicationException e){
						System.out.println("Error in the communication - " + e.getMessage());
						break;
					}

					System.out.println("Unexpected input");
					break;

				case "Read from a personal board":
					System.out.println("Indicate the id of the client you wish to read from: ");
					int client = s.nextInt();
					System.out.println("Please indicate the number of last posts you wish to see (0 for all):");
					int number = s.nextInt();
					Announcement[] announcements;

					try{
						if(client == 0){
							announcements = api.read(myPublicKey, number);
						} else {
							if(client-1 <= clientKeys.size()){
								announcements = api.read(clientKeys.get(client-1), number);
							}
							else{
								System.out.println("Invalid public key!");
								break;
							}
						}
						printRead(announcements);

					}catch(InvalidArgumentException e){
						System.out.println(e.getMessage());
						break;
					}catch (ClientNotRegisteredException e){
						System.out.println("Client not registered");
						break;
					} catch(ComunicationException e){
						System.out.println("Error in the communication - " + e.getMessage());
						break;
					}
					break;
				case "Read from the general board":
					System.out.println("Please indicate the number of last posts you wish to see (0 for all):");
					number = s.nextInt();

					try{
						announcements = api.readGeneral(number);
						printRead(announcements);

					} catch(InvalidArgumentException e){
						System.out.println(e.getMessage());
						break;
					} catch (ClientNotRegisteredException e){
						System.out.println("Client not registered");
						break;
					} catch(ComunicationException e){
						System.out.println("Error in the communication - " + e.getMessage());
						break;
					}
					break;
				default:
					break;
			}
		} while(!selectedOption.equals("Exit"));

		api.shutDown();
	}

	private static void printRead(Announcement[] announcements){
		if(announcements.length == 0){
			System.out.println("Posts: Empty");
			return;
		}
		System.out.println("Posts: \n");
		for(Announcement a : announcements){
			System.out.println("Id: " + a.getAnnouncementID());
			System.out.println("\tPublic key: " + a.getPublicKey());
			System.out.println("\tPost: " + new String(a.getPost()));
			if(a.getAnnouncements().length != 0){
				System.out.println("References: ");
				for(String reference : a.getAnnouncements()){
					System.out.println("\t\t" + reference);
				}
			}else{
				System.out.println("\tNo references.");
			}
		}
	}


}